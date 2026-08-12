#!/usr/bin/env python
"""Verify an externally uploaded Container_Audit release without rebuilding it."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kmtech_factory_contracts.active_work_probe.cli import (  # noqa: E402
    ALL_APPS,
    BUILD_IDENTITY_FILENAMES,
    PROBE_ARTIFACT_FILENAME,
)
from kmtech_factory_contracts.active_work_probe.core import (  # noqa: E402
    BUILD_IDENTITY_SCHEMA_VERSION as PROBE_IDENTITY_SCHEMA_VERSION,
)
from kmtech_factory_contracts.canonical import file_sha256, load_json_strict  # noqa: E402
from kmtech_factory_contracts.errors import FactoryContractError  # noqa: E402
from kmtech_factory_contracts.package import verify_staged_package  # noqa: E402
from tools.check_release_config import validate_release_config  # noqa: E402
from update_service import safe_extract_update_zip  # noqa: E402


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
PROBE_IDENTITY_FIELDS = frozenset(
    {
        "schema_version",
        "probe_name",
        "probe_version",
        "probe_artifact_sha256",
        "probe_source_commit",
        "workflow_mode",
        "supported_apps",
    }
)
REQUIRED_MANIFEST_EXPECTED_FILES = frozenset(
    {
        "Container_Audit.exe",
        PROBE_ARTIFACT_FILENAME,
        BUILD_IDENTITY_FILENAMES["independent"],
        BUILD_IDENTITY_FILENAMES["integrated"],
        "contract.lock.json",
        "build-identity.json",
        "build-compatibility.json",
    }
)
LOCAL_QUALIFICATION_SCHEMA = "container-audit-local-artifact-qualification-v1"
LOCAL_QUALIFICATION_STATUS = "LOCAL_ARTIFACT_QUALIFICATION_PASS"
LOCAL_QUALIFICATION_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "tag",
        "tag_object_sha",
        "source_commit",
        "source_tree",
        "local_mirror_main",
        "clone_origin_main",
        "factory_contract_sha256",
        "zip_name",
        "zip_sha256",
        "zip_size",
        "main_exe_sha256",
        "probe_sha256",
    }
)


def _require_lower_hex(value: str, length: int, *, label: str) -> str:
    normalized = str(value or "").strip()
    pattern = SHA256_RE if length == 64 else GIT_OBJECT_RE
    if not pattern.fullmatch(normalized):
        raise ValueError(f"{label} must be exact lowercase {length}-character hex")
    return normalized


def read_checksum(checksum_path: Path, *, expected_filename: str) -> str:
    if checksum_path.stat().st_size > 4096:
        raise ValueError("checksum asset is too large")
    try:
        text = checksum_path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("checksum asset must be ASCII") from exc
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("checksum asset must contain exactly one non-empty line")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", lines[0])
    if not match or match.group(2) != expected_filename:
        raise ValueError("checksum asset must name the exact release ZIP")
    return match.group(1)


def _archive_file_names(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path, "r") as archive:
        encrypted = [member.filename for member in archive.infolist() if member.flag_bits & 0x1]
        if encrypted:
            raise ValueError("release ZIP must not contain encrypted members")
        return {member.filename.rstrip("/") for member in archive.infolist() if not member.is_dir()}


def _files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            left_chunk = left_stream.read(1024 * 1024)
            right_chunk = right_stream.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def _verify_preserved_local_qualification(
    downloaded_zip: Path,
    preserved_zip: Path,
    receipt_path: Path,
    *,
    expected_tag: str,
    expected_tag_object: str,
    expected_commit: str,
    expected_tree: str,
    expected_contract_sha256: str,
    expected_zip_sha256: str,
    expected_zip_size: int,
    expected_main_exe_sha256: str,
) -> dict[str, Any]:
    if downloaded_zip.resolve() == preserved_zip.resolve():
        raise ValueError("preserved local ZIP must be distinct from the downloaded ZIP path")
    if preserved_zip.name != downloaded_zip.name:
        raise ValueError("preserved local ZIP name differs from the downloaded release ZIP")
    if receipt_path.stat().st_size > 64 * 1024:
        raise ValueError("local artifact qualification receipt is too large")
    initial_receipt_hash = file_sha256(receipt_path)
    receipt = load_json_strict(receipt_path)
    if not isinstance(receipt, Mapping) or set(receipt) != LOCAL_QUALIFICATION_FIELDS:
        raise ValueError("local artifact qualification receipt has invalid fields")
    expected_receipt = {
        "schema_version": LOCAL_QUALIFICATION_SCHEMA,
        "status": LOCAL_QUALIFICATION_STATUS,
        "tag": expected_tag,
        "tag_object_sha": expected_tag_object,
        "source_commit": expected_commit,
        "source_tree": expected_tree,
        "local_mirror_main": expected_commit,
        "clone_origin_main": expected_commit,
        "factory_contract_sha256": expected_contract_sha256,
        "zip_name": downloaded_zip.name,
        "zip_sha256": expected_zip_sha256,
        "zip_size": expected_zip_size,
        "main_exe_sha256": expected_main_exe_sha256,
    }
    for key, expected_value in expected_receipt.items():
        if receipt.get(key) != expected_value:
            raise ValueError(f"local artifact qualification receipt {key} differs")
    _require_lower_hex(str(receipt.get("probe_sha256") or ""), 64, label="receipt probe SHA-256")

    initial_local_size = preserved_zip.stat().st_size
    initial_local_hash = file_sha256(preserved_zip)
    if initial_local_size != expected_zip_size or initial_local_hash != expected_zip_sha256:
        raise ValueError("preserved local ZIP differs from its qualification receipt")
    if not _files_equal(downloaded_zip, preserved_zip):
        raise ValueError("downloaded release ZIP is not byte-identical to preserved qualified local bytes")
    if (
        preserved_zip.stat().st_size != initial_local_size
        or file_sha256(preserved_zip) != initial_local_hash
    ):
        raise ValueError("preserved local ZIP changed during byte-parity verification")
    if file_sha256(receipt_path) != initial_receipt_hash:
        raise ValueError("local artifact qualification receipt changed during verification")
    return {
        "status": "PASS",
        "comparison": "streamed-byte-for-byte",
        "qualified_zip_sha256": initial_local_hash,
        "qualified_zip_size": initial_local_size,
        "receipt_sha256": initial_receipt_hash,
    }


def _verify_probe_identities(package_root: Path, *, expected_commit: str) -> dict[str, Any]:
    artifact_path = package_root / PROBE_ARTIFACT_FILENAME
    artifact_hash = file_sha256(artifact_path)
    summaries: dict[str, Any] = {}
    probe_name = None
    probe_version = None
    expected_scopes = {
        "independent": ["Container_Audit"],
        "integrated": list(ALL_APPS),
    }
    for mode, filename in BUILD_IDENTITY_FILENAMES.items():
        identity = load_json_strict(package_root / filename)
        if not isinstance(identity, Mapping) or set(identity) != PROBE_IDENTITY_FIELDS:
            raise ValueError(f"{filename} has invalid fields")
        if identity.get("schema_version") != PROBE_IDENTITY_SCHEMA_VERSION:
            raise ValueError(f"{filename} has an unsupported schema")
        if identity.get("workflow_mode") != mode:
            raise ValueError(f"{filename} workflow mode differs")
        if identity.get("supported_apps") != expected_scopes[mode]:
            raise ValueError(f"{filename} supported-app scope differs")
        if identity.get("probe_source_commit") != expected_commit:
            raise ValueError(f"{filename} source commit differs")
        if identity.get("probe_artifact_sha256") != artifact_hash:
            raise ValueError(f"{filename} artifact hash differs")
        current_name = str(identity.get("probe_name") or "")
        current_version = str(identity.get("probe_version") or "")
        if current_name != "KMTechActiveWorkProbe" or current_version != "v1.0.3.4":
            raise ValueError(f"{filename} probe name/version differs")
        if probe_name is not None and (current_name, current_version) != (probe_name, probe_version):
            raise ValueError("probe identities disagree on name/version")
        probe_name, probe_version = current_name, current_version
        summaries[mode] = {
            "identity_sha256": file_sha256(package_root / filename),
            "supported_apps": identity["supported_apps"],
        }
    return {
        "artifact_sha256": artifact_hash,
        "probe_name": probe_name,
        "probe_version": probe_version,
        "identities": summaries,
    }


def verify_frozen_release(
    zip_path: Path,
    checksum_path: Path,
    *,
    expected_tag: str,
    expected_tag_object: str,
    expected_commit: str,
    expected_tree: str,
    expected_contract_sha256: str,
    expected_zip_sha256: str,
    expected_zip_size: int,
    expected_main_exe_sha256: str,
    qualified_local_zip_path: Path | None = None,
    local_qualification_receipt: Path | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", expected_tag):
        raise ValueError("expected tag must be exact vMAJOR.MINOR.PATCH")
    expected_tag_object = _require_lower_hex(
        expected_tag_object, 40, label="expected tag object"
    )
    expected_commit = _require_lower_hex(expected_commit, 40, label="expected commit")
    expected_tree = _require_lower_hex(expected_tree, 40, label="expected tree")
    expected_contract_sha256 = _require_lower_hex(
        expected_contract_sha256, 64, label="expected contract SHA-256"
    )
    expected_zip_sha256 = _require_lower_hex(
        expected_zip_sha256, 64, label="release-body ZIP SHA-256"
    )
    expected_main_exe_sha256 = _require_lower_hex(
        expected_main_exe_sha256, 64, label="release-body main EXE SHA-256"
    )
    if (
        isinstance(expected_zip_size, bool)
        or not isinstance(expected_zip_size, int)
        or expected_zip_size <= 0
        or expected_zip_size > (2**63 - 1)
    ):
        raise ValueError("release-body ZIP size must be a positive signed 64-bit integer")
    if (qualified_local_zip_path is None) != (local_qualification_receipt is None):
        raise ValueError(
            "preserved local ZIP and local qualification receipt must be supplied together"
        )
    expected_zip_name = f"Container_Audit-{expected_tag}.zip"
    if zip_path.name != expected_zip_name:
        raise ValueError(f"release ZIP must be named {expected_zip_name}")
    if checksum_path.name != f"{expected_zip_name}.sha256":
        raise ValueError("checksum asset name differs from the release ZIP")
    initial_zip_size = zip_path.stat().st_size
    if initial_zip_size != expected_zip_size:
        raise ValueError("release ZIP size differs from the immutable release body")
    initial_checksum_hash = file_sha256(checksum_path)
    expected_zip_hash = read_checksum(checksum_path, expected_filename=expected_zip_name)
    actual_zip_hash = file_sha256(zip_path)
    if actual_zip_hash != expected_zip_sha256:
        raise ValueError("release ZIP hash differs from the immutable release body")
    if actual_zip_hash != expected_zip_hash:
        raise ValueError("release ZIP differs from its checksum asset")

    archived_files = _archive_file_names(zip_path)
    with tempfile.TemporaryDirectory(prefix="container-release-verify-") as temporary:
        extraction_root = Path(temporary)
        safe_extract_update_zip(zip_path, extraction_root)
        package_root = extraction_root / "Container_Audit"
        manifest = load_json_strict(package_root / "build-manifest.json")
        if not isinstance(manifest, Mapping):
            raise ValueError("build manifest must be an object")
        inventory = manifest.get("payload_inventory")
        if not isinstance(inventory, list):
            raise ValueError("build manifest payload inventory is invalid")
        manifest_paths = {
            str(row.get("path") or "")
            for row in inventory
            if isinstance(row, Mapping)
        }
        expected_archive_files = {
            f"Container_Audit/{relative}" for relative in manifest_paths
        } | {"Container_Audit/build-manifest.json"}
        if archived_files != expected_archive_files:
            missing = sorted(expected_archive_files - archived_files)
            extra = sorted(archived_files - expected_archive_files)
            raise ValueError(
                f"archive membership differs from sealed manifest: missing={missing[:5]} extra={extra[:5]}"
            )
        if set(manifest.get("expected_files") or ()) != REQUIRED_MANIFEST_EXPECTED_FILES:
            raise ValueError("build manifest expected-files contract differs")

        package_report = verify_staged_package(
            package_root,
            expected_contract_sha256=expected_contract_sha256,
            expected_source_commit=expected_commit,
            expected_source_tree=expected_tree,
        )
        if package_report.get("app_id") != "container_audit":
            raise ValueError("embedded app id differs")
        if package_report.get("app_version") != expected_tag:
            raise ValueError("embedded app version differs from tag")
        validate_release_config(package_root / "config")
        release_settings = load_json_strict(
            package_root / "config" / "container_audit_settings.json"
        )
        update_settings = release_settings.get("update_settings") or {}
        probe_report = _verify_probe_identities(package_root, expected_commit=expected_commit)
        executable_hash = file_sha256(package_root / "Container_Audit.exe")
        if executable_hash != expected_main_exe_sha256:
            raise ValueError("main EXE hash differs from the immutable release body")

    if zip_path.stat().st_size != initial_zip_size or file_sha256(zip_path) != actual_zip_hash:
        raise ValueError("release ZIP changed during verification")
    if file_sha256(checksum_path) != initial_checksum_hash:
        raise ValueError("checksum asset changed during verification")

    local_byte_parity: dict[str, Any]
    if qualified_local_zip_path is None:
        local_byte_parity = {
            "status": "NOT_TESTED",
            "reason": "preserved qualified local bytes are unavailable on the hosted runner",
        }
    else:
        assert local_qualification_receipt is not None
        local_byte_parity = _verify_preserved_local_qualification(
            zip_path,
            qualified_local_zip_path,
            local_qualification_receipt,
            expected_tag=expected_tag,
            expected_tag_object=expected_tag_object,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            expected_contract_sha256=expected_contract_sha256,
            expected_zip_sha256=expected_zip_sha256,
            expected_zip_size=expected_zip_size,
            expected_main_exe_sha256=expected_main_exe_sha256,
        )

    return {
        "schema_version": "container-audit-frozen-release-verification-v2",
        "status": "PASS" if local_byte_parity["status"] == "PASS" else "PASS_SELF_CONSISTENCY",
        "tag": expected_tag,
        "tag_object_sha": expected_tag_object,
        "source_commit": expected_commit,
        "source_tree": expected_tree,
        "contract_bundle_sha256": expected_contract_sha256,
        "release_body_evidence": {
            "scope": "immutable-release-body-and-checksum-self-consistency",
            "zip_sha256": expected_zip_sha256,
            "zip_size": expected_zip_size,
            "main_exe_sha256": expected_main_exe_sha256,
        },
        "governing_local_byte_parity": local_byte_parity,
        "archive": {
            "name": expected_zip_name,
            "size_bytes": initial_zip_size,
            "sha256": actual_zip_hash,
            "file_count": len(archived_files),
            "checksum_asset": checksum_path.name,
            "checksum_asset_sha256": initial_checksum_hash,
            "crc_and_safe_extraction": True,
            "exact_manifest_membership": True,
        },
        "package": package_report,
        "container_audit_exe_sha256": executable_hash,
        "active_work_probe": probe_report,
        "release_config": {
            "status": "PASS",
            "update_provider": update_settings.get("provider"),
            "channel": update_settings.get("channel"),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip-path", required=True, type=Path)
    parser.add_argument("--checksum-path", required=True, type=Path)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--expected-tag-object", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-contract-sha256", required=True)
    parser.add_argument("--expected-zip-sha256", required=True)
    parser.add_argument("--expected-zip-size", required=True, type=int)
    parser.add_argument("--expected-main-exe-sha256", required=True)
    parser.add_argument("--qualified-local-zip-path", type=Path)
    parser.add_argument("--local-qualification-receipt", type=Path)
    parser.add_argument("--report-path", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.report_path.exists():
        print("frozen_release_verification=FAIL reason=report path already exists", file=sys.stderr)
        return 2
    try:
        report = verify_frozen_release(
            args.zip_path,
            args.checksum_path,
            expected_tag=args.expected_tag,
            expected_tag_object=args.expected_tag_object,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            expected_contract_sha256=args.expected_contract_sha256,
            expected_zip_sha256=args.expected_zip_sha256,
            expected_zip_size=args.expected_zip_size,
            expected_main_exe_sha256=args.expected_main_exe_sha256,
            qualified_local_zip_path=args.qualified_local_zip_path,
            local_qualification_receipt=args.local_qualification_receipt,
        )
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (FactoryContractError, OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"frozen_release_verification=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
