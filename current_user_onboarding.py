"""First-run current-user state onboarding for Container_Audit."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping, MutableMapping
import uuid

from direct_sync_push import load_json_no_duplicate_keys, manifest_hash
from direct_sync_runtime import load_credentials_from_json
from logistics_runtime_profile import (
    PROFILE_PATH_ENV,
    REQUIRED_ENV,
    load_logistics_runtime_profile,
    unprotect_current_user_secret,
)
from storage_policy import (
    DATA_ROOT_ENV,
    build_container_audit_storage_paths,
    current_user_data_home,
    is_legacy_syncthing_path,
    path_is_within,
)
from user_relay import (
    USER_RELAY_RUN_KEY,
    USER_RELAY_RUN_VALUE,
    USER_RELAY_MODE,
    install_user_relay_autostart,
    remove_user_relay_autostart,
    request_user_relay_stop,
    start_user_relay_process,
    user_relay_stop_path,
)
from vendor.kmtech_zero_pe import (
    ADMIN_RECOVERY_ACTION,
    AdminRecoveryRequired as PossessionKeyAdminRecoveryRequired,
    POSSESSION_KEY_CONTRACT_VERSION,
    PersistentPossessionKey,
    SCOPE_CURRENT_USER,
)

DEFAULT_SERVER_BASE_URL = "https://worker.kmtecherp.com"
DEFAULT_ENDPOINT_PATH = "/api/producer-ingest/v1/source-file"
ONBOARDING_REPORT_VERSION = "container-audit-current-user-onboarding-v1"
REMOVAL_REPORT_VERSION = "container-audit-current-user-removal-v1"
REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION = (
    "container-audit-replacement-lifecycle-restore-v1"
)
BOOTSTRAP_INTEGRITY_VERSION = "container-audit-bootstrap-integrity-v1"
LOGISTICS_PROFILE_PATH_ENV = "CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH"
ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV = "CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH"
ONBOARDING_EXIT_CODE = 4
SELF_ENROLLMENT_CONTRACT_VERSION = "producer-self-enrollment-v2"
REPLACEMENT_RECEIPT_VERSION = "container-audit-verified-replacement-v1"
PORTABLE_MANIFEST_VERSION = "container-audit-portable-tree-v1"

_REPLACEMENT_IDENTITY_FIELDS = frozenset(
    {
        "file_count",
        "aggregate_sha256",
        "integrity_sha256",
        "manifest_sha256",
        "source_commit",
        "source_tree",
        "owner_sid",
        "access_rules_protected",
        "acl_sddl_sha256",
        "reparse_count",
    }
)
_REPLACEMENT_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "app_id",
        "transaction_id",
        "created_at",
        "helper_sha256",
        "integrity_helper_sha256",
        "receipt_path",
        "install_root",
        "install_parent",
        "rollback_root",
        "failed_root",
        "parent_acl",
        "old",
        "new",
        "identity_or_credential_copied",
    }
)


class CurrentUserOnboardingError(RuntimeError):
    def __init__(
        self, message: str, *, report_path: Path, status: str = "FAILED"
    ) -> None:
        super().__init__(message)
        self.report_path = Path(report_path)
        self.status = status


class CurrentUserPossessionRecoveryRequired(ValueError):
    recovery_action = ADMIN_RECOVERY_ACTION


@dataclass(frozen=True)
class CurrentUserOnboardingPaths:
    app_root: Path
    data_root: Path
    events_dir: Path
    direct_sync_root: Path
    queue_dir: Path
    spool_dir: Path
    status_dir: Path
    logs_dir: Path
    identity_path: Path
    producer_manifest_path: Path
    credential_path: Path
    registration_report_path: Path
    onboarding_report_path: Path
    removal_report_path: Path
    logistics_profile_path: Path
    logistics_secret_path: Path
    bootstrap_tls_ca_bundle_path: Path
    ledger_path: Path
    bootstrap_integrity_path: Path


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _resolved(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def resolve_current_user_onboarding_paths(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> CurrentUserOnboardingPaths:
    values = os.environ if environ is None else environ
    selected_app_root = _resolved(app_root)
    explicit_data_root = str(values.get(DATA_ROOT_ENV) or "").strip()
    try:
        storage_paths = build_container_audit_storage_paths(
            application_path=str(selected_app_root),
            environ=values,
        )
        user_root = (
            storage_paths.data_root
            if explicit_data_root
            else current_user_data_home(values)
        )
    except ValueError as exc:
        safe_report_root = str(values.get("TEMP") or values.get("TMP") or "").strip()
        report_root = (
            _resolved(safe_report_root)
            if safe_report_root
            else _resolved(Path.home() / ".kmtech")
        )
        raise CurrentUserOnboardingError(
            str(exc),
            report_path=report_root
            / "container-audit-current-user-onboarding-rejected.json",
            status="FAILED",
        ) from exc
    data_root = storage_paths.data_root
    direct_sync_root = storage_paths.direct_sync_root
    if explicit_data_root:
        default_logistics_profile = (
            data_root / "logistics-profile" / "runtime-profile.json"
        )
    else:
        default_logistics_profile = (
            user_root
            / "KMTech"
            / "Logistics"
            / "profiles"
            / "Container_Audit"
            / "runtime-profile.json"
        )
    explicit_profile = str(values.get(LOGISTICS_PROFILE_PATH_ENV) or "").strip()
    if explicit_profile:
        profile_candidate = Path(explicit_profile).expanduser()
        if not profile_candidate.is_absolute():
            raise CurrentUserOnboardingError(
                f"{LOGISTICS_PROFILE_PATH_ENV} must be an absolute current-user path",
                report_path=user_root
                / "KMTech"
                / "ContainerAudit"
                / "current-user-onboarding-rejected.json",
                status="FAILED",
            )
        logistics_profile = _resolved(profile_candidate)
    else:
        logistics_profile = default_logistics_profile
    bootstrap_tls_ca_bundle = (
        data_root / "bootstrap" / "ca-bundle.pem"
        if explicit_data_root
        else user_root / "KMTech" / "Bootstrap" / "Container_Audit" / "ca-bundle.pem"
    )
    code_root_state_paths = (
        data_root,
        direct_sync_root,
        logistics_profile,
        bootstrap_tls_ca_bundle,
    )
    if any(
        path_is_within(candidate, selected_app_root)
        or path_is_within(selected_app_root, candidate)
        for candidate in code_root_state_paths
    ):
        safe_report_root = str(values.get("TEMP") or values.get("TMP") or "").strip()
        report_path = (
            _resolved(safe_report_root)
            if safe_report_root
            else _resolved(Path.home() / ".kmtech")
        ) / "container-audit-current-user-onboarding-rejected.json"
        raise CurrentUserOnboardingError(
            "current-user onboarding state must be outside the read-only application code root",
            report_path=report_path,
            status="FAILED",
        )
    for candidate in (data_root, direct_sync_root, logistics_profile):
        if is_legacy_syncthing_path(candidate):
            raise CurrentUserOnboardingError(
                "current-user onboarding state must not use the legacy Syncthing root",
                report_path=direct_sync_root
                / "status"
                / "current_user_onboarding.json",
            )
    status_dir = direct_sync_root / "status"
    return CurrentUserOnboardingPaths(
        app_root=selected_app_root,
        data_root=data_root,
        events_dir=data_root / "events",
        direct_sync_root=direct_sync_root,
        queue_dir=direct_sync_root / "queue",
        spool_dir=direct_sync_root / "spool",
        status_dir=status_dir,
        logs_dir=direct_sync_root / "logs",
        identity_path=direct_sync_root / "producer_identity.json",
        producer_manifest_path=direct_sync_root / "producer_manifest.json",
        credential_path=direct_sync_root / "credential.json",
        registration_report_path=status_dir / "worker_pc_registration.json",
        onboarding_report_path=status_dir / "current_user_onboarding.json",
        removal_report_path=status_dir / "current_user_removal.json",
        logistics_profile_path=logistics_profile,
        logistics_secret_path=(
            logistics_profile.parent / "secrets" / "bearer-token.dpapi"
        ),
        bootstrap_tls_ca_bundle_path=bootstrap_tls_ca_bundle,
        ledger_path=data_root / "transfer_seal" / "transfer_seal.db",
        bootstrap_integrity_path=selected_app_root / "bootstrap-integrity.json",
    )


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json_atomic_create_new(path: Path, payload: Mapping[str, Any]) -> None:
    """Publish JSON atomically without ever replacing an existing pathname."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(
                dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path, purpose: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"{purpose} is absent") from exc
    if size <= 0 or size > 1024 * 1024:
        raise ValueError(f"{purpose} size is invalid")
    try:
        value = load_json_no_duplicate_keys(path.read_bytes())
    except Exception as exc:
        raise ValueError(f"{purpose} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{purpose} must be a JSON object")
    return value


def _read_pinned_json(
    path: Path,
    purpose: str,
    *,
    expected_sha256: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    _require_regular_unredirected_file(path, purpose)
    try:
        with path.open("rb") as handle:
            data = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if not data or len(data) > maximum_bytes:
        raise ValueError(f"{purpose} size is invalid")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"{purpose} SHA-256 differs")
    try:
        value = load_json_no_duplicate_keys(data)
    except Exception as exc:
        raise ValueError(f"{purpose} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{purpose} must be a JSON object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bootstrap_integrity(
    paths: CurrentUserOnboardingPaths,
    *,
    required: bool,
) -> dict[str, Any]:
    if not required:
        return {"status": "NOT_TESTED", "reason": "source-mode onboarding"}
    try:
        record_stat = paths.bootstrap_integrity_path.lstat()
    except FileNotFoundError:
        return {
            "status": "ABSENT",
            "reason": "bootstrap integrity record is absent; continuing with a warning",
            "record_path": str(paths.bootstrap_integrity_path),
        }
    except OSError as exc:
        raise ValueError("bootstrap integrity record is unreadable") from exc
    if stat.S_ISLNK(record_stat.st_mode) or not stat.S_ISREG(record_stat.st_mode):
        raise ValueError(
            "bootstrap integrity record is redirected or not a regular file"
        )
    record = _read_json(paths.bootstrap_integrity_path, "bootstrap integrity record")
    if record.get("schema_version") != BOOTSTRAP_INTEGRITY_VERSION:
        raise ValueError("bootstrap integrity record schema is invalid")
    if record.get("status") != "PASS":
        raise ValueError("bootstrap integrity record is not PASS")
    declared_code_root = str(record.get("code_root") or "")
    resolved_code_root = (
        paths.bootstrap_integrity_path.parent.resolve()
        if declared_code_root == "."
        else _resolved(declared_code_root)
    )
    if resolved_code_root != paths.app_root:
        raise ValueError("bootstrap integrity record code root is invalid")
    files = record.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("bootstrap integrity record file inventory is invalid")
    if record.get("file_count") != len(files):
        raise ValueError("bootstrap integrity record file count is invalid")
    normalized: list[tuple[str, int, str]] = []
    declared_paths: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise ValueError("bootstrap integrity inventory entry is invalid")
        relative_text = str(item.get("path") or "").replace("\\", "/")
        parts = relative_text.split("/")
        if (
            not relative_text
            or relative_text.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or ":" in parts[0]
        ):
            raise ValueError("bootstrap integrity inventory path is unsafe")
        folded = relative_text.casefold()
        if folded in declared_paths:
            raise ValueError("bootstrap integrity inventory path is duplicated")
        declared_paths.add(folded)
        try:
            expected_size = int(item.get("size"))
        except (TypeError, ValueError) as exc:
            raise ValueError("bootstrap integrity inventory size is invalid") from exc
        expected_hash = str(item.get("sha256") or "").strip().lower()
        if expected_size < 0 or len(expected_hash) != 64:
            raise ValueError("bootstrap integrity inventory metadata is invalid")
        target = paths.app_root.joinpath(*parts)
        if target.is_symlink() or not target.is_file():
            raise ValueError(
                f"bootstrap code file is absent or redirected: {relative_text}"
            )
        if (
            target.stat().st_size != expected_size
            or _file_sha256(target) != expected_hash
        ):
            raise ValueError(f"bootstrap code file integrity failed: {relative_text}")
        normalized.append((expected_hash, expected_size, relative_text))
    actual_paths = set()
    for candidate in paths.app_root.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(paths.app_root).as_posix().casefold()
        if relative == paths.bootstrap_integrity_path.name.casefold():
            continue
        actual_paths.add(relative)
    if actual_paths != declared_paths:
        raise ValueError("bootstrap code inventory exact readback failed")
    aggregate_payload = "".join(
        f"{sha256} {size} {relative_path}\n"
        for sha256, size, relative_path in normalized
    ).encode("utf-8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    if aggregate != str(record.get("aggregate_sha256") or "").strip().lower():
        raise ValueError("bootstrap integrity aggregate is invalid")
    main_entries = [
        item
        for item in files
        if isinstance(item, Mapping)
        and str(item.get("path") or "").replace("\\", "/").casefold()
        == "container_audit.exe".casefold()
    ]
    if len(main_entries) != 1:
        raise ValueError(
            "bootstrap integrity record does not identify Container_Audit.exe"
        )
    executable = paths.app_root / "Container_Audit.exe"
    if not executable.is_file():
        raise ValueError("hardened Container_Audit executable is absent")
    return {
        "status": "PASS",
        "record_path": str(paths.bootstrap_integrity_path),
        "code_root": str(paths.app_root),
        "file_count": len(files),
        "aggregate_sha256": aggregate,
    }


def _is_reparse_or_link(path_stat: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    attributes = int(getattr(path_stat, "st_file_attributes", 0))
    return stat.S_ISLNK(path_stat.st_mode) or bool(attributes & reparse_flag)


def _require_regular_unredirected_file(path: Path, purpose: str) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if _is_reparse_or_link(path_stat) or not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{purpose} is redirected or not a regular file")
    return path_stat


def _assert_tree_has_no_reparse_points(root: Path, purpose: str) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise ValueError(f"{purpose} is absent or unreadable") from exc
    if _is_reparse_or_link(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(f"{purpose} is redirected or not a directory")
    for candidate in root.rglob("*"):
        try:
            candidate_stat = candidate.lstat()
        except OSError as exc:
            raise ValueError(f"{purpose} contains an unreadable path") from exc
        if _is_reparse_or_link(candidate_stat):
            raise ValueError(f"{purpose} contains a reparse point")


def _windows_acl_identity(path: Path) -> dict[str, Any]:
    """Read the same owner/protection/SDDL identity as bootstrap_integrity.ps1."""

    if os.name != "nt":
        raise OSError("replacement lifecycle ACL readback is Windows-only")
    import ctypes

    system_directory_buffer = ctypes.create_unicode_buffer(32768)
    system_directory_length = ctypes.windll.kernel32.GetSystemDirectoryW(
        system_directory_buffer,
        len(system_directory_buffer),
    )
    if system_directory_length <= 0 or system_directory_length >= len(
        system_directory_buffer
    ):
        raise OSError("Windows system directory readback failed")
    powershell = (
        Path(system_directory_buffer.value)
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    _require_regular_unredirected_file(
        powershell,
        "Windows PowerShell ACL reader",
    )
    escaped_path = str(path).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';"
        f"$item=Get-Item -LiteralPath '{escaped_path}' -Force;"
        "$sections=([Security.AccessControl.AccessControlSections]::Access -bor "
        "[Security.AccessControl.AccessControlSections]::Owner -bor "
        "[Security.AccessControl.AccessControlSections]::Group);"
        "$acl=if($item.PSIsContainer){"
        "[IO.Directory]::GetAccessControl($item.FullName,$sections)"
        "}else{[IO.File]::GetAccessControl($item.FullName,$sections)};"
        "$sddl=$acl.GetSecurityDescriptorSddlForm($sections);"
        "$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($sddl);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-',"
        "'').ToLowerInvariant()}finally{$sha.Dispose()};"
        "[ordered]@{owner_sid=[string]$acl.GetOwner("
        "[Security.Principal.SecurityIdentifier]).Value;"
        "access_rules_protected=[bool]$acl.AreAccessRulesProtected;"
        "acl_sddl_sha256=$hash}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=15,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if (
        completed.returncode != 0
        or len(completed.stdout.encode("utf-8")) > 4096
        or len(completed.stderr.encode("utf-8")) > 4096
    ):
        raise OSError("replacement lifecycle ACL readback failed")
    try:
        result = json.loads(completed.stdout)
    except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("replacement lifecycle ACL identity is invalid") from exc
    if not isinstance(result, dict):
        raise ValueError("replacement lifecycle ACL identity is invalid")
    return result


def _normalized_replacement_identity(
    value: Any,
    purpose: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _REPLACEMENT_IDENTITY_FIELDS:
        raise ValueError(f"{purpose} shape is invalid")
    file_count = value.get("file_count")
    reparse_count = value.get("reparse_count")
    protected = value.get("access_rules_protected")
    if type(file_count) is not int or file_count <= 0:
        raise ValueError(f"{purpose} file count is invalid")
    if type(reparse_count) is not int or reparse_count != 0:
        raise ValueError(f"{purpose} reparse count is invalid")
    if type(protected) is not bool:
        raise ValueError(f"{purpose} ACL protection is invalid")
    for field in (
        "aggregate_sha256",
        "integrity_sha256",
        "manifest_sha256",
        "acl_sddl_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(field) or "")):
            raise ValueError(f"{purpose} {field} is invalid")
    for field in ("source_commit", "source_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(value.get(field) or "")):
            raise ValueError(f"{purpose} {field} is invalid")
    owner_sid = str(value.get("owner_sid") or "")
    if not owner_sid or len(owner_sid) > 184:
        raise ValueError(f"{purpose} owner identity is invalid")
    return {field: value[field] for field in _REPLACEMENT_IDENTITY_FIELDS}


def _read_replacement_tree_identity(
    tree_root: Path,
    declared_code_root: Path,
    *,
    acl_identity_reader: Callable[[Path], Mapping[str, Any]] = _windows_acl_identity,
) -> dict[str, Any]:
    """Read an exact portable tree identity without executing code from that tree."""

    selected_root = _resolved(tree_root)
    expected_code_root = _resolved(declared_code_root)
    _assert_tree_has_no_reparse_points(selected_root, "replacement code tree")
    record_path = selected_root / "bootstrap-integrity.json"
    record_stat = _require_regular_unredirected_file(
        record_path,
        "replacement bootstrap integrity record",
    )
    if record_stat.st_size <= 0 or record_stat.st_size > 1024 * 1024:
        raise ValueError("replacement bootstrap integrity record size is invalid")
    record = _read_json(record_path, "replacement bootstrap integrity record")
    declared_root_text = str(record.get("code_root") or "")
    if declared_root_text == ".":
        resolved_declared_root = selected_root
    elif Path(declared_root_text).is_absolute():
        resolved_declared_root = _resolved(declared_root_text)
    else:
        raise ValueError("replacement bootstrap code root is invalid")
    files = record.get("files")
    if (
        record.get("schema_version") != BOOTSTRAP_INTEGRITY_VERSION
        or record.get("status") != "PASS"
        or resolved_declared_root != expected_code_root
        or not isinstance(files, list)
        or not files
        or type(record.get("file_count")) is not int
        or record.get("file_count") != len(files)
    ):
        raise ValueError("replacement bootstrap integrity identity is invalid")

    normalized: list[tuple[str, int, str]] = []
    declared_paths: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise ValueError("replacement bootstrap inventory entry is invalid")
        relative_text = str(item.get("path") or "").replace("\\", "/")
        parts = relative_text.split("/")
        folded = relative_text.casefold()
        expected_size = item.get("size")
        expected_hash = str(item.get("sha256") or "")
        if (
            not relative_text
            or relative_text.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
            or ":" in parts[0]
            or folded in declared_paths
            or type(expected_size) is not int
            or expected_size < 0
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            raise ValueError("replacement bootstrap inventory metadata is invalid")
        target = selected_root.joinpath(*parts)
        target_stat = _require_regular_unredirected_file(
            target,
            "replacement bootstrap code file",
        )
        if (
            target_stat.st_size != expected_size
            or _file_sha256(target) != expected_hash
        ):
            raise ValueError("replacement bootstrap code file integrity failed")
        declared_paths.add(folded)
        normalized.append((expected_hash, expected_size, relative_text))

    actual_paths: set[str] = set()
    for candidate in selected_root.rglob("*"):
        candidate_stat = candidate.lstat()
        if not stat.S_ISREG(candidate_stat.st_mode):
            continue
        relative = candidate.relative_to(selected_root).as_posix().casefold()
        if relative == "bootstrap-integrity.json":
            continue
        if relative in actual_paths:
            raise ValueError("replacement bootstrap inventory has a case collision")
        actual_paths.add(relative)
    if actual_paths != declared_paths:
        raise ValueError("replacement bootstrap inventory exact readback failed")
    aggregate_payload = "".join(
        f"{sha256} {size} {relative_path}\n"
        for sha256, size, relative_path in normalized
    ).encode("utf-8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    if aggregate != str(record.get("aggregate_sha256") or ""):
        raise ValueError("replacement bootstrap aggregate is invalid")
    if (
        "runtime/pythonw.exe" not in declared_paths
        or "app/main.py" not in declared_paths
        or "container_audit.exe" in declared_paths
    ):
        raise ValueError("replacement code tree is not the portable runtime layout")

    manifest_path = selected_root / "portable-manifest.json"
    manifest_stat = _require_regular_unredirected_file(
        manifest_path,
        "replacement portable manifest",
    )
    if manifest_stat.st_size <= 0 or manifest_stat.st_size > 65536:
        raise ValueError("replacement portable manifest size is invalid")
    manifest = _read_json(manifest_path, "replacement portable manifest")
    source_commit = str(manifest.get("source_commit") or "")
    source_tree = str(manifest.get("source_tree") or "")
    if (
        manifest.get("schema") != PORTABLE_MANIFEST_VERSION
        or manifest.get("entrypoint") != "runtime/pythonw.exe app/main.py"
        or not re.fullmatch(r"[0-9a-f]{40}", source_commit)
        or not re.fullmatch(r"[0-9a-f]{40}", source_tree)
    ):
        raise ValueError("replacement portable manifest identity is invalid")
    acl = dict(acl_identity_reader(selected_root))
    if set(acl) != {
        "owner_sid",
        "access_rules_protected",
        "acl_sddl_sha256",
    }:
        raise ValueError("replacement code ACL identity is invalid")
    return _normalized_replacement_identity(
        {
            "file_count": len(files),
            "aggregate_sha256": aggregate,
            "integrity_sha256": _file_sha256(record_path),
            "manifest_sha256": _file_sha256(manifest_path),
            "source_commit": source_commit,
            "source_tree": source_tree,
            "owner_sid": acl["owner_sid"],
            "access_rules_protected": acl["access_rules_protected"],
            "acl_sddl_sha256": acl["acl_sddl_sha256"],
            "reparse_count": 0,
        },
        "replacement code identity",
    )


def _owner_artifact_paths(
    paths: CurrentUserOnboardingPaths,
) -> dict[str, Path]:
    return {
        "identity": paths.identity_path,
        "producer_manifest": paths.producer_manifest_path,
        "credential": paths.credential_path,
        "registration_report": paths.registration_report_path,
        "logistics_profile": paths.logistics_profile_path,
        "logistics_secret": paths.logistics_secret_path,
        "ledger": paths.ledger_path,
    }


def _owner_artifact_fingerprints(
    owner_paths: Mapping[str, Path],
) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    for name, path in owner_paths.items():
        before = _require_regular_unredirected_file(
            path,
            f"current-user owner artifact {name}",
        )
        fingerprint = _file_sha256(path)
        after = _require_regular_unredirected_file(
            path,
            f"current-user owner artifact {name}",
        )
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or getattr(before, "st_ino", 0) != getattr(after, "st_ino", 0)
        ):
            raise ValueError("current-user owner state changed during readback")
        fingerprints[name] = fingerprint
    return fingerprints


def _replacement_user_relay_command(app_root: Path) -> list[str]:
    selected = _resolved(app_root)
    pythonw = selected.parent / "runtime" / "pythonw.exe"
    entrypoint = selected / "main.py"
    _require_regular_unredirected_file(
        pythonw,
        "replacement lifecycle canonical relay runtime",
    )
    _require_regular_unredirected_file(
        entrypoint,
        "replacement lifecycle canonical relay entrypoint",
    )
    return [str(pythonw), "-I", "-B", str(entrypoint), USER_RELAY_MODE]


def _replacement_user_relay_command_line(app_root: Path) -> str:
    return subprocess.list2cmdline(_replacement_user_relay_command(app_root))


def _start_replacement_user_relay_process(app_root: Path) -> dict[str, Any]:
    selected = _resolved(app_root)
    command = _replacement_user_relay_command(selected)
    creation_flags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )
    process = subprocess.Popen(
        command,
        cwd=str(selected),
        close_fds=True,
        creationflags=creation_flags,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if type(process.pid) is not int or process.pid <= 0:
        raise ValueError("replacement lifecycle relay launch did not return a process id")
    return {"status": "START_REQUESTED", "process_id": process.pid}


def _inspect_current_process_execution_context() -> dict[str, Any]:
    if os.name != "nt":
        raise ValueError("replacement lifecycle token inspection requires Windows")
    from ctypes import wintypes

    token_query = 0x0008
    token_elevation = 20
    token_integrity_level = 25
    error_insufficient_buffer = 122
    process_token = wintypes.HANDLE()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(process_token)
    ):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        elevated = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
            process_token,
            token_elevation,
            ctypes.byref(elevated),
            ctypes.sizeof(elevated),
            ctypes.byref(returned),
        ):
            raise OSError(ctypes.get_last_error(), "TokenElevation readback failed")

        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            process_token,
            token_integrity_level,
            None,
            0,
            ctypes.byref(required),
        )
        if ctypes.get_last_error() != error_insufficient_buffer or required.value <= 0:
            raise OSError(
                ctypes.get_last_error(), "TokenIntegrityLevel sizing failed"
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            process_token,
            token_integrity_level,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise OSError(
                ctypes.get_last_error(), "TokenIntegrityLevel readback failed"
            )

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

        sid = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents.sid
        count_pointer = advapi32.GetSidSubAuthorityCount(sid)
        if not count_pointer:
            raise OSError(ctypes.get_last_error(), "integrity SID count failed")
        count = count_pointer.contents.value
        if count <= 0:
            raise ValueError("integrity SID contains no subauthority")
        rid_pointer = advapi32.GetSidSubAuthority(sid, count - 1)
        if not rid_pointer:
            raise OSError(ctypes.get_last_error(), "integrity SID RID failed")
        rid = rid_pointer.contents.value
    finally:
        kernel32.CloseHandle(process_token)

    if 0x2000 <= rid < 0x3000:
        integrity = "MEDIUM"
    elif rid < 0x2000:
        integrity = "LOW"
    else:
        integrity = "HIGH"
    return {
        "status": "PASS",
        "token_elevated": bool(elevated.value),
        "integrity_level": integrity,
    }


def _install_replacement_user_relay_autostart(app_root: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise ValueError("replacement lifecycle HKCU relay requires Windows")
    import winreg

    command = _replacement_user_relay_command_line(app_root)
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        USER_RELAY_RUN_KEY,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
    ) as key:
        winreg.SetValueEx(key, USER_RELAY_RUN_VALUE, 0, winreg.REG_SZ, command)
        readback, value_type = winreg.QueryValueEx(key, USER_RELAY_RUN_VALUE)
    if value_type != winreg.REG_SZ or str(readback) != command:
        raise ValueError("replacement lifecycle HKCU relay exact readback failed")
    return {
        "status": "PASS",
        "principal": "current_user",
        "registry_hive": "HKEY_CURRENT_USER",
        "registry_key": USER_RELAY_RUN_KEY,
        "registry_value": USER_RELAY_RUN_VALUE,
        "command": command,
    }


def _default_profile_loader(path: Path) -> Any:
    return load_logistics_runtime_profile(
        required=True,
        profile_path=path,
        decryptor=unprotect_current_user_secret,
    )


def _possession_key_readback(identity: Mapping[str, Any]) -> dict[str, Any]:
    enrollment_contract = str(identity.get("enrollment_contract_version") or "")
    key_contract = str(identity.get("possession_key_contract_version") or "")
    expected_fingerprint = str(identity.get("possession_key_fingerprint") or "")
    if (
        enrollment_contract != SELF_ENROLLMENT_CONTRACT_VERSION
        or key_contract != POSSESSION_KEY_CONTRACT_VERSION
        or not expected_fingerprint
    ):
        raise CurrentUserPossessionRecoveryRequired(
            "legacy producer identity has no v2 possession-key binding; audited administrator recovery is required"
        )
    try:
        with PersistentPossessionKey.open_existing(
            scope=SCOPE_CURRENT_USER
        ) as possession_key:
            descriptor = possession_key.descriptor()
            non_exportability = possession_key.assert_non_exportable()
    except PossessionKeyAdminRecoveryRequired as exc:
        raise CurrentUserPossessionRecoveryRequired(
            f"persisted possession key requires audited administrator recovery: {exc.reason}"
        ) from exc
    if descriptor.fingerprint != expected_fingerprint:
        raise CurrentUserPossessionRecoveryRequired(
            "persisted producer identity and current possession key fingerprint differ"
        )
    return {
        "status": "READY",
        "contract_version": descriptor.contract_version,
        "scope": descriptor.scope,
        "fingerprint": descriptor.fingerprint,
        "export_policy": descriptor.export_policy,
        "private_export_status": non_exportability.private_export_status_hex,
    }


def inspect_current_user_state(
    paths: CurrentUserOnboardingPaths,
    *,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
) -> dict[str, Any]:
    state_paths = {
        "identity": paths.identity_path,
        "producer_manifest": paths.producer_manifest_path,
        "credential": paths.credential_path,
        "registration_report": paths.registration_report_path,
        "logistics_profile": paths.logistics_profile_path,
        "logistics_secret": paths.logistics_secret_path,
    }
    present = {name: path.is_file() for name, path in state_paths.items()}
    if not any(present.values()):
        return {"status": "ABSENT", "present": present}
    if present["registration_report"] and sum(present.values()) == 1:
        report = _read_json(paths.registration_report_path, "registration report")
        if (
            str(report.get("status") or "") == ADMIN_RECOVERY_ACTION
            or str(report.get("recovery_action") or "") == ADMIN_RECOVERY_ACTION
        ):
            return {
                "status": "RECOVERY_REQUIRED",
                "present": present,
                "reason": str(report.get("blocked_reason") or "").strip()
                or "audited administrator recovery is required",
                "recovery_action": ADMIN_RECOVERY_ACTION,
                "enrollment_error_code": str(report.get("enrollment_error_code") or ""),
            }
        if str(report.get("status") or "") in {"BLOCKED", "FAILED", "UNKNOWN"}:
            return {"status": "ABSENT_RETRYABLE", "present": present}
    if not all(present.values()):
        return {
            "status": "RECOVERY_REQUIRED",
            "present": present,
            "reason": "current-user onboarding state is partial",
        }
    try:
        identity = _read_json(paths.identity_path, "producer identity")
        manifest = _read_json(paths.producer_manifest_path, "producer manifest")
        credential = _read_json(paths.credential_path, "producer credential")
        registration = _read_json(paths.registration_report_path, "registration report")
        profile_payload = _read_json(paths.logistics_profile_path, "logistics profile")
        required_identity = {
            field: str(identity.get(field) or "").strip()
            for field in ("producer_id", "source_host_id", "producer_install_id")
        }
        if not all(required_identity.values()):
            raise ValueError("producer identity is incomplete")
        pc_identity = manifest.get("pc_identity")
        if not isinstance(pc_identity, Mapping):
            raise ValueError("producer manifest identity is absent")
        if (
            str(pc_identity.get("source_host_id") or "")
            != required_identity["source_host_id"]
            or str(pc_identity.get("producer_install_id") or "")
            != required_identity["producer_install_id"]
        ):
            raise ValueError("producer identity and manifest binding differ")
        expected_manifest_hash = str(registration.get("manifest_hash") or "").lower()
        if (
            registration.get("server_registration_verified") is not True
            or registration.get("manifest_hash_verified") is not True
            or registration.get("persisted_manifest_hash_verified") is not True
            or registration.get("possession_key_verified") is not True
            or registration.get("enrollment_contract_version")
            != SELF_ENROLLMENT_CONTRACT_VERSION
            or len(expected_manifest_hash) != 64
            or manifest_hash(manifest) != expected_manifest_hash
        ):
            raise ValueError("server-authorized manifest readback is incomplete")
        if str(credential.get("dpapi_scope") or "") != "current_user":
            raise ValueError("producer credential is not current-user scoped")
        if str(profile_payload.get("credential_scope") or "") != "current_user":
            raise ValueError("logistics profile is not current-user scoped")
        resolved_credential = credential_loader(paths.credential_path)
        resolved_profile = profile_loader(paths.logistics_profile_path)
        possession_key = _possession_key_readback(identity)
        if resolved_credential is None or resolved_profile is None:
            raise ValueError("credential/profile readback returned no value")
        if (
            str(getattr(resolved_profile, "source_host_id", ""))
            != required_identity["source_host_id"]
        ):
            raise ValueError("logistics profile identity binding differs")
    except Exception as exc:
        result = {
            "status": "RECOVERY_REQUIRED",
            "present": present,
            "reason": str(exc),
            "error_type": exc.__class__.__name__,
        }
        if isinstance(exc, CurrentUserPossessionRecoveryRequired):
            result["recovery_action"] = ADMIN_RECOVERY_ACTION
        return result
    return {
        "status": "READY",
        "present": present,
        "source_host_id": required_identity["source_host_id"],
        "producer_install_id": required_identity["producer_install_id"],
        "manifest_hash": expected_manifest_hash,
        "possession_key": possession_key,
        "tls_private_ca_configured": bool(
            getattr(resolved_profile, "tls_ca_bundle_path", "")
        ),
    }


def _configured_tls_ca_bundle_source(
    paths: CurrentUserOnboardingPaths,
    environ: Mapping[str, str] | None = None,
) -> str:
    values = os.environ if environ is None else environ
    explicit = str(values.get(ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV) or "").strip()
    if explicit:
        return explicit
    if paths.bootstrap_tls_ca_bundle_path.is_file():
        return str(paths.bootstrap_tls_ca_bundle_path)
    return ""


def _registration_runner(
    paths: CurrentUserOnboardingPaths,
    *,
    server_base_url: str,
    environ: Mapping[str, str] | None = None,
) -> int:
    from tools import register_container_audit_worker_pc

    endpoint_url = f"{server_base_url.rstrip('/')}{DEFAULT_ENDPOINT_PATH}"
    tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
    arguments = [
        "--app-root",
        str(paths.app_root),
        "--endpoint-url",
        endpoint_url,
        "--self-enroll",
        "--require-machine-credential-bundle",
        "--credential-scope",
        "current_user",
        "--logistics-profile-path",
        str(paths.logistics_profile_path),
        "--manifest-path",
        str(paths.producer_manifest_path),
        "--credential-path",
        str(paths.credential_path),
        "--report-path",
        str(paths.registration_report_path),
    ]
    if tls_ca_source:
        arguments.extend(["--tls-ca-bundle-path", tls_ca_source])
    return int(register_container_audit_worker_pc.main(arguments))


def _create_ledger(path: Path) -> None:
    from transfer_seal import TransferSealStore

    TransferSealStore(path)


def apply_current_user_runtime_environment(
    paths: CurrentUserOnboardingPaths,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    values = os.environ if environ is None else environ
    values[PROFILE_PATH_ENV] = str(paths.logistics_profile_path)
    values[REQUIRED_ENV] = "1"
    values[LOGISTICS_PROFILE_PATH_ENV] = str(paths.logistics_profile_path)


def onboard_current_user(
    app_root: str | os.PathLike[str],
    *,
    environ: MutableMapping[str, str] | None = None,
    server_base_url: str = DEFAULT_SERVER_BASE_URL,
    require_bootstrap_integrity: bool | None = None,
    registration_runner: Callable[[CurrentUserOnboardingPaths], Any] | None = None,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
    ledger_factory: Callable[[Path], None] = _create_ledger,
    autostart_installer: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = install_user_relay_autostart,
    relay_launcher: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = start_user_relay_process,
) -> dict[str, Any]:
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    tls_ca_source = _configured_tls_ca_bundle_source(paths, environ)
    for directory in (
        paths.data_root,
        paths.events_dir,
        paths.direct_sync_root,
        paths.queue_dir,
        paths.spool_dir,
        paths.status_dir,
        paths.logs_dir,
        paths.logistics_profile_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    require_integrity = (
        bool(getattr(sys, "frozen", False))
        if require_bootstrap_integrity is None
        else bool(require_bootstrap_integrity)
    )
    report: dict[str, Any] = {
        "report_version": ONBOARDING_REPORT_VERSION,
        "status": "UNKNOWN",
        "action": "UNKNOWN",
        "captured_at": _now(),
        "state_scope": "current_user",
        "elevation_required": False,
        "data_root": str(paths.data_root),
        "direct_sync_root": str(paths.direct_sync_root),
        "logistics_profile_path": str(paths.logistics_profile_path),
        "ledger_path": str(paths.ledger_path),
        "tls_ca_bundle_source_configured": bool(tls_ca_source),
        "server_registration_verified": False,
        "failure": "",
    }
    try:
        bootstrap_integrity_detail = verify_bootstrap_integrity(
            paths,
            required=require_integrity,
        )
        report["bootstrap_integrity"] = str(
            bootstrap_integrity_detail.get("status") or "UNKNOWN"
        ).lower()
        report["bootstrap_integrity_detail"] = bootstrap_integrity_detail
        state = inspect_current_user_state(
            paths,
            profile_loader=profile_loader,
            credential_loader=credential_loader,
        )
        report["initial_state"] = state
        if state["status"] == "READY" and tls_ca_source:
            from tools.install_logistics_runtime_profile import (
                install_tls_ca_bundle_for_existing_profile,
            )

            report["tls_ca_bundle_upgrade"] = (
                install_tls_ca_bundle_for_existing_profile(
                    profile_path=paths.logistics_profile_path,
                    tls_ca_bundle_path=tls_ca_source,
                    credential_scope="current_user",
                )
            )
            state = inspect_current_user_state(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
            )
        if state["status"] == "RECOVERY_REQUIRED":
            if state.get("recovery_action") == ADMIN_RECOVERY_ACTION:
                raise CurrentUserOnboardingError(
                    str(
                        state.get("reason")
                        or "audited administrator recovery is required"
                    ),
                    report_path=paths.onboarding_report_path,
                    status=ADMIN_RECOVERY_ACTION,
                )
            raise ValueError(str(state.get("reason") or "partial current-user state"))
        if state["status"] in {"ABSENT", "ABSENT_RETRYABLE"}:
            if registration_runner is None:
                return_code = _registration_runner(
                    paths,
                    server_base_url=server_base_url,
                    environ=environ,
                )
            else:
                return_code = registration_runner(paths)
            if type(return_code) is not int:
                raise CurrentUserOnboardingError(
                    "registration result is UNKNOWN because no exit code was returned",
                    report_path=paths.onboarding_report_path,
                    status="UNKNOWN",
                )
            if return_code != 0:
                raise ValueError(
                    f"current-user registration failed with exit code {return_code}"
                )
            state = inspect_current_user_state(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
            )
            if state["status"] != "READY":
                raise ValueError(
                    "registration returned success without complete current-user readback"
                )
            report["action"] = "CREATED"
        else:
            report["action"] = "REUSED"
        if tls_ca_source and not state.get("tls_private_ca_configured"):
            raise ValueError(
                "configured TLS CA bundle was not persisted in the logistics profile"
            )
        ledger_factory(paths.ledger_path)
        if not paths.ledger_path.is_file():
            raise ValueError("current-user business ledger readback failed")
        stop_path = user_relay_stop_path(paths.direct_sync_root)
        stop_path.unlink(missing_ok=True)
        report["relay_autostart"] = dict(autostart_installer(paths.app_root))
        autostart_status = str(report["relay_autostart"].get("status") or "")
        if autostart_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user relay autostart result is UNKNOWN",
                report_path=paths.onboarding_report_path,
                status="UNKNOWN",
            )
        if autostart_status != "PASS":
            raise ValueError("current-user relay autostart was not proven")
        report["relay_start"] = dict(relay_launcher(paths.app_root))
        relay_start_status = str(report["relay_start"].get("status") or "")
        if relay_start_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user relay launch result is UNKNOWN",
                report_path=paths.onboarding_report_path,
                status="UNKNOWN",
            )
        if relay_start_status != "START_REQUESTED":
            raise ValueError("current-user relay launch was not requested")
        apply_current_user_runtime_environment(
            paths,
            environ=environ,
        )
        report.update(
            {
                "status": "READY",
                "state_readback": state,
                "server_registration_verified": True,
                "ledger_status": "READY",
                "persistent_relay_principal": "current_user",
                "system_scheduled_task_required": False,
                "completed_at": _now(),
            }
        )
        _write_json_atomic(paths.onboarding_report_path, report)
        return report
    except CurrentUserOnboardingError as exc:
        report["status"] = exc.status
        report["failure"] = str(exc)
        report["error_type"] = exc.__class__.__name__
        _write_json_atomic(paths.onboarding_report_path, report)
        raise
    except Exception as exc:
        report["status"] = "FAILED"
        report["failure"] = str(exc)[:500]
        report["error_type"] = exc.__class__.__name__
        _write_json_atomic(paths.onboarding_report_path, report)
        raise CurrentUserOnboardingError(
            f"Container_Audit first-run onboarding failed: {exc}",
            report_path=paths.onboarding_report_path,
            status="FAILED",
        ) from exc


def remove_current_user_setup(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    autostart_remover: Callable[[], Mapping[str, Any]] = remove_user_relay_autostart,
    relay_stopper: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = request_user_relay_stop,
) -> dict[str, Any]:
    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    paths.status_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "report_version": REMOVAL_REPORT_VERSION,
        "status": "UNKNOWN",
        "captured_at": _now(),
        "state_scope": "current_user",
        "data_preserved": True,
        "preserved_paths": [
            str(paths.data_root),
            str(paths.direct_sync_root),
            str(paths.logistics_profile_path.parent),
        ],
        "machine_code_root": str(paths.app_root),
        "machine_code_removal_requires_elevation": True,
        "failure": "",
    }
    try:
        report["relay_autostart"] = dict(autostart_remover())
        report["relay_process"] = dict(relay_stopper(paths.direct_sync_root))
        autostart_status = str(report["relay_autostart"].get("status") or "")
        relay_status = str(report["relay_process"].get("status") or "")
        if autostart_status in {"", "UNKNOWN"} or relay_status in {"", "UNKNOWN"}:
            raise CurrentUserOnboardingError(
                "current-user removal result is UNKNOWN",
                report_path=paths.removal_report_path,
                status="UNKNOWN",
            )
        if autostart_status != "ABSENT":
            raise ValueError("HKCU relay persistence absence was not proven")
        if relay_status != "ABSENT":
            raise ValueError("current-user relay process absence is UNKNOWN")
        report.update({"status": "PASS_DATA_PRESERVED", "completed_at": _now()})
        _write_json_atomic(paths.removal_report_path, report)
        return report
    except CurrentUserOnboardingError as exc:
        report.update(
            {
                "status": exc.status,
                "failure": str(exc)[:500],
                "error_type": exc.__class__.__name__,
            }
        )
        _write_json_atomic(paths.removal_report_path, report)
        raise
    except Exception as exc:
        report.update(
            {
                "status": "FAILED",
                "failure": str(exc)[:500],
                "error_type": exc.__class__.__name__,
            }
        )
        _write_json_atomic(paths.removal_report_path, report)
        raise CurrentUserOnboardingError(
            f"Container_Audit current-user removal failed: {exc}",
            report_path=paths.removal_report_path,
        ) from exc


def restore_current_user_lifecycle_after_replacement(
    app_root: str | os.PathLike[str],
    *,
    code_root: str | os.PathLike[str],
    report_path: str | os.PathLike[str] | None = None,
    producer_code_root: str | os.PathLike[str] | None = None,
    session_id: str,
    attempt_id: str,
    session_started_at_utc: str,
    orchestrator_sha256: str,
    replacement_transaction_id: str,
    replacement_receipt_path: str | os.PathLike[str],
    replacement_receipt_sha256: str,
    writer_contract_sha256: str,
    environ: MutableMapping[str, str] | None = None,
    state_inspector: Callable[..., Mapping[str, Any]] = inspect_current_user_state,
    profile_loader: Callable[[Path], Any] = _default_profile_loader,
    credential_loader: Callable[[Path], Any] = load_credentials_from_json,
    code_identity_reader: Callable[[Path, Path], Mapping[str, Any]] | None = None,
    autostart_installer: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = _install_replacement_user_relay_autostart,
    autostart_remover: Callable[[], Mapping[str, Any]] = remove_user_relay_autostart,
    relay_launcher: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = _start_replacement_user_relay_process,
    relay_stopper: Callable[
        [str | os.PathLike[str]], Mapping[str, Any]
    ] = request_user_relay_stop,
    execution_context_inspector: Callable[[], Mapping[str, Any]] = (
        _inspect_current_process_execution_context
    ),
) -> dict[str, Any]:
    """Restore only lifecycle bindings for an exact, previously READY owner state.

    This path has no registration or network call and never constructs or opens the
    ledger database.  The ledger and all identity/credential artifacts are only
    hashed before and after the lifecycle actions to prove exact preservation.
    """

    paths = resolve_current_user_onboarding_paths(app_root, environ=environ)
    selected_code_root = _resolved(code_root)
    report_path = _resolved(
        report_path
        if report_path is not None
        else paths.status_dir / "replacement_lifecycle_restore.json"
    )
    if path_is_within(report_path, selected_code_root):
        raise CurrentUserOnboardingError(
            "replacement lifecycle report must be outside the mutable code root",
            report_path=report_path,
            status="FAILED",
        )
    owner_paths = _owner_artifact_paths(paths)
    receipt_path = _resolved(replacement_receipt_path)
    if report_path == receipt_path or report_path in {
        _resolved(path) for path in owner_paths.values()
    }:
        raise CurrentUserOnboardingError(
            "replacement lifecycle report collides with protected input or owner state",
            report_path=report_path,
            status="FAILED",
        )
    if report_path.exists():
        raise CurrentUserOnboardingError(
            "replacement lifecycle report must be absent for this attempt",
            report_path=report_path,
            status="FAILED",
        )
    report: dict[str, Any] = {
        "schema": REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION,
        "report_version": REPLACEMENT_LIFECYCLE_RESTORE_REPORT_VERSION,
        "status": "FAILED",
        "action": "NOT_RESTORED",
        "app_id": "container_audit",
        "captured_at": _now(),
        "state_scope": "current_user",
        "registration_attempted": False,
        "network_attempted": False,
        "ledger_opened": False,
        "identity_or_credential_copied": False,
        "secret_values_recorded": False,
        "session_id": session_id,
        "attempt_id": attempt_id,
        "session_started_at_utc": session_started_at_utc,
        "orchestrator_sha256": orchestrator_sha256,
        "producer_code_root": str(
            _resolved(producer_code_root)
            if producer_code_root is not None
            else Path(__file__).resolve().parent.parent
        ),
        "replacement_transaction_id": replacement_transaction_id,
        "replacement_receipt_path": str(replacement_receipt_path),
        "replacement_receipt_sha256": replacement_receipt_sha256,
        "writer_contract_sha256": writer_contract_sha256,
        "owner_artifact_count": len(owner_paths),
        "owner_artifact_paths": {
            name: str(_resolved(path)) for name, path in owner_paths.items()
        },
        "owner_state_preserved_exact": False,
        "containment_status": "NOT_REQUIRED",
        "failure_code": "AUTHORIZATION_FAILED",
        "failure": "",
    }
    owner_before: dict[str, str] | None = None
    lifecycle_mutated = False
    failure_stage = "OWNER_ARTIFACT_READBACK"
    try:
        if not paths.status_dir.is_dir():
            raise ValueError(
                "replacement lifecycle requires existing owner status state"
            )
        owner_before = _owner_artifact_fingerprints(owner_paths)
        report["owner_artifact_fingerprints_before"] = owner_before

        failure_stage = "EXECUTION_CONTEXT"
        execution_context = dict(execution_context_inspector())
        if execution_context != {
            "status": "PASS",
            "token_elevated": False,
            "integrity_level": "MEDIUM",
        }:
            raise ValueError(
                "replacement lifecycle requires a non-elevated medium-integrity token"
            )
        report["execution_context"] = execution_context

        failure_stage = "RECEIPT_BINDING"
        if not re.fullmatch(r"[0-9a-f]{32}", session_id):
            raise ValueError("replacement lifecycle session id is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", attempt_id):
            raise ValueError("replacement lifecycle attempt id is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", orchestrator_sha256):
            raise ValueError("replacement lifecycle orchestrator SHA-256 is invalid")
        try:
            session_started = datetime.fromisoformat(
                session_started_at_utc.replace("Z", "+00:00")
            )
            if session_started.tzinfo is None:
                raise ValueError("session start has no time zone")
            session_started = session_started.astimezone(timezone.utc)
        except (TypeError, ValueError) as exc:
            raise ValueError("replacement lifecycle session start is invalid") from exc
        current_time = datetime.now(timezone.utc)
        if session_started > current_time + timedelta(
            seconds=5
        ) or session_started < current_time - timedelta(hours=24):
            raise ValueError("replacement lifecycle session is not current")
        if paths.app_root != selected_code_root / "app":
            raise ValueError("replacement lifecycle code/app root binding is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", replacement_transaction_id):
            raise ValueError("replacement lifecycle transaction id is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", replacement_receipt_sha256):
            raise ValueError("replacement lifecycle receipt SHA-256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", writer_contract_sha256):
            raise ValueError("replacement lifecycle writer contract SHA-256 is invalid")
        if path_is_within(receipt_path, selected_code_root.parent):
            raise ValueError("replacement lifecycle receipt readback is invalid")
        receipt = _read_pinned_json(
            receipt_path,
            "replacement lifecycle receipt",
            expected_sha256=replacement_receipt_sha256,
            maximum_bytes=131072,
        )
        report["replacement_receipt_path"] = str(receipt_path)
        if set(receipt) != _REPLACEMENT_RECEIPT_FIELDS:
            raise ValueError("replacement lifecycle receipt shape is invalid")
        parent_acl = receipt.get("parent_acl")
        if (
            not isinstance(parent_acl, Mapping)
            or set(parent_acl) != {"owner_sid", "access_rules_protected", "sddl_sha256"}
            or not str(parent_acl.get("owner_sid") or "")
            or type(parent_acl.get("access_rules_protected")) is not bool
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(parent_acl.get("sddl_sha256") or ""),
            )
        ):
            raise ValueError("replacement lifecycle parent ACL receipt is invalid")
        for field in ("helper_sha256", "integrity_helper_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get(field) or "")):
                raise ValueError(
                    "replacement lifecycle receipt helper identity is invalid"
                )
        old_identity = _normalized_replacement_identity(
            receipt.get("old"),
            "replacement receipt old identity",
        )
        new_identity = _normalized_replacement_identity(
            receipt.get("new"),
            "replacement receipt new identity",
        )
        install_parent = _resolved(str(receipt.get("install_parent") or ""))
        rollback_root = _resolved(str(receipt.get("rollback_root") or ""))
        failed_root = _resolved(str(receipt.get("failed_root") or ""))
        selected_producer_root = _resolved(
            producer_code_root
            if producer_code_root is not None
            else Path(__file__).resolve().parent.parent
        )
        if (
            receipt.get("schema_version") != REPLACEMENT_RECEIPT_VERSION
            or receipt.get("status") != "OLD_PRESERVED_NEW_VERIFIED"
            or receipt.get("app_id") != "container_audit"
            or receipt.get("transaction_id") != replacement_transaction_id
            or receipt.get("identity_or_credential_copied") is not False
            or _resolved(str(receipt.get("receipt_path") or "")) != receipt_path
            or _resolved(str(receipt.get("install_root") or "")) != selected_code_root
            or install_parent != selected_code_root.parent
            or rollback_root.parent != install_parent
            or rollback_root.name != f".current.rollback.{replacement_transaction_id}"
            or rollback_root.exists()
            or failed_root.parent != install_parent
            or failed_root.name != f".current.failed.{replacement_transaction_id}"
            or selected_producer_root != failed_root
        ):
            raise ValueError("replacement lifecycle receipt identity is invalid")
        _assert_tree_has_no_reparse_points(failed_root, "replacement failed-new tree")
        ambiguous_siblings = [
            candidate
            for candidate in install_parent.iterdir()
            if candidate.is_dir()
            and re.fullmatch(
                r"\.current\.(?:rollback|failed)\.[0-9a-f]{32}", candidate.name
            )
            and candidate != failed_root
        ]
        if ambiguous_siblings:
            raise ValueError("replacement lifecycle transaction siblings are ambiguous")

        failure_stage = "RESTORED_CODE_READBACK"
        identity_reader = code_identity_reader or _read_replacement_tree_identity
        restored_identity = _normalized_replacement_identity(
            identity_reader(selected_code_root, selected_code_root),
            "restored replacement code identity",
        )
        failed_new_identity = _normalized_replacement_identity(
            identity_reader(failed_root, selected_code_root),
            "failed-new replacement code identity",
        )
        if restored_identity != old_identity or failed_new_identity != new_identity:
            raise ValueError(
                "replacement lifecycle trees differ from the exact receipt"
            )
        manifest_path = selected_code_root / "portable-manifest.json"
        writer_contract_path = (
            selected_code_root / "tools" / "container_writer_session_contract.json"
        )
        _require_regular_unredirected_file(
            writer_contract_path,
            "replacement writer session contract",
        )
        manifest = _read_json(manifest_path, "replacement portable manifest")
        if (
            str(manifest.get("writer_session_contract_sha256") or "")
            != writer_contract_sha256
            or _file_sha256(writer_contract_path) != writer_contract_sha256
        ):
            raise ValueError("replacement writer session contract binding differs")
        report.update(
            {
                "code_root": str(selected_code_root),
                "restored_code_identity": restored_identity,
                "failed_new_code_identity": failed_new_identity,
                "bootstrap_integrity": "PASS",
                "release_layout": "portable_runtime",
                "writer_contract_verified": True,
            }
        )

        failure_stage = "OWNER_STATE_READBACK"
        state = dict(
            state_inspector(
                paths,
                profile_loader=profile_loader,
                credential_loader=credential_loader,
            )
        )
        if state.get("status") != "READY":
            raise ValueError("replacement lifecycle restore requires exact READY state")
        possession_key = state.get("possession_key")
        report["owner_state_readback"] = {
            "status": "READY",
            "source_host_id": str(state.get("source_host_id") or ""),
            "producer_install_id": str(state.get("producer_install_id") or ""),
            "manifest_hash": str(state.get("manifest_hash") or ""),
            "possession_key_fingerprint": str(
                possession_key.get("fingerprint")
                if isinstance(possession_key, Mapping)
                else ""
            ),
        }

        failure_stage = "QUIESCENCE_RELEASE"
        stop_path = user_relay_stop_path(paths.direct_sync_root)
        _require_regular_unredirected_file(
            stop_path,
            "replacement lifecycle stop marker",
        )
        stop_path.unlink()
        lifecycle_mutated = True

        failure_stage = "RUN_RESTORE"
        autostart = dict(autostart_installer(paths.app_root))
        expected_autostart = {
            "status": "PASS",
            "principal": "current_user",
            "registry_hive": "HKEY_CURRENT_USER",
            "registry_key": USER_RELAY_RUN_KEY,
            "registry_value": USER_RELAY_RUN_VALUE,
            "command": _replacement_user_relay_command_line(paths.app_root),
        }
        if autostart != expected_autostart:
            raise ValueError(
                "replacement lifecycle HKCU relay autostart was not proven"
            )

        failure_stage = "RELAY_START"
        relay_start = dict(relay_launcher(paths.app_root))
        if (
            set(relay_start) != {"status", "process_id"}
            or str(relay_start.get("status") or "") != "START_REQUESTED"
            or type(relay_start.get("process_id")) is not int
            or int(relay_start["process_id"]) <= 0
        ):
            raise ValueError("replacement lifecycle relay launch was not requested")

        failure_stage = "OWNER_ARTIFACT_FINAL_READBACK"
        owner_after = _owner_artifact_fingerprints(owner_paths)
        report["owner_artifact_fingerprints_after"] = owner_after
        if owner_after != owner_before:
            raise ValueError("replacement lifecycle changed current-user owner state")
        report.update(
            {
                "status": "READY",
                "action": "REUSED",
                "completed_at": _now(),
                "failure_code": "",
                "failure": "",
                "owner_state_preserved_exact": True,
                "relay_autostart": autostart,
                "relay_start": relay_start,
                "persistent_relay_principal": "current_user",
                "system_scheduled_task_required": False,
            }
        )
        failure_stage = "REPORT_PERSISTENCE"
        _write_json_atomic_create_new(report_path, report)
        return report
    except Exception as exc:
        containment_status = "NOT_REQUIRED"
        if lifecycle_mutated:
            try:
                autostart_absent = dict(autostart_remover())
                relay_absent = dict(relay_stopper(paths.direct_sync_root))
                stop_path = user_relay_stop_path(paths.direct_sync_root)
                _require_regular_unredirected_file(
                    stop_path,
                    "replacement lifecycle containment stop marker",
                )
                if (
                    str(autostart_absent.get("status") or "") != "ABSENT"
                    or str(relay_absent.get("status") or "") != "ABSENT"
                ):
                    raise ValueError("replacement lifecycle containment is UNKNOWN")
                containment_status = "PASS_SAFE_QUIESCENT"
            except Exception:
                containment_status = "FAILED"
        owner_after: dict[str, str] | None = None
        if owner_before is not None:
            try:
                owner_after = _owner_artifact_fingerprints(owner_paths)
            except Exception:
                owner_after = None
        if owner_after is not None:
            report["owner_artifact_fingerprints_after"] = owner_after
        report.update(
            {
                "status": "FAILED",
                "action": "NOT_RESTORED",
                "failed_at": _now(),
                "failure_code": f"{failure_stage}_FAILED",
                "failure": "replacement lifecycle restore failed",
                "error_type": exc.__class__.__name__,
                "owner_state_preserved_exact": (
                    owner_before is not None and owner_after == owner_before
                ),
                "containment_status": containment_status,
            }
        )
        try:
            _write_json_atomic_create_new(report_path, report)
        except Exception as persistence_exc:
            raise CurrentUserOnboardingError(
                "Container_Audit replacement lifecycle failure evidence could not be persisted",
                report_path=report_path,
                status="FAILED",
            ) from persistence_exc
        raise CurrentUserOnboardingError(
            "Container_Audit replacement lifecycle restore failed",
            report_path=report_path,
            status="FAILED",
        ) from exc


def _default_app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def replacement_lifecycle_restore_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Restore an exact READY Container_Audit current-user lifecycle after "
            "verified replacement rollback."
        )
    )
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--code-root", required=True)
    parser.add_argument("--replacement-transaction-id", required=True)
    parser.add_argument("--replacement-receipt-path", required=True)
    parser.add_argument("--replacement-receipt-sha256", required=True)
    parser.add_argument("--writer-contract-sha256", required=True)
    parser.add_argument("--report-path")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--session-started-at-utc", required=True)
    parser.add_argument("--orchestrator-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = restore_current_user_lifecycle_after_replacement(
            args.app_root,
            code_root=args.code_root,
            report_path=args.report_path,
            session_id=args.session_id,
            attempt_id=args.attempt_id,
            session_started_at_utc=args.session_started_at_utc,
            orchestrator_sha256=args.orchestrator_sha256,
            replacement_transaction_id=args.replacement_transaction_id,
            replacement_receipt_path=args.replacement_receipt_path,
            replacement_receipt_sha256=args.replacement_receipt_sha256,
            writer_contract_sha256=args.writer_contract_sha256,
        )
    except CurrentUserOnboardingError as exc:
        print(f"replacement_lifecycle_restore_status={exc.status}")
        print(f"replacement_lifecycle_restore_report={exc.report_path}")
        return ONBOARDING_EXIT_CODE
    except Exception:
        fallback_report = (
            _resolved(args.report_path)
            if args.report_path
            else resolve_current_user_onboarding_paths(args.app_root).status_dir
            / "replacement_lifecycle_restore.json"
        )
        print("replacement_lifecycle_restore_status=FAILED")
        print(f"replacement_lifecycle_restore_report={fallback_report}")
        return ONBOARDING_EXIT_CODE
    print(f"replacement_lifecycle_restore_status={report['status']}")
    print(f"replacement_lifecycle_restore_action={report['action']}")
    print(
        "replacement_lifecycle_restore_report="
        f"{_resolved(args.report_path) if args.report_path else resolve_current_user_onboarding_paths(args.app_root).status_dir / 'replacement_lifecycle_restore.json'}"
    )
    return 0


def onboarding_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Onboard Container_Audit for the current user"
    )
    parser.add_argument("--app-root", default=str(_default_app_root()))
    parser.add_argument("--server-base-url", default=DEFAULT_SERVER_BASE_URL)
    args = parser.parse_args(argv)
    try:
        report = onboard_current_user(
            args.app_root,
            server_base_url=args.server_base_url,
            require_bootstrap_integrity=bool(getattr(sys, "frozen", False)),
        )
    except CurrentUserOnboardingError as exc:
        print(f"onboarding_status={exc.status}")
        print(f"onboarding_report={exc.report_path}")
        return ONBOARDING_EXIT_CODE
    print(f"onboarding_status={report['status']}")
    print(f"onboarding_action={report['action']}")
    print(f"bootstrap_integrity={report['bootstrap_integrity']}")
    print(
        f"onboarding_report={resolve_current_user_onboarding_paths(args.app_root).onboarding_report_path}"
    )
    return 0


def removal_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove Container_Audit current-user setup"
    )
    parser.add_argument("--app-root", default=str(_default_app_root()))
    args = parser.parse_args(argv)
    try:
        report = remove_current_user_setup(args.app_root)
    except CurrentUserOnboardingError as exc:
        print("current_user_removal_status=FAILED")
        print(f"current_user_removal_report={exc.report_path}")
        return ONBOARDING_EXIT_CODE
    paths = resolve_current_user_onboarding_paths(args.app_root)
    print(f"current_user_removal_status={report['status']}")
    print("data_preserved=true")
    print(f"current_user_removal_report={paths.removal_report_path}")
    print("machine_code_removal_command=INSTALL_THIS_PC.ps1 -Uninstall")
    return 0
