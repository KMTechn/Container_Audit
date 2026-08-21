import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import update_service
from kmtech_factory_contracts.active_work_probe.cli import ALL_APPS
from kmtech_factory_contracts.active_work_probe.core import BUILD_IDENTITY_SCHEMA_VERSION
from kmtech_factory_contracts.build_cli import prepare_identity
from kmtech_factory_contracts.canonical import file_sha256
from kmtech_factory_contracts.package import create_build_manifest, write_json
from tools.verify_frozen_release_artifact import (
    REQUIRED_MANIFEST_EXPECTED_FILES,
    read_checksum,
    verify_frozen_release,
)


ROOT = Path(__file__).resolve().parents[1]
TAG = "v2.0.76"
CONTRACT_SHA256 = "adaa08684ebb291837327f63f967a4f22650dff72c4c1dc56ce1a9bee6b5404a"


def _git(repo, *args):
    completed = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip().lower()


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )


def _frozen_candidate(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    shutil.copyfile(ROOT / "contract.lock.json", source / "contract.lock.json")
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Release Test")
    _git(source, "add", "contract.lock.json")
    _git(source, "commit", "-q", "-m", "fixture")
    _git(source, "tag", "-a", TAG, "-m", TAG)
    _git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    commit = _git(source, "rev-parse", "HEAD^{commit}")
    tree = _git(source, "rev-parse", "HEAD^{tree}")

    package = tmp_path / "stage" / "Container_Audit"
    prepare_identity(
        repository=source,
        stage_root=package,
        app_id="container_audit",
        app_version=TAG,
        db_schema_current=0,
        development=False,
    )
    for archive_name in update_service.REQUIRED_UPDATE_ARCHIVE_FILES:
        relative = Path(*Path(archive_name).parts[1:])
        target = package / relative
        if not target.exists() and target.name != "build-manifest.json":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(f"fixture:{relative.as_posix()}".encode("utf-8"))

    settings = {
        "scale_factor": 1.0,
        "enable_internal_test_commands": False,
        "update_settings": {"provider": "github", "channel": "stable"},
    }
    _write_json(package / "config" / "container_audit_settings.json", settings)
    probe = package / "KMTechActiveWorkProbe.exe"
    probe_hash = file_sha256(probe)
    common_probe = {
        "schema_version": BUILD_IDENTITY_SCHEMA_VERSION,
        "probe_name": "KMTechActiveWorkProbe",
        "probe_version": "v1.0.3.4",
        "probe_artifact_sha256": probe_hash,
        "probe_source_commit": commit,
    }
    _write_json(
        package / "KMTechActiveWorkProbe.independent.build-identity.json",
        {**common_probe, "workflow_mode": "independent", "supported_apps": ["Container_Audit"]},
    )
    _write_json(
        package / "KMTechActiveWorkProbe.integrated.build-identity.json",
        {**common_probe, "workflow_mode": "integrated", "supported_apps": list(ALL_APPS)},
    )
    manifest = create_build_manifest(
        package,
        expected_files=REQUIRED_MANIFEST_EXPECTED_FILES,
        built_at_utc="2026-08-12T00:00:00Z",
    )
    write_json(package / "build-manifest.json", manifest)

    qualified_root = tmp_path / "qualified"
    qualified_root.mkdir()
    qualified_zip = qualified_root / f"Container_Audit-{TAG}.zip"
    with zipfile.ZipFile(qualified_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                archive.write(path, f"Container_Audit/{path.relative_to(package).as_posix()}")
    download_root = tmp_path / "downloaded"
    download_root.mkdir()
    zip_path = download_root / qualified_zip.name
    shutil.copyfile(qualified_zip, zip_path)
    checksum = tmp_path / f"{zip_path.name}.sha256"
    checksum.write_text(f"{file_sha256(zip_path)}  {zip_path.name}\n", encoding="ascii")
    tag_object = _git(source, "rev-parse", f"refs/tags/{TAG}")
    main_exe_hash = file_sha256(package / "Container_Audit.exe")
    receipt = qualified_root / "local-artifact-qualification-receipt.json"
    _write_json(
        receipt,
        {
            "schema_version": "container-audit-local-artifact-qualification-v1",
            "status": "LOCAL_ARTIFACT_QUALIFICATION_PASS",
            "tag": TAG,
            "tag_object_sha": tag_object,
            "source_commit": commit,
            "source_tree": tree,
            "local_mirror_main": commit,
            "clone_origin_main": commit,
            "factory_contract_sha256": CONTRACT_SHA256,
            "zip_name": qualified_zip.name,
            "zip_sha256": file_sha256(qualified_zip),
            "zip_size": qualified_zip.stat().st_size,
            "main_exe_sha256": main_exe_hash,
            "probe_sha256": probe_hash,
        },
    )
    return (
        zip_path,
        checksum,
        commit,
        tree,
        tag_object,
        main_exe_hash,
        qualified_zip,
        receipt,
    )


def test_frozen_release_verifier_accepts_exact_sealed_candidate(tmp_path):
    (
        zip_path,
        checksum,
        commit,
        tree,
        tag_object,
        main_exe_hash,
        _qualified_zip,
        _receipt,
    ) = _frozen_candidate(tmp_path)

    report = verify_frozen_release(
        zip_path,
        checksum,
        expected_tag=TAG,
        expected_tag_object=tag_object,
        expected_commit=commit,
        expected_tree=tree,
        expected_contract_sha256=CONTRACT_SHA256,
        expected_zip_sha256=file_sha256(zip_path),
        expected_zip_size=zip_path.stat().st_size,
        expected_main_exe_sha256=main_exe_hash,
    )

    assert report["status"] == "PASS_SELF_CONSISTENCY"
    assert report["archive"]["sha256"] == file_sha256(zip_path)
    assert report["archive"]["exact_manifest_membership"] is True
    assert report["package"]["app_version"] == TAG
    assert report["tag_object_sha"] == tag_object
    assert report["source_commit"] == commit
    assert report["release_body_evidence"]["main_exe_sha256"] == main_exe_hash
    assert report["governing_local_byte_parity"]["status"] == "NOT_TESTED"
    assert report["active_work_probe"]["identities"]["independent"]["supported_apps"] == [
        "Container_Audit"
    ]


def test_checksum_parser_requires_exact_single_filename(tmp_path):
    checksum = tmp_path / "candidate.sha256"
    checksum.write_text(f"{'a' * 64}  wrong.zip\n", encoding="ascii")

    with pytest.raises(ValueError, match="exact release ZIP"):
        read_checksum(checksum, expected_filename="right.zip")


def test_frozen_release_verifier_proves_governing_preserved_local_byte_parity(tmp_path):
    (
        zip_path,
        checksum,
        commit,
        tree,
        tag_object,
        main_exe_hash,
        qualified_zip,
        receipt,
    ) = _frozen_candidate(tmp_path)

    report = verify_frozen_release(
        zip_path,
        checksum,
        expected_tag=TAG,
        expected_tag_object=tag_object,
        expected_commit=commit,
        expected_tree=tree,
        expected_contract_sha256=CONTRACT_SHA256,
        expected_zip_sha256=file_sha256(zip_path),
        expected_zip_size=zip_path.stat().st_size,
        expected_main_exe_sha256=main_exe_hash,
        qualified_local_zip_path=qualified_zip,
        local_qualification_receipt=receipt,
    )

    assert report["status"] == "PASS"
    assert report["governing_local_byte_parity"]["status"] == "PASS"
    assert report["governing_local_byte_parity"]["comparison"] == "streamed-byte-for-byte"


def test_frozen_release_verifier_rejects_tag_commit_mismatch(tmp_path):
    (
        zip_path,
        checksum,
        _commit,
        tree,
        tag_object,
        main_exe_hash,
        _qualified_zip,
        _receipt,
    ) = _frozen_candidate(tmp_path)

    with pytest.raises(Exception, match="source commit differs"):
        verify_frozen_release(
            zip_path,
            checksum,
            expected_tag=TAG,
            expected_tag_object=tag_object,
            expected_commit="1" * 40,
            expected_tree=tree,
            expected_contract_sha256=CONTRACT_SHA256,
            expected_zip_sha256=file_sha256(zip_path),
            expected_zip_size=zip_path.stat().st_size,
            expected_main_exe_sha256=main_exe_hash,
        )


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"expected_zip_sha256": "2" * 64}, "ZIP hash differs"),
        ({"expected_zip_size": 1}, "ZIP size differs"),
        ({"expected_main_exe_sha256": "3" * 64}, "main EXE hash differs"),
    ],
)
def test_frozen_release_verifier_rejects_candidate_outside_qualification_anchor(
    tmp_path, overrides, error
):
    (
        zip_path,
        checksum,
        commit,
        tree,
        tag_object,
        main_exe_hash,
        _qualified_zip,
        _receipt,
    ) = _frozen_candidate(tmp_path)
    arguments = {
        "expected_tag": TAG,
        "expected_tag_object": tag_object,
        "expected_commit": commit,
        "expected_tree": tree,
        "expected_contract_sha256": CONTRACT_SHA256,
        "expected_zip_sha256": file_sha256(zip_path),
        "expected_zip_size": zip_path.stat().st_size,
        "expected_main_exe_sha256": main_exe_hash,
    }
    arguments.update(overrides)

    with pytest.raises(ValueError, match=error):
        verify_frozen_release(zip_path, checksum, **arguments)


def test_frozen_release_verifier_rejects_changed_preserved_local_bytes(tmp_path):
    (
        zip_path,
        checksum,
        commit,
        tree,
        tag_object,
        main_exe_hash,
        qualified_zip,
        receipt,
    ) = _frozen_candidate(tmp_path)
    with qualified_zip.open("ab") as stream:
        stream.write(b"changed")

    with pytest.raises(ValueError, match="preserved local ZIP differs"):
        verify_frozen_release(
            zip_path,
            checksum,
            expected_tag=TAG,
            expected_tag_object=tag_object,
            expected_commit=commit,
            expected_tree=tree,
            expected_contract_sha256=CONTRACT_SHA256,
            expected_zip_sha256=file_sha256(zip_path),
            expected_zip_size=zip_path.stat().st_size,
            expected_main_exe_sha256=main_exe_hash,
            qualified_local_zip_path=qualified_zip,
            local_qualification_receipt=receipt,
        )
