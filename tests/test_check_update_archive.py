import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import update_service
from tools import check_update_archive


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "check_update_archive.py"


def _public_archive_record(completed, *, status, failure=False):
    # Five-source/public-location decision: diagnostic text and caller paths
    # disappear; archive validation and all refusal/preservation checks remain.
    text = completed.stderr if failure or status == 'BLOCKED' else completed.stdout
    lines = text.splitlines()
    assert len(lines) == 1 and lines[0].startswith('CONTAINER_AUDIT_SUPPORT=')
    report = json.loads(lines[0].split('=', 1)[1])
    assert report['status'] == status
    assert report['stage'] == 'update_archive_check'
    assert report['reason_code'] == ('SUPPORT_FAILURE' if failure else 'SUPPORT_RESULT')
    assert report['report_status'] == 'REPORT_UNAVAILABLE'
    assert report['guidance'] == '설정 파일과 설치 경로를 확인하고 다시 실행하세요.'
    assert not any(isinstance(value, (dict, list)) for value in report.values())
    assert 'message' not in report and 'update_archive_smoke_dir' not in report
    if failure:
        assert report['exception_type'] == 'builtins.ValueError'
    return report


def _write_required_update_archive(path):
    package_root = path.parent / "Container_Audit"
    with zipfile.ZipFile(path, "w") as zip_ref:
        for name in sorted(update_service.REQUIRED_UPDATE_ARCHIVE_FILES):
            payload = name.encode("utf-8")
            relative = Path(*Path(name).parts[1:])
            staged = package_root / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(payload)
            zip_ref.writestr(name, payload)
    return package_root


def test_check_update_archive_rejects_non_empty_destination_without_deleting_sentinel(tmp_path):
    zip_path = tmp_path / "update.zip"
    package_root = _write_required_update_archive(zip_path)
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 2
    assert sentinel.read_text(encoding="utf-8") == "keep"
    _public_archive_record(completed, status='BLOCKED')


def test_check_update_archive_extracts_to_absent_destination(tmp_path):
    zip_path = tmp_path / "update.zip"
    package_root = _write_required_update_archive(zip_path)
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 0
    assert (destination / "Container_Audit" / "Container_Audit.exe").is_file()
    _public_archive_record(completed, status='PASS')
    parity = check_update_archive.compare_staged_and_extracted(package_root, destination / package_root.name)
    assert parity['exact_membership'] is True and parity['byte_parity'] is True
    for name in update_service.REQUIRED_UPDATE_ARCHIVE_FILES:
        relative = Path(*Path(name).parts[1:])
        assert (package_root / relative).read_bytes() == (destination / package_root.name / relative).read_bytes()


def test_check_update_archive_rejects_runtime_local_state_member(tmp_path):
    zip_path = tmp_path / "runtime-local.zip"
    package_root = _write_required_update_archive(zip_path)
    with zipfile.ZipFile(zip_path, "a") as zip_ref:
        zip_ref.writestr("Container_Audit/relay_spool/queued.csv", b"queued")
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode != 0
    assert not (destination / "Container_Audit" / "relay_spool" / "queued.csv").exists()
    _public_archive_record(completed, status='FAILED', failure=True)
    with pytest.raises(ValueError, match='현장 런타임/민감 상태 파일|runtime-local path segment is not allowed'):
        update_service.safe_extract_update_zip(zip_path, tmp_path / 'second-smoke')


def test_check_update_archive_rejects_extra_safe_member_not_in_staging(tmp_path):
    zip_path = tmp_path / "extra.zip"
    package_root = _write_required_update_archive(zip_path)
    with zipfile.ZipFile(zip_path, "a") as zip_ref:
        zip_ref.writestr("Container_Audit/extra-safe.txt", b"extra")
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 1
    _public_archive_record(completed, status='FAILED', failure=True)
    with pytest.raises(ValueError, match='archive membership differs from staged package'):
        check_update_archive.compare_staged_and_extracted(package_root, destination / package_root.name)


def test_check_update_archive_rejects_extra_empty_directory_not_in_staging(tmp_path):
    zip_path = tmp_path / "extra-empty-dir.zip"
    package_root = _write_required_update_archive(zip_path)
    with zipfile.ZipFile(zip_path, "a") as zip_ref:
        zip_ref.writestr("Container_Audit/empty-safe/", b"")
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 1
    _public_archive_record(completed, status='FAILED', failure=True)
    with pytest.raises(ValueError, match='archive membership differs from staged package'):
        check_update_archive.compare_staged_and_extracted(package_root, destination / package_root.name)


def test_check_update_archive_rejects_staging_to_archive_byte_drift(tmp_path):
    zip_path = tmp_path / "drift.zip"
    package_root = _write_required_update_archive(zip_path)
    executable = package_root / "Container_Audit.exe"
    original = executable.read_bytes()
    executable.write_bytes(bytes(byte ^ 0xFF for byte in original))
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination), "--package-root", str(package_root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 1
    _public_archive_record(completed, status='FAILED', failure=True)
    with pytest.raises(ValueError, match='archive byte parity failed'):
        check_update_archive.compare_staged_and_extracted(package_root, destination / package_root.name)


def test_is_link_rejects_windows_reparse_points_on_python_311(monkeypatch, tmp_path):
    class ReparseMetadata:
        st_mode = stat.S_IFDIR
        st_file_attributes = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    candidate = tmp_path / "junction-like"
    candidate.mkdir()
    monkeypatch.setattr(check_update_archive.os, "lstat", lambda _path: ReparseMetadata())

    assert check_update_archive._is_link(candidate) is True


def test_check_update_archive_missing_staging_root_is_a_contract_failure(tmp_path):
    zip_path = tmp_path / "update.zip"
    _write_required_update_archive(zip_path)
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--zip-path",
            str(zip_path),
            "--destination",
            str(destination),
            "--package-root",
            str(tmp_path / "missing-package"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    creationflags=0x08000000)

    assert completed.returncode == 1
    _public_archive_record(completed, status='FAILED', failure=True)
    with pytest.raises(ValueError, match='staged package root is unavailable or linked'):
        check_update_archive.compare_staged_and_extracted(tmp_path / 'missing-package', destination / 'missing-package')
