import subprocess
import sys
import zipfile
from pathlib import Path

import update_service


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "check_update_archive.py"


def _write_required_update_archive(path):
    with zipfile.ZipFile(path, "w") as zip_ref:
        for name in sorted(update_service.REQUIRED_UPDATE_ARCHIVE_FILES):
            zip_ref.writestr(name, name.encode("utf-8"))


def test_check_update_archive_rejects_non_empty_destination_without_deleting_sentinel(tmp_path):
    zip_path = tmp_path / "update.zip"
    _write_required_update_archive(zip_path)
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert "destination must be an empty directory or absent" in completed.stderr


def test_check_update_archive_extracts_to_absent_destination(tmp_path):
    zip_path = tmp_path / "update.zip"
    _write_required_update_archive(zip_path)
    destination = tmp_path / "smoke"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--zip-path", str(zip_path), "--destination", str(destination)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert (destination / "Container_Audit" / "Container_Audit.exe").is_file()
    assert "update_archive_smoke_dir=" in completed.stdout
