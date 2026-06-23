import subprocess
import sys
from pathlib import Path

from tools import check_release_version


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_RELEASE_VERSION_SCRIPT = REPO_ROOT / "tools" / "check_release_version.py"


def test_release_version_reader_extracts_current_version(tmp_path):
    source = tmp_path / "Container_Audit.py"
    source.write_text('CURRENT_VERSION = "v9.8.7"\n', encoding="utf-8")

    assert check_release_version.read_current_version(source) == "v9.8.7"


def test_release_version_script_passes_matching_tag(tmp_path):
    source = tmp_path / "Container_Audit.py"
    source.write_text('CURRENT_VERSION = "v9.8.7"\n', encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(CHECK_RELEASE_VERSION_SCRIPT),
            "--tag",
            "v9.8.7",
            "--source-path",
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 0
    assert "release_version_check=PASS" in completed.stdout


def test_release_version_script_fails_mismatched_tag(tmp_path):
    source = tmp_path / "Container_Audit.py"
    source.write_text('CURRENT_VERSION = "v9.8.7"\n', encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(CHECK_RELEASE_VERSION_SCRIPT),
            "--tag",
            "v9.8.8",
            "--source-path",
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 1
    assert "tag=v9.8.8 current_version=v9.8.7" in completed.stderr


def test_release_version_script_rejects_malformed_tag(tmp_path):
    source = tmp_path / "Container_Audit.py"
    source.write_text('CURRENT_VERSION = "v9.8.7"\n', encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(CHECK_RELEASE_VERSION_SCRIPT),
            "--tag",
            "v9.8.7-hotfix",
            "--source-path",
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    assert "release tag must be" in completed.stderr


def test_release_version_script_rejects_malformed_current_version(tmp_path):
    source = tmp_path / "Container_Audit.py"
    source.write_text('CURRENT_VERSION = "current"\n', encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(CHECK_RELEASE_VERSION_SCRIPT),
            "--tag",
            "v9.8.7",
            "--source-path",
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert completed.returncode == 2
    assert "CURRENT_VERSION must be" in completed.stderr
