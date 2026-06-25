import re
from pathlib import Path

import update_service


def _release_workflow_required_assets(text):
    match = re.search(r"\$required = @\((?P<body>.*?)\)\s+foreach", text, flags=re.DOTALL)
    assert match is not None
    return frozenset(re.findall(r'"([^"]+)"', match.group("body")))


def test_ci_and_release_workflows_package_clean_release_config():
    root = Path(__file__).resolve().parents[1]
    for workflow_name in ("ci.yml", "release.yml"):
        text = (root / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        assert "python tools/check_release_config.py --config-dir build/release_config" in text
        assert '--add-data "build/release_config;config"' in text
        assert "build/release_tools" in text
        assert '--add-data "build/release_tools;tools"' in text
        assert '--add-data "config;config"' not in text
        assert '--add-data "tools;tools"' not in text
        assert "python -m pip install -r requirements.txt" in text
        assert "python -m pip install -r requirements-dev.txt" in text
        assert "python -m pip install pyinstaller" not in text
        assert "python -m pytest -q -p no:cacheprovider" in text
        assert "python -m PyInstaller" in text
        assert "Container_Audit_DirectSync_Install" in text
        assert "Container_Audit_DirectSync_Relay" in text
        assert "Container_Audit_Worker_PC_Register" in text
        assert "tools/register_container_audit_worker_pc.py" in text
        assert '--add-data "storage_policy.py;."' in text
        assert '--add-data "storage_utils.py;."' in text
        assert 'python tools/check_update_archive.py --zip-path "$zipPath" --destination "$smokeDir"' in text
        assert 'python tools/check_release_config.py --config-dir "$releaseConfigDir"' in text
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert _release_workflow_required_assets(release_text) == update_service.REQUIRED_UPDATE_ARCHIVE_FILES
    assert "Expand-Archive" not in release_text


def test_ci_workflow_tests_supported_python_minors():
    root = Path(__file__).resolve().parents[1]
    ci_text = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^permissions:\n\s+contents: read$", ci_text)
    assert "matrix:" in ci_text
    assert "python-version: ['3.11', '3.12']" in ci_text
    assert "python-version: ${{ matrix.python-version }}" in ci_text


def test_release_workflow_pins_actions_running_with_release_write_permission():
    root = Path(__file__).resolve().parents[1]
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    uses_values = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", release_text)

    assert uses_values
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in uses_values)
    assert "softprops/action-gh-release@v2" not in release_text


def test_dev_toolchain_is_pinned_in_requirements_dev():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements-dev.txt").read_text(encoding="utf-8")

    assert "pytest==9.0.2" in requirements
    assert "pyinstaller==6.20.0" in requirements
