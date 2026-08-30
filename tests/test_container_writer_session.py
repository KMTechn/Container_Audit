import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tools" / "container_writer_session.ps1"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell 5.1 is required")
    return executable


def test_writer_session_negative_injections_are_fail_closed_and_nonmutating():
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ADAPTER),
            "-Mode",
            "SelfTest",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["schema"] == "container-audit-writer-session-self-test-v1"
    assert result["status"] == "PASS"
    assert result["system_mutation_attempted"] is False
    assert result["secret_values_recorded"] is False
    assert {item["name"]: item["status"] for item in result["checks"]} == {
        "valid_current_session_prepared_receipt": "PASS",
        "stale_session_rejected": "PASS",
        "historical_binding_mismatch_rejected": "PASS",
        "expired_session_rejected": "PASS",
        "invalid_replacement_receipt_rejected": "PASS",
        "code_restore_failure_explicit_and_writer_not_run": "PASS",
        "writer_restore_failure_explicit": "PASS",
    }


def test_writer_session_adapter_exposes_only_natural_trigger_restore():
    source = ADAPTER.read_text(encoding="utf-8")

    assert "Start-ScheduledTask" not in source
    assert "Enable-ScheduledTask" in source
    assert "Disable-ScheduledTask" in source
    assert "natural trigger survival was not observed" in source
    assert "CODE_RESTORE_FAILED" in source
    assert "WRITER_RESTORE_FAILED" in source
    assert "PREPARED_RECEIPT_OR_LIVE_DISABLED_INVALID" in source


def test_writer_session_adapter_is_pinned_by_portable_manifest_contract():
    builder = (ROOT / "tools" / "build_portable_release_candidate.py").read_text(
        encoding="utf-8"
    )
    installer = (ROOT / "INSTALL_THIS_PC.ps1").read_text(encoding="utf-8")
    canonical_installer = (ROOT / "INSTALL_CANONICAL_PORTABLE.ps1").read_text(
        encoding="utf-8"
    )

    assert '"tools/container_writer_session.ps1"' in builder
    assert '"writer_session_adapter_sha256"' in builder
    assert "tools\\container_writer_session.ps1" in installer
    assert "writer_session_adapter_sha256" in installer
    assert "tools\\container_writer_session.ps1" in canonical_installer
    assert "writer_session_adapter_sha256" in canonical_installer
