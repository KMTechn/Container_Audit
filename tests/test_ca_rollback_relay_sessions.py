"""Actual canonical outer catch must preserve every unadmitted relay/marker."""
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from tests.native_process_fixtures import native_python_environment, native_python_executable
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell", "pwsh"))
@pytest.mark.parametrize("kind", ("allowed", "refusal"))
@pytest.mark.parametrize("case", (
    "same-session", "other-session", "other-sid", "pid-reused", "other-pid",
    "no-candidate", "other-round",
))
def test_actual_outer_catch_only_stops_this_round_same_session_candidate(tmp_path, engine, kind, case):
    output = tmp_path / "result.json"
    env = os.environ.copy()
    env.update(TEMP=str(tmp_path), TMP=str(tmp_path), PYTHONDONTWRITEBYTECODE="1")
    env["PSModulePath"] = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/Modules")
    result = run_powershell([
        shutil.which(engine), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        str(ROOT / f"tests/canonical_rollback_actual_g_{kind}.ps1"),
        str(ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"), str(output), sys.executable,
        str(ROOT / "tests/canonical_rollback_generation_child.py"), str(tmp_path / "sandbox"),
        "relay-" + case,
    ], env=env, capture_output=True, text=True)
    assert result.returncode == 0
    data = json.loads(output.read_text(encoding="utf-8-sig"))
    proof = data["relay_candidate"]
    assert data["actual_g_calls"] > 0
    if case == "same-session":
        assert proof["stop_calls"] > 0
        assert proof["guard_refused"] is False
        if kind == "allowed":
            assert data["recovery_verified"] is True
            assert data["fence_active_after"] is False
            assert data["observed"]["relay_start"] > 0
    else:
        assert proof["stop_calls"] == 0
        assert proof["marker_removal_calls"] == 0
        assert proof["marker_unchanged"] is True
        assert proof["candidate_alive"] is True
        assert proof["pid_birth_unchanged"] is True
        assert proof["guard_refused"] is True
        assert data["observed"]["relay_start"] == 0
        assert data["fence_active_after"] is True
        assert data["recovery_verified"] is False
