"""Reproduce the two approved general G104 boundaries and their entry gates."""
import json
from pathlib import Path
import re

import pytest

import auto_update
import writer_session_fence as fence
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"
FUNCTIONS = re.findall(r"^function ([\w-]+)", INSTALLER.read_text(encoding="utf-8-sig"), re.M)
DRIVER = (ROOT / "tests/ca_general_completed_release_fixture.ps1").read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("boundary", ("A_AFTER_SET", "B_RESTORING_BEFORE_SET", "B_RESTORING_AFTER_SET", "B_INSTALLING_AFTER_SET"))
def test_completed_general_boundary_has_an_official_fence_only_exit(tmp_path, monkeypatch, engine, boundary):
    values = {"CA_GENERAL_BOUNDARY": boundary, "CA_GENERAL_STAGE": "setup"}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 73, "producer boundary failed; raw diagnostics suppressed"
    values["CA_GENERAL_STAGE"] = "observe"
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 0, "reader probe failed; raw diagnostics suppressed"
    path = tmp_path / "general-observed.json"
    observed = json.loads(path.read_text(encoding="utf-8-sig"))
    assert observed["indented_audit"] and observed["continuation_refused"]
    assert observed["fence_preserved"] and observed["audit_preserved"]
    assert all(observed["refusals"].values())
    if boundary.startswith("A_"):
        assert observed["restore_state"] == "RESTORED"
    control = Path(observed["control_root"])
    environment = {"LOCALAPPDATA": observed["local_appdata"]}
    with pytest.raises(fence.WriterFencedError) as error:
        with fence._writer_admission("ledger_storage", control_root=control, environ=environment):
            pytest.fail("scan-save writer crossed a stranded fence")
    assert error.value.code == "ACTIVE_WRITER_FENCE"
    active = fence.active_fence(control, environ=environment)
    scope = fence._FailedInstallerRemoval(tmp_path / "current", tmp_path / "relay")
    try:
        assert not scope.admits("current_user_setup_removal", control, active)
    finally:
        scope.release()
    observed["refusals"]["scan_save"] = error.value.code
    observed["refusals"]["worker_setup_removal"] = True
    path.write_text(json.dumps(observed, indent=2), encoding="utf-8")
    # The approved dedicated entry is the only new exit. Other modes keep their meanings.
    values["CA_GENERAL_STAGE"] = "recover"
    for attempt in range(2):
        result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
        assert result.returncode == 0, "dedicated recovery probe failed; raw diagnostics suppressed"
        recovery = json.loads((tmp_path / "general-recovery-result.json").read_text(encoding="utf-8-sig"))
        assert recovery["code"] == ""
        assert recovery["result"]["status"] == "FENCE_RELEASED_FOLLOWUP_PENDING"
        assert recovery["result"]["original_audit_status"] == observed["status"]
        assert recovery["audit_preserved"] and not recovery["fence_present"]
    assert not (control / "active.json").exists(), "GENERAL_COMPLETED_RELEASE_HAS_NO_OFFICIAL_EXIT"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("boundary", ("A_BEFORE_SET", "B_INSTALLING_BEFORE_SET"))
def test_general_before_set_retains_the_g59_exit(tmp_path, monkeypatch, engine, boundary):
    values = {"CA_GENERAL_BOUNDARY": boundary, "CA_GENERAL_STAGE": "setup"}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 73, "producer boundary failed; raw diagnostics suppressed"
    values["CA_GENERAL_STAGE"] = "observe"
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, DRIVER, values=values, engine=engine)
    assert result.returncode == 0, "reader probe failed; raw diagnostics suppressed"
    observed = json.loads((tmp_path / "general-observed.json").read_text(encoding="utf-8-sig"))
    control = Path(observed["control_root"])
    environment = {"LOCALAPPDATA": observed["local_appdata"]}
    active = fence.active_fence(control, environ=environment)
    from tools import register_container_audit_worker_pc as registration
    import runtime_instance
    monkeypatch.setattr(registration, "_current_user_sid", lambda: observed["operator_sid"])
    monkeypatch.setattr(auto_update, "control_root", lambda root: tmp_path / "update-control")
    monkeypatch.setattr(auto_update, "process_snapshot", lambda root: {})
    monkeypatch.setattr(auto_update, "writer_processes", lambda snapshot, own_pid: [])

    class RelayLease:
        def release(self):
            pass

    monkeypatch.setattr(runtime_instance, "acquire_runtime_instance", lambda root: RelayLease())
    scope = fence._FailedInstallerRemoval(tmp_path / "current", tmp_path / "relay")
    try:
        assert scope.admits("current_user_setup_removal", control, active)
        monkeypatch.setattr(fence._WRITER_LOCAL, "removal_scope", scope, raising=False)
        monkeypatch.setattr(fence, "canonical_control_root", lambda values=None: control)
        receipt = fence._settle_failed_installer_removal()
        assert receipt and not (control / "active.json").exists()
        assert (control / "settled").is_dir()
    finally:
        scope.release()
