"""Actual launcher/relay boundaries, with GUI and transport kept headless."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_direct_main_records_before_gui_constructor(tmp_path, monkeypatch):
    import Container_Audit as app

    data = tmp_path / "data"
    data.mkdir()
    observations = []
    lease = SimpleNamespace(release=lambda: None)
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(app, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(app, "prepare_startup_item_catalog", lambda: None)
    monkeypatch.setattr(app, "acquire_runtime_instance", lambda *args: lease)

    def constructor():
        observations.append((data / "data-generation.json").exists())
        return SimpleNamespace(root=SimpleNamespace(after=lambda *args: None), run=lambda: None)

    monkeypatch.setattr(app, "ContainerAudit", constructor)
    assert app.main(["--data-root", str(data)]) == 0
    assert observations == [True]
    marker = json.loads((data / "data-generation.json").read_bytes())
    assert marker["version"] == app.CURRENT_VERSION
    from kmtech_shared.data_generation import probe_downgrade
    result = probe_downgrade([data / "data-generation.json"], "v2.0.33",
        app_id="container_audit", subject_sid=marker["subject_sid"], target_build_id="b" * 40)
    assert result["status"] == "REFUSE"


def test_marker_write_failure_prevents_gui_constructor(tmp_path, monkeypatch):
    import Container_Audit as app
    from kmtech_shared import data_generation as generation

    data = tmp_path / "data"
    data.mkdir()
    constructors, messages = [], []
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(app, "ContainerAudit", lambda: constructors.append(True))
    monkeypatch.setattr(app.messagebox, "showerror", lambda *args: messages.append(args))
    def denied(*args, **kwargs):
        raise PermissionError("synthetic marker refusal")
    monkeypatch.setattr(generation, "record_generation", denied)
    assert app.main(["--data-root", str(data)]) == 1
    assert not constructors
    assert "자료 판을 확인할 수 없어" in messages[0][1]


def test_onboarding_refusal_prevents_state_or_ledger_open(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    from data_generation_guard import DataGenerationBlocked
    import data_generation_guard as guard
    from kmtech_shared import data_generation as generation

    opened = []
    monkeypatch.setattr(onboarding, "inspect_current_user_state", lambda *args, **kwargs: opened.append(True))
    decision = {"status": "UNKNOWN", "allowed": False, "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE}
    monkeypatch.setattr(guard, "record_before_data_open", lambda *args, **kwargs: (_ for _ in ()).throw(DataGenerationBlocked(decision)))
    with pytest.raises(onboarding.CurrentUserOnboardingError, match="자료 판을 확인할 수 없어") as captured:
        onboarding.onboard_current_user(tmp_path / "code", ledger_factory=lambda *args: opened.append(True))
    assert not opened
    report = json.loads(captured.value.report_path.read_bytes())
    assert report["error_code"] == "data_generation_unknown"


def test_persistent_relay_refusal_keeps_runtime_unopened(tmp_path, monkeypatch):
    import user_relay as relay
    from data_generation_guard import DataGenerationBlocked
    from kmtech_shared import data_generation as generation

    data = tmp_path / "data"
    data.mkdir()
    calls = []
    monkeypatch.setattr(relay, "record_before_data_open", lambda *args: (_ for _ in ()).throw(DataGenerationBlocked(
        {"status": "REFUSE", "allowed": False, "message_key": "data_generation_downgrade_refused", "message": generation.REFUSAL_MESSAGE})))
    monkeypatch.setattr(relay, "run_persistent_relay_loop", lambda *args, **kwargs: calls.append(True))
    assert relay.main(["--data-root", str(data), "--once"]) == 1
    assert not calls
    report = json.loads((data / "direct_sync/status/container_audit_user_relay.json").read_bytes())
    assert "옛 판으로 되돌릴 수 없습니다" in report["error_message"]


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_installer_target_guard_preserves_preopen_rollback_and_refuses_used_generation(tmp_path, engine):
    from kmtech_shared.data_generation import record_generation
    from tests.powershell_contracts import run_functions

    root = Path(__file__).resolve().parents[1]
    local, data, old = tmp_path / "local", tmp_path / "data", tmp_path / "old"
    local.mkdir(); data.mkdir(); old.mkdir()
    sid = "S-1-5-21-219"
    metadata = old / "portable-manifest.json"
    metadata.write_text(json.dumps({"version": "v2.0.33", "source_commit": "b" * 40}))
    literal = lambda path: str(path).replace("'", "''")
    script = f"""
$args=@{{CandidateRoot='{literal(old)}';TargetSid='{sid}';LocalAppDataRoot='{literal(local)}';DataRoot='{literal(data)}';HelperRoot='{literal(root)}'}}
$blocked=$false
try {{ Assert-ContainerDataGenerationTarget @args }} catch {{ $blocked=$true; $message=$_.Exception.Message }}
@{{blocked=$blocked;message=$message}} | ConvertTo-Json -Compress
"""
    names = ["Get-StrictFullPath", "Get-FileSha256", "Assert-BootstrapNoReparsePoint",
             "Get-BootstrapSharedPortableLeaf", "Assert-ContainerDataGenerationTarget"]
    before = run_functions(tmp_path, root / "tools/bootstrap_integrity.ps1", names, script, engine=engine)
    assert before.returncode == 0, before.stdout + before.stderr
    assert json.loads(before.stdout)["blocked"] is False
    marker = data / "data-generation.json"
    record_generation(marker, "v2.0.99", app_id="container_audit", subject_sid=sid, build_id="a" * 40)
    preserved = marker.read_bytes()
    after = run_functions(tmp_path, root / "tools/bootstrap_integrity.ps1", names, script, engine=engine)
    assert after.returncode == 0, after.stdout + after.stderr
    report = json.loads(after.stdout)
    assert report["blocked"] and "옛 판으로 되돌릴 수 없습니다" in report["message"]
    assert marker.read_bytes() == preserved and metadata.exists()
    compatible = tmp_path / "compatible"
    compatible.mkdir()
    record_generation(compatible / "data-generation.json", "v2.0.99", app_id="container_audit",
        subject_sid=sid, build_id="a" * 40, data_compatible_min_version="v2.0.33", compatibility_verified=True)
    allowed = run_functions(tmp_path, root / "tools/bootstrap_integrity.ps1", names,
        script.replace(literal(data), literal(compatible)), engine=engine)
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert json.loads(allowed.stdout)["blocked"] is False
    corrupt = tmp_path / "corrupt"
    corrupt.mkdir()
    (corrupt / "data-generation.json").write_bytes(b"{")
    denied = run_functions(tmp_path, root / "tools/bootstrap_integrity.ps1", names,
        script.replace(literal(data), literal(corrupt)), engine=engine)
    assert denied.returncode == 0, denied.stdout + denied.stderr
    assert json.loads(denied.stdout)["blocked"] is True
    assert (corrupt / "data-generation.json").read_bytes() == b"{"
