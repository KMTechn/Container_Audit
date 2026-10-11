"""Actual launcher/relay boundaries, with GUI and transport kept headless."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_registration_preserves_original_path_policy_before_resolving_owner_alias(tmp_path, monkeypatch):
    from tools import register_container_audit_worker_pc as registration
    import data_generation_guard as guard
    captured = []
    def policy(args):
        captured.append(args.producer_identity_path)
        return {'status':'BLOCKED','blocked_reason':'legacy_owner_alias','unsafe_paths':[]}
    monkeypatch.setattr(registration, '_explicit_output_path_policy_report', policy)
    monkeypatch.setattr(guard, 'probe_before_owner_paths', lambda *args, **kwargs: None)
    monkeypatch.setattr(registration, 'build_registration_payloads', lambda *args: pytest.fail('blocked alias opened owner data'))
    monkeypatch.setenv('CONTAINER_AUDIT_DATA_ROOT', str(tmp_path/'data'))
    assert registration.main(['--producer-identity-path','~/original-owner.json']) == 2
    assert captured == ['~/original-owner.json']


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
    constructors, messages, notices = [], [], []
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(app, "ContainerAudit", lambda: constructors.append(True))
    from startup_check_report import NOTICE
    monkeypatch.setattr(app, "_show_startup_unavailable", lambda: notices.append(NOTICE))
    monkeypatch.setattr(app.messagebox, "showerror", lambda *args: messages.append(args))
    def denied(*args, **kwargs):
        raise PermissionError("synthetic marker refusal")
    monkeypatch.setattr(generation, "record_generation", denied)
    assert app.main(["--data-root", str(data)]) == 1
    assert not constructors
    assert not notices
    assert messages == [("자료 판 확인", app.DataGenerationBlocked({"status": "UNKNOWN", "allowed": False}).user_message)]


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
    assert isinstance(captured.value.__cause__, DataGenerationBlocked)
    assert captured.value.__cause__.decision["message_key"] == "data_generation_unknown"
    assert not captured.value.report_path.exists()


def test_persistent_relay_reports_child_refusal_without_launch_time_marker(tmp_path, monkeypatch, capsys):
    import user_relay as relay
    from kmtech_shared import data_generation as generation

    data = tmp_path / "data"
    data.mkdir()
    calls = []
    def child(**kwargs):
        calls.append(True)
        status = kwargs["direct_sync_root"] / "status/direct_sync_relay_status.json"
        status.parent.mkdir(parents=True, exist_ok=True)
        status.write_text(json.dumps({"status": "runtime_error", "error_code": "data_generation_downgrade_refused"}))
        return {"status": "FAIL", "returncode": 1}

    monkeypatch.setattr(relay, "run_session_direct_sync_once", child)
    assert relay.main(["--data-root", str(data), "--once"]) == 1
    assert calls == [True]
    assert not (data / "data-generation.json").exists()
    assert not (data / "direct_sync/status/container_audit_user_relay.json").exists()
    # Five-source child-output decision: the public diagnostic is a fixed
    # record; refusal, exit code, invocation count and no-marker checks stay.
    line = capsys.readouterr().out.strip()
    assert line.startswith('CONTAINER_AUDIT_SUPPORT=')
    public = json.loads(line.split('=', 1)[1])
    assert public['status'] == 'runtime_error' and public['stage'] == 'user_relay'
    assert public['reason_code'] == 'SUPPORT_RESULT'
    child_status = json.loads((data / 'direct_sync/status/direct_sync_relay_status.json').read_bytes())
    assert child_status['error_code'] == 'data_generation_downgrade_refused'
    assert public['guidance'] == '자료를 보존하고 관리자 지원 복구를 요청하세요.'
    assert public['report_status'] == 'REPORT_UNAVAILABLE'


def test_raw_relay_refusal_prevents_queue_open(tmp_path, monkeypatch, capsys):
    from tools import direct_sync_relay_runner as runner
    from data_generation_guard import DataGenerationBlocked
    from kmtech_shared import data_generation as generation

    opened = []
    monkeypatch.setattr(runner, "record_before_owner_paths", lambda *args, **kwargs: (_ for _ in ()).throw(DataGenerationBlocked(
        {"status": "UNKNOWN", "allowed": False, "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE})))
    monkeypatch.setattr(runner, "run_relay_once", lambda *args: opened.append(True))
    arguments = []
    for option, leaf in (("db-path", "queue.sqlite3"), ("spool-dir", "spool"),
                         ("producer-manifest-path", "producer.json"), ("credential-path", "credential.bin"),
                         ("upload-status-dir", "uploads"), ("runtime-status-path", "status.json"), ("log-path", "log.jsonl")):
        arguments.extend(["--" + option, str(tmp_path / leaf)])
    assert runner.main(arguments) == 1
    assert not opened and not (tmp_path / "queue.sqlite3").exists()
    assert not (tmp_path / "status.json").exists()
    assert "자료 판을 확인할 수 없어" in capsys.readouterr().out


def test_gui_duplicate_lease_does_not_record_unused_generation(tmp_path, monkeypatch):
    import Container_Audit as app
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(app, "verify_factory_contract_startup", lambda: None)
    monkeypatch.setattr(app, "acquire_runtime_instance", lambda *args: None)
    monkeypatch.setattr(app.messagebox, "showwarning", lambda *args: None)
    assert app.main(["--data-root", str(data)]) is None
    assert not (data / "data-generation.json").exists()


def test_onboarding_code_failure_does_not_record_before_data_open(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    data = tmp_path / "data"
    def invalid(*args, **kwargs):
        raise ValueError("synthetic code-integrity failure")
    monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", invalid)
    with pytest.raises(onboarding.CurrentUserOnboardingError):
        onboarding.onboard_current_user(tmp_path / "code", environ={"CONTAINER_AUDIT_DATA_ROOT": str(data)})
    assert not (data / "data-generation.json").exists()


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


@pytest.mark.parametrize("status", ["REFUSE", "UNKNOWN"])
def test_generation_failure_exposes_only_fixed_worker_recovery(status):
    from data_generation_guard import DataGenerationBlocked
    from kmtech_shared import data_generation as generation

    blocked = DataGenerationBlocked({"status": status, "message": "internal diagnostic"})
    expected = generation.REFUSAL_MESSAGE if status == "REFUSE" else generation.UNKNOWN_MESSAGE
    assert blocked.user_message == str(blocked) == expected
    assert "internal diagnostic" not in str(blocked)
