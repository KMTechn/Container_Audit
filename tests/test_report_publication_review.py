import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import report_publication as publication


def refused(value):
    raise ValueError("REPORT_UNAVAILABLE")


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError])
def test_counter_failure_never_changes_report_result(tmp_path, error_type):
    target = tmp_path / "diagnostic.json"
    def fail_counter(path, value):
        raise error_type("synthetic-counter-failure")
    prepared = publication.prepare_report({"detail": "synthetic-diagnostic"},
        render=refused, fallback_render=json.dumps, unavailable_codes=("REPORT_UNAVAILABLE",))
    assert publication.failure_count(target) == 0
    target.write_text(prepared.text, encoding="utf-8")
    publication.record_publication(prepared, path=target, writer=fail_counter)
    assert prepared.unavailable
    assert publication.failure_count(target) == 1


def test_counter_writer_runs_outside_count_lock(tmp_path):
    ownership = []
    target = tmp_path / "diagnostic.json"
    prepared = publication.prepare_report({}, render=refused, fallback_render=json.dumps,
        unavailable_codes=("REPORT_UNAVAILABLE",))
    assert ownership == [] and publication.failure_count(target) == 0
    target.write_text(prepared.text, encoding="utf-8")
    publication.record_publication(prepared, path=target,
        writer=lambda path, value: ownership.append(publication._LOCK._is_owned()))
    assert ownership == [False]


def test_directory_counter_does_not_accumulate_process_files(tmp_path, monkeypatch):
    def write_counter(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
    target = tmp_path / "diagnostic.json"
    for process in (31001, 31002):
        with monkeypatch.context() as change:
            change.setattr(os, "getpid", lambda: process)
            prepared = publication.prepare_report({}, render=refused, fallback_render=json.dumps,
                unavailable_codes=("REPORT_UNAVAILABLE",))
            target.write_text(prepared.text, encoding="utf-8")
            publication.record_publication(prepared, path=target, writer=write_counter)
    files = list(tmp_path.glob(".report-unavailable-count*.json"))
    assert len(files) == 1
    assert files[0].name == ".report-unavailable-count.json"
    assert json.loads(files[0].read_text(encoding="utf-8"))["count"] == 2


def test_empty_and_nonstring_diagnostics_keep_their_types():
    value = {"failure": None, "message": 0, "stdout": False, "stderr": [],
             "detail": {}, "stdout_tail": "", "stderr_tail": "synthetic-diagnostic"}
    prepared = publication.prepare_report(value, render=refused,
        fallback_render=json.dumps, diagnostic_fields=publication.DIAGNOSTIC_FIELDS,
        unavailable_codes=("REPORT_UNAVAILABLE",))
    result = json.loads(prepared.text)
    assert result == {**value, "stderr_tail": publication.UNAVAILABLE}


def test_portable_isolated_auto_update_entry_starts(tmp_path):
    app = tmp_path / "portable" / "app"
    from tools import build_portable_release_candidate as builder
    repo = Path(__file__).resolve().parents[1]
    builder._copy_application(repo, app)
    result = subprocess.run([sys.executable, "-I", "-B", str(app / "auto_update.py"), "--help"],
        cwd=tmp_path, capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, (result.returncode, b"ModuleNotFoundError" in result.stderr)


@pytest.mark.parametrize("field", ["hostname", "endpoint_url", "server_base_url"])
def test_registration_receipt_machine_collision_keeps_registered_state(tmp_path, monkeypatch, field):
    from tools import register_container_audit_worker_pc as registration
    synthetic = "synthetic-registration-machine-collision"
    monkeypatch.setenv("KMTECH_TEST_API_TOKEN", synthetic)
    path = tmp_path / "registration.json"
    payload = {"status": "REGISTERED", "server_registration_verified": True,
               "base_url": "https://example.invalid", field: synthetic}
    registration._write_registration_report(path, payload)
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result == payload


def test_create_new_ready_report_only_replaces_diagnostic_collision(tmp_path):
    import current_user_onboarding as onboarding
    target = tmp_path / "current_user_onboarding.json"
    synthetic = "synthetic-restored-diagnostic-collision"
    payload = {"status": "READY", "server_registration_verified": True,
               "base_url": "https://example.invalid", "message": synthetic}
    onboarding._write_json_atomic_create_new.__wrapped__(target, payload,
        environ={"KMTECH_TEST_API_TOKEN": synthetic})
    result = json.loads(target.read_text(encoding="utf-8"))
    assert result == {**payload, "message": publication.UNAVAILABLE}
    assert publication.failure_count(target) == 1
    with pytest.raises(FileExistsError):
        onboarding._write_json_atomic_create_new.__wrapped__(target, payload,
            environ={"KMTECH_TEST_API_TOKEN": synthetic})
    assert json.loads(target.read_text(encoding="utf-8")) == result


def test_install_pack_fallback_retains_status(tmp_path, monkeypatch):
    import auto_update
    from tools import direct_sync_relay_install_pack as pack
    monkeypatch.setattr(auto_update, "serialize_json_for_sink", refused)
    target = tmp_path / "install.json"
    assert pack._write_json(target, {"status": "BLOCKED", "message": "synthetic-diagnostic"})
    result = json.loads(target.read_text(encoding="utf-8"))
    assert result["status"] == "BLOCKED"
    assert result["message"] == publication.UNAVAILABLE


def test_install_pack_failed_marker_does_not_advertise_path(tmp_path, monkeypatch):
    import auto_update
    import data_generation_guard
    from tools import direct_sync_relay_install_pack as pack
    monkeypatch.setattr(auto_update, "serialize_json_for_sink", refused)
    monkeypatch.setattr(pack, "_legacy_path_block_report", lambda *args: None)
    monkeypatch.setattr(pack, "build_container_audit_storage_paths", lambda **kwargs: SimpleNamespace(data_root=tmp_path))
    monkeypatch.setattr(data_generation_guard, "resolve_owner_path", lambda value: Path(value))
    monkeypatch.setattr(data_generation_guard, "probe_before_owner_paths", lambda *args, **kwargs: None)
    def blocked(args):
        raise ValueError("synthetic-setup-blocked")
    monkeypatch.setattr(pack, "_apply_container_audit_storage_defaults", blocked)
    monkeypatch.setattr(pack, "_write_json_bytes", lambda *args: (_ for _ in ()).throw(OSError("synthetic-io-failure")))
    emitted = []
    monkeypatch.setattr(auto_update, "emit_support_record", lambda value, **kwargs: emitted.append(value))
    target = tmp_path / "install.json"
    assert pack.main(["--report-path", str(target)]) == 2
    assert not target.exists()
    assert not any("status_file_path" in row for row in emitted)


def test_fallback_keeps_public_projection_and_anonymous_diagnostics(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    monkeypatch.setenv("KMTECH_TEST_API_TOKEN", "4826")
    payload = {"status": "FAILED", "cause_code": "SUPPORT_FAILURE",
               "server_registration_verified": True, "base_url": "https://example.invalid",
               "autostart": {"message": 4826},
               "blocked_reason": "synthetic 4826 diagnostic",
               "failure_traceback": "trace [REDACTED:KMTECH_TEST_API_TOKEN]"}
    payload.pop("failure_traceback")
    payload["traceback"] = "trace [REDACTED:KMTECH_TEST_API_TOKEN]"
    target = tmp_path / "current_user_onboarding.json"
    onboarding._persist_failure_report(target, payload, RuntimeError("synthetic-original-failure"))
    raw = target.read_text(encoding="utf-8")
    result = json.loads(raw)
    assert result["status"] == "FAILED"
    assert result["cause_code"] == "SUPPORT_FAILURE"
    assert result["server_registration_verified"] is True
    assert result["base_url"] == payload["base_url"]
    assert "4826" not in raw and "KMTECH_TEST_API_TOKEN" not in raw
    assert publication.failure_count(target) == 1


def test_fallback_still_refuses_mandatory_machine_collision(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    synthetic = "synthetic-mandatory-machine-collision"
    monkeypatch.setenv("KMTECH_TEST_API_TOKEN", synthetic)
    target = tmp_path / "current_user_onboarding.json"
    old = b'{"status":"READY","invocation":"prior"}\n'
    target.write_bytes(old)
    payload = {"status": "READY", "message": synthetic, "hostname": synthetic}
    with pytest.raises(ValueError, match="MACHINE_METADATA_SECRET_DETECTED"):
        onboarding._write_json_atomic.__wrapped__(target, payload)
    assert target.read_bytes() == old
    assert publication.failure_count(target) == 0
