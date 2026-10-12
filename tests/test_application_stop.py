"""Normal remote shutdown stays on the existing headless GUI close path."""

import json
import queue
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import Container_Audit as application
import user_relay


def test_request_app_stop_writes_both_controls_without_starting_relay(tmp_path, monkeypatch):
    released = []
    stop_relay = user_relay.request_user_relay_stop
    monkeypatch.setattr(
        user_relay, "request_user_relay_stop",
        lambda root, **kwargs: stop_relay(
            root, **kwargs,
            lease_factory=lambda key: SimpleNamespace(release=lambda: released.append(key)),
        ),
    )

    result = user_relay.request_app_stop(tmp_path, timeout_seconds=0)

    request = json.loads(user_relay.app_stop_path(tmp_path).read_text(encoding="utf-8"))
    relay = json.loads(user_relay.user_relay_stop_path(tmp_path).read_text(encoding="utf-8"))
    assert request["schema_version"] == user_relay.APP_STOP_SCHEMA
    assert request["request_id"] == result["request_id"]
    assert relay["schema_version"] == "container-audit-user-relay-stop-v1"
    assert result["status"] == "REQUESTED"
    assert result["relay"]["status"] == "ABSENT"
    assert released == [tmp_path / "user-relay-instance"]
    assert not list((tmp_path / "control").glob("*.tmp"))


def test_request_app_stop_preserves_unknown_relay_absence(tmp_path, monkeypatch):
    stop_relay = user_relay.request_user_relay_stop
    monkeypatch.setattr(
        user_relay, "request_user_relay_stop",
        lambda root, **kwargs: stop_relay(root, **kwargs, lease_factory=lambda key: None),
    )

    result = user_relay.request_app_stop(tmp_path, timeout_seconds=0)

    assert result["relay"]["status"] == "UNKNOWN"
    assert user_relay.app_stop_path(tmp_path).is_file()
    assert user_relay.user_relay_stop_path(tmp_path).is_file()


def test_stop_cli_uses_explicit_root_and_only_writes_controls(tmp_path, monkeypatch, capsys):
    active = tmp_path / "active"
    active.mkdir()
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kwargs: pytest.fail("stop must not start a cycle"))
    monkeypatch.setattr(
        user_relay, "request_user_relay_stop",
        lambda root, **kwargs: {"status": "ABSENT"},
    )

    assert user_relay.main(["--data-root", str(active), "--request-app-stop"]) == 0

    assert user_relay.app_stop_path(active / "direct_sync").is_file()
    assert not (active / "events").exists()
    assert not (active / "direct_sync" / "status").exists()
    assert "REQUESTED" in capsys.readouterr().out


@pytest.mark.parametrize("save_ok", [True, False])
def test_clock_stop_uses_normal_close_and_preserves_unfinished_tray(tmp_path, monkeypatch, save_ok):
    app = application.ContainerAudit.__new__(application.ContainerAudit)
    app.direct_sync_program_data_root = str(tmp_path)
    app.worker_name = "fixture worker"
    app.current_tray = application.TraySession(master_label_code="ACTIVE", scanned_barcodes=["fixture scan"])
    app.current_exchange_session = application.ProductExchangeSession()
    calls = []
    deferred, notices = [], []
    app.COLOR_PRIMARY = "primary"
    app._log_event = lambda event, **kwargs: deferred.append(event) or True
    app.show_status_message = lambda message, *args, **kwargs: notices.append(message)
    app._current_tray_save_operation = lambda: app._save_current_tray_state
    def settle_record(steps, **kwargs):
        for operation in steps:
            operation()
        return True
    app._submit_scan_steps = settle_record
    app.root = SimpleNamespace(
        winfo_exists=lambda: "destroy" not in calls,
        after=lambda delay, callback: calls.append((delay, callback)),
        destroy=lambda: calls.append("destroy"),
    )
    app.log_queue = queue.Queue()
    app.log_thread = SimpleNamespace(is_alive=lambda: False)
    app.save_settings = lambda: calls.append("settings")
    app._cancel_all_jobs = lambda: calls.append("cancel")
    app._check_short_confirmation_expiry = lambda: None
    app._save_current_tray_state = lambda: calls.append("save") or save_ok
    app._preserve_preflight_hold_for_close = lambda: (True, False)
    app._operator_review_blocks_mutation = lambda: False
    app._end_work_session = lambda **kwargs: calls.append("work_end") or True
    app._refuse_scans_behind_save = lambda notice: ""
    app._set_scan_callback_pending = lambda pending: None
    app._set_preflight_scan_input_locked = lambda locked: None
    app._preflight_context_blocks_mutation = lambda: False
    app._show_field_notice = lambda *args, **kwargs: calls.append("notice")
    monkeypatch.setattr(application, "stop_all_sounds", lambda: None)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *args, **kwargs: {"status": "ABSENT"})
    user_relay.request_app_stop(tmp_path)

    app._update_clock()

    assert app.root.winfo_exists() and not getattr(app, "_application_close_complete", False)
    assert not getattr(app, "_ui_close_requested", False)
    assert user_relay.app_stop_path(tmp_path).exists()
    assert deferred == ["APP_STOP_DEFERRED"]
    assert notices == [application._APP_STOP_DEFERRED_MESSAGE]
    app.on_closing()  # The worker explicitly consents through the normal exit.

    assert "save" in calls
    assert ("destroy" in calls) is save_ok
    assert ("work_end" in calls) is save_ok
    assert app.current_tray.scanned_barcodes == ["fixture scan"]
    assert user_relay.app_stop_path(tmp_path).exists() is not save_ok
    assert calls[0] == (1000, app._update_clock)
    if not save_ok:
        assert "notice" in calls
        assert not app._ui_close_requested


@pytest.mark.parametrize("payload", [{}, {"schema_version": "unsupported", "request_id": "fixture"}])
def test_invalid_stop_control_does_not_close_gui(tmp_path, payload):
    app = application.ContainerAudit.__new__(application.ContainerAudit)
    app.direct_sync_program_data_root = str(tmp_path)
    app.on_closing = lambda: pytest.fail("invalid request must not close the GUI")
    path = user_relay.app_stop_path(tmp_path)
    path.parent.mkdir()
    path.write_text(json.dumps(payload), encoding="utf-8")

    app._poll_app_stop_request()

    assert path.is_file()


def test_consuming_an_older_request_preserves_a_newer_request(tmp_path, monkeypatch):
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *args, **kwargs: {"status": "ABSENT"})
    first = user_relay.request_app_stop(tmp_path)
    second = user_relay.request_app_stop(tmp_path)

    user_relay.consume_app_stop_request(tmp_path, first["request_id"])

    assert user_relay.read_app_stop_request(tmp_path)["request_id"] == second["request_id"]


@pytest.mark.parametrize("after_start", [False, True], ids=["before-start", "after-start"])
def test_clock_stop_ignores_requests_before_process_start(tmp_path, monkeypatch, capsys, after_start):
    started_at = datetime(2026, 10, 11, 12, 0, 0, 500000, tzinfo=timezone.utc)
    requested_at = started_at + timedelta(microseconds=100 if after_start else -100)

    class RequestClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return requested_at.astimezone(tz)

    monkeypatch.setattr(user_relay, "datetime", RequestClock)
    monkeypatch.setattr(application, "_APP_PROCESS_STARTED_AT", started_at, raising=False)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *args, **kwargs: {"status": "ABSENT"})
    user_relay.request_app_stop(tmp_path)
    app = application.ContainerAudit.__new__(application.ContainerAudit)
    app.direct_sync_program_data_root = str(tmp_path)
    closed = []
    app.on_closing = lambda: closed.append(True)
    app.root = SimpleNamespace(winfo_exists=lambda: True, after=lambda *args: None)
    app._check_short_confirmation_expiry = lambda: None

    app._update_clock()

    assert bool(closed) is after_start
    assert not user_relay.app_stop_path(tmp_path).exists()
    if not after_start:
        assert "앱 시작 전 멈춤 요청을 무시했습니다." in capsys.readouterr().out


def _stop_roots(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    return active


def test_remote_stop_is_accepted_before_the_update_gate(tmp_path, monkeypatch, capsys):
    import auto_update
    active = _stop_roots(tmp_path)
    monkeypatch.setattr(auto_update, "startup_gate", lambda *args, **kwargs: pytest.fail("stop must not enter the update gate"))
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda root, **kwargs: {"status": "ABSENT"})

    assert user_relay.main(["--data-root", str(active), "--direct-sync-root", str(active / "direct_sync"), "--request-app-stop"]) == 0

    assert user_relay.app_stop_path(active / "direct_sync").is_file()
    assert "REQUESTED" in capsys.readouterr().out


def test_other_relay_modes_still_pass_the_update_gate(tmp_path, monkeypatch):
    import auto_update
    seen = []
    monkeypatch.setattr(auto_update, "startup_gate", lambda root, arguments, **kwargs: seen.append(list(arguments)) or 20)
    monkeypatch.setattr(user_relay, "_runtime_cycle", lambda **kwargs: pytest.fail("a refused relay must not run"))

    assert user_relay.main(["--once"]) == 20
    assert seen == [[user_relay.USER_RELAY_MODE, "--once"]]


def _installed_operator(tmp_path, monkeypatch, caller_sid):
    import auto_update
    control = tmp_path / "update-control"
    control.mkdir()
    (control / "policy.json").write_text(json.dumps({"operator_sid": "S-1-5-21-0-0-0-1001"}), encoding="utf-8")
    monkeypatch.setattr(auto_update, "control_root", lambda app_root: control)
    monkeypatch.setattr(auto_update, "current_process_sid", lambda: caller_sid)


def test_another_account_must_name_the_operator_roots(tmp_path, monkeypatch, capsys):
    _installed_operator(tmp_path, monkeypatch, "S-1-5-21-0-0-0-1002")
    monkeypatch.setattr(user_relay, "request_app_stop", lambda root, **kwargs: pytest.fail("no request from a foreign profile"))
    monkeypatch.setattr(user_relay, "_notify_data_root_error", lambda: pytest.fail("no dialog in a remote session"))

    assert user_relay.main(["--request-app-stop"]) == 1

    assert json.loads(capsys.readouterr().out) == {"reason_code": "OPERATOR_ROOTS_REQUIRED", "status": "FAILED"}


def test_elevated_operator_uses_its_own_roots_without_arguments(tmp_path, monkeypatch, capsys):
    active = _stop_roots(tmp_path)
    _installed_operator(tmp_path, monkeypatch, "S-1-5-21-0-0-0-1001")
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(active))
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda root, **kwargs: {"status": "ABSENT"})

    assert user_relay.main(["--request-app-stop"]) == 0

    assert user_relay.app_stop_path(active / "direct_sync").is_file()
    assert "REQUESTED" in capsys.readouterr().out


def test_remote_stop_reports_an_unavailable_root_without_a_dialog(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing"
    monkeypatch.setattr(user_relay, "_notify_data_root_error", lambda: pytest.fail("no dialog in a remote session"))
    monkeypatch.setattr(user_relay, "request_app_stop", lambda root, **kwargs: pytest.fail("no request without a dataset"))

    assert user_relay.main(["--data-root", str(missing), "--direct-sync-root", str(missing / "direct_sync"), "--request-app-stop"]) == 1

    assert json.loads(capsys.readouterr().out) == {"reason_code": "DATA_ROOT_UNAVAILABLE", "status": "FAILED"}


def test_unmanaged_stop_without_a_data_root_is_refused(tmp_path, monkeypatch, capsys):
    import auto_update
    monkeypatch.setattr(auto_update, "control_root", lambda app_root: None)
    monkeypatch.setattr(user_relay, "request_app_stop", lambda root, **kwargs: pytest.fail("no request from an unknown owner profile"))

    assert user_relay.main(["--request-app-stop"]) == 1

    assert json.loads(capsys.readouterr().out) == {"reason_code": "OPERATOR_ROOTS_REQUIRED", "status": "FAILED"}


def test_stop_token_as_an_option_value_still_passes_the_gate(tmp_path, monkeypatch):
    import auto_update
    seen = []
    monkeypatch.setattr(auto_update, "startup_gate", lambda root, arguments, **kwargs: seen.append(list(arguments)) or 20)

    assert user_relay.main(["--app-root=--request-app-stop", "--once"]) == 20
    assert seen
