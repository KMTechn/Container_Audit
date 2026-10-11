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

    assert "save" in calls
    assert ("destroy" in calls) is save_ok
    assert ("work_end" in calls) is save_ok
    assert app.current_tray.scanned_barcodes == ["fixture scan"]
    assert not user_relay.app_stop_path(tmp_path).exists()
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
