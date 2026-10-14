"""Startup telemetry retains types/timing only and ordinary writer admission."""
import json
import sys
from types import SimpleNamespace
from pathlib import Path
from uuid import uuid4
import pytest
import Container_Audit as ca
import ca_screen_bridge as screen
import screen_startup_fallback as fallback
import writer_session_fence as fence
from tests.test_ca_new_screen_entry import entry
from tests.test_ca_s1_fallback import visible
from tests.test_ca_shell_v3162_integration import actual_shell


def records(data):
    return [json.loads(line) for line in (data / "screen-startup.jsonl").read_text(encoding="utf-8").splitlines()]


def test_actual_webview_start_normal_return_records_elapsed_ms(actual_shell, monkeypatch):
    state = actual_shell
    state.mode = "ready"
    ticks = iter((0, 0.125))
    monkeypatch.setattr(fallback, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    assert ca.main([]) == 0
    rows = records(state.data)
    assert [row["event"] for row in rows] == ["WEBVIEW_START_ENTER", "WEBVIEW_START_RETURN"]
    assert rows[1]["ms"] == 125 and rows[1]["exception"] is None and rows[1]["ready"] is True
    assert all(set(row) == {"event", "exception", "ms", "ready", "code", "cause"} for row in rows)


def test_actual_start_exception_and_before_exit_record_type_cause_only(actual_shell, monkeypatch):
    state = actual_shell
    hidden = uuid4().hex
    error = ValueError(hidden)
    def failed(*_args, **_kwargs):
        state.visible.web = 1
        state.windows[-1].events.shown.fire()
        raise error
    monkeypatch.setattr(sys.modules["webview"], "start", failed)
    ca.main([])
    rows = records(state.data)
    assert [row["event"] for row in rows] == ["WEBVIEW_START_ENTER", "WEBVIEW_START_ERROR", "BEFORE_EXIT"]
    assert rows[1]["exception"] == "ValueError" and rows[1]["ms"] >= 0
    assert rows[2]["code"] == "SHELL_START_FAILED"
    assert rows[2]["cause"] == "WEBVIEW_ENV_FAILED" and rows[2]["ready"] is False
    assert hidden not in (state.data / "screen-startup.jsonl").read_text()
    assert state.exits == [3] and state.visible.tk == state.visible.web == 0


def test_owner_failure_retains_original_error_and_its_distinct_record(entry, monkeypatch, tmp_path):
    data = tmp_path / "screen"
    data.mkdir()
    hidden = uuid4().hex
    error = LookupError(hidden)
    attempt = fallback.ScreenLaunchAttempt()
    attempt.startup_observer = lambda event, **fields: screen._record_screen_startup(data, event, **fields)
    def refused(_args):
        raise error
    monkeypatch.setattr(ca, "_run_gui_application", refused)
    assert screen.owner_main_for(ca, [], attempt=attempt)(entry.bridge) is None
    assert ca.CA_SCREEN_HOST["error"] is error
    rows = records(data)
    assert len(rows) == 1 and rows[0]["event"] == "OWNER_ERROR"
    assert rows[0]["exception"] == "LookupError" and rows[0]["ms"] >= 0
    assert hidden not in (data / "screen-startup.jsonl").read_text()
    ca.CA_SCREEN_HOST.pop("error")


def test_before_exit_records_host_error_ready_and_code_before_fencing(entry, monkeypatch, tmp_path):
    data = tmp_path / "screen"
    data.mkdir()
    monkeypatch.setattr(screen, "shell_data_dir", lambda: data)
    hidden = uuid4().hex
    error = ArithmeticError(hidden)
    def run(_profile, _data, **kwargs):
        ca.CA_SCREEN_HOST["error"] = error
        # The callback must inspect the observed bridge, not a cached READY flag.
        kwargs["owner_main"](entry.bridge)
        entry.bridge._startup_ready = True
        entry.bridge._startup_cause = "OWNER_START_FAILED"
        assert kwargs["before_exit"]("SHELL_START_FAILED", 120) is True
        raise SystemExit(3)
    monkeypatch.setattr(sys.modules["host"], "run_app", run)
    with pytest.raises(SystemExit):
        ca.main([])
    row = records(data)[-1]
    assert row["event"] == "BEFORE_EXIT" and row["exception"] == "ArithmeticError"
    assert row["ready"] is True and row["cause"] == "OWNER_START_FAILED"
    assert row["code"] == "SHELL_START_FAILED" and hidden not in json.dumps(row)


def test_telemetry_fenced_or_missing_directory_does_not_create_or_bypass(tmp_path, monkeypatch):
    data = tmp_path / "screen"
    screen._record_screen_startup(data, "WEBVIEW_START_ENTER")
    assert not data.exists()
    data.mkdir()
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", True)
    screen._record_screen_startup(data, "BEFORE_EXIT")
    assert list(data.iterdir()) == []


def test_telemetry_uses_existing_ordinary_writer_source_and_bounded_file(tmp_path, monkeypatch):
    from contextlib import contextmanager
    calls = []
    @contextmanager
    def admission(source, *, timeout_seconds):
        calls.append((source, timeout_seconds))
        yield
    monkeypatch.setattr(screen, "writer_admission", admission)
    screen._record_screen_startup(tmp_path, "WEBVIEW_START_ENTER")
    assert calls == [("screen_shell_fileio", 0.0)]
    path = tmp_path / "screen-startup.jsonl"
    path.write_bytes(b"x" * (256 * 1024))
    screen._record_screen_startup(tmp_path, "WEBVIEW_START_ENTER")
    assert path.stat().st_size == 256 * 1024


def test_telemetry_rejects_unstructured_codes_and_exception_names(tmp_path):
    hidden = uuid4().hex
    error = type(hidden + "-bad", (Exception,), {})(hidden)
    screen._record_screen_startup(tmp_path, "BEFORE_EXIT", error=error, code=hidden, cause=hidden)
    row = records(tmp_path)[0]
    assert row["exception"] == "Exception" and row["code"] == row["cause"] == "OTHER"
    assert hidden not in json.dumps(row)
