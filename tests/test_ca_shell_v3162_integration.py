"""Run the shipped shell and CA entry with headless native surface replacements."""

from contextlib import contextmanager
import hashlib
import importlib
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
import writer_session_fence as fence
from tests.test_ca_new_screen_entry import entry
from tests.test_ca_s1_fallback import visible


ROOT = Path(__file__).resolve().parents[1]


class Event:
    def __init__(self):
        self.callbacks = []
        self.fired = False

    def __iadd__(self, callback):
        self.callbacks.append(callback)
        return self

    def fire(self):
        self.fired = True
        for callback in list(self.callbacks):
            callback()

    def is_set(self):
        return self.fired


@pytest.fixture
def actual_shell(entry, visible, monkeypatch, tmp_path):
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    monkeypatch.syspath_prepend(str(ROOT / "shell"))
    monkeypatch.delitem(sys.modules, "host", raising=False)
    host = importlib.import_module("host")
    assert Path(host.__file__).resolve() == ROOT / "shell/host.py"
    state = SimpleNamespace(mode="start_error", order=[], exits=[], windows=[], bridges=[], notice_titles=[],
                            process_exited=threading.Event(),
                            data=tmp_path / "shell-data", visible=visible, host=host, api=None,
                            original_notice=host.show_startup_notice)

    original_bridge = host.Bridge

    class RecordedBridge(original_bridge):
        def __init__(self, *_args, **_kwargs):
            super().__init__(*_args, **_kwargs)
            state.bridges.append(self)

    class Window:
        def __init__(self):
            self._callbacks = {}
            self.events = SimpleNamespace(**{name: Event() for name in (
                "before_load", "loaded", "shown", "closing", "closed",
            )})

        def destroy(self):
            state.order.append("destroy")
            if state.mode == "destroy_error":
                raise RuntimeError("owned destroy failure")
            visible.web = 0
            self.events.closed.fire()

    class Native:
        def __init__(self, window, bridge, *_args, **_kwargs):
            self.window, self.bridge = window, bridge

        def before_load(self):
            pass

        def loaded(self):
            pass

        def notify_push(self, *_args):
            pass

        def show_closing(self, *_args):
            pass

        def pick_file(self, *_args):
            return None

        def pause_page(self):
            pass

        def page_ready(self, *_args):
            pass

        def close(self):
            pass

    class Reservation:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def bind(self, *_args):
            state.order.append("fake_socket")

        def getsockname(self):
            return ("127.0.0.1", 12345)

    def create_window(_title, **kwargs):
        state.order.append("create")
        state.api = kwargs["js_api"]
        window = Window()
        state.windows.append(window)
        return window

    def start(callback, **_kwargs):
        state.order.append("start")
        visible.web = 1
        state.windows[-1].events.shown.fire()
        assert visible.tk + visible.web <= 1
        if state.mode in {"start_error", "destroy_error"}:
            raise RuntimeError("owned start failure")
        if state.mode == "timeout":
            assert state.process_exited.wait(2), "real startup watchdog never exited"
            return
        state.api._on_ready({})
        callback()
        state.windows[-1].destroy()

    def exit_process(code):
        state.order.append("exit")
        state.exits.append(code)
        visible.web = 0  # The replacement models all surfaces dying at exit.
        state.process_exited.set()

    def notice(title, count=2):
        state.order.append("notice")
        state.notice_titles.append(title)
        assert visible.tk + visible.web <= 1

    fake_webview = SimpleNamespace(
        settings={}, windows=state.windows, create_window=create_window, start=start,
        http=SimpleNamespace(start_global_server=lambda **_kwargs: state.order.append("fake_http")),
    )
    monkeypatch.setitem(sys.modules, "webview", fake_webview)
    monkeypatch.setattr(host, "NativeHost", Native)
    monkeypatch.setattr(host, "Bridge", RecordedBridge)
    monkeypatch.setattr(host.socket, "socket", Reservation)
    monkeypatch.setattr(host.os, "_exit", exit_process)
    monkeypatch.setattr(host, "show_startup_notice", notice)
    monkeypatch.setattr(screen, "shell_data_dir", lambda: state.data)
    monkeypatch.setattr(host, "is_interactive_session", lambda: True)
    yield state
    # Startup recovery exits the real process without Bridge.close. The fake
    # exit leaves its in-memory push/pedal threads here, so dispose only those
    # shell resources before restoring the process-exit replacement.
    for bridge in state.bridges:
        bridge._publisher_stop.set()
        bridge._publisher.join(2)
        bridge.pedal.close()
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and thread.name in {
            "app-owner", "shell-start-watch", "shell-start-destroy", "shell-force-exit",
        }:
            thread.join(2)
            assert not thread.is_alive()
    assert visible.tk + visible.web <= 1


@pytest.mark.parametrize("failure", ["start_error", "timeout", "destroy_error"])
def test_real_shell_first_failure_retries_web_second_failure_uses_tk(actual_shell, entry, monkeypatch, failure):
    state = actual_shell
    state.mode = failure
    if failure == "timeout":
        monkeypatch.setattr(state.host, "READY_TIMEOUT_S", 0.05)
    original = fence.close_and_wait_writers
    observed = []

    def before_exit(deadline):
        state.order.append("before_exit")
        observed.append(deadline)
        return original(deadline)

    monkeypatch.setattr(fence, "close_and_wait_writers", before_exit)

    for count in (1, 2):
        if count == 2:
            # A new manual process has a fresh admission latch; its persisted marker is
            # the real shell's marker, and its CA switch/entry path is left intact.
            monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)

        ca.main([])
        assert state.exits == [3] * count
        assert observed == [120] * count
        assert state.notice_titles == ["이적"] * count
        retry = json.loads((state.data / "shell-start-retry.json").read_text(encoding="utf-8"))
        assert retry["count"] == count and retry["version"] == ca.CURRENT_VERSION
        assert state.host.web_allowed(state.data, ca.CURRENT_VERSION,
                                      write_guard=screen.admission_write_guard) is (count == 1)
        assert not state.visible.tk and not state.visible.web
        assert state.visible.preparations == [0] * count
    marker = json.loads((state.data / "shell-fallback.json").read_text(encoding="utf-8"))
    assert marker["version"] == ca.CURRENT_VERSION
    assert state.order.index("destroy") < state.order.index("notice") < state.order.index("before_exit") < state.order.index("exit")

    # A new manual process has a fresh admission latch; its persisted marker is
    # the real shell's marker, and its CA switch/entry path is left intact.
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)

    assert ca.main([]) == 0
    assert state.exits == [3, 3]
    assert state.visible.preparations == [0, 0, 1]
    assert state.visible.tk == 1 and state.visible.web == 0


def test_real_shell_runtime_missing_next_manual_start_is_tk(actual_shell, entry, monkeypatch):
    state = actual_shell
    class WebView2RuntimeNotFoundException(Exception):
        pass
    def missing(*_args, **_kwargs):
        state.visible.web = 1
        state.windows[-1].events.shown.fire()
        raise WebView2RuntimeNotFoundException()
    monkeypatch.setattr(sys.modules["webview"], "start", missing)
    ca.main([])
    assert state.exits == [3]
    retry = json.loads((state.data / "shell-start-retry.json").read_text(encoding="utf-8"))
    assert retry["cause"] == "RUNTIME_MISSING" and retry["count"] == 2
    assert state.host.web_allowed(state.data, ca.CURRENT_VERSION,
                                  write_guard=screen.admission_write_guard) is False
    # A new manual process has a fresh admission latch; its persisted marker is
    # the real shell's marker, and its CA switch/entry path is left intact.
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)

    assert ca.main([]) == 0
    assert state.visible.preparations == [0, 1]
    assert state.visible.tk == 1 and state.visible.web == 0


def test_real_shell_ready_returns_web_with_one_surface(actual_shell, entry):
    state = actual_shell
    state.mode = "ready"
    assert ca.main([]) == 0
    assert state.exits == []
    assert state.visible.preparations == [0]
    assert not (state.data / "shell-fallback.json").exists()


def test_real_shell_marker_version_change_uses_ca_write_guard(actual_shell, monkeypatch):
    state = actual_shell
    state.data.mkdir()
    marker = state.data / "shell-fallback.json"
    marker.write_text(json.dumps({"code": "SHELL_START_FAILED", "at": "owned-test-time", "version": "old"}), encoding="utf-8")
    calls = []

    @contextmanager
    def admission(source):
        calls.append(source)
        yield

    monkeypatch.setattr(screen, "writer_admission", admission)
    assert state.host.web_allowed(state.data, ca.CURRENT_VERSION,
                                  write_guard=screen.admission_write_guard) is True
    assert calls == ["screen_shell_fileio"]
    assert not marker.exists()


def test_shell_data_namespace_cannot_create_programdata_root(tmp_path, monkeypatch):
    program_data = tmp_path / "fake-program-data"
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.setenv("LOCALAPPDATA", str(program_data))
    with pytest.raises(ValueError, match="MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED"):
        screen.shell_data_dir()
    assert not (program_data / "KMTech").exists()


def test_ready_is_exact_accepted_bytes_and_no_relaunch_module():
    payload = (ROOT / "shell/SHELL-READY-v3.16.json").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == "a8183b660932778c08ebdf1ee24f137b4c2540a66207850afeff9990bbfb3198"
    ready = json.loads(payload)
    assert ready["version"] == "v3.16.3" and len(ready["files"]) == 19
    for row in ready["files"]:
        relative = Path(row["path"])
        assert relative.parts[0] == "shell-v3.16.3"
        source = (ROOT / "shell" / Path(*relative.parts[1:])).read_bytes()
        assert len(source) == row["bytes"]
        assert hashlib.sha256(source).hexdigest() == row["sha256"]
    assert not (ROOT / "relaunch_wait.py").exists()
    assert not (ROOT / "shell/relaunch_wait.py").exists()


def test_real_shell_defers_for_an_actual_registered_lane_then_exits(actual_shell, monkeypatch, caplog):
    state = actual_shell
    started, stop = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: (started.set(), stop.wait()), name="actual-app-lane")
    fence.start_lane_worker(worker)
    assert started.wait(1)
    calls = []

    def before_exit(code, deadline):
        drained = fence.close_and_wait_writers(0)
        calls.append((code, deadline, drained))
        if not drained:
            stop.set()
            worker.join(1)
            assert not worker.is_alive()
        return drained

    monkeypatch.setattr(state.host, "EXIT_POLL_S", 0)
    try:
        state.host._wait_before_exit(before_exit, "SHELL_START_FAILED")
    finally:
        stop.set()
        worker.join(1)
    assert calls == [("SHELL_START_FAILED", 120, False), ("SHELL_START_FAILED", 0, True)]
    assert "SHELL_EXIT_DEFERRED" in caplog.text


def test_real_os_notice_uses_ca_title_and_bounded_api(actual_shell, monkeypatch):
    import ctypes
    state = actual_shell
    calls = []

    class Notice:
        def __call__(self, parent, text, title, flags, language, timeout):
            calls.append((parent, title, flags, language, timeout))
            return 1

    monkeypatch.setattr(ctypes, "WinDLL",
                        lambda *_args, **_kwargs: SimpleNamespace(MessageBoxTimeoutW=Notice()))
    state.original_notice("이적")
    assert calls == [(None, "이적", 0x00040040, 0, 30000)]
