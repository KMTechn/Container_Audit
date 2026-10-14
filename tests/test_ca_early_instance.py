"""Actual entry sources with only the native boundary replaced; no GUI."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import runtime_entry as entry
import runtime_instance_win32 as native
import storage_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def user_root(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "machine"))
    monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    monkeypatch.setattr(storage_policy, "_persisted_data_root", lambda: None)
    monkeypatch.setattr(entry, "_ENTRY", None)
    root = tmp_path / "data"
    identity = {"exe": str(tmp_path / "runtime/pythonw.exe"), "started_at": 123456}
    monkeypatch.setattr(native, "process_identity", lambda pid: dict(identity))
    yield root, identity
    entry.end_gui_entry(force=True)


def _record(root, identity, state="running"):
    path = entry.instance_marker_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"pid": 123, **identity, "state": state}), encoding="utf-8")
    return path


@pytest.mark.parametrize("kind", ["web", "tk", "other"])
def test_visible_existing_web_tk_or_preparation_is_activated_without_notice(user_root, monkeypatch, kind):
    root, identity = user_root
    _record(root, identity)
    calls = []
    monkeypatch.setattr(native, "visible_top_level_windows", lambda pid: [(45, kind)])
    monkeypatch.setattr(native, "activate_window", calls.append)
    monkeypatch.setattr(native, "timed_notice", lambda *a: pytest.fail("found window opened a notice"))
    assert entry.activate_existing_instance(root) == 0
    assert calls == [45]


def test_web_window_is_preferred_to_other_visible_windows(user_root, monkeypatch):
    root, identity = user_root
    _record(root, identity)
    calls = []
    monkeypatch.setattr(native, "visible_top_level_windows", lambda pid: [(1, "tk"), (2, "other"), (3, "web")])
    monkeypatch.setattr(native, "activate_window", calls.append)
    assert entry.activate_existing_instance(root) == 0
    assert calls == [3]


@pytest.mark.parametrize("state", ["starting", "running", "closing"])
def test_no_window_has_the_exact_state_notice_title_ok_and_five_seconds(user_root, monkeypatch, state):
    root, identity = user_root
    _record(root, identity, state)
    calls = []
    monkeypatch.setattr(native, "visible_top_level_windows", lambda pid: [])
    monkeypatch.setattr(native, "timed_notice", lambda *args: calls.append(args))
    assert entry.activate_existing_instance(root) == 0
    expected = {"starting": "프로그램이 켜지는 중입니다 · 잠시 기다려 주세요",
                "closing": "프로그램을 닫는 중입니다 · 잠시 뒤 다시 누르세요",
                "running": "프로그램이 이미 켜져 있습니다 · 잠시 뒤 다시 누르세요"}[state]
    assert calls == [(expected, "이적", 0, 5000)]


@pytest.mark.parametrize("stale", ["dead", "exe", "started_at", "missing"])
def test_stale_or_missing_record_is_not_used_to_activate_a_window(user_root, monkeypatch, stale):
    root, identity = user_root
    if stale != "missing":
        _record(root, identity, "starting")
    if stale == "dead":
        monkeypatch.setattr(native, "process_identity", lambda pid: None)
    elif stale in {"exe", "started_at"}:
        other = dict(identity)
        other[stale] = "other.exe" if stale == "exe" else identity[stale] + 1
        monkeypatch.setattr(native, "process_identity", lambda pid: other)
    calls = []
    monkeypatch.setattr(native, "visible_top_level_windows", lambda pid: pytest.fail("stale PID was trusted"))
    monkeypatch.setattr(native, "timed_notice", lambda *args: calls.append(args))
    assert entry.activate_existing_instance(root) == 0
    assert calls == [("프로그램이 이미 켜져 있습니다 · 잠시 뒤 다시 누르세요", "이적", 0, 5000)]


def test_first_owner_atomic_state_and_borrowed_lease_survive_until_shutdown(user_root, monkeypatch):
    root, identity = user_root
    lease = native.RuntimeInstanceLease(native.runtime_mutex_name(root), 0)
    calls = []
    monkeypatch.setattr(native, "acquire_runtime_instance", lambda path: calls.append(path) or lease)
    assert entry.begin_gui_entry(["--data-root", str(root)], application_path=str(ROOT))
    marker = entry.instance_marker_path(root)
    assert json.loads(marker.read_bytes()) == {"pid": os.getpid(), **identity, "state": "starting"}
    assert not list(marker.parent.glob(marker.name + ".*.tmp"))
    assert entry.begin_gui_entry(["--data-root", str(root)], application_path=str(ROOT))
    assert len(calls) == 1
    loan = entry.entry_runtime_instance(root)
    entry.set_gui_state("running")
    entry.set_gui_state("closing")
    entry.set_gui_state("running")
    assert json.loads(marker.read_bytes())["state"] == "closing"
    entry.end_gui_entry()
    assert marker.exists() and not lease._released
    loan.release()
    assert not marker.exists() and lease._released


def test_marker_cleanup_does_not_require_business_writer_admission_after_exit(user_root, monkeypatch):
    import writer_session_fence as fence
    root, _ = user_root
    monkeypatch.setattr(native, "acquire_runtime_instance", lambda path: native.RuntimeInstanceLease(native.runtime_mutex_name(path), 0))
    assert entry.begin_gui_entry(["--data-root", str(root)])
    marker = entry.instance_marker_path(root)
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", True)
    entry.set_gui_state("closing")
    assert json.loads(marker.read_bytes())["state"] == "closing"
    entry.end_gui_entry()
    assert not marker.exists()


class _Function:
    def __init__(self, function):
        self.function = function
    def __call__(self, *args):
        return self.function(*args)


def test_native_window_enumeration_uses_pid_visibility_and_class_without_titles(monkeypatch):
    owners = {11: 123, 12: 999, 13: 123, 14: 123, 15: 123}
    classes = {11: "TkTopLevel", 14: "WindowsForms10.Window", 15: "PreparationWindow"}
    def owner(hwnd, output):
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = owners[hwnd]
        return 1
    def window_class(hwnd, output, size):
        output.value = classes[hwnd]
        return len(output.value)
    def enumerate_windows(callback, parameter):
        for hwnd in owners:
            assert callback(hwnd, parameter)
        return True
    api = SimpleNamespace(EnumWindows=_Function(enumerate_windows),
        GetWindowThreadProcessId=_Function(owner),
        IsWindowVisible=_Function(lambda hwnd: hwnd != 13),
        GetClassNameW=_Function(window_class))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: api)
    assert native.visible_top_level_windows(123) == [(11, "tk"), (14, "web"), (15, "other")]


@pytest.mark.parametrize("live", [True, False])
def test_native_process_identity_reads_image_and_creation_time_only_for_live_pid(monkeypatch, live):
    closed = []
    def image(handle, flags, output, size):
        output.value = "X:/isolated/pythonw.exe"
        return True
    def times(handle, created, *unused):
        value = ctypes.cast(created, ctypes.POINTER(wintypes.FILETIME)).contents
        value.dwHighDateTime, value.dwLowDateTime = 2, 3
        return True
    api = SimpleNamespace(OpenProcess=_Function(lambda access, inherit, pid: 42),
        WaitForSingleObject=_Function(lambda handle, timeout: native.WAIT_TIMEOUT if live else 0),
        QueryFullProcessImageNameW=_Function(image), GetProcessTimes=_Function(times),
        CloseHandle=_Function(closed.append))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: api)
    assert native.process_identity(123) == ({"exe": "X:/isolated/pythonw.exe", "started_at": (2 << 32) | 3} if live else None)
    assert closed == [42]


@pytest.mark.parametrize("minimized,foreground", [(False, True), (True, True), (True, False)])
def test_native_restore_foreground_and_flash_boundary(monkeypatch, minimized, foreground):
    events = []
    api = SimpleNamespace(IsIconic=_Function(lambda hwnd: minimized),
        ShowWindow=_Function(lambda hwnd, command: events.append(("restore", hwnd, command))),
        SetForegroundWindow=_Function(lambda hwnd: events.append(("foreground", hwnd)) or foreground),
        FlashWindowEx=_Function(lambda info: events.append(("flash", ctypes.cast(info, ctypes.POINTER(wintypes.UINT))[0]))))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: api)
    native.activate_window(99)
    assert events[0] == (("restore", 99, 9) if minimized else ("foreground", 99))
    assert any(event[0] == "flash" for event in events) is (not foreground)


@pytest.mark.parametrize("source", ["portable/main.py", "Container_Audit.py"])
@pytest.mark.parametrize("arguments", [[], ["--ui", "tk"], ["--old-screen"]])
def test_actual_cold_second_entry_exits_before_heavy_imports(user_root, tmp_path, source, arguments):
    root, _ = user_root
    script = tmp_path / "cold-entry.py"
    receipt = tmp_path / "entry-result.json"
    script.write_text('''import importlib.abc, json, pathlib, runpy, sys
repo, source, receipt, root, arguments = sys.argv[1:]
sys.path.insert(0, repo)
import runtime_instance_win32 as native
native.known_program_data = lambda: pathlib.Path(__import__("os").environ["PROGRAMDATA"])
import storage_policy
storage_policy._persisted_data_root = lambda: None
events = {"acquired": 0, "heavy": [], "notice": 0, "exit": None}
def acquire(path):
    events["acquired"] += 1
    return None
native.acquire_runtime_instance = acquire
native.process_identity = lambda pid: None
native.timed_notice = lambda *args: events.__setitem__("notice", events["notice"] + 1)
class NoHeavy(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"Container_Audit", "tkinter", "requests", "shell", "host", "auto_update", "writer_session_fence"}:
            events["heavy"].append(fullname)
            raise AssertionError("second entry attempted heavy import")
sys.meta_path.insert(0, NoHeavy())
sys.argv = [source, "--data-root", root, *json.loads(arguments)]
try:
    runpy.run_path(str(pathlib.Path(repo) / source), run_name="__main__")
except SystemExit as done:
    events["exit"] = done.code
pathlib.Path(receipt).write_text(json.dumps(events), encoding="utf-8")
''', encoding="utf-8")
    result = subprocess.run([sys.executable, "-B", str(script), str(ROOT), source, str(receipt), str(root), json.dumps(arguments)],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    assert json.loads(receipt.read_bytes()) == {"acquired": 1, "heavy": [], "notice": 1, "exit": 0}
