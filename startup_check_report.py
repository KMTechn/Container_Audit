"""Best-effort non-authoritative startup result; never add a launch refusal."""
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from threading import Thread
import uuid

from startup_check import REASON_CATEGORIES, startup_result
from writer_session_fence import _assert_no_reparse_components, writer_sink

NOTICE = "이 PC 는 지금 새 프로그램을 열 수 없습니다. 관리자에게 알렸습니다. 다른 작업대로 옮겨 주세요."
_STATE = ContextVar("container_start_check_report", default=None)
_GUI_READY_STARTED = False


def begin(version, *, enabled=True):
    _STATE.set(None)
    if not enabled:
        return
    category = os.environ.get("KMTECH_START_CHECK_TEST_CATEGORY", "")
    state = {"version": version, "build_sha": "", "reasons": [], "revision": 0,
             "published": -1, "forced": category if "TEST_" + category in REASON_CATEGORIES else ""}
    _STATE.set(state)


def note(reason):
    state = _STATE.get()
    if state is not None and reason not in state["reasons"]:
        state["reasons"].append(reason)
        state["revision"] += 1


def release_identity(release):
    state = _STATE.get()
    if state is not None:
        identity = (release.get("version", state["version"]), release.get("build_id", ""))
        if identity != (state["version"], state["build_sha"]):
            state["version"], state["build_sha"] = identity
            state["revision"] += 1


def gui_identity(version):
    state = _STATE.get() or {}
    return state.get("version") or version, state.get("build_sha", "")


def gui_ready(version, build_sha):
    """Queue one best-effort marker; never wait for native queries or disk I/O."""
    global _GUI_READY_STARTED
    if _GUI_READY_STARTED:
        return
    try:
        ready_at = startup_result()["checked_at"]
        _GUI_READY_STARTED = True
        Thread(target=_publish_gui_ready, args=(version, build_sha, ready_at),
               name="startup-gui-ready-report", daemon=True).start()
    except Exception:
        _GUI_READY_STARTED = False


def _publish_gui_ready(version, build_sha, ready_at):
    try:
        _write_gui_ready(version, build_sha, ready_at)
    except Exception:
        pass


def _process_start_utc():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(created),
                                  ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)):
        raise OSError("process creation time unavailable")
    ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
    return (datetime(1601, 1, 1, tzinfo=timezone.utc) +
            timedelta(microseconds=ticks // 10)).isoformat(timespec="microseconds")


def publish(reason=None, *, refused=False):
    state = _STATE.get()
    if state is None:
        return False
    try:
        if reason:
            note(reason)
        if state["published"] != state["revision"] or refused:
            reasons = ["TEST_" + state["forced"]] if state["forced"] else state["reasons"]
            result = startup_result(state["version"], state["build_sha"], reasons)
            state["published"] = state["revision"] if _write_result(result) else -1
        return bool(refused and state["published"] == state["revision"])
    except Exception:
        return False


def finish(reason=None, *, refused=False, failed=False):
    try:
        state = _STATE.get()
        if failed and state is not None and not any(
                REASON_CATEGORIES.get(item, "UNKNOWN") != "ALREADY_RUNNING" for item in state["reasons"]):
            note("UNKNOWN_CHECK")
        return publish(reason, refused=refused)
    finally:
        _STATE.set(None)


def observe(action, *args, **kwargs):
    try:
        if action == "begin":
            return begin(*args, **kwargs)
        if action == "note":
            return note(*args, **kwargs)
        if action == "release_identity":
            return release_identity(*args, **kwargs)
        if action == "gui_identity":
            return gui_identity(*args, **kwargs)
        if action == "gui_ready":
            return gui_ready(*args, **kwargs)
        if action == "publish":
            return publish(*args, **kwargs)
        if action == "finish":
            return finish(*args, **kwargs)
        raise ValueError("unknown report observation")
    except Exception:
        state = _STATE.get()
        if state is None and action == "begin" and kwargs.get("enabled", True):
            _STATE.set({"version": "", "build_sha": "", "reasons": [], "revision": 0,
                        "published": -1, "forced": ""})
        note("UNKNOWN_CHECK")
        return False


@writer_sink("startup_check_report", report_only=True)
def _write_result(result):
    temporary = None
    try:
        program_data = Path(os.environ["PROGRAMDATA"])
        if not program_data.is_absolute():
            return False
        folder = program_data / "KMTech/start-check"
        if not folder.is_dir():
            return False
        _assert_no_reparse_components(folder)
        # Rebuild the public envelope: discard any unapproved raw fields.
        result = startup_result(result["version"], result["build_sha"], result["reasons"])
        destination = folder / (result["checked_at"][:10].replace("-", "") + "-CA.json")
        _assert_no_reparse_components(destination)
        temporary = folder / ("." + destination.name + "." + uuid.uuid4().hex + ".tmp")
        payload = (json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload.decode("ascii"))
        os.replace(temporary, destination)
        _assert_no_reparse_components(destination)
        with destination.open("rb") as stream:
            return stream.read(len(payload) + 1) == payload
    except Exception:
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


@writer_sink("startup_gui_ready", report_only=True)
def _write_gui_ready(version, build_sha, ready_at):
    temporary = None
    try:
        program_data = Path(os.environ["PROGRAMDATA"])
        if not program_data.is_absolute():
            return
        folder = program_data / "KMTech/start-check"
        if not folder.is_dir():
            return
        _assert_no_reparse_components(folder)
        timestamp = datetime.fromisoformat(ready_at)
        if timestamp.utcoffset() != timedelta(hours=9):
            return
        ready_at = timestamp.isoformat(timespec="seconds")
        identity = startup_result(version, build_sha)
        payload = {"schema": "app_gui_ready.v1", "app": "CA",
                   "version": identity["version"], "build_sha": identity["build_sha"],
                   "pid": os.getpid(), "process_start_utc": _process_start_utc(), "ready_at": ready_at}
        destination = folder / (ready_at[:10].replace("-", "") + "-CA.gui.json")
        _assert_no_reparse_components(destination)
        temporary = folder / ("." + destination.name + "." + uuid.uuid4().hex + ".tmp")
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
        os.replace(temporary, destination)
    except Exception:
        pass
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
