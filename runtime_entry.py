"""Admission before application imports; only standard-library dependencies."""
from __future__ import annotations

import argparse
import atexit
import json
import os
from pathlib import Path
import threading

import runtime_instance_win32 as native
from storage_policy import build_container_audit_storage_paths, current_user_data_home, _is_machine_runtime_directory

APP_TITLE = "이적"
NON_GUI_MODES = frozenset({
    "--container-audit-direct-sync-relay", "--container-audit-user-relay", "--onboard-current-user",
    "--remove-current-user-setup", "--restore-current-user-lifecycle-after-replacement",
    "--zero-pe-portable-smoke", "--help", "-h",
})
STATE_NOTICES = {
    "starting": "프로그램이 켜지는 중입니다 · 잠시 기다려 주세요",
    "closing": "프로그램을 닫는 중입니다 · 잠시 뒤 다시 누르세요",
    "running": "프로그램이 이미 켜져 있습니다 · 잠시 뒤 다시 누르세요",
}
_LOCK = threading.RLock()
_ENTRY = None


def instance_marker_path(data_root) -> Path:
    home = (current_user_data_home() / "KMTech" / "ContainerAudit").resolve(strict=False)
    if _is_machine_runtime_directory(home, os.environ):
        raise ValueError("instance marker must remain in user storage")
    digest = native.runtime_mutex_name(data_root).rsplit(".", 1)[-1]
    return home / f"instance-{digest}.json"


def read_instance_marker(data_root) -> dict | None:
    try:
        path = instance_marker_path(data_root)
        if path.is_symlink() or path.stat().st_size > 4096:
            return None
        with path.open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            return None
        record = json.loads(data)
        if (not isinstance(record, dict) or set(record) != {"pid", "exe", "started_at", "state"}
                or type(record["pid"]) is not int or not 0 < record["pid"] <= 0xFFFFFFFF
                or not isinstance(record["exe"], str) or not record["exe"] or "\0" in record["exe"]
                or type(record["started_at"]) is not int or record["started_at"] <= 0
                or record["state"] not in STATE_NOTICES):
            return None
        return record
    except (OSError, ValueError, TypeError, KeyError):
        return None


def trusted_instance_marker(data_root) -> dict | None:
    record = read_instance_marker(data_root)
    if record is None:
        return None
    try:
        identity = native.process_identity(record["pid"])
        if (identity is not None and identity["started_at"] == record["started_at"]
                and os.path.normcase(identity["exe"]) == os.path.normcase(record["exe"])):
            return record
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return None


def activate_existing_instance(data_root) -> int:
    record = trusted_instance_marker(data_root)
    windows = []
    if record is not None:
        try:
            windows = native.visible_top_level_windows(record["pid"])
        except (OSError, ValueError, TypeError):
            pass
    if windows:
        window = next((hwnd for hwnd, kind in windows if kind == "web"), windows[0][0])
        try:
            native.activate_window(window)
        except (OSError, ValueError, TypeError):
            pass  # A found window never opens a second notice or GUI.
        return 0
    state = record["state"] if record is not None else "running"
    try:
        native.timed_notice(STATE_NOTICES[state], APP_TITLE, native.MB_OK, native.NOTICE_TIMEOUT_MS)
    except (OSError, ValueError, TypeError, AttributeError):
        pass  # There is no blocking MessageBox/Tk fallback.
    return 0


class _Entry:
    def __init__(self, root, lease):
        self.root = root
        self.lease = lease
        try:
            self.identity = native.process_identity(os.getpid())
        except (OSError, ValueError, TypeError, AttributeError):
            self.identity = None
        self.state = "starting"
        self.borrowers = 0
        self.end_requested = False


def _publish(entry) -> None:
    if entry.identity is None:
        return
    try:
        from runtime_instance import _write_entry_marker
        _write_entry_marker(entry)
    except (OSError, ValueError):
        pass  # Missing advisory metadata cannot create a second owner.


def begin_gui_entry(arguments, *, application_path=None) -> bool:
    global _ENTRY
    if (arguments and arguments[0] in NON_GUI_MODES) or "--zero-pe-portable-smoke" in arguments:
        return True
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--data-root", default=None)
    try:
        options, _ = parser.parse_known_args(arguments)
        root = build_container_audit_storage_paths(application_path=application_path, data_root=options.data_root).data_root
    except (OSError, ValueError, SystemExit):
        return True  # The existing startup path retains its data-root refusal.
    with _LOCK:
        if _ENTRY is not None:
            if native.runtime_mutex_name(root) != _ENTRY.lease.mutex_name:
                raise ValueError("data root changed after instance admission")
            return True
        lease = native.acquire_runtime_instance(root)
        if lease is None:
            activate_existing_instance(root)
            return False
        _ENTRY = _Entry(root, lease)
        atexit.register(end_gui_entry, force=True)
        _publish(_ENTRY)
        return True


def set_gui_state(state) -> None:
    with _LOCK:
        if _ENTRY is None or state not in STATE_NOTICES:
            return
        order = {"starting": 0, "running": 1, "closing": 2}
        if order[state] <= order[_ENTRY.state]:
            return
        _ENTRY.state = state
        _publish(_ENTRY)


class _BorrowedLease:
    def __init__(self, entry):
        self.entry = entry
        self._released = False

    def release(self):
        with _LOCK:
            if self._released:
                return
            self._released = True
            self.entry.borrowers -= 1
            if self.entry.end_requested and self.entry.borrowers == 0:
                _finish(self.entry)


def entry_runtime_instance(data_root):
    with _LOCK:
        if _ENTRY is None:
            # Library callers retain the existing lease API.
            return native.acquire_runtime_instance(data_root)
        if native.runtime_mutex_name(data_root) != _ENTRY.lease.mutex_name:
            raise ValueError("data root changed after instance admission")
        _ENTRY.borrowers += 1
        return _BorrowedLease(_ENTRY)


def _finish(entry):
    global _ENTRY
    try:
        from runtime_instance import _clear_entry_marker
        _clear_entry_marker(entry)
    except (OSError, ValueError):
        pass
    finally:
        entry.lease.release()
        if _ENTRY is entry:
            _ENTRY = None


def end_gui_entry(*, force=False):
    with _LOCK:
        if _ENTRY is None:
            return
        _ENTRY.end_requested = True
        if force or _ENTRY.borrowers == 0:
            _finish(_ENTRY)
