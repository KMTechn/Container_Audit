"""Current-user persistence for the Container_Audit DirectSync relay."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping, Sequence
import uuid

from direct_sync_auto_bootstrap import run_session_direct_sync_once
from direct_sync_auto_bootstrap import assert_runtime_state_outside_code_root
from runtime_instance import acquire_runtime_instance
from storage_policy import (
    build_container_audit_storage_paths,
    ensure_container_audit_storage_dirs,
)


USER_RELAY_MODE = "--container-audit-user-relay"
USER_RELAY_RUN_VALUE = "KMTech.ContainerAudit.Relay"
USER_RELAY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEFAULT_RETRY_INTERVAL_SECONDS = 30
MAX_RETRY_INTERVAL_SECONDS = 60
USER_RELAY_STATUS_NAME = "container_audit_user_relay.json"
USER_RELAY_STOP_NAME = "container_audit_user_relay.stop.json"


class UserRelayError(RuntimeError):
    """Raised when current-user relay persistence cannot be proven."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > 256 * 1024:
            return None
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def user_relay_status_path(direct_sync_root: str | os.PathLike[str]) -> Path:
    return Path(direct_sync_root).expanduser().resolve() / "status" / USER_RELAY_STATUS_NAME


def user_relay_stop_path(direct_sync_root: str | os.PathLike[str]) -> Path:
    return Path(direct_sync_root).expanduser().resolve() / "control" / USER_RELAY_STOP_NAME


def build_user_relay_command(app_root: str | os.PathLike[str]) -> list[str]:
    root = Path(app_root).expanduser().resolve()
    application_exe = root / "Container_Audit.exe"
    if application_exe.is_file():
        return [str(application_exe), USER_RELAY_MODE]
    source_entrypoint = root / "Container_Audit.py"
    if source_entrypoint.is_file() and not getattr(sys, "frozen", False):
        return [sys.executable, str(source_entrypoint), USER_RELAY_MODE]
    raise UserRelayError("the hardened Container_Audit relay host is unavailable")


def user_relay_command_line(app_root: str | os.PathLike[str]) -> str:
    return subprocess.list2cmdline(build_user_relay_command(app_root))


def _registry_set(value: str) -> None:
    if os.name != "nt":
        raise UserRelayError("HKCU relay persistence is available only on Windows")
    import winreg

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        USER_RELAY_RUN_KEY,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
    ) as key:
        winreg.SetValueEx(key, USER_RELAY_RUN_VALUE, 0, winreg.REG_SZ, value)


def _registry_get() -> str:
    if os.name != "nt":
        raise UserRelayError("HKCU relay persistence is available only on Windows")
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            USER_RELAY_RUN_KEY,
            0,
            winreg.KEY_QUERY_VALUE,
        ) as key:
            value, value_type = winreg.QueryValueEx(key, USER_RELAY_RUN_VALUE)
    except FileNotFoundError:
        return ""
    if value_type != winreg.REG_SZ:
        raise UserRelayError("the HKCU relay value has an unexpected registry type")
    return str(value)


def _registry_delete() -> None:
    if os.name != "nt":
        raise UserRelayError("HKCU relay persistence is available only on Windows")
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            USER_RELAY_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.DeleteValue(key, USER_RELAY_RUN_VALUE)
    except FileNotFoundError:
        return


def install_user_relay_autostart(
    app_root: str | os.PathLike[str],
    *,
    setter: Callable[[str], None] | None = None,
    getter: Callable[[], str] | None = None,
) -> dict[str, Any]:
    command_line = user_relay_command_line(app_root)
    (setter or _registry_set)(command_line)
    readback = (getter or _registry_get)()
    if readback != command_line:
        raise UserRelayError("HKCU relay persistence exact readback failed")
    return {
        "status": "PASS",
        "principal": "current_user",
        "registry_hive": "HKEY_CURRENT_USER",
        "registry_key": USER_RELAY_RUN_KEY,
        "registry_value": USER_RELAY_RUN_VALUE,
        "command": command_line,
    }


def remove_user_relay_autostart(
    *,
    deleter: Callable[[], None] | None = None,
    getter: Callable[[], str] | None = None,
) -> dict[str, Any]:
    (deleter or _registry_delete)()
    readback = (getter or _registry_get)()
    if readback:
        raise UserRelayError("HKCU relay persistence removal readback failed")
    return {
        "status": "ABSENT",
        "registry_hive": "HKEY_CURRENT_USER",
        "registry_key": USER_RELAY_RUN_KEY,
        "registry_value": USER_RELAY_RUN_VALUE,
    }


def start_user_relay_process(
    app_root: str | os.PathLike[str],
    *,
    launcher: Callable[[Sequence[str]], Any] | None = None,
) -> dict[str, Any]:
    command = build_user_relay_command(app_root)
    if launcher is not None:
        launched = launcher(command)
        return {"status": "START_REQUESTED", "launcher_result": launched}
    if os.name != "nt":
        return {"status": "NOT_TESTED", "reason": "Windows-only user relay launch"}
    creation_flags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )
    process = subprocess.Popen(
        command,
        cwd=str(Path(app_root).expanduser().resolve()),
        close_fds=True,
        creationflags=creation_flags,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if process.pid <= 0:
        raise UserRelayError("current-user relay launch did not return a process id")
    return {"status": "START_REQUESTED", "process_id": process.pid}


def _wait_with_stop_checks(
    seconds: float,
    stop_requested: Callable[[], bool],
    wait: Callable[[float], None],
) -> bool:
    remaining = max(0.0, float(seconds))
    while remaining > 0:
        if stop_requested():
            return True
        current = min(1.0, remaining)
        wait(current)
        remaining -= current
    return stop_requested()


def run_persistent_relay_loop(
    run_cycle: Callable[[], Mapping[str, Any]],
    *,
    status_path: str | os.PathLike[str],
    interval_seconds: int = DEFAULT_RETRY_INTERVAL_SECONDS,
    stop_requested: Callable[[], bool] | None = None,
    wait: Callable[[float], None] = time.sleep,
    max_cycles: int | None = None,
) -> dict[str, Any]:
    interval = int(interval_seconds)
    if interval < 0 or interval > MAX_RETRY_INTERVAL_SECONDS:
        raise ValueError("user relay retry interval must be between 0 and 60 seconds")
    if max_cycles is not None and int(max_cycles) < 1:
        raise ValueError("max_cycles must be positive when supplied")
    selected_status_path = Path(status_path).expanduser().resolve()
    should_stop = stop_requested or (lambda: False)
    cycle_count = 0
    last_cycle: dict[str, Any] = {"status": "NOT_TESTED"}
    while not should_stop():
        cycle_count += 1
        try:
            raw_cycle = run_cycle()
            cycle = dict(raw_cycle) if isinstance(raw_cycle, Mapping) else {}
            observed_status = str(cycle.get("status") or "").strip()
            if not observed_status:
                cycle["status"] = "UNKNOWN"
                cycle["reason"] = "relay cycle returned no status value"
        except Exception as exc:
            cycle = {
                "status": "UNKNOWN",
                "reason": "relay cycle did not return a result",
                "error_type": exc.__class__.__name__,
            }
        last_cycle = cycle
        report = {
            "report_version": "container-audit-user-relay-v1",
            "status": "RUNNING",
            "principal": "current_user",
            "persistent_retry": True,
            "retry_interval_seconds": interval,
            "cycle_count": cycle_count,
            "last_cycle": cycle,
            "updated_at": _now(),
        }
        _write_json_atomic(selected_status_path, report)
        if max_cycles is not None and cycle_count >= int(max_cycles):
            break
        if _wait_with_stop_checks(interval, should_stop, wait):
            break
    final = {
        "report_version": "container-audit-user-relay-v1",
        "status": "STOPPED" if should_stop() else "COMPLETED",
        "principal": "current_user",
        "persistent_retry": True,
        "retry_interval_seconds": interval,
        "cycle_count": cycle_count,
        "last_cycle": last_cycle,
        "updated_at": _now(),
    }
    _write_json_atomic(selected_status_path, final)
    return final


def _runtime_cycle(
    *,
    app_root: Path,
    direct_sync_root: Path,
    scan_source_dir: Path,
) -> dict[str, Any]:
    process_result = run_session_direct_sync_once(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=scan_source_dir,
        reason="PERSISTENT_USER_RELAY",
        timeout_seconds=45,
    )
    runtime_status = _read_json(
        direct_sync_root / "status" / "direct_sync_relay_status.json"
    )
    process_status = str(process_result.get("status") or "").strip() or "UNKNOWN"
    relay_status = (
        str((runtime_status or {}).get("status") or "").strip() or "UNKNOWN"
    )
    return {
        "status": relay_status if process_status == "PASS" else process_status,
        "process_status": process_status,
        "process_returncode": process_result.get("returncode", "UNKNOWN"),
        "relay_status": relay_status,
    }


def request_user_relay_stop(
    direct_sync_root: str | os.PathLike[str],
    *,
    timeout_seconds: float = 10.0,
    wait: Callable[[float], None] = time.sleep,
    lease_factory: Callable[[str | os.PathLike[str]], Any] = acquire_runtime_instance,
) -> dict[str, Any]:
    root = Path(direct_sync_root).expanduser().resolve()
    stop_path = user_relay_stop_path(root)
    request_id = uuid.uuid4().hex
    _write_json_atomic(
        stop_path,
        {
            "schema_version": "container-audit-user-relay-stop-v1",
            "request_id": request_id,
            "requested_at": _now(),
        },
    )
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    lease_key = root / "user-relay-instance"
    while True:
        lease = lease_factory(lease_key)
        if lease is not None:
            lease.release()
            return {
                "status": "ABSENT",
                "request_id": request_id,
                "stop_request_path": str(stop_path),
            }
        if time.monotonic() >= deadline:
            return {
                "status": "UNKNOWN",
                "request_id": request_id,
                "stop_request_path": str(stop_path),
                "reason": "relay process absence was not proven before timeout",
            }
        wait(0.25)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Container_Audit current-user persistent relay")
    parser.add_argument("--app-root", default="")
    parser.add_argument("--direct-sync-root", default="")
    parser.add_argument("--scan-source-dir", default="")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_RETRY_INTERVAL_SECONDS,
    )
    parser.add_argument("--once", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app_root = Path(
        args.app_root
        or (
            Path(sys.executable).parent
            if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parent
        )
    ).expanduser().resolve()
    storage = build_container_audit_storage_paths(application_path=str(app_root))
    ensure_container_audit_storage_dirs(storage)
    direct_sync_root = (
        Path(args.direct_sync_root).expanduser().resolve()
        if args.direct_sync_root
        else storage.direct_sync_root
    )
    scan_source_dir = (
        Path(args.scan_source_dir).expanduser().resolve()
        if args.scan_source_dir
        else storage.events_dir
    )
    assert_runtime_state_outside_code_root(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=scan_source_dir,
    )
    direct_sync_root.mkdir(parents=True, exist_ok=True)
    scan_source_dir.mkdir(parents=True, exist_ok=True)
    stop_path = user_relay_stop_path(direct_sync_root)
    if stop_path.exists():
        return 0
    lease = acquire_runtime_instance(direct_sync_root / "user-relay-instance")
    if lease is None:
        return 0
    try:
        result = run_persistent_relay_loop(
            lambda: _runtime_cycle(
                app_root=app_root,
                direct_sync_root=direct_sync_root,
                scan_source_dir=scan_source_dir,
            ),
            status_path=user_relay_status_path(direct_sync_root),
            interval_seconds=args.interval_seconds,
            stop_requested=stop_path.exists,
            max_cycles=1 if args.once else None,
        )
    finally:
        lease.release()
    last_status = str((result.get("last_cycle") or {}).get("status") or "UNKNOWN")
    return 1 if last_status in {"FAIL", "UNKNOWN", "runtime_error"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
