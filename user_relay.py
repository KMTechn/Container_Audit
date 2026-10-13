"""Current-user persistence for the Container_Audit DirectSync relay."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import ntpath
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
    DATA_ROOT_ENV,
    build_container_audit_storage_paths,
    ensure_container_audit_storage_dirs,
    notify_data_root_error as _notify_data_root_error,
    validate_existing_data_root,
)
from writer_session_fence import WriterFenceError, writer_admission, writer_sink
from kmtech_shared import data_generation as generation


USER_RELAY_MODE = "--container-audit-user-relay"
USER_RELAY_RUN_VALUE = "KMTech.ContainerAudit.Relay"
USER_RELAY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEFAULT_RETRY_INTERVAL_SECONDS = 30
MAX_RETRY_INTERVAL_SECONDS = 60
USER_RELAY_STATUS_NAME = "container_audit_user_relay.json"
USER_RELAY_STOP_NAME = "container_audit_user_relay.stop.json"
APP_STOP_NAME = "container_audit_app.stop.json"
APP_STOP_SCHEMA = "container-audit-app-stop-v1"


class UserRelayError(RuntimeError):
    """Raised when current-user relay persistence cannot be proven."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@writer_sink("persistent_relay_status")
def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    from auto_update import assert_machine_metadata_no_secrets
    encoded = json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert_machine_metadata_no_secrets(encoded)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
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


def app_stop_path(direct_sync_root: str | os.PathLike[str]) -> Path:
    return user_relay_stop_path(direct_sync_root).with_name(APP_STOP_NAME)


def read_app_stop_request(direct_sync_root: str | os.PathLike[str]) -> dict[str, Any] | None:
    path = app_stop_path(direct_sync_root)
    try:
        if path.stat().st_size > 2048:
            return None
    except OSError:
        return None
    request = _read_json(path)
    if request is None or request.get("schema_version") != APP_STOP_SCHEMA:
        return None
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or len(request_id) != 32:
        return None
    if any(character not in "0123456789abcdef" for character in request_id):
        return None
    try:
        requested_at = datetime.fromisoformat(request["requested_at"])
    except (KeyError, TypeError, ValueError):
        return None
    if requested_at.tzinfo is None:
        return None
    return request


@writer_sink("persistent_relay_status")
def consume_app_stop_request(direct_sync_root: str | os.PathLike[str], request_id: str) -> None:
    request = read_app_stop_request(direct_sync_root)
    if request is not None and request["request_id"] == request_id:
        app_stop_path(direct_sync_root).unlink(missing_ok=True)


def relay_data_root_arguments(
    app_root: str | os.PathLike[str], *, environ: Mapping[str, str] | None = None,
) -> list[str]:
    values = os.environ if environ is None else environ
    storage = build_container_audit_storage_paths(
        application_path=str(app_root), environ=values,
    )
    return ["--data-root", str(storage.data_root)] if storage.custom_data_root else []


def build_user_relay_command(
    app_root: str | os.PathLike[str], *, environ: Mapping[str, str] | None = None,
) -> list[str]:
    root = Path(app_root).expanduser().resolve()
    root_arguments = relay_data_root_arguments(root, environ=environ)
    from auto_update import control_root

    control = control_root(root)
    if control is not None:
        bootstrap = control.parent / "current"
        return [str(bootstrap / "runtime/pythonw.exe"), "-I", "-B", str(bootstrap / "app/auto_update.py"), "--bootstrap", "--role", "relay", "--", USER_RELAY_MODE, *root_arguments]
    application_exe = root / "Container_Audit.exe"
    if application_exe.is_file():
        return [str(application_exe), USER_RELAY_MODE, *root_arguments]
    portable_entrypoint = root / "main.py"
    if portable_entrypoint.is_file() and not getattr(sys, "frozen", False):
        return [
            sys.executable,
            "-I",
            "-B",
            str(portable_entrypoint),
            USER_RELAY_MODE,
            *root_arguments,
        ]
    source_entrypoint = root / "Container_Audit.py"
    if source_entrypoint.is_file() and not getattr(sys, "frozen", False):
        return [sys.executable, str(source_entrypoint), USER_RELAY_MODE, *root_arguments]
    raise UserRelayError("the hardened Container_Audit relay host is unavailable")


def user_relay_command_line(
    app_root: str | os.PathLike[str], *, environ: Mapping[str, str] | None = None,
) -> str:
    return subprocess.list2cmdline(build_user_relay_command(app_root, environ=environ))


@writer_sink("persistent_relay_registry")
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


@writer_sink("persistent_relay_registry")
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


@writer_sink("user_relay_autostart_install")
def install_user_relay_autostart(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    setter: Callable[[str], None] | None = None,
    getter: Callable[[], str] | None = None,
) -> dict[str, Any]:
    command_line = user_relay_command_line(app_root, environ=environ)
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


@writer_sink("user_relay_autostart_remove")
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


@writer_sink("persistent_relay_process_start")
def start_user_relay_process(
    app_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    launcher: Callable[[Sequence[str]], Any] | None = None,
) -> dict[str, Any]:
    if installation_relay_start_deferred():
        return {"status": "DEFERRED_CANONICAL_RELEASE", "process_id": 0}
    command = build_user_relay_command(app_root, environ=environ)
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


def installation_relay_start_deferred() -> bool:
    """Only an admitted INSTALLING delegation can defer its initial relay.

    The installer releases the live fence and starts the normal user Run
    launcher itself; neither an elevated bootstrap nor a temporary launcher
    PID constitutes resident relay proof.
    """
    import writer_session_fence as fence

    with writer_admission("persistent_relay_process_start"):
        active = fence.active_fence()
        return active is not None and active["status"] == "INSTALLING"


def ensure_user_relay_running(
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    getter: Callable[[], str] | None = None,
    launcher: Callable[..., Mapping[str, Any]] | None = None,
    lease_factory: Callable[[str | os.PathLike[str]], Any] = acquire_runtime_instance,
) -> dict[str, Any]:
    """Request the registered relay at app start when no relay holds its lease.

    Logon and onboarding start the relay, and the frozen app re-requests it on
    every start through onboarding. The portable app skips onboarding, so a
    relay that ended mid-session otherwise waits for the next logon.

    START_REQUESTED does not reserve a pending launch. Overlapping starts may
    request multiple processes before a child acquires the instance lease;
    main admits one active loop and the other children exit without running it.
    """

    if not (getter or _registry_get)():
        return {"status": "NOT_REGISTERED"}
    root = Path(direct_sync_root).expanduser().resolve()
    if user_relay_stop_path(root).exists():
        return {"status": "STOP_REQUESTED"}
    lease = lease_factory(root / "user-relay-instance")
    if lease is None:
        return {"status": "RUNNING"}
    lease.release()
    return dict((launcher or start_user_relay_process)(app_root, environ=environ))


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
    status_write_error: dict[str, Any] | None = None
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
        if cycle.get("error_code") in {"data_generation_unknown", "data_generation_downgrade_refused"}:
            from auto_update import emit_support_record
            emit_support_record({'status': 'runtime_error'}, stage='user_relay')
            return {"status": "runtime_error", "last_cycle": cycle}
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
        from auto_update import mixed_status_record
        report = mixed_status_record(report)
        from auto_update import relay_ready_metadata

        report.update(relay_ready_metadata(Path(__file__).resolve().parent))
        if status_write_error is not None:
            report["previous_status_write_error"] = status_write_error
        try:
            _write_json_atomic(selected_status_path, report)
        except Exception as exc:
            if isinstance(exc, WriterFenceError) and exc.code not in {
                "WRITER_GATE_TIMEOUT", "WRITER_GATE_ABANDONED",
            }:
                raise
            # The status file is evidence, not the relay. A writer that keeps
            # the per-user admission past the 5 s gate (a GUI start dialog, a
            # request waiting out an outage) or ends without releasing it
            # costs this line; the next cycle retries the queue and the write.
            status_write_error = {
                "cycle_count": cycle_count,
                "error_type": exc.__class__.__name__,
                "error_code": str(getattr(exc, "code", "") or ""),
            }
        else:
            status_write_error = None
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
    data_root: Path | None = None,
) -> dict[str, Any]:
    # Launch/control observation alone does not open user data. The raw runner
    # records under its existing admission immediately before queue/profile IO.
    from data_generation_guard import DataGenerationBlocked, probe_before_owner_paths
    from logistics_runtime_profile import resolve_logistics_profile_path
    try:
        with writer_admission("persistent_relay_status"):
            storage = build_container_audit_storage_paths(application_path=str(app_root), data_root=data_root)
            profile = resolve_logistics_profile_path()
            probe_before_owner_paths(storage.data_root, directory_paths=(direct_sync_root, scan_source_dir),
                                     file_paths=(profile,) if profile.is_file() else ())
            credential_path = direct_sync_root / "credential.json"
            if credential_path.is_file():
                from direct_sync_runtime import prepare_credential_config
                prepare_credential_config(credential_path, data_root=storage.data_root)
    except DataGenerationBlocked as exc:
        return {"status": "runtime_error", "error_code": exc.decision.get("message_key", "data_generation_unknown"), "error_message": exc.user_message}
    process_result = run_session_direct_sync_once(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=scan_source_dir,
        reason="PERSISTENT_USER_RELAY",
        timeout_seconds=45,
    )
    try:
        with writer_admission("persistent_relay_status"):
            probe_before_owner_paths(storage.data_root, directory_paths=(direct_sync_root, scan_source_dir),
                                     file_paths=(profile,) if profile.is_file() else ())
            credential_path = direct_sync_root / "credential.json"
            if credential_path.is_file():
                from direct_sync_runtime import prepare_credential_config
                prepare_credential_config(credential_path, data_root=storage.data_root)
            runtime_status = _read_json(
                direct_sync_root / "status" / "direct_sync_relay_status.json"
            )
    except DataGenerationBlocked as exc:
        return {"status": "runtime_error", "error_code": exc.decision["message_key"], "error_message": exc.user_message}
    process_status = str(process_result.get("status") or "").strip() or "UNKNOWN"
    relay_status = (
        str((runtime_status or {}).get("status") or "").strip() or "UNKNOWN"
    )
    error_code = (runtime_status or {}).get("error_code")
    if error_code in {"data_generation_unknown", "data_generation_downgrade_refused"}:
        return {"status": "runtime_error", "error_code": error_code,
                "error_message": generation.UNKNOWN_MESSAGE if error_code == "data_generation_unknown" else generation.REFUSAL_MESSAGE}
    from auto_update import prepare_feed_packet

    try:
        update_preparation = prepare_feed_packet(app_root)
    except Exception as exc:
        update_preparation = {"status": "FAILED", "error_type": type(exc).__name__}
    report = {
        "status": relay_status if process_status == "PASS" else process_status,
        "process_status": process_status,
        "process_returncode": process_result.get("returncode", "UNKNOWN"),
        "relay_status": relay_status,
    }
    if update_preparation.get("status") != "OFF":
        report["auto_update"] = update_preparation
    return report


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


def _windows_command_arguments(command: str) -> list[str]:
    import ctypes
    from ctypes import wintypes
    if not command:
        return []
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [wintypes.HLOCAL]
    count = ctypes.c_int()
    argv = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not argv:
        raise OSError("application arguments cannot be observed")
    try:
        return [argv[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(argv)


class AppProcessTracker:
    """Retain lifetime evidence for children after their verified parent exits."""

    def __init__(self, app_root, data_root, *, own_pid: int):
        bundle = ntpath.dirname(str(app_root)) if ntpath.basename(str(app_root)).lower() == "app" else str(app_root)
        self.runtime = ntpath.normcase(ntpath.abspath(ntpath.join(bundle, "runtime")))
        leaf = ntpath.basename(bundle).lower()
        parent = ntpath.dirname(bundle)
        self.managed = (ntpath.normcase(ntpath.abspath(parent)) if leaf == "current" else
                        ntpath.normcase(ntpath.abspath(ntpath.dirname(parent)))
                        if ntpath.basename(parent).lower() == "versions" and len(leaf) == 40
                        and all(c in "0123456789abcdef" for c in leaf) else None)
        self.udf = ntpath.normcase(ntpath.abspath(ntpath.join(str(data_root), "webview2")))
        # Match ca_screen_bridge.shell_data_dir without importing the GUI app.
        screen_base = Path(os.environ.get("LOCALAPPDATA") or Path(__file__).resolve().parent)
        self.screen_udf = ntpath.normcase(ntpath.abspath(str(
            screen_base / "KMTech" / "ContainerAudit" / "screen" / "webview2"
        )))
        self.own_pid = own_pid
        self.owned: dict[int, str] = {}

    def observe(self, rows: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        live = {row["pid"]: row for row in rows if row["pid"] != self.own_pid}
        selected = set()
        foreign_udf = set()
        for pid, row in live.items():
            name = row.get("name", "").lower()
            created = row.get("created_at")
            if pid in self.owned and created and self.owned[pid] == created:
                selected.add(pid)
            image = row.get("image", "")
            if name in {"python.exe", "pythonw.exe", "container_audit.exe"}:
                runtime = ntpath.normcase(ntpath.dirname(ntpath.abspath(image))) if image else ""
                version_runtime = False
                if self.managed and runtime.startswith(self.managed + "\\"):
                    parts = runtime[len(self.managed) + 1:].split("\\")
                    version_runtime = (parts == ["current", "runtime"] or len(parts) == 3
                        and parts[0] == "versions" and parts[2] == "runtime"
                        and len(parts[1]) == 40 and all(c in "0123456789abcdef" for c in parts[1]))
                if not image or runtime == self.runtime or version_runtime:
                    selected.add(pid)
            elif name == "msedgewebview2.exe":
                arguments = _windows_command_arguments(row.get("command", ""))
                has_udf = False
                for index, argument in enumerate(arguments):
                    udf = argument.partition("=")[2] if argument.lower().startswith("--user-data-dir=") else (
                        arguments[index + 1] if argument.lower() == "--user-data-dir" and index + 1 < len(arguments) else "")
                    if udf and ntpath.isabs(udf):
                        has_udf = True
                        normalized = ntpath.normcase(ntpath.abspath(udf))
                        if any(normalized == root or normalized.startswith(root + "\\")
                               for root in (self.udf, self.screen_udf)):
                            selected.add(pid)
                if has_udf and pid not in selected:
                    foreign_udf.add(pid)
        changed = True
        while changed:
            changed = False
            for pid, row in live.items():
                if pid in selected or pid in foreign_udf or row.get("name", "").lower() != "msedgewebview2.exe":
                    continue
                parent = live.get(row.get("parent_pid"))
                if parent is None or parent["pid"] not in selected:
                    continue
                try:
                    ordered = datetime.fromisoformat(row["created_at"]) >= datetime.fromisoformat(parent["created_at"])
                except (KeyError, TypeError, ValueError):
                    ordered = False
                if ordered and row.get("session_id") is not None and row.get("session_id") == parent.get("session_id"):
                    selected.add(pid)
                    changed = True
        for pid in selected:
            try:
                created = datetime.fromisoformat(live[pid]["created_at"])
                if created.tzinfo is None or type(live[pid].get("session_id")) is not int:
                    raise ValueError("application lifetime cannot be observed")
            except (KeyError, TypeError):
                raise ValueError("application lifetime cannot be observed") from None
        self.owned = {pid: live[pid]["created_at"] for pid in selected}
        return [live[pid] for pid in sorted(selected)]


@writer_sink("persistent_relay_status", probe_only=True)
def native_app_process_snapshot() -> list[dict[str, Any]]:
    """Read candidates only; captured command lines never enter the stop report."""
    from auto_update import system_executable
    script = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$rows=@()
foreach($p in @(Get-CimInstance Win32_Process -OperationTimeoutSec 2 -ErrorAction Stop)) {
 if([string]$p.Name -notmatch '^(pythonw?|Container_Audit|msedgewebview2)\.exe$'){continue}
 if(-not $p.ExecutablePath -and [string]$p.Name -match '^(pythonw?|Container_Audit)\.exe$') {
  $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId) -OperationTimeoutSec 2 -ErrorAction Stop
  if($null -eq $p){continue}
  if(-not $p.ExecutablePath){
   Start-Sleep -Milliseconds 100
   $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId) -OperationTimeoutSec 2 -ErrorAction Stop
   if($null -eq $p){continue}
  }
 }
 $rows+=@{pid=[int]$p.ProcessId;name=[string]$p.Name;image=[string]$p.ExecutablePath;
  command=[string]$p.CommandLine;parent_pid=[int]$p.ParentProcessId;session_id=[int]$p.SessionId;
  created_at=$(if($p.CreationDate){([datetime]$p.CreationDate).ToUniversalTime().ToString('o')}else{''})}
}
ConvertTo-Json -InputObject @($rows) -Compress
"""
    completed = subprocess.run([str(system_executable("WindowsPowerShell/v1.0/powershell.exe")),
        "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode:
        raise OSError("application processes cannot be observed")
    rows = json.loads(completed.stdout)
    if not isinstance(rows, list) or any(type(row.get("pid")) is not int or row["pid"] <= 0 for row in rows):
        raise ValueError("application process observation is incomplete")
    return rows


def request_app_stop(
    direct_sync_root: str | os.PathLike[str], *, timeout_seconds: float = 150.0,
    app_root: str | os.PathLike[str] | None = None,
    data_root: str | os.PathLike[str] | None = None,
    wait: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    root = Path(direct_sync_root).expanduser().resolve()
    deadline = time.monotonic() + min(150.0, max(0.0, float(timeout_seconds)))
    tracker = AppProcessTracker(app_root or Path(__file__).resolve().parent,
                                data_root or root, own_pid=os.getpid())
    # Capture the live parent chain before either stop marker can be consumed.
    try:
        tracker.observe(native_app_process_snapshot())
        initial_observable = True
    except (OSError, ValueError, TypeError, KeyError):
        initial_observable = False
    request_id = uuid.uuid4().hex
    path = app_stop_path(root)
    _write_json_atomic(path, {
        "schema_version": APP_STOP_SCHEMA,
        "request_id": request_id,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    })
    relay = request_user_relay_stop(root, timeout_seconds=0)
    result = {
        "status": "REQUESTED",
        "request_id": request_id,
        "app_stop_request_path": str(path),
        "relay": relay,
    }
    while True:
        try:
            remaining = tracker.observe(native_app_process_snapshot())
            result["remaining_processes"] = [{"pid": row["pid"], "name": row["name"]} for row in remaining]
            result["remaining_count"] = len(remaining)
            observable = all(row.get("image") or row.get("name", "").lower() == "msedgewebview2.exe" for row in remaining)
        except (OSError, ValueError, TypeError, KeyError):
            remaining, observable = [], False
            result["remaining_processes"] = []
            result["remaining_count"] = None
        result["observation_status"] = "COMPLETE" if observable and initial_observable else "UNKNOWN"
        if not remaining and observable and initial_observable and relay["status"] == "ABSENT":
            result["status"] = "STOPPED"
            return result
        budget = deadline - time.monotonic()
        if budget <= 0 or not initial_observable:
            result["status"] = "UNKNOWN"
            result["reason_code"] = "APP_PROCESS_ABSENCE_UNPROVEN"
            return result
        wait(min(0.25, budget))
        if relay["status"] != "ABSENT":
            lease = acquire_runtime_instance(root / "user-relay-instance")
            if lease is not None:
                lease.release()
                relay["status"] = "ABSENT"


def build_parser() -> argparse.ArgumentParser:
    from auto_update import SupportArgumentParser
    parser = SupportArgumentParser(description="Container_Audit current-user persistent relay")
    parser.add_argument("--app-root", default="")
    parser.add_argument("--data-root", default="")
    parser.add_argument("--direct-sync-root", default="")
    parser.add_argument("--scan-source-dir", default="")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_RETRY_INTERVAL_SECONDS,
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--request-app-stop", action="store_true")
    return parser


def _data_root_unavailable(remote_stop: bool) -> int:
    # A remote stop runs in an SSH session nobody can see; a modal dialog there
    # would hang the command, so it reports one JSON line instead.
    if remote_stop:
        print("CONTAINER_AUDIT_DATA_ROOT_UNAVAILABLE", file=sys.stderr)
        print(json.dumps({"status": "FAILED", "reason_code": "DATA_ROOT_UNAVAILABLE"}, sort_keys=True))
    else:
        _notify_data_root_error()
    return 1


@writer_sink("persistent_relay_status", probe_only=True)
def main(argv: list[str] | None = None) -> int:
    from auto_update import startup_gate, trial_stop_requested

    selected_arguments = list(sys.argv[1:] if argv is None else argv)
    # A remote stop request comes from an administrator SSH session (elevated, or
    # another account). It writes only the stop markers, so it is accepted before
    # the update gate like Label_Match; every other mode stays gated.
    gated = "--request-app-stop" not in selected_arguments
    if gated:
        gate_result = startup_gate(Path(__file__).resolve().parent, [USER_RELAY_MODE, *selected_arguments], role="relay")
        if gate_result is not None:
            return gate_result
    args = build_parser().parse_args(argv)
    if not gated and not args.request_app_stop:
        # The token appeared without selecting the stop mode; gate it after all.
        gate_result = startup_gate(Path(__file__).resolve().parent, [USER_RELAY_MODE, *selected_arguments], role="relay")
        if gate_result is not None:
            return gate_result
    app_root = Path(
        args.app_root
        or (
            Path(sys.executable).parent
            if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parent
        )
    ).expanduser().resolve()
    if args.request_app_stop and not (args.data_root and args.direct_sync_root):
        # Implicit roots are the caller's own profile; another account must name
        # the installed operator's roots instead of reporting a false ABSENT relay.
        from auto_update import control_root, current_process_sid, read_json
        try:
            control = control_root(app_root)
            operator_sid = read_json(control / "policy.json").get("operator_sid") if control is not None else None
            # Without an installed policy the account owning the app is unknown,
            # so both roots must be named like any other foreign caller.
            foreign_caller = control is None or operator_sid is None or operator_sid != current_process_sid()
        except (OSError, ValueError, AttributeError):
            foreign_caller = True
        if foreign_caller:
            print(json.dumps({"status": "FAILED", "reason_code": "OPERATOR_ROOTS_REQUIRED"}, sort_keys=True))
            return 1
    try:
        storage = build_container_audit_storage_paths(
            application_path=str(app_root), data_root=args.data_root or None,
        )
    except (OSError, ValueError):
        return _data_root_unavailable(args.request_app_stop)
    custom_root = storage.custom_data_root
    if custom_root and not storage.data_root.is_dir():
        return _data_root_unavailable(args.request_app_stop)
    from data_generation_guard import DataGenerationBlocked, probe_before_owner_paths, resolve_owner_path
    from logistics_runtime_profile import resolve_logistics_profile_path
    direct_sync_root = resolve_owner_path(args.direct_sync_root) if args.direct_sync_root else storage.direct_sync_root
    scan_source_dir = resolve_owner_path(args.scan_source_dir) if args.scan_source_dir else storage.events_dir
    if args.request_app_stop:
        try:
            if custom_root:
                validate_existing_data_root(storage.data_root)
            assert_runtime_state_outside_code_root(
                app_root=app_root, direct_sync_root=direct_sync_root,
                scan_source_dir=scan_source_dir,
            )
            result = request_app_stop(direct_sync_root, app_root=app_root, data_root=storage.data_root)
        except (OSError, ValueError):
            return _data_root_unavailable(True)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["status"] == "STOPPED" else 1
    profile = resolve_logistics_profile_path()
    try:
        from data_generation_guard import warm_runtime_release
        warm_runtime_release()
    except Exception:
        pass
    try:
        with writer_admission("persistent_relay_status"):
            probe_before_owner_paths(storage.data_root, directory_paths=(direct_sync_root, scan_source_dir),
                                     file_paths=(profile,) if profile.is_file() else ())
            credential_path = direct_sync_root / "credential.json"
            if credential_path.is_file():
                from direct_sync_runtime import prepare_credential_config
                prepare_credential_config(credential_path, data_root=storage.data_root)
    except DataGenerationBlocked as exc:
        print(exc.user_message)
        return 1
    try:
        with writer_admission("persistent_relay_status"):
            if custom_root:
                validate_existing_data_root(storage.data_root)
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
    except (OSError, ValueError):
        if not custom_root:
            raise
        _notify_data_root_error()
        return 1
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
                data_root=storage.data_root,
            ),
            status_path=user_relay_status_path(direct_sync_root),
            interval_seconds=args.interval_seconds,
            stop_requested=lambda: stop_path.exists() or trial_stop_requested(app_root),
            max_cycles=1 if args.once else None,
        )
    finally:
        lease.release()
    last_status = str((result.get("last_cycle") or {}).get("status") or "UNKNOWN")
    return 1 if last_status in {"FAIL", "UNKNOWN", "runtime_error"} else 0


if __name__ == "__main__":
    from auto_update import run_support_main
    raise SystemExit(run_support_main(main, stage='user_relay'))
