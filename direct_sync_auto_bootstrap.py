"""Current-user DirectSync wake paths for Container_Audit."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any
import uuid


DEFAULT_TASK_NAME = "direct-sync-relay-container-audit"
CANONICAL_INSTALL_ROOT = r"C:\KMTech\Apps\Container_Audit\current"
CANONICAL_DIRECT_SYNC_ROOT = r"%LOCALAPPDATA%\KMTech\DirectSync\container_audit"
DEFAULT_SOURCE_GLOB = "*.csv"
APPLICATION_EXE_NAME = "Container_Audit.exe"
DIRECT_SYNC_RELAY_MODE = "--container-audit-direct-sync-relay"

_STARTED_ROOTS: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _existing_file(*paths: Path) -> Path | None:
    for path in paths:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _runtime_paths(direct_sync_root: str | os.PathLike[str]) -> dict[str, str]:
    root = Path(direct_sync_root).expanduser().resolve()
    return {
        "db_path": str(root / "queue" / "direct_sync_relay.sqlite3"),
        "spool_dir": str(root / "spool"),
        "upload_status_dir": str(root / "upload_status"),
        "runtime_status_path": str(root / "status" / "direct_sync_relay_status.json"),
        "log_path": str(root / "logs" / "direct_sync_relay.jsonl"),
        "operator_pause_path": str(root / "control" / "pause.json"),
    }


def build_session_direct_sync_command(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    task_name: str = DEFAULT_TASK_NAME,
    min_source_file_age_seconds: int = 0,
) -> list[str]:
    selected_app_root = Path(app_root).expanduser().resolve()
    application_exe = _existing_file(selected_app_root / APPLICATION_EXE_NAME)
    runner_script = selected_app_root / "tools" / "direct_sync_relay_runner.py"
    if application_exe is not None:
        command = [str(application_exe), DIRECT_SYNC_RELAY_MODE]
    elif runner_script.is_file() and not getattr(sys, "frozen", False):
        command = [sys.executable, str(runner_script)]
    else:
        return []
    root = Path(direct_sync_root).expanduser().resolve()
    paths = _runtime_paths(root)
    command.extend(
        [
            "--db-path",
            paths["db_path"],
            "--spool-dir",
            paths["spool_dir"],
            "--producer-manifest-path",
            str(root / "producer_manifest.json"),
            "--credential-path",
            str(root / "credential.json"),
            "--upload-status-dir",
            paths["upload_status_dir"],
            "--runtime-status-path",
            paths["runtime_status_path"],
            "--log-path",
            paths["log_path"],
            "--operator-pause-path",
            paths["operator_pause_path"],
            "--worker-id",
            f"{task_name}-current-user",
            "--scan-source-dir",
            str(Path(scan_source_dir).expanduser().resolve()),
            "--source-glob",
            DEFAULT_SOURCE_GLOB,
            "--max-enqueue-files",
            "25",
            "--min-source-file-age-seconds",
            str(max(0, int(min_source_file_age_seconds or 0))),
            "--drain-after-scan",
        ]
    )
    return command


def _run_command(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return {
            "status": "UNKNOWN",
            "reason": "relay process did not return an exit code",
            "error_type": exc.__class__.__name__,
        }
    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def run_session_direct_sync_once(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    task_name: str = DEFAULT_TASK_NAME,
    reason: str = "TRAY_COMPLETE",
    timeout_seconds: int = 45,
) -> dict[str, Any]:
    command = build_session_direct_sync_command(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=scan_source_dir,
        task_name=task_name,
        min_source_file_age_seconds=0,
    )
    if not command:
        return {"status": "FAIL", "reason": "direct-sync relay runner is missing"}
    result = _run_command(command, max(10, int(timeout_seconds)))
    result["reason"] = reason
    return result


def _session_sync_trigger_enabled() -> bool:
    value = os.environ.get("CONTAINER_AUDIT_SESSION_SYNC_TRIGGER", "").strip().lower()
    if value in {"0", "false", "no", "off", "disabled"}:
        return False
    if value in {"1", "true", "yes", "on", "enabled"}:
        return True
    return not bool(os.environ.get("PYTEST_CURRENT_TEST"))


def start_session_direct_sync(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    reason: str = "TRAY_COMPLETE",
    task_name: str | None = None,
) -> threading.Thread | None:
    if not _session_sync_trigger_enabled():
        return None
    selected_task_name = task_name or DEFAULT_TASK_NAME
    root = Path(direct_sync_root).expanduser().resolve()

    def worker() -> None:
        result = run_session_direct_sync_once(
            app_root=app_root,
            direct_sync_root=root,
            scan_source_dir=scan_source_dir,
            task_name=selected_task_name,
            reason=reason,
        )
        _write_json(
            root / "status" / "container_audit_session_direct_sync_trigger.json",
            {
                "report_version": "container-audit-session-direct-sync-trigger-v2",
                "captured_at": _now(),
                "reason": reason,
                "principal": "current_user",
                "system_scheduled_task": False,
                "scan_source_dir": str(
                    Path(scan_source_dir).expanduser().resolve()
                ),
                "result": result,
            },
        )

    thread = threading.Thread(
        target=worker,
        name="direct-sync-session-container-audit",
        daemon=True,
    )
    thread.start()
    return thread


def run_direct_sync_auto_bootstrap(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    **_retired_task_options: Any,
) -> dict[str, Any]:
    """Wake one current-user relay cycle; never install or start a SYSTEM task."""

    result = run_session_direct_sync_once(
        app_root=app_root,
        direct_sync_root=direct_sync_root,
        scan_source_dir=scan_source_dir,
        reason="APP_START",
    )
    report = {
        "report_version": "container-audit-direct-sync-auto-bootstrap-v2",
        "captured_at": _now(),
        "status": result.get("status", "UNKNOWN"),
        "principal": "current_user",
        "system_scheduled_task": False,
        "persistent_retry": "HKCU_RUN_USER_RELAY",
        "result": result,
    }
    _write_json(
        Path(direct_sync_root).expanduser().resolve()
        / "status"
        / "container_audit_direct_sync_auto_bootstrap.json",
        report,
    )
    return report


def start_direct_sync_auto_bootstrap(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
) -> threading.Thread | None:
    if not _session_sync_trigger_enabled():
        return None
    root = Path(direct_sync_root).expanduser().resolve()
    key = os.path.normcase(str(root))
    if key in _STARTED_ROOTS:
        return None
    _STARTED_ROOTS.add(key)

    def worker() -> None:
        try:
            run_direct_sync_auto_bootstrap(
                app_root=app_root,
                direct_sync_root=root,
                scan_source_dir=scan_source_dir,
            )
        finally:
            _STARTED_ROOTS.discard(key)

    thread = threading.Thread(
        target=worker,
        name="direct-sync-bootstrap-container-audit",
        daemon=True,
    )
    thread.start()
    return thread


def _install_report_relay_topology(_report: dict[str, Any]) -> str:
    """Retired compatibility hook retained for old diagnostics only."""

    return "retired_scheduled_task_contract"
