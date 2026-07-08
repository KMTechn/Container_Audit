"""Auto-install Container_Audit direct-sync relay when the app starts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SERVER_BASE_URL = "https://worker.kmtecherp.com"
DEFAULT_ENDPOINT_PATH = "/api/producer-ingest/v1/source-file"
DEFAULT_TASK_NAME = "direct-sync-relay-container-audit"
DEFAULT_SOURCE_GLOB = "*.csv"
INSTALL_EXE_NAME = "Container_Audit_DirectSync_Install.exe"
RUNNER_EXE_NAME = "Container_Audit_DirectSync_Relay.exe"
REGISTER_EXE_NAME = "Container_Audit_Worker_PC_Register.exe"

_STARTED_ROOTS: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _join_url(base_url: str, path: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    return f"{base}{path if path.startswith('/') else '/' + path}"


def _enabled() -> bool:
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    value = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP", "").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _session_sync_trigger_enabled() -> bool:
    value = os.environ.get("CONTAINER_AUDIT_SESSION_SYNC_TRIGGER", "").strip().lower()
    if value in {"0", "false", "no", "off", "disabled"}:
        return False
    if value in {"1", "true", "yes", "on", "enabled"}:
        return True
    return not bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _existing_file(*paths: Path) -> Path | None:
    for path in paths:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _tool_command(app_root: Path, exe_name: str, script_name: str) -> list[str]:
    exe = _existing_file(app_root / exe_name, app_root / "tools" / exe_name)
    if exe is not None:
        return [str(exe)]
    script = app_root / "tools" / script_name
    if not script.is_file():
        return []
    if getattr(sys, "frozen", False):
        return []
    return [sys.executable, str(script)]


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
    runner_exe = _existing_file(selected_app_root / RUNNER_EXE_NAME, selected_app_root / "tools" / RUNNER_EXE_NAME)
    runner_script = selected_app_root / "tools" / "direct_sync_relay_runner.py"
    if runner_exe is not None:
        command = [str(runner_exe)]
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
            f"{task_name}-session-sync",
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


def build_registration_command(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    server_base_url: str = DEFAULT_SERVER_BASE_URL,
    report_path: str | os.PathLike[str] | None = None,
) -> list[str]:
    root = Path(direct_sync_root).expanduser().resolve()
    selected_app_root = Path(app_root).expanduser().resolve()
    selected_report = Path(report_path).expanduser().resolve() if report_path else root / "status" / "worker_pc_registration.json"
    command = _tool_command(
        selected_app_root,
        REGISTER_EXE_NAME,
        "register_container_audit_worker_pc.py",
    )
    if not command:
        return []
    command.extend(
        [
            "--app-root",
            str(selected_app_root),
            "--endpoint-url",
            _join_url(server_base_url, DEFAULT_ENDPOINT_PATH),
            "--self-enroll",
            "--manifest-path",
            str(root / "producer_manifest.json"),
            "--credential-path",
            str(root / "credential.json"),
            "--report-path",
            str(selected_report),
        ]
    )
    return command


def build_install_command(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    task_name: str = DEFAULT_TASK_NAME,
    report_path: str | os.PathLike[str] | None = None,
    confirm_production_install: bool = False,
    task_run_user: str = "",
    task_run_password_env: str = "",
    task_run_password_file: str = "",
    allow_interactive_task_for_local_test: bool = False,
) -> list[str]:
    root = Path(direct_sync_root).expanduser().resolve()
    selected_app_root = Path(app_root).expanduser().resolve()
    selected_report = Path(report_path).expanduser().resolve() if report_path else root / "status" / "container_audit_direct_sync_install.json"
    command = _tool_command(
        selected_app_root,
        INSTALL_EXE_NAME,
        "direct_sync_relay_install_pack.py",
    )
    if not command:
        return []
    command.extend(
        [
            "--apply",
            "--app-root",
            str(selected_app_root),
            "--program-data-root",
            str(root),
            "--producer-manifest-path",
            str(root / "producer_manifest.json"),
            "--credential-path",
            str(root / "credential.json"),
            "--scan-source-dir",
            str(Path(scan_source_dir).expanduser().resolve()),
            "--source-glob",
            DEFAULT_SOURCE_GLOB,
            "--task-name",
            task_name,
            "--report-path",
            str(selected_report),
        ]
    )
    if confirm_production_install:
        command.append("--confirm-production-install")
    if task_run_user:
        command.extend(["--task-run-user", task_run_user])
    if task_run_password_env:
        command.extend(["--task-run-password-env", task_run_password_env])
    if task_run_password_file:
        command.extend(["--task-run-password-file", task_run_password_file])
    if allow_interactive_task_for_local_test:
        command.append("--allow-interactive-task-for-local-test")
    return command


def _registration_ready(root: Path) -> bool:
    if not (root / "producer_manifest.json").is_file() or not (root / "credential.json").is_file():
        return False
    for report_path in sorted((root / "status").glob("*registration*.json")):
        report = _read_json(report_path)
        if not report:
            continue
        if report.get("server_registration_verified") is True:
            return True
        if str(report.get("status") or "") == "SELF_ENROLLMENT_REGISTERED":
            return True
    return False


def _task_exists(task_name: str) -> bool:
    if os.name != "nt":
        return False
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", task_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _install_ready(root: Path, task_name: str, scan_source_dir: str | os.PathLike[str]) -> bool:
    report = _read_json(root / "status" / "container_audit_direct_sync_install.json")
    if report.get("status") != "PASS":
        return False
    try:
        expected_root = str(root.resolve())
        report_root = str(Path(str(report.get("program_data_root") or "")).expanduser().resolve())
        if os.path.normcase(report_root) != os.path.normcase(expected_root):
            return False
        source_scan = report.get("source_scan") or {}
        expected_scan_dir = str(Path(scan_source_dir).expanduser().resolve())
        report_scan_dir = str(Path(str(source_scan.get("scan_source_dir") or "")).expanduser().resolve())
        if os.path.normcase(report_scan_dir) != os.path.normcase(expected_scan_dir):
            return False
        if task_name and str(report.get("task_name") or "") != task_name:
            return False
    except Exception:
        return False
    return True


def _start_task(task_name: str) -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "SKIPPED", "reason": "scheduled tasks are Windows-only"}
    try:
        completed = subprocess.run(
            ["schtasks.exe", "/Run", "/TN", task_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return {"status": "FAIL", "error_type": exc.__class__.__name__, "error_message": str(exc)}
    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-1000:],
        "stderr_tail": completed.stderr[-1000:],
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
        return {"status": "SKIPPED", "reason": "direct-sync relay runner is missing"}
    result = _run_command(command, max(10, timeout_seconds))
    result["reason"] = reason
    return result


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
    selected_task_name = task_name or os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_TASK_NAME", "").strip() or DEFAULT_TASK_NAME
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
                "report_version": "container-audit-session-direct-sync-trigger-v1",
                "captured_at": _now(),
                "reason": reason,
                "task_name": selected_task_name,
                "scan_source_dir": str(Path(scan_source_dir).expanduser().resolve()),
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
        return {"status": "FAIL", "error_type": exc.__class__.__name__, "error_message": str(exc)}
    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def run_direct_sync_auto_bootstrap(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
    task_name: str = DEFAULT_TASK_NAME,
    server_base_url: str = DEFAULT_SERVER_BASE_URL,
    timeout_seconds: int = 180,
    confirm_production_install: bool = False,
    task_run_user: str = "",
    task_run_password_env: str = "",
    task_run_password_file: str = "",
    allow_interactive_task_for_local_test: bool = False,
) -> dict[str, Any]:
    root = Path(direct_sync_root).expanduser().resolve()
    status_path = root / "status" / "container_audit_direct_sync_auto_bootstrap.json"
    report: dict[str, Any] = {
        "report_version": "container-audit-direct-sync-auto-bootstrap-v1",
        "captured_at": _now(),
        "program_data_root": str(root),
        "scan_source_dir": str(Path(scan_source_dir).expanduser().resolve()),
        "task_name": task_name,
        "server_base_url": server_base_url,
    }
    if os.name != "nt":
        report.update({"status": "SKIPPED", "reason": "direct-sync scheduled task install is Windows-only"})
        _write_json(status_path, report)
        return report

    root.mkdir(parents=True, exist_ok=True)
    if _registration_ready(root) and _install_ready(root, task_name, scan_source_dir) and _task_exists(task_name):
        report.update({"status": "READY", "task_start": _start_task(task_name)})
        _write_json(status_path, report)
        return report

    registration_command = build_registration_command(
        app_root=app_root,
        direct_sync_root=root,
        server_base_url=server_base_url,
    )
    report["registration_command_redacted"] = registration_command
    if not registration_command:
        report.update({"status": "FAIL", "reason": "direct-sync registration helper is missing"})
        _write_json(status_path, report)
        return report
    registration_result = _run_command(registration_command, max(30, timeout_seconds))
    report["registration_result"] = registration_result
    if registration_result["status"] != "PASS":
        report["status"] = "FAIL"
        _write_json(status_path, report)
        return report

    install_command = build_install_command(
        app_root=app_root,
        direct_sync_root=root,
        scan_source_dir=scan_source_dir,
        task_name=task_name,
        confirm_production_install=confirm_production_install,
        task_run_user=task_run_user,
        task_run_password_env=task_run_password_env,
        task_run_password_file=task_run_password_file,
        allow_interactive_task_for_local_test=allow_interactive_task_for_local_test,
    )
    report["install_command_redacted"] = install_command
    if not install_command:
        report.update({"status": "FAIL", "reason": "direct-sync install helper is missing"})
        _write_json(status_path, report)
        return report
    install_result = _run_command(install_command, max(30, timeout_seconds))
    report["install_result"] = install_result
    report["status"] = "PASS" if install_result["status"] == "PASS" else "FAIL"
    if report["status"] == "PASS":
        report["task_start"] = _start_task(task_name)
    _write_json(status_path, report)
    return report


def start_direct_sync_auto_bootstrap(
    *,
    app_root: str | os.PathLike[str],
    direct_sync_root: str | os.PathLike[str],
    scan_source_dir: str | os.PathLike[str],
) -> threading.Thread | None:
    if not _enabled():
        return None
    root = Path(direct_sync_root).expanduser().resolve()
    key = str(root)
    if key in _STARTED_ROOTS:
        return None
    _STARTED_ROOTS.add(key)
    try:
        timeout_seconds = int(os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP_TIMEOUT_SECONDS", "").strip() or "180")
    except ValueError:
        timeout_seconds = 180
    server_base_url = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_SERVER_BASE_URL", "").strip() or DEFAULT_SERVER_BASE_URL
    task_name = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_TASK_NAME", "").strip() or DEFAULT_TASK_NAME
    confirm_production_install = os.environ.get(
        "CONTAINER_AUDIT_DIRECT_SYNC_CONFIRM_PRODUCTION_INSTALL",
        "",
    ).strip().lower() in {"1", "true", "yes", "on"}
    allow_interactive_task_for_local_test = os.environ.get(
        "CONTAINER_AUDIT_DIRECT_SYNC_ALLOW_INTERACTIVE_TASK_FOR_LOCAL_TEST",
        "",
    ).strip().lower() in {"1", "true", "yes", "on"}
    task_run_user = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_TASK_RUN_USER", "").strip()
    task_run_password_env = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_TASK_RUN_PASSWORD_ENV", "").strip()
    task_run_password_file = os.environ.get("CONTAINER_AUDIT_DIRECT_SYNC_TASK_RUN_PASSWORD_FILE", "").strip()
    thread = threading.Thread(
        target=run_direct_sync_auto_bootstrap,
        kwargs={
            "app_root": app_root,
            "direct_sync_root": root,
            "scan_source_dir": scan_source_dir,
            "task_name": task_name,
            "server_base_url": server_base_url,
            "timeout_seconds": timeout_seconds,
            "confirm_production_install": confirm_production_install,
            "task_run_user": task_run_user,
            "task_run_password_env": task_run_password_env,
            "task_run_password_file": task_run_password_file,
            "allow_interactive_task_for_local_test": allow_interactive_task_for_local_test,
        },
        name="direct-sync-bootstrap-container-audit",
        daemon=True,
    )
    thread.start()
    return thread
