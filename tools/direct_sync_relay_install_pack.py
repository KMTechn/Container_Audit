#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build or apply the Container_Audit direct-sync scheduled-task install pack."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from direct_sync_push import (  # noqa: E402
    DEFAULT_PRODUCER_ROLE,
    DEFAULT_SOURCE_SYSTEM,
    DEFAULT_SOURCE_TRANSPORT,
    DEFAULT_STREAM_NAME,
    DirectSyncPushError,
    load_json_no_duplicate_keys,
    validate_endpoint_url,
)
from direct_sync_runtime import _production_profile_enabled, _safe_secret_ref_name  # noqa: E402
from storage_policy import (  # noqa: E402
    build_container_audit_storage_paths,
    ensure_container_audit_storage_dirs,
    is_legacy_syncthing_path,
)


DEFAULT_TASK_NAME = "direct-sync-relay-container-audit"
DEFAULT_SOURCE_GLOB = "*.csv"
DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS = 30
BUNDLED_RELAY_EXE_NAME = "Container_Audit_DirectSync_Relay.exe"
MAX_TASK_NAME_LENGTH = 128
TASK_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
LOCAL_TEST_TASK_ENV_NAMES = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
)


def _default_app_root() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent)
    return str(ROOT)


def _quote_cmd(parts: Sequence[str]) -> str:
    return subprocess.list2cmdline([str(part) for part in parts])


def _read_task_password(args: argparse.Namespace) -> tuple[str, str, str]:
    env_name = str(getattr(args, "task_run_password_env", "") or "").strip()
    file_path = str(getattr(args, "task_run_password_file", "") or "").strip()
    if env_name and file_path:
        return "", "", "use only one of --task-run-password-env or --task-run-password-file"
    if env_name:
        value = str(os.getenv(env_name) or "")
        if not value:
            return "", f"env:{env_name}", "task run password env var is empty or unavailable"
        return value, f"env:{env_name}", ""
    if file_path:
        try:
            value = Path(file_path).read_text(encoding="utf-8-sig").rstrip("\r\n")
        except Exception as exc:
            return "", "file", f"task run password file could not be read: {exc.__class__.__name__}"
        if not value:
            return "", "file", "task run password file is empty"
        return value, "file", ""
    return "", "", "stored-password task mode requires --task-run-password-env or --task-run-password-file"


def _task_principal_args(args: argparse.Namespace, *, redact_password: bool) -> tuple[list[str], dict]:
    user = str(getattr(args, "task_run_user", "") or "").strip()
    password_env = str(getattr(args, "task_run_password_env", "") or "").strip()
    password_file = str(getattr(args, "task_run_password_file", "") or "").strip()
    uninstall = bool(getattr(args, "uninstall", False))
    allow_interactive = bool(getattr(args, "allow_interactive_task_for_local_test", False))
    report = {
        "status": "PASS",
        "mode": "interactive_token_default",
        "run_user": "",
        "password_source": "",
        "password_supplied": False,
        "password_in_report": False,
        "blocked_reason": "",
    }
    if not user:
        if password_env or password_file:
            report.update({
                "status": "FAIL",
                "blocked_reason": "task password source requires --task-run-user",
            })
        elif allow_interactive:
            report.update({
                "mode": "interactive_token_default",
                "run_user": "",
            })
        elif not uninstall:
            report.update({
                "mode": "system_service_account",
                "run_user": "SYSTEM",
            })
            return ["/RU", "SYSTEM"], report
        return [], report
    password, source, error = _read_task_password(args)
    report.update({
        "mode": "stored_password",
        "run_user": user,
        "password_source": source,
        "password_supplied": bool(password),
        "blocked_reason": error,
        "status": "FAIL" if error else "PASS",
    })
    if error:
        return [], report
    return ["/RU", user, "/RP", "[redacted]" if redact_password else password], report


def _scheduled_task_create_command(
    *,
    task_name: str,
    minute_interval: int,
    task_action: str,
    task_principal_args: Sequence[str],
) -> list[str]:
    return [
        "schtasks.exe",
        "/Create",
        "/TN",
        task_name,
        "/SC",
        "MINUTE",
        "/MO",
        str(max(1, int(minute_interval))),
        "/TR",
        task_action,
        *[str(part) for part in task_principal_args],
        "/F",
    ]


def _ps_single_quote(value: str | os.PathLike[str]) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _encoded_powershell_command(script: str) -> list[str]:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]


def _stored_password_task_register_command(
    *,
    task_name: str,
    minute_interval: int,
    task_action_parts: Sequence[str],
    args: argparse.Namespace,
) -> list[str]:
    user = str(getattr(args, "task_run_user", "") or "").strip()
    env_name = str(getattr(args, "task_run_password_env", "") or "").strip()
    file_path = str(getattr(args, "task_run_password_file", "") or "").strip()
    if env_name:
        password_script = "\n".join(
            [
                f"$password = [Environment]::GetEnvironmentVariable({_ps_single_quote(env_name)}, 'Process')",
                "if ([string]::IsNullOrEmpty($password)) { throw 'task run password env var is empty or unavailable' }",
            ]
        )
    else:
        password_script = "\n".join(
            [
                f"$passwordPath = {_ps_single_quote(Path(file_path).expanduser().resolve())}",
                "$password = [System.IO.File]::ReadAllText($passwordPath, [System.Text.Encoding]::UTF8)",
                "if ($password.Length -gt 0 -and $password[0] -eq [char]0xfeff) { $password = $password.Substring(1) }",
                "$password = $password -replace '(?:\\r\\n|\\r|\\n)+$', ''",
                "if ($password.Length -eq 0) { throw 'task run password file is empty' }",
            ]
        )
    task_args = _quote_cmd([str(part) for part in task_action_parts[1:]])
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$taskName = {_ps_single_quote(task_name)}",
            f"$execute = {_ps_single_quote(str(task_action_parts[0]))}",
            f"$arguments = {_ps_single_quote(task_args)}",
            f"$user = {_ps_single_quote(user)}",
            password_script,
            "$action = New-ScheduledTaskAction -Execute $execute -Argument $arguments",
            "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes "
            + str(max(1, int(minute_interval)))
            + ") -RepetitionDuration (New-TimeSpan -Days 3650)",
            "$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries",
            "Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User $user -Password $password -Force | Out-Null",
            "",
        ]
    )
    return _encoded_powershell_command(script)


def _scheduled_task_wrapper_path(program_data_root: str | os.PathLike[str], task_name: str) -> Path:
    return Path(program_data_root).expanduser().resolve() / "bin" / f"{task_name}.cmd"


def _scheduled_task_launcher_path(program_data_root: str | os.PathLike[str], task_name: str) -> Path:
    return Path(program_data_root).expanduser().resolve() / "bin" / f"{task_name}.vbs"


def _vbs_string(value: str | os.PathLike[str]) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _local_test_task_environment(args: argparse.Namespace) -> dict[str, str]:
    if not bool(getattr(args, "allow_interactive_task_for_local_test", False)):
        return {}
    values: dict[str, str] = {}
    for env_name in LOCAL_TEST_TASK_ENV_NAMES:
        if env_name not in os.environ:
            continue
        value = str(os.environ.get(env_name) or "")
        if any(character in value for character in ("\x00", "\r", "\n", '"', "%")):
            raise ValueError(f"{env_name} contains characters unsafe for a local-test task wrapper")
        if env_name in {"HTTPS_PROXY", "HTTP_PROXY"} and value:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"{env_name} must be an HTTP(S) proxy URL")
            if parsed.username or parsed.password:
                raise ValueError(f"{env_name} must not contain proxy credentials")
        values[env_name] = value
    return values


def _write_scheduled_task_wrapper(
    path: Path,
    runner_parts: Sequence[str],
    *,
    environment: dict[str, str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    command = _quote_cmd(runner_parts)
    temp_path = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    environment_lines = [
        f'set "{env_name}={value}"'
        for env_name, value in (environment or {}).items()
    ]
    content_lines = ["@echo off", "chcp 65001 >nul", *environment_lines, command, "exit /b %ERRORLEVEL%", ""]
    content = "\n".join(content_lines)
    try:
        temp_path.write_text(content, encoding="utf-8", newline="\r\n")
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _scheduled_task_launcher_content(wrapper_path: str | os.PathLike[str]) -> str:
    return "\r\n".join(
        [
            'Set shell = CreateObject("WScript.Shell")',
            'comspec = shell.ExpandEnvironmentStrings("%ComSpec%")',
            f"runner = {_vbs_string(Path(wrapper_path).expanduser().resolve())}",
            'command = """" & comspec & """ /d /c """ & runner & """"',
            "exitCode = shell.Run(command, 0, True)",
            "WScript.Quit exitCode",
            "",
        ]
    )


def _write_scheduled_task_launcher(path: Path, wrapper_path: str | os.PathLike[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        temp_path.write_text(_scheduled_task_launcher_content(wrapper_path), encoding="ascii", newline="\r\n")
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _apply_container_audit_storage_defaults(args: argparse.Namespace) -> dict:
    paths = build_container_audit_storage_paths(application_path=args.app_root)
    defaulted_program_data_root = not bool(str(getattr(args, "program_data_root", "") or "").strip())
    defaulted_scan_source_dir = not bool(str(getattr(args, "scan_source_dir", "") or "").strip())
    defaulted_source_glob = not bool(getattr(args, "source_glob", []) or [])

    if defaulted_program_data_root:
        args.program_data_root = str(paths.direct_sync_root)
    if defaulted_scan_source_dir:
        args.scan_source_dir = str(paths.events_dir)
    if defaulted_source_glob:
        args.source_glob = [DEFAULT_SOURCE_GLOB]

    if not bool(getattr(args, "uninstall", False)):
        ensure_container_audit_storage_dirs(paths)

    return {
        "data_root": str(paths.data_root),
        "events_dir": str(paths.events_dir),
        "direct_sync_root": str(paths.direct_sync_root),
        "defaulted_program_data_root": defaulted_program_data_root,
        "defaulted_scan_source_dir": defaulted_scan_source_dir,
        "defaulted_source_glob": defaulted_source_glob,
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _task_name_report(task_name: str) -> dict:
    value = str(task_name or "")
    valid = bool(value) and len(value) <= MAX_TASK_NAME_LENGTH and bool(TASK_NAME_PATTERN.fullmatch(value))
    report = {
        "status": "PASS" if valid else "FAIL",
        "task_name_valid": valid,
        "max_length": MAX_TASK_NAME_LENGTH,
        "allowed_pattern": TASK_NAME_PATTERN.pattern,
    }
    if not valid:
        report["blocked_reason"] = (
            "task_name must be 1-128 characters and contain only letters, digits, underscore, dash, or dot"
        )
    return report


def _bundled_relay_executable_path(app_root: str | os.PathLike[str]) -> Path:
    return Path(app_root).expanduser().resolve() / BUNDLED_RELAY_EXE_NAME


def _bundled_relay_executable_report(app_root: str | os.PathLike[str]) -> dict:
    path = _bundled_relay_executable_path(app_root)
    exists = path.is_file()
    return {
        "status": "PASS" if exists else "MISSING",
        "blocked_reason": "" if exists else "bundled relay executable is not present",
        "path": str(path),
        "exists": exists,
    }


def _runtime_paths(program_data_root: str | os.PathLike[str]) -> dict[str, str]:
    root = Path(program_data_root).expanduser().resolve()
    return {
        "db_path": str(root / "queue" / "direct_sync_relay.sqlite3"),
        "spool_dir": str(root / "spool"),
        "upload_status_dir": str(root / "upload_status"),
        "runtime_status_path": str(root / "status" / "direct_sync_relay_status.json"),
        "log_path": str(root / "logs" / "direct_sync_relay.jsonl"),
        "operator_pause_path": str(root / "control" / "pause.json"),
    }


def _runtime_path_boundary_report(program_data_root: str | os.PathLike[str], paths: dict[str, str]) -> dict:
    raw_root = str(program_data_root).strip()
    if not raw_root:
        return {
            "status": "FAIL",
            "blocked_reason": "program_data_root is required",
            "all_runtime_paths_under_program_data_root": False,
        }
    root_path = Path(raw_root).expanduser()
    if not root_path.is_absolute():
        return {
            "status": "FAIL",
            "blocked_reason": "program_data_root must be an absolute path",
            "program_data_root": raw_root,
            "all_runtime_paths_under_program_data_root": False,
        }
    resolved_root = root_path.resolve()
    if resolved_root.exists() and not resolved_root.is_dir():
        return {
            "status": "FAIL",
            "blocked_reason": "program_data_root exists and is not a directory",
            "program_data_root": str(resolved_root),
            "all_runtime_paths_under_program_data_root": False,
        }
    if is_legacy_syncthing_path(resolved_root):
        return {
            "status": "FAIL",
            "blocked_reason": "program_data_root must not point at the legacy Syncthing folder",
            "program_data_root": str(resolved_root),
            "all_runtime_paths_under_program_data_root": False,
        }
    escaped_paths: list[str] = []
    resolved_paths: dict[str, str] = {}
    for name, path in paths.items():
        resolved = Path(path).expanduser().resolve()
        resolved_paths[name] = str(resolved)
        if not resolved.is_relative_to(resolved_root):
            escaped_paths.append(name)
    ok = not escaped_paths
    return {
        "status": "PASS" if ok else "FAIL",
        "blocked_reason": "" if ok else "runtime path escaped program_data_root",
        "program_data_root": str(resolved_root),
        "all_runtime_paths_under_program_data_root": ok,
        "escaped_paths": escaped_paths,
        "resolved_runtime_paths": resolved_paths,
    }


def _task_runtime_acl_plan(args: argparse.Namespace) -> dict:
    user = str(getattr(args, "task_run_user", "") or "").strip()
    root = Path(args.program_data_root).expanduser().resolve()
    enabled = bool(user) and not bool(getattr(args, "uninstall", False))
    status = "PASS"
    blocked_reason = ""
    if enabled and root.parent == root:
        status = "FAIL"
        blocked_reason = "program_data_root must not be a filesystem root"
    return {
        "status": status,
        "blocked_reason": blocked_reason,
        "enabled": enabled,
        "principal": user,
        "rights": "M",
        "inheritance": "(OI)(CI)",
        "paths": [str(root)] if enabled else [],
    }


def _apply_task_runtime_acl(plan: dict) -> dict:
    if plan.get("status") != "PASS":
        return {
            "status": "FAIL",
            "blocked_reason": plan.get("blocked_reason") or "task runtime ACL plan is not pass",
            "command_results": [],
        }
    paths = [str(path) for path in plan.get("paths") or []]
    created_paths: list[str] = []
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)
        created_paths.append(path)
    if not plan.get("enabled"):
        return {
            "status": "SKIPPED",
            "blocked_reason": "",
            "reason": "task_run_user_not_configured",
            "created_paths": created_paths,
            "command_results": [],
        }
    if os.name != "nt":
        return {
            "status": "SKIPPED",
            "blocked_reason": "",
            "reason": "non_windows_runtime",
            "created_paths": created_paths,
            "command_results": [],
        }
    principal = str(plan.get("principal") or "").strip()
    rights = str(plan.get("rights") or "M")
    inheritance = str(plan.get("inheritance") or "(OI)(CI)")
    grant = f"{principal}:{inheritance}{rights}"
    command_results = []
    for path in paths:
        command = ["icacls.exe", path, "/grant:r", grant]
        result = _run_command(command)
        command_results.append({
            "command": command,
            "returncode": result.get("returncode"),
            "stdout_omitted": bool(result.get("stdout")),
            "stderr_omitted": bool(result.get("stderr")),
            "stdout_bytes": len(str(result.get("stdout") or "").encode("utf-8", errors="replace")),
            "stderr_bytes": len(str(result.get("stderr") or "").encode("utf-8", errors="replace")),
        })
    ok = all(int(result.get("returncode") or 0) == 0 for result in command_results)
    return {
        "status": "PASS" if ok else "FAIL",
        "blocked_reason": "" if ok else "icacls grant failed for task runtime path",
        "created_paths": created_paths,
        "command_results": command_results,
    }


def _app_root_dependency_report(app_root: str | os.PathLike[str]) -> dict:
    root = Path(app_root).resolve()
    required = {
        "runner_script": root / "tools" / "direct_sync_relay_runner.py",
        "direct_sync_runtime": root / "direct_sync_runtime.py",
        "direct_sync_push": root / "direct_sync_push.py",
        "direct_sync_operator": root / "direct_sync_operator.py",
        "storage_policy": root / "storage_policy.py",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    return {
        "status": "PASS" if not missing else "FAIL",
        "blocked_reason": "" if not missing else "app_root missing direct-sync runtime dependencies",
        "app_root": str(root),
        "missing": missing,
        "required_paths": {name: str(path) for name, path in required.items()},
    }


def _python_executable_report(python_exe: str | os.PathLike[str]) -> dict:
    raw_path = str(python_exe or "").strip()
    if not raw_path:
        return {
            "status": "FAIL",
            "blocked_reason": "python_exe is required",
            "python_exe": raw_path,
        }
    resolved = Path(raw_path).expanduser().resolve()
    if not resolved.is_file():
        return {
            "status": "FAIL",
            "blocked_reason": "python_exe does not exist",
            "python_exe": str(resolved),
        }
    return {
        "status": "PASS",
        "blocked_reason": "",
        "python_exe": str(resolved),
    }


def _python_runtime_import_report(python_exe: str | os.PathLike[str], app_root: str | os.PathLike[str]) -> dict:
    resolved_python = Path(str(python_exe or "")).expanduser().resolve()
    resolved_app_root = Path(app_root).expanduser().resolve()
    modules = ["requests", "direct_sync_push", "direct_sync_runtime", "direct_sync_operator"]
    code = "\n".join(
        [
            "import sys",
            f"sys.path.insert(0, {str(resolved_app_root)!r})",
            *[f"import {module}" for module in modules],
        ]
    )
    try:
        completed = subprocess.run(
            [str(resolved_python), "-c", code],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "FAIL",
            "blocked_reason": "python_exe cannot import direct-sync runtime modules",
            "python_exe": str(resolved_python),
            "app_root": str(resolved_app_root),
            "required_modules": modules,
            "error_type": exc.__class__.__name__,
        }
    ok = completed.returncode == 0
    return {
        "status": "PASS" if ok else "FAIL",
        "blocked_reason": "" if ok else "python_exe cannot import direct-sync runtime modules",
        "python_exe": str(resolved_python),
        "app_root": str(resolved_app_root),
        "required_modules": modules,
        "returncode": completed.returncode,
        "stderr": completed.stderr[-1000:],
    }


def _skipped_report(reason: str) -> dict:
    return {
        "status": "SKIPPED",
        "blocked_reason": "",
        "reason": reason,
    }


def _load_json_object_report(path: str | os.PathLike[str], *, label: str) -> tuple[dict, dict | None]:
    raw_path = str(path or "").strip()
    if not raw_path:
        return {
            "status": "FAIL",
            "blocked_reason": f"{label} path is required",
            "path": raw_path,
        }, None
    resolved = Path(raw_path).expanduser().resolve()
    if not resolved.is_file():
        return {
            "status": "FAIL",
            "blocked_reason": f"{label} file does not exist",
            "path": str(resolved),
        }, None
    try:
        payload = load_json_no_duplicate_keys(resolved.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "status": "FAIL",
            "blocked_reason": f"{label} file is not valid JSON",
            "path": str(resolved),
            "error_type": exc.__class__.__name__,
        }, None
    except DirectSyncPushError as exc:
        return {
            "status": "FAIL",
            "blocked_reason": f"{label} file is not valid JSON",
            "path": str(resolved),
            "error_type": "DuplicateJSONKey",
            "error_message": str(exc),
        }, None
    if not isinstance(payload, dict):
        return {
            "status": "FAIL",
            "blocked_reason": f"{label} file must be a JSON object",
            "path": str(resolved),
        }, None
    return {
        "status": "PASS",
        "blocked_reason": "",
        "path": str(resolved),
    }, payload


def _legacy_path_block_report(field_name: str, path: str | os.PathLike[str]) -> dict | None:
    raw_path = str(path or "").strip()
    if raw_path and is_legacy_syncthing_path(raw_path):
        return {
            "field": field_name,
            "path": str(Path(raw_path).expanduser().resolve(strict=False)),
            "blocked_reason": f"{field_name} must not point at the legacy Syncthing folder",
        }
    return None


def _explicit_path_boundary_report(args: argparse.Namespace) -> dict:
    checks = [
        _legacy_path_block_report("producer_manifest_path", args.producer_manifest_path),
        _legacy_path_block_report("credential_path", args.credential_path),
        _legacy_path_block_report("report_path", args.report_path),
    ]
    unsafe_paths = [check for check in checks if check]
    return {
        "status": "PASS" if not unsafe_paths else "FAIL",
        "blocked_reason": "" if not unsafe_paths else "; ".join(item["blocked_reason"] for item in unsafe_paths),
        "unsafe_paths": unsafe_paths,
    }


def _producer_manifest_report(path: str | os.PathLike[str]) -> dict:
    report, payload = _load_json_object_report(path, label="producer_manifest")
    if payload is None:
        return report
    identity = payload.get("pc_identity") if isinstance(payload.get("pc_identity"), dict) else {}
    missing_identity = [
        name for name in ("producer_install_id", "source_host_id") if not str(identity.get(name) or "").strip()
    ]
    matching_stream = None
    for stream in payload.get("streams") or []:
        if isinstance(stream, dict) and stream.get("stream_name") == DEFAULT_STREAM_NAME:
            matching_stream = stream
            break
    stream_ok = bool(
        matching_stream
        and matching_stream.get("producer_role") == DEFAULT_PRODUCER_ROLE
        and matching_stream.get("source_system") == DEFAULT_SOURCE_SYSTEM
        and matching_stream.get("source_transport") == DEFAULT_SOURCE_TRANSPORT
    )
    failures: list[str] = []
    if missing_identity:
        failures.append("producer manifest identity is incomplete")
    if not stream_ok:
        failures.append("producer manifest stream does not match Container_Audit legacy CSV")
    report.update(
        {
            "missing_identity_fields": missing_identity,
            "container_audit_stream_present": matching_stream is not None,
            "container_audit_stream_valid": stream_ok,
        }
    )
    if failures:
        report["status"] = "FAIL"
        report["blocked_reason"] = "; ".join(failures)
    return report


def _credential_report(path: str | os.PathLike[str], *, forbid_raw_secret: bool = False) -> dict:
    report, payload = _load_json_object_report(path, label="credential")
    if payload is None:
        return report
    required_missing = [
        name for name in ("producer_id", "key_id", "endpoint_url") if not str(payload.get(name) or "").strip()
    ]
    raw_secret = payload.get("secret")
    secret_invalid = raw_secret is not None and (
        not isinstance(raw_secret, str) or (raw_secret != "" and not raw_secret.strip())
    )
    has_secret = isinstance(raw_secret, str) and bool(raw_secret.strip())
    has_secret_ref = bool(str(payload.get("secret_ref") or "").strip())
    secret_ref = str(payload.get("secret_ref") or "").strip()
    production_profile_enabled = _production_profile_enabled()
    failures: list[str] = []
    if required_missing:
        failures.append("credential file is missing required identity or endpoint fields")
    if secret_invalid:
        failures.append("credential secret must be a nonempty string")
    if has_secret and has_secret_ref:
        failures.append("credential file must not contain both secret and secret_ref")
    if not has_secret and not has_secret_ref:
        failures.append("credential file is missing secret or secret_ref")
    if has_secret and production_profile_enabled:
        failures.append("raw credential secret is disabled in production")
    elif has_secret and forbid_raw_secret:
        failures.append("raw credential secret is disabled for production apply; use secret_ref")
    secret_ref_scheme = ""
    if has_secret_ref:
        if ":" not in secret_ref:
            failures.append("secret_ref must start with env:, dpapi:, or wincred:")
        else:
            secret_ref_scheme, secret_ref_target = secret_ref.split(":", 1)
            secret_ref_scheme = secret_ref_scheme.lower()
            if secret_ref_scheme not in {"env", "dpapi", "wincred"}:
                failures.append("secret_ref must start with env:, dpapi:, or wincred:")
            try:
                _safe_secret_ref_name(secret_ref_target)
            except DirectSyncPushError as exc:
                failures.append(str(exc))
            if secret_ref_scheme == "env" and production_profile_enabled:
                failures.append("env secret_ref is disabled in production")
    endpoint_valid = False
    if not required_missing:
        try:
            validate_endpoint_url(str(payload.get("endpoint_url") or ""))
            endpoint_valid = True
        except DirectSyncPushError as exc:
            failures.append(str(exc))
    report.update(
        {
            "missing_fields": required_missing,
            "secret_material_configured": has_secret or has_secret_ref,
            "secret_ref_configured": has_secret_ref,
            "raw_secret_configured": has_secret,
            "secret_ref_scheme": secret_ref_scheme,
            "production_profile_enabled": production_profile_enabled,
            "raw_secret_forbidden": forbid_raw_secret,
            "endpoint_url_valid": endpoint_valid,
        }
    )
    if failures:
        report["status"] = "FAIL"
        report["blocked_reason"] = "; ".join(failures)
    return report


def _source_scan_config(args: argparse.Namespace) -> dict:
    scan_source_dir = str(getattr(args, "scan_source_dir", "") or "").strip()
    source_globs = [str(item) for item in (getattr(args, "source_glob", []) or [])]
    max_enqueue_files = int(getattr(args, "max_enqueue_files", 100) or 0)
    min_source_file_age_seconds = int(
        getattr(args, "min_source_file_age_seconds", DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS) or 0
    )
    return {
        "enabled": bool(scan_source_dir),
        "scan_source_dir": str(Path(scan_source_dir).resolve()) if scan_source_dir else "",
        "source_globs": source_globs,
        "max_enqueue_files": max_enqueue_files,
        "min_source_file_age_seconds": min_source_file_age_seconds,
        "drain_after_scan": bool(scan_source_dir),
    }


def _validate_source_scan_config(source_scan: dict) -> dict:
    if not source_scan["enabled"]:
        return {"status": "PASS", "enabled": False}
    failures: list[str] = []
    scan_source_dir = Path(source_scan["scan_source_dir"])
    if is_legacy_syncthing_path(scan_source_dir):
        failures.append("scan_source_dir must not point at the legacy Syncthing folder")
    elif not scan_source_dir.is_dir():
        failures.append("scan_source_dir does not exist or is not a directory")
    if source_scan["max_enqueue_files"] < 0:
        failures.append("max_enqueue_files must not be negative")
    if source_scan["min_source_file_age_seconds"] < 0:
        failures.append("min_source_file_age_seconds must not be negative")
    for pattern in source_scan["source_globs"]:
        text = str(pattern or "").strip()
        if not text:
            failures.append("source glob must not be empty")
        elif "**" in text or "/" in text or "\\" in text:
            failures.append("source glob must be a direct-child file pattern")
    report = {
        "status": "PASS" if not failures else "FAIL",
        "enabled": True,
        "scan_source_dir_exists": scan_source_dir.is_dir(),
        "source_globs_valid": not any("source glob" in failure for failure in failures),
        "source_scan_limits_valid": not any("must not be negative" in failure for failure in failures),
        "syncthing_path_rejected": any("legacy Syncthing folder" in failure for failure in failures),
    }
    if failures:
        report["blocked_reason"] = "; ".join(failures)
    return report


def _append_source_scan_args(runner_parts: list[str], source_scan: dict) -> None:
    if not source_scan["enabled"]:
        return
    runner_parts.extend(["--scan-source-dir", source_scan["scan_source_dir"]])
    for pattern in source_scan["source_globs"]:
        runner_parts.extend(["--source-glob", pattern])
    runner_parts.extend(["--max-enqueue-files", str(source_scan["max_enqueue_files"])])
    runner_parts.extend(["--min-source-file-age-seconds", str(source_scan["min_source_file_age_seconds"])])
    if source_scan.get("drain_after_scan"):
        runner_parts.append("--drain-after-scan")


def _backpressure_config(args: argparse.Namespace) -> dict:
    return {
        "max_active_queue_count": int(getattr(args, "max_active_queue_count", 1000) or 0),
        "max_active_queue_age_seconds": int(getattr(args, "max_active_queue_age_seconds", 24 * 60 * 60) or 0),
    }


def _validate_backpressure_config(backpressure: dict) -> dict:
    failures: list[str] = []
    if backpressure["max_active_queue_count"] < 0:
        failures.append("max_active_queue_count must not be negative")
    if backpressure["max_active_queue_age_seconds"] < 0:
        failures.append("max_active_queue_age_seconds must not be negative")
    report = {
        "status": "PASS" if not failures else "FAIL",
        "limits_valid": not failures,
    }
    if failures:
        report["blocked_reason"] = "; ".join(failures)
    return report


def build_install_plan(args: argparse.Namespace) -> dict:
    uninstall = bool(args.uninstall)
    container_audit_storage = getattr(args, "container_audit_storage", {})
    probe_python_runtime = bool(getattr(args, "probe_python_runtime", False) or getattr(args, "apply", False))
    task_name_validation = _task_name_report(args.task_name)
    explicit_path_boundary = _explicit_path_boundary_report(args)
    app_root = Path(args.app_root).resolve()
    runner_script = app_root / "tools" / "direct_sync_relay_runner.py"
    bundled_relay_executable = _bundled_relay_executable_report(app_root)
    python_exe_explicit = bool(getattr(args, "python_exe_explicit", False))
    use_bundled_relay_executable = (
        not uninstall and not python_exe_explicit and bundled_relay_executable["status"] == "PASS"
    )
    paths = _runtime_paths(args.program_data_root)
    runtime_path_boundary = (
        _skipped_report("uninstall does not use runtime data paths")
        if uninstall
        else _runtime_path_boundary_report(args.program_data_root, paths)
    )
    app_root_dependencies = (
        _skipped_report("uninstall does not use application runtime dependencies")
        if uninstall
        else (
            _skipped_report("bundled relay executable supplies scheduled-task runtime")
            if use_bundled_relay_executable
            else _app_root_dependency_report(app_root)
        )
    )
    python_executable = (
        _skipped_report("uninstall does not launch the Python relay runtime")
        if uninstall
        else (
            _skipped_report("bundled relay executable selected")
            if use_bundled_relay_executable
            else _python_executable_report(args.python_exe)
        )
    )
    if uninstall:
        python_runtime_imports = _skipped_report("uninstall does not import the Python relay runtime")
    elif use_bundled_relay_executable:
        python_runtime_imports = _skipped_report("bundled relay executable selected")
    elif probe_python_runtime and python_executable["status"] == "PASS" and app_root_dependencies["status"] == "PASS":
        python_runtime_imports = _python_runtime_import_report(args.python_exe, app_root)
    else:
        reason = (
            "python runtime import check requires --probe-python-runtime or production apply"
            if python_executable["status"] == "PASS" and app_root_dependencies["status"] == "PASS"
            else "python runtime import check requires valid python_exe and app_root dependencies"
        )
        python_runtime_imports = _skipped_report(reason)
    producer_manifest = (
        _skipped_report("uninstall does not read the producer manifest")
        if uninstall
        else _producer_manifest_report(args.producer_manifest_path)
    )
    credential = (
        _skipped_report("uninstall does not read producer credentials")
        if uninstall
        else _credential_report(args.credential_path, forbid_raw_secret=bool(getattr(args, "apply", False)))
    )
    source_scan = _source_scan_config(args)
    source_scan_validation = (
        _skipped_report("uninstall does not scan source files")
        if uninstall
        else _validate_source_scan_config(source_scan)
    )
    backpressure = _backpressure_config(args)
    backpressure_validation = (
        _skipped_report("uninstall does not run relay backpressure checks")
        if uninstall
        else _validate_backpressure_config(backpressure)
    )
    task_runtime_acl = _task_runtime_acl_plan(args)
    local_test_task_environment = _local_test_task_environment(args)
    runner_parts: list[str] = []
    create_command: list[str] = []
    wrapper_path = ""
    launcher_path = ""
    launcher_command = ""
    if not uninstall:
        runner_parts = [bundled_relay_executable["path"]] if use_bundled_relay_executable else [
            python_executable["python_exe"],
            str(runner_script),
        ]
        runner_parts.extend(
            [
                "--db-path",
                paths["db_path"],
                "--spool-dir",
                paths["spool_dir"],
                "--producer-manifest-path",
                str(Path(args.producer_manifest_path).resolve()),
                "--credential-path",
                str(Path(args.credential_path).resolve()),
                "--upload-status-dir",
                paths["upload_status_dir"],
                "--runtime-status-path",
                paths["runtime_status_path"],
                "--log-path",
                paths["log_path"],
                "--operator-pause-path",
                paths["operator_pause_path"],
                "--worker-id",
                args.task_name,
                "--min-free-bytes",
                str(max(0, int(args.min_free_bytes))),
                "--max-active-queue-count",
                str(backpressure["max_active_queue_count"]),
                "--max-active-queue-age-seconds",
                str(backpressure["max_active_queue_age_seconds"]),
            ]
        )
        _append_source_scan_args(runner_parts, source_scan)
        wrapper = _scheduled_task_wrapper_path(args.program_data_root, args.task_name)
        wrapper_path = str(wrapper)
        launcher = _scheduled_task_launcher_path(args.program_data_root, args.task_name)
        launcher_path = str(launcher)
        launcher_command = _quote_cmd(["wscript.exe", "//B", "//NoLogo", launcher_path])
        task_principal_args, task_principal = _task_principal_args(args, redact_password=True)
        create_command = _scheduled_task_create_command(
            task_name=args.task_name,
            minute_interval=args.minute_interval,
            task_action=launcher_command,
            task_principal_args=task_principal_args,
        )
    else:
        task_principal = {
            "status": "SKIPPED",
            "mode": "uninstall",
            "run_user": "",
            "password_source": "",
            "password_supplied": False,
            "password_in_report": False,
            "blocked_reason": "",
        }
    delete_command = ["schtasks.exe", "/Delete", "/TN", args.task_name, "/F"]
    return {
        "report_version": "container-audit-direct-sync-install-pack-v1",
        "status": "DRY_RUN" if not args.apply else "APPLY_REQUESTED",
        "apply": bool(args.apply),
        "uninstall": uninstall,
        "task_name": args.task_name,
        "task_name_validation": task_name_validation,
        "explicit_path_boundary": explicit_path_boundary,
        "container_audit_storage": container_audit_storage,
        "program_data_root": str(Path(args.program_data_root).expanduser().resolve()),
        "runtime_paths": paths,
        "runtime_path_boundary": runtime_path_boundary,
        "task_runtime_acl": task_runtime_acl,
        "bundled_relay_executable": bundled_relay_executable,
        "use_bundled_relay_executable": use_bundled_relay_executable,
        "python_exe_explicit": python_exe_explicit,
        "app_root_dependencies": app_root_dependencies,
        "python_executable": python_executable,
        "python_runtime_imports": python_runtime_imports,
        "producer_manifest": producer_manifest,
        "credential": credential,
        "source_scan": source_scan,
        "source_scan_validation": source_scan_validation,
        "backpressure": backpressure,
        "backpressure_validation": backpressure_validation,
        "runner_script": str(runner_script),
        "runner_command": runner_parts,
        "scheduled_task_wrapper_path": wrapper_path,
        "scheduled_task_wrapper_command": _quote_cmd([wrapper_path]),
        "scheduled_task_launcher_path": launcher_path,
        "scheduled_task_launcher_command": launcher_command,
        "scheduled_task_uses_hidden_launcher": True,
        "local_test_task_environment_names": list(local_test_task_environment),
        "local_test_task_environment_persisted": bool(local_test_task_environment),
        "task_principal": task_principal,
        "scheduled_task_create_command": create_command,
        "scheduled_task_delete_command": delete_command,
        "secret_redaction": {
            "credential_path_only": True,
            "raw_secret_in_report": False,
        },
        "production_apply_guard": {
            "requires_apply": True,
            "requires_confirm_production_install": True,
            "confirm_production_install": bool(args.confirm_production_install),
        },
    }


def _run_command(command: Sequence[str]) -> dict:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error_code": "scheduled_task_command_start_failed",
            "error_message": f"scheduled task command failed to start: {exc.__class__.__name__}",
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description="Container_Audit direct-sync relay scheduled-task install pack")
    parser.add_argument("--app-root", default=_default_app_root())
    parser.add_argument("--python-exe", default=sys.executable)
    parser.add_argument("--program-data-root", default="")
    parser.add_argument("--producer-manifest-path", default="")
    parser.add_argument("--credential-path", default="")
    parser.add_argument("--task-name", default=DEFAULT_TASK_NAME)
    parser.add_argument("--minute-interval", type=int, default=1)
    parser.add_argument("--min-free-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--scan-source-dir", default="")
    parser.add_argument("--source-glob", action="append", default=[])
    parser.add_argument("--max-enqueue-files", type=int, default=100)
    parser.add_argument("--min-source-file-age-seconds", type=int, default=DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS)
    parser.add_argument("--max-active-queue-count", type=int, default=1000)
    parser.add_argument("--max-active-queue-age-seconds", type=int, default=24 * 60 * 60)
    parser.add_argument("--report-path", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--confirm-production-install", action="store_true")
    parser.add_argument("--probe-python-runtime", action="store_true")
    parser.add_argument("--task-run-user", default="")
    parser.add_argument("--task-run-password-env", default="")
    parser.add_argument("--task-run-password-file", default="")
    parser.add_argument("--allow-interactive-task-for-local-test", action="store_true")
    args = parser.parse_args(raw_argv)
    args.python_exe_explicit = "--python-exe" in raw_argv
    report_path_policy = _legacy_path_block_report("report_path", args.report_path)
    if report_path_policy:
        plan = {
            "report_version": "container-audit-direct-sync-install-pack-v1",
            "status": "BLOCKED",
            "blocked_reason": report_path_policy["blocked_reason"],
            "explicit_path_boundary": {
                "status": "FAIL",
                "blocked_reason": report_path_policy["blocked_reason"],
                "unsafe_paths": [report_path_policy],
            },
        }
        print(json.dumps(plan, ensure_ascii=False, sort_keys=True))
        return 2
    try:
        args.container_audit_storage = _apply_container_audit_storage_defaults(args)
    except ValueError as exc:
        plan = {
            "report_version": "container-audit-direct-sync-install-pack-v1",
            "status": "BLOCKED",
            "blocked_reason": str(exc),
            "container_audit_storage": {
                "status": "FAIL",
                "blocked_reason": str(exc),
            },
        }
        _write_json(Path(args.report_path), plan)
        print(f"install_pack_report={Path(args.report_path).resolve()}")
        return 2

    plan = build_install_plan(args)
    if plan["task_name_validation"]["status"] != "PASS":
        plan["status"] = "BLOCKED"
        plan["blocked_reason"] = plan["task_name_validation"]["blocked_reason"]
        _write_json(Path(args.report_path), plan)
        print(f"install_pack_report={Path(args.report_path).resolve()}")
        return 2
    if plan["explicit_path_boundary"]["status"] != "PASS":
        plan["status"] = "BLOCKED"
        plan["blocked_reason"] = plan["explicit_path_boundary"]["blocked_reason"]
        _write_json(Path(args.report_path), plan)
        print(f"install_pack_report={Path(args.report_path).resolve()}")
        return 2
    if args.apply and not args.confirm_production_install:
        plan["status"] = "BLOCKED"
        plan["blocked_reason"] = "apply requires --confirm-production-install"
        _write_json(Path(args.report_path), plan)
        print(f"install_pack_report={Path(args.report_path).resolve()}")
        return 2
    if plan["task_principal"]["status"] not in {"PASS", "SKIPPED"}:
        plan["status"] = "BLOCKED"
        plan["blocked_reason"] = plan["task_principal"]["blocked_reason"]
        _write_json(Path(args.report_path), plan)
        print(f"install_pack_report={Path(args.report_path).resolve()}")
        return 2
    if not args.uninstall:
        if plan["runtime_path_boundary"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["runtime_path_boundary"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["app_root_dependencies"]["status"] != "PASS" and not plan.get("use_bundled_relay_executable"):
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["app_root_dependencies"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["python_executable"]["status"] != "PASS" and not plan.get("use_bundled_relay_executable"):
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["python_executable"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["python_runtime_imports"]["status"] == "FAIL":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["python_runtime_imports"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["producer_manifest"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["producer_manifest"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["credential"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["credential"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["source_scan_validation"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["source_scan_validation"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["backpressure_validation"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["backpressure_validation"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2
        if plan["task_runtime_acl"]["status"] != "PASS":
            plan["status"] = "BLOCKED"
            plan["blocked_reason"] = plan["task_runtime_acl"]["blocked_reason"]
            _write_json(Path(args.report_path), plan)
            print(f"install_pack_report={Path(args.report_path).resolve()}")
            return 2

    if args.apply:
        if args.uninstall:
            command = plan["scheduled_task_delete_command"]
        else:
            actual_principal_args, actual_principal = _task_principal_args(args, redact_password=True)
            if actual_principal["status"] != "PASS":
                plan["status"] = "BLOCKED"
                plan["blocked_reason"] = actual_principal["blocked_reason"]
                plan["task_principal"] = actual_principal
                _write_json(Path(args.report_path), plan)
                print(f"install_pack_report={Path(args.report_path).resolve()}")
                return 2
            task_action_parts = ["wscript.exe", "//B", "//NoLogo", plan["scheduled_task_launcher_path"]]
            if actual_principal["mode"] == "stored_password":
                command = _stored_password_task_register_command(
                    task_name=args.task_name,
                    minute_interval=args.minute_interval,
                    task_action_parts=task_action_parts,
                    args=args,
                )
            else:
                command = _scheduled_task_create_command(
                    task_name=args.task_name,
                    minute_interval=args.minute_interval,
                    task_action=plan["scheduled_task_launcher_command"],
                    task_principal_args=actual_principal_args,
                )
            acl_result = _apply_task_runtime_acl(plan["task_runtime_acl"])
            plan["task_runtime_acl"]["apply_result"] = acl_result
            if acl_result["status"] == "FAIL":
                plan["status"] = "FAIL"
                plan["blocked_reason"] = acl_result["blocked_reason"]
                _write_json(Path(args.report_path), plan)
                print(f"install_pack_report={Path(args.report_path).resolve()}")
                return 1
        plan["status"] = "APPLYING"
        _write_json(Path(args.report_path), plan)
        if not args.uninstall:
            _write_scheduled_task_wrapper(
                Path(plan["scheduled_task_wrapper_path"]),
                plan["runner_command"],
                environment=_local_test_task_environment(args),
            )
            _write_scheduled_task_launcher(
                Path(plan["scheduled_task_launcher_path"]),
                plan["scheduled_task_wrapper_path"],
            )
        plan["command_result"] = _run_command(command)
        plan["status"] = "PASS" if plan["command_result"]["returncode"] == 0 else "FAIL"

    _write_json(Path(args.report_path), plan)
    print(f"install_pack_report={Path(args.report_path).resolve()}")
    return 0 if plan["status"] in {"DRY_RUN", "PASS"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
