from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Mapping


EVIDENCE_ROOT = Path(
    r"E:\KMTech\autoloop-20260824\seq332-crash-matrix-2"
).resolve()
PROJECT_ROOT = Path(r"C:\company\program\Container_Audit").resolve()
DISPLAY3_BOUNDS = (3840, 326, 6400, 1766)
GEOMETRY = "1366x768+3840+326"
WORKER = "CrashProbe332"


def inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def durable_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ConfinementAudit:
    _PATH_EVENTS = {
        "os.remove",
        "os.rmdir",
        "os.rename",
        "os.replace",
        "os.mkdir",
        "os.symlink",
        "os.link",
        "os.truncate",
    }

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def check(self, value: object) -> None:
        if not isinstance(value, (str, bytes, os.PathLike)):
            return
        path = Path(os.fsdecode(value)).expanduser().resolve()
        if not inside(path, self.root):
            raise PermissionError(f"write escaped evidence root: {path}")

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        if event == "socket.connect":
            raise PermissionError("network disabled for isolated crash probe")
        if event == "subprocess.Popen":
            raise PermissionError("subprocess disabled inside isolated crash child")
        if event == "open" and args:
            mode = str(args[1] or "") if len(args) > 1 else ""
            flags = int(args[2] or 0) if len(args) > 2 and isinstance(args[2], int) else 0
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
            if any(marker in mode for marker in ("w", "a", "x", "+")) or flags & write_flags:
                self.check(args[0])
            return
        if event in self._PATH_EVENTS and args:
            self.check(args[0])
            if event in {"os.rename", "os.replace", "os.symlink", "os.link"} and len(args) > 1:
                self.check(args[1])


def window_rect(hwnd: int) -> list[int]:
    rect = wintypes.RECT()
    if not ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise ctypes.WinError(ctypes.get_last_error())
    return [rect.left, rect.top, rect.right, rect.bottom]


def contained_in_display3(rect: list[int]) -> bool:
    left, top, right, bottom = rect
    dl, dt, dr, db = DISPLAY3_BOUNDS
    return left >= dl and top >= dt and right <= dr and bottom <= db


def configure_environment(run_root: Path) -> Path:
    runtime = run_root / "runtime"
    env_roots = {
        "LOCALAPPDATA": runtime / "env" / "localappdata",
        "APPDATA": runtime / "env" / "appdata",
        "PROGRAMDATA": runtime / "env" / "programdata",
        "USERPROFILE": runtime / "env" / "userprofile",
        "TEMP": runtime / "env" / "temp",
        "TMP": runtime / "env" / "temp",
    }
    for path in env_roots.values():
        path.mkdir(parents=True, exist_ok=True)
    data_root = runtime / "data"
    data_root.mkdir(parents=True, exist_ok=True)
    os.environ.update({key: str(path) for key, path in env_roots.items()})
    os.environ.update(
        {
            "CONTAINER_AUDIT_DATA_ROOT": str(data_root),
            "CONTAINER_AUDIT_SESSION_SYNC_TRIGGER": "off",
            "CONTAINER_AUDIT_UPDATE_PROVIDER": "off",
            "CONTAINER_AUDIT_AUDIO_ENABLED": "off",
            "CONTAINER_AUDIT_STARTUP_GEOMETRY": GEOMETRY,
            "KMTECH_TEST_SILENT_AUDIO": "1",
            "SDL_AUDIODRIVER": "dummy",
            "PYGAME_HIDE_SUPPORT_PROMPT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_CURRENT_TEST": "container-atomicity-rest-live-probe",
        }
    )
    for key in list(os.environ):
        if key.startswith("WORKER_ANALYSIS_LOGISTICS_") or key == "WORKER_ANALYSIS_SERVER_URL":
            os.environ.pop(key, None)
    return data_root


def read_csv_matches(log_path: Path, event_type: str, idempotency_key: str) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    matches: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                detail = json.loads(row.get("details") or "{}")
            except json.JSONDecodeError:
                continue
            if row.get("event") != event_type:
                continue
            if detail.get("idempotency_key") != idempotency_key:
                continue
            matches.append(
                {
                    "timestamp": row.get("timestamp"),
                    "worker_name": row.get("worker_name"),
                    "event": row.get("event"),
                    "details": detail,
                }
            )
    return matches


def visible_state(app: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("current_item_label", "main_count_label", "status_label"):
        widget = getattr(app, name, None)
        try:
            result[name] = str(widget.cget("text")) if widget is not None else ""
        except Exception:
            result[name] = ""
    return result


def event_from_work_state(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    pending = state.get("pending_event")
    return pending if isinstance(pending, Mapping) else None


def event_from_parked_state(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    pending = state.get("pending_parked_restore")
    if not isinstance(pending, Mapping):
        return None
    events = pending.get("projection_events")
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, Mapping) and event.get("event_type") == "TRAY_RESTORED_FROM_PARK":
            return event
    return None


def checkpoint_payload(
    *,
    app: Any,
    case: str,
    boundary: str,
    state_path: Path,
    state: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    event_type = str(event["event_type"])
    idempotency_key = str(event["idempotency_key"])
    log_path = Path(app.save_folder) / str(event["projection_log_name"])
    matches = read_csv_matches(log_path, event_type, idempotency_key)
    state_stat = state_path.stat()
    log_stat = log_path.stat() if log_path.exists() else None
    parked = state.get("pending_parked_restore")
    source_path = None
    if isinstance(parked, Mapping):
        source_path = app._parked_store().directory / str(parked["parked_source_name"])
    return {
        "pid": os.getpid(),
        "case": case,
        "boundary": boundary,
        "last_execution_point": "DURABLE_STATE_RETURNED_TRUE__BEFORE_AUDIT_PROJECTION_CALL",
        "checkpoint_wall_time_ns": time.time_ns(),
        "state_path": str(state_path),
        "state_sha256": sha256_file(state_path),
        "state_size": state_stat.st_size,
        "state_mtime_ns": state_stat.st_mtime_ns,
        "state_phase": state.get("phase"),
        "event_type": event_type,
        "idempotency_key": idempotency_key,
        "observed_at": event.get("observed_at"),
        "projection_worker_name": event.get("projection_worker_name"),
        "projection_log_path": str(log_path),
        "projection_log_exists": log_path.exists(),
        "projection_log_mtime_ns": log_stat.st_mtime_ns if log_stat else None,
        "projection_log_size": log_stat.st_size if log_stat else 0,
        "exact_event_count": len(matches),
        "exact_rows": matches,
        "pending_event": dict(event),
        "parked_source_path": str(source_path) if source_path else None,
        "parked_source_exists": bool(source_path and source_path.exists()),
        "visible_before_original_save_returned_to_caller": visible_state(app),
        "cut_valid": len(matches) == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("work-start", "work-end", "parked-restore"), required=True)
    parser.add_argument("--mode", choices=("crash", "restart1", "restart2"), required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args()
    run_root = args.run_root.resolve()
    if not inside(run_root, EVIDENCE_ROOT):
        raise SystemExit(f"run root escaped evidence root: {run_root}")
    run_root.mkdir(parents=True, exist_ok=True)
    data_root = configure_environment(run_root)
    sys.addaudithook(ConfinementAudit(EVIDENCE_ROOT).hook)
    sys.path.insert(0, str(PROJECT_ROOT))

    import Container_Audit as product

    paths = product.build_container_audit_storage_paths(application_path=PROJECT_ROOT)
    product.ensure_container_audit_storage_dirs(paths)
    product.WorkerRegistry(str(paths.worker_registry_path)).register(WORKER)
    lease = product.acquire_runtime_instance(paths.data_root)
    if lease is None:
        durable_json(run_root / f"{args.mode}_failure.json", {"reason": "instance_lock_unavailable"})
        return 4

    original_work_save = product.ContainerAudit._save_work_session_state
    original_tray_save = product.ContainerAudit._save_tray_state_snapshot
    barrier = threading.Event()
    barrier.clear()

    def write_cut_and_wait(payload: Mapping[str, Any]) -> None:
        durable_json(run_root / "cut_checkpoint.json", payload)
        barrier.wait()

    def work_save_then_pause(self: Any, state: Mapping[str, Any]) -> bool:
        result = original_work_save(self, state)
        expected_phase = "START_PENDING" if args.case == "work-start" else "END_PENDING"
        if args.mode == "crash" and args.case in {"work-start", "work-end"} and result:
            state_path = Path(self.save_folder) / self.WORK_SESSION_STATE_FILE
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            event = event_from_work_state(persisted)
            if persisted.get("phase") == expected_phase and event is not None:
                write_cut_and_wait(
                    checkpoint_payload(
                        app=self,
                        case=args.case,
                        boundary=(
                            "ContainerAudit._save_work_session_state returned True with "
                            f"phase={expected_phase} before _reconcile_work_session_state audit projection"
                        ),
                        state_path=state_path,
                        state=persisted,
                        event=event,
                    )
                )
        return result

    def tray_save_then_pause(self: Any, state: Mapping[str, Any]) -> bool:
        result = original_tray_save(self, state)
        if args.mode == "crash" and args.case == "parked-restore" and result:
            state_path = Path(self.save_folder) / self.CURRENT_TRAY_STATE_FILE
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            event = event_from_parked_state(persisted)
            if event is not None:
                write_cut_and_wait(
                    checkpoint_payload(
                        app=self,
                        case=args.case,
                        boundary=(
                            "ContainerAudit._save_tray_state_snapshot returned True with "
                            "pending_parked_restore before _drain_pending_parked_restore audit projection"
                        ),
                        state_path=state_path,
                        state=persisted,
                        event=event,
                    )
                )
        return result

    product.ContainerAudit._save_work_session_state = work_save_then_pause
    product.ContainerAudit._save_tray_state_snapshot = tray_save_then_pause

    try:
        try:
            app = product.ContainerAudit()
        except Exception as exc:
            durable_json(
                run_root / f"{args.mode}_failure.json",
                {
                    "reason": "constructor_failed",
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                    "schema_table_set_gate": "FAILED",
                },
            )
            raise
        app.root.update_idletasks()
        hwnd = int(app.root.winfo_id())
        rect = window_rect(hwnd)
        if not contained_in_display3(rect):
            durable_json(run_root / f"{args.mode}_failure.json", {"reason": "window_not_on_display3", "rect": rect})
            return 5
        ready_payload = {
            "pid": os.getpid(),
            "hwnd": hwnd,
            "case": args.case,
            "mode": args.mode,
            "window_rect": rect,
            "display3_bounds": list(DISPLAY3_BOUNDS),
            "data_root": str(data_root),
            "worker": WORKER,
            "schema_table_set_gate": "PASS_CONSTRUCTOR_COMPLETED",
        }
        durable_json(run_root / f"{args.mode}_ready.json", ready_payload)

        if args.mode != "crash":
            cut = json.loads((run_root / "cut_checkpoint.json").read_text(encoding="utf-8"))
            started = time.monotonic()

            def record_restart_observation() -> None:
                event_type = str(cut["event_type"])
                key = str(cut["idempotency_key"])
                log_path = Path(str(cut["projection_log_path"]))
                matches = read_csv_matches(log_path, event_type, key)
                state_path = Path(str(cut["state_path"]))
                state: dict[str, Any] | None = None
                if state_path.exists():
                    try:
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        state = None
                timed_out = time.monotonic() - started > 180.0
                if not matches and not timed_out:
                    app.root.after(100, record_restart_observation)
                    return
                marker = state.get("pending_parked_restore") if isinstance(state, dict) else None
                source_path = Path(str(cut["parked_source_path"])) if cut.get("parked_source_path") else None
                durable_json(
                    run_root / f"{args.mode}_observation.json",
                    {
                        "pid": os.getpid(),
                        "case": args.case,
                        "mode": args.mode,
                        "observed_wall_time_ns": time.time_ns(),
                        "window_rect": window_rect(int(app.root.winfo_id())),
                        "schema_table_set_gate": "PASS_CONSTRUCTOR_COMPLETED",
                        "event_type": event_type,
                        "idempotency_key": key,
                        "exact_event_count": len(matches),
                        "exact_rows": matches,
                        "state_path": str(state_path),
                        "state_exists": state_path.exists(),
                        "state_sha256": sha256_file(state_path) if state_path.exists() else None,
                        "state_phase": state.get("phase") if isinstance(state, dict) else None,
                        "pending_event_present": bool(isinstance(state, dict) and state.get("pending_event")),
                        "pending_parked_restore_present": isinstance(marker, Mapping),
                        "parked_source_path": str(source_path) if source_path else None,
                        "parked_source_exists": bool(source_path and source_path.exists()),
                        "visible": visible_state(app),
                        "timed_out": timed_out,
                    },
                )

            app.root.after(100, record_restart_observation)

        print(json.dumps({"pid": os.getpid(), "hwnd": hwnd, "case": args.case, "mode": args.mode}), flush=True)
        app.run()
        return 0
    finally:
        lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
