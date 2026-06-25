#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run a bounded Container_Audit UI/scanner validation and capture evidence."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from storage_policy import build_container_audit_storage_paths  # noqa: E402
from storage_utils import atomic_write_json  # noqa: E402
from worker_registry import WorkerRegistry  # noqa: E402


WORKER_NAME = "VALIDATION"
ITEM_CODE = "AAA2270730200"
PRIMARY_MONITOR_FLAG = 1


def _timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def _default_output_root() -> Path:
    return ROOT / ".codex" / f"ui-validation-{_timestamp()}"


def _tk_offset(value: int) -> str:
    return f"+{value}" if value >= 0 else str(value)


def _detect_secondary_monitor_geometry() -> str:
    if os.name != "nt":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        class MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        monitors: list[dict[str, int | bool]] = []
        user32 = ctypes.windll.user32
        monitor_enum_proc = ctypes.WINFUNCTYPE(
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.RECT),
            ctypes.c_void_p,
        )
        user32.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MonitorInfo)]

        def callback(h_monitor, _hdc_monitor, _rect, _data):
            info = MonitorInfo()
            info.cbSize = ctypes.sizeof(MonitorInfo)
            if user32.GetMonitorInfoW(h_monitor, ctypes.byref(info)):
                monitors.append(
                    {
                        "left": int(info.rcWork.left),
                        "top": int(info.rcWork.top),
                        "right": int(info.rcWork.right),
                        "bottom": int(info.rcWork.bottom),
                        "primary": bool(info.dwFlags & PRIMARY_MONITOR_FLAG),
                    }
                )
            return 1

        user32.EnumDisplayMonitors(None, None, monitor_enum_proc(callback), None)
        primary = next((monitor for monitor in monitors if monitor["primary"]), None)
        secondary = [monitor for monitor in monitors if not monitor["primary"]]
        if not primary or not secondary:
            return ""
        right_side = [monitor for monitor in secondary if monitor["left"] >= primary["right"]]
        candidates = right_side or secondary
        selected = sorted(
            candidates,
            key=lambda monitor: (
                0 if monitor["left"] >= primary["right"] else 1,
                abs(int(monitor["top"]) - int(primary["top"])),
                int(monitor["left"]),
            ),
        )[0]
        margin = 40
        available_width = int(selected["right"]) - int(selected["left"])
        available_height = int(selected["bottom"]) - int(selected["top"])
        width = min(1600, max(640, available_width - margin * 2))
        height = min(900, max(480, available_height - margin * 2))
        x = int(selected["left"]) + margin
        y = int(selected["top"]) + margin
        return f"{width}x{height}{_tk_offset(x)}{_tk_offset(y)}"
    except Exception:
        return ""


def _resolve_startup_geometry(window_mode: str, explicit_geometry: str, offscreen_geometry: str) -> str:
    if explicit_geometry.strip():
        return explicit_geometry.strip()
    if window_mode == "offscreen":
        return offscreen_geometry.strip()
    return _detect_secondary_monitor_geometry()


def _write_worker_registry(config_root: Path, worker_name: str) -> None:
    registry_path = config_root / "worker_registry.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry = WorkerRegistry(str(registry_path))
    registry.register(worker_name)


def _read_csv_rows(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Container_Audit UI validation with screenshots")
    parser.add_argument("--output-root", default="")
    parser.add_argument("--worker-name", default=WORKER_NAME)
    parser.add_argument("--master-label", default="")
    parser.add_argument("--product-barcode", action="append", default=[])
    parser.add_argument("--test-log-count", type=int, default=3)
    parser.add_argument("--window-mode", choices=["offscreen", "normal"], default="offscreen")
    parser.add_argument("--offscreen-geometry", default="1600x900-32000-32000")
    parser.add_argument("--startup-geometry", default="")
    args = parser.parse_args(argv)

    run_id = _timestamp()
    output_root = Path(args.output_root).expanduser() if args.output_root else _default_output_root()
    startup_geometry = _resolve_startup_geometry(args.window_mode, args.startup_geometry, args.offscreen_geometry)
    master_label = args.master_label or (
        f"PHS=1|CLC={ITEM_CODE}|WID=MFG-WO-VALIDATION-{run_id}|SPC=A14|"
        "FPB=A146000306|OBD=2026-06-25|PJT=KMC_LHD|QT=2"
    )
    product_barcodes = list(args.product_barcode) or [
        f"{ITEM_CODE}-VALIDATION-{run_id}-0001",
        f"{ITEM_CODE}-VALIDATION-{run_id}-0002",
    ]
    screenshots_dir = output_root / "screenshots"
    config_root = output_root / "config"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    (config_root / "parked_trays").mkdir(parents=True, exist_ok=True)
    _write_worker_registry(config_root, args.worker_name)

    import tkinter as tk
    from PIL import ImageGrab
    import Container_Audit as ca

    original_setup_paths = ca.ContainerAudit._setup_paths_and_dirs
    original_load_settings = ca.ContainerAudit.load_app_settings

    def setup_validation_paths(self):
        original_setup_paths(self)
        self.config_folder = str(config_root)
        self.parked_trays_dir = str(config_root / "parked_trays")
        os.makedirs(self.config_folder, exist_ok=True)
        os.makedirs(self.parked_trays_dir, exist_ok=True)

    def load_validation_settings(self):
        settings = original_load_settings(self)
        settings["scale_factor"] = 1.0
        settings["enable_internal_test_commands"] = True
        return settings

    ca.ContainerAudit._setup_paths_and_dirs = setup_validation_paths
    ca.ContainerAudit.load_app_settings = load_validation_settings

    report: dict = {
        "report_version": "container-audit-ui-validation-v1",
        "status": "RUNNING",
        "started_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "run_id": run_id,
        "output_root": str(output_root.resolve()),
        "worker_name": args.worker_name,
        "master_label": master_label,
        "product_barcodes": product_barcodes,
        "screenshots": [],
        "steps": [],
        "window_mode": args.window_mode,
        "startup_geometry": startup_geometry,
    }
    storage_paths = build_container_audit_storage_paths(application_path=str(ROOT))
    log_file = storage_paths.events_dir / f"이적작업이벤트로그_{args.worker_name}_{dt.date.today():%Y%m%d}.csv"
    initial_row_count = len(_read_csv_rows(log_file)) if log_file.exists() else 0

    def pump(app, milliseconds: int = 500) -> None:
        deadline = time.time() + milliseconds / 1000.0
        while time.time() < deadline:
            app.root.update()
            time.sleep(0.03)

    def capture(app, label: str) -> None:
        app.root.update_idletasks()
        x = app.root.winfo_rootx()
        y = app.root.winfo_rooty()
        w = max(1, app.root.winfo_width())
        h = max(1, app.root.winfo_height())
        path = screenshots_dir / f"{len(report['screenshots']) + 1:02d}-{label}.png"
        try:
            try:
                image = ImageGrab.grab(window=app.root.winfo_id())
            except Exception:
                image = ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True)
            image.save(path)
            report["screenshots"].append({"label": label, "path": str(path.resolve()), "status": "PASS"})
        except Exception as exc:
            report["screenshots"].append({"label": label, "path": str(path.resolve()), "status": "FAIL", "error": str(exc)})

    def scan_entry(app, text: str, label: str) -> None:
        app.scan_entry.delete(0, tk.END)
        app.scan_entry.insert(0, text)
        app.process_barcode()
        pump(app, 900)
        report["steps"].append({"label": label, "input": text})
        capture(app, label)

    app = None
    try:
        previous_startup_geometry = os.environ.get("CONTAINER_AUDIT_STARTUP_GEOMETRY")
        if startup_geometry:
            os.environ["CONTAINER_AUDIT_STARTUP_GEOMETRY"] = startup_geometry
        app = ca.ContainerAudit()
        if startup_geometry:
            app.root.geometry(startup_geometry)
        app.root.update()
        capture(app, "login")
        app.worker_entry_var.set(args.worker_name)
        app.start_work()
        pump(app, 900)
        capture(app, "work-start")
        scan_entry(app, master_label, "master-label")
        for index, barcode in enumerate(product_barcodes, start=1):
            scan_entry(app, barcode, f"product-scan-{index}")
        if args.test_log_count > 0:
            scan_entry(app, f"TEST_LOG_{args.test_log_count}", "internal-test-log")
            pump(app, 1200)
        capture(app, "final-state")

        rows = _read_csv_rows(log_file)
        new_rows = rows[initial_row_count:]
        event_counts: dict[str, int] = {}
        for row in new_rows:
            event_counts[row.get("event", "")] = event_counts.get(row.get("event", ""), 0) + 1
        report.update(
            {
                "status": "PASS",
                "events_dir": str(storage_paths.events_dir),
                "log_file": str(log_file),
                "initial_row_count": initial_row_count,
                "row_count": len(rows),
                "new_row_count": len(new_rows),
                "event_counts": event_counts,
                "required_events_present": {
                    "WORK_START": event_counts.get("WORK_START", 0) >= 1,
                    "MASTER_LABEL_SCANNED_NEW": event_counts.get("MASTER_LABEL_SCANNED_NEW", 0) >= 1,
                    "SCAN_OK": event_counts.get("SCAN_OK", 0) >= 2,
                    "TRAY_COMPLETE": event_counts.get("TRAY_COMPLETE", 0) >= 1,
                },
            }
        )
        if not all(report["required_events_present"].values()):
            report["status"] = "FAIL"
        if log_file.exists():
            shutil.copy2(log_file, output_root / log_file.name)
    except Exception as exc:
        report["status"] = "FAIL"
        report["error"] = f"{exc.__class__.__name__}: {exc}"
    finally:
        if "previous_startup_geometry" in locals():
            if previous_startup_geometry is None:
                os.environ.pop("CONTAINER_AUDIT_STARTUP_GEOMETRY", None)
            else:
                os.environ["CONTAINER_AUDIT_STARTUP_GEOMETRY"] = previous_startup_geometry
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        atomic_write_json(output_root / "ui_validation_report.json", report, indent=2, ensure_ascii=False, trailing_newline=True)
        if app is not None:
            try:
                app.root.destroy()
            except Exception:
                pass

    print(f"ui_validation_report={(output_root / 'ui_validation_report.json').resolve()}")
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
