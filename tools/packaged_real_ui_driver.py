from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import win32clipboard
import win32api
import win32con
import win32gui

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from manual_real_ui_walkthrough_capture import (  # noqa: E402
    _resolve_startup_geometry,
    capture_window,
    find_window,
    move_window_to_geometry,
)


def _import_pywinauto():
    try:
        from pywinauto import Application, keyboard, mouse
    except ImportError as exc:
        raise SystemExit(
            "pywinauto is required. Install it in the validation venv: "
            ".tmp\\real-ui-uia-venv\\Scripts\\python.exe -m pip install pywinauto==0.6.9 pillow pywin32 pyautogui"
        ) from exc
    return Application, keyboard, mouse


def redacted_value(value: str) -> dict[str, Any]:
    raw = value or ""
    return {
        "sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
        "length": len(raw),
    }


def redacted_list(values: list[str]) -> list[dict[str, Any]]:
    return [redacted_value(value) for value in values]


def get_clipboard_text() -> str | None:
    try:
        win32clipboard.OpenClipboard()
    except Exception:
        return None
    try:
        if not win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            return None
        return str(win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT))
    except Exception:
        return None
    finally:
        win32clipboard.CloseClipboard()


def set_clipboard_text(text: str) -> None:
    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32clipboard.CF_UNICODETEXT, text)
    finally:
        win32clipboard.CloseClipboard()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_event_rows(data_root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    events_dir = data_root / "events"
    if not events_dir.exists():
        return rows
    for path in sorted(events_dir.glob("*.csv")):
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                row["_source_file"] = str(path.resolve())
                rows.append(row)
    return rows


def summarize_events(rows: list[dict[str, str]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    malformed_details = 0
    test_markers = 0
    source_files = sorted({row.get("_source_file", "") for row in rows if row.get("_source_file")})
    for row in rows:
        event = (row.get("event") or row.get("event_type") or "").strip()
        if event:
            counts[event] = counts.get(event, 0) + 1
        details = row.get("details") or ""
        if "_RUN_AUTO_TEST_" in details or "TEST_LOG_" in details:
            test_markers += 1
        if details:
            try:
                json.loads(details)
            except json.JSONDecodeError:
                malformed_details += 1
    return {
        "row_count": len(rows),
        "counts": counts,
        "malformed_details": malformed_details,
        "test_markers": test_markers,
        "source_file_count": len(source_files),
        "source_file_refs": [redacted_value(path) for path in source_files],
        "source_file_paths_redacted": True,
    }


class Driver:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.Application, self.keyboard, self.mouse = _import_pywinauto()
        self.output_root = args.output_root.resolve()
        self.screenshots_dir = self.output_root / "screenshots"
        self.data_root = args.data_root.resolve()
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.report: dict[str, Any] = {
            "report_version": "container-audit-packaged-real-ui-driver-v1",
            "started_at": datetime.now().astimezone().isoformat(),
            "exe": str(args.exe.resolve()),
            "output_root": str(self.output_root),
            "data_root": str(self.data_root),
            "geometry": args.geometry,
            "worker_ref": redacted_value(args.worker),
            "master_label_ref": redacted_value(args.master_label),
            "product_barcode_refs": redacted_list(args.product_barcode),
            "steps": [],
            "screenshots": [],
            "forbidden_test_inputs_used": False,
            "input_method": "external Windows mouse/keyboard against packaged exe",
            "raw_input_values_redacted": True,
        }
        self.original_clipboard_text = get_clipboard_text()
        self.process: subprocess.Popen | None = None
        self.hwnd: int | None = None
        self.app = None

    def _save_report(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        (self.output_root / "real_ui_no_human_walkthrough_report.json").write_text(
            json.dumps(self.report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def launch(self) -> None:
        if self.args.preseed_worker:
            registry_path = self.args.exe.parent / "config" / "worker_registry.json"
            registry_path.parent.mkdir(parents=True, exist_ok=True)
            registry_path.write_text(
                json.dumps(
                    {
                        "workers": [
                            {
                                "name": self.args.worker,
                                "active": True,
                                "created_at": datetime.now().isoformat(timespec="seconds"),
                            }
                        ]
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            self.report["preseed_worker_registry"] = str(registry_path.resolve())
        env = os.environ.copy()
        env["CONTAINER_AUDIT_STARTUP_GEOMETRY"] = self.args.geometry
        env["CONTAINER_AUDIT_DATA_ROOT"] = str(self.data_root)
        env["PYTHONUTF8"] = "1"
        self.process = subprocess.Popen([str(self.args.exe)], cwd=str(self.args.exe.parent), env=env)
        self.app = self.Application(backend="win32").connect(process=self.process.pid, timeout=self.args.startup_timeout)
        self.report["pid"] = self.process.pid
        deadline = time.time() + self.args.startup_timeout
        last_error = ""
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                window = find_window(self.args.window_title_pattern)
                if window["pid"] == self.process.pid or self.args.allow_title_match_any_pid:
                    self.hwnd = int(window["hwnd"])
                    move_window_to_geometry(self.hwnd, self.args.geometry)
                    time.sleep(0.3)
                    self.step("launch_window_found", "PASS", window=window)
                    return
            except Exception as exc:
                last_error = str(exc)
        raise RuntimeError(f"target window not found: {last_error}")

    def step(self, name: str, status: str, **extra: Any) -> None:
        item = {"name": name, "status": status, "at": datetime.now().astimezone().isoformat()}
        item.update(extra)
        self.report["steps"].append(item)
        self._save_report()

    def window_rect(self) -> tuple[int, int, int, int]:
        if self.hwnd is None:
            window = find_window(self.args.window_title_pattern)
            self.hwnd = int(window["hwnd"])
        left, top, right, bottom = win32gui.GetWindowRect(self.hwnd)
        return left, top, right, bottom

    def activate_window(self) -> None:
        if self.hwnd is None:
            window = find_window(self.args.window_title_pattern)
            self.hwnd = int(window["hwnd"])
        try:
            win32gui.ShowWindow(self.hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(self.hwnd)
        except Exception:
            # A real mouse click below is still enough to focus Tk controls on most desktops.
            pass
        time.sleep(0.15)

    def ensure_target_foreground(self) -> None:
        if self.hwnd is None:
            raise RuntimeError("target hwnd is not available")
        foreground = win32gui.GetForegroundWindow()
        if foreground == self.hwnd:
            return
        try:
            _, expected_pid = win32gui.GetWindowThreadProcessId(self.hwnd)
            _, actual_pid = win32gui.GetWindowThreadProcessId(foreground)
        except Exception as exc:
            raise RuntimeError(f"cannot verify foreground target: {exc}") from exc
        if actual_pid != expected_pid:
            title = win32gui.GetWindowText(foreground) or ""
            raise RuntimeError(
                "refusing to send scanner input because the target app is not foreground; "
                f"foreground_title={title!r}"
            )

    def click_rel(self, x_ratio: float, y_ratio: float) -> None:
        self.activate_window()
        left, top, right, bottom = self.window_rect()
        x = int(left + (right - left) * x_ratio)
        y = int(top + (bottom - top) * y_ratio)
        win32api.SetCursorPos((x, y))
        time.sleep(0.05)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, x, y, 0, 0)
        time.sleep(0.05)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, x, y, 0, 0)
        time.sleep(self.args.action_delay)

    def send_text_enter(self, text: str) -> None:
        self.activate_window()
        self.ensure_target_foreground()
        set_clipboard_text(text)
        self.keyboard.send_keys("^v")
        time.sleep(0.15)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)

    def press_enter(self) -> None:
        self.activate_window()
        self.ensure_target_foreground()
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)

    def capture(self, label: str) -> None:
        if self.hwnd is None:
            window = find_window(self.args.window_title_pattern)
            self.hwnd = int(window["hwnd"])
        move_window_to_geometry(self.hwnd, self.args.geometry)
        path = self.screenshots_dir / f"{len(self.report['screenshots']) + 1:02d}_{label}.png"
        capture = capture_window(self.hwnd, path)
        capture["label"] = label
        self.report["screenshots"].append(capture)
        self._save_report()

    def handle_login(self) -> None:
        self.capture("01_launch_login")
        entry = self.login_worker_entry()
        if entry is None:
            self.click_rel(0.50, 0.70)
        else:
            entry.click_input()
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        set_clipboard_text(self.args.worker)
        self.keyboard.send_keys("^v")
        time.sleep(0.3)
        start_button = self.login_start_button()
        if start_button is None:
            self.click_rel(0.56, 0.83)
        else:
            start_button.click_input()
        if not self.args.preseed_worker and self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=3.0):
            self.click_dialog_button(["확인", "OK"], timeout=3.0)
        time.sleep(1.5)
        self.capture("02_first_time_worker_registered_or_started")
        self.step("login_first_time_worker", "PASS")

    def login_worker_entry(self):
        if self.app is None:
            return None
        window = self.app.top_window()
        candidates = []
        for child in window.descendants():
            try:
                rect = child.rectangle()
            except Exception:
                continue
            if rect.width() >= 250 and 45 <= rect.height() <= 90:
                center_y = (rect.top + rect.bottom) / 2
                if center_y > window.rectangle().top + window.rectangle().height() * 0.55:
                    candidates.append((center_y, -rect.width(), child))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    def login_start_button(self):
        if self.app is None:
            return None
        window = self.app.top_window()
        win_rect = window.rectangle()
        candidates = []
        for child in window.descendants():
            try:
                rect = child.rectangle()
            except Exception:
                continue
            if 120 <= rect.width() <= 360 and 35 <= rect.height() <= 90:
                center_x = (rect.left + rect.right) / 2
                center_y = (rect.top + rect.bottom) / 2
                if center_x > win_rect.left + win_rect.width() * 0.50 and center_y > win_rect.top + win_rect.height() * 0.65:
                    candidates.append((center_y, -center_x, child))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    def click_dialog_button(self, titles: list[str], timeout: float = 5.0) -> bool:
        if self.app is None:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                dialog = self.app.top_window()
                if dialog.class_name() != "#32770":
                    time.sleep(0.1)
                    continue
                for title in titles:
                    try:
                        button = dialog.child_window(title=title, class_name="Button")
                        if button.exists(timeout=0.1):
                            button.click_input()
                            time.sleep(0.4)
                            return True
                    except Exception:
                        continue
                for button in dialog.children(class_name="Button"):
                    text = button.window_text()
                    if any(title in text for title in titles):
                        button.click_input()
                        time.sleep(0.4)
                        return True
            except Exception:
                pass
            time.sleep(0.1)
        return False

    def main_scan_entry(self):
        if self.app is None:
            return None
        window = self.app.top_window()
        win_rect = window.rectangle()
        candidates = []
        for child in window.descendants():
            try:
                rect = child.rectangle()
            except Exception:
                continue
            width = rect.width()
            height = rect.height()
            # Main scan entry is the wide center Tk child above the scanned list.
            if (
                width >= 700
                and 55 <= height <= 120
                and rect.top > win_rect.top + win_rect.height() * 0.25
                and rect.bottom < win_rect.top + win_rect.height() * 0.60
            ):
                candidates.append((rect.top, -width, child))
        if not candidates:
            return None
        candidates.sort()
        selected = candidates[0][2]
        try:
            rect = selected.rectangle()
            self.report.setdefault("scan_entry_candidates", []).append(
                {
                    "handle": int(selected.handle),
                    "rect": [rect.left, rect.top, rect.right, rect.bottom],
                    "width": rect.width(),
                    "height": rect.height(),
                    "class": selected.friendly_class_name(),
                }
            )
            self._save_report()
        except Exception:
            pass
        return selected

    def click_main_scan_entry(self) -> None:
        entry = self.main_scan_entry()
        if entry is None:
            self.click_rel(0.51, 0.37)
            return
        entry.click_input()
        time.sleep(self.args.action_delay)

    def dismiss_warning(self) -> None:
        # Fullscreen warning button sits around the lower middle. Native dialogs
        # also accept Enter.
        self.press_enter()
        self.click_rel(0.50, 0.73)
        time.sleep(0.5)

    def scan(self, value: str, step_name: str, capture_name: str, wait_after: float = 1.0) -> None:
        entry = self.main_scan_entry()
        if entry is None:
            self.click_main_scan_entry()
            entry = None
        else:
            entry.click_input()
        time.sleep(0.1)
        set_clipboard_text(value)
        if entry is not None:
            entry.click_input()
            self.ensure_target_foreground()
            import pyautogui

            pyautogui.hotkey("ctrl", "a")
            time.sleep(0.1)
            pyautogui.write(value, interval=0.001)
            time.sleep(0.1)
            pyautogui.press("enter")
            time.sleep(self.args.action_delay)
        else:
            self.send_text_enter(value)
        time.sleep(wait_after)
        self.capture(capture_name)
        self.step(step_name, "PASS", input_ref=redacted_value(value))

    def click_undo(self) -> None:
        self.click_rel(0.40, 0.88)
        time.sleep(0.8)
        self.capture("06_undo_last_scan")
        self.step("undo_last_scan_clicked", "PASS")

    def run(self) -> int:
        try:
            self.launch()
            self.handle_login()

            self.capture("03_main_waiting")

            if not self.args.skip_invalid_warning:
                self.scan("INVALID_MASTER_LABEL_REALUI", "invalid_master_sent", "04_invalid_master_warning", wait_after=0.8)
                self.dismiss_warning()
                self.capture("05_warning_dismissed_back_to_waiting")

            self.scan(self.args.master_label, "master_label_sent", "06_master_label_loaded", wait_after=1.2)
            if not self.args.product_barcode:
                raise RuntimeError("at least one --product-barcode is required")

            self.scan(self.args.product_barcode[0], "product_1_sent", "07_product_scan_1", wait_after=1.0)
            if self.args.do_undo:
                self.click_undo()
                self.scan(self.args.product_barcode[0], "product_1_rescanned_after_undo", "08_product_scan_1_after_undo", wait_after=1.0)

            if self.args.do_duplicate_warning:
                self.scan(self.args.product_barcode[0], "duplicate_product_sent", "09_duplicate_product_warning", wait_after=0.8)
                self.dismiss_warning()
                self.capture("10_duplicate_warning_dismissed")

            for index, barcode in enumerate(self.args.product_barcode[1:], start=2):
                self.scan(barcode, f"product_{index}_sent", f"{10 + index:02d}_product_scan_{index}", wait_after=1.3)

            time.sleep(1.2)
            self.capture("20_completion_or_waiting")
            self.collect_evidence()
            return 0 if self.report.get("status") == "PASS" else 2
        except Exception as exc:
            self.report["status"] = "FAIL"
            self.report["error"] = f"{exc.__class__.__name__}: {exc}"
            self._save_report()
            return 1
        finally:
            if self.original_clipboard_text is not None:
                try:
                    set_clipboard_text(self.original_clipboard_text)
                except Exception:
                    self.report["clipboard_restore_status"] = "FAILED"
                else:
                    self.report["clipboard_restore_status"] = "PASS"
                self._save_report()
            if not self.args.keep_running and self.process is not None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()

    def collect_evidence(self) -> None:
        rows = read_event_rows(self.data_root)
        summary = summarize_events(rows)
        (self.output_root / "event_csv_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        redacted_rows = []
        for row in rows:
            redacted_rows.append(
                {
                    "timestamp": row.get("timestamp") or row.get("created_at") or row.get("time") or "",
                    "event": row.get("event") or row.get("event_type") or "",
                    "_source_file_ref": redacted_value(row.get("_source_file", "")),
                    "details_present": bool(row.get("details")),
                    "redacted_columns": sorted(
                        key for key, value in row.items() if key not in {"timestamp", "created_at", "time", "event", "event_type", "_source_file", "details"} and bool(value)
                    ),
                }
            )
        (self.output_root / "event_rows_redacted.json").write_text(
            json.dumps(redacted_rows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        required = {
            "WORK_START": 1,
            "MASTER_LABEL_SCANNED_NEW": 1,
            "SCAN_OK": len(self.args.product_barcode),
            "TRAY_COMPLETE": 1,
        }
        checks = {
            event: summary["counts"].get(event, 0) >= minimum
            for event, minimum in required.items()
        }
        checks["no_test_markers"] = summary["test_markers"] == 0
        checks["details_json_parse"] = summary["malformed_details"] == 0
        checks["not_syncthing_data_root"] = not re.match(r"(?i)^c:\\sync(\\|$)", str(self.data_root))
        checks["screenshots_nonblank"] = all(not item.get("blank_suspected") for item in self.report["screenshots"])
        self.report["event_summary"] = summary
        self.report["pass_checks"] = checks
        self.report["status"] = "PASS" if all(checks.values()) else "FAIL"
        self.report["finished_at"] = datetime.now().astimezone().isoformat()
        self._save_report()
        evidence_index = {
            "report": str((self.output_root / "real_ui_no_human_walkthrough_report.json").resolve()),
            "event_summary": str((self.output_root / "event_csv_summary.json").resolve()),
            "event_rows_redacted": str((self.output_root / "event_rows_redacted.json").resolve()),
            "screenshots": [item["path"] for item in self.report["screenshots"]],
            "raw_payload_policy": "input payloads are SHA-256 hashed or omitted from JSON evidence",
        }
        (self.output_root / "evidence_index.json").write_text(
            json.dumps(evidence_index, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        hash_lines: list[str] = []
        for path in sorted(self.output_root.rglob("*")):
            if path.is_file() and path.name != "artifact_hashes.sha256":
                hash_lines.append(f"{sha256_file(path)}  {path.relative_to(self.output_root).as_posix()}")
        (self.output_root / "artifact_hashes.sha256").write_text("\n".join(hash_lines) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Drive packaged Container_Audit.exe through the real UI.")
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument(
        "--geometry",
        default="",
        help="Tk geometry for the validation window. Required unless --prefer-secondary-monitor detects a non-primary monitor.",
    )
    parser.add_argument(
        "--prefer-secondary-monitor",
        action="store_true",
        help="Use a detected non-primary monitor when --geometry is omitted.",
    )
    parser.add_argument("--window-title-pattern", default=r"이적 검사 시스템|Container_Audit|이적실|Audit")
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    parser.add_argument("--action-delay", type=float, default=0.5)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--master-label", required=True)
    parser.add_argument("--product-barcode", action="append", default=[])
    parser.add_argument("--do-undo", action="store_true")
    parser.add_argument("--do-duplicate-warning", action="store_true")
    parser.add_argument("--preseed-worker", action="store_true")
    parser.add_argument("--skip-invalid-warning", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--allow-title-match-any-pid", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.geometry:
        args.geometry = _resolve_startup_geometry("", args.prefer_secondary_monitor)
    if not args.geometry:
        raise SystemExit("--geometry is required unless --prefer-secondary-monitor detects a secondary display")
    if "_RUN_AUTO_TEST_" in args.master_label or "TEST_LOG_" in args.master_label:
        raise SystemExit("forbidden test marker in master label")
    for barcode in args.product_barcode:
        if "_RUN_AUTO_TEST_" in barcode or "TEST_LOG_" in barcode:
            raise SystemExit("forbidden test marker in product barcode")
    return Driver(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
