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
import win32process

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from manual_real_ui_walkthrough_capture import (  # noqa: E402
    _resolve_startup_geometry,
    _visible_windows,
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


def _parse_geometry_rect(geometry: str) -> tuple[int, int, int, int] | None:
    match = re.match(r"^(\d+)x(\d+)([+-]\d+)([+-]\d+)$", geometry.strip())
    if not match:
        return None
    width, height, x, y = match.groups()
    left = int(x)
    top = int(y)
    return left, top, left + int(width), top + int(height)


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
    tray_complete_partial_count = 0
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
                parsed_details = json.loads(details)
            except json.JSONDecodeError:
                malformed_details += 1
            else:
                if event == "TRAY_COMPLETE" and parsed_details.get("is_partial_submission") is True:
                    tray_complete_partial_count += 1
    return {
        "row_count": len(rows),
        "counts": counts,
        "malformed_details": malformed_details,
        "test_markers": test_markers,
        "tray_complete_partial_count": tray_complete_partial_count,
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
            "replacement_master_label_ref": redacted_value(args.replacement_master_label or ""),
            "product_barcode_refs": redacted_list(args.product_barcode),
            "scenario": args.scenario,
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

    def main_window_wrapper(self):
        if self.app is None:
            return None
        if self.hwnd is not None:
            try:
                return self.app.window(handle=self.hwnd)
            except Exception:
                pass
        return self.app.top_window()

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
        self.activate_window()
        foreground = win32gui.GetForegroundWindow()
        if foreground == self.hwnd:
            return
        try:
            _, expected_pid = win32process.GetWindowThreadProcessId(self.hwnd)
            _, actual_pid = win32process.GetWindowThreadProcessId(foreground)
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
        self.click_in_rect(left, top, right, bottom, x_ratio, y_ratio)

    def click_in_rect(self, left: int, top: int, right: int, bottom: int, x_ratio: float, y_ratio: float) -> None:
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

    def process_windows(self) -> list[dict[str, Any]]:
        if self.process is None:
            return []
        return [window for window in _visible_windows() if int(window["pid"]) == int(self.process.pid)]

    def find_process_window(
        self,
        *,
        title_pattern: str | None = None,
        exclude_main: bool = False,
        timeout: float = 5.0,
    ) -> dict[str, Any] | None:
        deadline = time.time() + timeout
        title_re = re.compile(title_pattern, re.IGNORECASE) if title_pattern else None
        main_re = re.compile(self.args.window_title_pattern, re.IGNORECASE)
        while time.time() < deadline:
            candidates = []
            for window in self.process_windows():
                title = window.get("title", "")
                if title_re and not title_re.search(title):
                    continue
                if exclude_main and main_re.search(title):
                    continue
                left, top, right, bottom = window["rect"]
                area = max(0, right - left) * max(0, bottom - top)
                candidates.append((area, window))
            if candidates:
                candidates.sort(key=lambda item: item[0], reverse=True)
                return candidates[0][1]
            time.sleep(0.1)
        return None

    def capture_hwnd(self, hwnd: int, label: str) -> None:
        path = self.screenshots_dir / f"{len(self.report['screenshots']) + 1:02d}_{label}.png"
        capture = capture_window(hwnd, path)
        capture["label"] = label
        capture["hwnd"] = int(hwnd)
        self.report["screenshots"].append(capture)
        self._save_report()

    def move_child_window_near_main(self, hwnd: int, *, width: int = 900, height: int = 650) -> None:
        main_left, main_top, main_right, main_bottom = self.window_rect()
        x = main_left + max(20, ((main_right - main_left) - width) // 2)
        y = main_top + max(40, ((main_bottom - main_top) - height) // 2)
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetWindowPos(
            hwnd,
            None,
            x,
            y,
            width,
            height,
            win32con.SWP_NOZORDER,
        )
        time.sleep(0.2)

    def capture_process_window(self, label: str, title_pattern: str, *, move_near_main: bool = True) -> bool:
        window = self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=5.0)
        if window is None:
            self.step(f"{label}_window_found", "FAIL", title_pattern=title_pattern)
            return False
        hwnd = int(window["hwnd"])
        if move_near_main:
            self.move_child_window_near_main(hwnd)
        self.capture_hwnd(hwnd, label)
        self.step(f"{label}_window_found", "PASS", title=window.get("title", ""))
        return True

    def click_process_window(
        self,
        title_pattern: str,
        x_ratio: float,
        y_ratio: float,
        *,
        timeout: float = 5.0,
        move_near_main: bool = True,
    ) -> bool:
        window = self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=timeout)
        if window is None:
            self.step("process_window_click", "FAIL", title_pattern=title_pattern)
            return False
        hwnd = int(window["hwnd"])
        if move_near_main:
            self.move_child_window_near_main(hwnd)
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        else:
            left, top, right, bottom = window["rect"]
        try:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        self.click_in_rect(left, top, right, bottom, x_ratio, y_ratio)
        self.step("process_window_clicked", "PASS", title=window.get("title", ""), x_ratio=x_ratio, y_ratio=y_ratio)
        return True

    def send_text_enter_to_process_window(
        self,
        title_pattern: str,
        value: str,
        x_ratio: float,
        y_ratio: float,
        *,
        timeout: float = 5.0,
    ) -> bool:
        if not self.click_process_window(title_pattern, x_ratio, y_ratio, timeout=timeout):
            return False
        set_clipboard_text(value)
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        self.keyboard.send_keys("^v")
        time.sleep(0.1)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)
        return True

    def capture_warning(self, label: str, title_pattern: str | None = None) -> bool:
        warning = self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=5.0)
        if warning is None:
            self.step(f"{label}_warning_window_found", "FAIL")
            return False
        self.capture_hwnd(int(warning["hwnd"]), label)
        self.step(f"{label}_warning_window_found", "PASS", title=warning.get("title", ""))
        return True

    def dismiss_warning(self) -> None:
        warning = self.find_process_window(exclude_main=True, timeout=2.0)
        if warning is not None:
            left, top, right, bottom = warning["rect"]
            hwnd = int(warning["hwnd"])
            title = warning.get("title", "")
            clicked = False
            try:
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            time.sleep(0.1)
            self.keyboard.send_keys("{SPACE}")
            time.sleep(0.3)
            still_open_after_key = self.find_process_window(title_pattern=re.escape(title), exclude_main=True, timeout=0.5)
            if still_open_after_key is None:
                self.step(
                    "warning_dismissed",
                    "PASS",
                    title=title,
                    clicked_by_text=False,
                    dismissed_by_key=True,
                    still_open=False,
                )
                return
            if self.app is not None:
                try:
                    popup = self.app.window(handle=hwnd)
                    for child in popup.descendants():
                        text = child.window_text() or ""
                        if "확인" in text:
                            child.click_input()
                            clicked = True
                            break
                except Exception:
                    clicked = False
            if not clicked:
                self.click_in_rect(left, top, right, bottom, 0.333, 0.55)
            time.sleep(0.8)
            still_open = self.find_process_window(title_pattern=re.escape(title), exclude_main=True, timeout=1.0)
            self.step(
                "warning_dismissed",
                "PASS" if still_open is None else "FAIL",
                title=title,
                clicked_by_text=clicked,
                still_open=still_open is not None,
            )
            return
        self.press_enter()
        self.click_rel(0.50, 0.73)
        time.sleep(0.5)
        self.step("warning_dismissed", "REVIEW")

    def click_button_by_text(
        self,
        fragments: list[str],
        *,
        fallback: tuple[float, float] | None = None,
        timeout: float = 5.0,
    ) -> bool:
        if self.app is None:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for window in self.app.windows():
                    for child in window.descendants():
                        try:
                            text = child.window_text() or ""
                            if not text:
                                continue
                            if all(fragment in text for fragment in fragments):
                                child.click_input()
                                time.sleep(self.args.action_delay)
                                self.step("button_clicked", "PASS", fragments=fragments, text=text)
                                return True
                        except Exception:
                            continue
            except Exception:
                pass
            time.sleep(0.1)
        if fallback is not None:
            self.click_rel(*fallback)
            self.step("button_clicked_by_fallback", "REVIEW", fragments=fragments, fallback=fallback)
            return True
        self.step("button_clicked", "FAIL", fragments=fragments)
        return False

    def capture_dialog(self, label: str) -> bool:
        if self.app is None:
            return False
        try:
            dialog = self.app.top_window()
            if dialog.class_name() == "#32770":
                self.capture_hwnd(int(dialog.handle), label)
                return True
        except Exception:
            pass
        return False

    def wait_for_event_rows(self, minimum: int, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if len(read_event_rows(self.data_root)) >= minimum:
                return True
            time.sleep(0.2)
        return len(read_event_rows(self.data_root)) >= minimum

    def event_count(self, event_name: str) -> int:
        return summarize_events(read_event_rows(self.data_root))["counts"].get(event_name, 0)

    def wait_for_event_count(self, event_name: str, minimum: int, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.event_count(event_name) >= minimum:
                return True
            time.sleep(0.2)
        return self.event_count(event_name) >= minimum

    def handle_possible_login_dialogs(self) -> None:
        for _ in range(3):
            if not self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=0.8):
                break
            self.step("login_dialog_yes_clicked", "PASS")
            self.click_dialog_button(["확인", "OK"], timeout=0.8)

    def handle_login(self) -> None:
        initial_event_count = len(read_event_rows(self.data_root))
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
        self.keyboard.send_keys("{ENTER}")
        time.sleep(0.8)
        self.handle_possible_login_dialogs()
        if not self.wait_for_event_rows(initial_event_count + 1, timeout=2.0):
            clicked_by_text = self.click_button_by_text(["작업", "시작"], timeout=2.0, fallback=(0.54, 0.71))
            if clicked_by_text:
                self.step("login_start_button_clicked", "PASS")
            else:
                start_button = self.login_start_button()
                if start_button is None:
                    self.click_rel(0.54, 0.71)
                    self.step("login_start_button_coordinate_fallback", "REVIEW")
                else:
                    start_button.click_input()
                    self.step("login_start_button_child_fallback", "PASS")
            self.handle_possible_login_dialogs()
        if not self.wait_for_event_rows(initial_event_count + 1, timeout=5.0):
            self.capture("login_failed_no_work_start")
            raise RuntimeError("login did not create WORK_START; still on worker screen or worker registration dialog")
        time.sleep(1.0)
        self.capture("02_first_time_worker_registered_or_started")
        self.step("login_first_time_worker", "PASS")

    def login_worker_entry(self):
        if self.app is None:
            return None
        window = self.main_window_wrapper()
        if window is None:
            return None
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
        window = self.main_window_wrapper()
        if window is None:
            return None
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

    def click_dialog_yes(self, title_pattern: str, *, x_ratio: float = 0.63, y_ratio: float = 0.82) -> bool:
        clicked_by_title = self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=1.0)
        if self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=0.4) is None:
            self.step("dialog_yes_clicked", "PASS", title_pattern=title_pattern, method="button_text")
            return True
        clicked_by_position = self.click_process_window(
            title_pattern,
            x_ratio,
            y_ratio,
            timeout=1.0,
            move_near_main=False,
        )
        if clicked_by_position:
            time.sleep(0.3)
        if self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=0.5) is None:
            self.step(
                "dialog_yes_clicked",
                "PASS",
                title_pattern=title_pattern,
                method="position",
                clicked_by_title=clicked_by_title,
            )
            return True
        self.keyboard.send_keys("{ENTER}")
        time.sleep(0.5)
        closed = self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=0.5) is None
        self.step(
            "dialog_yes_clicked",
            "PASS" if closed else "FAIL",
            title_pattern=title_pattern,
            method="enter_key",
            clicked_by_title=clicked_by_title,
            clicked_by_position=clicked_by_position,
        )
        return closed

    def main_scan_entry(self):
        if self.app is None:
            return None
        window = self.main_window_wrapper()
        if window is None:
            return None
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
            self.click_rel(0.51, 0.27)
            return
        entry.click_input()
        time.sleep(self.args.action_delay)

    def scan(self, value: str, step_name: str, capture_name: str, wait_after: float = 1.0) -> None:
        self.click_main_scan_entry()
        time.sleep(0.1)
        set_clipboard_text(value)
        self.ensure_target_foreground()
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        self.keyboard.send_keys("^v")
        time.sleep(0.1)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)
        time.sleep(wait_after)
        self.capture(capture_name)
        self.step(step_name, "PASS", input_ref=redacted_value(value))

    def click_undo(self) -> None:
        self.click_button_by_text(["마지막", "스캔", "취소"], fallback=(0.51, 0.86))
        time.sleep(0.8)
        self.capture("06_undo_last_scan")
        self.step("undo_last_scan_clicked", "PASS")

    def click_reset(self) -> None:
        self.click_button_by_text(["현재", "작업", "리셋"], fallback=(0.39, 0.86))
        self.capture_dialog("reset_confirm_dialog")
        self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=3.0)
        time.sleep(0.8)
        self.capture("reset_after_confirm")
        self.step("reset_current_work_clicked", "PASS")

    def click_park(self) -> None:
        expected_parked_count = self.event_count("TRAY_PARKED") + 1
        self.click_button_by_text(["트레이", "보류"], fallback=(0.54, 0.885))
        if not self.capture_dialog("park_confirm_dialog"):
            raise RuntimeError("park confirmation dialog was not shown")
        if not self.click_dialog_yes("트레이 보류 확인"):
            raise RuntimeError("park confirmation dialog was not accepted")
        if not self.wait_for_event_count("TRAY_PARKED", expected_parked_count, timeout=5.0):
            self.capture("park_failed_no_event")
            raise RuntimeError("park confirmation did not create TRAY_PARKED")
        time.sleep(0.8)
        self.capture("parked_waiting")
        self.step("park_current_tray_clicked", "PASS")

    def restore_parked_by_master_scan(self) -> None:
        expected_restored_count = self.event_count("TRAY_RESTORED_FROM_PARK") + 1
        self.scan(self.args.master_label, "parked_master_rescan_sent", "parked_restore_prompt", wait_after=0.5)
        if not self.capture_dialog("parked_restore_confirm_dialog"):
            raise RuntimeError("parked tray restore confirmation dialog was not shown")
        if not self.click_dialog_yes("보류|복원|작업"):
            raise RuntimeError("parked tray restore confirmation dialog was not accepted")
        if not self.wait_for_event_count("TRAY_RESTORED_FROM_PARK", expected_restored_count, timeout=5.0):
            self.capture("parked_restore_failed_no_event")
            raise RuntimeError("restore confirmation did not create TRAY_RESTORED_FROM_PARK")
        time.sleep(1.0)
        self.capture("parked_restored")
        self.step("parked_tray_restored", "PASS")

    def click_submit(self) -> None:
        self.click_button_by_text(["트레이", "제출"], fallback=(0.63, 0.91))
        self.capture_dialog("partial_submit_confirm_dialog")
        self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=3.0)
        time.sleep(1.0)
        self.capture("partial_submit_completed")
        self.step("partial_submit_clicked", "PASS")

    def run_invalid_warning(self) -> None:
        self.scan("INVALID_MASTER_LABEL_REALUI", "invalid_master_sent", "invalid_master_warning", wait_after=0.8)
        self.capture_warning("invalid_master_warning_toplevel")
        self.dismiss_warning()
        self.capture("invalid_warning_dismissed_back_to_waiting")

    def run_product_before_master(self) -> None:
        if len(self.args.product_barcode) < 2:
            raise RuntimeError("product-before-master scenario requires two valid product barcodes")
        self.scan(self.args.product_barcode[0], "product_before_master_sent", "product_before_master_warning", wait_after=0.8)
        self.capture_warning("product_before_master_warning_toplevel", r"작업|시작|오류|형식")
        self.dismiss_warning()
        self.capture("product_before_master_warning_dismissed")
        self.scan(self.args.master_label, "master_label_sent_after_product_before_master", "master_label_loaded_after_product_before_master", wait_after=1.2)
        for index, barcode in enumerate(self.args.product_barcode, start=1):
            self.scan(barcode, f"valid_product_{index}_sent_after_product_before_master", f"product_scan_{index}_after_product_before_master", wait_after=1.3)

    def run_duplicate_warning(self) -> None:
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1", wait_after=1.0)
        self.scan(self.args.product_barcode[0], "duplicate_product_sent", "duplicate_product_warning", wait_after=0.8)
        self.capture_warning("duplicate_product_warning_toplevel")
        self.dismiss_warning()
        self.capture("duplicate_warning_dismissed")
        for index, barcode in enumerate(self.args.product_barcode[1:], start=2):
            self.scan(barcode, f"product_{index}_sent", f"product_scan_{index}", wait_after=1.3)

    def run_mismatch_warning(self) -> None:
        if len(self.args.product_barcode) < 3:
            raise RuntimeError("mismatch-warning scenario requires mismatch barcode plus two valid product barcodes")
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "mismatch_product_sent", "mismatch_product_warning", wait_after=0.8)
        self.capture_warning("mismatch_product_warning_toplevel", r"품목|불일치")
        self.dismiss_warning()
        self.capture("mismatch_warning_dismissed")
        for index, barcode in enumerate(self.args.product_barcode[1:], start=1):
            self.scan(barcode, f"valid_product_{index}_sent_after_mismatch", f"product_scan_{index}_after_mismatch", wait_after=1.3)

    def run_reset(self) -> None:
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1_before_reset", wait_after=1.0)
        self.click_reset()

    def run_park_restore(self) -> None:
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1_before_park", wait_after=1.0)
        self.click_park()
        self.restore_parked_by_master_scan()
        for index, barcode in enumerate(self.args.product_barcode[1:], start=2):
            self.scan(barcode, f"product_{index}_sent", f"product_scan_{index}_after_restore", wait_after=1.3)

    def run_partial_submit(self) -> None:
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1_before_partial_submit", wait_after=1.0)
        self.click_submit()

    def close_and_save_active_tray(self) -> None:
        if self.hwnd is None:
            raise RuntimeError("cannot close app before hwnd is available")
        self.capture("exit_recover_before_close")
        win32gui.PostMessage(self.hwnd, win32con.WM_CLOSE, 0, 0)
        time.sleep(0.8)
        self.capture_dialog("exit_confirm_dialog")
        if not self.click_dialog_button(["확인", "OK"], timeout=3.0):
            raise RuntimeError("close confirmation dialog was not accepted")
        time.sleep(0.8)
        self.capture_dialog("exit_save_current_tray_dialog")
        if not self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=3.0):
            raise RuntimeError("save current tray dialog was not accepted")
        if self.process is None:
            raise RuntimeError("process object disappeared during close")
        self.process.wait(timeout=10)
        self.step("app_closed_with_active_tray_saved", "PASS")
        self.hwnd = None
        self.app = None
        self.process = None

    def run_exit_recover(self) -> None:
        if len(self.args.product_barcode) < 2:
            raise RuntimeError("exit-recover scenario requires two --product-barcode values")
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded_before_exit", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1_before_exit", wait_after=1.0)
        self.close_and_save_active_tray()
        self.launch()
        self.handle_login()
        self.capture("exit_recover_restored_after_relaunch")
        self.scan(self.args.product_barcode[1], "product_2_sent_after_recovery", "product_scan_2_after_recovery", wait_after=1.3)

    def click_change_worker(self) -> None:
        self.capture("change_worker_before_click")
        self.click_button_by_text(["작업자", "변경"], fallback=(0.16, 0.10), timeout=3.0)
        time.sleep(0.5)
        self.capture_dialog("change_worker_confirm_dialog")
        if not self.click_dialog_button(["예(&Y)", "예", "&Yes", "Yes"], timeout=3.0):
            raise RuntimeError("worker change confirmation dialog was not accepted")
        time.sleep(1.0)
        self.capture("change_worker_back_to_login")
        self.step("change_worker_clicked", "PASS")

    def run_worker_change_restore(self) -> None:
        if len(self.args.product_barcode) < 2:
            raise RuntimeError("worker-change-restore scenario requires two --product-barcode values")
        self.scan(self.args.master_label, "master_label_sent", "master_label_loaded_before_worker_change", wait_after=1.2)
        self.scan(self.args.product_barcode[0], "product_1_sent", "product_scan_1_before_worker_change", wait_after=1.0)
        self.click_change_worker()
        self.handle_login()
        self.capture("worker_change_restored")
        self.scan(self.args.product_barcode[1], "product_2_sent_after_worker_change_restore", "product_scan_2_after_worker_change_restore", wait_after=1.3)

    def exchange_scan_entry(self):
        if self.app is None:
            return None
        dialog = self.app.top_window()
        candidates = []
        for child in dialog.descendants():
            try:
                rect = child.rectangle()
            except Exception:
                continue
            if rect.width() >= 220 and 20 <= rect.height() <= 60:
                text = child.window_text() or ""
                candidates.append((rect.top, -rect.width(), text, child))
        if not candidates:
            return None
        candidates.sort()
        return candidates[-1][3]

    def scan_exchange_value(self, value: str, step_name: str, capture_name: str) -> None:
        sent = self.send_text_enter_to_process_window(r"개별 제품 교환", value, 0.32, 0.84, timeout=3.0)
        if not sent:
            entry = self.exchange_scan_entry()
            if entry is not None:
                entry.click_input()
                self.ensure_target_foreground()
                set_clipboard_text(value)
                self.keyboard.send_keys("^a")
                self.keyboard.send_keys("^v")
                self.keyboard.send_keys("{ENTER}")
            else:
                self.send_text_enter(value)
        time.sleep(0.8)
        if not self.capture_process_window(capture_name, r"개별 제품 교환"):
            self.capture(capture_name)
        self.step(step_name, "PASS", input_ref=redacted_value(value))

    def run_exchange(self) -> None:
        if len(self.args.product_barcode) < 2:
            raise RuntimeError("exchange scenario requires two --product-barcode values")
        self.click_button_by_text(["개별", "제품", "교환"], fallback=(0.51, 0.91))
        time.sleep(1.0)
        self.capture_process_window("exchange_dialog_opened", r"개별 제품 교환")
        self.scan_exchange_value(self.args.product_barcode[0], "exchange_defective_sent", "exchange_defective_scanned")
        self.scan_exchange_value(self.args.product_barcode[1], "exchange_good_sent", "exchange_good_scanned")
        if not self.click_button_by_text(["교환", "완료"], timeout=1.0):
            self.click_process_window(r"개별 제품 교환", 0.17, 0.91, timeout=3.0)
        self.capture_dialog("exchange_completed_info_dialog")
        self.click_dialog_button(["확인", "OK"], timeout=3.0)
        time.sleep(0.8)
        self.capture("exchange_after_completion")
        self.step("product_exchange_completed", "PASS")

    def run_replacement(self) -> None:
        if not self.args.replacement_master_label:
            raise RuntimeError("replacement scenario requires --replacement-master-label")
        self.scan(self.args.master_label, "master_label_sent", "replacement_original_master_loaded", wait_after=1.2)
        for index, barcode in enumerate(self.args.product_barcode, start=1):
            self.scan(barcode, f"product_{index}_sent", f"replacement_original_product_scan_{index}", wait_after=1.3)
        time.sleep(1.2)
        self.capture("replacement_original_completion")
        self.click_button_by_text(["완료", "현품표", "교체"], fallback=(0.39, 0.91))
        time.sleep(0.8)
        self.capture("replacement_mode_old_label_waiting")
        self.scan(self.args.master_label, "replacement_old_master_sent", "replacement_old_master_accepted", wait_after=0.8)
        self.scan(self.args.replacement_master_label, "replacement_new_master_sent", "replacement_new_master_applied", wait_after=1.2)
        self.capture_dialog("replacement_completed_info_dialog")
        self.click_dialog_button(["확인", "OK"], timeout=3.0)
        time.sleep(0.8)
        self.capture("replacement_after_completion")

    def run(self) -> int:
        try:
            self.launch()
            self.handle_login()

            self.capture("03_main_waiting")
            if self.args.scenario == "invalid-warning":
                self.run_invalid_warning()
            elif self.args.scenario == "product-before-master":
                self.run_product_before_master()
            elif self.args.scenario == "duplicate-warning" or self.args.do_duplicate_warning:
                self.run_duplicate_warning()
            elif self.args.scenario == "mismatch-warning":
                self.run_mismatch_warning()
            elif self.args.scenario == "reset":
                self.run_reset()
            elif self.args.scenario == "park-restore":
                self.run_park_restore()
            elif self.args.scenario == "partial-submit":
                self.run_partial_submit()
            elif self.args.scenario == "exit-recover":
                self.run_exit_recover()
            elif self.args.scenario == "worker-change-restore":
                self.run_worker_change_restore()
            elif self.args.scenario == "exchange":
                self.run_exchange()
            elif self.args.scenario == "replacement":
                self.run_replacement()
            else:
                self.scan(self.args.master_label, "master_label_sent", "06_master_label_loaded", wait_after=1.2)
                if not self.args.product_barcode:
                    raise RuntimeError("at least one --product-barcode is required")

                self.scan(self.args.product_barcode[0], "product_1_sent", "07_product_scan_1", wait_after=1.0)
                if self.args.do_undo or self.args.scenario == "undo":
                    self.click_undo()
                    self.scan(self.args.product_barcode[0], "product_1_rescanned_after_undo", "08_product_scan_1_after_undo", wait_after=1.0)

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
        required = self.expected_events()
        checks = {
            event: summary["counts"].get(event, 0) >= minimum
            for event, minimum in required.items()
        }
        if self.args.scenario == "partial-submit":
            checks["partial_tray_complete"] = summary["tray_complete_partial_count"] >= 1
        checks["no_test_markers"] = summary["test_markers"] == 0
        checks["details_json_parse"] = summary["malformed_details"] == 0
        checks["not_syncthing_data_root"] = not re.match(r"(?i)^c:\\sync(\\|$)", str(self.data_root))
        checks["screenshots_nonblank"] = all(not item.get("blank_suspected") for item in self.report["screenshots"])
        checks["raw_source_paths_redacted"] = summary.get("source_file_paths_redacted") is True
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

    def expected_events(self) -> dict[str, int]:
        scenario = self.args.scenario
        if scenario == "invalid-warning":
            return {"WORK_START": 1}
        if scenario == "product-before-master":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "TRAY_COMPLETE": 1,
            }
        if scenario == "undo" or self.args.do_undo:
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode) + 1,
                "SCAN_UNDO": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "duplicate-warning" or self.args.do_duplicate_warning:
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "SCAN_FAIL_DUPLICATE": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "mismatch-warning":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_FAIL_MISMATCH": 1,
                "SCAN_OK": len(self.args.product_barcode) - 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "reset":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": 1,
                "TRAY_RESET": 1,
            }
        if scenario == "park-restore":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "TRAY_PARKED": 1,
                "TRAY_RESTORED_FROM_PARK": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "partial-submit":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "exit-recover":
            return {
                "WORK_START": 2,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "TRAY_RESTORE": 1,
                "WORK_END": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "worker-change-restore":
            return {
                "WORK_START": 2,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "WORK_PAUSE": 1,
                "TRAY_RESTORE": 1,
                "TRAY_COMPLETE": 1,
            }
        if scenario == "exchange":
            return {"WORK_START": 1, "PRODUCT_EXCHANGE_COMPLETED": 1}
        if scenario == "replacement":
            return {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "TRAY_COMPLETE": 1,
                "HISTORICAL_REPLACE_START": 1,
                "MASTER_LABEL_REPLACEMENT_APPLIED": 1,
            }
        return {
            "WORK_START": 1,
            "MASTER_LABEL_SCANNED_NEW": 1,
            "SCAN_OK": len(self.args.product_barcode),
            "TRAY_COMPLETE": 1,
        }


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
    parser.add_argument(
        "--scenario",
        choices=[
            "normal",
            "undo",
            "product-before-master",
            "duplicate-warning",
            "mismatch-warning",
            "invalid-warning",
            "reset",
            "park-restore",
            "partial-submit",
            "exit-recover",
            "worker-change-restore",
            "exchange",
            "replacement",
        ],
        default="normal",
    )
    parser.add_argument("--worker", required=True)
    parser.add_argument("--master-label", required=True)
    parser.add_argument("--replacement-master-label", default="")
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
