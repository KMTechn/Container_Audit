from __future__ import annotations

import argparse
import csv
import ctypes
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import win32con
import win32api
import win32gui
import win32process
import win32ui
from PIL import Image, ImageStat

PRIMARY_MONITOR_FLAG = 1


DEFAULT_STEPS = [
    ("01_launch_login", "프로그램 실행 후 로그인 화면이 보이면 Enter"),
    ("02_worker_register_validation", "신규 작업자 등록/작업자명 입력 화면을 확인한 뒤 Enter"),
    ("03_main_waiting", "작업 시작 후 메인 대기 화면이 보이면 Enter"),
    ("04_master_label_loaded", "현품표 QR을 실제 UI에 입력/스캔한 뒤 품목/목표수량이 보이면 Enter"),
    ("05_product_scan_1", "첫 번째 제품 바코드를 입력/스캔한 뒤 카운트가 증가하면 Enter"),
    ("06_auto_complete", "목표 수량까지 스캔해 자동 완료 후 다음 현품표 대기 상태가 보이면 Enter"),
    ("07_local_events", "로컬 이벤트 로그 생성 확인 시점에서 Enter"),
    ("08_exit_restore", "종료/복구 안내 또는 복구 완료 화면이 보이면 Enter"),
    ("09_legacy_item_code_start", "13자리 품목코드 시작 흐름 확인 화면에서 Enter"),
    ("10_completion_durability", "자동 완료/부분 제출 후 금일 현황 반영 화면에서 Enter"),
    ("11_change_worker_with_active_tray", "작업자 변경 확인/복귀 화면에서 Enter"),
    ("12_direct_sync_status", "Direct Sync 상태 확인 화면 또는 상태 파일 확인 시점에서 Enter"),
    ("13_undo_last_scan", "마지막 스캔 취소 후 카운트/목록 상태가 보이면 Enter"),
    ("14_reset_current_work", "현재 작업 리셋 확인창 또는 리셋 후 대기 화면에서 Enter"),
    ("15_park_tray", "트레이 보류 후 보류 목록이 보이면 Enter"),
    ("16_restore_parked_tray", "보류 트레이 복원 후 기존 상태가 보이면 Enter"),
    ("17_manual_submit", "미달 수량 트레이 제출 확인/완료 화면에서 Enter"),
    ("18_product_exchange", "개별 제품 교환 창 또는 완료 화면에서 Enter"),
    ("19_master_replacement", "완료 현품표 교체 화면 또는 guardrail 화면에서 Enter"),
    ("20_error_warning", "중복/불일치/형식 오류 전체화면 경고가 보이면 Enter"),
]


def _visible_windows() -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []

    def callback(hwnd: int, _: object) -> bool:
        if not win32gui.IsWindowVisible(hwnd):
            return True
        title = win32gui.GetWindowText(hwnd) or ""
        if not title.strip():
            return True
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        if right - left < 100 or bottom - top < 100:
            return True
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        windows.append(
            {
                "hwnd": hwnd,
                "pid": pid,
                "title": title,
                "rect": [left, top, right, bottom],
            }
        )
        return True

    win32gui.EnumWindows(callback, None)
    return windows


def _tk_offset(value: int) -> str:
    return f"+{value}" if value >= 0 else str(value)


def _detect_secondary_monitor_geometry() -> str:
    monitors: list[dict[str, Any]] = []
    for monitor_handle, _dc, _rect in win32api.EnumDisplayMonitors():
        info = win32api.GetMonitorInfo(monitor_handle)
        left, top, right, bottom = info["Work"]
        monitors.append(
            {
                "left": int(left),
                "top": int(top),
                "right": int(right),
                "bottom": int(bottom),
                "primary": bool(info.get("Flags", 0) & PRIMARY_MONITOR_FLAG),
            }
        )
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


def _resolve_startup_geometry(explicit_geometry: str, prefer_secondary_monitor: bool) -> str:
    if explicit_geometry.strip():
        return explicit_geometry.strip()
    if prefer_secondary_monitor:
        return _detect_secondary_monitor_geometry()
    return ""


def _parse_tk_geometry(geometry: str) -> tuple[int, int, int, int] | None:
    match = re.match(r"^(\d+)x(\d+)([+-]\d+)([+-]\d+)$", geometry.strip())
    if not match:
        return None
    width, height, x, y = match.groups()
    return int(x), int(y), int(width), int(height)


def move_window_to_geometry(hwnd: int, geometry: str) -> None:
    parsed = _parse_tk_geometry(geometry)
    if parsed is None:
        return
    x, y, width, height = parsed
    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    win32gui.SetWindowPos(
        hwnd,
        None,
        x,
        y,
        width,
        height,
        win32con.SWP_NOZORDER | win32con.SWP_NOACTIVATE,
    )


def find_window(pattern: str) -> dict[str, Any]:
    regex = re.compile(pattern, re.IGNORECASE)
    matches = [item for item in _visible_windows() if regex.search(item["title"])]
    if not matches:
        titles = [item["title"] for item in _visible_windows()[:50]]
        raise RuntimeError(
            f"target window not found for pattern={pattern!r}; visible titles={titles}"
        )
    matches.sort(key=lambda item: (item["rect"][2] - item["rect"][0]) * (item["rect"][3] - item["rect"][1]), reverse=True)
    return matches[0]


def capture_window(hwnd: int, path: Path) -> dict[str, Any]:
    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    width = max(1, right - left)
    height = max(1, bottom - top)

    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(mfc_dc, width, height)
    save_dc.SelectObject(bitmap)

    try:
        result = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
        if not result:
            save_dc.BitBlt((0, 0), (width, height), mfc_dc, (0, 0), win32con.SRCCOPY)
        bmp_info = bitmap.GetInfo()
        bmp_bits = bitmap.GetBitmapBits(True)
        image = Image.frombuffer(
            "RGB",
            (bmp_info["bmWidth"], bmp_info["bmHeight"]),
            bmp_bits,
            "raw",
            "BGRX",
            0,
            1,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        image.save(path)
        extrema = image.convert("L").getextrema()
        stat = ImageStat.Stat(image)
        return {
            "path": str(path.resolve()),
            "width": width,
            "height": height,
            "blank_suspected": extrema == (255, 255) or extrema == (0, 0),
            "mean_luma": round(float(stat.mean[0]), 2),
        }
    finally:
        win32gui.DeleteObject(bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)


def event_counts(data_root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in data_root.rglob("*.csv"):
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    event_type = str(row.get("event_type") or row.get("event") or "").strip()
                    if event_type:
                        counts[event_type] = counts.get(event_type, 0) + 1
        except UnicodeDecodeError:
            continue
    return counts


def load_steps(path: Path | None) -> list[tuple[str, str]]:
    if path is None:
        return DEFAULT_STEPS
    raw = json.loads(path.read_text(encoding="utf-8"))
    steps: list[tuple[str, str]] = []
    for item in raw:
        steps.append((str(item["id"]), str(item["prompt"])))
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manual real-UI walkthrough capture helper. The operator performs the UI actions; this script only captures and records evidence."
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, default=None)
    parser.add_argument("--window-title-pattern", default=r"Container_Audit|이적실|Transfer|Audit")
    parser.add_argument("--steps-json", type=Path, default=None)
    parser.add_argument("--launch-exe", type=Path, default=None, help="Optional: launch the app only; no UI input is automated.")
    parser.add_argument(
        "--prefer-secondary-monitor",
        action="store_true",
        help="Launch/move the app to a detected non-primary monitor when possible.",
    )
    parser.add_argument(
        "--startup-geometry",
        default="",
        help="Tk geometry, for example 1600x900+2600+366. Passed to CONTAINER_AUDIT_STARTUP_GEOMETRY when launching.",
    )
    parser.add_argument("--report-path", type=Path, default=None)
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    screenshots_dir = output_root / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_path or output_root / "manual_real_ui_walkthrough_report.json"
    startup_geometry = _resolve_startup_geometry(args.startup_geometry, args.prefer_secondary_monitor)

    data_root = args.data_root.resolve() if args.data_root else None
    if data_root:
        data_root.mkdir(parents=True, exist_ok=True)

    if args.launch_exe:
        launch_env = os.environ.copy()
        if startup_geometry:
            launch_env["CONTAINER_AUDIT_STARTUP_GEOMETRY"] = startup_geometry
        if data_root:
            launch_env["CONTAINER_AUDIT_DATA_ROOT"] = str(data_root)
        subprocess.Popen([str(args.launch_exe)], cwd=str(args.launch_exe.parent), env=launch_env)
        print(f"Launched: {args.launch_exe}")
        if startup_geometry:
            print(f"Startup geometry: {startup_geometry}")
        if data_root:
            print(f"Data root: {data_root}")
        time.sleep(2)

    report: dict[str, Any] = {
        "report_version": "container-audit-manual-real-ui-walkthrough-v1",
        "started_at": datetime.now().astimezone().isoformat(),
        "output_root": str(output_root),
        "window_title_pattern": args.window_title_pattern,
        "startup_geometry": startup_geometry or None,
        "prefer_secondary_monitor": bool(args.prefer_secondary_monitor),
        "data_root": str(data_root) if data_root else None,
        "steps": [],
    }

    print("Manual walkthrough capture started.")
    print("Operate the real app UI yourself. Press Enter here after each requested screen is ready.")
    print("Type 'skip' then Enter to skip a step, or 'stop' to finish early.")

    for step_id, prompt in load_steps(args.steps_json):
        user_value = input(f"\n[{step_id}] {prompt}\nready> ").strip().lower()
        if user_value == "stop":
            report["stopped_at_step"] = step_id
            break
        if user_value == "skip":
            report["steps"].append({"id": step_id, "prompt": prompt, "status": "SKIPPED"})
            continue
        try:
            window = find_window(args.window_title_pattern)
            if startup_geometry:
                move_window_to_geometry(window["hwnd"], startup_geometry)
                time.sleep(0.2)
                window = find_window(args.window_title_pattern)
            capture = capture_window(window["hwnd"], screenshots_dir / f"{step_id}.png")
            report["steps"].append(
                {
                    "id": step_id,
                    "prompt": prompt,
                    "status": "PASS" if not capture["blank_suspected"] else "REVIEW",
                    "window": window,
                    "capture": capture,
                }
            )
            print(f"captured: {capture['path']}")
        except Exception as exc:
            report["steps"].append(
                {
                    "id": step_id,
                    "prompt": prompt,
                    "status": "FAIL",
                    "error": f"{exc.__class__.__name__}: {exc}",
                }
            )
            print(f"capture failed: {exc}")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if data_root:
        report["event_counts"] = event_counts(data_root)
    report["finished_at"] = datetime.now().astimezone().isoformat()
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nreport: {report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
