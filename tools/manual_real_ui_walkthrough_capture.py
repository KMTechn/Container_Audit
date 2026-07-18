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
from PIL import Image

try:
    from tools.capture_quality import (
        BLACK_LINE_COVERAGE_RATIO,
        BLACK_STRIPE_FAILURE_RATIO,
        DOMINANT_COLOR_RATIO_MIN,
        DOMINANT_COLOR_SAMPLE_MAX_SIZE,
        LOW_VARIANCE_STDDEV_MAX,
        NEAR_BLACK_FAILURE_RATIO,
        NEAR_BLACK_LUMA,
        analyze_capture_quality,
    )
except ModuleNotFoundError:  # Direct ``python tools/...py`` execution.
    from capture_quality import (
        BLACK_LINE_COVERAGE_RATIO,
        BLACK_STRIPE_FAILURE_RATIO,
        DOMINANT_COLOR_RATIO_MIN,
        DOMINANT_COLOR_SAMPLE_MAX_SIZE,
        LOW_VARIANCE_STDDEV_MAX,
        NEAR_BLACK_FAILURE_RATIO,
        NEAR_BLACK_LUMA,
        analyze_capture_quality,
    )

PRIMARY_MONITOR_FLAG = 1
DEFAULT_WINDOW_TITLE_PATTERN = (
    r"Container_Audit|이적 검사 시스템|이적실|Transfer|Audit"
)


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


def find_window(
    pattern: str,
    *,
    expected_pid: int | None = None,
    expected_hwnd: int | None = None,
) -> dict[str, Any]:
    regex = re.compile(pattern, re.IGNORECASE)
    visible_windows = _visible_windows()
    matches = [item for item in visible_windows if regex.search(item["title"])]
    if expected_pid is not None:
        matches = [item for item in matches if int(item["pid"]) == int(expected_pid)]
    if expected_hwnd is not None:
        matches = [item for item in matches if int(item["hwnd"]) == int(expected_hwnd)]
    if not matches:
        visible = [
            {
                "hwnd": item["hwnd"],
                "pid": item["pid"],
                "title": item["title"],
            }
            for item in visible_windows[:50]
        ]
        raise RuntimeError(
            "target window not found for "
            f"pattern={pattern!r}, expected_pid={expected_pid!r}, "
            f"expected_hwnd={expected_hwnd!r}; visible windows={visible}"
        )
    matches.sort(key=lambda item: (item["rect"][2] - item["rect"][0]) * (item["rect"][3] - item["rect"][1]), reverse=True)
    return matches[0]


def analyze_capture_image(image: Image.Image) -> dict[str, Any]:
    metrics = analyze_capture_quality(image)
    # Retain the manual report's historical two-decimal precision.
    metrics["luma_stddev"] = round(float(metrics["luma_stddev"]), 2)
    return metrics


def capture_review_status(capture: dict[str, Any]) -> str:
    if capture.get("requested_geometry_check") == "FAIL":
        return "FAIL"
    if any(
        capture.get(key)
        for key in (
            "blank_suspected",
            "excess_black_suspected",
            "edge_black_stripe_suspected",
            "contiguous_black_stripe_suspected",
            "uniform_low_variance_suspected",
        )
    ):
        return "REVIEW"
    return "PASS"


def annotate_manual_capture_geometry(
    capture: dict[str, Any],
    requested_geometry: str,
) -> None:
    capture["screenshot_role"] = "main"
    if not requested_geometry:
        capture["requested_size_gate_applicable"] = False
        capture["requested_geometry_check"] = "NOT_REQUESTED"
        return
    capture["requested_size_gate_applicable"] = True
    parsed = _parse_tk_geometry(requested_geometry)
    if parsed is None:
        capture["requested_geometry_valid"] = False
        capture["pixel_size_matches_requested"] = False
        capture["requested_geometry_check"] = "FAIL"
        return
    _x, _y, requested_width, requested_height = parsed
    capture["requested_geometry_valid"] = True
    capture["requested_pixel_size"] = [requested_width, requested_height]
    capture["actual_pixel_size"] = [capture["width"], capture["height"]]
    capture["pixel_size_matches_requested"] = (
        capture["width"], capture["height"]
    ) == (requested_width, requested_height)
    capture["requested_geometry_check"] = (
        "PASS" if capture["pixel_size_matches_requested"] else "FAIL"
    )


def manual_report_status(
    steps: list[dict[str, Any]],
    *,
    stopped_early: bool = False,
    review_required: bool = False,
) -> str:
    statuses = [str(step.get("status", "FAIL")) for step in steps]
    if "FAIL" in statuses:
        return "FAIL"
    if stopped_early or review_required or not statuses or any(
        status in {"REVIEW", "SKIPPED"} for status in statuses
    ):
        return "REVIEW"
    return "PASS"


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
        return {
            "path": str(path.resolve()),
            "width": width,
            "height": height,
            **analyze_capture_image(image),
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
    parser.add_argument("--window-title-pattern", default=DEFAULT_WINDOW_TITLE_PATTERN)
    parser.add_argument("--steps-json", type=Path, default=None)
    parser.add_argument("--launch-exe", type=Path, default=None, help="Optional: launch the app only; no UI input is automated.")
    parser.add_argument(
        "--expected-pid",
        type=int,
        default=None,
        help=(
            "Required for authoritative attach-mode evidence. Captures are limited "
            "to this PID and its first matching HWND."
        ),
    )
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
    if args.expected_pid is not None and args.expected_pid <= 0:
        parser.error("--expected-pid must be a positive integer")
    if args.launch_exe and args.expected_pid is not None:
        parser.error("--expected-pid cannot be combined with --launch-exe")

    output_root = args.output_root.resolve()
    screenshots_dir = output_root / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_path or output_root / "manual_real_ui_walkthrough_report.json"
    startup_geometry = _resolve_startup_geometry(args.startup_geometry, args.prefer_secondary_monitor)

    data_root = args.data_root.resolve() if args.data_root else None
    if data_root:
        data_root.mkdir(parents=True, exist_ok=True)

    launched_process: subprocess.Popen[Any] | None = None
    target_pid = args.expected_pid
    target_hwnd: int | None = None
    attach_identity_review_required = not args.launch_exe and target_pid is None

    if args.launch_exe:
        launch_env = os.environ.copy()
        if startup_geometry:
            launch_env["CONTAINER_AUDIT_STARTUP_GEOMETRY"] = startup_geometry
        if data_root:
            launch_env["CONTAINER_AUDIT_DATA_ROOT"] = str(data_root)
        launched_process = subprocess.Popen(
            [str(args.launch_exe)],
            cwd=str(args.launch_exe.parent),
            env=launch_env,
        )
        target_pid = int(launched_process.pid)
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
        "target_identity": {
            "mode": "launch" if args.launch_exe else "attach",
            "pid_source": (
                "launched_process"
                if args.launch_exe
                else "expected_pid_argument"
                if target_pid is not None
                else None
            ),
            "expected_pid": target_pid,
            "retained_pid": target_pid,
            "retained_hwnd": None,
            "status": (
                "REVIEW_REQUIRED"
                if attach_identity_review_required
                else "AWAITING_WINDOW_BINDING"
            ),
            "review_reason": (
                "attach mode did not provide --expected-pid; same-title window "
                "selection is not authoritative"
                if attach_identity_review_required
                else None
            ),
        },
        "status_semantics": {
            "PASS": "all requested captures succeeded and objective checks passed; exit code 0",
            "FAIL": "capture or requested-geometry validation failed; exit code 1",
            "REVIEW": "human review is required, or the walkthrough was skipped/stopped/interrupted/incomplete; exit code 2",
        },
        "steps": [],
    }

    print("Manual walkthrough capture started.")
    print("Operate the real app UI yourself. Press Enter here after each requested screen is ready.")
    print("Type 'skip' then Enter to skip a step, or 'stop' to finish early.")

    current_step_id: str | None = None
    try:
        for step_id, prompt in load_steps(args.steps_json):
            current_step_id = step_id
            user_value = input(f"\n[{step_id}] {prompt}\nready> ").strip().lower()
            if user_value == "stop":
                report["stopped_at_step"] = step_id
                break
            if user_value == "skip":
                report["steps"].append(
                    {"id": step_id, "prompt": prompt, "status": "SKIPPED"}
                )
                continue
            try:
                find_kwargs: dict[str, int] = {}
                if target_pid is not None:
                    find_kwargs["expected_pid"] = target_pid
                if target_hwnd is not None:
                    find_kwargs["expected_hwnd"] = target_hwnd
                window = (
                    find_window(args.window_title_pattern, **find_kwargs)
                    if find_kwargs
                    else find_window(args.window_title_pattern)
                )
                identity_was_bound = False
                if target_hwnd is None and window.get("pid") is not None:
                    if target_pid is None:
                        target_pid = int(window["pid"])
                        report["target_identity"]["pid_source"] = (
                            "first_observed_window"
                        )
                    target_hwnd = int(window["hwnd"])
                    report["target_identity"]["retained_pid"] = target_pid
                    report["target_identity"]["retained_hwnd"] = target_hwnd
                    report["target_identity"]["status"] = (
                        "BOUND_REVIEW_REQUIRED"
                        if attach_identity_review_required
                        else "BOUND"
                    )
                    identity_was_bound = True
                if identity_was_bound:
                    window = find_window(
                        args.window_title_pattern,
                        expected_pid=target_pid,
                        expected_hwnd=target_hwnd,
                    )
                if startup_geometry:
                    move_window_to_geometry(window["hwnd"], startup_geometry)
                    time.sleep(0.2)
                    window = (
                        find_window(
                            args.window_title_pattern,
                            expected_pid=target_pid,
                            expected_hwnd=target_hwnd,
                        )
                        if target_pid is not None
                        else find_window(args.window_title_pattern)
                    )
                capture = capture_window(window["hwnd"], screenshots_dir / f"{step_id}.png")
                annotate_manual_capture_geometry(capture, startup_geometry)
                report["steps"].append(
                    {
                        "id": step_id,
                        "prompt": prompt,
                        "status": capture_review_status(capture),
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
            report_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    except (EOFError, KeyboardInterrupt) as exc:
        report["input_interrupted"] = {
            "type": exc.__class__.__name__,
            "step": current_step_id,
        }
        print(f"\nmanual walkthrough interrupted: {exc.__class__.__name__}")

    if data_root:
        report["event_counts"] = event_counts(data_root)
    report["status"] = manual_report_status(
        report["steps"],
        stopped_early=(
            "stopped_at_step" in report or "input_interrupted" in report
        ),
        review_required=attach_identity_review_required,
    )
    report["status_summary"] = {
        status: sum(1 for step in report["steps"] if step.get("status") == status)
        for status in ("PASS", "REVIEW", "FAIL", "SKIPPED")
    }
    report["finished_at"] = datetime.now().astimezone().isoformat()
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nreport: {report_path.resolve()}")
    return {"PASS": 0, "FAIL": 1, "REVIEW": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
