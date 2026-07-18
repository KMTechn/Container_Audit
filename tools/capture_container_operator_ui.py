from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import functools
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from PIL import Image, ImageGrab


ROOT = Path(__file__).resolve().parents[1]
REPO_TMP_ROOT = ROOT / "tmp"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scan_display import compact_scan_value, format_scan_list_row
from tools.capture_quality import (
    NEAR_BLACK_FAILURE_RATIO,
    analyze_capture_quality,
)


DEFAULT_SIZES = ((1366, 768), (1440, 900), (1920, 1080), (2560, 1080))
DEFAULT_STATE_IDS = (
    "waiting",
    "normal",
    "duplicate",
    "operator_review",
    "completed",
    "recovered",
)
MIN_SCALE = 0.7
MAX_SCALE = 2.5
DEFAULT_SCALE = 1.0
PRIMARY_MONITOR_FLAG = 1


Rect = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class NoticeFixture:
    code: str
    title: str
    message: str
    severity: str
    blocking: bool = False


@dataclass(frozen=True, slots=True)
class CompletionFixture:
    outcome: str
    message: str
    receipt_id: str = ""
    error_code: str = ""


@dataclass(frozen=True, slots=True)
class TrayFixture:
    master_label: str
    item_code: str
    item_name: str
    item_spec: str
    target_count: int
    scanned_barcodes: tuple[str, ...]
    stopwatch_seconds: float
    restored: bool = False


@dataclass(frozen=True, slots=True)
class StateFixture:
    state_id: str
    state_label: str
    tray: TrayFixture | None = None
    last_normal_scan: str = ""
    last_normal_item_code: str = ""
    notice: NoticeFixture | None = None
    completion: CompletionFixture | None = None
    completed_tray_count: int = 0


@dataclass(frozen=True, slots=True)
class DisplayMonitor:
    """Stable subset of Win32 monitor metadata used by capture gates."""

    device_name: str
    monitor_rect: Rect
    work_rect: Rect
    primary: bool

    def as_manifest(self) -> dict[str, Any]:
        return {
            "device_name": self.device_name,
            "monitor_rect": list(self.monitor_rect),
            "work_rect": list(self.work_rect),
            "primary": self.primary,
        }


@dataclass(frozen=True, slots=True)
class MonitorTarget:
    """An explicitly selected non-primary monitor for fixture capture."""

    requested_device_name: str
    monitor: DisplayMonitor

    def requested_client_rect(self, size: tuple[int, int]) -> Rect:
        width, height = (int(value) for value in size)
        work_left, work_top, work_right, work_bottom = self.monitor.work_rect
        work_width = work_right - work_left
        work_height = work_bottom - work_top
        if width > work_width or height > work_height:
            raise RuntimeError(
                "capture size does not fit the selected monitor work area: "
                f"device={self.monitor.device_name!r} size={width}x{height} "
                f"work={self.monitor.work_rect}"
            )
        left = work_left + (work_width - width) // 2
        top = work_top + (work_height - height) // 2
        return left, top, left + width, top + height

    def tk_geometry(self, size: tuple[int, int]) -> str:
        left, top, right, bottom = self.requested_client_rect(size)
        return _format_tk_geometry(right - left, bottom - top, left, top)


def _products(count: int) -> tuple[str, ...]:
    return tuple(
        (
            "AAA2270730100|"
            f"SERIAL=CAPTURE-LINE-{index:04d}|"
            f"TRACE=TRACE-{index:04d}"
        )
        for index in range(1, count + 1)
    )


def build_state_fixtures() -> tuple[StateFixture, ...]:
    """Return deterministic, display-only fixtures for the operator screen."""

    normal_products = _products(3)
    review_products = _products(5)
    recovered_products = _products(6)
    common = {
        "master_label": "PHS=2|CLC=AAA2270730100|QT=8",
        "item_code": "AAA2270730100",
        "item_name": "캡처 기준 품목",
        "item_spec": "표준 트레이",
    }
    return (
        StateFixture(state_id="waiting", state_label="대기"),
        StateFixture(
            state_id="normal",
            state_label="정상",
            tray=TrayFixture(
                **common,
                target_count=8,
                scanned_barcodes=normal_products,
                stopwatch_seconds=74,
            ),
            last_normal_scan=normal_products[-1],
            last_normal_item_code=common["item_code"],
        ),
        StateFixture(
            state_id="duplicate",
            state_label="중복",
            tray=TrayFixture(
                **common,
                target_count=8,
                scanned_barcodes=normal_products,
                stopwatch_seconds=82,
            ),
            last_normal_scan=normal_products[-1],
            last_normal_item_code=common["item_code"],
            notice=NoticeFixture(
                code="capture.duplicate",
                title="중복 스캔",
                message=(
                    "이미 스캔된 제품입니다.\n"
                    + compact_scan_value(
                        normal_products[-1],
                        item_code=common["item_code"],
                    )
                ),
                severity="error",
                blocking=True,
            ),
        ),
        StateFixture(
            state_id="operator_review",
            state_label="OPERATOR_REVIEW",
            tray=TrayFixture(
                **{**common, "master_label": "PHS=2|CLC=AAA2270730100|QT=5"},
                target_count=5,
                scanned_barcodes=review_products,
                stopwatch_seconds=128,
            ),
            last_normal_scan=review_products[-1],
            last_normal_item_code=common["item_code"],
            completion=CompletionFixture(
                outcome="OPERATOR_REVIEW",
                message=(
                    "서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다."
                ),
                error_code="CAPTURE_REVIEW",
            ),
        ),
        StateFixture(
            state_id="completed",
            state_label="완료",
            last_normal_scan=review_products[-1],
            last_normal_item_code=common["item_code"],
            completion=CompletionFixture(
                outcome="ACKED",
                message="'캡처 기준 품목' 완료 · 서버 이적 확인이 완료되었습니다.",
                receipt_id="capture-receipt-0001",
            ),
            completed_tray_count=1,
        ),
        StateFixture(
            state_id="recovered",
            state_label="복구",
            tray=TrayFixture(
                **{**common, "master_label": "PHS=2|CLC=AAA2270730100|QT=12"},
                target_count=12,
                scanned_barcodes=recovered_products,
                stopwatch_seconds=196,
                restored=True,
            ),
            last_normal_scan=recovered_products[-1],
            last_normal_item_code=common["item_code"],
            notice=NoticeFixture(
                code="capture.recovered",
                title="작업 복구 완료",
                message="보류된 트레이를 복구했습니다. 중앙 목록을 확인하고 다음 제품을 스캔하세요.",
                severity="success",
                blocking=False,
            ),
        ),
    )


def _parse_size_sequence(
    value: str,
    *,
    preserve_duplicates: bool,
) -> tuple[tuple[int, int], ...]:
    sizes: list[tuple[int, int]] = []
    for raw_item in str(value or "").split(","):
        item = raw_item.strip().lower().replace("×", "x")
        if not item:
            continue
        parts = item.split("x")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(f"invalid capture size: {raw_item!r}")
        try:
            width, height = (int(part) for part in parts)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid capture size: {raw_item!r}") from exc
        if width < 1024 or height < 720:
            raise argparse.ArgumentTypeError(
                f"capture size must be at least 1024x720: {width}x{height}"
            )
        pair = (width, height)
        if preserve_duplicates or pair not in sizes:
            sizes.append(pair)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one capture size is required")
    return tuple(sizes)


def parse_sizes(value: str) -> tuple[tuple[int, int], ...]:
    return _parse_size_sequence(value, preserve_duplicates=False)


def parse_roundtrip_sizes(value: str) -> tuple[tuple[int, int], ...]:
    """Parse an ordered compact/wide/compact sequence without de-duplication."""

    if not str(value or "").strip():
        return ()
    sizes = _parse_size_sequence(value, preserve_duplicates=True)
    if len(sizes) < 3:
        raise argparse.ArgumentTypeError(
            "roundtrip sizes require compact, wide, compact (at least three sizes)"
        )
    if sizes[0] != sizes[-1]:
        raise argparse.ArgumentTypeError(
            "roundtrip first and last sizes must match exactly"
        )
    if not any(size != sizes[0] for size in sizes[1:-1]):
        raise argparse.ArgumentTypeError(
            "roundtrip must include a different middle size"
        )
    return sizes


def parse_states(value: str) -> tuple[str, ...]:
    states: list[str] = []
    allowed = set(DEFAULT_STATE_IDS)
    for raw_item in str(value or "").split(","):
        state_id = raw_item.strip().lower()
        if not state_id:
            continue
        if state_id not in allowed:
            raise argparse.ArgumentTypeError(
                f"unknown state {raw_item!r}; choose from {', '.join(DEFAULT_STATE_IDS)}"
            )
        if state_id not in states:
            states.append(state_id)
    if not states:
        raise argparse.ArgumentTypeError("at least one state is required")
    return tuple(states)


def parse_scale(value: object) -> float:
    """Parse a supported UI scale without silently clamping capture evidence."""

    if isinstance(value, bool):
        raise argparse.ArgumentTypeError("scale must be a finite number")
    try:
        scale = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("scale must be a finite number") from exc
    if not math.isfinite(scale):
        raise argparse.ArgumentTypeError("scale must be a finite number")
    if not MIN_SCALE <= scale <= MAX_SCALE:
        raise argparse.ArgumentTypeError(
            f"scale must be between {MIN_SCALE} and {MAX_SCALE}: {scale}"
        )
    return scale


def _format_tk_offset(value: int) -> str:
    return f"+{value}" if value >= 0 else str(value)


def _format_tk_geometry(width: int, height: int, left: int, top: int) -> str:
    return (
        f"{int(width)}x{int(height)}"
        f"{_format_tk_offset(int(left))}{_format_tk_offset(int(top))}"
    )


def rect_is_contained(inner: Rect, outer: Rect) -> bool:
    inner_left, inner_top, inner_right, inner_bottom = inner
    outer_left, outer_top, outer_right, outer_bottom = outer
    return bool(
        inner_left < inner_right
        and inner_top < inner_bottom
        and outer_left < outer_right
        and outer_top < outer_bottom
        and inner_left >= outer_left
        and inner_top >= outer_top
        and inner_right <= outer_right
        and inner_bottom <= outer_bottom
    )


def _monitor_from_win32_info(info: dict[str, Any]) -> DisplayMonitor:
    return DisplayMonitor(
        device_name=str(info.get("Device") or ""),
        monitor_rect=tuple(int(value) for value in info["Monitor"]),
        work_rect=tuple(int(value) for value in info["Work"]),
        primary=bool(int(info.get("Flags", 0) or 0) & PRIMARY_MONITOR_FLAG),
    )


def enumerate_display_monitors() -> tuple[DisplayMonitor, ...]:
    """Enumerate physical Windows display targets without guessing by position."""

    if os.name != "nt":
        raise RuntimeError("--monitor-device is supported only on Windows")
    try:
        import win32api
    except ImportError as exc:  # pragma: no cover - Windows dependency guard
        raise RuntimeError("pywin32 is required for --monitor-device") from exc

    monitors = tuple(
        _monitor_from_win32_info(win32api.GetMonitorInfo(handle))
        for handle, _dc, _rect in win32api.EnumDisplayMonitors()
    )
    if not monitors:
        raise RuntimeError("no Windows display monitors were detected")
    return monitors


def resolve_monitor_target(
    device_name: str,
    sizes: Sequence[tuple[int, int]],
    *,
    monitors: Sequence[DisplayMonitor] | None = None,
) -> MonitorTarget:
    """Resolve one exact, non-primary device and preflight every capture size."""

    requested = str(device_name or "").strip()
    if not requested:
        raise RuntimeError("an exact monitor device name is required")
    available = tuple(monitors) if monitors is not None else enumerate_display_monitors()
    matches = [monitor for monitor in available if monitor.device_name == requested]
    if len(matches) != 1:
        available_names = ", ".join(repr(monitor.device_name) for monitor in available)
        raise RuntimeError(
            "selected monitor device must match exactly one connected display: "
            f"requested={requested!r} available=[{available_names}]"
        )
    monitor = matches[0]
    if monitor.primary:
        raise RuntimeError(
            "selected monitor must be non-primary: "
            f"device={monitor.device_name!r} primary={monitor.primary}"
        )
    target = MonitorTarget(requested_device_name=requested, monitor=monitor)
    for size in sizes:
        requested_rect = target.requested_client_rect(size)
        if not rect_is_contained(requested_rect, monitor.work_rect):
            raise RuntimeError(
                "requested capture geometry is outside the selected monitor work area: "
                f"device={monitor.device_name!r} requested={requested_rect} "
                f"work={monitor.work_rect}"
            )
    return target


def monitor_preflight_manifest(
    target: MonitorTarget,
    sizes: Sequence[tuple[int, int]],
) -> dict[str, Any]:
    placements = []
    for size in sizes:
        requested_rect = target.requested_client_rect(size)
        placements.append(
            {
                "requested_size": [int(size[0]), int(size[1])],
                "tk_geometry": target.tk_geometry(size),
                "requested_client_rect": list(requested_rect),
                "requested_geometry_contained_in_work_area": rect_is_contained(
                    requested_rect,
                    target.monitor.work_rect,
                ),
            }
        )
    checks = {
        "requested_device_name_exact_match": (
            target.requested_device_name == target.monitor.device_name
        ),
        "target_is_non_primary": target.monitor.primary is False,
        "all_requested_geometries_contained_in_work_area": all(
            placement["requested_geometry_contained_in_work_area"]
            for placement in placements
        ),
    }
    return {
        "gate_applicable": True,
        "selection_mode": "explicit_device_name",
        "requested_device_name": target.requested_device_name,
        "resolved_monitor": target.monitor.as_manifest(),
        "placements": placements,
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_monitor_capture_gate(
    target: MonitorTarget,
    size: tuple[int, int],
    *,
    actual_client_rect: Rect,
    actual_monitor: DisplayMonitor,
) -> dict[str, Any]:
    """Build the per-capture proof that the client remained on the target."""

    requested_rect = target.requested_client_rect(size)
    actual_width = actual_client_rect[2] - actual_client_rect[0]
    actual_height = actual_client_rect[3] - actual_client_rect[1]
    checks = {
        "requested_device_name_exact_match": (
            target.requested_device_name == target.monitor.device_name
        ),
        "target_is_non_primary": target.monitor.primary is False,
        "requested_geometry_contained_in_target_work_area": rect_is_contained(
            requested_rect,
            target.monitor.work_rect,
        ),
        "actual_monitor_device_matches_target": (
            actual_monitor.device_name == target.monitor.device_name
        ),
        "actual_monitor_is_non_primary": actual_monitor.primary is False,
        "monitor_work_area_unchanged": (
            actual_monitor.work_rect == target.monitor.work_rect
        ),
        "actual_geometry_contained_in_target_work_area": rect_is_contained(
            actual_client_rect,
            target.monitor.work_rect,
        ),
        "actual_client_size_matches_requested": (
            actual_width,
            actual_height,
        )
        == (int(size[0]), int(size[1])),
    }
    return {
        "gate_applicable": True,
        "requested_device_name": target.requested_device_name,
        "target_monitor": target.monitor.as_manifest(),
        "actual_monitor": actual_monitor.as_manifest(),
        "requested_tk_geometry": target.tk_geometry(size),
        "requested_client_rect": list(requested_rect),
        "actual_client_rect": list(actual_client_rect),
        "checks": checks,
        "passed": all(checks.values()),
    }


def collect_monitor_capture_gate(
    root: Any,
    target: MonitorTarget,
    size: tuple[int, int],
) -> dict[str, Any]:
    """Read the live client rectangle and its owning Win32 monitor."""

    import win32api
    import win32con

    left = int(root.winfo_rootx())
    top = int(root.winfo_rooty())
    width = max(1, int(root.winfo_width()))
    height = max(1, int(root.winfo_height()))
    actual_rect = (left, top, left + width, top + height)
    handle = win32api.MonitorFromRect(
        actual_rect,
        win32con.MONITOR_DEFAULTTONEAREST,
    )
    actual_monitor = _monitor_from_win32_info(win32api.GetMonitorInfo(handle))
    return build_monitor_capture_gate(
        target,
        size,
        actual_client_rect=actual_rect,
        actual_monitor=actual_monitor,
    )


def _root_hwnd(hwnd: int) -> int:
    if os.name != "nt":
        return int(hwnd)
    return int(ctypes.windll.user32.GetAncestor(int(hwnd), 2) or int(hwnd))


def _window_pid(hwnd: int) -> int:
    if os.name != "nt" or not hwnd:
        return os.getpid() if hwnd else 0
    pid = ctypes.c_ulong(0)
    ctypes.windll.user32.GetWindowThreadProcessId(int(hwnd), ctypes.byref(pid))
    return int(pid.value)


def build_capture_focus_gate(
    *,
    state_id: str,
    process_pid: int,
    root_hwnd: int,
    root_hwnd_pid: int,
    foreground_root_hwnd: int,
    foreground_pid: int,
    tk_focus_path: str,
    scan_entry_path: str,
    tk_focus_owned_by_root: bool,
    scan_entry_enabled: bool,
) -> dict[str, Any]:
    blocking = state_id in {"duplicate", "operator_review"}
    checks = {
        "root_hwnd_present": int(root_hwnd) > 0,
        "root_hwnd_pid_matches_process": int(root_hwnd_pid) == int(process_pid),
        "foreground_root_hwnd_matches_capture_root": (
            int(foreground_root_hwnd) == int(root_hwnd)
        ),
        "foreground_pid_matches_process": int(foreground_pid) == int(process_pid),
        "tk_focus_owned_by_capture_root": bool(tk_focus_owned_by_root),
        "state_focus_contract": (
            bool(tk_focus_owned_by_root)
            if blocking
            else (
                scan_entry_enabled
                and bool(tk_focus_owned_by_root)
                and str(tk_focus_path) == str(scan_entry_path)
            )
        ),
    }
    return {
        "gate_applicable": True,
        "state": state_id,
        "blocking_state": blocking,
        "process_pid": int(process_pid),
        "root_hwnd": int(root_hwnd),
        "root_hwnd_pid": int(root_hwnd_pid),
        "foreground_root_hwnd": int(foreground_root_hwnd),
        "foreground_pid": int(foreground_pid),
        "tk_focus_path": str(tk_focus_path),
        "scan_entry_path": str(scan_entry_path),
        "scan_entry_enabled": bool(scan_entry_enabled),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _widget_is_owned_by_root(widget: Any, root: Any) -> bool:
    current = widget
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if current is root:
            return True
        seen.add(id(current))
        current = getattr(current, "master", None)
    return False


def settle_capture_focus(app: Any, state_id: str) -> None:
    """Put keyboard focus in the state-authoritative widget before evidence."""

    blocking = state_id in {"duplicate", "operator_review"}
    target = app.root if blocking else app.scan_entry
    app.root.deiconify()
    app.root.lift()
    try:
        target.focus_force()
    except Exception as exc:
        raise RuntimeError(f"capture focus setup failed for {state_id}: {exc}") from exc
    if os.name == "nt":
        hwnd = _root_hwnd(int(app.root.winfo_id()))
        ctypes.windll.user32.SetForegroundWindow(hwnd)
    pump_tk(app.root, 120)


def collect_capture_focus_gate(app: Any, state_id: str) -> dict[str, Any]:
    root = app.root
    root_hwnd = _root_hwnd(int(root.winfo_id()))
    foreground_hwnd = (
        _root_hwnd(int(ctypes.windll.user32.GetForegroundWindow()))
        if os.name == "nt"
        else root_hwnd
    )
    focus_widget = root.focus_get()
    try:
        scan_entry_enabled = str(app.scan_entry.cget("state")) != "disabled"
    except Exception:
        scan_entry_enabled = False
    return build_capture_focus_gate(
        state_id=state_id,
        process_pid=os.getpid(),
        root_hwnd=root_hwnd,
        root_hwnd_pid=_window_pid(root_hwnd),
        foreground_root_hwnd=foreground_hwnd,
        foreground_pid=_window_pid(foreground_hwnd),
        tk_focus_path=str(focus_widget or ""),
        scan_entry_path=str(app.scan_entry),
        tk_focus_owned_by_root=_widget_is_owned_by_root(focus_widget, root),
        scan_entry_enabled=scan_entry_enabled,
    )


def assert_descendant(path: Path, parent: Path, *, label: str) -> Path:
    resolved = path.resolve()
    resolved_parent = parent.resolve()
    if resolved == resolved_parent or not resolved.is_relative_to(resolved_parent):
        raise RuntimeError(f"{label} must stay below {resolved_parent}: {resolved}")
    return resolved


def prepare_isolated_environment(data_root: Path, geometry: str) -> dict[str, str]:
    """Force every mutable runtime path and integration into repository tmp."""

    resolved_data_root = assert_descendant(
        data_root,
        REPO_TMP_ROOT,
        label="capture data root",
    )
    resolved_data_root.mkdir(parents=True, exist_ok=True)
    temp_root = resolved_data_root / "temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    guards = {
        "CONTAINER_AUDIT_DATA_ROOT": str(resolved_data_root),
        "CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP": "off",
        "CONTAINER_AUDIT_SESSION_SYNC_TRIGGER": "off",
        "CONTAINER_AUDIT_UPDATE_PROVIDER": "off",
        "CONTAINER_AUDIT_AUDIO_ENABLED": "off",
        "CONTAINER_AUDIT_STARTUP_GEOMETRY": geometry,
        "KMTECH_TEST_SILENT_AUDIO": "1",
        "SDL_AUDIODRIVER": "dummy",
        "PYGAME_HIDE_SUPPORT_PROMPT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_CURRENT_TEST": "container_operator_ui_capture_isolated",
        "TEMP": str(temp_root),
        "TMP": str(temp_root),
    }
    os.environ.update(guards)
    for key in list(os.environ):
        if key.startswith("WORKER_ANALYSIS_LOGISTICS_") or key == "WORKER_ANALYSIS_SERVER_URL":
            os.environ.pop(key, None)
    return guards


def enable_per_monitor_dpi_awareness() -> str:
    if os.name != "nt":
        return "not-windows"
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return "per-monitor-aware"
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
            return "system-aware"
        except Exception:
            return "unchanged"


def pump_tk(root: Any, milliseconds: int = 220) -> None:
    deadline = time.monotonic() + max(0, milliseconds) / 1000.0
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.015)
    root.update_idletasks()
    root.update()


def _capture_client_with_print_window(root: Any) -> tuple[Image.Image, str]:
    import win32con
    import win32gui
    import win32ui

    hwnd = int(root.winfo_id())
    try:
        hwnd = int(win32gui.GetAncestor(hwnd, win32con.GA_ROOT))
    except Exception:
        while win32gui.GetParent(hwnd):
            hwnd = int(win32gui.GetParent(hwnd))

    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    window_width = max(1, right - left)
    window_height = max(1, bottom - top)
    client_left, client_top = win32gui.ClientToScreen(hwnd, (0, 0))
    client_rect = win32gui.GetClientRect(hwnd)
    client_width = max(1, int(client_rect[2] - client_rect[0]))
    client_height = max(1, int(client_rect[3] - client_rect[1]))

    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(mfc_dc, window_width, window_height)
    save_dc.SelectObject(bitmap)
    try:
        rendered = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
        if not rendered:
            save_dc.BitBlt(
                (0, 0),
                (window_width, window_height),
                mfc_dc,
                (0, 0),
                win32con.SRCCOPY,
            )
        info = bitmap.GetInfo()
        bits = bitmap.GetBitmapBits(True)
        full_image = Image.frombuffer(
            "RGB",
            (info["bmWidth"], info["bmHeight"]),
            bits,
            "raw",
            "BGRX",
            0,
            1,
        ).copy()
    finally:
        win32gui.DeleteObject(bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)

    crop_left = max(0, int(client_left - left))
    crop_top = max(0, int(client_top - top))
    crop_right = min(full_image.width, crop_left + client_width)
    crop_bottom = min(full_image.height, crop_top + client_height)
    image = full_image.crop((crop_left, crop_top, crop_right, crop_bottom))
    return image, "PrintWindow(PW_RENDERFULLCONTENT)+client-crop"


def capture_tk_client(root: Any) -> tuple[Image.Image, str]:
    """Capture the real Tk client area without including OS window chrome."""

    root.update_idletasks()
    root.update()
    if os.name == "nt":
        try:
            return _capture_client_with_print_window(root)
        except Exception as exc:
            fallback_reason = f"PrintWindow failed: {type(exc).__name__}: {exc}"
        else:  # pragma: no cover - kept for static flow clarity
            fallback_reason = ""
    else:
        fallback_reason = "PrintWindow unavailable"

    left = int(root.winfo_rootx())
    top = int(root.winfo_rooty())
    width = max(1, int(root.winfo_width()))
    height = max(1, int(root.winfo_height()))
    image = ImageGrab.grab(
        bbox=(left, top, left + width, top + height),
        all_screens=True,
    )
    return image, f"ImageGrab(client-bbox); {fallback_reason}"


def analyze_image(image: Image.Image, expected_size: tuple[int, int]) -> dict[str, Any]:
    rgb = image.convert("RGB")
    quality = analyze_capture_quality(rgb)
    # Preserve the original fixed-capture blank proxy while adding the shared,
    # stricter stripe and low-variance evidence used by manual captures.
    quality["blank_suspected"] = bool(
        quality["blank_suspected"]
        or quality["luma_extrema"][1] - quality["luma_extrema"][0] <= 2
        or quality["luma_stddev"] < 0.75
        or quality["dominant_color_ratio_sampled"] >= 0.997
    )
    quality.update({
        "expected_pixel_size": [int(expected_size[0]), int(expected_size[1])],
        "pixel_size": [rgb.width, rgb.height],
        "pixel_size_matches": (rgb.width, rgb.height) == expected_size,
    })
    return quality


def _descendants(widget: Any) -> Iterable[Any]:
    for child in widget.winfo_children():
        yield child
        yield from _descendants(child)


def _is_mapped(widget: Any) -> bool:
    try:
        return bool(widget.winfo_ismapped())
    except Exception:
        return False


def _widget_record(
    root: Any,
    widget: Any,
    name: str,
    *,
    check_requested_width: bool = False,
    check_requested_height: bool = False,
) -> dict[str, Any]:
    root_x = int(root.winfo_rootx())
    root_y = int(root.winfo_rooty())
    x = int(widget.winfo_rootx()) - root_x
    y = int(widget.winfo_rooty()) - root_y
    width = int(widget.winfo_width())
    height = int(widget.winfo_height())
    try:
        requested_size = [int(widget.winfo_reqwidth()), int(widget.winfo_reqheight())]
    except Exception:
        requested_size = [width, height]
    try:
        widget_class = str(widget.winfo_class())
    except Exception:
        widget_class = type(widget).__name__
    return {
        "name": name,
        "widget_path": str(widget),
        "widget_class": widget_class,
        "master_path": str(getattr(widget, "master", "")),
        "mapped": _is_mapped(widget),
        "bbox": [x, y, x + width, y + height],
        "size": [width, height],
        "requested_size": requested_size,
        "check_requested_width": check_requested_width,
        "check_requested_height": check_requested_height,
    }


def _normalized_grid_info(widget: Any) -> dict[str, Any]:
    try:
        info = dict(widget.grid_info())
    except Exception:
        return {}
    normalized: dict[str, Any] = {}
    for key in ("row", "column", "rowspan", "columnspan"):
        if key in info:
            try:
                normalized[key] = int(info[key])
            except (TypeError, ValueError):
                normalized[key] = str(info[key])
    if "sticky" in info:
        normalized["sticky"] = str(info["sticky"])
    return normalized


def _normalized_grid_row(widget: Any, row: int) -> dict[str, int]:
    try:
        info = dict(widget.grid_rowconfigure(row))
    except Exception:
        return {}
    normalized: dict[str, int] = {}
    for key in ("weight", "minsize", "pad"):
        try:
            normalized[key] = int(info.get(key, 0) or 0)
        except (TypeError, ValueError):
            normalized[key] = 0
    return normalized


def cluster_button_rows(
    records: Sequence[dict[str, Any]],
    *,
    tolerance: int = 10,
) -> list[list[str]]:
    """Return visual button order clustered into top-to-bottom rows."""

    positioned: list[tuple[float, float, str]] = []
    for record in records:
        if not record.get("mapped", False):
            continue
        left, top, right, bottom = (int(value) for value in record["bbox"])
        positioned.append(((top + bottom) / 2.0, (left + right) / 2.0, str(record["name"])))
    positioned.sort()
    rows: list[list[tuple[float, float, str]]] = []
    for item in positioned:
        if not rows:
            rows.append([item])
            continue
        row_center = sum(entry[0] for entry in rows[-1]) / len(rows[-1])
        if abs(item[0] - row_center) <= max(0, int(tolerance)):
            rows[-1].append(item)
        else:
            rows.append([item])
    return [
        [name for _center_y, _center_x, name in sorted(row, key=lambda item: item[1])]
        for row in rows
    ]


def evaluate_clipping_proxy(
    widget_records: Sequence[dict[str, Any]],
    root_size: tuple[int, int],
    *,
    overlap_pairs: Sequence[tuple[str, str]] = (),
    containment_pairs: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    """Evaluate conservative geometry proxies; no OCR assumption is made."""

    root_width, root_height = root_size
    by_name = {str(record["name"]): record for record in widget_records}
    clipped: list[str] = []
    unmapped: list[str] = []
    width_compressed: list[str] = []
    height_compressed: list[str] = []
    for record in widget_records:
        name = str(record["name"])
        if not record.get("mapped", False):
            unmapped.append(name)
            continue
        left, top, right, bottom = (int(value) for value in record["bbox"])
        if (
            right - left <= 1
            or bottom - top <= 1
            or left < -1
            or top < -1
            or right > root_width + 1
            or bottom > root_height + 1
        ):
            clipped.append(name)
        requested = record.get("requested_size") or record.get("size") or [0, 0]
        actual = record.get("size") or [0, 0]
        if record.get("check_requested_width", False) and int(requested[0]) > int(actual[0]) + 2:
            width_compressed.append(name)
        if record.get("check_requested_height", False) and int(requested[1]) > int(actual[1]) + 2:
            height_compressed.append(name)

    overlaps: list[dict[str, Any]] = []
    for first_name, second_name in overlap_pairs:
        first = by_name.get(first_name)
        second = by_name.get(second_name)
        if not first or not second or not first.get("mapped") or not second.get("mapped"):
            continue
        a_left, a_top, a_right, a_bottom = first["bbox"]
        b_left, b_top, b_right, b_bottom = second["bbox"]
        overlap_width = min(a_right, b_right) - max(a_left, b_left)
        overlap_height = min(a_bottom, b_bottom) - max(a_top, b_top)
        if overlap_width > 1 and overlap_height > 1:
            overlaps.append(
                {
                    "widgets": [first_name, second_name],
                    "overlap_size": [int(overlap_width), int(overlap_height)],
                }
            )
    outside_containers: list[dict[str, str]] = []
    for child_name, container_name in containment_pairs:
        child = by_name.get(child_name)
        container = by_name.get(container_name)
        if not child or not container or not child.get("mapped") or not container.get("mapped"):
            continue
        child_left, child_top, child_right, child_bottom = child["bbox"]
        parent_left, parent_top, parent_right, parent_bottom = container["bbox"]
        if (
            child_left < parent_left - 1
            or child_top < parent_top - 1
            or child_right > parent_right + 1
            or child_bottom > parent_bottom + 1
        ):
            outside_containers.append(
                {"widget": child_name, "container": container_name}
            )
    issue_count = (
        len(set(clipped))
        + len(set(unmapped))
        + len(set(width_compressed))
        + len(set(height_compressed))
        + len(overlaps)
        + len(outside_containers)
    )
    return {
        "method": (
            "Tk mapped widget bounds + requested-height + critical-pair overlap + "
            "requested-width + pane/card containment"
        ),
        "root_size": [root_width, root_height],
        "clipped_or_zero_sized_widgets": sorted(set(clipped)),
        "unmapped_critical_widgets": sorted(set(unmapped)),
        "width_compressed_widgets": sorted(set(width_compressed)),
        "height_compressed_widgets": sorted(set(height_compressed)),
        "overlaps": overlaps,
        "outside_containers": outside_containers,
        "issue_count": issue_count,
        "suspected": issue_count > 0,
    }


def collect_ui_geometry(app: Any) -> dict[str, Any]:
    root = app.root
    root_size = (int(root.winfo_width()), int(root.winfo_height()))
    critical_widgets = {
        "left_pane": (app.left_pane, False),
        "center_pane": (app.center_pane, False),
        "right_pane": (app.right_pane, False),
        "stage": (app.stage_label, True),
        "current_item": (app.current_item_label, True),
        "count": (app.main_count_label, True),
        "progress": (app.main_progress_bar, False),
        "scan_entry": (app.scan_entry, True),
        "notice": (app.notice_frame, False),
        "scan_list_frame": (app._scan_list_frame, False),
        "scan_list_header": (app.scanned_list_header_label, True),
        "scan_list": (app.scanned_listbox, False),
        "scan_list_scrollbar": (app.scanned_list_scrollbar, False),
        "actions": (app._center_button_frame, False),
        "right_status": (app.info_cards["status"]["frame"], False, False),
        "right_status_value": (app.info_cards["status"]["value"], True, True),
        "right_stopwatch": (app.info_cards["stopwatch"]["frame"], False, False),
        "right_stopwatch_value": (app.info_cards["stopwatch"]["value"], True, True),
        "right_context": (app._right_context_frame, False, False),
        "right_last_scan": (app.last_scan_value_label, True, True),
        "right_follow_up": (app.follow_up_label, True, True),
        "right_secondary": (app._secondary_stats_frame, False, False),
        "status_bar_text": (app.status_label, False, True),
    }
    for name in tuple(critical_widgets):
        value = critical_widgets[name]
        if len(value) == 2:
            widget, check_requested_height = value
            critical_widgets[name] = (widget, False, check_requested_height)
    core_action_widgets = {
        "action_undo": app.undo_button,
        "action_park": app.park_button,
        "action_submit": app.submit_tray_button,
        "action_operations": app.operations_button,
    }
    for name, button in core_action_widgets.items():
        critical_widgets[name] = (button, False, True)
    records = [
        _widget_record(
            root,
            widget,
            name,
            check_requested_width=check_requested_width,
            check_requested_height=check_requested_height,
        )
        for name, (widget, check_requested_width, check_requested_height) in critical_widgets.items()
    ]
    clipping = evaluate_clipping_proxy(
        records,
        root_size,
        overlap_pairs=(
            ("scan_entry", "notice"),
            ("notice", "scan_list"),
            ("scan_list", "actions"),
        ),
        containment_pairs=(
            ("stage", "center_pane"),
            ("current_item", "center_pane"),
            ("count", "center_pane"),
            ("progress", "center_pane"),
            ("scan_entry", "center_pane"),
            ("notice", "center_pane"),
            ("scan_list_frame", "center_pane"),
            ("scan_list_header", "scan_list_frame"),
            ("scan_list", "scan_list_frame"),
            ("scan_list_scrollbar", "scan_list_frame"),
            ("actions", "center_pane"),
            ("action_undo", "actions"),
            ("action_park", "actions"),
            ("action_submit", "actions"),
            ("action_operations", "actions"),
            ("right_status", "right_pane"),
            ("right_status_value", "right_status"),
            ("right_stopwatch", "right_pane"),
            ("right_stopwatch_value", "right_stopwatch"),
            ("right_context", "right_pane"),
            ("right_last_scan", "right_context"),
            ("right_follow_up", "right_context"),
            ("right_secondary", "right_pane"),
        ),
    )

    center_history = [
        widget
        for widget in _descendants(app.center_pane)
        if str(widget.winfo_class()) in {"Listbox", "Treeview"}
    ]
    right_history = [
        widget
        for widget in _descendants(app.right_pane)
        if str(widget.winfo_class()) in {"Listbox", "Treeview"}
    ]
    right_progress = [
        widget
        for widget in _descendants(app.right_pane)
        if str(widget.winfo_class()) in {"Progressbar", "TProgressbar"}
    ]
    record_by_name = {record["name"]: record for record in records}
    core_action_records = [record_by_name[name] for name in core_action_widgets]
    core_action_rows = cluster_button_rows(core_action_records)
    center_width = int(app.center_pane.winfo_width())
    expected_core_action_rows = (
        [["action_undo", "action_park", "action_submit", "action_operations"]]
        if center_width >= 620
        else [
            ["action_undo", "action_park"],
            ["action_submit", "action_operations"],
        ]
    )
    hidden_operations = [
        widget
        for widget in (
            getattr(app, "reset_button", None),
            getattr(app, "replace_master_label_button", None),
            getattr(app, "exchange_button", None),
        )
        if widget is not None
    ]
    scan_list_layout_signature = {
        "frame_path": str(app._scan_list_frame),
        "frame_master": str(app._scan_list_frame.master),
        "frame_grid": _normalized_grid_info(app._scan_list_frame),
        "center_row_5": _normalized_grid_row(app.center_pane, 5),
        "header_path": str(app.scanned_list_header_label),
        "header_master": str(app.scanned_list_header_label.master),
        "header_grid": _normalized_grid_info(app.scanned_list_header_label),
        "list_path": str(app.scanned_listbox),
        "list_master": str(app.scanned_listbox.master),
        "list_grid": _normalized_grid_info(app.scanned_listbox),
        "frame_row_1": _normalized_grid_row(app._scan_list_frame, 1),
    }
    scan_list_frame_contract = bool(
        app._scan_list_frame.master is app.center_pane
        and scan_list_layout_signature["frame_grid"].get("row") == 5
        and set(str(scan_list_layout_signature["frame_grid"].get("sticky", "")))
        == set("nsew")
        and app.scanned_list_header_label.master is app._scan_list_frame
        and scan_list_layout_signature["header_grid"].get("row") == 0
        and app.scanned_listbox.master is app._scan_list_frame
        and scan_list_layout_signature["list_grid"].get("row") == 1
        and set(str(scan_list_layout_signature["list_grid"].get("sticky", "")))
        == set("nsew")
        and scan_list_layout_signature["center_row_5"].get("weight", 0) > 0
        and scan_list_layout_signature["frame_row_1"].get("weight", 0) > 0
    )
    structure = {
        "center_history_widget_count": len(center_history),
        "center_history_widgets": [str(widget) for widget in center_history],
        "right_history_widget_count": len(right_history),
        "right_history_widgets": [str(widget) for widget in right_history],
        "right_progress_widget_count": len(right_progress),
        "right_progress_widgets": [str(widget) for widget in right_progress],
        "central_scan_list_is_only_center_history": center_history == [app.scanned_listbox],
        "right_has_no_full_scan_history": not right_history,
        "right_has_no_progress_widget": not right_progress,
        "scan_list_frame_contract": scan_list_frame_contract,
        "scan_list_layout_signature": scan_list_layout_signature,
        "scan_list_below_notice": (
            app.scanned_listbox.winfo_rooty()
            >= app.notice_frame.winfo_rooty() + app.notice_frame.winfo_height()
        ),
        "core_action_button_count": len(core_action_records),
        "core_action_common_parent": len(
            {record["master_path"] for record in core_action_records}
        ) == 1,
        "core_action_rows": core_action_rows,
        "expected_core_action_rows": expected_core_action_rows,
        "core_action_layout_matches": core_action_rows == expected_core_action_rows,
        "hidden_operation_button_count": len(hidden_operations),
        "hidden_operation_buttons_mapped": [
            str(widget) for widget in hidden_operations if _is_mapped(widget)
        ],
    }
    return {
        "root_client_size": [root_size[0], root_size[1]],
        "widgets": records,
        "clipping_proxy": clipping,
        "structure": structure,
    }


def _widget_text(widget: Any) -> str:
    try:
        return str(widget.cget("text"))
    except Exception:
        return ""


def collect_rendered_state(app: Any) -> dict[str, Any]:
    try:
        scan_rows = [str(value) for value in app.scanned_listbox.get(0, "end")]
    except Exception:
        scan_rows = []
    scan_row_colors: list[dict[str, str]] = []
    for row_index in range(len(scan_rows)):
        try:
            background = str(app.scanned_listbox.itemcget(row_index, "background"))
            foreground = str(app.scanned_listbox.itemcget(row_index, "foreground"))
        except Exception:
            background = ""
            foreground = ""
        scan_row_colors.append(
            {"background": background, "foreground": foreground}
        )
    scan_list_rows_neutral = all(
        colors == {
            "background": str(app.COLOR_SIDEBAR_BG),
            "foreground": str(app.COLOR_TEXT),
        }
        for colors in scan_row_colors
    )
    try:
        scan_entry_state = str(app.scan_entry.cget("state"))
    except Exception:
        scan_entry_state = "unknown"
    try:
        presenter_last_normal_scan_raw = str(
            app._warning_state_presenter().state.last_normal_scan or ""
        )
    except Exception:
        presenter_last_normal_scan_raw = ""
    try:
        active_tray_scans_raw = [
            str(value) for value in (app.current_tray.scanned_barcodes or [])
        ]
        active_tray_last_scan_raw = (
            active_tray_scans_raw[-1] if active_tray_scans_raw else ""
        )
    except Exception:
        active_tray_scans_raw = []
        active_tray_last_scan_raw = ""
    right_texts = {
        "status": _widget_text(app.info_cards["status"]["value"]),
        "stopwatch": _widget_text(app.info_cards["stopwatch"]["value"]),
        "last_normal_scan": _widget_text(app.last_scan_value_label),
        "next_action": _widget_text(app.follow_up_label),
        "average": _widget_text(app.info_cards["avg_time"]["value"]),
        "best": _widget_text(app.info_cards["best_time"]["value"]),
    }
    right_progress_count_texts = {
        key: text
        for key, text in right_texts.items()
        if re.search(r"\b\d+\s*/\s*\d+\b", text)
    }
    action_buttons: dict[str, dict[str, str]] = {}
    for name, button in (
        ("undo", app.undo_button),
        ("park", app.park_button),
        ("submit", app.submit_tray_button),
        ("operations", app.operations_button),
    ):
        try:
            state = str(button.cget("state"))
        except Exception:
            state = "unknown"
        action_buttons[name] = {"text": _widget_text(button), "state": state}
    return {
        "stage": _widget_text(app.stage_label),
        "current_item": _widget_text(app.current_item_label),
        "count": _widget_text(app.main_count_label),
        "notice_title": _widget_text(app.notice_title_label),
        "notice_message": _widget_text(app.notice_message_label),
        "last_normal_scan": _widget_text(app.last_scan_value_label),
        "last_normal_scan_display": _widget_text(app.last_scan_value_label),
        "presenter_last_normal_scan_raw": presenter_last_normal_scan_raw,
        "active_tray_scans_raw": active_tray_scans_raw,
        "active_tray_last_scan_raw": active_tray_last_scan_raw,
        "next_action": _widget_text(app.follow_up_label),
        "status": right_texts["status"],
        "stopwatch": right_texts["stopwatch"],
        "scan_entry_state": scan_entry_state,
        "scan_list_row_count": len(scan_rows),
        "scan_list_rows": scan_rows,
        "scan_list_row_colors": scan_row_colors,
        "scan_list_rows_neutral": scan_list_rows_neutral,
        "scan_list_header": _widget_text(app.scanned_list_header_label),
        "right_texts": right_texts,
        "right_progress_count_texts": right_progress_count_texts,
        "action_buttons": action_buttons,
    }


def _severity_from_fixture(value: str, severity_enum: Any) -> Any:
    try:
        return severity_enum(str(value).lower())
    except ValueError as exc:
        raise RuntimeError(f"invalid fixture severity: {value!r}") from exc


def normalize_capture_scan_rows(app: Any) -> int:
    """Put fixture rows into the same neutral style as a settled live scan list."""

    try:
        row_count = int(app.scanned_listbox.size())
    except Exception:
        row_count = 0
    for row_index in range(row_count):
        app.scanned_listbox.itemconfig(
            row_index,
            {"bg": app.COLOR_SIDEBAR_BG, "fg": app.COLOR_TEXT},
        )
    if row_count:
        app.scanned_listbox.see(0)
    return row_count


def build_scan_list_viewport_gate(
    *,
    expected_row_count: int,
    viewport_size: tuple[int, int],
    row_bboxes: Sequence[Sequence[int] | None],
    see_zero_applied: bool,
) -> dict[str, Any]:
    viewport_width, viewport_height = (int(value) for value in viewport_size)
    rows: list[dict[str, Any]] = []
    for index in range(expected_row_count):
        bbox = row_bboxes[index] if index < len(row_bboxes) else None
        if bbox is None:
            rows.append(
                {
                    "index": index,
                    "bbox": None,
                    "visible": False,
                    "horizontally_contained": False,
                    "vertically_contained": False,
                }
            )
            continue
        x, y, width, height = (int(value) for value in bbox)
        rows.append(
            {
                "index": index,
                "bbox": [x, y, width, height],
                "visible": width > 0 and height > 0,
                "horizontally_contained": (
                    width > 0 and x >= 0 and x + width <= viewport_width
                ),
                "vertically_contained": (
                    height > 0 and y >= 0 and y + height <= viewport_height
                ),
            }
        )
    checks = {
        "see_zero_applied": bool(see_zero_applied),
        "row_bbox_count_matches_fixture": len(row_bboxes) == expected_row_count,
        "every_fixture_row_visible": all(row["visible"] for row in rows),
        "every_fixture_row_horizontally_contained": all(
            row["horizontally_contained"] for row in rows
        ),
        "every_fixture_row_vertically_contained": all(
            row["vertically_contained"] for row in rows
        ),
    }
    return {
        "gate_applicable": True,
        "expected_row_count": int(expected_row_count),
        "viewport_size": [viewport_width, viewport_height],
        "rows": rows,
        "checks": checks,
        "passed": all(checks.values()),
    }


def collect_scan_list_viewport_gate(
    app: Any,
    *,
    expected_row_count: int,
) -> dict[str, Any]:
    listbox = app.scanned_listbox
    see_zero_applied = False
    if expected_row_count:
        listbox.see(0)
        see_zero_applied = True
        pump_tk(app.root, 80)
    else:
        # An empty fixture has no row to reveal; the operation is vacuously applied.
        see_zero_applied = True
    row_bboxes = [listbox.bbox(index) for index in range(expected_row_count)]
    return build_scan_list_viewport_gate(
        expected_row_count=expected_row_count,
        viewport_size=(int(listbox.winfo_width()), int(listbox.winfo_height())),
        row_bboxes=row_bboxes,
        see_zero_applied=see_zero_applied,
    )


def apply_state_fixture(app: Any, fixture: StateFixture, module: Any) -> None:
    """Render fixture state without invoking scan, ledger, network, or completion logic."""

    app._stop_stopwatch()
    app._stop_idle_checker()
    presenter = module.WarningPresenter()
    app.warning_presenter = presenter
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.work_summary = {}
    app.total_tray_count = fixture.completed_tray_count
    app.completed_tray_times = [142.0, 156.0] if fixture.completed_tray_count else []
    app.best_time_records = {"2026-07-15": 137.0}

    tray_fixture = fixture.tray
    if tray_fixture is None:
        app.current_tray = module.TraySession()
    else:
        start_time = dt.datetime.now() - dt.timedelta(seconds=tray_fixture.stopwatch_seconds)
        scan_times = [
            start_time + dt.timedelta(seconds=(index + 1) * 11)
            for index in range(len(tray_fixture.scanned_barcodes))
        ]
        app.current_tray = module.TraySession(
            master_label_code=tray_fixture.master_label,
            item_code=tray_fixture.item_code,
            item_name=tray_fixture.item_name,
            item_spec=tray_fixture.item_spec,
            scanned_barcodes=list(tray_fixture.scanned_barcodes),
            scan_times=scan_times,
            tray_size=tray_fixture.target_count,
            stopwatch_seconds=tray_fixture.stopwatch_seconds,
            start_time=start_time,
            has_error_or_reset=fixture.state_id in {"duplicate", "operator_review"},
            is_restored_session=tray_fixture.restored,
        )

    app.scanned_listbox.delete(0, "end")
    if tray_fixture is not None:
        for index, barcode in enumerate(tray_fixture.scanned_barcodes, start=1):
            app.scanned_listbox.insert(
                0,
                format_scan_list_row(
                    index,
                    barcode,
                    item_code=tray_fixture.item_code,
                ),
            )
    normalize_capture_scan_rows(app)

    if fixture.last_normal_scan:
        app._last_normal_scan_display_item_code = fixture.last_normal_item_code
        presenter.record_normal_scan(fixture.last_normal_scan)
    if fixture.notice is not None:
        presenter.present(
            module.Notice(
                code=fixture.notice.code,
                title=fixture.notice.title,
                message=fixture.notice.message,
                severity=_severity_from_fixture(
                    fixture.notice.severity,
                    module.NoticeSeverity,
                ),
                blocking=fixture.notice.blocking,
            )
        )
    if fixture.completion is not None:
        tray = fixture.tray
        scan_count = len(tray.scanned_barcodes) if tray is not None else 5
        target_count = tray.target_count if tray is not None else scan_count
        presenter.present_completion(
            module.CompletionOutcomeSnapshot(
                outcome=module.CompletionOutcome(fixture.completion.outcome),
                item_name=tray.item_name if tray is not None else "캡처 기준 품목",
                master_label=tray.master_label if tray is not None else "PHS=2|CLC=AAA2270730100|QT=5",
                scan_count=scan_count,
                target_count=target_count,
                message=fixture.completion.message,
                receipt_id=fixture.completion.receipt_id,
                error_code=fixture.completion.error_code,
            )
        )

    app.is_idle = fixture.state_id in {"waiting", "completed"}
    app._update_current_item_label()
    app._update_all_summaries()
    app._apply_center_layout()
    app._apply_scanned_listbox_layout()
    app._apply_right_sidebar_layout()

    status_card = app.info_cards.get("status")
    stopwatch_card = app.info_cards.get("stopwatch")
    if status_card:
        status_text = {
            "waiting": "대기 중",
            "normal": "작업 중",
            "duplicate": "확인 필요",
            "operator_review": "담당자 확인",
            "completed": "완료",
            "recovered": "복구 작업 중",
        }[fixture.state_id]
        status_card["value"].configure(text=status_text)
    if stopwatch_card:
        seconds = int(tray_fixture.stopwatch_seconds) if tray_fixture else 0
        stopwatch_card["value"].configure(text=f"{seconds // 60:02d}:{seconds % 60:02d}")
    app.status_label.configure(text="스캐너 준비")
    app._render_warning_state()
    app._update_action_button_states()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fixture_manifest(fixture: StateFixture) -> dict[str, Any]:
    record = asdict(fixture)
    tray = fixture.tray
    record["active_tray"] = tray is not None
    record["scan_count"] = len(tray.scanned_barcodes) if tray is not None else 0
    record["target_count"] = tray.target_count if tray is not None else 0
    record["last_normal_scan_preserved"] = bool(fixture.last_normal_scan)
    record["last_normal_scan_display"] = (
        compact_scan_value(
            fixture.last_normal_scan,
            item_code=fixture.last_normal_item_code,
        )
        if fixture.last_normal_scan
        else "-"
    )
    return record


def _expected_scan_list_rows(fixture: dict[str, Any]) -> list[str]:
    """Return the exact rows the active tray should render in current UI order."""

    if not fixture.get("active_tray"):
        return []
    tray = fixture.get("tray")
    if not isinstance(tray, dict):
        return []
    barcodes = tray.get("scanned_barcodes") or ()
    item_code = tray.get("item_code") or ""
    numbered_rows = [
        format_scan_list_row(index, barcode, item_code=item_code)
        for index, barcode in enumerate(barcodes, start=1)
    ]
    return list(reversed(numbered_rows))


def build_compact_display_gate(
    fixture: dict[str, Any],
    rendered: dict[str, Any],
) -> dict[str, Any]:
    expected_rows = _expected_scan_list_rows(fixture)
    actual_rows = [str(value) for value in rendered.get("scan_list_rows") or []]
    expected_last_raw = str(fixture.get("last_normal_scan") or "")
    expected_last_display = str(fixture.get("last_normal_scan_display") or "-")
    tray = fixture.get("tray") if fixture.get("active_tray") else None
    expected_tray_raw = (
        [str(value) for value in tray.get("scanned_barcodes") or []]
        if isinstance(tray, dict)
        else []
    )
    actual_last_display = str(rendered.get("last_normal_scan_display") or "")
    checks = {
        "central_rows_exact_compact": actual_rows == expected_rows,
        "central_rows_have_no_raw_payload_delimiters": all(
            "|" not in row and "=" not in row for row in actual_rows
        ),
        "right_last_normal_exact_compact": actual_last_display == expected_last_display,
        "right_last_normal_has_no_raw_payload_delimiters": (
            "|" not in actual_last_display and "=" not in actual_last_display
        ),
        "presenter_last_normal_raw_exact": (
            str(rendered.get("presenter_last_normal_scan_raw") or "")
            == expected_last_raw
        ),
        "current_tray_raw_list_exact": (
            [str(value) for value in rendered.get("active_tray_scans_raw") or []]
            == expected_tray_raw
        ),
    }
    return {
        "gate_applicable": True,
        "expected_central_rows": expected_rows,
        "actual_central_rows": actual_rows,
        "expected_right_last_normal": expected_last_display,
        "actual_right_last_normal": actual_last_display,
        "expected_presenter_last_normal_raw": expected_last_raw,
        "expected_current_tray_raw_list": expected_tray_raw,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _append_gate_issues(
    issues: list[str],
    record: dict[str, Any],
    gate_name: str,
) -> None:
    gate = record.get(gate_name)
    if not isinstance(gate, dict):
        issues.append(f"{gate_name}_missing")
        return
    if gate.get("gate_applicable") is not True:
        issues.append(f"{gate_name}_not_applicable")
    checks = gate.get("checks")
    if not isinstance(checks, dict) or not checks:
        issues.append(f"{gate_name}_checks_missing")
    else:
        issues.extend(
            f"{gate_name}_{name}"
            for name, passed in checks.items()
            if passed is not True
        )
    if gate.get("passed") is not True and not any(
        issue.startswith(f"{gate_name}_") for issue in issues
    ):
        issues.append(f"{gate_name}_failed")


def evaluate_capture(record: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    monitor_gate = record.get("monitor_gate")
    if monitor_gate is not None:
        if monitor_gate.get("gate_applicable") is not True:
            issues.append("monitor_gate_not_applicable")
        checks = monitor_gate.get("checks")
        if not isinstance(checks, dict) or not checks:
            issues.append("monitor_gate_checks_missing")
        else:
            issues.extend(
                f"monitor_gate_{name}"
                for name, passed in checks.items()
                if passed is not True
            )
        if monitor_gate.get("passed") is not True and not any(
            issue.startswith("monitor_gate_") for issue in issues
        ):
            issues.append("monitor_gate_failed")
    if "requested_scale" in record or "applied_scale_factor" in record:
        try:
            requested_scale = float(record["requested_scale"])
            applied_scale = float(record["applied_scale_factor"])
        except (KeyError, TypeError, ValueError):
            issues.append("scale_factor_not_applied")
        else:
            if not math.isclose(requested_scale, applied_scale, rel_tol=0, abs_tol=1e-9):
                issues.append("scale_factor_not_applied")
    image = record["image_analysis"]
    geometry = record["ui_geometry"]
    structure = geometry["structure"]
    if not image["pixel_size_matches"]:
        issues.append("pixel_size_mismatch")
    if image["blank_suspected"]:
        issues.append("blank_image_suspected")
    if image["near_black_ratio"] > NEAR_BLACK_FAILURE_RATIO:
        issues.append("near_black_ratio_high")
    if image.get("edge_black_stripe_suspected"):
        issues.append("edge_black_stripe_suspected")
    if image.get("contiguous_black_stripe_suspected"):
        issues.append("contiguous_black_stripe_suspected")
    if image.get("uniform_low_variance_suspected"):
        issues.append("uniform_low_variance_suspected")
    if geometry["clipping_proxy"]["suspected"]:
        issues.append("clipping_proxy_suspected")
    if not structure["central_scan_list_is_only_center_history"]:
        issues.append("center_scan_history_structure")
    if not structure["right_has_no_full_scan_history"]:
        issues.append("right_scan_history_duplicate")
    if not structure.get("right_has_no_progress_widget", False):
        issues.append("right_progress_widget_duplicate")
    if not structure.get("scan_list_frame_contract", False):
        issues.append("scan_list_frame_structure")
    if not structure["scan_list_below_notice"]:
        issues.append("scan_list_not_below_notice")
    if int(structure.get("core_action_button_count", 0)) != 4:
        issues.append("core_action_button_count")
    if not structure.get("core_action_common_parent", False):
        issues.append("core_action_parent_structure")
    if not structure.get("core_action_layout_matches", False):
        issues.append("core_action_responsive_layout")
    if structure.get("hidden_operation_buttons_mapped"):
        issues.append("secondary_operations_exposed")
    fixture = record.get("fixture") or {}
    rendered = record.get("rendered_state") or {}
    strict_capture_gates = int(record.get("capture_gate_schema_version", 1)) >= 2
    for gate_name in (
        "focus_gate",
        "scan_list_viewport_gate",
        "compact_display_gate",
    ):
        if strict_capture_gates or gate_name in record:
            _append_gate_issues(issues, record, gate_name)
    if rendered:
        if int(rendered.get("scan_list_row_count", -1)) != int(fixture.get("scan_count", 0)):
            issues.append("rendered_scan_count_mismatch")
        if "active_tray" in fixture:
            expected_scan_rows = _expected_scan_list_rows(fixture)
            rendered_scan_rows = [
                str(value) for value in (rendered.get("scan_list_rows") or [])
            ]
            if rendered_scan_rows != expected_scan_rows:
                issues.append("rendered_scan_rows_do_not_match_fixture")
        if rendered.get("scan_list_rows_neutral") is False:
            issues.append("scan_list_rows_not_settled")
        expected_last_scan_raw = str(fixture.get("last_normal_scan") or "")
        expected_last_scan_display = fixture.get("last_normal_scan_display")
        if expected_last_scan_display is None:
            expected_last_scan_display = expected_last_scan_raw or "-"
        rendered_last_scan_display = str(
            rendered.get("last_normal_scan_display", rendered.get("last_normal_scan")) or ""
        )
        if rendered_last_scan_display != str(expected_last_scan_display):
            issues.append("last_normal_scan_not_preserved")
        if expected_last_scan_raw:
            if str(rendered.get("presenter_last_normal_scan_raw") or "") != expected_last_scan_raw:
                issues.append("presenter_last_normal_scan_not_preserved")
            if fixture.get("active_tray") and (
                str(rendered.get("active_tray_last_scan_raw") or "") != expected_last_scan_raw
            ):
                issues.append("active_tray_last_scan_not_preserved")
            if (
                expected_last_scan_raw in rendered_last_scan_display
                or "|" in rendered_last_scan_display
                or "=" in rendered_last_scan_display
            ):
                issues.append("last_normal_scan_display_raw_leak")
        if "active_tray" in fixture:
            fixture_tray = fixture.get("tray")
            expected_active_scans_raw = (
                list(fixture_tray.get("scanned_barcodes") or [])
                if fixture.get("active_tray") and isinstance(fixture_tray, dict)
                else []
            )
            if rendered.get("active_tray_scans_raw") != expected_active_scans_raw:
                issues.append("active_tray_scans_not_preserved")
        if record.get("state") in {"duplicate", "operator_review"}:
            if str(rendered.get("scan_entry_state")) != "disabled":
                issues.append("blocking_state_scan_entry_enabled")
        if rendered.get("right_progress_count_texts"):
            issues.append("right_progress_count_duplicate")
    return issues


def apply_cross_capture_contracts(captures: Sequence[dict[str, Any]]) -> None:
    """Attach state-to-state invariants after one resolution matrix is rendered."""

    captures_by_size: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for capture in captures:
        size = tuple(int(value) for value in capture.get("requested_size", (0, 0)))
        captures_by_size.setdefault(size, []).append(capture)

    for size_captures in captures_by_size.values():
        if not size_captures:
            continue
        baseline_signature = size_captures[0]["ui_geometry"]["structure"].get(
            "scan_list_layout_signature"
        )
        for capture in size_captures:
            signature = capture["ui_geometry"]["structure"].get(
                "scan_list_layout_signature"
            )
            if signature != baseline_signature:
                if "scan_list_geometry_changed_across_states" not in capture["issues"]:
                    capture["issues"].append("scan_list_geometry_changed_across_states")

        by_state = {capture.get("state"): capture for capture in size_captures}
        normal = by_state.get("normal")
        duplicate = by_state.get("duplicate")
        if normal is not None and duplicate is not None:
            normal_rows = normal.get("rendered_state", {}).get("scan_list_rows", [])
            duplicate_rows = duplicate.get("rendered_state", {}).get("scan_list_rows", [])
            if duplicate_rows != normal_rows:
                duplicate["issues"].append("duplicate_scan_list_not_preserved")

        for capture in size_captures:
            capture["passed"] = not capture["issues"]


def build_roundtrip_signatures(record: dict[str, Any]) -> dict[str, Any]:
    geometry = record["ui_geometry"]
    widget_geometry = {
        str(widget["name"]): {
            "bbox": list(widget.get("bbox") or []),
            "size": list(widget.get("size") or []),
            "requested_size": list(widget.get("requested_size") or []),
            "mapped": bool(widget.get("mapped")),
        }
        for widget in geometry.get("widgets") or []
    }
    structure = geometry.get("structure") or {}
    geometry_signature = {
        "root_client_size": list(geometry.get("root_client_size") or []),
        "widgets": widget_geometry,
        "scan_list_layout": structure.get("scan_list_layout_signature"),
    }
    row_signature = list(record.get("rendered_state", {}).get("scan_list_rows") or [])
    action_signature = {
        "rows": structure.get("core_action_rows"),
        "buttons": record.get("rendered_state", {}).get("action_buttons"),
    }
    return {
        "geometry": geometry_signature,
        "rows": row_signature,
        "actions": action_signature,
        "geometry_sha256": hashlib.sha256(
            json.dumps(
                geometry_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "rows_sha256": hashlib.sha256(
            json.dumps(
                row_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "actions_sha256": hashlib.sha256(
            json.dumps(
                action_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def apply_roundtrip_contracts(captures: Sequence[dict[str, Any]]) -> None:
    roundtrip = [
        capture
        for capture in captures
        if capture.get("capture_sequence") == "roundtrip"
    ]
    if not roundtrip:
        return
    ordinals = sorted({int(capture["sequence_ordinal"]) for capture in roundtrip})
    first_ordinal, last_ordinal = ordinals[0], ordinals[-1]
    first_by_state = {
        str(capture["state"]): capture
        for capture in roundtrip
        if int(capture["sequence_ordinal"]) == first_ordinal
    }
    last_by_state = {
        str(capture["state"]): capture
        for capture in roundtrip
        if int(capture["sequence_ordinal"]) == last_ordinal
    }
    for state, first in first_by_state.items():
        last = last_by_state.get(state)
        if last is None:
            first["issues"].append("roundtrip_final_state_missing")
            first["passed"] = False
            continue
        first_signatures = first["roundtrip_signatures"]
        last_signatures = last["roundtrip_signatures"]
        checks = {
            "compact_size_exact": first.get("requested_size") == last.get("requested_size"),
            "geometry_signature_exact": (
                first_signatures["geometry"] == last_signatures["geometry"]
            ),
            "row_signature_exact": first_signatures["rows"] == last_signatures["rows"],
            "action_signature_exact": (
                first_signatures["actions"] == last_signatures["actions"]
            ),
        }
        last["roundtrip_comparison_gate"] = {
            "gate_applicable": True,
            "first_ordinal": first_ordinal,
            "last_ordinal": last_ordinal,
            "state": state,
            "first_signature_hashes": {
                key: value
                for key, value in first_signatures.items()
                if key.endswith("_sha256")
            },
            "last_signature_hashes": {
                key: value
                for key, value in last_signatures.items()
                if key.endswith("_sha256")
            },
            "checks": checks,
            "passed": all(checks.values()),
        }
        last["issues"].extend(
            f"roundtrip_{name}" for name, passed in checks.items() if passed is not True
        )
        last["passed"] = not last["issues"]


def build_isolated_app_settings(scale: object = DEFAULT_SCALE) -> dict[str, Any]:
    """Return the only settings allowed for an isolated visual capture."""

    return {
        "scale_factor": parse_scale(scale),
        "enable_internal_test_commands": False,
    }


class CaptureMutationBlocked(RuntimeError):
    pass


MUTATION_GUARD_APP_METHODS: dict[str, tuple[str, ...]] = {
    "barcode": (
        "process_barcode",
        "_process_barcode_logic",
    ),
    "event_write": (
        "_log_event",
        "_event_log_writer",
    ),
    "state_write": (
        "save_settings",
        "_save_best_time_records",
        "_update_best_time_records",
        "_save_current_tray_state",
        "_save_tray_state_snapshot",
        "_delete_current_tray_state",
        "_quarantine_current_tray_state",
    ),
    "completion": (
        "complete_tray",
        "submit_current_tray",
        "_complete_current_tray_as_partial",
    ),
    "transfer_seal": (
        "_prepare_and_attempt_transfer_seal",
        "_retry_pending_transfer_seals",
    ),
    "direct_sync": ("_trigger_session_direct_sync",),
    "worker_write": (
        "_register_worker_name",
        "_ensure_worker_login_name",
        "register_worker_from_login",
        "start_work",
        "change_worker",
    ),
    "parked_write": (
        "park_current_tray",
        "restore_parked_tray",
    ),
}


MUTATION_GUARD_NESTED_METHODS: tuple[
    tuple[str, str, tuple[str, ...]], ...
] = (
    ("worker_write", "worker_registry", ("_write_payload", "register", "mark_recent")),
    ("parked_write", "parked_tray_store", ("save_state", "delete")),
    (
        "transfer_seal",
        "transfer_seal_coordinator",
        ("prepare", "attempt", "drain_pending"),
    ),
    (
        "transfer_seal",
        "transfer_seal_coordinator.store",
        (
            "prepare",
            "bind_command",
            "record_error",
            "record_receipt",
            "record_exchange_block",
        ),
    ),
    ("event_write", "log_queue", ("put",)),
)


MUTATION_GUARD_MODULE_METHODS: dict[str, tuple[str, ...]] = {
    "event_write": ("append_event_log_entry",),
    "state_write": ("atomic_write_json",),
    "parked_write": ("quarantine_tray_state_file",),
    "direct_sync": (
        "start_session_direct_sync",
        "start_direct_sync_auto_bootstrap",
    ),
}


def _resolve_attribute_path(owner: Any, path: str) -> Any:
    current = owner
    for part in path.split("."):
        if not hasattr(current, part):
            raise RuntimeError(f"capture mutation guard target missing: {path}")
        current = getattr(current, part)
    return current


class CaptureMutationGuard:
    """Fail closed if isolated visual fixtures enter any business write path."""

    def __init__(self, app: Any, module: Any):
        self.app = app
        self.module = module
        self.armed = False
        self._originals: list[tuple[Any, str, Any]] = []
        self._protected: list[dict[str, str]] = []
        self._calls: list[dict[str, Any]] = []

    def _specs(self) -> list[tuple[str, str, Any, str]]:
        specs: list[tuple[str, str, Any, str]] = []
        for category, method_names in MUTATION_GUARD_APP_METHODS.items():
            specs.extend(
                (category, f"app.{name}", self.app, name) for name in method_names
            )
        for category, owner_path, method_names in MUTATION_GUARD_NESTED_METHODS:
            owner = _resolve_attribute_path(self.app, owner_path)
            specs.extend(
                (category, f"app.{owner_path}.{name}", owner, name)
                for name in method_names
            )
        for category, method_names in MUTATION_GUARD_MODULE_METHODS.items():
            specs.extend(
                (category, f"module.{name}", self.module, name)
                for name in method_names
            )
        return specs

    def arm(self) -> None:
        if self.armed:
            raise RuntimeError("capture mutation guard is already armed")
        specs = self._specs()
        missing = [
            label
            for _category, label, owner, name in specs
            if not callable(getattr(owner, name, None))
        ]
        if missing:
            raise RuntimeError(
                "capture mutation guard setup failed; missing callable targets: "
                + ", ".join(sorted(missing))
            )
        for category, label, owner, name in specs:
            original = getattr(owner, name)

            @functools.wraps(original)
            def blocked(*args: Any, __category=category, __label=label, **kwargs: Any):
                call = {
                    "category": __category,
                    "target": __label,
                    "positional_argument_count": len(args),
                    "keyword_names": sorted(str(key) for key in kwargs),
                }
                self._calls.append(call)
                raise CaptureMutationBlocked(
                    f"capture mutation blocked: {__category} {__label}"
                )

            self._originals.append((owner, name, original))
            setattr(owner, name, blocked)
            self._protected.append({"category": category, "target": label})
        self.armed = True

    def restore(self) -> None:
        for owner, name, original in reversed(self._originals):
            setattr(owner, name, original)
        self._originals.clear()
        self.armed = False

    def manifest(self) -> dict[str, Any]:
        protected_counts: dict[str, int] = {}
        call_counts: dict[str, int] = {}
        for item in self._protected:
            category = item["category"]
            protected_counts[category] = protected_counts.get(category, 0) + 1
        for item in self._calls:
            category = item["category"]
            call_counts[category] = call_counts.get(category, 0) + 1
        checks = {
            "guard_was_armed": bool(self._protected),
            "all_required_targets_protected": (
                len(self._protected)
                == sum(len(names) for names in MUTATION_GUARD_APP_METHODS.values())
                + sum(len(names) for _category, _owner, names in MUTATION_GUARD_NESTED_METHODS)
                + sum(len(names) for names in MUTATION_GUARD_MODULE_METHODS.values())
            ),
            "no_guarded_mutation_calls": not self._calls,
        }
        return {
            "gate_applicable": True,
            "armed": self.armed,
            "protected_targets": list(self._protected),
            "protected_target_counts_by_category": protected_counts,
            "total_protected_target_count": len(self._protected),
            "blocked_calls": list(self._calls),
            "blocked_call_counts_by_category": call_counts,
            "total_blocked_call_count": len(self._calls),
            "checks": checks,
            "passed": all(checks.values()),
        }


def inventory_isolated_data(data_root: Path) -> dict[str, Any]:
    resolved = data_root.resolve()
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted((item for item in resolved.rglob("*") if item.is_file())):
        size = path.stat().st_size
        relative_path = str(path.relative_to(resolved)).replace("\\", "/")
        file_hash = _sha256(path)
        files.append(
            {
                "path": relative_path,
                "size_bytes": size,
                "sha256": file_hash,
            }
        )
        total_bytes += size
    digest = hashlib.sha256()
    for item in files:
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item["size_bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    return {
        "root": str(resolved),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "inventory_sha256": digest.hexdigest(),
        "files": files,
    }


def build_isolated_data_gate(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "file_count_unchanged": before.get("file_count") == after.get("file_count"),
        "total_bytes_unchanged": before.get("total_bytes") == after.get("total_bytes"),
        "inventory_hash_unchanged": (
            before.get("inventory_sha256") == after.get("inventory_sha256")
        ),
        "file_inventory_exact": before.get("files") == after.get("files"),
    }
    return {
        "gate_applicable": True,
        "before": before,
        "after": after,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _make_capture_app(module: Any, scale: object = DEFAULT_SCALE) -> Any:
    isolated_settings = build_isolated_app_settings(scale)

    class CaptureContainerAudit(module.ContainerAudit):
        def _setup_paths_and_dirs(self) -> None:
            super()._setup_paths_and_dirs()
            isolated_root = Path(self.data_root)
            self.config_folder = str(isolated_root / "config")
            self.parked_trays_dir = str(isolated_root / "parked_trays")
            Path(self.config_folder).mkdir(parents=True, exist_ok=True)
            Path(self.parked_trays_dir).mkdir(parents=True, exist_ok=True)
            settings_path = Path(self.config_folder) / self.SETTINGS_FILE
            settings_path.write_text(
                json.dumps(isolated_settings, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.capture_settings_path = settings_path

    return CaptureContainerAudit()


def _load_app_module() -> Any:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import Container_Audit as module

    return module


def _cancel_runtime_jobs(app: Any) -> None:
    for name in (
        "clock_job",
        "stopwatch_job",
        "idle_check_job",
        "focus_return_job",
        "status_message_job",
        "_scanned_listbox_layout_job",
    ):
        job = getattr(app, name, None)
        if not job:
            continue
        try:
            app.root.after_cancel(job)
        except Exception:
            pass
        setattr(app, name, None)


def _align_tk_client_to_rect(root: Any, requested_rect: Rect) -> None:
    """Compensate for window chrome so the Tk client uses the requested rect."""

    requested_left, requested_top, requested_right, requested_bottom = requested_rect
    width = requested_right - requested_left
    height = requested_bottom - requested_top
    frame_left = requested_left
    frame_top = requested_top
    for _attempt in range(3):
        root.geometry(_format_tk_geometry(width, height, frame_left, frame_top))
        pump_tk(root, 140)
        actual_left = int(root.winfo_rootx())
        actual_top = int(root.winfo_rooty())
        delta_left = requested_left - actual_left
        delta_top = requested_top - actual_top
        if delta_left == 0 and delta_top == 0:
            break
        frame_left += delta_left
        frame_top += delta_top


def _configure_size(
    app: Any,
    size: tuple[int, int],
    monitor_target: MonitorTarget | None = None,
) -> None:
    width, height = size
    app.root.state("normal")
    if monitor_target is None:
        app.root.geometry(f"{width}x{height}+0+0")
    else:
        app.root.geometry(monitor_target.tk_geometry(size))
    app.root.attributes("-topmost", True)
    app.root.deiconify()
    app.root.lift()
    pump_tk(app.root, 260)
    app.apply_scaling()
    app.show_validation_screen()
    pump_tk(app.root, 420)
    if monitor_target is not None:
        _align_tk_client_to_rect(
            app.root,
            monitor_target.requested_client_rect(size),
        )
    _cancel_runtime_jobs(app)


def run_capture_matrix(
    *,
    output_root: Path,
    sizes: Sequence[tuple[int, int]],
    state_ids: Sequence[str],
    scale: object = DEFAULT_SCALE,
    monitor_device: str = "",
    roundtrip_sizes: Sequence[tuple[int, int]] = (),
) -> tuple[Path, dict[str, Any]]:
    requested_scale = parse_scale(scale)
    isolated_settings = build_isolated_app_settings(requested_scale)
    all_requested_sizes = tuple(sizes) + tuple(roundtrip_sizes)
    monitor_target = (
        resolve_monitor_target(monitor_device, all_requested_sizes)
        if str(monitor_device or "").strip()
        else None
    )
    monitor_preflight = (
        monitor_preflight_manifest(monitor_target, all_requested_sizes)
        if monitor_target is not None
        else {
            "gate_applicable": False,
            "selection_mode": "legacy_default_origin",
            "requested_device_name": None,
            "passed": True,
        }
    )
    if monitor_target is not None and monitor_preflight["passed"] is not True:
        raise RuntimeError("selected monitor failed capture preflight")
    resolved_output = assert_descendant(
        output_root,
        REPO_TMP_ROOT,
        label="capture output root",
    )
    resolved_output.mkdir(parents=True, exist_ok=True)
    screenshot_root = resolved_output / "screenshots"
    screenshot_root.mkdir(parents=True, exist_ok=True)
    data_root = resolved_output / "_isolated_data"
    geometry = (
        monitor_target.tk_geometry(sizes[0])
        if monitor_target is not None
        else f"{sizes[0][0]}x{sizes[0][1]}+0+0"
    )
    guards = prepare_isolated_environment(data_root, geometry)
    dpi_mode = enable_per_monitor_dpi_awareness()
    module = _load_app_module()
    fixtures_by_id = {fixture.state_id: fixture for fixture in build_state_fixtures()}

    manifest: dict[str, Any] = {
        "schema_version": 2,
        "tool": "tools/capture_container_operator_ui.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
        "repository_root": str(ROOT),
        "output_root": str(resolved_output),
        "data_root": str(data_root.resolve()),
        "isolation_guards": guards,
        "dpi_awareness": dpi_mode,
        "requested_sizes": [[width, height] for width, height in sizes],
        "roundtrip_sizes": [
            [width, height] for width, height in roundtrip_sizes
        ],
        "requested_states": list(state_ids),
        "requested_scale": requested_scale,
        "isolated_app_settings": isolated_settings,
        "monitor_preflight": monitor_preflight,
        "near_black_failure_ratio": NEAR_BLACK_FAILURE_RATIO,
        "captures": [],
    }

    app = None
    mutation_guard: CaptureMutationGuard | None = None
    isolated_data_before: dict[str, Any] | None = None
    isolated_data_after: dict[str, Any] | None = None
    try:
        app = _make_capture_app(module, requested_scale)
        isolated_data_before = inventory_isolated_data(data_root)
        mutation_guard = CaptureMutationGuard(app, module)
        mutation_guard.arm()
        manifest["applied_scale_factor"] = float(app.scale_factor)
        settings_path = Path(app.capture_settings_path).resolve()
        manifest["isolated_settings_path"] = str(
            settings_path.relative_to(resolved_output)
        ).replace("\\", "/")
        app.worker_name = "캡처 작업자"

        def capture_sequence_item(
            size: tuple[int, int],
            *,
            capture_sequence: str,
            sequence_ordinal: int | None = None,
        ) -> None:
            _configure_size(app, size, monitor_target)
            if capture_sequence == "roundtrip":
                if sequence_ordinal is None:
                    raise RuntimeError("roundtrip capture requires an ordinal")
                size_dir = (
                    screenshot_root
                    / "roundtrip"
                    / f"{sequence_ordinal:03d}_{size[0]}x{size[1]}"
                )
            else:
                size_dir = screenshot_root / f"{size[0]}x{size[1]}"
            size_dir.mkdir(parents=True, exist_ok=True)
            for state_id in state_ids:
                fixture = fixtures_by_id[state_id]
                apply_state_fixture(app, fixture, module)
                pump_tk(app.root, 260)
                viewport_gate = collect_scan_list_viewport_gate(
                    app,
                    expected_row_count=(
                        len(fixture.tray.scanned_barcodes)
                        if fixture.tray is not None
                        else 0
                    ),
                )
                settle_capture_focus(app, state_id)
                focus_gate = collect_capture_focus_gate(app, state_id)
                monitor_gate = (
                    collect_monitor_capture_gate(app.root, monitor_target, size)
                    if monitor_target is not None
                    else None
                )
                geometry_record = collect_ui_geometry(app)
                rendered_state = collect_rendered_state(app)
                image, source = capture_tk_client(app.root)
                path = size_dir / f"{state_id}.png"
                image.save(path, format="PNG", optimize=True)
                fixture_manifest = _fixture_manifest(fixture)
                record_id = f"{size[0]}x{size[1]}-{state_id}"
                if capture_sequence == "roundtrip":
                    record_id = f"roundtrip-{sequence_ordinal:03d}-{record_id}"
                record = {
                    "id": record_id,
                    "state": state_id,
                    "state_label": fixture.state_label,
                    "capture_sequence": capture_sequence,
                    "sequence_ordinal": sequence_ordinal,
                    "requested_size": [size[0], size[1]],
                    "requested_scale": requested_scale,
                    "applied_scale_factor": float(app.scale_factor),
                    "capture_gate_schema_version": 2,
                    "path": str(path.relative_to(resolved_output)).replace("\\", "/"),
                    "capture_source": source,
                    "sha256": _sha256(path),
                    "file_size_bytes": path.stat().st_size,
                    "fixture": fixture_manifest,
                    "image_analysis": analyze_image(image, size),
                    "ui_geometry": geometry_record,
                    "rendered_state": rendered_state,
                    "focus_gate": focus_gate,
                    "scan_list_viewport_gate": viewport_gate,
                    "compact_display_gate": build_compact_display_gate(
                        fixture_manifest,
                        rendered_state,
                    ),
                }
                if monitor_gate is not None:
                    record["monitor_gate"] = monitor_gate
                if capture_sequence == "roundtrip":
                    record["roundtrip_signatures"] = build_roundtrip_signatures(record)
                record["issues"] = evaluate_capture(record)
                record["passed"] = not record["issues"]
                manifest["captures"].append(record)

        for size in sizes:
            capture_sequence_item(size, capture_sequence="matrix")
        for ordinal, size in enumerate(roundtrip_sizes, start=1):
            capture_sequence_item(
                size,
                capture_sequence="roundtrip",
                sequence_ordinal=ordinal,
            )
    finally:
        if app is not None:
            _cancel_runtime_jobs(app)
            if isolated_data_before is not None:
                isolated_data_after = inventory_isolated_data(data_root)
            if mutation_guard is not None:
                manifest["mutation_guard"] = mutation_guard.manifest()
                mutation_guard.restore()
            try:
                app.root.attributes("-topmost", False)
            except Exception:
                pass
            try:
                app.root.destroy()
            except Exception:
                pass

    if isolated_data_before is None or isolated_data_after is None:
        raise RuntimeError("isolated data inventory was not completed")
    manifest["isolated_data_gate"] = build_isolated_data_gate(
        isolated_data_before,
        isolated_data_after,
    )

    captures = manifest["captures"]
    apply_cross_capture_contracts(
        [capture for capture in captures if capture["capture_sequence"] == "matrix"]
    )
    for ordinal in range(1, len(roundtrip_sizes) + 1):
        apply_cross_capture_contracts(
            [
                capture
                for capture in captures
                if capture["capture_sequence"] == "roundtrip"
                and capture["sequence_ordinal"] == ordinal
            ]
        )
    apply_roundtrip_contracts(captures)
    issue_counts: dict[str, int] = {}
    for capture in captures:
        for issue in capture["issues"]:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    if manifest.get("mutation_guard", {}).get("passed") is not True:
        issue_counts["mutation_guard_failed"] = 1
    if manifest["isolated_data_gate"].get("passed") is not True:
        issue_counts["isolated_data_changed"] = 1
    expected_capture_count = (
        len(sizes) + len(roundtrip_sizes)
    ) * len(state_ids)
    manifest["summary"] = {
        "requested_scale": requested_scale,
        "expected_capture_count": expected_capture_count,
        "capture_count": len(captures),
        "passed_capture_count": sum(1 for capture in captures if capture["passed"]),
        "failed_capture_count": sum(1 for capture in captures if not capture["passed"]),
        "clipping_issue_count": sum(
            int(capture["ui_geometry"]["clipping_proxy"].get("issue_count", 0))
            for capture in captures
        ),
        "issue_counts": issue_counts,
        "monitor_gate_applicable": monitor_target is not None,
        "monitor_gate_passed": (
            all(
                capture.get("monitor_gate", {}).get("passed") is True
                for capture in captures
            )
            if monitor_target is not None
            else True
        ),
        "mutation_guard_total_protected_target_count": manifest.get(
            "mutation_guard", {}
        ).get("total_protected_target_count", 0),
        "mutation_guard_total_blocked_call_count": manifest.get(
            "mutation_guard", {}
        ).get("total_blocked_call_count", 0),
        "isolated_data_file_count_before": isolated_data_before["file_count"],
        "isolated_data_file_count_after": isolated_data_after["file_count"],
        "isolated_data_total_bytes_before": isolated_data_before["total_bytes"],
        "isolated_data_total_bytes_after": isolated_data_after["total_bytes"],
        "roundtrip_capture_count": sum(
            1 for capture in captures if capture["capture_sequence"] == "roundtrip"
        ),
        "passed": len(captures) == expected_capture_count and not issue_counts,
    }
    manifest_path = resolved_output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest_path, manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render isolated Container_Audit operator states at fixed client sizes and "
            "write PNG screenshots plus a geometry/pixel manifest."
        )
    )
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_TMP_ROOT / f"container_operator_ui_capture_{timestamp}",
        help=f"new/output directory below {REPO_TMP_ROOT}",
    )
    parser.add_argument(
        "--sizes",
        type=parse_sizes,
        default=DEFAULT_SIZES,
        help="comma-separated client sizes, for example 1366x768,1440x900",
    )
    parser.add_argument(
        "--states",
        type=parse_states,
        default=DEFAULT_STATE_IDS,
        help=f"comma-separated states: {','.join(DEFAULT_STATE_IDS)}",
    )
    parser.add_argument(
        "--scale",
        type=parse_scale,
        default=DEFAULT_SCALE,
        help=f"UI scale factor from {MIN_SCALE} to {MAX_SCALE} (default: {DEFAULT_SCALE})",
    )
    parser.add_argument(
        "--monitor-device",
        default="",
        help=(
            "Exact Win32 non-primary monitor device name, for example "
            r"\\.\DISPLAY2. Omit to preserve legacy +0+0 placement."
        ),
    )
    parser.add_argument(
        "--roundtrip-sizes",
        type=parse_roundtrip_sizes,
        default=(),
        help=(
            "optional ordered same-instance compact,wide,compact sequence; "
            "duplicates are preserved and screenshots use ordinal paths"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return an error after writing the manifest when any proxy check fails",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path, manifest = run_capture_matrix(
        output_root=args.output_root,
        sizes=args.sizes,
        state_ids=args.states,
        scale=args.scale,
        monitor_device=args.monitor_device,
        roundtrip_sizes=args.roundtrip_sizes,
    )
    summary = manifest["summary"]
    print(
        json.dumps(
            {
                "manifest": str(manifest_path),
                "capture_count": summary["capture_count"],
                "requested_scale": summary["requested_scale"],
                "monitor_device": args.monitor_device or None,
                "monitor_gate_passed": summary["monitor_gate_passed"],
                "roundtrip_sizes": [list(size) for size in args.roundtrip_sizes],
                "passed": summary["passed"],
                "issue_counts": summary["issue_counts"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if summary["passed"] or not args.strict else 2


if __name__ == "__main__":
    raise SystemExit(main())
