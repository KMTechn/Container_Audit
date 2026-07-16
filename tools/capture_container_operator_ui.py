from __future__ import annotations

import argparse
import ctypes
import datetime as dt
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

from PIL import Image, ImageGrab, ImageStat


ROOT = Path(__file__).resolve().parents[1]
REPO_TMP_ROOT = ROOT / "tmp"
DEFAULT_SIZES = ((1366, 768), (1440, 900), (1920, 1080), (2560, 1080))
DEFAULT_STATE_IDS = (
    "waiting",
    "normal",
    "duplicate",
    "operator_review",
    "completed",
    "recovered",
)
NEAR_BLACK_LUMA = 16
NEAR_BLACK_FAILURE_RATIO = 0.35
MIN_SCALE = 0.7
MAX_SCALE = 2.5
DEFAULT_SCALE = 1.0


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
    notice: NoticeFixture | None = None
    completion: CompletionFixture | None = None
    completed_tray_count: int = 0


def _products(count: int) -> tuple[str, ...]:
    return tuple(f"AAA2270730100-LINE-{index:04d}" for index in range(1, count + 1))


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
            notice=NoticeFixture(
                code="capture.duplicate",
                title="중복 스캔",
                message=f"이미 스캔된 제품입니다: {normal_products[-1]}",
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
            notice=NoticeFixture(
                code="capture.recovered",
                title="작업 복구 완료",
                message="보류된 트레이를 복구했습니다. 중앙 목록을 확인하고 다음 제품을 스캔하세요.",
                severity="success",
                blocking=False,
            ),
        ),
    )


def parse_sizes(value: str) -> tuple[tuple[int, int], ...]:
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
        if pair not in sizes:
            sizes.append(pair)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one capture size is required")
    return tuple(sizes)


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
    gray = rgb.convert("L")
    histogram = gray.histogram()
    pixel_count = max(1, rgb.width * rgb.height)
    near_black_pixels = sum(histogram[: NEAR_BLACK_LUMA + 1])
    extrema = gray.getextrema() or (0, 0)
    stat = ImageStat.Stat(gray)
    luma_mean = float(stat.mean[0])
    luma_stddev = float(stat.stddev[0])

    sample = rgb.copy()
    sample.thumbnail((256, 256))
    colors = sample.getcolors(maxcolors=sample.width * sample.height) or []
    dominant_ratio = (
        max((count for count, _color in colors), default=0)
        / max(1, sample.width * sample.height)
    )
    blank_suspected = bool(
        extrema[1] - extrema[0] <= 2
        or luma_stddev < 0.75
        or dominant_ratio >= 0.997
    )
    return {
        "expected_pixel_size": [int(expected_size[0]), int(expected_size[1])],
        "pixel_size": [rgb.width, rgb.height],
        "pixel_size_matches": (rgb.width, rgb.height) == expected_size,
        "near_black_threshold_luma": NEAR_BLACK_LUMA,
        "near_black_pixels": near_black_pixels,
        "near_black_ratio": round(near_black_pixels / pixel_count, 6),
        "luma_mean": round(luma_mean, 3),
        "luma_stddev": round(luma_stddev, 3),
        "luma_extrema": [int(extrema[0]), int(extrema[1])],
        "dominant_color_ratio_sampled": round(dominant_ratio, 6),
        "blank_suspected": blank_suspected,
    }


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
    return {
        "stage": _widget_text(app.stage_label),
        "current_item": _widget_text(app.current_item_label),
        "count": _widget_text(app.main_count_label),
        "notice_title": _widget_text(app.notice_title_label),
        "notice_message": _widget_text(app.notice_message_label),
        "last_normal_scan": _widget_text(app.last_scan_value_label),
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
    return row_count


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
            app.scanned_listbox.insert(0, f"({index}) {barcode}")
    normalize_capture_scan_rows(app)

    if fixture.last_normal_scan:
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
    return record


def _expected_scan_list_rows(fixture: dict[str, Any]) -> list[str]:
    """Return the exact rows the active tray should render in current UI order."""

    if not fixture.get("active_tray"):
        return []
    tray = fixture.get("tray")
    if not isinstance(tray, dict):
        return []
    barcodes = tray.get("scanned_barcodes") or ()
    numbered_rows = [
        f"({index}) {barcode}"
        for index, barcode in enumerate(barcodes, start=1)
    ]
    return list(reversed(numbered_rows))


def evaluate_capture(record: dict[str, Any]) -> list[str]:
    issues: list[str] = []
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
        expected_last_scan = str(fixture.get("last_normal_scan") or "")
        rendered_last_scan = str(rendered.get("last_normal_scan") or "")
        if expected_last_scan and rendered_last_scan != expected_last_scan:
            issues.append("last_normal_scan_not_preserved")
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


def build_isolated_app_settings(scale: object = DEFAULT_SCALE) -> dict[str, Any]:
    """Return the only settings allowed for an isolated visual capture."""

    return {
        "scale_factor": parse_scale(scale),
        "enable_internal_test_commands": False,
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


def _configure_size(app: Any, size: tuple[int, int]) -> None:
    width, height = size
    app.root.state("normal")
    app.root.geometry(f"{width}x{height}+0+0")
    app.root.attributes("-topmost", True)
    app.root.deiconify()
    app.root.lift()
    pump_tk(app.root, 260)
    app.apply_scaling()
    app.show_validation_screen()
    pump_tk(app.root, 420)
    _cancel_runtime_jobs(app)


def run_capture_matrix(
    *,
    output_root: Path,
    sizes: Sequence[tuple[int, int]],
    state_ids: Sequence[str],
    scale: object = DEFAULT_SCALE,
) -> tuple[Path, dict[str, Any]]:
    requested_scale = parse_scale(scale)
    isolated_settings = build_isolated_app_settings(requested_scale)
    resolved_output = assert_descendant(
        output_root,
        REPO_TMP_ROOT,
        label="capture output root",
    )
    resolved_output.mkdir(parents=True, exist_ok=True)
    screenshot_root = resolved_output / "screenshots"
    screenshot_root.mkdir(parents=True, exist_ok=True)
    data_root = resolved_output / "_isolated_data"
    geometry = f"{sizes[0][0]}x{sizes[0][1]}+0+0"
    guards = prepare_isolated_environment(data_root, geometry)
    dpi_mode = enable_per_monitor_dpi_awareness()
    module = _load_app_module()
    fixtures_by_id = {fixture.state_id: fixture for fixture in build_state_fixtures()}

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "tool": "tools/capture_container_operator_ui.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
        "repository_root": str(ROOT),
        "output_root": str(resolved_output),
        "data_root": str(data_root.resolve()),
        "isolation_guards": guards,
        "dpi_awareness": dpi_mode,
        "requested_sizes": [[width, height] for width, height in sizes],
        "requested_states": list(state_ids),
        "requested_scale": requested_scale,
        "isolated_app_settings": isolated_settings,
        "near_black_failure_ratio": NEAR_BLACK_FAILURE_RATIO,
        "captures": [],
    }

    app = None
    try:
        app = _make_capture_app(module, requested_scale)
        manifest["applied_scale_factor"] = float(app.scale_factor)
        settings_path = Path(app.capture_settings_path).resolve()
        manifest["isolated_settings_path"] = str(
            settings_path.relative_to(resolved_output)
        ).replace("\\", "/")
        app.worker_name = "캡처 작업자"
        for size in sizes:
            _configure_size(app, size)
            size_dir = screenshot_root / f"{size[0]}x{size[1]}"
            size_dir.mkdir(parents=True, exist_ok=True)
            for state_id in state_ids:
                fixture = fixtures_by_id[state_id]
                apply_state_fixture(app, fixture, module)
                pump_tk(app.root, 260)
                geometry_record = collect_ui_geometry(app)
                image, source = capture_tk_client(app.root)
                path = size_dir / f"{state_id}.png"
                image.save(path, format="PNG", optimize=True)
                record = {
                    "id": f"{size[0]}x{size[1]}-{state_id}",
                    "state": state_id,
                    "state_label": fixture.state_label,
                    "requested_size": [size[0], size[1]],
                    "requested_scale": requested_scale,
                    "applied_scale_factor": float(app.scale_factor),
                    "path": str(path.relative_to(resolved_output)).replace("\\", "/"),
                    "capture_source": source,
                    "sha256": _sha256(path),
                    "file_size_bytes": path.stat().st_size,
                    "fixture": _fixture_manifest(fixture),
                    "image_analysis": analyze_image(image, size),
                    "ui_geometry": geometry_record,
                    "rendered_state": collect_rendered_state(app),
                }
                record["issues"] = evaluate_capture(record)
                record["passed"] = not record["issues"]
                manifest["captures"].append(record)
    finally:
        if app is not None:
            _cancel_runtime_jobs(app)
            try:
                app.root.attributes("-topmost", False)
            except Exception:
                pass
            try:
                app.root.destroy()
            except Exception:
                pass

    captures = manifest["captures"]
    apply_cross_capture_contracts(captures)
    issue_counts: dict[str, int] = {}
    for capture in captures:
        for issue in capture["issues"]:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    manifest["summary"] = {
        "requested_scale": requested_scale,
        "expected_capture_count": len(sizes) * len(state_ids),
        "capture_count": len(captures),
        "passed_capture_count": sum(1 for capture in captures if capture["passed"]),
        "failed_capture_count": sum(1 for capture in captures if not capture["passed"]),
        "clipping_issue_count": sum(
            int(capture["ui_geometry"]["clipping_proxy"].get("issue_count", 0))
            for capture in captures
        ),
        "issue_counts": issue_counts,
        "passed": len(captures) == len(sizes) * len(state_ids) and not issue_counts,
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
    )
    summary = manifest["summary"]
    print(
        json.dumps(
            {
                "manifest": str(manifest_path),
                "capture_count": summary["capture_count"],
                "requested_scale": summary["requested_scale"],
                "passed": summary["passed"],
                "issue_counts": summary["issue_counts"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if summary["passed"] or not args.strict else 2


if __name__ == "__main__":
    raise SystemExit(main())
