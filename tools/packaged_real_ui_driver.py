from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from PIL import Image
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


def annotate_requested_capture_size(capture: dict[str, Any], geometry: str) -> None:
    capture["screenshot_role"] = "main"
    capture["requested_size_gate_applicable"] = True
    requested_rect = _parse_geometry_rect(geometry)
    if requested_rect is None:
        capture["requested_geometry_valid"] = False
        capture["pixel_size_matches_requested"] = False
        return
    requested_width = requested_rect[2] - requested_rect[0]
    requested_height = requested_rect[3] - requested_rect[1]
    capture["requested_pixel_size"] = [requested_width, requested_height]
    capture["requested_geometry_valid"] = True
    capture["pixel_size_matches_requested"] = (
        capture["width"], capture["height"]
    ) == (requested_width, requested_height)


def main_screenshots_match_requested_size(screenshots: list[dict[str, Any]]) -> bool:
    main_screenshots = [
        item for item in screenshots if item.get("screenshot_role") == "main"
    ]
    return bool(main_screenshots) and all(
        item.get("requested_size_gate_applicable") is True
        and item.get("requested_geometry_valid") is True
        and item.get("pixel_size_matches_requested") is True
        for item in main_screenshots
    )


INLINE_WARNING_VISUAL_METHOD = (
    "central_pane_broad_vertical_red_border_and_pale_fill_v2"
)
INLINE_WARNING_ROI_NORMALIZED = {
    "left": 0.23,
    "top": 0.29,
    "right": 0.79,
    "bottom": 0.58,
}
INLINE_WARNING_RED_RULE = {
    "red_channel_min": 170,
    "red_over_green_min": 65,
    "red_over_blue_min": 65,
}
INLINE_WARNING_PINK_BORDER_RULE = {
    "red_channel_min": 235,
    "green_channel_min": 120,
    "green_channel_max": 205,
    "blue_channel_min": 120,
    "blue_channel_max": 205,
    "green_blue_delta_abs_max": 20,
}
INLINE_WARNING_PALE_FILL_RULE = {
    "red_channel_min": 245,
    "green_channel_min": 225,
    "blue_channel_min": 225,
    "red_over_green_min": 5,
    "red_over_blue_min": 5,
}
INLINE_WARNING_SIGNAL_THRESHOLDS = {
    "red_pixel_ratio_min": 0.004,
    "pink_border_max_contiguous_run_ratio_min": 0.30,
    "pale_warning_fill_ratio_min": 0.05,
    "red_pixel_ratio_delta_from_baseline_min": 0.003,
    "pink_border_run_ratio_delta_from_baseline_min": 0.20,
    "pale_fill_ratio_delta_from_baseline_min": 0.04,
}
INLINE_WARNING_DISAPPEARANCE_THRESHOLDS = {
    "red_pixel_ratio_drop_from_warning_min": 0.003,
    "pink_border_run_ratio_drop_from_warning_min": 0.20,
    "pale_fill_ratio_drop_from_warning_min": 0.04,
    "red_pixel_ratio_above_baseline_max": 0.002,
    "pink_border_run_ratio_after_enter_max": 0.10,
    "pale_fill_ratio_after_enter_max": 0.01,
    "pink_border_run_ratio_above_baseline_max": 0.05,
    "pale_fill_ratio_above_baseline_max": 0.005,
}


def analyze_inline_warning_visual(image: Image.Image) -> dict[str, Any]:
    """Measure a red banner signal only inside the central warning-band region."""
    rgb_image = image.convert("RGB")
    width, height = rgb_image.size
    if width <= 0 or height <= 0:
        raise ValueError("inline warning visual analysis requires a non-empty image")

    left = max(0, min(width - 1, round(width * INLINE_WARNING_ROI_NORMALIZED["left"])))
    top = max(0, min(height - 1, round(height * INLINE_WARNING_ROI_NORMALIZED["top"])))
    right = max(left + 1, min(width, round(width * INLINE_WARNING_ROI_NORMALIZED["right"])))
    bottom = max(top + 1, min(height, round(height * INLINE_WARNING_ROI_NORMALIZED["bottom"])))
    roi = rgb_image.crop((left, top, right, bottom))
    roi_width, roi_height = roi.size
    row_counts = [0] * roi_height
    column_counts = [0] * roi_width
    red_pixel_count = 0
    min_x = roi_width
    max_x = -1
    min_y = roi_height
    max_y = -1
    pink_border_pixel_count = 0
    pink_border_max_contiguous_run = 0
    pink_border_current_run = 0
    pale_warning_fill_pixel_count = 0
    red_min = INLINE_WARNING_RED_RULE["red_channel_min"]
    red_green_delta = INLINE_WARNING_RED_RULE["red_over_green_min"]
    red_blue_delta = INLINE_WARNING_RED_RULE["red_over_blue_min"]
    pixels = (
        roi.get_flattened_data()
        if hasattr(roi, "get_flattened_data")
        else roi.getdata()
    )
    for index, (red, green, blue) in enumerate(pixels):
        x = index % roi_width
        y = index // roi_width
        if x == 0:
            pink_border_current_run = 0
        if (
            red >= red_min
            and red - green >= red_green_delta
            and red - blue >= red_blue_delta
        ):
            red_pixel_count += 1
            row_counts[y] += 1
            column_counts[x] += 1
            min_x = min(min_x, x)
            max_x = max(max_x, x)
            min_y = min(min_y, y)
            max_y = max(max_y, y)
        pink_border_pixel = (
            red >= INLINE_WARNING_PINK_BORDER_RULE["red_channel_min"]
            and INLINE_WARNING_PINK_BORDER_RULE["green_channel_min"]
            <= green
            <= INLINE_WARNING_PINK_BORDER_RULE["green_channel_max"]
            and INLINE_WARNING_PINK_BORDER_RULE["blue_channel_min"]
            <= blue
            <= INLINE_WARNING_PINK_BORDER_RULE["blue_channel_max"]
            and abs(green - blue)
            <= INLINE_WARNING_PINK_BORDER_RULE["green_blue_delta_abs_max"]
        )
        if pink_border_pixel:
            pink_border_pixel_count += 1
            pink_border_current_run += 1
            pink_border_max_contiguous_run = max(
                pink_border_max_contiguous_run,
                pink_border_current_run,
            )
        else:
            pink_border_current_run = 0
        if (
            red >= INLINE_WARNING_PALE_FILL_RULE["red_channel_min"]
            and green >= INLINE_WARNING_PALE_FILL_RULE["green_channel_min"]
            and blue >= INLINE_WARNING_PALE_FILL_RULE["blue_channel_min"]
            and red - green
            >= INLINE_WARNING_PALE_FILL_RULE["red_over_green_min"]
            and red - blue >= INLINE_WARNING_PALE_FILL_RULE["red_over_blue_min"]
        ):
            pale_warning_fill_pixel_count += 1

    roi_pixel_count = roi_width * roi_height
    active_columns = sum(count > 0 for count in column_counts)
    active_rows = sum(count > 0 for count in row_counts)
    horizontal_span = max_x - min_x + 1 if max_x >= min_x else 0
    vertical_span = max_y - min_y + 1 if max_y >= min_y else 0
    metrics = {
        "strong_red_pixel_count": red_pixel_count,
        "strong_red_pixel_ratio": round(red_pixel_count / roi_pixel_count, 6),
        "active_red_column_count": active_columns,
        "active_red_column_ratio": round(active_columns / roi_width, 6),
        "active_red_row_count": active_rows,
        "active_red_row_ratio": round(active_rows / roi_height, 6),
        "max_row_red_pixel_count": max(row_counts, default=0),
        "max_row_red_coverage_ratio": round(max(row_counts, default=0) / roi_width, 6),
        "horizontal_red_span_pixels": horizontal_span,
        "horizontal_red_span_ratio": round(horizontal_span / roi_width, 6),
        "vertical_red_span_pixels": vertical_span,
        "vertical_red_span_ratio": round(vertical_span / roi_height, 6),
        "pink_border_pixel_count": pink_border_pixel_count,
        "pink_border_pixel_ratio": round(
            pink_border_pixel_count / roi_pixel_count,
            6,
        ),
        "pink_border_max_contiguous_run_pixels": (
            pink_border_max_contiguous_run
        ),
        "pink_border_max_contiguous_run_ratio": round(
            pink_border_max_contiguous_run / roi_width,
            6,
        ),
        "pale_warning_fill_pixel_count": pale_warning_fill_pixel_count,
        "pale_warning_fill_ratio": round(
            pale_warning_fill_pixel_count / roi_pixel_count,
            6,
        ),
    }
    return {
        "method": INLINE_WARNING_VISUAL_METHOD,
        "ocr_used": False,
        "visual_text_match_claimed": False,
        "image_size": [width, height],
        "roi_role": "central_warning_band_only_right_sidebar_excluded",
        "roi_normalized_bounds": dict(INLINE_WARNING_ROI_NORMALIZED),
        "roi_pixel_bounds": [left, top, right, bottom],
        "roi_size": [roi_width, roi_height],
        "strong_red_color_rule": dict(INLINE_WARNING_RED_RULE),
        "pink_border_color_rule": dict(INLINE_WARNING_PINK_BORDER_RULE),
        "pale_warning_fill_color_rule": dict(INLINE_WARNING_PALE_FILL_RULE),
        "metrics": metrics,
    }


def evaluate_inline_warning_visual_signal(
    baseline: dict[str, Any],
    warning: dict[str, Any],
) -> dict[str, Any]:
    baseline_metrics = baseline["metrics"]
    warning_metrics = warning["metrics"]
    comparison = {
        "red_pixel_ratio_delta_from_baseline": round(
            warning_metrics["strong_red_pixel_ratio"]
            - baseline_metrics["strong_red_pixel_ratio"],
            6,
        ),
        "pink_border_run_ratio_delta_from_baseline": round(
            warning_metrics["pink_border_max_contiguous_run_ratio"]
            - baseline_metrics["pink_border_max_contiguous_run_ratio"],
            6,
        ),
        "pale_fill_ratio_delta_from_baseline": round(
            warning_metrics["pale_warning_fill_ratio"]
            - baseline_metrics["pale_warning_fill_ratio"],
            6,
        ),
    }
    thresholds = INLINE_WARNING_SIGNAL_THRESHOLDS
    signal_detected = all(
        (
            warning_metrics["strong_red_pixel_ratio"]
            >= thresholds["red_pixel_ratio_min"],
            warning_metrics["pink_border_max_contiguous_run_ratio"]
            >= thresholds["pink_border_max_contiguous_run_ratio_min"],
            warning_metrics["pale_warning_fill_ratio"]
            >= thresholds["pale_warning_fill_ratio_min"],
            comparison["red_pixel_ratio_delta_from_baseline"]
            >= thresholds["red_pixel_ratio_delta_from_baseline_min"],
            comparison["pink_border_run_ratio_delta_from_baseline"]
            >= thresholds["pink_border_run_ratio_delta_from_baseline_min"],
            comparison["pale_fill_ratio_delta_from_baseline"]
            >= thresholds["pale_fill_ratio_delta_from_baseline_min"],
        )
    )
    return {
        "method": INLINE_WARNING_VISUAL_METHOD,
        "signal_detected": signal_detected,
        "ocr_used": False,
        "visual_text_match_claimed": False,
        "thresholds": dict(thresholds),
        "comparison": comparison,
        "baseline_analysis": baseline,
        "warning_analysis": warning,
    }


def evaluate_inline_warning_visual_disappearance(
    warning_proof: dict[str, Any],
    after_enter: dict[str, Any],
) -> dict[str, Any]:
    baseline_metrics = warning_proof["baseline_analysis"]["metrics"]
    warning_metrics = warning_proof["warning_analysis"]["metrics"]
    after_metrics = after_enter["metrics"]
    comparison = {
        "red_pixel_ratio_drop_from_warning": round(
            warning_metrics["strong_red_pixel_ratio"]
            - after_metrics["strong_red_pixel_ratio"],
            6,
        ),
        "pink_border_run_ratio_drop_from_warning": round(
            warning_metrics["pink_border_max_contiguous_run_ratio"]
            - after_metrics["pink_border_max_contiguous_run_ratio"],
            6,
        ),
        "pale_fill_ratio_drop_from_warning": round(
            warning_metrics["pale_warning_fill_ratio"]
            - after_metrics["pale_warning_fill_ratio"],
            6,
        ),
        "red_pixel_ratio_above_baseline": round(
            after_metrics["strong_red_pixel_ratio"]
            - baseline_metrics["strong_red_pixel_ratio"],
            6,
        ),
        "pink_border_run_ratio_above_baseline": round(
            after_metrics["pink_border_max_contiguous_run_ratio"]
            - baseline_metrics["pink_border_max_contiguous_run_ratio"],
            6,
        ),
        "pale_fill_ratio_above_baseline": round(
            after_metrics["pale_warning_fill_ratio"]
            - baseline_metrics["pale_warning_fill_ratio"],
            6,
        ),
    }
    thresholds = INLINE_WARNING_DISAPPEARANCE_THRESHOLDS
    disappeared = warning_proof.get("signal_detected") is True and all(
        (
            comparison["red_pixel_ratio_drop_from_warning"]
            >= thresholds["red_pixel_ratio_drop_from_warning_min"],
            comparison["pink_border_run_ratio_drop_from_warning"]
            >= thresholds["pink_border_run_ratio_drop_from_warning_min"],
            comparison["pale_fill_ratio_drop_from_warning"]
            >= thresholds["pale_fill_ratio_drop_from_warning_min"],
            comparison["red_pixel_ratio_above_baseline"]
            <= thresholds["red_pixel_ratio_above_baseline_max"],
            after_metrics["pink_border_max_contiguous_run_ratio"]
            <= thresholds["pink_border_run_ratio_after_enter_max"],
            after_metrics["pale_warning_fill_ratio"]
            <= thresholds["pale_fill_ratio_after_enter_max"],
            comparison["pink_border_run_ratio_above_baseline"]
            <= thresholds["pink_border_run_ratio_above_baseline_max"],
            comparison["pale_fill_ratio_above_baseline"]
            <= thresholds["pale_fill_ratio_above_baseline_max"],
        )
    )
    return {
        "method": INLINE_WARNING_VISUAL_METHOD,
        "disappeared_after_enter": disappeared,
        "ocr_used": False,
        "visual_text_match_claimed": False,
        "thresholds": dict(thresholds),
        "comparison": comparison,
        "after_enter_analysis": after_enter,
    }


def redacted_value(value: str) -> dict[str, Any]:
    raw = value or ""
    return {
        "sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
        "length": len(raw),
    }


def redacted_list(values: list[str]) -> list[dict[str, Any]]:
    return [redacted_value(value) for value in values]


@dataclass(frozen=True)
class ClipboardSnapshot:
    status: str
    text: str | None = None
    error: str | None = None
    formats: tuple[int, ...] = ()
    unsupported_formats: tuple[int, ...] = ()


SUPPORTED_CLIPBOARD_TEXT_FORMATS = frozenset({1, 7, 13, 16})


def clipboard_snapshot_is_supported(snapshot: ClipboardSnapshot) -> bool:
    unsupported = set(snapshot.unsupported_formats) | (
        set(snapshot.formats) - SUPPORTED_CLIPBOARD_TEXT_FORMATS
    )
    return snapshot.status in {"TEXT", "EMPTY"} and not unsupported


def capture_clipboard_snapshot() -> ClipboardSnapshot:
    try:
        win32clipboard.OpenClipboard()
    except Exception as exc:
        return ClipboardSnapshot(
            status="READ_FAILED",
            error=f"{exc.__class__.__name__}: {exc}",
        )
    status = "EMPTY"
    text: str | None = None
    error: str | None = None
    formats: list[int] = []
    unsupported_formats: list[int] = []
    try:
        current_format = 0
        while True:
            current_format = int(win32clipboard.EnumClipboardFormats(current_format))
            if current_format == 0:
                break
            formats.append(current_format)
        unsupported_formats = sorted(
            set(formats) - SUPPORTED_CLIPBOARD_TEXT_FORMATS
        )
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            text = str(win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT))
            status = (
                "UNSUPPORTED_FORMATS"
                if unsupported_formats
                else ("TEXT" if text else "EMPTY")
            )
        elif formats:
            status = "NON_TEXT"
    except Exception as exc:
        status = "READ_FAILED"
        error = f"{exc.__class__.__name__}: {exc}"
    try:
        win32clipboard.CloseClipboard()
    except Exception as exc:
        status = "READ_FAILED"
        close_error = f"{exc.__class__.__name__}: {exc}"
        error = f"{error}; close={close_error}" if error else close_error
    return ClipboardSnapshot(
        status=status,
        text=text,
        error=error,
        formats=tuple(formats),
        unsupported_formats=tuple(unsupported_formats),
    )


def clipboard_snapshot_matches_baseline(
    expected: ClipboardSnapshot,
    actual: ClipboardSnapshot,
) -> bool:
    if not clipboard_snapshot_is_supported(expected):
        return False
    if not clipboard_snapshot_is_supported(actual):
        return False
    if expected.status == "TEXT":
        return actual.status == "TEXT" and actual.text == expected.text
    if expected.status == "EMPTY":
        return actual.status == "EMPTY"
    return False


def set_clipboard_text(text: str) -> None:
    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32clipboard.CF_UNICODETEXT, text)
    finally:
        win32clipboard.CloseClipboard()


def clear_clipboard() -> None:
    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
    finally:
        win32clipboard.CloseClipboard()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_artifact_hashes(output_root: Path) -> None:
    hash_lines: list[str] = []
    for path in sorted(output_root.rglob("*")):
        if path.is_file() and path.name != "artifact_hashes.sha256":
            hash_lines.append(f"{sha256_file(path)}  {path.relative_to(output_root).as_posix()}")
    (output_root / "artifact_hashes.sha256").write_text(
        "\n".join(hash_lines) + "\n",
        encoding="utf-8",
    )


def inventory_root_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path.relative_to(root) for path in root.rglob("*") if path.is_file())


def redacted_relative_path_refs(paths: list[Path]) -> list[dict[str, Any]]:
    return [redacted_value(path.as_posix()) for path in paths]


def path_has_reparse_point(path: Path) -> bool:
    current = path.absolute()
    while True:
        if current.exists() or current.is_symlink():
            try:
                metadata = os.lstat(current)
            except OSError:
                return True
            attributes = int(getattr(metadata, "st_file_attributes", 0))
            if current.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def roots_are_distinct_and_non_overlapping(first: Path, second: Path) -> bool:
    first_resolved = first.resolve()
    second_resolved = second.resolve()
    return not (
        first_resolved == second_resolved
        or first_resolved.is_relative_to(second_resolved)
        or second_resolved.is_relative_to(first_resolved)
    )


def isolated_roots_are_clean_and_safe(
    output_files: list[Path],
    data_files: list[Path],
    *,
    roots_distinct_and_non_overlapping: bool,
    output_root_has_reparse_point: bool,
    data_root_has_reparse_point: bool,
) -> bool:
    return (
        not output_files
        and not data_files
        and roots_distinct_and_non_overlapping
        and not output_root_has_reparse_point
        and not data_root_has_reparse_point
    )


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
        self.requested_output_root = args.output_root.absolute()
        self.requested_data_root = args.data_root.absolute()
        self.roots_distinct_and_non_overlapping = roots_are_distinct_and_non_overlapping(
            self.requested_output_root,
            self.requested_data_root,
        )
        self.output_root_has_reparse_point = path_has_reparse_point(
            self.requested_output_root
        )
        self.data_root_has_reparse_point = path_has_reparse_point(self.requested_data_root)
        self.output_root = args.output_root.resolve()
        self.screenshots_dir = self.output_root / "screenshots"
        self.data_root = args.data_root.resolve()
        self.initial_output_files = inventory_root_files(self.output_root)
        self.initial_data_files = inventory_root_files(self.data_root)
        self.initial_output_file_count = len(self.initial_output_files)
        self.initial_data_file_count = len(self.initial_data_files)
        self.clean_start_ok = isolated_roots_are_clean_and_safe(
            self.initial_output_files,
            self.initial_data_files,
            roots_distinct_and_non_overlapping=self.roots_distinct_and_non_overlapping,
            output_root_has_reparse_point=self.output_root_has_reparse_point,
            data_root_has_reparse_point=self.data_root_has_reparse_point,
        )
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.initial_event_row_count = len(read_event_rows(self.data_root))
        self.source_snapshot_bytes = {
            "driver_source_snapshot.py": Path(__file__).read_bytes(),
            "capture_helper_source_snapshot.py": (
                TOOLS / "manual_real_ui_walkthrough_capture.py"
            ).read_bytes(),
        }
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
            "initial_event_row_count": self.initial_event_row_count,
            "initial_output_file_count": self.initial_output_file_count,
            "initial_data_file_count": self.initial_data_file_count,
            "clean_start": {
                "status": "PASS" if self.clean_start_ok else "FAIL",
                "isolated_output_root_file_count": self.initial_output_file_count,
                "isolated_output_root_file_refs": redacted_relative_path_refs(
                    self.initial_output_files
                ),
                "isolated_data_root_file_count": self.initial_data_file_count,
                "isolated_data_root_file_refs": redacted_relative_path_refs(
                    self.initial_data_files
                ),
                "roots_distinct_and_non_overlapping": self.roots_distinct_and_non_overlapping,
                "output_root_has_reparse_point": self.output_root_has_reparse_point,
                "data_root_has_reparse_point": self.data_root_has_reparse_point,
                "allowed_preexisting_files": [],
                "worker_registry_preseed": (
                    "generated_in_package_config_after_clean_start_check"
                    if args.preseed_worker
                    else "disabled"
                ),
            },
            "source_snapshot_sha256": {
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in self.source_snapshot_bytes.items()
            },
        }
        self.original_clipboard = capture_clipboard_snapshot()
        self.clipboard_mutated = False
        self.report["clipboard_initial_status"] = self.original_clipboard.status
        self.report["clipboard_initial_formats"] = list(
            self.original_clipboard.formats
        )
        self.report["clipboard_initial_unsupported_formats"] = list(
            self.original_clipboard.unsupported_formats
        )
        if self.original_clipboard.error:
            self.report["clipboard_initial_error"] = self.original_clipboard.error
        self.process: subprocess.Popen | None = None
        self.hwnd: int | None = None
        self.app = None

    def _save_report(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        (self.output_root / "real_ui_no_human_walkthrough_report.json").write_text(
            json.dumps(self.report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _finalize_evidence(self) -> None:
        clipboard_preflight_supported = clipboard_snapshot_is_supported(
            self.original_clipboard
        )
        clipboard_restored = not self.clipboard_mutated
        scan_value_removed = not self.clipboard_mutated
        snapshot = self.original_clipboard
        if self.clipboard_mutated and clipboard_snapshot_is_supported(snapshot):
            try:
                if snapshot.status == "TEXT":
                    set_clipboard_text(snapshot.text or "")
                else:
                    clear_clipboard()
            except Exception as exc:
                self.report["clipboard_restore_error"] = f"{exc.__class__.__name__}: {exc}"
            else:
                readback = capture_clipboard_snapshot()
                self.report["clipboard_restore_readback_status"] = readback.status
                self.report["clipboard_restore_readback_formats"] = list(
                    readback.formats
                )
                self.report["clipboard_restore_readback_unsupported_formats"] = list(
                    readback.unsupported_formats
                )
                if clipboard_snapshot_matches_baseline(snapshot, readback):
                    self.report["clipboard_restore_status"] = "PASS_VERIFIED"
                    clipboard_restored = True
                    scan_value_removed = True
        elif not self.clipboard_mutated:
            self.report["clipboard_restore_status"] = "NOT_MUTATED"

        if self.clipboard_mutated and not clipboard_restored:
            try:
                clear_clipboard()
            except Exception as clear_exc:
                self.report["clipboard_restore_status"] = "FAILED_UNSAFE"
                self.report["clipboard_clear_error"] = (
                    f"{clear_exc.__class__.__name__}: {clear_exc}"
                )
            else:
                cleared = capture_clipboard_snapshot()
                self.report["clipboard_clear_readback_status"] = cleared.status
                self.report["clipboard_clear_readback_formats"] = list(
                    cleared.formats
                )
                self.report["clipboard_clear_readback_unsupported_formats"] = list(
                    cleared.unsupported_formats
                )
                if cleared.status == "EMPTY" and clipboard_snapshot_is_supported(
                    cleared
                ):
                    self.report["clipboard_restore_status"] = "FAILED_CLEARED_SAFE"
                    scan_value_removed = True
                else:
                    self.report["clipboard_restore_status"] = "FAILED_UNSAFE"

        if self.clipboard_mutated and clipboard_restored:
            scan_value_removed = True
        if not self.clipboard_mutated and not clipboard_snapshot_is_supported(
            snapshot
        ):
            self.report["clipboard_restore_status"] = "NOT_MUTATED_UNSUPPORTED_BASELINE"

        pass_checks = self.report.setdefault("pass_checks", {})
        pass_checks["clipboard_preflight_supported"] = clipboard_preflight_supported
        pass_checks["clipboard_restore"] = clipboard_restored
        pass_checks["clipboard_scan_value_removed"] = scan_value_removed
        if not all(
            (
                clipboard_preflight_supported,
                clipboard_restored,
                scan_value_removed,
            )
        ):
            self.report["status"] = "FAIL"
        self._save_report()
        for name, payload in self.source_snapshot_bytes.items():
            (self.output_root / name).write_bytes(payload)
        write_artifact_hashes(self.output_root)

    def _stop_process(self) -> None:
        if self.args.keep_running or self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def _finish_run(self) -> None:
        try:
            self._stop_process()
        except Exception as exc:
            self.report["status"] = "FAIL"
            self.report["teardown_error"] = f"{exc.__class__.__name__}: {exc}"
        try:
            self._finalize_evidence()
        except Exception as exc:
            self.report["status"] = "FAIL"
            self.report["finalization_error"] = f"{exc.__class__.__name__}: {exc}"
            try:
                self._save_report()
            except Exception:
                pass

    def _validate_preconditions(self) -> None:
        if getattr(getattr(self, "args", None), "allow_title_match_any_pid", False):
            raise RuntimeError(
                "--allow-title-match-any-pid is unsafe for authoritative evidence"
            )
        if not self.clean_start_ok:
            raise RuntimeError(
                "isolated output/data roots must contain no files before evidence capture"
            )
        if not clipboard_snapshot_is_supported(self.original_clipboard):
            raise RuntimeError(
                "clipboard baseline cannot be preserved exactly; refusing to send scanner input"
            )

    def _set_clipboard_for_input(self, value: str) -> None:
        self.clipboard_mutated = True
        set_clipboard_text(value)

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
                window = self.find_process_window(
                    title_pattern=self.args.window_title_pattern,
                    timeout=0.2,
                )
                if window is not None:
                    self.hwnd = int(window["hwnd"])
                    self.verify_process_window(self.hwnd)
                    move_window_to_geometry(self.hwnd, self.args.geometry)
                    time.sleep(0.3)
                    self.step("launch_window_found", "PASS", window=window)
                    return
                if getattr(self, "last_process_window_selection_error", None):
                    last_error = json.dumps(
                        self.last_process_window_selection_error,
                        ensure_ascii=False,
                    )
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
            raise RuntimeError("target hwnd is not available")
        self.verify_process_window(self.hwnd)
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
            raise RuntimeError("target hwnd is not available")
        self.verify_process_window(self.hwnd)
        try:
            win32gui.ShowWindow(self.hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(self.hwnd)
        except Exception:
            # A real mouse click below is still enough to focus Tk controls on most desktops.
            pass
        time.sleep(0.15)

    def verify_process_window(self, hwnd: int) -> None:
        if self.process is None:
            raise RuntimeError("target process is not available")
        try:
            _, window_pid = win32process.GetWindowThreadProcessId(int(hwnd))
        except Exception as exc:
            raise RuntimeError(f"cannot verify target window process: {exc}") from exc
        if int(window_pid) != int(self.process.pid):
            raise RuntimeError(
                "refusing target window from a different process; "
                f"expected_pid={self.process.pid} actual_pid={window_pid}"
            )

    def ensure_window_foreground(self, hwnd: int) -> None:
        self.verify_process_window(hwnd)
        if win32gui.GetForegroundWindow() != int(hwnd):
            try:
                win32gui.ShowWindow(int(hwnd), win32con.SW_RESTORE)
                win32gui.SetForegroundWindow(int(hwnd))
            except Exception:
                pass
            time.sleep(0.15)
        foreground = int(win32gui.GetForegroundWindow())
        if foreground == int(hwnd):
            return
        try:
            _, actual_pid = win32process.GetWindowThreadProcessId(foreground)
        except Exception as exc:
            raise RuntimeError(f"cannot verify foreground target: {exc}") from exc
        title = win32gui.GetWindowText(foreground) or ""
        raise RuntimeError(
            "refusing raw key input because the exact target hwnd is not foreground; "
            f"expected_hwnd={int(hwnd)} foreground_hwnd={foreground} "
            f"foreground_pid={actual_pid} foreground_title={title!r}"
        )

    def ensure_target_foreground(self) -> None:
        if self.hwnd is None:
            raise RuntimeError("target hwnd is not available")
        self.ensure_window_foreground(self.hwnd)

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
        self._set_clipboard_for_input(text)
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
            raise RuntimeError("target hwnd is not available")
        self.verify_process_window(self.hwnd)
        move_window_to_geometry(self.hwnd, self.args.geometry)
        path = self.screenshots_dir / f"{len(self.report['screenshots']) + 1:02d}_{label}.png"
        capture = capture_window(self.hwnd, path)
        capture["label"] = label
        annotate_requested_capture_size(capture, self.args.geometry)
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
        self.last_process_window_selection_error = None
        deadline = time.time() + timeout
        title_re = re.compile(title_pattern, re.IGNORECASE) if title_pattern else None
        main_re = re.compile(self.args.window_title_pattern, re.IGNORECASE)
        while time.time() < deadline:
            candidates = []
            for window in self.process_windows():
                title = window.get("title", "")
                if title_re and not title_re.search(title):
                    continue
                if exclude_main:
                    if self.hwnd is not None and int(window["hwnd"]) == int(self.hwnd):
                        continue
                    if self.hwnd is None and main_re.search(title):
                        continue
                left, top, right, bottom = window["rect"]
                area = max(0, right - left) * max(0, bottom - top)
                candidates.append((area, window))
            if candidates:
                candidates.sort(key=lambda item: item[0], reverse=True)
                if len(candidates) == 1:
                    self.last_process_window_selection_error = None
                    return candidates[0][1]
                self.last_process_window_selection_error = {
                    "reason": "ambiguous_matching_windows",
                    "candidate_count": len(candidates),
                    "candidate_hwnds": sorted(
                        int(item[1]["hwnd"]) for item in candidates
                    ),
                    "title_pattern": title_pattern,
                    "exclude_main": exclude_main,
                }
            time.sleep(0.1)
        return None

    def capture_hwnd(self, hwnd: int, label: str) -> None:
        self.verify_process_window(hwnd)
        path = self.screenshots_dir / f"{len(self.report['screenshots']) + 1:02d}_{label}.png"
        capture = capture_window(hwnd, path)
        capture["label"] = label
        capture["hwnd"] = int(hwnd)
        capture["screenshot_role"] = "dialog_or_child"
        capture["requested_size_gate_applicable"] = False
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
            self.step(
                f"{label}_window_found",
                "FAIL",
                title_pattern=title_pattern,
                selection_error=getattr(
                    self,
                    "last_process_window_selection_error",
                    None,
                ),
            )
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
            self.step(
                "process_window_click",
                "FAIL",
                title_pattern=title_pattern,
                selection_error=getattr(
                    self,
                    "last_process_window_selection_error",
                    None,
                ),
            )
            return False
        hwnd = int(window["hwnd"])
        self.verify_process_window(hwnd)
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
        window = self.find_process_window(
            title_pattern=title_pattern,
            exclude_main=True,
            timeout=timeout,
        )
        if window is None:
            self.step(
                "process_window_text_target_found",
                "FAIL",
                title_pattern=title_pattern,
                selection_error=getattr(
                    self,
                    "last_process_window_selection_error",
                    None,
                ),
            )
            return False
        hwnd = int(window["hwnd"])
        self.verify_process_window(hwnd)
        self.move_child_window_near_main(hwnd)
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        self.click_in_rect(left, top, right, bottom, x_ratio, y_ratio)
        self.ensure_window_foreground(hwnd)
        self._set_clipboard_for_input(value)
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        self.keyboard.send_keys("^v")
        time.sleep(0.1)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)
        return True

    def main_window_texts(self) -> list[str]:
        wrapper = self.main_window_wrapper()
        if wrapper is None:
            return []
        controls = [wrapper]
        try:
            controls.extend(wrapper.descendants())
        except Exception:
            pass
        texts: list[str] = []
        for control in controls:
            try:
                text = (control.window_text() or "").strip()
            except Exception:
                continue
            if text and text not in texts:
                texts.append(text)
        return texts

    def capture_by_label(self, label: str) -> tuple[int, dict[str, Any]] | None:
        for index in range(len(self.report["screenshots"]) - 1, -1, -1):
            capture = self.report["screenshots"][index]
            if capture.get("screenshot_role") == "main" and capture.get("label") == label:
                return index, capture
        return None

    def analyze_capture_inline_warning_visual(
        self,
        capture: dict[str, Any],
    ) -> dict[str, Any]:
        with Image.open(Path(capture["path"])) as image:
            return analyze_inline_warning_visual(image)

    def prove_inline_warning_visual(self, warning_capture_label: str) -> dict[str, Any]:
        matched = self.capture_by_label(warning_capture_label)
        if matched is None:
            return {
                "method": INLINE_WARNING_VISUAL_METHOD,
                "signal_detected": False,
                "available": False,
                "reason": "warning_capture_not_found",
                "warning_capture_label": warning_capture_label,
                "ocr_used": False,
                "visual_text_match_claimed": False,
            }
        warning_index, warning_capture = matched
        baseline_capture = next(
            (
                capture
                for capture in reversed(self.report["screenshots"][:warning_index])
                if capture.get("screenshot_role") == "main"
            ),
            None,
        )
        if baseline_capture is None:
            return {
                "method": INLINE_WARNING_VISUAL_METHOD,
                "signal_detected": False,
                "available": False,
                "reason": "baseline_capture_not_found",
                "warning_capture_label": warning_capture_label,
                "ocr_used": False,
                "visual_text_match_claimed": False,
            }
        try:
            baseline_analysis = self.analyze_capture_inline_warning_visual(
                baseline_capture
            )
            warning_analysis = self.analyze_capture_inline_warning_visual(
                warning_capture
            )
        except (OSError, KeyError, ValueError) as exc:
            return {
                "method": INLINE_WARNING_VISUAL_METHOD,
                "signal_detected": False,
                "available": False,
                "reason": f"capture_analysis_failed:{exc.__class__.__name__}",
                "warning_capture_label": warning_capture_label,
                "ocr_used": False,
                "visual_text_match_claimed": False,
            }
        proof = evaluate_inline_warning_visual_signal(
            baseline_analysis,
            warning_analysis,
        )
        proof.update(
            {
                "available": True,
                "baseline_capture_label": baseline_capture.get("label"),
                "warning_capture_label": warning_capture_label,
            }
        )
        return proof

    def prove_inline_warning(
        self,
        required_fragments: list[str],
        *,
        visual_screenshot_label: str | None = None,
    ) -> dict[str, Any]:
        texts = self.main_window_texts()
        matched_fragments = [
            fragment
            for fragment in required_fragments
            if any(fragment in text for text in texts)
        ]
        all_fragments_matched = bool(required_fragments) and len(
            matched_fragments
        ) == len(required_fragments)
        visual_proof = (
            self.prove_inline_warning_visual(visual_screenshot_label)
            if visual_screenshot_label
            else {
                "method": INLINE_WARNING_VISUAL_METHOD,
                "signal_detected": False,
                "available": False,
                "reason": "visual_screenshot_label_not_requested",
                "ocr_used": False,
                "visual_text_match_claimed": False,
            }
        )
        visual_signal_detected = visual_proof.get("signal_detected") is True
        if all_fragments_matched:
            presence_proof_method = "pywinauto_accessibility_text"
        elif visual_signal_detected:
            presence_proof_method = INLINE_WARNING_VISUAL_METHOD
        else:
            presence_proof_method = "none"
        human_text_review_required = (
            visual_signal_detected and not all_fragments_matched
        )
        wording_verification = {
            "automated_accessibility_text_verified": all_fragments_matched,
            "visual_signal_proves_wording": False,
            "human_text_review_required": human_text_review_required,
            "human_text_review_status": (
                "REQUIRED_EXTERNAL_CANDIDATE_AUDIT_ATTESTATION"
                if human_text_review_required
                else (
                    "NOT_REQUIRED_ACCESSIBILITY_TEXT_VERIFIED"
                    if all_fragments_matched
                    else "UNAVAILABLE_NO_INLINE_PRESENCE_PROOF"
                )
            ),
            "external_attestation_artifact": "candidate_identity_and_audit.json",
            "required_fragments": required_fragments,
        }
        return {
            "required_fragments": required_fragments,
            "matched_fragments": matched_fragments,
            "all_fragments_matched": all_fragments_matched,
            "accessibility_text_proof_available": all_fragments_matched,
            "inline_presence_proved": all_fragments_matched or visual_signal_detected,
            "presence_proof_method": presence_proof_method,
            "visual_signal_detected": visual_signal_detected,
            "visual_fallback": visual_proof,
            "wording_verification": wording_verification,
            "ocr_used": False,
            "visual_text_match_claimed": False,
            "main_window_hwnd": self.hwnd,
        }

    def capture_warning(
        self,
        label: str,
        title_pattern: str | None = None,
        *,
        require_inline: bool = False,
        inline_text_fragments: list[str] | None = None,
        inline_disappearance_fragments: list[str] | None = None,
        inline_visual_screenshot_label: str | None = None,
    ) -> bool:
        if require_inline:
            self.pending_inline_warning_fragments = []
            self.pending_inline_warning_visual_proof = None
        warning = self.find_process_window(title_pattern=title_pattern, exclude_main=True, timeout=5.0)
        if warning is None:
            selection_error = getattr(
                self,
                "last_process_window_selection_error",
                None,
            )
            if selection_error is not None:
                self.step(
                    f"{label}_warning_window_found",
                    "FAIL",
                    presentation="ambiguous_toplevel_candidates",
                    selection_error=selection_error,
                )
                return False
            if require_inline:
                proof = self.prove_inline_warning(
                    inline_text_fragments or [],
                    visual_screenshot_label=inline_visual_screenshot_label,
                )
                proved = proof["inline_presence_proved"] is True
                self.step(
                    f"{label}_warning_window_found",
                    "PASS" if proved else "FAIL",
                    presentation="inline" if proved else "inline_not_proven",
                    **proof,
                )
                self.pending_inline_warning_fragments = (
                    list(inline_disappearance_fragments or inline_text_fragments or [])
                    if proof["all_fragments_matched"] is True
                    else []
                )
                self.pending_inline_warning_visual_proof = (
                    proof["visual_fallback"]
                    if proof["visual_signal_detected"] is True
                    else None
                )
                return proved
            self.step(
                f"{label}_warning_window_found",
                "FAIL",
                presentation="missing",
            )
            return False
        if require_inline:
            self.capture_hwnd(int(warning["hwnd"]), f"{label}_unexpected_toplevel")
            self.step(
                f"{label}_warning_window_found",
                "FAIL",
                presentation="toplevel",
                title=warning.get("title", ""),
            )
            return False
        self.capture_hwnd(int(warning["hwnd"]), label)
        self.step(
            f"{label}_warning_window_found",
            "PASS",
            presentation="toplevel",
            title=warning.get("title", ""),
        )
        return True

    def dismiss_warning(self, *, post_inline_capture_label: str | None = None) -> None:
        warning = self.find_process_window(exclude_main=True, timeout=2.0)
        if warning is None and getattr(
            self,
            "last_process_window_selection_error",
            None,
        ) is not None:
            self.step(
                "warning_dismissed",
                "FAIL",
                method="refused_ambiguous_toplevel_candidates",
                selection_error=self.last_process_window_selection_error,
            )
            return
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
            self.ensure_window_foreground(hwnd)
            self.keyboard.send_keys("{SPACE}")
            time.sleep(0.3)
            still_open_after_key = self.find_process_window(title_pattern=re.escape(title), exclude_main=True, timeout=0.5)
            selection_error = getattr(
                self,
                "last_process_window_selection_error",
                None,
            )
            if still_open_after_key is None and selection_error is None:
                self.step(
                    "warning_dismissed",
                    "PASS",
                    title=title,
                    clicked_by_text=False,
                    dismissed_by_key=True,
                    still_open=False,
                )
                return
            if selection_error is not None:
                self.step(
                    "warning_dismissed",
                    "FAIL",
                    method="refused_ambiguous_toplevel_candidates_after_key",
                    selection_error=selection_error,
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
            selection_error = getattr(
                self,
                "last_process_window_selection_error",
                None,
            )
            self.step(
                "warning_dismissed",
                "PASS"
                if still_open is None and selection_error is None
                else "FAIL",
                title=title,
                clicked_by_text=clicked,
                still_open=still_open is not None,
                selection_error=selection_error,
            )
            return
        self.press_enter()
        time.sleep(0.5)
        if post_inline_capture_label:
            self.capture(post_inline_capture_label)
        required_fragments = list(
            getattr(self, "pending_inline_warning_fragments", []) or []
        )
        remaining_fragments = [
            fragment
            for fragment in required_fragments
            if any(fragment in text for text in self.main_window_texts())
        ]
        text_warning_disappeared = (
            not remaining_fragments if required_fragments else None
        )
        pending_visual_proof = getattr(
            self,
            "pending_inline_warning_visual_proof",
            None,
        )
        visual_disappearance_proof = None
        visual_warning_disappeared = None
        if pending_visual_proof is not None and post_inline_capture_label:
            post_capture = self.capture_by_label(post_inline_capture_label)
            if post_capture is not None:
                try:
                    after_enter_analysis = self.analyze_capture_inline_warning_visual(
                        post_capture[1]
                    )
                    visual_disappearance_proof = (
                        evaluate_inline_warning_visual_disappearance(
                            pending_visual_proof,
                            after_enter_analysis,
                        )
                    )
                    visual_warning_disappeared = (
                        visual_disappearance_proof["disappeared_after_enter"] is True
                    )
                except (OSError, KeyError, ValueError) as exc:
                    visual_disappearance_proof = {
                        "method": INLINE_WARNING_VISUAL_METHOD,
                        "disappeared_after_enter": False,
                        "reason": f"capture_analysis_failed:{exc.__class__.__name__}",
                        "ocr_used": False,
                        "visual_text_match_claimed": False,
                    }
                    visual_warning_disappeared = False
        required_results = [
            result
            for result in (text_warning_disappeared, visual_warning_disappeared)
            if result is not None
        ]
        warning_disappeared = bool(required_results) and all(required_results)
        self.step(
            "warning_dismissed",
            "PASS" if warning_disappeared else "FAIL",
            method="inline_enter_without_follow_up_click",
            follow_up_click=False,
            inline_presence_signal_disappeared=warning_disappeared,
            accessibility_text_warning_disappeared=text_warning_disappeared,
            visual_presence_signal_disappeared=visual_warning_disappeared,
            visual_disappearance_proof=visual_disappearance_proof,
            remaining_inline_fragments=remaining_fragments,
        )
        self.pending_inline_warning_fragments = []
        self.pending_inline_warning_visual_proof = None

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
        self.ensure_target_foreground()
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        self._set_clipboard_for_input(self.args.worker)
        self.keyboard.send_keys("^v")
        time.sleep(0.3)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(0.8)
        self.handle_possible_login_dialogs()
        if not self.wait_for_event_rows(initial_event_count + 1, timeout=2.0):
            start_button = self.login_start_button()
            if start_button is not None:
                start_button.click_input()
                self.step("login_start_button_child_fallback", "PASS")
            else:
                clicked_by_text = self.click_button_by_text(
                    ["작업", "시작"], timeout=2.0
                )
                if clicked_by_text:
                    self.step("login_start_button_clicked", "PASS")
                else:
                    self.click_rel(0.57, 0.82)
                    self.step("login_start_button_coordinate_fallback", "REVIEW")
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
        remaining_after_text = self.find_process_window(
            title_pattern=title_pattern,
            exclude_main=True,
            timeout=0.4,
        )
        selection_error = getattr(
            self,
            "last_process_window_selection_error",
            None,
        )
        if remaining_after_text is None and selection_error is None:
            self.step("dialog_yes_clicked", "PASS", title_pattern=title_pattern, method="button_text")
            return True
        if selection_error is not None:
            self.step(
                "dialog_yes_clicked",
                "FAIL",
                title_pattern=title_pattern,
                method="refused_ambiguous_toplevel_candidates_after_text_click",
                selection_error=selection_error,
            )
            return False
        clicked_by_position = self.click_process_window(
            title_pattern,
            x_ratio,
            y_ratio,
            timeout=1.0,
            move_near_main=False,
        )
        if clicked_by_position:
            time.sleep(0.3)
        remaining_after_position = self.find_process_window(
            title_pattern=title_pattern,
            exclude_main=True,
            timeout=0.5,
        )
        selection_error = getattr(
            self,
            "last_process_window_selection_error",
            None,
        )
        if remaining_after_position is None and selection_error is None:
            self.step(
                "dialog_yes_clicked",
                "PASS",
                title_pattern=title_pattern,
                method="position",
                clicked_by_title=clicked_by_title,
            )
            return True
        if selection_error is not None:
            self.step(
                "dialog_yes_clicked",
                "FAIL",
                title_pattern=title_pattern,
                method="refused_ambiguous_toplevel_candidates_after_position_click",
                selection_error=selection_error,
            )
            return False
        remaining_dialog = self.find_process_window(
            title_pattern=title_pattern,
            exclude_main=True,
            timeout=0.2,
        )
        if remaining_dialog is None:
            self.step(
                "dialog_yes_clicked",
                "FAIL",
                title_pattern=title_pattern,
                method="enter_key_target_missing_or_ambiguous",
            )
            return False
        self.ensure_window_foreground(int(remaining_dialog["hwnd"]))
        self.keyboard.send_keys("{ENTER}")
        time.sleep(0.5)
        final_window = self.find_process_window(
            title_pattern=title_pattern,
            exclude_main=True,
            timeout=0.5,
        )
        selection_error = getattr(
            self,
            "last_process_window_selection_error",
            None,
        )
        closed = final_window is None and selection_error is None
        self.step(
            "dialog_yes_clicked",
            "PASS" if closed else "FAIL",
            title_pattern=title_pattern,
            method="enter_key",
            clicked_by_title=clicked_by_title,
            clicked_by_position=clicked_by_position,
            selection_error=selection_error,
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

    def scan(
        self,
        value: str,
        step_name: str,
        capture_name: str,
        wait_after: float = 1.0,
        *,
        focus_entry: bool = True,
        expected_event: str | None = None,
    ) -> None:
        event_count_before = self.event_count(expected_event) if expected_event else None
        if focus_entry:
            self.click_main_scan_entry()
        time.sleep(0.1)
        self._set_clipboard_for_input(value)
        self.ensure_target_foreground()
        self.keyboard.send_keys("^a")
        time.sleep(0.1)
        self.keyboard.send_keys("^v")
        time.sleep(0.1)
        self.keyboard.send_keys("{ENTER}")
        time.sleep(self.args.action_delay)
        time.sleep(wait_after)
        self.capture(capture_name)
        event_count_after = self.event_count(expected_event) if expected_event else None
        event_increment = (
            event_count_after - event_count_before
            if event_count_before is not None and event_count_after is not None
            else None
        )
        self.step(
            step_name,
            "PASS" if event_increment is None or event_increment >= 1 else "FAIL",
            input_ref=redacted_value(value),
            focus_entry_clicked=focus_entry,
            expected_event=expected_event,
            event_count_before=event_count_before,
            event_count_after=event_count_after,
            event_increment=event_increment,
        )

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
        self.scan(
            self.args.master_label,
            "master_label_sent",
            "master_label_loaded",
            wait_after=1.2,
            expected_event="MASTER_LABEL_SCANNED_NEW",
        )
        # Leave the production duplicate/debounce window before resending the same code.
        self.scan(
            self.args.product_barcode[0],
            "product_1_sent",
            "product_scan_1",
            wait_after=2.0,
            expected_event="SCAN_OK",
        )
        self.scan(
            self.args.product_barcode[0],
            "duplicate_product_sent",
            "duplicate_product_warning",
            wait_after=0.8,
            expected_event="SCAN_FAIL_DUPLICATE",
        )
        self.capture_warning(
            "duplicate_product_warning_toplevel",
            require_inline=True,
            inline_text_fragments=["바코드 중복", "이미 스캔되었습니다", "확인"],
            inline_disappearance_fragments=["바코드 중복", "이미 스캔되었습니다"],
            inline_visual_screenshot_label="duplicate_product_warning",
        )
        self.dismiss_warning(post_inline_capture_label="duplicate_warning_dismissed")
        for index, barcode in enumerate(self.args.product_barcode[1:], start=2):
            self.scan(
                barcode,
                f"product_{index}_sent",
                f"product_scan_{index}",
                wait_after=1.3,
                focus_entry=index != 2,
                expected_event="SCAN_OK",
            )

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

    def exchange_scan_entry(self, hwnd: int):
        if self.app is None:
            return None
        dialog = self.app.window(handle=hwnd)
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
            exchange_window = self.find_process_window(
                title_pattern=r"개별 제품 교환",
                exclude_main=True,
                timeout=1.0,
            )
            if exchange_window is None:
                raise RuntimeError(
                    "exchange input window is missing or ambiguous; refusing raw key input"
                )
            exchange_hwnd = int(exchange_window["hwnd"])
            entry = self.exchange_scan_entry(exchange_hwnd)
            if entry is not None:
                entry.click_input()
                self.ensure_window_foreground(exchange_hwnd)
                self._set_clipboard_for_input(value)
                self.keyboard.send_keys("^a")
                self.keyboard.send_keys("^v")
                self.keyboard.send_keys("{ENTER}")
            else:
                raise RuntimeError(
                    "exchange input control was not found on the verified dialog hwnd"
                )
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
            self._validate_preconditions()
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
        except Exception as exc:
            self.report["status"] = "FAIL"
            self.report["error"] = f"{exc.__class__.__name__}: {exc}"
            self._save_report()
        finally:
            self._finish_run()
        if self.report.get("status") == "PASS":
            return 0
        if any(key in self.report for key in ("error", "teardown_error", "finalization_error")):
            return 1
        return 2

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
        checks["initial_event_rows_zero"] = self.initial_event_row_count == 0
        checks["initial_output_files_zero"] = self.initial_output_file_count == 0
        checks["initial_data_files_zero"] = self.initial_data_file_count == 0
        checks["clean_start"] = self.clean_start_ok
        checks["screenshots_nonblank"] = all(not item.get("blank_suspected") for item in self.report["screenshots"])
        checks["screenshots_no_excess_black"] = all(
            not item.get("excess_black_suspected") for item in self.report["screenshots"]
        )
        checks["screenshots_no_contiguous_black_stripe"] = all(
            not item.get("edge_black_stripe_suspected")
            and not item.get("contiguous_black_stripe_suspected")
            for item in self.report["screenshots"]
        )
        checks["screenshots_no_uniform_low_variance_frame"] = all(
            not item.get("uniform_low_variance_suspected")
            for item in self.report["screenshots"]
        )
        checks["main_screenshots_match_requested_size"] = (
            main_screenshots_match_requested_size(self.report["screenshots"])
        )
        checks["raw_source_paths_redacted"] = summary.get("source_file_paths_redacted") is True
        checks["driver_steps_all_pass"] = bool(self.report["steps"]) and all(
            step.get("status") == "PASS" for step in self.report["steps"]
        )
        if self.args.scenario == "duplicate-warning" or self.args.do_duplicate_warning:
            exact_counts = {
                "WORK_START": 1,
                "MASTER_LABEL_SCANNED_NEW": 1,
                "SCAN_OK": len(self.args.product_barcode),
                "SCAN_FAIL_DUPLICATE": 1,
                "TRAY_COMPLETE": 1,
            }
            checks["duplicate_event_counts_exact"] = (
                summary["counts"] == exact_counts
                and summary["row_count"] == sum(exact_counts.values())
            )
            checks["duplicate_driver_steps_all_pass"] = checks[
                "driver_steps_all_pass"
            ]
            warning_presence_step = next(
                (
                    step
                    for step in self.report["steps"]
                    if step.get("name")
                    == "duplicate_product_warning_toplevel_warning_window_found"
                ),
                None,
            )
            wording_verification = (
                warning_presence_step.get("wording_verification", {})
                if warning_presence_step
                else {}
            )
            self.report["human_review_requirements"] = [
                {
                    "id": "duplicate_warning_wording",
                    "required": wording_verification.get(
                        "human_text_review_required"
                    )
                    is True,
                    "status": wording_verification.get(
                        "human_text_review_status",
                        "MISSING",
                    ),
                    "automated_accessibility_text_verified": (
                        wording_verification.get(
                            "automated_accessibility_text_verified"
                        )
                        is True
                    ),
                    "visual_signal_proves_wording": False,
                    "external_attestation_artifact": (
                        "candidate_identity_and_audit.json"
                    ),
                    "screenshot_label": "duplicate_product_warning",
                }
            ]
            self.report["automated_evidence_scope"] = {
                "status_covers": [
                    "driver_step_execution",
                    "event_and_capture_integrity",
                    "inline_warning_presence_and_transition",
                ],
                "warning_wording_included_in_status": (
                    wording_verification.get(
                        "automated_accessibility_text_verified"
                    )
                    is True
                ),
                "visual_signal_proves_warning_wording": False,
                "external_human_attestation_required": (
                    wording_verification.get("human_text_review_required")
                    is True
                ),
                "external_attestation_artifact": (
                    "candidate_identity_and_audit.json"
                ),
            }
            checks["duplicate_inline_presence_automated"] = any(
                step.get("name") == "duplicate_product_warning_toplevel_warning_window_found"
                and step.get("presentation") == "inline"
                and step.get("inline_presence_proved") is True
                and step.get("presence_proof_method")
                in {"pywinauto_accessibility_text", INLINE_WARNING_VISUAL_METHOD}
                and step.get("status") == "PASS"
                for step in self.report["steps"]
            )
            checks["duplicate_inline_presence_visual_signal"] = any(
                step.get("name") == "duplicate_product_warning_toplevel_warning_window_found"
                and step.get("visual_signal_detected") is True
                and step.get("visual_fallback", {}).get("signal_detected") is True
                and step.get("visual_fallback", {}).get("ocr_used") is False
                and step.get("visual_fallback", {}).get("visual_text_match_claimed")
                is False
                and step.get("status") == "PASS"
                for step in self.report["steps"]
            )
            checks["duplicate_inline_transition_no_follow_up_click"] = any(
                step.get("name") == "warning_dismissed"
                and step.get("method") == "inline_enter_without_follow_up_click"
                and step.get("follow_up_click") is False
                and step.get("inline_presence_signal_disappeared") is True
                and step.get("status") == "PASS"
                for step in self.report["steps"]
            )
            checks["duplicate_inline_visual_signal_disappeared_after_enter"] = any(
                step.get("name") == "warning_dismissed"
                and step.get("visual_presence_signal_disappeared") is True
                and step.get("visual_disappearance_proof", {}).get(
                    "disappeared_after_enter"
                )
                is True
                and step.get("visual_disappearance_proof", {}).get("ocr_used")
                is False
                and step.get("status") == "PASS"
                for step in self.report["steps"]
            )
            checks["duplicate_wording_review_disposition_recorded"] = bool(
                wording_verification
            ) and (
                wording_verification.get("automated_accessibility_text_verified")
                is True
                or (
                    wording_verification.get("human_text_review_required") is True
                    and wording_verification.get("human_text_review_status")
                    == "REQUIRED_EXTERNAL_CANDIDATE_AUDIT_ATTESTATION"
                    and wording_verification.get("visual_signal_proves_wording")
                    is False
                )
            )
            checks["product_2_accepted_without_focus_click"] = any(
                step.get("name") == "product_2_sent"
                and step.get("focus_entry_clicked") is False
                and step.get("expected_event") == "SCAN_OK"
                and step.get("event_increment", 0) >= 1
                and step.get("status") == "PASS"
                for step in self.report["steps"]
            )
            checks["duplicate_screenshots_exact_10"] = len(self.report["screenshots"]) == 10
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
    parser.add_argument(
        "--allow-title-match-any-pid",
        action="store_true",
        help="Deprecated unsafe option; authoritative evidence rejects it.",
    )
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
