from __future__ import annotations

import argparse

import pytest
from PIL import Image

from tools.capture_container_operator_ui import (
    DEFAULT_SCALE,
    DEFAULT_SIZES,
    DEFAULT_STATE_IDS,
    DisplayMonitor,
    MAX_SCALE,
    MIN_SCALE,
    analyze_image,
    apply_cross_capture_contracts,
    assert_descendant,
    build_monitor_capture_gate,
    build_isolated_app_settings,
    build_parser,
    build_state_fixtures,
    cluster_button_rows,
    evaluate_capture,
    evaluate_clipping_proxy,
    monitor_preflight_manifest,
    normalize_capture_scan_rows,
    parse_scale,
    parse_sizes,
    parse_states,
    rect_is_contained,
    resolve_monitor_target,
)


def test_default_matrix_has_four_required_sizes_and_six_required_states():
    assert DEFAULT_SIZES == (
        (1366, 768),
        (1440, 900),
        (1920, 1080),
        (2560, 1080),
    )
    assert DEFAULT_STATE_IDS == (
        "waiting",
        "normal",
        "duplicate",
        "operator_review",
        "completed",
        "recovered",
    )
    assert DEFAULT_SCALE == 1.0


def test_scale_parser_defaults_to_one_and_accepts_supported_boundaries():
    parser = build_parser()

    assert parser.parse_args([]).scale == 1.0
    assert parser.parse_args([]).monitor_device == ""
    assert parser.parse_args(["--scale", "1.4"]).scale == 1.4
    assert parser.parse_args(
        ["--monitor-device", r"\\.\DISPLAY2"]
    ).monitor_device == r"\\.\DISPLAY2"
    assert parse_scale(str(MIN_SCALE)) == MIN_SCALE
    assert parse_scale(str(MAX_SCALE)) == MAX_SCALE

    for value in ("0.69", "2.51", "nan", "inf", "large", True):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_scale(value)


def _display_monitors():
    return (
        DisplayMonitor(
            device_name=r"\\.\DISPLAY1",
            monitor_rect=(0, 0, 2560, 1440),
            work_rect=(0, 0, 2560, 1392),
            primary=True,
        ),
        DisplayMonitor(
            device_name=r"\\.\DISPLAY2",
            monitor_rect=(693, -1440, 3253, 0),
            work_rect=(693, -1440, 3253, -48),
            primary=False,
        ),
    )


def test_explicit_display2_preflight_centers_each_size_and_proves_non_primary():
    sizes = ((1440, 900), (2560, 1080))
    target = resolve_monitor_target(
        r"\\.\DISPLAY2",
        sizes,
        monitors=_display_monitors(),
    )
    manifest = monitor_preflight_manifest(target, sizes)

    assert target.tk_geometry((1440, 900)) == "1440x900+1253-1194"
    assert target.tk_geometry((2560, 1080)) == "2560x1080+693-1284"
    assert manifest["requested_device_name"] == r"\\.\DISPLAY2"
    assert manifest["resolved_monitor"]["primary"] is False
    assert manifest["resolved_monitor"]["work_rect"] == [693, -1440, 3253, -48]
    assert manifest["checks"] == {
        "requested_device_name_exact_match": True,
        "target_is_non_primary": True,
        "all_requested_geometries_contained_in_work_area": True,
    }
    assert manifest["passed"] is True


def test_explicit_monitor_preflight_rejects_primary_missing_and_oversized_targets():
    monitors = _display_monitors()

    with pytest.raises(RuntimeError, match="must be non-primary"):
        resolve_monitor_target(r"\\.\DISPLAY1", ((1440, 900),), monitors=monitors)
    with pytest.raises(RuntimeError, match="match exactly one"):
        resolve_monitor_target(r"\\.\DISPLAY9", ((1440, 900),), monitors=monitors)
    with pytest.raises(RuntimeError, match="does not fit"):
        resolve_monitor_target(r"\\.\DISPLAY2", ((2561, 1080),), monitors=monitors)


def test_per_capture_monitor_gate_records_actual_device_and_containment():
    monitors = _display_monitors()
    target = resolve_monitor_target(
        r"\\.\DISPLAY2",
        ((1440, 900),),
        monitors=monitors,
    )
    requested_rect = target.requested_client_rect((1440, 900))
    gate = build_monitor_capture_gate(
        target,
        (1440, 900),
        actual_client_rect=requested_rect,
        actual_monitor=monitors[1],
    )

    assert gate["actual_monitor"]["device_name"] == r"\\.\DISPLAY2"
    assert gate["actual_monitor"]["primary"] is False
    assert gate["requested_client_rect"] == [1253, -1194, 2693, -294]
    assert gate["actual_client_rect"] == [1253, -1194, 2693, -294]
    assert all(gate["checks"].values())
    assert gate["passed"] is True
    assert rect_is_contained(requested_rect, monitors[1].work_rect) is True

    wrong_monitor_gate = build_monitor_capture_gate(
        target,
        (1440, 900),
        actual_client_rect=requested_rect,
        actual_monitor=monitors[0],
    )
    assert wrong_monitor_gate["checks"]["actual_monitor_device_matches_target"] is False
    assert wrong_monitor_gate["checks"]["actual_monitor_is_non_primary"] is False
    assert wrong_monitor_gate["checks"]["monitor_work_area_unchanged"] is False
    assert wrong_monitor_gate["passed"] is False


def test_isolated_app_settings_keep_default_contract_and_apply_large_text_scale():
    assert build_isolated_app_settings() == {
        "scale_factor": 1.0,
        "enable_internal_test_commands": False,
    }
    assert build_isolated_app_settings(1.4) == {
        "scale_factor": 1.4,
        "enable_internal_test_commands": False,
    }


def test_size_and_state_parsers_accept_korean_multiplication_mark_and_deduplicate():
    assert parse_sizes("1366×768, 1440x900,1366x768") == (
        (1366, 768),
        (1440, 900),
    )
    assert parse_states("waiting,normal,waiting") == ("waiting", "normal")

    with pytest.raises(argparse.ArgumentTypeError):
        parse_sizes("800x600")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_sizes("wide")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_states("unknown")


def test_fixture_contract_preserves_last_normal_scan_across_duplicate_and_review():
    fixtures = {fixture.state_id: fixture for fixture in build_state_fixtures()}

    waiting = fixtures["waiting"]
    normal = fixtures["normal"]
    duplicate = fixtures["duplicate"]
    review = fixtures["operator_review"]
    completed = fixtures["completed"]
    recovered = fixtures["recovered"]

    assert waiting.tray is None
    assert normal.tray is not None and len(normal.tray.scanned_barcodes) == 3
    assert duplicate.tray is not None
    assert duplicate.tray.scanned_barcodes == normal.tray.scanned_barcodes
    assert duplicate.last_normal_scan == normal.last_normal_scan
    assert duplicate.notice is not None and duplicate.notice.blocking is True
    assert review.tray is not None
    assert len(review.tray.scanned_barcodes) == review.tray.target_count
    assert review.completion is not None
    assert review.completion.outcome == "OPERATOR_REVIEW"
    assert review.last_normal_scan == review.tray.scanned_barcodes[-1]
    assert completed.tray is None
    assert completed.completion is not None and completed.completion.outcome == "ACKED"
    assert recovered.tray is not None and recovered.tray.restored is True
    assert recovered.notice is not None and recovered.notice.blocking is False


def test_capture_rows_are_normalized_to_settled_neutral_colors():
    class FakeListbox:
        def __init__(self):
            self.calls = []

        @staticmethod
        def size():
            return 3

        def itemconfig(self, index, options):
            self.calls.append((index, dict(options)))

    class FakeApp:
        COLOR_SIDEBAR_BG = "#FFFFFF"
        COLOR_TEXT = "#172033"
        scanned_listbox = FakeListbox()

    app = FakeApp()

    assert normalize_capture_scan_rows(app) == 3
    assert app.scanned_listbox.calls == [
        (0, {"bg": app.COLOR_SIDEBAR_BG, "fg": app.COLOR_TEXT}),
        (1, {"bg": app.COLOR_SIDEBAR_BG, "fg": app.COLOR_TEXT}),
        (2, {"bg": app.COLOR_SIDEBAR_BG, "fg": app.COLOR_TEXT}),
    ]


def test_image_analysis_records_exact_size_near_black_and_blank_proxies():
    white = Image.new("RGB", (32, 24), "white")
    white_metrics = analyze_image(white, (32, 24))

    assert white_metrics["pixel_size"] == [32, 24]
    assert white_metrics["pixel_size_matches"] is True
    assert white_metrics["near_black_ratio"] == 0
    assert white_metrics["blank_suspected"] is True

    mixed = Image.new("RGB", (10, 10), "white")
    for x in range(5):
        for y in range(10):
            mixed.putpixel((x, y), (0, 0, 0))
    mixed_metrics = analyze_image(mixed, (11, 10))

    assert mixed_metrics["pixel_size_matches"] is False
    assert mixed_metrics["near_black_ratio"] == pytest.approx(0.5)
    assert mixed_metrics["blank_suspected"] is False


def _widget_record(
    name: str,
    bbox: list[int],
    *,
    mapped: bool = True,
    requested_width: int | None = None,
    requested_height: int | None = None,
    check_requested_width: bool = False,
    check_requested_height: bool = False,
):
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    return {
        "name": name,
        "mapped": mapped,
        "bbox": bbox,
        "size": [width, height],
        "requested_size": [
            requested_width if requested_width is not None else width,
            requested_height if requested_height is not None else height,
        ],
        "check_requested_width": check_requested_width,
        "check_requested_height": check_requested_height,
    }


def test_clipping_proxy_reports_bounds_unmapped_compression_and_overlap():
    records = [
        _widget_record("notice", [10, 10, 90, 40]),
        _widget_record("scan_list", [10, 30, 90, 70]),
        _widget_record("outside", [80, 80, 110, 110]),
        _widget_record(
            "compressed",
            [0, 70, 70, 90],
            requested_width=80,
            requested_height=30,
            check_requested_width=True,
            check_requested_height=True,
        ),
        _widget_record("hidden", [0, 0, 10, 10], mapped=False),
    ]

    result = evaluate_clipping_proxy(
        records,
        (100, 100),
        overlap_pairs=(("notice", "scan_list"),),
        containment_pairs=(("outside", "scan_list"),),
    )

    assert result["suspected"] is True
    assert result["clipped_or_zero_sized_widgets"] == ["outside"]
    assert result["unmapped_critical_widgets"] == ["hidden"]
    assert result["width_compressed_widgets"] == ["compressed"]
    assert result["height_compressed_widgets"] == ["compressed"]
    assert result["overlaps"][0]["widgets"] == ["notice", "scan_list"]
    assert result["outside_containers"] == [
        {"widget": "outside", "container": "scan_list"}
    ]
    assert result["issue_count"] == 6


def test_clipping_proxy_detects_right_value_outside_card_even_when_frame_is_in_pane():
    records = [
        _widget_record("right_pane", [100, 0, 300, 220]),
        _widget_record("right_status", [110, 10, 290, 80]),
        _widget_record(
            "right_status_value",
            [120, 35, 305, 72],
            requested_width=210,
            check_requested_width=True,
            check_requested_height=True,
        ),
    ]

    result = evaluate_clipping_proxy(
        records,
        (320, 240),
        containment_pairs=(
            ("right_status", "right_pane"),
            ("right_status_value", "right_status"),
        ),
    )

    assert result["width_compressed_widgets"] == ["right_status_value"]
    assert result["outside_containers"] == [
        {"widget": "right_status_value", "container": "right_status"}
    ]
    assert result["suspected"] is True


def test_button_row_clustering_preserves_approved_visual_order():
    one_row = [
        _widget_record("action_submit", [220, 10, 300, 50]),
        _widget_record("action_undo", [10, 10, 90, 50]),
        _widget_record("action_operations", [325, 10, 405, 50]),
        _widget_record("action_park", [115, 10, 195, 50]),
    ]
    for record in one_row:
        record["mapped"] = True

    assert cluster_button_rows(one_row) == [[
        "action_undo",
        "action_park",
        "action_submit",
        "action_operations",
    ]]

    two_by_two = [dict(record) for record in one_row]
    second_row_x = {"action_submit": 10, "action_operations": 115}
    for record in two_by_two:
        if record["name"] in second_row_x:
            left = second_row_x[record["name"]]
            record["bbox"] = [left, 70, left + 80, 110]
    assert cluster_button_rows(two_by_two) == [
        ["action_undo", "action_park"],
        ["action_submit", "action_operations"],
    ]


def test_capture_evaluation_combines_pixel_geometry_and_history_contracts():
    record = {
        "state": "normal",
        "requested_scale": 1.4,
        "applied_scale_factor": 1.4,
        "fixture": {"scan_count": 3, "last_normal_scan": "PRODUCT-003"},
        "rendered_state": {
            "scan_list_row_count": 3,
            "scan_list_rows_neutral": True,
            "last_normal_scan": "PRODUCT-003",
            "scan_entry_state": "normal",
            "right_progress_count_texts": {},
        },
        "image_analysis": {
            "pixel_size_matches": True,
            "blank_suspected": False,
            "near_black_ratio": 0.01,
        },
        "ui_geometry": {
            "clipping_proxy": {"suspected": False},
            "structure": {
                "central_scan_list_is_only_center_history": True,
                "right_has_no_full_scan_history": True,
                "right_has_no_progress_widget": True,
                "scan_list_frame_contract": True,
                "scan_list_below_notice": True,
                "core_action_button_count": 4,
                "core_action_common_parent": True,
                "core_action_layout_matches": True,
                "hidden_operation_buttons_mapped": [],
            },
        },
    }
    assert evaluate_capture(record) == []

    record["applied_scale_factor"] = 1.0
    assert evaluate_capture(record) == ["scale_factor_not_applied"]
    record["applied_scale_factor"] = 1.4

    record["rendered_state"]["scan_list_rows_neutral"] = False
    assert evaluate_capture(record) == ["scan_list_rows_not_settled"]
    record["rendered_state"]["scan_list_rows_neutral"] = True

    record["ui_geometry"]["structure"]["right_has_no_full_scan_history"] = False
    record["image_analysis"]["blank_suspected"] = True
    assert evaluate_capture(record) == [
        "blank_image_suspected",
        "right_scan_history_duplicate",
    ]

    record["state"] = "duplicate"
    assert evaluate_capture(record)[-1] == "blocking_state_scan_entry_enabled"


def _scan_row_evaluation_record(state: str, barcodes: list[str], rows: list[str]):
    return {
        "state": state,
        "fixture": {
            "active_tray": True,
            "scan_count": len(barcodes),
            "last_normal_scan": barcodes[-1] if barcodes else "",
            "tray": {"scanned_barcodes": list(barcodes)},
        },
        "rendered_state": {
            "scan_list_row_count": len(rows),
            "scan_list_rows": list(rows),
            "scan_list_rows_neutral": True,
            "last_normal_scan": barcodes[-1] if barcodes else "",
            "scan_entry_state": "disabled" if state == "duplicate" else "normal",
            "right_progress_count_texts": {},
        },
        "image_analysis": {
            "pixel_size_matches": True,
            "blank_suspected": False,
            "near_black_ratio": 0.01,
        },
        "ui_geometry": {
            "clipping_proxy": {"suspected": False},
            "structure": {
                "central_scan_list_is_only_center_history": True,
                "right_has_no_full_scan_history": True,
                "right_has_no_progress_widget": True,
                "scan_list_frame_contract": True,
                "scan_list_below_notice": True,
                "core_action_button_count": 4,
                "core_action_common_parent": True,
                "core_action_layout_matches": True,
                "hidden_operation_buttons_mapped": [],
            },
        },
    }


def test_capture_evaluation_fails_a_false_explicit_monitor_gate():
    record = _scan_row_evaluation_record("waiting", [], [])
    record["fixture"] = {
        "active_tray": False,
        "scan_count": 0,
        "last_normal_scan": "",
        "tray": None,
    }
    record["monitor_gate"] = {
        "gate_applicable": True,
        "checks": {
            "requested_device_name_exact_match": True,
            "target_is_non_primary": True,
            "requested_geometry_contained_in_target_work_area": True,
            "actual_monitor_device_matches_target": False,
            "actual_monitor_is_non_primary": True,
            "monitor_work_area_unchanged": True,
            "actual_geometry_contained_in_target_work_area": True,
            "actual_client_size_matches_requested": True,
        },
        "passed": False,
    }

    assert evaluate_capture(record) == [
        "monitor_gate_actual_monitor_device_matches_target"
    ]


def test_capture_evaluation_matches_every_fixture_barcode_in_display_order():
    barcodes = ["PRODUCT-001", "PRODUCT-002", "PRODUCT-003"]
    expected_rows = ["(3) PRODUCT-003", "(2) PRODUCT-002", "(1) PRODUCT-001"]
    record = _scan_row_evaluation_record("normal", barcodes, expected_rows)

    assert evaluate_capture(record) == []

    record["rendered_state"]["scan_list_rows"][1] = "(2) DECORATIVE-MOCK-ROW"
    assert evaluate_capture(record) == ["rendered_scan_rows_do_not_match_fixture"]


def test_capture_evaluation_preserves_exact_normal_rows_in_duplicate_state():
    barcodes = ["PRODUCT-001", "PRODUCT-002", "PRODUCT-003"]
    expected_rows = ["(3) PRODUCT-003", "(2) PRODUCT-002", "(1) PRODUCT-001"]
    normal = _scan_row_evaluation_record("normal", barcodes, expected_rows)
    duplicate = _scan_row_evaluation_record("duplicate", barcodes, expected_rows)

    assert evaluate_capture(normal) == []
    assert evaluate_capture(duplicate) == []
    assert duplicate["rendered_state"]["scan_list_rows"] == normal["rendered_state"]["scan_list_rows"]


def test_capture_evaluation_requires_empty_scan_list_without_active_tray():
    record = _scan_row_evaluation_record("waiting", [], [])
    record["fixture"] = {
        "active_tray": False,
        "scan_count": 0,
        "last_normal_scan": "",
        "tray": None,
    }

    assert evaluate_capture(record) == []

    record["rendered_state"]["scan_list_row_count"] = 1
    record["rendered_state"]["scan_list_rows"] = ["(1) MOCK-SCAN"]
    assert evaluate_capture(record) == [
        "rendered_scan_count_mismatch",
        "rendered_scan_rows_do_not_match_fixture",
    ]


def _matrix_capture(state: str, *, signature=None, rows=None):
    return {
        "state": state,
        "requested_size": [1366, 768],
        "ui_geometry": {
            "structure": {
                "scan_list_layout_signature": signature
                or {
                    "frame_path": ".scan_frame",
                    "frame_grid": {"row": 5, "sticky": "nsew"},
                    "list_path": ".scan_frame.list",
                    "list_grid": {"row": 1, "sticky": "nsew"},
                }
            }
        },
        "rendered_state": {"scan_list_rows": list(rows or [])},
        "issues": [],
        "passed": True,
    }


def test_cross_capture_contract_preserves_scan_geometry_and_duplicate_rows():
    normal_rows = ["(3) PRODUCT-003", "(2) PRODUCT-002", "(1) PRODUCT-001"]
    captures = [
        _matrix_capture("waiting"),
        _matrix_capture("normal", rows=normal_rows),
        _matrix_capture("duplicate", rows=normal_rows),
        _matrix_capture("operator_review", rows=normal_rows),
        _matrix_capture("completed"),
        _matrix_capture("recovered", rows=normal_rows[:2]),
    ]

    apply_cross_capture_contracts(captures)
    assert all(capture["passed"] for capture in captures)

    captures[2]["rendered_state"]["scan_list_rows"] = normal_rows[:-1]
    captures[5]["ui_geometry"]["structure"]["scan_list_layout_signature"] = {
        "frame_path": ".replacement",
        "frame_grid": {"row": 4},
    }
    apply_cross_capture_contracts(captures)

    assert "duplicate_scan_list_not_preserved" in captures[2]["issues"]
    assert "scan_list_geometry_changed_across_states" in captures[5]["issues"]
    assert captures[2]["passed"] is False
    assert captures[5]["passed"] is False


def test_isolation_guard_rejects_parent_and_sibling_paths(tmp_path):
    allowed = tmp_path / "tmp"
    allowed.mkdir()

    child = assert_descendant(allowed / "capture" / "data", allowed, label="data")
    assert child == (allowed / "capture" / "data").resolve()
    with pytest.raises(RuntimeError):
        assert_descendant(allowed, allowed, label="data")
    with pytest.raises(RuntimeError):
        assert_descendant(tmp_path / "other", allowed, label="data")
