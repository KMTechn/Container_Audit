from __future__ import annotations

import argparse
import copy
from types import SimpleNamespace

import pytest
from PIL import Image
from scan_display import compact_scan_value, format_scan_list_row
import tools.capture_container_operator_ui as capture_tool

from tools.capture_container_operator_ui import (
    DEFAULT_SCALE,
    DEFAULT_SIZES,
    DEFAULT_STATE_IDS,
    DisplayMonitor,
    MAX_SCALE,
    MIN_SCALE,
    CaptureMutationBlocked,
    CaptureMutationGuard,
    analyze_image,
    apply_cross_capture_contracts,
    apply_roundtrip_contracts,
    assert_descendant,
    build_capture_focus_gate,
    build_compact_display_gate,
    build_isolated_data_gate,
    build_monitor_capture_gate,
    build_isolated_app_settings,
    build_parser,
    build_roundtrip_signatures,
    build_scan_list_viewport_gate,
    build_state_fixtures,
    build_tree_heading_fit_gate,
    cluster_button_rows,
    evaluate_capture,
    evaluate_clipping_proxy,
    monitor_preflight_manifest,
    normalize_capture_scan_rows,
    inventory_isolated_data,
    parse_roundtrip_sizes,
    parse_scale,
    parse_sizes,
    parse_states,
    rect_is_contained,
    resolve_monitor_target,
    _expected_scan_list_rows,
    _fixture_manifest,
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


def _passing_focus_gate_kwargs(state_id="normal"):
    return {
        "state_id": state_id,
        "process_pid": 91,
        "root_hwnd": 701,
        "root_hwnd_pid": 91,
        "foreground_root_hwnd": 701,
        "foreground_pid": 91,
        "tk_focus_path": ".scan_entry" if state_id == "normal" else ".",
        "scan_entry_path": ".scan_entry",
        "tk_focus_owned_by_root": True,
        "scan_entry_enabled": state_id == "normal",
    }


def test_focus_gate_requires_foreground_root_pid_and_state_owned_tk_focus():
    normal = build_capture_focus_gate(**_passing_focus_gate_kwargs())
    blocking = build_capture_focus_gate(
        **_passing_focus_gate_kwargs("operator_review")
    )

    assert normal["passed"] is True
    assert blocking["passed"] is True

    mutations = {
        "foreground_root_hwnd": 702,
        "foreground_pid": 92,
        "root_hwnd_pid": 92,
        "tk_focus_owned_by_root": False,
        "tk_focus_path": ".other",
        "scan_entry_enabled": False,
    }
    for key, value in mutations.items():
        kwargs = _passing_focus_gate_kwargs()
        kwargs[key] = value
        gate = build_capture_focus_gate(**kwargs)
        assert gate["passed"] is False, key


class _FakeForegroundUser32:
    def __init__(self, mode):
        self.mode = mode
        self.target_hwnd = 701
        self.foreground_hwnd = 900
        self.calls = []
        self.pids = {701: 91, 900: 92}
        self.threads = {701: 11, 900: 12}

    def GetAncestor(self, hwnd, _flag):
        return hwnd

    def GetWindowThreadProcessId(self, hwnd, pid_pointer):
        pid_pointer._obj.value = self.pids.get(hwnd, 0)
        return self.threads.get(hwnd, 0)

    def GetForegroundWindow(self):
        return self.foreground_hwnd

    def ShowWindow(self, hwnd, command):
        self.calls.append(("restore", hwnd, command))
        return 0 if self.mode == "hidden_direct_success" else 1

    def BringWindowToTop(self, hwnd):
        self.calls.append(("bring", hwnd))
        return 1

    def SetForegroundWindow(self, hwnd):
        self.calls.append(("set", hwnd))
        if self.mode in {"direct_success", "hidden_direct_success"}:
            self.foreground_hwnd = hwnd
            return 1
        if self.mode == "reported_success_without_ownership":
            return 1
        return 0

    def AttachThreadInput(self, *_args):
        raise AssertionError("AttachThreadInput must not be called")


def test_win32_foreground_acquisition_direct_success_records_api_telemetry():
    user32 = _FakeForegroundUser32("direct_success")

    telemetry = capture_tool.acquire_win32_foreground(
        701,
        91,
        user32=user32,
    )

    assert telemetry["passed"] is True
    assert telemetry["attempt_count"] == 1
    assert telemetry["attempts"][0]["phase"] == "direct"
    assert telemetry["attempts"][0]["hwnd_matches"] is True
    assert telemetry["attempts"][0]["pid_matches"] is True
    assert telemetry["strategy"] == "direct_only_fail_closed"
    assert telemetry["thread_input"] == {
        "policy": "disabled_fail_closed",
        "attach_attempted": False,
        "attach_succeeded": False,
        "detach_attempted": False,
        "detach_succeeded": False,
    }
    assert [call[0] for call in user32.calls[:3]] == ["restore", "bring", "set"]


def test_win32_foreground_denial_fails_closed_without_attach_or_retry():
    user32 = _FakeForegroundUser32("direct_denied")

    telemetry = capture_tool.acquire_win32_foreground(
        701,
        91,
        user32=user32,
    )

    assert telemetry["passed"] is False
    assert telemetry["ownership_acquired"] is False
    assert telemetry["attempt_limit"] == 1
    assert telemetry["attempt_count"] == 1
    assert [attempt["phase"] for attempt in telemetry["attempts"]] == ["direct"]
    assert telemetry["thread_input"]["policy"] == "disabled_fail_closed"
    assert telemetry["thread_input"]["attach_attempted"] is False
    assert [call[0] for call in user32.calls] == ["restore", "bring", "set"]


def test_win32_foreground_api_success_still_fails_without_observed_ownership():
    user32 = _FakeForegroundUser32("reported_success_without_ownership")

    telemetry = capture_tool.acquire_win32_foreground(701, 91, user32=user32)

    attempt = telemetry["attempts"][0]
    assert attempt["api_results"]["SetForegroundWindow"] is True
    assert attempt["hwnd_matches"] is False
    assert attempt["pid_matches"] is False
    assert telemetry["ownership_acquired"] is False
    assert telemetry["passed"] is False


def test_win32_foreground_denial_makes_focus_gate_fail_fast():
    user32 = _FakeForegroundUser32("direct_denied")
    telemetry = capture_tool.acquire_win32_foreground(
        701,
        91,
        user32=user32,
    )
    gate = build_capture_focus_gate(
        **_passing_focus_gate_kwargs(),
        acquisition=telemetry,
    )

    assert telemetry["passed"] is False
    assert gate["checks"]["foreground_acquisition_passed"] is False
    with pytest.raises(RuntimeError, match="failed before evidence") as exc_info:
        capture_tool.require_capture_focus_gate(gate, phase="pre_capture")
    assert "phase='pre_capture'" in str(exc_info.value)
    assert "acquisition_telemetry=" in str(exc_info.value)
    assert '"attach_attempted":false' in str(exc_info.value)


def test_show_window_telemetry_records_prior_visibility_not_success():
    user32 = _FakeForegroundUser32("hidden_direct_success")

    telemetry = capture_tool.acquire_win32_foreground(
        701,
        91,
        user32=user32,
    )

    attempt = telemetry["attempts"][0]
    assert telemetry["passed"] is True
    assert attempt["show_window"] == {
        "command": "SW_RESTORE",
        "call_completed": True,
        "previously_visible": False,
        "error": "",
    }
    assert "ShowWindow" not in attempt["api_results"]


@pytest.mark.parametrize("failed_phase", ("pre_capture", "post_capture"))
def test_focus_verified_capture_rejects_phase_before_file_save(
    monkeypatch,
    tmp_path,
    failed_phase,
):
    events = []
    expected_acquisition = {
        "passed": True,
        "attempt_count": 1,
        "attempts": [],
        "thread_input": {"policy": "disabled_fail_closed"},
    }
    pre_kwargs = _passing_focus_gate_kwargs()
    post_kwargs = _passing_focus_gate_kwargs()
    if failed_phase == "pre_capture":
        pre_kwargs["foreground_pid"] = 92
    else:
        post_kwargs["foreground_pid"] = 92
    gates = [
        build_capture_focus_gate(
            **pre_kwargs,
            acquisition=expected_acquisition,
        ),
        build_capture_focus_gate(**post_kwargs),
    ]

    class FakeImage:
        def save(self, *_args, **_kwargs):
            events.append("save")

    def fake_settle(_app, _state_id):
        events.append("settle")
        return expected_acquisition

    def fake_collect(_app, _state_id, *, acquisition=None):
        index = sum(event.startswith("collect_") for event in events)
        events.append("collect_pre" if index == 0 else "collect_post")
        assert acquisition is (expected_acquisition if index == 0 else None)
        return gates[index]

    def fake_capture(_root, *, pump_events=True):
        assert pump_events is False
        events.append("capture")
        return FakeImage(), "synthetic"

    def fake_viewport(_app, *, expected_row_count):
        assert expected_row_count == 3
        events.append("viewport")
        return {"passed": True}

    def fake_monitor(_root, monitor_target, requested_size):
        assert monitor_target is monitor
        assert requested_size == (1, 1)
        events.append("monitor")
        return {"passed": True}

    monkeypatch.setattr(capture_tool, "settle_capture_focus", fake_settle)
    monkeypatch.setattr(capture_tool, "collect_scan_list_viewport_gate", fake_viewport)
    monkeypatch.setattr(capture_tool, "collect_monitor_capture_gate", fake_monitor)
    monkeypatch.setattr(
        capture_tool,
        "collect_ui_geometry",
        lambda _app: events.append("geometry") or {"snapshot": "geometry"},
    )
    monkeypatch.setattr(
        capture_tool,
        "collect_rendered_state",
        lambda _app: events.append("rendered") or {"snapshot": "rendered"},
    )
    monkeypatch.setattr(
        capture_tool,
        "build_tree_heading_fit_gate",
        lambda _app: events.append("tree_headings") or {"snapshot": "tree_headings"},
    )
    monkeypatch.setattr(capture_tool, "collect_capture_focus_gate", fake_collect)
    monkeypatch.setattr(capture_tool, "capture_tk_client", fake_capture)
    output_path = tmp_path / "rejected.png"
    monitor = object()

    with pytest.raises(RuntimeError, match=rf"phase='{failed_phase}'"):
        capture_tool.capture_and_save_focus_verified_tk_client(
            SimpleNamespace(root=object()),
            "normal",
            output_path,
            expected_row_count=3,
            monitor_target=monitor,
            requested_size=(1, 1),
        )

    assert "save" not in events
    assert output_path.exists() is False
    assert ("capture" in events) is (failed_phase == "post_capture")
    expected_events = [
        "settle",
        "viewport",
        "monitor",
        "geometry",
        "rendered",
        "tree_headings",
        "collect_pre",
    ]
    if failed_phase == "post_capture":
        expected_events.extend(["capture", "collect_post"])
    assert events == expected_events


def test_focus_verified_capture_saves_only_after_both_observations(monkeypatch, tmp_path):
    events = []
    expected_acquisition = {
        "passed": True,
        "attempt_count": 1,
        "attempts": [],
        "thread_input": {"policy": "disabled_fail_closed"},
    }
    gates = [
        build_capture_focus_gate(
            **_passing_focus_gate_kwargs(),
            acquisition=expected_acquisition,
        ),
        build_capture_focus_gate(**_passing_focus_gate_kwargs()),
    ]

    class FakeImage:
        def save(self, *_args, **_kwargs):
            events.append("save")

    monkeypatch.setattr(
        capture_tool,
        "settle_capture_focus",
        lambda _app, _state_id: events.append("settle") or expected_acquisition,
    )

    def fake_collect(_app, _state_id, *, acquisition=None):
        index = sum(event.startswith("collect_") for event in events)
        events.append("collect_pre" if index == 0 else "collect_post")
        assert acquisition is (expected_acquisition if index == 0 else None)
        return gates[index]

    def fake_capture(_root, *, pump_events=True):
        assert pump_events is False
        events.append("capture")
        return FakeImage(), "synthetic"

    def fake_viewport(_app, *, expected_row_count):
        assert expected_row_count == 3
        events.append("viewport")
        return {"snapshot": "viewport"}

    monitor = object()

    def fake_monitor(_root, monitor_target, requested_size):
        assert monitor_target is monitor
        assert requested_size == (1, 1)
        events.append("monitor")
        return {"snapshot": "monitor"}

    monkeypatch.setattr(capture_tool, "collect_scan_list_viewport_gate", fake_viewport)
    monkeypatch.setattr(capture_tool, "collect_monitor_capture_gate", fake_monitor)
    monkeypatch.setattr(
        capture_tool,
        "collect_ui_geometry",
        lambda _app: events.append("geometry") or {"snapshot": "geometry"},
    )
    monkeypatch.setattr(
        capture_tool,
        "collect_rendered_state",
        lambda _app: events.append("rendered") or {"snapshot": "rendered"},
    )
    monkeypatch.setattr(
        capture_tool,
        "build_tree_heading_fit_gate",
        lambda _app: events.append("tree_headings") or {"snapshot": "tree_headings"},
    )
    monkeypatch.setattr(capture_tool, "collect_capture_focus_gate", fake_collect)
    monkeypatch.setattr(capture_tool, "capture_tk_client", fake_capture)

    frame = capture_tool.capture_and_save_focus_verified_tk_client(
        SimpleNamespace(root=object()),
        "normal",
        tmp_path / "accepted.png",
        expected_row_count=3,
        monitor_target=monitor,
        requested_size=(1, 1),
    )

    assert isinstance(frame["image"], FakeImage)
    assert frame["source"] == "synthetic"
    assert frame["focus_gate"]["passed"] is True
    assert frame["focus_gate"]["checks"]["pre_capture_gate_passed"] is True
    assert frame["focus_gate"]["checks"]["post_capture_gate_passed"] is True
    assert frame["scan_list_viewport_gate"] == {"snapshot": "viewport"}
    assert frame["monitor_gate"] == {"snapshot": "monitor"}
    assert frame["ui_geometry"] == {"snapshot": "geometry"}
    assert frame["rendered_state"] == {"snapshot": "rendered"}
    assert frame["tree_heading_fit_gate"] == {"snapshot": "tree_headings"}
    assert events == [
        "settle",
        "viewport",
        "monitor",
        "geometry",
        "rendered",
        "tree_headings",
        "collect_pre",
        "capture",
        "collect_post",
        "save",
    ]


def test_focus_verified_capture_refuses_stale_target_before_settle(monkeypatch, tmp_path):
    output_path = tmp_path / "existing.png"
    output_path.write_bytes(b"prior evidence")
    settle_calls = []
    monkeypatch.setattr(
        capture_tool,
        "settle_capture_focus",
        lambda *_args: settle_calls.append(True),
    )

    with pytest.raises(RuntimeError, match="capture target already exists"):
        capture_tool.capture_and_save_focus_verified_tk_client(
            SimpleNamespace(root=object()),
            "normal",
            output_path,
            expected_row_count=0,
            monitor_target=None,
            requested_size=(1, 1),
        )

    assert settle_calls == []
    assert output_path.read_bytes() == b"prior evidence"


def test_capture_output_root_must_be_new(monkeypatch, tmp_path):
    monkeypatch.setattr(capture_tool, "REPO_TMP_ROOT", tmp_path)
    output_root = tmp_path / "capture-run"

    assert capture_tool.create_new_capture_output_root(output_root) == output_root.resolve()
    assert output_root.is_dir()
    with pytest.raises(RuntimeError, match="output root already exists"):
        capture_tool.create_new_capture_output_root(output_root)


def test_capture_tk_client_skips_tk_pump_for_focus_guarded_frame(monkeypatch):
    events = []
    root = SimpleNamespace(
        update_idletasks=lambda: events.append("update_idletasks"),
        update=lambda: events.append("update"),
    )
    expected_image = Image.new("RGB", (1, 1), "white")
    monkeypatch.setattr(capture_tool.os, "name", "nt")
    monkeypatch.setattr(
        capture_tool,
        "_capture_client_with_print_window",
        lambda _root: (expected_image, "synthetic"),
    )

    image, source = capture_tool.capture_tk_client(root, pump_events=False)

    assert image is expected_image
    assert source == "synthetic"
    assert events == []


@pytest.mark.parametrize(
    ("configured_rows", "viewport_height", "row_bboxes", "required_rows"),
    [
        (3, 60, [(2, 2, 80, 16), (2, 22, 80, 16), (2, 42, 80, 16), None, None, None], 3),
        (5, 100, [(2, 2, 80, 16), (2, 22, 80, 16), (2, 42, 80, 16), (2, 62, 80, 16), (2, 82, 80, 16), None], 5),
        (8, 120, [(2, 2, 80, 16), (2, 22, 80, 16), (2, 42, 80, 16), (2, 62, 80, 16), (2, 82, 80, 16), (2, 102, 80, 16)], 6),
    ],
)
def test_scan_list_viewport_gate_requires_responsive_recent_rows(
    configured_rows,
    viewport_height,
    row_bboxes,
    required_rows,
):
    gate = build_scan_list_viewport_gate(
        expected_row_count=6,
        configured_visible_rows=configured_rows,
        viewport_size=(100, viewport_height),
        row_bboxes=row_bboxes,
        see_zero_applied=True,
    )

    assert gate["total_row_count"] == 6
    assert gate["configured_visible_rows"] == configured_rows
    assert gate["minimum_recent_row_count"] == 3
    assert gate["required_visible_row_count"] == required_rows
    assert gate["visible_recent_row_count"] == required_rows
    assert gate["fully_contained_recent_row_count"] == required_rows
    assert gate["checks"]["required_recent_rows_horizontally_contained"] is True
    assert gate["passed"] is True


def test_scan_list_viewport_gate_requires_three_even_if_configured_for_two():
    gate = build_scan_list_viewport_gate(
        expected_row_count=6,
        configured_visible_rows=2,
        viewport_size=(100, 60),
        row_bboxes=[(2, 2, 80, 16), (2, 22, 80, 16), (2, 42, 80, 16), None, None, None],
        see_zero_applied=True,
    )

    assert gate["required_visible_row_count"] == 3
    assert gate["passed"] is True


def test_scan_list_viewport_gate_rejects_clipped_newest_row():
    gate = build_scan_list_viewport_gate(
        expected_row_count=6,
        configured_visible_rows=3,
        viewport_size=(100, 60),
        row_bboxes=[(2, 45, 80, 18), (2, 2, 80, 16), (2, 22, 80, 16), None, None, None],
        see_zero_applied=True,
    )

    assert gate["checks"]["newest_index_zero_visible"] is True
    assert gate["checks"]["newest_index_zero_vertically_contained"] is False
    assert gate["passed"] is False


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


def test_roundtrip_parser_preserves_duplicate_ordinals_and_requires_compact_return():
    expected = ((1366, 768), (1920, 1080), (1366, 768))

    assert parse_roundtrip_sizes("1366x768,1920×1080,1366x768") == expected
    assert build_parser().parse_args(
        ["--roundtrip-sizes", "1366x768,1920x1080,1366x768"]
    ).roundtrip_sizes == expected
    assert build_parser().parse_args([]).roundtrip_sizes == ()

    for invalid in (
        "1366x768,1366x768",
        "1366x768,1920x1080,1440x900",
        "1366x768,1366x768,1366x768",
    ):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_roundtrip_sizes(invalid)


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
    assert "|" in normal.last_normal_scan and "=" in normal.last_normal_scan
    assert duplicate.tray is not None
    assert duplicate.tray.scanned_barcodes == normal.tray.scanned_barcodes
    assert duplicate.last_normal_scan == normal.last_normal_scan
    assert duplicate.notice is not None and duplicate.notice.blocking is True
    assert duplicate.last_normal_scan not in duplicate.notice.message
    assert "|" not in duplicate.notice.message and "=" not in duplicate.notice.message
    assert review.tray is not None
    assert len(review.tray.scanned_barcodes) == review.tray.target_count
    assert review.completion is not None
    assert review.completion.outcome == "OPERATOR_REVIEW"
    assert review.last_normal_scan == review.tray.scanned_barcodes[-1]
    assert completed.tray is None
    assert completed.completion is not None and completed.completion.outcome == "ACKED"
    assert recovered.tray is not None and recovered.tray.restored is True
    assert recovered.notice is not None and recovered.notice.blocking is False


def test_capture_fixture_keeps_raw_source_but_requires_compact_visible_values():
    normal = next(
        fixture for fixture in build_state_fixtures() if fixture.state_id == "normal"
    )
    manifest = _fixture_manifest(normal)
    rows = _expected_scan_list_rows(manifest)

    assert normal.tray is not None
    assert manifest["last_normal_scan"] == normal.last_normal_scan
    assert manifest["last_normal_scan_display"] == compact_scan_value(
        normal.last_normal_scan,
        item_code=normal.last_normal_item_code,
    )
    assert all(raw not in row for raw in normal.tray.scanned_barcodes for row in rows)
    assert all("|" not in row and "=" not in row for row in rows)


@pytest.mark.parametrize(
    "mutation",
    [
        "central_raw",
        "right_raw",
        "presenter_raw_changed",
        "tray_raw_changed",
    ],
)
def test_compact_display_gate_rejects_visible_raw_and_preserves_runtime_raw(mutation):
    fixture = _fixture_manifest(
        next(item for item in build_state_fixtures() if item.state_id == "normal")
    )
    rendered = {
        "scan_list_rows": _expected_scan_list_rows(fixture),
        "last_normal_scan_display": fixture["last_normal_scan_display"],
        "presenter_last_normal_scan_raw": fixture["last_normal_scan"],
        "active_tray_scans_raw": list(fixture["tray"]["scanned_barcodes"]),
    }
    assert build_compact_display_gate(fixture, rendered)["passed"] is True

    if mutation == "central_raw":
        rendered["scan_list_rows"][0] = fixture["tray"]["scanned_barcodes"][-1]
    elif mutation == "right_raw":
        rendered["last_normal_scan_display"] = fixture["last_normal_scan"]
    elif mutation == "presenter_raw_changed":
        rendered["presenter_last_normal_scan_raw"] = "changed"
    else:
        rendered["active_tray_scans_raw"] = rendered["active_tray_scans_raw"][:-1]

    gate = build_compact_display_gate(fixture, rendered)
    assert gate["passed"] is False
    assert any(passed is False for passed in gate["checks"].values())


def test_capture_rows_are_normalized_to_settled_neutral_colors():
    class FakeListbox:
        def __init__(self):
            self.calls = []

        @staticmethod
        def size():
            return 3

        def itemconfig(self, index, options):
            self.calls.append((index, dict(options)))

        def see(self, index):
            self.seen = index

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
    assert app.scanned_listbox.seen == 0


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


@pytest.mark.parametrize("noisy", [False, True])
def test_image_analysis_rejects_thirty_percent_edge_black_stripe(noisy):
    image = Image.new("RGB", (100, 100), (235, 240, 245))
    for y in range(70, 100):
        for x in range(100):
            if noisy and x % 25 == 0:
                continue
            image.putpixel((x, y), (0, 0, 0))

    metrics = analyze_image(image, (100, 100))

    assert metrics["near_black_ratio"] == pytest.approx(0.288 if noisy else 0.30)
    assert metrics["edge_black_stripe_suspected"] is True
    assert metrics["contiguous_black_stripe_suspected"] is True


def test_image_analysis_rejects_uniform_gray_low_variance_frame():
    metrics = analyze_image(Image.new("RGB", (160, 90), (128, 128, 128)), (160, 90))

    assert metrics["uniform_low_variance_suspected"] is True
    assert metrics["luma_stddev"] == 0.0


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


def test_core_action_specs_enable_requested_width_and_proxy_compressed_buttons():
    buttons = {
        "undo_button": object(),
        "park_button": object(),
        "submit_tray_button": object(),
        "operations_button": object(),
    }
    specs = capture_tool._core_action_critical_widget_specs(SimpleNamespace(**buttons))
    assert set(specs) == {
        "action_undo",
        "action_park",
        "action_submit",
        "action_operations",
    }
    assert all(specification[1:] == (True, True) for specification in specs.values())

    records = [
        _widget_record(
            "action_submit",
            [0, 0, 154, 50],
            requested_width=208,
            check_requested_width=True,
        ),
        _widget_record(
            "action_operations",
            [154, 0, 307, 50],
            requested_width=174,
            check_requested_width=True,
        ),
        _widget_record(
            "action_submit_wide",
            [0, 60, 327, 110],
            requested_width=363,
            check_requested_width=True,
        ),
    ]
    result = evaluate_clipping_proxy(records, (400, 120))
    assert result["width_compressed_widgets"] == [
        "action_operations",
        "action_submit",
        "action_submit_wide",
    ]
    assert result["suspected"] is True


def test_notice_inner_specs_detect_wrap_aware_width_and_height_clipping():
    notice = object()
    title = object()
    message = object()
    acknowledge = SimpleNamespace(master=notice, winfo_ismapped=lambda: True)
    specs = capture_tool._notice_critical_widget_specs(
        SimpleNamespace(
            notice_frame=notice,
            notice_title_label=title,
            notice_message_label=message,
            notice_ack_button=acknowledge,
        )
    )
    assert specs == {
        "notice_title": (title, True, True),
        "notice_message": (message, True, True),
        "notice_ack": (acknowledge, True, True),
    }

    records = [
        _widget_record("notice", [0, 0, 200, 50]),
        _widget_record(
            "notice_message",
            [20, 10, 180, 30],
            requested_width=320,
            requested_height=44,
            check_requested_width=True,
            check_requested_height=True,
        ),
    ]
    result = evaluate_clipping_proxy(
        records,
        (220, 60),
        containment_pairs=(("notice_message", "notice"),),
    )
    assert result["width_compressed_widgets"] == ["notice_message"]
    assert result["height_compressed_widgets"] == ["notice_message"]
    assert result["outside_containers"] == []
    assert result["suspected"] is True


def test_hidden_nonblocking_notice_ack_is_omitted():
    notice = object()
    hidden_ack = SimpleNamespace(master=notice, winfo_ismapped=lambda: False)
    specs = capture_tool._notice_critical_widget_specs(
        SimpleNamespace(
            notice_frame=notice,
            notice_title_label=None,
            notice_message_label=None,
            notice_ack_button=hidden_ack,
        )
    )
    assert specs == {}


def test_mapped_blocking_notice_ack_is_measured_only_in_exact_notice_frame():
    notice = object()
    mapped_ack = SimpleNamespace(master=notice, winfo_ismapped=lambda: True)
    specs = capture_tool._notice_critical_widget_specs(
        SimpleNamespace(
            notice_frame=notice,
            notice_title_label=None,
            notice_message_label=None,
            notice_ack_button=mapped_ack,
        )
    )
    assert specs == {"notice_ack": (mapped_ack, True, True)}

    foreign_ack = SimpleNamespace(master=object(), winfo_ismapped=lambda: True)
    specs = capture_tool._notice_critical_widget_specs(
        SimpleNamespace(
            notice_frame=notice,
            notice_title_label=None,
            notice_message_label=None,
            notice_ack_button=foreign_ack,
        )
    )
    assert specs == {}


def test_tray_image_checkbox_checks_requested_size_and_left_pane_containment():
    checkbox = object()
    specs = capture_tool._left_sidebar_critical_widget_specs(
        SimpleNamespace(tray_image_checkbox=checkbox)
    )
    assert specs == {"tray_image_checkbox": (checkbox, True, True)}

    records = [
        _widget_record("left_pane", [0, 0, 160, 80]),
        _widget_record(
            "tray_image_checkbox",
            [5, 10, 155, 40],
            requested_width=174,
            requested_height=30,
            check_requested_width=True,
            check_requested_height=True,
        ),
    ]
    result = evaluate_clipping_proxy(
        records,
        (200, 100),
        containment_pairs=(("tray_image_checkbox", "left_pane"),),
    )
    assert result["width_compressed_widgets"] == ["tray_image_checkbox"]
    assert result["outside_containers"] == []
    assert result["suspected"] is True


class _HeadingGateTk:
    def __init__(self, image_widths=None):
        self.image_widths = dict(image_widths or {})

    @staticmethod
    def splitlist(value):
        if isinstance(value, (tuple, list)):
            return tuple(value)
        return tuple(str(value).split()) if str(value) else ()

    def call(self, *args):
        if args[:2] == ("tk", "scaling"):
            return 2.0
        if args[:2] == ("image", "width"):
            return self.image_widths[str(args[2])]
        raise AssertionError(args)


class _HeadingGateFont:
    def __init__(self, measures):
        self.measures = dict(measures)

    def measure(self, text):
        return self.measures[str(text)]

    @staticmethod
    def actual():
        return {"family": "Malgun Gothic", "size": 15, "weight": "bold"}

    @staticmethod
    def metrics():
        return {"linespace": 41}


class _HeadingGateStyle:
    @staticmethod
    def lookup(style_name, option):
        assert style_name == "Treeview.Heading"
        return {"font": "capture-heading-font", "padding": "3"}[option]


class _HeadingGateScrollbar:
    def __init__(self, tk, left, width=16):
        self.tk = tk
        self._left = left
        self._width = width

    @staticmethod
    def winfo_class():
        return "TScrollbar"

    @staticmethod
    def winfo_ismapped():
        return True

    @staticmethod
    def cget(option):
        assert option == "orient"
        return "vertical"

    def winfo_x(self):
        return self._left

    def winfo_width(self):
        return self._width

    def __str__(self):
        return ".scrollbar"


class _HeadingGateParent:
    def __init__(self, width):
        self._width = width
        self.children = []

    def winfo_width(self):
        return self._width

    def winfo_children(self):
        return list(self.children)


class _HeadingGateTree:
    def __init__(
        self,
        *,
        tk,
        texts,
        configured_widths,
        visible_heading_widths,
        widget_width,
        images=None,
        mapped=True,
    ):
        self.tk = tk
        self._columns = tuple(f"c{index}" for index in range(1, len(texts) + 1))
        self._texts = dict(zip(self._columns, texts))
        self._widths = dict(zip(self._columns, configured_widths))
        self._images = dict(zip(self._columns, images or ("",) * len(texts)))
        self._widget_width = widget_width
        self._mapped = mapped
        self._pixels = {}
        x = 2
        for position, visible_width in enumerate(visible_heading_widths, start=1):
            for pixel in range(x, x + visible_width):
                self._pixels[pixel] = ("heading", f"#{position}")
            x += visible_width
            for pixel in range(x, x + 2):
                self._pixels[pixel] = ("separator", f"#{position}")
            x += 2
        self.master = _HeadingGateParent(widget_width + 16)
        self.scrollbar = _HeadingGateScrollbar(tk, widget_width)
        self.master.children = [self, self.scrollbar]

    def cget(self, option):
        return {
            "columns": self._columns,
            "displaycolumns": ("#all",),
            "style": "Treeview",
        }[option]

    @staticmethod
    def winfo_pixels(value):
        return int(value)

    def winfo_ismapped(self):
        return self._mapped

    def winfo_width(self):
        return self._widget_width

    @staticmethod
    def winfo_height():
        return 48

    @staticmethod
    def winfo_x():
        return 0

    def identify_region(self, x, y):
        if not 2 <= y <= 32:
            return "nothing"
        return self._pixels.get(x, ("nothing", ""))[0]

    def identify_column(self, x):
        return self._pixels.get(x, ("nothing", ""))[1]

    def heading(self, column_id):
        return {"text": self._texts[column_id], "image": self._images[column_id]}

    def column(self, column_id, option):
        assert option == "width"
        return self._widths[column_id]

    def __str__(self):
        return ".tree"


def _heading_gate_app(
    *,
    summary_widths=(80, 80, 120),
    summary_visible=(70, 70, 115),
    summary_widget_width=320,
    summary_images=("", "", ""),
    image_widths=None,
    summary_mapped=True,
    parked_mapped=True,
    left_pane_height=900,
    scale_factor=1.0,
):
    tk = _HeadingGateTk(image_widths)
    summary = _HeadingGateTree(
        tk=tk,
        texts=("품목", "코드", "완료 수량"),
        configured_widths=summary_widths,
        visible_heading_widths=summary_visible,
        widget_width=summary_widget_width,
        images=summary_images,
        mapped=summary_mapped,
    )
    parked = _HeadingGateTree(
        tk=tk,
        texts=("품목명", "스캔 수량"),
        configured_widths=(140, 150),
        visible_heading_widths=(130, 145),
        widget_width=320,
        mapped=parked_mapped,
    )
    return SimpleNamespace(
        root=SimpleNamespace(tk=tk),
        style=_HeadingGateStyle(),
        scale_factor=scale_factor,
        left_pane=SimpleNamespace(winfo_height=lambda: left_pane_height),
        summary_tree=summary,
        parked_tree=parked,
    )


def _heading_font_factory(measures):
    calls = []

    def factory(*, root, font):
        calls.append((root, font))
        return _HeadingGateFont(measures)

    return factory, calls


def test_tree_heading_fit_gate_uses_live_font_measure_and_visible_heading_span():
    measures = {
        "품목": 60,
        "코드": 60,
        "완료 수량": 131,
        "품목명": 90,
        "스캔 수량": 100,
    }
    font_factory, calls = _heading_font_factory(measures)
    clipped = build_tree_heading_fit_gate(
        _heading_gate_app(),
        font_factory=font_factory,
    )

    count = clipped["trees"][0]["columns"][2]
    assert count["font_measured_text_width_px"] == 131
    assert count["visible_heading_width_px"] == 115
    assert count["available_text_width_px"] == 109
    assert count["fit_slack_px"] == -22
    assert count["passed"] is False
    assert clipped["checks"]["all_heading_text_fits"] is False
    assert clipped["passed"] is False
    assert calls and all(font == "capture-heading-font" for _root, font in calls)

    widened = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_widths=(80, 80, 155),
            summary_visible=(70, 70, 150),
            summary_widget_width=350,
        ),
        font_factory=font_factory,
    )
    assert widened["trees"][0]["columns"][2]["fit_slack_px"] == 13
    assert widened["passed"] is True


def test_tree_heading_fit_gate_reserves_explicit_sort_image_width():
    measures = {
        "품목": 40,
        "코드": 40,
        "완료 수량": 100,
        "품목명": 60,
        "스캔 수량": 80,
    }
    font_factory, _calls = _heading_font_factory(measures)
    without_image = build_tree_heading_fit_gate(
        _heading_gate_app(summary_visible=(70, 70, 119)),
        font_factory=font_factory,
    )
    assert without_image["trees"][0]["columns"][2]["passed"] is True

    with_image = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_visible=(70, 70, 119),
            summary_images=("", "", "sort-up"),
            image_widths={"sort-up": 12},
        ),
        font_factory=font_factory,
    )
    count = with_image["trees"][0]["columns"][2]
    assert count["heading_image_width_px"] == 12
    assert count["heading_image_gap_px"] == 2
    assert count["available_text_width_px"] == 99
    assert count["passed"] is False


def test_tree_heading_fit_gate_rejects_columns_extending_into_outer_viewport():
    measures = {
        "품목": 40,
        "코드": 40,
        "완료 수량": 60,
        "품목명": 60,
        "스캔 수량": 80,
    }
    font_factory, _calls = _heading_font_factory(measures)
    gate = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_widths=(100, 100, 100),
            summary_visible=(90, 90, 90),
            summary_widget_width=300,
        ),
        font_factory=font_factory,
    )

    summary = gate["trees"][0]
    assert summary["configured_column_extent_px"] == 300
    assert summary["heading_viewport"]["viewport_width_px"] == 296
    assert summary["checks"]["all_heading_text_fits"] is True
    assert summary["checks"]["column_extent_within_viewport"] is False
    assert gate["checks"]["all_column_extents_within_viewport"] is False
    assert gate["passed"] is False


def test_tree_heading_fit_gate_allows_only_explicit_compact_optional_unmapped_trees():
    measures = {
        "품목": 40,
        "코드": 40,
        "완료 수량": 60,
        "품목명": 60,
        "스캔 수량": 80,
    }
    font_factory, _calls = _heading_font_factory(measures)
    gate = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_mapped=False,
            parked_mapped=False,
            left_pane_height=694,
            scale_factor=1.4,
        ),
        font_factory=font_factory,
    )

    assert gate["visibility_policy"]["logical_left_pane_height"] == pytest.approx(
        495.7142857
    )
    assert gate["visibility_policy"]["visibility_required"] is False
    assert gate["checks"]["required_trees_mapped"] is True
    assert all(tree["visibility_required"] is False for tree in gate["trees"])
    assert all(tree["measurement_applicable"] is False for tree in gate["trees"])
    assert gate["passed"] is True

    mapped_but_clipped = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_mapped=True,
            parked_mapped=False,
            summary_visible=(70, 70, 50),
            left_pane_height=694,
            scale_factor=1.4,
        ),
        font_factory=font_factory,
    )
    assert mapped_but_clipped["trees"][0]["measurement_applicable"] is True
    assert mapped_but_clipped["checks"]["all_heading_text_fits"] is False
    assert mapped_but_clipped["passed"] is False


def test_tree_heading_fit_gate_fails_closed_when_required_tree_is_unmapped():
    measures = {
        "품목": 40,
        "코드": 40,
        "완료 수량": 60,
        "품목명": 60,
        "스캔 수량": 80,
    }
    font_factory, _calls = _heading_font_factory(measures)
    gate = build_tree_heading_fit_gate(
        _heading_gate_app(
            summary_mapped=False,
            parked_mapped=True,
            left_pane_height=620,
            scale_factor=1.0,
        ),
        font_factory=font_factory,
    )

    assert gate["visibility_policy"]["visibility_required"] is True
    assert gate["trees"][0]["checks"]["mapped_when_required"] is False
    assert gate["checks"]["required_trees_mapped"] is False
    assert gate["passed"] is False


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
    last_normal_raw = "PRODUCT-003"
    last_normal_display = compact_scan_value(last_normal_raw, item_code="PRODUCT")
    record = {
        "state": "normal",
        "requested_scale": 1.4,
        "applied_scale_factor": 1.4,
        "fixture": {
            "scan_count": 3,
            "last_normal_scan": last_normal_raw,
            "last_normal_scan_display": last_normal_display,
        },
        "rendered_state": {
            "scan_list_row_count": 3,
            "scan_list_rows_neutral": True,
            "last_normal_scan": last_normal_display,
            "last_normal_scan_display": last_normal_display,
            "presenter_last_normal_scan_raw": last_normal_raw,
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


def _scan_row_evaluation_record(
    state: str,
    barcodes: list[str],
    rows: list[str],
    *,
    item_code: str = "PRODUCT",
):
    last_normal_raw = barcodes[-1] if barcodes else ""
    last_normal_display = (
        compact_scan_value(last_normal_raw, item_code=item_code)
        if last_normal_raw
        else "-"
    )
    return {
        "state": state,
        "fixture": {
            "active_tray": True,
            "scan_count": len(barcodes),
            "last_normal_scan": last_normal_raw,
            "last_normal_scan_display": last_normal_display,
            "tray": {
                "item_code": item_code,
                "scanned_barcodes": list(barcodes),
            },
        },
        "rendered_state": {
            "scan_list_row_count": len(rows),
            "scan_list_rows": list(rows),
            "scan_list_rows_neutral": True,
            "last_normal_scan": last_normal_display,
            "last_normal_scan_display": last_normal_display,
            "presenter_last_normal_scan_raw": last_normal_raw,
            "active_tray_scans_raw": list(barcodes),
            "active_tray_last_scan_raw": last_normal_raw,
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


def test_capture_evaluation_schema_v2_fails_closed_when_any_strict_gate_is_missing():
    record = _scan_row_evaluation_record("normal", ["PRODUCT-001"], ["(1) 001"])
    record["capture_gate_schema_version"] = 2

    assert evaluate_capture(record) == [
        "focus_gate_missing",
        "scan_list_viewport_gate_missing",
        "compact_display_gate_missing",
        "rendered_scan_rows_do_not_match_fixture",
    ]


def _passing_capture_gate():
    return {
        "gate_applicable": True,
        "checks": {"synthetic_check": True},
        "passed": True,
    }


def test_capture_evaluation_schema_v3_requires_and_enforces_tree_heading_fit_gate():
    barcodes = ["PRODUCT-001"]
    rows = [format_scan_list_row(1, barcodes[0], item_code="PRODUCT")]
    record = _scan_row_evaluation_record("normal", barcodes, rows)
    record["capture_gate_schema_version"] = 3
    record["focus_gate"] = _passing_capture_gate()
    record["scan_list_viewport_gate"] = _passing_capture_gate()
    record["compact_display_gate"] = _passing_capture_gate()

    assert evaluate_capture(record) == ["tree_heading_fit_gate_missing"]

    record["tree_heading_fit_gate"] = {
        "gate_applicable": True,
        "checks": {
            "all_column_extents_within_viewport": True,
            "all_heading_text_fits": False,
            "all_scrollbar_layouts_safe": True,
        },
        "passed": False,
    }
    assert evaluate_capture(record) == [
        "tree_heading_fit_gate_all_heading_text_fits"
    ]

    record["tree_heading_fit_gate"] = _passing_capture_gate()
    assert evaluate_capture(record) == []


def test_capture_evaluation_matches_every_fixture_barcode_in_display_order():
    barcodes = ["PRODUCT-001", "PRODUCT-002", "PRODUCT-003"]
    expected_rows = [
        format_scan_list_row(index, barcode, item_code="PRODUCT")
        for index, barcode in reversed(tuple(enumerate(barcodes, start=1)))
    ]
    record = _scan_row_evaluation_record("normal", barcodes, expected_rows)

    assert evaluate_capture(record) == []

    record["rendered_state"]["scan_list_rows"][1] = "(2) DECORATIVE-MOCK-ROW"
    assert evaluate_capture(record) == ["rendered_scan_rows_do_not_match_fixture"]


def test_capture_evaluation_preserves_exact_normal_rows_in_duplicate_state():
    barcodes = ["PRODUCT-001", "PRODUCT-002", "PRODUCT-003"]
    expected_rows = [
        format_scan_list_row(index, barcode, item_code="PRODUCT")
        for index, barcode in reversed(tuple(enumerate(barcodes, start=1)))
    ]
    normal = _scan_row_evaluation_record("normal", barcodes, expected_rows)
    duplicate = _scan_row_evaluation_record("duplicate", barcodes, expected_rows)

    assert evaluate_capture(normal) == []
    assert evaluate_capture(duplicate) == []
    assert duplicate["rendered_state"]["scan_list_rows"] == normal["rendered_state"]["scan_list_rows"]


def test_capture_evaluation_rejects_raw_visible_label_but_preserves_raw_sources():
    barcodes = ["PRODUCT-001", "PRODUCT-002", "PRODUCT-003"]
    rows = [
        format_scan_list_row(index, barcode, item_code="PRODUCT")
        for index, barcode in reversed(tuple(enumerate(barcodes, start=1)))
    ]
    record = _scan_row_evaluation_record("normal", barcodes, rows)

    record["rendered_state"]["last_normal_scan"] = barcodes[-1]
    record["rendered_state"]["last_normal_scan_display"] = barcodes[-1]

    assert evaluate_capture(record) == [
        "last_normal_scan_not_preserved",
        "last_normal_scan_display_raw_leak",
    ]

    record = _scan_row_evaluation_record("normal", barcodes, rows)
    record["rendered_state"]["presenter_last_normal_scan_raw"] = "PRODUCT · 003"

    assert evaluate_capture(record) == ["presenter_last_normal_scan_not_preserved"]

    record = _scan_row_evaluation_record("normal", barcodes, rows)
    record["rendered_state"]["active_tray_scans_raw"] = barcodes[:-1]

    assert evaluate_capture(record) == ["active_tray_scans_not_preserved"]


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


def _mutation_guard_fixture():
    def allowed(*_args, **_kwargs):
        return "allowed"

    app = SimpleNamespace()
    from tools.capture_container_operator_ui import (
        MUTATION_GUARD_APP_METHODS,
        MUTATION_GUARD_MODULE_METHODS,
        MUTATION_GUARD_NESTED_METHODS,
    )

    for names in MUTATION_GUARD_APP_METHODS.values():
        for name in names:
            setattr(app, name, allowed)
    for _category, owner_path, names in MUTATION_GUARD_NESTED_METHODS:
        current = app
        parts = owner_path.split(".")
        for part in parts:
            if not hasattr(current, part):
                setattr(current, part, SimpleNamespace())
            current = getattr(current, part)
        for name in names:
            setattr(current, name, allowed)
    module = SimpleNamespace()
    for names in MUTATION_GUARD_MODULE_METHODS.values():
        for name in names:
            setattr(module, name, allowed)
    return app, module


def test_mutation_guard_arms_every_required_target_counts_and_blocks_calls():
    app, module = _mutation_guard_fixture()
    guard = CaptureMutationGuard(app, module)

    guard.arm()
    armed = guard.manifest()
    assert armed["armed"] is True
    assert armed["checks"]["all_required_targets_protected"] is True
    assert armed["total_protected_target_count"] == sum(
        armed["protected_target_counts_by_category"].values()
    )
    assert armed["total_blocked_call_count"] == 0

    with pytest.raises(CaptureMutationBlocked, match="barcode"):
        app.process_barcode("raw")
    blocked = guard.manifest()
    assert blocked["total_blocked_call_count"] == 1
    assert blocked["blocked_call_counts_by_category"] == {"barcode": 1}
    assert blocked["checks"]["no_guarded_mutation_calls"] is False
    assert blocked["passed"] is False

    guard.restore()
    assert app.process_barcode("raw") == "allowed"


def test_mutation_guard_missing_method_setup_fails_closed_before_arming():
    app, module = _mutation_guard_fixture()
    del app.worker_registry.mark_recent
    guard = CaptureMutationGuard(app, module)

    with pytest.raises(RuntimeError, match="worker_registry.mark_recent"):
        guard.arm()
    assert guard.armed is False
    assert guard.manifest()["total_protected_target_count"] == 0


def test_isolated_data_inventory_hash_gate_detects_any_file_write(tmp_path):
    data_root = tmp_path / "isolated"
    data_root.mkdir()
    (data_root / "settings.json").write_text('{"scale": 1}', encoding="utf-8")
    before = inventory_isolated_data(data_root)
    unchanged = inventory_isolated_data(data_root)

    assert build_isolated_data_gate(before, unchanged)["passed"] is True
    assert before["file_count"] == 1
    assert before["total_bytes"] > 0

    (data_root / "events.csv").write_text("forbidden", encoding="utf-8")
    after = inventory_isolated_data(data_root)
    gate = build_isolated_data_gate(before, after)
    assert gate["passed"] is False
    assert gate["checks"]["file_count_unchanged"] is False
    assert gate["checks"]["inventory_hash_unchanged"] is False


def _roundtrip_capture(ordinal, *, size=(1366, 768)):
    key_widget_paths = {
        attr: ".scan_list" for attr in capture_tool.ROUNDTRIP_KEY_WIDGET_ATTRS
    }
    key_widget_object_ids = {
        attr: 101 for attr in capture_tool.ROUNDTRIP_KEY_WIDGET_ATTRS
    }
    record = {
        "capture_sequence": "roundtrip",
        "sequence_ordinal": ordinal,
        "state": "normal",
        "requested_size": list(size),
        "roundtrip_rebuild_applied": ordinal == 1,
        "roundtrip_widget_identity": {
            "widget_count": 2,
            "tree_paths": [
                {"path": ".", "master_path": "", "widget_class": "Tk"},
                {
                    "path": ".scan_list",
                    "master_path": ".",
                    "widget_class": "Listbox",
                },
            ],
            "tree_object_ids": [
                {"path": ".", "python_object_id": 100},
                {"path": ".scan_list", "python_object_id": 101},
            ],
            "key_widget_paths": key_widget_paths,
            "key_widget_object_ids": key_widget_object_ids,
        },
        "ui_geometry": {
            "root_client_size": list(size),
            "widgets": [
                {
                    "name": "scan_list",
                    "bbox": [300, 400, 900, 610],
                    "size": [600, 210],
                    "requested_size": [600, 210],
                    "mapped": True,
                }
            ],
            "structure": {
                "scan_list_layout_signature": {"frame_grid": {"row": 5}},
                "core_action_rows": [["undo", "park"], ["submit", "operations"]],
            },
        },
        "rendered_state": {
            "scan_list_rows": ["(1) ITEM · SN 0001"],
            "action_buttons": {
                "undo": {"text": "취소", "state": "normal"},
                "park": {"text": "보류", "state": "normal"},
                "submit": {"text": "제출", "state": "normal"},
                "operations": {"text": "작업", "state": "normal"},
            },
        },
        "issues": [],
        "passed": True,
    }
    record["roundtrip_signatures"] = build_roundtrip_signatures(record)
    return record


def test_roundtrip_contract_requires_exact_compact_geometry_rows_and_actions():
    captures = [
        _roundtrip_capture(1),
        _roundtrip_capture(2, size=(1920, 1080)),
        _roundtrip_capture(3),
    ]
    apply_roundtrip_contracts(captures)
    assert captures[-1]["roundtrip_comparison_gate"]["passed"] is True
    assert captures[-1]["roundtrip_comparison_gate"]["checks"][
        "first_ordinal_rebuilt"
    ] is True
    assert captures[-1]["roundtrip_comparison_gate"]["checks"][
        "later_ordinals_not_rebuilt"
    ] is True

    changed = copy.deepcopy(captures)
    changed[-1]["ui_geometry"]["widgets"][0]["bbox"][2] += 1
    changed[-1]["rendered_state"]["scan_list_rows"].append("(2) ITEM · SN 0002")
    changed[-1]["rendered_state"]["action_buttons"]["park"]["text"] = "트레이 보류"
    changed[-1]["roundtrip_signatures"] = build_roundtrip_signatures(changed[-1])
    changed[-1]["issues"] = []
    apply_roundtrip_contracts(changed)

    checks = changed[-1]["roundtrip_comparison_gate"]["checks"]
    assert checks["geometry_signature_exact"] is False
    assert checks["row_signature_exact"] is False
    assert checks["action_signature_exact"] is False
    assert changed[-1]["passed"] is False


def test_roundtrip_signature_ignores_stale_geometry_for_unmapped_widgets():
    first = _roundtrip_capture(1)
    final = _roundtrip_capture(3)
    first["ui_geometry"]["widgets"].append(
        {
            "name": "hidden_stopwatch",
            "bbox": [1142, 298, 1393, 299],
            "size": [251, 1],
            "requested_size": [97, 52],
            "mapped": False,
        }
    )
    final["ui_geometry"]["widgets"].append(
        {
            "name": "hidden_stopwatch",
            "bbox": [1142, 355, 1568, 407],
            "size": [426, 52],
            "requested_size": [106, 58],
            "mapped": False,
        }
    )

    first_signature = build_roundtrip_signatures(first)
    final_signature = build_roundtrip_signatures(final)

    assert first_signature["geometry"] == final_signature["geometry"]
    assert first_signature["geometry"]["widgets"]["hidden_stopwatch"] == {
        "mapped": False
    }
    assert first_signature["geometry_sha256"] == final_signature["geometry_sha256"]


def test_roundtrip_signature_still_rejects_unmapped_to_mapped_state_change():
    first = _roundtrip_capture(1)
    final = _roundtrip_capture(3)
    hidden_widget = {
        "name": "hidden_stopwatch",
        "bbox": [1142, 298, 1393, 299],
        "size": [251, 1],
        "requested_size": [97, 52],
        "mapped": False,
    }
    first["ui_geometry"]["widgets"].append(copy.deepcopy(hidden_widget))
    final_widget = copy.deepcopy(hidden_widget)
    final_widget["mapped"] = True
    final["ui_geometry"]["widgets"].append(final_widget)

    first["roundtrip_signatures"] = build_roundtrip_signatures(first)
    final["roundtrip_signatures"] = build_roundtrip_signatures(final)
    captures = [first, _roundtrip_capture(2, size=(1920, 1080)), final]
    apply_roundtrip_contracts(captures)

    assert captures[-1]["roundtrip_comparison_gate"]["checks"][
        "geometry_signature_exact"
    ] is False
    assert captures[-1]["passed"] is False


def test_roundtrip_size_rebuilds_first_ordinal_only(monkeypatch):
    calls = []

    def fake_configure(app, size, monitor_target, *, rebuild_validation_screen):
        calls.append((size, rebuild_validation_screen))
        return {"validation_screen_rebuilt": rebuild_validation_screen}

    monkeypatch.setattr(capture_tool, "_configure_size", fake_configure)
    app = object()
    capture_tool._configure_size(
        app,
        (2560, 1392),
        None,
        rebuild_validation_screen=True,
    )
    for ordinal, size in enumerate(
        ((1366, 768), (1920, 1080), (1366, 768)),
        start=1,
    ):
        capture_tool._configure_roundtrip_size(app, size, ordinal)

    assert calls == [
        ((2560, 1392), True),
        ((1366, 768), True),
        ((1920, 1080), False),
        ((1366, 768), False),
    ]


def test_roundtrip_contract_rejects_later_rebuild_and_object_identity_drift():
    rebuilt = [
        _roundtrip_capture(1),
        _roundtrip_capture(2, size=(1920, 1080)),
        _roundtrip_capture(3),
    ]
    rebuilt[1]["roundtrip_rebuild_applied"] = True
    apply_roundtrip_contracts(rebuilt)
    rebuilt_checks = rebuilt[-1]["roundtrip_comparison_gate"]["checks"]
    assert rebuilt_checks["later_ordinals_not_rebuilt"] is False
    assert rebuilt[-1]["passed"] is False

    identity_drift = [
        _roundtrip_capture(1),
        _roundtrip_capture(2, size=(1920, 1080)),
        _roundtrip_capture(3),
    ]
    identity_drift[1]["roundtrip_widget_identity"]["tree_object_ids"][1][
        "python_object_id"
    ] = 202
    identity_drift[1]["roundtrip_widget_identity"]["key_widget_object_ids"] = {
        attr: 202 for attr in capture_tool.ROUNDTRIP_KEY_WIDGET_ATTRS
    }
    identity_drift[1]["roundtrip_signatures"] = build_roundtrip_signatures(
        identity_drift[1]
    )
    apply_roundtrip_contracts(identity_drift)

    identity_checks = identity_drift[-1]["roundtrip_comparison_gate"]["checks"]
    assert identity_checks["widget_path_signature_stable"] is True
    assert identity_checks["widget_identity_signature_stable"] is False
    assert identity_drift[-1]["passed"] is False


def test_roundtrip_contract_rejects_missing_or_empty_identity_payload():
    captures = [
        _roundtrip_capture(1),
        _roundtrip_capture(2, size=(1920, 1080)),
        _roundtrip_capture(3),
    ]
    for capture in captures:
        capture["roundtrip_widget_identity"] = {}
        capture["roundtrip_signatures"] = build_roundtrip_signatures(capture)

    apply_roundtrip_contracts(captures)

    checks = captures[-1]["roundtrip_comparison_gate"]["checks"]
    assert checks["widget_identity_payload_complete"] is False
    assert checks["widget_path_signature_stable"] is False
    assert checks["widget_identity_signature_stable"] is False
    assert captures[-1]["passed"] is False


def test_roundtrip_widget_identity_missing_key_widget_fails_closed():
    class FakeWidget:
        master = None

        def __str__(self):
            return "."

        def winfo_class(self):
            return "Tk"

        def winfo_children(self):
            return ()

    root = FakeWidget()
    attrs = {
        attr: root for attr in capture_tool.ROUNDTRIP_KEY_WIDGET_ATTRS
    }
    attrs.pop("follow_up_label")
    app = SimpleNamespace(root=root, **attrs)

    with pytest.raises(RuntimeError, match="follow_up_label"):
        capture_tool.collect_roundtrip_widget_identity(app)
