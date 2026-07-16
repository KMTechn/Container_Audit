from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

import tools.packaged_real_ui_driver as driver_module
import tools.manual_real_ui_walkthrough_capture as manual_module
from tools.manual_real_ui_walkthrough_capture import (
    analyze_capture_image,
    annotate_manual_capture_geometry,
    capture_review_status,
    manual_report_status,
)
from tools.packaged_real_ui_driver import (
    ClipboardSnapshot,
    Driver,
    analyze_inline_warning_visual,
    annotate_requested_capture_size,
    capture_clipboard_snapshot,
    clipboard_snapshot_matches_baseline,
    clipboard_snapshot_is_supported,
    evaluate_inline_warning_visual_disappearance,
    evaluate_inline_warning_visual_signal,
    inventory_root_files,
    isolated_roots_are_clean_and_safe,
    main_screenshots_match_requested_size,
    roots_are_distinct_and_non_overlapping,
    write_artifact_hashes,
)


def _manifest_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, relative_path = line.split("  ", 1)
        entries[relative_path] = digest
    return entries


def _warning_test_frame(
    *,
    banner: bool = False,
    right_sidebar: bool = False,
    size: tuple[int, int] = (1000, 600),
    banner_y_ratio: float = 0.43,
) -> Image.Image:
    width, height = size
    image = Image.new("RGB", size, (245, 248, 252))
    draw = ImageDraw.Draw(image)
    if banner:
        banner_bottom_ratio = banner_y_ratio + 0.05
        draw.rectangle(
            (
                int(width * 0.245),
                int(height * banner_y_ratio),
                int(width * 0.775),
                int(height * banner_bottom_ratio),
            ),
            fill=(255, 246, 246),
            outline=(255, 150, 150),
            width=3,
        )
        draw.rectangle(
            (
                int(width * 0.70),
                int(height * (banner_y_ratio + 0.008)),
                int(width * 0.76),
                int(height * (banner_bottom_ratio - 0.008)),
            ),
            fill=(180, 25, 25),
        )
    if right_sidebar:
        draw.rectangle(
            (
                int(width * 0.83),
                int(height * 0.333),
                int(width * 0.97),
                int(height * 0.65),
            ),
            fill=(255, 245, 245),
            outline=(220, 30, 30),
            width=5,
        )
        draw.rectangle(
            (
                int(width * 0.86),
                int(height * 0.417),
                int(width * 0.94),
                int(height * 0.558),
            ),
            fill=(185, 20, 20),
        )
    return image


def test_inline_warning_visual_detects_central_red_banner_against_baseline():
    baseline = analyze_inline_warning_visual(_warning_test_frame())
    warning = analyze_inline_warning_visual(_warning_test_frame(banner=True))

    proof = evaluate_inline_warning_visual_signal(baseline, warning)

    assert proof["signal_detected"] is True
    assert proof["method"] == (
        "central_pane_broad_vertical_red_border_and_pale_fill_v2"
    )
    assert proof["ocr_used"] is False
    assert proof["visual_text_match_claimed"] is False
    assert warning["roi_role"] == "central_warning_band_only_right_sidebar_excluded"
    assert proof["comparison"]["pink_border_run_ratio_delta_from_baseline"] >= 0.20
    assert proof["comparison"]["pale_fill_ratio_delta_from_baseline"] >= 0.04


@pytest.mark.parametrize(
    ("size", "banner_y_ratio"),
    [
        ((1366, 768), 0.44),
        ((1440, 900), 0.46),
        ((1920, 1080), 0.40),
        ((2560, 1080), 0.36),
        ((2560, 1392), 0.33),
    ],
)
def test_inline_warning_visual_signature_scales_with_supported_geometry(
    size,
    banner_y_ratio,
):
    baseline = analyze_inline_warning_visual(_warning_test_frame(size=size))
    warning = analyze_inline_warning_visual(
        _warning_test_frame(
            banner=True,
            size=size,
            banner_y_ratio=banner_y_ratio,
        )
    )

    proof = evaluate_inline_warning_visual_signal(baseline, warning)

    assert proof["signal_detected"] is True
    assert warning["image_size"] == list(size)


def test_inline_warning_visual_rejects_absent_banner():
    baseline = analyze_inline_warning_visual(_warning_test_frame())
    unchanged = analyze_inline_warning_visual(_warning_test_frame())

    proof = evaluate_inline_warning_visual_signal(baseline, unchanged)

    assert proof["signal_detected"] is False


def test_inline_warning_visual_rejects_right_sidebar_red_status_only():
    baseline = analyze_inline_warning_visual(_warning_test_frame())
    sidebar_only = analyze_inline_warning_visual(
        _warning_test_frame(right_sidebar=True)
    )

    proof = evaluate_inline_warning_visual_signal(baseline, sidebar_only)

    assert proof["signal_detected"] is False
    assert sidebar_only["metrics"]["strong_red_pixel_count"] == 0


def test_inline_warning_visual_rejects_stale_banner_after_enter():
    baseline = analyze_inline_warning_visual(_warning_test_frame())
    warning = analyze_inline_warning_visual(_warning_test_frame(banner=True))
    warning_proof = evaluate_inline_warning_visual_signal(baseline, warning)

    disappearance = evaluate_inline_warning_visual_disappearance(
        warning_proof,
        analyze_inline_warning_visual(_warning_test_frame(banner=True)),
    )

    assert warning_proof["signal_detected"] is True
    assert disappearance["disappeared_after_enter"] is False
    assert disappearance["comparison"]["red_pixel_ratio_drop_from_warning"] == 0


def test_inline_warning_visual_disappearance_requires_a_positive_pre_signal():
    baseline = analyze_inline_warning_visual(_warning_test_frame())
    missing_warning = evaluate_inline_warning_visual_signal(baseline, baseline)

    disappearance = evaluate_inline_warning_visual_disappearance(
        missing_warning,
        analyze_inline_warning_visual(_warning_test_frame()),
    )

    assert missing_warning["signal_detected"] is False
    assert disappearance["disappeared_after_enter"] is False


def test_capture_analysis_flags_partial_black_frame_but_accepts_normal_frame():
    clipped = Image.new("RGB", (100, 100), "white")
    clipped.paste("black", (0, 0, 60, 100))
    clipped_metrics = analyze_capture_image(clipped)

    normal = Image.new("RGB", (100, 100), "white")
    normal.paste("black", (0, 0, 5, 100))
    normal_metrics = analyze_capture_image(normal)

    assert clipped_metrics["blank_suspected"] is False
    assert clipped_metrics["exact_black_ratio"] == 0.6
    assert clipped_metrics["excess_black_suspected"] is True
    assert capture_review_status(clipped_metrics) == "REVIEW"
    assert normal_metrics["exact_black_ratio"] == 0.05
    assert normal_metrics["excess_black_suspected"] is False
    assert capture_review_status(normal_metrics) == "PASS"


def test_artifact_manifest_refresh_tracks_the_final_report_bytes(tmp_path):
    report_path = tmp_path / "real_ui_no_human_walkthrough_report.json"
    report_path.write_text('{"status":"PASS"}', encoding="utf-8")
    write_artifact_hashes(tmp_path)

    report_path.write_text(
        '{"status":"PASS","clipboard_restore_status":"PASS"}',
        encoding="utf-8",
    )
    write_artifact_hashes(tmp_path)

    entries = _manifest_entries(tmp_path / "artifact_hashes.sha256")
    assert entries[report_path.name] == hashlib.sha256(report_path.read_bytes()).hexdigest()


def test_requested_geometry_rejects_dpi_expanded_capture_size():
    expanded = {"width": 2184, "height": 1409}
    exact = {"width": 1440, "height": 900}
    invalid = {"width": 1440, "height": 900}

    annotate_requested_capture_size(expanded, "1440x900+0+0")
    annotate_requested_capture_size(exact, "1440x900+3840+326")
    annotate_requested_capture_size(invalid, "not-a-geometry")

    assert expanded["requested_pixel_size"] == [1440, 900]
    assert expanded["screenshot_role"] == "main"
    assert expanded["pixel_size_matches_requested"] is False
    assert exact["pixel_size_matches_requested"] is True
    assert invalid["requested_geometry_valid"] is False
    assert invalid["pixel_size_matches_requested"] is False


def test_requested_size_gate_ignores_dialog_but_requires_an_exact_main_capture():
    main = {"width": 1440, "height": 900}
    annotate_requested_capture_size(main, "1440x900+0+0")
    dialog = {
        "width": 640,
        "height": 480,
        "screenshot_role": "dialog_or_child",
        "requested_size_gate_applicable": False,
    }

    assert main_screenshots_match_requested_size([main, dialog]) is True
    assert main_screenshots_match_requested_size([dialog]) is False

    main["pixel_size_matches_requested"] = False
    assert main_screenshots_match_requested_size([main, dialog]) is False


def test_driver_finalization_hashes_report_after_clipboard_restore(tmp_path, monkeypatch):
    driver = Driver.__new__(Driver)
    driver.output_root = tmp_path
    driver.original_clipboard = ClipboardSnapshot("TEXT", "operator clipboard")
    driver.clipboard_mutated = True
    driver.report = {"status": "PASS"}
    driver.source_snapshot_bytes = {
        "driver_source_snapshot.py": b"executed driver bytes",
        "capture_helper_source_snapshot.py": b"executed helper bytes",
    }
    driver.process = None
    driver.args = type("Args", (), {"keep_running": False})()
    restored: list[str] = []
    monkeypatch.setattr(driver_module, "set_clipboard_text", restored.append)
    monkeypatch.setattr(
        driver_module,
        "capture_clipboard_snapshot",
        lambda: ClipboardSnapshot("TEXT", "operator clipboard"),
    )

    driver._finalize_evidence()

    report_path = tmp_path / "real_ui_no_human_walkthrough_report.json"
    entries = _manifest_entries(tmp_path / "artifact_hashes.sha256")
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert restored == ["operator clipboard"]
    assert payload["clipboard_restore_status"] == "PASS_VERIFIED"
    assert payload["pass_checks"]["clipboard_restore"] is True
    for name, expected_bytes in driver.source_snapshot_bytes.items():
        assert (tmp_path / name).read_bytes() == expected_bytes
        assert entries[name] == hashlib.sha256(expected_bytes).hexdigest()
    assert entries[report_path.name] == hashlib.sha256(report_path.read_bytes()).hexdigest()


def test_clipboard_restore_failure_fails_final_report(tmp_path, monkeypatch):
    driver = Driver.__new__(Driver)
    driver.output_root = tmp_path
    driver.original_clipboard = ClipboardSnapshot("TEXT", "operator clipboard")
    driver.clipboard_mutated = True
    driver.report = {"status": "PASS", "pass_checks": {"events": True}}
    driver.source_snapshot_bytes = {"driver_source_snapshot.py": b"driver"}

    def fail_restore(_text):
        raise OSError("clipboard unavailable")

    monkeypatch.setattr(driver_module, "set_clipboard_text", fail_restore)
    cleared: list[bool] = []
    monkeypatch.setattr(driver_module, "clear_clipboard", lambda: cleared.append(True))
    monkeypatch.setattr(
        driver_module,
        "capture_clipboard_snapshot",
        lambda: ClipboardSnapshot("EMPTY"),
    )
    driver._finalize_evidence()

    payload = json.loads(
        (tmp_path / "real_ui_no_human_walkthrough_report.json").read_text(encoding="utf-8")
    )
    assert payload["status"] == "FAIL"
    assert payload["clipboard_restore_status"] == "FAILED_CLEARED_SAFE"
    assert cleared == [True]
    assert payload["pass_checks"]["clipboard_restore"] is False
    assert payload["pass_checks"]["clipboard_scan_value_removed"] is True


def test_clipboard_restore_readback_mismatch_clears_scanner_value_and_fails(
    tmp_path,
    monkeypatch,
):
    driver = Driver.__new__(Driver)
    driver.output_root = tmp_path
    driver.original_clipboard = ClipboardSnapshot("TEXT", "operator clipboard")
    driver.clipboard_mutated = True
    driver.report = {"status": "PASS"}
    driver.source_snapshot_bytes = {"driver_source_snapshot.py": b"driver"}
    monkeypatch.setattr(driver_module, "set_clipboard_text", lambda _text: None)
    monkeypatch.setattr(driver_module, "clear_clipboard", lambda: None)
    snapshots = iter(
        (
            ClipboardSnapshot("TEXT", "scanner-value"),
            ClipboardSnapshot("EMPTY"),
        )
    )
    monkeypatch.setattr(
        driver_module,
        "capture_clipboard_snapshot",
        lambda: next(snapshots),
    )

    driver._finalize_evidence()

    payload = json.loads(
        (tmp_path / "real_ui_no_human_walkthrough_report.json").read_text(encoding="utf-8")
    )
    assert payload["status"] == "FAIL"
    assert payload["clipboard_restore_status"] == "FAILED_CLEARED_SAFE"
    assert payload["pass_checks"]["clipboard_scan_value_removed"] is True


def test_empty_clipboard_baseline_is_cleared_and_verified(tmp_path, monkeypatch):
    driver = Driver.__new__(Driver)
    driver.output_root = tmp_path
    driver.original_clipboard = ClipboardSnapshot("EMPTY")
    driver.clipboard_mutated = True
    driver.report = {"status": "PASS"}
    driver.source_snapshot_bytes = {"driver_source_snapshot.py": b"driver"}
    cleared: list[bool] = []
    monkeypatch.setattr(driver_module, "clear_clipboard", lambda: cleared.append(True))
    monkeypatch.setattr(
        driver_module,
        "capture_clipboard_snapshot",
        lambda: ClipboardSnapshot("EMPTY"),
    )

    driver._finalize_evidence()

    payload = json.loads(
        (tmp_path / "real_ui_no_human_walkthrough_report.json").read_text(encoding="utf-8")
    )
    assert cleared == [True]
    assert payload["status"] == "PASS"
    assert payload["clipboard_restore_status"] == "PASS_VERIFIED"


def test_finish_run_finalizes_even_when_process_teardown_fails(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.report = {"status": "PASS"}
    finalized: list[bool] = []

    def fail_stop():
        raise OSError("terminate failed")

    monkeypatch.setattr(driver, "_stop_process", fail_stop)
    monkeypatch.setattr(driver, "_finalize_evidence", lambda: finalized.append(True))
    driver._finish_run()

    assert finalized == [True]
    assert driver.report["status"] == "FAIL"
    assert "terminate failed" in driver.report["teardown_error"]


def test_required_inline_warning_rejects_toplevel(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.hwnd = 101
    steps: list[dict[str, object]] = []
    captures: list[tuple[int, str]] = []
    monkeypatch.setattr(
        driver,
        "step",
        lambda name, status, **extra: steps.append(
            {"name": name, "status": status, **extra}
        ),
    )
    monkeypatch.setattr(driver, "capture_hwnd", lambda hwnd, label: captures.append((hwnd, label)))

    monkeypatch.setattr(driver, "find_process_window", lambda **_kwargs: None)
    monkeypatch.setattr(driver, "main_window_texts", lambda: [])
    assert driver.capture_warning(
        "duplicate",
        require_inline=True,
        inline_text_fragments=["바코드 중복", "이미 스캔", "확인"],
    ) is False
    assert steps[-1]["presentation"] == "inline_not_proven"
    assert steps[-1]["status"] == "FAIL"

    monkeypatch.setattr(
        driver,
        "main_window_texts",
        lambda: ["바코드 중복!", "이미 스캔되었습니다.", "확인"],
    )
    assert driver.capture_warning(
        "duplicate",
        require_inline=True,
        inline_text_fragments=["바코드 중복", "이미 스캔", "확인"],
    ) is True
    assert steps[-1]["presentation"] == "inline"
    assert steps[-1]["status"] == "PASS"
    assert steps[-1]["all_fragments_matched"] is True

    monkeypatch.setattr(
        driver,
        "find_process_window",
        lambda **_kwargs: {"hwnd": 42, "title": "unexpected modal"},
    )
    assert driver.capture_warning(
        "duplicate",
        require_inline=True,
        inline_text_fragments=["바코드 중복", "이미 스캔", "확인"],
    ) is False
    assert captures[-1] == (42, "duplicate_unexpected_toplevel")
    assert steps[-1]["presentation"] == "toplevel"
    assert steps[-1]["status"] == "FAIL"


def test_inline_warning_does_not_treat_ambiguous_toplevels_as_absent(
    monkeypatch,
):
    driver = Driver.__new__(Driver)
    driver.hwnd = 101
    driver.last_process_window_selection_error = {
        "reason": "ambiguous_matching_windows",
        "candidate_hwnds": [41, 42],
    }
    steps: list[dict[str, object]] = []
    monkeypatch.setattr(driver, "find_process_window", lambda **_kwargs: None)
    monkeypatch.setattr(
        driver,
        "main_window_texts",
        lambda: ["바코드 중복", "이미 스캔되었습니다", "확인"],
    )
    monkeypatch.setattr(
        driver,
        "step",
        lambda name, status, **extra: steps.append(
            {"name": name, "status": status, **extra}
        ),
    )

    assert driver.capture_warning(
        "duplicate",
        require_inline=True,
        inline_text_fragments=["바코드 중복", "이미 스캔", "확인"],
    ) is False
    assert steps[-1]["status"] == "FAIL"
    assert steps[-1]["presentation"] == "ambiguous_toplevel_candidates"


def test_visual_inline_warning_fallback_records_signal_and_enter_disappearance(
    tmp_path,
    monkeypatch,
):
    baseline_path = tmp_path / "baseline.png"
    warning_path = tmp_path / "warning.png"
    after_path = tmp_path / "after.png"
    _warning_test_frame().save(baseline_path)
    _warning_test_frame(banner=True).save(warning_path)
    driver = Driver.__new__(Driver)
    driver.hwnd = 101
    driver.report = {
        "screenshots": [
            {
                "label": "product_scan_1",
                "path": str(baseline_path),
                "screenshot_role": "main",
            },
            {
                "label": "duplicate_product_warning",
                "path": str(warning_path),
                "screenshot_role": "main",
            },
        ]
    }
    steps: list[dict[str, object]] = []
    monkeypatch.setattr(driver, "find_process_window", lambda **_kwargs: None)
    monkeypatch.setattr(driver, "main_window_texts", lambda: [])
    monkeypatch.setattr(driver, "press_enter", lambda: None)
    monkeypatch.setattr(driver_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        driver,
        "step",
        lambda name, status, **extra: steps.append(
            {"name": name, "status": status, **extra}
        ),
    )

    def capture_after(label):
        _warning_test_frame().save(after_path)
        driver.report["screenshots"].append(
            {
                "label": label,
                "path": str(after_path),
                "screenshot_role": "main",
            }
        )

    monkeypatch.setattr(driver, "capture", capture_after)

    assert driver.capture_warning(
        "duplicate",
        require_inline=True,
        inline_text_fragments=["바코드 중복", "이미 스캔", "확인"],
        inline_visual_screenshot_label="duplicate_product_warning",
    ) is True
    warning_step = steps[-1]
    assert warning_step["presence_proof_method"] == (
        "central_pane_broad_vertical_red_border_and_pale_fill_v2"
    )
    assert warning_step["all_fragments_matched"] is False
    assert warning_step["visual_signal_detected"] is True
    assert warning_step["visual_fallback"]["ocr_used"] is False
    wording = warning_step["wording_verification"]
    assert wording["automated_accessibility_text_verified"] is False
    assert wording["visual_signal_proves_wording"] is False
    assert wording["human_text_review_required"] is True
    assert wording["human_text_review_status"] == (
        "REQUIRED_EXTERNAL_CANDIDATE_AUDIT_ATTESTATION"
    )

    driver.dismiss_warning(post_inline_capture_label="duplicate_warning_dismissed")

    dismiss_step = steps[-1]
    assert dismiss_step["status"] == "PASS"
    assert dismiss_step["inline_presence_signal_disappeared"] is True
    assert dismiss_step["visual_presence_signal_disappeared"] is True
    assert dismiss_step["visual_disappearance_proof"]["ocr_used"] is False


def test_secondary_toplevel_with_main_like_title_is_not_excluded(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.hwnd = 10
    driver.args = type("Args", (), {"window_title_pattern": r"Audit"})()
    monkeypatch.setattr(
        driver,
        "process_windows",
        lambda: [
            {"hwnd": 10, "title": "Container Audit", "rect": [0, 0, 1440, 900]},
            {"hwnd": 11, "title": "Container Audit warning", "rect": [10, 10, 500, 300]},
        ],
    )

    found = driver.find_process_window(exclude_main=True, timeout=0.1)

    assert found is not None
    assert found["hwnd"] == 11


def test_ambiguous_same_process_child_windows_are_not_selected(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.hwnd = 10
    driver.args = type("Args", (), {"window_title_pattern": r"Audit"})()
    monkeypatch.setattr(
        driver,
        "process_windows",
        lambda: [
            {"hwnd": 10, "title": "Container Audit", "rect": [0, 0, 1440, 900]},
            {"hwnd": 11, "title": "Warning", "rect": [10, 10, 500, 300]},
            {"hwnd": 12, "title": "Warning", "rect": [20, 20, 520, 320]},
        ],
    )

    found = driver.find_process_window(
        title_pattern=r"Warning",
        exclude_main=True,
        timeout=0.05,
    )

    assert found is None
    assert driver.last_process_window_selection_error == {
        "reason": "ambiguous_matching_windows",
        "candidate_count": 2,
        "candidate_hwnds": [11, 12],
        "title_pattern": r"Warning",
        "exclude_main": True,
    }


def test_exact_foreground_guard_rejects_different_hwnd_from_same_process(
    monkeypatch,
):
    driver = Driver.__new__(Driver)
    driver.hwnd = 10
    driver.process = type("Process", (), {"pid": 77})()
    monkeypatch.setattr(
        driver_module.win32process,
        "GetWindowThreadProcessId",
        lambda _hwnd: (1, 77),
    )
    monkeypatch.setattr(
        driver_module.win32gui,
        "GetForegroundWindow",
        lambda: 11,
    )
    monkeypatch.setattr(driver_module.win32gui, "ShowWindow", lambda *_args: None)
    monkeypatch.setattr(
        driver_module.win32gui,
        "SetForegroundWindow",
        lambda _hwnd: None,
    )
    monkeypatch.setattr(
        driver_module.win32gui,
        "GetWindowText",
        lambda _hwnd: "same process popup",
    )
    monkeypatch.setattr(driver_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="exact target hwnd"):
        driver.ensure_target_foreground()


def test_process_window_raw_key_sequence_guards_selected_child_before_input(
    monkeypatch,
):
    driver = Driver.__new__(Driver)
    driver.hwnd = 10
    driver.args = type(
        "Args",
        (),
        {"action_delay": 0, "window_title_pattern": r"Audit"},
    )()
    events: list[object] = []
    driver.keyboard = type(
        "Keyboard",
        (),
        {"send_keys": lambda _self, keys: events.append(("key", keys))},
    )()
    monkeypatch.setattr(
        driver,
        "find_process_window",
        lambda **_kwargs: {
            "hwnd": 11,
            "title": "Exchange",
            "rect": [100, 100, 600, 500],
        },
    )
    monkeypatch.setattr(driver, "verify_process_window", lambda hwnd: events.append(("verify", hwnd)))
    monkeypatch.setattr(driver, "move_child_window_near_main", lambda hwnd: events.append(("move", hwnd)))
    monkeypatch.setattr(driver_module.win32gui, "GetWindowRect", lambda _hwnd: (100, 100, 600, 500))
    monkeypatch.setattr(driver, "click_in_rect", lambda *_args: events.append("click"))
    monkeypatch.setattr(driver, "ensure_window_foreground", lambda hwnd: events.append(("guard", hwnd)))
    monkeypatch.setattr(driver, "_set_clipboard_for_input", lambda _value: events.append("clipboard"))
    monkeypatch.setattr(driver_module.time, "sleep", lambda _seconds: None)

    assert driver.send_text_enter_to_process_window(
        r"Exchange",
        "redacted input",
        0.3,
        0.8,
        timeout=0.1,
    ) is True

    assert events.index(("guard", 11)) < events.index("clipboard")
    assert events.index("clipboard") < events.index(("key", "^a"))


def test_inline_warning_ack_requires_warning_text_to_disappear(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.pending_inline_warning_fragments = ["바코드 중복", "이미 스캔", "확인"]
    steps: list[dict[str, object]] = []
    monkeypatch.setattr(driver, "find_process_window", lambda **_kwargs: None)
    monkeypatch.setattr(driver, "press_enter", lambda: None)
    monkeypatch.setattr(driver, "main_window_texts", lambda: ["스캐너 준비", "다음 제품 스캔"])
    monkeypatch.setattr(driver_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        driver,
        "step",
        lambda name, status, **extra: steps.append(
            {"name": name, "status": status, **extra}
        ),
    )

    driver.dismiss_warning()

    assert steps[-1]["status"] == "PASS"
    assert steps[-1]["inline_presence_signal_disappeared"] is True


def test_scan_without_focus_click_requires_expected_event_increment(monkeypatch):
    driver = Driver.__new__(Driver)
    driver.args = type("Args", (), {"action_delay": 0})()
    driver.keyboard = type("Keyboard", (), {"send_keys": lambda _self, _keys: None})()
    steps: list[dict[str, object]] = []
    clicks: list[bool] = []
    event_counts = iter((4, 5))
    monkeypatch.setattr(driver, "event_count", lambda _event: next(event_counts))
    monkeypatch.setattr(driver, "click_main_scan_entry", lambda: clicks.append(True))
    monkeypatch.setattr(driver, "ensure_target_foreground", lambda: None)
    monkeypatch.setattr(driver, "capture", lambda _name: None)
    monkeypatch.setattr(
        driver,
        "step",
        lambda name, status, **extra: steps.append(
            {"name": name, "status": status, **extra}
        ),
    )
    monkeypatch.setattr(driver_module, "set_clipboard_text", lambda _value: None)
    monkeypatch.setattr(driver_module.time, "sleep", lambda _seconds: None)

    driver.scan(
        "redacted-test-value",
        "product_2_sent",
        "product_scan_2",
        focus_entry=False,
        expected_event="SCAN_OK",
    )

    assert clicks == []
    assert steps[-1]["status"] == "PASS"
    assert steps[-1]["focus_entry_clicked"] is False
    assert steps[-1]["event_increment"] == 1


@pytest.mark.parametrize("failed_status", ["FAIL", "REVIEW"])
def test_non_duplicate_collect_evidence_cannot_pass_with_non_pass_driver_step(
    tmp_path,
    failed_status,
):
    data_root = tmp_path / "data"
    events_dir = data_root / "events"
    events_dir.mkdir(parents=True)
    (events_dir / "events.csv").write_text(
        "event,details\nWORK_START,\"{}\"\n",
        encoding="utf-8",
    )
    output_root = tmp_path / "evidence"
    output_root.mkdir()
    driver = Driver.__new__(Driver)
    driver.data_root = data_root
    driver.output_root = output_root
    driver.args = type(
        "Args",
        (),
        {
            "scenario": "invalid-warning",
            "do_duplicate_warning": False,
            "geometry": "1440x900+0+0",
        },
    )()
    capture = {
        "path": str(tmp_path / "not-read-by-collector.png"),
        "width": 1440,
        "height": 900,
        "blank_suspected": False,
        "excess_black_suspected": False,
    }
    annotate_requested_capture_size(capture, driver.args.geometry)
    driver.report = {
        "steps": [{"name": "invalid_warning_missing", "status": failed_status}],
        "screenshots": [capture],
    }
    driver.initial_event_row_count = 0
    driver.initial_output_file_count = 0
    driver.initial_data_file_count = 0
    driver.clean_start_ok = True

    driver.collect_evidence()

    assert driver.report["pass_checks"]["driver_steps_all_pass"] is False
    assert driver.report["status"] == "FAIL"


def test_clean_start_inventory_rejects_tray_state_overlap_and_reparse_roots(tmp_path):
    output_root = tmp_path / "evidence"
    data_root = tmp_path / "data"
    output_root.mkdir()
    data_root.mkdir()
    tray_state = data_root / "events" / "_current_tray_state_workstation.json"
    tray_state.parent.mkdir()
    tray_state.write_text("{}", encoding="utf-8")

    output_files = inventory_root_files(output_root)
    data_files = inventory_root_files(data_root)

    assert output_files == []
    assert data_files == [Path("events/_current_tray_state_workstation.json")]
    assert isolated_roots_are_clean_and_safe(
        output_files,
        data_files,
        roots_distinct_and_non_overlapping=True,
        output_root_has_reparse_point=False,
        data_root_has_reparse_point=False,
    ) is False
    assert roots_are_distinct_and_non_overlapping(data_root, data_root / "nested") is False
    assert isolated_roots_are_clean_and_safe(
        [],
        [],
        roots_distinct_and_non_overlapping=True,
        output_root_has_reparse_point=True,
        data_root_has_reparse_point=False,
    ) is False


def test_clipboard_snapshot_distinguishes_empty_non_text_and_read_failure(monkeypatch):
    monkeypatch.setattr(driver_module.win32clipboard, "OpenClipboard", lambda: None)
    monkeypatch.setattr(driver_module.win32clipboard, "CloseClipboard", lambda: None)
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "IsClipboardFormatAvailable",
        lambda _format: False,
    )
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "EnumClipboardFormats",
        lambda _current: 0,
    )
    assert capture_clipboard_snapshot() == ClipboardSnapshot("EMPTY")

    formats = iter((1, 0))
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "EnumClipboardFormats",
        lambda _current: next(formats),
    )
    non_text = capture_clipboard_snapshot()
    assert non_text.status == "NON_TEXT"
    assert non_text.formats == (1,)
    assert non_text.unsupported_formats == ()

    def fail_open():
        raise OSError("clipboard busy")

    monkeypatch.setattr(driver_module.win32clipboard, "OpenClipboard", fail_open)
    failed = capture_clipboard_snapshot()
    assert failed.status == "READ_FAILED"
    assert "clipboard busy" in str(failed.error)


def test_clipboard_snapshot_rejects_unicode_mixed_with_custom_format(monkeypatch):
    monkeypatch.setattr(driver_module.win32clipboard, "OpenClipboard", lambda: None)
    monkeypatch.setattr(driver_module.win32clipboard, "CloseClipboard", lambda: None)
    formats = iter((13, 49323, 0))
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "EnumClipboardFormats",
        lambda _current: next(formats),
    )
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "IsClipboardFormatAvailable",
        lambda clipboard_format: clipboard_format == 13,
    )
    monkeypatch.setattr(
        driver_module.win32clipboard,
        "GetClipboardData",
        lambda _clipboard_format: "operator text",
    )

    snapshot = capture_clipboard_snapshot()

    assert snapshot.status == "UNSUPPORTED_FORMATS"
    assert snapshot.text == "operator text"
    assert snapshot.formats == (13, 49323)
    assert snapshot.unsupported_formats == (49323,)
    assert clipboard_snapshot_is_supported(snapshot) is False
    driver = Driver.__new__(Driver)
    driver.clean_start_ok = True
    driver.original_clipboard = snapshot
    driver.clipboard_mutated = False
    with pytest.raises(RuntimeError, match="cannot be preserved exactly"):
        driver._validate_preconditions()
    assert driver.clipboard_mutated is False


def test_non_text_clipboard_preflight_refuses_input_before_mutation():
    driver = Driver.__new__(Driver)
    driver.clean_start_ok = True
    driver.original_clipboard = ClipboardSnapshot("NON_TEXT")
    driver.clipboard_mutated = False

    with pytest.raises(RuntimeError, match="cannot be preserved exactly"):
        driver._validate_preconditions()

    assert driver.clipboard_mutated is False


def test_clipboard_restore_requires_matching_readback():
    assert clipboard_snapshot_matches_baseline(
        ClipboardSnapshot("TEXT", "operator"),
        ClipboardSnapshot("TEXT", "operator"),
    ) is True
    assert clipboard_snapshot_matches_baseline(
        ClipboardSnapshot("TEXT", "operator"),
        ClipboardSnapshot("TEXT", "scanner-value"),
    ) is False
    assert clipboard_snapshot_matches_baseline(
        ClipboardSnapshot("EMPTY"),
        ClipboardSnapshot("EMPTY"),
    ) is True
    assert clipboard_snapshot_matches_baseline(
        ClipboardSnapshot("TEXT", "operator", formats=(13,)),
        ClipboardSnapshot(
            "UNSUPPORTED_FORMATS",
            "operator",
            formats=(13, 49323),
            unsupported_formats=(49323,),
        ),
    ) is False
    assert clipboard_snapshot_is_supported(
        ClipboardSnapshot("TEXT", "operator", formats=(1, 7, 13, 16))
    ) is True


def test_manual_capture_geometry_and_top_level_status_semantics():
    exact = {"width": 1440, "height": 900}
    mismatch = {"width": 1600, "height": 900}
    annotate_manual_capture_geometry(exact, "1440x900+0+0")
    annotate_manual_capture_geometry(mismatch, "1440x900+0+0")

    assert exact["screenshot_role"] == "main"
    assert exact["requested_geometry_check"] == "PASS"
    assert capture_review_status(exact) == "PASS"
    assert mismatch["requested_geometry_check"] == "FAIL"
    assert capture_review_status(mismatch) == "FAIL"
    assert manual_report_status([{"status": "PASS"}]) == "PASS"
    assert manual_report_status([{"status": "REVIEW"}]) == "REVIEW"
    assert manual_report_status([{"status": "SKIPPED"}]) == "REVIEW"
    assert manual_report_status([{"status": "FAIL"}]) == "FAIL"
    assert manual_report_status([{"status": "PASS"}], stopped_early=True) == "REVIEW"


def test_manual_capture_main_returns_nonzero_and_reports_failed_geometry(
    tmp_path,
    monkeypatch,
):
    steps_path = tmp_path / "steps.json"
    steps_path.write_text(
        json.dumps([{"id": "01", "prompt": "capture"}]),
        encoding="utf-8",
    )
    output_root = tmp_path / "output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manual_real_ui_walkthrough_capture.py",
            "--output-root",
            str(output_root),
            "--steps-json",
            str(steps_path),
            "--startup-geometry",
            "1440x900+0+0",
        ],
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr(
        manual_module,
        "find_window",
        lambda _pattern: {"hwnd": 1, "title": "Container Audit", "rect": [0, 0, 1600, 900]},
    )
    monkeypatch.setattr(manual_module, "move_window_to_geometry", lambda *_args: None)
    monkeypatch.setattr(manual_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manual_module,
        "capture_window",
        lambda _hwnd, path: {
            "path": str(path),
            "width": 1600,
            "height": 900,
            "blank_suspected": False,
            "excess_black_suspected": False,
        },
    )

    assert manual_module.main() == 1
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["status"] == "FAIL"
    assert report["steps"][0]["capture"]["actual_pixel_size"] == [1600, 900]
    assert "exit code 2" in report["status_semantics"]["REVIEW"]


@pytest.mark.parametrize("operator_response", ["skip", "stop"])
def test_manual_capture_review_states_exit_two(
    tmp_path,
    monkeypatch,
    operator_response,
):
    steps_path = tmp_path / "steps.json"
    steps_path.write_text(
        json.dumps([{"id": "01", "prompt": "capture"}]),
        encoding="utf-8",
    )
    output_root = tmp_path / "output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manual_real_ui_walkthrough_capture.py",
            "--output-root",
            str(output_root),
            "--steps-json",
            str(steps_path),
        ],
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: operator_response)

    assert manual_module.main() == 2
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["status"] == "REVIEW"


@pytest.mark.parametrize("interrupt_type", [EOFError, KeyboardInterrupt])
def test_manual_capture_interrupt_finalizes_review_report(
    tmp_path,
    monkeypatch,
    interrupt_type,
):
    steps_path = tmp_path / "steps.json"
    steps_path.write_text(
        json.dumps([{"id": "01", "prompt": "capture"}]),
        encoding="utf-8",
    )
    output_root = tmp_path / "output"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manual_real_ui_walkthrough_capture.py",
            "--output-root",
            str(output_root),
            "--steps-json",
            str(steps_path),
        ],
    )

    def interrupt(_prompt):
        raise interrupt_type()

    monkeypatch.setattr("builtins.input", interrupt)

    assert manual_module.main() == 2
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["status"] == "REVIEW"
    assert report["input_interrupted"] == {
        "type": interrupt_type.__name__,
        "step": "01",
    }
    assert report["finished_at"]
