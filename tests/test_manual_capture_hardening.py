from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

import tools.manual_real_ui_walkthrough_capture as manual


def _pass_capture(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "width": 320,
        "height": 200,
        "blank_suspected": False,
        "excess_black_suspected": False,
        "edge_black_stripe_suspected": False,
        "contiguous_black_stripe_suspected": False,
        "uniform_low_variance_suspected": False,
    }


def _write_steps(path: Path, count: int = 1) -> None:
    path.write_text(
        json.dumps(
            [
                {"id": f"{index:02d}", "prompt": f"capture {index}"}
                for index in range(1, count + 1)
            ]
        ),
        encoding="utf-8",
    )


def test_capture_analysis_keeps_varied_operator_ui_passable():
    image = Image.new("RGB", (300, 180), (242, 246, 250))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 299, 24), fill=(28, 57, 88))
    draw.rectangle((15, 40, 92, 165), fill=(226, 233, 241))
    draw.rectangle((105, 40, 214, 165), fill=(255, 255, 255))
    draw.rectangle((227, 40, 285, 165), fill=(235, 241, 246))
    draw.rectangle((120, 60, 198, 88), fill=(35, 116, 196))
    draw.line((120, 110, 196, 110), fill=(81, 94, 108), width=3)
    draw.line((120, 125, 180, 125), fill=(81, 94, 108), width=3)

    metrics = manual.analyze_capture_image(image)

    assert metrics["contiguous_black_stripe_suspected"] is False
    assert metrics["uniform_low_variance_suspected"] is False
    assert manual.capture_review_status(metrics) == "PASS"


@pytest.mark.parametrize("orientation", ["horizontal", "vertical"])
def test_capture_analysis_reviews_contiguous_thirty_percent_black_stripe(
    orientation,
):
    image = Image.new("RGB", (100, 100), (235, 240, 245))
    draw = ImageDraw.Draw(image)
    if orientation == "horizontal":
        draw.rectangle((0, 70, 99, 99), fill=(0, 0, 0))
    else:
        draw.rectangle((70, 0, 99, 99), fill=(0, 0, 0))

    metrics = manual.analyze_capture_image(image)

    assert metrics["near_black_ratio"] == pytest.approx(0.30)
    assert metrics["excess_black_suspected"] is False
    assert metrics["edge_black_stripe_suspected"] is True
    assert metrics["contiguous_black_stripe_suspected"] is True
    assert manual.capture_review_status(metrics) == "REVIEW"


def test_capture_analysis_reviews_uniform_gray_low_variance_frame():
    image = Image.new("RGB", (160, 90), (128, 128, 128))

    metrics = manual.analyze_capture_image(image)

    assert metrics["blank_suspected"] is False
    assert metrics["luma_stddev"] == 0.0
    assert metrics["dominant_color"] == [128, 128, 128]
    assert metrics["dominant_color_ratio"] == 1.0
    assert metrics["uniform_low_variance_suspected"] is True
    assert manual.capture_review_status(metrics) == "REVIEW"


def test_capture_analysis_reviews_alternating_low_variance_gray_frame():
    image = Image.new("RGB", (160, 90))
    image.putdata(
        [
            (127, 127, 127) if index % 2 == 0 else (129, 129, 129)
            for index in range(image.width * image.height)
        ]
    )

    metrics = manual.analyze_capture_image(image)

    assert metrics["luma_stddev"] == 1.0
    assert metrics["dominant_color_ratio"] == 0.5
    assert metrics["uniform_low_variance_suspected"] is True
    assert manual.capture_review_status(metrics) == "REVIEW"


def test_capture_analysis_reviews_noisy_ninety_seven_percent_width_stripe():
    image = Image.new("RGB", (100, 100), (235, 240, 245))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 69, 96, 99), fill=(0, 0, 0))

    metrics = manual.analyze_capture_image(image)

    assert metrics["near_black_ratio"] == pytest.approx(0.3007)
    assert metrics["excess_black_suspected"] is False
    assert metrics["black_line_coverage_threshold"] == 0.95
    assert metrics["edge_near_black_row_run_ratio"] == pytest.approx(0.31)
    assert metrics["contiguous_black_stripe_suspected"] is True
    assert manual.capture_review_status(metrics) == "REVIEW"


def test_default_title_pattern_matches_current_korean_window(monkeypatch):
    monkeypatch.setattr(
        manual,
        "_visible_windows",
        lambda: [
            {
                "hwnd": 31,
                "pid": 410,
                "title": "이적 검사 시스템",
                "rect": [0, 0, 1440, 900],
            }
        ],
    )

    assert manual.find_window(manual.DEFAULT_WINDOW_TITLE_PATTERN)["hwnd"] == 31


def test_find_window_filters_same_title_by_expected_pid_and_retained_hwnd(
    monkeypatch,
):
    windows = [
        {
            "hwnd": 11,
            "pid": 101,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 900, 600],
        },
        {
            "hwnd": 22,
            "pid": 202,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 1600, 900],
        },
        {
            "hwnd": 23,
            "pid": 202,
            "title": "이적 검사 시스템 - 다른 창",
            "rect": [0, 0, 1000, 700],
        },
    ]
    monkeypatch.setattr(manual, "_visible_windows", lambda: windows)

    assert manual.find_window("이적 검사", expected_pid=101)["hwnd"] == 11
    assert manual.find_window(
        "이적 검사", expected_pid=202, expected_hwnd=23
    )["hwnd"] == 23
    with pytest.raises(RuntimeError, match="expected_pid=303"):
        manual.find_window("이적 검사", expected_pid=303)
    with pytest.raises(RuntimeError, match="expected_hwnd=11"):
        manual.find_window("이적 검사", expected_pid=202, expected_hwnd=11)


def test_attach_without_expected_pid_marks_top_level_report_review(
    tmp_path,
    monkeypatch,
):
    steps_path = tmp_path / "steps.json"
    _write_steps(steps_path, count=2)
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
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    calls: list[dict[str, int]] = []

    def fake_find(_pattern, **kwargs):
        calls.append(kwargs)
        return {
            "hwnd": 11,
            "pid": 101,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 320, 200],
        }

    monkeypatch.setattr(manual, "find_window", fake_find)
    monkeypatch.setattr(manual, "capture_window", lambda _hwnd, path: _pass_capture(path))

    assert manual.main() == 2
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert [step["status"] for step in report["steps"]] == ["PASS", "PASS"]
    assert calls == [
        {},
        {"expected_pid": 101, "expected_hwnd": 11},
        {"expected_pid": 101, "expected_hwnd": 11},
    ]
    assert report["status"] == "REVIEW"
    assert report["target_identity"] == {
        "mode": "attach",
        "pid_source": "first_observed_window",
        "expected_pid": None,
        "retained_pid": 101,
        "retained_hwnd": 11,
        "status": "BOUND_REVIEW_REQUIRED",
        "review_reason": (
            "attach mode did not provide --expected-pid; same-title window "
            "selection is not authoritative"
        ),
    }


def test_attach_without_expected_pid_does_not_fallback_when_bound_hwnd_disappears(
    tmp_path,
    monkeypatch,
):
    steps_path = tmp_path / "steps.json"
    _write_steps(steps_path, count=2)
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
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    calls: list[dict[str, int]] = []

    def fake_find(_pattern, **kwargs):
        calls.append(kwargs)
        if len(calls) == 3:
            raise RuntimeError("retained HWND disappeared")
        return {
            "hwnd": 11,
            "pid": 101,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 320, 200],
        }

    monkeypatch.setattr(manual, "find_window", fake_find)
    monkeypatch.setattr(manual, "capture_window", lambda _hwnd, path: _pass_capture(path))

    assert manual.main() == 1
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert calls == [
        {},
        {"expected_pid": 101, "expected_hwnd": 11},
        {"expected_pid": 101, "expected_hwnd": 11},
    ]
    assert [step["status"] for step in report["steps"]] == ["PASS", "FAIL"]
    assert "retained HWND disappeared" in report["steps"][1]["error"]
    assert report["status"] == "FAIL"


def test_attach_expected_pid_retains_first_hwnd_for_later_captures(
    tmp_path,
    monkeypatch,
):
    steps_path = tmp_path / "steps.json"
    _write_steps(steps_path, count=2)
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
            "--expected-pid",
            "202",
        ],
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    calls: list[dict[str, int]] = []

    def fake_find(_pattern, **kwargs):
        calls.append(kwargs)
        return {
            "hwnd": 22,
            "pid": 202,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 320, 200],
        }

    monkeypatch.setattr(manual, "find_window", fake_find)
    monkeypatch.setattr(manual, "capture_window", lambda _hwnd, path: _pass_capture(path))

    assert manual.main() == 0
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert calls == [
        {"expected_pid": 202},
        {"expected_pid": 202, "expected_hwnd": 22},
        {"expected_pid": 202, "expected_hwnd": 22},
    ]
    assert report["target_identity"]["retained_hwnd"] == 22
    assert report["target_identity"]["status"] == "BOUND"
    assert report["status"] == "PASS"


def test_launch_mode_uses_popen_pid_and_retains_first_hwnd(
    tmp_path,
    monkeypatch,
):
    steps_path = tmp_path / "steps.json"
    _write_steps(steps_path, count=2)
    output_root = tmp_path / "output"
    exe_path = tmp_path / "Container_Audit.exe"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manual_real_ui_walkthrough_capture.py",
            "--output-root",
            str(output_root),
            "--steps-json",
            str(steps_path),
            "--launch-exe",
            str(exe_path),
        ],
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr(
        manual.subprocess,
        "Popen",
        lambda *_args, **_kwargs: type("Process", (), {"pid": 707})(),
    )
    monkeypatch.setattr(manual.time, "sleep", lambda _seconds: None)
    calls: list[dict[str, int]] = []

    def fake_find(_pattern, **kwargs):
        calls.append(kwargs)
        return {
            "hwnd": 77,
            "pid": 707,
            "title": "이적 검사 시스템",
            "rect": [0, 0, 320, 200],
        }

    monkeypatch.setattr(manual, "find_window", fake_find)
    monkeypatch.setattr(manual, "capture_window", lambda _hwnd, path: _pass_capture(path))

    assert manual.main() == 0
    report = json.loads(
        (output_root / "manual_real_ui_walkthrough_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert calls == [
        {"expected_pid": 707},
        {"expected_pid": 707, "expected_hwnd": 77},
        {"expected_pid": 707, "expected_hwnd": 77},
    ]
    assert report["target_identity"]["mode"] == "launch"
    assert report["target_identity"]["pid_source"] == "launched_process"
    assert report["target_identity"]["expected_pid"] == 707
    assert report["target_identity"]["retained_hwnd"] == 77
    assert report["status"] == "PASS"
