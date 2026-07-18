from __future__ import annotations

from typing import Any

from PIL import Image, ImageStat


NEAR_BLACK_LUMA = 16
NEAR_BLACK_FAILURE_RATIO = 0.35
BLACK_LINE_COVERAGE_RATIO = 0.95
BLACK_STRIPE_FAILURE_RATIO = 0.30
LOW_VARIANCE_STDDEV_MAX = 2.0
DOMINANT_COLOR_RATIO_MIN = 0.90
DOMINANT_COLOR_SAMPLE_MAX_SIZE = (256, 256)


def _longest_true_run(values: list[bool]) -> int:
    longest = 0
    current = 0
    for value in values:
        if value:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _edge_true_run(values: list[bool]) -> int:
    leading = 0
    for value in values:
        if not value:
            break
        leading += 1
    trailing = 0
    for value in reversed(values):
        if not value:
            break
        trailing += 1
    return max(leading, trailing)


def _near_black_line_runs(gray: Image.Image) -> dict[str, int]:
    near_black = gray.point(
        [255 if value <= NEAR_BLACK_LUMA else 0 for value in range(256)]
    )

    def line_flags(image: Image.Image) -> list[bool]:
        raw = image.tobytes()
        line_width = max(1, image.width)
        required = int(line_width * BLACK_LINE_COVERAGE_RATIO + 0.999999)
        return [
            raw[offset : offset + line_width].count(255) >= required
            for offset in range(0, len(raw), line_width)
        ]

    row_flags = line_flags(near_black)
    column_flags = line_flags(near_black.transpose(Image.Transpose.TRANSPOSE))
    return {
        "longest_row_run": _longest_true_run(row_flags),
        "longest_column_run": _longest_true_run(column_flags),
        "edge_row_run": _edge_true_run(row_flags),
        "edge_column_run": _edge_true_run(column_flags),
    }


def _dominant_color_metrics(image: Image.Image) -> tuple[list[int], float]:
    sample = image.convert("RGB")
    sample.thumbnail(DOMINANT_COLOR_SAMPLE_MAX_SIZE, Image.Resampling.NEAREST)
    sample_pixel_count = max(1, sample.width * sample.height)
    colors = sample.getcolors(maxcolors=sample_pixel_count) or []
    dominant_count, dominant_color = max(
        colors,
        default=(0, (0, 0, 0)),
        key=lambda item: item[0],
    )
    return list(dominant_color), dominant_count / sample_pixel_count


def analyze_capture_quality(image: Image.Image) -> dict[str, Any]:
    """Return deterministic, side-effect-free screenshot quality metrics."""

    gray = image.convert("L")
    histogram = gray.histogram()
    pixel_count = max(1, gray.width * gray.height)
    exact_black_ratio = histogram[0] / pixel_count
    near_black_ratio = sum(histogram[: NEAR_BLACK_LUMA + 1]) / pixel_count
    dominant_luma_count = max(histogram)
    dominant_luma = histogram.index(dominant_luma_count)
    dominant_luma_ratio = dominant_luma_count / pixel_count
    dominant_color, dominant_color_ratio = _dominant_color_metrics(image)
    extrema = gray.getextrema() or (0, 0)
    stat = ImageStat.Stat(gray)
    luma_stddev = float(stat.stddev[0])
    line_runs = _near_black_line_runs(gray)
    row_count = max(1, gray.height)
    column_count = max(1, gray.width)
    longest_row_ratio = line_runs["longest_row_run"] / row_count
    longest_column_ratio = line_runs["longest_column_run"] / column_count
    edge_row_ratio = line_runs["edge_row_run"] / row_count
    edge_column_ratio = line_runs["edge_column_run"] / column_count
    edge_black_stripe_suspected = (
        edge_row_ratio >= BLACK_STRIPE_FAILURE_RATIO
        or edge_column_ratio >= BLACK_STRIPE_FAILURE_RATIO
    )
    contiguous_black_stripe_suspected = (
        longest_row_ratio >= BLACK_STRIPE_FAILURE_RATIO
        or longest_column_ratio >= BLACK_STRIPE_FAILURE_RATIO
    )
    uniform_low_variance_suspected = luma_stddev <= LOW_VARIANCE_STDDEV_MAX
    return {
        "blank_suspected": extrema == (255, 255) or extrema == (0, 0),
        "excess_black_suspected": near_black_ratio > NEAR_BLACK_FAILURE_RATIO,
        "edge_black_stripe_suspected": edge_black_stripe_suspected,
        "contiguous_black_stripe_suspected": contiguous_black_stripe_suspected,
        "uniform_low_variance_suspected": uniform_low_variance_suspected,
        "exact_black_ratio": round(exact_black_ratio, 6),
        "near_black_threshold_luma": NEAR_BLACK_LUMA,
        "near_black_pixels": sum(histogram[: NEAR_BLACK_LUMA + 1]),
        "near_black_ratio": round(near_black_ratio, 6),
        "mean_luma": round(float(stat.mean[0]), 2),
        "luma_mean": round(float(stat.mean[0]), 3),
        "luma_stddev": round(luma_stddev, 3),
        "luma_extrema": [int(extrema[0]), int(extrema[1])],
        "dominant_luma": dominant_luma,
        "dominant_luma_ratio": round(dominant_luma_ratio, 6),
        "dominant_color": dominant_color,
        "dominant_color_ratio": round(dominant_color_ratio, 6),
        "dominant_color_ratio_sampled": round(dominant_color_ratio, 6),
        "black_line_coverage_threshold": BLACK_LINE_COVERAGE_RATIO,
        "black_stripe_failure_threshold": BLACK_STRIPE_FAILURE_RATIO,
        "longest_near_black_row_run_ratio": round(longest_row_ratio, 6),
        "longest_near_black_column_run_ratio": round(longest_column_ratio, 6),
        "edge_near_black_row_run_ratio": round(edge_row_ratio, 6),
        "edge_near_black_column_run_ratio": round(edge_column_ratio, 6),
        "low_variance_stddev_threshold": LOW_VARIANCE_STDDEV_MAX,
        "dominant_color_ratio_threshold": DOMINANT_COLOR_RATIO_MIN,
    }
