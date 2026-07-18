from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from responsive_layout import (
    MAX_SCALE,
    MIN_SCALE,
    center_layout_metrics,
    pane_layout_metrics,
    right_sidebar_metrics,
    scanned_list_metrics,
    select_layout_profile,
    worker_login_layout_metrics,
)


@pytest.mark.parametrize(
    ("size", "expected"),
    [
        ((1366, 768), "compact"),
        ((1440, 900), "standard"),
        ((1920, 1080), "wide"),
        ((2560, 1080), "wide"),
        ((1280, 1024), "compact"),
    ],
)
def test_select_layout_profile_for_supported_content_sizes(size, expected):
    profile = select_layout_profile(*size)

    assert profile.name == expected
    assert profile.content_width == size[0]
    assert profile.content_height == size[1]


def test_profile_selection_accounts_for_large_text_scale():
    default = select_layout_profile(1920, 1080, 1.0)
    enlarged = select_layout_profile(1920, 1080, 1.25)

    assert default.name == "wide"
    assert enlarged.name == "standard"
    assert enlarged.effective_width == pytest.approx(1536)


def test_scale_is_clamped_and_invalid_values_are_rejected():
    assert select_layout_profile(1440, 900, 0.1).scale == MIN_SCALE
    assert select_layout_profile(1440, 900, 99).scale == MAX_SCALE

    with pytest.raises(TypeError):
        select_layout_profile(True, 900)
    with pytest.raises(TypeError):
        select_layout_profile(1440, 900, False)
    with pytest.raises(ValueError):
        select_layout_profile(float("nan"), 900)
    with pytest.raises(ValueError):
        select_layout_profile(1440, float("inf"))


def test_numeric_dimensions_are_clamped_to_safe_minima():
    profile = select_layout_profile(-10, 0)
    panes = pane_layout_metrics(-10, 0)

    assert profile.content_width == 1
    assert profile.content_height == 1
    assert panes.total_width == 3
    assert panes.total_height == 1
    assert panes.left_width + panes.center_width + panes.right_width == 3
    assert min(panes.left_width, panes.center_width, panes.right_width) == 1


@pytest.mark.parametrize("size", [(1366, 768), (1440, 900), (1920, 1080), (2560, 1080), (1280, 1024)])
def test_pane_metrics_preserve_center_and_exact_total(size):
    metrics = pane_layout_metrics(*size)

    assert metrics.left_width + metrics.center_width + metrics.right_width == size[0]
    assert metrics.center_width >= metrics.center_min
    assert metrics.center_width > metrics.left_width
    assert metrics.center_width > metrics.right_width
    assert metrics.left_width >= metrics.left_min
    assert metrics.right_width >= metrics.right_min


def test_wide_sidebars_grow_without_starving_center_scan_area():
    standard = pane_layout_metrics(1440, 900)
    wide = pane_layout_metrics(2560, 1080)

    assert wide.left_width > 380
    assert wide.right_width > 360
    assert wide.left_width > standard.left_width
    assert wide.right_width > standard.right_width
    assert wide.center_width / wide.total_width >= 0.55


def test_extreme_scale_uses_possible_minima_and_keeps_center_largest():
    metrics = pane_layout_metrics(1366, 768, 2.5)

    assert metrics.compressed is True
    assert metrics.left_width + metrics.center_width + metrics.right_width == 1366
    assert metrics.center_width >= int(1366 * 0.53)
    assert metrics.left_min <= metrics.left_width
    assert metrics.center_min <= metrics.center_width
    assert metrics.right_min <= metrics.right_width


def test_compact_wide_compact_round_trip_has_no_accumulation():
    compact_before = pane_layout_metrics(1366, 768, 1.0)
    wide = pane_layout_metrics(2560, 1080, 1.0)
    compact_after = pane_layout_metrics(1366, 768, 1.0)

    assert wide != compact_before
    assert compact_after == compact_before


def test_large_text_short_login_reserves_controls_before_logo():
    metrics = worker_login_layout_metrics(1346, 718, 1.4)

    assert metrics.profile == "compact"
    assert metrics.short_height is True
    assert metrics.logo_max_height <= round(718 * 0.28)
    assert metrics.estimated_content_height <= 718 - 16
    assert metrics.entry_ipady <= 8
    assert metrics.button_pad_y[0] <= 16


def test_worker_login_layout_round_trip_has_no_accumulation():
    compact_before = worker_login_layout_metrics(1346, 718, 1.4)
    wide = worker_login_layout_metrics(2540, 1030, 1.4)
    compact_after = worker_login_layout_metrics(1346, 718, 1.4)

    assert wide != compact_before
    assert compact_after == compact_before


def test_center_metrics_reserve_scan_list_and_scale_with_room():
    compact = center_layout_metrics(820, 728, profile="compact")
    narrow = center_layout_metrics(580, 728, profile="compact")
    wide = center_layout_metrics(1500, 1040, profile="wide")

    assert compact.list_minsize >= 130
    assert wide.list_minsize > compact.list_minsize
    assert wide.list_minsize <= round(1040 * 0.48)
    assert compact.warning_band_height > 0
    assert wide.action_columns == 4
    assert compact.action_columns == 4
    assert narrow.action_columns == 2


def test_short_large_text_center_reserves_completed_state_action_row():
    short = center_layout_metrics(710, 707, 1.4, profile="compact")
    short_list = scanned_list_metrics(
        710,
        707,
        short.list_minsize,
        1.4,
        profile="compact",
    )

    assert short.action_columns == 4
    assert short.button_top <= 8
    assert short.list_minsize <= 128
    assert short_list.top_pady <= 10


def test_scanned_list_metrics_keep_readable_rows_at_supported_extremes():
    compact = scanned_list_metrics(720, 700, 220, profile="compact")
    standard = scanned_list_metrics(820, 834, 210, profile="standard")
    short_wide = scanned_list_metrics(1100, 1012, 300, profile="wide")
    wide = scanned_list_metrics(1500, 1040, 430, profile="wide")
    large_text = scanned_list_metrics(700, 700, 220, 2.5, profile="compact")

    for metrics in (compact, standard, short_wide, wide, large_text):
        assert metrics.font_size > 0
        assert metrics.estimated_row_height >= 20
    assert compact.visible_rows == 3
    assert standard.visible_rows == 5
    assert short_wide.visible_rows == 5
    assert 5 <= wide.visible_rows <= 18
    assert large_text.visible_rows == 3
    assert compact.header_font_size <= compact.font_size
    assert standard.header_font_size <= standard.font_size
    assert wide.font_size >= compact.font_size
    assert large_text.font_size >= compact.font_size


def test_right_sidebar_prioritizes_status_and_follow_up_over_secondary_stats():
    compact = right_sidebar_metrics(280, 728, profile="compact")
    wide = right_sidebar_metrics(510, 1040, profile="wide")

    for metrics in (compact, wide):
        assert metrics.primary_card_minsize > metrics.secondary_card_minsize
        assert metrics.follow_up_minsize > metrics.secondary_card_minsize
        assert metrics.follow_up_minsize > metrics.primary_card_minsize
        assert metrics.card_minsize == metrics.primary_card_minsize
        assert metrics.value_font > metrics.secondary_value_font
    assert wide.primary_card_minsize > compact.primary_card_minsize
    assert compact.follow_up_minsize >= 200
    assert wide.follow_up_minsize >= 190


def test_short_large_text_sidebar_caps_decorative_space_and_keeps_follow_up_primary():
    short = right_sidebar_metrics(302, 707, 1.4)
    roomy = right_sidebar_metrics(510, 1324, 1.4)

    assert short.short_large_text is True
    assert short.legend_visible is False
    assert short.date_font <= 20
    assert short.clock_font <= 27
    assert short.card_padding < roomy.card_padding
    assert short.context_padding < roomy.context_padding
    assert short.card_gap < roomy.card_gap
    assert short.follow_up_minsize > short.primary_card_minsize
    assert short.primary_card_minsize > short.secondary_card_minsize
    assert short.value_font > short.secondary_value_font
    # 1324 physical px at 1.4 is only 946 logical px, so it must retain the
    # constrained tier instead of expanding decorative padding.
    assert roomy.short_large_text is True
    assert roomy.legend_visible is True
    assert roomy.card_padding <= 8


def test_scale14_uses_logical_height_and_caps_only_short_fixed_rows():
    compact_center = center_layout_metrics(710, 694, 1.4)
    compact_list = scanned_list_metrics(
        710,
        694,
        compact_center.list_minsize,
        1.4,
    )
    tall_center = center_layout_metrics(1467, 1310, 1.4)
    tall_list = scanned_list_metrics(
        1467,
        1310,
        tall_center.list_minsize,
        1.4,
    )
    tall_sidebar = right_sidebar_metrics(502, 1310, 1.4)

    assert compact_center.entry_font <= 20
    assert compact_center.count_font <= 43
    assert compact_center.notice_title_font <= 12
    assert compact_list.font_size <= 13
    assert compact_list.visible_rows == 3
    assert compact_list.header_bottom_pady == 3

    assert tall_center.list_minsize <= 300
    assert tall_center.button_top <= 4
    assert tall_list.visible_rows == 5
    assert tall_sidebar.short_large_text is True
    assert tall_sidebar.card_padding <= 8


def test_scale14_short_sidebar_preserves_complete_value_hierarchy():
    metrics = right_sidebar_metrics(302, 707, 1.4)

    assert metrics.value_font == 14
    assert metrics.secondary_value_font == 12
    assert metrics.context_value_font == 11
    assert metrics.card_gap == 3
    assert metrics.date_gap == 1
    assert metrics.clock_gap == 3
    assert metrics.card_padding == 4
    assert metrics.context_padding == 4
    assert metrics.secondary_card_padding == 4


def test_short_large_text_sidebar_metrics_round_trip_without_accumulation():
    compact_before = right_sidebar_metrics(302, 707, 1.4)
    wide = right_sidebar_metrics(510, 1040, 1.4)
    compact_after = right_sidebar_metrics(302, 707, 1.4)

    assert wide != compact_before
    assert compact_after == compact_before


def test_operator_height_budgets_cover_768_900_and_short_1080p_panes():
    compact = center_layout_metrics(815, 704)
    standard = center_layout_metrics(818, 834)
    short_wide = center_layout_metrics(1096, 1012)
    tall_wide = center_layout_metrics(1467, 1324)

    assert compact.list_minsize <= 145
    assert standard.list_minsize <= 210
    assert short_wide.list_minsize <= 300
    assert compact.button_top <= 4
    assert standard.button_top <= 4
    assert short_wide.button_top <= 4
    assert compact.count_font < standard.count_font < short_wide.count_font < tall_wide.count_font
    assert compact.entry_font < standard.entry_font <= short_wide.entry_font < tall_wide.entry_font
    assert tall_wide.list_minsize > short_wide.list_minsize


def test_right_sidebar_reserves_value_lines_through_short_1080p_height():
    compact = right_sidebar_metrics(243, 704)
    standard = right_sidebar_metrics(278, 834)
    short_wide = right_sidebar_metrics(376, 1012)
    tall_wide = right_sidebar_metrics(502, 1324)

    for metrics in (compact, standard, short_wide):
        assert metrics.short_large_text is True
        assert metrics.card_padding <= 8
        assert metrics.primary_card_minsize >= 96
        assert metrics.follow_up_minsize >= 190
    assert compact.legend_visible is False
    assert standard.legend_visible is False
    assert short_wide.legend_visible is True
    assert tall_wide.short_large_text is False
    assert tall_wide.card_padding > short_wide.card_padding


def test_right_sidebar_fits_narrow_context_and_preserves_short_1080p_value_type():
    narrow_768 = right_sidebar_metrics(243, 704)
    short_1080 = right_sidebar_metrics(502, 1012)

    assert narrow_768.context_value_font == 11
    assert narrow_768.value_font > narrow_768.context_value_font

    # Keep the 19 pt primary values from the approved 1080p direction and
    # reclaim only the decorative 15 px that previously compressed each of
    # the three weighted cards by 5 px.
    assert short_1080.value_font == 19
    assert short_1080.outer_padding == 10
    assert short_1080.card_gap == 6
    assert short_1080.date_gap == 2
    assert short_1080.clock_gap == 4


def test_profile_override_is_validated():
    with pytest.raises(ValueError):
        pane_layout_metrics(1440, 900, profile="huge")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        center_layout_metrics(800, 700, profile=object())  # type: ignore[arg-type]


def test_metric_results_are_immutable():
    metrics = pane_layout_metrics(1440, 900)

    with pytest.raises(FrozenInstanceError):
        metrics.center_width = 1  # type: ignore[misc]
