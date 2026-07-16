from dataclasses import FrozenInstanceError

import pytest

import style_tokens


def test_existing_container_audit_color_defaults_are_preserved_for_aliasing():
    colors = style_tokens.DEFAULT_COLORS

    assert colors.canvas == style_tokens.COLOR_BG == "#F3F6FA"
    assert colors.sidebar == style_tokens.COLOR_SIDEBAR_BG == "#FFFFFF"
    assert colors.card == style_tokens.COLOR_CARD_BG == "#F8FAFC"
    assert colors.surface_alt == style_tokens.COLOR_SURFACE_ALT == "#EEF3F8"
    assert colors.text == style_tokens.COLOR_TEXT == "#172033"
    assert colors.text_subtle == style_tokens.COLOR_TEXT_SUBTLE == "#667085"
    assert colors.primary == style_tokens.COLOR_PRIMARY == "#2563EB"
    assert colors.primary_hover == style_tokens.COLOR_PRIMARY_HOVER == "#1D4ED8"
    assert colors.primary_soft == style_tokens.COLOR_PRIMARY_SOFT == "#DBEAFE"
    assert colors.success == style_tokens.COLOR_SUCCESS == "#16A34A"
    assert colors.success_hover == style_tokens.COLOR_SUCCESS_HOVER == "#15803D"
    assert colors.danger == style_tokens.COLOR_DANGER == "#DC2626"
    assert colors.danger_hover == style_tokens.COLOR_DANGER_HOVER == "#B91C1C"
    assert colors.warning == style_tokens.COLOR_IDLE == "#F59E0B"
    assert colors.warning_background == style_tokens.COLOR_IDLE_BG == "#FFF7ED"
    assert colors.warning_text == style_tokens.COLOR_IDLE_TEXT == "#92400E"
    assert colors.border == style_tokens.COLOR_BORDER == "#D7DEE8"
    assert colors.border_strong == style_tokens.COLOR_BORDER_STRONG == "#AEB8C6"
    assert colors.record_accent == style_tokens.COLOR_VELVET == "#991B1B"
    assert colors.input == style_tokens.COLOR_INPUT_BG == "#FFFFFF"
    assert style_tokens.DEFAULT_STYLE_TOKENS.fonts.family == style_tokens.DEFAULT_FONT == "Malgun Gothic"


@pytest.mark.parametrize(
    ("raw_scale", "expected"),
    [
        (-1, 0.7),
        (0.7, 0.7),
        (1.25, 1.25),
        (2.5, 2.5),
        (99, 2.5),
        (None, 1.0),
        (True, 1.0),
        (float("nan"), 1.0),
        (float("inf"), 1.0),
    ],
)
def test_scale_is_finite_and_clamped_to_supported_range(raw_scale, expected):
    assert style_tokens.clamp_scale(raw_scale) == expected
    assert style_tokens.build_style_tokens(scale=raw_scale).scale == expected


def test_profile_names_are_normalized_and_invalid_profiles_are_rejected():
    assert style_tokens.normalize_profile(" WIDE ") is style_tokens.StyleProfile.WIDE
    assert style_tokens.build_style_tokens("compact").profile is style_tokens.StyleProfile.COMPACT

    with pytest.raises(ValueError, match="unknown style profile"):
        style_tokens.build_style_tokens("poster")


def test_profiles_adjust_typography_spacing_and_control_sizes_monotonically():
    compact = style_tokens.build_style_tokens("compact")
    standard = style_tokens.build_style_tokens("standard")
    wide = style_tokens.build_style_tokens("wide")

    assert compact.fonts.body < standard.fonts.body <= wide.fonts.body
    assert compact.fonts.sidebar < standard.fonts.sidebar < wide.fonts.sidebar
    assert compact.fonts.stage_title < standard.fonts.stage_title < wide.fonts.stage_title
    assert compact.spacing.md < standard.spacing.md < wide.spacing.md
    assert compact.buttons.primary_min_height < standard.buttons.primary_min_height < wide.buttons.primary_min_height
    assert compact.components.row_height < standard.components.row_height < wide.components.row_height
    assert compact.components.progress_thickness < standard.components.progress_thickness < wide.components.progress_thickness


def test_wide_profile_never_makes_side_text_tiny_at_minimum_scale():
    tokens = style_tokens.build_style_tokens("wide", scale=style_tokens.MIN_SCALE)

    assert tokens.fonts.sidebar >= 14
    assert tokens.fonts.sidebar >= tokens.fonts.body
    assert tokens.fonts.caption >= 9


def test_scaled_spacing_and_component_sizes_keep_readable_minimums():
    tokens = style_tokens.build_style_tokens("compact", scale=0.1)

    assert 1 <= tokens.spacing.xxs <= tokens.spacing.xs <= tokens.spacing.sm
    assert tokens.spacing.sm <= tokens.spacing.md <= tokens.spacing.lg <= tokens.spacing.xl <= tokens.spacing.xxl
    assert tokens.buttons.primary_min_height >= 36
    assert tokens.buttons.support_min_height >= 36
    assert tokens.buttons.danger_min_height >= 36
    assert tokens.components.row_height >= 24
    assert tokens.components.progress_thickness >= 12
    assert tokens.components.scan_input_min_height >= 42


def test_larger_scale_increases_fonts_spacing_buttons_rows_and_progress():
    base = style_tokens.build_style_tokens("standard", scale=1.0)
    enlarged = style_tokens.build_style_tokens("standard", scale=2.5)

    assert enlarged.fonts.sidebar > base.fonts.sidebar
    assert enlarged.fonts.scan_input > base.fonts.scan_input
    assert enlarged.spacing.lg > base.spacing.lg
    assert enlarged.buttons.primary_min_height > base.buttons.primary_min_height
    assert enlarged.components.row_height > base.components.row_height
    assert enlarged.components.progress_thickness > base.components.progress_thickness


def test_state_labels_make_every_operator_state_distinct_without_color():
    labels = style_tokens.DEFAULT_STATE_LABELS
    label_values = (
        labels.waiting,
        labels.active,
        labels.success,
        labels.warning,
        labels.error,
        labels.operator_review,
        labels.retry_wait,
        labels.recovered,
    )

    assert all(label.strip() for label in label_values)
    assert len(set(label_values)) == len(label_values)
    assert style_tokens.DEFAULT_STYLE_TOKENS.states.operator_review.label == "확인 필요"
    assert style_tokens.DEFAULT_STYLE_TOKENS.states.recovered.label == "복구됨"


def test_state_styles_retain_text_labels_when_semantic_colors_are_identical():
    monochrome = style_tokens.SemanticColors(
        canvas="#FFFFFF",
        sidebar="#FFFFFF",
        card="#FFFFFF",
        surface_alt="#FFFFFF",
        input="#FFFFFF",
        text="#111111",
        text_subtle="#111111",
        primary="#111111",
        primary_hover="#111111",
        primary_soft="#FFFFFF",
        success="#111111",
        success_hover="#111111",
        success_soft="#FFFFFF",
        danger="#111111",
        danger_hover="#111111",
        danger_soft="#FFFFFF",
        warning="#111111",
        warning_background="#FFFFFF",
        warning_text="#111111",
        border="#111111",
        border_strong="#111111",
        record_accent="#111111",
    )

    states = style_tokens.build_style_tokens(colors=monochrome).states

    assert states.active.foreground == states.error.foreground == "#111111"
    assert states.active.label == "작업 중"
    assert states.error.label == "오류"
    assert states.operator_review.label == "확인 필요"


def test_style_tokens_and_nested_token_groups_are_immutable():
    tokens = style_tokens.build_style_tokens()

    with pytest.raises(FrozenInstanceError):
        tokens.scale = 2.0
    with pytest.raises(FrozenInstanceError):
        tokens.fonts.sidebar = 8
    with pytest.raises(FrozenInstanceError):
        tokens.colors.primary = "#000000"
    with pytest.raises(FrozenInstanceError):
        tokens.states.error.label = ""


def test_building_tokens_is_deterministic_and_does_not_accumulate_scale():
    first_compact = style_tokens.build_style_tokens("compact", scale=1.3)
    _wide = style_tokens.build_style_tokens("wide", scale=2.0)
    second_compact = style_tokens.build_style_tokens("compact", scale=1.3)

    assert second_compact == first_compact
