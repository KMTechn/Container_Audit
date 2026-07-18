"""Pure responsive-layout calculations for the Container Audit UI.

The functions in this module deliberately know nothing about Tk widgets.  They
turn the *actual content size* reported by a view into immutable pixel metrics.
Keeping the calculations pure makes compact -> wide -> compact round trips
repeatable and lets the GUI apply sizes without accumulating previous values.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Literal, TypeAlias


MIN_SCALE = 0.7
MAX_SCALE = 2.5

LayoutProfileName: TypeAlias = Literal["compact", "standard", "wide"]
_PROFILE_NAMES = frozenset({"compact", "standard", "wide"})


@dataclass(frozen=True, slots=True)
class LayoutProfile:
    """Responsive profile selected from usable content size and UI scale."""

    name: LayoutProfileName
    content_width: int
    content_height: int
    scale: float
    effective_width: float
    effective_height: float


@dataclass(frozen=True, slots=True)
class PaneLayoutMetrics:
    """Widths for the persistent left / center / right work areas."""

    profile: LayoutProfileName
    total_width: int
    total_height: int
    scale: float
    left_width: int
    center_width: int
    right_width: int
    left_min: int
    center_min: int
    right_min: int
    compressed: bool


@dataclass(frozen=True, slots=True)
class CenterLayoutMetrics:
    """Spacing and type sizes for the primary scan work area."""

    profile: LayoutProfileName
    horizontal_pad: int
    item_top: int
    item_bottom: int
    count_top: int
    count_bottom: int
    progress_bottom: int
    entry_ipady: int
    warning_band_height: int
    button_top: int
    button_pad_x: int
    list_minsize: int
    entry_font: int
    count_font: int
    notice_title_font: int
    notice_message_font: int
    action_columns: int


@dataclass(frozen=True, slots=True)
class ScannedListMetrics:
    """Readable sizing for the center-lower current-tray scan list."""

    profile: LayoutProfileName
    font_size: int
    header_font_size: int
    horizontal_pad: int
    top_pady: int
    header_bottom_pady: int
    visible_rows: int
    estimated_row_height: int


@dataclass(frozen=True, slots=True)
class WorkerLoginLayoutMetrics:
    """Height-budgeted geometry for the worker login screen."""

    profile: LayoutProfileName
    short_height: bool
    horizontal_pad: int
    logo_max_width: int
    logo_max_height: int
    logo_pad_y: tuple[int, int]
    title_pad_y: tuple[int, int]
    field_label_pad_y: tuple[int, int]
    entry_ipady: int
    button_pad_y: tuple[int, int]
    button_pad_x: int
    button_ipady: int
    estimated_content_height: int


@dataclass(frozen=True, slots=True)
class RightSidebarMetrics:
    """Sizing for status/time/follow-up cards and secondary statistics."""

    profile: LayoutProfileName
    short_large_text: bool
    outer_padding: int
    card_gap: int
    primary_card_minsize: int
    secondary_card_minsize: int
    follow_up_minsize: int
    legend_pad_y: int
    legend_visible: bool
    date_font: int
    clock_font: int
    date_gap: int
    clock_gap: int
    card_padding: int
    context_padding: int
    secondary_card_padding: int
    value_font: int
    secondary_value_font: int
    context_value_font: int

    @property
    def card_minsize(self) -> int:
        """Compatibility name for the existing primary-card layout hook."""

        return self.primary_card_minsize


def _finite_number(value: object, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be finite")
    return numeric


def _dimension(value: object, *, name: str, minimum: int = 1) -> int:
    """Validate a numeric dimension and clamp non-positive values safely."""

    numeric = _finite_number(value, name=name)
    return max(minimum, int(round(numeric)))


def _scale(value: object) -> float:
    numeric = _finite_number(value, name="scale")
    return max(MIN_SCALE, min(MAX_SCALE, numeric))


def _clamped_int(value: float, minimum: float, maximum: float) -> int:
    lower = max(0, int(round(minimum)))
    upper = max(lower, int(round(maximum)))
    return max(lower, min(upper, int(round(value))))


def _profile_name(
    profile: LayoutProfile | LayoutProfileName | None,
    *,
    width: int,
    height: int,
    scale: float,
) -> LayoutProfileName:
    if profile is None:
        return select_layout_profile(width, height, scale).name
    if isinstance(profile, LayoutProfile):
        return profile.name
    if isinstance(profile, str):
        if profile not in _PROFILE_NAMES:
            raise ValueError(f"unknown layout profile: {profile}")
        return profile  # type: ignore[return-value]
    raise TypeError("profile must be a LayoutProfile, profile name, or None")


def select_layout_profile(
    content_width: object,
    content_height: object,
    scale: object = 1.0,
) -> LayoutProfile:
    """Select compact, standard, or wide from usable content dimensions.

    Dividing by the clamped UI scale expresses how much logical room remains
    after the operator's text-size preference is applied.  Width and height are
    both required: an ultrawide but vertically short work area must still use a
    compact layout.
    """

    width = _dimension(content_width, name="content_width")
    height = _dimension(content_height, name="content_height")
    normalized_scale = _scale(scale)
    effective_width = width / normalized_scale
    effective_height = height / normalized_scale

    if effective_width < 1400 or effective_height < 800:
        name: LayoutProfileName = "compact"
    elif effective_width >= 1780 and effective_height >= 900:
        name = "wide"
    else:
        name = "standard"

    return LayoutProfile(
        name=name,
        content_width=width,
        content_height=height,
        scale=normalized_scale,
        effective_width=effective_width,
        effective_height=effective_height,
    )


_PANE_RULES: dict[LayoutProfileName, dict[str, float]] = {
    "compact": {
        "left_ratio": 0.205,
        "right_ratio": 0.185,
        "left_min": 230,
        "right_min": 220,
        "center_min": 500,
        "left_max": 340,
        "right_max": 320,
    },
    "standard": {
        "left_ratio": 0.220,
        "right_ratio": 0.200,
        "left_min": 280,
        "right_min": 260,
        "center_min": 560,
        "left_max": 430,
        "right_max": 400,
    },
    "wide": {
        "left_ratio": 0.220,
        "right_ratio": 0.200,
        "left_min": 320,
        "right_min": 300,
        "center_min": 680,
        "left_max": 600,
        "right_max": 540,
    },
}


def pane_layout_metrics(
    content_width: object,
    content_height: object,
    scale: object = 1.0,
    *,
    profile: LayoutProfile | LayoutProfileName | None = None,
) -> PaneLayoutMetrics:
    """Return non-overlapping widths for the three persistent work panes.

    On wide displays the sidebars are allowed to grow with the content instead
    of being frozen at the legacy 380/360 pixels.  The center remains the
    largest pane because it owns the current tray's scan list and scan input.
    """

    width = _dimension(content_width, name="content_width", minimum=3)
    height = _dimension(content_height, name="content_height")
    normalized_scale = _scale(scale)
    name = _profile_name(profile, width=width, height=height, scale=normalized_scale)
    rules = _PANE_RULES[name]

    left_min = max(1, int(round(rules["left_min"] * normalized_scale)))
    right_min = max(1, int(round(rules["right_min"] * normalized_scale)))
    center_min = max(1, int(round(rules["center_min"] * normalized_scale)))
    left_max = max(left_min, int(round(rules["left_max"] * normalized_scale)))
    right_max = max(right_min, int(round(rules["right_max"] * normalized_scale)))

    compressed = width < left_min + center_min + right_min
    if compressed:
        # The center keeps at least 53% even at an extreme text scale.  Returned
        # minima reflect what is actually possible so downstream sash clamping
        # cannot ask Tk to satisfy an impossible sum.
        side_total = min(width - 1, max(2, int(round(width * 0.47))))
        left_width = int(round(side_total * 0.52))
        right_width = side_total - left_width
        center_width = width - side_total
        left_min = min(left_min, left_width)
        right_min = min(right_min, right_width)
        center_min = min(center_min, center_width)
    else:
        left_width = _clamped_int(width * rules["left_ratio"], left_min, left_max)
        right_width = _clamped_int(width * rules["right_ratio"], right_min, right_max)
        center_width = width - left_width - right_width

        if center_width < center_min:
            deficit = center_min - center_width
            left_capacity = left_width - left_min
            right_capacity = right_width - right_min
            reduce_left = min(left_capacity, (deficit + 1) // 2)
            left_width -= reduce_left
            deficit -= reduce_left
            reduce_right = min(right_capacity, deficit)
            right_width -= reduce_right
            deficit -= reduce_right
            if deficit:
                extra_left = min(left_width - left_min, deficit)
                left_width -= extra_left
            center_width = width - left_width - right_width

    return PaneLayoutMetrics(
        profile=name,
        total_width=width,
        total_height=height,
        scale=normalized_scale,
        left_width=left_width,
        center_width=center_width,
        right_width=right_width,
        left_min=left_min,
        center_min=center_min,
        right_min=right_min,
        compressed=compressed,
    )


def center_layout_metrics(
    center_width: object,
    center_height: object,
    scale: object = 1.0,
    *,
    profile: LayoutProfile | LayoutProfileName | None = None,
) -> CenterLayoutMetrics:
    """Calculate absolute center-pane spacing without prior-layout state."""

    width = _dimension(center_width, name="center_width")
    height = _dimension(center_height, name="center_height")
    normalized_scale = _scale(scale)
    name = _profile_name(profile, width=width, height=height, scale=normalized_scale)
    logical_height = height / normalized_scale
    compact_height = logical_height < 700
    height_constrained = logical_height < 1080
    short_large_text = normalized_scale >= 1.2 and logical_height < 620
    # A 1.4 preference must enlarge text without turning every fixed center
    # row into a 1.4x height request on a 768/900 px operator display.  Keep
    # the requested scale for profile selection, then cap only the fixed-row
    # typography in this genuinely short logical-height tier.
    constrained_text_scale = min(normalized_scale, 1.2) if short_large_text else normalized_scale

    horizontal_pad = _clamped_int(width * 0.035, 12 * normalized_scale, 48 * normalized_scale)
    item_top = _clamped_int(height * 0.012, 5 * normalized_scale, 15 * normalized_scale)
    item_bottom = _clamped_int(height * 0.020, 7 * normalized_scale, 23 * normalized_scale)
    count_top = _clamped_int(height * 0.010, 5 * normalized_scale, 14 * normalized_scale)
    count_bottom = _clamped_int(height * 0.018, 7 * normalized_scale, 21 * normalized_scale)
    progress_bottom = _clamped_int(height * 0.016, 7 * normalized_scale, 19 * normalized_scale)
    entry_ipady = _clamped_int(height * 0.014, 8 * normalized_scale, 17 * normalized_scale)
    button_top = _clamped_int(height * 0.020, 9 * normalized_scale, 26 * normalized_scale)
    button_pad_x = _clamped_int(width * 0.010, 5 * normalized_scale, 14 * normalized_scale)
    if short_large_text:
        # Preserve the physical action-row height before assigning flexible
        # space to the scan history. This is the completed-state escape hatch
        # when both the instruction and completion notice wrap at 1366x768.
        button_top = min(button_top, 8)
    if height_constrained:
        # Tk font points consume substantially more physical pixels on the
        # high-DPI operator monitor. Reserve the action row before assigning
        # flexible history space on both 768 px and 900 px displays.
        item_top = min(item_top, 6)
        item_bottom = min(item_bottom, 8)
        count_top = min(count_top, 5)
        count_bottom = min(count_bottom, 7)
        progress_bottom = min(progress_bottom, 7)
        entry_ipady = min(entry_ipady, 7 if height < 780 else 8)
        button_top = min(button_top, 4)

    # Short operator displays must reserve enough room for the action groups
    # below the list.  The list remains the largest flexible center-lower
    # region, but it must not force recovery/reset controls off-screen.
    list_ratio = (
        0.22
        if logical_height < 780
        else {"compact": 0.32, "standard": 0.36, "wide": 0.39}[name]
    )
    list_cap = max(1, int(round(height * 0.48)))
    list_floor_base = 96 if logical_height < 620 else 130
    list_floor = min(list_cap, max(1, int(round(list_floor_base * normalized_scale))))
    list_ceiling = max(list_floor, min(list_cap, int(round(430 * normalized_scale))))
    list_minsize = _clamped_int(height * list_ratio, list_floor, list_ceiling)
    if short_large_text:
        # The history row remains weighted and grows whenever room is available.
        # Its short-display minimum must stay below the fixed action-row budget
        # so a wrapped completion notice cannot push the buttons off-screen.
        list_minsize = min(list_minsize, 128)
    if height_constrained:
        constrained_list_cap = 145 if height < 780 else 210 if height < 920 else 300
        list_minsize = min(list_minsize, constrained_list_cap)

    warning_cap = max(1, int(round(height * 0.12)))
    warning_floor = min(warning_cap, max(1, int(round(42 * constrained_text_scale))))
    warning_ceiling = max(
        warning_floor,
        min(warning_cap, int(round(72 * constrained_text_scale))),
    )
    warning_band_height = _clamped_int(height * 0.065, warning_floor, warning_ceiling)

    entry_floor = min(max(1, int(round(height * 0.12))), max(1, int(round(22 * normalized_scale))))
    entry_ceiling = max(entry_floor, min(int(round(height * 0.16)), int(round(35 * normalized_scale))))
    entry_font = _clamped_int(height * 0.034, entry_floor, entry_ceiling)

    count_floor = min(max(1, int(round(height * 0.18))), max(1, int(round(48 * normalized_scale))))
    count_ceiling = max(count_floor, min(int(round(height * 0.22)), int(round(76 * normalized_scale))))
    count_font = _clamped_int(height * (0.082 if compact_height else 0.088), count_floor, count_ceiling)
    notice_title_font = max(10, int(round(12 * normalized_scale)))
    notice_message_font = max(9, int(round(11 * normalized_scale)))
    if height_constrained and height < 920:
        entry_font = _clamped_int(
            height * 0.024,
            17 * constrained_text_scale,
            20 * constrained_text_scale,
        )
        count_font = _clamped_int(
            height * 0.052,
            36 * constrained_text_scale,
            44 * constrained_text_scale,
        )
        notice_title_font = max(9, int(round(10 * constrained_text_scale)))
        notice_message_font = max(9, int(round(9 * constrained_text_scale)))
    elif height_constrained:
        entry_font = _clamped_int(
            height * 0.024,
            20 * constrained_text_scale,
            24 * constrained_text_scale,
        )
        count_font = _clamped_int(
            height * 0.052,
            46 * constrained_text_scale,
            54 * constrained_text_scale,
        )
        notice_title_font = max(10, int(round(11 * constrained_text_scale)))
        notice_message_font = max(9, int(round(10 * constrained_text_scale)))

    # The center exposes exactly four short primary actions. Keeping them on
    # one physical row from 620 px prevents large-text settings from pushing
    # the scan list or actions below a 768 px operator display.
    action_columns = 4 if width >= 620 else 2

    return CenterLayoutMetrics(
        profile=name,
        horizontal_pad=horizontal_pad,
        item_top=item_top,
        item_bottom=item_bottom,
        count_top=count_top,
        count_bottom=count_bottom,
        progress_bottom=progress_bottom,
        entry_ipady=entry_ipady,
        warning_band_height=warning_band_height,
        button_top=button_top,
        button_pad_x=button_pad_x,
        list_minsize=list_minsize,
        entry_font=entry_font,
        count_font=count_font,
        notice_title_font=notice_title_font,
        notice_message_font=notice_message_font,
        action_columns=action_columns,
    )


def scanned_list_metrics(
    center_width: object,
    center_height: object,
    list_height: object | None = None,
    scale: object = 1.0,
    *,
    profile: LayoutProfile | LayoutProfileName | None = None,
) -> ScannedListMetrics:
    """Calculate readable metrics for the current tray's center scan list."""

    width = _dimension(center_width, name="center_width")
    height = _dimension(center_height, name="center_height")
    normalized_scale = _scale(scale)
    name = _profile_name(profile, width=width, height=height, scale=normalized_scale)
    logical_height = height / normalized_scale
    if list_height is None:
        measured_list_height = 0
    else:
        measured_list_height = _dimension(list_height, name="list_height", minimum=0)

    horizontal_pad = _clamped_int(width * 0.045, 10 * normalized_scale, 38 * normalized_scale)
    top_pady = _clamped_int(height * 0.022, 6 * normalized_scale, 24 * normalized_scale)
    height_constrained = logical_height < 1080
    short_large_text = normalized_scale >= 1.2 and logical_height < 620
    constrained_text_scale = min(normalized_scale, 1.2) if short_large_text else normalized_scale
    header_bottom_pady = (
        3 if short_large_text else max(4, int(round(6 * normalized_scale)))
    )
    if short_large_text:
        top_pady = min(top_pady, 10)
    elif logical_height < 620:
        top_pady = min(top_pady, max(1, int(round(12 * normalized_scale))))

    fallback_height = max(int(round(120 * normalized_scale)), height - int(round(330 * normalized_scale)))
    list_reference_height = measured_list_height if measured_list_height > 1 else fallback_height
    list_reference_height = max(1, min(height, list_reference_height))
    effective_list_height = list_reference_height / normalized_scale
    if effective_list_height < 180:
        target_rows = 6
    elif effective_list_height < 320:
        target_rows = 8
    elif effective_list_height < 520:
        target_rows = 12
    else:
        target_rows = 16

    row_px = max(22 * normalized_scale, min(44 * normalized_scale, list_reference_height / target_rows))
    base_font = {"compact": 16, "standard": 18, "wide": 19}[name] * normalized_scale
    candidate_font = max(base_font, row_px * 0.58)
    available_text_width = max(120, width - horizontal_pad * 2 - 12)
    width_limited_font = available_text_width / (36 * 0.62)
    minimum_font = 14 * normalized_scale
    maximum_font = min(25 * normalized_scale, max(minimum_font, width_limited_font))
    font_size = _clamped_int(candidate_font, minimum_font, maximum_font)
    estimated_row_height = max(20, int(round(font_size * 1.65)))
    minimum_rows = 3 if logical_height < 620 else 5
    visible_rows = _clamped_int(list_reference_height / estimated_row_height, minimum_rows, 18)
    header_font_size = max(10, int(round(12 * normalized_scale)))
    if height_constrained:
        # Listbox height is expressed in text rows. Explicit profile-sized
        # requests prevent high-DPI rows from crushing the final viewport and
        # action row. New scans remain at index zero.
        if height < 780:
            # Keep the same 11 pt base at every scale.  The former 14 pt base
            # switch plus multiplication made 1.0 -> 1.4 jump 11 -> 20 pt,
            # wider than the real 1366 viewport and too tall for three rows.
            if normalized_scale >= 2.0:
                # Preserve the existing explicit extreme-scale contract.  The
                # 1.4 operator tier uses the stable 11 pt base above; a 2x+
                # accessibility request remains deliberately oversized.
                font_size = max(10, int(round(14 * normalized_scale)))
                header_font_size = max(9, int(round(10 * normalized_scale)))
            else:
                font_size = max(10, int(round(11 * constrained_text_scale)))
                header_font_size = max(9, int(round(10 * constrained_text_scale)))
            visible_rows = 3 if height >= 650 else max(5, visible_rows)
            top_pady = min(top_pady, 4)
        elif height < 850:
            font_size = max(11, int(round(12 * constrained_text_scale)))
            header_font_size = max(10, int(round(11 * constrained_text_scale)))
            visible_rows = 5
            top_pady = min(top_pady, 6)
        elif height < 920 and list_reference_height >= 360:
            # An intermediate-height pane with a genuinely roomy measured
            # viewport can retain the standard type size without increasing
            # the fixed list-row minimum used by the supported 900 px window.
            font_size = max(12, int(round(18 * constrained_text_scale)))
            header_font_size = max(10, int(round(12 * constrained_text_scale)))
            visible_rows = max(8, visible_rows)
            top_pady = min(top_pady, 6)
        else:
            font_size = max(12, int(round(14 * constrained_text_scale)))
            header_font_size = max(10, int(round(12 * constrained_text_scale)))
            visible_rows = 5
            top_pady = min(top_pady, 8)
        horizontal_pad = min(
            horizontal_pad,
            max(12, int(round((22 if height < 920 else 28) * normalized_scale))),
        )
        estimated_row_height = max(20, int(round(font_size * 1.65)))

    return ScannedListMetrics(
        profile=name,
        font_size=font_size,
        header_font_size=header_font_size,
        horizontal_pad=horizontal_pad,
        top_pady=top_pady,
        header_bottom_pady=header_bottom_pady,
        visible_rows=visible_rows,
        estimated_row_height=estimated_row_height,
    )


def worker_login_layout_metrics(
    content_width: object,
    content_height: object,
    scale: object = 1.0,
    *,
    profile: LayoutProfile | LayoutProfileName | None = None,
) -> WorkerLoginLayoutMetrics:
    """Fit the login logo and controls inside the actual client height.

    The legacy login scaled a 400 px logo and every spacer directly with the
    text preference.  At 1366x768 and 1.4x text that requested more vertical
    space than the window owned.  These metrics reserve the text/control
    budget first, then cap the decorative logo with the remaining height.
    """

    width = _dimension(content_width, name="content_width")
    height = _dimension(content_height, name="content_height")
    normalized_scale = _scale(scale)
    name = _profile_name(profile, width=width, height=height, scale=normalized_scale)
    short_height = height / normalized_scale < 620

    if short_height:
        horizontal_pad = _clamped_int(width * 0.025, 10, 30)
        logo_pad_y = (4, 6)
        title_pad_y = (3, _clamped_int(height * 0.016, 8, 14))
        field_label_pad_y = (2, 3)
        entry_ipady = _clamped_int(height * 0.008, 4, 8)
        button_pad_y = (_clamped_int(height * 0.018, 8, 16), 0)
        button_pad_x = _clamped_int(width * 0.008, 6, 12)
        button_ipady = _clamped_int(height * 0.008, 4, 8)
        requested_logo_height = _clamped_int(height * 0.28, 96, 220)
        requested_logo_width = _clamped_int(width * 0.32, 180, 430)
    else:
        horizontal_pad = _clamped_int(width * 0.035, 14 * normalized_scale, 48 * normalized_scale)
        logo_pad_y = (
            _clamped_int(height * 0.018, 10 * normalized_scale, 22 * normalized_scale),
            _clamped_int(height * 0.012, 7 * normalized_scale, 15 * normalized_scale),
        )
        title_pad_y = (
            _clamped_int(height * 0.010, 6 * normalized_scale, 14 * normalized_scale),
            _clamped_int(height * 0.032, 18 * normalized_scale, 34 * normalized_scale),
        )
        field_label_pad_y = (
            _clamped_int(height * 0.007, 4 * normalized_scale, 9 * normalized_scale),
            _clamped_int(height * 0.005, 3 * normalized_scale, 6 * normalized_scale),
        )
        entry_ipady = _clamped_int(height * 0.011, 7 * normalized_scale, 12 * normalized_scale)
        button_pad_y = (
            _clamped_int(height * 0.045, 24 * normalized_scale, 46 * normalized_scale),
            0,
        )
        button_pad_x = _clamped_int(width * 0.009, 8 * normalized_scale, 14 * normalized_scale)
        button_ipady = _clamped_int(height * 0.009, 6 * normalized_scale, 10 * normalized_scale)
        requested_logo_height = _clamped_int(height * 0.31, 170 * normalized_scale, 320 * normalized_scale)
        requested_logo_width = _clamped_int(width * 0.30, 280 * normalized_scale, 440 * normalized_scale)

    # Approximate the physical line boxes used by the matching Tk styles. The
    # result is deliberately conservative: it includes ttk's vertical button
    # padding and a safety margin before assigning the remaining height to the
    # logo.  It is a clipping proxy, not a replacement for rendered capture.
    stage_font = {"compact": 24, "standard": 28, "wide": 32}[name] * normalized_scale
    label_font = 12 * normalized_scale
    entry_font = 18 * normalized_scale
    button_font = {"compact": 12, "standard": 14, "wide": 15}[name] * normalized_scale
    title_line = int(math.ceil(stage_font * 1.5))
    label_line = int(math.ceil(label_font * 1.5))
    entry_line = int(math.ceil(entry_font * 1.5)) + entry_ipady * 2
    style_button_padding = int(round({"compact": 12, "standard": 16, "wide": 20}[name] * normalized_scale))
    button_line = int(math.ceil(button_font * 1.5)) + style_button_padding + button_ipady * 2
    fixed_height = (
        sum(logo_pad_y)
        + title_line
        + sum(title_pad_y)
        + label_line
        + sum(field_label_pad_y)
        + entry_line
        + sum(button_pad_y)
        + button_line
    )
    safety_margin = _clamped_int(height * 0.035, 16, 36)
    logo_height_budget = max(64, height - fixed_height - safety_margin)
    logo_max_height = min(requested_logo_height, logo_height_budget)
    # Preserve the source logo's 1024:720 aspect even before Pillow loads it.
    logo_max_width = min(requested_logo_width, max(1, int(round(logo_max_height / 0.703125))))
    estimated_content_height = fixed_height + logo_max_height

    return WorkerLoginLayoutMetrics(
        profile=name,
        short_height=short_height,
        horizontal_pad=horizontal_pad,
        logo_max_width=logo_max_width,
        logo_max_height=logo_max_height,
        logo_pad_y=logo_pad_y,
        title_pad_y=title_pad_y,
        field_label_pad_y=field_label_pad_y,
        entry_ipady=entry_ipady,
        button_pad_y=button_pad_y,
        button_pad_x=button_pad_x,
        button_ipady=button_ipady,
        estimated_content_height=estimated_content_height,
    )


def right_sidebar_metrics(
    sidebar_width: object,
    sidebar_height: object,
    scale: object = 1.0,
    *,
    profile: LayoutProfile | LayoutProfileName | None = None,
) -> RightSidebarMetrics:
    """Size primary status/time cards and compact secondary information."""

    width = _dimension(sidebar_width, name="sidebar_width")
    height = _dimension(sidebar_height, name="sidebar_height")
    normalized_scale = _scale(scale)
    name = _profile_name(profile, width=width, height=height, scale=normalized_scale)
    logical_height = height / normalized_scale
    short_large_text = logical_height < 1080
    very_short_large_text = normalized_scale >= 1.2 and logical_height < 620

    if short_large_text:
        # Scaling every spacer and card minimum consumes the available height
        # before wrapped values are considered on short high-DPI displays.
        # Keep a slightly roomier tier for 1080p while still reserving every
        # value line and the follow-up context before secondary decoration.
        if height < 920:
            outer_padding = _clamped_int(width * 0.025, 6, 10)
            card_gap = _clamped_int(height * 0.007, 4, 7)
            primary_card_minsize = _clamped_int(height * 0.140, 96, 116)
            secondary_card_minsize = _clamped_int(height * 0.082, 58, 76)
            follow_up_minsize = _clamped_int(height * 0.285, 200, 248)
            legend_pad_y = 0
            legend_visible = False
            date_font = _clamped_int(width * 0.055, 15, 18)
            clock_font = _clamped_int(width * 0.075, 20, 24)
            date_gap = 2
            clock_gap = 5
            card_padding = 6
            context_padding = 6
            secondary_card_padding = 5
            value_font = _clamped_int(min(width * 0.055, height * 0.025), 13, 16)
            secondary_value_font = _clamped_int(
                min(width * 0.050, height * 0.025),
                11,
                14,
            )
            context_value_font = _clamped_int(
                min(width * 0.060, height * 0.030),
                11,
                13,
            )
            if width < 260:
                # At the supported 1366x768 geometry the right pane is only
                # 243 px wide.  Keeping the context values at 13 pt makes both
                # wrapped labels request more height than their shared card,
                # so the follow-up text escapes into the secondary statistics.
                # The primary status/time values remain larger and unchanged.
                context_value_font = 11
            if very_short_large_text:
                # Preserve complete value lines on 768/900 px displays.  An
                # intact 14/12/11 pt hierarchy is more readable than larger
                # glyphs clipped by the primary/context cards.  Reclaim only
                # decorative vertical space: these reductions return 23 px
                # at 1366x768 while leaving every font unchanged.
                card_gap = 3
                date_gap = 1
                clock_gap = 3
                card_padding = 4
                context_padding = 4
                secondary_card_padding = 4
                value_font = min(value_font, 14)
                secondary_value_font = min(secondary_value_font, 12)
                context_value_font = 11
        else:
            # A 1080 px window leaves a 1012 px sidebar after the status bar.
            # Cap decorative spacing so the two primary cards and context card
            # receive their full requested heights without reducing type size.
            outer_padding = _clamped_int(width * 0.025, 8, 10)
            card_gap = _clamped_int(height * 0.006, 5, 6)
            primary_card_minsize = _clamped_int(height * 0.120, 112, 126)
            secondary_card_minsize = _clamped_int(height * 0.072, 66, 80)
            follow_up_minsize = _clamped_int(height * 0.205, 190, 220)
            legend_pad_y = 6
            legend_visible = True
            date_font = _clamped_int(width * 0.055, 18, 21)
            clock_font = _clamped_int(width * 0.072, 24, 28)
            date_gap = 2
            clock_gap = 4
            card_padding = 8
            context_padding = 10
            secondary_card_padding = 7
            value_font = _clamped_int(min(width * 0.055, height * 0.030), 16, 19)
            secondary_value_font = _clamped_int(
                min(width * 0.045, height * 0.025),
                13,
                16,
            )
            context_value_font = _clamped_int(
                min(width * 0.055, height * 0.027),
                14,
                16,
            )
    else:
        outer_padding = _clamped_int(width * 0.035, 8 * normalized_scale, 18 * normalized_scale)
        card_gap = _clamped_int(height * 0.011, 5 * normalized_scale, 14 * normalized_scale)
        primary_card_minsize = _clamped_int(height * 0.115, 78 * normalized_scale, 142 * normalized_scale)
        secondary_card_minsize = _clamped_int(height * 0.070, 50 * normalized_scale, 88 * normalized_scale)
        follow_up_minsize = _clamped_int(height * 0.145, 88 * normalized_scale, 172 * normalized_scale)
        legend_pad_y = _clamped_int(height * 0.014, 7 * normalized_scale, 18 * normalized_scale)
        legend_visible = True
        date_font = max(1, int(18 * normalized_scale))
        clock_font = max(1, int(24 * normalized_scale))
        date_gap = 5
        clock_gap = 20
        card_padding = 20
        context_padding = 16
        secondary_card_padding = 10

        value_candidate = min(width * 0.060, height * 0.042)
        value_font = _clamped_int(value_candidate, 18 * normalized_scale, 31 * normalized_scale)
        secondary_value_font = _clamped_int(
            min(width * 0.043, height * 0.030),
            13 * normalized_scale,
            20 * normalized_scale,
        )
        # Zero tells the Tk adapter to restore the current root-profile token;
        # the sidebar's narrow width alone must not downgrade a wide display.
        context_value_font = 0

    return RightSidebarMetrics(
        profile=name,
        short_large_text=short_large_text,
        outer_padding=outer_padding,
        card_gap=card_gap,
        primary_card_minsize=primary_card_minsize,
        secondary_card_minsize=secondary_card_minsize,
        follow_up_minsize=follow_up_minsize,
        legend_pad_y=legend_pad_y,
        legend_visible=legend_visible,
        date_font=date_font,
        clock_font=clock_font,
        date_gap=date_gap,
        clock_gap=clock_gap,
        card_padding=card_padding,
        context_padding=context_padding,
        secondary_card_padding=secondary_card_padding,
        value_font=value_font,
        secondary_value_font=secondary_value_font,
        context_value_font=context_value_font,
    )
