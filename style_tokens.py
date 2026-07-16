"""Tk-independent visual tokens for the Container Audit operator UI.

The application currently exposes ``COLOR_*`` class attributes from
``ContainerAudit``.  The constants in this module intentionally keep those
values so the application can migrate to aliases without changing its visual
contract.  ``build_style_tokens`` returns deeply immutable, scaled values that
can also be exercised without creating a Tk root.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Final


MIN_SCALE: Final[float] = 0.7
MAX_SCALE: Final[float] = 2.5
DEFAULT_SCALE: Final[float] = 1.0
DEFAULT_FONT: Final[str] = "Malgun Gothic"

# Keep these defaults byte-for-byte compatible with ContainerAudit.COLOR_*.
COLOR_BG: Final[str] = "#F3F6FA"
COLOR_SIDEBAR_BG: Final[str] = "#FFFFFF"
COLOR_CARD_BG: Final[str] = "#F8FAFC"
COLOR_SURFACE_ALT: Final[str] = "#EEF3F8"
COLOR_TEXT: Final[str] = "#172033"
COLOR_TEXT_SUBTLE: Final[str] = "#667085"
COLOR_PRIMARY: Final[str] = "#2563EB"
COLOR_PRIMARY_HOVER: Final[str] = "#1D4ED8"
COLOR_PRIMARY_SOFT: Final[str] = "#DBEAFE"
COLOR_SUCCESS: Final[str] = "#16A34A"
COLOR_SUCCESS_HOVER: Final[str] = "#15803D"
COLOR_DANGER: Final[str] = "#DC2626"
COLOR_DANGER_HOVER: Final[str] = "#B91C1C"
COLOR_IDLE: Final[str] = "#F59E0B"
COLOR_IDLE_BG: Final[str] = "#FFF7ED"
COLOR_IDLE_TEXT: Final[str] = "#92400E"
COLOR_BORDER: Final[str] = "#D7DEE8"
COLOR_BORDER_STRONG: Final[str] = "#AEB8C6"
COLOR_VELVET: Final[str] = "#991B1B"
COLOR_INPUT_BG: Final[str] = "#FFFFFF"

# Additional soft surfaces do not replace any existing application constant.
COLOR_SUCCESS_SOFT: Final[str] = "#DCFCE7"
COLOR_DANGER_SOFT: Final[str] = "#FEE2E2"


class StyleProfile(str, Enum):
    """Content-size profile; independent from a physical monitor name."""

    COMPACT = "compact"
    STANDARD = "standard"
    WIDE = "wide"


@dataclass(frozen=True, slots=True)
class SemanticColors:
    canvas: str = COLOR_BG
    sidebar: str = COLOR_SIDEBAR_BG
    card: str = COLOR_CARD_BG
    surface_alt: str = COLOR_SURFACE_ALT
    input: str = COLOR_INPUT_BG
    text: str = COLOR_TEXT
    text_subtle: str = COLOR_TEXT_SUBTLE
    primary: str = COLOR_PRIMARY
    primary_hover: str = COLOR_PRIMARY_HOVER
    primary_soft: str = COLOR_PRIMARY_SOFT
    success: str = COLOR_SUCCESS
    success_hover: str = COLOR_SUCCESS_HOVER
    success_soft: str = COLOR_SUCCESS_SOFT
    danger: str = COLOR_DANGER
    danger_hover: str = COLOR_DANGER_HOVER
    danger_soft: str = COLOR_DANGER_SOFT
    warning: str = COLOR_IDLE
    warning_background: str = COLOR_IDLE_BG
    warning_text: str = COLOR_IDLE_TEXT
    border: str = COLOR_BORDER
    border_strong: str = COLOR_BORDER_STRONG
    record_accent: str = COLOR_VELVET


@dataclass(frozen=True, slots=True)
class StateLabels:
    """Text labels that keep state understandable without relying on color."""

    waiting: str = "대기"
    active: str = "작업 중"
    success: str = "완료"
    warning: str = "주의"
    error: str = "오류"
    operator_review: str = "확인 필요"
    retry_wait: str = "서버 재시도 대기"
    recovered: str = "복구됨"


@dataclass(frozen=True, slots=True)
class StateStyle:
    label: str
    foreground: str
    background: str
    border: str


@dataclass(frozen=True, slots=True)
class StateStyles:
    waiting: StateStyle
    active: StateStyle
    success: StateStyle
    warning: StateStyle
    error: StateStyle
    operator_review: StateStyle
    retry_wait: StateStyle
    recovered: StateStyle


@dataclass(frozen=True, slots=True)
class FontTokens:
    family: str
    caption: int
    body: int
    sidebar: int
    button: int
    section_title: int
    item_title: int
    stage_title: int
    counter: int
    scan_input: int


@dataclass(frozen=True, slots=True)
class SpacingTokens:
    xxs: int
    xs: int
    sm: int
    md: int
    lg: int
    xl: int
    xxl: int


@dataclass(frozen=True, slots=True)
class ButtonTokens:
    primary_min_height: int
    support_min_height: int
    danger_min_height: int


@dataclass(frozen=True, slots=True)
class ComponentTokens:
    row_height: int
    progress_thickness: int
    scan_input_min_height: int


@dataclass(frozen=True, slots=True)
class StyleTokens:
    profile: StyleProfile
    scale: float
    colors: SemanticColors
    labels: StateLabels
    states: StateStyles
    fonts: FontTokens
    spacing: SpacingTokens
    buttons: ButtonTokens
    components: ComponentTokens


DEFAULT_COLORS: Final[SemanticColors] = SemanticColors()
DEFAULT_STATE_LABELS: Final[StateLabels] = StateLabels()


@dataclass(frozen=True, slots=True)
class _ProfileBase:
    caption: int
    body: int
    sidebar: int
    button: int
    section_title: int
    item_title: int
    stage_title: int
    counter: int
    scan_input: int
    spacing: tuple[int, int, int, int, int, int, int]
    button_heights: tuple[int, int, int]
    row_height: int
    progress_thickness: int
    scan_input_min_height: int


_PROFILE_BASES: Final[dict[StyleProfile, _ProfileBase]] = {
    StyleProfile.COMPACT: _ProfileBase(
        caption=10,
        body=12,
        sidebar=12,
        button=12,
        section_title=15,
        item_title=18,
        stage_title=24,
        counter=50,
        scan_input=24,
        spacing=(2, 4, 6, 10, 14, 20, 28),
        button_heights=(44, 40, 40),
        row_height=28,
        progress_thickness=16,
        scan_input_min_height=48,
    ),
    StyleProfile.STANDARD: _ProfileBase(
        caption=11,
        body=14,
        sidebar=14,
        button=14,
        section_title=18,
        item_title=20,
        stage_title=28,
        counter=60,
        scan_input=28,
        spacing=(3, 6, 8, 12, 18, 24, 32),
        button_heights=(48, 44, 44),
        row_height=32,
        progress_thickness=20,
        scan_input_min_height=56,
    ),
    StyleProfile.WIDE: _ProfileBase(
        caption=12,
        body=15,
        sidebar=16,
        button=15,
        section_title=20,
        item_title=22,
        stage_title=32,
        counter=68,
        scan_input=32,
        spacing=(4, 8, 10, 16, 22, 30, 40),
        button_heights=(52, 48, 48),
        row_height=36,
        progress_thickness=22,
        scan_input_min_height=60,
    ),
}


def clamp_scale(value: object) -> float:
    """Return a finite UI scale constrained to the supported range."""

    if isinstance(value, bool):
        return DEFAULT_SCALE
    try:
        scale = float(value)
    except (TypeError, ValueError):
        return DEFAULT_SCALE
    if not math.isfinite(scale):
        return DEFAULT_SCALE
    return max(MIN_SCALE, min(MAX_SCALE, scale))


def normalize_profile(value: StyleProfile | str) -> StyleProfile:
    if isinstance(value, StyleProfile):
        return value
    try:
        return StyleProfile(str(value).strip().lower())
    except ValueError as exc:
        choices = ", ".join(profile.value for profile in StyleProfile)
        raise ValueError(f"unknown style profile {value!r}; expected one of: {choices}") from exc


def _scaled(value: int, scale: float, *, minimum: int = 1) -> int:
    return max(minimum, int(round(value * scale)))


def _build_state_styles(colors: SemanticColors, labels: StateLabels) -> StateStyles:
    return StateStyles(
        waiting=StateStyle(labels.waiting, colors.text_subtle, colors.surface_alt, colors.border),
        active=StateStyle(labels.active, colors.primary, colors.primary_soft, colors.primary),
        success=StateStyle(labels.success, colors.success, colors.success_soft, colors.success),
        warning=StateStyle(labels.warning, colors.warning_text, colors.warning_background, colors.warning),
        error=StateStyle(labels.error, colors.danger, colors.danger_soft, colors.danger),
        operator_review=StateStyle(
            labels.operator_review,
            colors.danger,
            colors.danger_soft,
            colors.danger,
        ),
        retry_wait=StateStyle(labels.retry_wait, colors.primary, colors.primary_soft, colors.primary),
        recovered=StateStyle(labels.recovered, colors.primary, colors.primary_soft, colors.primary),
    )


def build_style_tokens(
    profile: StyleProfile | str = StyleProfile.STANDARD,
    scale: object = DEFAULT_SCALE,
    *,
    colors: SemanticColors = DEFAULT_COLORS,
    labels: StateLabels = DEFAULT_STATE_LABELS,
) -> StyleTokens:
    """Build immutable tokens for a content-size profile and user scale."""

    normalized_profile = normalize_profile(profile)
    normalized_scale = clamp_scale(scale)
    base = _PROFILE_BASES[normalized_profile]

    sidebar_minimum = {
        StyleProfile.COMPACT: 11,
        StyleProfile.STANDARD: 12,
        StyleProfile.WIDE: 14,
    }[normalized_profile]
    fonts = FontTokens(
        family=DEFAULT_FONT,
        caption=_scaled(base.caption, normalized_scale, minimum=9),
        body=_scaled(base.body, normalized_scale, minimum=11),
        sidebar=_scaled(base.sidebar, normalized_scale, minimum=sidebar_minimum),
        button=_scaled(base.button, normalized_scale, minimum=11),
        section_title=_scaled(base.section_title, normalized_scale, minimum=13),
        item_title=_scaled(base.item_title, normalized_scale, minimum=16),
        stage_title=_scaled(base.stage_title, normalized_scale, minimum=18),
        counter=_scaled(base.counter, normalized_scale, minimum=40),
        scan_input=_scaled(base.scan_input, normalized_scale, minimum=20),
    )

    spacing_values = tuple(_scaled(value, normalized_scale) for value in base.spacing)
    spacing = SpacingTokens(*spacing_values)
    primary_height, support_height, danger_height = base.button_heights
    buttons = ButtonTokens(
        primary_min_height=_scaled(primary_height, normalized_scale, minimum=36),
        support_min_height=_scaled(support_height, normalized_scale, minimum=36),
        danger_min_height=_scaled(danger_height, normalized_scale, minimum=36),
    )
    components = ComponentTokens(
        row_height=_scaled(base.row_height, normalized_scale, minimum=24),
        progress_thickness=_scaled(base.progress_thickness, normalized_scale, minimum=12),
        scan_input_min_height=_scaled(base.scan_input_min_height, normalized_scale, minimum=42),
    )
    return StyleTokens(
        profile=normalized_profile,
        scale=normalized_scale,
        colors=colors,
        labels=labels,
        states=_build_state_styles(colors, labels),
        fonts=fonts,
        spacing=spacing,
        buttons=buttons,
        components=components,
    )


DEFAULT_STYLE_TOKENS: Final[StyleTokens] = build_style_tokens()


__all__ = [
    "ButtonTokens",
    "COLOR_BG",
    "COLOR_BORDER",
    "COLOR_BORDER_STRONG",
    "COLOR_CARD_BG",
    "COLOR_DANGER",
    "COLOR_DANGER_HOVER",
    "COLOR_DANGER_SOFT",
    "COLOR_IDLE",
    "COLOR_IDLE_BG",
    "COLOR_IDLE_TEXT",
    "COLOR_INPUT_BG",
    "COLOR_PRIMARY",
    "COLOR_PRIMARY_HOVER",
    "COLOR_PRIMARY_SOFT",
    "COLOR_SIDEBAR_BG",
    "COLOR_SUCCESS",
    "COLOR_SUCCESS_HOVER",
    "COLOR_SUCCESS_SOFT",
    "COLOR_SURFACE_ALT",
    "COLOR_TEXT",
    "COLOR_TEXT_SUBTLE",
    "COLOR_VELVET",
    "ComponentTokens",
    "DEFAULT_COLORS",
    "DEFAULT_FONT",
    "DEFAULT_SCALE",
    "DEFAULT_STATE_LABELS",
    "DEFAULT_STYLE_TOKENS",
    "FontTokens",
    "MAX_SCALE",
    "MIN_SCALE",
    "SemanticColors",
    "SpacingTokens",
    "StateLabels",
    "StateStyle",
    "StateStyles",
    "StyleProfile",
    "StyleTokens",
    "build_style_tokens",
    "clamp_scale",
    "normalize_profile",
]
