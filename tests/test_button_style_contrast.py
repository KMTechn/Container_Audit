"""Contrast of the state maps actually configured by the headless application."""

from types import SimpleNamespace

import pytest

from Container_Audit import ContainerAudit


class _StyleLookup:
    def __init__(self):
        self.options = {}
        self.maps = {}

    def configure(self, name, **options):
        self.options.setdefault(name, {}).update(options)

    def map(self, name, **options):
        self.maps.setdefault(name, {}).update(options)

    def lookup(self, name, option, state=()):
        for *conditions, value in self.maps.get(name, {}).get(option, ()):
            if all(
                condition[1:] not in state if condition.startswith("!") else condition in state
                for condition in conditions
            ):
                return value
        if option in self.options.get(name, {}):
            return self.options[name][option]
        if "." in name:
            return self.lookup(name.split(".", 1)[1], option, state)
        raise AssertionError(f"No configured {name} {option} for {state}")


def _contrast(foreground, background):
    def luminance(color):
        color = "#FFFFFF" if color == "white" else color
        srgb = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
                  for value in srgb]
        return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

    low, high = sorted((luminance(foreground), luminance(background)))
    return (high + 0.05) / (low + 0.05)


def _scaled_styles(scale, width, height):
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = SimpleNamespace(winfo_width=lambda: width, winfo_height=lambda: height)
    app.scale_factor = scale
    app.style = _StyleLookup()
    # Font metrics affect row heights, not the button palette; no Tcl/Tk is started.
    app._font_linespace_px = lambda size, **kwargs: max(1, round(size * 1.65))
    app.apply_scaling()
    return app.style


@pytest.mark.parametrize("scale", (0.7, 1.0, 2.5))
@pytest.mark.parametrize("width,height", ((1024, 768), (1440, 900), (2560, 1440)))
def test_warning_and_success_button_text_contrast_across_states(scale, width, height):
    style = _scaled_styles(scale, width, height)
    for name in ("Warning.TButton", "Success.TButton"):
        # Use the normal-text target even when the unchanged scaled font is large.
        for state in ((), ("active",), ("pressed",), ("active", "pressed"), ("focus",),
                      ("focus", "active"), ("focus", "active", "pressed")):
            foreground = style.lookup(name, "foreground", state)
            background = style.lookup(name, "background", state)
            assert _contrast(foreground, background) >= 4.5, (name, state, foreground, background)
        # Disabled remains the existing muted convention, including pointer overlap.
        for state in (("disabled",), ("disabled", "active"), ("disabled", "active", "pressed")):
            assert style.lookup(name, "foreground", state) == "#F8FAFC"
            assert style.lookup(name, "background", state) == "#CBD5E1"
