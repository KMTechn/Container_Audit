from __future__ import annotations

import pytest

from Container_Audit import apply_startup_geometry, parse_startup_geometry


class FakeRoot:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def geometry(self, value: str) -> None:
        self.calls.append(("geometry", value))

    def update_idletasks(self) -> None:
        self.calls.append(("update_idletasks", None))


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("1440x900+1253-1194", (1440, 900, 1253, -1194)),
        ("1366x768-320+40", (1366, 768, -320, 40)),
    ),
)
def test_parse_startup_geometry_uses_absolute_signed_coordinates(value, expected):
    assert parse_startup_geometry(value) == expected


@pytest.mark.parametrize(
    "value",
    ("", "1440x900", "1440x900+1253", "wide+1253-1194"),
)
def test_parse_startup_geometry_rejects_incomplete_values(value):
    with pytest.raises(ValueError, match="invalid startup geometry"):
        parse_startup_geometry(value)


def test_apply_startup_geometry_positions_hidden_native_window_absolutely():
    root = FakeRoot()
    positioned: list[tuple[object, int, int]] = []

    parsed = apply_startup_geometry(
        root,
        "1440x900+1253-1194",
        absolute_positioner=lambda widget, left, top: positioned.append(
            (widget, left, top)
        ),
    )

    assert parsed == (1440, 900, 1253, -1194)
    assert positioned == [(root, 1253, -1194)]
    assert root.calls == [
        ("geometry", "1440x900+1253-1194"),
        ("update_idletasks", None),
        ("update_idletasks", None),
    ]
