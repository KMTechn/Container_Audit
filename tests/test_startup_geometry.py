from __future__ import annotations

import ctypes
from ctypes import wintypes
from types import SimpleNamespace

import pytest

import Container_Audit as container_audit_module
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


class GeometryConfigured(Exception):
    """Stop normal construction before audio, settings or business state."""


class StartupRoot(FakeRoot):
    def __init__(self, *, zoom_supported=True):
        super().__init__()
        self.minimum = (1, 1)
        self.zoom_supported = zoom_supported

    def title(self, _value):
        pass

    def minsize(self, *size):
        if size:
            self.minimum = size
        return self.minimum

    def state(self, value):
        self.calls.append(("state", value))
        if not self.zoom_supported:
            raise container_audit_module.tk.TclError("zoom unsupported")

    def withdraw(self):
        self.calls.append(("withdraw", None))

    def deiconify(self):
        self.calls.append(("deiconify", None))

    def configure(self, **_options):
        raise GeometryConfigured


def start_geometry_only(monkeypatch, root):
    monkeypatch.setattr(container_audit_module, "container_startup_logistics_client", lambda: None)
    monkeypatch.setattr(container_audit_module.tk, "Tk", lambda: root)
    with pytest.raises(GeometryConfigured):
        container_audit_module.ContainerAudit()


@pytest.mark.parametrize(
    "work_area,outer,expected_size,expected_minimum,expected_position,zoom_supported",
    (
        ((0, 0, 1920, 1040), (100, 80, 1396, 939), "1280x820", (1024, 720), None, True),
        ((0, 0, 1366, 728), (100, 80, 1396, 939), "1280x689", (1024, 689), (70, 0), True),
        ((40, 30, 1000, 670), (100, 80, 1396, 939), "944x601", (944, 601), (40, 30), True),
        ((-1920, -900, 0, -60), (-1800, -780, -504, 79), "1280x801", (1024, 720), (-1800, -900), True),
        ((80, 32, 1366, 760), (100, 80, 1396, 939), "1270x689", (1024, 689), (80, 32), False),
    ),
)
def test_normal_startup_fits_client_frame_and_minimum_to_work_area(
    monkeypatch, work_area, outer, expected_size, expected_minimum, expected_position, zoom_supported
):
    monkeypatch.delenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", raising=False)
    root = StartupRoot(zoom_supported=zoom_supported)
    monkeypatch.setattr(
        container_audit_module,
        "_get_tk_root_work_area",
        lambda _root: (work_area, outer, (1280, 820)),
        raising=False,
    )
    positions = []
    monkeypatch.setattr(
        container_audit_module, "_position_tk_root_absolute",
        lambda _root, left, top: positions.append((left, top)),
    )

    start_geometry_only(monkeypatch, root)

    sizes = [value for action, value in root.calls if action == "geometry"]
    assert sizes[-1] == expected_size
    assert root.minimum == expected_minimum
    assert positions == ([] if expected_position is None else [expected_position])
    assert root.calls[-1] == ("state", "zoomed")


def test_explicit_startup_geometry_bypasses_ordinary_work_area_fit(monkeypatch):
    monkeypatch.setenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", "1440x900+1253-1194")
    root = StartupRoot()
    monkeypatch.setattr(
        container_audit_module, "_get_tk_root_work_area",
        lambda _root: pytest.fail("explicit placement must not be fitted"), raising=False,
    )
    positions = []
    monkeypatch.setattr(
        container_audit_module, "_position_tk_root_absolute",
        lambda _root, left, top: positions.append((left, top)),
    )

    start_geometry_only(monkeypatch, root)

    assert ("geometry", "1440x900+1253-1194") in root.calls
    assert positions == [(1253, -1194)]
    assert ("state", "zoomed") not in root.calls
    assert root.minimum == (1024, 720)


def test_work_area_reader_uses_root_window_and_monitor_work_rect(monkeypatch):
    child, wrapper, monitor = 0x100000001, 0x100000002, 0x100000003
    monkeypatch.setattr(container_audit_module, "os", SimpleNamespace(name="nt"))

    def get_ancestor(hwnd, flag):
        assert (hwnd.value, flag) == (child, 2)
        return wrapper

    def monitor_from_window(hwnd, flag):
        assert (hwnd, flag) == (wrapper, 2)
        return monitor

    def get_monitor_info(handle, output):
        assert handle == monitor
        info = output._obj
        assert info.cbSize == ctypes.sizeof(info)
        info.rcMonitor = wintypes.RECT(-1920, -900, 0, 0)
        info.rcWork = wintypes.RECT(-1880, -870, 0, -60)
        return 1

    def rectangle_reader(values):
        def read(hwnd, output):
            assert hwnd == wrapper
            output._obj.left, output._obj.top, output._obj.right, output._obj.bottom = values
            return 1
        return read

    api = SimpleNamespace(
        GetAncestor=get_ancestor, MonitorFromWindow=monitor_from_window,
        GetMonitorInfoW=get_monitor_info,
        GetWindowRect=rectangle_reader((-1800, -780, -504, 79)),
        GetClientRect=rectangle_reader((0, 0, 1280, 820)),
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: api, raising=False)

    assert container_audit_module._get_tk_root_work_area(
        SimpleNamespace(winfo_id=lambda: child)
    ) == ((-1880, -870, 0, -60), (-1800, -780, -504, 79), (1280, 820))
    assert ctypes.sizeof(api.MonitorFromWindow.restype) == ctypes.sizeof(ctypes.c_void_p)


def test_work_area_query_failure_keeps_normal_maximized_startup(monkeypatch, capsys):
    monkeypatch.delenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", raising=False)
    root = StartupRoot()

    def unavailable(_root):
        raise OSError("monitor query failed")

    monkeypatch.setattr(container_audit_module, "_get_tk_root_work_area", unavailable)
    start_geometry_only(monkeypatch, root)

    assert root.calls[-1] == ("state", "zoomed")
    assert ("geometry", "1280x820") in root.calls
    assert "Window work-area fit unavailable" in capsys.readouterr().out
