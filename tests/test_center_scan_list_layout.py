from __future__ import annotations

from dataclasses import asdict

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit
from responsive_layout import pane_layout_metrics


class FakeWidget:
    """Small Tk-shaped object that records geometry without opening a window."""

    def __init__(self, master=None, *, kind="Widget", **kwargs):
        self.master = master
        self.kind = kind
        self.options = dict(kwargs)
        self.grid_options = {}
        self.grid_rows = {}
        self.grid_columns = {}
        self.bindings = []
        self.pixel_width = 800
        self.pixel_height = 300 if kind == "Listbox" else 700

    def set_size(self, width, height):
        self.pixel_width = width
        self.pixel_height = height

    def grid(self, **kwargs):
        self.grid_options.update(kwargs)
        self.grid_options["mapped"] = True

    def grid_configure(self, **kwargs):
        self.grid_options.update(kwargs)

    def grid_forget(self):
        self.grid_options["mapped"] = False

    def grid_rowconfigure(self, row, **kwargs):
        self.grid_rows.setdefault(row, {}).update(kwargs)

    def grid_columnconfigure(self, column, **kwargs):
        self.grid_columns.setdefault(column, {}).update(kwargs)

    def bind(self, sequence, callback, add=None):
        self.bindings.append((sequence, callback, add))

    def configure(self, **kwargs):
        self.options.update(kwargs)

    config = configure

    def winfo_exists(self):
        return True

    def winfo_width(self):
        return self.pixel_width

    def winfo_height(self):
        return self.pixel_height

    def yview(self, *args):
        return args

    def set(self, *args):
        self.options["scroll"] = args

    def __getitem__(self, key):
        return self.options.get(key)

    def __setitem__(self, key, value):
        self.options[key] = value


class FakeRoot(FakeWidget):
    def __init__(self):
        super().__init__(kind="Root")
        self.after_calls = []

    @staticmethod
    def register(callback):
        return callback

    def after(self, delay, callback, *args):
        self.after_calls.append((delay, callback, args))
        return f"after-{len(self.after_calls)}"

    def after_idle(self, callback, *args):
        return self.after(0, callback, *args)


def _factory(kind):
    def create(master=None, *args, **kwargs):
        return FakeWidget(master, kind=kind, **kwargs)

    return create


@pytest.fixture
def center_view(monkeypatch):
    for name in ("Frame", "Label", "Button", "Entry", "Listbox"):
        monkeypatch.setattr(container_audit_module.tk, name, _factory(name))
    for name in ("Frame", "Label", "Progressbar", "LabelFrame", "Button", "Scrollbar"):
        monkeypatch.setattr(container_audit_module.ttk, name, _factory(f"ttk.{name}"))

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = FakeRoot()
    app.scale_factor = 1.0
    app._render_warning_state = lambda: None
    app._update_action_button_states = lambda: None
    parent = FakeWidget(kind="CenterPane")
    app._create_center_content(parent)
    return app, parent


def _layout_snapshot(app, parent):
    return {
        "notice_row": app.notice_frame.grid_options["row"],
        "list_frame_row": app._scan_list_frame.grid_options["row"],
        "header_row": app.scanned_list_header_label.grid_options["row"],
        "list_row": app.scanned_listbox.grid_options["row"],
        "list_sticky": app.scanned_listbox.grid_options["sticky"],
        "list_row_config": dict(parent.grid_rows[5]),
        "inner_list_row_config": dict(app._scan_list_frame.grid_rows[1]),
        "font": app.scanned_listbox.options["font"],
        "height": app.scanned_listbox.options["height"],
        "padx": app.scanned_listbox.grid_options["padx"],
        "pady": app.scanned_listbox.grid_options["pady"],
    }


def _apply_full_content_size(app, parent, width, height):
    panes = pane_layout_metrics(width, height, app.scale_factor)
    parent.set_size(panes.center_width, height)
    app.scanned_listbox.pixel_height = app._get_center_layout_metrics(
        panes.center_width,
        height,
    )["list_minsize"]
    app._apply_scanned_listbox_layout()
    return panes, _layout_snapshot(app, parent)


def test_current_tray_scan_list_is_the_expanding_row_below_notice(center_view):
    app, parent = center_view

    expected = app._get_center_layout_metrics(parent.winfo_width(), parent.winfo_height())
    app._apply_center_layout(parent, parent.winfo_width(), parent.winfo_height())

    assert app.notice_frame.master is parent
    assert app._scan_list_frame.master is parent
    assert app.scanned_list_header_label.master is app._scan_list_frame
    assert app.scanned_listbox.master is app._scan_list_frame
    assert app.notice_frame.grid_options["row"] == 4
    assert app._scan_list_frame.grid_options["row"] == 5
    assert app._scan_list_frame.grid_options["row"] > app.notice_frame.grid_options["row"]
    assert app._scan_list_frame.grid_options["sticky"] == "nsew"
    assert app.scanned_list_header_label.grid_options["row"] == 0
    assert app.scanned_listbox.grid_options["row"] == 1
    assert app.scanned_listbox.grid_options["sticky"] == "nsew"
    assert parent.grid_rows[5]["weight"] > 0
    assert parent.grid_rows[5]["minsize"] == expected["list_minsize"]
    assert app._scan_list_frame.grid_rows[1]["weight"] > 0
    assert parent.grid_rows.get(4, {}).get("weight", 0) == 0


def test_scan_list_survives_compact_standard_wide_compact_round_trip(center_view):
    app, parent = center_view
    original_list = app.scanned_listbox
    original_list_frame = app._scan_list_frame

    compact_profile, compact_before = _apply_full_content_size(app, parent, 1366, 768)
    standard_profile, standard = _apply_full_content_size(app, parent, 1440, 900)
    wide_profile, wide = _apply_full_content_size(app, parent, 2560, 1080)
    compact_profile_after, compact_after = _apply_full_content_size(app, parent, 1366, 768)

    assert [compact_profile.profile, standard_profile.profile, wide_profile.profile] == [
        "compact",
        "standard",
        "wide",
    ]
    assert asdict(compact_profile_after) == asdict(compact_profile)
    assert app.scanned_listbox is original_list
    assert app._scan_list_frame is original_list_frame
    assert compact_before == compact_after
    assert standard["list_frame_row"] == wide["list_frame_row"] == compact_before["list_frame_row"] == 5
    assert standard["header_row"] == wide["header_row"] == compact_before["header_row"] == 0
    assert standard["list_row"] == wide["list_row"] == compact_before["list_row"] == 1
    assert standard["notice_row"] == wide["notice_row"] == compact_before["notice_row"] == 4
    assert standard["list_row_config"]["minsize"] > compact_before["list_row_config"]["minsize"]
    assert wide["list_row_config"]["minsize"] >= standard["list_row_config"]["minsize"]
    assert parent.grid_rows.get(4, {}).get("weight", 0) == 0
