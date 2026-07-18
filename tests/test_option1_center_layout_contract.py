from __future__ import annotations

import math
from typing import Iterable

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from responsive_layout import (
    center_layout_metrics,
    pane_layout_metrics,
    scanned_list_metrics,
    select_layout_profile,
)
from style_tokens import build_style_tokens
from warning_presenter import Notice, NoticeSeverity, WarningPresenter


DISPLAY_WIDTH = 1366
DISPLAY_HEIGHT = 768
LAST_NORMAL = "AAA2270730200-DEMO-QT3-0001"
REJECTED_DUPLICATE = "AAA2270730200-DEMO-QT3-DUPLICATE"


class FakeWidget:
    """Tk-shaped widget that records state and geometry without a display."""

    def __init__(self, master=None, *args, kind="Widget", **kwargs):
        self.master = master
        self.kind = kind
        self.options = dict(kwargs)
        self.children: list[FakeWidget] = []
        self.grid_options: dict[str, object] = {}
        self.grid_rows: dict[int, dict[str, object]] = {}
        self.grid_columns: dict[int, dict[str, object]] = {}
        self.bindings: list[tuple[object, ...]] = []
        self.items: list[str] = []
        self.item_options: dict[int, dict[str, object]] = {}
        self.menu_entries: list[tuple[str, dict[str, object]]] = []
        self.pixel_width = 800
        self.pixel_height = 700
        if isinstance(master, FakeWidget):
            master.children.append(self)

    def set_size(self, width: int, height: int) -> None:
        self.pixel_width = width
        self.pixel_height = height

    def grid(self, **kwargs) -> None:
        self.grid_options.update(kwargs)
        self.grid_options["mapped"] = True

    def grid_configure(self, **kwargs) -> None:
        self.grid_options.update(kwargs)

    def grid_forget(self) -> None:
        self.grid_options["mapped"] = False

    def grid_rowconfigure(self, row, **kwargs) -> None:
        self.grid_rows.setdefault(int(row), {}).update(kwargs)

    def grid_columnconfigure(self, column, **kwargs) -> None:
        self.grid_columns.setdefault(int(column), {}).update(kwargs)

    def bind(self, sequence, callback, add=None) -> None:
        self.bindings.append((sequence, callback, add))

    def configure(self, **kwargs) -> None:
        self.options.update(kwargs)

    config = configure

    def winfo_exists(self) -> bool:
        return True

    def winfo_width(self) -> int:
        return self.pixel_width

    def winfo_height(self) -> int:
        return self.pixel_height

    def winfo_children(self) -> list[FakeWidget]:
        return list(self.children)

    def winfo_ismapped(self) -> bool:
        return bool(self.grid_options.get("mapped", False))

    def insert(self, index, value) -> None:
        if index in ("end", container_audit_module.tk.END):
            self.items.append(str(value))
            return
        self.items.insert(int(index), str(value))

    def delete(self, first, last=None) -> None:
        if not self.items:
            return
        first_index = len(self.items) - 1 if first in ("end", container_audit_module.tk.END) else int(first)
        if last is None:
            del self.items[first_index]
            return
        last_index = len(self.items) - 1 if last in ("end", container_audit_module.tk.END) else int(last)
        del self.items[first_index:last_index + 1]

    def get(self, first, last=None):
        first_index = len(self.items) - 1 if first in ("end", container_audit_module.tk.END) else int(first)
        if last is None:
            return self.items[first_index]
        last_index = len(self.items) - 1 if last in ("end", container_audit_module.tk.END) else int(last)
        return tuple(self.items[first_index:last_index + 1])

    def size(self) -> int:
        return len(self.items)

    def yview(self, *args):
        return tuple(args)

    def set(self, *args) -> None:
        self.options["set"] = tuple(args)

    def itemconfig(self, index, options=None, **kwargs) -> None:
        values = dict(options or {})
        values.update(kwargs)
        self.item_options.setdefault(int(index), {}).update(values)

    itemconfigure = itemconfig

    def add_command(self, **kwargs) -> None:
        self.menu_entries.append(("command", dict(kwargs)))

    def add_separator(self, **kwargs) -> None:
        self.menu_entries.append(("separator", dict(kwargs)))

    def __getitem__(self, key):
        return self.options.get(key)

    def __setitem__(self, key, value) -> None:
        self.options[key] = value


class FakeRoot(FakeWidget):
    def __init__(self):
        super().__init__(kind="Root")
        self.after_calls: list[tuple[object, ...]] = []

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
        return FakeWidget(master, *args, kind=kind, **kwargs)

    return create


def _walk(widget: FakeWidget) -> Iterable[FakeWidget]:
    yield widget
    for child in widget.children:
        yield from _walk(child)


def _text(widget: FakeWidget) -> str:
    return str(widget.options.get("text", "")).strip()


def _action_role(widget: FakeWidget) -> str | None:
    text = _text(widget)
    if "운영 작업" in text:
        return "operations"
    if "제출" in text or "판정 다시 확인" in text:
        return "submit"
    if "스캔 취소" in text:
        return "undo"
    if "보류" in text:
        return "park"
    return None


def _button_widgets(frame: FakeWidget) -> list[FakeWidget]:
    return [
        widget
        for widget in _walk(frame)
        if widget.kind.endswith("Button") or widget.kind.endswith("Menubutton")
        if widget.grid_options.get("mapped") is True
    ]


def _geometry(widget: FakeWidget) -> tuple[object, ...]:
    keys = ("row", "column", "rowspan", "columnspan", "sticky", "padx", "pady", "ipadx", "ipady")
    return (id(widget.master),) + tuple(widget.grid_options.get(key) for key in keys)


def _center_geometry_snapshot(app: ContainerAudit) -> dict[str, object]:
    action_buttons = _button_widgets(app._center_button_frame)
    return {
        "scan_frame": _geometry(app._scan_list_frame),
        "scan_list": _geometry(app.scanned_listbox),
        "action_frame": _geometry(app._center_button_frame),
        "actions": tuple(sorted((_action_role(button), _geometry(button)) for button in action_buttons)),
    }


@pytest.fixture
def fake_tk(monkeypatch):
    for name in ("Frame", "Label", "Button", "Menubutton", "Entry", "Listbox", "Menu"):
        monkeypatch.setattr(container_audit_module.tk, name, _factory(f"tk.{name}"), raising=False)
    for name in (
        "Frame",
        "Label",
        "Button",
        "Menubutton",
        "Progressbar",
        "LabelFrame",
        "Scrollbar",
    ):
        monkeypatch.setattr(container_audit_module.ttk, name, _factory(f"ttk.{name}"), raising=False)


def _build_center(*, scale: float) -> tuple[ContainerAudit, FakeWidget]:
    panes = pane_layout_metrics(DISPLAY_WIDTH, DISPLAY_HEIGHT, scale)
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = FakeRoot()
    app.scale_factor = scale
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730200|QT=3",
        item_code="AAA2270730200",
        item_name="계약 테스트 품목",
        scanned_barcodes=[LAST_NORMAL],
        tray_size=3,
    )
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(LAST_NORMAL)
    app.info_cards = {}
    app._update_action_button_states = lambda: None

    center = FakeWidget(kind="CenterPane")
    center.set_size(panes.center_width, DISPLAY_HEIGHT)
    app._create_center_content(center)
    app.scanned_listbox.insert(0, app._format_scanned_list_row(1, LAST_NORMAL))
    app._apply_center_layout(center, panes.center_width, DISPLAY_HEIGHT)
    return app, center


@pytest.mark.parametrize("scale", [1.0, 1.1, 1.2, 1.3, 1.4])
def test_1366_layout_budget_reserves_scan_list_and_one_four_button_row(scale):
    panes = pane_layout_metrics(DISPLAY_WIDTH, DISPLAY_HEIGHT, scale)
    profile = select_layout_profile(DISPLAY_WIDTH, DISPLAY_HEIGHT, scale)
    center = center_layout_metrics(panes.center_width, DISPLAY_HEIGHT, scale)
    scan_list = scanned_list_metrics(
        panes.center_width,
        DISPLAY_HEIGHT,
        center.list_minsize,
        scale,
    )
    tokens = build_style_tokens(profile.name, scale)

    # Option 1 keeps a 1x4 action row until the center pane is truly narrow.
    assert panes.center_width >= 620
    action_gap = tokens.spacing.sm
    action_inner_width = panes.center_width - 2 * center.horizontal_pad - 3 * action_gap
    available_per_button = action_inner_width // 4
    compact_label_width = math.ceil(tokens.fonts.button * 6.5 + tokens.spacing.md * 2)
    assert available_per_button >= compact_label_width

    # This is a deliberately conservative one-line height budget. It includes
    # the persistent header and a full-height primary action button; no row may
    # depend on clipping below the 768px center pane.
    hero_height = (
        center.item_top
        + center.item_bottom
        + tokens.fonts.body
        + tokens.fonts.item_title
        + tokens.spacing.xs
    )
    counter_height = center.count_top + center.count_bottom + tokens.fonts.counter
    progress_height = tokens.components.progress_thickness + center.progress_bottom
    input_height = max(
        tokens.components.scan_input_min_height,
        tokens.fonts.scan_input + center.entry_ipady * 2,
    )
    header_height = max(
        tokens.components.row_height,
        tokens.fonts.body + tokens.spacing.xs * 2,
    )
    scan_list_height = header_height + center.list_minsize + scan_list.top_pady
    action_height = (
        center.button_top
        + max(tokens.buttons.primary_min_height, tokens.buttons.support_min_height)
        + tokens.spacing.sm
    )
    required_height = sum(
        (
            hero_height,
            counter_height,
            progress_height,
            input_height,
            center.warning_band_height,
            scan_list_height,
            action_height,
        )
    )
    assert required_height <= DISPLAY_HEIGHT


@pytest.mark.parametrize("scale", [1.0, 1.2, 1.4])
def test_option1_center_uses_fixed_scan_header_and_one_by_four_actions(fake_tk, scale):
    app, center = _build_center(scale=scale)

    assert app._scan_list_frame.master is center
    assert app._scan_list_frame.grid_options["row"] == 5
    assert app.scanned_listbox.master is app._scan_list_frame
    assert app.scanned_listbox.grid_options["row"] == 1
    assert app._scan_list_frame.grid_rows[1]["weight"] > 0
    assert center.grid_rows[5]["weight"] > 0

    header_row = [
        child
        for child in app._scan_list_frame.children
        if child.grid_options.get("row") == 0
    ]
    assert len(header_row) == 1
    header_texts = {_text(widget) for widget in _walk(header_row[0])}
    assert any("현재 트레이 스캔 목록" in text for text in header_texts)

    buttons = _button_widgets(app._center_button_frame)
    roles = [_action_role(button) for button in buttons]
    assert len(buttons) == 4
    assert set(roles) == {"undo", "park", "submit", "operations"}
    assert len({id(button.master) for button in buttons}) == 1
    assert {button.grid_options.get("row") for button in buttons} == {0}
    assert {button.grid_options.get("column") for button in buttons} == {0, 1, 2, 3}
    ordered_roles = [
        _action_role(button)
        for button in sorted(buttons, key=lambda widget: int(widget.grid_options["column"]))
    ]
    assert ordered_roles == ["undo", "park", "submit", "operations"]
    assert app._center_button_frame.grid_options["row"] > app._scan_list_frame.grid_options["row"]


def test_duplicate_notice_preserves_scan_list_last_normal_and_center_geometry(fake_tk):
    app, _center = _build_center(scale=1.4)
    app.last_scan_value_label = FakeWidget(kind="ttk.Label", text="-")
    app.follow_up_label = FakeWidget(kind="ttk.Label", text="-")
    app._render_warning_state()

    rows_before = tuple(app.scanned_listbox.items)
    geometry_before = _center_geometry_snapshot(app)
    header_before = {
        _text(widget)
        for widget in _walk(app._scan_list_frame)
        if _text(widget)
    }

    app.warning_presenter.present(
        Notice(
            code="scan.duplicate",
            title="중복 스캔",
            message=f"이미 등록된 제품입니다: {REJECTED_DUPLICATE}",
            severity=NoticeSeverity.ERROR,
            blocking=True,
        )
    )
    app._render_warning_state()

    assert tuple(app.scanned_listbox.items) == rows_before
    assert all(REJECTED_DUPLICATE not in row for row in app.scanned_listbox.items)
    assert app.warning_presenter.state.last_normal_scan == LAST_NORMAL
    assert app.last_scan_value_label.options["text"] == app._format_last_normal_scan_value(
        LAST_NORMAL
    )
    assert _center_geometry_snapshot(app) == geometry_before
    assert {
        _text(widget)
        for widget in _walk(app._scan_list_frame)
        if _text(widget)
    } == header_before
