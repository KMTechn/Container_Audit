from __future__ import annotations

import ast
import inspect
import re
import textwrap

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    Notice,
    NoticeSeverity,
    WarningPresenter,
)


class FakeWidget:
    """Tk-shaped geometry recorder used without creating a display."""

    def __init__(self, master=None, *, kind="Widget", **kwargs):
        self.master = master
        self.kind = kind
        self.options = dict(kwargs)
        self.children = []
        self.grid_options = {}
        self.pack_options = {}
        self.grid_rows = {}
        self.grid_columns = {}
        self.bindings = []
        self.items = []
        self.item_styles = {}
        self._mapped = False
        self.pixel_width = 420
        self.pixel_height = 900
        if isinstance(master, FakeWidget):
            master.children.append(self)

    def grid(self, **kwargs):
        self.grid_options.update(kwargs)
        self.grid_options["mapped"] = True
        self._mapped = True

    def grid_configure(self, **kwargs):
        self.grid_options.update(kwargs)

    def grid_forget(self):
        self.grid_options["mapped"] = False
        self._mapped = False

    def pack(self, **kwargs):
        self.pack_options.update(kwargs)
        self._mapped = True

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

    def winfo_children(self):
        return list(self.children)

    def winfo_ismapped(self):
        return self._mapped

    def cget(self, key):
        return self.options.get(key, "")

    def insert(self, index, value):
        if index in (0, "0"):
            self.items.insert(0, value)
        else:
            self.items.append(value)

    def delete(self, first, last=None):
        if not self.items:
            return
        if last in ("end", "END"):
            self.items.clear()
            self.item_styles.clear()
            return
        index = int(first)
        if last is None:
            del self.items[index]
            self.item_styles.pop(index, None)
            return
        del self.items[index : int(last) + 1]

    def get(self, first, last=None):
        if last in ("end", "END"):
            return tuple(self.items[int(first) :])
        if last is None:
            return self.items[int(first)]
        return tuple(self.items[int(first) : int(last) + 1])

    def itemconfig(self, index, options=None, **kwargs):
        values = dict(options or {})
        values.update(kwargs)
        self.item_styles[int(index)] = values

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


def _walk(widget):
    yield widget
    for child in widget.children:
        yield from _walk(child)


@pytest.fixture
def operator_view(monkeypatch):
    for name in ("Frame", "Label", "Button", "Entry", "Listbox"):
        monkeypatch.setattr(container_audit_module.tk, name, _factory(f"tk.{name}"))
    for name in (
        "Frame",
        "Label",
        "Progressbar",
        "LabelFrame",
        "Button",
        "Treeview",
        "Separator",
        "Scrollbar",
    ):
        monkeypatch.setattr(container_audit_module.ttk, name, _factory(f"ttk.{name}"))

    app = ContainerAudit.__new__(ContainerAudit)
    app.root = FakeRoot()
    app.scale_factor = 1.0
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.warning_presenter = WarningPresenter()
    app.info_cards = {}
    app._update_action_button_states = lambda: None

    center = FakeWidget(kind="CenterPane")
    center.pixel_width = 900
    right = FakeWidget(kind="RightPane")
    app._create_center_content(center)
    app._create_right_sidebar_content(right)
    return app, center, right


def test_center_has_the_only_full_scan_history_and_right_has_no_history_table(operator_view):
    app, center, right = operator_view

    center_lists = [widget for widget in _walk(center) if widget.kind == "tk.Listbox"]
    right_lists = [
        widget
        for widget in _walk(right)
        if widget.kind in {"tk.Listbox", "ttk.Treeview", "ttk.Progressbar"}
    ]

    assert center_lists == [app.scanned_listbox]
    assert app._scan_list_frame.master is center
    assert app._scan_list_frame.grid_options["row"] == 5
    assert app._scan_list_frame.grid_options["sticky"] == "nsew"
    assert app.scanned_list_header_label.master is app._scan_list_frame
    assert app.scanned_list_header_label.grid_options["row"] == 0
    assert "현재 트레이 스캔 목록" in app.scanned_list_header_label.options["text"]
    assert app.scanned_listbox.master is app._scan_list_frame
    assert app.scanned_listbox.grid_options["row"] == 1
    assert app.scanned_listbox.grid_options["sticky"] == "nsew"
    assert app._scan_list_frame.grid_rows[1]["weight"] > 0
    assert center.grid_rows[5]["weight"] > 0
    assert right_lists == []

    source = textwrap.dedent(inspect.getsource(ContainerAudit._create_right_sidebar_content))
    tree = ast.parse(source)
    history_widget_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"Listbox", "Treeview", "Progressbar"}
    }
    assert history_widget_calls == set()


def test_four_exposed_actions_use_one_row_then_two_by_two_without_exposing_operations(operator_view):
    app, _center, _right = operator_view
    exposed = [
        app.undo_button,
        app.park_button,
        app.submit_tray_button,
        app.operations_button,
    ]

    assert app._center_action_buttons == exposed
    assert {button.master for button in exposed} == {app._center_button_frame}
    for hidden_operation in (
        app.reset_button,
        app.replace_master_label_button,
        app.exchange_button,
    ):
        assert hidden_operation.master is app._center_button_frame
        assert hidden_operation.winfo_ismapped() is False

    app._layout_center_action_buttons(815, 8)
    assert [
        (button.grid_options["row"], button.grid_options["column"])
        for button in exposed
    ] == [(0, 0), (0, 1), (0, 2), (0, 3)]

    compact_review_labels = app._action_button_labels(
        compact=True,
        operator_review=True,
        replacement_active=False,
        exchange_dialog_open=False,
        exact_exchange_blocked=False,
    )
    assert compact_review_labels["submit"] == "담당자 확인"

    app._layout_center_action_buttons(580, 8)
    assert [
        (button.grid_options["row"], button.grid_options["column"])
        for button in exposed
    ] == [(0, 0), (0, 1), (1, 0), (1, 1)]

    app._layout_center_action_buttons(815, 8)
    assert [
        (button.grid_options["row"], button.grid_options["column"])
        for button in exposed
    ] == [(0, 0), (0, 1), (0, 2), (0, 3)]


def _replace_scan_rows(app, barcodes):
    app.scanned_listbox.delete(0, "end")
    for index, barcode in enumerate(barcodes, start=1):
        app.scanned_listbox.insert(0, f"({index}) {barcode}")


def _scan_list_geometry(app, center):
    return {
        "frame_identity": id(app._scan_list_frame),
        "frame_parent": app._scan_list_frame.master,
        "frame_grid": dict(app._scan_list_frame.grid_options),
        "frame_rows": dict(app._scan_list_frame.grid_rows),
        "header_identity": id(app.scanned_list_header_label),
        "header_grid": dict(app.scanned_list_header_label.grid_options),
        "list_identity": id(app.scanned_listbox),
        "list_parent": app.scanned_listbox.master,
        "list_grid": dict(app.scanned_listbox.grid_options),
        "center_row": dict(center.grid_rows[5]),
    }


def test_scan_list_frame_and_widget_survive_error_completion_and_recovery_states(operator_view):
    app, center, _right = operator_view
    app._apply_center_layout(center, 900, 900)
    baseline_geometry = _scan_list_geometry(app, center)
    barcodes = ["AAA2270730100-001", "AAA2270730100-002", "AAA2270730100-003"]
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=list(barcodes),
        tray_size=3,
    )
    _replace_scan_rows(app, barcodes)
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(barcodes[-1])
    app._update_center_display()
    normal_rows = tuple(app.scanned_listbox.items)

    app.warning_presenter.present(
        Notice(
            code="scan.duplicate",
            title="중복 스캔",
            message="이미 처리된 제품입니다.",
            severity=NoticeSeverity.ERROR,
            blocking=True,
        )
    )
    app._update_center_display()
    assert tuple(app.scanned_listbox.items) == normal_rows
    assert _scan_list_geometry(app, center) == baseline_geometry

    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(barcodes[-1])
    app.warning_presenter.present_completion(
        CompletionOutcomeSnapshot(
            outcome=CompletionOutcome.OPERATOR_REVIEW,
            item_name="fixture item",
            master_label=app.current_tray.master_label_code,
            scan_count=3,
            target_count=3,
            message="담당자 확인이 필요합니다.",
        )
    )
    app._update_center_display()
    assert tuple(app.scanned_listbox.items) == normal_rows
    assert _scan_list_geometry(app, center) == baseline_geometry

    app.current_tray = TraySession()
    _replace_scan_rows(app, ())
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(barcodes[-1])
    app.warning_presenter.present_completion(
        CompletionOutcomeSnapshot(
            outcome=CompletionOutcome.ACKED,
            item_name="fixture item",
            master_label="PHS=2|CLC=AAA2270730100|QT=3",
            scan_count=3,
            target_count=3,
            message="서버 이적 확인이 완료되었습니다.",
        )
    )
    app._update_center_display()
    assert app.scanned_listbox.items == []
    assert _scan_list_geometry(app, center) == baseline_geometry

    recovered = barcodes[:2]
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=list(recovered),
        tray_size=3,
        is_restored_session=True,
    )
    _replace_scan_rows(app, recovered)
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.record_normal_scan(recovered[-1])
    app.warning_presenter.present(
        Notice(
            code="tray.recovered",
            title="작업 복구 완료",
            message="중앙 목록을 확인하고 다음 제품을 스캔하세요.",
            severity=NoticeSeverity.SUCCESS,
        )
    )
    app._update_center_display()
    assert len(app.scanned_listbox.items) == len(app.current_tray.scanned_barcodes) == 2
    assert "2건" in app.scanned_list_header_label.options["text"]
    assert _scan_list_geometry(app, center) == baseline_geometry


def test_duplicate_notice_acknowledgement_restores_working_display_without_changing_scan_context(
    operator_view,
):
    app, _center, _right = operator_view
    barcodes = ["AAA2270730100-001", "AAA2270730100-002"]
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=list(barcodes),
        tray_size=3,
    )
    _replace_scan_rows(app, barcodes)
    app.warning_presenter.record_normal_scan(barcodes[-1])
    duplicate_notice = Notice(
        code="scan.duplicate",
        title="중복 스캔",
        message="이미 처리된 제품입니다.",
        severity=NoticeSeverity.ERROR,
        blocking=True,
    )
    assert app.warning_presenter.present(duplicate_notice) is True
    assert app.warning_presenter.present(duplicate_notice) is False
    app._update_center_display()

    rows_before_ack = tuple(app.scanned_listbox.items)
    assert app.info_cards["status"]["value"].options["text"] == "중복 확인"
    assert app.follow_up_label.options["text"] == "경고 내용을 확인한 뒤 다음 스캔"
    assert app.scan_entry.options["state"] == container_audit_module.tk.DISABLED
    focus_jobs_before_ack = len(app.root.after_calls)

    app._acknowledge_active_notice()

    assert app.warning_presenter.state.active_notice is None
    assert app.info_cards["status"]["value"].options["text"] == "작업 중"
    assert app.follow_up_label.options["text"] == "다음 제품 스캔"
    assert app.scan_entry.options["state"] == container_audit_module.tk.NORMAL
    assert tuple(app.scanned_listbox.items) == rows_before_ack
    assert app.warning_presenter.state.last_normal_scan == barcodes[-1]
    assert app.last_scan_value_label.options["text"] == barcodes[-1]
    assert len(app.root.after_calls) == focus_jobs_before_ack + 1


def test_stage_label_tracks_master_then_product_scan_flow(operator_view):
    app, _center, _right = operator_view

    app._update_center_display()
    waiting_text = app.stage_label.options["text"]

    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        tray_size=3,
    )
    app._update_center_display()
    product_text = app.stage_label.options["text"]

    app.current_tray = TraySession()
    app._update_center_display()
    waiting_again_text = app.stage_label.options["text"]

    assert "1 / 2" in waiting_text and "현품표" in waiting_text
    assert "2 / 2" in product_text and "제품" in product_text
    assert waiting_again_text == waiting_text


def test_right_sidebar_primary_and_secondary_information_hierarchy(operator_view):
    app, _center, right = operator_view
    primary_keys = ("status", "stopwatch")
    secondary_keys = ("avg_time", "best_time")

    assert set(primary_keys + secondary_keys) <= set(app.info_cards)
    assert app.last_scan_value_label.master is app._right_context_frame
    assert app.follow_up_label.master is app._right_context_frame
    context_headings = {
        widget.options.get("text", "")
        for widget in app._right_context_frame.children
        if widget.kind == "ttk.Label"
    }
    assert "마지막 정상 스캔" in context_headings
    assert "다음 행동" in context_headings

    for key in primary_keys:
        assert app.info_cards[key]["frame"].options["style"] == "Card.TFrame"
    assert app._right_context_frame.options["style"] == "Card.TFrame"
    for key in secondary_keys:
        card = app.info_cards[key]
        assert card["frame"].options["style"] == "SecondaryCard.TFrame"
        assert card["label"].options["style"] == "SecondaryCard.Subtle.TLabel"
        assert card["value"].options["style"] == "SecondaryCard.Value.TLabel"

    app._apply_right_sidebar_layout()
    metrics = app._get_right_sidebar_layout_metrics(right.winfo_height())
    for key in ("status", "stopwatch", "last_normal_scan"):
        frame = app.info_cards[key]["frame"] if key in app.info_cards else app._right_context_frame
        row = frame.grid_options["row"]
        assert right.grid_rows[row]["minsize"] >= metrics["primary_card_minsize"]
    follow_up_row = app._right_context_frame.grid_options["row"]
    assert right.grid_rows[follow_up_row]["minsize"] >= metrics["follow_up_minsize"]
    secondary_row = app._secondary_stats_frame.grid_options["row"]
    assert right.grid_rows[secondary_row]["minsize"] <= metrics["secondary_card_minsize"]


def test_short_large_text_sidebar_values_fit_and_legend_restores_on_round_trip(operator_view):
    app, _center, right = operator_view
    app.scale_factor = 1.4

    def apply_at(width, height):
        right.pixel_width = width
        right.pixel_height = height
        app._right_sidebar_layout_metrics = None
        app._apply_right_sidebar_layout()
        return {
            "legend_mapped": app._legend_frame.winfo_ismapped(),
            "date_font": app.date_label.options["font"],
            "clock_font": app.clock_label.options["font"],
            "status_padding": app.info_cards["status"]["frame"].options["padding"],
            "context_padding": app._right_context_frame.options["padding"],
            "context_font": app.follow_up_label.options["font"],
            "spacer_weight": right.grid_rows[6]["weight"],
        }

    compact_before = apply_at(302, 707)
    assert compact_before["legend_mapped"] is False
    assert compact_before["date_font"][1] <= 20
    assert compact_before["clock_font"][1] <= 27
    assert compact_before["status_padding"] == 8
    assert compact_before["context_padding"] == 10
    assert compact_before["spacer_weight"] == 0

    for value_label in (
        app.info_cards["status"]["value"],
        app.info_cards["stopwatch"]["value"],
        app.last_scan_value_label,
        app.follow_up_label,
        app.info_cards["avg_time"]["value"],
        app.info_cards["best_time"]["value"],
    ):
        assert value_label.options["anchor"] == "center"
        assert value_label.options["justify"] == "center"

    wide = apply_at(510, 1040)
    assert wide["legend_mapped"] is True
    assert wide["status_padding"] == 20
    assert wide["context_padding"] == 16
    assert wide["spacer_weight"] == 1

    compact_after = apply_at(302, 707)
    assert compact_after == compact_before


def test_right_sidebar_values_show_last_normal_scan_and_next_operator_action(operator_view):
    app, _center, _right = operator_view

    app._update_center_display()
    assert "현품표" in app.follow_up_label.options["text"]

    barcode = "AAA2270730100-001"
    app.warning_presenter.record_normal_scan(barcode)
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[barcode],
        tray_size=3,
    )
    app._update_center_display()

    assert barcode in app.last_scan_value_label.options["text"]
    assert "제품" in app.follow_up_label.options["text"]


def test_right_sidebar_never_duplicates_the_center_progress_count(operator_view):
    app, _center, right = operator_view
    barcode = "AAA2270730100-001"
    app.warning_presenter.record_normal_scan(barcode)
    app.current_tray = TraySession(
        master_label_code="PHS=2|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[barcode],
        tray_size=3,
    )
    app._update_center_display()

    assert app.main_count_label.options["text"] == "1 / 3"
    right_progress_widgets = [
        widget
        for widget in _walk(right)
        if widget.kind in {"tk.Listbox", "ttk.Treeview", "ttk.Progressbar"}
    ]
    assert right_progress_widgets == []
    right_texts = [
        str(widget.options.get("text", ""))
        for widget in _walk(right)
        if widget.kind in {"tk.Label", "ttk.Label"}
    ]
    assert not any(re.search(r"\b\d+\s*/\s*\d+\b", text) for text in right_texts)
    assert app.follow_up_label.options["text"] == "다음 제품 스캔"
