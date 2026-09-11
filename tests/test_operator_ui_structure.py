from __future__ import annotations

import ast
import inspect
import re
import textwrap
import tkinter.font as tkfont
from types import SimpleNamespace

import pytest
from tests.native_widgets import native_tk_root

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from tools.capture_container_operator_ui import build_tree_heading_fit_gate
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    Notice,
    NoticeSeverity,
    WarningPresenter,
)


def _install_deterministic_root_viewport(monkeypatch, root, width: int, height: int):
    """Keep a real Tk root while isolating profile reads from the host WM.

    GitHub's Windows virtual desktop can clamp an off-screen 2560x1392 root
    request to its smaller desktop.  Only the two Python size readers used by
    the application are controlled here; Tcl/Tk widgets, bindings, generated
    events, and style work continue through the real root.
    """

    viewport = SimpleNamespace(width=int(width), height=int(height))
    monkeypatch.setattr(root, "winfo_width", lambda: viewport.width)
    monkeypatch.setattr(root, "winfo_height", lambda: viewport.height)
    return viewport


def _dispatch_root_viewport(root, viewport, width: int, height: int) -> None:
    viewport.width = int(width)
    viewport.height = int(height)
    root.event_generate("<Configure>", width=width, height=height)
    root.update()


def test_left_sidebar_capture_threshold_matches_runtime_contract():
    from tools.capture_container_operator_ui import (
        TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT,
    )

    assert (
        TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT
        == container_audit_module.LEFT_SIDEBAR_SWITCH_LOGICAL_HEIGHT
    )


@pytest.mark.real_gui
def test_summary_tree_columns_follow_real_tk_compact_wide_compact_round_trip(native_tk_root):
    root = native_tk_root
    root.geometry("310x320+10000+10000")
    try:
        # Keep the geometry manager active without showing a test window.
        root.attributes("-alpha", 0.0)
        root.tk.call("tk", "scaling", 2.00098)
        style = container_audit_module.ttk.Style(root)
        style.theme_use("clam")
        for scale, compact_tree_width in ((1.0, 236), (1.4, 290)):
            tokens = container_audit_module.build_style_tokens(
                container_audit_module.StyleProfile("compact"),
                scale,
            )
            style.configure(
                "Treeview.Heading",
                font=(ContainerAudit.DEFAULT_FONT, tokens.fonts.body, "bold"),
            )
            sidebar_font_size = max(11, min(tokens.fonts.caption, 13))
            style.configure(
                "Sidebar.Treeview.Heading",
                font=(ContainerAudit.DEFAULT_FONT, sidebar_font_size, "bold"),
            )
            style.configure(
                "Sidebar.Treeview",
                font=(ContainerAudit.DEFAULT_FONT, sidebar_font_size),
            )
            frame = container_audit_module.ttk.Frame(root)
            frame.pack(fill="both", expand=True)
            tree = container_audit_module.ttk.Treeview(
                frame,
                columns=("item_name_spec", "item_code", "count"),
                show="headings",
                style="Sidebar.Treeview",
            )
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            tree.grid(row=0, column=0, sticky="nsew")
            scrollbar = container_audit_module.ttk.Scrollbar(frame, orient="vertical")
            scrollbar.grid(row=0, column=1, sticky="ns")

            app = ContainerAudit.__new__(ContainerAudit)
            app.scale_factor = scale
            app._left_sidebar_compact = True
            app.root = root
            app.style = style
            app.summary_tree = tree
            tree.bind("<Configure>", app._adjust_summary_tree_columns)

            root.update()
            compact_root_width = compact_tree_width + scrollbar.winfo_reqwidth()
            snapshots = []
            for width in (compact_root_width, 1200, compact_root_width):
                app._left_sidebar_compact = width == compact_root_width
                root.geometry(f"{width}x320+10000+10000")
                root.update()
                available_width = tree.winfo_width() - 4
                displayed_columns = tuple(
                    tree.cget("displaycolumns")
                    if tree.cget("displaycolumns") != "#all"
                    else tree.cget("columns")
                )
                column_widths = tuple(
                    int(tree.column(column, "width"))
                    for column in displayed_columns
                )
                headings = tuple(
                    tree.heading(column, "text")
                    for column in displayed_columns
                )
                assert sum(column_widths) <= available_width
                if width == compact_root_width:
                    heading_y = next(
                        y
                        for y in range(max(1, tree.winfo_height()))
                        if tree.identify_region(max(2, tree.winfo_width() - 12), y)
                        == "heading"
                    )
                    visible_count_width = sum(
                        tree.identify_region(x, heading_y) == "heading"
                        and tree.identify_column(x) == "#2"
                        for x in range(tree.winfo_width())
                    )
                    tree_style = str(tree.cget("style") or "Treeview")
                    heading_font = tkfont.Font(
                        root=root,
                        font=style.lookup(f"{tree_style}.Heading", "font"),
                    )
                    padding_parts = root.tk.splitlist(
                        style.lookup(f"{tree_style}.Heading", "padding") or "0"
                    )
                    horizontal_padding = (
                        2 * root.winfo_pixels(padding_parts[0])
                        if len(padding_parts) == 1
                        else root.winfo_pixels(padding_parts[0])
                        + root.winfo_pixels(
                            padding_parts[2 if len(padding_parts) >= 4 else 0]
                        )
                    )
                    assert heading_font.measure("건") <= (
                        visible_count_width - horizontal_padding
                    )
                snapshots.append(
                    (tree.winfo_width(), displayed_columns, column_widths, headings)
                )

            assert snapshots[0] == snapshots[2]
            assert snapshots[0][1] == ("item_code", "count")
            assert snapshots[0][3] == ("품목 코드", "건")
            assert snapshots[1][1] == (
                "item_name_spec",
                "item_code",
                "count",
            )
            assert snapshots[1][3] == ("품목명", "품목코드", "완료 수량")
            assert snapshots[1][0] > snapshots[0][0]
            frame.destroy()
            root.update()
    finally:
        root.destroy()


def _assert_sidebar_tree_exact_rows_fit_real_tk_compact_wide_compact(
    root,
    scale_factor,
    compact_tree_width,
):
    root.geometry("1366x768+10000+10000")
    try:
        root.attributes("-alpha", 0.0)
        root.tk.call("tk", "scaling", 2.00098)
        root.update()

        app = ContainerAudit.__new__(ContainerAudit)
        app.root = root
        app.style = container_audit_module.ttk.Style(root)
        app.style.theme_use("clam")
        app.scale_factor = scale_factor
        app._left_sidebar_compact = True
        app._left_sidebar_view = "summary"
        app.left_context_switch_button = SimpleNamespace(
            winfo_ismapped=lambda: True
        )
        app.apply_scaling()

        host = container_audit_module.ttk.Frame(root)
        host.place(x=0, y=0, width=compact_tree_width + 20, height=160)
        host.grid_rowconfigure(0, weight=1)
        host.grid_columnconfigure(0, weight=1)
        app.left_pane = host

        tree_specs = {
            "summary": {
                "columns": ("item_name_spec", "item_code", "count"),
                "headings": ("품목명", "품목코드", "완료 수량"),
                "values": ("캡처 기준 품목", "AAA2270730200", "1"),
            },
            "parked": {
                "columns": ("item_name", "scan_count"),
                "headings": ("품목명", "스캔 수량"),
                "values": ("캡처 보류 트레이", "1"),
            },
        }
        frames = {}
        trees = {}
        scrollbars = {}
        for view, spec in tree_specs.items():
            frame = container_audit_module.ttk.Frame(host)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            tree = container_audit_module.ttk.Treeview(
                frame,
                columns=spec["columns"],
                show="headings",
                style="Sidebar.Treeview",
            )
            for column_id, heading in zip(spec["columns"], spec["headings"]):
                tree.heading(column_id, text=heading)
                tree.column(column_id, stretch=container_audit_module.tk.NO)
            tree.insert("", "end", values=spec["values"])
            tree.grid(row=0, column=0, sticky="nsew")
            scrollbar = container_audit_module.ttk.Scrollbar(
                frame,
                orient="vertical",
                command=tree.yview,
            )
            tree.configure(yscrollcommand=scrollbar.set)
            scrollbar.grid(row=0, column=1, sticky="ns")
            frames[view] = frame
            trees[view] = tree
            scrollbars[view] = scrollbar
        frames["parked"].grid_remove()
        app.summary_tree = trees["summary"]
        app.parked_tree = trees["parked"]
        tree_identities = {view: str(tree) for view, tree in trees.items()}

        root.update()
        scrollbar_width = max(
            scrollbar.winfo_reqwidth() for scrollbar in scrollbars.values()
        )
        snapshots = {"summary": [], "parked": []}
        viewports = (
            (True, (1366, 768), compact_tree_width),
            (False, (2560, 1392), 800),
            (True, (1366, 768), compact_tree_width),
        )
        for compact, (root_width, root_height), tree_width in viewports:
            root.geometry(f"{root_width}x{root_height}+10000+10000")
            root.update()
            app.apply_scaling()
            app._left_sidebar_compact = compact
            host.place_configure(
                width=tree_width + scrollbar_width,
                height=max(
                    120,
                    int(app._left_tree_minimum_one_row_height) + 16,
                ),
            )

            for view in ("summary", "parked"):
                other_view = "parked" if view == "summary" else "summary"
                frames[other_view].grid_remove()
                frames[view].grid(row=0, column=0, sticky="nsew")
                app._left_sidebar_view = view
                root.update()
                if view == "summary":
                    app._adjust_summary_tree_columns()
                else:
                    app._adjust_parked_tree_columns()
                root.update()

                gate = build_tree_heading_fit_gate(app)
                assert gate["passed"] is True, {
                    "scale_factor": scale_factor,
                    "compact": compact,
                    "view": view,
                    "gate_checks_failed": [
                        key for key, passed in gate["checks"].items() if not passed
                    ],
                    "tree_checks_failed": {
                        tree["name"]: [
                            key
                            for key, passed in tree.get("checks", {}).items()
                            if not passed
                        ]
                        for tree in gate["trees"]
                    },
                    "trees": gate["trees"],
                }
                active = next(
                    tree
                    for tree in gate["trees"]
                    if tree["name"] == f"{view}_tree"
                )
                assert active["mapped"] is True
                assert active["style"] == "Sidebar.Treeview"
                assert active["heading_style"] == "Sidebar.Treeview.Heading"
                assert active["checks"]["configured_row_height_fits_data_font"] is True
                assert active["checks"]["actual_first_row_height_fits_data_font"] is True
                assert active["first_row_height_px"] >= active["minimum_data_row_height_px"]
                assert active["first_row_bbox"][3] == active["first_row_height_px"]

                data_cells = [
                    cell
                    for column in active["columns"]
                    for cell in column["data_cells"]
                ]
                expected_texts = (
                    {"AAA2270730200", "1"}
                    if view == "summary" and compact
                    else set(tree_specs[view]["values"])
                )
                assert {cell["text"] for cell in data_cells} == expected_texts
                assert all(len(cell["cell_bbox"]) == 4 for cell in data_cells)
                assert all(cell["visible_cell_width_px"] > 0 for cell in data_cells)
                assert all(cell["fit_slack_px"] >= 0 for cell in data_cells)
                assert all(cell["passed"] is True for cell in data_cells)

                raw_displayed_columns = trees[view].cget("displaycolumns")
                displayed_columns = tuple(
                    trees[view].cget("columns")
                    if raw_displayed_columns in ("#all", ("#all",))
                    else raw_displayed_columns
                )
                snapshots[view].append(
                    {
                        "tree_width": trees[view].winfo_width(),
                        "displayed_columns": displayed_columns,
                        "column_widths": tuple(
                            int(trees[view].column(column_id, "width"))
                            for column_id in displayed_columns
                        ),
                        "headings": tuple(
                            trees[view].heading(column_id, "text")
                            for column_id in displayed_columns
                        ),
                        "style": active["style"],
                        "body_font_actual": active["body_font_actual"],
                        "configured_row_height": active["configured_row_height_px"],
                        "first_row_bbox": tuple(active["first_row_bbox"]),
                        "cell_slacks": tuple(
                            (cell["text"], cell["fit_slack_px"])
                            for cell in data_cells
                        ),
                    }
                )

        assert snapshots["summary"][0] == snapshots["summary"][2]
        assert snapshots["parked"][0] == snapshots["parked"][2]
        assert snapshots["summary"][0]["displayed_columns"] == (
            "item_code",
            "count",
        )
        assert snapshots["summary"][1]["displayed_columns"] == (
            "item_name_spec",
            "item_code",
            "count",
        )
        assert snapshots["parked"][0]["headings"] == ("품목", "건")
        assert snapshots["parked"][1]["headings"] == ("품목명", "스캔 수량")
        assert {view: str(tree) for view, tree in trees.items()} == tree_identities
    finally:
        for child in root.winfo_children():
            child.destroy()
        root.update_idletasks()


@pytest.mark.real_gui
def test_sidebar_tree_exact_rows_fit_real_tk_compact_wide_compact(native_tk_root):
    root = native_tk_root
    executed_scales = []
    try:
        for scale_factor, compact_tree_width in ((1.0, 236), (1.4, 290)):
            _assert_sidebar_tree_exact_rows_fit_real_tk_compact_wide_compact(
                root,
                scale_factor,
                compact_tree_width,
            )
            executed_scales.append(scale_factor)
        assert executed_scales == [1.0, 1.4]
    finally:
        root.destroy()


@pytest.mark.real_gui
def test_scale14_center_actions_fit_capture_tk_scaling_at_compact_and_wide_widths(native_tk_root):
    root = native_tk_root
    root.withdraw()
    try:
        # DISPLAY2 capture evidence reports the process Tk conversion at this
        # value.  The default test-interpreter scaling was lower and therefore
        # gave a false pass for Korean action labels.
        root.tk.call("tk", "scaling", 2.00098)
        style = container_audit_module.ttk.Style(root)
        style.theme_use("clam")
        app = ContainerAudit.__new__(ContainerAudit)
        app.scale_factor = 1.4
        for window_width, window_height, center_width, budgets, left_content_width in (
            (1366, 768, 710, (154, 153, 154, 153), 302),
            (2560, 1392, 1467, (327, 326, 327, 326), 539),
        ):
            profile = container_audit_module.select_layout_profile(
                window_width,
                window_height,
                1.4,
            )
            tokens = container_audit_module.build_style_tokens(
                container_audit_module.StyleProfile(profile.name),
                1.4,
            )
            padding = app._button_style_padding(tokens, window_height)
            style.configure(
                "WidthContract.Secondary.TButton",
                font=(app.DEFAULT_FONT, tokens.fonts.caption, "bold"),
                padding=padding,
            )
            style.configure(
                "WidthContract.Primary.TButton",
                font=(app.DEFAULT_FONT, tokens.fonts.body, "bold"),
                padding=padding,
            )
            style.configure(
                "WidthContract.TCheckbutton",
                font=(app.DEFAULT_FONT, tokens.fonts.body),
            )
            compact = center_width < 960
            normal = app._action_button_labels(
                compact=compact,
                operator_review=False,
            )
            review = app._action_button_labels(
                compact=compact,
                operator_review=True,
            )
            labels_and_styles = (
                (normal["undo"], "WidthContract.Secondary.TButton", budgets[0]),
                (normal["park"], "WidthContract.Primary.TButton", budgets[1]),
                (normal["submit"], "WidthContract.Primary.TButton", budgets[2]),
                (review["submit"], "WidthContract.Primary.TButton", budgets[2]),
                (normal["operations"], "WidthContract.Secondary.TButton", budgets[3]),
            )
            for label, button_style, available_width in labels_and_styles:
                button = container_audit_module.ttk.Button(
                    root,
                    text=label,
                    style=button_style,
                    width=0,
                )
                button.update_idletasks()
                assert button.winfo_reqwidth() <= available_width, (
                    window_width,
                    label,
                    button.winfo_reqwidth(),
                    available_width,
                )
                button.destroy()

            tray_image_label = "트레이 이미지" if compact else "트레이 이미지 보기"
            checkbox = container_audit_module.ttk.Checkbutton(
                root,
                text=tray_image_label,
                style="WidthContract.TCheckbutton",
            )
            checkbox.update_idletasks()
            assert checkbox.winfo_reqwidth() <= left_content_width, (
                window_width,
                tray_image_label,
                checkbox.winfo_reqwidth(),
                left_content_width,
            )
            checkbox.destroy()

        assert app._button_style_padding(
            container_audit_module.build_style_tokens(
                container_audit_module.StyleProfile("compact"),
                1.4,
            ),
            768,
        ) == (12, 7)
    finally:
        root.destroy()


@pytest.mark.real_gui
def test_real_root_configure_refreshes_button_styles_compact_wide_compact(monkeypatch, native_tk_root):
    root = native_tk_root
    root.geometry("900x700+10000+10000")
    try:
        root.attributes("-alpha", 0.0)
        root.tk.call("tk", "scaling", 2.00098)
        root.update()
        viewport = _install_deterministic_root_viewport(
            monkeypatch, root, 2560, 1392
        )

        app = ContainerAudit.__new__(ContainerAudit)
        app.root = root
        app.scale_factor = 1.4
        app.style = container_audit_module.ttk.Style(root)
        app.style.theme_use("clam")
        app._responsive_style_refresh_job = None
        app.apply_scaling()
        root.bind("<Configure>", app._schedule_responsive_style_refresh, add="+")
        assert app._responsive_style_signature[-1] == (31, 14)
        compact_snapshots = []
        for width, height in ((1366, 768), (2560, 1392), (1366, 768)):
            _dispatch_root_viewport(root, viewport, width, height)
            assert app._responsive_style_refresh_job is None
            if width == 1366:
                assert app._responsive_style_signature[-1] == (12, 7)
                labels = app._action_button_labels(
                    compact=True,
                    operator_review=False,
                )
                requested_widths = []
                for key, button_style, available_width in (
                    ("undo", "Secondary.TButton", 154),
                    ("park", "Warning.TButton", 153),
                    ("submit", "Success.TButton", 154),
                    ("operations", "Secondary.TButton", 153),
                ):
                    button = container_audit_module.ttk.Button(
                        root,
                        text=labels[key],
                        style=button_style,
                        width=0,
                    )
                    button.update_idletasks()
                    requested_widths.append(button.winfo_reqwidth())
                    assert button.winfo_reqwidth() <= available_width
                    button.destroy()
                compact_snapshots.append(
                    (app._responsive_style_signature, tuple(requested_widths))
                )
            else:
                assert app._responsive_style_signature[-1] == (31, 14)

        assert compact_snapshots[0] == compact_snapshots[1]
    finally:
        root.destroy()


@pytest.mark.real_gui
def test_right_context_real_tk_wide_geometry_is_deterministic_after_compact_round_trip(monkeypatch, native_tk_root):
    root = native_tk_root
    root.geometry("900x700+10000+10000")
    try:
        root.attributes("-alpha", 0.0)
        root.tk.call("tk", "scaling", 2.00098)
        root.update()
        viewport = _install_deterministic_root_viewport(
            monkeypatch, root, 2560, 1392
        )
        app = ContainerAudit.__new__(ContainerAudit)
        app.root = root
        app.scale_factor = 1.0
        app.style = container_audit_module.ttk.Style(root)
        app.style.theme_use("clam")
        app._responsive_style_refresh_job = None
        app._right_widget_generation = 1
        app._right_sidebar_layout_metrics = None
        app.apply_scaling()
        root.bind("<Configure>", app._schedule_responsive_style_refresh, add="+")

        right = container_audit_module.ttk.Frame(root, width=502, height=1310)
        right.place(x=0, y=0, width=502, height=1310)
        right.grid_propagate(False)
        right.grid_columnconfigure(0, weight=1)
        app._right_sidebar_frame = right
        app.date_label = container_audit_module.ttk.Label(right, text="2026-07-19")
        app.date_label.grid(row=0, column=0)
        app.clock_label = container_audit_module.ttk.Label(right, text="03:30:00")
        app.clock_label.grid(row=1, column=0)
        app.info_cards = {}
        for row, key, text_value in (
            (2, "status", "작업 중"),
            (3, "stopwatch", "02:08"),
        ):
            card = container_audit_module.ttk.Frame(right)
            card.grid(row=row, column=0, sticky="nsew")
            value = container_audit_module.ttk.Label(card, text=text_value)
            value.pack()
            app.info_cards[key] = {"frame": card, "value": value}
        context = container_audit_module.ttk.Frame(right)
        context.grid(row=4, column=0, sticky="nsew")
        app._right_context_frame = context
        app.last_scan_value_label = container_audit_module.ttk.Label(
            context,
            text="AAA2270730100 · ID 123456",
        )
        app.last_scan_value_label.grid(row=1, column=0)
        app._right_context_separator = container_audit_module.ttk.Separator(context)
        app._right_context_separator.grid(row=2, column=0)
        app.follow_up_label = container_audit_module.ttk.Label(
            context,
            text="다음 제품 스캔",
        )
        app.follow_up_label.grid(row=4, column=0)
        secondary = container_audit_module.ttk.Frame(right)
        secondary.grid(row=5, column=0, sticky="nsew")
        app._secondary_stats_frame = secondary
        for column, key in enumerate(("avg_time", "best_time")):
            card = container_audit_module.ttk.Frame(secondary)
            card.grid(row=0, column=column)
            value = container_audit_module.ttk.Label(card, text="01:42")
            value.pack()
            app.info_cards[key] = {"frame": card, "value": value}
        app._legend_frame = container_audit_module.ttk.Frame(right)
        app._legend_frame.grid(row=7, column=0)
        right.bind(
            "<Configure>",
            lambda _event: app._apply_right_sidebar_layout(generation=1),
        )
        def snapshot():
            root.update()
            return (
                app.last_scan_value_label.cget("font"),
                app.follow_up_label.cget("font"),
                app.last_scan_value_label.winfo_reqwidth(),
                app.last_scan_value_label.winfo_reqheight(),
                app.follow_up_label.winfo_reqwidth(),
                app.follow_up_label.winfo_reqheight(),
                context.winfo_reqwidth(),
                context.winfo_reqheight(),
            )

        app._apply_right_sidebar_layout(generation=1)
        direct_wide = snapshot()
        assert (right.winfo_width(), right.winfo_height()) == (502, 1310)
        assert app._get_right_sidebar_layout_metrics(1310)["context_value_font"] == 20
        assert tkfont.Font(
            root=root, font=app.last_scan_value_label.cget("font")
        ).cget("size") == 20

        right.place_configure(width=302, height=694)
        _dispatch_root_viewport(root, viewport, 1366, 768)
        assert app._responsive_style_refresh_job is None
        assert (right.winfo_width(), right.winfo_height()) == (302, 694)
        assert app._get_right_sidebar_layout_metrics(694)["context_value_font"] == 13
        assert tkfont.Font(
            root=root, font=app.last_scan_value_label.cget("font")
        ).cget("size") == 13

        right.place_configure(width=502, height=1310)
        _dispatch_root_viewport(root, viewport, 2560, 1392)
        roundtrip_wide = snapshot()
        assert app._responsive_style_refresh_job is None
        assert (right.winfo_width(), right.winfo_height()) == (502, 1310)
        assert app._get_right_sidebar_layout_metrics(1310)["context_value_font"] == 20
        assert tkfont.Font(
            root=root, font=app.last_scan_value_label.cget("font")
        ).cget("size") == 20
        assert roundtrip_wide == direct_wide
    finally:
        root.destroy()


@pytest.mark.real_gui
def test_notice_message_real_tk_tracks_actual_column_through_blocking_round_trip(native_tk_root):
    root = native_tk_root
    root.geometry("900x300+10000+10000")
    try:
        root.attributes("-alpha", 0.0)
        root.tk.call("tk", "scaling", 2.00098)
        root.update()
        app = ContainerAudit.__new__(ContainerAudit)
        app.root = root
        app.scale_factor = 1.0
        app._center_widget_generation = 1
        app._notice_message_wrap_job = None
        app._notice_message_wrap_metrics = None

        for center_width, center_height, notice_width in (
            (821, 694, 761),
            (824, 826, 764),
        ):
            metrics = app._get_center_layout_metrics(center_width, center_height)
            frame = container_audit_module.tk.Frame(
                root,
                width=notice_width,
                height=100,
            )
            frame.pack()
            frame.grid_propagate(False)
            frame.grid_columnconfigure(1, weight=1)
            title = container_audit_module.tk.Label(
                frame,
                text="담당자 확인",
                font=(app.DEFAULT_FONT, metrics["notice_title_font"], "bold"),
            )
            title.grid(row=0, column=0, padx=(12, 8), pady=8)
            message = container_audit_module.tk.Label(
                frame,
                text="서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다.",
                font=(app.DEFAULT_FONT, metrics["notice_message_font"]),
                anchor="w",
                justify="left",
            )
            message.grid(row=0, column=1, sticky="ew", padx=8, pady=8)
            acknowledge = container_audit_module.tk.Button(
                frame,
                text="담당자 확인 필요",
                state=container_audit_module.tk.DISABLED,
                padx=12,
                pady=4,
            )
            acknowledge.grid(row=0, column=2, padx=(8, 10), pady=6)
            app.notice_message_label = message
            app._notice_message_wrap_metrics = None
            message.bind(
                "<Configure>",
                lambda event: app._schedule_notice_message_wrap_refresh(
                    event,
                    generation=1,
                ),
            )

            root.update()
            app._schedule_notice_message_wrap_refresh(generation=1)
            root.update()
            blocked = (
                message.winfo_width(),
                message.winfo_reqwidth(),
                int(message.cget("wraplength")),
            )
            assert blocked[0] >= blocked[1]
            assert blocked[2] <= blocked[0] - 8
            assert message.winfo_x() + message.winfo_width() <= frame.winfo_width()

            acknowledge.grid_remove()
            message.configure(text="'캡처 기준 품목' 완료 · 서버 이적 확인이 완료되었습니다.")
            app._schedule_notice_message_wrap_refresh(generation=1)
            root.update()
            assert message.winfo_width() >= message.winfo_reqwidth()
            assert message.winfo_width() > blocked[0]

            acknowledge.grid()
            message.configure(
                text="서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다."
            )
            app._schedule_notice_message_wrap_refresh(generation=1)
            root.update()
            assert (
                message.winfo_width(),
                message.winfo_reqwidth(),
                int(message.cget("wraplength")),
            ) == blocked
            frame.destroy()
            root.update()
    finally:
        root.destroy()
