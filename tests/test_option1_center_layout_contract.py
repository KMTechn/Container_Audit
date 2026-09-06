from __future__ import annotations

import math
from tkinter import ttk

import pytest

from responsive_layout import center_layout_metrics, pane_layout_metrics, scanned_list_metrics, select_layout_profile
from style_tokens import build_style_tokens
from tests.native_widgets import action_buttons, assert_contained, build_center, native_tk_root, rectangle
from warning_presenter import Notice, NoticeSeverity

DISPLAY_WIDTH = 1366
DISPLAY_HEIGHT = 768
LAST_NORMAL = "AAA2270730200-DEMO-QT3-0001"
REJECTED_DUPLICATE = "AAA2270730200-DEMO-QT3-DUPLICATE"


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



@pytest.mark.real_gui
@pytest.mark.parametrize("scale", [1.0, 1.2, 1.4])
def test_option1_center_uses_fixed_scan_header_and_one_by_four_actions(native_tk_root, scale):
    width = pane_layout_metrics(DISPLAY_WIDTH, DISPLAY_HEIGHT, scale).center_width
    app, center = build_center(native_tk_root, scale=scale, width=width, height=DISPLAY_HEIGHT, barcode=LAST_NORMAL)
    for widget in [app.scanned_list_header_label, app.scanned_listbox, *action_buttons(app)]:
        assert_contained(widget, center)
    assert "현재 트레이 스캔 목록" in app.scanned_list_header_label.cget('text')
    assert app.scanned_list_header_label.winfo_rooty() < app.scanned_listbox.winfo_rooty()
    buttons = action_buttons(app)
    positions = [rectangle(button) for button in buttons]
    assert max(y for x,y,width,height in positions) < min(y+height for x,y,width,height in positions)
    assert all(left[0]+left[2] <= right[0] for left,right in zip(positions,positions[1:]))
    assert positions[0][1] >= app.scanned_listbox.winfo_rooty()+app.scanned_listbox.winfo_height()
    for button,fragment in zip(buttons,['스캔 취소','보류','제출','운영 작업']):
        assert fragment in button.cget('text')
        assert button.winfo_reqwidth() <= button.winfo_width(), 'action label is horizontally clipped'


@pytest.mark.real_gui
@pytest.mark.parametrize('scale', [1.0, 1.1, 1.2, 1.3, 1.4])
def test_duplicate_notice_preserves_scan_list_last_normal_and_center_geometry(native_tk_root, scale, record_testsuite_property):
    width = pane_layout_metrics(DISPLAY_WIDTH, DISPLAY_HEIGHT, scale).center_width
    app, center = build_center(native_tk_root, scale=scale, width=width, height=DISPLAY_HEIGHT, barcode=LAST_NORMAL)
    app.current_tray.tray_size = 20
    app.current_tray.scanned_barcodes = [f'AAA2270730200-DEMO-QT3-{i:04}' for i in range(9)] + [LAST_NORMAL]
    app.scanned_listbox.delete(0, 'end')
    for index,barcode in enumerate(app.current_tray.scanned_barcodes,1):
        app.scanned_listbox.insert('end', app._format_scanned_list_row(index,barcode))
    app.scanned_listbox.see('end')
    app.last_scan_value_label = ttk.Label(native_tk_root, text='-')
    app.follow_up_label = ttk.Label(native_tk_root, text='-')
    app._render_warning_state()
    native_tk_root.update()
    rows_before = app.scanned_listbox.get(0, 'end')
    geometry_before = tuple(rectangle(widget) for widget in [app.scanned_listbox, *action_buttons(app)])
    app.warning_presenter.present(Notice(code='scan.duplicate',title='중복 스캔',
        message=f'이미 등록된 제품입니다: {REJECTED_DUPLICATE}', severity=NoticeSeverity.ERROR,blocking=True))
    app._render_warning_state()
    native_tk_root.update()
    assert app.scanned_listbox.get(0, 'end') == rows_before
    assert all(REJECTED_DUPLICATE not in row for row in rows_before)
    assert app.warning_presenter.state.last_normal_scan == LAST_NORMAL
    assert app.last_scan_value_label.cget('text') == app._format_last_normal_scan_value(LAST_NORMAL)
    assert tuple(rectangle(widget) for widget in action_buttons(app)) == geometry_before[1:]
    visible_rows = [i for i in range(app.scanned_listbox.size())
                    if (bounds := app.scanned_listbox.bbox(i)) is not None
                    and bounds[1] >= 0 and bounds[1]+bounds[3] <= app.scanned_listbox.winfo_height()]
    assert visible_rows, 'no complete recent scan row remains visible'
    record_testsuite_property(f'notice_complete_recent_rows_scale_{scale}', len(visible_rows))
    record_testsuite_property(f'notice_latest_row_complete_scale_{scale}', app.scanned_listbox.size()-1 in visible_rows)
    record_testsuite_property(f'notice_list_geometry_scale_{scale}', str(rectangle(app.scanned_listbox)))
    assert '중복 스캔' in app.notice_title_label.cget('text')
    assert app.notice_ack_button.winfo_ismapped()
    for widget in [app.notice_ack_button, app.scanned_listbox, *action_buttons(app)]:assert_contained(widget, center)
    app.notice_ack_button.invoke()
    native_tk_root.update()
    assert tuple(rectangle(widget) for widget in [app.scanned_listbox, *action_buttons(app)]) == geometry_before
