from __future__ import annotations

import pytest

from tests.native_widgets import (
    action_buttons, assert_contained, build_center, native_tk_root, rectangle, resize_root,
)

pytestmark = pytest.mark.real_gui


def _resize(app, parent, width, height):
    resize_root(app.root, max(1366, width), max(768, height))
    parent.place_configure(width=width, height=height)
    app.root.update()
    app._apply_center_layout(parent, width, height)
    app.root.update()


def test_current_tray_scan_list_is_the_expanding_row_below_notice(native_tk_root):
    app, parent = build_center(native_tk_root)
    app.show_status_message("입력한 제품을 확인하세요.", app.COLOR_DANGER, duration=0)
    app.root.update()
    for widget in [app.notice_frame, app.scanned_listbox, *action_buttons(app)]:
        assert_contained(widget, parent)
    notice = rectangle(app.notice_frame)
    scan = rectangle(app.scanned_listbox)
    assert scan[1] >= notice[1] + notice[3]
    before = scan[3]
    _resize(app, parent, 815, 900)
    assert app.scanned_listbox.winfo_height() > before
    for button in action_buttons(app):assert_contained(button, parent)


def test_scan_list_survives_compact_standard_wide_compact_round_trip(native_tk_root):
    app, parent = build_center(native_tk_root)
    app.scanned_listbox.insert('end', 'retained scan row')
    snapshots = []
    for width, height in [(815,704), (818,834), (1096,1012), (815,704)]:
        _resize(app, parent, width, height)
        for widget in [app.scanned_listbox, *action_buttons(app)]:assert_contained(widget, parent)
        snapshots.append(tuple(rectangle(widget) for widget in [app.scanned_listbox, *action_buttons(app)]))
        assert app.scanned_listbox.get(0, 'end') == ('retained scan row',)
    assert snapshots[0] == snapshots[-1]
    assert snapshots[2][0][3] > snapshots[0][0][3]


@pytest.mark.parametrize('width,height,rows', [(815,704,3), (818,834,5), (1096,1012,5)])
def test_scan_list_requests_recent_rows_without_displacing_actions(native_tk_root, width, height, rows):
    resize_root(native_tk_root, 1366, max(768,height))
    app, parent = build_center(native_tk_root, width=width, height=height)
    for index in range(20):app.scanned_listbox.insert('end', f'current tray scan {index}')
    app.scanned_listbox.see('end')
    native_tk_root.update()
    assert_contained(app.scanned_listbox, parent)
    for index in range(20-rows,20):
        bounds = app.scanned_listbox.bbox(index)
        assert bounds is not None, 'required recent scan row is not visible'
        assert bounds[1] >= 0 and bounds[1] + bounds[3] <= app.scanned_listbox.winfo_height()
    for button in action_buttons(app):
        assert_contained(button, parent)
        assert button.winfo_rooty() >= app.scanned_listbox.winfo_rooty() + app.scanned_listbox.winfo_height()
