from __future__ import annotations

from tkinter import ttk

import pytest

from Container_Audit import ContainerAudit
from tests.native_widgets import assert_contained, native_tk_root, rectangle, resize_root
from worker_registry import WorkerRegistry

pytestmark = pytest.mark.real_gui


@pytest.fixture
def worker_login_view(native_tk_root, tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = native_tk_root
    app.scale_factor = 1.4
    app.style = ttk.Style(app.root)
    app.apply_scaling()
    app.logo_photo_ref = None
    app.worker_registry = WorkerRegistry(str(tmp_path/'workers.json'))
    app.worker_registry.register('테스트 작업자')
    app.worker_input_frame = ttk.Frame(app.root)
    app.paned_window = ttk.Frame(app.root)
    app._worker_login_layout_job = None
    app.show_worker_input_screen()
    app.root.update()
    return app


def _visible_controls(app):
    return [app._worker_login_logo_label, app._worker_login_title_label, app.worker_entry,
            *app._worker_login_buttons]


def test_large_text_short_login_fixture_keeps_logo_and_actions_in_budget(worker_login_view):
    app = worker_login_view
    assert app.logo_photo_ref.width() > 1 and app.logo_photo_ref.height() > 1
    for widget in _visible_controls(app):assert_contained(widget, app.worker_input_frame)
    assert app.worker_entry.get() == '테스트 작업자'
    assert [button.cget('text') for button in app._worker_login_buttons] == ['신규 등록', '작업 시작']
    assert app.worker_entry.winfo_rooty() < app._worker_login_buttons[0].winfo_rooty()


def test_worker_login_fixture_compact_wide_compact_does_not_accumulate(worker_login_view):
    app = worker_login_view
    snapshots = []
    for width, height in [(1366,768), (2560,1080), (1366,768)]:
        resize_root(app.root,width,height)
        # The real Configure binding and scheduled layout callback have completed.
        for widget in _visible_controls(app):assert_contained(widget, app.worker_input_frame)
        snapshots.append(tuple(rectangle(widget) for widget in _visible_controls(app)))
    assert snapshots[0] == snapshots[-1]
    assert snapshots[0] != snapshots[1]
