"""Work-result visibility through the real sidebar builder, without a Tk window."""
from types import SimpleNamespace

import pytest

import Container_Audit as ca


class Widget:
    def __init__(self, parent=None, **options):
        self.parent = parent
        self.options = options
        self.grid_options = {}
        self.visible = False
        self.children = []
        if isinstance(parent, Widget):
            parent.children.append(self)

    def configure(self, **options):
        self.options.update(options)

    def __setitem__(self, name, value):
        self.options[name] = value

    def grid(self, **options):
        self.grid_options.update(options)
        self.visible = True

    def grid_remove(self):
        self.visible = False

    def pack(self, **options):
        self.visible = True

    def grid_columnconfigure(self, *args, **options):
        pass

    def bind(self, *args):
        pass

    def unbind(self, *args):
        pass


@pytest.fixture
def sidebar(monkeypatch):
    for name in ("Frame", "Label", "Button", "Separator"):
        monkeypatch.setattr(ca.ttk, name, Widget)
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.scale_factor = 1
    app.root = SimpleNamespace(after=lambda *args: None)
    app._bind_label_to_container_width = lambda *args, **kwargs: None
    app._apply_right_sidebar_layout = lambda *args, **kwargs: None
    app._render_warning_state = lambda: None
    app._schedule_focus_return = lambda: None
    return app


@pytest.mark.parametrize("restored_expanded", [None, False, True])
def test_sidebar_start_and_rebuild_always_show_result_and_next_action(sidebar, restored_expanded):
    app = sidebar
    if restored_expanded is not None:
        app._work_details_expanded = restored_expanded
    for _ in range(2):
        parent = Widget()
        app._create_right_sidebar_content(parent)
        context = app._right_context_frame
        assert context.parent is parent
        assert context.grid_options["row"] == 6
        assert context.visible
        assert app.last_scan_value_label.parent is context
        assert app.follow_up_label.parent is context
        assert app.last_scan_value_label.visible and app.follow_up_label.visible
        assert app._secondary_stats_frame.grid_options["row"] == 7
        assert app._secondary_stats_frame.visible is bool(restored_expanded)


def test_details_toggle_changes_only_statistics_and_keeps_context_grid(sidebar):
    app = sidebar
    app._create_right_sidebar_content(Widget())
    context = app._right_context_frame
    context_grid = dict(context.grid_options)
    assert context.visible and not app._secondary_stats_frame.visible
    for expanded in (True, False, True, False):
        app._toggle_work_details()
        assert context.visible
        assert context.grid_options == context_grid
        assert app._secondary_stats_frame.visible is expanded
        assert app.work_details_button.options["text"] == (
            "작업 상세 ▾" if expanded else "작업 상세 ▸"
        )
