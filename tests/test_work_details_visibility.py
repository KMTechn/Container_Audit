"""Work-result visibility through the real sidebar builder, without a Tk window."""
from types import SimpleNamespace

import pytest

import Container_Audit as ca

_ContainerAudit = ca.ContainerAudit


class Widget:
    def __init__(self, parent=None, **options):
        self.parent = parent
        self.master = parent
        self.options = options
        self.grid_options = {}
        self.visible = False
        self.children = []
        self.width, self.height = 300, 768
        self.requested_height = 24
        self.row_options = {}
        self.pack_options = {}
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
        self.pack_options.update(options)
        self.visible = True

    def grid_info(self):
        return self.grid_options

    def grid_configure(self, **options):
        self.grid_options.update(options)

    def grid_rowconfigure(self, row, **options):
        if not options:
            return self.row_options.get(row, {})
        self.row_options.setdefault(row, {}).update(options)

    def cget(self, name):
        return self.options.get(name, "")

    def winfo_width(self):
        return self.width

    def winfo_height(self):
        return self.height

    def winfo_reqwidth(self):
        return 100

    def winfo_reqheight(self):
        return self.requested_height

    def winfo_ismapped(self):
        return self.visible

    def winfo_manager(self):
        return "grid" if self.visible and self.grid_options else ""

    def winfo_children(self):
        return self.children

    def add(self, child, **options):
        pass

    def after(self, *args):
        pass

    def grid_columnconfigure(self, *args, **options):
        pass

    def bind(self, *args, **options):
        pass

    def unbind(self, *args):
        pass


def install_sync_display(app):
    """Install only display stubs while retaining a flow's real lane/root helpers."""
    footer = Widget(app.root)
    footer.width = 1366
    app.direct_sync_status_label = Widget(footer)
    app.status_label = Widget(footer, font=("Malgun Gothic", 11))
    parent = Widget()
    app._right_sidebar_frame = parent
    app.catalog_notice_frame = Widget(parent)
    app.catalog_notice_frame.grid(row=3, column=0)
    app.catalog_notice_label = Widget(app.catalog_notice_frame)
    app.catalog_notice_label.grid(row=0, column=0)
    app.catalog_notice_details_label = Widget(app.catalog_notice_frame)
    app.catalog_notice_details_label.grid(row=1, column=0)
    app.work_details_button = Widget(parent)
    app.logistics_progress_button = Widget(parent)
    for name in ("_render_direct_sync_status_line", "_catalog_notice_for_display", "_apply_catalog_notice_layout"):
        setattr(app, name, getattr(_ContainerAudit, name).__get__(app))
    for name in ("COLOR_TEXT_SUBTLE", "COLOR_SIDEBAR_BG", "COLOR_DANGER", "COLOR_IDLE_TEXT", "COLOR_IDLE_BG", "DEFAULT_FONT"):
        setattr(app, name, getattr(_ContainerAudit, name))
    app._pane_viewport_height = _ContainerAudit._pane_viewport_height
    app._apply_catalog_notice_layout()


def catalog_notice_text(app):
    assert app.catalog_notice_frame.visible and app.catalog_notice_label.visible
    parts = [app.catalog_notice_label.options["text"]]
    detail = app.catalog_notice_details_label.options["text"]
    if detail:
        assert app.catalog_notice_details_label.visible
        parts.append(detail)
    return "\n".join(parts)


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
