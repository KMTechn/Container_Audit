"""Side-control focus contracts without a native Tk window."""
import ast
import inspect
import textwrap
from types import SimpleNamespace

import pytest

import Container_Audit as ca


@pytest.fixture
def focus_app():
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    events = []
    pending = []

    def after(delay, callback):
        events.append(("focus scheduled", delay))
        pending.append(callback)
        return "focus-job"

    app.root = SimpleNamespace(
        after=after, after_cancel=lambda _job: None,
        winfo_pointerx=lambda: 30, winfo_pointery=lambda: 40,
        focus_get=lambda: "side control",
    )
    app.scan_entry = SimpleNamespace(
        winfo_exists=lambda: True,
        focus_set=lambda: events.append("scan focused"),
    )
    app.warning_presenter = ca.WarningPresenter()
    app.current_tray = ca.TraySession()
    app._preflight_context_blocks_mutation = lambda: False
    app._active_blocking_completion_snapshot = lambda: None
    app._current_transfer_member_exchange_attempt = lambda: None
    app._exact_transfer_exchange_blocked = lambda: False
    app._is_preflight_hold_supervisor = lambda: False
    app._admin_pin_has_pending = lambda: False
    app.operations_button = SimpleNamespace(
        winfo_rootx=lambda: 10, winfo_rooty=lambda: 20, winfo_height=lambda: 15,
    )
    return app, events, pending


@pytest.mark.parametrize("expanded", [False, True])
def test_details_open_and_close_return_focus_after_visibility_change(focus_app, expanded):
    app, events, pending = focus_app
    app._work_details_expanded = expanded
    app.work_details_button = SimpleNamespace(configure=lambda **kw: events.append(kw))
    app._right_context_frame = SimpleNamespace(
        grid=lambda: events.append("shown"), grid_remove=lambda: events.append("hidden"),
    )
    app._secondary_stats_frame = app._right_context_frame

    app._toggle_work_details()

    assert app._work_details_expanded is not expanded
    assert events[:3] == [
        {"text": "작업 상세 ▸" if expanded else "작업 상세 ▾"},
        "hidden" if expanded else "shown", "hidden" if expanded else "shown",
    ]
    assert events[-1] == ("focus scheduled", 50)
    assert len(pending) == 1
    pending.pop()()
    assert events[-1] == "scan focused"


@pytest.mark.parametrize("pin_recheck", [False, True])
@pytest.mark.parametrize("exit_path", ["selected", "cancelled", "popup_error", "release_error"])
def test_operations_menu_always_schedules_focus_after_releasing_grab(
    focus_app, monkeypatch, pin_recheck, exit_path,
):
    app, events, pending = focus_app
    if pin_recheck:
        app.warning_presenter.present(ca.Notice(
            code="synthetic-blocking-warning", title="확인 필요", message="안내 확인",
            blocking=True,
        ))
    app._admin_pin_has_pending = lambda: pin_recheck
    app._show_direct_sync_status_details = lambda: events.append("selected")
    app._recheck_admin_pin_intents = lambda: events.append("selected")
    entries = []

    class Menu:
        def __init__(self, *_args, **_kwargs): pass
        def add_command(self, **kwargs): entries.append(kwargs)
        def add_separator(self): pass
        def tk_popup(self, *_args):
            events.append("popup")
            if exit_path == "popup_error":
                raise ca.tk.TclError("synthetic popup error")
            if exit_path == "selected":
                entries[0]["command"]()
        def grab_release(self):
            events.append("released")
            if exit_path == "release_error":
                raise ca.tk.TclError("synthetic release error")

    monkeypatch.setattr(ca.tk, "Menu", Menu)
    app._show_operations_menu()

    assert events[-2:] == ["released", ("focus scheduled", 50)]
    assert events.count("popup") == (2 if exit_path == "popup_error" and not pin_recheck else 1)
    assert ("selected" in events) == (exit_path == "selected")
    assert len(pending) == 1
    pending.pop()()
    # Existing blocking-notice/PIN input ownership remains in the focus helper.
    assert (events[-1] == "scan focused") is not pin_recheck


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("image_label_exists", [False, True])
def test_image_toggle_returns_focus_with_or_without_live_image_label(
    focus_app, enabled, image_label_exists,
):
    app, events, pending = focus_app
    app.tray_image_label = SimpleNamespace(winfo_exists=lambda: image_label_exists)
    app.show_tray_image_var = SimpleNamespace(get=lambda: enabled)
    app._apply_left_sidebar_layout = lambda: events.append("layout")
    app._clear_tray_image_label = lambda *args: events.append(("image cleared", args))

    app._update_tray_image_display()

    if image_label_exists:
        assert events[0] == "layout"
        assert events[1] == ("image cleared", (
            "현품표를 먼저\n스캔해주세요.", app.COLOR_TEXT_SUBTLE,
        ) if enabled else ("",))
    else:
        assert len(events) == 1
    assert events[-1] == ("focus scheduled", 50)
    assert len(pending) == 1
    pending.pop()()
    assert events[-1] == "scan focused"


@pytest.mark.parametrize("builder, command", [
    ("_create_left_sidebar_content", "change_worker"),
    ("_create_left_sidebar_content", "_toggle_left_sidebar_view"),
    ("_create_left_sidebar_content", "_update_tray_image_display"),
    ("_create_center_content", "_show_operations_menu"),
    ("_create_right_sidebar_content", "_show_direct_sync_status_details"),
    ("_create_right_sidebar_content", "show_logistics_progress"),
    ("_create_right_sidebar_content", "_toggle_work_details"),
])
def test_side_controls_leave_keyboard_tab_navigation_to_inputs(builder, command):
    tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(ca.ContainerAudit, builder))))
    controls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and any(kw.arg == "command" and isinstance(kw.value, ast.Attribute)
                        and kw.value.attr == command for kw in node.keywords)]
    assert len(controls) == 1
    options = {kw.arg: kw.value for kw in controls[0].keywords}
    assert "takefocus" in options
    assert ast.literal_eval(options["takefocus"]) is False
