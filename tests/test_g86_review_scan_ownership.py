"""Linked input regressions for the lane-approved REVIEW-G86 findings."""
from types import SimpleNamespace as NS

import pytest
import ca_screen_bridge as screen

from tests import test_g86_scan_input_ownership as g

RESTART = "입력 칸 오류 — 프로그램을 다시 켜세요"


def feedback(app):
    notices, sounds = g.record_refusals(app)
    app.show_status_message = lambda text, *_args, **_kw: notices.append(text)
    return notices, sounds


def bridge_for(app):
    bridge = type("ReviewBridge", (), g.CA_BRIDGE)()
    bridge.app, bridge.view, bridge._scan_answer, bridge._answer = app, None, None, None
    app._notice_button_captures_scan = lambda: False
    return bridge


@pytest.mark.parametrize("preserve_held", [False, True])
def test_invalidation_consumes_old_value_before_reopening(preserve_held):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app.scan_entry.insert("end", g.FIRST)
    app.process_barcode()
    app._invalidate_pending_scan_callbacks(preserve_held_scans=preserve_held)
    assert app.scan_entry.get() == ""
    app.scan_entry.insert("end", g.SECOND)
    app.root.drain()
    assert notices and "다시 스캔" in notices[-1] and sounds
    assert app.scan_entry.get() == g.SECOND
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [g.SECOND]


@pytest.mark.parametrize("residual", [False, True])
def test_stale_callback_discards_owned_prefix_before_later_enter(residual):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app.scan_entry.insert("end", g.FIRST)
    app.process_barcode()
    # Recreate an already-invalidated callback whose old entry was reopened.
    app._scan_callback_epoch = 1
    app.scan_entry.configure(state="normal")
    app.scan_entry.insert("end", g.SECOND)
    if residual:
        app._reject_residual_tag = lambda raw: raw == g.FIRST
    app.root.drain()
    app._reject_residual_tag = lambda _raw: False
    app.process_barcode()
    app.root.drain()
    assert app.accepted == []
    assert app.scan_entry.get() == ""
    assert notices and "다시 스캔" in notices[-1] and sounds
    app.scan_entry.insert("end", g.SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [g.SECOND]


@pytest.mark.parametrize("writer_failure", [False, True])
def test_bridge_rejects_empty_locked_entry_after_preflight_failure(writer_failure):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app._master_preflight_pending = True
    saved = NS(items=[])
    app._preflight_hold_snapshot = saved
    app._scans_behind_save = []
    if writer_failure:
        g.CA["_hold_scan_during_preflight"].__globals__["PreflightHoldFull"] = type("PreflightHoldFull", (Exception,), {})
        app._preflight_hold_writer = lambda: NS(submit=lambda work, finish, fail: (
            app.root.after(0, fail, RuntimeError()), NS(accepted=True))[1])
    app.scan_entry.insert("end", g.FIRST)
    app.process_barcode()
    app.root.drain()
    assert app._preflight_scan_input_locked
    assert app.scan_entry.get() == "" and app.scan_entry.state == "disabled"
    response = bridge_for(app).scan(g.SECOND, {})
    app.root.drain()
    assert response["accepted"] is False
    assert response["message"] and sounds
    assert app.accepted == [] and app._scans_behind_save == []
    assert app._preflight_hold_snapshot is saved
    assert not app._preflight_hold_append_pending
    app._master_preflight_pending = app._preflight_scan_input_locked = False
    app._set_scan_callback_pending(False)
    bridge_for(app).scan(g.SECOND, {})
    app.root.drain()
    assert app.accepted == [g.SECOND]


@pytest.mark.parametrize("failure", ["delete", "read"])
def test_bridge_permanent_cleanup_failure_latches_broken_input(failure):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app.scan_entry.insert("end", g.FIRST)
    get = app.scan_entry.get
    if failure == "delete":
        app.scan_entry.fail_delete = 20
    else:
        def unreadable():
            raise g.TclError("synthetic read failure")
        app.scan_entry.get = unreadable
    bridge = bridge_for(app)
    response = bridge.scan(g.SECOND, {})
    assert response["accepted"] is False
    assert getattr(app, "_scan_entry_broken", False)
    assert notices[-1] == response["message"] == RESTART
    app.scan_entry.get, app.scan_entry.fail_delete = get, 0
    response = bridge.scan(g.SECOND, {})
    app.root.drain()
    assert response["accepted"] is False and response["message"] == RESTART
    assert app.accepted == [] and len(sounds) >= 2


@pytest.mark.parametrize("failure", ["delete", "read"])
def test_bridge_transient_cleanup_failure_discards_without_breaking(failure):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app.scan_entry.insert("end", g.FIRST)
    if failure == "delete":
        app.scan_entry.fail_delete = 1
    else:
        get = app.scan_entry.get
        calls = []
        def one_bad_read():
            calls.append(True)
            if len(calls) == 1:
                raise g.TclError("synthetic read failure")
            return get()
        app.scan_entry.get = one_bad_read
    bridge = bridge_for(app)
    response = bridge.scan(g.SECOND, {})
    assert response["accepted"] is False
    assert app.scan_entry.get() == "" and not getattr(app, "_scan_entry_broken", False)
    assert notices and sounds
    bridge.scan(g.SECOND, {})
    app.root.drain()
    assert app.accepted == [g.SECOND]


def test_broken_input_blocks_real_common_logic_before_workflow_dispatch():
    app = g.ca_app()
    notices, sounds = feedback(app)
    app._scan_entry_broken = True
    app._handle_partial_submission_scan = lambda raw: app.accepted.append(raw) or True
    common = g.methods("Container_Audit.py", {"_process_barcode_logic"})["_process_barcode_logic"]
    common(app, g.SECOND)
    assert app.accepted == []
    assert notices[-1] == RESTART and sounds


def test_broken_input_survives_actual_warning_rerender():
    from Container_Audit import ContainerAudit
    from tests.test_warning_presenter_headless_integration import _scan_app
    app = _scan_app(save_succeeds=True, events=[])
    app._scan_entry_broken = True
    app.scan_entry = g.Entry()
    title, message = {}, {}
    visible = {}
    def widget(name, fields):
        return NS(configure=lambda **kw: fields.update(kw),
                  grid=lambda: visible.update({name: True}),
                  grid_remove=lambda: visible.update({name: False}))
    app.notice_frame = widget("frame", {})
    app.notice_title_label = widget("title", title)
    app.notice_message_label = widget("message", message)
    app._schedule_notice_message_wrap_refresh = lambda **_kw: None
    ContainerAudit._render_warning_state(app)
    assert app.scan_entry.state == "disabled"
    assert RESTART in (title.get("text"), message.get("text"))
    assert visible == {"frame": True, "title": True, "message": True}



@pytest.mark.parametrize("busy", [False, True])
def test_broken_input_survives_completion_lane_state_refresh(busy):
    app = g.ca_app()
    notices, sounds = feedback(app)
    app._scan_entry_broken = True
    app._update_action_button_states = lambda: None
    app._schedule_focus_return = lambda: None
    refresh = g.methods("Container_Audit.py", {"_set_completion_lane_busy"})["_set_completion_lane_busy"]
    refresh(app, busy)
    assert app._completion_lane_busy is busy
    assert app.scan_entry.state == "disabled"
    assert notices and notices[-1] == RESTART and sounds


def test_broken_input_persists_in_screen_result_alerts_and_fingerprint():
    import datetime
    state = NS(active_notice=None, completion=None, last_normal_scan="")
    tray = NS(master_label_code="", scanned_barcodes=[], tray_size=0)
    app = NS(current_tray=tray, _warning_state_presenter=lambda: NS(state=state),
             _partial_submission_state=lambda: None,
             _is_preflight_hold_supervisor=lambda: False)
    before = screen.fingerprint(app, "work", [], None)
    app._scan_entry_broken = True
    result = screen._result(app, state, tray, 0, None)
    assert result["kind"] == screen.RESULT_KIND[screen.NoticeSeverity.ERROR]
    assert result["title"] == RESTART
    alerts = screen._alerts(app, state, [], datetime.datetime.now())
    assert alerts and alerts[0]["text"] == RESTART
    assert screen.fingerprint(app, "work", [], None) != before


@pytest.mark.parametrize("permanent", [False, True])
def test_first_tk_read_failure_uses_shared_cleanup_before_another_scan(permanent):
    app = g.ca_app()
    notices, sounds = feedback(app)
    tray = app.current_tray
    app.scan_entry.insert("end", g.FIRST)
    get, calls = app.scan_entry.get, []
    def read():
        calls.append(True)
        if permanent or len(calls) == 1:
            raise g.TclError("synthetic read failure")
        return get()
    app.scan_entry.get = read
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [] and app.current_tray is tray
    assert notices and sounds
    assert bool(getattr(app, "_scan_entry_broken", False)) is permanent
    app.scan_entry.get = get
    if permanent:
        assert notices[-1] == RESTART
        assert bridge_for(app).scan(g.SECOND, {})["accepted"] is False
    else:
        assert app.scan_entry.get() == "" and "다시 스캔" in notices[-1]
        app.scan_entry.insert("end", g.SECOND)
        app.process_barcode()
        app.root.drain()
        assert app.accepted == [g.SECOND]
