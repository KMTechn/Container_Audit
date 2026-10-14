"""Web commands never use Tk modals or turn unknown/error returns into success."""
import random

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from tests.test_ca_screen_bridge import _app, _idle, flow, windows, fixed_operation_lease_clock
from tests.test_ca_v2106 import application, roster

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "windows", "owned_tk_workers")


@pytest.mark.parametrize("route", ["menu", "button", "resend", "handler", "restore", "start_work"])
@pytest.mark.parametrize("outcome", ["success", "failure", "error_text", "unknown"])
def test_app_return_is_not_implicitly_success(flow, monkeypatch, route, outcome):
    app = _app(flow)
    processor = screen.CaProcessor(app)
    value = {"success": True, "failure": False, "error_text": "synthetic-action-error", "unknown": None}[outcome]
    def action(*args, **kwargs):
        return value
    if route in {"menu", "resend"}:
        monkeypatch.setattr(screen, "operations_menu", lambda _app: {
            "reset": (True, action), "resend_completion": (True, action)})
        app._is_preflight_hold_supervisor = lambda: True
        reply = processor.command("reset", {"id": "confirmed"}) if route == "menu" else processor.command("resend_completion")
    elif route == "button":
        class Button(dict):
            def configure(self, **options):
                self.update(options)
            def invoke(self):
                return self["command"]()
        app.park_button = Button(state=ca.tk.NORMAL)
        from tk_callback_result import bind_button_callback
        bind_button_callback(app.park_button, action)
        reply = processor.command("park")
    elif route == "handler":
        processor._cmd_synthetic = action
        reply = processor.command("synthetic")
    elif route == "restore":
        processor._park_paths = {"known": "synthetic-path"}
        app.restore_parked_tray = action
        reply = processor.command("restore", {"id": "known"})
    else:
        from tests.test_observed_scanner_completion import ScannerEntry
        app.worker_entry = ScannerEntry("")
        app.start_work = action
        reply = processor.command("start_work", {"id": "worker"})
    assert reply["ok"] is (outcome == "success")
    if outcome == "unknown":
        assert reply["result"]["kind"] == "idle"
    elif outcome != "success":
        assert reply["result"]["kind"] == "warn"


def test_error_note_cannot_be_overwritten_by_a_later_info_or_resend_success(flow, monkeypatch):
    app = _app(flow)
    app._is_preflight_hold_supervisor = lambda: True
    processor = screen.CaProcessor(app)
    def action():
        ca.messagebox.showerror("작업 거절", "처리할 수 없습니다")
        ca.messagebox.showinfo("알림", "상태를 확인하세요")
        return True
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"resend_completion": (True, action)})
    processor.install()
    try:
        reply = processor.command("resend_completion")
        assert reply["ok"] is False and reply["result"]["text"].startswith("작업 거절")
    finally:
        processor.shutdown()


@pytest.mark.parametrize("admin_id", ["", " "])
def test_empty_admin_input_is_refused_before_action_or_tk(flow, monkeypatch, admin_id):
    processor = screen.CaProcessor(_app(flow))
    touched = []
    monkeypatch.setattr(screen, "operations_menu", lambda _app: touched.append("menu"))
    monkeypatch.setattr(ca.tk, "Toplevel", lambda *_a, **_k: touched.append("tk"))
    pin = "".join(random.choice("0123456789") for _ in range(6))
    reply = processor.admin("defer_unsettled", {"admin_id": admin_id, "pin": pin})
    assert reply["ok"] is False
    assert touched == []


def test_actual_web_registration_and_pin_paths_create_zero_toplevels(flow, tmp_path, monkeypatch):
    app = application(flow, tmp_path)
    app.worker_roster = roster(tmp_path / "web-roster")
    from tests.test_observed_scanner_completion import ScannerEntry
    app.worker_entry = ScannerEntry("")
    processor = screen.CaProcessor(app)
    top_levels = []
    def forbidden_toplevel(*args, **kwargs):
        top_levels.append(True)
        pytest.fail("web path created a Tk Toplevel")
    monkeypatch.setattr(ca.tk, "Toplevel", forbidden_toplevel)
    processor.install()
    try:
        assert processor.command("register_worker", {"name": "웹 등록 시험"})["ok"] is True
        assert app.worker_roster.pending_requests()
        monkeypatch.setattr(screen, "operations_menu", lambda _app: {
            "defer_unsettled": (True, app._prompt_blocked_work_admin_pin)})
        # No credentials available: return a web warning, without calling the old modal.
        reply = processor._menu("defer_unsettled")
        assert reply["ok"] is False and reply["result"]["text"].startswith("관리자 확인이 다시 필요합니다")
        assert top_levels == []
    finally:
        processor.shutdown()


def test_actual_web_scan_internal_test_path_creates_zero_toplevels(flow, monkeypatch):
    app = _app(flow)
    app.internal_test_commands_enabled = True
    processor = screen.CaProcessor(app)
    top_levels = []
    def forbidden_toplevel(*args, **kwargs):
        top_levels.append(True)
        pytest.fail("web scan created a Tk Toplevel")
    monkeypatch.setattr(ca.tk, "Toplevel", forbidden_toplevel)
    processor.install()
    try:
        assert processor.scan("_RUN_AUTO_TEST_", {})["accepted"] is True
        _idle(app, lambda: bool(processor.notes))
        assert top_levels == [] and processor.notes[-1]["kind"] == "warn"
    finally:
        processor.shutdown()
