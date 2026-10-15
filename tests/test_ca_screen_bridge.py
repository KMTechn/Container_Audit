"""이적 새 화면 이음(ca_screen_bridge) — 처리 층은 그대로, 다리만 본다(창 0 · 진짜 Tk 0 · 시험 고정물의 가짜 뿌리).

APP-SCREENS-1013 ③ · 셸 HOST-USE §7: state 꼴 = contract.json · scan → 처리 → push 순서 · 같은 seq 다시 → 처리 한 번 ·
admin 인수는 기록에 없음. 합성 PIN 은 실행 때 무작위로 만들고 화면 · 실패 글에 찍지 않는다.
"""
from __future__ import annotations

import json
import random
import sys
import threading
import time
from pathlib import Path

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from ca_screen_bridge import CaProcessor
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_scanonly_review_regressions import real_notice
from tests.test_w9scanonly_workflow import _active, _own_coordinators_on_lane, _pump_until, flow, windows  # noqa: F401
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "ui" / "app" / "ca" / "contract.json").read_text(encoding="utf-8"))
pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "windows")


def _schema_errors(value, schema, where="state"):
    """contract.json 의 JSON Schema 부분집합(틀 tests/ui/test_app_screens.py 와 같은 셈)."""
    errors = []
    if schema is CONTRACT["state"]["properties"]["sheet"] and isinstance(value, dict):
        # 고정 계약에 아직 없는 두 칸만 제외한다. 값과 취소 동작은 아래에서 직접 확인.
        value = {key: item for key, item in value.items()
                 if key not in {"modal", "cancel"} or key in schema.get("properties", {})}
    kinds = schema.get("type")
    checks = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list), "string": lambda v: isinstance(v, str),
              "boolean": lambda v: isinstance(v, bool), "null": lambda v: v is None,
              "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)}
    if kinds is not None and not any(checks[k](value) for k in ([kinds] if isinstance(kinds, str) else kinds)):
        return [f"{where}: 꼴 {kinds}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{where}: const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: enum {value!r}")
    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool) and value < schema["minimum"]:
        errors.append(f"{where}: minimum")
    if isinstance(value, dict):
        errors += [f"{where}.{k}: 없음" for k in schema.get("required", []) if k not in value]
        for key, item in value.items():
            if key in schema.get("properties", {}):
                errors += _schema_errors(item, schema["properties"][key], f"{where}.{key}")
            elif schema.get("additionalProperties", True) is False:
                errors.append(f"{where}.{key}: contract 밖")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{where}: maxItems")
        for index, item in enumerate(value if "items" in schema else []):
            errors += _schema_errors(item, schema["items"], f"{where}[{index}]")
    return errors


def _app(flow):
    """지금 시험의 public_scan 과 같은 준비(tests/test_scanonly_review_regressions.py) — 직렬 줄 · 이적 조정자를 그 줄 주인으로."""
    app = _active(flow)
    app.root.tk = object()
    app._ui_task_lane()
    _own_coordinators_on_lane(app)
    app.scan_entry = ScannerEntry("")
    if not str(getattr(app, "worker_name", "") or "").strip():
        app.worker_name = "작업자 05"
    return app


def _idle(app, predicate=lambda: True):
    _pump_until(app.root, lambda: predicate() and not app._ui_task_lane().is_busy())


def test_state_is_the_contract_shape_and_counts_come_from_the_tray(flow):
    app = _app(flow)
    state = CaProcessor(app).state()
    assert _schema_errors(state, CONTRACT["state"]) == []
    tray, work = app.current_tray, state["work"]
    assert (work["count"], work["target"]) == (len(tray.scanned_barcodes), tray.tray_size)
    assert work["left_kind"] == "remaining" and work["remaining"] == tray.tray_size - len(tray.scanned_barcodes)
    assert work["list_count"] == work["count"] and state["view"] == "work"
    defer = next(item for item in state["admin_menu"] if item["name"] == "defer_unsettled")
    assert defer["facts"][0][0] == "현재 묶음" and f"스캔 {len(tray.scanned_barcodes)}" in defer["facts"][0][1]  # 처리 층 값 그대로


def test_scan_goes_through_the_existing_door_and_the_list_grows(flow):
    app = _app(flow)
    processor = CaProcessor(app)
    member = app.current_tray.known_member_barcodes[0]  # 회사 서버가 준 이 트레이 제품
    reply = processor.scan(member, {"seq": 1})
    assert reply["accepted"] is True and reply["sound"] is None  # 소리는 처리 층(native_audio) — 셸이 겹쳐 내지 않음
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 1)
    state = processor.state()
    work = state["work"]
    assert (work["count"], work["list_count"], work["list"][0]["st"]) == (1, 1, "new")
    assert work["result"]["kind"] == "ok" and work["result"]["text"] == "제품 확인 1개"
    assert _schema_errors(state, CONTRACT["state"]) == []


def test_ack_is_the_empty_enter_door_for_a_blocking_notice(flow):
    app = _app(flow)
    real_notice(app)  # 고정물이 바꿔 둔 알림 그리기를 진짜로
    processor = CaProcessor(app)
    app.show_fullscreen_warning("시험 알림", "확인하세요", app.COLOR_DANGER)
    band = processor.state()["alerts"][0]
    assert band["kind"] == "bad" and band["choices"][0]["go"] == "command:ack"
    assert processor.command("ack", {}) == {"ok": True}
    _idle(app, lambda: app._warning_state_presenter().state.active_notice is None)
    assert not [a for a in processor.state()["alerts"] if a["kind"] == "bad"]


def test_band_choice_runs_the_same_callback_as_the_tk_button(flow):
    app = _app(flow)
    real_notice(app)
    processor = CaProcessor(app)
    app.change_worker()
    band = next(a for a in processor.state()["alerts"] if a.get("choices"))
    assert [c["id"] for c in band["choices"]] == ["change_worker", "continue"]
    assert [c["go"] for c in band["choices"]] == ["command:choose:change_worker", "command:choose:continue"]
    assert processor.command("choose", {"id": "continue"}) == {"ok": True}
    assert not app._inline_scan_choices and app._warning_state_presenter().state.active_notice is None
    assert processor.command("choose", {"id": "continue"})["ok"] is False  # 지나간 선택


def test_admin_pin_replaces_the_modal_once_and_keeps_no_value(flow, monkeypatch):
    app = _app(flow)
    processor = CaProcessor(app)
    processor.install()
    try:
        seen = []

        def action():
            seen.append(app._prompt_blocked_work_admin_pin(action="CA.TRAY_HOLD"))
            seen.append(app._prompt_blocked_work_admin_pin(action="CA.TRAY_HOLD"))
            ca.messagebox.showinfo("보류", "보류했습니다 — 다른 현품표 작업을 계속하세요")

        monkeypatch.setattr(screen, "operations_menu", lambda _app: {"list_paired": (True, action)})
        pin = "".join(random.choice("0123456789") for _ in range(6))
        reply = processor.admin("list_paired", {"admin_id": "opcheck", "pin": pin})
        handed = seen[0] == ("opcheck", pin)
        assert handed and seen[1] is None, "PIN 은 그 동작에 한 번만 넘어감"
        assert reply["ok"] is False and reply["result"]["text"].startswith("관리자 확인이 다시 필요합니다")
        leaked = pin in json.dumps(processor.state(), ensure_ascii=False) or pin in json.dumps(reply, ensure_ascii=False)
        assert not leaked, "state · 답에 PIN 이 남음"
        assert processor.admin("list_paired", {"admin_id": "opcheck", "pin": "12"})["ok"] is False
        assert processor.admin("view_sync", {"admin_id": "opcheck", "pin": pin})["ok"] is False  # PIN 없는 보기 판은 admin 아님
    finally:
        processor.shutdown()
    assert ca.messagebox is not processor.dialogs  # 닫으면 모듈 이름이 돌아옴


def test_resend_completion_is_a_worker_action_without_pin(flow, monkeypatch):
    app = _app(flow)
    app.worker_role = "WORKER"
    app._authenticated_protected_admin = False
    processor = CaProcessor(app)
    called = []
    def resend():
        called.append("same-command")
        return True
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"resend_completion": (True, resend)})
    item = next(item for item in processor.state()["admin_menu"] if item["name"] == "resend_completion")
    assert item["enabled"] is True and item["pin"] is False
    assert processor.command("resend_completion")["ok"]
    assert called == ["same-command"]
    assert processor._credentials is None


@pytest.mark.parametrize("role, protected", [("ADMIN", False), ("WORKER", True)])
def test_resend_completion_calls_the_recorded_menu_once_and_returns_its_note(flow, monkeypatch, role, protected):
    app = _app(flow)
    app.worker_role = role
    app._authenticated_protected_admin = protected
    processor = CaProcessor(app)
    called = []

    def action():
        called.append(True)
        ca.messagebox.showinfo("완료 작업 확인", "저장된 완료 요청을 다시 보냈습니다")
        return True

    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"resend_completion": (True, action)})
    processor.install()
    try:
        item = next(item for item in processor.state()["admin_menu"] if item["name"] == "resend_completion")
        assert item["enabled"] is True
        reply = processor.command("resend_completion")
        assert called == [True]
        assert reply == {"ok": True, "result": {"kind": "ok", "text": "완료 작업 확인 — 저장된 완료 요청을 다시 보냈습니다"}}
        assert processor._credentials is None and processor._admin_notes is None
        assert processor.notes == []
    finally:
        processor.shutdown()


def test_resend_completion_obeys_menu_disable_even_when_logged_in(flow, monkeypatch):
    app = _app(flow)
    app.worker_role = "ADMIN"
    processor = CaProcessor(app)
    called = []
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"resend_completion": (False, lambda: called.append(True))})
    item = next(item for item in processor.state()["admin_menu"] if item["name"] == "resend_completion")
    assert item["enabled"] is False
    assert processor.command("resend_completion")["ok"] is False
    assert called == []


def test_resend_completion_rejects_the_pin_api_without_running_the_menu(flow, monkeypatch):
    app = _app(flow)
    app.worker_role = "ADMIN"
    processor = CaProcessor(app)
    called = []
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"resend_completion": (True, lambda: called.append(True))})
    pin = "".join(random.choice("0123456789") for _ in range(6))
    reply = processor.admin("resend_completion", {"admin_id": "SYNTHETIC-ADMIN", "pin": pin})
    assert reply["ok"] is False
    assert called == []
    assert processor._credentials is None


def test_question_becomes_a_sheet_waits_for_the_screen_and_holds_scans(flow):
    app = _app(flow)
    processor = CaProcessor(app)
    seen = {}

    def screen_answers(_answer):
        seen["state"] = processor.state()
        seen["scan"] = processor.scan(app.current_tray.known_member_barcodes[0], {"seq": 9})
        processor.command("choose", {"id": "ask_yes"})

    processor._wait = screen_answers
    assert processor.dialogs.askyesno("이전 작업 삭제", "이전 작업을 영구적으로 삭제할까요?") is True
    sheet = seen["state"]["sheet"]
    assert sheet["title"] == "이전 작업 삭제"
    assert [a["go"] for a in sheet["actions"]] == ["command:choose:ask_no", "command:choose:ask_yes"]
    assert _schema_errors(seen["state"], CONTRACT["state"]) == []
    assert seen["scan"]["accepted"] is False  # 물음이 열린 동안 스캔은 미접수(먼저 답)
    assert processor.state()["sheet"] is None and len(app.current_tray.scanned_barcodes) == 0


@pytest.mark.parametrize("method, expected", [
    ("askyesno", False), ("askokcancel", False), ("askretrycancel", False),
    ("askquestion", "no"), ("askyesnocancel", False),
])
def test_question_becomes_a_modal_sheet_and_cancel_returns_no(flow, method, expected):
    app = _app(flow)
    processor = CaProcessor(app)

    def cancel_from_screen(_answer):
        state = processor.state()
        sheet = state["sheet"]
        assert sheet["modal"] is True and sheet["cancel"] == "choose:ask_no"
        assert _schema_errors(state, CONTRACT["state"]) == []
        assert processor.scan(app.current_tray.known_member_barcodes[0], {})["accepted"] is False
        route, choice = sheet["cancel"].split(":", 1)
        assert processor.command(route, {"id": choice}) == {"ok": True}

    processor._wait = cancel_from_screen
    assert getattr(processor.dialogs, method)("확인", "이 작업을 계속할까요?") == expected
    assert processor.state()["sheet"] is None and not app.current_tray.scanned_barcodes


@pytest.mark.parametrize("method", ["askstring", "askinteger"])
def test_scan_question_modal_cancel_returns_none(flow, method):
    app = _app(flow)
    processor = CaProcessor(app)

    def cancel_from_screen(_answer):
        state = processor.state()
        sheet = state["sheet"]
        assert sheet["modal"] is True and sheet["cancel"] == "choose:ask_cancel"
        assert sheet["actions"][0]["go"] == "command:" + sheet["cancel"]
        assert _schema_errors(state, CONTRACT["state"]) == []
        route, choice = sheet["cancel"].split(":", 1)
        assert processor.command(route, {"id": choice}) == {"ok": True}

    processor._wait = cancel_from_screen
    assert getattr(processor.dialogs, method)("원 현품표 확인", "현품표를 스캔하세요") is None
    assert processor.state()["sheet"] is None


def test_reset_only_from_the_confirm_sheet(flow, monkeypatch):
    app = _app(flow)
    processor = CaProcessor(app)
    called = []
    def action():
        called.append(1)
        return True
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {"reset": (True, action)})
    assert processor.command("reset", {})["ok"] is False and not called
    assert processor.command("reset", {"id": "confirmed"}) == {"ok": True} and called == [1]


def test_progress_pane_uses_the_server_remaining_values(flow):
    app = _app(flow)
    app._progress_visible = True
    app._progress_disconnected = False
    app._progress_last_success = "10-13 09:00:00"
    app._progress_data = {"date": "2026-10-13", "items": [
        {"item_id": app.current_tray.item_code, "name": "시험 품목", "plan_qty": 120, "transferred_qty": 40, "remaining_qty": 80, "remaining_boxes": 2},
        {"item_id": "OTHER", "plan_qty": 60, "transferred_qty": 60, "remaining_qty": 0, "remaining_boxes": 0}]}
    state = CaProcessor(app).state()
    assert state["view"] == "progress" and _schema_errors(state, CONTRACT["state"]) == []
    rows = state["progress"]["rows"]
    assert (rows[0]["left"], rows[0]["trays_left"], rows[0].get("now")) == (80, 2, True)  # 처리 층(회사 서버) 값 그대로
    assert (rows[1]["item"], rows[1]["left"]) == ("OTHER", 0) and state["progress"]["at"] == "09:00:00"


def test_held_pane_today_comes_from_the_same_summary_as_tk(flow):
    app = _app(flow)
    app.total_tray_count = 5
    app.work_summary = {"A": {"name": "시험 품목", "spec": "RHD", "count": 3, "test_count": 0, "shipping_supplement_intents": {"i1", "i2"}},
                        "B": {"name": "다른 품목", "spec": "", "count": 2, "test_count": 1}}
    app._shipping_confirmed_intents = {"i2"}
    processor = CaProcessor(app)
    assert processor.command("open", {"id": "held"}) == {"ok": True}
    state = processor.state()
    assert state["view"] == "held" and _schema_errors(state, CONTRACT["state"]) == []
    today = state["today"]
    assert today["total_trays"] == 5 and today["supply"] == 1  # 보충 = 의도 − 확인된 것(지금 「금일 작업 현황」 셈과 같음)
    assert today["rows"] == [{"item": "시험 품목 · RHD", "trays": 3, 'products': 0}, {"item": "다른 품목", "trays": 2, 'products': 0}]
    assert processor.command("close", {}) == {"ok": True} and processor.state()["view"] == "work"


def test_start_pane_lists_the_roster_and_starts_through_the_entry(flow):
    from types import SimpleNamespace
    app = _app(flow)
    app.worker_name = ""
    app._worker_selection_names = lambda: ["작업자 01", "작업자 05"]
    app._worker_roster_notice_text = lambda: "이름을 고르세요. 목록에 없으면 『새 이름 등록』을 누르세요."
    app.worker_registry = SimpleNamespace(recent_worker=lambda: "작업자 05", list_workers=lambda: [])
    started = []
    def start_work(*args, **kwargs):
        started.append(app.worker_entry.get())
        return True
    app.start_work = start_work
    app.worker_entry = ScannerEntry("")
    processor = CaProcessor(app)
    state = processor.state()
    assert state["view"] == "start" and _schema_errors(state, CONTRACT["state"]) == []
    roster = state["roster"]
    assert [n["id"] for n in roster["names"]] == ["작업자 01", "작업자 05"] and roster["names"][1].get("last") is True
    assert roster["note"].startswith("이름을 고르세요")
    assert processor.command("start_work", {"id": "작업자 05"}) == {"ok": True} and started == ["작업자 05"]


@pytest.mark.parametrize("flags, step, stopped", [
    ({}, 0, False),
    ({"_phs_reconciliation_resolve_pending": True}, 1, False),
    ({"_phs_label_exchange_pending": True}, 2, False),
    ({"_phs_label_exchange_recovery_visible": True}, 2, True),
])
def test_f8_pane_uses_the_existing_panel_state_and_omits_missing_plan(flow, flags, step, stopped):
    app = _app(flow)
    app._phs_label_exchange_panel_open = True
    for name, value in flags.items():
        setattr(app, name, value)
    app.phs_active_label_info_label = {"text": f"회사 서버 지시 · {app.current_tray.tray_size}개"}
    state = CaProcessor(app).state()
    assert state["view"] == "f8" and _schema_errors(state, CONTRACT["state"]) == []
    pane = state["f8"]
    assert pane["sub"] == app.phs_active_label_info_label["text"]
    assert (pane["step"], pane["stop"]) == (step, stopped)
    assert "plan" not in pane and "target" not in pane and "print_error" not in pane


def test_f8_candidate_text_and_changes_use_the_existing_panel_sources(flow):
    from types import SimpleNamespace
    app = _app(flow)
    app._phs_label_exchange_panel_open = True
    app.phs_active_label_info_label = None
    candidate = {"target_qty_pcs": 47}
    app._phs_label_candidates = [candidate]
    selected = f"교체할 수량 {candidate['target_qty_pcs']}개"
    app.phs_label_candidate_var = SimpleNamespace(get=lambda: selected)
    processor = CaProcessor(app)
    assert processor.state()["f8"]["sub"] == app.phs_label_candidate_var.get()
    assert processor.state()["f8"]["step"] == 2
    before = screen.fingerprint(app, None, [], None)
    app._phs_label_exchange_pending = True
    assert screen.fingerprint(app, None, [], None) != before


@pytest.mark.parametrize("enabled", [True, False])
def test_f8_reprint_confirms_the_existing_variable_and_invokes_only_an_enabled_button(flow, enabled):
    from types import SimpleNamespace
    app = _app(flow)
    confirmed, calls = [], []
    app.phs_label_reprint_confirm_var = SimpleNamespace(set=confirmed.append)

    class Button(dict):
        def configure(self, **options):
            self.update(options)
        def invoke(self):
            return self["command"]()

    app.phs_label_exchange_execute_button = Button(state=ca.tk.NORMAL if enabled else ca.tk.DISABLED)
    def callback():
        calls.append(list(confirmed))
        return True
    from tk_callback_result import bind_button_callback
    bind_button_callback(app.phs_label_exchange_execute_button, callback)
    reply = CaProcessor(app).command("f8_reprint")
    assert confirmed == [True] and reply["ok"] is enabled
    assert calls == ([[True]] if enabled else [])


def test_preserve_check_facts_identify_only_the_existing_source_and_copy(flow, tmp_path):
    app = _app(flow)
    app._paired_stale_current_blocked = True
    app._paired_stale_current_path = tmp_path / "current.json"
    app._paired_stale_current_preserved_path = str(tmp_path / "preserved.json")
    assert screen.admin_facts(app, "preserve_check") == [
        ["현재 작업 원본", app._paired_stale_current_path.name],
        ["보존 사본 이름", Path(app._paired_stale_current_preserved_path).name],
    ]
    app._paired_stale_current_blocked = False
    assert screen.admin_facts(app, "preserve_check") == []


def test_resend_completion_facts_use_the_same_first_bound_case_as_the_action(flow):
    app = _app(flow)
    selected = {"command_bound": True, "item_id": "대상 품목", "scan_count": 27}
    app._transfer_post_review_cases = [
        {"command_bound": False, "item_id": "다른 품목", "scan_count": 99}, selected,
        {"command_bound": True, "item_id": "나중 품목", "scan_count": 41},
    ]
    state = CaProcessor(app).state()
    facts = next(item["facts"] for item in state["admin_menu"] if item["name"] == "resend_completion")
    assert facts == [["품목", selected["item_id"]], ["수량", f"{selected['scan_count']}개"]]
    assert _schema_errors(state, CONTRACT["state"]) == []
    app._transfer_post_review_cases = []
    assert screen.admin_facts(app, "resend_completion") == []


# ── 셸 host(v3.7 bridge, owner='external')와 한 바퀴 ─────────────────
class _Pedal:
    def snapshot(self):
        return False, 0

    def set_callback(self, _callback):
        return None

    def close(self):
        return None


class _Sound:
    def __init__(self):
        self.played = []

    def play(self, kind):
        self.played.append(kind)


def _meta(seq):
    return {"seq": seq, "evidence": {"pedal_pressed": False, "source": "webview_event_order"}, "paths": {"keydown": 1}}


def test_shell_bridge_scan_order_duplicate_and_admin_args_not_logged(flow, tmp_path):
    sys.path.insert(0, str(ROOT / "shell"))
    try:
        from bridge import Bridge
    finally:
        sys.path.remove(str(ROOT / "shell"))
    app = _app(flow)
    sound, pushes = _Sound(), []
    shell = Bridge(tmp_path / "shell", "rw", pedal=_Pedal(), sound=sound, owner="external")
    shell.set_notifier(pushes.append)
    processor = CaProcessor(app, bridge=shell)
    shell.attach_owner(processor)  # 이 시험 스레드가 주인(Tk 스레드 자리)
    members = list(app.current_tray.known_member_barcodes[:2])
    replies = {}

    def js_api():  # pywebview js_api 스레드 자리 — 접수만
        replies[1] = shell.scan(members[0], _meta(1))
        end = time.monotonic() + 10  # 스캐너 사이 간격 — 첫 제품이 들어간 뒤 다음
        while len(app.current_tray.scanned_barcodes) < 1 and time.monotonic() < end:
            time.sleep(0.01)
        replies["again"] = shell.scan(members[0], _meta(1))
        replies[2] = shell.scan(members[1], _meta(2))
        replies["admin"] = shell.admin("view_sync", {"admin_id": "opcheck", "pin": "".join(random.choice("0123456789") for _ in range(6))})

    caller = threading.Thread(target=js_api)
    caller.start()
    deadline = time.monotonic() + 15
    while caller.is_alive() and time.monotonic() < deadline:
        shell.pump()
        if app.root.jobs:
            app.root.run_next()
        time.sleep(0.003)
    caller.join(1)
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 2)
    try:
        assert replies[1]["accepted"] and replies[2]["accepted"] and replies["again"].get("duplicate") is True
        assert app.current_tray.scanned_barcodes == members  # seq 순서 그대로 · 같은 seq 는 처리 한 번
        assert sound.played == []  # sound=None — 셸은 겹쳐 내지 않음
        admin = replies["admin"]  # 셸이 처리 층 {ok, …} 를 펴든(틀이 펴든) 안쪽 ok 는 거절
        inner = admin["result"] if isinstance(admin.get("result"), dict) and "ok" in admin["result"] else admin
        assert inner["ok"] is False  # PIN 없는 보기 판은 admin 아님
        assert [p for p in pushes if p.get("kind") == "scan_result"]
        events = (tmp_path / "shell" / "events.jsonl").read_text(encoding="utf-8")
        assert '"admin_id"' not in events and '"pin"' not in events  # admin 인수는 기록에 없음
        state = shell.state()
        assert _schema_errors(state, CONTRACT["state"]) == [] and state["work"]["count"] == 2
    finally:
        shell.close()
