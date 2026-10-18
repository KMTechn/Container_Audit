"""D-01 — 막는 띠가 떠 있는 동안 들어온 스캔은 조용히 사라지지 않고 보이게 거절한다.

가벼운 시험이다: 진짜 Tk·가짜 시계 되풀이 0. 앱은 ``__new__`` 로 만들고 필요한 칸만 채운다(주기 job 은 아예 걸리지 않는다).
"""
from types import SimpleNamespace

import pytest

import Container_Audit as ca
from Container_Audit import ContainerAudit, NOTICE_SCAN_REFUSAL_TEXT
from ca_screen_bridge import CaProcessor
from event_stream_policy import CONTRACT_CANDIDATE_EVENT_TYPES, LOCAL_ONLY_EVENT_TYPES
from tests.test_observed_scanner_completion import ScannerEntry
from warning_presenter import Notice, NoticeSeverity, WarningPresenter

SCAN = "AAA2270730100|SERIAL=SERIAL-0009|TRACE=TRACE-0009"
LINE_1 = "경고를 확인하기 전에는 스캔을 받지 않습니다"
LINE_2 = "[확인]을 누르거나 Esc 키를 누르세요"


class _Label:
    def __init__(self):
        self.text = ""

    def configure(self, **kwargs):
        self.text = kwargs.get("text", self.text)


def _app(*, blocking=True):
    app = ContainerAudit.__new__(ContainerAudit)
    app.warning_presenter = WarningPresenter()
    if blocking:
        app.warning_presenter.present(Notice(
            code="scan.duplicate", title="중복 스캔", message="이미 처리된 제품입니다.",
            severity=NoticeSeverity.ERROR, blocking=True))
    app.scan_entry = ScannerEntry("")
    app.scan_entry.state = "disabled"  # 막는 띠가 입력칸을 닫은 모습
    app.notice_title_label, app.notice_message_label = _Label(), _Label()
    app.notice_frame = SimpleNamespace(configure=lambda **kw: None)
    app.COLOR_DANGER, app.COLOR_PRIMARY, app.COLOR_TEXT = "danger", "primary", "text"
    app.calls = []
    app.events = []
    app.error_sound = None
    app._update_center_display = lambda: app.calls.append("center")
    app._process_barcode_logic = lambda raw: app.calls.append(("logic", raw))
    app._log_event = lambda name, **kw: app.events.append((name, kw)) or True
    app._start_warning_beep = lambda: app.calls.append("beep")
    app._stop_warning_beep = lambda: app.calls.append("stop_beep")
    app.show_status_message = lambda *a, **kw: app.calls.append(("status", a[0]))
    app.root = SimpleNamespace(after=lambda *a, **kw: app.calls.append(("after", a[1].__name__)))
    return app


def _type_like_scanner(app, text):
    for char in text:
        app._on_scan_entry_key_during_notice(SimpleNamespace(char=char))
    app._on_scan_entry_key_during_notice(SimpleNamespace(char="\r"))  # 끝의 Enter 는 글자가 아니다


def test_text_is_the_two_fixed_lines_without_dot_join_or_blank_enter():
    assert NOTICE_SCAN_REFUSAL_TEXT == LINE_1 + "\n" + LINE_2
    assert "·" not in NOTICE_SCAN_REFUSAL_TEXT and "빈 Enter" not in NOTICE_SCAN_REFUSAL_TEXT
    assert not any(line.endswith(".") for line in NOTICE_SCAN_REFUSAL_TEXT.splitlines())


def test_scan_during_blocking_band_is_refused_visibly_and_not_processed():
    app = _app()
    _type_like_scanner(app, SCAN)
    assert app.scan_entry.value == ""  # 닫힌 칸은 글자를 받지 않는다 — 그래서 따로 모은다
    app.process_barcode()
    assert ("logic", SCAN) not in app.calls and not [c for c in app.calls if isinstance(c, tuple) and c[0] == "logic"]
    assert "beep" in app.calls
    assert app.warning_presenter.state.is_blocking  # 띠는 그대로
    assert [name for name, _ in app.events] == ["SCAN_REFUSED_DURING_NOTICE"]
    assert SCAN not in repr(app.events)  # 스캔 글자는 기록에 싣지 않는다
    # 진짜 그리기 길이 두 줄 거절 글을 띠 아래에 붙인다
    assert app.notice_message_label.text == "이미 처리된 제품입니다.\n" + NOTICE_SCAN_REFUSAL_TEXT


def test_blank_enter_still_closes_the_band():
    app = _app()
    app.process_barcode()
    assert not app.warning_presenter.state.is_blocking
    assert app.events == [] and "beep" not in app.calls


def test_escape_on_the_entry_closes_the_band():
    app = _app()
    assert app._on_scan_entry_escape_during_notice(SimpleNamespace()) == "break"
    assert not app.warning_presenter.state.is_blocking


def test_refusal_text_goes_away_with_the_band():
    app = _app()
    _type_like_scanner(app, SCAN)
    app.process_barcode()
    app._acknowledge_active_notice()
    assert app._scan_refusal_visible is False
    app._render_warning_state()
    assert NOTICE_SCAN_REFUSAL_TEXT not in app.notice_message_label.text


def test_inline_choice_keeps_its_scan_meaning():
    app = _app()
    app._inline_scan_choices = [("계속", lambda: True)]
    assert app._notice_blocks_scan() is False
    app._render_warning_state()
    assert app.scan_entry.state == "normal"  # :15242 「Scanner characters and Return belong to the entry」
    _type_like_scanner(app, SCAN)
    assert getattr(app, "_notice_scan_buffer", "") == ""


def test_refusal_event_is_local_only_never_in_the_server_csv_set():
    assert "SCAN_REFUSED_DURING_NOTICE" in LOCAL_ONLY_EVENT_TYPES
    assert "SCAN_REFUSED_DURING_NOTICE" not in CONTRACT_CANDIDATE_EVENT_TYPES


def _bridge(app):
    bridge = CaProcessor.__new__(CaProcessor)
    bridge.app, bridge._scan_answer, bridge._answer, bridge.view = app, None, None, None
    bridge._enter = lambda raw: app.calls.append(("enter", raw))
    return bridge


def test_new_screen_bridge_answers_accepted_false_with_the_refusal_text():
    app = _app()
    reply = _bridge(app).scan(SCAN, {})
    assert reply["accepted"] is False and reply["message"] == NOTICE_SCAN_REFUSAL_TEXT
    assert reply["result"] == {"kind": "bad", "text": NOTICE_SCAN_REFUSAL_TEXT}
    assert ("enter", SCAN) not in app.calls and "beep" in app.calls
    assert app.warning_presenter.state.is_blocking
    assert [name for name, _ in app.events] == ["SCAN_REFUSED_DURING_NOTICE"]


def test_new_screen_bridge_without_a_band_still_takes_the_scan():
    app = _app(blocking=False)
    reply = _bridge(app).scan(SCAN, {})
    assert reply["accepted"] is True and ("enter", SCAN) in app.calls and app.events == []


def test_new_screen_band_shows_the_refusal_lines():
    from ca_screen_bridge import _alerts
    app = _app()
    app._refuse_scan_during_notice()
    band = _alerts(app, app.warning_presenter.state, [], None)[0]
    assert LINE_1 in band["text"] and band["tail"] == LINE_2


def test_selecting_a_worker_goes_through_one_door():
    app = _app(blocking=False)
    started = []
    app._start_selected_worker = lambda label: started.append(label) or "started"
    app._set_worker_entry_value = lambda value: app.calls.append(("set", value))
    app.worker_entry = SimpleNamespace(get=lambda: "홍길동")
    assert app.start_work() == "started"  # 콤보·Enter
    assert app._select_worker("김철수", source="grid") == "started"  # 격자 단추
    assert started == ["홍길동", "김철수"] and ("set", "김철수") in app.calls
    with pytest.raises(ValueError):
        app._select_worker("김철수", source="unknown")


def test_empty_selection_starts_nothing_and_says_so():
    app = _app(blocking=False)
    app._start_selected_worker = lambda label: pytest.fail("빈 값은 시작하지 않는다")
    app.worker_entry = SimpleNamespace(get=lambda: "")
    assert app.start_work() is None
    assert ("status", "작업자를 고르세요") in app.calls


def _type_on_button(app, text):
    for char in text:
        app._on_notice_button_key(SimpleNamespace(char=char))


@pytest.mark.parametrize("review", [False, True], ids=["ordinary", "operator-review"])
def test_button_focus_scan_then_enter_is_refused_and_button_not_pressed(review):
    app = _app()
    app._ui_lane_fault_blocked = review  # 담당자 확인 중과 같은 규칙
    assert app._operator_review_blocks_mutation() is review
    _type_on_button(app, SCAN)
    assert app._on_notice_button_return(SimpleNamespace(char="\r")) == "break"
    assert app.warning_presenter.state.is_blocking  # 단추 안 눌림 — 띠 그대로
    assert "beep" in app.calls and "stop_beep" not in app.calls
    assert getattr(app, "_notice_scan_buffer", "") == ""
    if review:  # 담당자 확인 중은 기존 거절 길(오류 문구)로 간다
        assert app.events == [] and "처리 오류를 확인해야" in app.notice_message_label.text
    else:
        assert [name for name, _ in app.events] == ["SCAN_REFUSED_DURING_NOTICE"]
        assert app.notice_message_label.text.endswith(NOTICE_SCAN_REFUSAL_TEXT)


@pytest.mark.parametrize("review", [False, True], ids=["ordinary", "operator-review"])
def test_button_focus_blank_enter_keeps_todays_meaning(review):
    app = _app()
    app._ui_lane_fault_blocked = review
    assert app._on_notice_button_return(SimpleNamespace(char="\r")) is None
    assert not app.warning_presenter.state.is_blocking
    assert app.events == []


def test_button_focus_keys_are_ignored_without_a_band():
    app = _app(blocking=False)
    _type_on_button(app, SCAN)
    assert getattr(app, "_notice_scan_buffer", "") == ""


# --- P2-1 담당자 확인·사전 검토 재시도 중, P3 붙여넣기·1 초·KP_Enter ---------------------------------

class _Clock:
    def __init__(self):
        self.t = 100.0


def _review_app():
    app = _app()
    app._ui_lane_fault_blocked = True  # 담당자 확인 중
    app.clock = _Clock()
    app._notice_now = lambda: app.clock.t
    assert app._operator_review_blocks_mutation() and not app._notice_blocks_scan()
    return app


def _admission_refusals(app):
    return [c[1] for c in app.calls if isinstance(c, tuple) and c[0] == "status"]


def test_operator_review_entry_scan_is_refused_by_the_existing_path_with_sound():
    app = _review_app()
    _type_like_scanner(app, SCAN)
    app.process_barcode()
    assert not [c for c in app.calls if isinstance(c, tuple) and c[0] == "logic"]
    assert "beep" in app.calls and app.warning_presenter.state.is_blocking
    assert _admission_refusals(app) and "처리 오류를 확인해야" in _admission_refusals(app)[-1]
    assert getattr(app, "_notice_scan_buffer", "") == ""


def test_operator_review_button_focus_scan_is_refused_not_acknowledged():
    app = _review_app()
    _type_on_button(app, SCAN)
    assert app._on_notice_button_return(SimpleNamespace(char="\r")) == "break"
    assert "beep" in app.calls and app.warning_presenter.state.is_blocking
    assert not [c for c in app.calls if isinstance(c, tuple) and c[0] == "logic"]


def test_operator_review_bridge_answers_accepted_false():
    app = _review_app()
    app._notice_scan_put = ContainerAudit._notice_scan_put.__get__(app)
    reply = _bridge(app).scan(SCAN, {})
    assert reply["accepted"] is False and "처리 오류를 확인해야" in reply["message"]
    assert ("enter", SCAN) not in app.calls and "beep" in app.calls
    assert app.warning_presenter.state.is_blocking


def test_paste_during_band_is_collected_and_refused_on_enter():
    app = _app()
    app.root = SimpleNamespace(clipboard_get=lambda: SCAN + "\n", after=lambda *a, **k: None)
    assert app._on_scan_entry_paste_during_notice(SimpleNamespace()) == "break"
    assert app.scan_entry.value == ""
    app.process_barcode()
    assert [n for n, _ in app.events] == ["SCAN_REFUSED_DURING_NOTICE"]


def test_buffer_is_dropped_after_one_second_so_a_blank_enter_confirms():
    app = _app()
    app.clock = _Clock()
    app._notice_now = lambda: app.clock.t
    app._on_scan_entry_key_during_notice(SimpleNamespace(char="x"))
    app.clock.t += 1.5
    app.process_barcode()
    assert app.events == [] and not app.warning_presenter.state.is_blocking  # 빈 Enter = 확인


def test_buffer_is_cleared_when_the_band_closes():
    app = _app()
    app._on_scan_entry_key_during_notice(SimpleNamespace(char="x"))
    app.warning_presenter.acknowledge()
    app._render_warning_state()
    assert app._notice_scan_buffer == ""


def test_keypad_enter_is_bound_like_return():
    import inspect
    src = inspect.getsource(ContainerAudit)
    assert src.count("bind('<Return>', self.process_barcode)") == src.count("bind('<KP_Enter>', self.process_barcode)") >= 2


# --- 2차 손질: N-1 다시 닫기, N-2 다리 accepted 는 실제 결과 ---------------------------------

def test_insert_failure_while_injecting_still_closes_the_entry_again():
    app = _review_app()
    app._notice_scan_buffer = SCAN
    app.scan_entry.insert = lambda *a: (_ for _ in ()).throw(ca.tk.TclError("boom"))
    app._render_warning_state = lambda: setattr(app.scan_entry, "state", "disabled")
    app.process_barcode()
    assert app.scan_entry.state == "disabled"  # 칸이 다시 닫혔다
    assert app._notice_scan_injected is False


def test_bridge_answers_accepted_false_when_a_scan_callback_is_pending():
    app = _review_app()
    app._notice_scan_put = ContainerAudit._notice_scan_put.__get__(app)
    app._scan_callback_pending = True
    reply = _bridge(app).scan(SCAN, {})
    assert reply["accepted"] is False and "처리 오류를 확인해야" in reply["message"]
    assert "beep" not in app.calls  # 상태 글만 쓰는 길 — 그래도 다리는 미접수
    assert not [c for c in app.calls if isinstance(c, tuple) and c[0] == "logic"]


def test_bridge_answers_accepted_false_when_old_characters_stay_in_the_entry():
    app = _review_app()
    app._notice_scan_put = ContainerAudit._notice_scan_put.__get__(app)
    app._notice_scan_buffer = ""
    app.scan_entry.state = "normal"
    app.scan_entry.value = "OLD"
    reply = _bridge(app).scan(SCAN, {})
    assert reply["accepted"] is False and "이전 글자가 남아" in reply["message"]


# --- 3차 손질: P3-A 칸 비우기, P3-B 주입 실패는 미접수, P3-C 안 보이는 거절도 미접수 -----------

def _bound(app, *names):
    for name in names:
        setattr(app, name, getattr(ContainerAudit, name).__get__(app))


def test_pending_branch_clears_injected_characters_but_keeps_plain_input():
    app = _review_app()
    _bound(app, "_mark_scan_unaccepted", "_clear_consumed_scan_entry", "_hold_or_refuse_entry_scan")
    app._set_scan_callback_pending = lambda pending: setattr(app, "_scan_callback_pending", pending)
    app._scan_callback_pending = True
    app.scan_entry.state, app.scan_entry.value = "normal", SCAN
    app._notice_scan_injected = True
    app._hold_or_refuse_entry_scan(SCAN, "처리 오류를 확인해야")
    assert app.scan_entry.value == ""
    app.scan_entry.value, app._notice_scan_injected = SCAN, False
    app._hold_or_refuse_entry_scan(SCAN, "처리 오류를 확인해야")
    assert app.scan_entry.value == SCAN  # 평상시 갈래: 입력값 유지


def test_insert_failure_while_injecting_is_unaccepted_not_a_blank_enter():
    app = _review_app()
    _bound(app, "_mark_scan_unaccepted")
    app._notice_scan_buffer = SCAN
    app._notice_scan_stamp = app.clock.t
    app.scan_entry.insert = lambda *a: (_ for _ in ()).throw(ca.tk.TclError("boom"))
    app._render_warning_state = lambda: None
    app.process_barcode()
    assert app._last_scan_unaccepted_text == "스캔을 받지 못했습니다. 다시 스캔하세요"
    assert "beep" in app.calls and app.warning_presenter.state.is_blocking  # 띠 그대로


def test_invisible_refusal_on_the_collected_path_is_marked_unaccepted():
    app = _app(blocking=False)
    _bound(app, "_mark_scan_unaccepted")
    app._notice_scan_injected = True
    app._refuse_entry_scan("받지 않았습니다. 다시 스캔하세요.")
    assert app._last_scan_unaccepted_text == "받지 않았습니다. 다시 스캔하세요."
