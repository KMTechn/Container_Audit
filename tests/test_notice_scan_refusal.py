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
