"""Post-completion transport review never owns the next scanner round."""
from types import SimpleNamespace
import threading

import pytest

import Container_Audit as ca
from Container_Audit import TraySession
from ca_screen_bridge import _alerts
from tests.test_notice_scan_refusal import _app, _bridge
from tests.test_warning_presenter_headless_integration import SECOND_BARCODE, _completion_app, _scan_app
from transfer_common import TransferSealError
from transfer_seal import SealAttempt, TransferSealStore
from warning_presenter import Notice, NoticeSeverity


SCANS = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=NEXT|CLC=AAA2270730100|LBL=NEXT|HSH=NEXT|QT=3",
    "AAA2270730100|SERIAL=NEXT-1|TRACE=NEXT-1",
)


def _scanner_app():
    app = _app(blocking=False)
    app.current_tray = TraySession()
    app._update_action_button_states = lambda: None
    app._schedule_focus_return = lambda: None
    app._schedule_notice_message_wrap_refresh = lambda **_kwargs: None
    app._preflight_context_blocks_mutation = lambda: False
    app.root = SimpleNamespace(after=lambda _delay, callback, *args: callback(*args))
    return app


def _assert_next_scans_allowed(app):
    assert app.warning_presenter.state.active_notice.blocking is False
    assert app._notice_blocks_scan() is False
    assert app._scan_entry_admission_block_reason() == ""
    bridge = _bridge(app)
    for raw in SCANS:
        assert bridge.scan(raw, {})["accepted"] is True
        assert ("enter", raw) in app.calls
        app.scan_entry.value = raw
        app.process_barcode()
        assert ("logic", raw) in app.calls
    assert not app.events


@pytest.mark.parametrize("error_code,status_code", [
    ("VERSION_CONFLICT", 409),
    ("LOGISTICS_REDIRECT_BLOCKED", 302),
])
@pytest.mark.parametrize("restarted", [False, True])
def test_durable_review_snapshot_allows_next_label_and_product(
    tmp_path, error_code, status_code, restarted,
):
    path = tmp_path / "review.db"
    owner_thread_id = threading.get_ident()
    owner = lambda: owner_thread_id
    store = TransferSealStore(path, owner_thread_id_provider=owner)
    prepared = store.prepare(
        master_label="COMPLETED", source_identity={"source_bundle_id": "SOURCE"},
        item_id="AAA2270730100", operator="tester", scanned_barcodes=["PRODUCT-1"],
        relay_log_file_path=str(tmp_path / "events.csv"),
    )
    terminal = store.record_error(prepared["intent_id"], TransferSealError(
        error_code, "company confirmation requires review", status_code=status_code,
    ))
    assert terminal["local_completion_id"] == prepared["local_completion_id"]
    assert terminal["status"] == "OPERATOR_REVIEW"
    if restarted:
        store = TransferSealStore(path, owner_thread_id_provider=owner)
    cases = tuple(dict(row) for row in store.post_review_cases(active_only=True))
    app = _scanner_app()

    assert app._finish_transfer_post_review_refresh({"cases": cases}) is True

    _assert_next_scans_allowed(app)
    assert app._transfer_post_review_cases == cases
    assert tuple(dict(row) for row in store.post_review_cases(active_only=True)) == cases
    band, = _alerts(app, app.warning_presenter.state, [], None)
    assert band["kind"] == "warn"
    assert "관리자" in band["text"]
    assert band["choices"][0]["go"] == "command:ack"
    app._acknowledge_active_notice()
    assert app.warning_presenter.state.active_notice is None
    assert _alerts(app, app.warning_presenter.state, [], None) == []
    assert app._transfer_post_review_cases == cases


def test_terminal_review_after_local_completion_allows_next_scans(tmp_path):
    events = []
    app = _completion_app(save_root=tmp_path, seal_status="OPERATOR_REVIEW",
                          ledger_succeeds=True, events=events)
    app._prepare_and_attempt_transfer_seal = lambda **_kwargs: SealAttempt(
        intent_id="review-linked", status="OPERATOR_REVIEW",
        command_id="container-seal:review-linked", local_completion_id="local-1",
        error_code="VERSION_CONFLICT",
    )
    assert app.complete_tray() is True
    assert app.current_tray.master_label_code == ""
    assert app.warning_presenter.state.is_blocking is False
    scanner = _scanner_app()
    scanner.warning_presenter = app.warning_presenter
    scanner._render_warning_state()
    _assert_next_scans_allowed(scanner)


def test_restart_projection_retry_guidance_also_allows_next_scans():
    app = _scanner_app()
    assert app._finish_transfer_post_review_refresh({
        "cases": (), "refresh_requested": True, "replay_failed": True,
    }) is True
    assert app._post_review_refresh_required is True
    _assert_next_scans_allowed(app)


def test_post_review_keeps_tk_acknowledgement_available_without_closing_entry():
    app = _scanner_app()
    button = SimpleNamespace(
        visible=False, options={},
        grid=lambda: setattr(button, "visible", True),
        grid_remove=lambda: setattr(button, "visible", False),
        configure=lambda **kw: button.options.update(kw),
    )
    app.notice_ack_button = button
    assert app._present_transfer_post_review_required_notice("review-1") is True
    assert button.visible is True
    assert button.options["state"] == "normal"
    assert app.scan_entry.state == "normal"


@pytest.mark.parametrize("key", ["enter", "escape"])
def test_post_review_keeps_existing_empty_enter_and_escape_acknowledgement(key):
    app = _scanner_app()
    assert app._present_transfer_post_review_required_notice("review-1") is True
    if key == "enter":
        app.process_barcode()
    else:
        assert app._on_scan_entry_escape_during_notice() == "break"
    assert app.warning_presenter.state.active_notice is None
    assert app.warning_presenter.state.is_blocking is False


@pytest.mark.parametrize("guard", ["operation_lease", "preflight", "storage", "exchange"])
def test_post_review_does_not_release_existing_business_guard(guard):
    app = _scanner_app()
    if guard == "operation_lease":
        app.current_tray.operation_lease_hold = {"error_code": "OPERATION_RESOURCE_ALREADY_LEASED"}
        blocked = app._operation_lease_hold_blocks_scan
    elif guard == "preflight":
        del app._preflight_context_blocks_mutation
        app._paired_stale_current_blocked = True
        blocked = app._preflight_context_blocks_mutation
    elif guard == "storage":
        app._storage_failure_blocked = True
        blocked = app._scan_entry_admission_block_reason
    else:
        app._current_transfer_member_exchange_attempt = lambda: SimpleNamespace(
            status="OPERATOR_REVIEW", local_apply_status="PENDING")
        app._show_field_notice = lambda *_args, **_kwargs: None
        blocked = lambda: app._transfer_member_exchange_blocks_local_action("이적 봉인 및 완료")
    assert blocked()
    assert app._present_transfer_post_review_required_notice("past-review") is True
    assert app.warning_presenter.state.active_notice.code == "transfer.post_review_required"
    assert blocked()
    app._acknowledge_active_notice()
    assert blocked()


@pytest.mark.parametrize("ledger_succeeds", [False, True], ids=["ledger-refused", "unbound-completion"])
def test_post_review_cannot_replace_or_acknowledge_unfinished_completion(tmp_path, ledger_succeeds):
    app = _completion_app(
        save_root=tmp_path, seal_status="OPERATOR_REVIEW" if ledger_succeeds else "ACKED",
        ledger_succeeds=ledger_succeeds, events=[],
    )
    original = app.current_tray
    assert app.complete_tray() is False
    blocked_state = app.warning_presenter.state
    assert blocked_state.is_blocking is True
    assert app._present_transfer_post_review_required_notice("past-review") is False
    assert app.warning_presenter.state == blocked_state
    app._acknowledge_active_notice()
    assert app.warning_presenter.state.is_blocking is True
    assert app.current_tray is original


def test_post_review_does_not_replace_an_intentional_blocking_notice():
    app = _scanner_app()
    notice = Notice(code="local.checkpoint", title="저장 확인", message="현재 작업을 보존합니다.",
                    severity=NoticeSeverity.ERROR, blocking=True)
    app.warning_presenter.present(notice)
    assert app._present_transfer_post_review_required_notice("past-review") is False
    assert app.warning_presenter.state.active_notice is notice
    assert app._notice_blocks_scan() is True
    assert _bridge(app).scan(SCANS[1], {})["accepted"] is False


def _use_real_notice_methods(app, monkeypatch):
    for name in ("show_status_message", "_render_warning_state",
                 "_start_warning_beep", "_stop_warning_beep"):
        app.__dict__.pop(name, None)
    app.COLOR_TEXT = "text"
    for name in ("_update_center_display", "_schedule_focus_return",
                 "_update_action_button_states"):
        app.__dict__.setdefault(name, lambda: None)
    app.error_sound = object()
    app.audio = []
    monkeypatch.setattr(ca, "play_sound", lambda _sound, loops=0: app.audio.append(("play", loops)) or True)
    monkeypatch.setattr(ca, "stop_sound", lambda _sound: app.audio.append(("stop",)))
    monkeypatch.setattr("tray_completion.play_sound", lambda _sound: True)
    button = SimpleNamespace(
        visible=False, options={},
        grid=lambda: setattr(button, "visible", True),
        grid_remove=lambda: setattr(button, "visible", False),
        configure=lambda **kw: button.options.update(kw),
    )
    app.notice_ack_button = button
    return app


@pytest.mark.parametrize("key", ["enter", "escape"])
@pytest.mark.parametrize("projection_saved", [True, False])
def test_partial_review_survives_real_status_and_keeps_acknowledgement(
    tmp_path, monkeypatch, key, projection_saved,
):
    app = _completion_app(save_root=tmp_path, seal_status="OPERATOR_REVIEW",
                          ledger_succeeds=True, events=[])
    _use_real_notice_methods(app, monkeypatch)
    app.current_tray.scanned_barcodes.pop()
    app.current_tray.scan_times.pop()
    app.current_tray.is_partial_submission = True
    app._settle_short_completion_projection = lambda _key: projection_saved
    app._prepare_and_attempt_transfer_seal = lambda **_kwargs: SealAttempt(
        intent_id="partial-review", status="OPERATOR_REVIEW",
        command_id="container-seal:partial-review", local_completion_id="local-1",
        error_code="VERSION_CONFLICT",
    )

    assert app.complete_tray() is True
    assert app.warning_presenter.state.active_notice.code == "transfer.post_review_required"
    assert app.notice_ack_button.visible is True
    assert app.notice_ack_button.options["state"] == "normal"
    assert app._warning_beep_active is True
    assert ("play", -1) in app.audio
    app.scan_entry = _scanner_app().scan_entry
    app.scan_entry.value = ""
    if key == "enter":
        app.process_barcode()
    else:
        assert app._on_scan_entry_escape_during_notice() == "break"
    assert app.warning_presenter.state.active_notice is None
    assert app._warning_beep_active is False
    assert app.audio[-1] == ("stop",)


def test_review_survives_other_status_and_an_already_scheduled_expiry(monkeypatch):
    app = _use_real_notice_methods(_scanner_app(), monkeypatch)
    scheduled = []
    app.root = SimpleNamespace(
        after=lambda delay, callback, *args: scheduled.append((callback, args)) or "timer",
        after_cancel=lambda _job: None,
    )
    app.show_status_message("이전 상태")
    expire, args = scheduled.pop()
    app._present_transfer_post_review_required_notice("review-1")
    expire(*args)
    assert app.warning_presenter.state.active_notice.code == "transfer.post_review_required"
    app.show_status_message("다른 작업 상태", duration=0)
    assert app.warning_presenter.state.active_notice.code == "transfer.post_review_required"
    app._reset_status_message()
    assert app.warning_presenter.state.active_notice.code == "transfer.post_review_required"
    assert app._warning_beep_active is True


@pytest.mark.parametrize("replacement", ["clear", "notice", "completion"])
def test_review_repeating_sound_stops_when_band_leaves(monkeypatch, replacement):
    app = _use_real_notice_methods(_scanner_app(), monkeypatch)
    app._present_transfer_post_review_required_notice("review-1")
    assert app._warning_beep_active is True
    app._start_warning_beep()  # A refusal can retrigger sound while this same band remains.
    if replacement == "clear":
        app.warning_presenter.clear()
    elif replacement == "notice":
        app.warning_presenter.present(Notice(
            code="scan.hint", title="안내", message="다음 작업", blocking=False,
            severity=NoticeSeverity.INFO))
    else:
        from warning_presenter import CompletionOutcome, CompletionOutcomeSnapshot
        app.warning_presenter.present_completion(CompletionOutcomeSnapshot(CompletionOutcome.ACKED))
    app._render_warning_state()
    assert app._warning_beep_active is False
    assert app.audio[-1] == ("stop",)


@pytest.mark.parametrize("key", ["enter", "escape", "web"])
def test_processing_fault_keeps_review_notice_for_all_ack_keys(key):
    app = _scanner_app()
    app._present_transfer_post_review_required_notice("review-1")
    app._ui_lane_fault_blocked = True
    notice = app.warning_presenter.state.active_notice
    if key == "enter":
        app.process_barcode()
    elif key == "escape":
        app._on_scan_entry_escape_during_notice()
    else:
        _bridge(app)._cmd_ack(None, {})
    assert app.warning_presenter.state.active_notice is notice
    assert app._scan_entry_admission_block_reason()


def test_next_product_scan_clears_review_and_stops_repeating_sound(tmp_path, monkeypatch):
    app = _use_real_notice_methods(
        _scan_app(save_succeeds=True, events=[], save_root=tmp_path), monkeypatch)
    app.notice_frame = None
    app._present_transfer_post_review_required_notice("review-1")
    app._process_barcode_logic(SECOND_BARCODE)
    assert app.warning_presenter.state.active_notice is None
    assert app.warning_presenter.state.last_normal_scan == SECOND_BARCODE
    assert app.current_tray.scanned_barcodes[-1] == SECOND_BARCODE
    assert app._warning_beep_active is False
    assert app.audio[-1] == ("stop",)


def test_new_blocking_warning_keeps_its_own_repeating_sound(monkeypatch):
    app = _use_real_notice_methods(_scanner_app(), monkeypatch)
    app._present_transfer_post_review_required_notice("review-1")
    app.show_fullscreen_warning("중복 스캔", "다시 확인하세요.", app.COLOR_DANGER)
    assert app.warning_presenter.state.active_notice.blocking is True
    assert app._warning_beep_active is True
    assert app.audio[-1] == ("play", -1)
    app._acknowledge_active_notice()
    assert app._warning_beep_active is False
