"""Post-completion transport review never owns the next scanner round."""
from types import SimpleNamespace
import threading

import pytest

from Container_Audit import TraySession
from ca_screen_bridge import _alerts
from tests.test_notice_scan_refusal import _app, _bridge
from tests.test_warning_presenter_headless_integration import _completion_app
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
