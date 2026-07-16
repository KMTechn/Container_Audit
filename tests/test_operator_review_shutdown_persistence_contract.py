import datetime
import json

import pytest

import Container_Audit as container_audit_module
from Container_Audit import ContainerAudit, TraySession
from transfer_seal import SealAttempt
from tray_state import (
    OPERATOR_REVIEW_STATE_KEY,
    TrayStateValidationError,
    validate_tray_state,
)
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    WarningPresenter,
)


ITEM_CODE = "AAA2270730100"
MASTER_LABEL = f"PHS=1|CLC={ITEM_CODE}|QT=1"
PRODUCT_BARCODE = f"{ITEM_CODE}-001"
PARTIAL_MASTER_LABEL = f"PHS=1|CLC={ITEM_CODE}|QT=3"


class HeadlessRoot:
    def after_cancel(self, _job):
        return None


def _review_tray(
    *,
    master_label=MASTER_LABEL,
    tray_size=1,
    is_partial_submission=False,
):
    scan_time = datetime.datetime.now() - datetime.timedelta(seconds=5)
    return TraySession(
        master_label_code=master_label,
        item_code=ITEM_CODE,
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=[PRODUCT_BARCODE],
        scan_times=[scan_time],
        tray_size=tray_size,
        stopwatch_seconds=30.0,
        start_time=scan_time - datetime.timedelta(seconds=30),
        has_error_or_reset=True,
        is_partial_submission=is_partial_submission,
    )


def _operator_review_snapshot(*, master_label=MASTER_LABEL, target_count=1):
    return CompletionOutcomeSnapshot(
        outcome=CompletionOutcome.OPERATOR_REVIEW,
        item_name="fixture item",
        master_label=master_label,
        scan_count=1,
        target_count=target_count,
        message="서버 판정에 담당자 확인이 필요합니다.",
        error_code="MEMBERSHIP_CONFLICT",
    )


def _save_review_state(tmp_path, *, worker_name="review-worker", tray=None):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = worker_name
    app.current_tray = tray or _review_tray()
    app.warning_presenter = WarningPresenter()
    app.warning_presenter.present_completion(
        _operator_review_snapshot(
            master_label=app.current_tray.master_label_code,
            target_count=app.current_tray.tray_size,
        )
    )
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    assert app._operator_review_blocks_mutation() is True
    assert app._save_current_tray_state() is True
    return app


def _restore_app(tmp_path, *, worker_name):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = worker_name
    app.current_tray = TraySession()
    app.warning_presenter = WarningPresenter()
    app._pending_operator_review_snapshot = None
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app._is_completed_master_label = lambda _label: False
    app._invalidate_pending_scan_callbacks = lambda: None
    app._start_warning_beep = lambda: None
    app.show_status_message = lambda *_args, **_kwargs: None
    return app


def _load_saved_json(tmp_path):
    return json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))


def _unexpected_action(name):
    def fail(*_args, **_kwargs):
        raise AssertionError(f"{name} must not be reached for OPERATOR_REVIEW state")

    return fail


def test_operator_review_guard_survives_close_state_save_and_same_worker_restore(
    monkeypatch,
    tmp_path,
):
    closing_app = _save_review_state(tmp_path)
    restored_app = _restore_app(tmp_path, worker_name=closing_app.worker_name)
    logged = []
    warnings = []
    restored_app._log_event = (
        lambda event, detail=None, synchronous=False, **_kwargs:
        logged.append((event, detail, synchronous)) or True
    )
    restored_app._delete_current_tray_state = _unexpected_action("state delete")
    restored_app._log_saved_tray_discarded = _unexpected_action("decline/discard ledger")
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        _unexpected_action("same-worker restore prompt"),
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showwarning",
        lambda *args, **_kwargs: warnings.append(args),
    )

    restored_app._load_current_tray_state()

    assert restored_app.current_tray.master_label_code == MASTER_LABEL
    assert restored_app.current_tray.scanned_barcodes == [PRODUCT_BARCODE]
    assert restored_app._operator_review_blocks_mutation() is True
    assert logged[0][0] == "TRAY_RESTORE"
    assert logged[0][1]["operator_review_restored"] is True
    assert logged[0][2] is True
    assert warnings and warnings[-1][0] == "담당자 확인 필요"
    assert (tmp_path / "current.json").exists()


@pytest.mark.parametrize(
    "malformed_case",
    [
        "not_mapping",
        "unsupported_schema",
        "wrong_outcome",
        "missing_message",
        "boolean_scan_count",
        "scan_count_mismatch",
        "target_count_mismatch",
        "master_label_mismatch",
        "item_name_mismatch",
        "blank_message",
    ],
)
def test_malformed_optional_operator_review_metadata_is_rejected(
    malformed_case,
    tmp_path,
):
    _save_review_state(tmp_path)
    state = _load_saved_json(tmp_path)
    payload = state[OPERATOR_REVIEW_STATE_KEY]

    if malformed_case == "not_mapping":
        state[OPERATOR_REVIEW_STATE_KEY] = "OPERATOR_REVIEW"
    elif malformed_case == "unsupported_schema":
        payload["schema_version"] = 999
    elif malformed_case == "wrong_outcome":
        payload["outcome"] = "ACKED"
    elif malformed_case == "missing_message":
        payload.pop("message")
    elif malformed_case == "boolean_scan_count":
        payload["scan_count"] = True
    elif malformed_case == "scan_count_mismatch":
        payload["scan_count"] = 0
    elif malformed_case == "target_count_mismatch":
        payload["target_count"] = 2
    elif malformed_case == "master_label_mismatch":
        payload["master_label"] = "PHS=1|CLC=OTHER|QT=1"
    elif malformed_case == "item_name_mismatch":
        payload["item_name"] = "different item"
    elif malformed_case == "blank_message":
        payload["message"] = "   "

    with pytest.raises(TrayStateValidationError):
        validate_tray_state(state, default_tray_size=60)


def test_repository_quarantines_malformed_operator_review_metadata(monkeypatch, tmp_path):
    _save_review_state(tmp_path)
    state = _load_saved_json(tmp_path)
    state[OPERATOR_REVIEW_STATE_KEY]["scan_count"] = 0
    state_path = tmp_path / "current.json"
    state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

    app = _restore_app(tmp_path, worker_name="review-worker")
    warnings = []
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showwarning",
        lambda *args, **_kwargs: warnings.append(args),
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        _unexpected_action("restore prompt for quarantined state"),
    )

    app._load_current_tray_state()

    assert app.current_tray.master_label_code == ""
    assert not state_path.exists()
    assert list(tmp_path.glob("current.json.bad-*"))
    assert warnings and warnings[-1][0] == "오류"


def test_other_worker_takeover_preserves_operator_review_lock(monkeypatch, tmp_path):
    _save_review_state(tmp_path, worker_name="previous-worker")
    app = _restore_app(tmp_path, worker_name="takeover-worker")
    logged = []
    app._log_event = (
        lambda event, detail=None, synchronous=False, **_kwargs:
        logged.append((event, detail, synchronous)) or True
    )
    app._delete_current_tray_state = _unexpected_action("state delete during takeover")
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        _unexpected_action("permanent delete confirmation during takeover"),
    )

    app._load_current_tray_state()

    assert app.worker_name == "takeover-worker"
    assert app.current_tray.master_label_code == MASTER_LABEL
    assert app._operator_review_blocks_mutation() is True
    persisted = _load_saved_json(tmp_path)
    validate_tray_state(persisted, default_tray_size=60)
    assert persisted["worker_name"] == "takeover-worker"
    assert persisted[OPERATOR_REVIEW_STATE_KEY]["outcome"] == "OPERATOR_REVIEW"
    assert logged == [
        (
            "TRAY_TAKEOVER",
            {
                "previous_worker": "previous-worker",
                "new_worker": "takeover-worker",
                "item_name": "fixture item",
            },
            True,
        )
    ]


def test_other_worker_takeover_audit_exception_rolls_back_review_owner(
    monkeypatch,
    tmp_path,
):
    _save_review_state(tmp_path, worker_name="previous-worker")
    before = _load_saved_json(tmp_path)
    app = _restore_app(tmp_path, worker_name="takeover-worker")
    errors = []

    def raise_audit_error(*_args, **_kwargs):
        raise RuntimeError("audit backend unavailable")

    app._log_event = raise_audit_error
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showerror",
        lambda *args, **_kwargs: errors.append(args),
    )

    app._load_current_tray_state()

    assert _load_saved_json(tmp_path) == before
    assert app.current_tray.master_label_code == ""
    assert app._operator_review_blocks_mutation() is False
    assert errors and errors[-1][0] == "작업 기록 실패"


def test_other_worker_cannot_delete_operator_review_state_when_takeover_declined(
    monkeypatch,
    tmp_path,
):
    _save_review_state(tmp_path, worker_name="previous-worker")
    before = _load_saved_json(tmp_path)
    app = _restore_app(tmp_path, worker_name="next-worker")
    warnings = []
    login_screens = []
    app._log_event = _unexpected_action("takeover ledger on declined review")
    app._log_saved_tray_discarded = _unexpected_action("discard ledger")
    app._delete_current_tray_state = _unexpected_action("operator-review state delete")
    app.show_worker_input_screen = lambda: login_screens.append(True)
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        _unexpected_action("permanent delete confirmation"),
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showwarning",
        lambda *args, **_kwargs: warnings.append(args),
    )

    app._load_current_tray_state()

    assert app.worker_name == ""
    assert app.current_tray.master_label_code == ""
    assert login_screens == [True]
    assert warnings and warnings[-1][0] == "삭제 불가"
    after = _load_saved_json(tmp_path)
    assert after == before
    validate_tray_state(after, default_tray_size=60)
    assert after[OPERATOR_REVIEW_STATE_KEY]["outcome"] == "OPERATOR_REVIEW"


def test_partial_submission_operator_review_preserves_partial_flag_in_snapshot_and_restore():
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "partial-worker"
    app.current_tray = _review_tray(
        master_label=PARTIAL_MASTER_LABEL,
        tray_size=3,
    )
    app.warning_presenter = WarningPresenter()
    app._pending_operator_review_snapshot = None
    app.root = HeadlessRoot()
    app.status_message_job = None
    app._status_message_generation = 0
    app.error_sound = None
    app._warning_beep_active = False
    app.COLOR_DANGER = "danger"
    app._prepare_and_attempt_transfer_seal = lambda **_kwargs: SealAttempt(
        intent_id="partial-review-intent",
        status="OPERATOR_REVIEW",
        error_code="MEMBERSHIP_CONFLICT",
        error_message="membership conflict",
    )
    app._log_event = _unexpected_action("completion ledger for OPERATOR_REVIEW")
    app._render_warning_state = lambda: None
    app._update_action_button_states = lambda: None
    app._start_warning_beep = lambda: None
    app._stop_warning_beep = lambda: None

    assert app._complete_current_tray_as_partial() is False

    assert app.current_tray.is_partial_submission is True
    assert app._operator_review_blocks_mutation() is True
    state = app._current_tray_state_snapshot()
    assert state["is_partial_submission"] is True
    assert state[OPERATOR_REVIEW_STATE_KEY]["scan_count"] == 1
    assert state[OPERATOR_REVIEW_STATE_KEY]["target_count"] == 3
    validate_tray_state(state, default_tray_size=60)

    restored = ContainerAudit.__new__(ContainerAudit)
    restored.current_tray = TraySession()
    restored.warning_presenter = WarningPresenter()
    restored._pending_operator_review_snapshot = None
    restored._invalidate_pending_scan_callbacks = lambda: None
    restored._start_warning_beep = lambda: None
    restored.show_status_message = lambda *_args, **_kwargs: None
    restored._restore_tray_from_state(state)

    assert restored.current_tray.is_partial_submission is True
    assert restored._operator_review_blocks_mutation() is True
