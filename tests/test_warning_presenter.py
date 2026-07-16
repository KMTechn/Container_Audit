from dataclasses import FrozenInstanceError

import pytest

from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    Notice,
    NoticeSeverity,
    WarningPresenter,
    WarningViewState,
    notice_for_completion,
)


OPERATOR_REVIEW_CORE = (
    "서버 판정 미완료 · 완료 처리 중지 · 트레이·목록 유지 · 담당자 확인"
)


def _notice(*, code="scan.duplicate", blocking=False):
    return Notice(
        code=code,
        title="중복 스캔",
        message="이미 스캔된 제품입니다.",
        severity=NoticeSeverity.ERROR,
        blocking=blocking,
    )


def _completion(outcome, **overrides):
    values = {
        "outcome": outcome,
        "item_name": "fixture item",
        "master_label": "PHS=1|CLC=AAA2270730100|QT=3",
        "scan_count": 3,
        "target_count": 3,
    }
    values.update(overrides)
    return CompletionOutcomeSnapshot(**values)


def test_notice_and_view_state_are_immutable():
    notice = _notice()
    state = WarningViewState(active_notice=notice, last_normal_scan="AAA2270730100-001")

    with pytest.raises(FrozenInstanceError):
        notice.message = "changed"
    with pytest.raises(FrozenInstanceError):
        state.active_notice = None


def test_presenter_deduplicates_an_identical_active_notice():
    presenter = WarningPresenter()
    notice = _notice()

    assert presenter.present(notice) is True
    first_state = presenter.state
    assert presenter.present(notice) is False

    assert presenter.state is first_state
    assert presenter.state.active_notice is notice


def test_presenter_keeps_exactly_one_active_notice_location():
    presenter = WarningPresenter()
    first = _notice()
    second = Notice(
        code="scan.mismatch",
        title="품목 불일치",
        message="다른 품목입니다.",
        severity=NoticeSeverity.ERROR,
    )

    assert presenter.present(first) is True
    assert presenter.present(second) is True

    assert presenter.state.active_notice == second
    assert not hasattr(presenter.state, "secondary_notice")


def test_blocking_notice_survives_clear_and_rejects_unrelated_replacement_until_acknowledged():
    presenter = WarningPresenter()
    blocking = _notice(code="completion.operator_review", blocking=True)

    assert presenter.present(blocking) is True
    assert presenter.clear() is False
    assert presenter.present(_notice(code="scan.mismatch")) is False
    assert presenter.state.active_notice == blocking
    assert presenter.state.is_blocking is True

    assert presenter.acknowledge() is True
    assert presenter.state.active_notice is None


def test_clear_removes_only_non_blocking_notice_and_ack_is_idempotent():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-001")
    presenter.present(_notice())

    assert presenter.clear() is True
    assert presenter.clear() is False
    assert presenter.acknowledge() is False
    assert presenter.state.last_normal_scan == "AAA2270730100-001"


def test_error_and_clear_do_not_erase_last_normal_scan():
    presenter = WarningPresenter()

    assert presenter.record_normal_scan("AAA2270730100-001") is True
    assert presenter.present(_notice()) is True
    assert presenter.state.last_normal_scan == "AAA2270730100-001"
    assert presenter.acknowledge() is True
    assert presenter.state.last_normal_scan == "AAA2270730100-001"
    assert presenter.record_normal_scan("   ") is False
    assert presenter.state.last_normal_scan == "AAA2270730100-001"

    assert presenter.clear_last_normal_scan() is True
    assert presenter.state.last_normal_scan is None


@pytest.mark.parametrize(
    ("outcome", "severity", "blocking", "confirmed"),
    [
        (CompletionOutcome.ACKED, NoticeSeverity.SUCCESS, False, True),
        (CompletionOutcome.RETRY_WAIT, NoticeSeverity.WARNING, False, False),
        (CompletionOutcome.OPERATOR_REVIEW, NoticeSeverity.ERROR, True, False),
    ],
)
def test_completion_outcomes_have_distinct_non_misleading_presentation(outcome, severity, blocking, confirmed):
    snapshot = _completion(outcome)
    notice = notice_for_completion(snapshot)

    assert notice.severity is severity
    assert notice.blocking is blocking
    assert snapshot.blocks_completion is blocking
    assert snapshot.server_confirmed is confirmed
    if outcome is CompletionOutcome.RETRY_WAIT:
        assert "아직 완료되지 않았습니다" in notice.message
    if outcome is CompletionOutcome.OPERATOR_REVIEW:
        assert notice.message == OPERATOR_REVIEW_CORE
        assert "\n" not in notice.message


@pytest.mark.parametrize(
    "equivalent_detail",
    [
        OPERATOR_REVIEW_CORE,
        f"  {OPERATOR_REVIEW_CORE}  ",
        "서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다.",
        "서버 판정을 완료할 수 없습니다. 현재 트레이와 중앙 스캔 목록을 유지합니다.",
        "완료 처리를 진행하지 말고 담당자 확인을 받으세요.",
    ],
)
def test_operator_review_does_not_repeat_default_equivalent_detail(equivalent_detail):
    notice = notice_for_completion(
        _completion(CompletionOutcome.OPERATOR_REVIEW, message=equivalent_detail)
    )

    assert notice.message == OPERATOR_REVIEW_CORE
    assert notice.message.count("서버 판정 미완료") == 1


def test_operator_review_removes_default_prefix_but_preserves_diagnostic_detail():
    detail = (
        "서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다.\n"
        "상세: MEMBERSHIP_CONFLICT · authoritative membership hash mismatch"
    )

    notice = notice_for_completion(
        _completion(CompletionOutcome.OPERATOR_REVIEW, message=detail)
    )

    assert notice.message == (
        f"{OPERATOR_REVIEW_CORE}\n"
        "상세: MEMBERSHIP_CONFLICT · authoritative membership hash mismatch"
    )
    assert "현재 트레이와 스캔 목록을 유지합니다" not in notice.message


def test_operator_review_preserves_arbitrary_diagnostic_detail_verbatim():
    detail = "MEMBERSHIP_CONFLICT: server bundle version=17"

    notice = notice_for_completion(
        _completion(CompletionOutcome.OPERATOR_REVIEW, message=detail)
    )

    assert notice.message == f"{OPERATOR_REVIEW_CORE}\n{detail}"


def test_operator_review_remains_blocking_after_notice_acknowledgement():
    presenter = WarningPresenter()
    snapshot = _completion(
        CompletionOutcome.OPERATOR_REVIEW,
        message="membership 충돌을 확인하세요.",
        error_code="MEMBERSHIP_CONFLICT",
    )

    assert presenter.present_completion(snapshot) is True
    assert presenter.state.completion == snapshot
    assert presenter.state.active_notice.blocking is True
    assert presenter.state.is_blocking is True
    assert presenter.clear_completion() is False

    assert presenter.acknowledge() is True
    assert presenter.state.active_notice is None
    assert presenter.state.completion == snapshot
    assert presenter.state.is_blocking is True
    assert presenter.clear_completion() is False
    assert presenter.present(_notice(code="scan.mismatch")) is False
    assert presenter.state.active_notice is None


def test_new_business_completion_result_can_resolve_operator_review_block():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-003")
    presenter.present_completion(_completion(CompletionOutcome.OPERATOR_REVIEW))

    acked = _completion(CompletionOutcome.ACKED, receipt_id="receipt-1")
    assert presenter.present_completion(acked) is True

    assert presenter.state.completion == acked
    assert presenter.state.active_notice.severity is NoticeSeverity.SUCCESS
    assert presenter.state.is_blocking is False
    assert presenter.state.last_normal_scan == "AAA2270730100-003"


def test_identical_completion_snapshot_and_notice_are_deduplicated():
    presenter = WarningPresenter()
    snapshot = _completion(CompletionOutcome.RETRY_WAIT)

    assert presenter.present_completion(snapshot) is True
    first_state = presenter.state
    assert presenter.present_completion(snapshot) is False

    assert presenter.state is first_state


def test_clear_completion_does_not_clear_an_unrelated_notice_or_last_normal_scan():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-003")
    presenter.present_completion(_completion(CompletionOutcome.ACKED))
    unrelated = _notice(code="settings.info")
    presenter.present(unrelated)

    assert presenter.clear_completion() is True
    assert presenter.state.completion is None
    assert presenter.state.active_notice == unrelated
    assert presenter.state.last_normal_scan == "AAA2270730100-003"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scan_count": -1},
        {"target_count": -1},
        {"scan_count": 4, "target_count": 3},
        {"scan_count": 1, "target_count": 0},
        {"scan_count": True},
    ],
)
def test_completion_snapshot_rejects_invalid_counts(kwargs):
    with pytest.raises(ValueError):
        _completion(CompletionOutcome.ACKED, **kwargs)


def test_presentation_snapshot_has_no_durability_claim_field():
    snapshot = _completion(CompletionOutcome.ACKED, receipt_id="receipt-1")

    assert not hasattr(snapshot, "durable")
    assert not hasattr(snapshot, "persisted")
    assert not hasattr(snapshot, "ledger_written")


def test_record_normal_scan_ignores_non_text_values_without_erasing_previous_scan():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-001")

    assert presenter.record_normal_scan(None) is False
    assert presenter.state.last_normal_scan == "AAA2270730100-001"
