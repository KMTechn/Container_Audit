"""Pure presentation contracts for ContainerAudit integration points.

These tests intentionally do not import Tk or Container_Audit. They describe
when the business layer is allowed to publish presentation state without
standing in for storage, ledger, or transfer-seal tests.
"""

import pytest

from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    Notice,
    NoticeSeverity,
    WarningPresenter,
    notice_for_completion,
)


MASTER_LABEL = "PHS=1|CLC=AAA2270730100|QT=3"
OPERATOR_REVIEW_CORE = (
    "서버 판정 미완료 · 완료 처리 중지 · 트레이·목록 유지 · 담당자 확인"
)


def _completion(outcome, *, message=""):
    return CompletionOutcomeSnapshot(
        outcome=outcome,
        item_name="fixture item",
        master_label=MASTER_LABEL,
        scan_count=3,
        target_count=3,
        message=message,
    )


def _scan_error(code="scan.duplicate"):
    return Notice(
        code=code,
        title="스캔 오류",
        message="제품 스캔을 반영하지 않았습니다.",
        severity=NoticeSeverity.ERROR,
    )


def test_scan_candidate_is_not_last_normal_until_state_save_gate_succeeds():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-001")

    candidate = "AAA2270730100-002"
    state_save_succeeded = False
    if state_save_succeeded:
        presenter.record_normal_scan(candidate)

    assert presenter.state.last_normal_scan == "AAA2270730100-001"

    state_save_succeeded = True
    if state_save_succeeded:
        presenter.record_normal_scan(candidate)

    assert presenter.state.last_normal_scan == candidate


@pytest.mark.parametrize("error_code", ["scan.duplicate", "scan.mismatch"])
def test_rejected_scan_notice_does_not_replace_last_normal_scan(error_code):
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-001")

    presenter.present(_scan_error(error_code))

    assert presenter.state.last_normal_scan == "AAA2270730100-001"
    assert presenter.state.active_notice.code == error_code


def test_operator_review_snapshot_preserves_scan_context_and_cannot_be_cleared_by_ack():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-003")

    presenter.present_completion(
        _completion(
            CompletionOutcome.OPERATOR_REVIEW,
            message="MEMBERSHIP_CONFLICT: 서버 membership을 확인하세요.",
        )
    )

    assert presenter.state.last_normal_scan == "AAA2270730100-003"
    assert presenter.state.completion.outcome is CompletionOutcome.OPERATOR_REVIEW
    assert presenter.state.is_blocking is True
    assert presenter.state.active_notice.message.startswith(OPERATOR_REVIEW_CORE)
    assert presenter.state.active_notice.message.count(OPERATOR_REVIEW_CORE) == 1
    assert "MEMBERSHIP_CONFLICT" in presenter.state.active_notice.message

    assert presenter.acknowledge() is True
    assert presenter.state.active_notice is None
    assert presenter.state.is_blocking is True
    assert presenter.clear_completion() is False


def test_operator_review_default_equivalent_detail_uses_one_notice_and_keeps_last_scan():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-003")

    presenter.present_completion(
        _completion(
            CompletionOutcome.OPERATOR_REVIEW,
            message="서버 판정 미완료 · 현재 트레이와 스캔 목록을 유지합니다.",
        )
    )

    assert presenter.state.active_notice.message == OPERATOR_REVIEW_CORE
    assert presenter.state.last_normal_scan == "AAA2270730100-003"
    assert presenter.state.is_blocking is True
    assert not hasattr(presenter.state, "secondary_notice")


@pytest.mark.parametrize(
    ("outcome", "expected_title", "required_text", "forbidden_text", "confirmed"),
    [
        (
            CompletionOutcome.ACKED,
            "서버 이적 확인 완료",
            "서버 이적 확인이 완료되었습니다.",
            "아직 완료되지 않았습니다",
            True,
        ),
        (
            CompletionOutcome.RETRY_WAIT,
            "서버 이적 확인 대기",
            "서버 이적 확인이 아직 완료되지 않았습니다.",
            "서버 이적 확인이 완료되었습니다",
            False,
        ),
    ],
)
def test_settled_completion_wording_distinguishes_acked_from_retry_wait(
    outcome,
    expected_title,
    required_text,
    forbidden_text,
    confirmed,
):
    snapshot = _completion(outcome, message="서버 응답 상세")
    notice = notice_for_completion(snapshot)

    assert notice.title == expected_title
    assert required_text in notice.message
    assert forbidden_text not in notice.message
    assert "서버 응답 상세" in notice.message
    assert snapshot.server_confirmed is confirmed
    assert notice.blocking is False


def test_failed_completion_ledger_gate_leaves_no_acked_or_retry_wait_snapshot():
    presenter = WarningPresenter()
    presenter.record_normal_scan("AAA2270730100-003")

    tray_complete_ledger_succeeded = False
    pending_outcome = _completion(CompletionOutcome.ACKED)
    if tray_complete_ledger_succeeded:
        presenter.present_completion(pending_outcome)

    assert presenter.state.completion is None
    assert presenter.state.last_normal_scan == "AAA2270730100-003"


def test_later_business_result_can_replace_operator_review_but_ack_alone_cannot():
    presenter = WarningPresenter()
    presenter.present_completion(_completion(CompletionOutcome.OPERATOR_REVIEW))
    presenter.acknowledge()

    assert presenter.state.is_blocking is True

    presenter.present_completion(_completion(CompletionOutcome.RETRY_WAIT))

    assert presenter.state.is_blocking is False
    assert presenter.state.completion.outcome is CompletionOutcome.RETRY_WAIT
    assert presenter.state.active_notice.severity is NoticeSeverity.WARNING
