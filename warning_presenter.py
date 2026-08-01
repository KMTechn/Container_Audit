from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class NoticeSeverity(str, Enum):
    """Visual severity only; it does not imply a business outcome."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class CompletionOutcome(str, Enum):
    """Completion result that the business layer has already decided."""

    ACKED = "ACKED"
    LINKED = "LINKED"
    RETRY_WAIT = "RETRY_WAIT"
    OPERATOR_REVIEW = "OPERATOR_REVIEW"


@dataclass(frozen=True, slots=True)
class Notice:
    """One immutable message for the application's single notice location."""

    code: str
    title: str
    message: str
    severity: NoticeSeverity = NoticeSeverity.INFO
    blocking: bool = False

    def __post_init__(self) -> None:
        for name in ("code", "title", "message"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"notice {name} must be a string")
        if not self.code.strip():
            raise ValueError("notice code must not be empty")
        if not self.title.strip():
            raise ValueError("notice title must not be empty")
        if not self.message.strip():
            raise ValueError("notice message must not be empty")
        if not isinstance(self.severity, NoticeSeverity):
            raise TypeError("notice severity must be a NoticeSeverity")
        if not isinstance(self.blocking, bool):
            raise TypeError("notice blocking must be a boolean")


@dataclass(frozen=True, slots=True)
class CompletionOutcomeSnapshot:
    """Ephemeral completion data for rendering only.

    Creating this value does not prove that a ledger row, state file, receipt, or
    any other business record was written. The business layer should construct
    it only at the integration point appropriate for the result it has already
    obtained. ``message``, ``receipt_id``, and ``error_code`` are diagnostic
    context for persistence, logs, and technical support; presentation code
    must not render them to an operator.
    """

    outcome: CompletionOutcome
    item_name: str = ""
    master_label: str = ""
    scan_count: int = 0
    target_count: int = 0
    message: str = ""
    receipt_id: str = ""
    error_code: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, CompletionOutcome):
            raise TypeError("completion outcome must be a CompletionOutcome")
        for name in ("item_name", "master_label", "message", "receipt_id", "error_code"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        for name in ("scan_count", "target_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.scan_count > self.target_count:
            raise ValueError("scan_count must not exceed target_count")

    @property
    def blocks_completion(self) -> bool:
        return self.outcome in {
            CompletionOutcome.RETRY_WAIT,
            CompletionOutcome.OPERATOR_REVIEW,
        }

    @property
    def server_confirmed(self) -> bool:
        return self.outcome is CompletionOutcome.ACKED


@dataclass(frozen=True, slots=True)
class WarningViewState:
    """The complete immutable input for the single notice presentation area."""

    active_notice: Notice | None = None
    last_normal_scan: str | None = None
    completion: CompletionOutcomeSnapshot | None = None

    @property
    def is_blocking(self) -> bool:
        notice_blocks = self.active_notice is not None and self.active_notice.blocking
        completion_blocks = self.completion is not None and self.completion.blocks_completion
        return notice_blocks or completion_blocks


_OPERATOR_REVIEW_DEFAULT_MESSAGE = (
    "서버 판정 미완료 · 완료 처리 중지 · 트레이·목록 유지 · 담당자 확인"
)

_COMPLETION_NOTICE_DEFAULTS = {
    CompletionOutcome.ACKED: (
        "completion.acked",
        "서버 이적 확인 완료",
        "서버 이적 확인이 완료되었습니다.",
        NoticeSeverity.SUCCESS,
        False,
    ),
    CompletionOutcome.LINKED: (
        "completion.linked",
        "이적 연계 완료",
        "이 PC에 이적 정보를 안전하게 저장했습니다.",
        NoticeSeverity.SUCCESS,
        False,
    ),
    CompletionOutcome.RETRY_WAIT: (
        "completion.retry_wait",
        "서버 이적 확인 대기",
        "서버 이적 확인이 아직 완료되지 않았습니다. 자동 재시도를 기다려 주세요.",
        NoticeSeverity.WARNING,
        True,
    ),
    CompletionOutcome.OPERATOR_REVIEW: (
        "completion.operator_review",
        "완료 확인 필요",
        _OPERATOR_REVIEW_DEFAULT_MESSAGE,
        NoticeSeverity.ERROR,
        True,
    ),
}


def notice_for_completion(snapshot: CompletionOutcomeSnapshot) -> Notice:
    """Build operator-safe copy without rendering diagnostic snapshot fields."""

    if not isinstance(snapshot, CompletionOutcomeSnapshot):
        raise TypeError("snapshot must be a CompletionOutcomeSnapshot")
    code, title, default_message, severity, blocking = _COMPLETION_NOTICE_DEFAULTS[snapshot.outcome]
    return Notice(
        code=code,
        title=title,
        message=default_message,
        severity=severity,
        blocking=blocking,
    )


class WarningPresenter:
    """Small in-memory state machine for warnings and completion outcomes.

    The presenter deliberately has no Tk, filesystem, network, ledger, or clock
    dependency. Callers render ``state`` after a method returns ``True``.
    """

    def __init__(self, initial_state: WarningViewState | None = None) -> None:
        if initial_state is not None and not isinstance(initial_state, WarningViewState):
            raise TypeError("initial_state must be a WarningViewState")
        self._state = initial_state or WarningViewState()

    @property
    def state(self) -> WarningViewState:
        return self._state

    def present(self, notice: Notice) -> bool:
        """Place one notice, unless it is a duplicate or a block is active."""

        if not isinstance(notice, Notice):
            raise TypeError("notice must be a Notice")
        active = self._state.active_notice
        if active == notice:
            return False
        if self._state.is_blocking:
            return False
        self._state = replace(self._state, active_notice=notice)
        return True

    def clear(self) -> bool:
        """Clear a non-blocking notice without changing other presentation data."""

        active = self._state.active_notice
        if active is None or active.blocking:
            return False
        self._state = replace(self._state, active_notice=None)
        return True

    def acknowledge(self) -> bool:
        """Acknowledge the visible notice.

        Acknowledging an OPERATOR_REVIEW notice hides that notice, but its
        completion snapshot remains blocking until a later business result
        replaces it.
        """

        if self._state.active_notice is None:
            return False
        self._state = replace(self._state, active_notice=None)
        return True

    def record_normal_scan(self, barcode: str) -> bool:
        """Remember a successful scan independently from notices and outcomes."""

        if not isinstance(barcode, str):
            return False
        normalized = barcode.strip()
        if not normalized or normalized == self._state.last_normal_scan:
            return False
        self._state = replace(self._state, last_normal_scan=normalized)
        return True

    def clear_last_normal_scan(self) -> bool:
        """Explicitly clear scan context when the business layer starts a new session."""

        if self._state.last_normal_scan is None:
            return False
        self._state = replace(self._state, last_normal_scan=None)
        return True

    def present_completion(self, snapshot: CompletionOutcomeSnapshot) -> bool:
        """Present a business-decided completion outcome in the single location.

        A newer completion result is an explicit business-layer resolution and
        may therefore replace an earlier OPERATOR_REVIEW notice. Identical
        snapshots are deduplicated.
        """

        if not isinstance(snapshot, CompletionOutcomeSnapshot):
            raise TypeError("snapshot must be a CompletionOutcomeSnapshot")
        notice = notice_for_completion(snapshot)
        if self._state.completion == snapshot and self._state.active_notice == notice:
            return False
        self._state = replace(self._state, completion=snapshot, active_notice=notice)
        return True

    def clear_completion(self) -> bool:
        """Clear a settled outcome; an OPERATOR_REVIEW block cannot be dismissed."""

        completion = self._state.completion
        if completion is None or completion.blocks_completion:
            return False
        completion_notice = notice_for_completion(completion)
        active_notice = self._state.active_notice
        if active_notice == completion_notice:
            active_notice = None
        self._state = replace(self._state, completion=None, active_notice=active_notice)
        return True

    def resolve_blocking_completion(
        self,
        expected: CompletionOutcomeSnapshot,
    ) -> bool:
        """Clear one exact block after the business layer proves it resolved."""

        if (
            not isinstance(expected, CompletionOutcomeSnapshot)
            or not expected.blocks_completion
            or self._state.completion != expected
        ):
            return False
        completion_notice = notice_for_completion(expected)
        active_notice = self._state.active_notice
        if active_notice == completion_notice:
            active_notice = None
        self._state = replace(
            self._state,
            completion=None,
            active_notice=active_notice,
        )
        return True
