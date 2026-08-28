from __future__ import annotations

from pathlib import Path


CONTRACT_CANDIDATE_EVENT_TYPES = frozenset(
    {
        "HISTORICAL_REPLACE_CANCEL",
        "PHS_LABEL_ACTIVE_REFRESHED",
        "PHS_LABEL_DATE_EXCHANGED",
        "PRODUCT_EXCHANGE_CANCELLED",
        "PRODUCT_EXCHANGE_COMPLETED",
        "SCAN_FAIL_AMBIGUOUS_ITEM_CODE",
        "SCAN_FAIL_FORMAT",
        "SCAN_FAIL_MISMATCH",
        "SCAN_FAIL_TRAY_FULL",
        "SCAN_UNDO",
        "TRAY_PARKED",
        "TRAY_RESTORED_FROM_PARK",
        "TRAY_TAKEOVER",
        "WORK_PAUSE",
    }
)


LOCAL_ONLY_EVENT_TYPES = frozenset(
    {
        "ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED",
        "ACTIVE_TRAY_PHS2_SCAN_REJECTED",
        "HISTORICAL_REPLACE_START",
        "IDLE_END",
        "IDLE_START",
        "MASTER_LABEL_PREFLIGHT_FAILED",
        "MASTER_LABEL_REPLACEMENT_BLOCKED_EXACT_MEMBERSHIP",
        "PRODUCT_EXCHANGE_BLOCKED_EXACT_MEMBERSHIP",
        "RANDOM_TEST_SESSION_START",
        "TRANSFER_SEAL_PREFLIGHT_RETRY_REQUESTED",
        "TRAY_RESET_STATE_DELETE_FAILED",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE",
        "TRAY_STATE_DISCARDED_AFTER_COMPLETION",
    }
)


FORBIDDEN_EVENT_TYPES = frozenset()


# This recovery branch is a real committed product-exchange fact, but the
# preceding audit's literal-only collector missed it because the value is
# selected by a conditional expression before _log_event is called.
ADJACENT_CONTRACT_CANDIDATE_EVENT_TYPES = frozenset(
    {"PRODUCT_EXCHANGE_LOCAL_RECONCILED"}
)


AUDITED_OUT_OF_CATALOG_EVENT_TYPES = frozenset(
    CONTRACT_CANDIDATE_EVENT_TYPES
    | LOCAL_ONLY_EVENT_TYPES
    | FORBIDDEN_EVENT_TYPES
)


def local_only_event_log_path(
    contract_log_file_path: str | Path,
    *,
    local_events_dir: str | Path | None = None,
) -> Path:
    """Return a sibling stream path that the non-recursive relay cannot scan."""

    contract_path = Path(contract_log_file_path)
    destination_dir = (
        Path(local_events_dir)
        if str(local_events_dir or "").strip()
        else contract_path.parent / "local_only"
    )
    filename = contract_path.name
    if filename.startswith("이적작업이벤트로그_"):
        filename = filename.replace(
            "이적작업이벤트로그_",
            "이적로컬이벤트로그_",
            1,
        )
    else:
        filename = f"local-only-{filename}"
    return destination_dir / filename
