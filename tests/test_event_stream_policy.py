import ast
import json
from pathlib import Path

from event_stream_policy import (
    ADJACENT_CONTRACT_CANDIDATE_EVENT_TYPES,
    AUDITED_OUT_OF_CATALOG_EVENT_TYPES,
    CONTRACT_CANDIDATE_EVENT_TYPES,
    FORBIDDEN_EVENT_TYPES,
    LOCAL_ONLY_EVENT_TYPES,
    local_only_event_log_path,
)


EXPECTED_AUDITED_OUT_OF_CATALOG_EVENTS = frozenset(
    {
        "ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED",
        "ACTIVE_TRAY_PHS2_SCAN_REJECTED",
        "HISTORICAL_REPLACE_CANCEL",
        "HISTORICAL_REPLACE_START",
        "IDLE_END",
        "IDLE_START",
        "MASTER_LABEL_PREFLIGHT_FAILED",
        "MASTER_LABEL_REPLACEMENT_BLOCKED_EXACT_MEMBERSHIP",
        "PHS_LABEL_ACTIVE_REFRESHED",
        "PHS_LABEL_DATE_EXCHANGED",
        "PRODUCT_EXCHANGE_BLOCKED_EXACT_MEMBERSHIP",
        "PRODUCT_EXCHANGE_CANCELLED",
        "PRODUCT_EXCHANGE_COMPLETED",
        "RANDOM_TEST_SESSION_START",
        "SCAN_FAIL_AMBIGUOUS_ITEM_CODE",
        "SCAN_FAIL_FORMAT",
        "SCAN_FAIL_MISMATCH",
        "SCAN_FAIL_TRAY_FULL",
        "SCAN_UNDO",
        "TRANSFER_SEAL_PREFLIGHT_RETRY_REQUESTED",
        "TRAY_PARKED",
        "TRAY_RESET_STATE_DELETE_FAILED",
        "TRAY_RESTORED_FROM_PARK",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE",
        "TRAY_STATE_DISCARDED_AFTER_COMPLETION",
        "TRAY_TAKEOVER",
        "WORK_PAUSE",
    }
)


def test_audited_container_csv_values_have_one_exhaustive_disposition():
    assert AUDITED_OUT_OF_CATALOG_EVENT_TYPES == (
        EXPECTED_AUDITED_OUT_OF_CATALOG_EVENTS
    )
    assert len(CONTRACT_CANDIDATE_EVENT_TYPES) == 14
    assert len(LOCAL_ONLY_EVENT_TYPES) == 14
    assert not FORBIDDEN_EVENT_TYPES
    assert not (CONTRACT_CANDIDATE_EVENT_TYPES & LOCAL_ONLY_EVENT_TYPES)


def test_dynamic_recovery_event_is_tracked_as_an_adjacent_contract_candidate():
    assert ADJACENT_CONTRACT_CANDIDATE_EVENT_TYPES == frozenset(
        {"PRODUCT_EXCHANGE_LOCAL_RECONCILED"}
    )
    assert not (
        ADJACENT_CONTRACT_CANDIDATE_EVENT_TYPES
        & AUDITED_OUT_OF_CATALOG_EVENT_TYPES
    )


def test_local_only_path_is_outside_the_relay_scan_directory(tmp_path):
    scan_dir = tmp_path / "events"
    contract_path = scan_dir / "이적작업이벤트로그_작업자_20260829.csv"
    local_dir = tmp_path / "local_events"

    local_path = local_only_event_log_path(
        contract_path,
        local_events_dir=local_dir,
    )

    assert local_path == (
        local_dir / "이적로컬이벤트로그_작업자_20260829.csv"
    )
    assert local_path.parent != Path(scan_dir)


def test_headless_fallback_uses_a_non_recursive_child_directory(tmp_path):
    contract_path = tmp_path / "events.csv"

    local_path = local_only_event_log_path(contract_path)

    assert local_path == tmp_path / "local_only" / "local-only-events.csv"


def test_production_emitters_are_closed_by_catalog_or_reviewed_policy():
    root = Path(__file__).resolve().parents[1]
    container_tree = ast.parse(
        (root / "Container_Audit.py").read_text(encoding="utf-8-sig")
    )
    product_scan_tree = ast.parse(
        (root / "product_scan.py").read_text(encoding="utf-8-sig")
    )
    literal_log_events = {
        call.args[0].value
        for call in ast.walk(container_tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "_log_event"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }
    decision_events = {
        keyword.value.value
        for call in ast.walk(product_scan_tree)
        if isinstance(call, ast.Call)
        for keyword in call.keywords
        if keyword.arg == "event_name"
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
        and keyword.value.value
    }
    catalog = json.loads(
        (
            root
            / "kmtech_factory_contracts"
            / "bundle"
            / "v1"
            / "catalogs"
            / "canonical-stream-catalog.json"
        ).read_text(encoding="utf-8")
    )
    stream = next(
        row
        for row in catalog["streams"]
        if row.get("app_id") == "container_audit"
    )
    reviewed = (
        set(stream["raw_event_names"])
        | set(AUDITED_OUT_OF_CATALOG_EVENT_TYPES)
        | set(ADJACENT_CONTRACT_CANDIDATE_EVENT_TYPES)
    )

    assert literal_log_events | decision_events <= reviewed
    assert not (set(stream["raw_event_names"]) & LOCAL_ONLY_EVENT_TYPES)
