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
        "ADMIN_PIN_APPLIED",
        "ADMIN_PIN_CONSUMED",
        "ADMIN_PIN_HANDOFF_UNKNOWN",
        "ADMIN_PIN_REJECTED",
        "ADMIN_PIN_RESUMED",
        "ADMIN_PIN_SUPERSEDED",
        "ADMIN_PIN_UNVERIFIED",
        "ADMIN_PIN_UNVERIFIED_HOLD",
        "ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED",
        "ACTIVE_TRAY_PHS2_SCAN_REJECTED",
        "APP_CLOSE_DELAY",
        "APP_STOP_DEFERRED",
        "HISTORICAL_REPLACE_CANCEL",
        "HISTORICAL_REPLACE_START",
        "IDLE_END",
        "IDLE_START",
        "MASTER_LABEL_PREFLIGHT_FAILED",
        "MASTER_LABEL_REPLACEMENT_BLOCKED_EXACT_MEMBERSHIP",
        "OPERATION_LEASE_COMPLETION_TIME_RAISED",
        "OPERATION_LEASE_RELEASE_RESULT",
        "PHS2_ATOMIC_TEMP_QUARANTINED",
        "PHS2_AUDIT_EVIDENCE_BOUND",
        "PHS2_AUDIT_EVIDENCE_UNVERIFIED_HOLD",
        "PHS2_DAMAGED_PARKED_DEFERRED",
        "PHS2_PAIRED_MANUAL_HOLD",
        "PHS2_PAIRED_PREFLIGHT_DEFERRED",
        "PHS2_PAIRED_RECEIPT_RECHECK_REQUESTED",
        "PHS2_PAIRED_RECOVERY_DEFERRED",
        "PHS2_PAIRED_STALE_CURRENT_DEFERRED",
        "PHS2_PAIRED_STALE_CURRENT_PRESERVATION_REQUESTED",
        "PHS2_STALE_HOLD_RECHECKED",
        "PHS2_PREFLIGHT_HOLD_CLOSE_HANDOFF",
        "PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING",
        "PHS2_PREFLIGHT_HOLD_QUARANTINED",
        "PHS2_PREFLIGHT_HOLD_RESTORED",
        "PHS_LABEL_ACTIVE_REFRESHED",
        "PHS_LABEL_DATE_EXCHANGED",
        "PRODUCT_EXCHANGE_BLOCKED_EXACT_MEMBERSHIP",
        "PRODUCT_EXCHANGE_CANCELLED",
        "PRODUCT_EXCHANGE_COMPLETED",
        "RANDOM_TEST_SESSION_START",
        "SCAN_COMMAND_UNKNOWN",
        "TRAY_SHORT_CONFIRMATION_UNDONE",
        "SCAN_FAIL_AMBIGUOUS_ITEM_CODE",
        "SCAN_FAIL_FORMAT",
        "SCAN_FAIL_MISMATCH",
        "SCAN_FAIL_TRAY_FULL",
        "SCAN_UNDO",
        "TRANSFER_SEAL_PREFLIGHT_RETRY_REQUESTED",
        "TRANSFER_SEAL_REVIEW_RETRY_REQUESTED",
        "TRAY_PARKED",
        "TRAY_RESET_STATE_DELETE_FAILED",
        "TRAY_RESTORED_FROM_PARK",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION",
        "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE",
        "TRAY_STATE_DISCARDED_AFTER_COMPLETION",
        "TRAY_TAKEOVER",
        "WORK_PAUSE",
        "PHS_REPLACEMENT_WAITING_MARK_FAILED",
        "WORKER_ACTION_AUTHORIZED",
        "WORKER_ACTION_RESUMED",
        "WORKER_ACTION_APPLIED",
        "UI_LANE_FAULT",
    }
)


def test_audited_container_csv_values_have_one_exhaustive_disposition():
    assert AUDITED_OUT_OF_CATALOG_EVENT_TYPES == (
        EXPECTED_AUDITED_OUT_OF_CATALOG_EVENTS
    )
    assert len(CONTRACT_CANDIDATE_EVENT_TYPES) == 14
    assert len(LOCAL_ONLY_EVENT_TYPES) == 49
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
    from event_emitter_audit import collect_emitters
    import subprocess

    paths = subprocess.check_output(
        ["git", "ls-files", "*.py"], cwd=root, text=True
    ).splitlines()
    paths = [p for p in paths if not p.startswith((
        "tests/", "vendor/", "kmtech_factory_contracts/", "kmtech_shared/"
    ))]
    emitters = []
    unresolved = []
    for path in paths:
        rows, dynamic = collect_emitters(
            (root / path).read_text(encoding="utf-8-sig"), path
        )
        emitters.extend(rows)
        unresolved.extend(dynamic)
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

    missing = [row for row in emitters if row["event"] not in reviewed]
    assert not missing, "Unclassified event emitters: " + "; ".join(
        f"{row['event']} {row['path']}:{row['line']} ({row['shape']})"
        for row in missing
    )
    assert not (set(stream["raw_event_names"]) & LOCAL_ONLY_EVENT_TYPES)
    # Forwarding boundaries are reviewed separately from finite event names.
    # A new/changed unresolved expression must fail instead of disappearing.
    from collections import Counter
    expected_dynamic = json.loads(
        (root / "tests/fixtures/event_emitter_dynamic_sources.json").read_text()
    )
    key = lambda row: (row["path"], row["scope"], row["expression"])
    assert Counter(map(key, unresolved)) == Counter(map(key, expected_dynamic)), (
        "Unreviewed dynamic event forwarding sites: " + repr(unresolved)
    )


def test_collector_resolves_alias_partial_constants_and_keyword_arguments():
    from event_emitter_audit import collect_emitters

    source = """
import functools
from functools import partial as bind
PREFIX = "ASSEMBLED_"
class App:
    def emit(self):
        name = PREFIX + "EVENT"
        logger = getattr(self, "_log_event", None)
        logger(name)
        direct = self._log_event
        direct(event="KEYWORD_EVENT")
        bound = functools.partial(self._log_event, event_type="PARTIAL_EVENT")
        bound(detail={})
        positional = functools.partial(logger, "POSITIONAL_EVENT")
        positional()
        chosen = "TRUE_EVENT" if self.ready else "FALSE_EVENT"
        self._log_event(event_type=chosen)
        joined = f"{PREFIX}FORMATTED"
        self._log_event(joined)
        names = {"a": "MAPPED_A", "b": "MAPPED_B"}
        self._log_event(names[self.choice])
        other = bind(direct, event="RENAMED_PARTIAL")
        other()
"""
    rows, unresolved = collect_emitters(source)
    assert {row["event"] for row in rows} == {
        "ASSEMBLED_EVENT", "KEYWORD_EVENT", "PARTIAL_EVENT",
        "POSITIONAL_EVENT", "TRUE_EVENT", "FALSE_EVENT",
        "ASSEMBLED_FORMATTED", "MAPPED_A", "MAPPED_B", "RENAMED_PARTIAL",
    }
    assert not unresolved


def test_collector_preserves_unresolved_dynamic_calls_for_review():
    from event_emitter_audit import collect_emitters

    rows, unresolved = collect_emitters(
        "def emit(self, name):\n    alias = self._log_event\n    alias(event_type=name)\n"
    )
    assert rows == []
    assert len(unresolved) == 1
    assert unresolved[0]["scope"] == "emit"
    assert unresolved[0]["shape"] == "alias"
