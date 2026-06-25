from pathlib import Path


PLAN = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "THREE_AGENT_PRODUCTION_CUTOVER_PLAN_20260625.md"
)


def _text() -> str:
    return PLAN.read_text(encoding="utf-8")


def test_three_agent_plan_records_current_blocked_state_and_owners():
    text = _text()

    required = [
        "Production cutover is still `BLOCKED`.",
        "OPTIONS 200",
        "No authenticated producer `POST`, HMAC, nonce, idempotency, receipt",
        "PLAN_C_ROLLOUT_GATE_BLOCKED",
        "direct_sync_ops_status.py",
        "Syncthing remains a shadow and rollback safety path",
        "Agent A: Server/DB/Ingest",
        "Agent B: Producer PC/Field/Security",
        "Agent C: Downstream/Shadow/Rollback",
    ]

    assert [item for item in required if item not in text] == []


def test_three_agent_plan_covers_p0_server_schema_and_promotion_gates():
    text = _text()

    required = [
        "Read-only 기준선 고정",
        "Schema blocker approval packet",
        "Hash-checked backup and additive schema",
        "Post-schema direct-sync readiness",
        "Promotion evidence bundle",
        "producer_ingest_receipts",
        "producer_ingest_nonces",
        "producer_ingest_raw_artifacts",
        "source_claim_history",
        "process_state_summary_sources",
        "defect_hmac_chain_state",
        "health_ingest_before_after",
        "rollback_marker_and_drain_receipt",
    ]

    assert [item for item in required if item not in text] == []


def test_three_agent_plan_covers_field_canary_ui_and_twenty_pc_validation():
    text = _text()

    required = [
        "Credential and canary preparation",
        "One-PC authenticated canary",
        "Actual scanner/UI validation",
        "20-PC/VM concurrency",
        "login, new/existing worker, master label, product scan",
        "auto complete, undo, reset, park/restore",
        "completed-label replacement, individual exchange, close/recover",
        "same Korean filename",
        "relay restart",
        "exactly 20 distinct source identities",
    ]

    assert [item for item in required if item not in text] == []


def test_three_agent_plan_covers_downstream_shadow_rollback_and_soak():
    text = _text()

    required = [
        "Downstream and dashboard validation",
        "Syncthing/archive parallel shadow",
        "Rollback rehearsal",
        "Shadow burn-in and final signoff",
        "today/past/trace/summary/export",
        "source_claim history",
        "projection parity report",
        "queued uploads resume without duplicate projection",
        "minimum 3 business days",
        "4-8 hours or one full day volume",
    ]

    assert [item for item in required if item not in text] == []


def test_three_agent_plan_defines_syncthing_retirement_gate_and_hard_stops():
    text = _text()

    required = [
        "Hard Stop Conditions",
        "expected_db_sha256",
        "Any POST writes a receipt without nonce, raw artifact, source_claim, and summary reconciliation",
        "Any replay, retry, or Syncthing/archive shadow creates duplicate projection",
        "Any raw secret, HMAC key, receipt JSON, or raw payload appears",
        "Syncthing Retirement Gate",
        "20-PC ingest PASS",
        "source_claim unresolved conflict count is `0`",
        "promotion_allowed=true",
        "production_removal_ready=true",
        "Syncthing remains enabled as shadow/rollback safety",
    ]

    assert [item for item in required if item not in text] == []
