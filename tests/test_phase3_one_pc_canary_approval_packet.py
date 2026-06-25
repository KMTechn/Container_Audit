from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "03_one_pc_canary"
    / "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase3_canary_packet_preserves_no_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "does not authorize producer POST upload",
        "HMAC secret disclosure",
        "credential issue/rotation/revocation",
        "20-PC run",
        "Syncthing mutation",
        "rollback rehearsal",
        "service or scheduled task changes",
        "Syncthing removal",
    ]
    unconditional_allow_claims = [
        "authorizes 20-PC",
        "authorizes Syncthing removal",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase3_canary_packet_requires_phase2_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md",
        "`schema_ready=true`, `missing_tables=[]`, and `missing_columns={}`",
        "pre-canary `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, and `source_claim` counts are `0`",
        "credential owner approves one canary key id",
        "field operator approves exactly one worker PC/scanner",
        "downstream owner identifies the dashboard/program target",
        "rollback owner confirms Syncthing/archive remains enabled",
        "Change coordinator",
    ]

    assert [item for item in required if item not in text] == []


def test_phase3_canary_packet_binds_endpoint_identity_and_replay_scope():
    text = _packet_text()

    required = [
        "Approved endpoint: `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file`",
        "Canary scope: one PC, one worker, one source CSV/tray scenario, one initial upload, one idempotency replay.",
        "`source_host_id`",
        "`producer_install_id`",
        "`key_id`",
        "`client_batch_id`",
        "`idempotency_key`",
        "`server_source_file_id`",
        "HMAC timestamp must be within the approved skew window.",
        "Nonce must be accepted exactly once",
    ]

    assert [item for item in required if item not in text] == []


def test_phase3_canary_packet_defines_required_evidence_and_pass_stop_gates():
    text = _packet_text()

    required = [
        "TLS/certificate/proxy metadata",
        "redacted request metadata",
        "server receipt summary",
        "nonce/idempotency evidence",
        "producer_ingest_receipts",
        "producer_ingest_nonces",
        "producer_ingest_raw_artifacts",
        "source_claim",
        "common_ingested_events",
        "projection, summary, and quarantine deltas",
        "Downstream today/trace/summary/export outputs match",
        "Bad HMAC, expired key, revoked key, duplicate key id, or timestamp skew is accepted.",
        "Nonce replay creates a second accepted write",
        "Syncthing/archive or replay double counts",
    ]

    assert [item for item in required if item not in text] == []


def test_phase3_canary_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md`",
        "credential owner signoff",
        "one `producer_install_id`, one `source_host_id`",
        "field operator signoff",
        "DB owner signoff for Phase 2 PASS",
        "redacted request metadata",
        "receipt summary",
        "nonce/idempotency evidence",
        "Do not place raw HMAC secrets",
        "does not authorize 20-PC testing",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
