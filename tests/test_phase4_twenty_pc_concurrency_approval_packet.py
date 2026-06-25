from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "05_twenty_pc_concurrency"
    / "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase4_concurrency_packet_preserves_no_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "does not authorize producer POST upload outside the approved 20-PC staging/test window",
        "HMAC secret disclosure",
        "credential issue/rotation/revocation",
        "Syncthing mutation",
        "rollback rehearsal",
        "service or scheduled task changes",
        "schema `--execute`",
        "production DB mutation",
        "Syncthing removal",
    ]
    unconditional_allow_claims = [
        "authorizes Syncthing removal",
        "remove Syncthing",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase4_concurrency_packet_requires_phase3_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md",
        "records one-PC canary PASS",
        "HMAC, timestamp, nonce, idempotency, receipt storage",
        "`source_claim`, downstream reconciliation, and no double count",
        "credential owner approves at least 20 distinct `source_host_id`, `producer_install_id`, and `key_id` mappings",
        "field operator approves at least 20 physical/VM PCs",
        "same Korean filename scenario",
        "same worker name scenario",
        "downstream owner approves the dashboard/program target",
        "rollback owner confirms Syncthing/archive remains enabled",
        "change coordinator confirms the planned fault windows",
    ]

    assert [item for item in required if item not in text] == []


def test_phase4_concurrency_packet_binds_identity_scope_and_required_scenarios():
    text = _packet_text()

    required = [
        "Minimum cohort: at least 20 distinct approved physical/VM PCs.",
        "`source_host_id`",
        "`producer_install_id`",
        "`key_id`",
        "source CSV SHA-256",
        "all PCs use the same Korean CSV filename and the same worker name",
        "at least five PCs repeat the same upload with the same idempotency key",
        "at least one controlled network interruption or endpoint retry window",
        "relay queue restart/resume is performed on at least five PCs",
        "server `source_claim` and projection logic must prevent same source artifact replay",
    ]

    assert [item for item in required if item not in text] == []


def test_phase4_concurrency_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries and hashes in `05_twenty_pc_concurrency`.",
        "20 PC identity matrix",
        "per-PC relay DB before/after queue counts",
        "retry/resume evidence for duplicate resend, network interruption, timeout/retry, queue restart, and resume drain",
        "server receipt summary per accepted upload",
        "producer_ingest_receipts",
        "producer_ingest_nonces",
        "producer_ingest_raw_artifacts",
        "source_claim",
        "common_ingested_events",
        "projection, summary, and quarantine deltas",
        "At least 20 distinct approved identities",
        "Same Korean filename and same worker name do not collapse separate PC identities.",
        "Duplicate resend and idempotency replay do not create extra receipts",
        "Operator status explains every failure",
        "Fewer than 20 approved distinct PC identities produce usable evidence.",
        "Syncthing/archive or replay double counts any source event.",
    ]

    assert [item for item in required if item not in text] == []


def test_phase4_concurrency_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md`",
        "at least 20 distinct `source_host_id`, `producer_install_id`, and `key_id` rows",
        "same Korean filename",
        "same worker name",
        "duplicate resend",
        "network interruption",
        "queue restart",
        "redacted server receipt summaries",
        "DB reconciliation for receipt, nonce, raw artifact, source_claim, common_ingested_events, projection, summary, and quarantine deltas",
        "Syncthing/archive shadow observation proving no double count",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload outside the approved 20-PC window",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
