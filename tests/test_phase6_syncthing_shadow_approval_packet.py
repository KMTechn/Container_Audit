from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "07_syncthing_shadow_no_double_count"
    / "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase6_syncthing_shadow_packet_preserves_no_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "does not authorize producer POST upload outside the approved staging/test window",
        "HMAC secret disclosure",
        "credential issue/rotation/revocation",
        "Syncthing config changes",
        "Syncthing folder removal",
        "Syncthing service stop/start",
        "scheduled task changes",
        "schema `--execute`",
        "production DB mutation",
        "rollback rehearsal",
        "Syncthing removal",
    ]
    unconditional_allow_claims = [
        "authorizes Syncthing removal",
        "remove Syncthing",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase6_syncthing_shadow_packet_requires_downstream_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md",
        "records downstream receiver PASS",
        "direct HTTPS evidence includes receipt summaries",
        "`source_claim`, `common_ingested_events`, projection, summary, and quarantine reconciliation",
        "downstream evidence proves today, past lookup, trace, summary, and export totals",
        "Syncthing/archive owner identifies the exact legacy archive folder",
        "DB owner approves source-claim and projection reconciliation queries",
        "app owner confirms the deployed conflict/idempotency policy",
        "rollback owner confirms the legacy Syncthing/archive path remains available",
        "change coordinator confirms test window",
    ]

    assert [item for item in required if item not in text] == []


def test_phase6_syncthing_shadow_packet_binds_direct_legacy_conflict_scope():
    text = _packet_text()

    required = [
        "Direct path",
        "Legacy path",
        "Conflict path",
        "`source_claim_history`",
        "Projection parity",
        "Downstream parity",
        "Rollback availability",
        "same source artifact hash",
        "authoritative path",
        "duplicate path was idempotent, ignored, or quarantined",
        "counted once per source event",
    ]

    assert [item for item in required if item not in text] == []


def test_phase6_syncthing_shadow_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries and hashes in `07_syncthing_shadow_no_double_count`.",
        "direct HTTPS receipt evidence",
        "Syncthing/archive observation",
        "`source_claim` and `source_claim_history` evidence",
        "common_ingested_events",
        "projection, summary, quarantine",
        "downstream today/past/trace/summary/export evidence",
        "rollback availability note",
        "Exactly one authoritative `source_claim` outcome",
        "Common event, projection, summary, and downstream totals remain counted once.",
        "Syncthing/archive remains available and unchanged for rollback.",
        "HTTPS direct and Syncthing/archive paths double count",
        "Syncthing config, folder registration, service, or scheduled task state changes",
    ]

    assert [item for item in required if item not in text] == []


def test_phase6_syncthing_shadow_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md`",
        "legacy archive path observation",
        "no config mutation",
        "direct-vs-archive conflict policy",
        "`source_claim`, `source_claim_history`",
        "direct HTTPS receipt evidence",
        "Syncthing/archive observation",
        "authoritative path",
        "duplicate classification",
        "downstream today/past/trace/summary/export evidence showing unchanged single-count totals",
        "rollback availability note",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload outside the approved staging/test window",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
