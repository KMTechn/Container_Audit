from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "08_rollback_rehearsal"
    / "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase7_rollback_packet_preserves_no_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "does not authorize producer POST upload",
        "HMAC secret disclosure",
        "credential issue/rotation/revocation",
        "relay pause/resume",
        "service stop/start",
        "scheduled task changes",
        "HTTPS failure injection",
        "schema `--execute`",
        "production DB mutation",
        "Syncthing config changes",
        "Syncthing folder removal",
        "Syncthing removal",
    ]
    unconditional_allow_claims = [
        "authorizes Syncthing removal",
        "remove Syncthing",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase7_rollback_packet_requires_shadow_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md",
        "records Syncthing shadow no-double-count PASS",
        "accepted records are counted once and legacy path remains available",
        "rollback owner approves the rollback window",
        "app owner identifies the relay process",
        "Windows/operator owner identifies scheduled task or service names",
        "Syncthing/archive owner identifies the legacy archive path",
        "DB owner approves read-only before/after reconciliation queries",
        "downstream owner approves the legacy-path verification screen/program",
        "change coordinator confirms evidence directory",
    ]

    assert [item for item in required if item not in text] == []


def test_phase7_rollback_packet_binds_pause_stop_fallback_resume_scope():
    text = _packet_text()

    required = [
        "Relay pause",
        "Scheduled task/service stop",
        "HTTPS failure fallback",
        "CSV/archive preservation",
        "Resume",
        "Downstream rollback verification",
        "Operator visibility",
        "source CSV",
        "event CSV",
        "relay spool",
        "queue DB",
        "parked tray files",
        "archive files",
    ]

    assert [item for item in required if item not in text] == []


def test_phase7_rollback_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries and hashes in `08_rollback_rehearsal`.",
        "relay pause evidence",
        "scheduled task/service stop evidence",
        "HTTPS failure/fallback evidence",
        "CSV/archive preservation evidence",
        "queued upload resume evidence",
        "DB reconciliation evidence",
        "downstream evidence",
        "operator report",
        "Relay pause is visible in operator status",
        "Scheduled task/service stop affects only the approved target",
        "Legacy Syncthing/archive-compatible path remains available",
        "Queued uploads resume and drain without duplicate receipt",
        "Relay pause/resume, task/service stop/start, or HTTPS failure injection targets the wrong process",
        "Queued uploads do not resume",
    ]

    assert [item for item in required if item not in text] == []


def test_phase7_rollback_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md`",
        "rollback owner signoff",
        "relay pause/resume",
        "task/service roster",
        "legacy path verification",
        "relay pause evidence",
        "scheduled task/service stop evidence",
        "HTTPS failure/fallback evidence",
        "CSV/archive preservation evidence",
        "queued upload resume evidence",
        "DB reconciliation for receipt, raw artifact, source_claim, common event, projection, summary, and quarantine counts",
        "downstream today/past/trace/summary/export totals",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
