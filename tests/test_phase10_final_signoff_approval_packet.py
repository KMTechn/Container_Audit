from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "11_final_signoff"
    / "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase10_final_signoff_packet_preserves_no_execution_boundary():
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
        "remove Syncthing now",
        "retire Syncthing now",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase10_final_signoff_packet_requires_all_phase_and_owner_evidence():
    text = _packet_text()

    required = [
        "Phase 0 through Phase 9 packets record PASS",
        "evidence archive hash is computed",
        "backup/retention owner approves retention periods",
        "release owner approves final package hash",
        "downstream owner approves dashboard browser XSS evidence",
        "rollback owner approves rollback rehearsal PASS",
        "security owner approves credential lifecycle evidence",
        "DB owner approves receipt, nonce, raw artifact, source_claim",
        "field/operator owner approves field UI/scanner, 20-PC concurrency, operator visibility, and soak evidence",
        "change coordinator confirms all hard stops are cleared",
    ]

    assert [item for item in required if item not in text] == []


def test_phase10_final_signoff_packet_binds_retirement_flags_to_hard_gates():
    text = _packet_text()

    required = [
        "`promotion_allowed=true` may be set only when every required Phase 0-10 evidence item is present",
        "`production_removal_ready=true` may be set only after `promotion_allowed=true`",
        "Syncthing shadow no-double-count PASS",
        "20-PC ingest PASS",
        "downstream totals PASS",
        "rollback PASS",
        "operator report PASS",
        "soak/security PASS",
        "backup/retention PASS",
        "release package PASS",
        "dashboard browser XSS PASS",
        "Syncthing/archive owner signoff",
        "exact Syncthing retirement action",
        "post-retirement verification commands",
    ]

    assert [item for item in required if item not in text] == []


def test_phase10_final_signoff_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Final Evidence Checklist",
        "backup/retention PASS",
        "release package PASS",
        "dashboard browser XSS PASS",
        "Every Phase 0-9 packet has PASS evidence",
        "Source CSV rows, accepted receipts, quarantines, errors, source_claim rows",
        "Release package/config evidence proves no local/dev endpoint",
        "Syncthing shadow and rollback evidence proves the legacy path remains available",
        "Any Phase 0-9 packet is missing, unsigned, stale, failed",
        "Evidence archive hash is missing",
        "Syncthing removal would happen before shadow no-double-count",
    ]

    assert [item for item in required if item not in text] == []


def test_phase10_final_signoff_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md`",
        "final owner signoff record",
        "evidence archive hash",
        "Phase 0 read-only preflight PASS",
        "Phase 4 20-PC concurrency PASS",
        "Phase 6 Syncthing shadow PASS",
        "Phase 9 soak/security PASS",
        "backup/retention PASS",
        "release package PASS",
        "dashboard browser XSS PASS",
        "`promotion_allowed=true` owner signature only after all evidence is present",
        "`production_removal_ready=true` owner signature only after Syncthing retirement gate passes",
        "exact Syncthing retirement action",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
