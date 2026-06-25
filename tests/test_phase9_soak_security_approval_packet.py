from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "10_soak_and_security"
    / "PHASE9_SOAK_SECURITY_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase9_soak_security_packet_preserves_no_execution_boundary():
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


def test_phase9_soak_security_packet_requires_phase8_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md",
        "records operator visibility PASS",
        "app owner approves the staging/test endpoint",
        "security owner approves the credential lifecycle plan",
        "field/operator owner approves the PC set",
        "DB owner approves read-only reconciliation queries",
        "downstream owner approves today view, past lookup, trace, summary, export",
        "rollback owner confirms abort criteria",
        "change coordinator confirms run window",
    ]

    assert [item for item in required if item not in text] == []


def test_phase9_soak_security_packet_binds_all_p1_security_and_soak_scope():
    text = _packet_text()

    required = [
        "Producer credential lifecycle",
        "valid key",
        "wrong key",
        "revoked key",
        "expired key",
        "Clock drift",
        "HMAC timestamp outside accepted window",
        "Malicious input",
        "SQL, XSS, formula, and path traversal strings",
        "Fault injection",
        "server 500/503",
        "DNS failure",
        "TLS/certificate failure",
        "DB lock",
        "spool corruption",
        "Soak",
        "at least 4-8 hours or full-day-volume equivalent",
        "CPU/memory sampling",
    ]

    assert [item for item in required if item not in text] == []


def test_phase9_soak_security_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries and hashes in `10_soak_and_security`.",
        "credential lifecycle evidence",
        "clock drift evidence",
        "malicious input evidence",
        "fault injection evidence",
        "soak metrics",
        "downstream evidence",
        "rollback/abort evidence",
        "Valid producer credentials write exactly once",
        "Malicious SQL, XSS, formula, and path traversal strings remain inert data",
        "Queue depth, DB size, memory, CPU, or log size grows without bound during soak",
        "Wrong, revoked, expired, duplicated, or rotated-out credentials can create receipt",
    ]

    assert [item for item in required if item not in text] == []


def test_phase9_soak_security_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md`",
        "app owner command bundle",
        "security owner checklist",
        "field/operator roster",
        "DB owner read-only reconciliation query bundle",
        "downstream target",
        "rollback owner abort criteria",
        "credential lifecycle evidence",
        "clock drift evidence",
        "malicious input evidence",
        "fault injection evidence",
        "soak metrics",
        "dashboard browser XSS",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
