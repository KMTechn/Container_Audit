from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "09_operator_visibility"
    / "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase8_operator_visibility_packet_preserves_no_execution_boundary():
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


def test_phase8_operator_visibility_packet_requires_rollback_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md",
        "records rollback rehearsal PASS",
        "controlled fault-status evidence only",
        "app owner identifies the relay status command",
        "field/operator owner identifies the operator accounts",
        "DB owner approves read-only queue/count reconciliation",
        "downstream owner approves the status-to-dashboard trace checks",
        "rollback owner confirms the report displays whether legacy Syncthing/archive-compatible analysis is available",
        "security owner approves screenshot and JSON redaction rules",
        "change coordinator confirms evidence directory",
    ]

    assert [item for item in required if item not in text] == []


def test_phase8_operator_visibility_packet_binds_status_report_failure_scope():
    text = _packet_text()

    required = [
        "Healthy state",
        "Retryable network/server fault",
        "Credential/key fault",
        "DNS/TLS/proxy fault",
        "Disk/spool/status corruption",
        "Operator-review rows",
        "Downstream trace",
        "Rollback visibility",
        "last failure",
        "next retry time",
        "operator-review path",
        "dead-letter path",
        "legacy Syncthing/archive-compatible analysis is available",
    ]

    assert [item for item in required if item not in text] == []


def test_phase8_operator_visibility_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries and hashes in `09_operator_visibility`.",
        "healthy state evidence",
        "retryable fault evidence",
        "credential fault evidence",
        "DNS/TLS/proxy fault evidence",
        "disk/spool/status corruption evidence",
        "operator-review evidence",
        "downstream trace evidence",
        "rollback visibility evidence",
        "Operator can identify the latest upload success",
        "Queue, pending, retryable, dead-letter, operator-review, accepted receipt, quarantine, projection, and summary counts reconcile",
        "Status/report lacks last failure",
        "Operator cannot diagnose the failure reason and next owner action",
    ]

    assert [item for item in required if item not in text] == []


def test_phase8_operator_visibility_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md`",
        "field/operator owner signoff",
        "status/report",
        "runtime status path",
        "queue DB path",
        "receipt summary path",
        "DB owner read-only reconciliation query bundle",
        "healthy state evidence",
        "retryable fault evidence",
        "credential fault evidence",
        "DNS/TLS/proxy fault evidence",
        "disk/spool/status corruption evidence",
        "operator-review evidence",
        "downstream trace evidence",
        "rollback visibility evidence",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
