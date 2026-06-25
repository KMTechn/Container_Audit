from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "06_downstream_today_past_export"
    / "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def test_phase5_downstream_packet_preserves_no_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "does not authorize producer POST upload",
        "HMAC secret disclosure",
        "credential issue/rotation/revocation",
        "service or scheduled task changes",
        "schema `--execute`",
        "production DB mutation",
        "rollback rehearsal",
        "Syncthing mutation",
        "Syncthing removal",
        "raw receipt JSON",
        "full raw payloads",
    ]
    unconditional_allow_claims = [
        "authorizes Syncthing removal",
        "remove Syncthing",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase5_downstream_packet_requires_ingest_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md",
        "records 20-PC concurrency PASS",
        "explicitly narrows the review to Phase 3 one-PC canary evidence",
        "server receipts, `source_claim`, `common_ingested_events`, projection, summary, and quarantine deltas reconcile",
        "downstream owner approves the exact target",
        "DB owner approves read-only reconciliation queries",
        "app owner identifies the deployed downstream build/version",
        "field operator provides the source PC list",
        "security owner approves screenshot/export redaction",
        "rollback owner confirms Syncthing/archive remains available",
        "change coordinator confirms date/time window",
    ]

    assert [item for item in required if item not in text] == []


def test_phase5_downstream_packet_binds_today_past_trace_summary_export_scope():
    text = _packet_text()

    required = [
        "Today view",
        "Past lookup",
        "Trace",
        "`receipt_id`",
        "`server_source_file_id`",
        "`source_claim`",
        "`source_host_id`",
        "`producer_install_id`",
        "raw artifact hash",
        "source CSV hash",
        "transfer summary quantities match accepted source CSV product quantity counts",
        "do not mix packaging `TRAY_COMPLETE` with Container_Audit legacy transfer events",
        "exported CSV/XLSX/JSON row count",
        "Error/quarantine view",
        "Malicious-string rendering",
    ]

    assert [item for item in required if item not in text] == []


def test_phase5_downstream_packet_defines_evidence_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "Store only redacted summaries, screenshots, exports, and hashes in `06_downstream_today_past_export`.",
        "downstream target identity",
        "today view screenshot or exported API JSON",
        "past lookup screenshot or exported API JSON",
        "trace evidence linking downstream row to receipt",
        "summary evidence comparing downstream quantities with receipt totals",
        "export evidence: file name, SHA-256, row count",
        "malicious-string rendering evidence",
        "Syncthing/archive observation showing legacy path data is not double counted",
        "Today view totals match",
        "Past lookup returns the same records",
        "Trace resolves every sampled downstream row",
        "Container_Audit legacy transfer events are not mixed",
        "Malicious strings render as inert text",
        "Downstream totals differ from receipt totals",
        "Trace cannot resolve",
    ]

    assert [item for item in required if item not in text] == []


def test_phase5_downstream_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md`",
        "WorkerAnalysisGUI-web URL or actual receiving program",
        "today view",
        "past lookup",
        "trace",
        "summary",
        "export workflow",
        "DB identity hash",
        "source roster with PC identities",
        "trace evidence linking downstream row to receipt, source_claim, source PC identity, raw artifact hash, and source CSV hash",
        "export evidence with file name, SHA-256, row count",
        "Syncthing/archive observation proving no downstream double count",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST upload",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
