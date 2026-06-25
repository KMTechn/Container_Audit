from pathlib import Path


REPORT = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "OPERATIONAL_DB_READONLY_AUDIT_20260625.md"
)


def _report_text() -> str:
    return REPORT.read_text(encoding="utf-8")


def test_operational_db_audit_records_readonly_boundary_and_identity():
    text = _report_text()

    required = [
        "Read-only SSH and HTTPS health checks only",
        "mode=ro",
        "PRAGMA query_only=ON",
        "7918022656",
        "OPTIONS 200",
        "Allow: OPTIONS, POST",
        "schema_identity_sha256",
        "3e9ff097ba41af445d37cee9806250c8cb86f4cc4dffced793ba9b3376d942d2",
        "worker-analysis.service",
        "worker-csv-sync.timer",
        "Server-Local Ops Status Cross-Check",
        "direct_sync_ops_status.py",
        "status=BLOCKED",
        "read_only=true",
    ]

    assert [item for item in required if item not in text] == []


def test_operational_db_audit_records_counts_and_missing_direct_sync_tables():
    text = _report_text()

    required = [
        "`sessions` | `55745`",
        "`raw_events` | `1982276`",
        "`common_ingested_events` | `11`",
        "`common_event_quarantine` | `3`",
        "`producer_ingest_receipts` | `MISSING`",
        "`producer_ingest_nonces` | `MISSING`",
        "`producer_ingest_raw_artifacts` | `MISSING`",
        "`source_claim` | `MISSING`",
        "`transfer_legacy_projection` | `MISSING`",
        "`process_state_summary_sources` | `MISSING`",
        "deployed helper missing tables: `producer_ingest_receipts`, `producer_ingest_nonces`, `source_claim`, `defect_hmac_chain_state`",
        "common projection counts match the manual audit: `common_ingested_events=11`, `common_event_quarantine=3`",
    ]

    assert [item for item in required if item not in text] == []


def test_operational_db_audit_records_ingest_health_blocker_and_write_flag_risk():
    text = _report_text()

    required = [
        "PLAN_C_ROLLOUT_GATE_BLOCKED",
        "common_projection_schema=healthy",
        "schema_ready=true",
        "schema_ready=false` for deployed direct-sync ops status",
        "COMMON_INGEST_WRITE_ENABLED=true",
        "blocked_pending_promotion_evidence",
        "missing_promotion_evidence_bundle",
        "confirms common projection readiness, not full producer direct-sync readiness",
        "not ready for `Container_Audit` HTTPS direct ingest",
        "Deployment parity note",
        "Operating server repo reports `HEAD=f4bbbd9`",
        "deployed `scripts/direct_sync_ops_status.py` SHA-256 is `c5b7020a1d5788ed0e7d8690c2fe21e9bf1469735bbaff007389725a153c7ea0`",
        "expanded, uncommitted `scripts/direct_sync_ops_status.py` SHA-256 beginning `BD1A79FEA0CA7C7B...`",
        "server helper's `BLOCKED` result is sufficient to stop upload, but not sufficient to prove all direct-sync schema gaps are enumerated",
    ]

    assert [item for item in required if item not in text] == []


def test_operational_db_audit_preserves_no_live_write_cutover_decision():
    text = _report_text()

    required = [
        "No producer upload POST",
        "no production DB write",
        "no schema migration",
        "Do not run real `Container_Audit` producer upload",
        "Do not remove Syncthing",
        "The FQDN HTTPS producer route is exposed by `OPTIONS 200`",
        "no authenticated POST/HMAC/nonce/idempotency/receipt path was executed",
        "Create and verify a backup or snapshot",
        "Run additive schema migration only inside an approved rollback/change window",
        "keep producer upload disabled",
        "Local Additive Remediation Proof",
        "tests\\test_operational_db_additive_schema_remediation.py",
        "operational remediation fixture: `1 passed`",
        "related WorkerAnalysisGUI-web schema/ops gate: `8 passed`",
        "The deployed server-local ops helper also returns `BLOCKED`",
    ]

    assert [item for item in required if item not in text] == []
