from pathlib import Path


REPORT = Path(__file__).resolve().parents[1] / "docs" / "LOCAL_AUDIT_READINESS_REPORT_20260624.md"


def _report_text() -> str:
    return REPORT.read_text(encoding="utf-8")


def test_local_readiness_report_records_latest_local_and_downstream_gates():
    text = _report_text()

    required = [
        "Latest Container_Audit suite: `797 passed, 1 warning`",
        "WorkerAnalysisGUI-web downstream targeted gate: `187 passed`",
        "Local/headless verification status: PASS",
        "Company server read-only precheck",
        "FQDN HTTPS producer route `OPTIONS` returns 200",
        "no POST/HMAC/nonce/idempotency/receipt path was tested",
        "`/health/ingest` remains 503 blocked by promotion evidence",
        "Operational DB read-only audit",
        "legacy dashboard DB is live and healthy",
        "`producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `transfer_legacy_projection`, and `process_state_summary_sources` are missing",
        "deployed `direct_sync_ops_status.py` also reports `BLOCKED`",
        "Release config precheck",
        "current workspace `config` is not release-ready because `config\\parked_trays` is runtime-local",
        "tools\\build_release_config.py",
        "generated release config PASS",
        "production cutover is not approved from local evidence alone",
    ]

    assert [item for item in required if item not in text] == []


def test_local_readiness_report_covers_core_improvement_areas():
    text = _report_text()

    required = [
        "Human workflow map",
        "Field runbook",
        "Pre-production validation matrix",
        "Durable completion event",
        "Multi-PC direct identity",
        "Same-file append integrity",
        "Runtime/operator visibility",
        "Downstream web receiver",
        "20-PC virtual concurrency",
        "Local received data and injection security",
        "Company server read-only precheck",
        "Operational DB read-only audit",
        "Operational change-window runbook",
        "Phase 0 preflight command packet",
        "Phase 0 execution inputs manifest",
        "Phase 0 execution input checker",
        "Phase 0 owner approval checklist",
        "Phase 0 dry-run transcript template",
        "Phase 1 additive schema approval packet",
        "Phase 2 post-schema readiness packet",
        "Phase 3 one-PC canary approval packet",
        "Phase 4 20-PC concurrency approval packet",
        "Phase 5 downstream receiver approval packet",
        "Phase 6 Syncthing shadow approval packet",
        "Phase 7 rollback rehearsal approval packet",
        "Phase 8 operator visibility approval packet",
        "Phase 9 soak/security approval packet",
        "Phase 10 final signoff approval packet",
        "Three-agent production cutover plan",
        "Production evidence packet scaffold",
        "Final local consistency audit",
        "Release config hardening",
        "Dashboard XSS static hardening",
    ]

    assert [item for item in required if item not in text] == []


def test_local_readiness_report_preserves_production_evidence_boundary():
    text = _report_text()

    required = [
        "Live POST upload, production HTTPS endpoint mutation, production DB mutation, scheduled-task apply: not executed",
        "no POST upload executed",
        "`C:\\Sync` not registered in Syncthing config",
        "FQDN HTTPS producer route `OPTIONS 200`",
        "IP HTTPS trust/path not approved",
        "`/health/ingest` 503 blocked by promotion evidence",
        "missing producer receipt/nonce/raw artifact/source_claim/transfer projection tables",
        "no POST/write/migration boundary",
        "Dual-run no-double-count proof",
        "Server receipt totals matching CSV row counts",
        "Rollback rehearsal",
        "20-PC external edge evidence",
        "dashboard XSS rendering evidence",
        "snapshot `/mnt/rebuild/worker-analysis/data/worker_analysis.db`",
        "approved additive schema migration",
        "PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        "PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md",
        "PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md",
        "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md",
        "PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md",
        "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md",
        "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md",
        "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md",
        "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md",
        "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md",
        "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md",
        "PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md",
        "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md",
        "DB/app/field/security/downstream/rollback/change-coordinator signoff",
        "phase0_readonly_pass`/`phase0_blocked_before_mutation",
        "exact `APP`, `DB`, FQDN, route, evidence root, redaction policy",
        "tools/check_phase0_execution_inputs.py",
        "DB/app/rollback/downstream/security/change packet",
        "before schema `--execute`",
        "direct_sync_ops_status.after.json",
        "zero pre-canary receipt/nonce/source-claim counts",
        "credential/field/DB/app/downstream/rollback/change packet",
        "HMAC timestamp/nonce/idempotency evidence",
        "server receipt summary",
        "at least 20 distinct PC identities",
        "same Korean filename",
        "queue restart/resume",
        "DB reconciliation",
        "today view",
        "past lookup",
        "export checksum",
        "malicious-string rendering",
        "source_claim_history",
        "projection parity",
        "rollback availability",
        "no Syncthing config/folder/service mutation",
        "relay pause/resume",
        "scheduled task/service stop/start",
        "HTTPS failure fallback",
        "CSV/archive/spool/queue preservation",
        "retryable/permanent class",
        "dead-letter/operator-review rows",
        "rollback visibility",
        "valid/wrong/revoked/expired credentials",
        "clock drift",
        "malicious SQL/XSS/formula/path traversal corpus",
        "4-8 hour/full-day-volume soak metrics",
        "evidence archive hash",
        "backup/retention PASS",
        "release package PASS",
        "dashboard browser XSS PASS",
        "`production_removal_ready=true`",
        "does not approve schema apply, canary POST, 20-PC run, shadow run, rollback, or Syncthing retirement",
        "SQLite `mode=ro`/`query_only` counts",
        "THREE_AGENT_PRODUCTION_CUTOVER_PLAN_20260625.md",
        "tools/build_production_evidence_packet.py",
        "Phase 0-10 approval packet placeholders",
        "production-cutover-packet-v5-20260625",
        "final evidence archive hash",
        "Syncthing retirement gate",
        "READY_TO_RUN with approval",
        "hash-checked backup",
        "authenticated HTTPS canary",
        "hard stop conditions",
        "build config package without `config\\parked_trays`",
        "static/dashboard.js`",
        "not sufficient to remove Syncthing from production",
    ]

    assert [item for item in required if item not in text] == []


def test_local_readiness_report_lists_stop_conditions():
    text = _report_text()

    required = [
        "duplicated CSV header",
        "mismatched `source_host_id`",
        "Runtime/operator status cannot explain",
        "Server receipt totals do not match source row count",
        "double count the same source event",
        "direct-sync ops status reports missing producer/source-claim tables",
        "no authenticated HTTPS receipt path is available",
        "Operational DB is missing producer receipt/nonce/raw artifact/source_claim/projection tables",
        "COMMON_INGEST_WRITE_ENABLED=true",
        "Release config checker fails",
    ]

    assert [item for item in required if item not in text] == []
