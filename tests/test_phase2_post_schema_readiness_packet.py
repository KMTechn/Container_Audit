from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "02_post_schema_readiness"
    / "PHASE2_POST_SCHEMA_READINESS_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def _bash_block() -> str:
    text = _packet_text()
    match = re.search(r"```bash\n(?P<body>.*?)\n```", text, flags=re.S)
    assert match is not None
    return match.group("body")


def test_phase2_post_schema_packet_preserves_readonly_boundary():
    text = _packet_text()

    required = [
        "read-only Phase 2 checks",
        "This packet does not authorize schema `--execute`, producer POST upload, authenticated HMAC canary",
        "credential lifecycle operations",
        "service or scheduled task changes",
        "relay pause/resume",
        "20-PC run",
        "Syncthing removal",
        "They must not send producer data and must not mutate DB schema or service state.",
    ]
    unconditional_allow_claims = [
        "authorizes producer POST",
        "authorizes Syncthing removal",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase2_post_schema_packet_requires_phase1_success_prerequisites():
    text = _packet_text()

    required = [
        "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md",
        "`apply_additive_schema_report.json` exists and records `status=PASS`",
        "`backup_created=true`",
        "`actual_db_sha256_before` equals the owner-approved `EXPECTED_DB_SHA256`",
        "backup DB file path and backup DB SHA-256 are archived",
        "legacy row counts were not reduced by Phase 1",
        "DB owner and app owner confirm the same `DB` and `BACKUP_DIR` values",
    ]

    assert [item for item in required if item not in text] == []


def test_phase2_post_schema_packet_collects_required_readonly_artifacts():
    block = _bash_block()

    required = [
        "cd /root/WorkerAnalysisGUI-web",
        "DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db",
        "BACKUP_DIR=<approved Phase 1 backup directory>",
        "scripts/direct_sync_ops_status.py --db \"$DB\"",
        "--report-path \"$BACKUP_DIR/direct_sync_ops_status.after.json\"",
        "https://worker.kmtecherp.com/health/ingest",
        "post_schema_readonly_counts.after.json",
        "sqlite3.connect(f\"file:{db}?mode=ro\", uri=True)",
        "PRAGMA query_only=ON",
        "producer_ingest_receipts",
        "producer_ingest_nonces",
        "source_claim",
        "post_schema_readiness_hashes.sha256",
    ]
    forbidden = ["-X POST", "--execute", "plan_c_apply_additive_schema.py", "systemctl", "service "]

    assert [item for item in required if item not in block] == []
    assert [item for item in forbidden if item.lower() in block.lower()] == []


def test_phase2_post_schema_packet_defines_pass_and_stop_gates():
    text = _packet_text()

    required = [
        "PASS Criteria",
        "`direct_sync_ops_status.after.json` reports `schema_ready=true`",
        "`missing_tables=[]`",
        "`missing_columns={}`",
        "`producer_ingest_receipts`, `producer_ingest_nonces`, and `source_claim` counts are still `0` before any canary",
        "remaining promotion/canary evidence blocker may be recorded for Phase 3",
        "Stop Conditions",
        "`schema_ready` is false",
        "`missing_tables` or `missing_columns` is non-empty",
        "counts are non-zero before canary",
        "schema absence blocker after Phase 1",
    ]

    assert [item for item in required if item not in text] == []


def test_phase2_post_schema_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md`",
        "`direct_sync_ops_status.after.json`",
        "`health_ingest.after.json`",
        "`post_schema_readonly_counts.after.json`",
        "`post_schema_readiness_hashes.sha256`",
        "`schema_ready=true`, `missing_tables=[]`, and `missing_columns={}`",
        "counts are zero before any canary",
        "does not authorize producer POST",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
