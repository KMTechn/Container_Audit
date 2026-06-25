from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "01_schema_backup_and_apply"
    / "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def _bash_block() -> str:
    text = _packet_text()
    match = re.search(r"```bash\n(?P<body>.*?)\n```", text, flags=re.S)
    assert match is not None
    return match.group("body")


def test_phase1_schema_packet_preserves_non_execution_boundary():
    text = _packet_text()

    required = [
        "This document is not execution approval.",
        "Do not run schema `--execute`, producer POST, credential lifecycle operations, service or scheduled task changes",
        "Syncthing mutation",
        "Syncthing removal",
        "The following command is the exact mutation shape to review.",
        "It must not be run until the owners above explicitly approve Phase 1 execution",
    ]
    unconditional_allow_claims = [
        "authorizes producer POST",
        "authorizes Syncthing removal",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase1_schema_packet_requires_phase0_and_owner_prerequisites():
    text = _packet_text()

    required = [
        "PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        "PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md",
        "`phase0_readonly_pass`",
        "`phase0_blocked_before_mutation` resolution",
        "`phase0_artifact_hashes.sha256` and `db.sha256.before.txt` are archived",
        "DB owner",
        "App owner",
        "Rollback owner",
        "Downstream owner",
        "Security owner",
        "Change coordinator",
    ]

    assert [item for item in required if item not in text] == []


def test_phase1_schema_packet_reviews_exact_hash_checked_command_shape():
    block = _bash_block()

    required = [
        "cd /root/WorkerAnalysisGUI-web",
        "DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db",
        "BACKUP_DIR=/mnt/rebuild/worker-analysis/backups/direct-sync-schema-$STAMP",
        "mkdir -p \"$BACKUP_DIR\"",
        "EXPECTED_DB_SHA256=$(sha256sum \"$DB\" | awk '{print $1}')",
        "python3 scripts/plan_c_apply_additive_schema.py",
        "--db-path \"$DB\"",
        "--execute",
        "--expected-db-sha256 \"$EXPECTED_DB_SHA256\"",
        "--backup-dir \"$BACKUP_DIR\"",
        "--report-path \"$BACKUP_DIR/apply_additive_schema_report.json\"",
    ]

    assert [item for item in required if item not in block] == []


def test_phase1_schema_packet_defines_evidence_and_stop_conditions():
    text = _packet_text()

    required = [
        "01_schema_backup_and_apply",
        "`expected_db_sha256.txt`",
        "`backup_dir.txt`",
        "`apply_additive_schema_report.json`",
        "`status=PASS`",
        "`backup_created=true`",
        "`actual_db_sha256_before` equals `EXPECTED_DB_SHA256`",
        "legacy row counts are not reduced",
        "Stop Conditions",
        "Any required owner signoff is missing.",
        "unresolved `phase0_blocked_before_mutation`",
        "`EXPECTED_DB_SHA256` does not match `db.sha256.before.txt`",
        "App owner cannot confirm script hash/version.",
    ]

    assert [item for item in required if item not in text] == []


def test_phase1_schema_packet_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md`",
        "DB owner signoff",
        "App owner signoff",
        "Rollback owner signoff",
        "Security owner signoff",
        "reference to filled Phase 0 transcript",
        "`apply_additive_schema_report.json`",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
