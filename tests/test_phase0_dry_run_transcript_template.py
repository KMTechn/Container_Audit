from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs" / "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "00_freeze_manifest"
    / "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE.md"
)


def _template_text() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_phase0_dry_run_template_binds_approval_and_command_packet_refs():
    text = _template_text()

    required = [
        "docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        "docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        "`APP` | `/root/WorkerAnalysisGUI-web`",
        "`DB` | `/mnt/rebuild/worker-analysis/data/worker_analysis.db`",
        "approved FQDN | `https://worker.kmtecherp.com`",
        "route checked | `OPTIONS /api/producer-ingest/v1/source-file`",
        "evidence directory",
        "local packet scaffold",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_dry_run_template_requires_pre_run_confirmation():
    text = _template_text()

    required = [
        "Pre-Run Confirmation",
        "All required owner signoff entries are present.",
        "Evidence directory is fresh and empty before command output.",
        "`APP`, `DB`, FQDN, route, and evidence root match the approved checklist.",
        "No producer credential, HMAC secret, bearer token, raw receipt JSON, or full raw payload is needed.",
        "Stop before command execution if any pre-run check fails.",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_dry_run_template_covers_every_readonly_artifact_row():
    text = _template_text()

    required = [
        "Command Result Transcript",
        "`direct_sync_ops_status.before.json`",
        "`health.before.json`",
        "`health_ingest.before.json`",
        "`producer_ingest_options.before.txt`",
        "`db.sha256.before.txt`",
        "`db_readonly_counts.before.json`",
        "`redaction_check.before.json`",
        "`phase0_artifact_hashes.sha256`",
        "SQLite `mode=ro` and `PRAGMA query_only=ON`",
        "OPTIONS 200 with `Allow: OPTIONS, POST`",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_dry_run_template_blocks_later_phase_authority():
    text = _template_text()

    required = [
        "does not authorize producer POST upload",
        "schema `--execute`",
        "DB write/update/delete",
        "credential lifecycle operations",
        "service or scheduled task changes",
        "relay pause/resume",
        "Syncthing mutation",
        "rollback rehearsal",
        "20-PC run",
        "Syncthing removal",
        "phase0_readonly_pass",
        "phase0_blocked_before_mutation",
        "later Phase 1 work still requires separate approval",
    ]
    unconditional_allow_claims = [
        "authorizes producer POST",
        "authorizes DB migration",
        "authorizes Syncthing removal",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase0_dry_run_template_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md`",
        "run metadata with change id",
        "owner checklist reference and command packet reference",
        "command result transcript rows",
        "`direct_sync_ops_status.before.json`",
        "`phase0_artifact_hashes.sha256`",
        "`phase0_readonly_pass` or `phase0_blocked_before_mutation`",
        "does not authorize producer POST",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
