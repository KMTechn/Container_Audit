from pathlib import Path


DOC = Path(__file__).resolve().parents[1] / "docs" / "PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_phase0_execution_inputs_manifest_pins_exact_runtime_inputs():
    text = _text()

    required = [
        "Phase 0 Execution Inputs Manifest",
        "PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        "PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        "`APP`",
        "`/root/WorkerAnalysisGUI-web`",
        "`DB`",
        "`/mnt/rebuild/worker-analysis/data/worker_analysis.db`",
        "`https://worker.kmtecherp.com`",
        "`OPTIONS /api/producer-ingest/v1/source-file`",
        "00_freeze_manifest/phase0-preflight",
        "phase0_execution_inputs.json",
        "tools\\check_phase0_execution_inputs.py",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_execution_inputs_manifest_preserves_no_mutation_boundary():
    text = _text()

    required = [
        "does not authorize producer POST",
        "authenticated HMAC canary",
        "schema `--execute`",
        "DB write",
        "credential lifecycle work",
        "service or scheduled task changes",
        "relay pause/resume",
        "Syncthing mutation",
        "rollback rehearsal",
        "20-PC run",
        "Syncthing removal",
        "The checker only validates the input packet",
        "It does not connect to the server",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_execution_inputs_manifest_lists_stop_conditions_and_redaction_rules():
    text = _text()

    required = [
        "Any owner in the approval checklist is missing",
        "check_phase0_execution_inputs.py --inputs-json phase0_execution_inputs.json",
        "Evidence directory exists and is not empty",
        "raw HMAC secret",
        "producer secret",
        "bearer token",
        "raw receipt JSON",
        "full source payload",
        "`POST /api/producer-ingest/v1/source-file`",
        "SQLite cannot be opened with `mode=ro` and `PRAGMA query_only=ON`",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_execution_inputs_manifest_defines_expected_artifacts_and_outcomes():
    text = _text()

    required = [
        "direct_sync_ops_status.before.json",
        "health.before.json",
        "health_ingest.before.json",
        "producer_ingest_options.before.txt",
        "db.sha256.before.txt",
        "db_readonly_counts.before.json",
        "redaction_check.before.json",
        "phase0_artifact_hashes.sha256",
        "phase0_execution_inputs.json checker PASS output",
        "phase0_readonly_pass",
        "phase0_blocked_before_mutation",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_execution_inputs_manifest_requires_separate_phase1_authority():
    text = _text()

    required = [
        "Phase 1 may be reviewed only after Phase 0 evidence is archived",
        "expected DB SHA-256",
        "Approved DB backup directory",
        "Script hash",
        "Credential material is handled outside the evidence archive",
        "Downstream owner baseline acceptance",
        "Phase 1 is a separate operation from Phase 0",
    ]

    assert [item for item in required if item not in text] == []
