from pathlib import Path


RUNBOOK = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "OPERATIONAL_CHANGE_WINDOW_RUNBOOK_20260625.md"
)


def _text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_change_window_runbook_preserves_production_safety_boundary():
    text = _text()

    required = [
        "This runbook is a prepared procedure. It was not executed against production.",
        "Do not run the `--execute`, service stop/start, credential issue, producer POST, or Syncthing change steps",
        "Do not paste raw HMAC secrets",
        "Use FQDN HTTPS for external producer testing",
        "Do not use raw IP HTTPS or internal HTTP 8089 as the external cutover target",
    ]

    assert [item for item in required if item not in text] == []


def test_change_window_runbook_has_readonly_preflight_and_backup_gates():
    text = _text()

    required = [
        "Phase 0: Read-Only Preflight",
        "python3 scripts/direct_sync_ops_status.py --db \"$DB\"",
        "curl -sS -i -X OPTIONS https://worker.kmtecherp.com/api/producer-ingest/v1/source-file",
        "backup_space_ok",
        "Free disk space is at least two DB sizes",
        "Phase 1: Backup And Additive Schema",
        "EXPECTED_DB_SHA256=$(sha256sum \"$DB\"",
        "scripts/plan_c_apply_additive_schema.py",
        "--expected-db-sha256 \"$EXPECTED_DB_SHA256\"",
        "backup_created=true",
    ]

    assert [item for item in required if item not in text] == []


def test_change_window_runbook_requires_post_schema_and_canary_reconciliation():
    text = _text()

    required = [
        "Phase 2: Post-Schema Readiness",
        "schema_ready=true",
        "missing_tables=[]",
        "missing_columns={}",
        "direct receipt, nonce, and source claim counts are still `0` before canary",
        "Phase 3: Authenticated HTTPS Canary",
        "nonce stored exactly once",
        "idempotency replay returns stored receipt",
        "raw artifact saved and content hash matches source CSV",
        "source_claim row created",
        "transfer projection and summary totals match",
    ]

    assert [item for item in required if item not in text] == []


def test_change_window_runbook_keeps_shadow_rollback_and_stop_conditions():
    text = _text()

    required = [
        "Phase 4: Shadow And Rollback Proof",
        "Keep Syncthing/archive enabled",
        "same source event through HTTPS and legacy archive is counted once",
        "queued HTTPS uploads resume without duplicate projection",
        "Hard Stop Conditions",
        "`expected_db_sha256` mismatch",
        "Any replay, Syncthing shadow row, or retry creates duplicate projection",
        "Any raw secret, HMAC key, receipt JSON, or raw payload appears",
        "Operator cannot explain last failure, next retry, and rollback state",
        "Local Rehearsal Evidence",
        "tests\\test_operational_db_additive_schema_remediation.py",
    ]

    assert [item for item in required if item not in text] == []
