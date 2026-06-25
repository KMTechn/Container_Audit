# Phase 2 Post-Schema Readiness Packet

작성일: 2026-06-25
대상: WorkerAnalysisGUI-web 운영 DB additive schema 적용 후 direct-sync readiness 검증

## Purpose

This packet defines the read-only Phase 2 checks to run after Phase 1 additive schema execution has been separately approved and completed.

This packet does not authorize schema `--execute`, producer POST upload, authenticated HMAC canary, credential lifecycle operations, service or scheduled task changes, relay pause/resume, rollback rehearsal, 20-PC run, Syncthing mutation, or Syncthing removal.

## Preconditions

Phase 2 may be run only after:

- `docs/PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md` is signed.
- `apply_additive_schema_report.json` exists and records `status=PASS`.
- `backup_created=true`.
- `actual_db_sha256_before` equals the owner-approved `EXPECTED_DB_SHA256`.
- backup DB file path and backup DB SHA-256 are archived.
- legacy row counts were not reduced by Phase 1.
- DB owner and app owner confirm the same `DB` and `BACKUP_DIR` values should be used for Phase 2 evidence.

## Read-Only Command Packet

The following commands collect post-schema readiness evidence only. They must not send producer data and must not mutate DB schema or service state.

```bash
set -euo pipefail

cd /root/WorkerAnalysisGUI-web
DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db
BACKUP_DIR=<approved Phase 1 backup directory>

python3 scripts/direct_sync_ops_status.py --db "$DB" \
  --report-path "$BACKUP_DIR/direct_sync_ops_status.after.json"

curl -sS https://worker.kmtecherp.com/health/ingest \
  > "$BACKUP_DIR/health_ingest.after.json" || true

python3 - <<'PY' > "$BACKUP_DIR/post_schema_readonly_counts.after.json"
from pathlib import Path
import json
import sqlite3

db = Path("/mnt/rebuild/worker-analysis/data/worker_analysis.db")
tables = [
    "producer_ingest_receipts",
    "producer_ingest_nonces",
    "producer_ingest_raw_artifacts",
    "source_claim",
    "source_claim_history",
    "transfer_legacy_projection",
    "packaging_set_projection",
    "process_state_summary_sources",
    "common_ingested_events",
    "common_event_quarantine",
]

out = {"table_counts": {}, "missing_tables": []}
conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
try:
    conn.execute("PRAGMA query_only=ON")
    existing = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    for table in tables:
        if table not in existing:
            out["missing_tables"].append(table)
            continue
        out["table_counts"][table] = conn.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        ).fetchone()[0]
finally:
    conn.close()

print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
PY

sha256sum "$BACKUP_DIR/direct_sync_ops_status.after.json" \
  "$BACKUP_DIR/health_ingest.after.json" \
  "$BACKUP_DIR/post_schema_readonly_counts.after.json" \
  > "$BACKUP_DIR/post_schema_readiness_hashes.sha256"
```

## PASS Criteria

- `direct_sync_ops_status.after.json` reports `schema_ready=true`.
- `missing_tables=[]`.
- `missing_columns={}`.
- `producer_ingest_receipts`, `producer_ingest_nonces`, and `source_claim` counts are still `0` before any canary.
- `post_schema_readonly_counts.after.json` has no missing direct-sync tables.
- `/health/ingest` has no unexpected schema blocker; a remaining promotion/canary evidence blocker may be recorded for Phase 3.
- `post_schema_readiness_hashes.sha256` hashes every Phase 2 output.
- No producer POST, HMAC secret, credential operation, service/task change, rollback rehearsal, 20-PC run, Syncthing mutation, or Syncthing removal occurs.

## Stop Conditions

Stop before Phase 3 if any item is true:

- `direct_sync_ops_status.after.json` is not captured.
- `schema_ready` is false.
- `missing_tables` or `missing_columns` is non-empty.
- direct receipt, nonce, raw artifact, or source_claim counts are non-zero before canary without a documented explanation.
- `/health/ingest` reports a schema absence blocker after Phase 1.
- Any Phase 2 evidence file contains raw HMAC secret, producer credential, bearer token, raw receipt JSON, full raw payload, or barcode dump.
- Any operator requests producer POST or credential material during Phase 2.

## Phase 3 Handoff

Phase 3 one-PC authenticated canary may be reviewed only after Phase 2 PASS and explicit credential approval. Phase 2 PASS does not approve canary POST, 20-PC concurrency, shadow run, rollback rehearsal, or Syncthing retirement.
