# Operational Change Window Runbook

작성일: 2026-06-25
대상: WorkerAnalysisGUI-web 운영 DB direct-sync schema readiness, `Container_Audit` HTTPS canary, Syncthing shadow 유지

## Safety Boundary

- This runbook is a prepared procedure. It was not executed against production.
- Do not run the `--execute`, service stop/start, credential issue, producer POST, or Syncthing change steps without the DB owner, app owner, rollback owner, and field operator present.
- Do not paste raw HMAC secrets, producer credentials, receipt JSON, raw payloads, or barcode dumps into chat, logs, docs, or evidence manifests.
- Use FQDN HTTPS for external producer testing: `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file`.
- Do not use raw IP HTTPS or internal HTTP 8089 as the external cutover target.

## Required Inputs

| Input | Required value |
| --- | --- |
| DB path | `/mnt/rebuild/worker-analysis/data/worker_analysis.db` |
| App directory | `/root/WorkerAnalysisGUI-web` |
| Approved endpoint | `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file` or a separately approved staging URL |
| DB backup directory | New empty directory under `/mnt/rebuild/worker-analysis/backups/` |
| Producer credentials | Per-PC `source_host_id`, `producer_install_id`, key id, active manifest hash, HMAC secret in approved secret store |
| Rollback owner | Named person present during the change window |
| Field canary PC | One approved PC/scanner first; 20-PC test only after canary PASS |

## Phase 0: Read-Only Preflight

Run these first. They must not write to production DB or send producer data.

```bash
cd /root/WorkerAnalysisGUI-web
DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db

python3 scripts/direct_sync_ops_status.py --db "$DB" > /tmp/direct_sync_ops_status.before.json
curl -fsS https://worker.kmtecherp.com/health > /tmp/health.before.json
curl -sS https://worker.kmtecherp.com/health/ingest > /tmp/health_ingest.before.json || true
curl -sS -i -X OPTIONS https://worker.kmtecherp.com/api/producer-ingest/v1/source-file > /tmp/producer_ingest_options.before.txt
python3 - <<'PY'
from pathlib import Path
import shutil, json
root = Path('/mnt/rebuild/worker-analysis')
db = root / 'data' / 'worker_analysis.db'
usage = shutil.disk_usage(root)
print(json.dumps({
    'db_size_bytes': db.stat().st_size,
    'wal_size_bytes': Path(str(db) + '-wal').stat().st_size if Path(str(db) + '-wal').exists() else 0,
    'free_bytes': usage.free,
    'backup_space_ok': usage.free > db.stat().st_size * 2,
}, indent=2, sort_keys=True))
PY
```

Preflight PASS requires:

- FQDN producer endpoint `OPTIONS` returns `200` with `Allow: OPTIONS, POST`.
- `/health/ingest` is understood: common projection may be `schema_ready=true`, but promotion can still be blocked.
- `direct_sync_ops_status.py` missing tables are recorded before migration.
- Free disk space is at least two DB sizes.
- No producer POST has been sent.

## Phase 1: Backup And Additive Schema

Only run inside the approved change window.

```bash
cd /root/WorkerAnalysisGUI-web
DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR=/mnt/rebuild/worker-analysis/backups/direct-sync-schema-$STAMP
mkdir -p "$BACKUP_DIR"

EXPECTED_DB_SHA256=$(sha256sum "$DB" | awk '{print $1}')

python3 scripts/plan_c_apply_additive_schema.py \
  --db-path "$DB" \
  --execute \
  --expected-db-sha256 "$EXPECTED_DB_SHA256" \
  --backup-dir "$BACKUP_DIR" \
  --report-path "$BACKUP_DIR/apply_additive_schema_report.json"
```

The schema step must produce:

- `status=PASS` in `apply_additive_schema_report.json`
- `backup_created=true`
- `actual_db_sha256_before` equal to `EXPECTED_DB_SHA256`
- backup DB file exists and has a recorded SHA-256
- no existing legacy row counts are reduced

## Phase 2: Post-Schema Readiness

```bash
cd /root/WorkerAnalysisGUI-web
DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db
BACKUP_DIR=<same directory from Phase 1>

python3 scripts/direct_sync_ops_status.py --db "$DB" \
  --report-path "$BACKUP_DIR/direct_sync_ops_status.after.json"

curl -sS https://worker.kmtecherp.com/health/ingest \
  > "$BACKUP_DIR/health_ingest.after.json" || true
```

Post-schema PASS requires:

- `direct_sync_ops_status.after.json` has `schema_ready=true`
- `missing_tables=[]`
- `missing_columns={}`
- direct receipt, nonce, and source claim counts are still `0` before canary
- `/health/ingest` blocker is only expected promotion/canary evidence, not schema absence

## Phase 3: Authenticated HTTPS Canary

Run one PC/scanner canary before any 20-PC test.

Required canary evidence:

- TLS/FQDN endpoint: `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file`
- producer id, key id, `source_host_id`, `producer_install_id`, active manifest hash
- HMAC timestamp within skew window
- nonce stored exactly once
- idempotency replay returns stored receipt and does not duplicate projection
- raw artifact saved and content hash matches source CSV
- source_claim row created with expected state
- transfer projection and summary totals match the `Container_Audit` source CSV rows
- quarantine count equals rejected or review rows

Stop immediately if any credential or receipt detail would expose raw secret material in logs.

## Phase 4: Shadow And Rollback Proof

Keep Syncthing/archive enabled during the canary and 20-PC test.

Shadow PASS requires:

- same source event through HTTPS and legacy archive is counted once
- duplicate direct replay does not create extra projection rows
- downstream today/past/trace/summary/export totals match source receipts

Rollback rehearsal PASS requires:

- relay pause recorded
- scheduled task/service stop command rehearsed in the approved window
- CSV/archive preserved with hashes
- HTTPS failure path returns to legacy analysis
- queued HTTPS uploads resume without duplicate projection

## Hard Stop Conditions

- Backup cannot be created or verified.
- `expected_db_sha256` mismatch before schema apply.
- `direct_sync_ops_status.py` remains missing producer/source-claim/projection tables after schema apply.
- `/health/ingest` reports an unexpected schema blocker after schema apply.
- Any POST canary writes a receipt without raw artifact, nonce, source_claim, and summary reconciliation.
- Any replay, Syncthing shadow row, or retry creates duplicate projection.
- Any raw secret, HMAC key, receipt JSON, or raw payload appears in evidence output.
- Operator cannot explain last failure, next retry, and rollback state from the status/report artifacts.

## Local Rehearsal Evidence

The production DB was not mutated. The local WorkerAnalysisGUI-web rehearsal proves the command shape:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider tests\test_operational_db_additive_schema_remediation.py
$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider tests\test_operational_db_additive_schema_remediation.py tests\test_direct_sync_ops_status.py tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_cli_initializes_required_tables tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_blocks_existing_db_without_execute tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_executes_existing_db_with_hash_backup_and_report
```

Results:

- `1 passed` for operational-style partial schema remediation
- `8 passed` for remediation, ops-status, and schema-apply contracts
