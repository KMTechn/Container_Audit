# Phase 1 Additive Schema Approval Packet

작성일: 2026-06-25
대상: WorkerAnalysisGUI-web 운영 DB direct-sync additive schema readiness review

## Purpose

This packet lets the DB owner, app owner, rollback owner, downstream owner, security owner, and change coordinator review the exact Phase 1 backup and additive schema command shape before anyone runs it.

This document is not execution approval. Do not run schema `--execute`, producer POST, credential lifecycle operations, service or scheduled task changes, relay pause/resume, rollback rehearsal, 20-PC run, Syncthing mutation, or Syncthing removal from this packet alone.

## Preconditions

Phase 1 review may start only after:

- `docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md` is signed.
- `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` has been run in the approved window.
- `docs/PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md` is filled with either `phase0_readonly_pass` or a reviewed `phase0_blocked_before_mutation` resolution.
- `phase0_artifact_hashes.sha256` and `db.sha256.before.txt` are archived.
- `/mnt/rebuild/worker-analysis/data/worker_analysis.db` is the approved DB path.
- `/root/WorkerAnalysisGUI-web` is the approved app directory.
- Free disk space is at least two DB sizes.
- No raw HMAC secret, producer credential, raw receipt JSON, full raw payload, or barcode dump is required for the schema step.

## Required Owner Signoff

| Owner role | Required approval before execution | Evidence marker |
| --- | --- | --- |
| DB owner | Approves backup directory, expected DB SHA-256, schema command, row-count preservation checks, and rollback copy retention. | name, timestamp, DB SHA-256 |
| App owner | Confirms deployed `scripts/plan_c_apply_additive_schema.py` and `scripts/direct_sync_ops_status.py` are the intended versions for this window. | name, timestamp, script hashes |
| Rollback owner | Confirms backup restore path, rollback window, and no service/task stop is implied by this packet. | name, timestamp, rollback path |
| Downstream owner | Confirms downstream dashboards/export are baseline-only until post-schema readiness and canary evidence pass. | name, timestamp, downstream target |
| Security owner | Confirms evidence contains schema flags, paths, counts, and hashes only; no secret or raw payload material. | name, timestamp, redaction rule |
| Change coordinator | Confirms this packet is attached to the approved change id and that Phase 1 has not started before signoff. | name, timestamp, change id |

## Command Under Review

The following command is the exact mutation shape to review. It must not be run until the owners above explicitly approve Phase 1 execution inside the change window.

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

## Required Evidence If Executed Later

Store only redacted schema evidence under `01_schema_backup_and_apply`.

- `expected_db_sha256.txt`
- `backup_dir.txt`
- backup DB file path and backup DB SHA-256
- `apply_additive_schema_report.json`
- legacy `sessions`, `raw_events`, `common_ingested_events`, and `common_event_quarantine` row counts before and after
- script SHA-256 values for `scripts/plan_c_apply_additive_schema.py` and `scripts/direct_sync_ops_status.py`
- reviewer note that no raw secrets, raw receipt JSON, full raw payloads, or barcode dumps are present

`apply_additive_schema_report.json` must show:

- `status=PASS`
- `backup_created=true`
- `actual_db_sha256_before` equals `EXPECTED_DB_SHA256`
- backup DB file exists and has a recorded SHA-256
- legacy row counts are not reduced

## Stop Conditions

Stop before execution if any item is true:

- Any required owner signoff is missing.
- Phase 0 transcript is missing, unreviewed, or ended as unresolved `phase0_blocked_before_mutation`.
- `DB` path is not `/mnt/rebuild/worker-analysis/data/worker_analysis.db`.
- `BACKUP_DIR` already exists with previous artifacts.
- `apply_additive_schema_report.json` already exists before the command.
- Free disk space is less than two DB sizes.
- `EXPECTED_DB_SHA256` does not match `db.sha256.before.txt` from Phase 0 or the DB owner-approved current hash.
- App owner cannot confirm script hash/version.
- Any output would expose raw HMAC secret, producer credential, bearer token, raw receipt JSON, full raw payload, or barcode dump.

## Post-Execution Handoff If Approved Later

If the command is approved and executed in the real change window, the next required step is Phase 2 post-schema readiness:

- run `scripts/direct_sync_ops_status.py --db "$DB" --report-path "$BACKUP_DIR/direct_sync_ops_status.after.json"`;
- capture `/health/ingest` to `health_ingest.after.json`;
- verify `schema_ready=true`, `missing_tables=[]`, `missing_columns={}`;
- verify receipt, nonce, and source-claim counts remain zero before any canary;
- do not run producer POST until Phase 2 readiness and credential approval pass.
