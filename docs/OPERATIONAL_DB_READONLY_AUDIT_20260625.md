# Operational DB Read-Only Audit

작성일: 2026-06-25
대상: 회사 서버 WorkerAnalysisGUI-web 운영 SQLite DB와 `Container_Audit` HTTPS direct-sync 전환 게이트

## Scope And Safety Boundary

- Read-only SSH and HTTPS health checks only.
- No producer upload POST, no production DB write, no schema migration, no service restart, no scheduled task/timer change, and no Syncthing config change was executed.
- SQLite was opened with `file:...?...mode=ro` and `PRAGMA query_only=ON`.
- Queries were limited to schema, table presence, counts, date ranges, and grouped aggregate counts. No raw payload rows, receipt JSON, barcode row dumps, HMAC secrets, auth headers, or producer secrets were read into this report.

## Server And DB Identity

| Field | Value |
| --- | --- |
| SSH host alias used | `company-server` |
| Server hostname | `s196e2737426` |
| Server time during check | `2026-06-25T02:45:01+09:00` to `2026-06-25T02:46:10+09:00` |
| DB path | `/mnt/rebuild/worker-analysis/data/worker_analysis.db` |
| DB size | `7918022656` bytes |
| DB file mode | `0644` |
| SQLite journal mode | `wal` |
| SQLite page size / page count | `4096` / `1933111` |
| `schema_identity_sha256` | `3e9ff097ba41af445d37cee9806250c8cb86f4cc4dffced793ba9b3376d942d2` |

## Service And Health Status

| Check | Result |
| --- | --- |
| `https://worker.kmtecherp.com/health` | `200`, dashboard app reports database healthy |
| `http://127.0.0.1:8089/health` on server | `200`, database healthy |
| `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file` | `OPTIONS 200`, `Allow: OPTIONS, POST`; no POST upload executed |
| `https://worker.kmtecherp.com/health/ingest` | `503`, blocked by promotion evidence |
| `http://127.0.0.1:8089/health/ingest` on server | `503`, blocked by promotion evidence |
| `worker-analysis.service` | active/running, enabled, main PID `122301` |
| `worker-csv-sync.timer` | active/waiting, enabled |
| `syncthing@syncthing.service` | active |

`/health/ingest` reports:

- `reason=PLAN_C_ROLLOUT_GATE_BLOCKED`
- `common_projection_schema=healthy`
- `schema_ready=true`
- `COMMON_INGEST_WRITE_ENABLED=true`
- `PROJECTION_API_READ_ENABLED=true`
- `PROJECTION_SHADOW_ENABLED=true`
- `DASHBOARD_PROJECTION_UI_ENABLED=true`
- `ERP_RECONCILIATION_API_READ_ENABLED=false`
- `rollout_gates.status=blocked_pending_promotion_evidence`
- `blocking_reasons=["missing_promotion_evidence_bundle"]`
- promotion evidence bundle exists but is incomplete because required artifact SHA fields are missing.
- Important boundary: this health endpoint confirms common projection readiness, not full producer direct-sync readiness. `direct_sync_ops_status.py` still blocks direct ingest because producer/source-claim tables are missing.

## Operational DB Counts

| Table | Count |
| --- | ---: |
| `sessions` | `55745` |
| `raw_events` | `1982276` |
| `scan_events` | `1720807` |
| `tray_events` | `55745` |
| `event_barcodes` | `2280031` |
| `event_payloads` | `1982276` |
| `source_files` | `1727` |
| `source_file_versions` | `4047` |
| `file_sync_log` | `1727` |
| `archive_manifest` | `8230` |
| `common_ingested_events` | `11` |
| `common_raw_evidence_events` | `11` |
| `common_event_quarantine` | `3` |
| `common_ingest_runs` | `0` |
| `return_bundle_projection` | `4` |
| `inspection_bundle_projection` | `3` |
| `process_state_summary` | `6` |
| `projection_snapshots` | `0` |
| `projection_snapshot_events` | `0` |

Date ranges:

- `sessions.date`: `2025-08-09` to `2026-06-24`
- `raw_events.timestamp`: `2025-08-09 08:20:04.425249` to `2026-06-24 18:50:03.981770`
- `scan_events.timestamp`: `2025-08-09 08:31:44.771434` to `2026-06-24 18:50:03.981264`

## Direct-Sync Required Tables

| Required object | Status |
| --- | --- |
| `producer_ingest_receipts` | `MISSING` |
| `producer_ingest_nonces` | `MISSING` |
| `producer_ingest_raw_artifacts` | `MISSING` |
| `source_claim` | `MISSING` |
| `source_claim_history` | `MISSING` |
| `transfer_legacy_projection` | `MISSING` |
| `packaging_set_projection` | `MISSING` |
| `process_state_summary_sources` | `MISSING` |
| `common_ingested_events` | present, partial legacy/common projection shape |
| `common_event_quarantine` | present |
| `return_bundle_projection` | present |
| `inspection_bundle_projection` | present |
| `process_state_summary` | present, older column shape |

## Projection And Quarantine Snapshot

`common_ingested_events` currently contains `11` rows:

- `inspection_worker_product_ledger/outbox`: `7` projected `INSPECTION_BUNDLE` rows.
- `defect_return_bundle_ledger/hmac_csv`: `4` projected `RETURN_BUNDLE` rows with `UNVERIFIED_HMAC_PRESENT`.

`common_event_quarantine` currently contains `3` rows:

- `2` rows with `reason=VALIDATION_ERROR`
- `1` row with `reason=IDENTITY_CONFLICT`, `source_system=inspection_worker_product_ledger`

## Server-Local Ops Status Cross-Check

The deployed server-local read-only helper was executed without a report write:

```bash
ssh company-server "cd /root/WorkerAnalysisGUI-web && python3 scripts/direct_sync_ops_status.py --db /mnt/rebuild/worker-analysis/data/worker_analysis.db"
```

Result:

- `status=BLOCKED`
- `read_only=true`
- `production_ready=false`
- `schema_ready=false` for deployed direct-sync ops status, even though `/health/ingest` reports common projection `schema_ready=true`
- deployed helper missing tables: `producer_ingest_receipts`, `producer_ingest_nonces`, `source_claim`, `defect_hmac_chain_state`
- redaction contract: `no_raw_payloads_no_secrets_no_auth_material_no_receipt_json`
- direct receipt count: `0`
- nonce ledger count: `0`
- source claim count: `0`
- common projection counts match the manual audit: `common_ingested_events=11`, `common_event_quarantine=3`

Deployment parity note:

- Operating server repo reports `HEAD=f4bbbd9` on `main`.
- The operating server's deployed `scripts/direct_sync_ops_status.py` SHA-256 is `c5b7020a1d5788ed0e7d8690c2fe21e9bf1469735bbaff007389725a153c7ea0`.
- The local WorkerAnalysisGUI-web working tree has an expanded, uncommitted `scripts/direct_sync_ops_status.py` SHA-256 beginning `BD1A79FEA0CA7C7B...`.
- The deployed helper checks a narrower table set than the local expanded helper. Therefore the server helper's `BLOCKED` result is sufficient to stop upload, but not sufficient to prove all direct-sync schema gaps are enumerated.

## Local Additive Remediation Proof

No production DB migration was run. A local WorkerAnalysisGUI-web fixture now reproduces the operational failure mode with a partial legacy/common projection schema and existing rows, then proves the additive remediation path:

- before remediation: `direct_sync_ops_status.py` returns `BLOCKED`, missing `producer_ingest_receipts`, `producer_ingest_nonces`, `source_claim`, `transfer_legacy_projection`, and `process_state_summary_sources`
- remediation command shape: `scripts/plan_c_apply_additive_schema.py --execute --expected-db-sha256 <before-hash> --backup-dir <backup-dir> --report-path <report>`
- proof: backup is created, expected DB SHA-256 is checked, legacy `sessions`, `raw_events`, `common_ingested_events`, and `common_event_quarantine` row counts are preserved, and post-remediation `direct_sync_ops_status.py` returns `PASS`

Verification:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider tests\test_operational_db_additive_schema_remediation.py
$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider tests\test_operational_db_additive_schema_remediation.py tests\test_direct_sync_ops_status.py tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_cli_initializes_required_tables tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_blocks_existing_db_without_execute tests\test_rollout_gate.py::test_plan_c_apply_additive_schema_executes_existing_db_with_hash_backup_and_report
```

Results:

- operational remediation fixture: `1 passed`
- related WorkerAnalysisGUI-web schema/ops gate: `8 passed`

## Decision

- The operational legacy dashboard DB is live and healthy for the existing application.
- The same operational DB is not ready for `Container_Audit` HTTPS direct ingest because the producer receipt/nonce/raw artifact/source claim tables and transfer projection tables are missing.
- `/health/ingest` correctly blocks promotion with `PLAN_C_ROLLOUT_GATE_BLOCKED` and missing promotion evidence.
- The FQDN HTTPS producer route is exposed by `OPTIONS 200`, but no authenticated POST/HMAC/nonce/idempotency/receipt path was executed.
- The deployed server-local ops helper also returns `BLOCKED`; its narrower schema checklist means an updated diagnostic/deploy parity check is required before treating any server status as exhaustive.
- Do not run real `Container_Audit` producer upload against this operational DB yet.
- Do not remove Syncthing or make direct HTTPS authoritative until schema readiness, promotion evidence, receipt/idempotency tables, source-claim tables, downstream transfer projection, and rollback evidence pass.

## Required Next Actions Before Production Upload

1. Create and verify a backup or snapshot of `/mnt/rebuild/worker-analysis/data/worker_analysis.db`.
2. Run additive schema migration only inside an approved rollback/change window.
3. Re-run `/health/ingest` and require `schema_ready=true` and rollout gate healthy.
4. Ensure `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `source_claim_history`, `transfer_legacy_projection`, `packaging_set_projection`, and `process_state_summary_sources` exist with expected columns.
5. Until schema and promotion evidence are green, either keep producer upload disabled or ensure `COMMON_INGEST_WRITE_ENABLED` cannot accept production writes.
6. After schema readiness, run a staging/canary upload with HMAC, nonce, idempotency, receipt storage, source_claim, projection, summary, quarantine count, and rollback proof.
