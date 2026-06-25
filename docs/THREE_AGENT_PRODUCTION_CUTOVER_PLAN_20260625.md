# Three-Agent Production Cutover Plan

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync production 검증, Syncthing shadow 유지 및 최종 제거 승인

## Current Decision

Production cutover is still `BLOCKED`.

- FQDN producer endpoint `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file` is exposed by `OPTIONS 200` with `Allow: OPTIONS, POST`.
- No authenticated producer `POST`, HMAC, nonce, idempotency, receipt, raw artifact, source_claim, or projection write has been executed.
- `/health/ingest` reports common projection `schema_ready=true`, but still returns `503` with `PLAN_C_ROLLOUT_GATE_BLOCKED`.
- `direct_sync_ops_status.py` remains the direct-sync gate and blocks while producer/source-claim/projection tables are missing.
- Syncthing remains a shadow and rollback safety path. It must not be removed before all P0 evidence and final owner signoff pass.

## Agent Ownership

| Agent | Ownership | Primary gates |
| --- | --- | --- |
| Agent A: Server/DB/Ingest | Operating DB, additive schema, direct-sync ops status, FQDN route, promotion evidence, canary receipt reconciliation | DB backup, schema readiness, promotion bundle, POST canary receipt |
| Agent B: Producer PC/Field/Security | Worker PC install/config, scanner UI scenarios, credentials, HMAC/nonce/idempotency, 20-PC concurrency, malicious input, fault/soak/operator visibility | Field UI PASS, credential lifecycle PASS, 20PC PASS, security/fault/soak PASS |
| Agent C: Downstream/Shadow/Rollback | WorkerAnalysisGUI-web today/past/trace/summary/export, dashboard XSS rendering, Syncthing/archive shadow, projection parity, rollback, removal signoff | Downstream totals PASS, no-double-count PASS, rollback PASS, Syncthing retirement signoff |

## P0 Sequence

1. **Authority and freeze / Read-only 기준선 고정**
   - Owners: DB owner, app owner, field operator, rollback owner.
   - Actions: freeze endpoint, deployed code hash, service env, DB path/hash, Syncthing device/folder state, production config, target PC list.
   - Evidence: production freeze manifest, `direct_sync_ops_status.before.json`, `/health`, `/health/ingest`, FQDN `OPTIONS`, DB/WAL size, disk free-space proof.
   - Pass: no POST, no DB write, no service change, no Syncthing change; all current blockers are captured.

2. **Schema blocker approval packet**
   - Owners: Agent A, DB owner, rollback owner.
   - Required direct-sync objects: `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `source_claim_history`, `transfer_legacy_projection`, `packaging_set_projection`, `process_state_summary_sources`, `defect_hmac_chain_state`, `defect_hmac_chain_review_audit`.
   - Evidence: approved change window, expected DB SHA-256, backup directory, rollback owner present, additive migration report path.
   - Stop: any owner unavailable, backup path not empty/approved, expected hash mismatch risk, or unclear rollback owner.

3. **Hash-checked backup and additive schema**
   - Owners: DB owner executes, Agent A verifies.
   - Command source: `docs/OPERATIONAL_CHANGE_WINDOW_RUNBOOK_20260625.md`.
   - Evidence: `apply_additive_schema_report.json`, backup DB path/SHA-256, `actual_db_sha256_before == expected_db_sha256`, legacy row counts before/after.
   - Pass: report `status=PASS`, `backup_created=true`, required tables/columns exist, existing `sessions`, `raw_events`, `common_*` row counts do not decrease.
   - Rollback: keep producer POST disabled; restore from approved backup only under rollback owner direction, then re-check DB SHA and row counts.

4. **Post-schema direct-sync readiness**
   - Owners: Agent A, app owner.
   - Evidence: updated/deployed `direct_sync_ops_status.after.json`, `/health/ingest.after.json`.
   - Pass: `schema_ready=true`, `missing_tables=[]`, `missing_columns={}`; canary-before counts for receipts, nonces, and source_claim are zero or explicitly explained.
   - Stop: any missing producer/source-claim/projection table remains.

5. **Promotion evidence bundle**
   - Owners: app owner, operator, rollback owner.
   - Required evidence: `health_ingest_before_after`, `temp_db_dry_run_report`, `shared_writer_lease_smoke`, `api_data_non_regression`, `redaction_scan`, `rollback_marker_and_drain_receipt`.
   - Pass: `PLAN_C_PROMOTION_EVIDENCE_BUNDLE` has `status=PASS`, valid artifact references, captured timestamps, SHA-bound artifacts, and no redaction failures.
   - Stop: `/health/ingest` remains blocked for unexpected reasons or bundle artifact SHA fields are missing.

6. **Credential and canary preparation**
   - Owners: Agent B, field operator, Agent A.
   - Evidence: per-PC `source_host_id`, `producer_install_id`, producer id, key id, active manifest hash, secret-store reference, allowed stream, revocation/rotation procedure.
   - Pass: no raw HMAC secret in files/docs/logs; FQDN HTTPS only; Syncthing/archive remains enabled; rollback owner present.

7. **One-PC authenticated canary**
   - Owners: field operator executes, Agent A verifies, Agent C watches downstream.
   - Evidence: request id, key id, nonce fingerprint, idempotency key fingerprint, content hash, receipt hash, raw artifact ref/hash, source_claim row, projection/summary/quarantine count.
   - Pass: first upload accepted once, replay is idempotent, nonce replay is rejected, raw artifact hash matches source CSV, source CSV row count equals inserted + replayed + quarantined + errors.
   - Rollback: pause relay, disable producer write path, keep Syncthing/archive authoritative, mark or review affected source_scope.

8. **Actual scanner/UI validation**
   - Owners: Agent B, field operator.
   - Scenarios: login, new/existing worker, master label, product scan, bad scan warning/focus return, auto complete, undo, reset, park/restore, partial submit, completed-label replacement, individual exchange, close/recover.
   - Pass: each scenario creates expected CSV/event rows and no silent data loss; parked tray and replacement/exchange evidence hashes are captured.

9. **20-PC/VM concurrency**
   - Owners: Agent B, Agent A.
   - Cases: same Korean filename, same worker name, duplicate resend, replay, network interruption, relay restart, queue resume, queue contention.
   - Pass: exactly 20 distinct source identities, no duplicate projection, receipt/source_claim rows reconcile with per-PC CSV counts.

10. **Downstream and dashboard validation**
    - Owners: Agent C, downstream owner.
    - Evidence: DB aggregate, dashboard API JSON, today/past/trace/summary/export screenshots, export checksum/row count.
    - Pass: dashboard/export totals equal source receipt totals; trace resolves source identity; malicious strings render as inert text.

11. **Syncthing/archive parallel shadow**
    - Owners: Agent C, rollback owner.
    - Evidence: Syncthing/archive ingest evidence, direct receipt, source_claim history, projection parity report.
    - Pass: raw evidence can exist on both paths, but common projection, dashboard, summary, and export count the logical event once.
    - Stop: any double count, unresolved source_claim conflict, or parity diff.

12. **Rollback rehearsal**
    - Owners: rollback owner, field operator, Agent C.
    - Actions: relay pause, scheduled task/service stop rehearsal, HTTPS failure simulation, legacy path verification, queued HTTPS resume.
    - Pass: no CSV/archive loss, HTTPS failure does not block legacy analysis, queued uploads resume without duplicate projection.

13. **Shadow burn-in and final signoff**
    - Owners: all agents plus owners.
    - Duration: minimum 3 business days or approved production batch window.
    - Pass: P0/P1 incidents 0, double count 0, unresolved parity diff 0, source_claim unresolved conflict 0, operator report PASS.

## P1 And P2 Gates

- Credential lifecycle: valid, revoked, expired, duplicated key id, producer disable, key rotation.
- Clock drift: HMAC timestamp skew, source timestamp skew, today/past summary correctness.
- Fault injection: 500/503, timeout, DNS/TLS failure, DB lock, disk pressure, spool corruption, `status.json` corruption.
- Security: SQL/XSS/formula/path traversal strings in worker, item, barcode, CSV, HTTPS, DB, dashboard, export.
- Operator visibility: last failure, next retry, queue age, review row, rollback state explainable from report artifacts.
- Soak: 4-8 hours or one full day volume; bounded memory, CPU, DB growth, log growth; backlog drains after faults.
- Backup/retention: CSV, relay spool, receipt, raw artifact, projection DB, archive retention and restore drill.
- Production config freeze: no local dev endpoint, no raw secret, no debug/fault/test flag, no runtime-local `config\parked_trays` in release package.

## Evidence Pack

Required archive contents:

- production freeze manifest
- DB backup and additive schema report
- `direct_sync_ops_status` before/after
- `/health` and `/health/ingest` before/after
- FQDN `OPTIONS` and authenticated `POST` evidence
- credential registry export with secrets redacted
- PC identity table
- UI/scanner scenario checklist and screenshots/video
- relay queue/status/operator report
- receipt, nonce, raw artifact, source_claim, projection, summary, quarantine count reports
- malicious input dashboard/export screenshots
- source_claim collision and projection parity reports
- Syncthing peer/folder/archive snapshot
- rollback rehearsal transcript
- owner signoff record

## Hard Stop Conditions

- Production backup cannot be created or verified.
- `expected_db_sha256` mismatch before migration.
- `direct_sync_ops_status.py` remains `BLOCKED` after schema step.
- `/health/ingest` reports unexpected schema or promotion blocker after remediation.
- Any POST writes a receipt without nonce, raw artifact, source_claim, and summary reconciliation.
- Any replay, retry, or Syncthing/archive shadow creates duplicate projection.
- Any raw secret, HMAC key, receipt JSON, or raw payload appears in evidence output.
- Dashboard executes XSS/formula/path traversal payload instead of rendering inert text.
- Operator cannot identify last failure, next retry, review row, and rollback state from status/report artifacts.

## Syncthing Retirement Gate

Syncthing removal is allowed only when all conditions are true:

- one-PC canary PASS
- 20-PC ingest PASS
- credential lifecycle PASS
- source_claim unresolved conflict count is `0`
- idempotency replay-zero/parity PASS
- downstream today/past/trace/summary/export totals PASS
- dashboard XSS rendering PASS
- Syncthing shadow no-double-count PASS
- rollback rehearsal PASS
- backup/retention/restore proof PASS
- operator visibility PASS
- production config freeze PASS
- owner signoff from DB owner, app owner, field operator, downstream owner, and rollback owner

Until a signed artifact states `promotion_allowed=true` and `production_removal_ready=true`, Syncthing remains enabled as shadow/rollback safety.
