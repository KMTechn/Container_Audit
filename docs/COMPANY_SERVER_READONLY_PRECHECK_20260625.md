# Company Server Read-Only Precheck

작성일: 2026-06-25
대상: 이적실 `Container_Audit` HTTPS direct-sync 전환 전 회사 서버 등록/상태 확인

## Scope And Safety Boundary

- This precheck is read-only evidence only.
- No POST upload executed, no producer credential used, no production DB mutation, no scheduled task/service change, and no Syncthing config change was executed.
- Secret-bearing local config values were treated as sensitive and are intentionally not reproduced here.

## Server Registration Findings

| Area | Finding | Operational meaning |
| --- | --- | --- |
| Syncthing registration | Syncthing device named `Server` is registered and connected. The live connection target observed from this PC is `175.45.200.171:22000`. | A company-server-like Syncthing peer is registered and currently reachable. |
| Syncthing folder scope | `C:\Sync` is not registered in Syncthing config. The only shared folder observed in the Syncthing config is `C:\Obsidian` with label `옵시디언`. | The existing `C:\Sync` CSV folder cannot be assumed to be synchronized through this PC's current Syncthing config. |
| Local scheduled task | Windows scheduled task `SyncthingStartup` exists and starts the local Syncthing binary. Syncthing processes were running during the check. | Legacy Syncthing is present on the PC, but this does not prove `Container_Audit` data is currently synced. |
| Direct HTTPS producer config | Local `Container_Audit` config/environment did not expose an approved HTTPS endpoint, producer manifest, HMAC credential, or per-PC producer identity registry. | The worker PC is not yet registered for direct HTTPS cutover from local config evidence. |

## Company Server Route Findings

| Endpoint | Read-only result | Decision |
| --- | --- | --- |
| `https://175.45.200.171/health` | Route probe reached HTTPS nginx/app surface and returned 404. A Windows trust-validating client also reported TLS certificate trust failure for the HTTPS producer host. | Server has HTTPS, but it is not yet an approved TLS/certificate path for this cutover. |
| `https://175.45.200.171/health/ingest` | Route probe returned 404. | 443 HTTPS does not currently expose the ingest health route. |
| `https://175.45.200.171/api/producer-ingest/v1/source-file` | IP-host route probe returned 404; Windows trust-validating check failed TLS certificate trust before route validation. | IP-based HTTPS remains unapproved for worker PCs. Use the FQDN route for future approved testing, not raw IP HTTPS. |
| `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file` | FQDN HTTPS `OPTIONS` returned 200 with `Allow: OPTIONS, POST`, Cloudflare, and HSTS. | The producer route is exposed on the company FQDN, but no POST upload, HMAC, nonce, idempotency, receipt, or DB write was tested. |
| `http://175.45.200.171:8089/health` | Returned 200 from WorkerAnalysisGUI-web health. | WorkerAnalysisGUI-web is reachable on HTTP 8089. |
| `https://worker.kmtecherp.com/health/ingest` | Returned 503. Reason: `PLAN_C_ROLLOUT_GATE_BLOCKED`; `schema_ready=true`; `common_projection_schema=healthy`; promotion evidence bundle incomplete. | Common projection health is initialized, but production promotion remains blocked. |
| `http://175.45.200.171:8089/api/producer-ingest/v1/source-file` | Route exists with `POST, OPTIONS`; read-only GET/HEAD returned method errors. | Internal HTTP route exists; external cutover validation must use trusted HTTPS FQDN and approved credentials. |

## Server Health Blockers

`/health/ingest` on `https://worker.kmtecherp.com` reported:

- Latest read-only recheck confirmed Syncthing `Server` connected to `175.45.200.171:22000`, FQDN HTTPS producer route `OPTIONS` returned 200, and `/health/ingest` returned 503.
- `status=blocked`
- `reason=PLAN_C_ROLLOUT_GATE_BLOCKED`
- `common_ingest_write_enabled=true`
- `common_projection_schema=healthy`
- `schema_ready=true`
- `counts={"common_ingested_events": 11, "common_event_quarantine": 3, "inspection_bundle_projection": 3, "process_state_summary": 6, "return_bundle_projection": 4}`
- `rollout_gates.status=blocked_pending_promotion_evidence`
- `blocking_reasons=["missing_promotion_evidence_bundle"]`
- Required promotion evidence includes `health_ingest_before_after`, `temp_db_dry_run_report`, `shared_writer_lease_smoke`, `api_data_non_regression`, `redaction_scan`, and `rollback_marker_and_drain_receipt`.

This blocks real P0 upload validation until the approved target remains trusted HTTPS, producer credentials are provisioned, direct-sync schema/ops status is ready, the promotion evidence bundle is complete, and the canary upload receipt path is verified.

## Local Received-Data Check

Read-only local CSV inspection of `C:\Sync` found:

- `17` CSV files and `102` total rows.
- `0` malformed CSV rows, `0` JSON parse errors, and `0` dangerous-marker hits in the sampled fields.
- No rows dated `2026-06-25`.
- Transfer-room CSV files contain `WORK_START` / `WORK_END` rows but no completed `TRAY_COMPLETE` sessions, so local transfer completed-session count is `0`.
- Packaging CSV analysis through WorkerAnalysisGUI-web found `2` completed sessions on `2026-06-23`, total `120` pieces.
- Inspection CSV files use newer `event_type`-style schemas, while the local legacy analyzer expects an `event` column; those files need schema-specific downstream handling and should not be treated as malformed transfer CSVs.

## Current Decision

- Company server registration exists at the Syncthing peer level: `Server` is registered and connected.
- Container_Audit direct HTTPS cutover is not ready from current evidence: the FQDN producer route is exposed, but no local producer endpoint/credential registry was found, no POST/HMAC/nonce/idempotency/receipt path was tested, `/health/ingest` remains blocked by promotion evidence, and direct-sync ops status still reports missing producer/source-claim tables.
- Do not POST production or staging upload data to the producer endpoint yet. The route exists, but the credential, receipt, DB schema, promotion evidence, and rollback gates are not complete.

## Required Next Evidence Before Real Upload

1. Approved staging/test HTTPS URL for `POST /api/producer-ingest/v1/source-file` on 443 or another TLS endpoint; current FQDN `OPTIONS` route exists but upload is not approved.
2. Per-PC `source_host_id`, `producer_install_id`, key id, HMAC secret provisioning, key rotation/revocation procedure, and allowed nonce/idempotency policy.
3. Server-side ingest health showing complete promotion evidence bundle, direct-sync ops status with no missing producer/source-claim tables, non-empty expected counts after dry run/canary, and saved receipts.
4. Staging/test DB access with production-equivalent schema and least-privilege ingest role.
5. 20 PC/VM list and rollback window for the external concurrency run.
6. Downstream owner confirmation for WorkerAnalysisGUI-web today/past/trace/summary/export validation.
7. Explicit rollback owner and procedure for relay pause, scheduled task/service stop, legacy path resume, and queued HTTPS resend.
