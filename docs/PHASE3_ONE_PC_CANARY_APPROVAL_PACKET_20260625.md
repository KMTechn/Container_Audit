# Phase 3 One-PC Authenticated Canary Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync one-PC authenticated canary review

## Purpose

This packet defines what owners must approve and what evidence must be collected before a single approved worker PC sends the first authenticated HTTPS producer canary.

This document is not execution approval. It does not authorize producer POST upload, HMAC secret disclosure, credential issue/rotation/revocation, 20-PC run, Syncthing mutation, rollback rehearsal, service or scheduled task changes, or Syncthing removal.

## Preconditions

Canary review may start only after:

- `docs/PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md` records Phase 2 PASS.
- `direct_sync_ops_status.after.json` reports `schema_ready=true`, `missing_tables=[]`, and `missing_columns={}`.
- pre-canary `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, and `source_claim` counts are `0` or explicitly explained.
- `/health/ingest` has no unexpected schema blocker.
- credential owner approves one canary key id and keeps the HMAC secret in the approved secret store.
- field operator approves exactly one worker PC/scanner and one source CSV/tray scenario.
- downstream owner identifies the dashboard/program target for today, trace, summary, and export validation.
- rollback owner confirms Syncthing/archive remains enabled as shadow/rollback and is not removed during canary.

## Required Owner Signoff

| Owner role | Required approval before canary POST | Evidence marker |
| --- | --- | --- |
| Credential owner | Approves one active key id, one `producer_install_id`, one `source_host_id`, and secret-store access without exposing the HMAC secret. | key id, install id, source host id |
| Field operator | Approves the specific PC, scanner, operator, worker name, master label, and source CSV/tray scenario. | PC id, operator, scenario id |
| DB owner | Confirms Phase 2 schema readiness and pre-canary counts. | Phase 2 refs |
| App owner | Confirms approved FQDN route and deployed ingest app state. | endpoint, app hash/ref |
| Downstream owner | Confirms expected trace/summary/export checks after canary. | dashboard/program target |
| Rollback owner | Confirms legacy Syncthing/archive remains available and no service/task changes are bundled with canary. | rollback contact |
| Change coordinator | Confirms canary is limited to one PC and one source file before 20-PC testing. | change id |

## Endpoint And Identity Scope

- Approved endpoint: `https://worker.kmtecherp.com/api/producer-ingest/v1/source-file` or separately approved staging URL.
- Canary scope: one PC, one worker, one source CSV/tray scenario, one initial upload, one idempotency replay.
- Identity fields: `source_host_id`, `producer_install_id`, `key_id`, `client_batch_id`, `idempotency_key`, and `server_source_file_id`.
- HMAC timestamp must be within the approved skew window.
- Nonce must be accepted exactly once; replay must return the stored receipt or an explicitly idempotent result.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `03_one_pc_canary`.

- TLS/certificate/proxy metadata for the FQDN route.
- redacted request metadata: program, source ids, key id, nonce hash, idempotency key hash, source CSV hash, source row count, and request id.
- server receipt summary: receipt id/hash, accepted row count, rejected/quarantined row count, raw artifact id/hash, and server source file id.
- nonce/idempotency evidence: first upload accepted, replay returns stored receipt/idempotent result, no duplicate projection.
- DB evidence: `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `common_ingested_events`, projection, summary, and quarantine deltas.
- downstream evidence: today view, trace, summary, and export counts match the source CSV row/product counts.
- operator status evidence showing last success/failure, queue state, and retry state.

Do not store raw HMAC secret, producer secret, bearer token, raw receipt JSON, full raw payload, full barcode dump, personal password, or private contact details.

## PASS Criteria

- TLS/FQDN route is valid for the approved endpoint.
- HMAC/key id/timestamp/nonce validation passes.
- Replay is idempotent and does not create an extra receipt, projection row, or summary quantity.
- Raw artifact is saved server-side and its content hash matches the source CSV hash.
- `source_claim` row exists with the expected source identity and claim state.
- `common_ingested_events`, transfer projection, summary, and quarantine deltas reconcile to the source CSV row count.
- Downstream today/trace/summary/export outputs match the canary source and receipt summary.
- Syncthing/archive remains enabled but does not double count the canary event.

## Stop Conditions

Stop before 20-PC testing if any item is true:

- Credential material would be exposed in evidence, logs, screenshots, or chat.
- Bad HMAC, expired key, revoked key, duplicate key id, or timestamp skew is accepted.
- Nonce replay creates a second accepted write instead of an idempotent result.
- Receipt, raw artifact, source_claim, common event, projection, summary, or quarantine deltas do not reconcile to source rows.
- Downstream today/trace/summary/export cannot find the canary or reports different totals.
- Syncthing/archive or replay double counts the same source event.
- Operator status cannot explain the last canary failure or retry state.

## Next Gate

One-PC canary PASS does not approve 20-PC concurrency, shadow burn-in, rollback rehearsal, production Syncthing removal, or release-package installation. Those require separate evidence and signoff.
