# Phase 4 Twenty-PC Field Concurrency Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync 20-PC field/VM concurrency review

## Purpose

This packet defines what owners must approve and what evidence must be collected before a minimum 20 approved physical/VM worker PCs run a concurrent HTTPS producer test.

This document is not execution approval. It does not authorize producer POST upload outside the approved 20-PC staging/test window, HMAC secret disclosure, credential issue/rotation/revocation, Syncthing mutation, rollback rehearsal, service or scheduled task changes, schema `--execute`, production DB mutation, or Syncthing removal.

## Preconditions

20-PC concurrency review may start only after:

- `docs/PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md` records one-PC canary PASS.
- the one-PC canary evidence proves HMAC, timestamp, nonce, idempotency, receipt storage, raw artifact storage, `source_claim`, downstream reconciliation, and no double count.
- the approved staging/test HTTPS endpoint is healthy for the planned test window.
- DB owner records pre-run counts for `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `common_ingested_events`, projection, summary, and quarantine tables.
- credential owner approves at least 20 distinct `source_host_id`, `producer_install_id`, and `key_id` mappings without exposing HMAC secrets.
- field operator approves at least 20 physical/VM PCs, scanner availability, same Korean filename scenario, same worker name scenario, and restart/resume procedure.
- downstream owner approves the dashboard/program target for today, past lookup, trace, summary, and export checks.
- rollback owner confirms Syncthing/archive remains enabled as shadow/rollback and is not removed during this run.
- change coordinator confirms the planned fault windows, network interruption method, relay restart/resume scope, and stop authority.

## Required Owner Signoff

| Owner role | Required approval before 20-PC run | Evidence marker |
| --- | --- | --- |
| Credential owner | Approves at least 20 unique PC identity rows and verifies no duplicate `source_host_id`, `producer_install_id`, or key id collision. | redacted identity matrix |
| Field operator | Approves physical/VM PC list, scanner readiness, same Korean filename, same worker name, duplicate resend, network interruption, and relay queue restart/resume steps. | PC roster and scenario id |
| DB owner | Confirms schema readiness, query-only baseline counts, and reconciliation queries. | before-count artifact |
| App owner | Confirms endpoint route, deployed ingest version, rate limit policy, and allowed test window. | endpoint and app ref |
| Downstream owner | Confirms today/past/trace/summary/export validation target and expected aggregation grain. | dashboard/program target |
| Rollback owner | Confirms Syncthing/archive remains available and that no Syncthing retirement is bundled with this test. | rollback contact |
| Security owner | Confirms redaction rules for request metadata, receipt summaries, identities, screenshots, and logs. | redaction checklist |
| Change coordinator | Confirms the exact run window, fault windows, stop conditions, and communication channel. | change id |

## Test Scope

- Minimum cohort: at least 20 distinct approved physical/VM PCs.
- Required identity fields per PC: `source_host_id`, `producer_install_id`, `key_id`, hostname, worker name, scanner/VM marker, and approved endpoint scope.
- Required source artifact fields per PC: source CSV filename, source CSV SHA-256, source row count, product quantity count, and local event time range.
- Required same-name stress case: all PCs use the same Korean CSV filename and the same worker name while retaining distinct source identities.
- Required replay case: at least five PCs repeat the same upload with the same idempotency key and nonce replay coverage as approved by the app owner.
- Required interruption case: at least one controlled network interruption or endpoint retry window occurs while queues contain pending uploads.
- Required resume case: relay queue restart/resume is performed on at least five PCs after pending rows exist.
- Required duplicate source defense: server `source_claim` and projection logic must prevent same source artifact replay from creating duplicate summary counts.

The scope does not include credential lifecycle beyond already approved static keys, Syncthing removal, production DB schema mutation, scheduled task/service rollout, or rollback rehearsal.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `05_twenty_pc_concurrency`.

- 20 PC identity matrix with HMAC secrets redacted.
- per-PC source CSV filename, CSV SHA-256, row count, product quantity count, local event time range, and worker name.
- per-PC relay DB before/after queue counts, pending/dead-letter counts, runtime status, and `status.json` hash.
- retry/resume evidence for duplicate resend, network interruption, timeout/retry, queue restart, and resume drain.
- server receipt summary per accepted upload: receipt id/hash, request id, source ids, accepted row count, quarantined row count, raw artifact id/hash, `source_claim` id, and idempotency result.
- DB reconciliation evidence for `producer_ingest_receipts`, `producer_ingest_nonces`, `producer_ingest_raw_artifacts`, `source_claim`, `common_ingested_events`, projection, summary, and quarantine deltas.
- downstream evidence for today view, past lookup, trace, summary, and export totals.
- operator report evidence showing last failure, next retry, pending count, operator-review rows, and final queue-drained state.
- Syncthing/archive shadow observation proving the legacy path is still available but does not double count the direct HTTPS events.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, personal passwords, or private contact details.

## PASS Criteria

- At least 20 distinct approved identities are present in the signed identity matrix and every accepted receipt maps to one of them.
- Same Korean filename and same worker name do not collapse separate PC identities.
- Duplicate resend and idempotency replay do not create extra receipts, `source_claim` rows, projection rows, or summary quantities.
- Network interruption and retry evidence show pending queues resume and drain without data loss.
- Queue restart/resume evidence shows no orphaned spool files, no lost CSV rows, and no duplicate projection.
- DB deltas reconcile: accepted + quarantined + rejected/error rows match the original source CSV row counts across all PCs.
- Downstream today, past lookup, trace, summary, and export totals match the receipt and source CSV totals.
- Operator status explains every failure, retry, operator-review row, and final queue state.
- Syncthing/archive remains enabled but does not double count any source event.

## Stop Conditions

Stop before downstream/shadow/rollback expansion if any item is true:

- Fewer than 20 approved distinct PC identities produce usable evidence.
- Any duplicate `source_host_id`, `producer_install_id`, key id, idempotency key, or server source id collision is accepted unexpectedly.
- Same filename or same worker name causes merged, overwritten, or missing source claims.
- Duplicate resend creates a second accepted write or extra projection/summary count.
- A network interruption leaves queued uploads stuck without a visible retry reason or operator action.
- Queue restart/resume loses CSV rows, spool files, runtime status, or receipt correlation.
- Receipt, raw artifact, source claim, common event, projection, summary, or quarantine deltas do not reconcile to source rows.
- Downstream today/past/trace/summary/export totals differ from receipt/source totals.
- Syncthing/archive or replay double counts any source event.
- Evidence would expose raw HMAC secrets, raw receipt JSON, full payloads, or private credentials.

## Next Gate

20-PC concurrency PASS does not approve Syncthing removal, rollback rehearsal, or production rollout by itself. The next gates are downstream today/past/export validation, Syncthing shadow no-double-count proof, rollback rehearsal, operator report acceptance, and final signoff.
