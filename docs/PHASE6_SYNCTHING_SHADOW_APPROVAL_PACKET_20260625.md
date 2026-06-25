# Phase 6 Syncthing Shadow No-Double-Count Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync plus Syncthing/archive shadow no-double-count review

## Purpose

This packet defines what owners must approve and what evidence must be collected before running HTTPS direct ingest and the existing Syncthing/archive compatibility path side by side as a shadow run.

This document is not execution approval. It does not authorize producer POST upload outside the approved staging/test window, HMAC secret disclosure, credential issue/rotation/revocation, Syncthing config changes, Syncthing folder removal, Syncthing service stop/start, scheduled task changes, schema `--execute`, production DB mutation, rollback rehearsal, or Syncthing removal.

## Preconditions

Syncthing shadow review may start only after:

- `docs/PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md` records downstream receiver PASS.
- direct HTTPS evidence includes receipt summaries, raw artifact hashes, `source_claim`, `common_ingested_events`, projection, summary, and quarantine reconciliation.
- downstream evidence proves today, past lookup, trace, summary, and export totals match receipt/source totals.
- Syncthing/archive owner identifies the exact legacy archive folder, file naming rule, ingest path, retention rule, and read-only observation method.
- DB owner approves source-claim and projection reconciliation queries before and after shadow observation.
- app owner confirms the deployed conflict/idempotency policy for direct HTTPS versus legacy archive artifacts.
- field operator provides source CSV hashes, worker names, PC identities, and run window.
- rollback owner confirms the legacy Syncthing/archive path remains available and is not removed or reconfigured during this packet.
- security owner approves redaction for receipt summaries, source identifiers, archive paths, screenshots, and logs.
- change coordinator confirms test window, evidence directory, reviewer, and stop authority.

## Required Owner Signoff

| Owner role | Required approval before shadow run | Evidence marker |
| --- | --- | --- |
| Syncthing/archive owner | Approves legacy archive path observation, no config mutation, no folder removal, and no service stop/start. | archive path ref |
| App owner | Confirms direct-vs-archive conflict policy, idempotency behavior, and source-claim precedence. | policy/build ref |
| DB owner | Approves read-only source_claim/source_claim_history/common/projection/summary/quarantine reconciliation queries. | query bundle |
| Downstream owner | Confirms no-double-count validation in today/past/trace/summary/export views. | dashboard/program target |
| Field operator | Provides source CSV hashes, PC identities, worker names, and run window. | source roster |
| Rollback owner | Confirms legacy path remains available for rollback and is not retired by shadow PASS. | rollback contact |
| Security owner | Confirms redaction and no raw secret/raw receipt/full payload evidence rules. | redaction checklist |
| Change coordinator | Confirms run window, evidence path, stop conditions, and communication channel. | change id |

## Validation Scope

- Direct path: approved HTTPS receipt, raw artifact hash, `source_claim`, common event, projection, summary, quarantine, and downstream trace.
- Legacy path: Syncthing/archive file observation or legacy ingest evidence for the same source artifact hash.
- Conflict path: `source_claim_history` or equivalent conflict evidence showing which path became authoritative and why the duplicate path was idempotent, ignored, or quarantined.
- Projection parity: summary/projection totals before and after the shadow observation remain counted once per source event.
- Downstream parity: today, past lookup, trace, summary, and export outputs do not show a duplicate row or duplicate quantity.
- Rollback availability: Syncthing/archive remains available as rollback evidence but is not used to justify production retirement.

The scope does not include Syncthing config edits, folder removal, service/task changes, production DB writes, schema migration, rollback rehearsal, or Syncthing removal.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `07_syncthing_shadow_no_double_count`.

- direct HTTPS receipt evidence: receipt id/hash, request id, source ids, accepted row count, quarantined row count, raw artifact id/hash, and idempotency result.
- Syncthing/archive observation: archive path hash/ref, file name, source CSV hash, row count, observed timestamp, and legacy ingest status.
- `source_claim` and `source_claim_history` evidence showing direct and legacy claims, conflict state, authoritative path, and duplicate classification.
- DB reconciliation for `common_ingested_events`, projection, summary, quarantine, and source-claim deltas before and after shadow observation.
- downstream today/past/trace/summary/export evidence showing unchanged single-count totals.
- operator report showing no unexpected retry, dead-letter, or operator-review row caused by the shadow duplicate.
- rollback availability note proving the legacy path still exists after the shadow run.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, personal passwords, private contact details, or unredacted production customer data.

## PASS Criteria

- The same source CSV/artifact hash is visible in both HTTPS direct evidence and Syncthing/archive evidence.
- Exactly one authoritative `source_claim` outcome exists for the source event.
- `source_claim_history` or equivalent evidence records the duplicate/shadow decision.
- Common event, projection, summary, and downstream totals remain counted once.
- Direct replay, legacy archive replay, and mixed path replay do not create extra accepted rows or summary quantities.
- Quarantined or ignored shadow duplicates are visible to operators without being counted as accepted transfer summary.
- Syncthing/archive remains available and unchanged for rollback.
- No evidence exposes raw secrets, raw receipt JSON, or full raw payloads.

## Stop Conditions

Stop before rollback rehearsal or Syncthing retirement review if any item is true:

- HTTPS direct and Syncthing/archive paths double count the same source event.
- `source_claim` or `source_claim_history` cannot explain the authoritative path and duplicate/shadow decision.
- Direct and legacy source artifact hashes do not match when the scenario claims they are the same source.
- Projection, summary, downstream today/past/trace/export, or DB reconciliation totals differ from receipt/source totals.
- A shadow duplicate is silently accepted as a new source instead of idempotent, ignored, or quarantined.
- Syncthing config, folder registration, service, or scheduled task state changes during this packet.
- Rollback owner cannot confirm legacy path availability after the shadow run.
- Evidence would expose raw HMAC secrets, raw receipt JSON, full payloads, or private credentials.

## Next Gate

Syncthing shadow PASS does not approve Syncthing removal. The next gates are rollback rehearsal, operator visibility acceptance, soak/security evidence, backup/retention review, release-package signoff, and final signed retirement approval.
