# Phase 7 Rollback Rehearsal Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync rollback rehearsal review

## Purpose

This packet defines what owners must approve and what evidence must be collected before rehearsing rollback from HTTPS direct-sync back to the legacy Syncthing/archive-compatible path.

This document is not execution approval. It does not authorize producer POST upload, HMAC secret disclosure, credential issue/rotation/revocation, relay pause/resume, service stop/start, scheduled task changes, HTTPS failure injection, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.

## Preconditions

Rollback rehearsal review may start only after:

- `docs/PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md` records Syncthing shadow no-double-count PASS.
- direct HTTPS, downstream, and shadow evidence prove accepted records are counted once and legacy path remains available.
- rollback owner approves the rollback window, owner contact list, abort criteria, and restore order.
- app owner identifies the relay process, runtime status path, queue DB path, spool path, and approved pause/resume commands.
- Windows/operator owner identifies scheduled task or service names, stop/start commands, and restore verification commands.
- Syncthing/archive owner identifies the legacy archive path and confirms no Syncthing removal or reconfiguration is bundled with rehearsal.
- DB owner approves read-only before/after reconciliation queries for receipt, source_claim, common event, projection, summary, and quarantine counts.
- downstream owner approves the legacy-path verification screen/program and expected no-duplicate totals.
- security owner approves redaction for status JSON, service/task screenshots, queue DB summaries, archive paths, and receipts.
- change coordinator confirms evidence directory, communications channel, stop authority, and timebox.

## Required Owner Signoff

| Owner role | Required approval before rollback rehearsal | Evidence marker |
| --- | --- | --- |
| Rollback owner | Approves rollback window, abort criteria, restore order, and final go/no-go authority. | rollback ticket |
| App owner | Approves relay pause/resume commands, runtime status path, queue DB path, spool path, and expected status transitions. | command bundle |
| Windows/operator owner | Approves scheduled task/service stop/start commands and restore checks. | task/service roster |
| Syncthing/archive owner | Approves legacy path verification and confirms no config/folder/service mutation beyond the rehearsal script. | archive path ref |
| DB owner | Approves read-only before/after reconciliation queries. | query bundle |
| Downstream owner | Approves legacy-path screen/program checks and summary/export parity checks. | dashboard/program target |
| Security owner | Confirms redaction and no raw secret/raw receipt/full payload rules. | redaction checklist |
| Change coordinator | Confirms run window, communications, evidence path, and stop authority. | change id |

## Rehearsal Scope

- Relay pause: confirm the approved relay pause command changes status visibly and stops new HTTPS sends without deleting queue/spool data.
- Scheduled task/service stop: confirm approved stop command affects only the intended relay/task/service and can be restored.
- HTTPS failure fallback: confirm the operator can identify HTTPS failure and use the legacy Syncthing/archive-compatible path for analysis.
- CSV/archive preservation: confirm source CSV, event CSV, relay spool, queue DB, parked tray files, and archive files retain hashes before and after rehearsal.
- Resume: confirm queued uploads resume after relay/task/service restoration and do not duplicate projection or summary counts.
- Downstream rollback verification: confirm today/past/trace/summary/export views remain available through legacy or restored paths.
- Operator visibility: confirm `status/report` explains pause, stop, failure, next retry, operator-review rows, and final queue-drained state.

The scope does not include production cutover, Syncthing removal, schema migration, credential lifecycle changes, or unapproved service/task changes.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `08_rollback_rehearsal`.

- relay pause evidence: command transcript, status before/after, pending count, last failure/next retry, and runtime status hash.
- scheduled task/service stop evidence: exact target name, status before/after, restore command, and restore status.
- HTTPS failure/fallback evidence: controlled failure marker, operator diagnosis, legacy path verification, and downstream availability.
- CSV/archive preservation evidence: source CSV hash, event CSV hash, spool hash, queue DB hash, parked tray hash, archive file hash before/after.
- queued upload resume evidence: queue counts before pause, during pause, after resume, accepted receipt summary, and idempotency result.
- DB reconciliation evidence: receipt, raw artifact, source_claim, common event, projection, summary, and quarantine counts before/after.
- downstream evidence: today/past/trace/summary/export totals before/after rollback rehearsal.
- operator report showing no unexplained pending, dead-letter, or operator-review rows after restoration.
- final rollback rehearsal PASS/STOP checklist signed by rollback owner and change coordinator.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, personal passwords, private contact details, or unredacted production customer data.

## PASS Criteria

- Relay pause is visible in operator status and does not delete queue/spool/source files.
- Scheduled task/service stop affects only the approved target and is restored successfully.
- Legacy Syncthing/archive-compatible path remains available for analysis while HTTPS is unavailable.
- CSV, archive, spool, queue DB, and parked tray hashes are preserved or every intentional hash change is explained.
- Queued uploads resume and drain without duplicate receipt, source_claim, projection, summary, or downstream counts.
- DB and downstream totals before/after rollback rehearsal reconcile to source receipts and CSV row counts.
- Operator status/report explains pause, failure, retry, resume, operator-review, and final queue state.
- No evidence exposes raw secrets, raw receipt JSON, or full raw payloads.

## Stop Conditions

Stop before soak/security, final signoff, or Syncthing retirement review if any item is true:

- Relay pause/resume, task/service stop/start, or HTTPS failure injection targets the wrong process or cannot be restored.
- Source CSV, event CSV, relay spool, queue DB, parked tray, or archive files are lost or hash-mismatched without explanation.
- Legacy path cannot support analysis while HTTPS is unavailable.
- Queued uploads do not resume, remain stuck without operator-visible reason, or duplicate projection/summary counts.
- DB reconciliation, downstream today/past/trace/export, or operator report totals differ from source receipts.
- Syncthing config, folder registration, or service state changes outside the approved rehearsal scope.
- Evidence would expose raw HMAC secrets, raw receipt JSON, full payloads, or private credentials.

## Next Gate

Rollback rehearsal PASS does not approve Syncthing removal. The next gates are operator visibility acceptance, soak/security evidence, backup/retention review, release-package signoff, and final signed retirement approval.
