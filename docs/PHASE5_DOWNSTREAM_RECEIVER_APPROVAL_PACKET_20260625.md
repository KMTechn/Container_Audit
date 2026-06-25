# Phase 5 Downstream Receiver Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync downstream today/past/trace/summary/export review

## Purpose

This packet defines what downstream, DB, app, field, security, rollback, and change owners must approve before validating that WorkerAnalysisGUI-web or the actual receiving program correctly receives the approved canary/20-PC data.

This document is not execution approval. It does not authorize producer POST upload, HMAC secret disclosure, credential issue/rotation/revocation, service or scheduled task changes, schema `--execute`, production DB mutation, rollback rehearsal, Syncthing mutation, Syncthing removal, or export of raw secrets, raw receipt JSON, or full raw payloads.

## Preconditions

Downstream receiver review may start only after:

- `docs/PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md` records 20-PC concurrency PASS or the change coordinator explicitly narrows the review to Phase 3 one-PC canary evidence.
- server receipts, `source_claim`, `common_ingested_events`, projection, summary, and quarantine deltas reconcile to source CSV row counts.
- downstream owner approves the exact target: WorkerAnalysisGUI-web URL or actual receiving program, environment, account, and read-only access scope.
- DB owner approves read-only reconciliation queries and confirms the dashboard/program reads the intended staging/test or production-equivalent DB.
- app owner identifies the deployed downstream build/version and any API route used for screenshots or export.
- field operator provides the source PC list, worker names, source CSV hashes, and run window used in Phase 3/4.
- security owner approves screenshot/export redaction and malicious-string rendering checks.
- rollback owner confirms Syncthing/archive remains available and is not removed during downstream validation.
- change coordinator confirms date/time window, timezone, evidence path, and stop authority.

## Required Owner Signoff

| Owner role | Required approval before downstream validation | Evidence marker |
| --- | --- | --- |
| Downstream owner | Approves target dashboard/program, today view, past lookup, trace, summary, and export workflow. | target URL/program and account |
| DB owner | Approves read-only query set, projection tables, summary tables, quarantine tables, and time-window filters. | query bundle and before-counts |
| App owner | Confirms deployed downstream build/version and API/export routes under test. | build ref and route list |
| Field operator | Provides PC identities, worker names, source CSV hashes, product quantities, and run window. | source roster |
| Security owner | Confirms redaction rules, screenshot/export handling, XSS/formula/path traversal test strings, and no raw secrets. | security checklist |
| Rollback owner | Confirms Syncthing/archive remains available and not retired by this packet. | rollback contact |
| Change coordinator | Confirms evidence directory, date/timezone window, pass/fail reviewer, and stop authority. | change id |

## Validation Scope

- Today view: shows the approved canary/20-PC records for the current work date and excludes unrelated legacy/archive duplicates.
- Past lookup: finds the same approved records when queried by historical date/time window after the work date changes.
- Trace: links a downstream row back to `receipt_id`, `server_source_file_id`, `source_claim`, `source_host_id`, `producer_install_id`, raw artifact hash, and source CSV hash.
- Summary: transfer summary quantities match accepted source CSV product quantity counts and do not mix packaging `TRAY_COMPLETE` with Container_Audit legacy transfer events.
- Export: exported CSV/XLSX/JSON row count, product quantity, date range, worker names, source ids, and SHA-256 match the approved downstream query result.
- Error/quarantine view: quarantined or rejected rows are visible through the approved review path without being counted in accepted transfer summary totals.
- Malicious-string rendering: barcode, item, worker name, formula, HTML/script, and path traversal strings remain inert text in dashboard views and exports.

The scope does not include producer upload execution, production DB writes, schema migration, service/task rollout, Syncthing removal, rollback rehearsal, or credential lifecycle changes.

## Evidence To Collect If Approved Later

Store only redacted summaries, screenshots, exports, and hashes in `06_downstream_today_past_export`.

- downstream target identity: URL/program, environment, account role, deployed build/version, and DB identity hash.
- today view screenshot or exported API JSON with secrets redacted.
- past lookup screenshot or exported API JSON with date/timezone filter recorded.
- trace evidence linking downstream row to receipt, source claim, source PC identity, raw artifact hash, and source CSV hash.
- summary evidence comparing downstream quantities with receipt totals, source CSV row counts, product quantity counts, accepted/quarantined/rejected counts, and projection deltas.
- export evidence: file name, SHA-256, row count, product quantity total, date range, worker names, source ids, and formula neutralization note.
- malicious-string rendering evidence for dashboard and export paths.
- Syncthing/archive observation showing legacy path data is not double counted in downstream summary.
- reviewer checklist with PASS/STOP outcome and unresolved gaps.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, personal passwords, private contact details, or unredacted production customer data.

## PASS Criteria

- Today view totals match the approved receipt/source totals for the run window.
- Past lookup returns the same records by date/timezone without changing quantities or losing traceability.
- Trace resolves every sampled downstream row to receipt, source claim, source PC identity, raw artifact hash, and source CSV hash.
- Summary quantities equal accepted source product counts and exclude quarantined/rejected rows.
- Container_Audit legacy transfer events are not mixed with packaging `TRAY_COMPLETE` summary rows.
- Export row count, product quantity total, source ids, worker names, date range, and SHA-256 are recorded and match the dashboard/API query result.
- Malicious strings render as inert text and do not execute script, HTML, path traversal, SQL behavior, or spreadsheet formulas.
- Syncthing/archive observation proves no downstream double count.

## Stop Conditions

Stop before Syncthing shadow, rollback, or final retirement signoff if any item is true:

- Today view, past lookup, trace, summary, or export cannot find the approved canary/20-PC records.
- Downstream totals differ from receipt totals, source CSV row counts, product quantity counts, projection deltas, or DB summary counts.
- Trace cannot resolve to `receipt_id`, `server_source_file_id`, `source_claim`, `source_host_id`, `producer_install_id`, raw artifact hash, and source CSV hash.
- Export row count, quantity total, date range, source ids, or SHA-256 cannot be reproduced.
- Container_Audit transfer events are mixed with packaging `TRAY_COMPLETE` rows.
- Quarantined/rejected rows are counted as accepted summary rows.
- Malicious strings execute or mutate dashboard, DB, query, path, or spreadsheet behavior.
- Evidence would expose raw secrets, raw receipt JSON, full payloads, or private credentials.
- Syncthing/archive or replay double counts any source event in downstream views.

## Next Gate

Downstream receiver PASS does not approve Syncthing removal, rollback rehearsal, or production rollout by itself. The next gates are Syncthing shadow no-double-count proof, rollback rehearsal, operator visibility acceptance, soak/security evidence, and final signoff.
