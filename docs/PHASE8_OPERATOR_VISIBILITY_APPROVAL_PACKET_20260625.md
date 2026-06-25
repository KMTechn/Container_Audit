# Phase 8 Operator Visibility Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync operator visibility review

## Purpose

This packet defines what owners must approve and what evidence must be collected before accepting the field operator status/report experience for HTTPS direct-sync cutover.

This document is not execution approval. It does not authorize producer POST upload, HMAC secret disclosure, credential issue/rotation/revocation, relay pause/resume, service stop/start, scheduled task changes, HTTPS failure injection, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.

## Preconditions

Operator visibility review may start only after:

- `docs/PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md` records rollback rehearsal PASS, or the change coordinator narrows this review to controlled fault-status evidence only.
- app owner identifies the relay status command, report command, runtime status path, queue DB path, spool path, dead-letter path, operator-review path, and receipt summary path.
- field/operator owner identifies the operator accounts, scanner PC names, approved language for status messages, and the person expected to diagnose upload failures.
- DB owner approves read-only queue/count reconciliation for pending, retryable, permanent, dead-letter, operator-review, accepted receipt, quarantine, projection, and summary rows.
- downstream owner approves the status-to-dashboard trace checks for today view, past lookup, trace, summary, and export.
- rollback owner confirms the report displays whether legacy Syncthing/archive-compatible analysis is available during HTTPS failure.
- security owner approves screenshot and JSON redaction rules, including no raw HMAC secret, producer secret, bearer token, raw receipt JSON, full raw payload, private password, or private contact detail.
- change coordinator confirms evidence directory, scenario order, stop authority, and PASS/STOP checklist.

## Required Owner Signoff

| Owner role | Required approval before operator visibility review | Evidence marker |
| --- | --- | --- |
| Field/operator owner | Approves operator accounts, expected status language, and diagnosis checklist. | operator checklist |
| App owner | Approves status/report commands, runtime status path, queue DB path, spool path, and receipt summary path. | command bundle |
| DB owner | Approves read-only reconciliation for queue, receipt, quarantine, projection, and summary counts. | query bundle |
| Downstream owner | Approves today/past/trace/summary/export checks tied to operator-visible receipt ids. | dashboard/program target |
| Rollback owner | Confirms legacy path availability is visible when HTTPS is paused or failing. | rollback status marker |
| Security owner | Confirms redaction and no raw secret/raw receipt/full payload rules. | redaction checklist |
| Change coordinator | Confirms run window, evidence path, stop authority, and final go/no-go owner. | change id |

## Review Scope

- Healthy state: status/report shows endpoint target, source host id, producer install id, queue counts, last success, last receipt summary, and no hidden pending work.
- Retryable network/server fault: status/report shows last failure, retry class, next retry time, attempt count, queued artifact count, and the expected operator action.
- Credential/key fault: status/report shows key id, rejection class, permanent or review routing, and the exact owner to contact without exposing secrets.
- DNS/TLS/proxy fault: status/report distinguishes DNS failure, TLS/certificate failure, proxy/header rejection, timeout, server 500/503, and DB lock when available.
- Disk/spool/status corruption: status/report shows disk-full, unreadable spool, corrupt spool, corrupt `status.json`, queue DB issue, and the repair path without deleting source CSV.
- Operator-review rows: status/report lists count, reason, artifact hash or safe id, worker/source identity, created time, and required manual disposition.
- Downstream trace: operator can connect last receipt/source id to today view, past lookup, trace, summary, and export without using raw payloads.
- Rollback visibility: status/report shows whether relay is paused, service/task is stopped, legacy Syncthing/archive-compatible analysis is available, and queued uploads can resume.

The scope does not include production cutover, producer upload outside the approved scenario, schema migration, credential lifecycle changes, service/task mutation, relay pause/resume, Syncthing reconfiguration, or Syncthing removal.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `09_operator_visibility`.

- healthy state evidence: status JSON, report output, last success, last receipt summary, endpoint label, queue counts, and runtime status hash.
- retryable fault evidence: endpoint timeout or server 500/503 status, last failure, retry class, `next_retry_after`, attempt count, and queue drain after recovery.
- credential fault evidence: rejected key id, rejection class, operator action, and confirmation that no raw key or secret appears.
- DNS/TLS/proxy fault evidence: failure class, certificate/proxy metadata summary, last failure, and next action.
- disk/spool/status corruption evidence: disk-full marker or corrupt test artifact marker, operator-review/dead-letter row, source CSV hash, and recovery status.
- operator-review evidence: row count, safe artifact id or hash, reason code, worker/source identity, created time, and disposition checklist.
- downstream trace evidence: today/past/trace/summary/export screenshots or hashes tied to the same receipt/source id.
- rollback visibility evidence: paused/stopped/fallback status marker, legacy path availability marker, and resume-ready queue count.
- final operator checklist proving the field operator can diagnose the reason, next retry, owner action, and data-safety state from report output alone.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, personal passwords, private contact details, or unredacted production customer data.

## PASS Criteria

- Operator can identify the latest upload success, latest failure, failure class, retryable/permanent status, next retry time, and required next action from status/report alone.
- Queue, pending, retryable, dead-letter, operator-review, accepted receipt, quarantine, projection, and summary counts reconcile with read-only DB or local queue evidence.
- Credential, DNS, TLS, proxy, timeout, server 500/503, DB lock, disk-full, corrupt spool, and corrupt `status.json` cases are distinguishable in the report.
- Operator-review rows show safe ids/hashes, reason codes, source identity, created time, and disposition path without exposing raw payloads or secrets.
- Downstream today view, past lookup, trace, summary, and export can be tied to the same safe receipt/source id visible to the operator.
- Rollback/legacy availability and queued-upload resume state are visible without changing Syncthing configuration or deleting queue/spool/source data.
- No screenshot, JSON, report output, or evidence placeholder exposes raw secrets, raw receipt JSON, full payloads, or private credentials.

## Stop Conditions

Stop before soak/security, final signoff, or Syncthing retirement review if any item is true:

- Status/report lacks last failure, next retry time, queue counts, operator-review count, or required next action.
- Status/report cannot distinguish retryable network/server faults from permanent credential, malformed artifact, or corrupt local-state faults.
- Queue counts, receipt counts, projection counts, summary counts, or downstream totals differ without explanation.
- Operator-review/dead-letter rows are hidden, lack reason codes, or cannot be tied to safe artifact ids/hashes.
- Report output exposes raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full payloads, passwords, private contact details, or unredacted production customer data.
- Relay paused/stopped, legacy path availability, or resume-ready state is missing or misleading.
- Operator cannot diagnose the failure reason and next owner action from report output without developer assistance.

## Next Gate

Operator visibility PASS does not approve Syncthing removal. The next gates are soak/security evidence, backup/retention review, release-package signoff, dashboard browser XSS rendering evidence, and final signed retirement approval.
