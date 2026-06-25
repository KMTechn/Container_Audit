# Phase 9 Soak And Security Approval Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync soak, credential, clock, malicious-input, and fault-injection review

## Purpose

This packet defines what owners must approve and what evidence must be collected before running the extended soak and security validation set for HTTPS direct-sync cutover.

This document is not execution approval. It does not authorize producer POST upload, HMAC secret disclosure, credential issue/rotation/revocation, relay pause/resume, service stop/start, scheduled task changes, HTTPS failure injection, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.

## Preconditions

Soak and security review may start only after:

- `docs/PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md` records operator visibility PASS.
- app owner approves the staging/test endpoint, relay config, queue DB path, spool path, runtime status path, log path, and report command used for the soak.
- security owner approves the credential lifecycle plan, key id registry export format, revoked/expired/wrong-key test identities, malicious input corpus, and no-secret evidence rules.
- field/operator owner approves the PC set, scanner availability, worker names, clock-drift method, network interruption method, and operator review checklist.
- DB owner approves read-only reconciliation queries for receipt, nonce, raw artifact, source_claim, common event, projection, summary, quarantine, and operator-review counts.
- downstream owner approves today view, past lookup, trace, summary, export, dashboard browser XSS, and export formula-safety checks for the malicious input corpus.
- rollback owner confirms abort criteria, rollback availability, and restore checks before any 4-8 hour run.
- change coordinator confirms run window, scenario order, evidence directory, stop authority, and PASS/STOP checklist.

## Required Owner Signoff

| Owner role | Required approval before soak/security review | Evidence marker |
| --- | --- | --- |
| App owner | Approves endpoint, relay config, queue/spool/status/log paths, and report command. | command bundle |
| Security owner | Approves credential lifecycle, malicious input corpus, clock/HMAC timestamp checks, and redaction. | security checklist |
| Field/operator owner | Approves PC/scanner set, worker names, clock drift, network interruption, and operator checklist. | field roster |
| DB owner | Approves read-only reconciliation queries and least-privilege test DB role. | query bundle |
| Downstream owner | Approves dashboard/program, export, trace, and browser XSS checks. | downstream target |
| Rollback owner | Approves abort criteria, rollback availability, and restore checks. | rollback marker |
| Change coordinator | Confirms run window, evidence path, stop authority, and final go/no-go owner. | change id |

## Review Scope

- Producer credential lifecycle: valid key, wrong key, revoked key, expired key, duplicated `source_host_id`, duplicated `producer_install_id`, duplicated key id, and key rotation boundary.
- Clock drift: fast PC clock, slow PC clock, HMAC timestamp outside accepted window, server receipt arrival time, source event timestamp, today summary, and past lookup behavior.
- Malicious input: barcode, item, worker name, replacement/exchange fields, CSV details, HTTPS payload, DB rows, dashboard rendering, trace view, summary view, and export fields with SQL, XSS, formula, and path traversal strings.
- Fault injection: server 500/503, timeout, DNS failure, TLS/certificate failure, proxy/header rejection, DB lock, disk pressure, spool corruption, status JSON corruption, queue DB issue, and retry/backoff behavior.
- Soak: at least 4-8 hours or full-day-volume equivalent with one or more retry windows, log growth sampling, DB growth sampling, CPU/memory sampling, queue drain, receipt count, projection count, summary count, and downstream export reconciliation.
- Operator visibility during soak/security: status/report must show last failure, retry class, next retry, queue counts, dead-letter/operator-review rows, rollback availability, and required owner action.

The scope does not include production cutover, production credentials, schema migration, service/task mutation, relay pause/resume outside the approved scenario, Syncthing reconfiguration, or Syncthing removal.

## Evidence To Collect If Approved Later

Store only redacted summaries and hashes in `10_soak_and_security`.

- credential lifecycle evidence: key id registry export hash, accepted valid-key receipt summary, wrong/revoked/expired key rejection summaries, duplicate identity rejection summary, and key rotation boundary result.
- clock drift evidence: PC time offset, signed timestamp, HMAC timestamp decision, server receipt arrival time, source event timestamp, today summary, past lookup, and downstream trace result.
- malicious input evidence: corpus hash, UI/CSV/HTTPS/DB/dashboard/export result table, inert dashboard screenshots or DOM notes, export formula-safety note, and row-count reconciliation.
- fault injection evidence: server 500/503, timeout, DNS, TLS, proxy/header, DB lock, disk pressure, spool corruption, status corruption, queue DB issue, retry/backoff, operator-review, dead-letter, and recovery evidence.
- soak metrics: run duration, event volume, per-PC throughput, retry windows, queue depth over time, receipt count, accepted/quarantine/error counts, DB size samples, CPU/memory samples, log size samples, and final queue drain.
- downstream evidence: today view, past lookup, trace, summary, export checksum, and dashboard browser XSS result tied to safe receipt/source ids.
- rollback/abort evidence: abort criteria acknowledgement, rollback availability marker, restore check, and no data loss/no double-count summary.

Do not store raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data.

## PASS Criteria

- Valid producer credentials write exactly once; wrong, revoked, expired, duplicated, or rotated-out credentials cannot write receipt, source_claim, projection, or summary rows.
- Clock drift is handled by server-authoritative receipt time and HMAC timestamp policy without corrupting today summary, past lookup, trace, or export.
- Malicious SQL, XSS, formula, and path traversal strings remain inert data across UI, CSV, HTTPS, DB, dashboard, trace, summary, and export.
- Faults are classified correctly, retryable faults retry with bounded backoff, permanent/corrupt artifacts go to operator review or dead letter, and recovery drains the queue without duplicate projection.
- Soak completes at least 4-8 hours or full-day-volume equivalent without unbounded CPU, memory, DB, or log growth.
- Accepted, quarantined, errored, projected, summarized, downstream, and exported counts reconcile to the original source CSV rows and receipts.
- Operator status/report remains useful during and after the soak, including last failure, retry class, next retry, queue counts, operator-review/dead-letter rows, rollback availability, and required owner action.
- No evidence exposes raw secrets, raw receipt JSON, full payloads, private credentials, or unredacted production customer data.

## Stop Conditions

Stop before final signoff or Syncthing retirement review if any item is true:

- Wrong, revoked, expired, duplicated, or rotated-out credentials can create receipt, source_claim, projection, summary, or downstream rows.
- Clock drift bypasses HMAC timestamp policy or corrupts today/past summaries.
- Malicious input executes as SQL, script, formula, path traversal, HTML, or command behavior in any UI, CSV, HTTPS, DB, dashboard, trace, summary, or export path.
- Retryable faults do not retry, permanent/corrupt artifacts are silently dropped, or operator-review/dead-letter rows are missing.
- Queue depth, DB size, memory, CPU, or log size grows without bound during soak.
- Accepted/quarantine/error/projection/summary/downstream/export counts do not reconcile to source CSV rows and receipts.
- Evidence would expose raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full payloads, passwords, private contacts, or unredacted production customer data.
- Rollback availability, abort criteria, or restore checks are missing before or during the run.

## Next Gate

Soak/security PASS does not approve Syncthing removal. The next gate is final signoff: backup/retention review, release-package/config freeze, dashboard browser XSS evidence, evidence archive hash, and signed Syncthing retirement approval.
