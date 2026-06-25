# Phase 0 Dry-Run Transcript Template

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync Phase 0 read-only preflight 실행 기록

## Scope

Use this transcript after `docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md` is signed and while running `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md`.

This template records evidence review only. It does not authorize producer POST upload, authenticated HMAC canary, schema `--execute`, DB write/update/delete, credential lifecycle operations, service or scheduled task changes, relay pause/resume, Syncthing mutation, rollback rehearsal, 20-PC run, or Syncthing removal.

## Run Metadata

| Field | Value |
| --- | --- |
| change id | |
| transcript id | `phase0-readonly-YYYYMMDDThhmmssZ` |
| operator | |
| reviewer | |
| server host | |
| `APP` | `/root/WorkerAnalysisGUI-web` |
| `DB` | `/mnt/rebuild/worker-analysis/data/worker_analysis.db` |
| approved FQDN | `https://worker.kmtecherp.com` |
| route checked | `OPTIONS /api/producer-ingest/v1/source-file` |
| evidence directory | |
| owner checklist ref | `docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md` |
| command packet ref | `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` |
| local packet scaffold | `.agents/agent-loop/runs/container-audit-e2e-20260624/evidence/production-cutover-packet-v5-20260625/00_freeze_manifest` |

## Pre-Run Confirmation

| Check | PASS/FAIL | Evidence ref | Notes |
| --- | --- | --- | --- |
| All required owner signoff entries are present. | | | |
| Evidence directory is fresh and empty before command output. | | | |
| `APP`, `DB`, FQDN, route, and evidence root match the approved checklist. | | | |
| No producer credential, HMAC secret, bearer token, raw receipt JSON, or full raw payload is needed. | | | |
| Operator understands Phase 0 may end as `phase0_blocked_before_mutation`. | | | |

Stop before command execution if any pre-run check fails.

## Command Result Transcript

Record one row per command or generated artifact from the read-only packet.

| Step | Command/artifact | Start time UTC | End time UTC | Exit/status | Evidence file | Redaction check | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `direct_sync_ops_status.before.json` | | | | | no secrets/full payloads | PASS/STOP |
| 2 | `health.before.json` | | | | | no secrets/full payloads | PASS/STOP |
| 3 | `health_ingest.before.json` | | | 200 or captured 503 | | no secrets/full payloads | PASS/STOP |
| 4 | `producer_ingest_options.before.txt` | | | OPTIONS 200 with `Allow: OPTIONS, POST` | | no secrets/full payloads | PASS/STOP |
| 5 | `db.sha256.before.txt` | | | | | hash only | PASS/STOP |
| 6 | `db_readonly_counts.before.json` | | | SQLite `mode=ro` and `PRAGMA query_only=ON` | | aggregate counts only | PASS/STOP |
| 7 | `redaction_check.before.json` | | | PASS or REVIEW | | no secret path hits accepted without review | PASS/STOP |
| 8 | `phase0_artifact_hashes.sha256` | | | all Phase 0 artifacts hashed | | hashes only | PASS/STOP |

## Review Questions

- Did `producer_ingest_options.before.txt` show `OPTIONS 200` and `Allow: OPTIONS, POST`?
- Was `/health/ingest` captured even if it returned `503`?
- Did `direct_sync_ops_status.before.json` clearly show PASS or BLOCKED with missing-table/rollout evidence?
- Did `db_readonly_counts.before.json` include DB size, WAL size, free bytes, `backup_space_ok`, table counts, and missing tables?
- Did artifact hashing include every Phase 0 output file?
- Did the evidence archive avoid raw HMAC secret, producer credential, bearer token, raw receipt JSON, and full raw payload material?

## Outcome

Select exactly one:

- `phase0_readonly_pass`: all read-only outputs are captured and reviewed; later Phase 1 work still requires separate approval.
- `phase0_blocked_before_mutation`: a blocker was found before any mutation; document the blocker and do not continue to schema, POST, credential, service/task, rollback, 20-PC, shadow, or Syncthing-retirement steps.

## Follow-Up Gate

This transcript cannot approve production upload, DB migration, credential lifecycle work, field PC execution, shadow run, rollback rehearsal, or Syncthing removal.

Next phase may start only after:

- this transcript and `phase0_artifact_hashes.sha256` are archived;
- DB owner accepts backup/hash and migration window;
- security/credential owner approves key material handling outside the evidence archive;
- rollback owner approves service/task procedures;
- downstream owner accepts the baseline for later reconciliation;
- change coordinator records a separate Phase 1 approval.
