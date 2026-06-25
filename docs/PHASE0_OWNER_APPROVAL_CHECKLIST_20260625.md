# Phase 0 Owner Approval Checklist

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync 전환 전 `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` 실행 승인

## Purpose

This checklist authorizes only the read-only Phase 0 preflight command packet. It confirms who approved the evidence location, target server paths, safety boundary, and stop conditions before collecting production/staging baseline evidence.

It does not authorize producer POST upload, authenticated HMAC canary, schema `--execute`, credential issue/rotation/revocation, service or scheduled task changes, Syncthing configuration changes, or Syncthing removal.

## Required Owner Signoff

| Owner role | Required approval | Evidence marker |
| --- | --- | --- |
| DB owner | Confirms DB path, read-only access, backup-space threshold, and that Phase 0 may collect SQLite `mode=ro`/`query_only` counts. | name, timestamp, DB path |
| App owner | Confirms app directory, deployed `scripts/direct_sync_ops_status.py`, FQDN health endpoints, and no application mutation in Phase 0. | name, timestamp, app path |
| Field operator | Confirms no worker PC or scanner workflow is changed by Phase 0 and that no producer upload is attempted. | name, timestamp, site/window |
| Security/credential owner | Confirms no raw HMAC secret, producer secret, bearer token, raw receipt JSON, or full raw payload may enter the evidence archive. | name, timestamp, redaction rule |
| Downstream owner | Confirms Phase 0 captures baseline only and does not change dashboard, projection, summary, export, or downstream receiver state. | name, timestamp, receiver target |
| Rollback owner | Confirms Phase 0 does not stop services, tasks, relay, or Syncthing and does not replace the existing rollback path. | name, timestamp, rollback contact |
| Change coordinator | Confirms this checklist, evidence path, and `PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` are the exact approved inputs for the window. | name, timestamp, change id |

All owner signoff entries must be stored as redacted text, screenshot, or PDF metadata in the evidence archive. Do not store private phone numbers, personal passwords, raw keys, or full secret material.

## Approved Phase 0 Inputs

- `APP` must be `/root/WorkerAnalysisGUI-web`.
- `DB` must be `/mnt/rebuild/worker-analysis/data/worker_analysis.db`.
- Approved FQDN must be `https://worker.kmtecherp.com`.
- Producer route check is `OPTIONS` only against `/api/producer-ingest/v1/source-file`.
- `EVIDENCE_DIR` must be a fresh approved archive path under the server-side evidence root.
- Evidence archive must contain redacted aggregate outputs and hashes only.
- Local scaffold reference: `.agents/agent-loop/runs/container-audit-e2e-20260624/evidence/production-cutover-packet-v5-20260625/00_freeze_manifest/PHASE0_OWNER_APPROVAL_CHECKLIST.md`.

## Authorized Read-Only Actions

After every owner above signs, the operator may run `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` exactly as approved. The checklist authorizes only:

- `scripts/direct_sync_ops_status.py --db "$DB"` output capture.
- `GET /health` capture.
- `GET /health/ingest` capture, including a blocked `503` result.
- `OPTIONS /api/producer-ingest/v1/source-file` capture.
- DB SHA-256 capture with `sha256sum "$DB"`.
- SQLite read-only row counts using `mode=ro` and `PRAGMA query_only=ON`.
- Evidence path redaction scan.
- Phase 0 artifact hash manifest.

## Not Authorized By This Checklist

- `POST /api/producer-ingest/v1/source-file` or any producer data upload.
- Authenticated HMAC canary, nonce replay test, idempotency receipt write, or live receipt save.
- `plan_c_apply_additive_schema.py`, schema `--execute`, DB write/update/delete, or `COMMON_INGEST_WRITE_ENABLED` change.
- Credential issue, key rotation, key revocation, producer install registration, or secret export.
- `direct_sync_relay_install_pack.py --apply`, service start/stop, scheduled task creation/change, relay pause/resume, or PC install mutation.
- Syncthing configuration change, `C:\Sync` mutation, shadow-run enablement, or Syncthing removal.
- Dashboard deployment, downstream receiver mutation, production config package install, or rollback rehearsal.

## Pre-Run Stop Conditions

Stop before running the command packet if any item is true:

- Any required owner signoff is missing.
- `APP`, `DB`, FQDN, route, or evidence directory differs from the approved values.
- The evidence directory already contains previous run artifacts.
- DB owner cannot confirm enough free space for a DB snapshot or baseline hash retention.
- The operator would need raw HMAC secret, producer secret, bearer token, or private credential material to run Phase 0.
- Any requested command would perform POST, schema mutation, service/task mutation, credential mutation, Syncthing mutation, or DB write.

Known missing direct-sync tables may be captured by Phase 0 as blocker evidence. They do not authorize Phase 1 schema work or producer upload.

## Post-Run Acceptance

Phase 0 is accepted only when the evidence archive contains:

- `direct_sync_ops_status.before.json`
- `health.before.json`
- `health_ingest.before.json`
- `producer_ingest_options.before.txt`
- `db.sha256.before.txt`
- `db_readonly_counts.before.json`
- `redaction_check.before.json`
- `phase0_artifact_hashes.sha256`
- this owner approval record or its redacted signed equivalent

The accepted outcome is either `phase0_readonly_pass` or `phase0_blocked_before_mutation`. Neither outcome approves Phase 1 schema apply, staging/production canary POST, 20-PC run, shadow run, rollback rehearsal, or Syncthing retirement. Each later phase requires its own evidence review and explicit approval.
