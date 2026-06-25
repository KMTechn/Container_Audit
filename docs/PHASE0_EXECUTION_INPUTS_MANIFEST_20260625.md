# Phase 0 Execution Inputs Manifest

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync 전환 Phase 0 read-only preflight 실행 전 입력값 고정

## Purpose

This manifest is the operator-facing input sheet for running `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` after `docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md` is signed.

It is not an approval by itself. It does not authorize producer POST, authenticated HMAC canary, schema `--execute`, DB write, credential lifecycle work, service or scheduled task changes, relay pause/resume, Syncthing mutation, rollback rehearsal, 20-PC run, or Syncthing removal.

## Required Inputs Before Command Execution

Before any command in `PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md` runs, save the approved values as `phase0_execution_inputs.json` outside any public web root and validate it locally:

```powershell
python tools\check_phase0_execution_inputs.py --inputs-json phase0_execution_inputs.json
```

The checker only validates the input packet and the empty evidence subdir. It does not connect to the server, open the DB, run producer POST, run schema `--execute`, mutate services/tasks, or touch Syncthing.

| Input | Required value | Owner | Evidence rule |
| --- | --- | --- | --- |
| change id | approved change-window id | change coordinator | redacted id only |
| run id | `phase0-readonly-YYYYMMDDThhmmssZ` | change coordinator | unique per run |
| server host | approved WorkerAnalysisGUI-web host | app owner | hostname only, no passwords |
| `APP` | `/root/WorkerAnalysisGUI-web` | app owner | must match exactly |
| `DB` | `/mnt/rebuild/worker-analysis/data/worker_analysis.db` | DB owner | must match exactly |
| FQDN | `https://worker.kmtecherp.com` | app owner/security owner | FQDN only, no raw IP fallback |
| producer route | `OPTIONS /api/producer-ingest/v1/source-file` | app owner | OPTIONS only |
| evidence root | approved empty archive root | change coordinator/security owner | fresh and empty before run |
| evidence subdir | `00_freeze_manifest/phase0-preflight` or approved equivalent | change coordinator | no previous artifacts |
| DB free-space threshold | enough space for baseline hash retention and later backup review | DB owner | record free bytes |
| redaction policy | no raw HMAC secret, producer secret, bearer token, raw receipt JSON, or full raw payload | security owner | aggregate outputs and hashes only |
| operator | named field/server operator for this run | field operator | name/timestamp only |
| reviewer | named reviewer for Phase 0 outcome | change coordinator | name/timestamp only |

Required JSON fields:

- `change_id`
- `run_id` matching `phase0-readonly-YYYYMMDDThhmmssZ`
- `server_host`
- `app_path` equal to `/root/WorkerAnalysisGUI-web`
- `db_path` equal to `/mnt/rebuild/worker-analysis/data/worker_analysis.db`
- `fqdn` equal to `https://worker.kmtecherp.com`
- `producer_route_method` equal to `OPTIONS`
- `producer_route_path` equal to `/api/producer-ingest/v1/source-file`
- `evidence_root`
- `evidence_subdir` equal to `00_freeze_manifest/phase0-preflight`
- `operator`
- `reviewer`
- `redaction_policy_accepted` equal to `true`
- `owners.db`, `owners.app`, `owners.field`, `owners.security`, `owners.downstream`, `owners.rollback`, and `owners.change_coordinator` all equal to `true`

## Pre-Run Validation

Stop before running any command when any check fails:

- Any owner in the approval checklist is missing.
- `python tools\check_phase0_execution_inputs.py --inputs-json phase0_execution_inputs.json` fails.
- `APP`, `DB`, FQDN, producer route, or evidence root differs from the approved value.
- Evidence directory exists and is not empty.
- The operator needs producer credentials, raw HMAC secret, bearer token, raw receipt JSON, or a full source payload to complete Phase 0.
- Any requested step would run `POST /api/producer-ingest/v1/source-file`.
- Any requested step would run schema `--execute`, DB write/update/delete, credential issue/rotation/revocation, service/task mutation, relay pause/resume, rollback rehearsal, Syncthing mutation, or Syncthing removal.
- FQDN route cannot be checked with `OPTIONS` only.
- SQLite cannot be opened with `mode=ro` and `PRAGMA query_only=ON`.

## Expected Phase 0 Evidence Files

- `direct_sync_ops_status.before.json`
- `health.before.json`
- `health_ingest.before.json`
- `producer_ingest_options.before.txt`
- `db.sha256.before.txt`
- `db_readonly_counts.before.json`
- `redaction_check.before.json`
- `phase0_artifact_hashes.sha256`
- phase0_execution_inputs.json checker PASS output
- signed or redacted owner checklist
- filled Phase 0 dry-run transcript

## Outcome Values

Use exactly one outcome in the transcript:

- `phase0_readonly_pass`: all read-only outputs were captured and reviewed.
- `phase0_blocked_before_mutation`: a blocker was found before any mutation or producer upload.

Neither outcome authorizes Phase 1 schema apply, authenticated canary POST, credential lifecycle work, 20-PC run, downstream validation, Syncthing shadow, rollback rehearsal, operator visibility fault injection, soak/security, final signoff, or Syncthing removal.

## Phase 1 Handoff Inputs

Phase 1 may be reviewed only after Phase 0 evidence is archived and these additional inputs are available:

- DB owner expected DB SHA-256 from `db.sha256.before.txt`.
- Approved DB backup directory and rollback path.
- Script hash for the additive schema tool.
- Rollback owner contact for service/task procedures.
- Security owner confirmation that Credential material is handled outside the evidence archive.
- Downstream owner baseline acceptance for later reconciliation.
- Change coordinator approval that Phase 1 is a separate operation from Phase 0.
