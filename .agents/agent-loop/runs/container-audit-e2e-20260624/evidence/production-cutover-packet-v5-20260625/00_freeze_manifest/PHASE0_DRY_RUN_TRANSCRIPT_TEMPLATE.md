# Phase0 Dry Run Transcript Template Evidence Placeholder

Source document: `docs/PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md`

Collect these only after owner approval:

- run metadata with change id
- `tools/check_phase0_execution_inputs.py` PASS output
- owner checklist reference and command packet reference
- command result transcript rows
- `direct_sync_ops_status.before.json`
- `phase0_artifact_hashes.sha256`
- `phase0_readonly_pass` or `phase0_blocked_before_mutation`
- production freeze manifest
- FQDN OPTIONS response
- DB/WAL size and disk free-space proof
- release config checker output

Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.

This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.
