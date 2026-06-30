# Phase0 Preflight Command Packet Evidence Placeholder

Source document: `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md`

Collect these only after owner approval:

- `phase0_execution_inputs.json`
- `tools/check_phase0_execution_inputs.py` PASS output
- `direct_sync_ops_status.before.json`
- `producer_ingest_options.before.txt`
- `phase0_artifact_hashes.sha256`
- production freeze manifest
- FQDN OPTIONS response
- DB/WAL size and disk free-space proof
- release config checker output

Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.

This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.
