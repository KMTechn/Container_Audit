# Phase4 Twenty Pc Concurrency Approval Packet Evidence Placeholder

Source document: `docs/PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md`

Collect these only after owner approval:

- at least 20 distinct `source_host_id`, `producer_install_id`, and `key_id` rows
- same Korean filename
- same worker name
- duplicate resend
- network interruption
- queue restart
- redacted server receipt summaries
- DB reconciliation for receipt, nonce, raw artifact, source_claim, common_ingested_events, projection, summary, and quarantine deltas
- Syncthing/archive shadow observation proving no double count
- does not authorize producer POST upload outside the approved 20-PC window
- 20 PC identity table with secrets redacted
- per-PC CSV hash and row count
- replay, network interruption, queue restart, and resume evidence

Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.

This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.
