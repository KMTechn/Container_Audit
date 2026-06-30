# Phase3 One Pc Canary Approval Packet Evidence Placeholder

Source document: `docs/PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md`

Collect these only after owner approval:

- credential owner signoff
- one `producer_install_id`, one `source_host_id`
- field operator signoff
- DB owner signoff for Phase 2 PASS
- redacted request metadata
- receipt summary
- nonce/idempotency evidence
- does not authorize 20-PC testing
- redacted request id, key id, nonce fingerprint, and idempotency key fingerprint
- receipt hash
- raw artifact reference and hash
- source_claim and projection reconciliation counts

Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.

This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.
