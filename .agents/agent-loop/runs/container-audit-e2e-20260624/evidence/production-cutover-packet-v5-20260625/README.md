# Production Cutover Evidence Packet

This packet is a scaffold only. It does not authorize production writes.

Rules:

- Do not store raw HMAC secrets, producer credentials, bearer tokens, raw receipt JSON, or full raw payloads here.
- Store hashes, redacted identifiers, aggregate counts, screenshots with secrets hidden, and owner signoff records.
- Keep Syncthing enabled as shadow/rollback until the final signoff manifest says promotion_allowed=true and production_removal_ready=true.
- Stop if any hard stop condition in the three-agent plan or operational change-window runbook occurs.
