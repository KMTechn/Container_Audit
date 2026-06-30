# Phase9 Soak Security Approval Packet Evidence Placeholder

Source document: `docs/PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md`

Collect these only after owner approval:

- app owner command bundle
- security owner checklist
- field/operator roster
- DB owner read-only reconciliation query bundle
- downstream target
- rollback owner abort criteria
- credential lifecycle evidence
- clock drift evidence
- malicious input evidence
- fault injection evidence
- soak metrics
- dashboard browser XSS
- 4-8 hour or full-day-volume soak metrics
- malicious input UI/CSV/HTTPS/DB/dashboard/export evidence
- fault injection evidence for timeout, 500/503, DNS/TLS, DB lock, disk pressure, spool/status corruption

Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.

This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.
