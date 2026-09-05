# Independently generated test contracts

These fixtures validate the desktop client's wire format and durable state. They do not qualify server CAS transactions, an installed product, or production readiness.

The generator records source repository commit, relative source paths, file SHA256 values, generator SHA256 and output SHA256. Regeneration is an explicit maintenance operation against the stated source checkout in an in-process ephemeral instance. Ordinary pytest only reads the committed fixtures and never imports that checkout or contacts a server.

`exchange.json` and `exchange-conflict.json` capture actual server capability, target/source resolution and commit responses. The conflict is produced by an actual competing commit between resolution and submission. The desktop test uses a local HTTP responder, enforces each request and persists the real coordinator outcome. HTTP loopback transport does not qualify TLS.

`runtime-token.json` captures an acquired authority and two consume transactions using the same token. The desktop test drains copied SQLite queues, checks authority binding, applies the accepted rotation and quarantines the stale clone. Only the runtime contract fields originate in this vector; the ordinary ingest receipt envelope uses the existing test adapter.

Regenerate explicitly with `python -B tests/contracts/generate_server_contracts.py --server-root <pinned-source> --scratch <new-owned-directory> --output <new-output-directory>`. A clean checkout at the pinned commit is required, or pass `--source-archive <git-archive.zip>` with a snapshot exported from that commit; every snapshot source byte is verified against the archive. The archive commit and digest are recorded. Generation needs the server's test dependencies and must be performed only with authorization for that source. Compare two fresh runs byte for byte before replacing fixtures. The two documented normalizations affect SQLite informational commit timestamps and the inert replay credential, and never alter versions, errors or runtime state.

## Capture validator gap

The historical capture validator was referenced as `HANDOVER/tools/validate_capture_bundle_v1.py` by the capture tool and user-manual contract. The referenced external artifact is absent, and searches in Container_Audit and the approved WorkerAnalysisGUI-web checkout found no authoritative copy. The builder's actual PNG/state/manifest/hash behavior remains an executing test; the separate authoritative-validator comparison explicitly skips until an independently sourced, reviewed validator is vendored at `capture_validator/validate_capture_bundle_v1.py` with provenance. No replacement validator has been invented from the builder itself.

Main approved preserving this exact gap on 2026-09-06 during the test-audit plan review. The missing guarantee is acceptance of the generated bundle by the independently maintained external capture contract; this is not counted as passed.
