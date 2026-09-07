# Independently generated test contracts

These fixtures validate the desktop client's wire format and durable state. They do not qualify server CAS transactions, an installed product, or production readiness.

The generator records source repository commit, relative source paths, file SHA256 values, generator SHA256 and output SHA256. Regeneration is an explicit maintenance operation against the stated source checkout in an in-process ephemeral instance. Ordinary pytest only reads the committed fixtures and never imports that checkout or contacts a server.

`exchange.json` and `exchange-conflict.json` capture actual server capability, target/source resolution and commit responses. The conflict is produced by an actual competing commit between resolution and submission. The desktop test uses a local HTTP responder, enforces each request and persists the real coordinator outcome. HTTP loopback transport does not qualify TLS.

`runtime-token.json` captures an acquired authority and two consume transactions using the same token. The desktop test drains copied SQLite queues, checks authority binding, applies the accepted rotation and quarantines the stale clone. Only the runtime contract fields originate in this vector; the ordinary ingest receipt envelope uses the existing test adapter.

Regenerate explicitly with `python -B tests/contracts/generate_server_contracts.py --server-root <pinned-source> --scratch <new-owned-directory> --output <new-output-directory>`. A clean checkout at the pinned commit is required, or pass `--source-archive <git-archive.zip>` with a snapshot exported from that commit; every snapshot source byte is verified against the archive. The archive commit and digest are recorded. Generation needs the server's test dependencies and must be performed only with authorization for that source. Compare two fresh runs byte for byte before replacing fixtures. The two documented normalizations affect SQLite informational commit timestamps and the inert replay credential, and never alter versions, errors or runtime state.

## Reviewed capture validator integration

The historical `HANDOVER/tools/validate_capture_bundle_v1.py` remains unavailable.
The repository now contains the independently reviewed reconstruction at
[`tools/validate_capture_bundle_v1.py`](../../tools/validate_capture_bundle_v1.py),
25335 bytes, SHA256 `86713b77bd004a3577b53221be8667362d67984f915395dec95727ca5b1235e1`.
The existing `test_external_bundle_matches_authoritative_validator_when_vendored`
requires that exact local file, invokes it as a real child and preserves exit3,
FAIL=0 and exactly five organization-pending checks; absence or different bytes fail.
The historical test name remains for continuity, not a claim of recovered authority.

Accepted source: `E:/KMTech/coordinator-takeover-20260905/capture-validator-reconstruction-g5`;
`FILE-HASHES.json` SHA256 `e7b6f69ba1aa220904881eb3f10b8486021871539411806aa09e9ca0f95cf880`.
Main's `main-g5-20260906/CAPTURE-VALIDATOR-ACCEPTANCE.md` and
`capture-validator-review-g5/INDEPENDENT-REVIEW.md` in the same takeover root record
135 inherited, 18 adverse and 15 copied-consumer passes on those final bytes.
This is retained reconstruction evidence, not current CA integration execution.

[SPEC](../../docs/capture_validator/SPEC.md) and
[PROVENANCE](../../docs/capture_validator/PROVENANCE.md) are exact accepted copies.
Their original candidate wording is preserved; the later acceptance is recorded
above. Independent fixtures live in [`../capture_validator`](../capture_validator):
the fixture is unchanged and the complete 135-case test only adapts its relative
fixture import and repository ancestor depth. Runtime support is stdlib plus Pillow;
pytest and the existing CA fixture/provider closure are required for the tests.

The original absence skip was deliberately retained during the 2026-09-06 audit;
this reviewed-source integration replaces that guard without rewriting old results.
Run the complete `tests/test_capture_container_operator_ui.py` and
`tests/capture_validator/test_contract.py` only through Main's admitted guest route.
Main accepted the [independent CA source review](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-independent/REVIEW.md)
and the admitted h02 result: 238 PASS (103 + 135), 714 ordered phase PASS,
zero FAIL/ERROR/SKIP, with four retained reader-thread decoding warnings.
The [source-unit disposition](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/MAIN-DISPOSITION.md)
also accepts the separate finite current custody match. Original h01/h02 controller,
index byte/read-only preservation and first Main reader failures remain FAILED;
the exact index writer remains UNPROVEN. These results support this bounded source
integration, accepted by Main for its single commit; FULL, exact build/freeze
and installed/native qualification remain NOT TESTED. [CA-G07](../../docs/spec/BACKLOG.md#ca-g07)
retains the exact evidence and false qualification/runtimeAcceptance/closure flags.
Historical equivalence, organizational authority, actual GUI/source truth, hostile
concurrent-filesystem atomicity and installed/native readiness remain unproven.
Builder PNG/state/hash and link/path checks retain their own evidence scope.
