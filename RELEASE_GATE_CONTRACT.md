# Container_Audit release gate contract

This contract separates fast feedback, exact-SHA local regression, local artifact qualification, publication, and TEST1 field evidence. GitHub Actions is not a release gate.

## Factory Contract adoption status

`RETIRE_CANONICAL_ADOPTION_LAYER` is the governing compatibility decision. The
never-merged Factory Contract 1.1.0 canonical-adoption candidate is rejected:
its ADR-0002 synchronized-adoption proposal and ADR-0003 executable-plan
authorization proposal are `HISTORICAL_REJECTED`. None of that candidate's
generation pointers, cohorts, receipts, coordinators, owner plans, or
contract-change blocking ceremony is a release prerequisite or authority.

The existing Factory Contract 1.0.3 bundle and `contract.lock.json` remain
enforced, including schemas required for wire and package compatibility.
Package, installer, runtime/active-work, and exact tag/artifact verification
also remain enforced. Uses of “canonical” below mean deterministic encoding or
exact business, Git, or artifact identity; they do not revive synchronized
canonical adoption.

| Gate | Accident prevented | Unique signal | Timing | Failure decision |
| --- | --- | --- | --- | --- |
| quick-check | Changed-area contract breakage | Focused pytest node; Python 3.11 import/version compatibility is a distinct CI lane | During development, before candidate freeze | Fix the affected area; do not advance the candidate |
| local-ci | Functional regression | Exact-commit/tree local tests and source release-config contract in the isolated environment; Python 3.11 compatibility remains distinct | Before the pre-push candidate build and again whenever source changes | Do not build or publish a candidate whose local exact-SHA gates are not `PROVEN` |
| release-gate | Wrong tag/SHA or rebuilt/altered package/archive/hash | Pre-push build in an isolated local bare mirror/clone under the already-created FINAL tag object, exact local qualification receipt, external immutable-policy gate, immutable release snapshots, and downloaded-vs-preserved local byte parity | Build and qualify before any push; publish `main`; wait for zero nonterminal workflows; satisfy policy gate; push the unchanged tag; publish and compare the immutable asset | Any missing, moved, recreated, rebuilt, mutable, or mismatched identity/byte fails; use a new patch version and keep rollout at 0 |
| test1-e2e | Frozen GUI, scanner, relay, canary, or rollback failure | Exact qualified ZIP on TEST1, real UI/scanner, direct-sync receipt, update and rollback preservation | After immutable release byte parity, before stable rollout | Keep rollout at 0 and quarantine the artifact |

## Installation, discoverability, and rollback contract

`install_status=PASS` proves installation infrastructure only: authenticated
self-enrollment, the SYSTEM relay task, its current server lease, and the
all-users launcher contract. The installer must also print
`operator_readiness_status=PENDING_FIRST_LAUNCH` and
`first_launch_catalog_status=NOT_TESTED`. Overall installation qualification is
therefore `UNPROVEN` until the same non-elevated operator captured before UAC
launches the installed application and proves the authenticated central catalog
baseline. The installer must not seed the per-user cache, copy the bundled
catalog into it, weaken trusted-origin or authentication checks, or claim
catalog success from an elevated install.

The supported operator entry point is exactly the all-users Start Menu shortcut
`CommonPrograms\KMTech\이적 검사 시스템.lnk`. Its target and icon are
`C:\KMTech\Apps\Container_Audit\current\Container_Audit.exe`, its working
directory is `C:\KMTech\Apps\Container_Audit\current`, and it has no
arguments. Installation must read those fields back before reporting
infrastructure PASS. An identical shortcut is idempotent; a conflicting link
blocks installation or removal. No desktop shortcut is part of this contract.

Plain deconfiguration is deliberately non-destructive:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\INSTALL_THIS_PC.ps1 -Uninstall
```

It removes only the exact owned task and shortcut, preserves application,
event, queue, catalog, profile, credential, and update state, and reports
`uninstall_status=PASS_DATA_PRESERVED`. It is not pristine rollback and must
never print `rollback_status=PASS`.

Qualification-only permanent rollback requires all three explicit inputs:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\INSTALL_THIS_PC.ps1 `
  -Uninstall `
  -PurgeContainerAuditState `
  -ConfirmPermanentContainerAuditDataRemoval `
  -RollbackReportPath <EXTERNAL-EVIDENCE-PATH>
```

The confirmation may be supplied only after the qualification owner has proved
no active tray or unresolved operation, a fully ACKed relay, and no running GUI
or packaged relay process. The report path must be a fresh absolute file
outside every deletion target. The bounded report records only path/status
metadata and must never contain tokens, DPAPI bytes, profile secrets, event
payloads, or barcodes.

Before any deletion, rollback must prove canonical production paths, the
captured operator SID/LocalAppData binding, exact task action/principal, exact
shortcut metadata, app-scoped DirectSync ownership, an allowlisted application
parent inventory, and absence of reparse points throughout every existing
target. A foreign task, shortcut, application-parent child, path escape,
filesystem root, alternate stream, symlink, or junction is a blocking failure.
`AllowNoncanonicalLayoutForTest` cannot authorize deletion.

Deletion order is fixed: task; shortcut; app-scoped logistics profile;
DirectSync root; captured operator data; captured operator catalog; update
backup and evidence siblings; application `current` root last. Only the now
empty `C:\KMTech\Apps\Container_Audit` parent and now-empty KMTech Start Menu
group may then be removed; shared `Apps`, `ProgramData\KMTech`, Logistics,
DirectSync, LocalAppData `KMTech`, profile, and filesystem roots must never be
recursively deleted. `rollback_status=PASS` requires a final task lookup and
existence check proving every inventory item absent. Exact-target qualification
must compare that result with the recorded pristine prestate while proving
unrelated parents and siblings unchanged.

## Exact commands

One-time environment setup (not part of `quick-check`):

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Quick compatibility signal:

```powershell
python -c "import Container_Audit, update_service; print('python311_compatibility=PASS')"
python -m pytest -q -p no:cacheprovider tests/test_release_version.py tests/test_release_config.py
```

The isolated local gate owns the full suite for the exact candidate SHA:

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider
```

The tag workflow is verification-only. It does not install build dependencies, run PyInstaller, prepare/reseal an identity or manifest, recompress the package, create/edit a release, upload an asset, or promote the private feed. It prebinds the pushed annotated tag object and peel to checked-out `HEAD` and `origin/main` and parses the exact canonical message `Release <tag>\n`. It records any exact-SHA hosted-CI status factually, but `Hosted-CI-Release-Gate` remains `WAIVED_NOT_TESTED`; absence, failure, or a later attempt does not by itself reject bytes that passed the governing local gates. It may prove the immutable release body's hash/size, checksum, API asset metadata, extracted main EXE, embedded identities, and sealed-manifest self-consistency. Because a hosted runner cannot access the preserved qualified local bytes, its report must say governing local byte parity is `NOT_TESTED`.

Repository immutability remains an external pre-tag-publication gate because `GET /repos/{owner}/{repo}/immutable-releases` requires Administration (read), which the workflow's read-only `github.token` cannot receive. The workflow instead requires `immutable=true` in every release snapshot. Immutability prevents a successful post-download comparison from later being invalidated by asset replacement.

## Frozen v2.0.62+ publication sequence

### Immutable failed local candidate history

`v2.0.68` is permanently quarantined with **no artifact**. Its annotated local
tag object is `a28d7b57cd624f29b18356adc05c6e64c8b5d887`, peeling to
`5e2d7bd284a6a36f360c862dba51e4d8bba169cd`. The authority stopped after
creating that local tag and before invoking the official builder, so no ZIP,
manifest, checksum, or qualification receipt exists. Never delete, recreate,
retarget, publish, or retry that tag; every successor must use a new patch
version and fresh absent release and candidate roots.

### Supported pre-push isolated candidate build

Phase 8.3 requires the FINAL intended annotated tag object before any release-mode identity or build. Artifact hashes therefore do not belong in the tag message. Prepare an isolated local bare mirror, make the exact candidate commit its `refs/heads/main`, create the intended tag there exactly once, then clone that mirror for the build. The canonical LF-terminated tag message is only:

```text
Release v2.0.62
```

The following is a template; every path must be fresh and the candidate source must already be a clean local commit. It performs no network operation:

```powershell
$sourceRepo = "C:\company\program\Container_Audit"
$releaseRoot = "E:\KMTech\Container_Audit\v2.0.62-prepush"
$mirrorRoot = "$releaseRoot\mirror.git"
$workClone = "$releaseRoot\work"
$candidateRoot = "E:\KMTech\Container_Audit\v2.0.62-candidate"
$tagMessage = "$releaseRoot\FINAL_TAG_MESSAGE.txt"
$pythonExecutable = "E:\KMTech\Container_Audit\release-python\Scripts\python.exe"
$candidateCommit = (git -C $sourceRepo rev-parse --verify "HEAD^{commit}").Trim().ToLowerInvariant()
if ((Test-Path -LiteralPath $releaseRoot) -or (Test-Path -LiteralPath $candidateRoot)) {
  throw "Use fresh absent release and candidate roots."
}
New-Item -ItemType Directory -Path $releaseRoot | Out-Null
git clone --mirror --no-hardlinks $sourceRepo $mirrorRoot
if ($LASTEXITCODE -ne 0) { throw "Local mirror creation failed." }
git -C $mirrorRoot update-ref refs/heads/main $candidateCommit
[IO.File]::WriteAllText($tagMessage, "Release v2.0.62`n", [Text.UTF8Encoding]::new($false))
git -C $mirrorRoot tag --annotate v2.0.62 --cleanup=verbatim --file $tagMessage $candidateCommit
if ($LASTEXITCODE -ne 0) { throw "FINAL intended tag creation failed." }
git clone --no-hardlinks $mirrorRoot $workClone
if ($LASTEXITCODE -ne 0) { throw "Isolated work clone creation failed." }
git -C $workClone checkout -B main origin/main
pwsh -NoProfile -File "$workClone\tools\build_frozen_release_candidate.ps1" `
  -Tag v2.0.62 `
  -MirrorRoot $mirrorRoot `
  -PythonExecutable $pythonExecutable `
  -OutputRoot $candidateRoot
```

The `tools/build_frozen_release_candidate.ps1` builder accepts only that prepared isolated clone. It fails closed unless the clone is clean, its absolute local `origin` is the supplied bare mirror, `HEAD`, local `main`, clone `origin/main`, and mirror `main` are identical, and the FINAL tag object/type/peel are exact in both repositories. Before `build_cli prepare`, PyInstaller, or any other release-mode generation, it parses the canonical tag and writes `FINAL_RELEASE_IDENTITY.json`. It then creates the package once, seals and verifies the manifest, checks extraction/config/probes, and writes `local-artifact-qualification-receipt.json` containing the tag object, source commit/tree, mirror refs, ZIP name/hash/size, and principal EXE hash.

The authority must prepend the prepared Python environment to `PATH` and pass
that exact executable through `-PythonExecutable`. The builder resolves all
PATH-visible Python applications in precedence order, accepts additional
lower-priority installations only when the first result is the exact prepared
executable, and invokes that resolved path for every Python build step. Zero
results or a different first result fail before release-mode generation.

Never delete, recreate, or move that tag object. There is no provisional-to-final transition and no post-build tag mutation. If the tag preparation or build fails, or source/manifest bytes change, abandon that version and use a new patch version. Do not repair or overwrite a failed candidate root.

Run the complete installation qualification on a fresh unmodified target using the exact candidate and supported commands, including end-to-end checks and rollback verification. Preserve the qualified local ZIP, checksum, qualification receipt, and target evidence unchanged.

### Main push and pre-tag-publication gates

Only after every local gate and artifact qualification is `PROVEN` may the exact candidate commit be pushed to `main`. Before pushing the already-created tag object, all of the following are mandatory:

1. Fetch live `origin/main` and prove it equals the receipt's `source_commit` and tree.
2. Record any exact-SHA hosted workflow status factually. If none ran, record `WAIVED_NOT_TESTED`; never relabel it `PASS` or use it instead of the local gate.
3. Require zero nonterminal workflows before any release mutation. Terminal failure/absence is recorded but is not by itself an artifact rejection.
4. With an authorized Administration-read credential, query `GET /repos/KMTechn/Container_Audit/immutable-releases` using API version `2026-03-10` and require `enabled=true`.
5. Prove the remote tag, release, and same-name assets are absent.
6. Re-read the mirror tag object/type/peel and require exact equality with `FINAL_RELEASE_IDENTITY.json` and `local-artifact-qualification-receipt.json`.

The read-only 2026-08-12 policy preflight reported `enabled=false`; tag publication remains BLOCKED until an authorized repository administrator enables it. Candidate building itself does not query or change that setting. This contract does not authorize changing repository policy.

Push the unchanged tag object only after the external immutable-setting gate and zero-nonterminal-workflow gate pass. Re-fetch it and require the remote tag object SHA and peeled commit to equal the local mirror exactly. A name-only match is insufficient.

### Immutable prerelease and governing byte parity

1. Create a **draft prerelease** for the exact tag/commit with the exact title/body below.
2. Upload exactly the preserved qualified ZIP and checksum while the release remains draft; never rebuild, recompress, replace, or use `--clobber`.
3. Re-read the draft by release ID and validate metadata, exact two asset names, uploaded states, IDs, sizes, and API SHA-256 digests.
4. Publish with `draft=false`, retain `prerelease=true`, and require `immutable=true` using API version `2026-03-10`.
5. Download both assets to a fresh path. The governing parity check is a streamed byte-for-byte comparison of the downloaded ZIP against the preserved qualified local ZIP, bound to the preserved local receipt:

```powershell
python tools/verify_frozen_release_artifact.py `
  --zip-path <FRESH_DOWNLOADED_ZIP> `
  --checksum-path <FRESH_DOWNLOADED_ZIP>.sha256 `
  --expected-tag v2.0.62 `
  --expected-tag-object <FINAL_TAG_OBJECT_SHA> `
  --expected-commit <TAG_COMMIT> `
  --expected-tree <TAG_TREE> `
  --expected-contract-sha256 adaa08684ebb291837327f63f967a4f22650dff72c4c1dc56ce1a9bee6b5404a `
  --expected-zip-sha256 <RELEASE_BODY_ZIP_SHA256> `
  --expected-zip-size <RELEASE_BODY_ZIP_SIZE> `
  --expected-main-exe-sha256 <RELEASE_BODY_MAIN_EXE_SHA256> `
  --qualified-local-zip-path <PRESERVED_QUALIFIED_LOCAL_ZIP> `
  --local-qualification-receipt <PRESERVED_LOCAL_RECEIPT> `
  --report-path <FRESH_LOCAL_PARITY_REPORT>
```

The hosted tag workflow may independently validate release-body/checksum self-consistency while polling for at most 1800 seconds, but that is not a substitute for the local comparison above. After local parity passes, re-read the immutable release snapshot, remote tag object/peel, and `origin/main`. Any mismatch or timeout is a failure, not permission to replace an asset or mutate the tag. TEST1 and later promotion use only these exact verified bytes.

The release title must be exactly `Release v2.0.62`. Its body must be exactly this LF-normalized record with no leading or trailing newline:

```text
Internal prerelease; not production-ready.
Tag: v2.0.62
Commit: <40 lowercase hex>
Tree: <40 lowercase hex>
Artifact: Container_Audit-v2.0.62.zip
Artifact-SHA256: <qualified 64 lowercase hex>
Artifact-Size: <qualified positive decimal bytes>
Main-EXE-SHA256: <qualified 64 lowercase hex>
Factory-Contract-SHA256: adaa08684ebb291837327f63f967a4f22650dff72c4c1dc56ce1a9bee6b5404a
Hosted-CI-Release-Gate: WAIVED_NOT_TESTED
Status: QUARANTINED_PENDING_FACTORY_QUALIFICATION
```

The existing v2.0.61 tag, release, and assets are immutable historical evidence and must not be edited or reused for this sequence.

Approved TEST1 invocation template:

```powershell
python tools/packaged_real_ui_driver.py --archive <RELEASE_ZIP> --expected-archive-sha256 <APPROVED_ZIP_SHA256> --exe <EXTRACTED_ZIP>\Container_Audit\Container_Audit.exe --expected-exe-sha256 <APPROVED_EXE_SHA256> --archive-member Container_Audit/Container_Audit.exe --output-root <FRESH_EVIDENCE_DIR> --data-root <FRESH_TEST_DATA_ROOT> --worker TEST1 --master-label <APPROVED_PHS2>
```

### Process-only TEST1 legacy override

`KMTECH_TEST1_ALLOW_ISOLATED_LEGACY_LOGISTICS=1` is permitted only in the
process that runs the approved package on the physical `TEST1` machine. It must
never be stored at User/Machine scope, added to a release workflow, or enabled
on a production worker. `KM_LOGISTICS_PROFILE_PATH` and
`KM_LOGISTICS_REQUIRED` must be absent. The data root and private CA file must
be non-reparse paths below the same fresh
`C:\KMTech\Test1\Runs\<run>` directory.

The endpoint must be the exact origin `https://127.0.0.1:<port>` with no path,
query, fragment, redirect, or hostname alias. The loopback TLS proxy must
present a certificate containing IP SAN `127.0.0.1`, signed by the approved
TEST1-only CA referenced by `REQUESTS_CA_BUNDLE`; the proxy may forward only to
the isolated TEST1 backend. A LAN, Internet, production, or production-credential
endpoint is forbidden.

Provision the private CA and extracted exact-SHA release outside Git, then run
the following packet after replacing every placeholder:

```powershell
$ErrorActionPreference = "Stop"
if ($env:COMPUTERNAME -ine "TEST1") { throw "BLOCKED: this packet runs only on TEST1" }

$runId = "container-<UTC-RUN-ID>"
$scope = "TEST1-CONTAINER-<UTC-RUN-ID>"
$token = "<TEST1-only-token>"
$archive = "<APPROVED-RELEASE-ZIP>"
$expectedArchiveSha256 = "<APPROVED-ZIP-SHA256>"
$packageExe = "<EXTRACTED-EXACT-SHA-ZIP>\Container_Audit\Container_Audit.exe"
$expectedExeSha256 = "<APPROVED-EXE-SHA256>"
$masterLabel = "<APPROVED-TEST1-PHS2>"
if (@(
  $runId, $scope, $token, $archive, $expectedArchiveSha256,
  $packageExe, $expectedExeSha256, $masterLabel
) -match "<|>") {
  throw "BLOCKED: replace every TEST1 placeholder"
}
$runRoot = "C:\KMTech\Test1\Runs\$runId"
$caBundle = "$runRoot\tls\test1-ca.pem"
New-Item -ItemType Directory -Force `
  -Path "$runRoot\ContainerAudit", "$runRoot\evidence", "$runRoot\tls" |
  Out-Null
if (-not (Test-Path -LiteralPath $caBundle -PathType Leaf)) {
  throw "BLOCKED: approved TEST1 CA is missing"
}

Remove-Item Env:KM_LOGISTICS_PROFILE_PATH -ErrorAction SilentlyContinue
Remove-Item Env:KM_LOGISTICS_REQUIRED -ErrorAction SilentlyContinue
$env:KMTECH_TEST1_ALLOW_ISOLATED_LEGACY_LOGISTICS = "1"
$env:CONTAINER_AUDIT_DATA_ROOT = "$runRoot\ContainerAudit"
$env:WORKER_ANALYSIS_LOGISTICS_API_BASE_URL = "https://127.0.0.1:18443"
$env:WORKER_ANALYSIS_LOGISTICS_API_TOKEN = $token
$env:WORKER_ANALYSIS_LOGISTICS_AUTHORITY_SCOPE_ID = $scope
$env:WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID = "test1-container-host"
$env:WORKER_ANALYSIS_LOGISTICS_DEVICE_ID = "test1-container-device"
$env:REQUESTS_CA_BUNDLE = $caBundle

python -c "from transfer_seal import logistics_transfer_client_from_env; c = logistics_transfer_client_from_env(probe_required=False); assert c is not None; print('test1_profile=PASS')"
if ($LASTEXITCODE -ne 0) { throw "BLOCKED: TEST1 process profile preflight failed" }
python tools/packaged_real_ui_driver.py `
  --archive $archive `
  --expected-archive-sha256 $expectedArchiveSha256 `
  --exe $packageExe `
  --expected-exe-sha256 $expectedExeSha256 `
  --archive-member "Container_Audit/Container_Audit.exe" `
  --output-root "$runRoot\evidence" `
  --data-root "$runRoot\ContainerAudit" `
  --worker TEST1 `
  --master-label $masterLabel
if ($LASTEXITCODE -ne 0) { throw "BLOCKED: Container TEST1 E2E failed" }
```

The two expected hashes must come from the approved release attestation, not
from hashing the candidate supplied to the driver. Before `Popen`, the driver
verifies the ZIP, installed EXE, and exact ZIP member byte identity. Immediately
after launch it records the OS-reported process executable path and requires it
to equal the attested EXE. Archive SHA-256, installed executable SHA-256, process
path, and post-run hash stability are part of
`real_ui_no_human_walkthrough_report.json`; any mismatch is fail-closed.

Any throw, nonzero exit, CA/origin/scope mismatch, relay receipt failure, or
evidence outside `$runRoot` is `TEST1 BLOCKED`. Keep rollout at `0`, quarantine
the artifact, never fall back to production paths/profile/credentials, and
preserve the failed run directory. A retry after correction uses a new run ID.

Hosted CI is `WAIVED_NOT_TESTED` as a release gate. Existing workflows may run automatically after a `main` push; their actual status is recorded, and release mutation waits for zero nonterminal workflows, but their result does not replace or invalidate the exact-SHA local gate. Hosted CI intentionally does not build or mutate the release artifact. The prerelease must remain quarantined with rollout `0` until the exact artifact passes the tag gate and TEST1. GitHub branch protection, prerelease creation/upload, private-feed promotion, and production owner approvals are external actions and blockers; the workflow does not infer or acquire that authority.
