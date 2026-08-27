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

Worker-PC registration on the public install path is hosted by the already
required `Container_Audit_DirectSync_Install.exe` entrypoint. Its
`--register-worker-pc` dispatch calls the registration module in-process and
forwards the existing registration arguments unchanged; a standalone
`Container_Audit_Worker_PC_Register.exe` must not be built, shipped, required,
or launched. The server authorization, machine credential, TLS, routing,
manifest-hash, and registration-report gates remain unchanged.

The supported operator entry point is exactly the all-users Start Menu shortcut
`CommonPrograms\KMTech\이적 검사 시스템.lnk`. Its target and icon are
`C:\KMTech\Apps\Container_Audit\current\Container_Audit.exe`, its working
directory is `C:\KMTech\Apps\Container_Audit\current`, and it has no
arguments. Installation must read those fields back before reporting
infrastructure PASS. An identical shortcut is idempotent; a conflicting link
blocks installation or removal. No desktop shortcut is part of this contract.

The package-integrated isolated qualification route is enabled only by the
explicit `-EnableWindowsSandboxQualification` installer switch. The switch is
fail-closed unless the captured non-elevated operator is the canonical Windows
Sandbox `WDAGUtilityAccount` profile with its RID-504 SID, the install uses the
canonical application and ProgramData roots, and `ServerBaseUrl` remains the
unaltered production default. The packaged authority then generates a new
private CA, TLS key, producer secret, logistics token, and operation-lease key
inside that disposable guest; binds HTTPS only to `127.0.0.1`; and exposes only
the enrollment, runtime-lease, ingest, authenticated item-catalog, PHS=2 lookup,
and signed operation-lease boundaries needed for representative qualification.
It retains no uploaded payloads and cannot write to production. Production URL,
private-address, authentication, and credential guards remain unchanged when
that exact package-owned context is absent.

The qualification authority is an owned SYSTEM startup task named
`container-audit-isolated-qualification-authority`. Its runtime-generated state
is under the app-scoped DirectSync root, its private files are readable only by
SYSTEM and Administrators, and the operator receives read access only to the
public client context, CA certificate, and sanitized operator fixture. Plain
uninstall removes the owned task and process while preserving this data;
explicit pristine rollback removes the task first and then removes the entire
app-owned DirectSync tree under the same strict guards as production state.

Plain uninstall removes the replaceable application footprint while preserving
runtime and business state:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\INSTALL_THIS_PC.ps1 -Uninstall
```

It removes the exact owned tasks, shortcut, and
`C:\KMTech\Apps\Container_Audit\current` tree. It preserves event, queue,
catalog, profile, credential, update-backup, update-evidence, and unrelated
sibling state, and reports `uninstall_status=PASS_DATA_PRESERVED` plus
`application_root_status=ABSENT`. It is not pristine rollback and must never
print `rollback_status=PASS`.

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
or packaged relay process. The packaged relay is a separate SYSTEM process that
hosts relay mode in `Container_Audit.exe`; it is not a distinct relay helper PE.
The report path must be a fresh absolute file
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

Deletion order is fixed: qualification-authority task; relay task; shortcut;
app-scoped logistics profile; DirectSync root; captured operator data; captured
operator catalog; update
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

`v2.0.69` is permanently quarantined as an unpublished local candidate after
Windows Sandbox qualification classified it `INCONCLUSIVE`. Its annotated tag
object is `9f0c76bbd26f0dd56d6c6e396c30c2d3ede01a72`, peeling to
`3c126160560620694bbbcd0378f53f343340c5b6`; its one preserved ZIP is exactly
110970957 bytes with SHA-256
`da86ead0067cd2196681be18221faf301db67633bbf41e6a7ac9304a6a0259f6`.
The artifact lacked a product-supported isolated enrollment/relay-lease route,
so it could not complete fresh-target installation qualification without
external guest preconditioning. Never alter, rebuild, retag, publish, or reuse
those bytes; the successor is `v2.0.70`.

`v2.0.70` is permanently quarantined with **no artifact**. Its annotated local
tag object is `2ae5f677447a1e2db4cfcc53c71a4aceef5f4e9a`, peeling to
`848b3fed38190cb26d643dd50697f5d3a0c24d94`. The isolated qualification route
and exact frozen-tree tests passed, but the one authorized official-builder
invocation stopped before creating the candidate root because ambient Python
preceded the explicitly supplied prepared interpreter. No ZIP, manifest,
checksum, or qualification receipt exists. Never delete, recreate, retarget,
publish, or retry that tag; the successor is `v2.0.71`.

`v2.0.71` is permanently quarantined as an unpublished local candidate after
fresh Windows Sandbox qualification classified it `FAIL`. Its annotated tag
object is `6c46d0e078f77a6c395e94c441c949f7abd79244`, peeling to
`46dee4e55e134b37cab31fda4db0509d3c658cfe`; its one preserved ZIP is exactly
126453345 bytes with SHA-256
`c557a7899bf990b414552dc7a4355e07e65a9a26c0425bae25dda024b8a419e1`.
The installed SYSTEM relay made no isolated runtime-lease request, and the
owned qualification authority process survived official uninstall and
rollback. Never alter, rebuild, retag, publish, or reuse those bytes; the
successor is `v2.0.72`.

`v2.0.72` is permanently quarantined as an unpublished local candidate after
fresh Windows Sandbox qualification classified it `FAIL`. Its annotated tag
object is `abc9b958833b6b6a9264a075a5473e9bb41224af`, peeling to
`fdc4cb3ef934c25b9087ccf68b958dfd5730f989`; its one preserved ZIP is exactly
126455428 bytes with SHA-256
`6423e829eebd551dfd5d23e8294c353cc2fef37f70cabe718a2f87e9a99dbc5e`.
The isolated authority initialized, probed, and enrolled successfully, but the
SYSTEM relay exited `1` without a status, log, or runtime-lease request. The
public destructive rollback also left the application root locked when invoked
from a shell whose working directory was that root. Never alter, rebuild,
retag, publish, or reuse those bytes; the successor is `v2.0.73`.

`v2.0.73` is permanently quarantined as an unpublished local candidate after
independent post-build review classified it `FAIL`. Its annotated tag object is
`1dee7f93a2c98e07ae2a9381c575d451b05a6a96`, peeling to
`83fc636def457b8a34af929a00b1f8f5c7443b6a`; its one preserved ZIP is exactly
126456593 bytes with SHA-256
`f1f7e6ad385d06918abbe6021fbfa3929129d5986201e51da563dba94b73c233`.
The retained smoke extraction contained six unsealed `__pycache__/*.pyc` files
totaling 295120 bytes after the extracted-source help probes, so its final
inventory did not match the sealed package. Never clean, alter, rebuild, retag,
publish, retry, or reuse those bytes; the successor is `v2.0.74`.

`v2.0.74` is permanently quarantined with **no artifact**. Its annotated local
tag object is `4e7b960e4a6f1fba59772a8645d9cfa0e65d03cc`, peeling to
`935014a0fbca214390815392d71193f30796d622`. The one authorized builder child
stopped before source-builder entry because PowerShell 7 deterministically
prepended its standard current-user and all-users module directories to the
sealed two-entry parent `PSModulePath`, while the frozen bootstrap accepted
only the unexpanded value. No ZIP, manifest, checksum, qualification receipt,
candidate root, or success marker exists. Never delete, recreate, retarget,
repair, publish, or retry that tag; the successor is `v2.0.75`.

`v2.0.75` is permanently quarantined as an unpublished local candidate after
exclusive Windows Sandbox qualification classified it `FAIL`. Its annotated tag
object is `17531bc92faddf1c769447ac0cf1909fd559bbc6`, peeling to
`b4a7acdf83c0cac37dbcf59bd518fd3171f61d96`; its one preserved ZIP is exactly
126456582 bytes with SHA-256
`da142199a3f4017f3984324b34aa9b69fb4a4bbb1fe0c2b3b243f35a5452499b`.
The public install exited `1` after 130.739 seconds because the package-owned
isolated SYSTEM relay returned LastTaskResult `1`, produced no launcher or
runtime evidence, and the isolated authority received zero runtime-lease
requests. Never clean, alter, rebuild, retag, publish, retry, or reuse those
bytes; the successor is `v2.0.76`.

`v2.0.76` is permanently quarantined with **no artifact**. Its annotated local
tag object is `14e431f78dc42d64217014e4f8c6ca933dcf3e33`, peeling to
`5e6e1c239918844c55534d5bc09f3952d565773e`. The one authorized official
builder invocation started, wrote the candidate identity, and entered the
first PyInstaller of `Container_Audit.spec`, then stalled because the
external spawn wrapper redirected both stdout and stderr and called
`ReadToEnd()` on stdout before stderr. That redirected-pipe deadlock is not
a product-source defect. No ZIP, checksum, or qualification receipt exists.
Never delete, recreate, retarget, repair, publish, or retry that tag; the
successor is `v2.0.77`.

`v2.0.77` is permanently quarantined with **no artifact**. Its annotated tag
object `4a27455be3fd21cc0236505931fb5372082b5b50`, preserved only in the isolated
release-preparation mirror and work clone, peels to
`ba8eca5b37e60457f2282e6513f2dc0d4e8d311f`. The create-once `git tag -m`
operation materialized its message as the 15 bytes `Release v2.0.77`, without
the required terminal LF. The canonical parser rejected it before the official
builder was invoked. No candidate root, ZIP, checksum, qualification receipt,
or official builder log exists. Never delete, recreate, retarget, repair,
publish, retry, or reuse that tag; the successor is `v2.0.78`.

`v2.0.78` is permanently quarantined with **no artifact**. Its annotated tag
object `8c72cb1be12841b3338f4fb60cad9e5f602b27d3`, preserved only in the isolated
release-preparation mirror and work clone, peels to
`a0821534944dea5315101f4e0493803a9a7b70b2`. The one authorized official
builder invocation passed source, tag, Python, configuration, and the first
eight PyInstaller target gates, then failed at the protected-administrator ACL
wrapper dry-run because line 332 invoked bare `powershell.exe` while the sealed
`PATH` omitted `WindowsPowerShell\v1.0`. No ZIP, checksum, or qualification
receipt exists; the partial candidate is not qualified. Never delete, recreate,
retarget, repair, publish, retry, or reuse that tag or candidate; the successor
is `v2.0.79`.

`v2.0.84` is permanently quarantined with **no artifact**. Its annotated tag
object `e13b9b84559abb977e752c343670f0d1388e9abb`, preserved only in the
BUILD-10 isolated bare mirror and clones, peels to
`653736a5b22ea90d200d562d8227554fd6e5af35`. The one exact-SHA full-CI run
failed 15 verifier-fixture cases because the fixture copied the regenerated
contract lock while retaining its prior digest expectation. The official
builder and frozen-artifact verifier were not invoked, and no candidate root,
ZIP, checksum, identity, or qualification receipt exists. Never delete,
recreate, move, retarget, publish, retry, or reuse that tag or version; the
successor is `v2.0.85`.

`v2.0.85` is permanently quarantined. Commit
`39ddc2500234d24b1924819673eb6e195a37fa30` has tree
`af2a231739f9779b3d1239c7f45a76361d2bd8a8`; its exact candidate ZIP is
126468142 bytes with SHA-256
`fe70c4bcc868e1fd56b832ef8c6e73a2e4a7769601c6ff813a3f7b51480a902c`.
The charged Sandbox-13 run failed as PRODUCT: Windows Application Control
blocked the public installer's packaged
`Container_Audit_Worker_PC_Register.exe`, and the exact public uninstall then
returned while leaving `C:\KMTech\Apps\Container_Audit\current` present. Never
alter, rebuild, retag, publish, retry, or reuse those bytes; the successor is
`v2.0.86`.

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

The `tools/build_frozen_release_candidate.ps1` builder accepts only that prepared isolated clone. It fails closed unless the clone is clean, its absolute local `origin` is the supplied bare mirror, `HEAD`, local `main`, clone `origin/main`, and mirror `main` are identical, and the FINAL tag object/type/peel are exact in both repositories. Before `build_cli prepare`, PyInstaller, or any other release-mode generation, it parses the canonical tag and writes schema-v2 `FINAL_RELEASE_IDENTITY.json`. It then creates the package once, seals and verifies the manifest, checks extraction/config/probes, and writes schema-v2 `local-artifact-qualification-receipt.json` containing the tag object, source commit/tree, mirror refs, ZIP name/hash/size, principal EXE hash, final-release-identity file hash, and exact nested Windows PowerShell identity.

The authority passes the exact prepared E:-resident executable through
`-PythonExecutable`; the builder itself then establishes and verifies that
authority before release-mode generation. It requires an absolute non-reparse
`.exe` below `E:\KMTech`, snapshots its path, size, SHA-256, file/runtime
version, CPython implementation, machine, and 64-bit architecture, prepends its
directory once to a de-duplicated absolute-only process `PATH`, and requires a
nonempty, unique `PATHEXT` containing `.EXE` exactly once. It then resolves all
PATH-visible Python applications in precedence order. Additional distinct
lower-priority installations are allowed only when the first result is the
exact prepared executable and no second `python` application exists in its
directory; zero, mismatched-first, duplicate, or ambiguous results fail closed.
Every Python build step uses the resolved absolute path, and the builder
revalidates the complete interpreter identity after packaging before issuing a
qualification receipt. The release interpreter must be CPython 3.12, 64-bit.

Before release-mode generation, the builder derives the canonical Windows
PowerShell 5.1 executable from `[Environment]::SystemDirectory`, requires its
fully qualified `WindowsPowerShell\v1.0\powershell.exe` path to exist as a
ordinary non-reparse file, snapshots its size and SHA-256, and proves through
an actual structured-JSON subprocess that `PSEdition` is exactly `Desktop` and
the runtime version is 5.1. The ACL wrapper revalidates that complete identity
and invokes only the sealed absolute executable path with the reviewed
arguments. After packaging, the builder revalidates the identity again and
requires `FINAL_RELEASE_IDENTITY.json` to remain byte-identical before copying
the exact nested identity and its file hash into the final qualification
receipt. The strict verifier requires both files, exact schemas and field
types, and exact cross-receipt equality. Resolution through process `PATH`,
including ambient or launcher-supplied Windows PowerShell directories, is
forbidden.

Every successor authority that creates a new PowerShell builder child must set
the sealed two-entry prelaunch module path and its SHA-256 token before process
creation, while keeping `PSModuleAnalysisCachePath`, `TEMP`, and `TMP` below the
reviewed E:-owned roots. After rehashing the exact candidate source input, the
child uses `tools/enter_release_powershell_module_fence.ps1`, whose load path
performs no module resolution. It must accept only the exact four-entry
PowerShell startup closure: the pinned standard current-user and all-users
module directories followed by the exact sealed PowerShell 7 and Windows
PowerShell directories. The child must then collapse the live path to those
sealed two entries and remove both prelaunch tokens before any module
resolution or source-builder invocation. Any missing, additional, reordered,
duplicate, noncanonical, ambient, or hostile module path fails closed.

Never delete, recreate, or move that tag object. There is no provisional-to-final transition and no post-build tag mutation. If the tag preparation or build fails, or source/manifest bytes change, abandon that version and use a new patch version. Do not repair or overwrite a failed candidate root.

Run the complete installation qualification on a fresh unmodified target using the exact candidate and supported commands, including end-to-end checks and rollback verification. Preserve the qualified local ZIP, `FINAL_RELEASE_IDENTITY.json`, checksum, qualification receipt, and target evidence unchanged.

### Main push and pre-tag-publication gates

Only after every local gate and artifact qualification is `PROVEN` may the exact candidate commit be pushed to `main`. Before pushing the already-created tag object, all of the following are mandatory:

1. Fetch live `origin/main` and prove it equals the receipt's `source_commit` and tree.
2. Record any exact-SHA hosted workflow status factually. If none ran, record `WAIVED_NOT_TESTED`; never relabel it `PASS` or use it instead of the local gate.
3. Require zero nonterminal workflows before any release mutation. Terminal failure/absence is recorded but is not by itself an artifact rejection.
4. With an authorized Administration-read credential, query `GET /repos/KMTechn/Container_Audit/immutable-releases` using API version `2026-03-10` and require `enabled=true`.
5. Prove the remote tag, release, and same-name assets are absent.
6. Re-read the mirror tag object/type/peel and require exact equality with `FINAL_RELEASE_IDENTITY.json` and `local-artifact-qualification-receipt.json`; require the receipt's final-identity SHA-256 and complete Windows PowerShell object to equal the preserved final-identity file exactly.

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
  --expected-contract-sha256 a60ab6e9b74aed08c53b801d52b415ffb728e73afbf64908eba7885c7f474046 `
  --expected-zip-sha256 <RELEASE_BODY_ZIP_SHA256> `
  --expected-zip-size <RELEASE_BODY_ZIP_SIZE> `
  --expected-main-exe-sha256 <RELEASE_BODY_MAIN_EXE_SHA256> `
  --qualified-local-zip-path <PRESERVED_QUALIFIED_LOCAL_ZIP> `
  --final-release-identity <PRESERVED_FINAL_RELEASE_IDENTITY_JSON> `
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
Factory-Contract-SHA256: a60ab6e9b74aed08c53b801d52b415ffb728e73afbf64908eba7885c7f474046
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
