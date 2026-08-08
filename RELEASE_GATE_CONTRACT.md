# Container_Audit release gate contract

This contract separates fast feedback, full regression, release-only evidence, and TEST1 field evidence. A tag workflow must never rerun the full suite for a commit already attested by `Full CI`.

| Gate | Accident prevented | Unique signal | Timing | Failure decision |
| --- | --- | --- | --- | --- |
| quick-check | Changed-area contract breakage | Focused pytest node; Python 3.11 import/version compatibility is a distinct CI lane, not selected compile | During development, before final candidate freeze | Fix the affected area; do not advance the candidate |
| full-ci | Functional regression | Python 3.12 full pytest once and source release-config contract; Python 3.11 is compatibility-only | Once for the final `main` SHA; no PR or manual trigger | Make a focused fix and validate the new SHA; do not tag the failed SHA |
| release-gate | Wrong tag/SHA, malformed or altered package/archive/hash/signature | exact tag commit equals `origin/main`, exact-SHA main `Full CI` success, version/config, PyInstaller, CRC/safe extraction, exact staged membership and byte parity, SHA-256, manifest signature self-verification | Tag push after exact-SHA full-ci success | Before GitHub publication: publish nothing. After canary GitHub Release: a feed failure leaves the prerelease quarantined and unpromoted |
| test1-e2e | Frozen GUI, scanner, relay, canary, or rollback failure | Exact ZIP SHA on TEST1, real UI/scanner, direct-sync receipt, update and rollback preservation | Candidate rehearsal before final CI and the identical release artifact before stable rollout | Keep rollout at 0, quarantine artifact |

## Exact commands

One-time environment setup (not part of `quick-check`):

```powershell
python -m pip install -r requirements.txt
python -m pip install pytest==9.0.2
```

Quick compatibility signal:

```powershell
python -c "import Container_Audit, update_service; print('python311_compatibility=PASS')"
python -m pytest -q -p no:cacheprovider tests/test_release_version.py tests/test_release_config.py
```

Full CI ownership:

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider
```

Release-only checks are the commands in `.github/workflows/release.yml` from `Check release version` through `Smoke check release archive`; no pytest or compile command may be added there. The workflow queries `actions/workflows/ci.yml/runs` and requires a successful `main` `push` run whose `head_sha` equals the tag commit.

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

Full CI intentionally does not stage the release config or run PyInstaller/archive smoke because the tag workflow produces and verifies those package-context signals once. A newer `main` push cancels an obsolete in-progress Full CI run. The tag workflow may publish only a canary prerelease when private feed is enabled and enforces rollout `0`. Private-feed publication occurs after GitHub Release success, so feed failure can leave a GitHub prerelease; it must remain quarantined and not latest/stable. Stable rollout is a separate owner-approved operation after TEST1 PASS. GitHub branch protection and production owner approvals are external blockers.
