# Container_Audit release gate contract

This contract separates fast feedback, full regression, release-only evidence, and TEST1 field evidence. A tag workflow must never rerun the full suite for a commit already attested by `Full CI`.

| Gate | Accident prevented | Unique signal | Timing | Failure decision |
| --- | --- | --- | --- | --- |
| quick | Changed-area contract breakage | Focused pytest node; Python 3.11 import/version compatibility is a distinct CI lane, not selected compile | Before main push | Do not push |
| full | Functional regression | Python 3.12 full pytest once and source release-config contract; Python 3.11 is compatibility-only | Once per main-push SHA; no PR or manual trigger | Make a focused fix and validate the new SHA; do not tag the failed SHA |
| release | Wrong tag/SHA, malformed package/archive/hash/signature | exact tag commit equals `origin/main`, exact-SHA main `Full CI` success, version/config, PyInstaller, safe extraction, SHA-256, manifest signature self-verification | Tag push | Before GitHub publication: publish nothing. After canary GitHub Release: a feed failure leaves the prerelease quarantined and unpromoted |
| test1 | Frozen GUI, scanner, relay, canary, or rollback failure | Exact ZIP SHA on TEST1, real UI/scanner, direct-sync receipt, update and rollback preservation | After GitHub artifact exists, before stable rollout | Keep rollout at 0, quarantine artifact |

## Exact commands

Quick compatibility signal:

```powershell
python -m pip install -r requirements.txt
python -m pip install pytest==9.0.2
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
python tools/packaged_real_ui_driver.py --exe <EXTRACTED_ZIP>\Container_Audit\Container_Audit.exe --output-root <FRESH_EVIDENCE_DIR> --data-root <FRESH_TEST_DATA_ROOT> --worker TEST1 --master-label <APPROVED_PHS2>
```

Full CI intentionally does not stage the release config or run PyInstaller/archive smoke because the tag workflow produces and verifies those package-context signals once. A newer `main` push cancels an obsolete in-progress Full CI run. The tag workflow may publish only a canary prerelease when private feed is enabled and enforces rollout `0`. Private-feed publication occurs after GitHub Release success, so feed failure can leave a GitHub prerelease; it must remain quarantined and not latest/stable. Stable rollout is a separate owner-approved operation after TEST1 PASS. GitHub branch protection/CODEOWNER enforcement and production owner approvals are external blockers.
