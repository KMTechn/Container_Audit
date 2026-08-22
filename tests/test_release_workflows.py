import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
QUALIFICATION_READER = ROOT / "tools" / "read_release_qualification_tag.py"
RELEASE_CONTRACT = ROOT / "RELEASE_GATE_CONTRACT.md"
FROZEN_BUILDER = ROOT / "tools" / "build_frozen_release_candidate.ps1"


def test_tag_release_workflow_is_verification_only():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "contents: read" in release
    assert "contents: write" not in release
    assert "Verify immutable release self-consistency and embedded identities" in release
    assert "tools/verify_frozen_release_artifact.py" in release
    assert "gh release download" in release
    assert "gh release create" not in release
    assert "action-gh-release" not in release
    assert "COMPANY_UPDATE_UPLOAD" not in release
    assert "curl.exe" not in release

    forbidden_build_markers = (
        "PyInstaller",
        "Compress-Archive",
        "build_cli prepare",
        "build_cli manifest",
        "build_cli verify",
        "pip install",
        "dist/Container_Audit",
    )
    assert all(marker not in release for marker in forbidden_build_markers)


def test_frozen_asset_wait_is_bounded_and_requires_exact_prerelease_assets():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "$maximumAttempts = 180" in release
    assert "$pollSeconds = 10" in release
    assert "$attempt -le $maximumAttempts" in release
    assert "Start-Sleep -Seconds $pollSeconds" in release
    assert "$release.draft -ne $false" in release
    assert "$release.prerelease -ne $true" in release
    assert "$release.immutable -ne $true" in release
    assert "$release.tag_name -cne $env:RELEASE_TAG" in release
    assert "$releaseTarget -cne $env:RELEASE_TAG_COMMIT_SHA" in release
    assert '$releaseTarget -cne "main"' in release
    assert "$assetNames.Count -ne 2" in release
    assert "Container_Audit-$env:RELEASE_TAG.zip" in release
    assert '"$zipName.sha256"' in release
    assert "FROZEN_ZIP_ASSET_ID" in release
    assert "FROZEN_CHECKSUM_ASSET_ID" in release
    assert "prerelease assets changed during download" in release
    assert "downloaded bytes differ from GitHub asset size/digest metadata" in release
    assert "uploaded ZIP metadata differs from the immutable release body record" in release
    assert "$candidateRelease.immutable -eq $true" in release
    assert 'X-GitHub-Api-Version: $apiVersion' in release
    assert "immutable-releases" not in release
    assert "Governing comparison with preserved qualified local bytes" in release
    assert "NOT TESTED on hosted runner" in release


def test_release_requires_exact_title_body_identity_and_quarantined_status():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    for line in (
        '"Internal prerelease; not production-ready."',
        '"Tag: $env:RELEASE_TAG"',
        '"Commit: $releaseCommit"',
        '"Tree: $releaseTree"',
        '"Artifact: $zipName"',
        '"Artifact-SHA256: $($releaseEvidence.zip_sha256)"',
        '"Artifact-Size: $($releaseEvidence.zip_size)"',
        '"Main-EXE-SHA256: $($releaseEvidence.main_exe_sha256)"',
        '"Factory-Contract-SHA256: $factoryContractSha256"',
        '"Hosted-CI-Release-Gate: WAIVED_NOT_TESTED"',
        '"Status: QUARANTINED_PENDING_FACTORY_QUALIFICATION"',
    ):
        assert line in release
    assert '$expectedReleaseTitle = "Release $env:RELEASE_TAG"' in release
    assert "Read-ReleaseBodyEvidence" in release
    assert "Artifact-SHA256: (?<zip>[0-9a-f]{64})" in release
    assert "$candidateRelease.name -ceq $expectedReleaseTitle" in release
    assert "$releaseBody -cne $expectedReleaseBody" in release


def test_release_verifier_is_bound_to_tag_source_and_factory_contract():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "RELEASE_TAG_OBJECT_SHA" in release
    assert "RELEASE_TAG_COMMIT_SHA" in release
    assert "--expected-tag" in release
    assert "--expected-tag-object $env:RELEASE_TAG_OBJECT_SHA" in release
    assert "--expected-commit $releaseCommit" in release
    assert "--expected-tree $releaseTree" in release
    assert "--expected-zip-sha256 $env:RELEASE_BODY_ZIP_SHA256" in release
    assert "--expected-zip-size $env:RELEASE_BODY_ZIP_SIZE" in release
    assert "--expected-main-exe-sha256 $env:RELEASE_BODY_MAIN_EXE_SHA256" in release
    assert "QUALIFIED_ZIP" not in release
    assert (
        "FACTORY_CONTRACT_SHA256: "
        "adaa08684ebb291837327f63f967a4f22650dff72c4c1dc56ce1a9bee6b5404a"
    ) in release
    assert "--expected-contract-sha256 $env:FACTORY_CONTRACT_SHA256" in release
    assert "frozen-release-verification.json" in release
    assert "GITHUB_STEP_SUMMARY" in release


def test_release_records_hosted_ci_factually_without_making_it_a_gate():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "Prebind annotated tag object and peel to exact origin main" in release
    assert 'git cat-file -t $tagRef' in release
    assert 'git rev-parse --verify "$tagRef^{commit}"' in release
    assert "Bind canonical create-once FINAL tag identity" in release
    assert "tools/read_release_qualification_tag.py" in release
    assert '--tag-ref "refs/tags/$env:GITHUB_REF_NAME"' in release
    assert release.index("Prebind annotated tag object") < release.index(
        "tools/read_release_qualification_tag.py"
    )
    assert "Canonical tag parser disagrees with the prebound create-once object or peel" in release
    assert "Record hosted CI status without release gating" in release
    hosted = release[
        release.index("- name: Record hosted CI status without release gating") :
        release.index("- name: Check release version")
    ]
    assert "-f status=completed" not in hosted
    assert "WAIVED_NOT_TESTED" in hosted
    assert "UNPROVEN_QUERY_FAILED" in hosted
    assert "hosted_ci_observation=NOT_FOUND" in hosted
    assert "run_attempt" in hosted
    assert "conclusion" in hosted
    assert "throw" not in hosted.lower()
    assert "$runs.Count -eq 0" in hosted
    assert "$runs.Count -ne 1" not in hosted
    assert "python -m pytest" not in release


def test_qualification_reader_parses_bounded_raw_annotated_tag_object_exactly():
    reader = QUALIFICATION_READER.read_text(encoding="utf-8")

    assert '"cat-file", "-t", tag_ref' in reader
    assert '"cat-file", "-s", tag_ref' in reader
    assert '"cat-file", "tag", tag_ref, binary=True' in reader
    assert "MAX_TAG_OBJECT_BYTES" in reader
    assert 'expected_message = b"Release " + expected_tag_bytes + b"\\n"' in reader
    assert "Qualified-ZIP-SHA256:" not in reader
    assert "Qualified-ZIP-Size:" not in reader
    assert "Qualified-Main-EXE-SHA256:" not in reader


def test_release_contract_requires_final_tag_before_isolated_prepush_build():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "isolated local bare mirror" in contract
    assert "FINAL intended annotated tag object" in contract
    assert "before any release-mode identity or build" in contract
    assert "never delete, recreate, or move" in contract.lower()
    assert "Narrow Phase 8.3 circular-anchor exception" not in contract
    assert "There is no provisional-to-final transition" in contract
    assert "Supported pre-push isolated candidate build" in contract
    assert "tools/build_frozen_release_candidate.ps1" in contract
    assert "attempt-1" not in contract
    assert "GitHub Actions is not a release gate" in contract
    assert "Hosted-CI-Release-Gate: WAIVED_NOT_TESTED" in contract
    assert "zero nonterminal workflows" in contract
    assert "enabled=false" in contract
    assert "draft prerelease" in contract
    assert "immutable=true" in contract
    assert "preserved qualified local bytes" in contract


def test_release_contract_quarantines_v2068_tag_without_an_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.68` is permanently quarantined with **no artifact**" in contract
    assert "a28d7b57cd624f29b18356adc05c6e64c8b5d887" in contract
    assert "5e2d7bd284a6a36f360c862dba51e4d8bba169cd" in contract
    assert "no ZIP,\nmanifest, checksum, or qualification receipt exists" in contract
    assert "Never delete, recreate,\nretarget, publish, or retry that tag" in contract


def test_release_contract_quarantines_v2069_inconclusive_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.69` is permanently quarantined as an unpublished local candidate" in contract
    assert "9f0c76bbd26f0dd56d6c6e396c30c2d3ede01a72" in contract
    assert "3c126160560620694bbbcd0378f53f343340c5b6" in contract
    assert "110970957 bytes" in contract
    assert "da86ead0067cd2196681be18221faf301db67633bbf41e6a7ac9304a6a0259f6" in contract
    assert "the successor is `v2.0.70`" in contract


def test_release_contract_quarantines_v2070_builder_failure_without_an_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.70` is permanently quarantined with **no artifact**" in contract
    assert "2ae5f677447a1e2db4cfcc53c71a4aceef5f4e9a" in contract
    assert "848b3fed38190cb26d643dd50697f5d3a0c24d94" in contract
    assert "ambient Python\npreceded the explicitly supplied prepared interpreter" in contract
    assert "No ZIP, manifest,\nchecksum, or qualification receipt exists" in contract
    assert "Never delete, recreate, retarget,\npublish, or retry that tag" in contract
    assert "the successor is `v2.0.71`" in contract


def test_release_contract_quarantines_v2071_sandbox_failure_and_exact_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.71` is permanently quarantined as an unpublished local candidate" in contract
    assert "6c46d0e078f77a6c395e94c441c949f7abd79244" in contract
    assert "46dee4e55e134b37cab31fda4db0509d3c658cfe" in contract
    assert "126453345 bytes" in contract
    assert "c557a7899bf990b414552dc7a4355e07e65a9a26c0425bae25dda024b8a419e1" in contract
    assert "SYSTEM relay made no isolated runtime-lease request" in contract
    assert "qualification authority process survived official uninstall" in contract
    assert "the\nsuccessor is `v2.0.72`" in contract


def test_release_contract_quarantines_v2072_sandbox_failure_and_exact_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.72` is permanently quarantined as an unpublished local candidate" in contract
    assert "abc9b958833b6b6a9264a075a5473e9bb41224af" in contract
    assert "fdc4cb3ef934c25b9087ccf68b958dfd5730f989" in contract
    assert "126455428 bytes" in contract
    assert "6423e829eebd551dfd5d23e8294c353cc2fef37f70cabe718a2f87e9a99dbc5e" in contract
    assert "SYSTEM relay exited `1` without a status, log, or runtime-lease request" in contract
    assert "shell whose working directory was that root" in contract
    assert "the successor is `v2.0.73`" in contract


def test_release_contract_quarantines_v2073_postbuild_failure_and_exact_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.73` is permanently quarantined as an unpublished local candidate" in contract
    assert "1dee7f93a2c98e07ae2a9381c575d451b05a6a96" in contract
    assert "83fc636def457b8a34af929a00b1f8f5c7443b6a" in contract
    assert "126456593 bytes" in contract
    assert "f1f7e6ad385d06918abbe6021fbfa3929129d5986201e51da563dba94b73c233" in contract
    assert "six unsealed `__pycache__/*.pyc` files" in contract
    assert "totaling 295120 bytes" in contract
    assert "the successor is `v2.0.74`" in contract


def test_release_contract_quarantines_v2074_builder_bootstrap_failure_without_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.74` is permanently quarantined with **no artifact**" in contract
    assert "4e7b960e4a6f1fba59772a8645d9cfa0e65d03cc" in contract
    assert "935014a0fbca214390815392d71193f30796d622" in contract
    assert "stopped before source-builder entry" in contract
    assert "standard current-user and all-users module directories" in contract
    assert "No ZIP, manifest, checksum, qualification receipt,\ncandidate root, or success marker exists" in contract
    assert "Never delete, recreate, retarget,\nrepair, publish, or retry that tag" in contract
    assert "the successor is `v2.0.75`" in contract


def test_release_contract_quarantines_v2075_sandbox_system_relay_lease_failure():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.75` is permanently quarantined as an unpublished local candidate after" in contract
    assert "exclusive Windows Sandbox qualification classified it `FAIL`" in contract
    assert "17531bc92faddf1c769447ac0cf1909fd559bbc6" in contract
    assert "b4a7acdf83c0cac37dbcf59bd518fd3171f61d96" in contract
    assert "126456582 bytes" in contract
    assert "da142199a3f4017f3984324b34aa9b69fb4a4bbb1fe0c2b3b243f35a5452499b" in contract
    assert "LastTaskResult `1`" in contract
    assert "zero runtime-lease" in contract
    assert "the successor is `v2.0.76`" in contract


def test_release_contract_quarantines_v2076_spawn_wrapper_deadlock_without_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.76` is permanently quarantined with **no artifact**" in contract
    assert "14e431f78dc42d64217014e4f8c6ca933dcf3e33" in contract
    assert "5e6e1c239918844c55534d5bc09f3952d565773e" in contract
    assert "redirected both stdout and stderr and called\n`ReadToEnd()` on stdout before stderr" in contract
    assert "redirected-pipe deadlock is not\na product-source defect" in contract
    assert "No ZIP, checksum, or qualification receipt exists" in contract
    assert "Never delete, recreate, retarget, repair, publish, or retry that tag" in contract
    assert "the\nsuccessor is `v2.0.77`" in contract


def test_release_contract_quarantines_v2077_noncanonical_tag_without_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.77` is permanently quarantined with **no artifact**" in contract
    assert "4a27455be3fd21cc0236505931fb5372082b5b50" in contract
    assert "ba8eca5b37e60457f2282e6513f2dc0d4e8d311f" in contract
    assert "materialized its message as the 15 bytes `Release v2.0.77`" in contract
    assert "without\nthe required terminal LF" in contract
    assert "canonical parser rejected it before the official\nbuilder was invoked" in contract
    assert "No candidate root, ZIP, checksum, qualification receipt,\nor official builder log exists" in contract
    assert "Never delete, recreate, retarget, repair,\npublish, retry, or reuse that tag" in contract
    assert "the successor is `v2.0.78`" in contract


def test_release_contract_quarantines_v2078_bare_powershell_failure_without_artifact():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "`v2.0.78` is permanently quarantined with **no artifact**" in contract
    assert "8c72cb1be12841b3338f4fb60cad9e5f602b27d3" in contract
    assert "a0821534944dea5315101f4e0493803a9a7b70b2" in contract
    assert "one authorized official\nbuilder invocation" in contract
    assert "line 332 invoked bare `powershell.exe`" in contract
    assert "sealed\n`PATH` omitted `WindowsPowerShell\\v1.0`" in contract
    assert "No ZIP, checksum, or qualification\nreceipt exists" in contract
    assert "partial candidate is not qualified" in contract
    assert "the successor\nis `v2.0.79`" in contract


def test_release_contract_requires_exact_builder_child_module_path_closure():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "sealed two-entry prelaunch module path and its SHA-256 token" in contract
    assert "`PSModuleAnalysisCachePath`, `TEMP`, and `TMP` below the\nreviewed E:-owned roots" in contract
    assert "`tools/enter_release_powershell_module_fence.ps1`" in contract
    assert "whose load path\nperforms no module resolution" in contract
    assert "accept only the exact four-entry\nPowerShell startup closure" in contract
    assert "collapse the live path to those\nsealed two entries" in contract
    assert "before any module\nresolution or source-builder invocation" in contract
    assert "additional, reordered,\nduplicate, noncanonical, ambient, or hostile module path fails closed" in contract


def test_release_contract_requires_builder_owned_python_authority():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "builder itself then establishes and verifies that\nauthority" in contract
    assert "absolute non-reparse\n`.exe` below `E:\\KMTech`" in contract
    assert "size, SHA-256, file/runtime\nversion" in contract
    assert "de-duplicated absolute-only process `PATH`" in contract
    assert "unique `PATHEXT` containing `.EXE` exactly once" in contract
    assert "zero, mismatched-first, duplicate, or ambiguous results fail closed" in contract
    assert "revalidates the complete interpreter identity after packaging" in contract
    assert "CPython 3.12, 64-bit" in contract


def test_release_contract_requires_absolute_windows_powershell_authority():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "derives the canonical Windows\nPowerShell 5.1 executable" in contract
    assert "`[Environment]::SystemDirectory`" in contract
    assert "fully qualified `WindowsPowerShell\\v1.0\\powershell.exe` path" in contract
    assert "ordinary non-reparse file" in contract
    assert "structured-JSON subprocess that `PSEdition` is exactly `Desktop`" in contract
    assert "runtime version is 5.1" in contract
    assert "invokes only the sealed absolute executable path" in contract
    assert "revalidates the identity again" in contract
    assert "`FINAL_RELEASE_IDENTITY.json` to remain byte-identical" in contract
    assert "exact nested identity and its file hash" in contract
    assert "exact cross-receipt equality" in contract
    assert "Resolution through process `PATH`" in contract


def test_release_contract_requires_v2_receipt_and_final_identity_parity_input():
    contract = RELEASE_CONTRACT.read_text(encoding="utf-8")

    assert "schema-v2 `FINAL_RELEASE_IDENTITY.json`" in contract
    assert "schema-v2 `local-artifact-qualification-receipt.json`" in contract
    assert "final-release-identity file hash" in contract
    assert "exact nested Windows PowerShell identity" in contract
    assert "--final-release-identity <PRESERVED_FINAL_RELEASE_IDENTITY_JSON>" in contract


def test_release_finally_revalidates_remote_tag_main_release_and_assets():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    final = release[release.index("- name: Finally revalidate remote tag main"):]

    assert "git/ref/tags/$env:RELEASE_TAG" in final
    assert "git/tags/$env:RELEASE_TAG_OBJECT_SHA" in final
    assert "$remoteRef.object.sha -cne $env:RELEASE_TAG_OBJECT_SHA" in final
    assert "$remoteTag.object.sha -cne $env:RELEASE_TAG_COMMIT_SHA" in final
    assert "refs/remotes/origin/main^{commit}" in final
    assert "$finalRelease.tag_name -cne $env:RELEASE_TAG" in final
    assert "$finalRelease.draft -ne $false" in final
    assert "$finalRelease.prerelease -ne $true" in final
    assert "$finalRelease.immutable -ne $true" in final
    assert "$finalRelease.target_commitish -cne $env:FROZEN_RELEASE_TARGET" in final
    assert "$finalRelease.target_commitish -cne $env:RELEASE_TAG_COMMIT_SHA" in final
    assert '$finalRelease.target_commitish -cne "main"' in final
    assert "$finalAssets.Count -ne 2" in final
    assert "FROZEN_ZIP_ASSET_ID" in final
    assert "FROZEN_CHECKSUM_ASSET_ID" in final
    assert "FROZEN_ZIP_ASSET_SIZE" in final
    assert "FROZEN_CHECKSUM_ASSET_SIZE" in final
    assert "FROZEN_ZIP_ASSET_DIGEST" in final
    assert "FROZEN_CHECKSUM_ASSET_DIGEST" in final
    assert "immutable-releases" not in final
    assert "$finalSnapshot -cne $initialSnapshot" in final
    assert "final immutable release snapshot differs" in final


def test_release_workflow_pins_external_actions():
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    uses_values = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", release)

    assert uses_values
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in uses_values)


def test_ci_workflow_tests_supported_python_minors():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^permissions:\n\s+contents: read$", ci)
    assert "full-ci (Python 3.12)" in ci
    assert "compatibility-quick (Python 3.11)" in ci
    assert ci.count("python -m pytest -q -p no:cacheprovider") == 2
    assert "python -m PyInstaller" not in ci
    assert "pull_request:" not in ci
    assert "workflow_dispatch:" not in ci
    assert "cancel-in-progress: true" in ci


def test_dev_toolchain_is_pinned_in_requirements_dev():
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")

    assert "pytest==9.0.2" in requirements
    assert "pyinstaller==6.20.0" in requirements
