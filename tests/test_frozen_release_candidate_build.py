import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_frozen_release_candidate.ps1"


def test_frozen_candidate_builder_requires_prepared_isolated_mirror_and_final_tag():
    script = BUILDER.read_text(encoding="utf-8")

    assert "[string]$MirrorRoot" in script
    assert '"--is-bare-repository"' in script
    assert "Prepared release work clone origin must be the exact supplied local bare mirror" in script
    assert '"refs/heads/main^{commit}"' in script
    assert '"refs/remotes/origin/main^{commit}"' in script
    assert '"refs/heads/main^{commit}"' in script
    assert '"cat-file", "-t", $tagRef' in script
    assert '"rev-parse", "--verify", "$tagRef^{commit}"' in script
    assert "tools/read_release_qualification_tag.py" in script
    assert '"FINAL_RELEASE_IDENTITY.json"' in script
    assert script.index("tools/read_release_qualification_tag.py") < script.index(
        '"kmtech_factory_contracts.build_cli", "prepare"'
    )
    assert "OutputRoot must be a fresh absent path" in script
    assert "Isolated release work clone must be clean" in script

    for forbidden in (
        "PROVISIONAL",
        "provisional",
        "FINAL_TAG_MESSAGE.txt",
        '"tag", "--delete"',
        '"tag", "--annotate"',
        "actions/workflows/ci.yml/runs",
        "immutable-releases",
        "gh api",
        "git fetch",
        "ls-remote",
    ):
        assert forbidden not in script


def test_frozen_candidate_builder_builds_seals_and_smokes_the_complete_package():
    script = BUILDER.read_text(encoding="utf-8")

    for marker in (
        'm.version(\'pyinstaller\') == \'6.20.0\'',
        '"kmtech_factory_contracts.build_cli", "prepare"',
        '"Container_Audit.spec"',
        '"Container_Audit_DirectSync_Relay"',
        '"Container_Audit_DirectSync_Install"',
        '"Container_Audit_Worker_PC_Register"',
        '"Container_Audit_Protected_Admin_Install"',
        '"KMTech_Logistics_Profile_Install"',
        '"KMTech_Logistics_Profile_Check"',
        '"KMTechActiveWorkProbe"',
        '"kmtech_factory_contracts.build_cli", "manifest"',
        '"kmtech_factory_contracts.build_cli", "verify"',
        "Compress-Archive",
        '"tools/check_update_archive.py"',
        '"tools/check_release_config.py"',
        '"local-artifact-qualification-receipt.json"',
        'status = "LOCAL_ARTIFACT_QUALIFICATION_PASS"',
        "tag_object_sha = $tagObject",
        "zip_sha256 = $zipSha256",
        "zip_size = $zipInfo.Length",
        "main_exe_sha256 = $mainExeSha256",
    ):
        assert marker in script
    assert "gh release create" not in script
    assert "gh release upload" not in script
    assert "git push" not in script
    assert "PRIVATE_UPDATE_MANIFEST" not in script


def test_frozen_candidate_builder_powershell_parses():
    escaped = str(BUILDER).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){$errors|ForEach-Object{$_.Message}|Write-Error;exit 1}"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )


def test_git_output_helpers_accept_a_clean_status_with_no_stdout():
    script = BUILDER.read_text(encoding="utf-8")

    assert script.count('return (([string[]]$value) -join "`n").Trim()') == 2
    assert "return ([string]$value).Trim()" not in script
