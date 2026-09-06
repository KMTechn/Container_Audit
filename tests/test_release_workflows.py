import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
QUALIFICATION_READER = ROOT / "tools" / "read_release_qualification_tag.py"
RELEASE_CONTRACT = ROOT / "RELEASE_GATE_CONTRACT.md"
FROZEN_BUILDER = ROOT / "tools" / "build_frozen_release_candidate.ps1"
PREPUBLISH_GATE = ROOT / "tools" / "prepublish_release_gate.ps1"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell is required")
    return executable


def test_prepublish_release_gate_rejects_string_boolean_and_integer_sentinels():
    environment = dict(os.environ)
    environment["KMTECH_TEST_PREPUBLISH_GATE"] = str(PREPUBLISH_GATE)
    command = r"""
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_PREPUBLISH_GATE,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { exit 10 }
foreach ($name in @('Test-JsonInteger','Test-ExactBooleanValue','Assert-ReleaseMatchesState')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$Tag = 'v1.2.3'
$body = "Tag: v1.2.3`nCommit: $('a' * 40)`nArtifact: app.zip"
$state = [pscustomobject][ordered]@{
    release_id = 101
    target_commitish = ('a' * 40)
    body = $body
    assets = @(
        [pscustomobject][ordered]@{ id = 201; name = 'app.zip'; size = 7; digest = ('sha256:' + ('b' * 64)); state = 'uploaded' },
        [pscustomobject][ordered]@{ id = 202; name = 'app.zip.sha256'; size = 9; digest = ('sha256:' + ('c' * 64)); state = 'uploaded' }
    )
}
$release = [pscustomobject][ordered]@{
    id = 101
    tag_name = $Tag
    name = "Release $Tag"
    draft = $false
    prerelease = $true
    immutable = $true
    target_commitish = ('a' * 40)
    body = $body
    assets = @(
        [pscustomobject][ordered]@{ id = 201; name = 'app.zip'; size = 7; digest = ('sha256:' + ('b' * 64)); state = 'uploaded' },
        [pscustomobject][ordered]@{ id = 202; name = 'app.zip.sha256'; size = 9; digest = ('sha256:' + ('c' * 64)); state = 'uploaded' }
    )
}
Assert-ReleaseMatchesState -Release $release -State $state -ExpectedDraft $false -ExpectedImmutable $true
function Assert-Rejected($ReleaseValue, $StateValue, [int]$ExitCode) {
    try {
        Assert-ReleaseMatchesState -Release $ReleaseValue -State $StateValue -ExpectedDraft $false -ExpectedImmutable $true
    }
    catch { return }
    exit $ExitCode
}
$stringFalse = $release | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$stringFalse.prerelease = 'false'
Assert-Rejected $stringFalse $state 20
$stringZero = $release | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$zeroState = $state | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$stringZero.id = '0'
$zeroState.release_id = 0
Assert-Rejected $stringZero $zeroState 21
$stringSize = $release | ConvertTo-Json -Depth 6 | ConvertFrom-Json
$stringSize.assets[0].size = '7'
Assert-Rejected $stringSize $state 22
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


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
