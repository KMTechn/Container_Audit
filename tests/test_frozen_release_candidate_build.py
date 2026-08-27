import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_frozen_release_candidate.ps1"
PYTHON_RESOLVER = ROOT / "tools" / "resolve_release_python.ps1"
WINDOWS_POWERSHELL_RESOLVER = ROOT / "tools" / "resolve_windows_powershell.ps1"
PWSH = "pwsh"


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
    assert "[string]$PythonExecutable" in script
    assert 'Initialize-ReleasePythonAuthority' in script
    assert 'Assert-ReleasePythonIdentity' in script
    assert 'release_python_authority=PASS' in script
    assert 'release_python = [ordered]@{' in script
    assert 'Invoke-Checked -FilePath "python"' not in script
    assert '= python tools/read_release_qualification_tag.py' not in script

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


def test_frozen_candidate_builder_uses_preflighted_absolute_windows_powershell():
    script = BUILDER.read_text(encoding="utf-8")

    authority = script.index("Initialize-WindowsPowerShellAuthority")
    generation = script.index('"kmtech_factory_contracts.build_cli", "prepare"')
    assertion = script.index("Assert-WindowsPowerShellIdentity")
    wrapper = script.index(
        "Invoke-Checked -FilePath $windowsPowerShellExecutable -Arguments @("
    )

    assert '. (Join-Path $PSScriptRoot "resolve_windows_powershell.ps1")' in script
    assert "$windowsPowerShellSystemDirectory = [Environment]::SystemDirectory" in script
    assert '"WindowsPowerShell\\v1.0\\powershell.exe"' in script
    assert "windows_powershell = [ordered]@{" in script
    assert 'schema_version = "container-audit-final-release-identity-v2"' in script
    assert script.count("Assert-WindowsPowerShellIdentity") == 2
    assert authority < generation
    assert generation < assertion < wrapper
    assert 'Invoke-Checked -FilePath "powershell.exe"' not in script
    assert '"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"' in script
    assert (
        '"-File", (Join-Path $packageRoot "PROVISION_PROTECTED_ADMIN_ACL.ps1"), "-DryRun"'
        in script
    )

    final_identity = script[
        script.index("$releaseIdentity = [ordered]@{") : script.index(
            "$finalReleaseIdentityPath ="
        )
    ]
    for field in (
        "executable",
        "system_directory",
        "file_type",
        "is_reparse_point",
        "sha256",
        "size",
        "psedition",
        "powershell_version",
        "version_major",
        "version_minor",
        "file_product_version",
    ):
        assert f"{field} = $windowsPowerShellIdentity.{field}" in final_identity

    receipt = script[script.index("$receipt = [ordered]@{") :]
    assert 'schema_version = "container-audit-local-artifact-qualification-v2"' in receipt
    assert "final_release_identity_sha256 = $finalReleaseIdentitySha256" in receipt
    assert "windows_powershell = $sealedWindowsPowerShellIdentity" in receipt
    assert "$sealedFinalReleaseIdentity.windows_powershell" in script
    assert "$currentFinalReleaseIdentitySha256 -cne $finalReleaseIdentitySha256" in script
    assert script.rindex("Assert-WindowsPowerShellIdentity") < script.index(
        "$receipt = [ordered]@{"
    )


def test_frozen_candidate_builder_builds_seals_and_smokes_the_complete_package():
    script = BUILDER.read_text(encoding="utf-8")

    for marker in (
        'm.version(\'pyinstaller\') == \'6.20.0\'',
        '"kmtech_factory_contracts.build_cli", "prepare"',
        '"Container_Audit.spec"',
        '"--container-audit-direct-sync-relay", "--help"',
        '"Container_Audit_DirectSync_Install"',
        '"Container_Audit_Qualification_Authority"',
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
    assert '"Container_Audit_DirectSync_Relay"' not in script
    assert '"Container_Audit_Worker_PC_Register"' not in script
    assert "gh release create" not in script
    assert "gh release upload" not in script
    assert "git push" not in script
    assert "PRIVATE_UPDATE_MANIFEST" not in script


def test_post_seal_python_smokes_cannot_write_bytecode_and_reverify_inventory():
    script = BUILDER.read_text(encoding="utf-8")
    post_seal = script[script.index("Compress-Archive") : script.index("$zipInfo")]

    for marker in (
        '"-B", "tools/check_update_archive.py"',
        '(Join-Path $smokeRoot "Container_Audit/Container_Audit.exe")',
        '@("--container-audit-direct-sync-relay", "--help")',
        '"-I", "-B", (Join-Path $smokeRoot "Container_Audit/tools/direct_sync_relay_operator.py")',
        '"-B", "tools/check_release_config.py"',
        '"-B", "-m", "kmtech_factory_contracts.build_cli", "verify"',
    ):
        assert marker in post_seal

    assert script.count('"kmtech_factory_contracts.build_cli", "verify"') == 2
    assert post_seal.index('"tools/check_release_config.py"') < post_seal.index(
        '"kmtech_factory_contracts.build_cli", "verify"'
    )
    assert "Remove-Item" not in post_seal
    assert "post_probe_smoke_inventory=PASS" in script


@pytest.mark.parametrize(
    "relative_script",
    (
        "tools/direct_sync_relay_runner.py",
        "tools/direct_sync_relay_operator.py",
    ),
)
def test_supported_source_help_probe_writes_no_bytecode(tmp_path, relative_script):
    cache_prefix = tmp_path / "bytecode"
    environment = os.environ.copy()
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    environment["PYTHONPYCACHEPREFIX"] = str(cache_prefix)

    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / relative_script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert not cache_prefix.exists()


def test_frozen_candidate_builder_powershell_parses():
    for script_path in (BUILDER, PYTHON_RESOLVER, WINDOWS_POWERSHELL_RESOLVER):
        escaped = str(script_path).replace("'", "''")
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


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
def test_windows_powershell_preflight_and_acl_arguments_ignore_sealed_path(tmp_path):
    argument_probe = tmp_path / "acl_argument_probe.ps1"
    argument_probe.write_text(
        """param(
    [switch]$DryRun,
    [Parameter(Mandatory = $true)][string]$Sentinel
)
[ordered]@{
    dry_run = $DryRun.IsPresent
    sentinel = $Sentinel
    bound_parameter_count = $PSBoundParameters.Count
} | ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER": str(WINDOWS_POWERSHELL_RESOLVER),
            "KMTECH_TEST_ARGUMENT_PROBE": str(argument_probe),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER
$systemDirectory = [Environment]::SystemDirectory
$expectedPath = Join-Path $systemDirectory "WindowsPowerShell\v1.0\powershell.exe"
$windowsPowerShellDirectory = [IO.Path]::GetDirectoryName($expectedPath)
$env:PATH = $systemDirectory
if (@(([string]$env:PATH).Split(';') | Where-Object {
    $_.Equals($windowsPowerShellDirectory, [StringComparison]::OrdinalIgnoreCase)
}).Count -ne 0) {
    throw "Test PATH unexpectedly contains the Windows PowerShell directory."
}
$identity = Initialize-WindowsPowerShellAuthority `
    -ExpectedPath $expectedPath `
    -ExpectedSystemDirectory $systemDirectory
$asserted = Assert-WindowsPowerShellIdentity -ExpectedIdentity $identity
$sentinel = "spaces and = signs remain exact"
$wrapperOutput = @(
    & $identity.executable `
        -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $env:KMTECH_TEST_ARGUMENT_PROBE -DryRun -Sentinel $sentinel
)
if ($LASTEXITCODE -ne 0) {
    throw "Windows PowerShell ACL argument probe failed."
}
if ($wrapperOutput.Count -ne 1) {
    throw "Windows PowerShell ACL argument probe was ambiguous."
}
[ordered]@{
    identity = $identity
    asserted_executable = $asserted.executable
    sealed_path = $env:PATH
    excluded_directory = $windowsPowerShellDirectory
    wrapper = ConvertFrom-Json -InputObject ([string]$wrapperOutput[0])
} | ConvertTo-Json -Depth 4 -Compress
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    expected = str(Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    assert result["identity"]["executable"].casefold() == expected.casefold()
    assert result["identity"]["file_type"] == "ordinary-file"
    assert result["identity"]["is_reparse_point"] is False
    assert result["identity"]["psedition"] == "Desktop"
    assert result["identity"]["powershell_version"].startswith("5.1.")
    assert result["asserted_executable"].casefold() == expected.casefold()
    assert result["sealed_path"].casefold() == str(Path(expected).parents[2]).casefold()
    assert result["excluded_directory"].casefold() != result["sealed_path"].casefold()
    assert result["wrapper"] == {
        "dry_run": True,
        "sentinel": "spaces and = signs remain exact",
        "bound_parameter_count": 2,
    }


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
def test_windows_powershell_authority_rejects_missing_executable(tmp_path):
    system_directory = tmp_path / "System32"
    (system_directory / "WindowsPowerShell" / "v1.0").mkdir(parents=True)
    expected = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER": str(WINDOWS_POWERSHELL_RESOLVER),
            "KMTECH_TEST_SYSTEM_DIRECTORY": str(system_directory),
            "KMTECH_TEST_EXPECTED_POWERSHELL": str(expected),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER
try {
    Initialize-WindowsPowerShellAuthority `
        -ExpectedPath $env:KMTECH_TEST_EXPECTED_POWERSHELL `
        -ExpectedSystemDirectory $env:KMTECH_TEST_SYSTEM_DIRECTORY | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 21
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 21
    assert completed.stdout == ""
    assert "executable does not exist" in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
def test_windows_powershell_authority_rejects_wrong_executable_path():
    environment = os.environ.copy()
    environment["KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER"] = str(
        WINDOWS_POWERSHELL_RESOLVER
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER
$systemDirectory = [Environment]::SystemDirectory
try {
    Initialize-WindowsPowerShellAuthority `
        -ExpectedPath (Join-Path $systemDirectory "cmd.exe") `
        -ExpectedSystemDirectory $systemDirectory | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 22
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 22
    assert completed.stdout == ""
    assert "exact canonical Windows PowerShell 5.1 executable path" in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (
            '{"psedition":"Core","powershell_version":"5.1.26100.1"}',
            "PSEdition is not exactly Desktop",
        ),
        (
            '{"psedition":"Desktop","powershell_version":"7.4.0"}',
            "not Windows PowerShell 5.1",
        ),
        ('{"powershell_version":"5.1.26100.1"}', "invalid fields"),
        ("not-json", "invalid identity JSON"),
        (
            '{"psedition":1,"powershell_version":"5.1.26100.1"}',
            "invalid field types",
        ),
        (
            '{"psedition":"Desktop","powershell_version":5.1}',
            "invalid field types",
        ),
        (
            '{"psedition":"desktop","powershell_version":"5.1.26100.1"}',
            "PSEdition is not exactly Desktop",
        ),
        (
            '{"PSEdition":"Desktop","powershell_version":"5.1.26100.1"}',
            "invalid fields",
        ),
        (
            '{"psedition":"Desktop","powershell_version":"5.1.26100.1","extra":true}',
            "invalid fields",
        ),
    ],
    ids=(
        "core_edition",
        "fake_core_runtime",
        "missing_edition",
        "wrong_json",
        "edition_type",
        "version_type",
        "edition_value_case",
        "edition_field_case",
        "extra_field",
    ),
)
def test_windows_powershell_probe_rejects_hostile_identity_payload(payload, error):
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER": str(WINDOWS_POWERSHELL_RESOLVER),
            "KMTECH_TEST_PROBE_PAYLOAD": payload,
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_WINDOWS_POWERSHELL_RESOLVER
try {
    ConvertFrom-WindowsPowerShellProbe `
        -ProbeOutput @($env:KMTECH_TEST_PROBE_PAYLOAD) | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 23
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 23
    assert completed.stdout == ""
    assert error in completed.stderr


def test_git_output_helpers_accept_a_clean_status_with_no_stdout():
    script = BUILDER.read_text(encoding="utf-8")

    assert script.count('return (([string[]]$value) -join "`n").Trim()') == 2
    assert "return ([string]$value).Trim()" not in script


@pytest.mark.parametrize(
    ("discovered_sources", "should_pass", "error"),
    [
        ([r"E:\ReleasePython\python.exe"], True, ""),
        (
            [r"E:\RELEASEPYTHON\PYTHON.EXE", r"C:\OtherPython\python.exe"],
            True,
            "",
        ),
        ([], False, "No Python application"),
        ([r"C:\OtherPython\python.exe"], False, "first PATH-discovered"),
        (
            [r"C:\OtherPython\python.exe", r"E:\ReleasePython\python.exe"],
            False,
            "first PATH-discovered",
        ),
        (
            [r"E:\ReleasePython\python.exe", r"E:\RELEASEPYTHON\PYTHON.EXE"],
            False,
            "duplicate or ambiguous",
        ),
        (
            [r"E:\ReleasePython\python.exe", r"E:\ReleasePython\python.cmd"],
            False,
            "directory has ambiguous",
        ),
        (
            [
                r"E:\ReleasePython\python.exe",
                r"C:\OtherPython\python.exe",
                r"C:\OTHERPYTHON\PYTHON.EXE",
            ],
            False,
            "duplicate or ambiguous",
        ),
    ],
    ids=(
        "scalar_expected",
        "multiple_expected_first",
        "zero",
        "scalar_wrong",
        "multiple_expected_later",
        "duplicate_expected",
        "ambiguous_same_directory",
        "duplicate_lower_priority",
    ),
)
def test_release_python_resolver_uses_only_the_first_path_ordered_application(
    discovered_sources,
    should_pass,
    error,
):
    expected = r"E:\ReleasePython\python.exe"
    environment = os.environ.copy()
    environment["KMTECH_TEST_RESOLVER_PATH"] = str(PYTHON_RESOLVER)
    environment["KMTECH_TEST_DISCOVERED_JSON"] = json.dumps(discovered_sources)
    environment["KMTECH_TEST_EXPECTED_PYTHON"] = expected
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$decoded = ConvertFrom-Json -InputObject $env:KMTECH_TEST_DISCOVERED_JSON
$discovered = if ($null -eq $decoded) { @() } else { @($decoded) }
try {
    $resolved = Resolve-ReleasePythonApplication `
        -DiscoveredSources $discovered `
        -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON
    [Console]::Out.Write("resolved=$resolved")
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 3
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    if should_pass:
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == f"resolved={expected}"
    else:
        assert completed.returncode == 3
        assert completed.stdout == ""
        assert error in completed.stderr


@pytest.mark.parametrize(
    "discovered_source",
    [r"C:", r"C:relative\python.exe", r"\rooted-without-drive\python.exe", "python.exe"],
    ids=("drive_relative_root", "drive_relative_child", "rooted_without_drive", "relative"),
)
def test_release_python_resolver_rejects_non_fully_qualified_discovery(discovered_source):
    environment = os.environ.copy()
    environment["KMTECH_TEST_RESOLVER_PATH"] = str(PYTHON_RESOLVER)
    environment["KMTECH_TEST_DISCOVERED"] = discovered_source
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
try {
    Resolve-ReleasePythonApplication `
        -DiscoveredSources @($env:KMTECH_TEST_DISCOVERED) `
        -ExpectedPath "E:\ReleasePython\python.exe" | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 4
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 4
    assert "fully qualified path" in completed.stderr


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
def test_release_python_authority_precedes_hostile_path_and_pathext(tmp_path):
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "python.cmd").write_text("@exit /b 91\r\n", encoding="ascii")
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_RESOLVER_PATH": str(PYTHON_RESOLVER),
            "KMTECH_TEST_EXPECTED_PYTHON": sys.executable,
            "KMTECH_TEST_APPROVED_ROOT": Path(sys.executable).anchor,
            "KMTECH_TEST_HOSTILE_PATH": str(hostile),
            "KMTECH_TEST_VERSION_MAJOR": str(sys.version_info.major),
            "KMTECH_TEST_VERSION_MINOR": str(sys.version_info.minor),
            "KMTECH_TEST_ARCH_BITS": str(8 * __import__("struct").calcsize("P")),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$pythonDirectory = [IO.Path]::GetDirectoryName($env:KMTECH_TEST_EXPECTED_PYTHON)
$env:PATH = "$env:KMTECH_TEST_HOSTILE_PATH;$pythonDirectory;$env:KMTECH_TEST_HOSTILE_PATH"
$env:PATHEXT = ".CMD;.EXE"
$identity = Initialize-ReleasePythonAuthority `
    -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON `
    -ApprovedRoot $env:KMTECH_TEST_APPROVED_ROOT `
    -ExpectedVersionMajor ([int]$env:KMTECH_TEST_VERSION_MAJOR) `
    -ExpectedVersionMinor ([int]$env:KMTECH_TEST_VERSION_MINOR) `
    -ExpectedArchitectureBits ([int]$env:KMTECH_TEST_ARCH_BITS)
$discovered = @(Get-Command python -CommandType Application -All).Source
[ordered]@{
    identity = $identity
    first_path = ([string]$env:PATH).Split(';')[0]
    path_entry_count = ([string]$env:PATH).Split(';').Count
    first_discovered = $discovered[0]
    discovered_count = $discovered.Count
} | ConvertTo-Json -Depth 4 -Compress
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    expected = str(Path(sys.executable).resolve())
    assert result["identity"]["executable"].casefold() == expected.casefold()
    assert result["identity"]["sha256"] == _file_sha256(sys.executable)
    assert result["identity"]["python_version"] == ".".join(map(str, sys.version_info[:3]))
    assert result["identity"]["architecture_bits"] == 8 * __import__("struct").calcsize("P")
    assert result["first_path"].casefold() == str(Path(sys.executable).parent).casefold()
    assert result["path_entry_count"] == 2
    assert result["first_discovered"].casefold() == expected.casefold()
    assert result["discovered_count"] == 2


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
def test_release_python_authority_preserves_c_and_e_drive_roots():
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_RESOLVER_PATH": str(PYTHON_RESOLVER),
            "KMTECH_TEST_EXPECTED_PYTHON": sys.executable,
            "KMTECH_TEST_APPROVED_ROOT": Path(sys.executable).anchor,
            "KMTECH_TEST_VERSION_MAJOR": str(sys.version_info.major),
            "KMTECH_TEST_VERSION_MINOR": str(sys.version_info.minor),
            "KMTECH_TEST_ARCH_BITS": str(8 * __import__("struct").calcsize("P")),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$env:PATH = "C:\;E:\"
$env:PATHEXT = ".EXE"
$identity = Initialize-ReleasePythonAuthority `
    -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON `
    -ApprovedRoot $env:KMTECH_TEST_APPROVED_ROOT `
    -ExpectedVersionMajor ([int]$env:KMTECH_TEST_VERSION_MAJOR) `
    -ExpectedVersionMinor ([int]$env:KMTECH_TEST_VERSION_MINOR) `
    -ExpectedArchitectureBits ([int]$env:KMTECH_TEST_ARCH_BITS)
$entries = @(([string]$env:PATH).Split(';'))
[ordered]@{
    executable = $identity.executable
    entries = $entries
    all_fully_qualified = (@($entries | Where-Object {
        -not [IO.Path]::IsPathFullyQualified($_)
    }).Count -eq 0)
} | ConvertTo-Json -Depth 3 -Compress
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["executable"].casefold() == str(Path(sys.executable).resolve()).casefold()
    assert "C:\\" in result["entries"]
    assert "E:\\" in result["entries"]
    assert "C:" not in result["entries"]
    assert "E:" not in result["entries"]
    assert result["all_fully_qualified"] is True


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
@pytest.mark.parametrize(
    "path_entry",
    ["C:", r"C:relative", r"\rooted-without-drive", "relative"],
    ids=("drive_relative_root", "drive_relative_child", "rooted_without_drive", "relative"),
)
def test_release_python_authority_rejects_non_fully_qualified_path_entries(path_entry):
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_RESOLVER_PATH": str(PYTHON_RESOLVER),
            "KMTECH_TEST_EXPECTED_PYTHON": sys.executable,
            "KMTECH_TEST_APPROVED_ROOT": Path(sys.executable).anchor,
            "KMTECH_TEST_HOSTILE_PATH": path_entry,
            "KMTECH_TEST_VERSION_MAJOR": str(sys.version_info.major),
            "KMTECH_TEST_VERSION_MINOR": str(sys.version_info.minor),
            "KMTECH_TEST_ARCH_BITS": str(8 * __import__("struct").calcsize("P")),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$env:PATH = $env:KMTECH_TEST_HOSTILE_PATH
$env:PATHEXT = ".EXE"
try {
    Initialize-ReleasePythonAuthority `
        -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON `
        -ApprovedRoot $env:KMTECH_TEST_APPROVED_ROOT `
        -ExpectedVersionMajor ([int]$env:KMTECH_TEST_VERSION_MAJOR) `
        -ExpectedVersionMinor ([int]$env:KMTECH_TEST_VERSION_MINOR) `
        -ExpectedArchitectureBits ([int]$env:KMTECH_TEST_ARCH_BITS) | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 6
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 6
    assert "fully qualified directories" in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
@pytest.mark.parametrize(
    ("pathext", "error"),
    [
        (".CMD", "contain .EXE exactly once"),
        (".EXE;.exe;.CMD", "duplicate application extensions"),
    ],
    ids=("missing_exe", "duplicate_exe"),
)
def test_release_python_authority_rejects_hostile_pathext(tmp_path, pathext, error):
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_RESOLVER_PATH": str(PYTHON_RESOLVER),
            "KMTECH_TEST_EXPECTED_PYTHON": sys.executable,
            "KMTECH_TEST_APPROVED_ROOT": Path(sys.executable).anchor,
            "KMTECH_TEST_PATH": str(Path(sys.executable).parent),
            "KMTECH_TEST_PATHEXT": pathext,
            "KMTECH_TEST_VERSION_MAJOR": str(sys.version_info.major),
            "KMTECH_TEST_VERSION_MINOR": str(sys.version_info.minor),
            "KMTECH_TEST_ARCH_BITS": str(8 * __import__("struct").calcsize("P")),
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$env:PATH = $env:KMTECH_TEST_PATH
$env:PATHEXT = $env:KMTECH_TEST_PATHEXT
try {
    Initialize-ReleasePythonAuthority `
        -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON `
        -ApprovedRoot $env:KMTECH_TEST_APPROVED_ROOT `
        -ExpectedVersionMajor ([int]$env:KMTECH_TEST_VERSION_MAJOR) `
        -ExpectedVersionMinor ([int]$env:KMTECH_TEST_VERSION_MINOR) `
        -ExpectedArchitectureBits ([int]$env:KMTECH_TEST_ARCH_BITS) | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 7
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 7
    assert error in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="release builder is Windows-only")
@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("sha256", "0" * 64, "sha256 identity changed"),
        ("python_version", "0.0.0", "python_version identity changed"),
        ("architecture_bits", "32", "wrong architecture"),
    ],
    ids=("hash", "version", "architecture"),
)
def test_release_python_authority_rejects_changed_identity(field, replacement, error):
    environment = os.environ.copy()
    environment.update(
        {
            "KMTECH_TEST_RESOLVER_PATH": str(PYTHON_RESOLVER),
            "KMTECH_TEST_EXPECTED_PYTHON": sys.executable,
            "KMTECH_TEST_APPROVED_ROOT": Path(sys.executable).anchor,
            "KMTECH_TEST_PATH": str(Path(sys.executable).parent),
            "KMTECH_TEST_VERSION_MAJOR": str(sys.version_info.major),
            "KMTECH_TEST_VERSION_MINOR": str(sys.version_info.minor),
            "KMTECH_TEST_ARCH_BITS": str(8 * __import__("struct").calcsize("P")),
            "KMTECH_TEST_FIELD": field,
            "KMTECH_TEST_REPLACEMENT": replacement,
        }
    )
    command = r"""
Set-StrictMode -Version Latest
. $env:KMTECH_TEST_RESOLVER_PATH
$env:PATH = $env:KMTECH_TEST_PATH
$env:PATHEXT = ".EXE"
$identity = Initialize-ReleasePythonAuthority `
    -ExpectedPath $env:KMTECH_TEST_EXPECTED_PYTHON `
    -ApprovedRoot $env:KMTECH_TEST_APPROVED_ROOT `
    -ExpectedVersionMajor ([int]$env:KMTECH_TEST_VERSION_MAJOR) `
    -ExpectedVersionMinor ([int]$env:KMTECH_TEST_VERSION_MINOR) `
    -ExpectedArchitectureBits ([int]$env:KMTECH_TEST_ARCH_BITS)
$identity.($env:KMTECH_TEST_FIELD) = $env:KMTECH_TEST_REPLACEMENT
try {
    Assert-ReleasePythonIdentity -ExpectedIdentity $identity | Out-Null
} catch {
    [Console]::Error.Write($_.Exception.Message)
    exit 9
}
"""
    completed = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 9
    assert error in completed.stderr
