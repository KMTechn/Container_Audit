import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "INSTALL_THIS_PC.ps1"
INTEGRITY_HELPER = ROOT / "tools" / "bootstrap_integrity.ps1"
WRITER_SESSION_CONTRACT = ROOT / "tools" / "container_writer_session_contract.json"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell is required")
    return executable


def _run_powershell(
    command: str, environment: dict[str, str]
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )


def test_bootstrap_integrity_rejects_numeric_string_record_fields(tmp_path):
    release = tmp_path / "frozen-release"
    release.mkdir()
    (release / "Container_Audit.exe").write_bytes(b"fixture executable")
    environment = dict(os.environ)
    environment["KMTECH_TEST_INTEGRITY_HELPER"] = str(INTEGRITY_HELPER)
    environment["KMTECH_TEST_RELEASE_ROOT"] = str(release)
    write_record = _run_powershell(
        ". $env:KMTECH_TEST_INTEGRITY_HELPER; "
        "Write-BootstrapIntegrityRecord $env:KMTECH_TEST_RELEASE_ROOT '.' | Out-Null",
        environment,
    )
    assert write_record.returncode == 0, write_record.stderr or write_record.stdout

    record_path = release / "bootstrap-integrity.json"
    valid = json.loads(record_path.read_text(encoding="utf-8"))
    mutations = (
        ("file_count", lambda value: value.__setitem__("file_count", str(value["file_count"]))),
        (
            "file_size",
            lambda value: value["files"][0].__setitem__(
                "size", str(value["files"][0]["size"])
            ),
        ),
    )
    for name, mutate in mutations:
        payload = json.loads(json.dumps(valid))
        mutate(payload)
        record_path.write_text(json.dumps(payload), encoding="utf-8")
        checked = _run_powershell(
            ". $env:KMTECH_TEST_INTEGRITY_HELPER; "
            "Assert-BootstrapIntegrityRecord $env:KMTECH_TEST_RELEASE_ROOT | Out-Null",
            environment,
        )
        assert checked.returncode != 0, f"numeric string accepted for {name}"


def test_bootstrap_replacement_identity_rejects_string_zero():
    environment = dict(os.environ)
    environment["KMTECH_TEST_INTEGRITY_HELPER"] = str(INTEGRITY_HELPER)
    command = r"""
. $env:KMTECH_TEST_INTEGRITY_HELPER
$actual = [pscustomobject][ordered]@{
    file_count = 1
    aggregate_sha256 = ('a' * 64)
    integrity_sha256 = ('b' * 64)
    manifest_sha256 = ('c' * 64)
    source_commit = ('d' * 40)
    source_tree = ('e' * 40)
    owner_sid = 'S-1-5-32-544'
    access_rules_protected = $true
    acl_sddl_sha256 = ('f' * 64)
    reparse_count = 0
}
$stringZero = $actual | ConvertTo-Json -Depth 4 | ConvertFrom-Json
$stringZero.reparse_count = '0'
if (Test-BootstrapReplacementTreeIdentity $stringZero $actual) { exit 10 }
exit 0
"""
    completed = _run_powershell(command, environment)

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_install_helper_rejects_string_false_writer_contract(tmp_path):
    valid_contract = json.loads(WRITER_SESSION_CONTRACT.read_text(encoding="utf-8"))
    invalid_contract = json.loads(json.dumps(valid_contract))
    invalid_contract["lifecycle_restore"][
        "require_lifecycle_restore_before_writer_restore"
    ] = "false"
    valid_path = tmp_path / "valid-contract.json"
    invalid_path = tmp_path / "string-false-contract.json"
    valid_path.write_text(json.dumps(valid_contract), encoding="utf-8")
    invalid_path.write_text(json.dumps(invalid_contract), encoding="utf-8")
    environment = dict(os.environ)
    environment.update(
        {
            "KMTECH_TEST_INSTALLER": str(INSTALLER),
            "KMTECH_TEST_VALID_CONTRACT": str(valid_path),
            "KMTECH_TEST_VALID_SHA256": hashlib.sha256(valid_path.read_bytes()).hexdigest(),
            "KMTECH_TEST_INVALID_CONTRACT": str(invalid_path),
            "KMTECH_TEST_INVALID_SHA256": hashlib.sha256(
                invalid_path.read_bytes()
            ).hexdigest(),
        }
    )
    command = r"""
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_INSTALLER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { exit 10 }
function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}
function Test-BootstrapJsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}
foreach ($name in @('Assert-WriterSessionPublicContract')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
Assert-WriterSessionPublicContract $env:KMTECH_TEST_VALID_CONTRACT $env:KMTECH_TEST_VALID_SHA256
try {
    Assert-WriterSessionPublicContract $env:KMTECH_TEST_INVALID_CONTRACT $env:KMTECH_TEST_INVALID_SHA256
    exit 12
}
catch {
    if ($_.Exception.Message -cne 'Writer session public contract semantics differ.') { exit 13 }
}
exit 0
"""
    completed = _run_powershell(command, environment)

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_install_helper_keeps_restore_booleans_exact_before_evidence_write():
    source = INSTALLER.read_text(encoding="utf-8")

    assert "-not (Test-BootstrapJsonInteger $manifest.file_count_before_manifest)" in source
    assert "-not (Test-BootstrapJsonInteger $manifest.byte_count_before_manifest)" in source
    assert "$result.prior_code_exact -isnot [bool]" in source
    assert "$result.failed_new_preserved -isnot [bool]" in source
    assert "prior_code_exact = $result.prior_code_exact" in source
    assert "failed_new_preserved = $result.failed_new_preserved" in source
