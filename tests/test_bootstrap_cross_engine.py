"""Bootstrap records retain byte identity across Windows PowerShell and PS7."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.powershell_contracts import run_powershell


ROOT = Path(__file__).resolve().parents[1]
BASELINE = "7416378"
ENGINES = ("powershell.exe", "pwsh.exe")
CULTURES = ("ko-KR", "en-US")


def invoke(tmp_path, engine, culture, script, **values):
    assert shutil.which(engine), f"Required bootstrap engine is unavailable: {engine}"
    driver = tmp_path / "cross-engine.ps1"
    driver.write_text(r'''
$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($env:CA_CULTURE)
[Threading.Thread]::CurrentThread.CurrentUICulture = [Threading.Thread]::CurrentThread.CurrentCulture
. $env:CA_HELPER
''' + script, encoding="utf-8-sig")
    env = dict(os.environ, CA_CULTURE=culture,
               CA_HELPER=str(ROOT / "tools/bootstrap_integrity.ps1"))
    env.update({key: str(value) for key, value in values.items()})
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)],
                            env=env, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def release_tree(tmp_path):
    tree = tmp_path / "code"
    for relative in ("Container_Audit.exe", "A.txt", "a_z.txt", "b.txt", "Z.txt",
                     "가.txt", "나.txt", "sub/x.txt", "sub-z.txt",
                     "tools/container_writer_session.ps1"):
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("utf-8"))
    # Real, committed deployed contracts, not a reduced/reissued writer record.
    for name in ("container_writer_session_contract.json", "container_writer_sink_inventory.json"):
        (tree / "tools" / name).write_bytes(subprocess.check_output(
            ["git", "show", f"{BASELINE}:tools/{name}"], cwd=ROOT))
    return tree


@pytest.mark.parametrize("legacy", (True, False), ids=("issued-v1", "ordinal"))
@pytest.mark.parametrize("culture", CULTURES)
@pytest.mark.parametrize("engine", ENGINES)
def test_records_cross_engines_and_cultures_without_reissue(tmp_path, engine, culture, legacy):
    tree = release_tree(tmp_path)
    helper = ROOT / "tools/bootstrap_integrity.ps1"
    if legacy:
        helper = tmp_path / "issued-helper.ps1"
        helper.write_bytes(subprocess.check_output(
            ["git", "show", f"{BASELINE}:tools/bootstrap_integrity.ps1"], cwd=ROOT))
    generated = invoke(tmp_path, engine, culture, r'''
$record = Write-BootstrapIntegrityRecord $env:CA_TREE $env:CA_TREE '2026-09-13T00:00:00Z'
$record | ConvertTo-Json -Depth 8 -Compress
''', CA_TREE=tree, CA_HELPER=helper)
    paths = [entry["path"] for entry in generated["files"]]
    if not legacy:
        assert paths == sorted(paths)
    record_bytes = (tree / "bootstrap-integrity.json").read_bytes()
    original_files = {path.relative_to(tree): path.read_bytes() for path in tree.rglob("*") if path.is_file()}
    for reader, reader_culture in itertools.product(ENGINES, CULTURES):
        accepted = invoke(tmp_path, reader, reader_culture, r'''
Assert-BootstrapIntegrityRecord $env:CA_TREE | ConvertTo-Json -Compress
''', CA_TREE=tree)
        assert accepted["aggregate_sha256"] == generated["aggregate_sha256"]
        assert (tree / "bootstrap-integrity.json").read_bytes() == record_bytes
    relocated = tmp_path / "relocated"
    tree.rename(relocated)
    for reader, reader_culture in itertools.product(ENGINES, CULTURES):
        accepted = invoke(tmp_path, reader, reader_culture, r'''
Assert-BootstrapRelocatedIntegrityRecord $env:CA_TREE $env:CA_ORIGINAL | ConvertTo-Json -Compress
''', CA_TREE=relocated, CA_ORIGINAL=tree)
        assert accepted["aggregate_sha256"] == generated["aggregate_sha256"]
        assert accepted["integrity_sha256"] == hashlib.sha256(record_bytes).hexdigest()
    assert {path.relative_to(relocated): path.read_bytes() for path in relocated.rglob("*")
            if path.is_file()} == original_files


@pytest.mark.parametrize("culture", CULTURES)
@pytest.mark.parametrize("engine", ENGINES)
def test_record_tamper_rejected_by_both_consumers(tmp_path, engine, culture):
    tree = release_tree(tmp_path)
    results = invoke(tmp_path, engine, culture, r'''
$root = $env:CA_TREE
[void](Write-BootstrapIntegrityRecord $root $root)
$recordPath = Join-Path $root 'bootstrap-integrity.json'
$original = [IO.File]::ReadAllBytes($recordPath)
$contentPath = Join-Path $root 'A.txt'
$content = [IO.File]::ReadAllBytes($contentPath)
$results = @()
foreach ($case in @('duplicate', 'missing', 'case', 'hash', 'size', 'aggregate', 'order', 'content', 'extra')) {
    $record = [Text.Encoding]::UTF8.GetString($original) | ConvertFrom-Json
    switch ($case) {
        'duplicate' { $record.files[1] = $record.files[0] }
        'missing' { $record.files = @($record.files | Select-Object -Skip 1); $record.file_count -= 1 }
        'case' { $record.files[0].path = $record.files[0].path.ToUpperInvariant() }
        'hash' { $record.files[0].sha256 = '0' * 64 }
        'size' { $record.files[0].size = [string]$record.files[0].size }
        'aggregate' { $record.aggregate_sha256 = '0' * 64 }
        'order' { [array]::Reverse($record.files) }
        'content' { $changed = $content.Clone(); $changed[0] = $changed[0] -bxor 1; [IO.File]::WriteAllBytes($contentPath, $changed) }
        'extra' { [IO.File]::WriteAllText((Join-Path $root 'extra.txt'), 'extra') }
    }
    # Recomputed hashes must not hide duplicate/missing/case/type violations.
    if ($case -in @('duplicate', 'missing', 'case', 'hash', 'size')) {
        $record.aggregate_sha256 = Get-InventoryAggregate $record.files
    }
    Write-Utf8Json $recordPath $record
    foreach ($reader in @('normal', 'relocated')) {
        $errorText = ''
        try {
            if ($reader -ceq 'normal') { [void](Assert-BootstrapIntegrityRecord $root) }
            else { [void](Assert-BootstrapRelocatedIntegrityRecord $root $root) }
        } catch { $errorText = $_.Exception.Message }
        $results += [ordered]@{ case = $case; reader = $reader; rejected = [bool]$errorText }
    }
    [IO.File]::WriteAllBytes($recordPath, $original)
    [IO.File]::WriteAllBytes($contentPath, $content)
    if ($case -ceq 'extra') { Remove-Item -LiteralPath (Join-Path $root 'extra.txt') }
}
$results | ConvertTo-Json -Compress
''', CA_TREE=tree)
    assert len(results) == 18
    assert not [row for row in results if not row["rejected"]]


@pytest.mark.parametrize("culture", CULTURES)
def test_acl_identity_matches_ps5_sections_for_file_and_directory(tmp_path, culture):
    tree = release_tree(tmp_path)
    oracle = invoke(tmp_path, "powershell.exe", culture, r'''
$sections = [Security.AccessControl.AccessControlSections]::Access -bor
    [Security.AccessControl.AccessControlSections]::Owner -bor
    [Security.AccessControl.AccessControlSections]::Group
@($env:CA_TREE, (Join-Path $env:CA_TREE 'A.txt')) | ForEach-Object {
    $item = Get-Item -LiteralPath $_
    $acl = if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($_, $sections) }
           else { [IO.File]::GetAccessControl($_, $sections) }
    [ordered]@{
        owner_sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        access_rules_protected = $acl.AreAccessRulesProtected
        sddl_sha256 = Get-BootstrapStringSha256 $acl.GetSecurityDescriptorSddlForm($sections)
    }
} | ConvertTo-Json -Compress
''', CA_TREE=tree)
    for engine in ENGINES:
        actual = invoke(tmp_path, engine, culture, r'''
@($env:CA_TREE, (Join-Path $env:CA_TREE 'A.txt')) | ForEach-Object {
    Get-BootstrapAclIdentity $_
} | ConvertTo-Json -Compress
''', CA_TREE=tree)
        assert actual == oracle
