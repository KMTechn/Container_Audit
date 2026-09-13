"""Keep a real pre-X13-B installed contract eligible for the new installer."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.powershell_contracts import run_functions
from tests import test_zero_touch_installer as fixtures


BASELINE = "adcaf86340c90e92ce1e7b3da8f598c0e133394f"


@pytest.mark.parametrize("culture", ("ko-KR", "en-US"))
@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_pre_shared_installed_tree_passes_current_preflight_and_verified_replacement(
    tmp_path, monkeypatch, engine, culture,
):
    assert shutil.which(engine), f"Required upgrade engine is unavailable: {engine}"
    # Read the fixed local Git objects, not the moving sibling repository. These
    # are the real old installer, writer contract/inventory and 0.2.0 package.
    old_repo = tmp_path / "before"
    bindings = (
        "PORTABLE_INSTALLER", "INSTALLER", "INTEGRITY_HELPER", "WRITER_SESSION_ADAPTER",
        "WRITER_SESSION_CONTRACT", "WRITER_FENCE_HELPER", "WRITER_SINK_INVENTORY",
    )
    paths = [getattr(fixtures, name).relative_to(fixtures.ROOT) for name in bindings]
    paths += [Path("kmtech_shared") / name for name in (
        "__init__.py", "catalog.py", "raster.py", "runtime.py",
    )]
    paths += [Path("kmtech_shared.manifest.json"), Path("kmtech_shared.lock.json")]
    for relative in paths:
        contents = subprocess.check_output(
            ["git", "show", f"{BASELINE}:{relative.as_posix()}"], cwd=fixtures.ROOT,
        )
        target = old_repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
    with monkeypatch.context() as old:
        for name in bindings:
            old.setattr(fixtures, name, old_repo / getattr(fixtures, name).relative_to(fixtures.ROOT))
        old.setattr(fixtures, "ROOT", old_repo)
        installed = fixtures._portable_release_fixture(
            tmp_path, directory="owned/current", source_commit=BASELINE,
        )
    source = fixtures._portable_release_fixture(tmp_path, directory="packet")
    leaf = "app/kmtech_shared/powershell/portable.ps1"
    assert not (installed / leaf).exists()
    assert json.loads((installed / "app/kmtech_shared.lock.json").read_bytes())["version"] == "0.2.0"
    assert (source / leaf).is_file()

    result = run_functions(tmp_path, fixtures.PORTABLE_INSTALLER, [
        "Full", "Same", "Sha", "Test-JsonTrue", "Test-JsonInteger",
        "Get-WriterContractSessionMutexName", "Assert-WriterSessionPublicContract",
        "Assert-WriterSinkInventory", "Manifest", "InstalledManifest", "Get-WriterInventorySemantics",
    ], r'''
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($env:CA_UPGRADE_CULTURE)
[Threading.Thread]::CurrentThread.CurrentUICulture = [Threading.Thread]::CurrentThread.CurrentCulture
$source=$env:CA_UPGRADE_SOURCE
$install=$env:CA_UPGRADE_INSTALLED
$SkipSignatureValidationForTest=$true
$sourceManifest=Manifest $source $true
$sourceWriterInventory=Assert-WriterSinkInventory `
    (Join-Path $source 'tools/container_writer_sink_inventory.json') `
    $sourceManifest.writer_sink_inventory_sha256 $sourceManifest.writer_sink_inventory_contract_sha256
. (Join-Path $source 'tools/container_writer_fence.ps1')
# Match the real canonical entrypoint's late bootstrap validator binding.
. (Join-Path $source 'tools/bootstrap_integrity.ps1')
[void](Write-BootstrapIntegrityRecord $install $install)
$originalAggregate=(Assert-BootstrapIntegrityRecord $install).aggregate_sha256

# Execute the actual preflight statement, including its integrity and writer
# semantics checks, before any fence or lifecycle mutation can be reached.
$preflight=@($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
    $_.Extent.Text.Contains('$preflightCandidate = InstalledManifest')
})
if ($preflight.Count -ne 1) { throw 'expected the actual installed-tree preflight' }
Invoke-Expression $preflight[0].Extent.Text
if ([string]$preflightCandidate.source_commit -cne $env:CA_UPGRADE_BASELINE) { throw 'old manifest identity changed' }
if ((Assert-BootstrapIntegrityRecord $install).aggregate_sha256 -cne $originalAggregate) { throw 'preflight mutated old tree' }

# Missing core files and an equal-length content change remain rejected even
# though an old tree legitimately lacks the newly introduced shared leaf.
foreach ($relative in @('runtime/python.exe','app/main.py')) {
    $path=Join-Path $install $relative
    $original=[IO.File]::ReadAllBytes($path)
    try {
        if ($relative -ceq 'runtime/python.exe') { Remove-Item -LiteralPath $path }
        else { $changed=$original.Clone(); $changed[0]=$changed[0] -bxor 1; [IO.File]::WriteAllBytes($path,$changed) }
        $rejection=''
        try { Invoke-Expression $preflight[0].Extent.Text } catch { $rejection=$_.Exception.Message }
        $expected=if ($relative -ceq 'runtime/python.exe') { 'Installed portable tree is missing' } else { 'Bootstrap integrity inventory differs' }
        if (-not $rejection.StartsWith($expected)) { throw ('old damage rejection differs: '+$rejection) }
    } finally { [IO.File]::WriteAllBytes($path,$original) }
}
Invoke-Expression $preflight[0].Extent.Text
$receipt=Join-Path $env:CA_CONTRACT_ROOT 'replacement.json'
# Use the existing noncanonical test switch for a real, isolated code-tree
# replacement. It bypasses elevation/ACL/fence ownership, not code integrity.
# The canonical entrypoint always runs this child in stock Windows PowerShell,
# including when preflight and final readback run in PowerShell 7.
$winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
& $winps -NoProfile -NonInteractive -File (Join-Path $source 'INSTALL_THIS_PC.ps1') `
    -SourceRoot $source -InstallRoot $install -AllowNoncanonicalLayoutForTest `
    -ReplaceExistingVerifiedPortable -ReplacementTransactionId ('1'*32) -ReplacementReceiptPath $receipt
if ($LASTEXITCODE -ne 0) { throw ('synthetic replacement failed: '+$LASTEXITCODE) }
$replacement=Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json
if ($replacement.status -cne 'OLD_PRESERVED_NEW_VERIFIED') { throw 'replacement was not verified' }
$rollback=[string]$replacement.rollback_root
if (Test-Path -LiteralPath (Join-Path $rollback 'app/kmtech_shared/powershell/portable.ps1')) { throw 'old rollback gained new leaf' }
if ((Get-InventoryAggregate @(Get-CodeInventory $rollback)) -cne $originalAggregate) { throw 'rollback bytes differ' }
[void](Manifest $install $true)
[void](InstalledManifest $install $true)
[void](Assert-BootstrapIntegrityRecord $install)
$leaf=Get-BootstrapSharedPortableLeaf $install
if ((Sha $leaf) -cne (Sha (Join-Path $source 'app/kmtech_shared/powershell/portable.ps1'))) { throw 'replacement leaf differs' }
Remove-Item -LiteralPath $leaf
$missing=''
try { [void](Get-BootstrapSharedPortableLeaf $install) } catch { $missing=$_.Exception.Message }
if (-not $missing) { throw 'new installed tree accepted absent shared leaf' }
Copy-Item -LiteralPath (Join-Path $source 'app/kmtech_shared/powershell/portable.ps1') -Destination $leaf
[void](Assert-BootstrapIntegrityRecord $install)
'PRE_SHARED_UPGRADE_PASS'
''', values={
        "CA_UPGRADE_SOURCE": str(source), "CA_UPGRADE_INSTALLED": str(installed),
        "CA_UPGRADE_BASELINE": BASELINE,
        "CA_UPGRADE_CULTURE": culture,
        "KMTECH_FACTORY_INSTALL_TEST_MODE": "1",
    }, engine=engine)
    (tmp_path / "upgrade-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (tmp_path / "upgrade-stderr.txt").write_text(result.stderr, encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PRE_SHARED_UPGRADE_PASS" in result.stdout
