"""Execute the three product manifest readers at their byte boundaries."""
import json
from pathlib import Path
import shutil
import subprocess
import os

import pytest


REPO = Path(__file__).resolve().parents[1]
PORTABLE_FILES = (
    'portable-manifest.json', 'runtime/python.exe', 'runtime/pythonw.exe',
    'app/main.py', 'launch-container-audit.cmd', 'INSTALL_CANONICAL_PORTABLE.ps1',
    'INSTALL_THIS_PC.ps1', 'tools/bootstrap_integrity.ps1',
    'tools/container_writer_fence.ps1', 'tools/container_writer_session.ps1',
    'tools/container_writer_session_contract.json',
    'tools/container_writer_sink_inventory.json',
)
READERS = {
    'InstalledManifest': (
        'INSTALL_CANONICAL_PORTABLE.ps1',
        'Installed portable manifest is oversized.',
        'Installed portable manifest readback failed.',
    ),
    'Assert-RequiredRelease': (
        'INSTALL_THIS_PC.ps1',
        'Portable release manifest is oversized.',
        'Portable release manifest contract is invalid.',
    ),
    'Remove-OwnedLegacyTask': (
        'INSTALL_THIS_PC.ps1',
        'Legacy task removal manifest is oversized.',
        'Legacy task removal writer-fence helper pin differs.',
    ),
}


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('reader', list(READERS))
@pytest.mark.parametrize('byte_count', [65535, 65536, 65537])
def test_actual_manifest_read_boundary(tmp_path, engine, reader, byte_count):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip('PowerShell engine unavailable')
    root = tmp_path / 'portable'
    for relative in PORTABLE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'')
    (root / 'portable-manifest.json').write_bytes(b'{}' + b' ' * (byte_count - 2))
    source, oversized_message, contract_message = READERS[reader]
    environment = dict(os.environ)
    environment.update(
        CA_MANIFEST_PROBE_ROOT=str(root),
        CA_MANIFEST_PRODUCT_SOURCE=str(REPO / source),
        CA_MANIFEST_READER=reader,
        CA_MANIFEST_OVERSIZED_MESSAGE=oversized_message,
        CA_MANIFEST_CONTRACT_MESSAGE=contract_message,
    )
    script = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_MANIFEST_PRODUCT_SOURCE,[ref]$tokens,[ref]$errors)
if($errors.Count){[Console]::Error.WriteLine('Product parse failed.');exit 2}
$definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $env:CA_MANIFEST_READER},$true))
if($definitions.Count -ne 1){[Console]::Error.WriteLine('Product function selection differs.');exit 2}
. ([scriptblock]::Create($definitions[0].Extent.Text))
# Task observation is a seam; no native scheduler or removal command executes.
function Get-LegacyTaskByNameFailClosed([string]$Name){
    [pscustomobject]@{TaskName=$Name;TaskPath='\';Actions=@([pscustomobject]@{Execute=(Join-Path $env:CA_MANIFEST_PROBE_ROOT 'launch-container-audit.cmd');Arguments=''})}
}
try{
    if($env:CA_MANIFEST_READER -ceq 'Remove-OwnedLegacyTask'){
        Remove-OwnedLegacyTask 'manifest-probe' $env:CA_MANIFEST_PROBE_ROOT
    }else{& $env:CA_MANIFEST_READER $env:CA_MANIFEST_PROBE_ROOT $true}
    [Console]::Error.WriteLine('Incomplete contract unexpectedly accepted.');exit 2
}catch{
    $oversized=$_.Exception.Message -ceq $env:CA_MANIFEST_OVERSIZED_MESSAGE
    $contract=$_.Exception.Message -ceq $env:CA_MANIFEST_CONTRACT_MESSAGE
    if(-not($oversized -or $contract)){[Console]::Error.WriteLine('Unexpected product rejection.');exit 2}
    [Console]::WriteLine((@{oversized=$oversized;contract_reached=$contract}|ConvertTo-Json -Compress))
}
"""
    script_path = tmp_path / 'manifest-probe.ps1'
    script_path.write_text(script, encoding='utf-8-sig')
    completed = subprocess.run(
        [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script_path)],
        text=True, encoding='utf-8', stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    code = completed.returncode
    output = completed.stdout
    del completed
    assert code == 0, 'Actual product manifest boundary probe failed.'
    observed = json.loads(output)
    assert observed['oversized'] is (byte_count > 65536)
    assert observed['contract_reached'] is (byte_count <= 65536)
