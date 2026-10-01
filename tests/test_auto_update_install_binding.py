"""Installer command admission without registry, relay or task execution."""
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("installed_update", [False, True])
@pytest.mark.parametrize("custom_data", [False, True])
@pytest.mark.parametrize("retired", [False, True])
@pytest.mark.parametrize("drift", ["none", "argument", "new-for-old", "kind"])
def test_installed_run_binding_is_independent_of_candidate_settings(
    tmp_path, installed_update, custom_data, retired, drift
):
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell required")
    repository = Path(__file__).resolve().parents[1]
    script = tmp_path / "run-binding.ps1"
    script.write_text(r'''param([string]$Source,[string]$Work,[bool]$InstalledUpdate,[bool]$CustomData,[bool]$Retired,[string]$Drift)
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $Source) 'kmtech_shared\powershell\portable.ps1')
$tokens=$null; $errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'Installer parse error' }
foreach($name in @('Full','Arg','Same','Command','Get-CanonicalRelayCommandIdentity','Assert-CanonicalRuntimePreimage')) {
    $definition=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
    if($null -eq $definition) { throw ('Required function absent: '+$name) }
    Invoke-Expression $definition.Extent.Text
}
$SourceRoot=Join-Path $Work 'candidate'
$root=Join-Path $Work 'installed with spaces'
New-Item -ItemType Directory -Path (Join-Path $SourceRoot 'app'),(Join-Path $root 'app') | Out-Null
[IO.File]::WriteAllText((Join-Path $SourceRoot 'app\auto-update-settings.json'),'{}')
$oldPacket=''
if($Retired) {
    $oldPacket=Join-Path $Work 'admitted-old-packet'
    New-Item -ItemType Directory -Path (Join-Path $oldPacket 'app') | Out-Null
    if($InstalledUpdate) { [IO.File]::WriteAllText((Join-Path $oldPacket 'app\auto-update-settings.json'),'{}') }
} elseif($InstalledUpdate) { [IO.File]::WriteAllText((Join-Path $root 'app\auto-update-settings.json'),'{}') }
$env:CONTAINER_AUDIT_DATA_ROOT=''
$suffix=''
if($CustomData) {
    $data=Join-Path $Work 'existing data'
    New-Item -ItemType Directory -Path $data | Out-Null
    $env:CONTAINER_AUDIT_DATA_ROOT=$data
    $suffix=' --data-root '+(Arg $data)
}
$old=(Arg (Join-Path $root 'runtime\pythonw.exe'))+' -I -B '+(Arg (Join-Path $root 'app\main.py'))+' --container-audit-user-relay'+$suffix
$new=(Arg (Join-Path $root 'runtime\pythonw.exe'))+' -I -B '+(Arg (Join-Path $root 'app\auto_update.py'))+' --bootstrap --role relay -- --container-audit-user-relay'+$suffix
$expected=if($InstalledUpdate){$new}else{$old}
if((Command $root -Installed -InstalledPacket $oldPacket) -cne $expected) { throw 'Candidate settings changed installed command' }
if((Command $root) -cne $new) { throw 'Candidate command was not retained' }
$before=@{exists=$true;kind='String';data=$expected}
if($Drift -eq 'argument') { $before.data+=' --arbitrary' }
if($Drift -eq 'new-for-old') { $before.data=if($InstalledUpdate){$old}else{$new} }
if($Drift -eq 'kind') { $before.kind='ExpandString' }
$original=$before | ConvertTo-Json -Compress
$process=@{ExecutablePath=(Join-Path $root 'runtime\pythonw.exe');CommandLine=$expected}
try {
    $binding=Assert-CanonicalRuntimePreimage -Before $before -Processes @($process) -ExpectedCommand (Command $root -Installed -InstalledPacket $oldPacket) -ExpectedRoot $root -StopMarkerExists $false
    if($Drift -ne 'none' -or $binding.status -cne 'PASS') { throw 'Drift was accepted' }
} catch {
    if($Drift -eq 'none' -or $_.Exception.Message -cne 'CANONICAL_HKCU_RUN_BINDING_MISMATCH') { throw }
}
if(($before | ConvertTo-Json -Compress) -cne $original) { throw 'Preimage was modified' }
'PASS'
''', encoding="utf-8")
    # PowerShell -File bool binding accepts a string only as $true; use a small
    # wrapper with literal booleans and named, safely quoted paths instead.
    wrapper = tmp_path / "invoke.ps1"
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    wrapper.write_text(
        f"& {quote(script)} -Source {quote(repository / 'INSTALL_CANONICAL_PORTABLE.ps1')} "
        f"-Work {quote(tmp_path)} -InstalledUpdate ${str(installed_update).lower()} "
        f"-CustomData ${str(custom_data).lower()} -Retired ${str(retired).lower()} -Drift {quote(drift)}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
        capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"
