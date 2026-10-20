param([string]$Root,[string]$Mode)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'PS51_REQUIRED' }
. (Join-Path $Root 'tools/bootstrap_integrity.ps1')
. (Join-Path $Root 'kmtech_shared/powershell/portable.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'CANONICAL_PARSE_FAILED'}
foreach($statement in $ast.EndBlock.Statements){
    if($statement -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($statement.Extent.Text))}
}
$testMode=$true
$caller=[pscustomobject]@{elevated=$true;session_id=1;sid='S-1-5-21-1-2-3-1001'}
if($Mode -eq 'DEFINED_NO_MARKER'){
    function Get-ContainerMachineInstallStateRoot { return (Join-Path ([IO.Path]::GetTempPath()) 'ca117-no-such-state') }
}
try { [void](Resolve-CanonicalMachineRemovalWorker '' $caller (Join-Path ([IO.Path]::GetTempPath()) 'ca117-root')); Write-Output 'RETURNED' }
catch { Write-Output ('CODE '+$_.Exception.Message) }
