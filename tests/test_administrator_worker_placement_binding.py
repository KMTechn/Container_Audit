"""Execute the CA helper's real placement binding without installing on the host."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


HELPER = Path(__file__).resolve().parents[1] / "INSTALL_THIS_PC.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_actual_placement_binding_accepts_same_and_different_caller_sid(tmp_path, engine):
    result = run_functions(tmp_path, HELPER, ["Enter-ContainerPlacementWriterFence"], r'''
$callerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$otherSid=$callerSid.Substring(0,$callerSid.LastIndexOf('-')+1)+([int]($callerSid.Split('-')[-1])+1)
$setupStart=@($ast.EndBlock.Statements|Where-Object {
 $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$testOverride'
})
$setupEnd=@($ast.EndBlock.Statements|Where-Object {
 $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$applyHardenedAcl'
})
if($setupStart.Count -ne 1 -or $setupEnd.Count -ne 1){throw 'Actual helper binding setup is missing'}
$helperText=$ast.Extent.Text
$setupText=$helperText.Substring($setupStart[0].Extent.StartOffset,$setupEnd[0].Extent.StartOffset-$setupStart[0].Extent.StartOffset)
$setup=[scriptblock]::Create($ast.ParamBlock.Extent.Text+"`n"+$setupText+"`n"+
 '[pscustomobject]@{sid=$OperatorSid;local=$OperatorLocalAppDataRoot;machine=$MachineControlRoot;override=$testOverride}')
$placement=@($definition_nodes|Where-Object {$_.Name -ceq 'Enter-ContainerPlacementWriterFence'})
if($placement.Count -ne 1){throw 'Actual placement fence is missing'}
$binding=@($placement[0].Body.EndBlock.Statements|Where-Object {
 $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
 $_.Left.Extent.Text -ceq '$operatorBinding'
})
if($binding.Count -ne 1){throw 'Actual placement operator binding is missing'}
$fencePath=Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\container_writer_fence.ps1'
$fenceAst=[Management.Automation.Language.Parser]::ParseFile($fencePath,[ref]$null,[ref]$null)
foreach($function in @($fenceAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){
 Invoke-Expression $function.Extent.Text
}
$testOverride=$false
$WriterFenceSessionId='1'*32;$WriterFenceAttemptId='2'*32;$WriterFenceReplacementTransactionId='3'*32
$MachineControlRoot=Join-Path (Get-ContainerMachineInstallStateRoot) 'control\writer-session'
$BootstrapBoundParameters=@{}
foreach($selected in @($callerSid,$otherSid)){
 $OperatorSid=$selected
 $profileRoot=Join-Path $env:CA_CONTRACT_ROOT 'worker'
 $OperatorLocalAppDataRoot=Join-Path $profileRoot 'AppData\Local'
 $admitted=& $setup -OperatorSid $selected -OperatorLocalAppDataRoot $OperatorLocalAppDataRoot `
  -OperatorDataRoot (Join-Path $OperatorLocalAppDataRoot 'KMTech\ContainerAudit') -MachineControlRoot $MachineControlRoot
 if($admitted.sid -cne $selected -or $admitted.local -cne $OperatorLocalAppDataRoot -or
  $admitted.machine -cne $MachineControlRoot -or $admitted.override){throw 'Explicit worker placement binding changed'}
 $expectedProfileKey='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$selected
 function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction)
  if($LiteralPath -cne $expectedProfileKey -or $Name -cne 'ProfileImagePath'){throw 'Unexpected registry access'}
  return [pscustomobject]@{ProfileImagePath=$profileRoot}
 }
 $receipt=[ordered]@{
  schema='container-audit-canonical-writer-prepared-v1';status='PREPARED';app_id='container_audit'
  session_id=$WriterFenceSessionId;attempt_id=$WriterFenceAttemptId;replacement_transaction_id=$WriterFenceReplacementTransactionId
  session_started_at_utc=[DateTime]::UtcNow.ToString('o');orchestrator_sha256=('4'*64);writer_contract_sha256=('5'*64)
  writer_inventory_sha256=('6'*64);source_manifest_sha256=('7'*64);operator_sid=$selected
  operator_local_appdata_root=$OperatorLocalAppDataRoot;created_at_utc=[DateTime]::UtcNow.ToString('o');secret_values_recorded=$false
 }
 $WriterFencePreparedReceiptPath=Join-Path $env:CA_CONTRACT_ROOT 'prepared.json'
 [IO.File]::WriteAllText($WriterFencePreparedReceiptPath,($receipt|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 $WriterFencePreparedReceiptSha256=Get-ContainerWriterFenceFileSha256 $WriterFencePreparedReceiptPath
 Invoke-Expression $binding[0].Extent.Text
 if($operatorBinding.control_root -cne $MachineControlRoot){throw 'Machine worker binding differs'}
 # The same real binding must still reject a worker/receipt mismatch.
 $OperatorSid=if($selected -ceq $callerSid){$otherSid}else{$callerSid}
 $rejected=$false
 try{Invoke-Expression $binding[0].Extent.Text}catch{
  if($_.Exception.Message -cne 'CONTAINER_OPERATOR_PREPARED_BINDING_MISMATCH'){throw}
  $rejected=$true
 }
 if(-not $rejected){throw 'Mismatched worker receipt was accepted'}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"
