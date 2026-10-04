"""The existing rollback dispatch handles A != B without moving either original.

File moves, raw bytes, hashes and replay are real NTFS; stock signature/ACL
observations are injected at the same OS seams as canonical continuation tests.
"""
import os
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]
NAMES=['Get-BootstrapSupportedVersionRestoreState','Get-BootstrapVerifiedReplacementRestoreState','Invoke-BootstrapVerifiedReplacementRestore']
DRIVER=r'''
. $env:CA_SUPPORT_LIBRARY
$base=$env:CA_SUPPORT_ROOT;$fixed=Join-Path $base 'current';$from=Join-Path $base ('versions\'+('b'*40));$to=Join-Path $base ('versions\'+('c'*40))
$tx='1'*32;$saved=Join-Path $base ('.startup-update-install.'+$tx)
$control=Join-Path $base 'update-control'
foreach($p in @($fixed,$from,$to,$saved,$control)){[void][IO.Directory]::CreateDirectory($p)}
foreach($p in @($fixed,$from,$to)){[IO.File]::WriteAllText((Join-Path $p 'code.bin'),(Split-Path -Leaf $p))}
function Assert-InstallationEvidenceProtectedPath([string]$Path){if(-not $Path.StartsWith($base) -or -not(Test-Path -LiteralPath $Path)){throw 'protection seam rejected'}}
function Get-BootstrapAclIdentity([string]$Path){return [pscustomobject]@{sddl_sha256='f'*64;owner_sid='fixture';access_rules_protected=$true}}
function Test-BootstrapAclIdentity($Expected,$Actual){return $Expected.sddl_sha256 -ceq $Actual.sddl_sha256}
function Get-BootstrapReplacementTreeIdentity([string]$Root,[string]$CodeRoot){return [pscustomobject]@{aggregate_sha256=Get-FileSha256 (Join-Path $Root 'code.bin');source_commit=$(if((Split-Path -Leaf $Root) -ceq 'current'){'a'*40}else{Split-Path -Leaf $CodeRoot});manifest_sha256='a'*64}}
function Test-BootstrapReplacementTreeIdentity($Expected,$Actual){return $Expected.aggregate_sha256 -ceq $Actual.aggregate_sha256 -and $Expected.source_commit -ceq $Actual.source_commit}
$before=@();$after=@()
foreach($name in @('policy.json','active.json','transition.json')){
 [IO.File]::WriteAllText((Join-Path $saved $name),'original '+$name)
 [IO.File]::WriteAllText((Join-Path $control $name),'new '+$name)
 $before+=[pscustomobject]@{name=$name;exists=$true;sha256=Get-FileSha256 (Join-Path $saved $name)}
 $after+=[pscustomobject]@{name=$name;sha256=Get-FileSha256 (Join-Path $control $name)}
}
$preimage=[ordered]@{schema='container-audit-startup-update-install-preimage-v1';root=$fixed;operator_sid='fixture';files=$before}
[IO.File]::WriteAllText((Join-Path $saved 'preimage.json'),($preimage|ConvertTo-Json -Depth 12))
$receiptPath=Join-Path $base 'receipt.json'
$r=[pscustomobject]@{schema_version='container-audit-verified-replacement-v1';status='OLD_PRESERVED_NEW_VERIFIED';app_id='container_audit';transaction_id=$tx;helper_sha256='f'*64;
 receipt_path=$receiptPath;install_root=$fixed;install_parent=$base;rollback_root=$from;failed_root=Join-Path $base ('.version.failed.'+$tx);
 parent_acl=Get-BootstrapAclIdentity $base;old=Get-BootstrapReplacementTreeIdentity $fixed $fixed;new=Get-BootstrapReplacementTreeIdentity $to $to;
 startup_update_preimage=$saved;startup_update_preimage_sha256=Get-FileSha256 (Join-Path $saved 'preimage.json');
 active_version=[pscustomobject]@{kind='SUPPORTED_ACTIVE_VERSION';from_sha='b'*40;to_sha='c'*40;from_root=$from;to_root=$to;from=Get-BootstrapReplacementTreeIdentity $from $from;control_after=$after}}
$aBytes=[IO.File]::ReadAllBytes((Join-Path $fixed 'code.bin'));$bBytes=[IO.File]::ReadAllBytes((Join-Path $from 'code.bin'))
$cut=$env:CA_SUPPORT_CUT
if($cut -ceq 'owner'){[IO.File]::WriteAllText((Join-Path $fixed 'code.bin'),'changed')}
if($cut -ceq 'active'){[IO.File]::WriteAllText((Join-Path $from 'code.bin'),'changed')}
if($cut -ceq 'candidate'){[IO.File]::WriteAllText((Join-Path $to 'code.bin'),'changed')}
if($cut -ceq 'control'){[IO.File]::WriteAllText((Join-Path $control 'active.json'),'foreign')}
if($cut -ceq 'preimage'){[IO.File]::WriteAllText((Join-Path $saved 'active.json'),'foreign')}
if($cut -ceq 'from-binding'){$r.active_version.from_sha='a'*40}
$bad=$cut -cin @('owner','active','candidate','control','preimage','from-binding')
if($bad){
 try{[void](Invoke-BootstrapVerifiedReplacementRestore $r $receiptPath $fixed 'container_audit' $tx ('f'*64));throw 'unexpected acceptance'}catch{if($_.Exception.Message -ceq 'unexpected acceptance'){throw}}
 if(-not(Test-Path -LiteralPath $to) -or (Test-Path -LiteralPath $r.failed_root)){throw 'rejected proof mutated a tree'}
}else{
 $state=Get-BootstrapVerifiedReplacementRestoreState $r $receiptPath $fixed 'container_audit' $tx ('f'*64)
 if($state.status -cne 'PENDING'){throw 'wrong pending state'}
 if($cut -ceq 'interrupt'){
  try{[void](Invoke-BootstrapVerifiedReplacementRestore $r $receiptPath $fixed 'container_audit' $tx ('f'*64) -InjectFailureAfterDisplace);throw 'missing injection'}catch{if($_.Exception.Message -ceq 'missing injection'){throw}}
 }
 foreach($again in @(1,2,3)){ $result=Invoke-BootstrapVerifiedReplacementRestore $r $receiptPath $fixed 'container_audit' $tx ('f'*64);if(-not $result.prior_code_exact -or -not $result.failed_new_preserved){throw 'weak restore proof'} }
 if((Test-Path -LiteralPath $to) -or -not(Test-Path -LiteralPath $r.failed_root)){throw 'candidate not preserved'}
 if((Get-FileSha256 (Join-Path $fixed 'code.bin')) -cne $r.old.aggregate_sha256 -or (Get-FileSha256 (Join-Path $from 'code.bin')) -cne $r.active_version.from.aggregate_sha256){throw 'A or B changed'}
}
'PASS'
'''

@pytest.mark.parametrize('engine',['powershell.exe','pwsh.exe'])
@pytest.mark.parametrize('cut',['','interrupt','owner','active','candidate','control','preimage','from-binding'])
def test_receipt_dispatch_preserves_a_b_and_c_and_refuses_foreign_cuts(tmp_path,engine,cut):
    source=Path(os.environ.get('CA_SUPPORT_SOURCE',str(ROOT/'tools/bootstrap_integrity.ps1')))
    result=run_functions(tmp_path, source, NAMES, DRIVER, engine=engine,
                         values=dict(CA_SUPPORT_LIBRARY=str(ROOT/'tools/bootstrap_integrity.ps1'),CA_SUPPORT_ROOT=str(tmp_path/'scope'),CA_SUPPORT_CUT=cut))
    assert result.returncode==0,result.stdout+result.stderr
    assert 'PASS' in result.stdout


FORWARD=DRIVER[:DRIVER.index('$receiptPath=')] + r'''
$sourceRootFull=Join-Path $base 'source'
Copy-Item -LiteralPath $to -Destination $sourceRootFull -Recurse
Remove-Item -LiteralPath (Join-Path $to 'code.bin');Remove-Item -LiteralPath $to
$installRootFull=$fixed;$SupportedFromCommit='b'*40;$ReplacementTransactionId=$tx;$WriterFenceAttemptId=$tx
$ReplaceExistingVerifiedPortable=$true;$testOverride=$false;$WriterFencePreparedReceiptPath='fixture-authority'
$BootstrapScriptPath=Join-Path $sourceRootFull 'INSTALL_THIS_PC.ps1';$BootstrapIntegrityFunctions=Join-Path $sourceRootFull 'tools\bootstrap_integrity.ps1'
foreach($directory in @((Join-Path $sourceRootFull 'app'),(Join-Path $sourceRootFull 'tools'),(Join-Path $fixed 'app'),(Join-Path $base 'evidence'))){[void][IO.Directory]::CreateDirectory($directory)}
[IO.File]::WriteAllText($BootstrapScriptPath,'verified-source-helper');[IO.File]::WriteAllText($BootstrapIntegrityFunctions,'verified-source-library')
foreach($directory in @($sourceRootFull,$fixed)){[IO.File]::WriteAllText((Join-Path $directory 'app\update-manifest-key-config.json'),'unchanged trust key')}
[IO.File]::WriteAllText((Join-Path $sourceRootFull 'portable-manifest.json'),(@{source_commit='c'*40}|ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path $sourceRootFull 'app\auto-update-settings.json'),(@{feed_url='';channel='stable';profile_auth=$false;approved_transitions=@();apply_during_work=$false}|ConvertTo-Json))
$policy=@{schema='container-audit-startup-update-policy-v1';feed_url='';channel='stable';profile_auth=$false;approved_transitions=@()}
foreach($name in @('policy.json','active.json','transition.json')){
 $value=switch($name){'policy.json'{$policy};'active.json'{@{schema='container-audit-startup-update-v1';sha='b'*40}};'transition.json'{@{schema='container-audit-startup-update-v1';phase='CONFIRMED';candidate_sha='b'*40;failed_shas=@()}}}
 [IO.File]::WriteAllText((Join-Path $control $name),($value|ConvertTo-Json -Depth 12))
}
Remove-Item -LiteralPath (Join-Path $saved 'preimage.json')
foreach($name in @('policy.json','active.json','transition.json')){Remove-Item -LiteralPath (Join-Path $saved $name)}
Remove-Item -LiteralPath $saved
$script:InstallationEvidenceRoot=Join-Path $base 'evidence';$OperatorSid='fixture';$script:InstallationEvidenceFailed=$false
$sourceAggregate=Get-InventoryAggregate @(Get-CodeInventory $sourceRootFull)
function Assert-ContainerStartupUpdateTrust {}
function Set-HardenedCodeAcl {}
function New-InstallationProtectedDirectory([string]$Path,[string]$Sid){[void][IO.Directory]::CreateDirectory($Path)}
function Get-ContainerStartupUpdateTaskPreimage {return [ordered]@{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));exists=$false;xml='';sddl=''}}
function Get-ContainerSupportedInstallContext {return [pscustomobject]@{lifecycle_state='HEALTHY';from_commit='b'*40;bootstrap_commit='a'*40}}
function Assert-ContainerReplacementRestoreQuiescent {}
function Get-ContainerWriterFenceStringSha256([string]$Value){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Write-InstallationEvidenceEvent {}
function Write-BootstrapReplacementReceipt([string]$Path,$Payload){if(Test-Path -LiteralPath $Path){throw 'immutable receipt exists'};[IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 16));return [pscustomobject]@{path=$Path;sha256=Get-FileSha256 $Path}}
function Invoke-ContainerStartupUpdateTaskMutation([scriptblock]$Action){& $Action}
function Get-ScheduledTask {return $null}
$cut=$env:CA_SUPPORT_CUT
function Write-ContainerStartupUpdateRecord([string]$Path,$Payload){
 [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 16))
 if($cut -ceq 'publication' -and $Path -ceq (Join-Path $control 'policy.json')){throw 'injected publication failure'}
}
$original=@{};foreach($name in @('policy.json','active.json','transition.json')){$original[$name]=[IO.File]::ReadAllText((Join-Path $control $name))}
$a=Get-FileSha256 (Join-Path $fixed 'code.bin');$b=Get-FileSha256 (Join-Path $from 'code.bin')
$failed=$false;try{Invoke-ContainerSupportedActiveVersionPlacement}catch{$failed=$true;if($cut -cne 'publication'){throw}}
if($cut -ceq 'publication' -and -not $failed){throw 'publication interruption not reached'}
$path=Join-Path $script:InstallationEvidenceRoot 'replacement-receipt.json';$r=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
if($r.active_version.from_sha -cne ('b'*40) -or $r.old.source_commit -cne ('a'*40) -or $r.new.source_commit -cne ('c'*40)){throw 'from was not actual B'}
if($cut -ceq ''){
 $pointer=Get-Content -LiteralPath (Join-Path $control 'active.json') -Raw|ConvertFrom-Json
 if($pointer.sha -cne ('c'*40) -or -not(Test-Path -LiteralPath $to)){throw 'C installation not published'}
}else{
 foreach($again in @(1,2,3)){[void](Invoke-BootstrapVerifiedReplacementRestore $r $path $fixed 'container_audit' $tx (Get-FileSha256 $BootstrapScriptPath))}
 $cut=''
 Restore-ContainerStartupUpdatePreimage $fixed ([string]$r.startup_update_preimage) ([string]$r.startup_update_preimage_sha256)
 foreach($name in @('policy.json','active.json','transition.json')){if([IO.File]::ReadAllText((Join-Path $control $name)) -cne $original[$name]){throw 'control preimage not restored'}}
 if((Test-Path -LiteralPath $to) -or -not(Test-Path -LiteralPath $r.failed_root)){throw 'failed C not preserved'}
}
if((Get-FileSha256 (Join-Path $fixed 'code.bin')) -cne $a -or (Get-FileSha256 (Join-Path $from 'code.bin')) -cne $b){throw 'A or B changed'}
'PASS'
'''

@pytest.mark.parametrize('engine',['powershell.exe','pwsh.exe'])
@pytest.mark.parametrize('cut',['','publication','late-failure'])
def test_actual_supported_placement_uses_b_and_c_success_or_same_receipt_rollback(tmp_path,engine,cut):
    names=['Test-SamePath','Test-PathWithin','Assert-NoReparsePoint','Save-ContainerStartupUpdatePreimage','Restore-ContainerStartupUpdatePreimage','Invoke-ContainerSupportedActiveVersionPlacement']
    source=Path(os.environ.get('CA_SUPPORT_PLACEMENT_SOURCE',str(ROOT/'INSTALL_THIS_PC.ps1')))
    result=run_functions(tmp_path,source,names,FORWARD,engine=engine,
                         values=dict(CA_SUPPORT_LIBRARY=str(ROOT/'tools/bootstrap_integrity.ps1'),CA_SUPPORT_ROOT=str(tmp_path/'scope'),CA_SUPPORT_CUT=cut))
    assert result.returncode==0,result.stdout+result.stderr
    assert 'PASS' in result.stdout
