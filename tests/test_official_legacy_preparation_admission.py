from pathlib import Path
import re
import pytest
from tests.powershell_contracts import run_functions
from tests.test_official_legacy_relay_identity import XML_SETUP

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'INSTALL_CANONICAL_PORTABLE.ps1'

@pytest.mark.parametrize('engine',('powershell.exe','pwsh.exe'))
@pytest.mark.parametrize('case',('no_task','matching','missing_launcher','different_launcher','reparse_launcher','invalid_action'))
def test_first_install_legacy_admission_precedes_preparation(tmp_path,engine,case):
    names=re.findall(r'^function\s+([^\s(]+)',SOURCE.read_text(encoding='utf-8'),re.M)
    result=run_functions(tmp_path,SOURCE,names,XML_SETUP+r'''
$source=$env:CA_FIXTURE_SOURCE;$root=$env:CA_CONTRACT_ROOT
$inventoryPath=Join-Path $source 'tools/container_writer_sink_inventory.json'
$inventory=Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8|ConvertFrom-Json
[void](Assert-WriterSinkInventory $inventoryPath (Sha $inventoryPath) ([string]$inventory.inventory_sha256))
$operatorSid='S-1-5-21-350';$lad=Join-Path $root 'local';$activeDataRoot=Join-Path $root 'data'
$canonical=Join-Path $root 'canonical-absent';$install=Join-Path $canonical 'current'
$physical=Join-Path $root 'public-launchers';$old=Join-Path $root 'old-public-v2.0.33'
foreach($p in @($lad,$activeDataRoot,$physical,$old)){[void][IO.Directory]::CreateDirectory($p)}
$expectedLauncher=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'KMTech\DirectSync\container_audit\bin\direct-sync-relay-container-audit.vbs'
$expectedCmd=[IO.Path]::ChangeExtension($expectedLauncher,'cmd')
if($env:CA_PRE_RUN_CASE -cne 'no_task'){[IO.File]::WriteAllText((Join-Path $physical 'direct-sync-relay-container-audit.cmd'),('"'+(Join-Path $old 'Container_Audit_DirectSync_Relay.exe')+'" --worker-id direct-sync-relay-container-audit'))}
[IO.File]::WriteAllText((Join-Path $old 'Container_Audit_DirectSync_Relay.exe'),'synthetic-public-relay')
if($env:CA_PRE_RUN_CASE -cnotin @('missing_launcher','no_task')){[IO.File]::WriteAllText((Join-Path $physical 'direct-sync-relay-container-audit.vbs'),'synthetic launcher linked by exact official task path')}
$script:events=[Collections.Generic.List[string]]::new();$script:enabled=$true;$script:mutations=0;$script:registryMutations=0
$script:ancestorState=[ordered]@{protected=$false;owner='S-1-5-32-544';effective_acl='synthetic-existing-default-ACL'}
$ancestorBefore=$script:ancestorState|ConvertTo-Json -Compress
$nativeAclBefore=(Get-Acl -LiteralPath $root).Sddl
$EvidencePath=Join-Path $root 'caller-admission-report.json'
function Set-ItemProperty {$script:registryMutations++;throw 'UNEXPECTED_REGISTRY_MUTATION'}
function Remove-ItemProperty {$script:registryMutations++;throw 'UNEXPECTED_REGISTRY_MUTATION'}
function FixturePath([string]$Path){
 if($Path -ieq $expectedLauncher -or $Path -ieq $expectedCmd){return Join-Path $physical ([IO.Path]::GetFileName($Path))}
 if($Path.StartsWith(([Environment]::GetFolderPath('CommonApplicationData')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'NATIVE_PROGRAMDATA_READ_FORBIDDEN'}
 return $Path
}
$realTestPath=Get-Command Test-Path -CommandType Cmdlet;$realGetItem=Get-Command Get-Item -CommandType Cmdlet;$realGetContent=Get-Command Get-Content -CommandType Cmdlet
$realNoReparse=${function:Assert-BootstrapNoReparsePoint}
function Test-Path {param($LiteralPath,$Path,$PathType);$chosen=if($LiteralPath){$LiteralPath}else{$Path};$bound=@{LiteralPath=(FixturePath $chosen)};if($PathType){$bound.PathType=$PathType};& $realTestPath @bound}
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction);$chosen=FixturePath $LiteralPath;if($chosen -ceq $canonical -and -not([IO.Directory]::Exists($canonical))){throw 'CANONICAL_ROOT_REQUIRED_BEFORE_CREATION'};if($env:CA_PRE_RUN_CASE -ceq 'reparse_launcher' -and $chosen -ceq (Join-Path $physical 'direct-sync-relay-container-audit.vbs')){return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;FullName=$chosen;PSIsContainer=$false}};& $realGetItem -LiteralPath $chosen -Force:$Force -ErrorAction Stop}
function Get-Content {param($LiteralPath,[switch]$Raw,$Encoding);& $realGetContent -LiteralPath (FixturePath $LiteralPath) -Raw:$Raw -Encoding UTF8}
function Assert-BootstrapNoReparsePoint {param($Path,$Purpose,[switch]$PathOnly);& $realNoReparse (FixturePath $Path) $Purpose -PathOnly:$PathOnly}
function Sha {param($Path);return (Get-FileHash -LiteralPath (FixturePath $Path) -Algorithm SHA256).Hash.ToLowerInvariant()}
function Get-ScheduledTask {
 if($env:CA_PRE_RUN_CASE -ceq 'no_task'){return @()}
 $arguments='//B //NoLogo '+$expectedLauncher
 if($env:CA_PRE_RUN_CASE -ceq 'different_launcher'){$arguments=$arguments.Replace('.vbs','-different.vbs')}
 $execute=if($env:CA_PRE_RUN_CASE -ceq 'invalid_action'){'unrecognized-action.exe'}else{Join-Path ([Environment]::SystemDirectory) 'wscript.exe'}
 return [pscustomobject]@{TaskName=$name;TaskPath='\';Settings=[pscustomobject]@{Enabled=$script:enabled};Actions=@([pscustomobject]@{Execute=$execute;Arguments=$arguments})}
}
function Export-ScheduledTask {
 $value=$xml.Replace('<Enabled>true</Enabled>',('<Enabled>'+([string]$script:enabled).ToLowerInvariant()+'</Enabled>'))
 if($env:CA_PRE_RUN_CASE -ceq 'different_launcher'){$value=$value.Replace('.vbs','-different.vbs')}
 return $value
}
$actualInitializeBase=${function:Initialize-InstallationProtectedBase}
function Get-InstallationEvidenceControlRoot {return (Join-Path $canonical 'control')}
function Assert-InstallationEvidenceProtectedPath {param($Path,[switch]$AllowSupportedPreparation)}
function Protect-KmtechCodeAncestors {param($Path,[switch]$BeforeAppCreation);$script:events.Add('protect');$script:mutations++;$script:ancestorState.protected=$true;$script:ancestorState.effective_acl='synthetic-reviewed-protected-ACL'}
function New-InstallationProtectedDirectory {param($Path,$Sid);$script:events.Add('base_create');$script:mutations++;[void][IO.Directory]::CreateDirectory($Path)}
function Initialize-InstallationEvidence {param($BasePath,$OperatorSid,$SensitiveValues);$script:events.Add('base_prepare');& $actualInitializeBase $OperatorSid;$script:events.Add('evidence_create');$script:mutations++;[void][IO.Directory]::CreateDirectory((Join-Path $canonical 'control/installation-evidence/preparation'));[void][IO.Directory]::CreateDirectory((Join-Path $canonical 'control/installation-evidence/stages'));return $physical}
function DisableAndStop-ContainerScheduledTaskUnderWriterFence {param($SessionId,$AttemptId,$ReplacementTransactionId,$DelegationToken,$AuthorityLease,$TaskName,$TaskPath);$script:events.Add('disable');$script:mutations++;$script:enabled=$false}
function Get-CanonicalOfficialLegacyRelayRunningCount {return 0}
function Write-InstallationCaughtFailure {param($Failure)}
$actualG=${function:Assert-ContainerDataGenerationTarget}
function Assert-ContainerDataGenerationTarget {param($CandidateRoot,$TargetSid,$LocalAppDataRoot,$DataRoot,$HelperRoot);$script:events.Add('g');& $actualG @PSBoundParameters}
$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false;$testMode=$false;$abandonedPending=$null
$auditPath=Join-Path $root 'audit.json'
$definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$legacyRelayBefore'},$true))
$preparation=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$installationEvidenceRoot' -and $n.Right.Extent.Text.Contains('if($null -eq $abandonedPending)')},$true))
$gate=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if (-not $Uninstall -and -not $RestoreVerifiedReplacement -and -not $CompleteRetiredRemoval)') -and $n.Extent.Text.Contains('Assert-ContainerDataGenerationTarget -CandidateRoot $source')},$true))
$gate=@($gate|Sort-Object {$_.Extent.StartOffset}|Select-Object -Last 1)
if($definitions.Count -ne 1 -or $preparation.Count -ne 1 -or $gate.Count -ne 1){throw 'ACTUAL_MAIN_ADMISSION_BOUNDARY_NOT_UNIQUE'}
$beforeFiles=@([IO.Directory]::GetFiles($root,'*',[IO.SearchOption]::AllDirectories)|Sort-Object|ForEach-Object {$_+':'+(Sha $_)}) -join "`n"
$beforeDirectories=@([IO.Directory]::GetDirectories($root,'*',[IO.SearchOption]::AllDirectories)|Sort-Object) -join "`n"
$failure='';$failureId='';$exception=$null
try{
 foreach($node in @($gate[0],$definitions[0],$preparation[0])|Sort-Object {$_.Extent.StartOffset}){Invoke-Expression $node.Extent.Text}
 if($null -ne $legacyRelayBefore){[void](Disable-CanonicalOfficialLegacyRelay $legacyRelayBefore)}
}catch{$failure=$_.Exception.Message;$failureId=$_.FullyQualifiedErrorId;$exception=$_.Exception}
if($env:CA_PRE_RUN_CASE -cin @('missing_launcher','different_launcher','reparse_launcher','invalid_action')){
 $afterFiles=@([IO.Directory]::GetFiles($root,'*',[IO.SearchOption]::AllDirectories)|Where-Object {$_ -cne $EvidencePath}|Sort-Object|ForEach-Object {$_+':'+(Sha $_)}) -join "`n"
 $afterDirectories=@([IO.Directory]::GetDirectories($root,'*',[IO.SearchOption]::AllDirectories)|Sort-Object) -join "`n"
  if(-not $failure -or $script:mutations -ne 0 -or $script:registryMutations -ne 0 -or [IO.Directory]::Exists($canonical) -or $beforeFiles -cne $afterFiles -or $beforeDirectories -cne $afterDirectories){throw ('PRE_RUN_LEGACY_REJECTION_CHANGED_STATE;mutations='+$script:mutations)}
 if(($script:ancestorState|ConvertTo-Json -Compress) -cne $ancestorBefore -or (Get-Acl -LiteralPath $root).Sddl -cne $nativeAclBefore){throw 'PRE_RUN_PROTECTED_OWNER_EFFECTIVE_ACL_CHANGED'}
 $report=Get-Content -LiteralPath $EvidencePath -Raw -Encoding UTF8|ConvertFrom-Json
 if([string]$report.status -cne 'REJECTED_BEFORE_PREPARATION' -or [string]$report.message -cne $failure -or [string]$report.code -cne [string]$exception.Data['canonical_code']){throw 'CALLER_REPORT_OR_REDACTED_NOTICE_MISSING'}
 if($failure -notmatch '관리자' -or $failure -notmatch '보존' -or $failure.Length -gt 300 -or $failure -match '[\r\n]' -or $null -eq $exception.InnerException -or $null -eq $exception.Data['original_error_record']){throw 'PRE_RUN_ADMIN_NOTICE_OR_ORIGINAL_ERROR_MISSING'}
 if($env:CA_PRE_RUN_CASE -cin @('different_launcher','invalid_action') -and $exception.Data['canonical_code'] -cne 'NONCANONICAL_WRITER_ENABLED'){throw 'ORIGINAL_IDENTITY_ERROR_CODE_CHANGED'}
}else{
 if($failure -or -not [IO.Directory]::Exists($canonical) -or $script:events[0] -cne 'g'){throw ('FIRST_INSTALL_PREPARATION_OR_G_FAILED;code='+$failureId+';events='+($script:events -join ','))}
 if($env:CA_PRE_RUN_CASE -ceq 'matching' -and ($script:enabled -or ($script:events -join ',') -cne 'g,base_prepare,protect,base_create,evidence_create,disable')){throw 'ROOT_ABSENT_OFFICIAL_DISABLE_FAILED'}
 if($env:CA_PRE_RUN_CASE -ceq 'no_task' -and ($null -ne $legacyRelayBefore -or $script:mutations -ne 3 -or [IO.File]::Exists($EvidencePath))){throw 'TASK_ABSENT_REQUIRED_LAUNCHER'}
}
'PASS_FIRST_INSTALL_ADMISSION'
''',engine=engine,values={'CA_FIXTURE_SOURCE':str(ROOT),'CA_PRE_RUN_CASE':case})
    assert result.returncode==0,result.stderr
