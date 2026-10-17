"""Removal admission is read-only and excludes only authenticated ancestors."""
from pathlib import Path
import re
import shutil

import pytest

from tests.powershell_contracts import run_powershell


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('case', ['absent', 'completion', 'run', 'both'])
def test_loaded_hive_value_names_follow_registry_case_semantics(tmp_path, case):
    source = str(ROOT / 'INSTALL_THIS_PC.ps1').replace("'", "''")
    _run(tmp_path, "$source='" + source + "'\n$case='" + case + "'\n" + r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
$definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Test-ContainerRemovalWorkerNeverStarted','Get-ContainerRemovalWorkerRunPresent')},$false))
if($definitions.Count -ne 2){throw 'hive reader definitions missing'}
foreach($definition in $definitions){
    $text=$definition.Extent.Text.Replace('[Microsoft.Win32.Registry]::Users.OpenSubKey([string]$Binding.sid,$false)','(Get-FixtureHive)')
    Invoke-Expression $text
}
$script:FixtureCompletedNames=if($case -in @('completion','both')){@('completedinstallid')}else{@()}
$script:FixtureRunNames=if($case -in @('run','both')){@('kmtech.containeraudit.relay')}else{@()}
$script:FixtureCompletedKey=[pscustomobject]@{}
$script:FixtureRunKey=[pscustomobject]@{}
$script:FixtureCompletedKey|Add-Member ScriptMethod GetValueNames {$script:FixtureCompletedNames}
$script:FixtureRunKey|Add-Member ScriptMethod GetValueNames {$script:FixtureRunNames}
foreach($key in @($script:FixtureCompletedKey,$script:FixtureRunKey)){$key|Add-Member ScriptMethod Dispose {}}
function Get-FixtureHive {
    $hive=[pscustomobject]@{}
    $hive|Add-Member ScriptMethod OpenSubKey {param($Path,$Writable) if($Path -like '*\Run'){$script:FixtureRunKey}else{$script:FixtureCompletedKey}}
    $hive|Add-Member ScriptMethod Dispose {}
    $hive
}
$binding=[pscustomobject]@{sid='fixture'}
if((Test-ContainerRemovalWorkerNeverStarted $binding) -ne ($case -eq 'absent')){throw 'completion or Run name casing changed admission'}
if((Get-ContainerRemovalWorkerRunPresent $binding) -ne ($case -in @('run','both'))){throw 'Run name casing changed audit'}
''')


@pytest.mark.parametrize('index,field', [(0, 'CreationDate'), (0, 'ParentProcessId'), (1, 'CreationDate'), (1, 'ParentProcessId')])
def test_verified_chain_missing_identity_fields_are_unknown(tmp_path, index, field):
    _run(tmp_path, r'''
$now=[datetime]::UtcNow
$engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$RemovalControllerProcessId=20000
$RemovalControllerStartedAtUtc=$now.AddSeconds(-1).ToString('o')
$rows=@(
    [pscustomobject]@{ProcessId=$PID;ParentProcessId=20000;CreationDate=$now;ExecutablePath=$engine;CommandLine='helper'},
    [pscustomobject]@{ProcessId=20000;ParentProcessId=0;CreationDate=$now.AddSeconds(-1);ExecutablePath=$engine;CommandLine='canonical'}
)
function Get-Process {param($Id,$ErrorAction) [pscustomobject]@{StartTime=($rows|Where-Object ProcessId -eq $Id).CreationDate}}
function Invoke-CimMethod {param($InputObject,$MethodName,$ErrorAction) [pscustomobject]@{ReturnValue=0;Sid='fixture-owner'}}
function Get-ContainerRemovalInvocation {param($Row) [pscustomobject]@{kind=$(if($Row.ProcessId -eq $PID){'helper'}else{'canonical'})}}
''' + '$rows[' + str(index) + '].' + field + r'''=$null
try {Get-ContainerRemovalVerifiedChain $rows;throw 'expected unknown'}
catch {if($_.Exception.Message -cne 'REMOVAL_PROCESS_OBSERVATION_UNKNOWN'){throw}}
''')


@pytest.mark.parametrize('case', ['reported_recording_failure', 'unreported_missing_path', 'different_failure_code', 'reported_hash_mismatch'])
def test_retired_capture_separates_reported_recording_failure_from_integrity_failure(tmp_path, case):
    canonical = str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').replace("'", "''")
    library = str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''")
    _run(tmp_path, "$canonical='" + canonical + "'\n$library='" + library + "'\n$case='" + case + "'\n" + r'''
$tokens=$null;$errors=$null;$count=0
foreach($path in @($canonical,$library)){
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    $definitions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Read-CanonicalRetiredRemovalCapture','Invoke-CanonicalRetiredRemovalChild','Initialize-InstallationChildCapture','ConvertTo-SafeInstallationOutput')},$false))
    $count+=$definitions.Count
    foreach($definition in $definitions){Invoke-Expression $definition.Extent.Text}
}
if($count -ne 4){throw 'capture definitions missing'}
function Same {param($Left,$Right) $Left -ceq $Right}
function Protect-InstallationText {param($Text,$Limit) $Text}
function Assert-BootstrapNoReparsePoint {param($Path,$Label,[switch]$PathOnly)}
function Assert-InstallationEvidenceProtectedPath {param($Path)}
function Sha {param($Path) 'actual-digest'}
$Script:InstallationEvidenceFailed=$false
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
$capturePath=''
if($case -eq 'reported_hash_mismatch'){
    $capturePath=Join-Path $PSScriptRoot 'captured.txt'
    [IO.File]::WriteAllText($capturePath,'fixture',[Text.UTF8Encoding]::new($false))
}
function Invoke-InstallationElevationCapture {
    param($Target,$Arguments,$AuditBase,$Sid)
    $codes=if($case -eq 'different_failure_code'){@('other')}else{@('CHILD_STREAM_IO_OR_ACL_FAILURE')}
    [pscustomobject]@{Id=42;ExitCode=0;Streams=@{stdout=[pscustomobject]@{path=$capturePath;sha256='different-digest'};stderr=[pscustomobject]@{path=$capturePath;sha256='different-digest'}};
        EvidenceSummary=[pscustomobject]@{recording_failed=($case -ne 'unreported_missing_path');failure_codes=$codes}}
}
$arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','helper.ps1','-Uninstall')
$failed=$false
try {$child=Invoke-CanonicalRetiredRemovalChild 'helper.ps1' $arguments 'audit' 'fixture-sid'}catch{$failed=$true}
if($case -eq 'reported_recording_failure'){
    if($failed -or $child.ExitCode -ne 0 -or -not $Script:InstallationEvidenceFailed -or
        -not $Script:InstallationEvidenceFailureCodes.Contains('CHILD_STREAM_IO_OR_ACL_FAILURE')){throw 'recording failure changed helper outcome or lost evidence failure'}
} elseif(-not $failed){throw 'unverified capture accepted'}
''')


@pytest.mark.parametrize('case', ['normal', 'hash_mismatch', 'over_existing_admission'])
def test_retired_stream_reuses_existing_bounded_capture_policy(tmp_path, case):
    canonical = str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').replace("'", "''")
    library = str(ROOT / 'tools/bootstrap_integrity.ps1').replace("'", "''")
    _run(tmp_path, "$canonical='" + canonical + "'\n$library='" + library + "'\n$case='" + case + "'\n" + r'''
$tokens=$null;$errors=$null
foreach($path in @($canonical,$library)){
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    $definitions=$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Read-CanonicalRetiredRemovalCapture','Initialize-InstallationChildCapture','ConvertTo-SafeInstallationOutput')},$false)
    foreach($definition in $definitions){Invoke-Expression $definition.Extent.Text}
}
function Assert-BootstrapNoReparsePoint {param($Path,$Label,[switch]$PathOnly)}
function Assert-InstallationEvidenceProtectedPath {param($Path)}
function Protect-InstallationText {param($Text,$Limit) $Text}
function ConvertTo-KmtechRedactedSinkText {param($Text) $Text}
function Sha {
    param($Path)
    $input=[IO.File]::OpenRead($Path);$hash=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($hash.ComputeHash($input))).Replace('-','').ToLowerInvariant()}
    finally {$input.Dispose();$hash.Dispose()}
}
$path=Join-Path $PSScriptRoot 'captured-output.txt'
[IO.File]::WriteAllText($path,'fixture output',[Text.UTF8Encoding]::new($false))
if($case -eq 'over_existing_admission'){
    $file=[IO.File]::OpenWrite($path)
    try {$file.SetLength(33554433)} finally {$file.Dispose()}
}
$digest=Sha $path
if($case -eq 'hash_mismatch'){$digest='different'}
try {
    $text=Read-CanonicalRetiredRemovalCapture ([pscustomobject]@{path=$path;sha256=$digest})
    if($case -eq 'hash_mismatch'){throw 'expected binding failure'}
    if($case -eq 'normal' -and $text -cne 'fixture output'){throw 'capture bytes differ'}
    if($case -eq 'over_existing_admission' -and -not $text.StartsWith('[TRUNCATED: child input exceeded ')){throw 'existing overflow policy differs'}
} catch {
    if($case -ne 'hash_mismatch' -or $_.Exception.Message -cne 'Retired removal captured stream binding differs.'){throw}
}
''')


def test_retired_capture_passes_only_script_arguments_to_existing_wrapper(tmp_path):
    source = str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1').replace("'", "''")
    _run(tmp_path, "$canonical='" + source + "'\n" + r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($canonical,[ref]$tokens,[ref]$errors)
$definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-CanonicalRetiredRemovalChild'},$false)
Invoke-Expression $definition.Extent.Text
function Same {param($Left,$Right) $Left -ceq $Right}
function Protect-InstallationText {param($Text,$Limit) $Text}
function Invoke-InstallationElevationCapture {
    param($Target,$Arguments,$AuditBase,$Sid)
    $script:CapturedArguments=@($Arguments)
    [pscustomobject]@{Id=42;ExitCode=0;Streams=$null}
}
$arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','helper.ps1','-Uninstall','-InstallRoot','fixture')
$child=Invoke-CanonicalRetiredRemovalChild 'helper.ps1' $arguments 'audit' 'fixture-sid'
if(($script:CapturedArguments -join ',') -cne '-Uninstall,-InstallRoot,fixture' -or $child.ExitCode -ne 0){throw 'engine arguments leaked into script parameters'}
''')


@pytest.mark.parametrize('shape', ['missing_parent', 'reused_parent', 'blank_created', 'blocked_above'])
def test_ancestor_walk_stops_at_first_broken_or_ineligible_link(tmp_path, shape):
    _run(tmp_path, r'''
$root=Join-Path $env:TEMP 'application'
$now=[datetime]::UtcNow
$system=[Environment]::SystemDirectory
$rows=@(
    [pscustomobject]@{ProcessId=800;ParentProcessId=801;CreationDate=$now;ExecutablePath=(Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe');CommandLine='canonical'},
    [pscustomobject]@{ProcessId=801;ParentProcessId=802;CreationDate=$now.AddSeconds(-1);ExecutablePath=(Join-Path $system 'cmd.exe');CommandLine='cmd.exe'},
    [pscustomobject]@{ProcessId=802;ParentProcessId=803;CreationDate=$now.AddSeconds(-2);ExecutablePath=(Join-Path $system 'explorer.exe');CommandLine='explorer.exe'}
)
$Script:ContainerRemovalVerifiedProcessIdentities=@{}
function Get-Process { param($Id,$ErrorAction) [pscustomobject]@{StartTime=($rows|Where-Object ProcessId -eq $Id).CreationDate} }
''' + "$shape='" + shape + r''''
if($shape -eq 'reused_parent'){$rows[1].CreationDate=$now.AddSeconds(1)}
if($shape -eq 'blank_created'){$rows[1].CreationDate=$null}
if($shape -eq 'blocked_above'){
    $rows+= [pscustomobject]@{ProcessId=803;ParentProcessId=0;CreationDate=$now.AddSeconds(-3);ExecutablePath=(Join-Path $system 'cmd.exe');CommandLine=('cmd.exe '+$root+'\busy.ps1')}
}
try {
    $ids=@(Get-ContainerRemovalCallingAncestors $rows 800 $root)
    if($shape -eq 'blank_created'){throw 'expected unknown'}
    if($shape -eq 'reused_parent'){if($ids.Count -ne 0){throw 'reused parent excluded'}}
    elseif($ids.Count -ne 1 -or $ids[0] -ne 801){throw 'walk did not stop'}
    if($shape -eq 'blocked_above'){
        function Get-ContainerRemovalControllerProcessId { param($ProcessRows) @($ids)+800 }
        function Get-CimInstance { param($ClassName,$ErrorAction) $rows }
        try { Assert-ContainerRemovalQuiescent $root;throw 'expected busy' }
        catch { if($_.Exception.Message -notlike '*REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP*'){throw} }
    }
} catch {
    if($shape -ne 'blank_created' -or $_.Exception.Message -cne 'REMOVAL_PROCESS_OBSERVATION_UNKNOWN'){throw}
}
''')


def _run(tmp_path, body):
    engine = shutil.which("powershell.exe")
    assert engine
    driver = tmp_path / "chain-admission.ps1"
    source = str(ROOT / "INSTALL_THIS_PC.ps1").replace("'", "''")
    driver.write_text(
        "$ErrorActionPreference='Stop';Set-StrictMode -Version Latest\n"
        f"$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('{source}',[ref]$tokens,[ref]$errors)\n"
        "if($errors.Count){throw 'SOURCE_PARSE_FAILED'}\n"
        "$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and "
        "$n.Name -in @('Get-ContainerRemovalProcessArguments','Read-ContainerRemovalTransport',"
        "'Get-ContainerRemovalInvocation','Assert-ContainerRemovalHelperArguments',"
        "'Get-ContainerRemovalVerifiedChain','Assert-ContainerRemovalQuiescent',"
        "'Assert-ContainerMachineRemovalWorkerPart','Assert-ContainerRemovalBoundary',"
        "'Get-ContainerRemovalIoPath','Get-ContainerRemovalCallingAncestors',"
        "'Read-ContainerRemovalWorkerReceipt','Test-ContainerAttestedNewPlacementRemoval')},$false)|"
        "ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }\n"
        "function Get-StrictFullPath([string]$p,[string]$label){[IO.Path]::GetFullPath($p).TrimEnd('\\')}\n"
        "function Test-SamePath([string]$a,[string]$b){[IO.Path]::GetFullPath($a).TrimEnd('\\') -ieq [IO.Path]::GetFullPath($b).TrimEnd('\\')}\n"
        + body,
        encoding="utf-8-sig",
    )
    result = run_powershell(
        [engine, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
        timeout=60,
    )
    (tmp_path / "child-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (tmp_path / "child-stderr.txt").write_text(result.stderr, encoding="utf-8")
    # Child streams may contain process arguments; keep them out of pytest output.
    kinds = sorted(set(re.findall(r"\b(?:RuntimeException|MethodException|ParameterBindingException|CommandNotFoundException|InvalidOperationException)\b", result.stderr)))
    locations = re.findall(r"\.ps1:(\d+)\s", result.stderr)
    assert result.returncode == 0, f"isolated removal admission assertion failed: {kinds}, lines {locations}"


@pytest.mark.parametrize("outside", [False, True])
def test_only_verified_chain_is_excluded_from_census(tmp_path, outside):
    _run(tmp_path, r"""
$root=Join-Path $PSScriptRoot 'application'
$engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$ids=@(31001,31002,31003,[int]$PID)
$Script:rows=@()
for($i=0;$i -lt $ids.Count;$i++){
 $Script:rows+=[pscustomobject]@{ProcessId=$ids[$i];ParentProcessId=$(if($i){$ids[$i-1]}else{0});ExecutablePath=$engine;CommandLine='safe';CreationDate=[datetime]::UtcNow.AddMinutes(-10).AddSeconds($i)}
}
$Script:rows[1].CommandLine='powershell -File packet\INSTALL_THIS_PC.ps1 -InstallRoot '+$root+'\current'
function Get-Process([int]$Id){$r=@($Script:rows|Where-Object ProcessId -eq $Id);if($r.Count -ne 1){throw 'MISSING'};[pscustomobject]@{StartTime=$r[0].CreationDate}}
function Get-ContainerRemovalInvocation($row){[pscustomobject]@{kind=$(if([int]$row.ProcessId -eq 31001){'canonical'}elseif([int]$row.ProcessId -eq 31003){'wrapper'}else{'helper'});arguments=@();parent_id=$(if([int]$row.ProcessId -eq 31003){31002}else{0})}}
function Invoke-CimMethod($InputObject,[string]$MethodName){[pscustomobject]@{ReturnValue=0;Sid='fixture-owner'}}
$RemovalControllerProcessId=31001
$RemovalControllerStartedAtUtc=$Script:rows[0].CreationDate.ToUniversalTime().ToString('o')
$MachineControlRoot=''
$excluded=@(Get-ContainerRemovalVerifiedChain $Script:rows)
if($excluded.Count -ne 4 -or @($ids|Where-Object {$_ -notin $excluded}).Count){throw 'CHAIN_NOT_EXCLUDED'}
function Get-CimInstance { $Script:rows }
""" + (r"""
$Script:rows+=[pscustomobject]@{ProcessId=31999;ParentProcessId=0;ExecutablePath=$root+'\current\runtime\pythonw.exe';CommandLine='';CreationDate=[datetime]::UtcNow}
try{Assert-ContainerRemovalQuiescent $root $excluded;throw 'OUTSIDE_PROCESS_ACCEPTED'}catch{if($_.Exception.Message -cne 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'){throw}}
""" if outside else "Assert-ContainerRemovalQuiescent $root $excluded\n"))


@pytest.mark.parametrize("case", ["reused", "parent_exited", "engine", "arguments", "order"])
def test_chain_rejects_unverified_process_identity(tmp_path, case):
    _run(tmp_path, r"""
$engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$start=[datetime]::UtcNow.AddMinutes(-5)
$Script:rows=@([pscustomobject]@{ProcessId=31001;ParentProcessId=0;ExecutablePath=$engine;CommandLine='safe';CreationDate=$start},[pscustomobject]@{ProcessId=[int]$PID;ParentProcessId=31001;ExecutablePath=$engine;CommandLine='safe';CreationDate=$start.AddSeconds(1)})
function Get-ContainerRemovalInvocation($row){if($Script:case -ceq 'arguments'){throw 'REMOVAL_CONTROLLER_ARGUMENTS_INVALID'};[pscustomobject]@{kind=$(if([int]$row.ProcessId -eq 31001){'canonical'}else{'helper'});arguments=@();parent_id=0}}
function Invoke-CimMethod($InputObject,[string]$MethodName){[pscustomobject]@{ReturnValue=0;Sid='fixture-owner'}}
function Get-Process([int]$Id){if($Script:case -ceq 'parent_exited' -and $Id -eq 31001){throw 'MISSING'};$r=@($Script:rows|Where-Object ProcessId -eq $Id);[pscustomobject]@{StartTime=$(if($Script:case -ceq 'reused' -and $Id -eq 31001){$r[0].CreationDate.AddSeconds(2)}else{$r[0].CreationDate})}}
$RemovalControllerProcessId=31001
$RemovalControllerStartedAtUtc=$start.ToUniversalTime().ToString('o')
$MachineControlRoot=''
""" + f"$Script:case='{case}'\n" + r"""
if($Script:case -ceq 'engine'){$Script:rows[0].ExecutablePath=Join-Path $PSScriptRoot 'powershell.exe'}
if($Script:case -ceq 'order'){$Script:rows[0].CreationDate=$start.AddMinutes(1)}
$rejected=$false
try{[void](Get-ContainerRemovalVerifiedChain $Script:rows)}catch{if($_.Exception.Message -cnotlike 'REMOVAL_CONTROLLER_*'){throw};$rejected=$true}
if(-not $rejected){throw 'UNVERIFIED_CHAIN_ACCEPTED'}
""")


def test_census_normalizes_root_and_keeps_sibling_prefix_outside(tmp_path):
    _run(tmp_path, r"""
$root=Join-Path $PSScriptRoot 'application'
$Script:rows=@([pscustomobject]@{ProcessId=31999;ExecutablePath=$root+'-sibling\app.exe';CommandLine=''})
function Get-CimInstance {$Script:rows}
Assert-ContainerRemovalQuiescent ($root+'\')
$Script:rows[0].ExecutablePath=$root+'\runtime\pythonw.exe'
$rejected=$false
try{Assert-ContainerRemovalQuiescent ($root+'\')}catch{if($_.Exception.Message -cne 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'){throw};$rejected=$true}
if(-not $rejected){throw 'TRAILING_SEPARATOR_BYPASS'}
""")


@pytest.mark.parametrize("case", ["absent", "interrupted", "wrong_sid", "reparse", "wrong_status", "outside_profile", "unreadable"])
def test_machine_removal_without_worker_proof_is_read_only(tmp_path, case):
    _run(tmp_path, r"""
$Script:writes=0
function Read-ContainerMachineRemovalBinding {[pscustomobject]@{sid='fixture-owner';profile_root=$PSScriptRoot;local_appdata_root=(Join-Path $PSScriptRoot 'AppData\Local');pending_valid=$true;profile_registered=$true}}
function Test-ContainerRemovalWorkerUnavailable { $false }
function Test-ContainerRemovalWorkerProfileAbsent { $false }
function Test-ContainerRemovalWorkerNeverStarted { $false }
function Read-ContainerRemovalWorkerReceipt {
 if($Script:case -in @('absent','interrupted')){return $null}
 if($Script:case -ceq 'unreadable'){throw [UnauthorizedAccessException]::new()}
 [pscustomobject]@{status=$(if($Script:case -ceq 'wrong_status'){'pass_data_preserved'}else{'PASS_DATA_PRESERVED'});operator_sid=$(if($Script:case -ceq 'wrong_sid'){'fixture-other'}else{'fixture-owner'});path=$(if($Script:case -ceq 'outside_profile'){Join-Path (Split-Path -Parent $PSScriptRoot) 'other\current_user_removal.json'}else{Join-Path $PSScriptRoot 'AppData\Local\current_user_removal.json'});state_scope='current_user';data_preserved=$true;relay_autostart=@{status='ABSENT'};relay_process=@{status='ABSENT'}}
}
function Assert-ContainerRemovalBoundary([string]$Path){if($Script:case -ceq 'reparse'){throw 'REMOVAL_BOUNDARY_REDIRECTED'}}
function Set-Item {$Script:writes++}
function Remove-Item {$Script:writes++}
function Set-ItemProperty {$Script:writes++}
""" + f"$Script:case='{case}'\n" + r"""
$rejected=$false
try{[void](Assert-ContainerMachineRemovalWorkerPart)}catch{if($_.Exception.Message -cne 'MACHINE_REMOVAL_WORKER_PART_PENDING'){throw};$rejected=$true}
if(-not $rejected -or $Script:writes){throw 'MACHINE_REMOVAL_MUTATED_WITHOUT_PROOF'}
""")


@pytest.mark.parametrize("proof", ["pending", "profile_absent", "receipt", "account_unresolved", "account_disabled"])
def test_machine_removal_allows_settled_absence_proofs(tmp_path, proof):
    _run(tmp_path, r"""
function Read-ContainerMachineRemovalBinding {[pscustomobject]@{sid='fixture-owner';profile_root=$PSScriptRoot;local_appdata_root=(Join-Path $PSScriptRoot 'AppData\Local');pending_valid=$true;profile_registered=$true}}
function Test-ContainerRemovalWorkerUnavailable { $Script:proof -in @('account_unresolved','account_disabled') }
function Test-ContainerRemovalWorkerProfileAbsent { $Script:proof -ceq 'profile_absent' }
function Test-ContainerRemovalWorkerNeverStarted { $Script:proof -ceq 'pending' }
function Read-ContainerRemovalWorkerReceipt {if($Script:proof -ceq 'receipt'){return [pscustomobject]@{operator_sid='fixture-owner';status='PASS_DATA_PRESERVED';path=(Join-Path $PSScriptRoot 'AppData\Local\current_user_removal.json')}};return $null}
function Get-ContainerRemovalWorkerRunPresent { $true }
""" + f"$Script:proof='{proof}'\n" + r"""
$result=Assert-ContainerMachineRemovalWorkerPart
if($null -eq $result){throw 'MACHINE_REMOVAL_PROOF_NOT_RETURNED'}
""")


@pytest.mark.parametrize("kind", ["helper", "wrapper", "tampered", "unrelated_source", "wrong_arguments"])
def test_invocation_authenticates_existing_pinned_transport(tmp_path, kind):
    library = str(ROOT / "tools/bootstrap_integrity.ps1").replace("'", "''")
    helper = str(ROOT / "INSTALL_THIS_PC.ps1").replace("'", "''")
    _run(tmp_path, f"$librarySource='{library}';$helperSourcePath='{helper}'\n" + r"""
$t=$null;$e=$null;$libraryAst=[Management.Automation.Language.Parser]::ParseFile($librarySource,[ref]$t,[ref]$e)
$libraryAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-InstallationVerifiedScript','Get-InstallationElevationWrapperSource','Get-InstallationHelperMemorySource','New-InstallationMemoryTransport','ConvertTo-InstallationMemoryCommand','Assert-InstallationMemoryCommandBound','ConvertTo-BootstrapRelayArgument','Remove-InstallationMemoryTransport')},$false)|ForEach-Object {. ([scriptblock]::Create($_.Extent.Text))}
function Assert-InstallationEvidenceWriteRoot([string]$Path){if(-not(Test-SamePath $Path $PSScriptRoot)){throw 'FIXTURE_ROOT_DIFFERS'}}
function Get-FileSha256([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$uninstallSource=Join-Path $PSScriptRoot 'packet';[void][IO.Directory]::CreateDirectory((Join-Path $uninstallSource 'tools'))
$BootstrapScriptPath=Join-Path $uninstallSource 'INSTALL_THIS_PC.ps1'
Copy-Item -LiteralPath $helperSourcePath -Destination $BootstrapScriptPath
$library=Join-Path $uninstallSource 'tools\bootstrap_integrity.ps1';Copy-Item -LiteralPath $librarySource -Destination $library
$canonical=Join-Path $PSScriptRoot 'manager\INSTALL_CANONICAL_PORTABLE.ps1'
$installRootFull=Join-Path $PSScriptRoot 'application\current'
$OperatorLocalAppDataRoot=Join-Path $PSScriptRoot 'worker\AppData\Local'
$OperatorSid='fixture-owner';$RemovalControllerProcessId=31001;$RemovalControllerStartedAtUtc=[datetime]::UtcNow.ToString('o')
$WriterFenceSessionId='fixture-session';$WriterFenceAttemptId='fixture-attempt';$WriterFenceReplacementTransactionId='fixture-transaction'
$WriterFencePreparedReceiptPath=Join-Path $PSScriptRoot 'prepared.json';$WriterFencePreparedReceiptSha256='fixture-pin'
$parameters=@('-Uninstall','-SourceRoot',$uninstallSource,'-InstallRoot',$installRootFull,'-OperatorLocalAppDataRoot',$OperatorLocalAppDataRoot,'-OperatorSid',$OperatorSid,'-RemovalControllerProcessId',[string]$RemovalControllerProcessId,'-RemovalControllerStartedAtUtc',$RemovalControllerStartedAtUtc,'-RemovalControllerCanonicalPath',$canonical,'-WriterFenceSessionId',$WriterFenceSessionId,'-WriterFenceAttemptId',$WriterFenceAttemptId,'-WriterFenceReplacementTransactionId',$WriterFenceReplacementTransactionId,'-WriterFencePreparedReceiptPath',$WriterFencePreparedReceiptPath,'-WriterFencePreparedReceiptSha256',$WriterFencePreparedReceiptSha256)
""" + f"$kind='{kind}'\n" + r"""
if($kind -ceq 'wrong_arguments'){$parameters[2]=Join-Path $PSScriptRoot 'unrelated-packet'}
if($kind -ceq 'wrapper'){
 $source=Get-InstallationElevationWrapperSource
 $values=@($BootstrapScriptPath,(Join-Path $PSScriptRoot 'elevation-result.json'),(Join-Path $PSScriptRoot 'audit'),'fixture-owner','31002',(Get-FileSha256 $BootstrapScriptPath),(Get-FileSha256 $library)) + @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$BootstrapScriptPath) + $parameters
}else{
 $source='function Get-InstallationVerifiedScript {'+${function:Get-InstallationVerifiedScript}.ToString()+"}`n"+(Get-InstallationHelperMemorySource)
 if($kind -ceq 'unrelated_source'){$source+=';throw 1'}
 $values=@($BootstrapScriptPath,(Get-FileSha256 $BootstrapScriptPath),$library,(Get-FileSha256 $library),$PSScriptRoot)+$parameters
}
$transport=New-InstallationMemoryTransport $source $values $PSScriptRoot
try{
 if($kind -ceq 'tampered'){Remove-Item -LiteralPath $transport.Paths[1];[IO.File]::WriteAllText($transport.Paths[1],'[]')}
 $row=[pscustomobject]@{ProcessId=[int]$PID;ParentProcessId=31002;CommandLine=('powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$transport.Encoded)}
 $rejected=$false
 try{$result=Get-ContainerRemovalInvocation $row}catch{
  $code=if($_.Exception.Message -clike 'REMOVAL_CONTROLLER_*'){$_.Exception.Message}else{'UNCLASSIFIED'}
  [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'admission-error.json'),(@{type=$_.Exception.GetType().FullName;code=$code;stack=$_.ScriptStackTrace;diagnostic=@{actual_length=$_.Exception.Data['actual_length'];expected_length=$_.Exception.Data['expected_length'];first_difference=$_.Exception.Data['first_difference'];literal_length=$_.Exception.Data['literal_length']}}|ConvertTo-Json))
  if($_.Exception.Message -cnotlike 'REMOVAL_CONTROLLER_*'){throw};$rejected=$true
 }
 if($kind -in @('tampered','unrelated_source','wrong_arguments')){if(-not $rejected){throw 'UNBOUND_TRANSPORT_ACCEPTED'}}
 elseif($rejected -or $result.kind -cne $kind){throw 'BOUND_TRANSPORT_REJECTED'}
}finally{Remove-InstallationMemoryTransport $transport}
""")


@pytest.mark.parametrize("case", ["powershell", "pwsh", "cmd", "sshd", "conhost", "python", "other_argument", "reused"])
def test_calling_ancestor_exclusion_has_exact_engine_and_argument_boundary(tmp_path, case):
    _run(tmp_path, f"$case='{case}'\n" + r"""
$root=Join-Path $PSScriptRoot 'application'
$system=[Environment]::SystemDirectory
$exe=switch($case){'pwsh'{Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'PowerShell\7\pwsh.exe'};'cmd'{Join-Path $system 'cmd.exe'};'sshd'{Join-Path $system 'OpenSSH\sshd.exe'};'conhost'{Join-Path $system 'conhost.exe'};'python'{Join-Path $root 'current\runtime\python.exe'};default{Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'}}
$start=[datetime]::UtcNow.AddMinutes(-5)
$Script:rows=@([pscustomobject]@{ProcessId=31001;ParentProcessId=31000;ExecutablePath=$exe;CommandLine='canonical';CreationDate=$start.AddSeconds(1)},[pscustomobject]@{ProcessId=31000;ParentProcessId=0;ExecutablePath=$exe;CommandLine=('"'+$exe+'" -File fixture.ps1 -InstallRoot "'+$root+'\current"');CreationDate=$start})
if($case -ceq 'other_argument'){$Script:rows[1].CommandLine+=' -Other "'+$root+'\current\runtime\python.exe"'}
function Get-Process([int]$Id){$r=@($Script:rows|Where-Object ProcessId -eq $Id);[pscustomobject]@{StartTime=$(if($case -ceq 'reused'){$r[0].CreationDate.AddSeconds(2)}else{$r[0].CreationDate})}}
$Script:ContainerRemovalVerifiedProcessIdentities=@{}
$excluded=@(Get-ContainerRemovalCallingAncestors $Script:rows 31001 $root)
if($case -in @('python','other_argument','reused')){if($excluded.Count){throw 'UNVERIFIED_CALLER_EXCLUDED'}}
elseif($excluded.Count -ne 1 -or $excluded[0] -ne 31000){throw 'VERIFIED_CALLER_NOT_EXCLUDED'}
""")


def test_real_receipt_reparse_component_is_rejected(tmp_path):
    _run(tmp_path, r"""
$profile=Join-Path $PSScriptRoot 'worker'
$local=Join-Path $profile 'AppData\Local'
$relay=Join-Path $local 'KMTech\DirectSync\container_audit'
$other=Join-Path $PSScriptRoot 'unrelated-status'
[void][IO.Directory]::CreateDirectory($relay);[void][IO.Directory]::CreateDirectory($other)
[void](New-Item -ItemType Junction -Path (Join-Path $relay 'status') -Target $other)
[IO.File]::WriteAllText((Join-Path $other 'current_user_removal.json'),'{"operator_sid":"fixture-owner","status":"PASS_DATA_PRESERVED"}')
function Read-ContainerMachineRemovalBinding {[pscustomobject]@{sid='fixture-owner';profile_root=$profile;local_appdata_root=$local;pending_valid=$false;profile_registered=$true}}
$rejected=$false
try{[void](Assert-ContainerMachineRemovalWorkerPart)}catch{if($_.Exception.Message -cne 'MACHINE_REMOVAL_WORKER_PART_PENDING'){throw};$rejected=$true}
if(-not $rejected){throw 'REPARSE_RECEIPT_ACCEPTED'}
""")


@pytest.mark.parametrize("middle_itp", [False, True])
def test_preserved_old_census_accepts_direct_retired_elevation_only(tmp_path, middle_itp):
    old = str(ROOT / "tests/fixtures/removal_census_1d6b2d9.ps1").replace("'", "''")
    _run(tmp_path, f". '{old}'\n" + r"""
$root=Join-Path $PSScriptRoot 'application'
$engine=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$Script:rows=@([pscustomobject]@{ProcessId=31001;ExecutablePath=$engine;CommandLine='canonical external-packet'},[pscustomobject]@{ProcessId=31003;ExecutablePath=$engine;CommandLine='powershell -EncodedCommand opaque'},[pscustomobject]@{ProcessId=[int]$PID;ExecutablePath=$engine;CommandLine='old-helper'})
""" + (r"""
$Script:rows+=[pscustomobject]@{ProcessId=31002;ExecutablePath=$engine;CommandLine=('powershell -File external-packet\INSTALL_THIS_PC.ps1 -Uninstall -InstallRoot '+$root+'\current')}
""" if middle_itp else "") + r"""
function Get-CimInstance {$Script:rows}
$rejected=$false
try{Assert-ContainerRemovalQuiescent $root @(31001)}catch{if($_.Exception.Message -cne 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'){throw};$rejected=$true}
""" + f"if($rejected -ne ${str(middle_itp).lower()}){{throw 'OLD_CENSUS_CHAIN_DIFFERS'}}\n")


@pytest.mark.parametrize("new_placement", [True, False])
def test_attested_new_placement_compensation_keeps_its_existing_admission(tmp_path, new_placement):
    _run(tmp_path, r"""
$MachineControlRoot='fixture-control';$placementWriterFenceLease=@{}
$WriterFenceReplacementTransactionId='fixture-transaction';$WriterFenceSessionId='fixture-session';$WriterFenceAttemptId='fixture-attempt';$OperatorSid='fixture-owner'
$WriterFencePreparedReceiptPath=Join-Path $PSScriptRoot 'prepared.json';$WriterFencePreparedReceiptSha256='fixture-prepared'
$installRootFull=Join-Path $PSScriptRoot 'application\current';$SourceRoot=Join-Path $PSScriptRoot 'packet';$testOverride=$true
$Script:ContainerWriterFenceAdmissionProductionRoot='fixture-control'
function Get-ContainerMachineInstallStateRoot {$PSScriptRoot}
function Read-ContainerWriterFence {[pscustomobject]@{orchestrator_sha256='fixture-orchestrator'}}
function Assert-ContainerWriterSessionAuthority {}
function Get-FileSha256 {[string]'fixture-manifest'}
$path=Join-Path $PSScriptRoot 'install-audit\machine-prestate-fixture-transaction\prestate.json'
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $path))
$state=@{schema='container-audit-machine-install-prestate-v1';run_id=$WriterFenceReplacementTransactionId;session_id=$WriterFenceSessionId;attempt_id=$WriterFenceAttemptId;worker_sid=$OperatorSid;before_manifest_sha256='';install_root=$installRootFull;orchestrator_sha256='fixture-orchestrator';prepared_receipt=@{path=$WriterFencePreparedReceiptPath;sha256=$WriterFencePreparedReceiptSha256};source_manifest_sha256='fixture-manifest'}
""" + ("$state.before_manifest_sha256='existing-code'\n" if not new_placement else "") + r"""
[IO.File]::WriteAllText($path,($state|ConvertTo-Json -Depth 6))
$Script:guardCalls=0
function Assert-ContainerMachineRemovalWorkerPart {$Script:guardCalls++;throw 'MACHINE_REMOVAL_WORKER_PART_PENDING'}
$Uninstall=[Management.Automation.SwitchParameter]::new($true);$RemoveUncommittedPlacement=$false
$entry=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -ceq '$Uninstall.IsPresent'},$true)
if($null -eq $entry){throw 'UNINSTALL_ENTRY_NOT_FOUND'}
$admission=($entry.Clauses[0].Item2.Statements[1..2]|ForEach-Object {$_.Extent.Text}) -join "`n"
$rejected=$false
try{. ([scriptblock]::Create($admission))}catch{if($_.Exception.Message -cne 'MACHINE_REMOVAL_WORKER_PART_PENDING'){throw};$rejected=$true}
""" + f"if($rejected -eq ${str(new_placement).lower()}){{throw 'COMPENSATION_ADMISSION_DIFFERS'}}\n" + f"if($Script:guardCalls -ne {0 if new_placement else 1}){{throw 'WORKER_GATE_SCOPE_DIFFERS'}}\n")
