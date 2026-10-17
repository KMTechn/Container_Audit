"""Direct retirement capture and protected audit path, without installer entry."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("overflow", [False, True])
def test_retired_capture_preserves_first_diagnostic_in_protected_records(tmp_path, engine, overflow):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", [
        "Full", "Same", "Sha", "Read-CanonicalRetiredRemovalCapture",
        "Invoke-CanonicalRetiredRemovalChild", "Get-CanonicalRetirementChildFailure",
        "ConvertTo-CanonicalAuditJson", "Save", "Write-CanonicalInstallationPublicRecord",
    ], r'''
Set-StrictMode -Version Latest
$root=$env:CA_CONTRACT_ROOT
$evidence=Join-Path $root 'protected'
[void][IO.Directory]::CreateDirectory($evidence)
$Script:InstallationEvidenceRoot=$evidence
$Script:InstallationProtectedRunRoot=$evidence
$Script:InstallationEvidencePrivileged=$true
$Script:InstallationEvidenceSid='fixture'
$Script:InstallationEvidenceFailed=$false
$Script:InstallationEvidenceFailureCodes=[Collections.Generic.List[string]]::new()
$Script:InstallationPreparationEvents=$null
$privateValue=[Guid]::NewGuid().ToString('N')
$env:CONTAINER_AUDIT_ENROLLMENT_TOKEN=$privateValue
$Script:InstallationEvidenceSensitiveValues=@($privateValue)
function Assert-InstallationEvidenceProtectedPath([string]$Path) {
 if(-not [IO.Path]::GetFullPath($Path).StartsWith($evidence+'\',[StringComparison]::OrdinalIgnoreCase) -and $Path -cne $evidence){throw 'ACL boundary escaped fixture'}
}
function Set-InstallationEvidenceAcl([string]$Path,[string]$Sid,[switch]$Directory) {
 Assert-InstallationEvidenceProtectedPath $Path
}
function Invoke-ContainerAtomicReplace([string]$Source,[string]$Destination,[string]$Mode) {
 if(-not [IO.Path]::GetFullPath($Destination).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Atomic boundary escaped fixture'}
 [IO.File]::Copy($Source,$Destination,$true);[IO.File]::Delete($Source)
}
$cap=(Protect-InstallationText -Configuration).full_byte_cap
$script:LongCause=("diagnostic line`n"*512)+'TAIL'
$script:Diagnostic=if($env:OVERFLOW -ceq '1'){("diagnostic line`n"*[int]($cap/4))+'TAIL'}else{$script:LongCause}
$script:CaptureNumber=0
function Invoke-InstallationElevationCapture {
 $script:CaptureNumber++
 $streams=@{}
 foreach($name in @('stdout','stderr')){
  $text=if($name -ceq 'stdout'){''}elseif($script:CaptureNumber -eq 1){'Authorization: Bearer '+$privateValue+"`n"+$script:Diagnostic}else{'RECOVERY_RESULT'}
  $bytes=[Text.Encoding]::UTF8.GetBytes($text)
  $safe=ConvertTo-SafeInstallationOutput ([pscustomobject]@{bytes=$bytes;observed=$bytes.Length;complete=$true})
  $path=Join-Path $evidence ('capture-'+$script:CaptureNumber+'-'+$name+'.bin')
  [IO.File]::WriteAllBytes($path,[byte[]]$safe.bytes)
  $streams[$name]=[pscustomobject]@{path=$path;sha256=(Get-FileSha256 $path);truncated=$safe.truncated;saved_bytes=$safe.bytes.Length}
 }
 return [pscustomobject]@{Id=$script:CaptureNumber;ExitCode=if($script:CaptureNumber -eq 1){1}else{0};Streams=$streams;EvidenceSummary=[pscustomobject]@{status='COMPLETE';recording_failed=$false}}
}
$target=Join-Path $root 'fixture-helper.ps1'
$arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$target,'-Uninstall')
$first=Invoke-CanonicalRetiredRemovalChild $target $arguments (Join-Path $root 'audit') 'fixture'
$failure=Get-CanonicalRetirementChildFailure $first
$audit=[ordered]@{status='FAILED_ROLLED_BACK';rollback=@{runtime_restored=$true};code_replacement=@{};retirement_child_failure=$failure}
$privateAudit=Join-Path $evidence 'private-audit.json'
$publicAudit=Join-Path $root 'public-audit.json'
Save $privateAudit $audit
Save $publicAudit $audit
$recovery=Invoke-CanonicalRetiredRemovalChild $target $arguments (Join-Path $root 'recovery') 'fixture'
if($recovery.ExitCode -ne 0){throw 'Recovery capture failed'}
Save $privateAudit $audit
$protected=Get-Content -LiteralPath $privateAudit -Raw -Encoding UTF8|ConvertFrom-Json
$public=Get-Content -LiteralPath $publicAudit -Raw -Encoding UTF8|ConvertFrom-Json
if($public.retirement_child_failure.stderr -cne 'SUPPORT_FAILURE'){throw 'Public audit contains diagnostic'}
if($first.ExitCode -ne 1 -or $failure.exit_code -ne 1){throw 'First failure changed'}
if($env:OVERFLOW -ceq '1'){
 if(-not $first.Streams.stderr.truncated -or $first.Streams.stderr.saved_bytes -gt $cap){throw 'Capture cap changed'}
 if(-not $protected.retirement_child_failure.stderr.Contains('[TRUNCATED:')){throw 'Truncation marker missing'}
}else{
 if(-not $protected.retirement_child_failure.stderr.Contains($script:LongCause)){throw 'Protected diagnostic incomplete'}
 $events=@(Get-ChildItem -LiteralPath $evidence -Filter '*.jsonl' -File|ForEach-Object {Get-Content -LiteralPath $_.FullName -Encoding UTF8}|ForEach-Object {$_|ConvertFrom-Json})
 $found=@($events|Where-Object {$_.event -ceq 'CANONICAL_DIAGNOSTIC_REPORT'}|ForEach-Object {$_.diagnostics}|Where-Object {$_.field -ceq 'stderr' -and $_.diagnostic.Contains($script:LongCause)})
 if(-not $found.Count){throw 'Protected journal diagnostic incomplete'}
}
foreach($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force)){
 if([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName)).Contains($privateValue)){throw 'Raw private value persisted'}
}
$canonicalWriterFenceActive=$false
$line=Write-CanonicalInstallationPublicRecord -ExitCode 1
if($line.Contains($script:LongCause) -or @($line).Count -ne 1 -or -not $line.StartsWith('CONTAINER_AUDIT_INSTALL_CANONICAL=')){throw 'Public output is not a fixed record'}
Write-Output $line
''', values={"OVERFLOW": "1" if overflow else "0"}, engine=engine)
    assert result.returncode == 0
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0].split("=", 1)[1])
    assert record["status"] == "FAILED"
    assert record["report_status"] == "REPORT_UNAVAILABLE"
