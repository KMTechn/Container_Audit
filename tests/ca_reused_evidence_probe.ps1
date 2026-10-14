$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. $env:CA_BOOTSTRAP_SOURCE
function Full([string]$Path,[string]$Purpose){return [IO.Path]::GetFullPath($Path)}
function Same([string]$Left,[string]$Right){return [IO.Path]::GetFullPath($Left) -ieq [IO.Path]::GetFullPath($Right)}
function Sha([string]$Path){return Get-FileSha256 $Path}
# Only the OS ACL/privilege boundary is substituted. Real files, aggregate,
# atomic create-only publisher and parent journal/hash reader remain in use.
function Assert-InstallationEvidenceWriteRoot([string]$Path){}
function Assert-InstallationEvidenceProtectedPath([string]$Path){}
function Set-InstallationEvidenceAcl([string]$Path,[string]$Sid){}
$control=Join-Path $env:CA_CONTRACT_ROOT 'control'
function Get-InstallationEvidenceControlRoot {return $control}
$proofRoot=Join-Path (Join-Path (Join-Path $control 'installation-evidence') ('run-'+('b'*32))) ('helper-audit.evidence.'+$PID)
[void][IO.Directory]::CreateDirectory($proofRoot)
$Script:InstallationEvidenceRoot=$proofRoot
$Script:InstallationEvidenceFailed=$false
function Write-InstallationEvidenceEvent($Value){
    [IO.File]::AppendAllText((Join-Path $proofRoot 'stages.jsonl'),(($Value|ConvertTo-Json -Depth 6 -Compress)+"`n"),[Text.UTF8Encoding]::new($false))
}
$source=Join-Path $env:CA_CONTRACT_ROOT 'source'
$installed=Join-Path $env:CA_CONTRACT_ROOT 'current'
[void][IO.Directory]::CreateDirectory((Join-Path $source 'app'))
[void][IO.Directory]::CreateDirectory((Join-Path $source 'tools'))
$helper=Join-Path $source 'INSTALL_THIS_PC.ps1'
[IO.File]::WriteAllText($helper,'# helper fixture')
[IO.File]::WriteAllText((Join-Path $source 'app\module.py'),'# module fixture')
[IO.File]::WriteAllText((Join-Path $source 'tools\container_writer_sink_inventory.json'),'{}')
$manifest=[ordered]@{source_commit=('a'*40);helper_sha256=Get-FileSha256 $helper;
    writer_sink_inventory_sha256=('c'*64);writer_sink_inventory_contract_sha256=('d'*64)}
[IO.File]::WriteAllText((Join-Path $source 'portable-manifest.json'),($manifest|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $source -Destination $installed -Recurse
$transaction='e'*32
$saved=Write-BootstrapReusedPlacementEvidence $source $installed $transaction 'unused' $helper
$binding=[pscustomobject]@{status='BOUND_DIRECT_CHILD';stage_evidence_root=$proofRoot;helper_process_id=$PID}
$record=Get-Content -LiteralPath $saved.path -Raw -Encoding UTF8|ConvertFrom-Json
$case=$env:CA_REUSED_CASE
switch($case){
    'absent' {Remove-Item -LiteralPath $saved.path}
    'run' {$record.run_id='f'*32}
    'transaction' {$record.transaction_id='f'*32}
    'pid' {$record.helper_process_id=$PID+1}
    'evidence_run' {$record.evidence_run_id='run-'+('f'*32)}
    'source_manifest' {$record.source_manifest_sha256='f'*64}
    'installed_manifest' {$record.installed_manifest_sha256='f'*64}
    'inventory' {$record.installed_inventory_sha256='f'*64}
    'aggregate' {$record.installed_aggregate_sha256='f'*64}
    'replacement' {[IO.File]::WriteAllText((Join-Path $proofRoot 'replacement-receipt.json'),'{}')}
    'unknown_field' {$record|Add-Member NoteProperty unknown_field 'unknown'}
    'changed_source' {[IO.File]::WriteAllText((Join-Path $source 'app\module.py'),'# changed fixture')}
}
if($case -notin @('valid','absent','replacement','changed_source')){
    # A fresh valid journal hash cannot make mismatched identity fields valid.
    [IO.File]::WriteAllText($saved.path,($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $proofRoot 'stages.jsonl'),(([ordered]@{event='REUSED_EVIDENCE_READY';path=$saved.path;sha256=Get-FileSha256 $saved.path}|ConvertTo-Json -Compress)+"`n"),[Text.UTF8Encoding]::new($false))
}
$rejected=$false
try{$read=Read-CanonicalReusedPlacementEvidence $binding $source $installed ([pscustomobject]$manifest) $transaction}
catch{$rejected=$true}
if($case -eq 'valid'){
    if($rejected -or $read.record.code_replaced -or $read.record.helper_process_id -ne $PID){throw 'valid current no-op rejected'}
}elseif(-not $rejected){throw 'invalid no-op admitted'}
Write-Output 'REUSED_EVIDENCE_PASS'
