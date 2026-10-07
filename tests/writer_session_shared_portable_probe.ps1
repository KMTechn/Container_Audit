param([string]$CodeRoot,[string]$FixtureRoot,[ValidateSet('normal','managed','loader')][string]$Case)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$writer=Join-Path $CodeRoot 'tools\container_writer_session.ps1'
$tokens=$null;$errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($writer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Writer entrypoint does not parse.'}
# Execute the entrypoint's actual top-level dot-source statements, in order.
# Its later lifecycle dispatcher is outside this dependency-loading probe.
$loads=@($tree.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.PipelineAst] -and
    $_.PipelineElements.Count -eq 1 -and
    $_.PipelineElements[0] -is [Management.Automation.Language.CommandAst] -and
    $_.PipelineElements[0].InvocationOperator -eq [Management.Automation.Language.TokenKind]::Dot
})
$Script:IntegrityHelperPath=Join-Path $CodeRoot 'tools\bootstrap_integrity.ps1'
$Script:WriterFenceHelperPath=Join-Path $CodeRoot 'tools\container_writer_fence.ps1'
$record=[ordered]@{case=$Case;engine_version=$PSVersionTable.PSVersion.ToString();loader_count=$loads.Count;bootstrap_sha256='';
    status='RED';reader_loaded=$false;reader_leaf_sha256='';missing_reader=$false;reject_code='';exception_type='';location_module='';location_line=0;
    native_api_compiled=$false;managed_identity_verified=$false;host_dispatch_attempted=$false}
try {
    foreach($load in $loads){. ([ScriptBlock]::Create($load.Extent.Text))}
    $record.bootstrap_sha256=Get-FileSha256 (Get-Command Import-BootstrapCanonicalUserProcessApi).ScriptBlock.File
    $record.reader_loaded=$null -ne (Get-Command Read-KmtechPortableManifest -CommandType Function -ErrorAction SilentlyContinue)
    if($record.reader_loaded){$record.reader_leaf_sha256=Get-FileSha256 (Get-Command Read-KmtechPortableManifest).ScriptBlock.File}
    if($Case -ceq 'loader'){$record.status='LOADED'}
    elseif($Case -ceq 'normal'){
        $Script:ProbeSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        # Isolate the host token/evidence/dispatch boundaries, retaining the real
        # elevated branch, manifest reader, byte verification and native API.
        function Get-BootstrapRelaySecurity {return [pscustomobject]@{sid=$Script:ProbeSid;session_id=1;elevated=$true;integrity_level=12288}}
        function Initialize-InstallationEvidence {return (Join-Path $FixtureRoot 'capture')}
        function Set-InstallationEvidenceStage {}
        function New-InstallationMemoryTransport {$Script:PastNativeImport=$true;throw 'SHARED_PROBE_AFTER_NATIVE_IMPORT'}
        function Remove-InstallationMemoryTransport {}
        function Start-BootstrapNormalProducerWrapper {$record.host_dispatch_attempted=$true;throw 'Unexpected host dispatch in shared dependency probe.'}
        $Script:PastNativeImport=$false
        $producer=Join-Path $FixtureRoot 'producer'
        try {
            [void](Invoke-BootstrapNormalFiniteProducer $producer 'inert.exe' @('inert.py') (Join-Path $FixtureRoot 'finite'))
            throw 'Finite producer unexpectedly returned before the probe boundary.'
        }catch{
            if($_.Exception.Message -cne 'SHARED_PROBE_AFTER_NATIVE_IMPORT'){throw}
        }
        $record.native_api_compiled=$Script:PastNativeImport -and
            $null -ne [ContainerAuditCanonicalUserProcess].GetMethod('StartLimitedWithOverrides')
        if(-not $record.native_api_compiled){throw 'Actual verified normal-user API was not reached.'}
        $record.status='PASS'
    }else{
        # Installed-path ACL/inventory admission are host boundaries. No reader
        # or identity function is replaced; their actual managed branch runs.
        function Assert-BootstrapProtectedRelayPath {}
        function Assert-BootstrapIntegrityRecord {return [pscustomobject]@{aggregate_sha256=('c'*64)}}
        $current=Join-Path $FixtureRoot 'install\current'
        $runtime=Join-Path $current 'runtime\pythonw.exe'
        $run=(ConvertTo-BootstrapRelayArgument $runtime)+' -I -B '+
            (ConvertTo-BootstrapRelayArgument (Join-Path $current 'app\auto_update.py'))+
            ' --bootstrap --role relay -- --container-audit-user-relay'
        $identity=Get-BootstrapRelayExpectedIdentity $current $run
        $sha='a'*40
        $bundle=Join-Path $FixtureRoot ('install\versions\'+$sha)
        $record.managed_identity_verified=$identity.managed -and $identity.requires_status_identity -and
            $identity.source_commit -ceq $sha -and
            $identity.manifest_sha256 -ceq (Get-FileSha256 (Join-Path $bundle 'portable-manifest.json')) -and
            $identity.aggregate_sha256 -ceq ('c'*64) -and
            (Test-BootstrapSamePath $identity.root $bundle) -and
            (Test-BootstrapSamePath $identity.executable (Join-Path $bundle 'runtime\pythonw.exe'))
        if(-not $record.managed_identity_verified){throw 'Actual managed relay identity differs.'}
        $record.status='PASS'
    }
}catch{
    $record.exception_type=$_.Exception.GetType().FullName
    $record.location_module=[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)
    $record.location_line=$_.InvocationInfo.ScriptLineNumber
    $record.missing_reader=$_.Exception -is [Management.Automation.CommandNotFoundException] -and
        $_.Exception.CommandName -ceq 'Read-KmtechPortableManifest'
    if($_.Exception.Message -ceq 'Portable manifest is oversized.'){$record.reject_code='MANIFEST_OVERSIZED'}
    elseif($_.Exception.Message -cin @('Normal-user process API byte pin differs.','Relay active manifest binding differs.')){$record.reject_code='MANIFEST_BINDING_DIFFERS'}
    elseif($_.FullyQualifiedErrorId -match 'ConvertFromJson'){$record.reject_code='MANIFEST_JSON_INVALID'}
    if($Case -ceq 'loader'){
        if($_.Exception.Message -ceq 'shared installer input is unavailable.'){$record.reject_code='INPUT_UNAVAILABLE'}
        elseif($_.Exception.Message -ceq 'Shared installer input must be a file.'){$record.reject_code='INPUT_NOT_FILE'}
        elseif($_.Exception.Message -ceq 'Shared PowerShell leaf pin mismatch.'){$record.reject_code='LEAF_PIN_MISMATCH'}
        if($record.reject_code){$record.status='REJECTED'}
    }
}
$json=$record|ConvertTo-Json -Depth 4 -Compress
[IO.File]::WriteAllText((Join-Path $FixtureRoot ('writer-shared-'+$Case+'-'+$PSVersionTable.PSVersion.Major+'.json')),$json,[Text.UTF8Encoding]::new($false))
$json
