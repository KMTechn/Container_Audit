param([string]$Root,[string]$Scratch,[string]$Proof)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'PS51_REQUIRED' }
. (Join-Path $Root 'tools/bootstrap_integrity.ps1')
. (Join-Path $Root 'kmtech_shared/powershell/portable.ps1')
# Load canonical definitions into a fresh process, never its installer entrypoint.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'CANONICAL_PARSE_FAILED'}
foreach($statement in $ast.EndBlock.Statements){
    if($statement -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($statement.Extent.Text))}
}
$verifiedScript=${function:Get-InstallationVerifiedScript}
# Replace only OS registry observations, preserving the verified helper's real
# binding, path comparisons, receipt reader and proof-selection functions.
Add-Type @'
public class RemovalScopeRegistry {
    public static RemovalScopeRegistry LocalMachine = new RemovalScopeRegistry();
    public static RemovalScopeRegistry Users = new RemovalScopeRegistry();
    public static string Profile;
    public static string Proof;
    public object OpenSubKey(string name, bool writable) {
        if (name.StartsWith("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"))
            return Proof == "PROFILE_ABSENT" ? null : new RemovalScopeRegistry();
        return Proof == "NEVER_STARTED" && name.StartsWith("S-") ? new RemovalScopeRegistry() : null;
    }
    public object GetValue(string name) { return Profile; }
    public string[] GetValueNames() { return new string[0]; }
    public void Dispose() {}
}
'@
function Get-InstallationVerifiedScript([string]$Path,[string]$ExpectedSha256) {
    $verified=& $verifiedScript $Path $ExpectedSha256
    $text=$verified.Ast.Extent.Text.Replace('[Microsoft.Win32.Registry]','[RemovalScopeRegistry]')
    return [scriptblock]::Create($text)
}
$testMode=$true
$sid='S-'+(@(1,5,21,123456781,123456782,123456783,1001)-join '-')
$profile=Join-Path $Scratch 'profile'
$local=Join-Path $profile 'AppData/Local'
$rootPath=Join-Path $Scratch 'apps/current'
$statePath=Join-Path $Scratch 'machine-install'
$policyPath=Join-Path (Split-Path -Parent $rootPath) 'update-control/policy.json'
[void][IO.Directory]::CreateDirectory($statePath)
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $policyPath))
function Get-ContainerMachineInstallStateRoot { return $statePath }
function Get-LocalUser {
    [pscustomobject]@{SID=[Security.Principal.SecurityIdentifier]::new($sid);Enabled=($Proof -ne 'ACCOUNT_UNAVAILABLE')}
}
[RemovalScopeRegistry]::Profile=$profile
[RemovalScopeRegistry]::Proof=$Proof
@{schema='container-audit-machine-pending-v1';status='PENDING';install_root=$rootPath;target_sid=$sid} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $statePath 'pending-onboarding.json') -Encoding UTF8
@{operator_sid=$sid;operator_local_app_data=$local} | ConvertTo-Json | Set-Content -LiteralPath $policyPath -Encoding UTF8
if($Proof -ne 'PROFILE_ABSENT'){[void][IO.Directory]::CreateDirectory($local)}
if($Proof -eq 'USER_RECEIPT'){
    $receipt=Join-Path $local 'KMTech/DirectSync/container_audit/status/current_user_removal.json'
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $receipt))
    @{operator_sid=$sid;status='PASS_DATA_PRESERVED'} | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
$manifest=@{helper_sha256=(Get-FileHash -LiteralPath (Join-Path $Root 'INSTALL_THIS_PC.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()}
Assert-CanonicalMachineRemovalWorkerPart ([pscustomobject]@{sid=$sid;profile_root=$profile}) $Root $rootPath $manifest
if($Script:ContainerMachineRemovalProofKind -cne $Proof){throw 'PROOF_DIFFERS'}
if($Proof -eq 'ACCOUNT_UNAVAILABLE' -and $null -ne $Script:ContainerMachineRemovalWorkerRunPresent){throw 'RUN_OBSERVATION_DIFFERS'}
Write-Output ('PASS '+$Proof)
