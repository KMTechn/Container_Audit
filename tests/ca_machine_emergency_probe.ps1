$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
trap {
    $frames=@([regex]::Matches($_.ScriptStackTrace,'at ([\w-]+), .*?: line (\d+)') | ForEach-Object {@{function=$_.Groups[1].Value;line=[int]$_.Groups[2].Value}})
    $meta=@{type=$_.Exception.GetType().Name;error_id=$_.FullyQualifiedErrorId;frames=$frames}
    [IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'machine-probe-failure.json'),($meta|ConvertTo-Json -Depth 6))
    break
}
$env:KMTECH_TEST_CA_WORKER_SHORTCUT_ROOT=Join-Path $env:CA_CONTRACT_ROOT 'known-folders'
. $env:CA_BOOTSTRAP_SOURCE
function Full([string]$Path,[string]$Purpose){return [IO.Path]::GetFullPath($Path)}
function Same([string]$First,[string]$Second){return [IO.Path]::GetFullPath($First) -ieq [IO.Path]::GetFullPath($Second)}
function Sha([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
$base=Join-Path $env:CA_CONTRACT_ROOT 'application'
$root=Join-Path $base 'current'
$programs=Join-Path $env:CA_CONTRACT_ROOT 'programs'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'app\assets'))
[void][IO.Directory]::CreateDirectory($programs)
# Substitute only the OS known-folder query, retaining the machine function's
# real ownership, preimage and emergency-path branches on the temporary drive.
$parseTokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'machine source parse failed'}
$definition=($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-CanonicalMachineArtifactPaths'},$false))[0].Extent.Text
$knownFolder='[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)'
if(([regex]::Matches($definition,[regex]::Escape($knownFolder))).Count -ne 1){throw 'known-folder boundary differs'}
. ([scriptblock]::Create($definition.Replace($knownFolder,"(Join-Path `$env:CA_CONTRACT_ROOT 'programs')")))
$launcher=Join-Path $root 'launch-container-audit.cmd'
[IO.File]::WriteAllText($launcher,'exit /b 0')
[IO.File]::WriteAllBytes((Join-Path $root 'app\assets\logo.ico'),[byte[]]@(0))
$emergency=Get-BootstrapEmergencyShortcutPath $root
$shell=New-Object -ComObject WScript.Shell
try{
    $paths=@(Get-CanonicalMachineArtifactPaths $env:CA_CONTRACT_ROOT $root)
    if($paths.Count -ne 3 -or $paths[2] -ine $emergency){throw 'emergency preimage route missing'}
    $before=@(Get-CanonicalMachineArtifactPreimage @($emergency))
    if($before.Count -ne 1 -or $before[0].exists){throw 'fresh emergency preimage differs'}
    New-CanonicalMachineShortcut $root $programs
    Restore-CanonicalMachineArtifacts $before
    if(Test-Path -LiteralPath $emergency){throw 'failed fresh installation retained emergency link'}
    # Fresh machine install, same-current reinstall, then changed current bytes.
    foreach($phase in @('fresh','reinstall','update')){
        if($phase -eq 'update'){[IO.File]::WriteAllText($launcher,'exit /b 1')}
        New-CanonicalMachineShortcut $root $programs
        if(-not [IO.File]::Exists($emergency)){throw 'machine emergency link absent'}
        $link=$shell.CreateShortcut($emergency)
        if($link.TargetPath -ine $launcher -or $link.Arguments -cne '--ui tk' -or
            $link.WorkingDirectory -ine $root -or $link.IconLocation -ine ((Join-Path $root 'app\assets\logo.ico')+',0')){
            throw 'machine emergency link readback differs'
        }
    }
    # Restoration to an existing current preserves the owned emergency link.
    $pending=Join-Path $env:CA_CONTRACT_ROOT 'pending.json'
    $normal=Join-Path $programs 'KMTech 이적 검사.lnk'
    Remove-CanonicalMachineArtifacts $root ([pscustomobject]@{sid='unused'}) @($pending,$normal)
    if(-not [IO.File]::Exists($emergency)){throw 'restore removed emergency link'}
    New-CanonicalMachineShortcut $root $programs
    # Actual code removal has already made current's launcher absent.
    Remove-Item -LiteralPath $launcher
    Remove-CanonicalMachineArtifacts $root ([pscustomobject]@{sid='unused'}) @($pending,$normal)
    if(Test-Path -LiteralPath $emergency){throw 'machine removal retained emergency link'}
    if(Test-Path -LiteralPath (Split-Path -Parent $emergency)){throw 'empty management directory retained'}
    # Foreign files are never included in our journal or modified by creation.
    [IO.File]::WriteAllText($launcher,'exit /b 0')
    $directory=Split-Path -Parent $emergency
    [void][IO.Directory]::CreateDirectory($directory)
    $foreign=Join-Path $directory 'foreign.txt'
    [IO.File]::WriteAllText($foreign,'foreign')
    $paths=@(Get-CanonicalMachineArtifactPaths $env:CA_CONTRACT_ROOT $root)
    if($paths.Count -ne 2){throw 'foreign directory entered recovery journal'}
$foreignPublicationRefused=$false
try {     New-CanonicalMachineShortcut $root $programs -WarningAction SilentlyContinue } catch {
    if($_.Exception.Message -cne 'EMERGENCY_SHORTCUT_PUBLICATION_BLOCKED'){throw}
    $foreignPublicationRefused=$true
}
if(-not $foreignPublicationRefused){throw 'Foreign emergency publication was accepted.'}
    if(Test-Path -LiteralPath $emergency){throw 'foreign directory changed'}
    if([IO.File]::ReadAllText($foreign) -cne 'foreign'){throw 'foreign data changed'}
}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
Write-Output 'MACHINE_EMERGENCY_PASS'
