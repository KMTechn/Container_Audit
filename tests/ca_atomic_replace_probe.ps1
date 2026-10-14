param([string]$Library,[string]$Root,[string]$Receipt)
$ErrorActionPreference='Stop'
. $Library
$Script:OriginalAtomicOnce=(Get-Item Function:\Invoke-ContainerAtomicReplaceOnce).ScriptBlock
function Invoke-ContainerAtomicReplaceOnce([string]$Source,[string]$Destination,[string]$Mode,[string]$Backup) {
    $Script:AtomicAttempts++
    try { & $Script:OriginalAtomicOnce $Source $Destination $Mode $Backup }
    catch {
        if ($null -eq $Script:AtomicFirst) { $Script:AtomicFirst=$_ }
        throw
    }
}
function Start-Sleep([int]$Milliseconds) {
    if ($Script:ReleaseOnSleep) {
        $Script:Reader.Dispose();$Script:Reader=$null
        $Script:ReleaseOnSleep=$false
    }
    Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $Milliseconds
}
function Reset-AtomicProbe {
    $Script:AtomicAttempts=0;$Script:AtomicFirst=$null;$Script:ReleaseOnSleep=$false
}
$rows=@()
foreach($mode in @('Replace','WriteThrough')) {
    Reset-AtomicProbe
    $target=Join-Path $Root ($mode+'.json');$source=$target+'.new'
    [IO.File]::WriteAllText($target,'old');[IO.File]::WriteAllText($source,'new')
    $Script:Reader=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $Script:ReleaseOnSleep=$true
    try { Invoke-ContainerAtomicReplace $source $target -Mode $mode }
    finally { if($Script:Reader){$Script:Reader.Dispose()} }
    $rows+=@{case=('overlap-'+$mode);attempts=$Script:AtomicAttempts;first_present=($null -ne $Script:AtomicFirst);value=[IO.File]::ReadAllText($target)}
}
foreach($mode in @('Replace','WriteThrough')) {
    Reset-AtomicProbe
    $target=Join-Path $Root ('persistent-'+$mode+'.json');$source=$target+'.new'
    [IO.File]::WriteAllText($target,'old');[IO.File]::WriteAllText($source,'new')
    $Script:Reader=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $clock=[Diagnostics.Stopwatch]::StartNew();$caught=$null
    try { Invoke-ContainerAtomicReplace $source $target -Mode $mode }
    catch { $caught=$_ }
    finally { $Script:Reader.Dispose();$Script:Reader=$null }
    $rows+=@{case=('persistent-'+$mode);attempts=$Script:AtomicAttempts;seconds=$clock.Elapsed.TotalSeconds;
        original=($null -ne $caught -and [object]::ReferenceEquals($caught.Exception,$Script:AtomicFirst.Exception));
        source_preserved=[IO.File]::Exists($source);value=[IO.File]::ReadAllText($target)}
}
Reset-AtomicProbe
$target=Join-Path $Root 'missing.json';[IO.File]::WriteAllText($target,'old')
$caught=$null
try { Invoke-ContainerAtomicReplace (Join-Path $Root 'absent') $target -Mode Replace }
catch { $caught=$_ }
$rows+=@{case='missing';attempts=$Script:AtomicAttempts;original=($null -ne $caught -and [object]::ReferenceEquals($caught.Exception,$Script:AtomicFirst.Exception))}
Reset-AtomicProbe
$source=Join-Path $Root 'create.new';$target=Join-Path $Root 'create.json'
[IO.File]::WriteAllText($source,'new');[IO.File]::WriteAllText($target,'old');$caught=$null
try { Invoke-ContainerAtomicReplace $source $target -Mode CreateNew }
catch { $caught=$_ }
$rows+=@{case='create-collision';attempts=$Script:AtomicAttempts;failed=($null -ne $caught);value=[IO.File]::ReadAllText($target);source_preserved=[IO.File]::Exists($source)}
Reset-AtomicProbe
$source=Join-Path $Root 'backup.new';$target=Join-Path $Root 'backup.json';$backup=Join-Path $Root 'backup.old'
[IO.File]::WriteAllText($source,'new');[IO.File]::WriteAllText($target,'old')
Invoke-ContainerAtomicReplace $source $target -Mode Replace -Backup $backup
$rows+=@{case='backup';attempts=$Script:AtomicAttempts;value=[IO.File]::ReadAllText($target);backup=[IO.File]::ReadAllText($backup)}
[IO.File]::WriteAllText($Receipt,($rows|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
