param([string]$Fence,[string]$Library,[string]$Root,[string]$Receipt)
$ErrorActionPreference='Stop'
. $Fence
$cold=[bool](Get-Command Invoke-ContainerAtomicReplace -CommandType Function -ErrorAction SilentlyContinue)
$original=(Get-Item Function:\Invoke-ContainerAtomicReplace).ScriptBlock
$copyFence=Join-Path $Root 'container_writer_fence.ps1'
$copyLibrary=Join-Path $Root 'bootstrap_integrity.ps1'
[IO.File]::WriteAllBytes($copyFence,[IO.File]::ReadAllBytes($Fence))
[IO.File]::WriteAllText($copyLibrary,'throw "unverified bootstrap evaluated"',[Text.UTF8Encoding]::new($false))
. $copyFence
$cached=[object]::ReferenceEquals($original,(Get-Item Function:\Invoke-ContainerAtomicReplace).ScriptBlock)
Remove-Item Function:\Invoke-ContainerAtomicReplace
Remove-Item Function:\Invoke-ContainerAtomicReplaceOnce
$rejected=$false
try { . $copyFence }
catch { $rejected=$_.Exception.Message -ceq 'Atomic bootstrap library byte pin differs.' }
[IO.File]::WriteAllText($Receipt,(@{cold=$cold;cached=$cached;rejected=$rejected}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
