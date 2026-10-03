"""ACL readback ignores DACL AI only; identity and permission drift stay rejected."""
import json
import os
from pathlib import Path
import uuid

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("ai", "order", "owner", "group", "protection", "ace", "inherited", "other_control", "invalid", "deny_order"))
def test_startup_task_restore_uses_permission_identity(tmp_path, engine, case):
    result = run_functions(
        tmp_path, ROOT / "INSTALL_THIS_PC.ps1", ["Restore-ContainerStartupUpdatePreimage"], r'''
. $env:CA_ACL_LIBRARY
$OperatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$managed=Join-Path $env:CA_CONTRACT_ROOT 'app'
$root=Join-Path $managed 'current'
$pre=Join-Path $managed ('.startup-update-install.'+[Guid]::NewGuid().ToString('N'))
foreach($path in @($root,$pre,(Join-Path $managed 'update-control'))){[void][IO.Directory]::CreateDirectory($path)}
$before='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+$OperatorSid+')'
if($env:CA_ACL_CASE -ceq 'deny_order'){$before+='(A;;FR;;;WD)(D;;FR;;;WD)'}
$Script:actual=$before
switch($env:CA_ACL_CASE){
 'ai' {$Script:actual=$before.Replace('D:P','D:PAI')}
 'order' {$Script:actual='O:BAG:BAD:PAI(A;;FA;;;BA)(A;;0x1200a9;;;'+$OperatorSid+')(A;;FA;;;SY)'}
 'owner' {$Script:actual=$before.Replace('O:BA','O:SY')}
 'group' {$Script:actual=$before.Replace('G:BA','G:SY')}
 'protection' {$Script:actual=$before.Replace('D:P','D:')}
 'ace' {$Script:actual=$before+'(A;;FW;;;WD)'}
 'inherited' {$Script:actual=$before.Replace('(A;;FA;;;SY)','(A;ID;FA;;;SY)')}
 'other_control' {$Script:actual=$before.Replace('D:P','D:PAR')}
 'invalid' {$Script:actual='invalid descriptor'}
 'deny_order' {$Script:actual=$before.Replace('(A;;FR;;;WD)(D;;FR;;;WD)','(D;;FR;;;WD)(A;;FR;;;WD)')}
}
$task=[pscustomobject]@{name=('KMTech.ContainerAudit.StartupUpdate.'+('a'*24));exists=$true;xml='<Task/>';sddl=$before}
$saved=[ordered]@{schema='container-audit-startup-update-install-preimage-v1';root=$root;operator_sid=$OperatorSid;task=$task;files=@(@{name='policy.json';exists=$false},@{name='active.json';exists=$false},@{name='transition.json';exists=$false})}
$path=Join-Path $pre 'preimage.json'
[IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 6))
function Assert-ContainerStartupUpdateTrust {param($Root)}
function Assert-NoReparsePoint {param($Path,$Purpose)}
function Test-PathWithin {param($Child,$Parent) return $Child.StartsWith($Parent+'\',[StringComparison]::OrdinalIgnoreCase)}
function Test-SamePath {param($First,$Second) return [IO.Path]::GetFullPath($First) -ieq [IO.Path]::GetFullPath($Second)}
function Get-ScheduledTask {param($TaskName,$ErrorAction) return $null}
function Register-ScheduledTask {param($TaskName,$Xml,[switch]$Force)}
function Invoke-ContainerStartupUpdateTaskMutation {param([scriptblock]$Operation) & $Operation}
$Script:registered=[pscustomobject]@{Xml='<Task/>'}
$Script:registered|Add-Member ScriptMethod SetSecurityDescriptor {param($Text,$Flags)}
$Script:registered|Add-Member ScriptMethod GetSecurityDescriptor {param($Flags) return $Script:actual}
$Script:folder=[pscustomobject]@{}
$Script:folder|Add-Member ScriptMethod GetTask {param($Name) return $Script:registered}
$Script:service=[pscustomobject]@{}
$Script:service|Add-Member ScriptMethod Connect {}
$Script:service|Add-Member ScriptMethod GetFolder {param($Path) return $Script:folder}
function New-Object {param($ComObject) if($ComObject -cne 'Schedule.Service'){throw 'Unexpected native object'};return $Script:service}
$rejected=$false
try {Restore-ContainerStartupUpdatePreimage $root $pre (Get-FileSha256 $path)}catch{$rejected=$true}
[ordered]@{rejected=$rejected}|ConvertTo-Json -Compress
''', engine=engine, values={"CA_ACL_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"), "CA_ACL_CASE": case},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["rejected"] is (case not in ("ai", "order"))


@pytest.mark.skipif(os.name != "nt", reason="native NTFS descriptor readback")
@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_native_acl_mutations_remain_different(tmp_path, engine):
    native = Path(os.environ.get("CA_NTFS_TEST_ROOT", str(tmp_path))) / ("acl-" + uuid.uuid4().hex[:8])
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Get-BootstrapAclComparisonKey"], r'''
$root=[IO.Path]::GetFullPath($env:CA_NATIVE_ACL_ROOT)
[void][IO.Directory]::CreateDirectory($root)
$sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
function Read-Sddl {return (Get-Acl -LiteralPath $root).GetSecurityDescriptorSddlForm($sections)}
$acl=[Security.AccessControl.DirectorySecurity]::new($root,[Security.AccessControl.AccessControlSections]::Access)
$acl.SetAccessRuleProtection($true,$true)
function Persist($Acl){if($PSVersionTable.PSEdition -ceq 'Core'){[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($root),$Acl)}else{[IO.Directory]::SetAccessControl($root,$Acl)}}
Persist $acl
$before=Read-Sddl
$changed=[Security.AccessControl.DirectorySecurity]::new($root,[Security.AccessControl.AccessControlSections]::Access)
$changed.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Write','Allow'))
Persist $changed
$extra=Read-Sddl
$changed.SetAccessRuleProtection($false,$true);Persist $changed
$unprotected=Read-Sddl
if((Get-BootstrapAclComparisonKey $before) -ceq (Get-BootstrapAclComparisonKey $extra)){throw 'Native ACE addition was admitted'}
if((Get-BootstrapAclComparisonKey $extra) -ceq (Get-BootstrapAclComparisonKey $unprotected)){throw 'Native protection removal was admitted'}
'PASS'
''', engine=engine, values={"CA_NATIVE_ACL_ROOT": str(native)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "PASS"
