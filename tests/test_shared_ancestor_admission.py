"""Shared literal ancestors use native target-shape admission, never leaf rights."""
import os
from pathlib import Path
import uuid

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = Path(os.environ.get('CA_SHARED_ADMISSION_SOURCE_ROOT', str(ROOT)))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('guard', ('relay', 'evidence', 'installer', 'updater', 'recovery'))
@pytest.mark.parametrize('scenario', ('target', 'target_kmtech', 'default', 'extra_write', 'user_owner', 'reparse', 'nonliteral'))
def test_native_shared_ancestor_admission(tmp_path, engine, guard, scenario):
    native_root = Path(os.environ.get('CA_NTFS_TEST_ROOT', str(tmp_path))) / ('a-' + uuid.uuid4().hex[:8])
    result = run_functions(tmp_path, SOURCE_ROOT / 'tools/bootstrap_integrity.ps1', [
        'Protect-KmtechCodeAncestors', 'Assert-BootstrapProtectedRelayPath',
        'Assert-InstallationEvidenceProtectedPath', 'Get-StrictFullPath',
        'New-InstallationProtectedDirectory', 'Set-InstallationEvidenceAcl',
        'Assert-BootstrapNoReparsePoint',
    ], r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:nativeRoot=[IO.Path]::GetFullPath($env:CA_NATIVE_ROOT)
[void][IO.Directory]::CreateDirectory($script:nativeRoot)
$script:mapped=@{'C:\'=Join-Path $script:nativeRoot 'volume';'C:\KMTech'=Join-Path $script:nativeRoot 'volume\KMTech';'C:\KMTech\Apps'=Join-Path $script:nativeRoot 'volume\KMTech\Apps';'C:\KMTech\Apps\Container_Audit'=Join-Path $script:nativeRoot 'volume\KMTech\Apps\Container_Audit';'C:\Mirror'=Join-Path $script:nativeRoot 'mirror'}
function Native-Path([string]$Path){if(-not $script:mapped.ContainsKey($Path)){throw ('Unmapped native fixture path: '+$Path)};return $script:mapped[$Path]}
function Test-Path {param($LiteralPath) Microsoft.PowerShell.Management\Test-Path -LiteralPath (Native-Path $LiteralPath)}
function Get-Item {param($LiteralPath,$ErrorAction,[switch]$Force) Microsoft.PowerShell.Management\Get-Item -LiteralPath (Native-Path $LiteralPath) -ErrorAction Stop}
function Get-Acl {param($LiteralPath,$ErrorAction)
 $acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath (Native-Path $LiteralPath)
 # The host is non-elevated: translate only privileged owner admission. The
 # descriptors, flags, inheritance and reparse attributes are actual NTFS.
 if($env:CA_NATIVE_SCENARIO -cne 'user_owner' -or $LiteralPath -cne 'C:\KMTech\Apps'){$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))}
 return $acl
}
function Write-InstallationEvidenceEvent {param($Payload)}
function Write-InstallationCaughtFailure {param($Failure)}
function Test-InstallationEvidencePrivileged {return $true}
function Get-InstallationEvidenceControlRoot {return 'C:\KMTech\Apps\Container_Audit\update-control'}
function Set-Acl {throw 'Admission attempted an ACL write.'}
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class AncestorAdmissionFixture {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool SetFileSecurityW(string path,uint flags,byte[] descriptor);
}
'@
function Set-FixtureDacl([string]$Path,[string]$Sddl){
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl);$bytes=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($bytes,0)
 if(-not[AncestorAdmissionFixture]::SetFileSecurityW($Path,[uint32]2147483652,$bytes)){throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())}
}
$original=(Microsoft.PowerShell.Security\Get-Acl -LiteralPath $script:nativeRoot).Sddl
$target='D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;;0x1200af;;;AU)(A;OICIIO;SDGXGWGR;;;AU)'
foreach($literal in @('C:\','C:\KMTech','C:\KMTech\Apps','C:\KMTech\Apps\Container_Audit','C:\Mirror')){[void][IO.Directory]::CreateDirectory((Native-Path $literal))}
foreach($literal in @('C:\KMTech','C:\KMTech\Apps','C:\Mirror')){Set-FixtureDacl (Native-Path $literal) $target}
Set-FixtureDacl (Native-Path 'C:\') 'D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200af;;;AU)(A;OICIIO;SDGXGWGR;;;AU)'
Set-FixtureDacl (Native-Path 'C:\KMTech\Apps\Container_Audit') ('D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;'+$sid+')')
$junction=$null
try{
 if($env:CA_NATIVE_SCENARIO -ceq 'default'){
  Set-FixtureDacl (Native-Path 'C:\KMTech') 'D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)'
 }
 if($env:CA_NATIVE_SCENARIO -ceq 'extra_write'){
  $acl=Microsoft.PowerShell.Security\Get-Acl -LiteralPath (Native-Path 'C:\KMTech\Apps')
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Write','Allow'))
  Set-FixtureDacl (Native-Path 'C:\KMTech\Apps') ($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
 }
 if($env:CA_NATIVE_SCENARIO -ceq 'reparse'){
  $junction=Native-Path 'C:\KMTech\Apps';$destination=Join-Path $script:nativeRoot 'redirect'
  Set-FixtureDacl $junction $original
  [IO.Directory]::Move($junction,$destination)
  [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $junction -Target $destination)
 }
 $before=@{};foreach($literal in $script:mapped.Keys){$before[$literal]=(Microsoft.PowerShell.Security\Get-Acl -LiteralPath (Native-Path $literal)).Sddl}
 if($env:CA_NATIVE_GUARD -in @('installer','updater')){
  $relative=if($env:CA_NATIVE_GUARD -ceq 'installer'){'INSTALL_THIS_PC.ps1'}else{'tools\apply_prepared_update.ps1'}
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:CA_NATIVE_REPO $relative),[ref]$tokens,[ref]$errors)
  $name=if($env:CA_NATIVE_GUARD -ceq 'installer'){'Assert-ProtectedCodeAncestors'}else{'Assert-Protected'}
  $definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
  if($errors.Count -or $null -eq $definition){throw 'Actual guard unavailable'}
  Invoke-Expression $definition.Extent.Text
  if($env:CA_NATIVE_GUARD -ceq 'updater'){$script:StartupUpdateBootstrapLoaded=$true}
 }
 $path=if($env:CA_NATIVE_SCENARIO -ceq 'nonliteral'){'C:\Mirror'}elseif($env:CA_NATIVE_SCENARIO -ceq 'target_kmtech'){'C:\KMTech'}else{'C:\KMTech\Apps'}
 $failure=$null
 try{
  switch($env:CA_NATIVE_GUARD){
   relay {Assert-BootstrapProtectedRelayPath $path}
   evidence {Assert-InstallationEvidenceProtectedPath $path}
   installer {Assert-ProtectedCodeAncestors $path}
   updater {Assert-Protected $path}
   recovery {if($env:CA_NATIVE_SCENARIO -ceq 'nonliteral'){Assert-InstallationEvidenceProtectedPath $path}else{New-InstallationProtectedDirectory 'C:\KMTech\Apps\Container_Audit' $sid -RecoverAbandoned}}
  }
 }catch{$failure=$_.Exception}
 $chain=@();$inner=$failure;while($inner){$chain+=,$inner.Message;$inner=$inner.InnerException}
 [IO.File]::WriteAllText((Join-Path $script:nativeRoot 'diagnosis.json'),([ordered]@{scenario=$env:CA_NATIVE_SCENARIO;guard=$env:CA_NATIVE_GUARD;chain=$chain;before=$before}|ConvertTo-Json -Depth 8))
 $expectedPass=$env:CA_NATIVE_SCENARIO -in @('target','target_kmtech')
 if($expectedPass -and $null -ne $failure){throw $failure}
 if(-not $expectedPass -and $null -eq $failure){throw 'Unsupported native ancestor was admitted.'}
 if($null -ne $failure){
  $expected=if($env:CA_NATIVE_SCENARIO -ceq 'reparse'){
   switch($env:CA_NATIVE_GUARD){installer{'Unsafe update path component.'}updater{'Reparse point in update storage.'}default{'Relay path contains a reparse point.'}}
  }elseif($env:CA_NATIVE_SCENARIO -ceq 'user_owner'){'owner is not privileged'}else{'user mutable'}
  if(-not(($chain -join ';').Contains($expected))){throw ('Rejection diagnostic changed: '+($chain -join ';'))}
 }
 $diff=0;foreach($literal in $script:mapped.Keys){if($before[$literal] -cne (Microsoft.PowerShell.Security\Get-Acl -LiteralPath (Native-Path $literal)).Sddl){$diff++}}
 if($diff){throw 'Admission changed an NTFS descriptor.'}
 [IO.File]::WriteAllText((Join-Path $script:nativeRoot 'proof.json'),([ordered]@{engine=$PSVersionTable.PSVersion.ToString();guard=$env:CA_NATIVE_GUARD;scenario=$env:CA_NATIVE_SCENARIO;owner_admission_seam=$true;real_ntfs=$true;acl_diff=$diff;failure=$(if($failure){$failure.Message}else{$null});before=$before}|ConvertTo-Json -Depth 8))
 'PASS'
}finally{
 foreach($literal in @('C:\Mirror','C:\KMTech\Apps\Container_Audit','C:\KMTech\Apps','C:\KMTech','C:\')){
  $native=Native-Path $literal
  if(Microsoft.PowerShell.Management\Test-Path -LiteralPath $native){Set-FixtureDacl $native $original}
 }
}
''', engine=engine, values={'CA_NATIVE_ROOT': str(native_root), 'CA_NATIVE_SCENARIO': scenario,
                           'CA_NATIVE_GUARD': guard, 'CA_NATIVE_REPO': str(SOURCE_ROOT)})
    assert result.returncode == 0, result.stdout + result.stderr
