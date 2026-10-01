"""Exercise the literal two-folder operation entirely through memory-only seams."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


def test_shipped_installers_keep_utf8_bom_for_windows_powershell_korean_errors():
    for relative in ('INSTALL_THIS_PC.ps1', 'INSTALL_CANONICAL_PORTABLE.ps1', 'tools/bootstrap_integrity.ps1'):
        assert (ROOT / relative).read_bytes().startswith(b'\xef\xbb\xbf'), relative


def test_windows_powershell_decodes_actual_shared_rejection_literal(tmp_path):
    result = run_functions(tmp_path, ROOT/'tools/bootstrap_integrity.ps1', ['Protect-KmtechCodeAncestors'], r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_REAL_HELPER,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual shipped helper parse failed.'}
$functions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Protect-KmtechCodeAncestors'},$true))
if($functions.Count -ne 1){throw 'Actual shipped rejection function missing.'}
. ([scriptblock]::Create($functions[0].Extent.Text))
function Test-Path {param($LiteralPath) return $true}
function Get-Item {param($LiteralPath,$ErrorAction) return [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory}}
function Get-Acl {param($LiteralPath,$ErrorAction)
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetSecurityDescriptorSddlForm('O:S-1-5-21-1-2-3-1000G:BAD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;0xe0010000;;;AU)')
 return $acl
}
function Set-Acl {throw 'Rejected shape performed an ACL write.'}
function Write-InstallationEvidenceEvent {param($Payload)}
$rejected=$false
try{[void](Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit')}
catch{
 $rejected=$true
 $expected='설치 폴더 권한을 확인하세요: C:\KMTech (폴더 소유자가 예상과 다릅니다). 지원 담당자에게 문의하세요.'
 if($_.Exception.Message -cne $expected){throw 'Actual PS5 file decoding changed the Korean rejection.'}
}
if(-not $rejected){throw 'User-owned ancestor was admitted.'}
'PASS'
''', engine='powershell.exe', values={'CA_REAL_HELPER': str(ROOT/'tools/bootstrap_integrity.ps1')})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('scenario', ('default', 'target', 'user_owner', 'deny', 'extra_sid', 'partial', 'reparse', 'post_guard_failure'))
def test_shared_protection_admits_only_reviewed_shapes_and_keeps_creation(tmp_path, engine, scenario):
    result = run_functions(tmp_path, ROOT/'tools/bootstrap_integrity.ps1', ['Protect-KmtechCodeAncestors'], r'''
$ErrorActionPreference='Stop'
$script:events=@();$script:writes=@();$script:acls=@{}
function Write-InstallationEvidenceEvent {param($Payload) $script:events+=,$Payload}
function Write-InstallationCaughtFailure {param($Failure)}
function Test-Path {param($LiteralPath) return $true}
function Get-Item {param($LiteralPath,$ErrorAction) return [pscustomobject]@{Attributes=if($env:CA_SHAPE_SCENARIO -ceq 'reparse' -and $LiteralPath -ceq 'C:\KMTech\Apps'){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory}}}
function Get-Acl {param($LiteralPath,$ErrorAction)
 $copy=[Security.AccessControl.DirectorySecurity]::new()
 $copy.SetSecurityDescriptorBinaryForm($script:acls[$LiteralPath].GetSecurityDescriptorBinaryForm())
 return $copy
}
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction)
 if($LiteralPath -notin @('C:\KMTech','C:\KMTech\Apps')){throw 'Nonliteral target was written.'}
 $script:writes+=,$LiteralPath;$script:acls[$LiteralPath]=$AclObject
}
function Assert-ProtectedCodeAncestors {param($Path)
 if($Path -cne 'C:\KMTech\Apps\Container_Audit'){throw 'Wrong guarded leaf.'}
 if($env:CA_SHAPE_SCENARIO -ceq 'post_guard_failure'){throw 'injected actual guard rejection'}
 foreach($acl in $script:acls.Values){
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   if($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and -not ($rule.PropagationFlags -band 2) -and ([int64]$rule.FileSystemRights -band 0x500D0150)){throw 'Guard-denied bits remain.'}
  }
 }
}
foreach($path in @('C:\KMTech','C:\KMTech\Apps')){
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $sddl='O:BAG:BAD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;0xe0010000;;;AU)'
 if($env:CA_SHAPE_SCENARIO -ceq 'target'){$sddl='O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;;0x1200af;;;AU)(A;OICIIO;0xe0010000;;;AU)'}
 if($path -ceq 'C:\KMTech\Apps'){
  switch($env:CA_SHAPE_SCENARIO){
   'user_owner' {$sddl=$sddl.Replace('O:BA','O:S-1-5-21-1-2-3-1000')}
   'deny' {$sddl=$sddl.Replace('D:AI','D:AI(D;;WD;;;AU)')}
   'extra_sid' {$sddl += '(A;;WD;;;WD)'}
   'partial' {$sddl=$sddl.Replace('0x1301bf','0x1200af')}
  }
 }
 $acl.SetSecurityDescriptorSddlForm($sddl);$script:acls[$path]=$acl
}
$before=@{};foreach($path in $script:acls.Keys){$before[$path]=$script:acls[$path].GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)}
$failed=$false
try{$result=Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit'}catch{$failed=$true;if(-not $_.Exception.Message.Contains('설치 폴더 권한을 확인하세요')){throw ('Plain-language rejection missing: '+$_.Exception.Message)}}
$expectedFail=$env:CA_SHAPE_SCENARIO -notin @('default','target')
if($failed -ne $expectedFail){throw 'Shape admission result differs.'}
if($env:CA_SHAPE_SCENARIO -in @('user_owner','deny','extra_sid','partial','reparse')){
 if($script:writes.Count){throw 'Unexpected second-folder shape changed an earlier folder.'}
 foreach($path in $script:acls.Keys){if($before[$path] -cne $script:acls[$path].GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)){throw 'Rejected ACL changed in memory.'}}
} elseif($env:CA_SHAPE_SCENARIO -ceq 'target'){
 if($script:writes.Count){throw 'Idempotent target was rewritten.'}
} else {
 if($script:writes.Count -ne 2){throw 'Expected exactly two literal writes.'}
 foreach($acl in $script:acls.Values){
  if(-not $acl.AreAccessRulesProtected){throw 'Ancestor inheritance remains active.'}
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  $self=@($rules | Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-11' -and [int]$_.PropagationFlags -eq 0})
  $child=@($rules | Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-11' -and [int]$_.PropagationFlags -eq 2})
  if($rules.Count -ne 5 -or $self.Count -ne 1 -or [int64]$self[0].FileSystemRights -ne 1179823 -or ([int64]$self[0].FileSystemRights -band 6) -ne 6 -or $child.Count -ne 1 -or [int64]$child[0].FileSystemRights -ne -536805376){throw 'B rights or child inheritance changed.'}
 }
 if($env:CA_SHAPE_SCENARIO -ceq 'default'){
  $second=Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit'
  if($script:writes.Count -ne 2 -or @($second.records | Where-Object {$_.changed}).Count){throw 'Repeated B operation changed permissions.'}
 }
}
'PASS'
''', engine=engine, values={'CA_SHAPE_SCENARIO': scenario})
    assert result.returncode == 0, result.stdout + result.stderr
