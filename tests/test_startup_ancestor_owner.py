"""Use actual guard against in-memory Windows ACLs, never host ancestor ACLs."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('relative,function', [
    ('INSTALL_THIS_PC.ps1', 'Assert-ProtectedCodeAncestors'),
    ('tools/apply_prepared_update.ps1', 'Assert-Protected'),
    ('tools/bootstrap_integrity.ps1', 'Assert-BootstrapProtectedRelayPath'),
])
@pytest.mark.parametrize('owner,allowed', [
    (TI, True), ('S-1-5-18', True), ('S-1-5-32-544', True),
    ('S-1-5-11', False), ('S-1-5-32-545', False), ('S-1-1-0', False),
    ('S-1-5-4', False), ('S-1-5-21-1-2-3-1000', False), ('S-1-5-80-1-2-3-4-5', False),
])
def test_privileged_volume_owner_uses_exact_sid_with_default_inheritance(tmp_path, engine, relative, function, owner, allowed):
    result = run_functions(tmp_path, ROOT/relative, [function], r'''
. $env:CA_OWNER_LIBRARY
function Test-Path { param($LiteralPath) return $true }
function Get-Item { param($LiteralPath,$ErrorAction) return [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
function Get-Acl {
 param($LiteralPath,$ErrorAction)
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $owner=if($LiteralPath -ceq 'C:\'){$env:CA_OWNER_FIXTURE}else{'S-1-5-32-544'}
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 }
 if($LiteralPath -ceq 'C:\'){
  $user=[Security.Principal.SecurityIdentifier]::new('S-1-5-11')
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,'AppendData','None','None','Allow'))
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,'Modify','ContainerInherit,ObjectInherit','InheritOnly','Allow'))
 }
 return $acl
}
$passed=$false
try { & $env:CA_OWNER_FUNCTION 'C:\fixture\App'; $passed=$true }
catch { if(-not $_.Exception.Message.Contains('owner is not privileged')){throw 'Wrong owner rejection.'} }
if($passed -ne ($env:CA_OWNER_ALLOWED -ceq '1')){throw 'Owner whitelist differs from the reviewed SIDs.'}
'PASS'
''', engine=engine, values={'CA_OWNER_FIXTURE': owner, 'CA_OWNER_ALLOWED': '1' if allowed else '0',
                          'CA_OWNER_LIBRARY': str(ROOT/'tools/bootstrap_integrity.ps1'),
                          'CA_OWNER_FUNCTION': function})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_pretrust_owner_rule_is_the_exact_shared_pure_function(tmp_path, engine):
    result = run_functions(tmp_path, ROOT/'tools/bootstrap_integrity.ps1',
                           ['Test-BootstrapPrivilegedOwnerSid'], r'''
$shared=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-BootstrapPrivilegedOwnerSid'},$true)
$copyAst=[Management.Automation.Language.Parser]::ParseFile($env:CA_OWNER_PRETRUST,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Pretrust parser error'}
$copy=$copyAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-BootstrapPrivilegedOwnerSid'},$true)
if($null -eq $copy -or $shared.Extent.Text -cne $copy.Extent.Text){throw 'Pretrust owner rule differs from the shared rule'}
'PASS'
''', engine=engine, values={'CA_OWNER_PRETRUST': str(ROOT/'tools/apply_prepared_update.ps1')})
    assert result.returncode == 0, result.stdout + result.stderr
