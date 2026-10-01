"""Use actual guard against in-memory Windows ACLs, never host ancestor ACLs."""
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('owner,allowed', [
    (TI, True), ('S-1-5-18', True), ('S-1-5-32-544', True),
    ('S-1-5-11', False), ('S-1-5-32-545', False), ('S-1-1-0', False),
    ('S-1-5-4', False), ('S-1-5-21-1-2-3-1000', False), ('S-1-5-80-1-2-3-4-5', False),
])
def test_privileged_volume_owner_uses_exact_sid_with_default_inheritance(tmp_path, engine, owner, allowed):
    result = run_functions(tmp_path, ROOT/'INSTALL_THIS_PC.ps1', ['Assert-ProtectedCodeAncestors'], r'''
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
try { Assert-ProtectedCodeAncestors 'C:\fixture\App'; $passed=$true }
catch { if(-not $_.Exception.Message.Contains('owner is not privileged')){throw 'Wrong owner rejection.'} }
if($passed -ne ($env:CA_OWNER_ALLOWED -ceq '1')){throw 'Owner whitelist differs from the reviewed SIDs.'}
'PASS'
''', engine=engine, values={'CA_OWNER_FIXTURE': owner, 'CA_OWNER_ALLOWED': '1' if allowed else '0'})
    assert result.returncode == 0, result.stdout + result.stderr
