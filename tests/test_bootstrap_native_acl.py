"""Owned code ACL readback; elevation is an explicit native capability."""
import ctypes
import json
import os
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL contract')
def test_bootstrap_hardens_owned_tree_and_rejects_extra_write_permission(tmp_path):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('code ACL owner change requires an already elevated native process')
    code = tmp_path / 'owned code'
    code.mkdir()
    child = code / 'payload.txt'
    child.write_text('owned payload', encoding='utf-8')
    result = run_functions(
        tmp_path, ROOT / 'INSTALL_THIS_PC.ps1',
        ['Test-SamePath', 'Assert-NoReparsePoint', 'ConvertTo-NormalizedAclRights',
         'Assert-HardenedCodeAcl', 'Set-HardenedCodeAcl'],
        r'''
. $env:CA_ACL_INTEGRITY
$root=Join-Path $env:CA_CONTRACT_ROOT 'owned code'
$child=Join-Path $root 'payload.txt'
$beforeRoot=Get-Acl -LiteralPath $root
$beforeChild=Get-Acl -LiteralPath $child
try {
    Set-HardenedCodeAcl $root -Recursive
    Assert-HardenedCodeAcl $root -Recursive
    $readback=Get-Acl -LiteralPath $root
    $acl=Get-Acl -LiteralPath $root
    $sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    $extra=[Security.AccessControl.FileSystemAccessRule]::new($sid,'Write','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($extra)
    Set-Acl -LiteralPath $root -AclObject $acl
    $rejected=$false
    try {Assert-HardenedCodeAcl $root -Recursive} catch {$rejected=$true}
    [ordered]@{
        owner=$readback.GetOwner([Security.Principal.SecurityIdentifier]).Value
        protected=$readback.AreAccessRulesProtected
        extra_write_rejected=$rejected
    } | ConvertTo-Json -Compress
} finally {
    Set-Acl -LiteralPath $root -AclObject $beforeRoot
    Set-Acl -LiteralPath $child -AclObject $beforeChild
}
''', values={'CA_ACL_INTEGRITY':str(ROOT/'tools/bootstrap_integrity.ps1')},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        'owner':'S-1-5-32-544', 'protected':True, 'extra_write_rejected':True,
    }
    assert child.read_text(encoding='utf-8') == 'owned payload'
