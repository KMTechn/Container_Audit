"""Exercise the actual canonical routing statement without host installation.

Lifecycle authentication and actual receipt/NTFS custody have their own tests;
this contract prevents the equal-owner route from selecting versions placement.
"""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('engine',['powershell.exe','pwsh.exe'])
def test_actual_canonical_keeps_equal_owner_current_route_and_uses_actual_b(tmp_path,engine):
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',['Full'],r'''
$route=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text.Contains('$supportedContext.bootstrap_commit -cne [string]$supportedContext.from_commit')},$true))
if($route.Count -ne 1){throw 'actual supported placement decision is ambiguous'}
$install=Join-Path $env:CA_CONTRACT_ROOT 'owned/current'
$sourceManifest=[pscustomobject]@{source_commit=('c'*40)}
foreach($from in @(('a'*40),('b'*40))){
    $supportedContext=[pscustomobject]@{lifecycle_state='HEALTHY';managed=$true;bootstrap_commit=('a'*40);from_commit=$from}
    $supportedPlacement=$false;$installedCodeRoot=$install
    Invoke-Expression $route[0].Extent.Text
    if($from -ceq ('a'*40)){
        if($supportedPlacement -or $installedCodeRoot -cne $install){throw 'equal owner left the existing current placement route'}
    }else{
        $expected=Join-Path (Split-Path -Parent $install) ('versions/'+('c'*40))
        if(-not $supportedPlacement -or $installedCodeRoot -cne $expected){throw 'actual B did not select supported C placement'}
    }
}
'ACTUAL_EQUAL_OWNER_ROUTE_PASS'
''',engine=engine)
    assert result.returncode==0,result.stdout+result.stderr
    assert 'ACTUAL_EQUAL_OWNER_ROUTE_PASS' in result.stdout
