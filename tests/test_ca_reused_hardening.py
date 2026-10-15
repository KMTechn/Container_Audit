from pathlib import Path
import pytest

from tests.powershell_contracts import run_functions
from tests.test_ca_atomic_replace import _powershell_replacements

ROOT=Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('test_mode',[False,True])
@pytest.mark.parametrize('fault',['missing','duplicate','unknown','valid'])
def test_replacing_child_status_is_closed_before_evidence(tmp_path,test_mode,fault):
    script=r'''
$testMode=($env:CA_STATUS_TEST -ceq 'True')
$lines=switch($env:CA_STATUS_FAULT){
    missing {''}
    duplicate {"bootstrap_status=REUSED`nbootstrap_status=REUSED"}
    unknown {'bootstrap_status=UNKNOWN'}
    valid {'bootstrap_status=REUSED'}
}
$caught=$false
try{$status=Read-CanonicalPlacementStatus $lines $true}catch{$caught=$true}
if($env:CA_STATUS_FAULT -ceq 'valid'){
    if($caught -or $status -cne 'REUSED'){throw 'VALID_STATUS_REFUSED'}
}elseif(-not $caught){throw 'MALFORMED_STATUS_ADMITTED'}
'''
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',
                         ['Read-CanonicalPlacementStatus'],script,
                         values={'CA_STATUS_TEST':str(test_mode),'CA_STATUS_FAULT':fault})
    assert result.returncode==0


@pytest.mark.parametrize('extension',['.ps1','.psm1'])
@pytest.mark.parametrize('statement',[
    "Microsoft.PowerShell.Management\\Rename-Item -LiteralPath 'prepared' -NewName 'live'",
    "[IO.File]::Move('prepared','live')",
    "[System.IO.File]::Replace('prepared','live',$null)",
    "[Native]::MoveFileExW('prepared','live',9)",
])
def test_atomic_guard_covers_module_and_raw_native_forms(tmp_path,extension,statement):
    (tmp_path/('injected'+extension)).write_text('function Publish-Unowned {\n'+statement+'\n}',encoding='utf-8')
    assert _powershell_replacements(tmp_path)


def test_write_through_preparation_cannot_start_expired_retry(monkeypatch,tmp_path):
    import atomic_replace as atomic
    clock=[0.0]
    calls=[]
    preparations=[]
    first=OSError('ordered native denial')
    first.winerror=32
    class Move:
        def __call__(self,*args):
            calls.append(args)
            return False if len(calls)==1 else True
    move=Move()
    class Kernel:
        MoveFileExW=move
    def prepare(*args,**kwargs):
        preparations.append(True)
        if len(preparations)==2:clock[0]=2.0
        return Kernel()
    monkeypatch.setattr(atomic.ctypes,'WinDLL',prepare)
    monkeypatch.setattr(atomic.ctypes,'WinError',lambda code:first)
    monkeypatch.setattr(atomic.ctypes,'get_last_error',lambda:32)
    monkeypatch.setattr(atomic,'monotonic',lambda:clock[0])
    monkeypatch.setattr(atomic,'sleep',lambda seconds:clock.__setitem__(0,clock[0]+seconds))
    with pytest.raises(OSError) as caught:
        atomic.atomic_replace(tmp_path/'prepared',tmp_path/'live',write_through=True)
    assert caught.value is first
    assert len(preparations)==2 and len(calls)==1
