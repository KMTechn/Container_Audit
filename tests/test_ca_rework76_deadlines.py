import ctypes
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
import atomic_replace
import user_relay
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]


def test_inventory_budget_keyword_is_scoped_to_original_relay_sink(monkeypatch):
    from tools import derive_container_writer_sinks as derive
    visitor=object.__new__(derive._NodeVisitor)
    visitor.current_qualname='user_relay._write_json_atomic'
    monkeypatch.setattr(visitor,'_resolve_callable',lambda _:derive.ATOMIC_REPLACEMENT_HELPER)
    monkeypatch.setattr(visitor,'_mutation_record',lambda *args:'same-filesystem-effect')
    call=ast.parse('atomic_replace(source,destination,deadline=deadline)').body[0].value
    assert visitor._classify_mutation(call)=='same-filesystem-effect'
    visitor.current_qualname='other.publisher'
    with pytest.raises(derive.InventoryError):visitor._classify_mutation(call)
    visitor.current_qualname='user_relay._write_json_atomic'
    for expression in ('atomic_replace(source,destination,deadline=other)',
                       'atomic_replace(source,destination,**options)',
                       'atomic_replace(source,destination,write_through=other)',
                       'atomic_replace(source,destination,unknown=True)'):
        with pytest.raises(derive.InventoryError):
            visitor._classify_mutation(ast.parse(expression).body[0].value)


@pytest.mark.parametrize('engine',['powershell','pwsh'])
def test_powershell_transient_hresult5_retries_to_success(tmp_path,engine):
    driver=r'''
$first=[UnauthorizedAccessException]::new('fixture publication denial')
$script:calls=0
function Invoke-ContainerAtomicReplaceOnce {
    param($Source,$Destination,$Mode,$Backup)
    $script:calls++
    if($script:calls -eq 1){throw $first}
}
Invoke-ContainerAtomicReplace 'prepared' 'target' -Mode Replace
if($script:calls -ne 2){throw 'Transient HRESULT retry count differs.'}
'''
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',
        ['Invoke-ContainerAtomicReplace'],driver,engine=engine)
    assert result.returncode==0


def test_relay_stop_publication_and_wait_share_deadline(tmp_path,monkeypatch):
    now=[0.0];calls=[];waits=[]
    monkeypatch.setattr(user_relay.time,'monotonic',lambda:now[0])
    def publish(path,payload,*,deadline):
        calls.append(deadline);now[0]+=0.75
    monkeypatch.setattr(user_relay,'_write_json_atomic',publish)
    def wait(seconds):
        waits.append(seconds);now[0]+=seconds
    result=user_relay.request_user_relay_stop(tmp_path,timeout_seconds=1.0,
        wait=wait,lease_factory=lambda _:None)
    assert result['status']=='UNKNOWN' and calls==[1.0]
    assert sum(waits)==pytest.approx(0.25) and now[0]==pytest.approx(1.0)


def test_app_stop_passes_remaining_common_budget_to_both_publications(tmp_path,monkeypatch):
    now=[0.0];budgets=[];waits=[]
    monkeypatch.setattr(user_relay.time,'monotonic',lambda:now[0])
    monkeypatch.setattr(user_relay,'native_app_process_snapshot',lambda:[])
    monkeypatch.setattr(user_relay,'acquire_runtime_instance',lambda _:None)
    stop=user_relay.request_user_relay_stop
    monkeypatch.setattr(user_relay,'request_user_relay_stop',
        lambda *args,**kwargs:stop(*args,lease_factory=lambda _:None,**kwargs))
    def publish(path,payload,*,deadline):
        budgets.append(deadline);now[0]+=0.5
    monkeypatch.setattr(user_relay,'_write_json_atomic',publish)
    def wait(seconds):waits.append(seconds);now[0]+=seconds
    result=user_relay.request_app_stop(tmp_path,timeout_seconds=1.0,wait=wait)
    assert result['status']=='UNKNOWN' and budgets==[1.0,1.0]
    assert waits==[] and now[0]==1.0


def test_stop_publication_failure_preserves_original_exception(tmp_path,monkeypatch):
    first=ctypes.WinError(5)
    def fail(*args,**kwargs):raise first
    monkeypatch.setattr(atomic_replace,'atomic_replace',fail)
    with pytest.raises(OSError) as failure:
        user_relay.request_user_relay_stop(tmp_path,timeout_seconds=0.1)
    assert failure.value is first


@pytest.mark.parametrize('engine',['powershell','pwsh'])
@pytest.mark.parametrize('kind',['native','unauthorized','nontransient'])
def test_powershell_deadline_and_hresult_keep_first_denial(tmp_path,engine,kind):
    driver=r'''
$Script:attempts=0
$Script:sleeps=0
$Script:kind=$env:CA_ATOMIC_KIND
$Script:first=if($Script:kind -ceq 'unauthorized'){
    [UnauthorizedAccessException]::new('isolated fixture denial')
}else{[ComponentModel.Win32Exception]::new($(if($Script:kind -ceq 'nontransient'){87}else{5}),'isolated fixture denial')}
function Invoke-ContainerAtomicReplaceOnce {
    $Script:attempts++
    if($Script:attempts -eq 1){throw $Script:first}
}
function Start-Sleep {param($Milliseconds) $Script:sleeps++;[Threading.Thread]::Sleep(1600)}
$caught=$null
try{Invoke-ContainerAtomicReplace 'prepared' 'target' -Mode WriteThrough}catch{$caught=$_}
if($null -eq $caught -or $Script:attempts -ne 1){throw 'First denial was lost or native retried past deadline.'}
$cause=$caught.Exception
while($cause.InnerException){$cause=$cause.InnerException}
if(-not [object]::ReferenceEquals($cause,$Script:first)){throw 'Original exception identity differs.'}
if($Script:kind -ceq 'nontransient' -and $Script:sleeps -ne 0){throw 'Nontransient denial retried.'}
if($Script:kind -cne 'nontransient' -and $Script:sleeps -ne 1){throw 'Transient native HRESULT was not classified narrowly.'}
'''
    result=run_functions(tmp_path,ROOT/'tools/bootstrap_integrity.ps1',
        ['Invoke-ContainerAtomicReplace'],driver,engine=engine,values={'CA_ATOMIC_KIND':kind})
    assert result.returncode==0
