import ast
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import auto_update
import current_user_onboarding as onboarding
import user_relay
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]
WORKER='S-1-5-21-100-200-300-1001'
OTHER='S-1-5-21-100-200-300-1002'


def _worker(tmp_path,monkeypatch,*,sid=WORKER,session=1,elevated=False):
    install=tmp_path/'install';app=install/'current/app';app.mkdir(parents=True)
    control=install/'update-control';control.mkdir()
    (control/'policy.json').write_text(json.dumps({'operator_sid':WORKER}),encoding='utf-8')
    monkeypatch.setattr(auto_update,'current_process_sid',lambda:sid)
    monkeypatch.setattr(onboarding,'_current_process_session_id',lambda:session)
    monkeypatch.setattr(onboarding,'_inspect_current_process_execution_context',lambda:{
        'status':'PASS','token_elevated':elevated,'integrity_level':'MEDIUM'})
    return app


@pytest.mark.parametrize('settings',[{'sid':OTHER},{'session':0},{'session':-1},{'session':None},{'elevated':True}])
def test_relay_start_rejects_foreign_or_noninteractive_token_before_spawn(tmp_path,monkeypatch,settings):
    app=_worker(tmp_path,monkeypatch,**settings)
    starts=[]
    monkeypatch.setattr(user_relay,'build_user_relay_command',lambda *a,**k:pytest.fail('command built before token admission'))
    with pytest.raises(ValueError):
        user_relay.start_user_relay_process(app,launcher=starts.append)
    assert starts==[]


def test_interactive_worker_relay_start_uses_only_relay_dispatch(tmp_path,monkeypatch):
    app=_worker(tmp_path,monkeypatch)
    starts=[]
    monkeypatch.setattr(user_relay.subprocess,'Popen',lambda command,**kw:starts.append((command,kw)) or SimpleNamespace(pid=123))
    result=user_relay.start_user_relay_process(app,environ={'LOCALAPPDATA':str(tmp_path/'local'),'PROGRAMDATA':str(tmp_path/'machine')})
    assert result['status']=='START_REQUESTED' and len(starts)==1
    assert user_relay.USER_RELAY_MODE in starts[0][0]
    assert '--ui' not in starts[0][0]
    assert starts[0][1]['stdin']==user_relay.subprocess.DEVNULL


def test_noninteractive_first_setup_rejects_before_any_paths_or_gui(tmp_path,monkeypatch):
    app=_worker(tmp_path,monkeypatch,session=0)
    monkeypatch.setattr(onboarding,'resolve_current_user_onboarding_paths',lambda *a,**k:pytest.fail('setup paths prepared before token admission'))
    shell_calls=[]
    monkeypatch.setitem(sys.modules,'shell.host',SimpleNamespace(run_app=lambda *a,**k:shell_calls.append(1)))
    with pytest.raises(ValueError):onboarding.onboard_current_user(app)
    assert shell_calls==[]


def test_pending_worker_must_match_installed_policy_and_actual_token(tmp_path,monkeypatch):
    app=_worker(tmp_path,monkeypatch)
    with pytest.raises(ValueError):onboarding._machine_worker_context(app,target_sid=OTHER)
    assert onboarding._machine_worker_context(app,target_sid=WORKER)['session_id']==1


@pytest.mark.parametrize('engine',['powershell','pwsh'])
def test_operating_install_requires_explicit_worker_account(tmp_path,engine):
    driver=r'''
$failed=$false
try{Assert-CanonicalOperatingWorkerAccount '' $false $false $false}catch{$failed=$true}
if(-not $failed){throw 'Operating installation silently chose a worker.'}
Assert-CanonicalOperatingWorkerAccount 'fixture-worker' $false $false $false
Assert-CanonicalOperatingWorkerAccount '' $true $false $false
Assert-CanonicalOperatingWorkerAccount '' $false $true $false
Assert-CanonicalOperatingWorkerAccount '' $false $false $true
'''
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',
        ['Assert-CanonicalOperatingWorkerAccount'],driver,engine=engine)
    assert result.returncode==0


def test_machine_completion_and_onboarding_have_no_gui_or_immediate_relay_route():
    source=(ROOT/'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8-sig')
    start=source.index('function Invoke-CanonicalMachineInstallation(')
    end=source.index('# Admit the worker',start)
    body=source[start:end]
    assert 'Initialize-CanonicalSameWorkerScope $Root $workerPreparation' not in body
    assert 'Start-CanonicalRelayAfterFenceRelease' not in body
    assert "Product $" not in body and 'StartRaw ' not in body
    tree=ast.parse((ROOT/'current_user_onboarding.py').read_text(encoding='utf-8-sig'))
    setup=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='onboard_current_user')
    calls=[n for n in ast.walk(setup) if isinstance(n,ast.Call)]
    assert any(isinstance(n.func,ast.Name) and n.func.id=='relay_launcher' for n in calls)
    assert not any(isinstance(n.func,ast.Attribute) and n.func.attr in {'Popen','run_app','create_window'} for n in calls)
