"""Exercise recovery through the real SYSTEM guard and READY consumer."""
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import uuid

import pytest

import auto_update as updates
from kmtech_shared import data_generation as generation
import startup_check_report


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = SimpleNamespace(control=tmp_path/'control', stage=tmp_path/'stage',
                        previous='a'*40, candidate='b'*40, clock=1000.0,
                        rows=[], launches=[], writes=[], auto_ready=False, depth=0)
    w.policy = {'operator_sid':uuid.uuid4().hex,
                'operator_local_app_data':str(tmp_path/'profile'), 'staging_root':str(w.stage)}
    w.now = lambda: (datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=w.clock)).isoformat()
    w.at = lambda seconds: (datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat()
    before = {'status':'READ','marker_path':str(tmp_path/'generation.json'),
              'record':{'version':'1.0.0','build_id':w.previous}}
    w.generation = copy.deepcopy(before)
    w.files = {w.control/'policy.json':w.policy, w.control/'active.json':{'sha':w.previous}}

    def seed(phase, *, claim='ABSENT', active=None):
        state = {'schema':updates.SCHEMA,'phase':phase,'previous_sha':w.previous,
                 'candidate_sha':w.candidate,'applied_at':w.at(900),'rollback_at':w.at(900),
                 'transition_id':uuid.uuid4().hex,'nonce':uuid.uuid4().hex,
                 'trial_pid':None,'generation_before':copy.deepcopy(before),
                 'generation_previous_release':{'version':'1.0.0','source_commit':w.previous},
                 'generation_candidate_release':{'version':'2.0.0','source_commit':w.candidate}}
        if phase=='DEFERRED':state.update(recovery_pending=True,recovery_phase='FAILED',deferred_at=w.at(950))
        if phase=='APPLIED_PENDING_READY':state.pop('rollback_at')
        w.files[w.control/'transition.json']=state
        w.files[w.control/'active.json']={'sha':active or w.previous}
        w.files[w.control/'apply-claim.json']={'schema':'code-update-apply-claim-v1','status':'SETTLED'} if claim=='NONE' else {
            'schema':'code-update-apply-claim-v1','status':'RUNNING','pid':os.getpid()+9999,'creation_identity':'absent'}

    w.seed=seed
    w.state=lambda:w.files[w.control/'transition.json']
    w.active=lambda:w.files[w.control/'active.json']['sha']
    w.row=lambda role,pid,born=None,sha=None:dict(pid=pid,role=role,sha=sha or w.active(),sid=w.policy['operator_sid'],
        observable=True,bootstrap=False,ordinary_user=True,created_at=w.at(995) if born is None else born)

    @contextlib.contextmanager
    def locked(*args,**kwargs):
        w.depth+=1
        try:yield True
        finally:w.depth-=1

    def write(path,value):
        w.files[Path(path)]=copy.deepcopy(value)
        w.writes.append(Path(path).name)

    def ready():
        state=w.state(); sha=w.active()
        w.rows=[w.row('gui',6001,born=w.now(),sha=sha),w.row('relay',6002,born=w.now(),sha=sha)]
        w.files[w.stage/'trial.json']={'pid':6001,'nonce':state['nonce'],'transition_id':state['transition_id']}
        w.files[w.stage/'ready.json']=dict(pid=6001,sha=sha,nonce=state['nonce'],transition_id=state['transition_id'],
                                        ready_at=w.now(),**{name:True for name in updates.READY_CHECKS})

    def snapshot(*_):
        if w.auto_ready and w.state()['phase']=='ROLLBACK_PENDING_READY':ready()
        return copy.deepcopy(w.rows)

    def spawn(command,**options):
        assert w.depth>0
        pid=5000+len(w.launches)
        role='relay' if '--container-audit-user-relay' in command else 'gui'
        w.launches.append((command,options))
        w.rows.append(w.row(role,pid,born=w.now()))
        return SimpleNamespace(pid=pid)

    monkeypatch.setattr(updates,'control_root',lambda *_:w.control)
    monkeypatch.setattr(updates,'read_json',lambda p:copy.deepcopy(w.files[Path(p)]))
    monkeypatch.setattr(updates,'optional_record',lambda p:copy.deepcopy(w.files.get(Path(p))))
    monkeypatch.setattr(updates,'write_json_durable',write)
    monkeypatch.setattr(updates,'update_lock',locked)
    monkeypatch.setattr(updates,'startup_update_lock',locked)
    monkeypatch.setattr(updates,'ordinary_user_context',lambda *_:True)
    monkeypatch.setattr(updates,'process_snapshot',snapshot)
    monkeypatch.setattr(updates,'prepared_pending',lambda *_:False)
    monkeypatch.setattr(updates,'current_generation_status',lambda *_:'ALLOW')
    monkeypatch.setattr(updates,'read_trial_generation',lambda *_:copy.deepcopy(w.generation))
    monkeypatch.setattr(updates,'fixed_helper',lambda *a,**k:None)
    monkeypatch.setattr(updates,'version_bundle',lambda c,s:tmp_path/s)
    monkeypatch.setattr(updates,'version_manifest',lambda *a,**k:{'source_commit':w.active(),'version':'1.0.0'})
    monkeypatch.setattr(updates,'native_process_identity',lambda pid:{'status':'LIVE','creation_identity':'current'} if pid==os.getpid() else {'status':'ABSENT'})
    monkeypatch.setattr(updates,'emit_support_record',lambda *a,**k:None)
    monkeypatch.setattr(updates,'emit_progress_guidance',lambda:None)
    monkeypatch.setattr(updates,'now_utc',w.now)
    monkeypatch.setattr(updates,'os',SimpleNamespace(environ={},getpid=os.getpid,path=os.path))
    monkeypatch.setattr(updates.time,'monotonic',lambda:w.clock)
    monkeypatch.setattr(updates.time,'sleep',lambda seconds:setattr(w,'clock',w.clock+max(seconds,10)))
    monkeypatch.setattr(subprocess,'Popen',spawn)
    monkeypatch.setattr(startup_check_report,'observe',lambda *a,**k:None)
    monkeypatch.setattr(generation,'probe_downgrade',lambda paths,version,**kw:{'status':'ALLOW' if version=='2.0.0' or w.generation==before else 'DENY'})

    def system():
        try:return updates._apply_prepared(w.control)
        finally:updates.complete_apply_claim(w.control)

    w.system=system
    w.gui=lambda:updates._bootstrap(tmp_path/'app',[],role='gui')
    w.relay=lambda:updates._bootstrap(tmp_path/'app',['--container-audit-user-relay'],role='relay')
    w.ready=ready
    seed('FAILED')
    return w


@pytest.mark.parametrize('bound_gui',[False,True])
@pytest.mark.parametrize('receipt',[False,True])
@pytest.mark.parametrize('trial_relay',[False,True])
def test_actual_system_guard_and_ready_consumer_matrix(world, bound_gui, receipt, trial_relay):
    w=world
    w.seed('APPLIED_PENDING_READY',active=w.candidate)
    state=w.state()
    # A retained recovery relay predates a *new* trial. A same-epoch bound mix
    # cannot be produced by recovery admission; the separate tests prove that.
    born=w.at(899) if bound_gui else w.at(995)
    w.rows=[w.row('relay',5001,born=born)]
    if bound_gui:
        gui=w.row('gui',6001,born=w.at(996))
        w.rows.append(gui)
        state.update(trial_pid=6001,trial_started_at=gui['created_at'])
    if trial_relay:w.rows.append(w.row('relay',6002,born=w.at(997)))
    claim={'pid':6001,'nonce':state['nonce'],'transition_id':state['transition_id']}
    proof=dict(pid=6001,sha=w.candidate,nonce=state['nonce'],transition_id=state['transition_id'],
               ready_at=w.now(),**{name:True for name in updates.READY_CHECKS}) if receipt else None
    w.files[w.stage/'trial.json']=claim
    if proof:w.files[w.stage/'ready.json']=proof
    original_state=copy.deepcopy(state)
    _,confirmed,_=updates.observe_trial_ready(w.control,w.policy,copy.deepcopy(state),w.rows,claim,proof,deadline=w.clock+120)
    assert confirmed is (bound_gui and receipt and trial_relay)
    w.files[w.control/'transition.json']=original_state
    result=w.system()
    assert (w.state()['phase']=='CONFIRMED') is (bound_gui and receipt and trial_relay)
    if not bound_gui:
        assert result==0 and w.state()['phase']=='DEFERRED' and w.state()['recovery_pending'] is True
    elif receipt and trial_relay:
        assert result==0
    assert not w.launches


@pytest.mark.parametrize('phase',['FAILED','DEFERRED'])
def test_gui_and_relay_defer_system_then_restore_with_fresh_ready(world, phase):
    w=world;w.seed(phase)
    w.rows=[w.row('relay',5001)]
    before=copy.deepcopy(w.files)
    assert w.gui()==0 and len(w.launches)==1
    assert w.files==before
    assert w.launches[0][1]['env']['KMTECH_CA_UPDATE_DEFERRED_AT']==w.at(995)
    assert 'KMTECH_CA_UPDATE_TRIAL_NONCE' not in w.launches[0][1]['env']
    assert w.system()==0 and w.state()['phase']=='DEFERRED' and w.state()['recovery_pending'] is True
    held=copy.deepcopy(w.state())
    assert w.system()==0 and w.state()==held
    w.rows=[];w.clock+=500;w.auto_ready=True
    assert w.system()==0
    assert w.state()['phase']=='ROLLED_BACK' and w.active()==w.previous
    assert updates._utc(w.state()['rollback_at'])>updates._utc(held['rollback_at'])
    assert updates.apply_claim_status(w.control)=='NONE'


@pytest.mark.parametrize('via_relay',[False,True])
@pytest.mark.parametrize('advanced',[False,True])
def test_abandoned_applied_gui_matches_existing_writer_zero_settlement(world, via_relay, advanced):
    w=world;w.seed('APPLIED_PENDING_READY',active=w.candidate)
    if via_relay:w.rows=[w.row('relay',5001)]
    assert w.gui()==0
    assert all('KMTECH_CA_UPDATE_TRIAL_NONCE' not in options['env'] for _,options in w.launches)
    assert w.system()==0 and w.state()['recovery_pending'] is True
    assert w.state()['phase']=='DEFERRED'
    if advanced:w.generation['record']={'version':'2.0.0','build_id':w.candidate}
    w.rows=[];w.clock+=500;w.auto_ready=True
    assert w.system() in (0,20)
    expected='TRIAL_GENERATION_ADVANCED' if advanced else 'TRIAL_GENERATION_UNCHANGED'
    assert w.state()['failure_decision']['code']==expected
    assert w.active()==(w.candidate if advanced else w.previous)
    assert w.state()['phase']==('DEFERRED' if advanced else 'ROLLED_BACK')
    assert bool(w.state().get('retained_candidate')) is advanced


def test_logon_relay_then_late_system_then_gui_is_recoverable(world):
    w=world;w.seed('FAILED',claim='NONE')
    assert w.relay()==0 and len(w.launches)==1 and w.rows[0]['role']=='relay'
    w.clock+=5
    assert w.system()==0 and w.state()['recovery_pending'] is True
    before=copy.deepcopy(w.files)
    assert w.gui()==0 and len(w.launches)==2 and w.rows[-1]['role']=='gui'
    assert w.files==before
    assert w.launches[-1][1]['env']['KMTECH_CA_UPDATE_DEFERRED_AT']==w.rows[0]['created_at']


def test_recovery_admission_cannot_create_same_epoch_bound_trial_mix(world):
    w=world;w.seed('APPLIED_PENDING_READY',active=w.candidate)
    gui=w.row('gui',6001,born=w.at(990))
    w.state().update(trial_pid=6001,trial_started_at=gui['created_at'])
    w.rows=[gui]
    updates.os.environ['KMTECH_CA_UPDATE_DEFERRED_AT']=w.at(995)
    assert w.relay()==20 and not w.launches
    w.rows.append(w.row('relay',5001,born=w.at(995)))
    assert w.gui()==0 and not w.launches
    recycled={**gui,'created_at':w.now()}
    assert not updates.process_matches_trial(recycled,state=w.state(),sha=w.candidate,sid=w.policy['operator_sid'],role='gui')


@pytest.mark.parametrize('phase',['APPLIED_PENDING_READY','ROLLBACK_PENDING_READY'])
def test_ordinary_gui_and_relay_cannot_publish_trial_readiness(world, monkeypatch, phase):
    import sqlite3
    w=world;w.seed(phase,active=w.candidate if phase=='APPLIED_PENDING_READY' else w.previous)
    w.rows=[w.row('relay',5001)]
    assert w.gui()==0
    updates.os.environ=dict(w.launches[-1][1]['env'])
    before=copy.deepcopy(w.files)
    monkeypatch.setattr(sqlite3,'connect',lambda *a,**k:pytest.fail('ordinary GUI must not open trial readiness stores'))
    assert updates.trial_context(w.control/'app') is None
    assert updates.publish_gui_ready(w.control/'app') is True
    assert 'update_nonce' not in updates.relay_ready_metadata(w.control/'app')
    assert w.files==before and w.stage/'ready.json' not in w.files
