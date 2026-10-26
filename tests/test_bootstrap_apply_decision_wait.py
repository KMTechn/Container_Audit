from pathlib import Path
import contextlib,json,pytest
import auto_update as updates
from tests.test_bootstrap_live_apply_wait import scene,world,ordinary
NATIVE_STARTUP_LOCK=updates.startup_update_lock
@pytest.mark.parametrize('claim',['UNKNOWN','ABSENT'])
def test_actual_startup_lock_claim_loss_bounded_observation(scene,monkeypatch,claim):
 w=world(scene,monkeypatch,decision=False,final_claim=claim,claim_boundary=366.941488 + updates.READY_WINDOW_SECONDS - 240)
 reads=[];calls=[];returned=[];original=updates.apply_claim_status
 @contextlib.contextmanager
 def recorded_native(*args,**kwargs):
  with NATIVE_STARTUP_LOCK(*args,**kwargs) as acquired:
   returned.append({'at':w.s.clock[0],'acquired':acquired});yield acquired
 monkeypatch.setattr(updates,'startup_update_lock',recorded_native)
 def observe_claim(*args):
  value=original(*args);reads.append({'at':w.s.clock[0],'claim':value});return value
 @contextlib.contextmanager
 def root_busy(*args,timeout_ms=5000,trial=False,**kwargs):
  if trial or w.s.clock[0]<w.stop:
   yield
   return
  calls.append({'at':w.s.clock[0],'timeout_ms':timeout_ms,'ends':w.s.clock[0]+max(0,timeout_ms)/1000})
  w.advance_to(w.s.clock[0]+max(0,timeout_ms)/1000)
  error=RuntimeError('update mutex ownership is busy or abandoned');error.wait_result=0x102;raise error
 monkeypatch.setattr(updates,'apply_claim_status',observe_claim)
 monkeypatch.setattr(updates,'update_lock',root_busy)
 rc=updates._bootstrap(w.s.control.parent,[],role='gui')
 loss=[r for r in reads if r['claim']==claim]
 first_busy_end=min(c['ends'] for c in calls if c['ends']>=w.claim_boundary)
 first_false=min(r['at'] for r in returned if not r['acquired'] and r['at']>=w.claim_boundary)
 w.s.write(w.s.control/('native-loss-'+claim+'.json'),{'rc':rc,'finished':w.s.clock[0],'claim_change':w.claim_boundary,'first_nonlive_read':loss[0] if loss else None,'nonlive_reads':len(loss),'root_waits_tail':calls[-8:],'ordinary_popens':ordinary(w),'actual_native_helper_false_at':first_false,'first_busy_after_loss_ends':first_busy_end,'helper_returns_tail':returned[-6:]})
 assert rc==20 and ordinary(w)==[]
 assert loss and loss[0]['at']<=w.s.clock[0]
 assert first_false==pytest.approx(first_busy_end,rel=0,abs=1e-6)

def test_terminal_decision_keeps_retained_relay_support_branch(scene,monkeypatch):
 w=world(scene,monkeypatch)
 rc=updates._bootstrap(w.s.control.parent,['--container-audit-user-relay'],role='relay')
 support=updates.read_json(w.s.stage/'startup-support.json')
 w.s.write(w.s.control/'terminal-branch-observed.json',{'rc':rc,'finished':w.s.clock[0],'reason_code':support.get('reason_code'),'retained_candidate':support.get('retained_candidate'),'transition_code':support.get('transition_code'),'ordinary_popens':ordinary(w)})
 assert rc==0 and len(ordinary(w))==1 and ordinary(w)[0]['relay']
 assert support['retained_candidate'] is True
 assert support['reason_code']=='UPDATE_TERMINAL_RECOVERED'


def test_extended_rollback_decision_uses_previous_confirmed_branch(scene, monkeypatch):
    w = world(scene, monkeypatch, ready_phase="ROLLBACK_PENDING_READY",
              terminal="ROLLED_BACK", normal_stop=False)
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 0
    support = updates.read_json(w.s.stage / "startup-support.json")
    assert support["reason_code"] == "UPDATE_PREVIOUS_CONFIRMED"
    assert len(ordinary(w)) == 1 and not ordinary(w)[0]["relay"]
