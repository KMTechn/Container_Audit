"""A proven ordinary relay must not hide the recovery GUI."""
from datetime import datetime, timedelta
from types import SimpleNamespace
import subprocess

import pytest

import auto_update as updates
from tests.test_auto_update_recovery_relay import recovery, CREATED, NOW, SHA


@pytest.fixture
def gui_recovery(recovery, monkeypatch):
    r = recovery
    r.parent['role'] = 'relay'
    r.claim_state = ['NONE']
    monkeypatch.delenv('KMTECH_CA_UPDATE_DEFERRED_AT')
    monkeypatch.setattr(updates, 'apply_claim_status', lambda *_: r.claim_state[0])
    monkeypatch.setattr(updates, 'prepared_pending', lambda *_: False)

    def launch(command, **options):
        assert r.held.depth > 0
        r.launches.append((command, options))
        pid = r.parent['pid'] + len(r.launches)
        role = 'relay' if '--container-audit-user-relay' in command else 'gui'
        r.rows.append({**r.parent, 'pid': pid, 'role': role, 'created_at': NOW})
        return SimpleNamespace(pid=pid)

    monkeypatch.setattr(subprocess, 'Popen', launch)
    r.gui = lambda: r.invoke(role='gui', arguments=[])
    return r


@pytest.mark.parametrize('phase,claim', [
    ('FAILED', 'NONE'), ('FAILED', 'ABSENT'),
    ('UNKNOWN', 'NONE'), ('UNKNOWN', 'ABSENT'),
    ('DEFERRED', 'NONE'), ('DEFERRED', 'ABSENT'),
    ('APPLIED_PENDING_READY', 'ABSENT'), ('ROLLBACK_PENDING_READY', 'ABSENT'),
])
def test_relay_only_recovery_launches_gui_with_relay_birth_boundary(gui_recovery, monkeypatch, phase, claim):
    r = gui_recovery
    r.state.update(phase=phase, recovery_pending=phase == 'DEFERRED')
    r.claim_state[0] = claim
    assert r.gui() == 0
    assert len(r.launches) == 1
    _, options = r.launches[0]
    assert options['env']['KMTECH_CA_UPDATE_DEFERRED_AT'] == CREATED
    assert 'KMTECH_CA_UPDATE_NONCE' not in options['env']
    with monkeypatch.context() as child:
        child.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', options['env']['KMTECH_CA_UPDATE_DEFERRED_AT'])
        assert updates.startup_gate(r.tmp_path / 'app', [], role='gui') is None
    r.unchanged()


def test_deferred_live_claim_must_settle_before_gui_admission(gui_recovery, monkeypatch):
    r = gui_recovery
    r.state.update(phase='DEFERRED', recovery_pending=True, deferred_at=CREATED)
    statuses = iter(['LIVE', 'LIVE', 'NONE'])
    monkeypatch.setattr(updates, 'apply_claim_status', lambda *_: next(statuses, 'NONE'))
    assert r.gui() == 0
    assert len(r.launches) == 1
    assert r.launches[0][1]['env']['KMTECH_CA_UPDATE_DEFERRED_AT'] == CREATED
    r.unchanged()


@pytest.mark.parametrize('phase', ['FAILED', 'DEFERRED', 'APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'])
@pytest.mark.parametrize('defect', ['sha', 'sid', 'ordinary_user', 'role', 'observable', 'created_at', 'future', 'two', 'generation', 'unreadable'])
def test_any_missing_relay_proof_keeps_gui_blocked(gui_recovery, monkeypatch, phase, defect):
    r = gui_recovery
    r.state.update(phase=phase, recovery_pending=phase == 'DEFERRED', deferred_at=CREATED)
    r.claim_state[0] = 'ABSENT'
    if defect in ('sha', 'sid', 'role', 'created_at'):
        r.parent[defect] = 'unproved'
    elif defect in ('ordinary_user', 'observable'):
        r.parent[defect] = False
    elif defect == 'future':
        r.parent['created_at'] = (datetime.fromisoformat(NOW) + timedelta(seconds=1)).isoformat()
    elif defect == 'two':
        r.rows.append({**r.parent, 'pid': r.parent['pid'] + 100})
    elif defect == 'generation':
        monkeypatch.setattr(updates, 'current_generation_status', lambda *_: 'UNKNOWN')
    else:
        def unreadable(*_):
            raise OSError('observation unavailable')
        monkeypatch.setattr(updates, 'process_snapshot', unreadable)
    try:
        r.gui()
    except (OSError, ValueError, TypeError, KeyError):
        pass
    assert not r.launches
    r.unchanged()


@pytest.mark.parametrize('phase', ['PREPARED', 'ROLLBACK_PENDING', 'DEFERRED'])
def test_other_phases_keep_existing_relay_only_result(gui_recovery, phase):
    r = gui_recovery
    r.state.update(phase=phase, recovery_pending=False)
    r.claim_state[0] = 'ABSENT'
    assert r.gui() == 0
    assert not r.launches
    r.unchanged()


@pytest.mark.parametrize('phase', ['APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'])
@pytest.mark.parametrize('claim', ['LIVE', 'NONE'])
def test_supervised_waiting_state_keeps_its_existing_trial_path(gui_recovery, monkeypatch, phase, claim):
    r = gui_recovery
    r.state['phase'] = phase
    r.claim_state[0] = claim
    original = updates.optional_record
    monkeypatch.setattr(updates, 'optional_record', lambda p: {'nonce': r.state['nonce']} if p.name == 'trial.json' else original(p))
    assert r.gui() == 20
    assert not r.launches
    r.unchanged()


def test_existing_gui_is_reused_without_launch(gui_recovery):
    r = gui_recovery
    r.rows.append({**r.parent, 'pid': r.parent['pid'] + 100, 'role': 'gui'})
    assert r.gui() == 0
    assert not r.launches
    r.unchanged()
