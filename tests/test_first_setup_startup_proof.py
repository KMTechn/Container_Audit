"""Updated ordinary starts reach real first setup without changing control state."""
from contextlib import nullcontext
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import auto_update as updates
import Container_Audit as app
import current_user_onboarding as onboarding
import data_generation_guard
from tests.test_supported_lifecycle import installed, OLD, NEW


class FirstSetupReached(BaseException):
    """Stop before enrollment, credentials, persistence or any GUI creation."""


@pytest.fixture
def first_setup(installed, monkeypatch, tmp_path):
    control = installed / 'update-control'
    active_app = installed / 'versions' / NEW / 'app'
    policy = updates.read_json(control / 'policy.json')
    policy['operator_sid'] = updates.current_process_sid()
    policy['staging_root'] = str(tmp_path / 'stage')
    Path(policy['staging_root']).mkdir()
    (control / 'policy.json').write_text(json.dumps(policy))
    monkeypatch.setattr(updates, 'version_manifest',
                        lambda root: updates.read_json(root / 'portable-manifest.json'))
    monkeypatch.setattr(updates, 'ordinary_user_context', lambda *_args: True)
    monkeypatch.setattr(updates, 'startup_update_lock', lambda *_args: nullcontext(True))
    monkeypatch.setattr(updates, 'current_generation_status', lambda *_args: 'ALLOW')
    monkeypatch.setattr(updates, 'process_snapshot', lambda *_args: [])
    monkeypatch.setattr(updates, 'request_bootstrap', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(onboarding, '_inspect_current_process_execution_context',
                        lambda: {'status': 'PASS', 'token_elevated': False,
                                 'integrity_level': 'MEDIUM'})
    monkeypatch.setattr(onboarding, '_current_process_session_id', lambda: 1)
    monkeypatch.setattr(data_generation_guard, 'warm_runtime_release', lambda: None)
    monkeypatch.setattr(app, '__file__', str(active_app / 'Container_Audit.py'))
    monkeypatch.setattr(updates, '__file__', str(active_app / 'auto_update.py'))
    monkeypatch.setattr(app, '_first_run_onboarding_enabled', lambda: True)
    monkeypatch.setattr(app, 'consume_pending_machine_onboarding', lambda *_args: None)
    monkeypatch.setattr(app, 'verify_factory_contract_startup', lambda: None)
    monkeypatch.setattr(app, 'probe_before_owner_paths', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(app, '_consume_startup_app_stop_request', lambda *_args: False)
    monkeypatch.setattr(app, 'acquire_runtime_instance',
                        lambda *_args: SimpleNamespace(release=lambda: None))
    data = tmp_path / 'first-user-data'
    data.mkdir()
    monkeypatch.setenv(app.DATA_ROOT_ENV, str(data))
    monkeypatch.delenv('KMTECH_CA_UPDATE_DEFERRED_AT', raising=False)
    monkeypatch.delenv('KMTECH_CA_UPDATE_TRIAL_NONCE', raising=False)
    reached = []

    def enter_setup(root, **_kwargs):
        reached.append(Path(root))
        raise FirstSetupReached()

    monkeypatch.setattr(onboarding, 'resolve_current_user_onboarding_paths', enter_setup)
    return installed, control, active_app, reached


@pytest.mark.parametrize('phase,updated', [
    ('CONFIRMED', True), ('DEFERRED', True), ("PREPARED", True), ("UNKNOWN", True), ('CONFIRMED', False),
])
def test_actual_gui_start_enters_first_setup(first_setup, monkeypatch, phase, updated):
    root, control, active_app, reached = first_setup
    sha = NEW if updated else OLD
    active_app = root / 'versions' / sha / 'app'
    monkeypatch.setattr(app, '__file__', str(active_app / 'Container_Audit.py'))
    monkeypatch.setattr(updates, '__file__', str(active_app / 'auto_update.py'))
    (control / 'active.json').write_text(json.dumps(
        {'schema': updates.SCHEMA, 'sha': sha}))
    (control / 'transition.json').write_text(json.dumps(
        {'schema': updates.SCHEMA, 'phase': phase, 'candidate_sha': sha,
         'previous_sha': sha}))
    if phase in {"PREPARED", "UNKNOWN"}:
        monkeypatch.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', updates.now_utc())
    before = {path: path.read_bytes() for path in control.iterdir() if path.is_file()}
    assert updates.startup_gate(active_app, []) is None
    lifecycle_results = []
    resolve = updates.resolve_lifecycle_context
    def observe_lifecycle(*args, **kwargs):
        result = resolve(*args, **kwargs)
        lifecycle_results.append(result)
        return result
    monkeypatch.setattr(updates, "resolve_lifecycle_context", observe_lifecycle)
    with pytest.raises(FirstSetupReached):
        app._prepare_gui_startup()
    assert [result["status"] for result in lifecycle_results] == (["PASS"] if updated else [])
    assert reached == [active_app]
    assert all(path.read_bytes() == content for path, content in before.items())


@pytest.mark.parametrize('refusal', ['unapproved', 'inactive_code', 'other_sha', 'generation', 'system'])
def test_prepared_start_preserves_existing_refusal(first_setup, monkeypatch, refusal):
    root, control, active_app, reached = first_setup
    (control / 'transition.json').write_text(json.dumps(
        {'schema': updates.SCHEMA, 'phase': 'PREPARED', 'candidate_sha': NEW}))
    if refusal != 'unapproved':
        monkeypatch.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', updates.now_utc())
    if refusal == 'inactive_code':
        (control / 'active.json').write_text(json.dumps({'schema': updates.SCHEMA, 'sha': OLD}))
    if refusal == 'other_sha':
        monkeypatch.setattr(updates, 'process_snapshot', lambda *_args: [
            {'pid': 99123, 'observable': True, 'ordinary_user': True, 'sha': OLD,
             'sid': updates.current_process_sid(), 'role': 'relay',
             'created_at': updates.now_utc()}])
    if refusal == 'generation':
        monkeypatch.setattr(updates, 'current_generation_status', lambda *_args: 'REFUSE')
    if refusal == 'system':
        monkeypatch.setattr(updates, 'ordinary_user_context', lambda *_args: False)
    if refusal in {'other_sha', 'generation'}:
        with pytest.raises(ValueError):
            updates.startup_gate(active_app, [])
    else:
        assert updates.startup_gate(active_app, []) == (20 if refusal == 'system' else 0)
    assert reached == []


@pytest.mark.parametrize('phase', ['FAILED', 'UNKNOWN', 'APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'])
def test_other_accepted_deferred_starts_share_the_same_proof(first_setup, monkeypatch, phase):
    root, control, active_app, _reached = first_setup
    state = {'schema': updates.SCHEMA, 'phase': phase, 'candidate_sha': NEW,
             'previous_sha': NEW, 'nonce': 'b' * 32, 'transition_id': 'c' * 32}
    (control / 'transition.json').write_text(json.dumps(state))
    monkeypatch.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', updates.now_utc())
    monkeypatch.setattr(updates, 'apply_claim_status', lambda *_args: 'ABSENT')
    before = {path: path.read_bytes() for path in control.iterdir() if path.is_file()}
    assert updates.startup_gate(active_app, []) is None
    assert updates.resolve_lifecycle_context(root, operation='register', startup=True)['from_commit'] == NEW
    assert all(path.read_bytes() == content for path, content in before.items())


@pytest.mark.parametrize('phase', ['APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'])
@pytest.mark.parametrize('changed_claim', [False, True])
def test_trial_first_setup_rechecks_the_original_claim(first_setup, monkeypatch, phase, changed_claim):
    root, control, active_app, _reached = first_setup
    state = {'schema': updates.SCHEMA, 'phase': phase, 'candidate_sha': NEW,
             'previous_sha': NEW, 'nonce': 'b' * 32, 'transition_id': 'c' * 32}
    (control / 'transition.json').write_text(json.dumps(state))
    stage = Path(updates.read_json(control / 'policy.json')['staging_root'])
    claim = {'nonce': state['nonce'], 'transition_id': state['transition_id'], 'pid': os.getpid()}
    (stage / 'trial.json').write_text(json.dumps(claim))
    monkeypatch.setenv('KMTECH_CA_UPDATE_TRIAL_NONCE', state['nonce'])
    assert updates.startup_gate(active_app, []) is None
    if changed_claim:
        (stage / 'trial.json').write_text(json.dumps({**claim, 'pid': os.getpid() + 1}))
        with pytest.raises(ValueError):
            updates.resolve_lifecycle_context(root, operation='register', startup=True)
    else:
        assert updates.resolve_lifecycle_context(root, operation='register', startup=True)['from_commit'] == NEW


@pytest.mark.parametrize('change', ["no_gate", "generation", "system", "writer", "journal", "pid", "module"])
def test_registration_rechecks_start_proof_before_entering_setup(first_setup, monkeypatch, change):
    root, control, active_app, _reached = first_setup
    state = {'schema': updates.SCHEMA, 'phase': 'PREPARED', 'previous_sha': NEW,
             'candidate_sha': '3' * 40}
    (control / 'transition.json').write_text(json.dumps(state))
    monkeypatch.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', updates.now_utc())
    if change != 'no_gate':
        assert updates.startup_gate(active_app, []) is None
    if change == 'generation':
        monkeypatch.setattr(updates, 'current_generation_status', lambda *_args: 'REFUSE')
    elif change == 'system':
        monkeypatch.setattr(updates, 'ordinary_user_context', lambda *_args: False)
    elif change == 'writer':
        monkeypatch.setattr(updates, 'process_snapshot', lambda *_args: [
            {'pid': 99123, 'observable': True, 'ordinary_user': True, 'sha': OLD,
             'sid': updates.current_process_sid(), 'role': 'relay', 'created_at': updates.now_utc()}])
    elif change == 'journal':
        (control / 'transition.json').write_text(json.dumps({**state, 'candidate_sha': '4' * 40}))
    elif change == "pid":
        own_pid = os.getpid()
        monkeypatch.setattr(updates.os, "getpid", lambda: own_pid + 1)
    elif change == "module":
        monkeypatch.setattr(updates, "__file__", str(control.parent / "current/app/auto_update.py"))
    expected_cause = {
        "generation": "ordinary recovery requires current data generation allowance",
        "writer": "an earlier or unrelated writer prevents ordinary recovery",
    }.get(change, "lifecycle_transition_requires_recovery")
    public_message = re.escape(updates.LIFECYCLE_RECOVERY + " [ValueError]")
    with pytest.raises(ValueError, match="^" + public_message + "$") as failure:
        updates.resolve_lifecycle_context(root, operation='register', startup=True)
    assert isinstance(failure.value.__cause__, ValueError)
    assert str(failure.value.__cause__) == expected_cause


@pytest.mark.parametrize('operation', ['install', 'inspect', 'register'])
def test_start_proof_does_not_change_manual_classification(first_setup, monkeypatch, operation):
    root, control, active_app, _reached = first_setup
    (control / 'transition.json').write_text(json.dumps(
        {'schema': updates.SCHEMA, 'phase': 'PREPARED', 'candidate_sha': '3' * 40, 'previous_sha': NEW}))
    monkeypatch.setenv('KMTECH_CA_UPDATE_DEFERRED_AT', updates.now_utc())
    assert updates.startup_gate(active_app, []) is None
    with pytest.raises(ValueError):
        updates.resolve_lifecycle_context(root, operation=operation)


def test_manual_onboarding_clears_prior_startup_proof(first_setup, monkeypatch):
    root, control, active_app, _reached = first_setup
    (control / "transition.json").write_text(json.dumps({
        "schema": updates.SCHEMA, "phase": "PREPARED",
        "previous_sha": NEW, "candidate_sha": OLD,
    }))
    monkeypatch.setenv("KMTECH_CA_UPDATE_DEFERRED_AT", updates.now_utc())
    assert updates.startup_gate(active_app, []) is None
    assert updates.resolve_lifecycle_context(root, operation="register", startup=True)["status"] == "PASS"
    assert updates.startup_gate(active_app, ["--onboard-current-user"]) is None
    with pytest.raises(ValueError):
        updates.resolve_lifecycle_context(root, operation="register", startup=True)
