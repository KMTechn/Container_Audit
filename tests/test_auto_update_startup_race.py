"""Daily updater/startup races, through the real gate and transition engine."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
import auto_update as updates
import current_user_onboarding as onboarding
from kmtech_shared import data_generation as generation
import writer_session_fence as fence
from tests.test_auto_update_endpoints import endpoint, hotfix_packet, OLD, NEW
from tests.test_supported_lifecycle import installed
from tests.update_mutex_namespace import isolate_update_mutex_names

pytestmark = pytest.mark.usefixtures("clean_shared_writer_root")

REAL_LOCK = updates.update_lock
MONOTONIC, SLEEP = time.monotonic, time.sleep
REPO = Path(updates.__file__).parent


@pytest.fixture(autouse=True)
def test_update_namespace(monkeypatch):
    isolate_update_mutex_names(monkeypatch)


@pytest.fixture
def startup_installation(tmp_path, monkeypatch):
    control = tmp_path / 'managed/update-control'
    control.mkdir(parents=True)
    stage, local = tmp_path / 'stage', tmp_path / 'local'
    stage.mkdir(); local.mkdir()
    sid = updates.current_process_sid()
    policy = dict(schema='container-audit-startup-update-policy-v1', operator_sid=sid,
                  operator_local_app_data=str(local), staging_root=str(stage),
                  feed_url='https://updates.invalid/feed', channel='stable')
    updates.write_json_durable(control / 'policy.json', policy)
    updates.write_json_durable(control / 'active.json', dict(schema=updates.SCHEMA, sha=OLD))
    updates.write_json_durable(control / 'transition.json',
                               dict(schema=updates.SCHEMA, phase='CONFIRMED', candidate_sha=OLD))
    for bundle in (control.parent / 'current', updates.version_bundle(control, OLD)):
        (bundle / 'app').mkdir(parents=True)
        for name in (*updates.CONTRACT_FILES, *("app/" + name for name in updates.DATA_API_FILES)):
            target = bundle / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / name.removeprefix('app/')).read_bytes())
        (bundle / 'app/Container_Audit.py').write_text('CURRENT_VERSION = "v2.0.98"\n')
        updates.write_json_durable(bundle / 'portable-manifest.json', {
            'schema': 'container-audit-portable-tree-v1', 'startup_update_protocol': 1,
            'source_commit': OLD, 'version': 'v2.0.98',
            'writer_sink_inventory_contract_sha256': 'a' * 64})
    marker = fence.canonical_control_root({'LOCALAPPDATA': str(local)}) / 'data-generation' / (sid + '.json')
    marker.parent.mkdir(parents=True, exist_ok=True)
    generation.record_generation(marker, 'v2.0.98', app_id='container_audit', subject_sid=sid, build_id=OLD)
    monkeypatch.setattr(updates, 'ordinary_user_context', lambda *_: True)
    delegated = []
    monkeypatch.setattr(updates, 'request_bootstrap', lambda *a, **k: delegated.append((a, k)))
    return control, policy, marker, delegated


@contextlib.contextmanager
def holder(control, policy, delay, *, live=False):
    ready = control.parent / 'holder-ready'
    process = subprocess.Popen(
        [sys.executable, '-B', str(REPO / 'tests/update_startup_race_child.py'),
         str(control), policy['operator_sid'], str(ready), str(delay), 'live' if live else 'none'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = MONOTONIC() + 15
        while not ready.exists() and process.poll() is None and MONOTONIC() < deadline:
            SLEEP(0.01)
        assert ready.exists(), 'test holder did not acquire its isolated mutex'
        yield process
    finally:
        process.communicate()
        assert process.returncode == 0


@pytest.mark.parametrize('delay,live', [(6, False), (30, True)])
def test_startup_waits_for_real_other_process_then_admits_current(startup_installation, delay, live):
    control, policy, _, delegated = startup_installation
    original = (control / 'transition.json').read_bytes()
    with holder(control, policy, delay, live=live):
        started = MONOTONIC()
        assert updates.startup_gate(control.parent / 'current/app', []) is None
        assert MONOTONIC() - started >= delay - 0.5
    assert not delegated
    assert (control / 'transition.json').read_bytes() == original


@pytest.mark.parametrize('console', [True, False])
def test_startup_wait_limit_admits_current_with_zero_exit_record(startup_installation, monkeypatch, capsys, console):
    control, policy, _, delegated = startup_installation
    monkeypatch.setattr(updates, 'APPLY_PROGRESS_TIMEOUT', 0.2)
    original = {p.name: p.read_bytes() for p in control.glob('*.json')}
    with holder(control, policy, 6):
        started = MONOTONIC()
        with monkeypatch.context() as stream:
            if not console:
                stream.setattr(sys, 'stdout', None)
            assert updates.startup_gate(control.parent / 'current/app', []) is None
        assert MONOTONIC() - started < 2
    output = capsys.readouterr().out
    report = updates.read_json(Path(policy['staging_root']) / 'startup-support.json')
    if console:
        assert json.loads(output.split('=', 1)[1]) == report
    else:
        assert not output
    assert report['reason_code'] == 'UPDATE_LOCK_WAIT_EXPIRED'
    assert report['exit_code'] == 0
    assert not delegated
    assert {p.name: p.read_bytes() for p in control.glob('*.json')} == original

@pytest.mark.parametrize('refusal', ['generation', 'different_active', 'trial', 'recovery', 'retained_pointer'])
def test_lock_limit_preserves_current_version_refusals(startup_installation, monkeypatch, refusal):
    control, policy, marker, delegated = startup_installation
    monkeypatch.setattr(updates, 'APPLY_PROGRESS_TIMEOUT', 0.2)
    if refusal == 'generation':
        generation.record_generation(marker, 'v9.0.0', app_id='container_audit',
                                     subject_sid=policy['operator_sid'], build_id=NEW)
    elif refusal == 'different_active':
        updates.write_json_durable(control / 'active.json', dict(schema=updates.SCHEMA, sha=NEW))
    elif refusal == 'retained_pointer':
        updates.write_json_durable(control / 'transition.json', dict(
            schema=updates.SCHEMA, phase='DEFERRED', retained_candidate=True,
            previous_sha=OLD, candidate_sha=NEW, failure_decision={'selected_sha': NEW}))
    else:
        state = updates.read_json(control / 'transition.json')
        state.update(phase='APPLIED_PENDING_READY' if refusal == 'trial' else 'DEFERRED',
                     recovery_pending=refusal == 'recovery')
        updates.write_json_durable(control / 'transition.json', state)
    with holder(control, policy, 6):
        assert updates.startup_gate(control.parent / 'current/app', []) == 20
    assert not delegated


def test_abandoned_lock_is_not_treated_as_contention(startup_installation, monkeypatch):
    control, policy, _, _ = startup_installation
    import ctypes
    native = ctypes.WinDLL
    def abandoned(name, *args, **kwargs):
        library = native(name, *args, **kwargs)
        if str(name).lower() == 'kernel32':
            library.WaitForSingleObject = lambda *_: 0x80
        return library
    monkeypatch.setattr(ctypes, 'WinDLL', abandoned)
    with pytest.raises(RuntimeError):
        updates.startup_gate(control.parent / 'current/app', [])


def fingerprints(control):
    return {p.relative_to(control).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in control.rglob('*') if p.is_file()}


@pytest.mark.parametrize('marker_shape', ['valid', 'malformed', 'unreadable'])
def test_failed_prepared_is_preserved_once_without_second_state_write(endpoint, monkeypatch, marker_shape):
    control, stage, policy, _, _, _ = endpoint
    policy['operator_sid'] = updates.current_process_sid()
    updates.write_json_durable(control / 'policy.json', policy)
    monkeypatch.setattr(updates, 'update_lock', REAL_LOCK)
    monkeypatch.setattr(time, 'monotonic', MONOTONIC)
    monkeypatch.setattr(time, 'sleep', SLEEP)
    (control / 'transition.json').unlink()
    updates.write_json_durable(control / 'active.json', {'sha': OLD})
    candidate = hotfix_packet(endpoint, monkeypatch)
    signature = bytearray((stage / 'manifest.sig').read_bytes())
    signature[0] ^= 1
    (stage / 'manifest.sig').write_bytes(signature)
    if marker_shape == 'malformed':
        (stage / 'prepared.json').write_bytes(b'{invalid')
    prepared = (stage / 'prepared.json').read_bytes()
    if marker_shape == 'unreadable':
        checked = updates._assert_no_reparse_components
        def refuse_marker(path):
            if Path(path) == stage / 'prepared.json':
                raise ValueError('prepared marker path is untrusted')
            return checked(path)
        monkeypatch.setattr(updates, '_assert_no_reparse_components', refuse_marker)
    assert updates.apply_prepared(control) == 0
    assert len(list(control.glob('failure-*.json'))) == 1
    assert updates.read_json(control / 'transition.json')['reason_code'] == 'UPDATE_PREPARATION_FAILED'
    before = fingerprints(control)
    assert updates.apply_prepared(control) == 0
    assert fingerprints(control) == before
    assert (stage / 'prepared.json').read_bytes() == prepared
    assert not updates.prepared_pending(control, policy, updates.read_json(control / 'transition.json'))
    if marker_shape == 'valid':
        updates.write_json_durable(stage / 'prepared.json', {'source_commit': candidate, 'prepared_at': updates.now_utc()})
        assert updates.apply_prepared(control) == 0
        assert fingerprints(control) == before
        updates.write_json_durable(stage / 'prepared.json', {'source_commit': NEW})
        assert updates.prepared_pending(control, policy, updates.read_json(control / 'transition.json'))


@pytest.fixture
def lifecycle_race(installed, monkeypatch):
    control = installed / 'update-control'
    policy = updates.read_json(control / 'policy.json')
    policy['staging_root'] = str(installed / 'user-staging')
    Path(policy['staging_root']).mkdir()
    policy['operator_sid'] = updates.current_process_sid()
    updates.write_json_durable(control / 'policy.json', policy)
    state = dict(schema=updates.SCHEMA, phase='DEFERRED', candidate_sha=NEW,
                 deferred_at=(datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat())
    updates.write_json_durable(control / 'transition.json', state)
    def rewrite(change):
        def task_present(*_):
            with REAL_LOCK(control, policy['operator_sid']):
                if change == 'diagnostic':
                    updates.write_json_durable(control / 'transition.json', {**state, 'deferred_at': updates.now_utc()})
                elif change == 'pointer':
                    updates.write_json_durable(control / 'active.json', dict(schema=updates.SCHEMA, sha=OLD))
                elif change == 'unknown':
                    (control / 'transition.json').write_bytes(b'{invalid')
            return True
        monkeypatch.setattr(updates, 'supported_task_present', task_present)
    return installed, rewrite


def test_lifecycle_rereads_equal_meaning_under_real_update_lock(lifecycle_race):
    root, rewrite = lifecycle_race
    rewrite('diagnostic')
    result = updates.resolve_lifecycle_context(root, operation='register', startup=True)
    assert result['status'] == 'PASS'
    assert result['from_commit'] == NEW


@pytest.mark.parametrize('change,status', [('pointer', 'CHANGED'), ('unknown', 'UNKNOWN')])
def test_startup_lifecycle_change_keeps_current_root_with_record(lifecycle_race, monkeypatch, capsys, change, status):
    root, rewrite = lifecycle_race
    rewrite(change)
    reached = []
    class CurrentRootReached(Exception):
        pass
    def paths(app_root, **kwargs):
        reached.append(Path(app_root))
        raise CurrentRootReached()
    import data_generation_guard
    monkeypatch.setattr(data_generation_guard, 'warm_runtime_release', lambda: None)
    monkeypatch.setattr(onboarding, 'resolve_current_user_onboarding_paths', paths)
    app = root / 'versions' / NEW / 'app'
    with monkeypatch.context() as stream:
        stream.setattr(sys, 'stdout', None)
        with pytest.raises(CurrentRootReached):
            onboarding.onboard_current_user(app, startup=True)
    assert reached == [app]
    policy = updates.read_json(root / 'update-control/policy.json')
    report = updates.read_json(Path(policy['staging_root']) / 'startup-support.json')
    assert not capsys.readouterr().out
    assert report['reason_code'] == 'UPDATE_LIFECYCLE_' + status
    assert report['exit_code'] == 0

@pytest.mark.parametrize('change', ['pointer', 'diagnostic'])
def test_manual_lifecycle_change_still_refuses(lifecycle_race, monkeypatch, change):
    root, rewrite = lifecycle_race
    rewrite(change)
    import data_generation_guard
    monkeypatch.setattr(data_generation_guard, 'warm_runtime_release', lambda: None)
    with pytest.raises(ValueError):
        onboarding.onboard_current_user(root / 'versions' / NEW / 'app')

@pytest.fixture
def fast_native_wait(monkeypatch):
    """Advance the 240-second supervision clock on real native contention."""
    import ctypes
    clock = [0.0]
    native = ctypes.WinDLL
    class Wait:
        def __init__(self, function):
            object.__setattr__(self, 'function', function)
        def __setattr__(self, name, value):
            setattr(self.function, name, value)
        def __call__(self, handle, milliseconds):
            result = self.function(handle, 0)
            if result == 0x102 and milliseconds:
                clock[0] += 60
            return result
    def accelerated(name, *args, **kwargs):
        library = native(name, *args, **kwargs)
        if str(name).lower() == 'kernel32':
            library.WaitForSingleObject = Wait(library.WaitForSingleObject)
        return library
    monkeypatch.setattr(ctypes, 'WinDLL', accelerated)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    return clock


@pytest.mark.parametrize('entry', ['gate', 'bootstrap'])
def test_live_claim_bound_starts_allowed_current_after_native_contention(
        startup_installation, fast_native_wait, monkeypatch, capsys, entry):
    control, policy, _, delegated = startup_installation
    launches = []
    monkeypatch.setattr(updates, 'launch_version', lambda *_args, **_kwargs: launches.append(_args))
    with holder(control, policy, 6, live=True):
        if entry == 'gate':
            assert updates.startup_gate(control.parent / 'current/app', []) is None
        else:
            assert updates.bootstrap(control.parent / 'current/app', [], role='gui') == 0
    assert fast_native_wait[0] == 240
    assert not delegated
    if entry == 'gate':
        report = json.loads(capsys.readouterr().out.split('=', 1)[1])
        assert not launches
    else:
        report = updates.read_json(Path(policy['staging_root']) / 'startup-support.json')
        assert len(launches) == 1 and launches[0][1] == OLD
    assert report['reason_code'] == 'UPDATE_LOCK_WAIT_EXPIRED'
    assert report['exit_code'] == 0
