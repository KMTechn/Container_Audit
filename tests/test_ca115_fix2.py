"""Fresh canonical scope and observation-cost regressions for review F2/F3."""
from pathlib import Path
import shutil

import pytest

import auto_update as updates
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('proof', ['NEVER_STARTED', 'PROFILE_ABSENT', 'USER_RECEIPT', 'ACCOUNT_UNAVAILABLE'])
def test_canonical_worker_proof_in_fresh_ps51(tmp_path, proof):
    engine = shutil.which('powershell.exe')
    assert engine, 'Windows PowerShell 5.1 required'
    result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'tests/canonical_worker_removal_scope.ps1'),
        '-Root', str(ROOT), '-Scratch', str(tmp_path), '-Proof', proof])
    # No child diagnostics or identifiers enter pytest failure output.
    assert result.returncode == 0, 'canonical worker proof failed'
    assert result.stdout.strip() == 'PASS ' + proof


def test_trial_relay_observes_only_when_attempt_is_eligible(monkeypatch):
    clock = [10.0]
    observations, launches = [], []
    monkeypatch.setattr(updates, 'apply_claim_status', lambda *_: 'PRESENT')
    monkeypatch.setattr(updates.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(updates, 'process_snapshot', lambda *_: observations.append(clock[0]) or [])
    monkeypatch.setattr(updates, 'writer_processes', lambda rows, **_: rows)
    monkeypatch.setattr(updates, '_launch_bootstrap_version', lambda *a, **k: launches.append(clock[0]))
    state = {'nonce': 'trial', 'transition_id': 'transition'}
    active, policy, attempts = {'sha': 'candidate'}, {'operator_sid': 'synthetic'}, {}
    for tick in (10, 10.25, 11.99, 12, 12.25, 14, 16, 20):
        clock[0] = tick
        updates._bootstrap_trial_relay(Path('unused'), policy, state, active, [], attempts, deadline=30)
    assert observations == [10, 12, 14]
    assert launches == [10, 12, 14]
    clock[0] = 30
    updates._bootstrap_trial_relay(Path('unused'), policy, state, active, [], {}, deadline=30)
    assert observations == [10, 12, 14]
