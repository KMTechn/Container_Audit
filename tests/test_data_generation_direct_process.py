"""G refusal must precede every independent owner-data CLI and state mutation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCENARIOS = ('register', 'register-hash', 'register-2pc', 'onboarding', 'supervisor', 'raw-relay',
             'operator-status', 'operator-pause', 'operator-resume', 'operator-retry-dead',
             'operator-restore-spool', 'profile-check', 'profile-install', 'install-pack', 'lifecycle',
             'removal', 'active-probe', 'review-report', 'gui', 'hosted-onboarding', 'hosted-supervisor')

def run_entry(tmp_path, scenario, generation_case):
    root = tmp_path / scenario
    root.mkdir()
    env = os.environ.copy()
    for name, suffix in (('LOCALAPPDATA', 'local'), ('APPDATA', 'roaming'), ('PROGRAMDATA', 'program'), ('TEMP', 'tmp'), ('TMP', 'tmp')):
        env[name] = str(root / suffix)
        Path(env[name]).mkdir(exist_ok=True)
    env['KMTECH_TEST_CA_WRITER_ROOT'] = str(root / 'control')
    env['KMTECH_TEST_CA_WRITER_MUTEX'] = 'Local.KMTech.CA.GClass.' + hashlib.sha256(str(root).encode()).hexdigest()[:16]
    completed = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('gclass_child.py')),
        str(Path.cwd()), scenario, str(root), generation_case], env=env, capture_output=True, text=True,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert completed.returncode == 0, completed.stderr[-1200:]
    return json.loads(completed.stdout.splitlines()[-1])

@pytest.mark.parametrize('scenario', SCENARIOS)
@pytest.mark.parametrize('generation_case', ('newer', 'other-build', 'corrupt'))
def test_direct_entry_refuses_before_identity_and_preserves_state(tmp_path, scenario, generation_case):
    observed = run_entry(tmp_path, scenario, generation_case)
    assert observed['data_reads'] == 0, observed
    assert observed['network_calls'] == 0, observed
    assert observed['relay_stops'] == observed['autostart_changes'] == observed['task_changes'] == 0, observed
    assert observed['korean_refusal'], observed
    assert observed['state_changes'] == [], observed
    assert observed['marker_changes'] == [], observed

@pytest.mark.parametrize('scenario', ('register', 'register-hash', 'profile-check', 'operator-status'))
@pytest.mark.parametrize('generation_case', ('allow', 'missing'))
def test_allowed_entry_reaches_existing_owner_read(tmp_path, scenario, generation_case):
    observed = run_entry(tmp_path, scenario, generation_case)
    assert observed['data_reads'] > 0, observed
    assert not observed['korean_refusal'], observed
