"""External-parent refusal and allowed reader controls, each in its own process."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCENARIOS = ('tls-profile', 'tls-onboarding', 'tls-onboarding-default', 'admin-gui', 'admin-gui-default',
             'admin-onboarding', 'admin-onboarding-default', 'admin-install', 'task-password',
             'lifecycle-receipt', 'register-tls', 'register-journal', 'register-context')

def run_input(tmp_path, scenario, generation_case, spelling='absolute'):
    root = tmp_path / 'probe'
    root.mkdir()
    env = os.environ.copy()
    for name, suffix in (('LOCALAPPDATA','local'), ('APPDATA','roaming'), ('PROGRAMDATA','program'),
                         ('TEMP','tmp'), ('TMP','tmp')):
        target = root / suffix
        target.mkdir(exist_ok=True)
        env[name] = str(target)
    for name in ('CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH', 'KM_LOGISTICS_PROFILE_PATH',
                 'CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH', 'CONTAINER_AUDIT_PROTECTED_ADMIN_PROFILE'):
        env.pop(name, None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    process = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('external_input_child.py')),
        str(Path.cwd()), scenario, str(root), generation_case, spelling], cwd=Path.cwd(), env=env,
        capture_output=True, text=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    (root/'child.stdout.txt').write_text(process.stdout, encoding='utf-8')
    (root/'child.stderr.txt').write_text(process.stderr, encoding='utf-8')
    assert process.returncode == 0, 'probe crashed; inspect owned child.stderr.txt'
    return json.loads(process.stdout.splitlines()[-1])

@pytest.mark.parametrize('scenario', SCENARIOS)
@pytest.mark.parametrize('generation_case', ('newer', 'unknown'))
def test_external_input_refuses_before_read_or_mutation(tmp_path, scenario, generation_case):
    value = run_input(tmp_path, scenario, generation_case)
    assert value['status'] == ('REFUSE' if generation_case == 'newer' else 'UNKNOWN'), value
    assert value['observed'] == dict(input_reads=0, network_calls=0, native_calls=0), value
    assert value['changed_file_count'] == 0, value
    assert value['external_marker_preserved'], value

@pytest.mark.parametrize('scenario', SCENARIOS)
@pytest.mark.parametrize('generation_case', ('same', 'missing'))
def test_external_input_allowed_control(tmp_path, scenario, generation_case):
    value = run_input(tmp_path, scenario, generation_case)
    assert value['status'] == 'NONE', value
    assert value['observed']['native_calls'] == value['observed']['network_calls'] == 0, value
    if scenario != 'admin-install':
        assert value['observed']['input_reads'] > 0, value
    assert value['external_marker_preserved'], value

@pytest.mark.parametrize('scenario', ('tls-profile','tls-onboarding','admin-gui','task-password','lifecycle-receipt','register-tls'))
@pytest.mark.parametrize('spelling', ('relative','tilde','case'))
def test_external_input_spelling_uses_the_admitted_reader_path(tmp_path, scenario, spelling):
    value = run_input(tmp_path, scenario, 'newer', spelling)
    assert value['status'] == 'REFUSE', value
    assert value['observed'] == dict(input_reads=0, network_calls=0, native_calls=0), value
    assert value['changed_file_count'] == 0, value

NESTED = tuple('nested-' + entry + '-' + value for entry in ('raw','onboard','operator','pack','registrar','gui','resident')
               for value in ('secret-explicit','secret-default','tls'))

@pytest.mark.parametrize('scenario', NESTED)
@pytest.mark.parametrize('generation_case', ('newer','unknown','same','missing'))
def test_nested_credential_admission_precedes_every_mutation(tmp_path, scenario, generation_case):
    value = run_input(tmp_path, scenario, generation_case)
    assert value['locator_reads'] == 1, value
    assert value['observed']['network_calls'] == value['observed']['native_calls'] == 0, value
    if generation_case in ('newer','unknown'):
        assert value['status'] == ('REFUSE' if generation_case == 'newer' else 'UNKNOWN'), value
        assert value['observed']['input_reads'] == 0, value
        assert value['changed_file_count'] == 0, value
    else:
        assert value['status'] == 'NONE', value
        if scenario.startswith(('nested-gui','nested-resident')):
            assert value['observed']['input_reads'] == 0, value
        elif not scenario.startswith('nested-operator') or not scenario.endswith('tls'):
            assert value['observed']['input_reads'] == 1, value
    assert value['external_marker_preserved'], value

def test_credential_locator_is_admitted_before_its_first_read(tmp_path):
    value = run_input(tmp_path, 'nested-raw-locator-high-explicit', 'newer')
    assert value['status'] == 'REFUSE', value
    assert value['locator_reads'] == value['observed']['input_reads'] == 0, value
    assert value['changed_file_count'] == 0, value

def test_valid_locator_unresolvable_nested_path_is_unknown_before_mutation(tmp_path):
    value = run_input(tmp_path, 'nested-raw-unresolvable-explicit', 'missing')
    assert value['status'] == 'UNKNOWN', value
    assert value['locator_reads'] == 1 and value['observed']['input_reads'] == 0, value
    assert value['changed_file_count'] == 0, value

def test_malformed_locator_retains_admitted_install_pack_diagnostic(tmp_path):
    value = run_input(tmp_path, 'nested-pack-malformed-explicit', 'missing')
    assert value['status'] == 'NONE' and value['result'] == 2, value
    assert value['locator_reads'] == 1 and value['observed']['input_reads'] == 0, value
    assert value['report_change_count'] == 1, value
    assert value['observed']['network_calls'] == value['observed']['native_calls'] == 0, value
