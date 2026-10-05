"""Execute a real CA entry in a child against synthetic owner artifacts."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import sys

source, scenario, root, generation_case = sys.argv[1:]
is_external = generation_case.startswith('external')
sys.path.insert(0, source)
root = Path(root)
data = root / 'data'
data.mkdir(parents=True, exist_ok=True)
os.environ['CONTAINER_AUDIT_DATA_ROOT'] = str(data)
from tools import register_container_audit_worker_pc as registration
registration._current_user_sid = lambda: 'S-1-5-21-233-233-233-1001'
registration._current_machine_guid = lambda: '23323323-3233-4233-8233-233233233233'
from data_generation_guard import marker_paths, _runtime_release
from kmtech_shared import data_generation as generation
from storage_policy import build_container_audit_storage_paths
from writer_session_fence import writer_admission

storage = build_container_audit_storage_paths(application_path=source)
paths = marker_paths(data, registration._current_user_sid())
release = _runtime_release()
for path in paths:
    path.parent.mkdir(parents=True, exist_ok=True)
    if generation_case == 'corrupt':
        path.write_text('{', encoding='utf-8')
    elif generation_case != 'missing' and not is_external:
        generation.record_generation(path, app_id='container_audit', subject_sid=registration._current_user_sid(),
            version='v999.0.0' if generation_case == 'newer' else release['version'],
            build_id='b'*40 if generation_case != 'allow' else release['build_id'],
            data_compatible_min_version='v999.0.0' if generation_case == 'newer' else release['version'],
            compatibility_verified=False)

identity = storage.direct_sync_root / registration.PRODUCER_IDENTITY_FILENAME
external = root/'external'
if is_external:
    external.mkdir()
    generation.record_generation(external/'data-generation.json', app_id='container_audit',
        subject_sid=registration._current_user_sid(), version='v999.0.0',build_id='b'*40,
        data_compatible_min_version='v999.0.0',compatibility_verified=False)
    identity = external/'identity.json'
identity.parent.mkdir(parents=True, exist_ok=True)
identity.write_text(json.dumps({'schema_version': registration.PRODUCER_IDENTITY_SCHEMA_VERSION,
    **{name: 'synthetic-' + name.replace('_', '-') for name in registration.PRODUCER_IDENTITY_REQUIRED_FIELDS}}), encoding='utf-8')
credential = storage.credential_path
if is_external: credential = external/'credential.bin'
credential.parent.mkdir(parents=True, exist_ok=True)
credential.write_text('{}', encoding='utf-8')
manifest = storage.producer_manifest_path
if is_external: manifest = external/'manifest.json'
manifest.write_text('{}', encoding='utf-8')
profile = root/'profile/logistics-profile.json'
if is_external: profile = external/'profile.json'
if generation_case == 'external-default':
    from logistics_runtime_profile import default_logistics_profile_path
    for name in ('CONTAINER_AUDIT_DATA_ROOT','KM_LOGISTICS_PROFILE_PATH','CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH'):
        os.environ.pop(name, None)
    profile = default_logistics_profile_path()
    profile.parent.mkdir(parents=True, exist_ok=True)
    generation.record_generation(profile.parent/'data-generation.json',app_id='container_audit',
        subject_sid=registration._current_user_sid(),version='v999.0.0',build_id='b'*40,
        data_compatible_min_version='v999.0.0',compatibility_verified=False)
profile.parent.mkdir(parents=True, exist_ok=True)
profile.write_text('{}', encoding='utf-8')
queue = storage.direct_sync_root/'queue/relay.sqlite3'
if is_external: queue = external/'queue.sqlite3'
queue.parent.mkdir(parents=True, exist_ok=True)
queue.write_bytes(b'synthetic owner queue')
resident_status = storage.direct_sync_root/'status/resident-existing.json'
resident_status.parent.mkdir(parents=True, exist_ok=True)
resident_status.write_text('{"status":"RUNNING","preserved":true}', encoding='utf-8')
onboard_report = storage.direct_sync_root/'status/current_user_onboarding.json'
onboard_report.parent.mkdir(parents=True, exist_ok=True)
onboard_report.write_text('{"status":"READY","preserved":true}', encoding='utf-8')
raw_status = storage.direct_sync_root/'status/direct_sync_relay_status.json'
raw_status.write_text('{"status":"PASS"}', encoding='utf-8')
os.environ['CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH'] = str(profile)
os.environ['KM_LOGISTICS_PROFILE_PATH'] = str(profile)
if generation_case == 'external-default':
    os.environ.pop('KM_LOGISTICS_PROFILE_PATH',None)
    os.environ.pop('CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH',None)
if generation_case == 'external-tilde': os.environ['USERPROFILE'] = str(root)
if generation_case == 'external-link':
    import subprocess
    link = root/'link'
    assert external.resolve().is_relative_to(root.resolve())
    completed = subprocess.run(['cmd.exe','/c','mklink','/J',str(link),str(external)],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, 'isolated junction creation failed'

def argument(path):
    if generation_case == 'external-tilde': return '~/' + path.relative_to(root).as_posix()
    if generation_case == 'external-relative': return os.path.relpath(path, Path.cwd())
    if generation_case == 'external-case': return str(path).swapcase()
    if generation_case == 'external-link': return str(link/path.relative_to(external))
    return str(path)
watched = {str(p.resolve()).casefold() for p in (identity, credential, manifest, profile, queue, raw_status)}
observed = {'data_reads': 0, 'network_calls': 0, 'relay_stops': 0, 'autostart_changes': 0, 'task_changes': 0}

def snapshot():
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and not p.name.endswith('.lock')}

before = snapshot()
class BoundaryReached(Exception):
    pass

def audit(event, args):
    if event == 'ctypes.dlsym' and str(args[1]).startswith('NCrypt'):
        raise BoundaryReached('host CNG is forbidden')
    if event == 'socket.connect':
        observed['network_calls'] += 1
        raise BoundaryReached('all child network is forbidden')
    if event == 'subprocess.Popen':
        command = args[0]
        if not command:
            command = args[1][0] if isinstance(args[1], (tuple, list)) else str(args[1]).split(' ', 1)[0]
        executable = Path(str(command).strip('"')).name.casefold()
        if executable not in ('git', 'git.exe'):
            if 'schtasks' in executable:
                observed['task_changes'] += 1
            raise BoundaryReached('native command replaced by isolated boundary')
    if event == 'sqlite3.connect':
        from urllib.parse import unquote
        selected = str(args[0])
        if selected.startswith('file:'):
            selected = unquote(selected[5:].split('?', 1)[0])
        if str(Path(selected).resolve()).casefold() in watched:
            observed['data_reads'] += 1
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = str(Path(os.fsdecode(args[0])).resolve()).casefold()
        if path in watched and ('r' in str(args[1]) or args[1] is None):
            observed['data_reads'] += 1
sys.addaudithook(audit)

import requests
def network(*args, **kwargs):
    observed['network_calls'] += 1
    raise BoundaryReached('network forbidden')
requests.Session.request = network
import user_relay
def registry_change(*args, **kwargs):
    observed['autostart_changes'] += 1
user_relay._registry_set = registry_change
user_relay._registry_delete = registry_change
user_relay._registry_get = lambda: 'preserved synthetic autostart'
def stop(*args, **kwargs):
    observed['relay_stops'] += 1
    return {'status': 'ABSENT'}
user_relay.request_user_relay_stop = stop
def child(*args, **kwargs):
    if generation_case in ('allow', 'missing'):
        return {'status': 'PASS', 'returncode': 0}
    raise BoundaryReached('real relay launch forbidden')
user_relay.run_session_direct_sync_once = child
user_relay.start_user_relay_process = child

def execute():
    if scenario.startswith('register'):
        args = ['--app-root', source, '--producer-identity-path', argument(identity), '--report-path', str(root/'registration-report.json')]
        if scenario == 'register-hash':
            args += ['--manifest-path', str(manifest), '--verify-manifest-hash', '0'*64]
        if scenario == 'register-2pc':
            args += ['--admin-recovery-two-phase', '--admin-recovery-secret-file', str(root/'synthetic-recovery.json')]
        return registration.main(args)
    if scenario == 'onboarding':
        from current_user_onboarding import onboarding_main
        return onboarding_main(['--app-root', source])
    if scenario == 'supervisor':
        return user_relay.main(['--app-root', source, '--data-root', str(data), '--once'] +
            (['--direct-sync-root',str(external)] if is_external else []))
    if scenario == 'resident-cycle':
        result = user_relay.run_persistent_relay_loop(
            lambda: user_relay._runtime_cycle(app_root=Path(source), direct_sync_root=external if is_external else storage.direct_sync_root,
                                             scan_source_dir=storage.events_dir),
            status_path=storage.direct_sync_root/'status/resident-existing.json', max_cycles=1)
        print(result.get('last_cycle', {}).get('error_message', ''))
        return 1
    if scenario == 'raw-relay':
        from tools.direct_sync_relay_runner import main
        return main(['--db-path', str(queue), '--spool-dir', str(root/'spool'),
            '--producer-manifest-path', str(manifest), '--credential-path', str(credential),
            '--upload-status-dir', str(root/'uploads'), '--runtime-status-path', str(root/'raw-status.json'), '--log-path', str(root/'raw-log.jsonl')])
    if scenario.startswith('operator-'):
        from tools.direct_sync_relay_operator import main
        mode = scenario.removeprefix('operator-')
        if mode == 'status':
            args = [mode, '--db-path', str(queue)]
        elif mode in ('pause', 'resume'):
            args = [mode, '--operator-pause-path', str((external if is_external else root)/'pause.json'), '--operator-id', 'test', '--reason', 'synthetic']
        elif mode == 'resolve-review':
            args = [mode, '--db-path', str(queue), '--relay-id', 'synthetic', '--operator-id', 'test', '--reason', 'synthetic',
                '--resolution', 'historical_local_only', '--evidence-path', str(root/'evidence.json'), '--evidence-sha256', 'a'*64,
                '--expected-request-id', 'synthetic', '--expected-server-source-file-id', 'synthetic', '--expected-relative-path', 'synthetic',
                '--expected-byte-length', '1', '--expected-inserted-count', '0', '--expected-replayed-count', '0',
                '--expected-error-count', '0', '--expected-quarantined-count', '0', '--expected-content-sha256', 'a'*64, '--audit-log-path', str(root/'audit.jsonl')]
        elif mode == 'retry-dead':
            args = [mode, '--db-path', str(queue), '--relay-id', 'synthetic', '--operator-id', 'test', '--reason', 'synthetic', '--expected-error-code', 'synthetic']
        else:
            args = [mode, '--db-path', str(queue), '--relay-id', 'synthetic', '--spool-root', str(root/'spool'), '--credential-path', str(credential), '--operator-id', 'test', '--reason', 'synthetic']
        return main(args)
    if scenario == 'profile-check':
        from tools.check_logistics_runtime_profile import main
        return main(['--profile-path', argument(profile)])
    if scenario == 'profile-check-default':
        from tools.check_logistics_runtime_profile import main
        return main([])
    if scenario in ('profile-check-empty','profile-check-env'):
        from tools.check_logistics_runtime_profile import main
        return main(['--profile-path',''] if scenario=='profile-check-empty' else [])
    if scenario == 'profile-install':
        from tools.install_logistics_runtime_profile import main
        os.environ['KMTECH_GCLASS_SYNTHETIC_TOKEN'] = 'synthetic-test-input'
        return main(['--profile-path', str(profile), '--base-url', 'https://127.0.0.1', '--authority-scope', 'test',
            '--authority-epoch', '1', '--plane-epoch', '1', '--device-id', 'test', '--source-host-id', 'test',
            '--token-env', 'KMTECH_GCLASS_SYNTHETIC_TOKEN', '--replace'])
    if scenario == 'install-pack':
        from tools.direct_sync_relay_install_pack import main
        return main(['--app-root', source, '--report-path', str(root/'install-pack-report.json')] +
            (['--credential-path',str(credential)] if is_external else []))
    if scenario == 'lifecycle':
        from current_user_onboarding import restore_current_user_lifecycle_after_replacement
        return restore_current_user_lifecycle_after_replacement(source, code_root=source,
            session_id='a'*32, attempt_id='c'*32, session_started_at_utc='2026-10-04T12:00:00Z',
            orchestrator_sha256='d'*64, replacement_transaction_id='e'*32,
            replacement_receipt_path=root/'receipt.json', replacement_receipt_sha256='f'*64, writer_contract_sha256='a'*64)
    if scenario == 'removal':
        from current_user_onboarding import remove_current_user_setup
        return remove_current_user_setup(source, relay_stopper=stop)
    if scenario == 'active-probe':
        if is_external:
            from types import SimpleNamespace
            from kmtech_factory_contracts.active_work_probe import adapters
            adapters.create_adapter = lambda app, target: SimpleNamespace(data_root=data,
                direct_sync_root=external,profile_path=profile,legacy_profile_paths=())
        from tools.active_work_probe import main
        return main(['-Mode', 'active-work-evidence', '-App', 'Container_Audit', '-OutputPath', str(root/'active-work.json'),
            '-TargetPc','TEST1','-ReleaseRunId','23323323-3233-4233-8233-233233233233',
            '-CanaryRunId','23323323-3233-4233-8233-233233233234'])
    if scenario == 'review-report':
        from tools.build_operator_review_case_report import main
        return main(['--case', str(manifest), '--quarantine-detail', str(credential), '--out-json', str(root/'review.json'), '--out-md', str(root/'review.md')])
    if scenario == 'gui':
        import Container_Audit as app
        app.messagebox.showerror = lambda _title, message: print(message)
        return app.main(['--data-root', str(data)])
    if scenario.startswith('hosted-'):
        from container_audit_product_host import dispatch_product_mode, ONBOARD_CURRENT_USER_MODE, USER_RELAY_MODE
        mode = scenario.removeprefix('hosted-')
        if mode == 'onboarding':
            return dispatch_product_mode([ONBOARD_CURRENT_USER_MODE, '--app-root', source])
        return dispatch_product_mode([USER_RELAY_MODE, '--app-root', source, '--data-root', str(data), '--once'] +
            (['--direct-sync-root',str(external)] if is_external else []))
    raise AssertionError(scenario)

capture = io.StringIO()
error = ''
with redirect_stdout(capture), redirect_stderr(capture):
    try:
        result = execute()
    except Exception as exc:
        error = str(exc)
        result = 1
output = capture.getvalue() + error
# Installer children serialize fixed G guidance inside the approved record.
# Decode that boundary for the existing refusal observation without accepting
# arbitrary exception text or weakening the no-read/no-write assertions.
prefix = 'CONTAINER_AUDIT_INSTALLER_FAILURE='
for line in capture.getvalue().splitlines():
    if not line.startswith(prefix):
        continue
    try:
        record = json.loads(line[len(prefix):])
    except ValueError:
        continue
    if (record.get('reason_code') == 'DATA_GENERATION_REFUSED'
            and record.get('guidance') == generation.REFUSAL_MESSAGE):
        output += generation.REFUSAL_MESSAGE
    elif (record.get('reason_code') == 'DATA_GENERATION_UNKNOWN'
            and record.get('guidance') == generation.UNKNOWN_MESSAGE):
        output += generation.UNKNOWN_MESSAGE
# Disable only observation after the entry finished; snapshot is test readback.
watched.clear()
after = snapshot()
changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
print(json.dumps({**observed, 'result': result if isinstance(result, int) else None,
    'korean_refusal': generation.REFUSAL_MESSAGE in output or generation.UNKNOWN_MESSAGE in output,
    'g_status': 'REFUSE' if generation.REFUSAL_MESSAGE in output else 'UNKNOWN' if generation.UNKNOWN_MESSAGE in output else 'NONE',
    'state_changes': [name for name in changed if 'data-generation' not in name],
    'marker_changes': [name for name in changed if 'data-generation' in name]}, ensure_ascii=True))
