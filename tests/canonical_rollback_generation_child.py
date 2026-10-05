"""Real entrypoint/reader probes with synthetic state and no host lifecycle."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

source, scenario, root, generation_case, spelling = sys.argv[1:6]
requested_scenario = scenario
if scenario in {"nested-readonly", "nested-final-target"}:
    scenario = "nested-onboard-secret-explicit"
source, root = Path(source), Path(root)
sys.path.insert(0, str(source))
def reject_host_api(event, args):
    denied = ('CryptUnprotectData','CryptProtectData','CredReadW','CredEnumerateW','CredWriteW','CredDeleteW',
              'CertOpenSystemStoreW','CertEnumCertificatesInStore','SHGetKnownFolderPath','SHGetFolderPathW',
              'ShellExecuteW','ShellExecuteExW')
    if event == 'ctypes.dlsym' and str(args[1]) in denied:
        raise RuntimeError('native host API prohibited')
sys.addaudithook(reject_host_api)
from tests.sitecustomize import install_write_boundary
install_write_boundary()
import writer_session_fence as fence
from tools import register_container_audit_worker_pc as registration
registration._current_user_sid = lambda: 'S-' + '-'.join(map(str, (1, 5, 21, 263, 263, 263, 1001)))
registration._current_machine_guid = lambda: hashlib.md5(str(root).encode()).hexdigest()
import data_generation_guard as guard
from kmtech_shared import data_generation as generation
import current_user_onboarding as onboarding
import storage_policy
storage_policy._persisted_data_root = lambda: None
import protected_admin as admin
from logistics_runtime_profile import assert_path_has_no_reparse_components
from tools import install_logistics_runtime_profile as installer

data = root / 'data'
data.mkdir(parents=True, exist_ok=True)
os.environ['CONTAINER_AUDIT_DATA_ROOT'] = str(data)
os.environ['KMTECH_TEST_CA_WRITER_ROOT'] = str(root / 'control')
os.environ['KMTECH_TEST_CA_WRITER_MUTEX'] = 'Local.KMTech.CA.External.' + hashlib.sha256(str(root).encode()).hexdigest()[:16]
os.environ['CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH'] = str(data / 'logistics/profile.json')
external = root / 'external'
external.mkdir()
if scenario == 'tls-onboarding-default':
    os.environ.pop('CONTAINER_AUDIT_DATA_ROOT', None)
paths = onboarding.resolve_current_user_onboarding_paths(source)
data = paths.data_root
data.mkdir(parents=True, exist_ok=True)
if scenario.startswith('tls') or scenario == 'register-tls':
    from tests.test_logistics_runtime_profile import _private_ca_pem
    selected = external / 'source.pem'
    if scenario == 'tls-onboarding-default':
        selected = paths.bootstrap_tls_ca_bundle_path
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_bytes(_private_ca_pem())
elif scenario.startswith('admin'):
    selected = external / 'profile.json'
    if scenario.endswith('-default'):
        os.environ.pop(admin.PROTECTED_ADMIN_PROFILE_ENV, None)
        selected = Path(admin.default_protected_admin_profile_path())
    else:
        os.environ[admin.PROTECTED_ADMIN_PROFILE_ENV] = str(selected)
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text(json.dumps(admin.build_protected_admin_profile(str(10**5 + sum(range(30))))), encoding='utf-8')
else:
    selected = external / ('input.txt' if scenario == 'task-password' else 'input.json')
    selected.write_text(str(sum(range(30))) if scenario == 'task-password' else '{}', encoding='utf-8')

credential_locator = None
marker_root = selected.parent
if scenario.startswith('nested-'):
    import direct_sync_runtime as runtime
    runtime.current_user_data_home = lambda: Path(os.environ['LOCALAPPDATA'])
    credential_locator = external / 'credential.json' if 'locator-high' in scenario else paths.credential_path
    credential_locator.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(producer_id='isolated', key_id='isolated', endpoint_url=registration.DEFAULT_ENDPOINT_URL)
    if scenario.endswith('tls'):
        from tests.test_logistics_runtime_profile import _private_ca_pem
        selected = external / 'source.pem'
        selected.write_bytes(_private_ca_pem())
        payload.update(secret=hashlib.sha256(str(root).encode()).hexdigest(), tls_ca_bundle_path=str(selected))
    else:
        base = (runtime._default_secret_data_dir(credential_locator)
                if scenario.endswith('default') else external)
        selected = base / 'secrets/isolated.dpapi'
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(hashlib.sha256(str(root).encode()).digest())
        payload['secret_ref'] = 'dpapi:isolated'
        if not scenario.endswith('default'):
            payload['secret_data_dir'] = str(base)
        runtime._dpapi_unprotect_current_user = lambda value: hashlib.sha256(value).hexdigest().encode()
    marker_root = selected.parent if scenario.endswith('tls') else selected.parent.parent
    credential_locator.write_text(json.dumps(payload), encoding='utf-8')
    if 'locator-high' in scenario:
        marker_root = credential_locator.parent
    if 'malformed' in scenario:
        credential_locator.write_text('{', encoding='utf-8')
    if 'unresolvable' in scenario:
        payload['tls_ca_bundle_path'] = str(external / ('invalid' + chr(0) + '.pem'))
        credential_locator.write_text(json.dumps(payload), encoding='utf-8')

receipt_hash = hashlib.sha256(selected.read_bytes()).hexdigest()
if scenario == 'lifecycle-receipt':
    from dataclasses import replace
    code_root = root / 'installed/current'
    paths = replace(paths, app_root=code_root/'app')
    onboarding.resolve_current_user_onboarding_paths = lambda *a, **k: paths
    paths.status_dir.mkdir(parents=True, exist_ok=True)

marker = marker_root / 'data-generation.json'
release = guard._runtime_release()
if generation_case == 'unknown':
    marker.write_text('{', encoding='utf-8')
elif generation_case != 'missing':
    generation.record_generation(marker, app_id='container_audit', subject_sid=registration._current_user_sid(),
        version='v999.0.0' if generation_case == 'newer' else release['version'],
        build_id=release['build_id'],
        data_compatible_min_version='v999.0.0' if generation_case == 'newer' else release['version'],
        compatibility_verified=False)

def argument(path):
    if spelling == 'relative':
        return os.path.relpath(path, Path.cwd())
    if spelling == 'tilde':
        os.environ['USERPROFILE'] = str(root)
        return '~/' + path.relative_to(root).as_posix()
    if spelling == 'case':
        return str(path).swapcase()
    return str(path)

if scenario in ('tls-onboarding', 'tls-onboarding-default'):
    if scenario == 'tls-onboarding':
        os.environ[onboarding.ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV] = argument(selected)
    else:
        os.environ.pop(onboarding.ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV, None)
if scenario.startswith('admin') and not scenario.endswith('-default'):
    os.environ[admin.PROTECTED_ADMIN_PROFILE_ENV] = argument(selected)

def snapshot():
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and not p.name.endswith('.lock')}

before = snapshot()
observed = dict(input_reads=0, network_calls=0, native_calls=0)
locator_reads = 0
watch_enabled = True
class BoundaryStop(Exception):
    pass

def audit(event, args):
    global locator_reads
    if not watch_enabled:
        return
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if credential_locator is not None and Path(os.fsdecode(args[0])).resolve() == credential_locator.resolve() and ('r' in str(args[1]) or args[1] is None):
            locator_reads += 1
        if Path(os.fsdecode(args[0])).resolve() == selected.resolve() and ('r' in str(args[1]) or args[1] is None):
            observed['input_reads'] += 1
    if event == 'socket.connect':
        observed['network_calls'] += 1
        raise BoundaryStop()
    if event == 'ctypes.dlsym' and str(args[1]).startswith(('NCrypt', 'CryptUnprotect', 'CredRead', 'CredEnumerate')):
        observed['native_calls'] += 1
        raise BoundaryStop()
    if event == 'winreg.OpenKey' and 'CurrentVersion\\Run' in str(args[1]):
        observed['native_calls'] += 1
        raise BoundaryStop()
    if event == 'subprocess.Popen':
        command = args[0] or (args[1][0] if isinstance(args[1], (list, tuple)) else str(args[1]).split()[0])
        if Path(str(command).strip('"')).name.casefold() not in ('git', 'git.exe'):
            observed['native_calls'] += 1
            raise BoundaryStop()
sys.addaudithook(audit)

def execute():
    if requested_scenario == "nested-readonly":
        return {"status": "READONLY_ALLOWED", "binding": onboarding.preflight_current_user_onboarding(source)}
    if scenario.startswith('nested-'):
        def load(prepared=None):
            value = runtime.load_credentials_from_json(credential_locator, prepared_config=prepared) if prepared is not None else runtime.load_credentials_from_json(credential_locator)
            if scenario.endswith('tls'):
                Path(value.tls_ca_bundle_path).read_bytes()
            raise BoundaryStop()
        if scenario.startswith('nested-onboard'):
            onboarding.inspect_current_user_state = lambda *a, **k: load(k.get('prepared_credential'))
            return onboarding.onboard_current_user(source, require_bootstrap_integrity=False)
        if scenario.startswith('nested-operator'):
            from tools import direct_sync_relay_operator as operator
            operator.restore_relay_spool_from_server = lambda **k: (_ for _ in ()).throw(BoundaryStop())
            return operator.main(['restore-spool','--db-path',str(data/'q.db'),'--relay-id','isolated',
                '--spool-root',str(data/'spool'),'--credential-path',str(credential_locator),
                '--operator-id','isolated','--reason','isolated'])
        if scenario.startswith('nested-pack'):
            from tools import direct_sync_relay_install_pack as pack
            if 'malformed' in scenario:
                def plan(args):
                    detail = pack._credential_report(args.credential_path, prepared_config=getattr(args,'prepared_credential',None))
                    return dict(status='BLOCKED', credential=detail,
                        task_name_validation=dict(status='FAIL',blocked_reason='isolated credential validation'))
                pack.build_install_plan = plan
            else:
                pack.build_install_plan = lambda args: load(getattr(args,'prepared_credential',None))
            return pack.main(['--app-root',str(source),'--credential-path',str(credential_locator),'--report-path',str(data/'report.json')])
        if scenario.startswith('nested-registrar'):
            registration.build_registration_payloads = lambda args: load(getattr(args,'prepared_credential',None))
            return registration.main(['--app-root',str(source),'--credential-path',str(credential_locator)])
        if scenario.startswith('nested-gui'):
            import Container_Audit as app
            app.verify_factory_contract_startup = lambda: None
            app.acquire_runtime_instance = lambda *a: SimpleNamespace(release=lambda: None)
            app.clear_shutdown_stall = lambda *a: None
            app._first_run_onboarding_enabled = lambda: False
            app.prepare_startup_item_catalog = lambda: None
            app.ContainerAudit = lambda: SimpleNamespace(root=SimpleNamespace(after=lambda *a: None))
            return app._prepare_gui_startup()
        if scenario.startswith('nested-resident'):
            import user_relay
            user_relay.acquire_runtime_instance = lambda *a: SimpleNamespace(release=lambda: None)
            user_relay.run_persistent_relay_loop = lambda *a, **k: (_ for _ in ()).throw(BoundaryStop())
            return user_relay.main(['--app-root',str(source),'--data-root',str(data),'--direct-sync-root',str(credential_locator.parent),
                '--scan-source-dir',str(paths.events_dir),'--once'])
        from tools import direct_sync_relay_runner as runner
        runner.run_relay_once = lambda config: load(getattr(config,'prepared_credential',None))
        return runner.main(['--db-path',str(data/'q.db'),'--spool-dir',str(data/'spool'),
            '--producer-manifest-path',str(data/'manifest.json'),'--credential-path',str(credential_locator),
            '--upload-status-dir',str(data/'upload'),'--runtime-status-path',str(data/'status.json'),'--log-path',str(data/'events.jsonl')])
    if scenario == 'tls-profile':
        os.environ[installer.DEFAULT_INSTALL_TOKEN_ENV] = hashlib.sha256(str(root).encode()).hexdigest()
        return installer.main(['--profile-path', str(paths.logistics_profile_path), '--tls-ca-bundle-path', argument(selected),
            '--base-url', 'https://127.0.0.1:1', '--authority-scope', 'source-only', '--authority-epoch', '1',
            '--plane-epoch', '1', '--device-id', 'isolated', '--source-host-id', 'isolated', '--dry-run'])
    if scenario.startswith('tls-onboarding') or scenario.startswith('admin-onboarding'):
        onboarding.inspect_current_user_state = lambda *a, **k: {'status': 'READY'}
        try:
            onboarding.onboard_current_user(source, require_bootstrap_integrity=False,
                autostart_installer=lambda **k: (_ for _ in ()).throw(BoundaryStop()),
                relay_launcher=lambda **k: (_ for _ in ()).throw(BoundaryStop()))
        except onboarding.CurrentUserOnboardingError as exc:
            if generation.REFUSAL_MESSAGE in str(exc) or generation.UNKNOWN_MESSAGE in str(exc):
                raise
        if scenario.startswith('admin'):
            return admin.load_protected_admin_profile(selected)
        return None
    if scenario.startswith('admin-gui'):
        import Container_Audit as app
        app.verify_factory_contract_startup = lambda: None
        app.acquire_runtime_instance = lambda *a: SimpleNamespace(release=lambda: None)
        app.clear_shutdown_stall = lambda *a: None
        app._first_run_onboarding_enabled = lambda: False
        app.prepare_startup_item_catalog = lambda: None
        app.ContainerAudit = lambda: SimpleNamespace(root=SimpleNamespace(after=lambda *a: None))
        result = app._prepare_gui_startup()
        product = result[0]
        return admin.load_protected_admin_profile(getattr(product, '_protected_admin_profile_path', None))
    if scenario == 'admin-install':
        from tools import install_protected_admin as provision
        return provision.main(['--profile-path', argument(selected), '--dry-run'])
    if scenario == 'task-password':
        from tools import direct_sync_relay_install_pack as pack
        def plan(args):
            pack._read_task_password(args)
            raise BoundaryStop()
        pack.build_install_plan = plan
        return pack.main(['--app-root', str(source), '--report-path', str(data/'report.json'),
            '--task-run-password-file', argument(selected)])
    if scenario == 'lifecycle-receipt':
        onboarding._owner_artifact_fingerprints = lambda paths: {}
        return onboarding.restore_current_user_lifecycle_after_replacement(source, code_root=code_root,
            replacement_receipt_path=argument(selected), replacement_receipt_sha256=receipt_hash,
            replacement_transaction_id=hashlib.md5(str(root).encode()).hexdigest(), writer_contract_sha256=hashlib.sha256(b'contract').hexdigest(),
            session_id=hashlib.md5(b'session').hexdigest(), attempt_id=hashlib.md5(b'attempt').hexdigest(),
            session_started_at_utc=datetime.now(timezone.utc).isoformat(), orchestrator_sha256=hashlib.sha256(b'orchestrator').hexdigest(),
            execution_context_inspector=lambda: dict(status='PASS', token_elevated=False, integrity_level='MEDIUM'))
    if scenario.startswith('register'):
        option = {'register-tls': '--tls-ca-bundle-path', 'register-journal': '--admin-recovery-journal-path',
                  'register-context': '--isolated-qualification-context'}[scenario]
        def payloads(args):
            if scenario == 'register-tls':
                installer._resolve_tls_ca_bundle(args.tls_ca_bundle_path, paths.logistics_profile_path)
            elif scenario == 'register-context':
                from isolated_qualification import load_isolated_qualification_context
                load_isolated_qualification_context(args.isolated_qualification_context)
            else:
                selected_path = Path(args.admin_recovery_journal_path)
                json.loads(selected_path.read_text(encoding='utf-8'))
            raise BoundaryStop()
        registration.build_registration_payloads = payloads
        return registration.main(['--app-root', str(source), option, argument(selected)])
    raise AssertionError('unsupported scenario')

if requested_scenario == "nested-final-target":
    # The PS recovery reproduction already doubles exact code/receipt proof.
    # Only that identity reader is doubled here; locator/nested G stays real.
    target_release = dict(release, aggregate_sha256="a" * 64, manifest_sha256="b" * 64)
    onboarding._verified_onboarding_target_release = lambda _target: target_release
    try:
        target_arg = sys.argv[sys.argv.index("--target-release-root") + 1]
        binding = onboarding.preflight_current_user_onboarding(source, target_release_root=target_arg)
        print("onboarding_input_binding=" + binding)
        raise SystemExit(0)
    except onboarding.CurrentUserOnboardingError as exc:
        print("onboarding_preflight_error=" + json.dumps(str(exc), ensure_ascii=True))
        raise SystemExit(4)

capture = io.StringIO()
result, failure, failure_type = None, '', ''
with redirect_stdout(capture), redirect_stderr(capture):
    try:
        result = execute()
    except Exception as exc:
        failure = str(exc)
        failure_type = type(exc).__name__
watch_enabled = False
output = capture.getvalue() + failure
after = snapshot()
changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
status = 'REFUSE' if generation.REFUSAL_MESSAGE in output else 'UNKNOWN' if generation.UNKNOWN_MESSAGE in output else 'NONE'
print(json.dumps(dict(scenario=scenario, generation_case=generation_case, spelling=spelling, source_commit=release['build_id'],
    status=status, failure_type=failure_type, result=result if isinstance(result, int) else None, observed=observed, locator_reads=locator_reads,
    changed_file_count=len(changed), generation_change_count=sum('data-generation' in name for name in changed),
    report_change_count=sum('report' in name or 'onboarding.json' in name for name in changed),
    external_marker_preserved=not marker.exists() if generation_case == 'missing' else before.get(marker.relative_to(root).as_posix()) == after.get(marker.relative_to(root).as_posix()))))
