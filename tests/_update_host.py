"""Opt-in, headless CA 120 update reproduction; product sources stay unchanged.

All durable product records and native mutex ownership come from the isolated
product. OS identity/ACL, task dispatch, local feed transport and credential
protection are fixture boundaries. No real host credentials are accessed.
"""
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import zipfile

ORIGIN = "https://setup.test.invalid"
SID = "S-1-5-21-100-200-300-1001"
NATIVE_POPEN = getattr(subprocess.Popen, "native", subprocess.Popen)
NATIVE_RUN = subprocess.run


def departure_identity():
    """Select the attested starting release; defaults retain the frozen RED."""
    return {
        'version': os.environ.get('CONTAINER_AUDIT_HOST_TEST_START_VERSION', 'v2.0.120'),
        'source_commit': os.environ.get('CONTAINER_AUDIT_HOST_TEST_START_COMMIT',
                                      '50d6b83bc8d6bac7cbc564d8a818225e9f396eb3'),
        'sha256': os.environ.get('CONTAINER_AUDIT_HOST_TEST_START_SHA256',
                                'ea12e50bcd6716dcf9897ebd4a65f04afc855792ad6fff788512c68917f639f9'),
    }

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

def inventory(root):
    from datetime import datetime, timezone
    rows = []
    for path in sorted(root.rglob("*"),
                       key=lambda item: item.relative_to(root).as_posix().encode("utf-16-be")):
        if not path.is_file() or path == root / "bootstrap-integrity.json":
            continue
        rows.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size,
                     "sha256": hashlib.file_digest(path.open("rb"), "sha256").hexdigest()})
    aggregate = hashlib.sha256("".join(
        f"{row['sha256']} {row['size']} {row['path']}\n" for row in rows).encode()).hexdigest()
    target = root / "bootstrap-integrity.json"
    write(target, {"schema_version": "container-audit-bootstrap-integrity-v1", "status": "PASS",
                   "code_root": str(root.resolve()), "file_count": len(rows), "files": rows,
                   "aggregate_sha256": aggregate, "identity_profile_created": False,
                   "state_scope": "current_user_first_run",
        'installed_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f') + '0Z',
    })
    return target

def relocate_ancestor_boundary(bundle, root):
    """Map only the OS's canonical ancestor names into the isolated fixture."""
    path = bundle / "tools/bootstrap_integrity.ps1"
    raw = path.read_text(encoding="utf-8-sig")
    first = raw.index("function Protect-KmtechCodeAncestors(")
    last = raw.index("\nfunction ", first + 1)
    body = raw[first:last]
    assert "C:\\KMTech\\Apps" in body
    body = body.replace("C:\\KMTech\\Apps", str(root))
    body = body.replace("C:\\KMTech", str(root.parent))
    path.write_text(raw[:first] + body + raw[last:], encoding="utf-8-sig")
    manifest = json.loads((bundle / "portable-manifest.json").read_bytes())
    manifest["integrity_helper_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    helper = bundle / "tools/apply_prepared_update.ps1"
    source = helper.read_text(encoding="utf-8-sig")
    native_identity = "$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    assert source.count(native_identity) == 1
    source = source.replace(native_identity,
        "$sid = if ($env:CONTAINER_AUDIT_HOST_TEST_SYSTEM -ceq '1') { 'S-1-5-18' } else { '" + SID + "' }")
    helper.write_text(source, encoding="utf-8-sig")
    manifest["startup_update_helper_sha256"] = hashlib.sha256(helper.read_bytes()).hexdigest()
    write(bundle / "portable-manifest.json", manifest)

def native_acl(root):
    text = r'''
function Get-Acl {
    param($LiteralPath)
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    if ([IO.Path]::GetFullPath($LiteralPath) -in @('ROOT','PARENT')) {
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0xe0010000;;;AU)(A;;0x1200af;;;AU)')
        return $acl
    }
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
    }
    return $acl
}
function Set-Acl { param($LiteralPath,$AclObject) }
Export-ModuleMember -Function Get-Acl,Set-Acl
'''
    (root / "native-boundary.psm1").write_text(
        text.replace("'ROOT'", "'" + str(root).replace("'", "''") + "'")
            .replace("'PARENT'", "'" + str(root.parent).replace("'", "''") + "'"), encoding="utf-8-sig")

def wait_for(config, predicate, *, seconds=600):
    """Only this test controller waits; product deadlines are never patched."""
    root = Path(config).parent
    deadline = time.monotonic() + seconds
    observed = None
    progress_at = time.monotonic()
    extended = False
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        paths = [root / "machine/update-control/transition.json",
                 root / "machine/update-control/active.json", root / "stage/prepared.json"]
        shape = tuple((path.stat().st_size, path.stat().st_mtime_ns) if path.exists() else None for path in paths)
        if shape != observed:
            progress_at, observed = time.monotonic(), shape
        if (not extended and deadline - time.monotonic() < 30
                and time.monotonic() - progress_at < 60 and owned_processes_alive(config)):
            deadline += seconds
            extended = True
        time.sleep(min(30, max(0, deadline - time.monotonic())))
    raise TimeoutError("inspect bounded controller progress before another run")

def owned_processes_alive(config):
    import auto_update as updates
    for path in (Path(config).parent / "processes").glob("*.json"):
        row = json.loads(path.read_text())
        identity = updates.native_process_identity(row["ProcessId"])
        if (identity.get("status") == "LIVE"
                and identity.get("creation_identity") == row.get("CreationIdentity")):
            return True
    return False

TEST_POSSESSION_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "y": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
}
TEST_POSSESSION_FINGERPRINT = "test-possession-fingerprint"


def fake_possession_descriptor(*, created=True):
    return {
        "contract_version": "producer-machine-possession-key-v1",
        "provider_name": "Microsoft Software Key Storage Provider",
        "key_name": "KMTech.DirectSync.Possession.v1",
        "scope": "current_user",
        "unique_name": "test-unique-name",
        "created": created,
        "public_jwk": dict(TEST_POSSESSION_JWK),
        "fingerprint": TEST_POSSESSION_FINGERPRINT,
        "machine_key": False,
        "export_policy": 0,
        "key_usage": 2,
    }


def fake_v2_enrollment_response(
    module, payload, secret, *, authorization_state="OPERATION_PENDING"
):
    identity = payload["manifest"]["pc_identity"]
    active_manifest_hashes = [module.manifest_hash(payload["manifest"])]
    response = {
        "contract_version": module.SELF_ENROLLMENT_CONTRACT_VERSION,
        "status": "enrolled",
        "identity_action": "CREATED",
        "authorization_state": authorization_state,
        "credential_epoch": 1,
        "producer_id": payload["producer_id"],
        "key_id": payload["key_id"],
        "secret": secret,
        "secret_fingerprint_sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        "endpoint_url": payload["endpoint_url"],
        "source_host_id": identity["source_host_id"],
        "producer_install_id": identity["producer_install_id"],
        "active_manifest_hashes": active_manifest_hashes,
        "possession_key": {
            "contract_version": "producer-machine-possession-key-v1",
            "fingerprint": TEST_POSSESSION_FINGERPRINT,
        },
        "server_binding": {
            "producer_manifest_path": "/srv/producers/label/producer_manifest.json",
            "registry_path": "/srv/producers/label/source_registry.json",
        },
    }
    response["client_receipt"] = {
        "receipt_schema_version": "producer-self-enrollment-client-receipt-v1",
        "contract_version": module.SELF_ENROLLMENT_CONTRACT_VERSION,
        "status": "enrolled",
        "identity_action": "CREATED",
        "authorization_state": response["authorization_state"],
        "credential_epoch": 1,
        "producer_id": payload["producer_id"],
        "key_id": payload["key_id"],
        "secret_fingerprint_sha256": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        "endpoint_url": payload["endpoint_url"],
        "source_host_id": identity["source_host_id"],
        "producer_install_id": identity["producer_install_id"],
        "active_manifest_hashes": active_manifest_hashes,
        "possession_key_fingerprint": TEST_POSSESSION_FINGERPRINT,
        "server_binding": dict(response["server_binding"]),
    }
    return response

def _machine_enrollment_response(
    timeout_seconds,
    *,
    logistics_token="logistics-token-01",
):
    return {
        "producer_id": "producer-label-host-01",
        "producer_install_id": "install-label-host-01",
        "source_host_id": "label-host-01",
        "endpoint_url": "https://worker.example.invalid/api/producer-ingest/v1/source-file",
        "active_manifest_hashes": ["a" * 64],
        "key_id": "producer-key-01",
        "secret": "producer-secret-01",
        "machine_credential_bundle": {
            "contract_version": "producer-self-enrollment-machine-credentials-v1",
            "bindings": {
                "app": "container_audit",
                "program": "Container_Audit",
                "source_host_id": "label-host-01",
                "device_id": "label-pc-01",
                "authority_scope_id": "scope-machine",
            },
            "credentials": {
                "producer_ingest": {
                    "audience": "producer-ingest-hmac-v1",
                    "auth_scheme": "hmac-sha256",
                    "key_id": "producer-key-01",
                    "secret": "producer-secret-01",
                },
                "logistics": {
                    "audience": "worker-analysis-logistics-v1",
                    "auth_scheme": "bearer",
                    "token_header": "X-Logistics-API-Token",
                    "token": logistics_token,
                },
            },
            "profiles": {
                "logistics": {
                    "contract_version": "km-logistics-runtime-profile-v1",
                    "base_url": "https://logistics.example.invalid",
                    "authority_scope": "scope-machine",
                    "authority_epoch": 7,
                    "authority_plane": "AUTHORITATIVE",
                    "ledger_plane": "AUTHORITATIVE",
                    "plane_epoch": 3,
                    "device_id": "label-pc-01",
                    "source_host_id": "label-host-01",
                    "timeout_seconds": timeout_seconds,
                }
            },
        },
    }

def event(root, kind, **fields):
    target = root / 'observations' / (str(os.getpid()) + '.jsonl')
    target.parent.mkdir(exist_ok=True)
    with target.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'at': time.monotonic(), 'pid': os.getpid(), 'kind': kind, **fields}) + '\n')


def error_record(root, entry, error):
    import traceback
    chain, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        chain.append({'type': type(error).__name__,
                      'mutex_busy': isinstance(error, RuntimeError) and str(error) == 'update mutex ownership is busy or abandoned',
                      'wait_result': getattr(error, 'wait_result', None),
                      'frames': [{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno}
                                 for f in traceback.extract_tb(error.__traceback__)]})
        error = error.__cause__ or error.__context__
    write(root / 'errors' / (str(os.getpid()) + '-' + str(time.time_ns()) + '.json'),
          {'entry': Path(entry).name, 'system': '--apply-prepared' in sys.argv, 'chain': chain})


def refresh_file_pins(bundle, manifest):
    pins = {'launcher_sha256': 'launch-container-audit.cmd',
            'installer_sha256': 'INSTALL_CANONICAL_PORTABLE.ps1', 'helper_sha256': 'INSTALL_THIS_PC.ps1',
            'integrity_helper_sha256': 'tools/bootstrap_integrity.ps1',
            'writer_fence_helper_sha256': 'tools/container_writer_fence.ps1',
            'writer_session_adapter_sha256': 'tools/container_writer_session.ps1',
            'writer_session_contract_sha256': 'tools/container_writer_session_contract.json',
            'writer_sink_inventory_sha256': 'tools/container_writer_sink_inventory.json',
            'startup_update_helper_sha256': 'tools/apply_prepared_update.ps1',
            'update_key_config_sha256': 'app/update-manifest-key-config.json'}
    for field, name in pins.items():
        assert field in manifest, field
        manifest[field] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()


def manifest(version, commit):
    from tests.test_update_service import _private_update_manifest
    value = _private_update_manifest(version=version)
    value.update(signature_version='es256-v1', source_commit=commit)
    value['archive'].update(layout='canonical_portable', entrypoint='app/main.py',
                            required_files=['Container_Audit/app/main.py'])
    value['artifact']['url'] = ORIGIN + '/artifacts/' + value['artifact']['name']
    return value


def install_writer_gate_os(root):
    import writer_session_fence as fence
    root = Path(root).resolve()
    originals = getattr(fence, '_host_gate_originals', None)
    if originals is None:
        originals = (fence.writer_admission_mutex_name, fence._acquire_named_mutex, fence._NamedMutexLease.release)
        fence._host_gate_originals = originals
    real_gate_name, real_gate_acquire, real_gate_release = originals
    gate_namespace = hashlib.sha256(str(root).casefold().encode('utf-8')).hexdigest()[:16]
    gate_names = set()
    def isolated_gate_name(*args, **kwargs):
        name = real_gate_name(*args, **kwargs) + '.' + gate_namespace
        gate_names.add(name)
        return name
    fence.writer_admission_mutex_name = isolated_gate_name
    def observed_gate_acquire(name, timeout_seconds):
        tracked = name in gate_names
        began = time.monotonic()
        if tracked:
            event(root, 'writer_gate_request', gate_namespace=gate_namespace, timeout_seconds=timeout_seconds)
        lease = real_gate_acquire(name, timeout_seconds)
        if tracked:
            event(root, 'writer_gate_acquired' if lease is not None else 'writer_gate_timeout',
                  gate_namespace=gate_namespace, elapsed=time.monotonic()-began,
                  abandoned=bool(lease and lease.abandoned))
            if lease is not None:
                lease._host_gate_namespace = gate_namespace
                lease._host_gate_root = root
        return lease
    fence._acquire_named_mutex = observed_gate_acquire
    def observed_gate_release(lease):
        namespace = getattr(lease, '_host_gate_namespace', None)
        tracked = namespace and bool(lease.handle)
        target = getattr(lease, '_host_gate_root', root)
        try:
            return real_gate_release(lease)
        finally:
            if tracked:
                event(target, 'writer_gate_released', gate_namespace=namespace)
    fence._NamedMutexLease.release = observed_gate_release


def prepare(root, source, packet, signer, *, slow_observe=0, departure=None):
    import auto_update as updates
    root = Path(root).resolve()
    departure = departure_identity() if departure is None else departure
    with Path(packet).open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == departure['sha256']
    install_writer_gate_os(root)
    current = root / 'machine/current'
    current.mkdir(parents=True)
    with zipfile.ZipFile(packet) as archive:
        assert archive.testzip() is None
        assert all((current / info.filename).resolve().is_relative_to(current) for info in archive.infolist())
        for info in archive.infolist():
            if info.is_dir():
                continue
            relative = Path(info.filename).relative_to('Container_Audit')
            target = current / relative
            assert target.resolve().is_relative_to(current)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as stream, target.open('xb') as output:
                shutil.copyfileobj(stream, output)
    declared = json.loads((current / 'portable-manifest.json').read_bytes())
    assert declared['version'] == departure['version']
    assert declared['source_commit'] == departure['source_commit']
    for name in ('auto_update.py', 'Container_Audit.py', 'user_relay.py', 'current_user_onboarding.py'):
        assert (current / 'app' / name).read_bytes() == (source / name).read_bytes()
    settings = {'feed_url': ORIGIN + '/feed/latest.json', 'channel': 'stable',
                'profile_auth': True, 'apply_during_work': False}
    raw = (json.dumps(settings, sort_keys=True, separators=(',', ':')) + '\n').encode()
    (current / 'app/auto-update-settings.json').write_bytes(raw)
    write(current / 'app/update-manifest-key-config.json', {'manifest_public_key': json.dumps(signer.public_jwk),
        'schema': 'container-audit-update-key-config-v1',
    })
    refresh_file_pins(current, declared)
    write(current / 'portable-manifest.json', declared)
    relocate_ancestor_boundary(current, root)
    inventory(current)
    selected = root / 'machine/versions' / declared['source_commit']
    shutil.copytree(current, selected)
    inventory(selected)
    policy = {**settings, 'operator_sid': SID, 'operator_local_app_data': str(root / 'local'),
              'settings_sha256': hashlib.sha256(raw).hexdigest(), 'staging_root': str(root / 'stage'),
        'schema': 'container-audit-startup-update-policy-v1',
        'approved_transitions': [],
        'hiberboot_enabled': None,
        'hiberboot_read_status': 'UNPROVEN',
    }
    control = root / 'machine/update-control'
    write(control / 'policy.json', policy)
    write(control / 'active.json', {'schema': updates.SCHEMA, 'sha': declared['source_commit'],
        'transition_id': 'CANONICAL_INSTALL',
    })
    write(control / 'transition.json', {'schema': updates.SCHEMA, 'phase': 'DEFERRED', 'deferred_at': updates.now_utc(),
        'reason': 'canonical installation',
        'failed_shas': [],
    })
    for name in ('local', 'stage'):
        (root / name).mkdir()
    config = root / 'host-config.json'
    write(config, {'root': str(root), 'repo': str(source), 'current': str(current), 'selected': str(selected),
                   'control': str(control), 'slow_observe': slow_observe, 'gui_trial_authorized': True,
                   'start_version': declared['version'], 'start_source_commit': declared['source_commit'],
                   'start_sha256': departure['sha256'],
                   'next_version': declared['version'].rsplit('.', 1)[0] + '.' +
                                   str(int(declared['version'].rsplit('.', 1)[1]) + 1)})
    feed = manifest(declared['version'], declared['source_commit'])
    write(root / 'feed.json', feed)
    (root / 'feed.sig').write_bytes(signer.sign_es256(
        json.dumps(feed, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()))
    native_acl(root)
    return config


def prepare_update(config, signer):
    import auto_update as updates
    value = json.loads(config.read_bytes())
    root, current = config.parent, Path(value['selected'])
    before = updates.version_manifest(current)
    next_version = value['next_version']
    source = Path(value['repo'])
    cached = os.environ.get('CONTAINER_AUDIT_HOST_TEST_SOURCE121')
    if cached:
        source121 = Path(cached)
        binding = json.loads((source121 / '.cache-binding.json').read_bytes())
        names = {p.relative_to(source121).as_posix() for p in source121.rglob('*') if p.is_file()}
        assert names == set(binding['files']) | {'.cache-binding.json'}
        for name, digest in binding['files'].items():
            assert hashlib.sha256((source121 / name).read_bytes()).hexdigest() == digest, name
        assert binding['declarations'] == [{'mode': '--write', 'rc': 0}, {'mode': '--check', 'rc': 0}]
        write(root / 'declaration-proof.json', {'cached': True, 'declarations': binding['declarations'],
              'binding_sha256': hashlib.sha256((source121 / '.cache-binding.json').read_bytes()).hexdigest()})
    else:
        source121 = root / 's121'
        with (root / 'clone.private.log').open('xb') as stream:
            NATIVE_RUN(['git', '-c', 'core.autocrlf=false', 'clone', '--shared', str(source), str(source121)],
                       check=True, stdout=stream, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        path = source121 / 'Container_Audit.py'
        raw = path.read_bytes()
        old = ('CURRENT_VERSION = "' + before['version'] + '"').encode()
        assert raw.count(old) == 1
        new = ('CURRENT_VERSION = "' + next_version + '"').encode()
        path.write_bytes(raw.replace(old, new, 1))
        declarations = []
        for mode in ('--write', '--check'):
            with (root / ('declarations-' + mode[2:] + '.private.log')).open('xb') as stream:
                result = NATIVE_RUN([sys.executable, '-s', '-B', str(source121 / 'tools/refresh_container_update_declarations.py'), mode],
                                    cwd=source121, stdout=stream, stderr=subprocess.STDOUT,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            declarations.append({'mode': mode, 'rc': result.returncode})
            write(root / 'declaration-proof.json', declarations)
            assert result.returncode == 0, 'inspect bounded declaration diagnostics'
    candidate = root / 'offer/Container_Audit'
    shutil.copytree(current, candidate)
    (candidate / 'bootstrap-integrity.json').unlink()
    # Reuse stock layout: root app files, app/tools and installer assets are
    # mapped to their source names exactly as the portable builder maps them.
    for target in candidate.rglob('*'):
        if not target.is_file():
            continue
        relative = target.relative_to(candidate).as_posix()
        original = relative.removeprefix('app/') if relative.startswith('app/') else relative
        if original == 'main.py':
            original = 'portable/main.py'
        source_path = source121 / original
        # Test SID/ACL relocation and public test key stay consistent with 120.
        if relative in {'tools/bootstrap_integrity.ps1', 'tools/apply_prepared_update.ps1',
                        'app/update-manifest-key-config.json', 'app/auto-update-settings.json'}:
            continue
        if source_path.is_file():
            shutil.copyfile(source_path, target)
    hot = hashlib.sha1((before['source_commit'] + ':host121').encode()).hexdigest()
    declared = json.loads((candidate / 'portable-manifest.json').read_bytes())
    declared.update(version=next_version, data_compatible_min_version=next_version, source_commit=hot)
    refresh_file_pins(candidate, declared)
    declared['writer_sink_inventory_contract_sha256'] = json.loads(
        (candidate / 'tools/container_writer_sink_inventory.json').read_bytes())['inventory_sha256']
    write(candidate / 'portable-manifest.json', declared)
    assert updates.version_manifest(candidate, require_version=True)['version'] == next_version
    after = updates.version_identity(lambda name: (candidate / name).read_bytes())
    forward = {'from_commit': before['source_commit'], 'to_commit': hot,
               'from_contract_sha256': before['contract_sha256'], 'to_contract_sha256': after['contract_sha256']}
    reverse = {'from_commit': hot, 'to_commit': before['source_commit'],
               'from_contract_sha256': after['contract_sha256'], 'to_contract_sha256': before['contract_sha256']}
    pin = lambda row: hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    packet = root / ('offer/Container_Audit-' + next_version + '.zip')
    with zipfile.ZipFile(packet, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(candidate.rglob('*')):
            if path.is_file():
                archive.write(path, 'Container_Audit/' + path.relative_to(candidate).as_posix())
    feed = manifest(next_version, hot)
    feed.update(approved_transitions=[forward, reverse],
                auto_update={'from_commit': before['source_commit'], 'to_commit': hot,
                             'forward_contract_sha256': pin(forward), 'rollback_contract_sha256': pin(reverse)})
    with packet.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    feed['artifact'].update(size_bytes=packet.stat().st_size, sha256=digest)
    write(root / 'offer/feed.json', feed)
    (root / 'offer/feed.sig').write_bytes(signer.sign_es256(
        json.dumps(feed, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()))
    write(root / 'offer-info.json', {'source_commit': hot, 'packet': str(packet),
                                    'artifact_url': feed['artifact']['url'], 'from_commit': before['source_commit']})
    return hot


def launch(config, entry='onboard', arguments=(), *, environment=None):
    config = Path(config)
    value = json.loads(config.read_bytes())
    code = ('import sys;sys.path.insert(0,sys.argv[1]);'
            'from tests._update_host import child_main;'
            'raise SystemExit(child_main(sys.argv[2],sys.argv[3],sys.argv[4:]))')
    output = config.parent / (Path(entry).name + '-' + str(time.time_ns()) + '.private.log')
    with output.open('xb') as stream:
        process = NATIVE_POPEN([sys.executable, '-B', '-c', code, value['repo'], str(config), entry, *arguments],
                               env=environment, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    process.host_test_output = output
    return process


def observe_script(helper, current, processes):
    adapters = r'''
$ErrorActionPreference='Stop'
Add-Type 'public static class KMTechStartupUpdateToken { public static System.Collections.Generic.HashSet<uint> Elevated = new System.Collections.Generic.HashSet<uint>(); public static bool Ordinary(uint pid) { return !Elevated.Contains(pid); } }'
function Get-CimInstance {
 foreach ($metadata in @(Get-ChildItem -LiteralPath 'PROCESSDIR' -Filter '*.json' -File)) {
  $item = Get-Content -LiteralPath $metadata.FullName -Raw | ConvertFrom-Json
  if ($item.OrdinaryUser -ceq $false) { [void][KMTechStartupUpdateToken]::Elevated.Add([uint32]$item.ProcessId) }
  $item.CreationDate = [datetime]$item.CreationDate
  $native=$null
  try {
   $native=[Diagnostics.Process]::GetProcessById([int]$item.ProcessId)
   $difference=$native.StartTime.ToUniversalTime().Ticks-$item.CreationDate.ToUniversalTime().Ticks
   if (-not $native.HasExited -and $difference -ge 0 -and $difference -lt 10) { $item }
  } catch {} finally { if ($null -ne $native) { $native.Dispose() } }
 }
}
function Invoke-CimMethod { param($InputObject,$MethodName) return @{ReturnValue=0;Sid=$InputObject.Sid} }
'''.replace('PROCESSDIR', str(processes.parent / 'processes').replace("'", "''"))
    quote = lambda p: "'" + str(p).replace("'", "''") + "'"
    # Execute the entire installed helper: tree admission, integrity, shared
    # library loading and the actual process-selection function all run.
    return (adapters + '\nImport-Module ' + quote(current.parent.parent / 'native-boundary.psm1')
            + '\n& ' + quote(helper) + ' -InstallRoot ' + quote(current)
            + ' -Mode Observe\nexit $LASTEXITCODE\n')


def install_os(config, app):
    global TEST_POSSESSION_FINGERPRINT
    import auto_update as updates
    import current_user_onboarding as onboarding
    import direct_sync_runtime
    import logistics_runtime_profile as profiles
    import tools.install_logistics_runtime_profile as profile_installer
    from tools import register_container_audit_worker_pc as registration
    import requests
    import protected_admin
    import user_relay
    import writer_session_fence as fence
    value = json.loads(config.read_bytes())
    root, current = config.parent, Path(value['current'])
    install_writer_gate_os(root)
    real_acl_identity = onboarding._windows_acl_identity
    def isolated_acl_identity(path):
        assert Path(path).resolve().is_relative_to(root.resolve())
        identity = real_acl_identity(path)
        # The helper's Get-Acl boundary already maps this same private tree.
        # Keep its native SDDL evidence; map owner/protection in Python too.
        return {**identity, 'owner_sid': 'S-1-5-32-544', 'access_rules_protected': True}
    onboarding._windows_acl_identity = isolated_acl_identity
    real_prepare_packet = updates.prepare_feed_packet
    def observed_prepare_packet(*args, **kwargs):
        try:
            result = real_prepare_packet(*args, **kwargs)
        except Exception as error:
            error_record(root, 'prepare_feed_packet', error)
            raise
        event(root, 'packet_preparation', status=result.get('status'))
        return result
    updates.prepare_feed_packet = observed_prepare_packet
    children = []
    os.environ['LOCALAPPDATA'] = str(root / 'local')
    os.environ['APPDATA'] = str(root / 'roaming')
    os.environ['CONTAINER_AUDIT_DATA_ROOT'] = str(root / 'data')
    os.environ[profiles.PROFILE_PATH_ENV] = str(root / 'data/logistics/runtime_profile.json')
    os.environ[registration.DEFAULT_ENROLLMENT_TOKEN_ENV] = ''
    os.environ['CONTAINER_AUDIT_DIRECT_SYNC_SERVER_BASE_URL'] = ORIGIN
    # Default path selection and persisted HKCU read use the same virtual Run.
    run_value = root / 'hkcu-run.json'
    user_relay._registry_set = lambda command: write(run_value, {'command': command})
    user_relay._registry_get = lambda: json.loads(run_value.read_bytes())['command'] if run_value.exists() else ''
    user_relay._registry_delete = lambda: run_value.unlink(missing_ok=True)
    import inspect
    inspect.unwrap(onboarding.onboard_current_user).__kwdefaults__.update(
        autostart_installer=user_relay.install_user_relay_autostart,
        relay_launcher=user_relay.start_user_relay_process)
    native_sid = updates.current_process_sid()
    system = '--apply-prepared' in sys.argv
    os.environ['CONTAINER_AUDIT_HOST_TEST_SYSTEM'] = '1' if system else '0'
    virtual_sid = 'S-1-5-18' if system else SID
    updates.current_process_sid = lambda: virtual_sid
    updates.ordinary_user_context = lambda expected=None: not system and expected in (None, SID)
    onboarding._inspect_current_process_execution_context = lambda: {
        'status': 'PASS', 'token_elevated': system, 'integrity_level': 'SYSTEM' if system else 'MEDIUM'}
    onboarding._current_process_session_id = lambda: 0 if system else 1
    registration._current_user_sid = lambda: SID
    registration._current_machine_guid = lambda: '00112233-4455-6677-8899-aabbccddeeff'
    def security(pid):
        metadata = root / 'processes' / (str(pid) + '.json')
        elevated = system if pid == os.getpid() else json.loads(metadata.read_bytes())['OrdinaryUser'] is False
        return {'sid': 'S-1-5-18' if elevated else SID, 'session_id': 0 if elevated else 1,
                'elevated': elevated, 'integrity_rid': 16384 if elevated else 8192}
    updates.runtime_matches = lambda *_: True
    native_source = updates.unredirected_source
    def source_identity(path, *, expected_owner_sid=None):
        assert Path(path).resolve().is_relative_to(root.resolve())
        assert expected_owner_sid in (None, SID)
        return native_source(path, expected_owner_sid=native_sid if expected_owner_sid else None)
    updates.unredirected_source = source_identity
    real_lock = updates.update_lock
    held = [0]
    role = ('SYSTEM' if system else 'bootstrap' if '--bootstrap' in sys.argv
            else 'relay' if '--container-audit-user-relay' in sys.argv else 'GUI')
    def lock_fields():
        import traceback
        return {'role': role, 'utc': datetime.now(timezone.utc).isoformat(),
                'caller_frames': [{'file': Path(frame.filename).name, 'function': frame.name,
                                   'line': frame.lineno}
                                  for frame in traceback.extract_stack(limit=12)[:-2]]}
    @contextlib.contextmanager
    def observed_lock(control, sid, **kwargs):
        began = time.monotonic()
        trial = kwargs.get('trial', False)
        event(root, 'lock_request', trial=trial, system=system, timeout_ms=kwargs.get('timeout_ms', 5000), **lock_fields())
        try:
            with real_lock(control, native_sid, **kwargs):
                if not trial:
                    held[0] += 1
                event(root, 'lock_acquired', trial=trial, system=system, waited=time.monotonic()-began, **lock_fields())
                try:
                    state = updates.optional_record(control / 'transition.json') or {}
                    phase = state.get('phase')
                    original = state.get('rollback_at', state.get('applied_at')) if phase == 'ROLLBACK_PENDING_READY' else state.get('applied_at')
                    if phase in {'APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'} and original:
                        observed_at = time.monotonic()
                        end = observed_at + 120 - (updates._utc(updates.now_utc()) - updates._utc(original)).total_seconds()
                        event(root, 'ready_window', phase=phase, applied_at=state.get('applied_at'),
                              rollback_at=state.get('rollback_at'), monotonic_deadline=end, **lock_fields())
                except Exception:
                    pass  # Instrumentation grants no authority and changes no lock result.
                try:
                    yield
                finally:
                    if not trial:
                        held[0] -= 1
                    event(root, 'lock_releasing', trial=trial, system=system, **lock_fields())
        except RuntimeError as error:
            event(root, 'lock_error', trial=trial, system=system, elapsed=time.monotonic()-began,
                  type=type(error).__name__, wait_result=getattr(error, 'wait_result', None), **lock_fields())
            raise
    updates.update_lock = observed_lock
    real_rollback_ready = updates.wait_for_rollback_ready
    def observed_rollback_ready(*args, **kwargs):
        event(root, 'rollback_window_entered', system=system)
        try:
            return real_rollback_ready(*args, **kwargs)
        except Exception as error:
            error_record(root, 'wait_for_rollback_ready', error)
            raise
    updates.wait_for_rollback_ready = observed_rollback_ready
    real_apply = updates._apply_prepared_once
    def observed_apply(*args, **kwargs):
        try:
            return real_apply(*args, **kwargs)
        except Exception as error:
            error_record(root, 'system_apply', error)
            raise
    updates._apply_prepared_once = observed_apply
    protect = lambda text: b'host-test-dpapi:' + text.encode()
    unprotect = lambda raw: raw.removeprefix(b'host-test-dpapi:').decode()
    registration._dpapi_protect_current_user = protect
    registration._dpapi_unprotect_current_user = unprotect
    direct_sync_runtime._dpapi_unprotect_current_user = lambda raw: unprotect(raw).encode()
    profiles.protect_current_user_secret = protect
    profiles.unprotect_current_user_secret = unprotect
    onboarding.unprotect_current_user_secret = unprotect
    profile_installer.protect_current_user_secret = protect
    profile_installer.unprotect_current_user_secret = unprotect
    from tests.test_worker_pc_registration import _FakePossessionKey, TEST_POSSESSION_FINGERPRINT
    class Key(_FakePossessionKey):
        @classmethod
        def provision_initial(cls, **_):
            return cls()
        open_existing = provision_initial
    registration.PersistentPossessionKey = Key
    onboarding.PersistentPossessionKey = Key
    real_inspect = onboarding.inspect_current_user_state
    def observed_inspect(*args, **kwargs):
        result = real_inspect(*args, **kwargs)
        event(root, 'onboarding_readback', status=result['status'], present=result.get('present'),
              error_type=result.get('error_type'))
        return result
    onboarding.inspect_current_user_state = observed_inspect
    real_key_readback = onboarding._possession_key_readback
    def observed_key_readback(*args, **kwargs):
        try:
            return real_key_readback(*args, **kwargs)
        except Exception as error:
            error_record(root, 'key_readback', error)
            raise
    onboarding._possession_key_readback = observed_key_readback
    real_profile_readback = onboarding.load_logistics_runtime_profile
    def observed_profile_readback(*args, **kwargs):
        try:
            return real_profile_readback(*args, **kwargs)
        except Exception as error:
            error_record(root, 'profile_readback', error)
            raise
    onboarding.load_logistics_runtime_profile = observed_profile_readback
    real_registration = registration.build_registration_payloads
    def observed_registration(*args, **kwargs):
        try:
            return real_registration(*args, **kwargs)
        except Exception as error:
            error_record(root, 'registration', error)
            raise
    registration.build_registration_payloads = observed_registration
    def post(url, **kwargs):
        assert url == ORIGIN + '/api/producer-ingest/v2/enroll'
        assert 'X-Producer-Enrollment-Token' not in kwargs.get('headers', {})
        payload = kwargs['json']
        response = fake_v2_enrollment_response(registration, payload, secret=os.urandom(32).hex())
        bundle = _machine_enrollment_response(10)['machine_credential_bundle']
        identity = payload['manifest']['pc_identity']
        bundle['bindings'].update(app=registration.CONTAINER_AUDIT_APP,
                                  source_host_id=identity['source_host_id'], device_id=identity['pc_id'])
        bundle['credentials']['producer_ingest'].update(key_id=response['key_id'], secret=response['secret'])
        bundle['profiles']['logistics'].update(base_url=ORIGIN, source_host_id=identity['source_host_id'], device_id=identity['pc_id'])
        response['machine_credential_bundle'] = bundle
        event(root, 'http', route='enrollment')
        return SimpleNamespace(status_code=200, json=lambda: response)
    requests.post = post
    class Response:
        def __init__(self, url, path):
            self.url, self.path, self.status_code = url, path, 200
            self.headers = {'Content-Length': str(path.stat().st_size)}
        @property
        def content(self):
            return self.path.read_bytes()
        def iter_content(self, chunk_size=65536, **_):
            with self.path.open('rb') as stream:
                while chunk := stream.read(chunk_size):
                    yield chunk
        def json(self):
            return json.loads(self.content)
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
    class Session:
        def __init__(self):
            self.cookies = SimpleNamespace(clear=lambda: None)
            self.headers, self.trust_env, self.leases = {}, False, None
            self.offered = (root / 'offer-ready').exists()
        def get(self, url, **_):
            feed_root = root / 'offer' if self.offered else root
            paths = {ORIGIN + '/feed/latest.json': feed_root / 'feed.json',
                     ORIGIN + '/feed/latest.json.sig': feed_root / 'feed.sig'}
            if self.offered:
                offered = json.loads((root / 'offer-info.json').read_bytes())
                paths[offered['artifact_url']] = Path(offered['packet'])
            assert url in paths, 'unmodelled local update route'
            event(root, 'http', route='update')
            return Response(url, paths[url])
        def post(self, url, **kwargs):
            if url == ORIGIN + '/api/producer-ingest/v2/enroll':
                return post(url, **kwargs)
            import producer_runtime_client
            from tests.test_producer_runtime_client import _LeaseSession
            expected = producer_runtime_client._runtime_endpoint(ORIGIN + '/api/producer-ingest/v1/source-file')
            assert url == expected, 'unmodelled local runtime route'
            if self.leases is None:
                self.leases = _LeaseSession()
            response = self.leases.post(url, **kwargs)
            paths = onboarding.resolve_current_user_onboarding_paths(app)
            identity = json.loads(paths.identity_path.read_bytes())
            response.payload['producer_install_id'] = identity['producer_install_id']
            event(root, 'http', route='runtime')
            return response
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
    requests.Session = Session
    def run(command, *args, **kwargs):
        if any(str(part).endswith('apply_prepared_update.ps1') for part in command):
            mode = command[command.index('-Mode') + 1]
            if mode == 'Observe':
                rows = []
                for path in (root / 'processes').glob('*.json'):
                    row = json.loads(path.read_bytes())
                    native = updates.native_process_identity(row['ProcessId'])
                    if native.get('status') == 'LIVE' and native.get('creation_identity') == row['CreationIdentity']:
                        rows.append(row)
                processes = root / ('query-' + str(os.getpid()) + '.json')
                write(processes, rows)
                script = observe_script(current / 'tools/apply_prepared_update.ps1', current, processes)
                state = json.loads((Path(value['control']) / 'transition.json').read_bytes())
                slow = (value['slow_observe'] > 0 and not system and app == current / 'app' and state['phase'] in {'APPLIED_PENDING_READY', 'ROLLBACK_PENDING_READY'}
                        and not (root / 'slow-observe-started').exists())
                if slow:
                    (root / 'slow-observe-started').touch()
                    script = 'Start-Sleep -Seconds ' + str(value['slow_observe']) + '\n' + script
                target = root / ('query-' + str(os.getpid()) + '.ps1')
                target.write_text(script, encoding='utf-8-sig')
                began = time.monotonic()
                event(root, 'observe_start', system=system, lock_held=held[0] > 0, slow=slow,
                      delay=value['slow_observe'] if slow else 0, phase=state['phase'])
                completed = NATIVE_RUN([updates.system_executable('WindowsPowerShell/v1.0/powershell.exe'),
                                       '-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
                                       '-ExecutionPolicy', 'Bypass', '-File', str(target)],
                                      capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                event(root, 'observe_end', system=system, lock_held=held[0] > 0, slow=slow,
                      elapsed=time.monotonic()-began, rc=completed.returncode)
                if completed.returncode:
                    target.with_suffix('.private.log').write_text(completed.stderr, encoding='utf-8')
                return subprocess.CompletedProcess(command, completed.returncode, completed.stdout, completed.stderr)
            if mode in {'Verify', 'Authority'}:
                quote = lambda path: "'" + str(path).replace("'", "''") + "'"
                driver = root / (mode + '-' + str(os.getpid()) + '.ps1')
                selected = command[command.index('-CodeRoot') + 1] if '-CodeRoot' in command else None
                driver.write_text('Import-Module ' + quote(root / 'native-boundary.psm1') + '\n& '
                    + quote(current / 'tools/apply_prepared_update.ps1') + ' -InstallRoot ' + quote(current)
                    + ' -Mode ' + mode + (' -CodeRoot ' + quote(selected) if selected else '')
                    + '\nexit $LASTEXITCODE\n', encoding='utf-8-sig')
                completed = NATIVE_RUN([updates.system_executable('WindowsPowerShell/v1.0/powershell.exe'),
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', str(driver)],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if completed.returncode:
                    driver.with_suffix('.private.log').write_text(completed.stderr, encoding='utf-8')
                return subprocess.CompletedProcess(command, completed.returncode, completed.stdout, completed.stderr)
            raise AssertionError('unmodelled helper mode')
        if command and Path(command[0]).name.casefold() == 'schtasks.exe':
            assert command[1:3] == ['/Run', '/TN']
            assert command[3] == updates.task_name(current, SID)
            process = launch(config, str(current / 'app/auto_update.py'),
                             ['--apply-prepared', '--control-root', str(value['control'])])
            children.append(process)
            event(root, 'system_dispatched', child_pid=process.pid)
            return subprocess.CompletedProcess(command, 0, b'', b'')
        if command and Path(command[0]).name.casefold() in {'icacls', 'icacls.exe'}:
            return subprocess.CompletedProcess(command, 0, b'', b'')
        return NATIVE_RUN(command, *args, **kwargs)
    subprocess.run = run
    def popen(command, *args, **kwargs):
        entries = [(i, part) for i, part in enumerate(command) if str(part).endswith('.py')]
        if entries:
            index, entry = entries[0]
            if Path(entry).resolve().is_relative_to((root / 'machine').resolve()):
                event(root, 'product_launch', entry=Path(entry).name, child_role='relay' if '--container-audit-user-relay' in command else 'gui')
                process = launch(config, str(entry), command[index+1:], environment=kwargs.get('env'))
                children.append(process)
                return process
        return NATIVE_POPEN(command, *args, **kwargs)
    subprocess.Popen = popen
    return children


def child_main(config, entry, arguments):
    from datetime import datetime, timedelta, timezone
    config = Path(config)
    value = json.loads(config.read_bytes())
    root = config.parent
    if entry in {'onboard', 'helper-probe'}:
        app = Path(value['current']) / 'app'
    elif entry == 'ordinary-probe':
        active = json.loads((Path(value['control']) / 'active.json').read_bytes())['sha']
        app = root / 'machine/versions' / active / 'app'
    else:
        app = Path(entry).parent
    sys.path[:0] = ['E:/KMTech/shared-tools/prodblock', str(app), str(app / 'site-packages')]
    sys.argv = [str(app / 'main.py') if entry in {'onboard', 'ordinary-probe'} else entry, *arguments]
    children = install_os(config, app)
    import auto_update as updates
    identity = updates.native_process_identity(os.getpid())
    created = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(identity['creation_identity'])//10)
    actual_entry = app / 'main.py' if entry in {'onboard', 'ordinary-probe'} else Path(entry)
    product_arguments = ['--onboard-current-user', '--app-root', str(app)] if entry == 'onboard' else arguments
    write(root / 'processes' / (str(os.getpid()) + '.json'), {
        'ProcessId': os.getpid(), 'ParentProcessId': os.getppid(), 'Name': 'pythonw.exe', 'ExecutablePath': str(app.parent / 'runtime/pythonw.exe'),
        'CommandLine': subprocess.list2cmdline([str(app.parent / 'runtime/pythonw.exe'), '-I', '-B', str(actual_entry), *product_arguments]),
        'CreationDate': created.isoformat(), 'CreationIdentity': identity['creation_identity'],
        'Sid': updates.current_process_sid(), 'OrdinaryUser': '--apply-prepared' not in arguments})
    event(root, 'entry_started', entry=Path(entry).name)
    try:
        if entry == 'helper-probe':
            control = Path(value['control'])
            updates.fixed_helper(control, 'Authority')
            began = time.monotonic()
            rows = json.loads(updates.fixed_helper(control, 'Observe'))
            elapsed = time.monotonic() - began
            updates.fixed_helper(control, 'Verify', code_root=Path(value['selected']))
            write(root / 'helper-proof.json', {'Authority': 'PASS', 'Observe': 'PASS', 'Verify': 'PASS',
                                              'row_count': len(rows), 'full_helper': True, 'observe_seconds': elapsed})
            return 0
        if entry == 'ordinary-probe':
            # Exercise the real portable gate and onboarding; no toolkit is
            # created after it returns. A refusal is the original exception.
            gate = updates.startup_gate(app, [])
            if gate is not None:
                child_rcs = [child.wait() for child in children]
                write(root / 'ordinary-result.json', {'status': 'GATE_RETURNED', 'rc': gate, 'child_rcs': child_rcs})
                return gate
            import current_user_onboarding as onboarding
            report = onboarding.onboard_current_user(app, server_base_url=ORIGIN, startup=True)
            write(root / 'ordinary-result.json', {'status': report['status'], 'rc': 0})
            return 0
        if entry == 'onboard':
            import container_audit_product_host as host
            rc = host.dispatch_product_mode(['--onboard-current-user', '--app-root', str(app), '--server-base-url', ORIGIN])
            import current_user_onboarding as onboarding
            paths = onboarding.resolve_current_user_onboarding_paths(app)
            report = json.loads(paths.onboarding_report_path.read_bytes())
            write(root / 'initial-result.json', {'status': report['status'], 'relay_start': report.get('relay_start'), 'rc': rc})
            return rc
        if Path(entry).name == 'auto_update.py':
            return updates.main(arguments)
        if not arguments or arguments[:1] == ['--data-root']:
            assert value['gui_trial_authorized'], 'headless GUI boundary requires lane authorization'
            assert not arguments or (len(arguments) == 2 and Path(arguments[1]).resolve() == root / 'data')
            return gui_readiness_loop(config, app, arguments)
        import container_audit_product_host as host
        if arguments[:1] == ['--container-audit-user-relay']:
            # This is portable/main.py's real startup gate before dispatch.
            result = updates.startup_gate(app, arguments)
            if result is not None:
                return result
        result = host.dispatch_product_mode(arguments)
        assert result is not None, 'explicit headless product mode required'
        return result
    except BaseException as error:
        if not isinstance(error, SystemExit):
            error_record(root, entry, error)
            if entry == 'ordinary-probe':
                write(root / 'ordinary-result.json', {'status': 'EXCEPTION', 'type': type(error).__name__, 'rc': 1})
        raise
    finally:
        event(root, 'entry_finished', entry=Path(entry).name)


def ready(config):
    process = launch(config)
    assert process.wait() == 0, 'inspect fixed error frames and isolated report'
    result = json.loads((config.parent / 'initial-result.json').read_bytes())
    assert result['status'] == 'READY'
    status = config.parent / 'data/direct_sync/status/user_relay_status.json'
    import current_user_onboarding as onboarding
    import user_relay
    # Resolve through the same isolated explicit override in the controller.
    paths = onboarding.resolve_current_user_onboarding_paths(Path(json.loads(config.read_bytes())['current']),
        environ={'LOCALAPPDATA': str(config.parent / 'local'), 'CONTAINER_AUDIT_DATA_ROOT': str(config.parent / 'data'),
                 'CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH': str(config.parent / 'data/logistics/runtime_profile.json')})
    status = user_relay.user_relay_status_path(paths.direct_sync_root)
    wait_for(config, lambda: status.exists() and json.loads(status.read_bytes()).get('status') == 'RUNNING', seconds=180)
    write(config.parent / 'initial-ready-proof.json', {'onboarding': result['status'], 'relay': 'RUNNING',
          'direct_sync_root': str(paths.direct_sync_root)})
    return result


def stop_owned_relays(config):
    import user_relay
    root = config.parent.resolve()
    (root / 'host-finish').touch()
    proof = root / 'initial-ready-proof.json'
    if proof.exists():
        direct = Path(json.loads(proof.read_bytes())['direct_sync_root'])
    else:
        from storage_policy import build_container_audit_storage_paths
        direct = build_container_audit_storage_paths(data_root=root / 'data').direct_sync_root
    assert direct.resolve().is_relative_to(root)
    user_relay.request_user_relay_stop(direct, timeout_seconds=0)
    wait_for(config, lambda: not owned_processes_alive(config), seconds=180)


def session_end(config):
    """The reference harness's owned-process logoff, without an app-stop marker."""
    import ctypes
    from ctypes import wintypes as W
    import auto_update as updates
    import user_relay
    root = config.parent
    direct = Path(json.loads((root / 'initial-ready-proof.json').read_bytes())['direct_sync_root'])
    assert not user_relay.user_relay_stop_path(direct).exists()
    status = json.loads(user_relay.user_relay_status_path(direct).read_bytes())
    pid = status['process_id']
    recorded = json.loads((root / 'processes' / (str(pid) + '.json')).read_bytes())
    assert '--container-audit-user-relay' in recorded['CommandLine']
    # Every link was written by that actual adapter process, from os.getppid().
    ancestry, cursor = [], recorded
    while cursor['ParentProcessId'] != os.getpid():
        parent = root / 'processes' / (str(cursor['ParentProcessId']) + '.json')
        assert parent.is_file() and cursor['ProcessId'] not in ancestry
        ancestry.append(cursor['ProcessId'])
        cursor = json.loads(parent.read_bytes())
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, ctypes.POINTER(W.BOOL)]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    assert handle
    try:
        identity = updates.native_process_identity(pid)
        assert identity.get('status') == 'LIVE' and identity['creation_identity'] == recorded['CreationIdentity']
        contained = W.BOOL()
        assert kernel.IsProcessInJob(handle, None, ctypes.byref(contained)) and contained.value
        result = NATIVE_RUN([updates.system_executable('taskkill.exe'), '/PID', str(pid), '/T', '/F'],
                            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode in (0, 128)
    finally:
        kernel.CloseHandle(handle)
    wait_for(config, lambda: not owned_processes_alive(config), seconds=180)
    assert not user_relay.user_relay_stop_path(direct).exists()
    write(root / 'session-end-proof.json', {'native_birth_proven': True, 'parent_chain_proven': True,
                                           'job_contained': True, 'stop_marker_present': False})


def autorun(config):
    """Execute the exact command produced by actual user-relay installation."""
    import ctypes
    from ctypes import wintypes as W
    command = json.loads((config.parent / 'hkcu-run.json').read_bytes())['command']
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [W.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(W.LPWSTR)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    argv = shell.CommandLineToArgvW(command, ctypes.byref(count))
    assert argv
    try:
        parts = [argv[i] for i in range(count.value)]
    finally:
        kernel.LocalFree(argv)
    assert parts[1:3] == ['-I', '-B'] and Path(parts[3]).name == 'auto_update.py'
    assert parts[4:7] == ['--bootstrap', '--role', 'relay']
    process = launch(config, parts[3], parts[4:])
    rc = process.wait()
    write(config.parent / 'autorun-result.json', {'registered_command_exact': True, 'rc': rc, 'pid': process.pid})
    return rc


def read_result(config, target, bootstrap_rc):
    value = json.loads(config.read_bytes())
    control = Path(value['control'])
    state = json.loads((control / 'transition.json').read_bytes())
    active = json.loads((control / 'active.json').read_bytes())['sha']
    system_errors, bootstrap_errors = [], []
    for path in (config.parent / 'errors').glob('*.json'):
        row = json.loads(path.read_bytes())
        if row['system']:
            system_errors.append(row)
    events = []
    for path in (config.parent / 'observations').glob('*.jsonl'):
        events.extend(json.loads(line) for line in path.read_text().splitlines())
    observed = [row for row in events if row['kind'] in {'observe_start', 'observe_end', 'lock_error'}]
    # Apply catches and preserves the original exception itself; collect that
    # exception at its original product boundary as well as top-level failures.
    result = {'candidate_sha': target, 'active_sha': active, 'phase': state['phase'],
              'applied_at': state.get('applied_at'), 'confirmed': state['phase'] == 'CONFIRMED',
              'bootstrap_rc': bootstrap_rc, 'errors': system_errors, 'timing': observed,
              'ready_receipt_present': (config.parent / 'stage/ready.json').exists(),
              'rolled_back': active == json.loads((config.parent / 'offer-info.json').read_bytes())['from_commit']}
    write(config.parent / 'chain-result.json', result)
    return result


def gui_readiness_loop(config, app, arguments=()):
    """ANSWER-1: actual user readiness, with only toolkit/rendering omitted."""
    import auto_update as updates
    import current_user_onboarding as onboarding
    root = config.parent
    event(root, 'gui_startup_gate_called')
    gate = updates.startup_gate(app, list(arguments))
    if gate is not None:
        event(root, 'gui_gate_returned', rc=gate)
        return gate
    # Match Container_Audit.main: consume machine completion before optional
    # first-run onboarding, using the native caller setting for this branch.
    report = onboarding.consume_pending_machine_onboarding(app)
    enabled = onboarding.first_run_onboarding_enabled()
    event(root, 'gui_native_onboarding_route', first_run_enabled=enabled,
          pending_report_available=report is not None,
          pending_report_status=report.get('status') if report is not None else None)
    if enabled and report is None:
        event(root, 'gui_onboard_called')
        report = onboarding.onboard_current_user(app, server_base_url=ORIGIN, startup=True)
        event(root, 'gui_onboarded', status=report['status'])
    else:
        state = onboarding.inspect_current_user_state(onboarding.resolve_current_user_onboarding_paths(app))
        event(root, 'gui_existing_onboarding_state', status=state.get('status'),
              first_run_enabled=enabled, pending_report_available=report is not None)
    published = False
    called = set()
    while not (root / 'host-finish').exists():
        if 'stop' not in called:
            event(root, 'gui_trial_stop_called')
            called.add('stop')
        if updates.trial_stop_requested(app):
            event(root, 'gui_trial_stop')
            return 0
        if 'context' not in called:
            event(root, 'gui_trial_context_called')
            called.add('context')
        context = updates.trial_context(app)
        if context is not None:
            marker = root / 'withhold-trial-ready'
            withheld = (context[2]['phase'] == 'APPLIED_PENDING_READY'
                        and marker.exists() and marker.stat().st_size <= 64
                        and marker.read_text(encoding='ascii').strip() == context[2]['candidate_sha'])
            if withheld:
                if 'withheld' not in called:
                    event(root, 'gui_ready_withheld', candidate_sha=context[2]['candidate_sha'])
                    called.add('withheld')
            else:
                try:
                    if 'ready' not in called:
                        event(root, 'gui_publish_ready_called')
                        called.add('ready')
                    if updates.publish_gui_ready(app) and not published:
                        event(root, 'gui_ready_published')
                        published = True
                except (OSError, ValueError):
                    pass  # Same read-only retry as Container_Audit.py:23943-23948.
        # The real GUI readiness callback uses 250 ms; this substitutes its
        # event-loop scheduling, not a product timeout or readiness decision.
        time.sleep(0.25)
    return 0


def run_chain(config, target):
    root = config.parent
    (root / 'offer-ready').touch()
    wait_for(config, lambda: (root / 'stage/prepared.json').exists(), seconds=600)
    state = json.loads((Path(json.loads(config.read_bytes())['control']) / 'transition.json').read_bytes())
    write(root / 'prepared-proof.json', {'phase': state['phase'],
          'source_commit': json.loads((root / 'stage/prepared.json').read_bytes())['source_commit']})
    session_end(config)
    rc = autorun(config)
    result = read_result(config, target, rc)
    ordinary = launch(config, 'ordinary-probe')
    ordinary_rc = ordinary.wait()
    result['ordinary_process_rc'] = ordinary_rc
    result['ordinary'] = json.loads((root / 'ordinary-result.json').read_bytes())
    write(root / 'chain-result.json', result)
    return result


def prepare_followup_update(config, signer):
    """ANSWER-8: signed Y from retained active X, with compatibility floor X."""
    import auto_update as updates
    from data_generation_guard import verified_private_compatibility
    root = config.parent.resolve()
    value = json.loads(config.read_bytes())
    active = json.loads((Path(value['control']) / 'active.json').read_bytes())['sha']
    selected = root / 'machine/versions' / active
    before = updates.version_manifest(selected)
    numbers = [int(n) for n in before['version'].removeprefix('v').split('.')]
    numbers[-1] += 1
    next_version = 'v' + '.'.join(str(n) for n in numbers)
    source_x, source_y = root / 's121', root / 'followup-source'
    assert source_x.is_dir() and not source_y.exists()
    shutil.copytree(source_x, source_y,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.cache-binding.json'))
    version_file = source_y / 'Container_Audit.py'
    old = ('CURRENT_VERSION = "' + before['version'] + '"').encode()
    raw = version_file.read_bytes()
    assert raw.count(old) == 1
    version_file.write_bytes(raw.replace(old, ('CURRENT_VERSION = "' + next_version + '"').encode(), 1))
    declarations = []
    for mode in ('--write', '--check'):
        with (root / ('followup-declarations-' + mode[2:] + '.private.log')).open('xb') as stream:
            result = NATIVE_RUN(
                [sys.executable, '-s', '-B', str(source_y / 'tools/refresh_container_update_declarations.py'), mode],
                cwd=source_y, stdout=stream, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW)
        declarations.append({'mode': mode, 'rc': result.returncode})
        assert result.returncode == 0, 'inspect bounded followup declaration diagnostics'
    binding = {'files': {q.relative_to(source_y).as_posix(): hashlib.sha256(q.read_bytes()).hexdigest()
                         for q in source_y.rglob('*') if q.is_file()},
               'declarations': declarations}
    write(source_y / '.cache-binding.json', binding)

    previous_offer = root / 'offer-x'
    assert not previous_offer.exists()
    assert (root / 'offer').resolve().is_relative_to(root)
    assert previous_offer.resolve().is_relative_to(root)
    (root / 'offer').rename(previous_offer)
    value.update(selected=str(selected), next_version=next_version)
    write(config, value)
    name = 'CONTAINER_AUDIT_HOST_TEST_SOURCE121'
    previous_cache = os.environ.get(name)
    os.environ[name] = str(source_y)
    try:
        target = prepare_update(config, signer)
    finally:
        if previous_cache is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous_cache

    candidate = root / 'offer/Container_Audit'
    declared = json.loads((candidate / 'portable-manifest.json').read_bytes())
    compatibility = manifest(next_version, target)
    compatibility['data_compatible_min_version'] = before['version']
    encoded = json.dumps(compatibility, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    signature = signer.sign_es256(encoded)
    public = json.loads((candidate / 'app/update-manifest-key-config.json').read_bytes())['manifest_public_key']
    proof = verified_private_compatibility(compatibility, signature, public,
                                          version=next_version, build_id=target)
    assert proof['compatibility_verified'] is True
    assert proof['data_compatible_min_version'] == before['version']
    declared.update(data_compatible_min_version=before['version'],
                    data_generation_signed_manifest=compatibility,
                    data_generation_signature_hex=signature.hex())
    write(candidate / 'portable-manifest.json', declared)
    packet = root / ('offer/Container_Audit-' + next_version + '.zip')
    archived = root / 'followup-before-compat.zip'
    assert packet.resolve().is_relative_to(root) and not archived.exists()
    packet.rename(archived)
    with zipfile.ZipFile(packet, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for q in sorted(candidate.rglob('*')):
            if q.is_file():
                archive.write(q, 'Container_Audit/' + q.relative_to(candidate).as_posix())
    feed_path = root / 'offer/feed.json'
    feed = json.loads(feed_path.read_bytes())
    feed['data_compatible_min_version'] = before['version']
    with packet.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    feed['artifact'].update(size_bytes=packet.stat().st_size, sha256=digest)
    write(feed_path, feed)
    (root / 'offer/feed.sig').write_bytes(signer.sign_es256(
        json.dumps(feed, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()))
    write(root / 'followup-compatible-proof.json', {
        'from_commit': active, 'target_commit': target, 'version': next_version,
        'data_compatible_min_version': before['version'], 'signature_verified': True,
        'source_declarations': declarations, 'packet_sha256': digest,
        'test_key_only': True, 'product_source_modified_by_hook': False})
    return target
