"""Signed stock-shaped ZIPs exercise the public USER preparation boundary."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest
import requests

import auto_update as update
import update_service
from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('variant', ['canonical', 'root-file', 'outside-prefix', 'duplicate',
    'runtime-extra', 'runtime-hash', 'runtime-ledger', 'runtime-logs', 'runtime-credential',
    'runtime-unlisted-inventory', 'runtime-duplicate-inventory'])
def test_authenticated_stock_zip_prepares_only_with_valid_single_prefix(tmp_path, monkeypatch, variant):
    def stock(commit, version):
        files = {name: (REPO / name).read_bytes() for name in update.CONTRACT_FILES}
        files.update({'app/' + name: (REPO / name).read_bytes() for name in update.DATA_API_FILES})
        files['app/Container_Audit.py'] = ('CURRENT_VERSION = "' + version + '"\n').encode()
        files['portable-manifest.json'] = json.dumps(dict(schema='container-audit-portable-tree-v1',
            source_commit=commit, version=version)).encode()
        # The stock builder archives this entire portable tree under Container_Audit/.
        for name in ('runtime/python.exe', 'runtime/pythonw.exe', 'app/main.py', 'app/auto_update.py',
                     'app/update-manifest-key-config.json', 'tools/bootstrap_integrity.ps1',
                     'tools/apply_prepared_update.ps1', 'INSTALL_CANONICAL_PORTABLE.ps1',
                     'INSTALL_THIS_PC.ps1', 'launch-container-audit.cmd'):
            files.setdefault(name, b'stock fixture')
        return files

    current_files, candidate_files = stock('1' * 40, 'v2.0.99'), stock('2' * 40, 'v2.0.100')
    sensitive = {'runtime-ledger': 'runtime/ledger.sqlite3', 'runtime-logs': 'runtime/logs/state.txt',
                 'runtime-credential': 'runtime/credential.json'}
    if variant in sensitive:
        candidate_files[sensitive[variant]] = b'sensitive fixture must stay forbidden even if listed'
    portable = json.loads(candidate_files['portable-manifest.json'])
    rows = [dict(path=name, sha256=hashlib.sha256(data).hexdigest())
        for name, data in candidate_files.items() if name.startswith('runtime/')]
    if variant == 'runtime-duplicate-inventory': rows.append(rows[0])
    inventory_raw = json.dumps(dict(schema=update_service.RUNTIME_FILE_INVENTORY_SCHEMA, files=rows)).encode()
    candidate_files[update_service.RUNTIME_FILE_INVENTORY_FILENAME] = inventory_raw
    portable['runtime_file_inventory_sha256'] = hashlib.sha256(inventory_raw).hexdigest()
    portable['runtime_file_inventory_bytes'] = len(inventory_raw)
    if variant == 'runtime-unlisted-inventory': portable.pop('runtime_file_inventory_sha256')
    candidate_files['portable-manifest.json'] = json.dumps(portable).encode()
    if variant == 'runtime-extra': candidate_files['runtime/extra.bin'] = b'not declared in stock'
    elif variant == 'runtime-hash': candidate_files['runtime/python.exe'] += b'changed bytes'
    current, candidate = update.version_identity(current_files.__getitem__), update.version_identity(candidate_files.__getitem__)
    packet = io.BytesIO()
    with zipfile.ZipFile(packet, 'w') as archive:
        for name, data in candidate_files.items():
            archive.writestr('Container_Audit/' + name, data)
        if variant == 'root-file':
            archive.writestr('portable-manifest.json', candidate_files['portable-manifest.json'])
        elif variant == 'outside-prefix':
            archive.writestr('Other/portable-manifest.json', candidate_files['portable-manifest.json'])
        elif variant == 'duplicate':
            with pytest.warns(UserWarning, match='Duplicate name'):
                archive.writestr('Container_Audit/portable-manifest.json', candidate_files['portable-manifest.json'])
    packet_bytes = packet.getvalue()
    forward = dict(from_commit=current['source_commit'], to_commit=candidate['source_commit'],
        from_contract_sha256=current['contract_sha256'], to_contract_sha256=candidate['contract_sha256'])
    reverse = dict(from_commit=forward['to_commit'], to_commit=forward['from_commit'],
        from_contract_sha256=forward['to_contract_sha256'], to_contract_sha256=forward['from_contract_sha256'])
    pin = lambda direction: hashlib.sha256(update_service.canonical_manifest_bytes(direction)).hexdigest()
    feed_url, packet_url = 'https://updates.example/feed.json', 'https://updates.example/Container_Audit-v2.0.100.zip'
    manifest = dict(schema_version='kmtech-private-update-manifest-v1', manifest_version=1,
        signature_version='es256-v1', app_id='Container_Audit', package_id='Container_Audit', channel='stable',
        version=candidate['version'], source_commit=candidate['source_commit'],
        artifact=dict(name='Container_Audit-v2.0.100.zip', url=packet_url, size_bytes=len(packet_bytes),
                      sha256=hashlib.sha256(packet_bytes).hexdigest()),
        archive=dict(format='zip', top_level='Container_Audit', layout='canonical_portable',
                     entrypoint='launch-container-audit.cmd', required_files=['Container_Audit/portable-manifest.json']),
        install=dict(strategy='robocopy_backup_then_mirror', preserve_paths=['config', 'logs', 'ledger'],
                     restart_executable='Container_Audit.exe'),
        rollout=dict(percentage=100, allow_pc_ids=[], deny_pc_ids=[]),
        auto_update=dict(from_commit=forward['from_commit'], to_commit=forward['to_commit'],
            forward_contract_sha256=pin(forward), rollback_contract_sha256=pin(reverse)),
        approved_transitions=[forward, reverse])
    with P256KeyPair.generate() as key:
        signature = key.sign_es256(update_service.canonical_manifest_bytes(manifest))
        public = json.dumps(key.public_jwk)
    control, stage = tmp_path / 'owned/control', tmp_path / 'stage'
    control.mkdir(parents=True)
    records = {control / 'policy.json': dict(feed_url=feed_url, channel='stable', staging_root=str(stage)),
        control.parent / 'current/app/update-manifest-key-config.json': dict(manifest_public_key=public),
        control / 'active.json': dict(sha=current['source_commit'])}
    original_read = update.read_json
    monkeypatch.setattr(update, 'read_json', lambda path, **kw: records[path] if path in records else original_read(path, **kw))
    monkeypatch.setattr(update, 'control_root', lambda _root: control)
    monkeypatch.setattr(update, 'verify_lifecycle_stock', lambda _root: None)
    monkeypatch.setattr(update, 'version_manifest', lambda _root, **kw: current)
    monkeypatch.setattr(update, 'create_protected_stage', lambda path: path.mkdir())
    bodies = {feed_url: update_service.canonical_manifest_bytes(manifest), feed_url + '.sig': signature, packet_url: packet_bytes}

    class Response:
        status_code = 200
        def __init__(self, url): self.url, self.body = url, bodies[url]
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_content(self, size):
            for offset in range(0, len(self.body), size): yield self.body[offset:offset + size]
        def close(self): pass

    class Session:
        cookies = type('Cookies', (), {'clear': lambda self: None})()
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs): return Response(url)

    monkeypatch.setattr(requests, 'Session', Session)
    if variant == 'canonical':
        assert update.prepare_feed_packet(tmp_path) == dict(status='PREPARED', source_commit=candidate['source_commit'])
        prepared = original_read(stage / 'prepared.json')
        assert prepared['packet_sha256'] == hashlib.sha256(packet_bytes).hexdigest()
        assert (stage / 'packet.zip').read_bytes() == packet_bytes
        assert (stage / 'manifest.sig').read_bytes() == signature
        extracted = update_service.safe_extract_update_zip(stage / 'packet.zip', tmp_path / 'extracted',
            archive_policy=manifest['archive'])
        assert (extracted / 'Container_Audit/runtime/python.exe').read_bytes() == candidate_files['runtime/python.exe']
    else:
        with pytest.raises(ValueError): update.prepare_feed_packet(tmp_path)
        assert not (stage / 'prepared.json').exists()
        assert not (stage / 'packet.zip').exists()
        downloaded = next(stage.glob('download-*')) / 'packet.zip'
        with pytest.raises(ValueError):
            update_service.safe_extract_update_zip(downloaded, tmp_path / 'rejected-extraction', archive_policy=manifest['archive'])
        assert not list((tmp_path / 'rejected-extraction').rglob('*'))
