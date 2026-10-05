"""Authenticate bounded stock runtime inventory before granting ZIP exceptions."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

import update_service as service
from tools import build_portable_release_candidate as builder


POLICY = {'layout': 'canonical_portable', 'top_level': 'Container_Audit'}
REQUIRED = (
    'app/main.py', 'app/auto_update.py', 'app/update-manifest-key-config.json',
    'tools/container_writer_sink_inventory.json', 'tools/container_writer_session_contract.json',
    'tools/bootstrap_integrity.ps1', 'tools/apply_prepared_update.ps1',
    'INSTALL_CANONICAL_PORTABLE.ps1', 'INSTALL_THIS_PC.ps1', 'launch-container-audit.cmd',
)


def packet(*, raw=None, rows=None, stock_change=None, file_change=None):
    files = {name: b'stock' for name in REQUIRED}
    files.update({'runtime/python.exe': b'python', 'runtime/pythonw.exe': b'pythonw'})
    if rows is None:
        rows = [{'path': name, 'sha256': hashlib.sha256(data).hexdigest()}
                for name, data in files.items() if name.startswith('runtime/')]
    if raw is None:
        raw = json.dumps({'schema': service.RUNTIME_FILE_INVENTORY_SCHEMA, 'files': rows}).encode()
    stock = {'schema': 'container-audit-portable-tree-v1',
             'runtime_file_inventory_bytes': len(raw),
             'runtime_file_inventory_sha256': hashlib.sha256(raw).hexdigest()}
    if stock_change:
        stock_change(stock)
    files[service.RUNTIME_FILE_INVENTORY_FILENAME] = raw
    files['portable-manifest.json'] = json.dumps(stock).encode()
    if file_change:
        file_change(files)
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr('Container_Audit/' + name, data)
    result.seek(0)
    return zipfile.ZipFile(result)


@pytest.mark.parametrize('byte_count', [None, 1048576])
def test_actual_archive_accepts_authenticated_inventory_at_bound(byte_count):
    raw = None
    if byte_count:
        with packet() as original:
            raw = original.read('Container_Audit/' + service.RUNTIME_FILE_INVENTORY_FILENAME)
        raw += b' ' * (byte_count - len(raw))
    with packet(raw=raw) as archive:
        service.validate_update_archive(archive, POLICY)


@pytest.mark.parametrize('change', ['oversized', 'declared-oversized', 'length', 'hash', 'missing',
                                  'boolean-length', 'inline', 'both'])
def test_inventory_pin_rejections_precede_inventory_json(monkeypatch, change):
    raw = b' ' * 1048577 if change == 'oversized' else None
    def stock_change(stock):
        if change == 'declared-oversized': stock['runtime_file_inventory_bytes'] = 1048577
        elif change == 'length': stock['runtime_file_inventory_bytes'] += 1
        elif change == 'hash': stock['runtime_file_inventory_sha256'] = '0' * 64
        elif change == 'boolean-length': stock['runtime_file_inventory_bytes'] = True
        elif change in ('inline', 'both'):
            stock['runtime_files'] = [{'path': 'runtime/python.exe', 'sha256': '0' * 64}]
            if change == 'inline':
                del stock['runtime_file_inventory_bytes']
                del stock['runtime_file_inventory_sha256']
        elif change == 'oversized': stock['runtime_file_inventory_bytes'] = 1048576
    def file_change(files):
        if change == 'missing': del files[service.RUNTIME_FILE_INVENTORY_FILENAME]
    archive = packet(raw=raw, stock_change=stock_change, file_change=file_change)
    loads = service.json.loads
    calls = []
    def counted(*args, **kwargs):
        calls.append(None)
        return loads(*args, **kwargs)
    monkeypatch.setattr(service.json, 'loads', counted)
    with archive, pytest.raises(ValueError, match='canonical stock runtime inventory'):
        service.validate_update_archive(archive, POLICY)
    assert len(calls) == 1, 'Inventory JSON must remain unread until its pin passes.'


@pytest.mark.parametrize('change', ['missing-member', 'extra-member', 'member-hash', 'duplicate-path',
                                  'case-duplicate', 'invalid-digest', 'invalid-path', 'row-field',
                                  'empty-list', 'schema', 'top-field', 'duplicate-json-field'])
def test_authenticated_inventory_still_enforces_runtime_membership_and_hashes(change):
    with packet() as original:
        inventory = json.loads(original.read('Container_Audit/' + service.RUNTIME_FILE_INVENTORY_FILENAME))
    rows = inventory['files']
    if change == 'duplicate-path': rows.append(dict(rows[0]))
    elif change == 'case-duplicate': rows.append(dict(rows[0], path='runtime/PYTHON.EXE'))
    elif change == 'invalid-digest': rows[0]['sha256'] = 'invalid'
    elif change == 'invalid-path': rows[0]['path'] = 'runtime/../outside'
    elif change == 'row-field': rows[0]['extra'] = True
    elif change == 'empty-list': rows.clear()
    elif change == 'schema': inventory['schema'] = 'unknown'
    elif change == 'top-field': inventory['extra'] = True
    raw = json.dumps(inventory).encode()
    if change == 'duplicate-json-field':
        raw = raw[:-1] + b',"schema":"duplicate"}'
    def file_change(files):
        if change == 'missing-member': del files['runtime/python.exe']
        elif change == 'extra-member': files['runtime/extra.bin'] = b'extra'
        elif change == 'member-hash': files['runtime/python.exe'] += b'changed'
    with packet(raw=raw, file_change=file_change) as archive, pytest.raises(ValueError):
        service.validate_update_archive(archive, POLICY)


def test_builder_sidecar_is_pinned_and_part_of_pre_manifest_metrics(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    (runtime / 'python.exe').write_bytes(b'python')
    before_count, before_bytes = builder._tree_metrics(tmp_path)
    pin = builder._write_runtime_file_inventory(tmp_path)
    raw = (tmp_path / service.RUNTIME_FILE_INVENTORY_FILENAME).read_bytes()
    assert pin == {'runtime_file_inventory_bytes': len(raw),
                   'runtime_file_inventory_sha256': hashlib.sha256(raw).hexdigest()}
    assert builder._tree_metrics(tmp_path) == (before_count + 1, before_bytes + len(raw))
    assert len(json.dumps(pin).encode()) < 65536


def test_builder_refuses_inventory_beyond_reader_bound_before_publication(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    (runtime / 'python.exe').write_bytes(b'python')
    monkeypatch.setattr(builder, 'DEFAULT_MAX_RUNTIME_FILE_INVENTORY_BYTES', 1)
    with pytest.raises(builder.PortableBuildError, match='reader bound'):
        builder._write_runtime_file_inventory(tmp_path)
    assert not (tmp_path / service.RUNTIME_FILE_INVENTORY_FILENAME).exists()


def test_actual_application_copy_omits_unused_validator_asset_preserving_used_defaults(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    source = repo / 'config/validator_settings.json'
    before = source.read_bytes()
    app = tmp_path / 'app'
    builder._copy_application(repo, app)
    assert not (app / 'config/validator_settings.json').exists()
    assert (app / 'config/container_audit_settings.json').read_bytes() == (repo / 'config/container_audit_settings.json').read_bytes()
    assert source.read_bytes() == before
