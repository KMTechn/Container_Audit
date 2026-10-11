import copy
import hashlib
import json

import pytest

from tools import refresh_container_update_declarations as refresh


@pytest.fixture
def declaration_root(tmp_path, monkeypatch):
    (tmp_path / 'tools').mkdir()
    old, new = '1' * 64, '2' * 64
    files = {
        'writer_session_fence.py': ('WRITER_INVENTORY_SHA256 = "' + old + '"\n').encode(),
        'tools/container_writer_fence.ps1': b'\xef\xbb\xbf' + ("$Script:ContainerWriterFenceInventorySha256 = '" + old + "'\r\n").encode(),
        'tools/container_writer_session_contract.json': json.dumps({'writer_inventory_sha256': old}).encode(),
        'tools/container_writer_sink_inventory.json': json.dumps({'inventory_sha256': new}).encode(),
        'current_user_onboarding.py': b'changed_current_bytes\n',
    }
    for path, contents in files.items():
        (tmp_path / path).write_bytes(contents)
    declaration = {
        'schema_version': 'container-audit-g-forward-transition-v1', 'direction': 'forward',
        'after_inventory_sha256': old, 'before_inventory_sha256': old,
        'source_replacements': [{'path': 'current_user_onboarding.py', 'before': old, 'after': old},
                                {'path': 'tools/container_writer_fence.ps1', 'before': old, 'after': old}],
        'files': [{'path': 'app/current_user_onboarding.py', 'before': old, 'after': old},
                  {'path': 'tools/container_writer_fence.ps1', 'before': old, 'after': old},
                  {'path': 'tools/container_writer_sink_inventory.json', 'before': old, 'after': old},
                  {'path': 'runtime/unchanged.bin', 'before': old, 'after': old}],
        'installed_release_preimages': [{'source_commit': '3' * 40, 'files': [{'sha256': old}]}],
        'hash_provenance': {'before': 'retained released bytes'},
    }
    path = tmp_path / 'tools/container_data_generation_transition.json'
    path.write_bytes(refresh.inventory._canonical_json_bytes(declaration))
    monkeypatch.setattr(refresh, 'ROOT', tmp_path)
    monkeypatch.setattr(refresh.inventory, 'main', lambda _args: 0)
    return tmp_path, copy.deepcopy(declaration)


def test_refresh_preserves_all_released_preimages_and_ps_bom(declaration_root):
    root, original = declaration_root
    assert refresh.main(['--write']) == 0
    current = json.loads((root / 'tools/container_data_generation_transition.json').read_bytes())
    assert current['before_inventory_sha256'] == original['before_inventory_sha256']
    assert current['installed_release_preimages'] == original['installed_release_preimages']
    assert current['hash_provenance'] == original['hash_provenance']
    for name in ('source_replacements', 'files'):
        assert [row['before'] for row in current[name]] == [row['before'] for row in original[name]]
    assert current['files'][-1] == original['files'][-1]
    for row in current['source_replacements']:
        assert row['after'] == hashlib.sha256((root / row['path']).read_bytes()).hexdigest()
    ps = (root / 'tools/container_writer_fence.ps1').read_bytes()
    assert ps.startswith(b'\xef\xbb\xbf') and ps.endswith(b'\r\n')
    before_check = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert refresh.main(['--check']) == 0
    assert before_check == {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('stale', ['writer_session_fence.py', 'tools/container_writer_session_contract.json',
                                  'current_user_onboarding.py'])
def test_check_rejects_stale_bindings_without_rewriting(declaration_root, stale):
    root, _ = declaration_root
    refresh.main(['--write'])
    path = root / stale
    path.write_bytes(path.read_bytes().replace(b'2' * 64, b'1' * 64) + b'\n')
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with pytest.raises(SystemExit, match='stale'):
        refresh.main(['--check'])
    assert before == {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
