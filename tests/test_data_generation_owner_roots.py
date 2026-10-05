"""Impossible plain-file paths retain errors without trusting another root."""
from pathlib import Path
from types import SimpleNamespace
import stat

import pytest

import data_generation_guard as guard
from tools import register_container_audit_worker_pc as registrar


@pytest.fixture
def release(monkeypatch):
    sid = 'S-1-5-21-233-233-233-233'
    monkeypatch.setattr(registrar, '_current_user_sid', lambda: sid)
    monkeypatch.setattr(guard, '_runtime_release', lambda: {
        'version': 'v2.0.99', 'build_id': 'a' * 40,
        'data_compatible_min_version': 'v2.0.99', 'compatibility_verified': False})
    return sid


def higher_marker(path, sid):
    path.parent.mkdir(parents=True, exist_ok=True)
    guard.generation.record_generation(path, 'v999.0.0', app_id='container_audit',
        subject_sid=sid, build_id='b' * 40, data_compatible_min_version='v999.0.0',
        compatibility_verified=False)
    return path.read_bytes()


@pytest.mark.parametrize('as_directory', (False, True))
def test_plain_file_ancestor_does_not_substitute_parent_marker(tmp_path, release, as_directory):
    default = tmp_path / 'default'
    external = tmp_path / 'external'
    original = higher_marker(external / 'data-generation.json', release)
    blocker = external / 'plain-file'
    blocker.write_bytes(b'not a directory')
    impossible = blocker / 'missing-owner'
    kwargs = {'directory_paths': (impossible,)} if as_directory else {'file_paths': (impossible / 'identity.json',)}
    guard.probe_before_owner_paths(default, **kwargs)
    assert (external / 'data-generation.json').read_bytes() == original
    assert blocker.read_bytes() == b'not a directory'
    assert not default.exists()


def test_real_external_directory_still_refuses_higher_marker(tmp_path, release):
    default = tmp_path / 'default'
    external = tmp_path / 'external'
    original = higher_marker(external / 'data-generation.json', release)
    with pytest.raises(guard.DataGenerationBlocked) as error:
        guard.probe_before_owner_paths(default, file_paths=(external / 'identity.json',))
    assert error.value.decision['status'] == 'REFUSE'
    assert (external / 'data-generation.json').read_bytes() == original
    assert not default.exists()


def test_reparse_ancestor_cannot_prove_owner_root_absent(tmp_path, release, monkeypatch):
    alias = tmp_path / 'alias'
    alias.mkdir()
    blocker = alias / 'plain-file'
    blocker.write_bytes(b'not a directory')
    original_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if path == alias:
            return SimpleNamespace(st_mode=metadata.st_mode,
                st_file_attributes=getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))
        return metadata

    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(guard.DataGenerationBlocked) as error:
        guard.probe_before_owner_paths(tmp_path / 'default', file_paths=(blocker / 'identity.json',))
    assert error.value.decision['status'] == 'UNKNOWN'
    assert blocker.read_bytes() == b'not a directory'
