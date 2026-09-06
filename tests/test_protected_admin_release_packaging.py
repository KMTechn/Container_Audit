"""Actual archive admission and native packaged-wrapper argument behavior."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

import update_service
from tests.native_process_fixtures import native_argument_recorder

ROOT = Path(__file__).resolve().parents[1]
INSTALLER_NAME = 'Container_Audit_Protected_Admin_Install.exe'
ACL_SCRIPT_NAME = 'PROVISION_PROTECTED_ADMIN_ACL.ps1'
PROVISIONING_DOC_NAME = 'PROTECTED_ADMIN_PROVISIONING.md'


@pytest.mark.parametrize('missing', [INSTALLER_NAME, ACL_SCRIPT_NAME, PROVISIONING_DOC_NAME])
def test_release_archive_requires_each_protected_admin_payload(tmp_path, missing):
    archive = tmp_path / 'release.zip'
    members = set(update_service.REQUIRED_UPDATE_ARCHIVE_FILES)
    required = {f'Container_Audit/{name}' for name in (INSTALLER_NAME, ACL_SCRIPT_NAME, PROVISIONING_DOC_NAME)}
    assert required <= members
    assert not any('install_protected_admin.py' in name for name in members)
    with zipfile.ZipFile(archive, 'w') as output:
        for name in sorted(members):
            output.writestr(name, name.encode())
    accepted = update_service.safe_extract_update_zip(archive, tmp_path / 'complete')
    assert all((accepted / name).is_file() for name in required)
    with zipfile.ZipFile(archive, 'w') as output:
        for name in sorted(members - {f'Container_Audit/{missing}'}):
            output.writestr(name, name.encode())
    with pytest.raises(ValueError, match=missing.replace('.', r'\.')):
        update_service.safe_extract_update_zip(archive, tmp_path / 'incomplete')
    assert not any((tmp_path / 'incomplete').iterdir())


def _wrapper(tmp_path, recorder):
    packet = tmp_path / 'owned release 한글'
    packet.mkdir()
    shutil.copy2(recorder, packet / INSTALLER_NAME)
    wrapper = packet / ACL_SCRIPT_NAME
    shutil.copy2(ROOT / 'tools/provision_protected_admin_acl.ps1', wrapper)
    return wrapper


def _run(wrapper, tmp_path, *arguments, exit_code=0):
    receipt = tmp_path / 'arguments.json'
    env = dict(os.environ, CA_ARGUMENT_RECEIPT=str(receipt), CA_ARGUMENT_EXIT_CODE=str(exit_code))
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(wrapper), *arguments],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=20)
    return result, json.loads(receipt.read_text()) if receipt.exists() else None


@pytest.mark.parametrize('exit_code', [0, 23])
def test_acl_wrapper_forwards_exact_dry_run_profile_and_propagates_child_failure(tmp_path, native_argument_recorder, exit_code):
    wrapper = _wrapper(tmp_path, native_argument_recorder)
    profile = tmp_path / 'profile with spaces 한글.json'
    result, arguments = _run(wrapper, tmp_path, '-DryRun', '-ProfilePath', str(profile), exit_code=exit_code)
    assert arguments == ['--dry-run', '--profile-path', str(profile)]
    assert result.returncode == (0 if exit_code == 0 else 1)
    if exit_code == 0:
        assert 'protected_admin_provision=PASS mode=dry-run' in result.stdout
    else:
        assert 'exit code 23' in result.stderr
        assert 'protected_admin_provision=PASS' not in result.stdout
    assert not profile.exists()


@pytest.mark.parametrize('invalid', ['replace_dry_run', 'code_parameter', 'missing_installer', 'missing_reader'])
def test_acl_wrapper_rejects_invalid_request_before_native_child(tmp_path, native_argument_recorder, invalid):
    wrapper = _wrapper(tmp_path, native_argument_recorder)
    arguments = ['-DryRun']
    if invalid == 'replace_dry_run':
        arguments.append('-Replace')
    elif invalid == 'code_parameter':
        arguments += ['-Code', 'inert-fixture-value']
    elif invalid == 'missing_installer':
        (wrapper.parent / INSTALLER_NAME).unlink()
    else:
        arguments = []
    result, observed = _run(wrapper, tmp_path, *arguments)
    assert result.returncode != 0
    assert observed is None
    assert 'protected_admin_provision=PASS' not in result.stdout


def test_acl_wrapper_forwards_reader_and_replace_after_native_elevation_prerequisite(tmp_path, native_argument_recorder):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('non-dry-run wrapper requires an already elevated native process')
    wrapper = _wrapper(tmp_path, native_argument_recorder)
    profile = tmp_path / 'unchanged profile.json'
    result, arguments = _run(wrapper, tmp_path, '-ReaderPrincipal', r'Fixture\Reader With Spaces', '-ProfilePath', str(profile), '-Replace')
    assert result.returncode == 0, result.stderr[-1600:]
    assert arguments == ['--reader-principal', r'Fixture\Reader With Spaces', '--profile-path', str(profile), '--replace']
    assert not profile.exists()
