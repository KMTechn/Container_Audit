"""Regressions for the Windows FULL fixture/environment failures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import venv

import pytest

from tests.native_process_fixtures import native_python_environment, native_python_executable
from tests.powershell_contracts import run_powershell
from tests import test_canonical_portable_uninstall as uninstall
from tools.run_test1_exact_artifact import query_process_executable_path

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows process/PowerShell boundary')


@pytest.mark.parametrize('mode', ['-File', '-Command'])
@pytest.mark.parametrize('exit_code', [0, 23])
def test_powershell_utf8_preserves_arguments_diagnostics_and_exit(tmp_path, mode, exit_code):
    powershell = shutil.which('powershell.exe')
    assert powershell
    driver = tmp_path / "protocol ' 한글.ps1"
    driver.write_text(r'''
param([string]$Value, [switch]$Enabled)
@{value=$Value; enabled=$Enabled.IsPresent; root=$PSScriptRoot; encoding=[Console]::OutputEncoding.WebName} | ConvertTo-Json -Compress
[Console]::Error.WriteLine('오류: strict diagnostic')
exit __EXIT__
'''.replace('__EXIT__', str(exit_code)), encoding='utf-8-sig')
    value = "공백 ' $value ` literal"
    if mode == '-File':
        arguments = [str(driver), '-Value', value, '-Enabled']
    else:
        arguments = ["& '" + str(driver).replace("'", "''") + "' -Value '" + value.replace("'", "''")
                     + "' -Enabled; exit $LASTEXITCODE"]
    result = run_powershell([powershell, '-NoProfile', '-NonInteractive', mode, *arguments], timeout=15)
    assert result.returncode == exit_code
    assert json.loads(result.stdout) == {
        'value': value, 'enabled': True, 'root': str(tmp_path), 'encoding': 'utf-8',
    }
    assert result.stderr == '오류: strict diagnostic\n'


def test_powershell_invalid_utf8_raises_on_calling_thread():
    powershell = shutil.which('powershell.exe')
    assert powershell
    with pytest.raises(UnicodeDecodeError):
        run_powershell([powershell, '-NoProfile', '-NonInteractive', '-Command',
                        '[Console]::OpenStandardError().WriteByte(255)'], timeout=15)


@pytest.mark.parametrize('use_venv', [False, True])
def test_native_python_keeps_exact_pid_and_environment(tmp_path, monkeypatch, use_venv):
    expected_prefix = sys.prefix
    if use_venv:
        environment_root = tmp_path / 'venv'
        venv.EnvBuilder(with_pip=False).create(environment_root)
        (environment_root / 'Lib/site-packages/owned_venv_probe.py').write_text('VALUE = 42\n')
        monkeypatch.setattr(sys, 'executable', str(environment_root / 'Scripts/python.exe'))
        expected_prefix = str(environment_root)
    receipt = tmp_path / 'identity.json'
    script = (
        'import json,os,sys,threading; from pathlib import Path; '
        'timer=threading.Timer(15,lambda:os._exit(9)); timer.start(); '
        + ('import owned_venv_probe; assert owned_venv_probe.VALUE == 42; ' if use_venv else '')
        + 'Path(sys.argv[1]).write_text(json.dumps(dict(pid=os.getpid(),prefix=sys.prefix,executable=sys.executable))); '
        'sys.stdin.buffer.read(1); timer.cancel()'
    )
    with (tmp_path / 'native.stdout').open('xb') as stdout, (tmp_path / 'native.stderr').open('xb') as stderr:
        child = subprocess.Popen([str(native_python_executable()), '-I', '-B', '-c', script, str(receipt)],
                                 env=native_python_environment(), stdin=subprocess.PIPE,
                                 stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = time.monotonic() + 10
        while not receipt.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.025)
        observed = json.loads(receipt.read_text())
        assert observed['pid'] == child.pid
        assert Path(observed['prefix']).resolve() == Path(expected_prefix).resolve()
        assert Path(observed['executable']).resolve() == Path(sys.executable).resolve()
        assert query_process_executable_path(child.pid).resolve() == native_python_executable()
    finally:
        child.stdin.close()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            child.wait(timeout=5)
    assert child.returncode == 0


@pytest.mark.parametrize('failure', ['startup', 'preimage'])
def test_relay_owner_cleans_up_before_first_assertion(tmp_path, monkeypatch, failure):
    host = tmp_path / 'host.py'
    host.write_text(r'''
import os, time
from pathlib import Path
root = Path(os.environ['CA_UNINSTALL_ROOT'])
if os.environ['OWNED_FAILURE'] == 'startup':
    raise SystemExit(9)
(root / 'relay.ready').touch()
try:
    while not (root / 'finish').exists(): time.sleep(.025)
finally:
    (root / 'relay.ready').unlink()
''', encoding='utf-8')
    environment = native_python_environment()
    environment.update(CA_UNINSTALL_PYTHON=str(native_python_executable()), CA_UNINSTALL_HOST=str(host),
                       CA_UNINSTALL_ROOT=str(tmp_path), OWNED_FAILURE=failure)
    children = []
    launch = subprocess.Popen

    def record(*args, **kwargs):
        child = launch(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(uninstall.subprocess, 'Popen', record)
    try:
        with pytest.raises(AssertionError, match='isolated relay did not start|preimage assertion'):
            with uninstall._launch_relay(tmp_path, environment):
                raise AssertionError('preimage assertion')
        assert len(children) == 1
        assert children[0].poll() is not None
        assert (tmp_path / 'finish').exists()
        assert not (tmp_path / 'relay.ready').exists()
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
