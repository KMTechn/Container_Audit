"""Canonical preflight refuses before state writes; no G adapter is replaced."""
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import pytest


@pytest.mark.parametrize('case',[
    'nested-newer','nested-unknown','locator-newer','same','absent',
    'malformed','duplicate','binding-changed',
])
def test_readonly_onboarding_preflight_real_child(tmp_path,case):
    root=tmp_path/'isolated'
    root.mkdir()
    env=os.environ.copy()
    env.update(TEMP=str(root),TMP=str(root),PYTHONDONTWRITEBYTECODE='1')
    child=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('onboarding_preflight_child.py')),
        str(Path.cwd()),str(root),case],env=env,capture_output=True,text=True,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    (root/'stdout.txt').write_text(child.stdout,encoding='utf-8')
    (root/'stderr.txt').write_text(child.stderr,encoding='utf-8')
    assert child.returncode==0
    result=json.loads(child.stdout.splitlines()[-1])
    assert result['g_stubbed'] is False
    assert result['unchanged'] is True
    assert result['report_exists'] is False
    assert result['exit']==(0 if case in {'same','absent'} else 4)
    if case=='binding-changed':
        assert result['status']=='BLOCKED'


@pytest.mark.parametrize('engine',['powershell.exe','pwsh.exe'])
@pytest.mark.parametrize('case',['nested-newer','nested-unknown','locator-newer','same','absent','malformed','duplicate',
    'restore-newer','restore-locator-newer','restore-same','restore-absent','restore-unknown',
    'restore-bootstrap-tampered','restore-manifest-tampered'])
def test_canonical_powershell_readonly_child(tmp_path,engine,case):
    assert shutil.which(engine), f'required PowerShell engine unavailable: {engine}'
    root=tmp_path/'isolated'
    root.mkdir()
    env=os.environ.copy()
    env.update(TEMP=str(root),TMP=str(root),PYTHONDONTWRITEBYTECODE='1')
    child=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('onboarding_preflight_child.py')),
        str(Path.cwd()),str(root),case,engine],env=env,capture_output=True,text=True,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    (root/'stdout.txt').write_text(child.stdout,encoding='utf-8')
    (root/'stderr.txt').write_text(child.stderr,encoding='utf-8')
    assert child.returncode==0
    result=json.loads(child.stdout.splitlines()[-1])
    assert result['g_stubbed'] is False
    assert result['unchanged'] is True
    assert result['report_exists'] is False
    assert result['authority_released'] is True
    assert result['exit']==(0 if case in {'same','absent','restore-same','restore-absent'} else 4)


@pytest.mark.parametrize('case',[
    'restore-newer','restore-locator-newer','restore-same','restore-absent',
    'restore-unknown','restore-bootstrap-tampered','restore-manifest-tampered',
])
def test_verified_restore_uses_old_target_generation_before_changes(tmp_path,case):
    root=tmp_path/'isolated'
    root.mkdir()
    env=os.environ.copy()
    env.update(TEMP=str(root),TMP=str(root),PYTHONDONTWRITEBYTECODE='1')
    child=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('onboarding_preflight_child.py')),
        str(Path.cwd()),str(root),case],env=env,capture_output=True,text=True,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    (root/'stdout.txt').write_text(child.stdout,encoding='utf-8')
    (root/'stderr.txt').write_text(child.stderr,encoding='utf-8')
    assert child.returncode==0
    result=json.loads(child.stdout.splitlines()[-1])
    assert result['g_stubbed'] is False
    assert result['unchanged'] is True
    assert result['report_exists'] is False
    assert result['exit']==(0 if case in {'restore-same','restore-absent'} else 4)
