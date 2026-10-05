"""Shared bootstrap CA selection stays stable across source/install roots."""
from pathlib import Path
import json,subprocess,sys
import pytest

REPO=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('case',['bootstrap-same','bootstrap-changed'])
def test_bootstrap_ca_binding_before_writer_admission(tmp_path,case):
    process=subprocess.run([sys.executable,'-B',str(REPO/'tests/onboarding_preflight_child.py'),
                            str(REPO),str(tmp_path),case],capture_output=True,text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW,timeout=60)
    assert process.returncode==0, 'isolated bootstrap fixture failed'
    result=json.loads(process.stdout.strip().splitlines()[-1])
    assert result['same_input_binding'] is True
    assert result['changed_file_count']==0
    if case=='bootstrap-same':
        assert result['code']==0
        assert result['admission_cutoff_reached'] is True
    else:
        assert result['code']==4
        assert result['status']=='BLOCKED'
        assert result['admission_cutoff_reached'] is False
