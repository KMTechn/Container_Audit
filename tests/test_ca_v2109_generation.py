"""Release constants and real generation readers against immutable old sources."""
import ast
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from kmtech_shared import data_generation as generation
from tests.powershell_contracts import run_powershell
from tools.check_release_version import read_current_version
from tools import build_portable_release_candidate as builder

ROOT = Path(__file__).resolve().parents[1]
OLD_RELEASES = (
    ('e0c46f4104c3034f061580f11718aca2bc209bcc', 'v2.0.107'),
    ('d3a1ad7b2364aae808c36a2359b18b04f92025e2', 'v2.0.108'),
)


def test_current_app_alias_and_default_data_floor_are_109():
    assert read_current_version(ROOT / 'Container_Audit.py') == 'v2.0.109'
    tree = ast.parse((ROOT / 'Container_Audit.py').read_text(encoding='utf-8-sig'))
    aliases = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'APP_VERSION' for t in n.targets)]
    assert len(aliases) == 1
    assert isinstance(aliases[0].value, ast.Name) and aliases[0].value.id == 'CURRENT_VERSION'
    assert builder._release_data_metadata(ROOT, None) == {
        'version': 'v2.0.109', 'data_compatible_min_version': 'v2.0.109'}


@pytest.mark.parametrize('old_sha,old_version', OLD_RELEASES)
@pytest.mark.parametrize('slot', ('direct-user', 'machine'))
@pytest.mark.parametrize('reader', ('python', 'powershell', 'pwsh'))
def test_109_data_record_refuses_immutable_107_and_108_sources(tmp_path, old_sha, old_version, slot, reader):
    old_source = subprocess.check_output(
        ['git', 'show', old_sha + ':Container_Audit.py'], cwd=ROOT,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    old_path = tmp_path / 'old-source.py'
    old_path.write_bytes(old_source)
    assert read_current_version(old_path) == old_version
    current = read_current_version(ROOT / 'Container_Audit.py')
    build = subprocess.check_output(['git', 'rev-parse', 'HEAD^{commit}'], cwd=ROOT,
        text=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).strip()
    marker = tmp_path / slot / 'data-generation.json'
    marker.parent.mkdir()
    business = tmp_path / 'business.dat'
    business.write_bytes(b'preserved-business-state')
    sid = 'S-1-5-21-109'
    assert generation.probe_downgrade([marker], old_version, app_id='container_audit',
        subject_sid=sid, target_build_id=old_sha)['allowed'] is True
    generation.record_generation(marker, current, app_id='container_audit', subject_sid=sid, build_id=build)
    before = marker.read_bytes()
    assert json.loads(before)['data_compatible_min_version'] == current
    if reader == 'python':
        decision = generation.probe_downgrade([marker], old_version, app_id='container_audit',
            subject_sid=sid, target_build_id=old_sha)
    else:
        assert shutil.which(reader)
        helper = str(ROOT / 'kmtech_shared/powershell/data_generation.ps1').replace("'", "''")
        literal = str(marker).replace("'", "''")
        driver = tmp_path / 'reader.ps1'
        driver.write_text(f"$ErrorActionPreference='Stop'\n. '{helper}'\n"
            f"Get-KmtechDataDowngradeDecision @('{literal}') '{old_version}' 'container_audit' '{sid}' '{old_sha}' | ConvertTo-Json -Compress\n",
            encoding='utf-8-sig')
        result = run_powershell([reader, '-NoProfile', '-NonInteractive', '-File', str(driver)])
        assert result.returncode == 0
        decision = json.loads(result.stdout)
    assert decision['status'] == 'REFUSE' and decision['allowed'] is False
    assert marker.read_bytes() == before
    assert business.read_bytes() == b'preserved-business-state'
