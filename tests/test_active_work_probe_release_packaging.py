import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

import update_service
from tools.verify_frozen_release_artifact import _verify_probe_identities

ROOT=Path(__file__).resolve().parents[1]
PROBE_FILES=('KMTechActiveWorkProbe.exe','KMTechActiveWorkProbe.independent.build-identity.json',
             'KMTechActiveWorkProbe.integrated.build-identity.json')
APPS=['Inspection_worker','Rework_worker','Defect_Inspection','Container_Audit','Label_Match']


def test_active_work_probe_wrapper_is_only_the_canonical_cli_entrypoint(tmp_path):
    before={path.relative_to(tmp_path) for path in tmp_path.rglob('*')}
    completed=subprocess.run([sys.executable,'-B',str(ROOT/'tools/active_work_probe.py'),'--help'],
                             cwd=tmp_path,capture_output=True,text=True,timeout=20)
    assert completed.returncode==0,completed.stderr[-1200:]
    assert 'usage:' in completed.stdout and '-Mode' in completed.stdout
    assert '-ProbeBuildIdentityPath' in completed.stdout and '-WorkflowMode' in completed.stdout
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob('*')}==before,'help must not produce a probe artifact'


@pytest.mark.parametrize('mode',['independent','integrated'])
@pytest.mark.parametrize('defect,error',[('scope','supported-app scope'),('commit','source commit'),('hash','artifact hash')])
def test_frozen_release_verifier_proves_both_probe_identity_scopes(tmp_path,mode,defect,error):
    artifact=tmp_path/PROBE_FILES[0];artifact.write_bytes(b'owned probe identity artifact')
    expected_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
    for current in ['independent','integrated']:
        value={'schema_version':'kmtech-active-work-probe-build-v1.0.3.4','probe_name':'KMTechActiveWorkProbe',
               'probe_version':'v1.0.3.4','probe_artifact_sha256':expected_hash,'probe_source_commit':'a'*40,
               'workflow_mode':current,'supported_apps':['Container_Audit'] if current=='independent' else APPS}
        (tmp_path/f'KMTechActiveWorkProbe.{current}.build-identity.json').write_text(json.dumps(value),encoding='utf-8')
    report=_verify_probe_identities(tmp_path,expected_commit='a'*40)
    assert report['artifact_sha256']==expected_hash
    assert report['identities']['independent']['supported_apps']==['Container_Audit']
    assert report['identities']['integrated']['supported_apps']==APPS
    path=tmp_path/f'KMTechActiveWorkProbe.{mode}.build-identity.json'
    wrong=json.loads(path.read_text())
    if defect=='scope':wrong['supported_apps']=['Label_Match']
    elif defect=='commit':wrong['probe_source_commit']='b'*40
    else:wrong['probe_artifact_sha256']='b'*64
    path.write_text(json.dumps(wrong),encoding='utf-8')
    with pytest.raises(ValueError,match=error):_verify_probe_identities(tmp_path,expected_commit='a'*40)


@pytest.mark.parametrize('missing',PROBE_FILES)
def test_probe_artifacts_are_manifested_and_required_by_the_exact_update_zip(tmp_path,missing):
    archive=tmp_path/'release.zip'
    members=set(update_service.REQUIRED_UPDATE_ARCHIVE_FILES)
    required={f'Container_Audit/{name}' for name in PROBE_FILES}
    assert required <= members
    with zipfile.ZipFile(archive,'w') as output:
        for name in sorted(members):output.writestr(name,name.encode('utf-8'))
    accepted=update_service.safe_extract_update_zip(archive,tmp_path/'complete')
    assert all((accepted/name).is_file() for name in required)
    with zipfile.ZipFile(archive,'w') as output:
        for name in sorted(members):
            if name!=f'Container_Audit/{missing}':output.writestr(name,name.encode('utf-8'))
    with pytest.raises(ValueError,match=missing.replace('.','\\.')):
        update_service.safe_extract_update_zip(archive,tmp_path/'extract')
