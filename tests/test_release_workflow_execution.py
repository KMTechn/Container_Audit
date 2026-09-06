from copy import deepcopy
import json
from pathlib import Path

import pytest

from tests.workflow_contracts import COMMIT, CONTRACT_SHA, FINAL, TAG, TAG_OBJECT, TREE, WAIT, WorkflowHarness


@pytest.mark.parametrize('defect', ['none', 'lightweight_tag', 'head', 'main', 'fetch'])
def test_release_prebind_rejects_unannotated_or_different_head_main(tmp_path, defect):
    harness = WorkflowHarness(tmp_path)
    result, observed = harness.run('Prebind annotated tag object and peel to exact origin main',
        tag_type='commit' if defect == 'lightweight_tag' else 'tag',
        head_commit='b'*40 if defect == 'head' else COMMIT,
        main_commit='b'*40 if defect == 'main' else COMMIT, fetch_failure=defect == 'fetch')
    assert result.returncode == (0 if defect == 'none' else 1)
    if defect == 'none':
        recorded = (tmp_path/'github.env').read_text(encoding='utf-8-sig')
        assert 'RELEASE_TAG_OBJECT_SHA='+TAG_OBJECT in recorded
        assert 'RELEASE_TAG_COMMIT_SHA='+COMMIT in recorded
        assert observed['git_calls'][-2:] == ['fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main', 'rev-parse --verify refs/remotes/origin/main^{commit}']
    else:
        assert not (tmp_path/'github.env').exists()


@pytest.mark.parametrize('defect', ['none', 'object', 'peel', 'message', 'parser_failure'])
def test_release_tag_parser_caller_binds_arguments_and_independent_preimage(tmp_path, defect):
    harness = WorkflowHarness(tmp_path)
    identity = {'tag_object_sha': TAG_OBJECT, 'peeled_commit_sha': COMMIT, 'message': 'Release '+TAG}
    if defect == 'object': identity['tag_object_sha'] = 'b'*40
    elif defect == 'peel': identity['peeled_commit_sha'] = 'b'*40
    elif defect == 'message': identity['message'] += '\nextra'
    result, observed = harness.run('Bind canonical create-once FINAL tag identity',
        parser_identity=identity, parser_failure=defect == 'parser_failure')
    assert observed['python_arguments'] == ['tools/read_release_qualification_tag.py', '--repository', '.', '--tag-ref', 'refs/tags/'+TAG, '--expected-tag', TAG]
    assert result.returncode == (0 if defect == 'none' else 1)
    assert ('final_tag_identity=PASS' in result.stdout) == (defect == 'none')


def test_frozen_release_wait_uses_bounded_retry_then_seals_exact_metadata(tmp_path):
    harness=WorkflowHarness(tmp_path)
    result,observed=harness.run(WAIT,missing_before=2)
    assert result.returncode==0, result.stderr[-1600:]
    assert observed['gh_calls']==3 and observed['sleeps']==[10,10]
    assert harness.env['FROZEN_RELEASE_ID']=='7'
    assert harness.env['FROZEN_ZIP_ASSET_ID']=='10'
    assert harness.env['FROZEN_CHECKSUM_ASSET_ID']=='11'
    assert harness.env['FROZEN_RELEASE_TARGET']==COMMIT
    assert (tmp_path/'container-audit-frozen-release-metadata.json').is_file()


@pytest.mark.parametrize('defect', ['api','draft','prerelease','immutable','tag','title','target','body_status',
                                   'body_hash','extra_asset','zip_digest','zip_size'])
def test_frozen_release_wait_rejects_wrong_identity_status_or_asset_metadata(tmp_path,defect):
    harness=WorkflowHarness(tmp_path)
    changed=deepcopy(harness.release)
    if defect in ['draft','prerelease','immutable']:changed[defect]=not changed[defect]
    elif defect=='tag':changed['tag_name']='wrong-tag'
    elif defect=='title':changed['name']='wrong-title'
    elif defect=='target':changed['target_commitish']='wrong-commit'
    elif defect=='body_status':changed['body']=changed['body'].replace('QUARANTINED_PENDING_FACTORY_QUALIFICATION','READY')
    elif defect=='body_hash':changed['body']=changed['body'].replace('Artifact-SHA256: ','Artifact-SHA256: invalid')
    elif defect=='extra_asset':changed['assets'].append(deepcopy(changed['assets'][0]))
    elif defect=='zip_digest':changed['assets'][0]['digest']='sha256:'+'a'*64
    elif defect=='zip_size':changed['assets'][0]['size']+=1
    result,observed=harness.run(WAIT,release=changed,missing_before=1000 if defect=='api' else 0)
    assert result.returncode==1
    assert 'not finalized within 1800 seconds' in observed['error']
    assert observed['gh_calls']==180 and observed['sleeps']==[10]*179
    assert not (tmp_path/'container-audit-frozen-release-metadata.json').exists()


@pytest.mark.parametrize('defect', ['none','tag_object','tag_peel','main','title','body','asset_id','asset_digest'])
def test_final_release_revalidation_detects_remote_or_snapshot_changes(tmp_path,defect):
    harness=WorkflowHarness(tmp_path)
    result,_=harness.run(WAIT)
    assert result.returncode==0, result.stderr[-1600:]
    changed=deepcopy(harness.release)
    overrides={}
    if defect=='tag_object':overrides['ref_sha']='b'*40
    elif defect=='tag_peel':overrides['peel']='b'*40
    elif defect=='main':overrides['main_commit']='b'*40
    elif defect=='title':changed['name']='wrong title'
    elif defect=='body':changed['body']+='\n'
    elif defect=='asset_id':changed['assets'][0]['id']+=1
    elif defect=='asset_digest':changed['assets'][0]['digest']='sha256:'+'b'*64
    result,observed=harness.run(FINAL,release=changed,**overrides)
    assert result.returncode==(0 if defect=='none' else 1), result.stderr[-1600:]
    if defect=='none':assert 'final_remote_revalidation=PASS' in result.stdout
    else:assert 'BLOCKED:' in observed['error']


@pytest.mark.parametrize('corrupt',[False,True])
def test_download_step_binds_actual_file_bytes_to_sealed_metadata(tmp_path,corrupt):
    harness=WorkflowHarness(tmp_path)
    result,_=harness.run(WAIT)
    assert result.returncode==0, result.stderr[-1600:]
    result,observed=harness.run('Download exact frozen assets read-only',corrupt_download=corrupt)
    assert result.returncode==(1 if corrupt else 0),result.stderr[-1600:]
    if corrupt:assert 'downloaded bytes differ' in observed['error']
    else:assert len(list((tmp_path/'container-audit-frozen-release').iterdir()))==2


def test_verifier_step_passes_every_independent_identity_binding(tmp_path):
    root=Path(__file__).resolve().parents[1]
    lock=json.loads((root/'contract.lock.json').read_text(encoding='utf-8'))
    bundle_digest=(root/'kmtech_factory_contracts/bundle/v1/bundle.sha256').read_text(encoding='ascii').strip()
    assert lock['contract_bundle_sha256']==CONTRACT_SHA
    assert bundle_digest==CONTRACT_SHA
    harness=WorkflowHarness(tmp_path)
    result,_=harness.run(WAIT)
    assert result.returncode==0, result.stderr[-1600:]
    result,_=harness.run('Download exact frozen assets read-only')
    assert result.returncode==0, result.stderr[-1600:]
    result,observed=harness.run('Verify immutable release self-consistency and embedded identities')
    assert result.returncode==0, result.stderr[-1600:]
    args=observed['python_arguments']
    assert args[0]=='tools/verify_frozen_release_artifact.py'
    values=dict(zip(args[1::2],args[2::2]))
    assert values['--expected-tag']==TAG and values['--expected-tag-object']==TAG_OBJECT
    assert values['--expected-commit']==COMMIT and values['--expected-tree']==TREE
    assert values['--expected-contract-sha256']==CONTRACT_SHA
    assert values['--expected-zip-sha256']==harness.release['assets'][0]['digest'][7:]
    assert int(values['--expected-zip-size'])==harness.release['assets'][0]['size']
    assert values['--expected-main-exe-sha256']=='4'*64
    assert 'NOT TESTED on hosted runner' in (tmp_path/'summary.md').read_text(encoding='utf-8-sig')


@pytest.mark.parametrize('state',['query_failed','missing','failed','running','multiple','wrong_commit'])
def test_hosted_ci_observation_records_actual_status_without_gating(tmp_path,state):
    harness=WorkflowHarness(tmp_path)
    runs=[]
    if state not in ['query_failed','missing']:
        runs=[{'id':30,'run_attempt':2,'head_sha':COMMIT,'head_branch':'main','event':'push',
               'status':'in_progress' if state=='running' else 'completed','conclusion':'failure'}]
        if state=='multiple':runs.append(dict(runs[0],id=31,run_attempt=1,conclusion='success'))
        if state=='wrong_commit':runs[0]['head_sha']='a'*40
    result,observed=harness.run('Record hosted CI status without release gating',workflow_runs=runs,
                                missing_before=1 if state=='query_failed' else 0)
    assert result.returncode==0, result.stderr[-1600:]
    assert observed['gh_calls']==1
    assert 'status=completed' not in observed['gh_arguments'][0]
    assert 'head_sha='+COMMIT in observed['gh_arguments'][0]
    summary=(tmp_path/'summary.md').read_text(encoding='utf-8-sig')
    assert 'WAIVED_NOT_TESTED' in summary
    if state=='query_failed':assert 'UNPROVEN_QUERY_FAILED' in summary
    elif state in ['missing','wrong_commit']:assert 'NOT_FOUND' in summary
    else:
        assert 'id=30,attempt=2' in summary and 'conclusion=failure' in summary
        if state=='running':assert 'status=in_progress' in summary
        if state=='multiple':assert 'id=31,attempt=1' in summary
