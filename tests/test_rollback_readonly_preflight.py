"""Real pending continuation, exact target G, and native PS5/PS7 transports."""
import json
from pathlib import Path
import re
import shutil
import uuid

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_canonical_rollback_resume import _fixture, _produce_pending
from tests.test_canonical_portable_uninstall import _launch_relay, _live_preimage, _sha, _tree


READ_OBSERVATION = r'''
    mode=os.environ.get('CA_RESUME_PREFLIGHT_CASE','match')
    reads={'locator':0,'nested':0}
    import direct_sync_runtime as credentials
    from tools.register_container_audit_worker_pc import _current_user_sid
    original_payload=credentials._read_credential_payload
    nested=root/'external-preflight/payload.json'
    def advance(owner):
        marker=owner/'data-generation.json'
        marker.write_text(json.dumps({'schema':'kmtech-data-generation-v2','app_id':'container_audit',
            'subject_sid':_current_user_sid(),'version':'v2.0.1000','data_compatible_min_version':'v2.0.1000',
            'build_id':'c'*40,'compatibility_verified':False}),encoding='utf-8')
    def payload(path):
        reads['locator']+=1
        value=original_payload(path)
        if mode=='nested_advance':
            value=dict(value,isolated_qualification_context_path=str(nested))
            advance(nested.parent)
        return value
    credentials._read_credential_payload=payload
    original_prepare=onboarding._prepare_onboarding_inputs
    def prepare(paths,*args,**kwargs):
        if mode=='locator_advance': advance(paths.credential_path.parent)
        return original_prepare(paths,*args,**kwargs)
    onboarding._prepare_onboarding_inputs=prepare
    import builtins
    original_open=builtins.open
    def observe_open(path,*args,**kwargs):
        if isinstance(path,(str,bytes,Path)) and Path(path)==nested: reads['nested']+=1
        return original_open(path,*args,**kwargs)
    builtins.open=observe_open
    original_main=onboarding.onboarding_main
    def observed_main(*args,**kwargs):
        try:return original_main(*args,**kwargs)
        finally:(root/'preflight-read-observation.json').write_text(json.dumps(reads),encoding='utf-8')
    onboarding.onboarding_main=observed_main
'''


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_exact_pending_preflight_is_readonly_and_rechecks_each_owner(tmp_path, engine):
    env, source, install, _, _ = _fixture(tmp_path)
    with _launch_relay(tmp_path, env) as child:
        _live_preimage(tmp_path, env, source, install, child)
        journal, record = _produce_pending(tmp_path, env, source, install, engine)
    fence = Path(env['CA_UNINSTALL_CONTROL']) / 'active.json'
    original_journal, original_fence = journal.read_bytes(), fence.read_bytes()
    target = json.loads(Path(record['receipt_path']).read_text(encoding='utf-8-sig'))['rollback_root']
    host = Path(env['CA_UNINSTALL_HOST'])
    text = host.read_text(encoding='utf-8')
    anchor = "elif sys.argv[1] == 'preflight':"
    assert text.count(anchor) == 1
    host.write_text(text.replace(anchor, anchor + '\n' + READ_OBSERVATION), encoding='utf-8')
    nested = tmp_path / 'external-preflight/payload.json'
    nested.parent.mkdir()
    nested.write_text('{}', encoding='utf-8')
    observation = tmp_path / 'preflight-read-observation.json'
    generation_preimage = {path: path.read_bytes() for path in tmp_path.rglob('data-generation.json')}
    synthetic = uuid.uuid4().hex + uuid.uuid4().hex
    env['CUSTOM_PREFLIGHT_SECRET'] = synthetic
    for case in ('match', 'tuple_mismatch', 'unrelated', 'locator_advance', 'nested_advance'):
        journal.write_bytes(original_journal)
        fence.write_bytes(original_fence)
        for marker in tmp_path.rglob('data-generation.json'):
            data=json.loads(marker.read_text(encoding='utf-8-sig'))
            if data.get('version') == 'v2.0.1000':
                if marker in generation_preimage: marker.write_bytes(generation_preimage[marker])
                else: marker.unlink()
        if observation.exists(): observation.unlink()
        env['CA_RESUME_PREFLIGHT_CASE'] = case
        if case == 'tuple_mismatch':
            value=json.loads(original_journal)
            value['session_id']=uuid.uuid4().hex
            journal.write_text(json.dumps(value), encoding='utf-8')
        elif case == 'unrelated':
            value=json.loads(original_fence)
            value['owner_kind']='session_adapter'
            fence.write_text(json.dumps(value), encoding='utf-8')
        before=_tree(tmp_path)
        def literal(value): return "'" + str(value).replace("'", "''") + "'"
        args=[env['CA_UNINSTALL_PYTHON'],'-I','-B',env['CA_UNINSTALL_PREFLIGHT'],
              '--onboard-current-user','--app-root',str(source/'app'),'--preflight-only',
              '--target-release-root',target,'--rollback-preflight-journal-path',str(journal),
              '--rollback-preflight-journal-sha256',_sha(journal),
              '--rollback-preflight-fence-sha256',_sha(fence)]
        command="[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);& " + ' '.join(map(literal,args)) + ';exit $LASTEXITCODE'
        result=run_powershell([shutil.which(engine),'-NoLogo','-NoProfile','-NonInteractive','-Command',command],
            env=env,capture_output=True,text=True,check=False,timeout=45)
        assert synthetic not in result.stdout + result.stderr
        reads=json.loads(observation.read_text())
        if case == 'match':
            assert result.returncode == 0 and re.fullmatch('onboarding_input_binding=[0-9a-f]{64}:[0-9a-f]{64}\\s*',result.stdout)
        else:
            assert result.returncode != 0
            if case in ('tuple_mismatch','unrelated'):
                diagnostic=json.loads(next(line.split('=',1)[1] for line in result.stdout.splitlines()
                    if line.startswith('onboarding_preflight_error=')))
                assert diagnostic['original_error_type'] == 'WriterFencedError'
                assert diagnostic['reason_code'] == 'ACTIVE_WRITER_FENCE'
            if case != 'nested_advance': assert reads['locator'] == 0
            assert reads['nested'] == 0
        after=_tree(tmp_path)
        after.pop(str(observation.relative_to(tmp_path)))
        # External generation publication is the injected competing event;
        # every product file, Run/task double and exact fence stays unchanged.
        for marker in tmp_path.rglob('data-generation.json'):
            if json.loads(marker.read_text()).get('version') == 'v2.0.1000':
                relative = str(marker.relative_to(tmp_path))
                after.pop(relative)
                before.pop(relative, None)
        assert after == before
