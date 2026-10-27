"""Actual CA stock/control observations with injected integrity/task OS seams."""
import json
from pathlib import Path

import pytest
import auto_update as update
import current_user_onboarding as onboarding
from tests.test_auto_update import OLD, NEW


@pytest.fixture
def installed(tmp_path, monkeypatch):
    root=tmp_path/'managed'
    for bundle, sha in [('current', OLD), ('versions/'+OLD, OLD), ('versions/'+NEW, NEW)]:
        code=root/bundle; (code/'app').mkdir(parents=True)
        (code/'portable-manifest.json').write_text(json.dumps(dict(schema='container-audit-portable-tree-v1',source_commit=sha)))
        (code/'app/update-manifest-key-config.json').write_bytes(b'unchanged installed trust key')
    control=root/'update-control'; control.mkdir()
    for name, payload in [('policy', dict(schema='container-audit-startup-update-policy-v1',operator_sid='S-1-5-21-1-2-3-1001')),
                          ('active', dict(schema=update.SCHEMA, sha=NEW)),
                          ('transition', dict(schema=update.SCHEMA,phase='CONFIRMED',candidate_sha=NEW,failed_shas=['3'*40]))]:
        (control/(name+'.json')).write_text(json.dumps(payload))
    monkeypatch.setattr(update,'verify_lifecycle_stock',lambda bundle:dict(status='PASS'))
    monkeypatch.setattr(update,'supported_task_present',lambda *args:True)
    return root


def test_owner_a_active_b_and_actual_b_from_are_independent(installed):
    result=update.resolve_lifecycle_context(installed,operation='install',expected_from_commit=NEW)
    assert result['bootstrap_commit']==OLD and result['from_commit']==NEW
    assert Path(result['owner_app_root'])==installed/'current/app'
    assert Path(result['active_app_root'])==installed/'versions'/NEW/'app'
    with pytest.raises(ValueError) as failure: update.resolve_lifecycle_context(installed,expected_from_commit=OLD)
    assert 'from_commit_mismatch' in str(failure.value.__cause__)


@pytest.mark.parametrize('phase',['PREPARED','APPLIED_PENDING_READY','ROLLBACK_PENDING','ROLLBACK_PENDING_READY','UNKNOWN','FAILED'])
@pytest.mark.parametrize('operation',['install','register'])
def test_unstable_control_refuses_before_any_write(installed,phase,operation):
    """Manual classification has no accepted startup proof, even for register."""
    state=installed/'update-control/transition.json'; state.write_text(json.dumps(dict(schema=update.SCHEMA,phase=phase)))
    originals={p:p.read_bytes() for p in installed.rglob('*') if p.is_file()}
    with pytest.raises(ValueError,match='지원 제거'):update.resolve_lifecycle_context(installed,operation=operation)
    assert all(p.read_bytes()==raw for p,raw in originals.items())


@pytest.mark.parametrize('operation',['uninstall','user_remove'])
@pytest.mark.parametrize('damaged',['policy','active','transition','all'])
def test_removal_scope_never_parses_damaged_machine_control(installed,operation,damaged):
    for name in ['policy','active','transition'] if damaged=='all' else [damaged]:
        (installed/'update-control'/f'{name}.json').write_bytes(b'{broken')
    result=update.resolve_lifecycle_context(installed,operation=operation)
    assert result['lifecycle_state']=='REMOVAL_READY' and result['from_commit'] is None


def test_missing_task_and_missing_active_code_are_not_healthy(installed,monkeypatch):
    monkeypatch.setattr(update,'supported_task_present',lambda *args:False)
    with pytest.raises(ValueError,match='지원 제거'):update.resolve_lifecycle_context(installed)
    monkeypatch.setattr(update,'supported_task_present',lambda *args:True)
    (installed/'versions'/NEW/'portable-manifest.json').unlink()
    with pytest.raises(ValueError,match='지원 제거'):update.resolve_lifecycle_context(installed)


def test_owner_a_active_a_remains_existing_supported_path(installed):
    state=installed/'update-control/transition.json'; state.write_text(json.dumps(dict(schema=update.SCHEMA,phase='DEFERRED')))
    pointer=installed/'update-control/active.json'; pointer.write_text(json.dumps(dict(schema=update.SCHEMA,sha=OLD)))
    result=update.resolve_lifecycle_context(installed,operation='install')
    assert result['bootstrap_commit']==result['from_commit']==OLD


def test_first_install_ignores_retained_foreign_version_material(tmp_path, monkeypatch):
    monkeypatch.setattr(update,'supported_tasks_absent',lambda root, **kwargs:True)
    root=tmp_path/'removed'; (root/'versions/foreign').mkdir(parents=True)
    original=root/'versions/foreign/data.bin';original.write_bytes(b'quantity and membership')
    assert update.resolve_lifecycle_context(root,operation='install')['lifecycle_state']=='REMOVED'
    assert original.read_bytes()==b'quantity and membership'


def test_absent_current_with_live_or_unknown_task_is_not_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(update,'supported_tasks_absent',lambda root, **kwargs:False)
    with pytest.raises(ValueError,match='지원 제거'):
        update.resolve_lifecycle_context(tmp_path/'removed',operation='install')


def test_reserved_namespace_collision_rejects_before_mutation(tmp_path):
    root=tmp_path/'managed';root.mkdir();(root/'versions').write_bytes(b'preserved foreign material')
    with pytest.raises(ValueError,match='지원 제거'):
        update.resolve_lifecycle_context(root,operation='install')
    assert (root/'versions').read_bytes()==b'preserved foreign material'


def test_failure_chain_keeps_native_error_but_masks_nested_credentials():
    inner=OSError(5,'native permission failure'); outer=RuntimeError('Authorization: Bearer synthetic-test-value\n{"credential":{"password":"test-only"}}')
    outer.__cause__=inner
    detail=update._failure_details(outer)
    serialized=json.dumps(detail)
    assert 'synthetic-test-value' not in serialized and 'test-only' not in serialized
    assert detail[1]['errno']==5 and detail[1]['message']=='[Errno 5] native permission failure'
