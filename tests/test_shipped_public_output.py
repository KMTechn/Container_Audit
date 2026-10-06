"""Field support output must not publish arbitrary diagnostic text."""
import json
from pathlib import Path

import pytest

MARKER = 'UNTRUSTED_DIAGNOSTIC_393'


def _assert_absent(value):
    # Do not let pytest reproduce a failing diagnostic or environment value.
    if MARKER in json.dumps(value, ensure_ascii=True):
        pytest.fail('Untrusted diagnostic reached public output', pytrace=False)


def test_profile_check_failure_has_no_exception_sentence(monkeypatch, capsys):
    from tools import check_logistics_runtime_profile as tool

    def fail(*args, **kwargs):
        raise ValueError(MARKER)

    monkeypatch.setattr(tool, 'resolve_logistics_profile_path', fail)
    assert tool.main(['--profile-path', 'isolated-profile.json']) == 2
    captured = capsys.readouterr()
    _assert_absent(captured.out + captured.err)


def test_relay_operator_report_has_no_free_text(tmp_path, capsys):
    from tools import direct_sync_relay_operator as tool
    report = tmp_path / 'operator-report.json'
    assert tool._emit({'status': 'FAIL', 'operation': 'pause',
                       'error_code': 'invalid_operator_input',
                       'error_message': MARKER}, str(report)) == 1
    _assert_absent(json.loads(report.read_bytes()))
    captured = capsys.readouterr()
    _assert_absent(captured.out + captured.err)


def test_hosted_relay_diagnostics_drop_untrusted_worker_id(tmp_path, monkeypatch, capsys):
    import container_audit_product_host as host
    records = []
    monkeypatch.setattr(host, '_write_json_atomic', lambda path, payload: records.append(payload))
    monkeypatch.setattr(host, '_append_jsonl', lambda path, payload: records.append(payload))
    host._record_hosted_relay_failure([
        '--worker-id', MARKER, '--runtime-status-path', str(tmp_path / 'status.json'),
        '--log-path', str(tmp_path / 'log.jsonl'),
    ], RuntimeError(MARKER))
    assert records
    # User instruction: identity/status metadata retains its original bytes.
    assert records[0]['worker_id'] == MARKER
    assert records[0]['status'] == 'runtime_error'
    _assert_absent(records[0]['error_message'])
    _assert_absent(records[1:])
    captured = capsys.readouterr()
    _assert_absent(captured.out + captured.err)


def test_bootstrap_diagnostic_report_has_no_child_output(tmp_path, monkeypatch):
    import direct_sync_auto_bootstrap as bootstrap
    import user_relay
    monkeypatch.setattr(bootstrap, 'run_session_direct_sync_once',
                        lambda **kwargs: {'status': 'FAIL', 'stdout': MARKER, 'stderr': MARKER})
    monkeypatch.setattr(user_relay, 'ensure_user_relay_running',
                        lambda *args: {'status': 'UNKNOWN'})
    bootstrap.run_direct_sync_auto_bootstrap(
        app_root=tmp_path, direct_sync_root=tmp_path, scan_source_dir=tmp_path)
    _assert_absent(json.loads((tmp_path / 'status/container_audit_direct_sync_auto_bootstrap.json').read_bytes()))


def test_archive_check_failure_has_no_exception_sentence(tmp_path, monkeypatch, capsys):
    from tools import check_update_archive as tool

    def fail(*args, **kwargs):
        raise ValueError(MARKER)

    monkeypatch.setattr(tool, 'safe_extract_update_zip', fail)
    assert tool.main(['--zip-path', str(tmp_path / 'package.zip'),
                      '--destination', str(tmp_path / 'destination'),
                      '--package-root', str(tmp_path / 'package')]) == 1
    captured = capsys.readouterr()
    _assert_absent(captured.out + captured.err)


@pytest.mark.parametrize('module_name,valid_args', [
    ('tools.check_logistics_runtime_profile', []),
    ('tools.check_update_archive', ['--zip-path', 'a', '--destination', 'b', '--package-root', 'c']),
    ('tools.direct_sync_relay_operator', ['status', '--db-path', 'a']),
])
def test_support_argument_errors_do_not_echo_input(module_name, valid_args, capsys):
    import importlib
    module = importlib.import_module(module_name)
    with pytest.raises(SystemExit) as raised:
        module.main(valid_args + ['--' + MARKER])
    assert raised.value.code == 2
    captured = capsys.readouterr()
    _assert_absent(captured.out + captured.err)
def test_upload_status_preserves_exact_receipt_and_metadata_for_resume(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    import direct_sync_push as push

    receipt = {'server_source_file_id': 123, 'error_message': 'original protocol value'}
    metadata = {'producer_manifest_ref': 'unchanged', 'error_message': 'original metadata'}
    source = tmp_path / 'source.csv'
    payload = {'success': True, 'committed': True, 'retryable': False,
               'receipt': receipt, 'metadata': metadata,
               'source_file_path': str(source), 'error_message': 'untrusted diagnostic'}
    path = tmp_path / 'upload.json'
    push._write_json_atomic(path, payload)
    stored = json.loads(path.read_bytes())
    assert stored.keys() == payload.keys()
    assert stored['receipt'] == receipt and stored['metadata'] == metadata
    assert stored['error_message'] == 'SUPPORT_FAILURE'
    monkeypatch.setattr(push, '_terminal_safe_metadata_matches_status_artifact',
                        lambda original, artifact: original == artifact)
    plan = SimpleNamespace(source_file_path=source, metadata=metadata)
    assert push._upload_status_artifact_matches_relay(status_path=str(path), plan=plan, receipt=receipt)
def test_mixed_report_serialization_keeps_authenticated_container_values(tmp_path):
    import json
    import direct_sync_auto_bootstrap as bootstrap
    from tools import direct_sync_relay_install_pack as installer
    from tools import direct_sync_relay_operator as operator

    payload={'status':'RUNNING','credential':{'epoch':3,'error_message':'authenticated-field'},
             'profile':{'blocked_reason':'authenticated-field'},
             'receipt':{'error_message':'authenticated-field'},
             'identity':{'producer':'computed-identity'}, 'credential_ref':'original-reference',
             'error_message':'untrusted diagnostic'}
    for name,writer in (('bootstrap',bootstrap._write_json),):
        path=tmp_path/(name+'.json')
        writer(path,payload)
        persisted=json.loads(path.read_bytes())
        assert persisted.keys()==payload.keys()
        for field in ('credential','profile','receipt','identity','credential_ref','status'):
            assert persisted[field]==payload[field]
    assert persisted['error_message']=='SUPPORT_FAILURE'
    # e91a427: install-pack plans are public diagnostics, unlike authenticated
    # bootstrap/operator records. Keep their machine fields and mask credentials.
    plan_path = tmp_path / "installer-plan.json"
    # The original credential leaf is also in non-secret receipt/profile fields;
    # use a unique existing secret marker to prove absence from the whole plan.
    plan_payload = {**payload, "credential": {**payload["credential"], "error_message": MARKER}}
    installer._write_json(plan_path, plan_payload)
    plan_bytes = plan_path.read_bytes()
    plan = json.loads(plan_bytes)
    assert plan.keys() == payload.keys()
    for field in ("profile", "receipt", "identity", "status"):
        assert plan[field] == payload[field]
    assert plan["credential"] == "[REDACTED:field]"
    assert plan["credential_ref"] == "[REDACTED:field]"
    assert plan["error_message"] == "SUPPORT_FAILURE"
    assert MARKER.encode() not in plan_bytes
    assert payload["credential_ref"].encode() not in plan_bytes
    operator._emit(payload,str(tmp_path/'operator.json'))
    persisted=json.loads((tmp_path/'operator.json').read_bytes())
    for field in ('credential','profile','receipt','identity','credential_ref','status'):
        assert persisted[field]==payload[field]


def test_mixed_diagnostic_fields_keep_keys_types_and_drop_nested_input():
    from auto_update import mixed_status_record

    value = {'nested': {'admin_pin': {'parts': [MARKER, 7, True]},
                        'message': MARKER},
             'credential': {'message': MARKER}, 'queue': {'count': 7}}
    actual = mixed_status_record(value)
    assert actual == {'nested': {'admin_pin': {'parts': ['SUPPORT_FAILURE', 7, True]},
                                 'message': 'SUPPORT_FAILURE'},
                      'credential': value['credential'], 'queue': value['queue']}


@pytest.mark.parametrize('module_name', ('direct_sync_auto_bootstrap',
                                      'tools.direct_sync_relay_install_pack'))
def test_known_environment_value_in_authentication_is_rejected_before_write(tmp_path, monkeypatch, module_name):
    import importlib
    import os

    module = importlib.import_module(module_name)
    monkeypatch.setattr(os, 'environ', {'CUSTOM_SERVICE_SECRET': MARKER})
    destination = tmp_path / 'report.json'
    before = {str(path.relative_to(tmp_path)): path.is_dir() for path in tmp_path.rglob('*')}
    if module_name == "tools.direct_sync_relay_install_pack":
        # e91a427 projects the public plan before opening the atomic output.
        # No environment secret may reach its bytes, nor a leftover temp file.
        import json
        module._write_json.__wrapped__(destination, {"credential": {"value": MARKER}})
        assert json.loads(destination.read_bytes()) == {"credential": "[REDACTED:field]"}
        assert MARKER.encode() not in destination.read_bytes()
        after = {str(path.relative_to(tmp_path)): path.is_dir() for path in tmp_path.rglob("*")}
        assert after == {**before, str(destination.relative_to(tmp_path)): False}
        return
    with pytest.raises(ValueError, match='MACHINE_METADATA_SECRET_DETECTED'):
        module._write_json.__wrapped__(destination, {'credential': {'value': MARKER}})
    assert {str(path.relative_to(tmp_path)): path.is_dir() for path in tmp_path.rglob('*')} == before
