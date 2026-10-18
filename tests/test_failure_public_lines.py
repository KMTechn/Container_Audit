"""Public installer diagnostics contain codes; private reports retain causes."""
import hashlib
import json
from pathlib import Path
import re
import secrets

import pytest

import current_user_onboarding as onboarding
from tests.powershell_contracts import run_functions

PREFIX = 'CONTAINER_AUDIT_INSTALLER_FAILURE='
MODES = ('onboarding', 'preflight', 'removal', 'restore')


def _cli(monkeypatch, tmp_path, mode, operation):
    arguments = ['--app-root', str(tmp_path / 'app')]
    if mode in ('onboarding', 'preflight'):
        target = 'preflight_current_user_onboarding' if mode == 'preflight' else 'onboard_current_user'
        monkeypatch.setattr(onboarding, target, operation)
        if mode == 'preflight': arguments.append('--preflight-only')
        return lambda: onboarding.onboarding_main(arguments)
    if mode == 'removal':
        monkeypatch.setattr(onboarding, 'remove_current_user_setup', operation)
        return lambda: onboarding.removal_main(arguments)
    monkeypatch.setattr(onboarding, 'restore_current_user_lifecycle_after_replacement', operation)
    arguments += ['--code-root', str(tmp_path / 'code'), '--replacement-transaction-id', 'synthetic',
                  '--replacement-receipt-path', str(tmp_path / 'receipt.json'),
                  '--replacement-receipt-sha256', 'a' * 64, '--writer-contract-sha256', 'b' * 64,
                  '--session-id', 'synthetic', '--attempt-id', 'synthetic',
                  '--session-started-at-utc', '2026-10-06T00:00:00Z', '--orchestrator-sha256', 'c' * 64]
    return lambda: onboarding.replacement_lifecycle_restore_main(arguments)


def _invoke(cli, capsys, *, expected_exit=onboarding.ONBOARDING_EXIT_CODE):
    unhandled = False
    try:
        result = cli()
    except Exception:
        unhandled = True
        result = None
    streams = capsys.readouterr()
    raw = streams.out + streams.err
    if unhandled:
        pytest.fail('Uncaught installer exception count=1', pytrace=False)
    if result != expected_exit:
        pytest.fail('Installer failure exit code differed', pytrace=False)
    return raw


def _public(raw, private, *, expected_reason='INSTALLER_CHILD_FAILURE', expected_guidance=None):
    hits = raw.count(private)
    lines = raw.splitlines()
    if hits or len(lines) != 1 or not lines[0].startswith(PREFIX):
        pytest.fail(f'Public diagnostic: original-count={hits}, line-count={len(lines)}, framed-count={raw.count(PREFIX)}', pytrace=False)
    try:
        payload = json.loads(lines[0][len(PREFIX):])
    except ValueError:
        pytest.fail('Public diagnostic JSON count=0', pytrace=False)
    approved = {'status', 'stage', 'reason_code', 'exception_type', 'location_module',
                'location_function', 'location_line', 'exit_code', 'attempt_id',
                'report_path', 'report_sha256', 'report_status', 'guidance'}
    if set(payload) - approved or any(isinstance(v, (dict, list)) for v in payload.values()):
        pytest.fail('Public diagnostic contains a non-flat or free-text field', pytrace=False)
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,127}', payload['exception_type']):
        pytest.fail('Public exception format name differs', pytrace=False)
    if payload['status'] != 'FAILED' or payload['reason_code'] != expected_reason:
        pytest.fail('Public failure code differs', pytrace=False)
    if expected_guidance is None:
        expected_guidance = '자료를 보존하고 관리자 지원 복구를 요청하세요.'
    if payload.get('guidance') != expected_guidance:
        pytest.fail('Public fixed guidance differs', pytrace=False)
    return payload


@pytest.mark.parametrize('mode', ('onboarding', 'preflight', 'removal', 'replacement'))
@pytest.mark.parametrize('code', ('ACTIVE_WRITER_FENCE', 'FENCE_BINDING_INVALID'))
def test_writer_refusal_preserves_exit_and_cause_in_public_record(tmp_path, monkeypatch, capsys, mode, code):
    from writer_session_fence import WriterFenceError
    private = secrets.token_hex(20)

    def operation(*args, **kwargs):
        raise WriterFenceError(code, private)

    record = _public(_invoke(_cli(monkeypatch, tmp_path, mode, operation), capsys, expected_exit=23),
                     private, expected_reason=code)
    if record['exit_code'] != 23 or record.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Writer refusal public exit/report contract differs', pytrace=False)


def test_unregistered_writer_code_remains_private_with_original_exit(tmp_path, monkeypatch, capsys):
    from writer_session_fence import WriterFenceError
    private = secrets.token_hex(20)

    def operation(*args, **kwargs):
        raise WriterFenceError(private, private)

    record = _public(_invoke(_cli(monkeypatch, tmp_path, 'preflight', operation), capsys, expected_exit=23),
                     private, expected_reason='WRITER_FENCE_FAILED')
    if record['exit_code'] != 23:
        pytest.fail('Unknown writer refusal exit contract differs', pytrace=False)


@pytest.mark.parametrize('kind', ('refuse', 'unknown', 'wrapped_unknown'))
def test_generation_refusal_keeps_fixed_guidance_in_flat_record(tmp_path, monkeypatch, capsys, kind):
    from data_generation_guard import DataGenerationBlocked
    from kmtech_shared import data_generation as generation
    private = secrets.token_hex(20)
    unknown = kind != 'refuse'
    guidance = generation.UNKNOWN_MESSAGE if unknown else generation.REFUSAL_MESSAGE
    def operation(*args, **kwargs):
        try:
            if kind == 'wrapped_unknown':
                raise ValueError(private)
            raise DataGenerationBlocked({'status': 'UNKNOWN' if unknown else 'REFUSE'})
        except Exception as cause:
            raise onboarding.CurrentUserOnboardingError(guidance, report_path=tmp_path / 'unpublished.json', reason_code="DATA_GENERATION_UNKNOWN" if unknown else "DATA_GENERATION_REFUSED") from cause
    record = _public(_invoke(_cli(monkeypatch, tmp_path, 'onboarding', operation), capsys), private,
                     expected_reason='DATA_GENERATION_UNKNOWN' if unknown else 'DATA_GENERATION_REFUSED',
                     expected_guidance=guidance)
    if 'report_path' in record or record.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Unpublished generation refusal report reference count=1', pytrace=False)


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('kind', ('typed', 'unexpected'))
def test_cli_failure_emits_only_allowlisted_structure(tmp_path, monkeypatch, capsys, mode, kind):
    private = secrets.token_hex(20)
    def operation(*args, **kwargs):
        message = 'PRIVATE-CONTEXT-' + private + ' C:/private/' + private
        if kind == 'typed':
            error = onboarding.CurrentUserOnboardingError(message, report_path=tmp_path / 'old-report.json',
                                                          status='ARBITRARY-' + private)
            error.reason_code = 'ARBITRARY-' + private
            raise error
        raise ValueError(message)
    failure = _public(_invoke(_cli(monkeypatch, tmp_path, mode, operation), capsys), private)
    if 'report_path' in failure or failure.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Unpublished report reference count=1', pytrace=False)


def _published_failure(monkeypatch, tmp_path, capsys, *, reject=False, tamper=False):
    private = secrets.token_hex(20)
    monkeypatch.setenv('CONTAINER_RUNTIME_SECRET', private)
    path = tmp_path / 'protected' / 'current_user_onboarding.json'
    path.parent.mkdir()
    old = b'{"old":"report"}\n'
    path.write_bytes(old)
    if reject:
        monkeypatch.setattr(onboarding.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError('synthetic publication refusal')))
    saved = []
    def operation(*args, **kwargs):
        try:
            raise ValueError('FIRST-CAUSE ' + private + ' ' + '\uac00' * 50000 + '\nLAST-CAUSE')
        except ValueError as cause:
            onboarding._persist_failure_report(path, {'status': 'FAILED'}, cause)
            if tamper:
                path.write_bytes(old)
            failure = onboarding.CurrentUserOnboardingError('private wrapper ' + private, report_path=path)
            saved.append(failure)
            raise failure from cause
    failure = _public(_invoke(_cli(monkeypatch, tmp_path, 'onboarding', operation), capsys), private)
    return private, path, old, failure, saved


def test_report_reference_binds_current_atomic_utf8_publication(tmp_path, monkeypatch, capsys):
    private, path, _, failure, _ = _published_failure(monkeypatch, tmp_path, capsys)
    raw = path.read_bytes()
    # No reader ACL is proven at this caller-selected/current-user path.
    assert 'report_path' not in failure and 'report_sha256' not in failure
    assert failure['report_status'] == 'REPORT_UNAVAILABLE'
    report = json.loads(raw)
    assert report['failure'] == 'SUPPORT_FAILURE'
    assert report['failure_evidence_refs'] == []
    assert report['failure_evidence_status'] == 'REPORT_UNAVAILABLE'
    assert private not in raw.decode() and 'FIRST-CAUSE' not in raw.decode() and 'LAST-CAUSE' not in raw.decode()
    assert not list(path.parent.glob('failure-text-*.json'))


@pytest.mark.parametrize('stage', ('onboarding', 'current_user_removal'))
def test_saved_failure_retains_application_location_without_private_text(tmp_path, capsys, stage):
    path = tmp_path / 'failure.json'
    private = secrets.token_hex(20)
    try:
        onboarding._read_json(tmp_path / (private + '.json'), 'private ' + private)
    except ValueError as error:
        report = {'status': 'FAILED'}
        onboarding._persist_failure_report(path, report, error)
        onboarding.emit_installer_failure(error, stage)
    record = _public(capsys.readouterr().err, private)
    saved = json.loads(path.read_bytes())
    assert saved['exception_type'] == record['exception_type']
    assert saved['location_module'] == record['location_module'] == 'current_user_onboarding'
    assert saved['location_function'] == record['location_function'] == '_read_json'
    assert saved['location_line'] == record['location_line'] > 0
    assert private not in path.read_text(encoding='utf-8')


def test_unraised_cause_still_reports_application_failure_location(tmp_path, capsys):
    private = secrets.token_hex(20)
    try:
        raise onboarding.CurrentUserOnboardingError(private, report_path=tmp_path / 'report.json') from ValueError(private)
    except onboarding.CurrentUserOnboardingError as error:
        onboarding.emit_installer_failure(error, 'onboarding')
    record = _public(capsys.readouterr().err, private)
    assert record['location_module'] == __name__
    assert record['location_function'] == 'test_unraised_cause_still_reports_application_failure_location'
    assert record['location_line'] > 0


def test_json_decoder_failure_reports_innermost_application_frame(tmp_path, capsys):
    private = secrets.token_hex(20)
    path = tmp_path / 'bad.json'
    path.write_text('{"private":"' + private + '"', encoding='utf-8')
    try:
        onboarding._read_json(path, 'synthetic input')
    except ValueError as error:
        onboarding.emit_installer_failure(error, 'onboarding')
    record = _public(capsys.readouterr().err, private)
    assert record['exception_type'] == 'json.decoder.JSONDecodeError'
    assert record['location_module'] == 'direct_sync_push'
    assert record['location_function'] == 'load_json_no_duplicate_keys'
    assert record['location_line'] > 0


def test_failed_publication_has_no_reference_to_preexisting_report(tmp_path, monkeypatch, capsys):
    _, path, old, failure, _ = _published_failure(monkeypatch, tmp_path, capsys, reject=True)
    if 'report_path' in failure or failure.get('report_status') != 'REPORT_UNAVAILABLE' or path.read_bytes() != old:
        pytest.fail('Failed publication reused or modified old report', pytrace=False)


def test_report_changed_after_publication_is_not_referenced(tmp_path, monkeypatch, capsys):
    _, _, _, failure, _ = _published_failure(monkeypatch, tmp_path, capsys, tamper=True)
    if 'report_path' in failure or failure.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Changed protected report reference count=1', pytrace=False)


def test_second_cli_attempt_cannot_reuse_old_exception_report_reference(tmp_path, monkeypatch, capsys):
    private, _, _, first, saved = _published_failure(monkeypatch, tmp_path, capsys)
    assert 'report_path' not in first and first['report_status'] == 'REPORT_UNAVAILABLE'
    def reuse(*args, **kwargs):
        raise saved[0]
    second = _public(_invoke(_cli(monkeypatch, tmp_path, 'onboarding', reuse), capsys), private)
    if 'report_path' in second or second.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Second attempt reused previous report reference', pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('malformed', (False, True))
@pytest.mark.parametrize('stream', ('stdout', 'stderr'))
@pytest.mark.parametrize('reason', ('generic', 'refuse', 'unknown', 'writer'))
def test_native_installer_reader_consumes_safe_public_failure(tmp_path, engine, malformed, stream, reason):
    import sys
    root = tmp_path / 'bundle'
    (root / 'app').mkdir(parents=True)
    private = secrets.token_hex(20)
    record = {'status': 'FAILED', 'stage': 'onboarding_preflight',
              'reason_code': 'INSTALLER_CHILD_FAILURE', 'exception_type': 'ValueError',
              'exit_code': 4, 'report_status': 'REPORT_UNAVAILABLE'}
    if reason == 'writer':
        record.update(reason_code='ACTIVE_WRITER_FENCE', exit_code=23)
    elif reason != 'generic':
        from kmtech_shared import data_generation as generation
        record.update(reason_code='DATA_GENERATION_REFUSED' if reason == 'refuse' else 'DATA_GENERATION_UNKNOWN',
                      guidance=generation.REFUSAL_MESSAGE if reason == 'refuse' else generation.UNKNOWN_MESSAGE)
    if malformed:
        record['message'] = 'PRIVATE-CONTEXT-' + private
    (root / 'app' / 'failure.txt').write_text(PREFIX + json.dumps(record, separators=(',', ':')), encoding='utf-8')
    (root / 'app' / 'main.py').write_text(
        "from pathlib import Path\nimport sys\nprint(Path(__file__).with_name('failure.txt').read_text(encoding='utf-8'), file=sys."
        + stream + ")\nsys.exit(" + str(record["exit_code"]) + ")\n",
        encoding='utf-8')
    result = run_functions(tmp_path, Path(__file__).resolve().parents[1] / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Get-CanonicalOnboardingInputBinding'], r'''
function Join-Path([string]$Path,[string]$ChildPath){
    if($ChildPath -ceq 'runtime\python.exe'){return $env:CA_OWNED_PYTHON}
    return Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
}
try{Get-CanonicalOnboardingInputBinding $env:CA_OWNED_BUNDLE; 'UNEXPECTED_SUCCESS'}
catch{[Console]::WriteLine([string]$_.Exception.Message)}
''', engine=engine, values={'CA_OWNED_PYTHON': sys.executable, 'CA_OWNED_BUNDLE': str(root)})
    expected = 'PUBLIC_FIELD_NONCONFORMING' if malformed else 'ONBOARDING_PREFLIGHT_FAILED'
    if result.returncode or result.stdout.strip() != expected or private in result.stdout + result.stderr:
        pytest.fail('Native installer safe failure reader differs; original-count=' + str((result.stdout + result.stderr).count(private)), pytrace=False)


def test_portable_installer_entry_failure_uses_same_public_record(monkeypatch, capsys):
    import sys
    import auto_update
    from portable import main as portable
    private = secrets.token_hex(20)
    monkeypatch.setattr(sys, 'argv', ['main.py', '--onboard-current-user'])
    def rejected_gate(*args, **kwargs):
        raise ValueError('PRIVATE-ENTRY-' + private)
    monkeypatch.setattr(auto_update, 'startup_gate', rejected_gate)
    record = _public(_invoke(portable.main, capsys), private)
    if record.get('stage') != 'installer_entrypoint' or record.get('report_status') != 'REPORT_UNAVAILABLE':
        pytest.fail('Portable installer entry failure record differs', pytrace=False)


def test_failure_report_preserves_owner_metadata_fields(tmp_path):
    private = secrets.token_hex(20)
    report = {'status': 'FAILED',
              'owner_artifact_paths': {'credential': str(tmp_path / 'owner.json')},
              'owner_artifact_fingerprints_before': {'credential': 'a' * 64}}
    path = tmp_path / 'protected-failure.json'
    onboarding._persist_failure_report(path, report, RuntimeError('password=' + private))
    raw = path.read_bytes()
    stored = json.loads(raw)
    for field in ('owner_artifact_paths', 'owner_artifact_fingerprints_before'):
        if stored[field] != report[field]:
            pytest.fail('Failure publication changed owner metadata field names or bytes', pytrace=False)
    if private.encode() in raw:
        pytest.fail('Protected report original-count=' + str(raw.count(private.encode())), pytrace=False)
def test_packaged_dependency_trace_reports_the_application_caller(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding

    app_root = tmp_path / 'app'
    monkeypatch.setattr(onboarding, '__file__', str(app_root / 'current_user_onboarding.py'))
    dependency = {'__name__': 'packaged_dependency'}
    exec(compile('def fail():\n    raise ValueError("PRIVATE_DIAGNOSTIC")\n',
                 str(app_root / 'site-packages/dependency.py'), 'exec'), dependency)
    application = {'__name__': 'owned_application', 'dependency': dependency['fail']}
    exec(compile('def fail():\n    dependency()\n', str(app_root / 'owned_application.py'), 'exec'), application)
    try:
        application['fail']()
    except ValueError as error:
        fields = onboarding._failure_location(error)
    assert fields == {'exception_type': 'builtins.ValueError',
                      'location_module': 'owned_application',
                      'location_function': 'fail', 'location_line': 2}


def test_unregistered_multiline_onboarding_error_keeps_last_line(tmp_path):
    failure = onboarding.CurrentUserOnboardingError(
        "unregistered first line\nunregistered last line",
        report_path=tmp_path / "failure.json",
    )
    assert failure.args == ("unregistered last line",)
    assert str(failure) == "unregistered last line"


@pytest.mark.parametrize("kind", ("refused", "unknown", "unregistered"))
def test_codeless_onboarding_error_keeps_generic_public_guidance(tmp_path, capsys, kind):
    from kmtech_shared import data_generation as generation
    message = (generation.REFUSAL_MESSAGE if kind == "refused" else
               generation.UNKNOWN_MESSAGE if kind == "unknown" else
               "unregistered first line\nunregistered last line")
    failure = onboarding.CurrentUserOnboardingError(message, report_path=tmp_path / "failure.json")
    assert len(str(failure).splitlines()) == 1
    assert failure.reason_code == ""
    onboarding.emit_installer_failure(failure, "onboarding")
    streams = capsys.readouterr()
    _public(streams.out + streams.err, "not-present-private-fixture",
            expected_reason="INSTALLER_CHILD_FAILURE",
            expected_guidance=onboarding.INSTALLER_SAFE_MESSAGES[0])


@pytest.mark.parametrize("refused", (True, False))
def test_coded_generation_public_json_has_no_control_bytes(tmp_path, capsys, refused):
    from kmtech_shared import data_generation as generation
    reason = "DATA_GENERATION_REFUSED" if refused else "DATA_GENERATION_UNKNOWN"
    guidance = generation.REFUSAL_MESSAGE if refused else generation.UNKNOWN_MESSAGE
    failure = onboarding.CurrentUserOnboardingError(
        guidance, report_path=tmp_path / "failure.json", reason_code=reason,
    )
    assert len(str(failure).splitlines()) == 1
    onboarding.emit_installer_failure(failure, "onboarding")
    streams = capsys.readouterr()
    raw = streams.out + streams.err
    assert raw.endswith("\n")
    line = raw[:-1].encode("utf-8")
    assert line and all(0x20 <= byte <= 0x7F for byte in line)
    _public(raw, "not-present-private-fixture", expected_reason=reason, expected_guidance=guidance)


@pytest.mark.parametrize("source", ("user_relay.py", "tools/active_work_probe.py"))
@pytest.mark.parametrize("refused", (True, False))
def test_generation_plain_print_fragment_preserves_registered_message_bytes(capsys, source, refused):
    import ast
    from types import SimpleNamespace
    from kmtech_shared import data_generation as generation
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / source).read_bytes())
    prints = []
    for handler in ast.walk(tree):
        if (isinstance(handler, ast.ExceptHandler) and isinstance(handler.type, ast.Name)
                and handler.type.id == "DataGenerationBlocked"):
            prints.extend(statement for statement in handler.body
                          if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                          and isinstance(statement.value.func, ast.Name) and statement.value.func.id == "print")
    assert len(prints) == 1
    guidance = generation.REFUSAL_MESSAGE if refused else generation.UNKNOWN_MESSAGE
    exec(compile(ast.Module(body=prints, type_ignores=[]), source, "exec"),
         {"exc": SimpleNamespace(user_message=guidance)})
    streams = capsys.readouterr()
    raw = streams.out + streams.err
    assert raw.endswith("\n")
    assert raw.encode("utf-8") == (guidance + "\n").encode("utf-8")
