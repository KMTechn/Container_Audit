"""Diagnostic publication failure must preserve the actual onboarding result."""
import json
from pathlib import Path
import pytest
import current_user_onboarding as onboarding
from tests import test_current_user_onboarding as support
from tests.test_current_user_onboarding import _isolate_onboarding_control_root, existing_possession_key_contract
pytestmark = pytest.mark.usefixtures("existing_possession_key_contract")

@pytest.mark.parametrize('scene', ['late-marker', 'replacement-marker', 'json-number'])
def test_report_redaction_does_not_fail_actual_onboarding(tmp_path, monkeypatch, scene):
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    selected = ('KMTECH_TEST_API_TOKEN', 'REDACTED' if scene == 'replacement-marker' else 'KMTECH_TEST_SHORT' if scene == 'late-marker' else '4826')
    environment[selected[0]] = selected[1]
    if scene == 'late-marker':
        environment['KMTECH_TEST_SHORT_PASSWORD'] = 'x'
    pass
    calls = []
    def register(p):
        calls.append(p)
        support._ready_state(p)
        receipt = json.loads(p.registration_report_path.read_bytes())
        receipt['base_url'] = 'https://synthetic.invalid'
        p.registration_report_path.write_text(json.dumps(receipt), encoding='utf-8')
        return 0
    def autostart(*args, **kwargs):
        result = dict(support._autostart(*args, **kwargs))
        result['message'] = int(selected[1]) if scene == 'json-number' else selected[1]
        return result
    report = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=autostart,
        relay_launcher=support._relay_start)
    assert report['status'] == 'READY'
    persisted = json.loads(paths.onboarding_report_path.read_bytes())
    receipt = json.loads(paths.registration_report_path.read_bytes())
    assert persisted['status'] == 'READY'
    assert persisted['server_registration_verified'] is True
    assert receipt['server_registration_verified'] is True
    assert receipt['base_url'] == 'https://synthetic.invalid'
    raw = paths.onboarding_report_path.read_text(encoding='utf-8')
    assert selected[0] not in raw and selected[1] not in raw
    assert len(calls) == 1
    assert paths.ledger_path.is_file()
    from report_publication import failure_count, UNAVAILABLE
    assert failure_count(paths.onboarding_report_path) == 1
    counters = list(paths.status_dir.glob('.report-unavailable-count-*.json'))
    assert len(counters) == 1
    assert json.loads(counters[0].read_bytes()) == {'count': 1}
    assert persisted['relay_autostart']['message'] == UNAVAILABLE


def test_original_registration_failure_is_still_failed(tmp_path, monkeypatch):
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    with pytest.raises(onboarding.CurrentUserOnboardingError) as captured:
        onboarding.onboard_current_user(app, environ=environment,
            require_bootstrap_integrity=False, registration_runner=lambda p: 7,
            profile_loader=support._profile_loader, credential_loader=support._credential_loader,
            ledger_factory=support._ledger_factory, autostart_installer=support._autostart,
            relay_launcher=support._relay_start)
    assert captured.value.status == 'FAILED'
    assert json.loads(paths.onboarding_report_path.read_bytes())['status'] == 'FAILED'


def test_marker_io_failure_keeps_actual_onboarding_ready(tmp_path, monkeypatch):
    import auto_update
    import atomic_replace
    from tools import direct_sync_relay_install_pack as pack
    from report_publication import failure_count
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {'CONTAINER_AUDIT_DATA_ROOT': str(tmp_path / 'state')}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    marker = paths.status_dir / 'standalone-diagnostic.json'
    before = b'{"old":1}\n'
    def unavailable(payload):
        raise ValueError('REPORT_UNAVAILABLE')
    monkeypatch.setattr(auto_update, 'serialize_json_for_sink', unavailable)
    original = atomic_replace.atomic_replace
    def interrupted(source, target, **kwargs):
        if Path(target) == marker:
            raise OSError('synthetic marker interruption')
        return original(source, target, **kwargs)
    monkeypatch.setattr(atomic_replace, 'atomic_replace', interrupted)
    def register(selected):
        support._ready_state(selected)
        return 0
    calls = []
    def autostart(*args, **kwargs):
        calls.append(1)
        marker.write_bytes(before)
        pack._write_json(marker, {'message': 'public'})
        return support._autostart(*args, **kwargs)
    result = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=autostart,
        relay_launcher=support._relay_start)
    assert result['status'] == 'READY'
    assert json.loads(paths.onboarding_report_path.read_bytes())['status'] == 'READY'
    assert marker.read_bytes() == before
    assert failure_count(marker) == 1
    assert calls == [1]


def test_counter_io_failure_keeps_actual_onboarding_ready(tmp_path, monkeypatch):
    import atomic_replace
    from report_publication import failure_count, UNAVAILABLE
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {'CONTAINER_AUDIT_DATA_ROOT': str(tmp_path / 'state'),
                   'KMTECH_TEST_API_TOKEN': 'synthetic-diagnostic'}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    original = atomic_replace.atomic_replace
    def interrupted(source, target, **kwargs):
        if Path(target).name.startswith('.report-unavailable-count-'):
            raise OSError('synthetic counter interruption')
        return original(source, target, **kwargs)
    monkeypatch.setattr(atomic_replace, 'atomic_replace', interrupted)
    def register(selected):
        support._ready_state(selected)
        return 0
    def autostart(*args, **kwargs):
        return {**support._autostart(*args, **kwargs), 'message': environment['KMTECH_TEST_API_TOKEN']}
    result = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=autostart,
        relay_launcher=support._relay_start)
    assert result['status'] == 'READY'
    persisted = json.loads(paths.onboarding_report_path.read_bytes())
    assert persisted['relay_autostart']['message'] == UNAVAILABLE
    assert failure_count(paths.onboarding_report_path) == 1
    assert not list(paths.status_dir.glob('.report-unavailable-count-*.json'))


def test_registration_receipt_diagnostic_preserves_ready_and_origin(tmp_path, monkeypatch):
    from tools import register_container_audit_worker_pc as registration_writer
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    environment['KMTECH_TEST_API_TOKEN'] = '4826'
    monkeypatch.setenv('KMTECH_TEST_API_TOKEN', '4826')
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    def register(selected):
        support._ready_state(selected)
        receipt = json.loads(selected.registration_report_path.read_bytes())
        receipt.update(base_url='https://synthetic.invalid', detail=4826)
        manifest = json.loads(selected.producer_manifest_path.read_bytes())
        credential = json.loads(selected.credential_path.read_bytes())
        monkeypatch.setattr(registration_writer, 'build_registration_payloads',
                            lambda args: (manifest, credential, receipt))
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        return onboarding._registration_runner(selected, server_base_url='https://synthetic.invalid',
                                                environ=environment)
    result = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=support._autostart,
        relay_launcher=support._relay_start)
    assert result['status'] == 'READY'
    receipt = json.loads(paths.registration_report_path.read_bytes())
    assert receipt['server_registration_verified'] is True
    assert receipt['base_url'] == 'https://synthetic.invalid'
    raw = paths.registration_report_path.read_text(encoding='utf-8')
    assert '4826' not in raw and 'KMTECH_TEST_API_TOKEN' not in raw
    assert json.loads(paths.onboarding_report_path.read_bytes())['status'] == 'READY'


def test_helper_report_refusal_does_not_become_parent_setup_failure(tmp_path, monkeypatch):
    import auto_update
    from tools import direct_sync_relay_install_pack as pack
    from report_publication import failure_count, UNAVAILABLE
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {'CONTAINER_AUDIT_DATA_ROOT': str(tmp_path / 'state')}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    report_path = paths.status_dir / 'helper-diagnostic.json'
    fake_environment = {'KMTECH_TEST_API_TOKEN': '4826'}
    raw_text = auto_update.redact_for_sink
    raw_json = auto_update.redact_json_for_sink
    monkeypatch.setattr(auto_update, 'redact_for_sink', lambda text, environ=None, **kwargs: raw_text(text, fake_environment if environ is None else environ, **kwargs))
    monkeypatch.setattr(auto_update, 'redact_json_for_sink', lambda value, environ=fake_environment: raw_json(value, environ))
    returns = []
    def register(selected):
        def helper():
            pack._write_json(report_path, {'detail': 4826})
            support._ready_state(selected)
            return 0
        rc = auto_update.run_support_main(helper, stage='registration')
        returns.append(rc)
        return rc
    result = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=support._autostart,
        relay_launcher=support._relay_start)
    assert result['status'] == 'READY'
    assert returns == [0]
    assert json.loads(report_path.read_bytes())['message'] == UNAVAILABLE
    assert failure_count(report_path) == 1
    assert json.loads(paths.onboarding_report_path.read_bytes())['status'] == 'READY'


def test_report_failure_preserves_original_registration_failure(tmp_path, monkeypatch):
    from report_publication import failure_count
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    environment['KMTECH_TEST_API_TOKEN'] = 'REDACTED'
    monkeypatch.setenv('KMTECH_TEST_API_TOKEN', 'REDACTED')
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    original = ValueError('REDACTED')
    def register(selected):
        raise original
    with pytest.raises(onboarding.CurrentUserOnboardingError) as captured:
        onboarding.onboard_current_user(app, environ=environment,
            require_bootstrap_integrity=False, registration_runner=register,
            profile_loader=support._profile_loader, credential_loader=support._credential_loader,
            ledger_factory=support._ledger_factory, autostart_installer=support._autostart,
            relay_launcher=support._relay_start)
    assert captured.value.status == 'FAILED'
    assert captured.value.__cause__ is original
    persisted = json.loads(paths.onboarding_report_path.read_bytes())
    assert persisted['status'] == 'FAILED'
    raw = paths.onboarding_report_path.read_text(encoding='utf-8')
    assert 'REDACTED' not in raw and 'KMTECH_TEST_API_TOKEN' not in raw
    assert failure_count(paths.onboarding_report_path) == 1


def test_two_report_refusals_keep_one_actual_first_setup(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from report_publication import failure_count, UNAVAILABLE
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    reports = [paths.status_dir / 'first-diagnostic.json', paths.status_dir / 'second-diagnostic.json']
    calls = []
    import auto_update
    from tools import direct_sync_relay_install_pack as pack
    fake_environment = {'KMTECH_TEST_API_TOKEN': '4826'}
    raw_text, raw_json = auto_update.redact_for_sink, auto_update.redact_json_for_sink
    monkeypatch.setattr(auto_update, 'redact_for_sink', lambda text, environ=None, **kwargs: raw_text(text, fake_environment if environ is None else environ, **kwargs))
    monkeypatch.setattr(auto_update, 'redact_json_for_sink', lambda value, environ=fake_environment: raw_json(value, environ))
    def register(selected):
        calls.append(1)
        support._ready_state(selected)
        return 0
    def launch(*args, **kwargs):
        def report(path):
            pack._write_json(path, {'detail': 4826})
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(report, reports))
        return support._relay_start(*args, **kwargs)
    result = onboarding.onboard_current_user(app, environ=environment,
        require_bootstrap_integrity=False, registration_runner=register,
        profile_loader=support._profile_loader, credential_loader=support._credential_loader,
        ledger_factory=support._ledger_factory, autostart_installer=support._autostart,
        relay_launcher=launch)
    assert result['status'] == 'READY'
    assert calls == [1]
    for path in reports:
        decoded = json.loads(path.read_bytes())
        assert UNAVAILABLE in decoded.values()
        raw = path.read_text(encoding='utf-8')
        assert '4826' not in raw and 'KMTECH_TEST_API_TOKEN' not in raw
    assert failure_count(paths.onboarding_report_path) == 2
    assert json.loads(next(paths.status_dir.glob('.report-unavailable-count-*.json')).read_bytes()) == {'count': 2}
    assert json.loads(paths.onboarding_report_path.read_bytes())['status'] == 'READY'
