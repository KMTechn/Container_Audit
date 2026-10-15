import json
from pathlib import Path

import pytest

import auto_update
import current_user_onboarding as onboarding
import container_audit_product_host as product_host
import user_relay


@pytest.fixture
def installed_worker(monkeypatch, tmp_path):
    app = tmp_path / 'current' / 'app'
    app.mkdir(parents=True)
    policy = app.parent / 'update-control' / 'policy.json'
    policy.parent.mkdir()
    policy.write_text(json.dumps({'operator_sid': 'S-1-5-21-100-200-300-1001'}))
    monkeypatch.setattr(auto_update, 'installation_root', lambda root: app.parent)
    monkeypatch.setattr(auto_update, 'startup_gate', lambda *args, **kwargs: None)
    monkeypatch.setattr(auto_update, 'current_process_sid', lambda: 'S-1-5-21-100-200-300-1001')
    monkeypatch.setattr(onboarding, '_inspect_current_process_execution_context', lambda: {
        'status': 'PASS', 'token_elevated': False, 'integrity_level': 'MEDIUM'})
    monkeypatch.setattr(onboarding, '_current_process_session_id', lambda: 1)
    return app


@pytest.mark.parametrize('denial', ['session_zero', 'foreign_worker', 'sid_unobservable', 'elevated'])
def test_product_dispatch_refuses_resident_before_storage(monkeypatch, installed_worker, capsys, denial):
    if denial == 'session_zero':
        monkeypatch.setattr(onboarding, '_current_process_session_id', lambda: 0)
    elif denial == 'foreign_worker':
        monkeypatch.setattr(auto_update, 'current_process_sid', lambda: 'S-1-5-21-100-200-300-1002')
    elif denial == 'sid_unobservable':
        def unavailable():
            raise OSError('identity observation unavailable')
        monkeypatch.setattr(auto_update, 'current_process_sid', unavailable)
    else:
        monkeypatch.setattr(onboarding, '_inspect_current_process_execution_context', lambda: {
            'status': 'PASS', 'token_elevated': True, 'integrity_level': 'HIGH'})
    def forbidden(*args, **kwargs):
        pytest.fail('refused resident reached storage or loop')
    monkeypatch.setattr(auto_update, 'startup_gate', forbidden)
    monkeypatch.setattr(user_relay, 'build_container_audit_storage_paths', forbidden)
    monkeypatch.setattr(user_relay, 'run_persistent_relay_loop', forbidden)
    assert product_host.dispatch_product_mode([
        product_host.USER_RELAY_MODE, '--app-root', str(installed_worker), '--once']) == 1
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == 'FAILED'
    assert output['reason_code'] == 'WORKER_INTERACTIVE_SESSION_REQUIRED'
    assert 'sid' not in output and 'session_id' not in output


def test_interactive_installed_worker_is_admitted(installed_worker):
    assert onboarding._machine_worker_context(installed_worker)['session_id'] == 1


def test_remote_stop_dispatch_keeps_administrator_exception(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('administrator stop entered resident gate')
    monkeypatch.setattr(auto_update, 'startup_gate', forbidden)
    monkeypatch.setattr(onboarding, '_machine_worker_context', forbidden)
    called = []
    monkeypatch.setattr(user_relay, 'main', lambda args: called.append(args) or 0)
    args = ['--request-app-stop', '--data-root', 'isolated-data', '--direct-sync-root', 'isolated-relay']
    assert product_host.dispatch_product_mode([product_host.USER_RELAY_MODE, *args]) == 0
    assert called == [args]


def test_resident_cannot_bypass_installed_context_with_an_unmanaged_root(monkeypatch, installed_worker, tmp_path, capsys):
    trusted = Path(user_relay.__file__).resolve().parent
    alternate = tmp_path / "unmanaged-root"
    monkeypatch.setattr(auto_update, "installation_root", lambda root:
                        installed_worker.parent if Path(root).resolve() == trusted else None)
    monkeypatch.setattr(onboarding, "_current_process_session_id", lambda: 0)
    def forbidden(*args, **kwargs):
        pytest.fail("unmanaged root bypassed executing-code admission")
    monkeypatch.setattr(auto_update, "startup_gate", forbidden)
    monkeypatch.setattr(user_relay, "build_container_audit_storage_paths", forbidden)
    assert product_host.dispatch_product_mode([
        product_host.USER_RELAY_MODE, "--app-root", str(alternate), "--once"]) == 1
    assert json.loads(capsys.readouterr().out)["reason_code"] == "WORKER_INTERACTIVE_SESSION_REQUIRED"
