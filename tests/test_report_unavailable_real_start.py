"""Enter the real startup function and finish onboarding before any real window."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import current_user_onboarding as onboarding
from tests import test_current_user_onboarding as support
from tests.test_current_user_onboarding import _isolate_onboarding_control_root, existing_possession_key_contract
pytestmark = pytest.mark.usefixtures("existing_possession_key_contract")

class ReadyReached(BaseException):
    pass


def test_actual_startup_continues_after_diagnostic_refusal(tmp_path, monkeypatch):
    import Container_Audit as gui
    app = support._generation_packet(tmp_path, monkeypatch)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    environment['KMTECH_TEST_API_TOKEN'] = 'REDACTED'
    pass
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    seen = []
    def register(selected):
        support._ready_state(selected)
        return 0
    def autostart(*args, **kwargs):
        return {**support._autostart(*args, **kwargs), 'message': 'REDACTED'}
    def actual_onboarding(*args, **kwargs):
        result = onboarding.onboard_current_user(app, environ=environment,
            require_bootstrap_integrity=False, registration_runner=register,
            profile_loader=support._profile_loader, credential_loader=support._credential_loader,
            ledger_factory=support._ledger_factory, autostart_installer=autostart,
            relay_launcher=support._relay_start, startup=kwargs.get("startup", False))
        seen.append(result['status'])
        return result
    def reached(*args, **kwargs):
        raise ReadyReached()
    monkeypatch.setattr(gui, 'onboard_current_user', actual_onboarding)
    monkeypatch.setattr(gui, '_first_run_onboarding_enabled', lambda: True)
    monkeypatch.setattr(gui, 'verify_factory_contract_startup', lambda: None)
    monkeypatch.setattr(gui, '_show_first_run_onboarding_error', lambda error: None)
    from storage_policy import build_container_audit_storage_paths
    storage = build_container_audit_storage_paths(application_path=str(app), data_root=str(paths.data_root), environ=environment)
    storage.data_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(gui, '__file__', str(app / 'Container_Audit.py'))
    monkeypatch.setattr(gui, 'build_container_audit_storage_paths', lambda **kwargs: storage)
    monkeypatch.setattr(gui, 'acquire_runtime_instance', lambda root: SimpleNamespace(release=lambda: None))
    monkeypatch.setattr(gui, '_consume_startup_app_stop_request', lambda *args: False)
    monkeypatch.setattr(gui, 'consume_pending_machine_onboarding', lambda *args: None)
    monkeypatch.setattr(gui, 'prepare_startup_item_catalog', reached)
    with pytest.raises(ReadyReached):
        gui._prepare_gui_startup(data_root=str(paths.data_root))
    assert seen == ['READY']
    persisted = json.loads(paths.onboarding_report_path.read_bytes())
    assert persisted['status'] == 'READY'
    assert persisted['server_registration_verified'] is True
    raw = paths.onboarding_report_path.read_text(encoding='utf-8')
    assert 'REDACTED' not in raw and 'KMTECH_TEST_API_TOKEN' not in raw
