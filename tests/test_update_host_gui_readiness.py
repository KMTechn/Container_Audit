"""The trial adapter follows the native GUI onboarding branch."""
import pytest

from tests import _update_host as host


@pytest.mark.parametrize("enabled,pending,expected_calls", [(False, None, 0), (True, None, 1), (True, {"status": "READY"}, 0)])
def test_trial_gui_uses_native_onboarding_route(tmp_path, monkeypatch, enabled, pending, expected_calls):
    import auto_update as updates
    import current_user_onboarding as onboarding

    root = tmp_path / "case"
    root.mkdir()
    (root / "host-finish").touch()
    app = root / "app"
    events = []
    consumed = []
    calls = []
    monkeypatch.setattr(host, "event", lambda target, kind, **fields: events.append((kind, fields)))
    monkeypatch.setattr(updates, "startup_gate", lambda *args: None)
    def consume(target):
        consumed.append(target)
        return pending
    def onboard(target, **kwargs):
        calls.append((target, kwargs))
        return {"status": "READY"}
    monkeypatch.setattr(onboarding, "consume_pending_machine_onboarding", consume)
    monkeypatch.setattr(onboarding, "first_run_onboarding_enabled", lambda: enabled)
    monkeypatch.setattr(onboarding, "onboard_current_user", onboard)

    assert host.gui_readiness_loop(root / "host-config.json", app, []) == 0
    assert consumed == [app]
    assert len(calls) == expected_calls
    assert sum(kind == "gui_onboard_called" for kind, _ in events) == expected_calls
    assert sum(kind == "gui_onboarded" for kind, _ in events) == int(expected_calls == 1 or pending is not None)
    if calls:
        assert calls[0] == (app, {"server_base_url": host.ORIGIN, "startup": True})
