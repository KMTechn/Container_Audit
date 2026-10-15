"""Request-only stop calls still publish after a slow initial observation."""
import json

import atomic_replace
import pytest
import user_relay


@pytest.mark.parametrize("timeout_seconds", (0, "0"))
def test_zero_timeout_publishes_both_controls_after_slow_observation(tmp_path, monkeypatch, timeout_seconds):
    clock = [0.0]
    monkeypatch.setattr(user_relay.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(atomic_replace, "monotonic", lambda: clock[0])

    def observe():
        clock[0] += 2.0
        return []

    monkeypatch.setattr(user_relay, "native_app_process_snapshot", observe)
    stop_relay = user_relay.request_user_relay_stop
    monkeypatch.setattr(
        user_relay, "request_user_relay_stop",
        lambda *args, **kwargs: stop_relay(*args, lease_factory=lambda _root: None, **kwargs),
    )
    waits = []
    result = user_relay.request_app_stop(tmp_path, timeout_seconds=timeout_seconds, wait=waits.append)

    application = json.loads(user_relay.app_stop_path(tmp_path).read_text(encoding="utf-8"))
    relay = json.loads(user_relay.user_relay_stop_path(tmp_path).read_text(encoding="utf-8"))
    assert application["request_id"] == result["request_id"]
    assert application["schema_version"] == user_relay.APP_STOP_SCHEMA
    assert relay["schema_version"] == "container-audit-user-relay-stop-v1"
    assert len(relay["request_id"]) == 32
    assert result["status"] == "UNKNOWN" and result["relay"]["status"] == "UNKNOWN"
    assert not waits
