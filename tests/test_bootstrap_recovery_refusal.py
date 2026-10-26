"""A start_current cohort refusal stays on the guided bootstrap exit path."""
import contextlib

import pytest

import auto_update as updates


@pytest.mark.parametrize("change", [
    {"role": "writer"}, {"sha": "b" * 40},
], ids=["onboarding-or-finite-writer", "old-sha"])
def test_bootstrap_start_current_refusal_is_guided_20(monkeypatch, tmp_path, change):
    control = tmp_path / "control"
    sha = "a" * 40
    policy = {"operator_sid": "synthetic-operator", "staging_root": str(tmp_path)}
    state = {"schema": updates.SCHEMA, "phase": "PREPARED"}
    row = dict(pid=713, observable=True, bootstrap=False, role="relay", sha=sha,
               sid=policy["operator_sid"], ordinary_user=True,
               created_at="2026-10-25T10:00:00Z")
    guidance = []
    monkeypatch.setattr(updates.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(updates, "control_root", lambda *a: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *a: True)
    monkeypatch.setattr(updates, "optional_record", lambda p: state if p.name == "transition.json" else None)
    monkeypatch.setattr(updates, "apply_claim_status", lambda *a: "NONE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *a: False)
    monkeypatch.setattr(updates, "update_relay_stop_requested", lambda *a: False)

    class Poll(contextlib.AbstractContextManager):
        acquired = True

        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, callback):
            return callback()

    monkeypatch.setattr(updates, "_BootstrapPoll", Poll)

    def unavailable(*a):
        raise OSError("synthetic task unavailable")

    monkeypatch.setattr(updates, "request_apply_task", unavailable)
    monkeypatch.setattr(updates, "process_snapshot", lambda *a: [{**row, **change}])
    monkeypatch.setattr(updates, "read_json", lambda p: policy if p.name == "policy.json" else {"sha": sha})
    monkeypatch.setattr(updates, "current_generation_status", lambda *a: "ALLOW")
    monkeypatch.setattr(updates, "now_utc", lambda: "2026-10-26T10:00:00Z")
    monkeypatch.setattr(updates, "write_json_durable", lambda *a: None)
    monkeypatch.setattr(updates, "emit_progress_guidance", lambda: guidance.append(True))
    monkeypatch.setattr(updates, "launch_version", lambda *a, **kw: pytest.fail("unsafe launch"))
    assert updates.bootstrap(control, [], role="gui") == 20
    assert guidance
