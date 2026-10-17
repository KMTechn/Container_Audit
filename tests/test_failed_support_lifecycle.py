"""Only the explicit support preflight may classify a verified FAILED install."""
import json
import os

import pytest

from tests.test_supported_lifecycle import installed


@pytest.mark.parametrize("case", ["allow", "code", "writer", "generation", "fence", "prepared", "ordinary_caller"])
def test_failed_lifecycle_requires_explicit_preflight_and_separate_proofs(installed, monkeypatch, tmp_path, request, case):
    import auto_update as update
    import writer_session_fence as fence
    from kmtech_shared import data_generation as generation

    control = installed / "update-control"
    state_path = control / "transition.json"
    state = update.read_json(state_path)
    state.update(phase="FAILED", reason="readiness failure", last_ready_error="not ready")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    policy = update.read_json(control / "policy.json")
    policy["operator_local_app_data"] = str(tmp_path / "operator-local")
    (control / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    active = update.read_json(control / "active.json")["sha"]
    marker = fence.canonical_control_root({"LOCALAPPDATA": policy["operator_local_app_data"]}) / "data-generation" / (policy["operator_sid"] + ".json")
    marker.parent.mkdir(parents=True, exist_ok=True)
    original_marker = marker.read_bytes() if marker.exists() else None
    def restore_marker():
        if original_marker is None:
            marker.unlink(missing_ok=True)
        else:
            marker.write_bytes(original_marker)
    request.addfinalizer(restore_marker)
    version = "v99.0.0" if case == "generation" else "v2.0.112"
    generation.record_generation(marker, version, app_id="container_audit", subject_sid=policy["operator_sid"], build_id=active)
    calls = []

    def stock(bundle):
        calls.append("code")
        if case == "code" and bundle == installed / "versions" / active:
            raise ValueError("changed inventory")
        return {"status": "PASS"}

    def observed(_control):
        calls.append("writer")
        return [{"pid": os.getpid() + 1, "observable": True}] if case == "writer" else []

    def active_fence(*args, **kwargs):
        calls.append("fence")
        return {"status": "INSTALLING"} if case == "fence" else None

    def pending(*args, **kwargs):
        calls.append("prepared")
        return case == "prepared"

    def manifest(*args, **kwargs):
        calls.append("generation")
        return {"version": "v2.0.112", "source_commit": active}

    monkeypatch.setattr(update, "verify_lifecycle_stock", stock)
    monkeypatch.setattr(update, "process_snapshot", observed)
    monkeypatch.setattr(fence, "active_fence", active_fence)
    monkeypatch.setattr(update, "prepared_pending", pending)
    monkeypatch.setattr(update, "version_manifest", manifest)
    before = state_path.read_bytes()
    if case == "allow":
        assert update.resolve_lifecycle_context(installed, operation="install", failed_support_preflight=True)["status"] == "PASS"
        assert {"code", "writer", "generation", "fence", "prepared"}.issubset(calls)
    else:
        with pytest.raises(ValueError):
            if case == "ordinary_caller":
                update.resolve_lifecycle_context(installed, operation="install")
            else:
                update.resolve_lifecycle_context(installed, operation="install", failed_support_preflight=True)
        if case != "ordinary_caller":
            assert case in calls
    assert state_path.read_bytes() == before


def test_failed_lifecycle_unobservable_prepared_fails_closed(installed, monkeypatch):
    import auto_update as update
    import writer_session_fence as fence

    state_path = installed / "update-control/transition.json"
    state = update.read_json(state_path)
    state["phase"] = "FAILED"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    before = state_path.read_bytes()
    monkeypatch.setattr(update, "process_snapshot", lambda _control: [])
    monkeypatch.setattr(fence, "active_fence", lambda *args, **kwargs: None)
    def unreadable(*args, **kwargs):
        raise TypeError("prepared receipt cannot be observed")
    monkeypatch.setattr(update, "prepared_pending", unreadable)
    with pytest.raises(ValueError):
        update.resolve_lifecycle_context(installed, operation="install", failed_support_preflight=True)
    assert state_path.read_bytes() == before
