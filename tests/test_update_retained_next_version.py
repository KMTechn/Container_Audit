"""Retained X requests and supervises a distinct authenticated Y."""
import contextlib
import copy
import json

import pytest

import auto_update as updates
from kmtech_shared import data_generation as generation
from tests.test_auto_update_recovery_integrity import world
from tests.test_signed_pairrule import identities, signed


@pytest.mark.parametrize("candidate_ready", [True, False], ids=["b1-confirm-y", "b2-rollback-x"])
def test_retained_x_next_version_system_outcome(world, monkeypatch, tmp_path, candidate_ready):
    w = world
    current, candidate = identities()
    x, y, old = current["source_commit"], candidate["source_commit"], "3" * 40
    w.previous, w.candidate = x, y
    marker = str(tmp_path / "generation.json")
    w.generation = {"status": "READ", "marker_path": marker,
                    "record": {"version": current["version"], "build_id": x}}
    monkeypatch.setattr(generation, "probe_downgrade", lambda *a, **k: {"status": "ALLOW"})
    retained = updates.prepare_transition(previous_sha=old, candidate_sha=x,
        packet_sha256="3" * 64, forward_pin="4" * 64, rollback_pin="5" * 64,
        transition_id="6" * 32, nonce="7" * 32, now=w.at(870))
    retained = updates.apply_transition(retained, writers_absent=True, packet_verified=True,
                                       durable_prepared=True, now=w.at(870))
    retained.update(generation_before={"status": "READ", "marker_path": marker,
                    "record": {"version": "v2.0.98", "build_id": old}},
                    generation_previous_release={"version": "v2.0.98", "source_commit": old},
                    generation_candidate_release=current)
    retained = updates.request_rollback(retained, reason="candidate startup failed or readiness timed out")
    retained = updates.decide_trial_failure({**retained, "recovery_pending": False}, w.policy)
    assert retained["phase"] == "DEFERRED"
    assert retained["retained_candidate"] is True
    assert retained["failed_shas"] == [x]
    w.files[w.control / "transition.json"] = copy.deepcopy(retained)
    w.files[w.control / "active.json"] = {"schema": updates.SCHEMA, "sha": x,
                                        "transition_id": retained["transition_id"]}
    requests = []
    monkeypatch.setattr(updates, "apply_claim_status", lambda *_: "NONE")
    monkeypatch.setattr(updates, "prepared_pending", lambda *_: True)
    monkeypatch.setattr(updates, "request_apply_task", lambda *_: requests.append(w.clock))
    monkeypatch.setattr(updates, "start_current", lambda *a, **k: 0)
    assert w.gui() == 0
    assert len(requests) == 1

    manifest = signed(current, candidate)
    forward, reverse, pair, authority = updates.manifest_transition_pins(
        manifest, current=current, candidate=candidate)
    pending = updates.prepare_transition(previous_sha=x, candidate_sha=y,
        packet_sha256="8" * 64, forward_pin=forward, rollback_pin=reverse,
        transition_id="9" * 32, nonce="a" * 32, now=w.now(),
        failed_shas=retained["failed_shas"])
    pending.update(protected_packet="packet-" + "b" * 32,
                   rollback_pair=pair, pin_authority=authority,
                   generation_before=copy.deepcopy(w.generation),
                   generation_previous_release=current, generation_candidate_release=candidate)
    w.files[w.control / "transition.json"] = pending
    w.policy["channel"] = "stable"
    w.files[w.control.parent / "current/app/update-manifest-key-config.json"] = {"manifest_public_key": {}}
    monkeypatch.setattr(updates, "version_manifest",
        lambda path, **kw: copy.deepcopy(current if path.name == x else candidate))
    monkeypatch.setattr(updates, "verify_prepared_packet",
        lambda *a, **k: (manifest, {"sha256": pending["packet_sha256"]}))
    monkeypatch.setattr(updates, "prepared_pending", lambda *_: False)
    original_snapshot = updates.process_snapshot
    original_lock = updates.update_lock
    applied_lock_released = [False]

    @contextlib.contextmanager
    def locked(*args, **kwargs):
        with original_lock(*args, **kwargs) as ownership:
            yield ownership
        if w.state()["phase"] == "APPLIED_PENDING_READY":
            applied_lock_released[0] = True

    monkeypatch.setattr(updates, "update_lock", locked)

    def snapshot(*args):
        # Native bootstrap cannot launch its GUI while SYSTEM still owns the
        # initial apply lock. Introduce the receipt only after that release.
        if candidate_ready and applied_lock_released[0] and w.state()["phase"] == "APPLIED_PENDING_READY":
            w.ready()
        return original_snapshot(*args)

    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    w.auto_ready = not candidate_ready
    policy_before = copy.deepcopy(w.files[w.control / "policy.json"])
    outcome = w.system()
    (tmp_path / "retained-next-observed.json").write_text(json.dumps({
        "case": "b1" if candidate_ready else "b2", "rc": outcome,
        "phase": w.state()["phase"], "active": w.active(),
        "trial_pid": w.state().get("trial_pid"),
        "trial_started_at": w.state().get("trial_started_at"),
        "ready_at": w.files.get(w.stage / "ready.json", {}).get("ready_at"),
        "ready_pid": w.files.get(w.stage / "ready.json", {}).get("pid"),
        "row_roles": [row["role"] for row in w.rows],
        "row_created_at": [row["created_at"] for row in w.rows],
        "clock": w.clock,
    }, indent=2) + "\n", encoding="utf-8")
    assert outcome == 0
    final = w.state()
    policy = w.files[w.control / "policy.json"]
    assert final["previous_sha"] == x
    assert final["rollback_pair"]["to_commit"] == x
    if candidate_ready:
        assert final["phase"] == "CONFIRMED"
        assert w.active() == y
        assert final["failed_shas"] == [x]
        assert policy["last_confirmed_rollback"] == pair
        assert policy["confirmed_transition_id"] == final["transition_id"]
        assert final["policy_audit_applied"] is True
        assert w.writes.count("policy.json") == 1
    else:
        assert final["phase"] == "ROLLED_BACK"
        assert w.active() == x
        assert final["failed_shas"] == [x, y]
        assert policy == policy_before
        assert w.writes.count("policy.json") == 0
    (tmp_path / "retained-next-result.json").write_text(json.dumps({
        "case": "b1" if candidate_ready else "b2", "phase": final["phase"],
        "active": w.active(), "previous_sha": final["previous_sha"],
        "failed_shas": final["failed_shas"], "rollback_pair": final["rollback_pair"],
        "policy_write_count": w.writes.count("policy.json"),
        "confirmed_transition_id": policy.get("confirmed_transition_id"),
        "request_count": len(requests),
        "authenticated_packet_verifier_mocked_for_unit": True,
        "signed_exact_pair_authorization_function_actual": True,
        "system_apply_rollback_ready_and_policy_functions_actual": True,
    }, indent=2) + "\n", encoding="utf-8")
