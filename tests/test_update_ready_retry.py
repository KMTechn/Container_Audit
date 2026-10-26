"""READY window of 600 seconds and a bounded second chance after a READY timeout."""
import copy

import pytest

import auto_update as updates
from kmtech_shared import data_generation as generation
from tests.test_auto_update_recovery_integrity import world
from tests.test_signed_pairrule import identities, signed


OLD, NEW = "1" * 40, "2" * 40
T0 = "2026-10-01T04:00:00+00:00"


def at(hours):
    from datetime import datetime, timedelta, timezone
    return (datetime(2026, 10, 1, 4, tzinfo=timezone.utc) + timedelta(hours=hours)).isoformat()


def trial_state(**extra):
    state = updates.prepare_transition(
        previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64, forward_pin="4" * 64,
        rollback_pin="5" * 64, transition_id="6" * 32, nonce="7" * 32, now=T0, **extra)
    state = updates.apply_transition(state, writers_absent=True, packet_verified=True,
                                     durable_prepared=True, now=T0)
    return updates.bind_trial(state, sha=NEW, pid=42, ordinary_user=True, now=T0)


def test_ready_window_is_ten_minutes_and_the_bootstrap_cap_outlasts_it():
    assert updates.READY_WINDOW_SECONDS == 600
    assert updates.BOOTSTRAP_OBSERVATION_CAP_SECONDS >= updates.READY_WINDOW_SECONDS + 240
    state = {"phase": "APPLIED_PENDING_READY", "applied_at": T0}
    deadline = updates.bootstrap_supervision_deadline(state, started=0, now=0, utc_now=T0)
    assert deadline == updates.READY_WINDOW_SECONDS + 15


def test_a_confirmed_rejection_stays_permanent_at_once():
    state = updates.request_rollback(trial_state(), reason="candidate startup failed or readiness timed out")
    assert state["failed_shas"] == [NEW] and "retry_shas" not in state


def test_a_transient_failure_is_not_blacklisted_until_the_third_chance_inside_a_day():
    state = trial_state()
    first = updates.request_rollback(state, reason="timeout", transient=True, now=at(0))
    assert first["failed_shas"] == []
    assert first["retry_shas"][NEW] == {"attempts": 1, "first_at": at(0), "last_at": at(0)}
    second = updates.request_rollback({**state, "retry_shas": first["retry_shas"]}, reason="timeout",
                                      transient=True, now=at(1))
    assert second["failed_shas"] == [] and second["retry_shas"][NEW]["attempts"] == 2
    third = updates.request_rollback({**state, "retry_shas": second["retry_shas"]}, reason="timeout",
                                     transient=True, now=at(2))
    assert third["failed_shas"] == [NEW] and third["retry_shas"][NEW]["attempts"] == 3


def test_chances_start_over_after_a_day_and_bad_records_are_ignored():
    state = trial_state()
    old = {NEW: {"attempts": 2, "first_at": at(0), "last_at": at(1)},
           "not-a-sha": {"attempts": 5, "first_at": at(0), "last_at": at(0)}}
    later = updates.request_rollback({**state, "retry_shas": old}, reason="timeout", transient=True, now=at(25))
    assert later["failed_shas"] == []
    assert later["retry_shas"] == {NEW: {"attempts": 1, "first_at": at(25), "last_at": at(25)}}


def test_the_next_transition_keeps_the_retry_record():
    retry = {NEW: {"attempts": 1, "first_at": at(0), "last_at": at(0)}}
    carried = updates.prepare_transition(
        previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64, forward_pin="4" * 64,
        rollback_pin="5" * 64, transition_id="6" * 32, nonce="7" * 32, now=T0, retry_shas=retry)
    assert carried["retry_shas"] == retry
    assert "retry_shas" not in updates.prepare_transition(
        previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64, forward_pin="4" * 64,
        rollback_pin="5" * 64, transition_id="6" * 32, nonce="7" * 32, now=T0)


def pend_candidate(w, monkeypatch, tmp_path, *, failed=(), retry=None):
    current, candidate = identities()
    w.previous, w.candidate = current["source_commit"], candidate["source_commit"]
    w.generation = {"status": "READ", "marker_path": str(tmp_path / "generation.json"),
                    "record": {"version": current["version"], "build_id": w.previous}}
    monkeypatch.setattr(generation, "probe_downgrade", lambda *a, **k: {"status": "ALLOW"})
    manifest = signed(current, candidate)
    forward, reverse, pair, authority = updates.manifest_transition_pins(
        manifest, current=current, candidate=candidate)
    pending = updates.prepare_transition(previous_sha=w.previous, candidate_sha=w.candidate,
        packet_sha256="8" * 64, forward_pin=forward, rollback_pin=reverse,
        transition_id="9" * 32, nonce="a" * 32, now=w.now(), failed_shas=list(failed), retry_shas=retry)
    pending.update(protected_packet="packet-" + "b" * 32, rollback_pair=pair,
                   pin_authority=authority, generation_before=copy.deepcopy(w.generation),
                   generation_previous_release=current, generation_candidate_release=candidate)
    w.files[w.control / "transition.json"] = pending
    w.files[w.control / "active.json"] = {"schema": updates.SCHEMA, "sha": w.previous}
    w.files[w.control.parent / "current/app/update-manifest-key-config.json"] = {"manifest_public_key": {}}
    w.policy["channel"] = "stable"
    monkeypatch.setattr(updates, "version_manifest",
        lambda path, **kw: copy.deepcopy(current if path.name == w.previous else candidate))
    monkeypatch.setattr(updates, "verify_prepared_packet",
        lambda *a, **k: (manifest, {"sha256": pending["packet_sha256"]}))
    w.auto_ready = True  # A failed candidate also exercises the real rollback consumer.


def test_candidate_ready_at_300_seconds_confirms_instead_of_rolling_back(world, monkeypatch, tmp_path):
    w = world
    pend_candidate(w, monkeypatch, tmp_path)
    snapshot = updates.process_snapshot
    started = w.clock

    def delayed_candidate(*args):
        if w.state()["phase"] == "APPLIED_PENDING_READY" and w.clock - started >= 300:
            w.ready()
        return snapshot(*args)

    monkeypatch.setattr(updates, "process_snapshot", delayed_candidate)
    assert w.system() == 0
    assert w.state()["phase"] == "CONFIRMED" and w.active() == w.candidate
    assert w.state()["failed_shas"] == [] and "retry_shas" not in w.state()
    assert 300 <= w.clock - started < updates.READY_WINDOW_SECONDS


def test_a_ready_timeout_is_retried_twice_more_and_only_then_permanent(world, monkeypatch, tmp_path):
    w = world
    retry = None
    for round_number in (1, 2, 3):
        pend_candidate(w, monkeypatch, tmp_path, retry=retry)
        w.system()
        state = w.state()
        assert state["phase"] == "ROLLED_BACK" and w.active() == w.previous
        assert state["retry_shas"][w.candidate]["attempts"] == round_number
        assert state["failed_shas"] == ([] if round_number < 3 else [w.candidate])
        retry = state["retry_shas"]
        w.clock += 60


def test_the_retry_record_survives_the_real_journal_writer(isolate_product_state, tmp_path):
    control = tmp_path / "control"
    control.mkdir()
    state = updates.request_rollback(trial_state(), reason="candidate startup failed or readiness timed out",
                                     transient=True, now=at(0))
    updates.write_json_durable(control / "transition.json", state)
    assert updates.read_json(control / "transition.json")["retry_shas"] == state["retry_shas"]
