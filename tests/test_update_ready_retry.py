"""READY window of 900 seconds and a bounded second chance after a READY timeout."""
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


def test_ready_window_is_fifteen_minutes_and_the_bootstrap_cap_outlasts_it():
    assert updates.READY_WINDOW_SECONDS == 900
    assert updates.BOOTSTRAP_OBSERVATION_CAP_SECONDS == updates.READY_WINDOW_SECONDS + 240 == 1140
    state = {"phase": "APPLIED_PENDING_READY", "applied_at": T0}
    deadline = updates.bootstrap_supervision_deadline(state, started=0, now=0, utc_now=T0)
    assert deadline == updates.READY_WINDOW_SECONDS + 15


def test_a_confirmed_rejection_stays_permanent_at_once():
    state = updates.request_rollback(trial_state(), reason="candidate startup failed or readiness timed out")
    assert state["failed_shas"] == [NEW] and "retry_shas" not in state


def test_transient_failures_never_blacklist_even_after_three_chances():
    state = trial_state()
    first = updates.request_rollback(state, reason="timeout", transient=True, now=at(0))
    assert first["failed_shas"] == []
    assert first["retry_shas"][NEW] == {"attempts": 1, "first_at": at(0), "last_at": at(0)}
    second = updates.request_rollback({**state, "retry_shas": first["retry_shas"]}, reason="timeout",
                                      transient=True, now=at(1))
    assert second["failed_shas"] == [] and second["retry_shas"][NEW]["attempts"] == 2
    third = updates.request_rollback({**state, "retry_shas": second["retry_shas"]}, reason="timeout",
                                     transient=True, now=at(2))
    assert third["failed_shas"] == [] and third["retry_shas"][NEW]["attempts"] == 3


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
        transition_id="9" * 32, nonce="a" * 32, now=w.now(), failed_shas=list(failed), **({"retry_shas": retry} if retry else {}))
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
        lambda *a, **k: ({**manifest, "source_commit": w.candidate}, {"sha256": pending["packet_sha256"]}))
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


def test_a_ready_timeout_uses_three_chances_without_permanent_rejection(world, monkeypatch, tmp_path):
    w = world
    retry = None
    for round_number in (1, 2, 3):
        # A fresh login has stopped the restored trial and discarded its proof.
        w.rows = []
        for name in ("trial.json", "ready.json"):
            w.files.pop(w.stage / name, None)
        pend_candidate(w, monkeypatch, tmp_path, retry=retry)
        w.system()
        state = w.state()
        assert state["phase"] == "ROLLED_BACK" and w.active() == w.previous
        assert state["retry_shas"][w.candidate]["attempts"] == round_number
        assert state["failed_shas"] == []
        retry = state["retry_shas"]
        w.clock += 60


def test_the_retry_record_survives_the_real_journal_writer(isolate_product_state, tmp_path):
    control = tmp_path / "control"
    control.mkdir()
    state = updates.request_rollback(trial_state(), reason="candidate startup failed or readiness timed out",
                                     transient=True, now=at(0))
    updates.write_json_durable(control / "transition.json", state)
    assert updates.read_json(control / "transition.json")["retry_shas"] == state["retry_shas"]


def _preparation_case(tmp_path, monkeypatch, error):
    from contextlib import nullcontext
    from types import SimpleNamespace
    control, stage = tmp_path / "control", tmp_path / "stage"
    policy = {"operator_sid": "test-sid", "staging_root": str(stage), "feed_url": "https://invalid.test/feed"}
    files = {control / "active.json": {"sha": OLD}, control / "policy.json": policy,
             stage / "prepared.json": {"source_commit": NEW}}
    clock = [0]
    monkeypatch.setattr(updates, "now_utc", lambda: at(clock[0] / 3600))
    monkeypatch.setattr(updates, "read_json", lambda path: files[path].copy())
    monkeypatch.setattr(updates, "optional_record", lambda path: files.get(path, {}).copy() or None)
    monkeypatch.setattr(updates, "write_json_durable", lambda path, value: files.__setitem__(path, dict(value)))
    monkeypatch.setattr(updates, "fixed_helper", lambda *a, **k: None)
    monkeypatch.setattr(updates, "update_lock", lambda *a, **k: nullcontext())
    monkeypatch.setattr(updates, "complete_apply_claim", lambda *a: None)
    if hasattr(updates, "load_policy"):
        monkeypatch.setattr(updates, "load_policy", lambda *a: policy)
        monkeypatch.setattr(updates, "prepared_marker_sha256", lambda *a: "c" * 64)
    else:
        monkeypatch.setattr(updates, "prepared_failure_identity", lambda *a: "c" * 64)

    def fail(*args):
        raise error

    monkeypatch.setattr(updates, "_apply_prepared", fail)
    return SimpleNamespace(control=control, policy=policy, files=files, clock=clock,
                           state=lambda: files[control / "transition.json"],
                           run=lambda: updates.apply_prepared(control))


def _native_error(code):
    error = OSError("simulated native I/O failure")
    error.winerror = code
    return error


@pytest.mark.parametrize("error", [TimeoutError(), PermissionError(), ConnectionResetError(),
    _native_error(5), _native_error(32), _native_error(33), _native_error(1117),
    RuntimeError("unknown failure"), ValueError("unknown failure"), OSError("unknown failure")])
def test_transient_preparation_gets_a_durable_retry_after_900_seconds(tmp_path, monkeypatch, error):
    case = _preparation_case(tmp_path, monkeypatch, error)
    assert case.run() == 0
    state = case.state()
    assert NEW not in state.get("failed_shas", [])
    assert state["retry_shas"][NEW]["attempts"] == 1
    assert not updates.prepared_pending(case.control, case.policy, state)
    case.clock[0] = 899
    assert not updates.prepared_pending(case.control, case.policy, state)
    case.clock[0] = 900
    assert updates.prepared_pending(case.control, case.policy, state)
    case.clock[0] = 1800
    assert case.run() == 0
    assert case.state()["retry_shas"][NEW]["attempts"] == 2
    case.clock[0] = 2700
    assert case.run() == 0
    assert case.state().get("failed_shas", []) == []
    case.clock[0] = 30 * 3600
    assert updates.prepared_pending(case.control, case.policy, case.state())


def _confirmed_error():
    error = ValueError("manifest verification failed")
    error._preparation_rejection = True
    return error


@pytest.mark.parametrize("error", [_confirmed_error()])
def test_confirmed_preparation_failure_still_blocks_immediately(tmp_path, monkeypatch, error):
    case = _preparation_case(tmp_path, monkeypatch, error)
    assert case.run() == 0
    assert not case.state().get("retry_shas")
    case.clock[0] = 3600
    assert not updates.prepared_pending(case.control, case.policy, case.state())


def test_preparation_retry_window_resets_after_24_hours(tmp_path, monkeypatch):
    case = _preparation_case(tmp_path, monkeypatch, TimeoutError())
    case.run()
    case.clock[0] = 24 * 3600
    assert updates.prepared_pending(case.control, case.policy, case.state())
    case.run()
    assert case.state()["retry_shas"][NEW] == {"attempts": 1, "first_at": at(24), "last_at": at(24)}


def test_a_preparation_error_after_an_uncertain_pointer_never_opens_a_retry(tmp_path, monkeypatch):
    case = _preparation_case(tmp_path, monkeypatch, TimeoutError())
    case.files[case.control / "transition.json"] = {"phase": "APPLIED_PENDING_READY"}
    assert case.run() == 20
    assert case.state()["phase"] == "UNKNOWN"
    assert not case.state().get("retry_shas")


def test_observe_generic_stdout_remains_unknown(monkeypatch, tmp_path):
    import subprocess
    from types import SimpleNamespace
    completed = SimpleNamespace(returncode=1, stdout='CONTAINER_AUDIT_UPDATE={"reason_code":"STARTUP_UPDATE_FAILURE"}', stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)
    monkeypatch.setattr(updates, "system_executable", lambda *a: tmp_path / "powershell.exe")
    try:
        updates._run_fixed_helper(tmp_path / "control", "Observe")
    except RuntimeError as error:
        assert updates._transient_preparation_error(error)
    else:
        pytest.fail("Observe must reject the timed-out query")


def test_system_preparation_entry_obeys_the_saved_retry_interval(tmp_path, monkeypatch):
    from contextlib import nullcontext
    case = _preparation_case(tmp_path, monkeypatch, TimeoutError())
    case.run()
    case.policy["operator_local_app_data"] = str(tmp_path / "profile")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "profile"))
    lock = "_initial_ready_lock" if hasattr(updates, "_initial_ready_lock") else "_ready_window_update_lock"
    monkeypatch.setattr(updates, lock, lambda *a, **k: nullcontext())
    def unexpected_claim():
        pytest.fail("cooldown must return before starting a new apply")
    monkeypatch.setattr(updates, "new_apply_claim", unexpected_claim)
    case.clock[0] = 899
    assert updates._apply_prepared_once(case.control) == 0
    assert case.state()["retry_shas"][NEW]["attempts"] == 1


@pytest.mark.parametrize("kind", ["network", "query_timeout", "disk_io", "disk_full"])
def test_only_the_approved_io_errors_are_temporary(kind):
    import errno
    import subprocess
    from requests.exceptions import ConnectionError as RequestConnectionError
    errors = {"network": RequestConnectionError(), "query_timeout": subprocess.TimeoutExpired("Observe", 20),
              "disk_io": OSError(errno.EIO, "simulated"), "disk_full": OSError(errno.ENOSPC, "simulated")}
    assert updates._transient_preparation_error(errors[kind]) is True


def test_an_unreadable_prepared_identity_keeps_its_saved_wait_after_restart(tmp_path, monkeypatch):
    real_write, real_read = updates.write_json_durable, updates.read_json
    case = _preparation_case(tmp_path, monkeypatch, PermissionError())
    readable = [False]
    original_read, original_optional = updates.read_json, updates.optional_record
    def read(path):
        if path.name == "prepared.json" and not readable[0]:
            raise PermissionError()
        return original_read(path)
    def optional(path):
        if path.name == "prepared.json" and not readable[0]:
            raise PermissionError()
        return original_optional(path)
    monkeypatch.setattr(updates, "read_json", read)
    monkeypatch.setattr(updates, "optional_record", optional)
    if hasattr(updates, "prepared_marker_sha256"):
        monkeypatch.setattr(updates, "prepared_marker_sha256", lambda *a: "d" * 64 if readable[0] else None)
    else:
        monkeypatch.setattr(updates, "prepared_failure_identity", lambda *a: ("d" if readable[0] else "c") * 64)
    assert case.run() == 0
    assert case.state()["preparation_retry_pending"] is True
    assert not case.state().get("retry_shas") and not case.state().get("failed_shas")
    assert not updates.prepared_pending(case.control, case.policy, case.state())
    # Read through the real protected JSON writer, then resume with that record.
    journal = tmp_path / "persisted" / "transition.json"
    journal.parent.mkdir()
    real_write(journal, case.state())
    case.files[case.control / "transition.json"] = real_read(journal)
    readable[0] = True
    case.clock[0] = 899
    assert not updates.prepared_pending(case.control, case.policy, case.state())
    case.clock[0] = 900
    assert updates.prepared_pending(case.control, case.policy, case.state())
    case.run()
    assert not case.state().get("preparation_retry_pending")
    assert case.state()["retry_shas"][NEW]["attempts"] == 1


def test_exhaustion_reports_the_approved_notice_and_keeps_the_current_app(tmp_path, monkeypatch, capsys):
    case = _preparation_case(tmp_path, monkeypatch, RuntimeError("unknown failure"))
    # A prior confirmed candidate must not hide the current preparation's budget.
    case.files[case.control / "transition.json"] = {"schema": updates.SCHEMA, "phase": "CONFIRMED", "candidate_sha": OLD}
    for second in (0, 900, 1800):
        case.clock[0] = second
        assert case.run() == 0
    state = case.state()
    assert NEW not in state.get("failed_shas", [])
    assert state["retry_shas"][NEW]["attempts"] == 3
    assert not updates.prepared_pending(case.control, case.policy, state)
    launched = []
    monkeypatch.setattr(updates, "launch_version", lambda _c, sha, *a, **k: (launched.append(sha), 123)[1])
    if hasattr(updates, "_bootstrap_relay_readback"):
        monkeypatch.setattr(updates, "_bootstrap_relay_readback", lambda *a, **k: True)
    assert updates.start_current(case.control, case.policy, state, {"sha": OLD}, [], code="UPDATE_PREPARATION_FAILED") == 0
    report = case.files[__import__("pathlib").Path(case.policy["staging_root"]) / "startup-support.json"]
    assert report["reason_code"] == "UPDATE_RETRY_REVIEW_REQUIRED"
    assert report["guidance"] == updates.RETRY_REVIEW_MESSAGE
    import json
    emitted = [json.loads(line.split("=", 1)[-1]) for line in capsys.readouterr().out.splitlines()]
    assert any(record.get("guidance") == updates.RETRY_REVIEW_MESSAGE for record in emitted)
    assert launched == [OLD]
    case.clock[0] = 24 * 3600
    assert updates.prepared_pending(case.control, case.policy, state)
    assert not updates._retry_review_required(state)


def test_a_rolled_back_ready_timeout_has_the_same_review_budget(monkeypatch):
    monkeypatch.setattr(updates, "now_utc", lambda: at(2))
    state = trial_state()
    for hour in (0, 1, 2):
        pending = trial_state(retry_shas=state.get("retry_shas"))
        state = updates.request_rollback(pending, reason="timeout", transient=True, now=at(hour))
    state["phase"] = "ROLLED_BACK"
    assert state["failed_shas"] == []
    assert updates._retry_review_required(state)
    monkeypatch.setattr(updates, "now_utc", lambda: at(24))
    assert not updates._retry_review_required(state)


def test_the_real_generic_helper_stdout_keeps_an_unknown_preparation_retry(tmp_path, monkeypatch):
    import json
    import subprocess
    from types import SimpleNamespace
    case = _preparation_case(tmp_path, monkeypatch, RuntimeError())
    output = 'CONTAINER_AUDIT_UPDATE=' + json.dumps({
        "status": "FAILED", "stage": "startup_update", "reason_code": "STARTUP_UPDATE_FAILURE",
        "exit_code": 1, "report_status": "REPORT_UNAVAILABLE"})
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout=output, stderr=""))
    monkeypatch.setattr(updates, "system_executable", lambda *a: tmp_path / "powershell.exe")
    monkeypatch.setattr(updates, "_apply_prepared", lambda control: updates._run_fixed_helper(control, "Verify"))
    assert case.run() == 0
    assert case.state().get("failed_shas", []) == []
    assert case.state()["retry_shas"][NEW]["attempts"] == 1
    case.clock[0] = 899
    assert not updates.prepared_pending(case.control, case.policy, case.state())
    case.clock[0] = 900
    assert updates.prepared_pending(case.control, case.policy, case.state())



def test_a_new_day_budget_takes_precedence_over_a_recent_attempt_interval(tmp_path, monkeypatch):
    case = _preparation_case(tmp_path, monkeypatch, TimeoutError())
    last = at(24 - 1 / 60)
    state = {"schema": updates.SCHEMA, "phase": "DEFERRED", "reason_code": "UPDATE_PREPARATION_FAILED",
             "deferred_at": last, "retry_shas": {NEW: {"attempts": 3, "first_at": at(0), "last_at": last}}}
    case.files[case.control / "transition.json"] = state
    case.clock[0] = 24 * 3600 - 1
    assert not updates.prepared_pending(case.control, case.policy, state)
    case.clock[0] = 24 * 3600
    assert updates.prepared_pending(case.control, case.policy, state)
    assert case.run() == 0
    assert case.state().get("failed_shas", []) == []
    assert case.state()["retry_shas"][NEW] == {"attempts": 1, "first_at": at(24), "last_at": at(24)}



def test_an_inherited_ready_timeout_records_a_chance_without_permanent_rejection(world, monkeypatch, tmp_path):
    w = world
    pend_candidate(w, monkeypatch, tmp_path)
    pending = updates.apply_transition(w.state(), writers_absent=True, packet_verified=True,
                                       durable_prepared=True, now=w.now())
    w.files[w.control / "transition.json"] = pending
    w.files[w.control / "active.json"] = {"schema": updates.SCHEMA, "sha": w.candidate}
    w.clock += 600
    assert w.system() == 0
    assert w.state()["phase"] == "ROLLED_BACK" and w.active() == w.previous
    assert w.state()["failure_decision"]
    assert w.state()["retry_shas"][w.candidate]["attempts"] == 1
    assert w.state()["failed_shas"] == []
