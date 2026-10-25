"""The real bootstrap waits for a live SYSTEM owner without renewing READY."""
import contextlib
import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import pytest

import auto_update as updates
from tests.test_auto_update_trial_supervision import NEW, OLD, START_CURRENT, scene, stamp


LAUNCH_BODY = getattr(updates.launch_version, "__wrapped__", updates.launch_version)


def world(scene, monkeypatch, *, decision=True, final_claim="ABSENT", repeated_busy=False,
          ready_phase="APPLIED_PENDING_READY", terminal="DEFERRED", normal_stop=True,
          terminal_at_old_end=False, applied=110.941488, initial_missing=False,
          decision_at=None, released_at=None, claim_boundary=None):
    s = scene
    ready_end = applied + 240
    old_end = ready_end + 15
    stop = ready_end + 1.699512
    decided = ready_end + 17.672191 if decision else float("inf")
    released = ready_end + 38.605512 if decision else float("inf")
    if terminal_at_old_end:
        decided = released = old_end
    if decision_at is not None:
        decided = decision_at
    if released_at is not None:
        released = released_at
    unlocked = released
    (s.stage / "trial.json").unlink()
    initial = {**s.state, "phase": "PREPARED"}
    s.write(s.control / "transition.json", initial)
    if initial_missing:
        (s.control / "transition.json").unlink()
    current_sha = OLD if ready_phase == "ROLLBACK_PENDING_READY" else NEW
    popens, denials, progress, consumed = [], [], [], set()

    def sync():
        now = s.clock[0]
        if now >= applied and "applied" not in consumed:
            consumed.add("applied")
            state = {**s.state, "phase": ready_phase, "applied_at": stamp(applied)}
            if ready_phase == "ROLLBACK_PENDING_READY":
                state.update(rollback_at=stamp(applied), failure_decision={"selected_sha": OLD})
            s.write(s.control / "active.json", {"schema": updates.SCHEMA, "sha": current_sha})
            s.write(s.control / "transition.json", state)
        if now >= stop and "stop" not in consumed:
            consumed.add("stop")
            state = updates.read_json(s.control / "transition.json")
            # This is the real X sequence: normal-stop decision precedes Observe.
            if normal_stop and ready_phase == "APPLIED_PENDING_READY" and terminal == "DEFERRED":
                state.update(phase="ROLLBACK_PENDING", normal_stop_started_at=stamp(stop))
                s.write(s.control / "transition.json", state)
        if now >= decided and "decided" not in consumed:
            consumed.add("decided")
            state = updates.read_json(s.control / "transition.json")
            state.update(phase=terminal)
            if terminal == "DEFERRED":
                state.update(retained_candidate=True, failure_decision={
                    "selected_sha": NEW, "code": "TRIAL_GENERATION_ADVANCED"})
            s.write(s.control / "transition.json", state)
            s.rows.clear()

    events = [applied, ready_end, stop, old_end, decided, released, 480]
    if claim_boundary is not None:
        events.append(claim_boundary)

    def advance_to(target):
        for point in sorted({point for point in events if s.clock[0] < point <= target}):
            s.clock[0] = point
            sync()
        s.clock[0] = target
        sync()

    def sleep(seconds):
        # Preserve the existing poll interval and hit each SYSTEM event exactly.
        target = s.clock[0] + seconds
        next_event = min((point for point in events if point > s.clock[0]), default=target)
        advance_to(min(target, next_event))

    def claim(*_):
        boundary = old_end if claim_boundary is None else claim_boundary
        if final_claim in {"ABSENT", "UNKNOWN"} and not decision and s.clock[0] >= boundary:
            return final_claim
        return "ABSENT" if s.clock[0] >= released else "LIVE"

    @contextlib.contextmanager
    def startup_lock(*args, deadline, **kwargs):
        if stop <= s.clock[0] < unlocked:
            target = min(deadline, unlocked)
            if repeated_busy and s.clock[0] >= old_end:
                target = min(target, s.clock[0] + 1)
            advance_to(max(s.clock[0], target))
            acquired = s.clock[0] >= unlocked
            if not acquired:
                denials.append(s.clock[0])
            yield acquired
        else:
            yield True

    def popen(command, **kwargs):
        relay = "--container-audit-user-relay" in command
        trial = bool(kwargs["env"].get("KMTECH_CA_UPDATE_TRIAL_NONCE"))
        popens.append({"at": s.clock[0], "relay": relay, "trial": trial})
        pid = (102 if relay else 101) if trial else (202 if relay else 201)
        if trial:
            s.rows.append({**s.relay(current_sha), "pid": pid,
                           "role": "relay" if relay else "gui"})
        assert kwargs["creationflags"] & subprocess.CREATE_NO_WINDOW
        return SimpleNamespace(pid=pid)

    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(updates, "apply_claim_status", claim)
    monkeypatch.setattr(updates, "startup_update_lock", startup_lock)
    monkeypatch.setattr(updates, "start_current", START_CURRENT)
    # Native admission/identity is supplied by scene; exercise the real Popen body.
    monkeypatch.setattr(updates, "launch_version", LAUNCH_BODY)
    monkeypatch.setattr(updates, "version_bundle", lambda *_: s.control / current_sha)
    monkeypatch.setattr(updates, "version_manifest", lambda *_: {"source_commit": current_sha})
    monkeypatch.setattr(updates, "emit_progress_guidance", lambda: progress.append(s.clock[0]))
    monkeypatch.setattr(subprocess, "Popen", popen)
    return SimpleNamespace(**locals())


def ordinary(w):
    return [row for row in w.popens if not row["trial"]]


@pytest.mark.parametrize("role", ["gui", "relay"])
def test_live_apply_finishes_after_stage_deadline_and_opens_original_role(scene, monkeypatch, role):
    w = world(scene, monkeypatch)
    arguments = ["--container-audit-user-relay"] if role == "relay" else []
    result = updates._bootstrap(w.s.control.parent, arguments, role=role)
    observed = {"rc": result, "finished": w.s.clock[0], "ordinary_popens": ordinary(w),
                "original_supervision_end": w.old_end, "SYSTEM_release": w.released}
    (w.s.control / "live-apply-observed.json").write_text(json.dumps(observed), encoding="utf-8")
    assert result == 0
    assert len(ordinary(w)) == 1
    assert ordinary(w)[0]["relay"] is (role == "relay")
    # The unchanged protected poll discards an observation at its expired old
    # deadline, sleeps once, then takes the unchanged final START_CURRENT path.
    assert ordinary(w)[0]["at"] == pytest.approx(w.released + 0.1)
    assert w.s.clock[0] == pytest.approx(w.released + 0.1)
    assert not w.progress


def test_live_apply_does_not_break_on_lock_busy_during_extension(scene, monkeypatch):
    w = world(scene, monkeypatch, repeated_busy=True)
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 0
    assert len(ordinary(w)) == 1
    assert any(w.old_end < denied < w.released for denied in w.denials)


@pytest.mark.parametrize("phase,normal_stop", [
    ("APPLIED_PENDING_READY", False),
    ("APPLIED_PENDING_READY", True),
    ("ROLLBACK_PENDING_READY", False),
])
def test_live_apply_never_decides_stops_at_existing_480_cap(scene, monkeypatch, phase, normal_stop):
    w = world(scene, monkeypatch, decision=False, final_claim="LIVE",
              ready_phase=phase, normal_stop=normal_stop)
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 20
    assert w.s.clock[0] == 480
    assert w.progress == [480]
    assert ordinary(w) == []


@pytest.mark.parametrize("claim", ["ABSENT", "UNKNOWN"])
def test_nonlive_claim_keeps_the_existing_timeout_exit(scene, monkeypatch, claim):
    w = world(scene, monkeypatch, decision=False, final_claim=claim)
    result = updates._bootstrap(w.s.control.parent, [], role="gui")
    (w.s.control / "nonlive-observed.json").write_text(json.dumps({
        "rc": result, "finished": w.s.clock[0], "old_end": w.old_end,
        "progress": w.progress, "ordinary_popens": ordinary(w), "claim": claim,
    }), encoding="utf-8")
    assert result == 20
    # UTC anchors have microsecond precision; binary float subtraction need not
    # reproduce an exactly equal representation of the same deadline.
    assert w.s.clock[0] == pytest.approx(w.old_end, rel=0, abs=1e-6)
    assert w.progress == pytest.approx([w.old_end], rel=0, abs=1e-6)
    assert ordinary(w) == []


def test_already_terminal_record_does_not_extend_supervision(scene, monkeypatch):
    w = world(scene, monkeypatch, terminal_at_old_end=True)
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 0
    assert len(ordinary(w)) == 1
    assert w.s.clock[0] == pytest.approx(w.old_end + 0.1)


@pytest.mark.parametrize("initial_missing", [False, True], ids=["PREPARED", "missing"])
def test_live_preapply_owner_finishes_and_opens_app_in_same_attempt(scene, monkeypatch, initial_missing):
    w = world(scene, monkeypatch, applied=260, initial_missing=initial_missing,
              terminal="CONFIRMED", normal_stop=False, decision_at=280, released_at=281)
    result = updates._bootstrap(w.s.control.parent, [], role="gui")
    w.s.write(w.s.control / "preapply-finished.json", {
        "rc": result, "finished": w.s.clock[0], "decision_at": w.decided,
        "popens": w.popens,
    })
    assert result == 0
    assert any(row["trial"] and not row["relay"] for row in w.popens)
    # The existing protected poll observes the terminal phase with its expired
    # original deadline, then takes its existing final read after one 0.1s sleep.
    assert w.s.clock[0] == pytest.approx(w.decided + 0.1, rel=0, abs=1e-6)
    assert not w.progress


@pytest.mark.parametrize("initial_missing", [False, True], ids=["PREPARED", "missing"])
def test_preapply_without_live_claim_keeps_original_exit(scene, monkeypatch, initial_missing):
    w = world(scene, monkeypatch, applied=600, initial_missing=initial_missing,
              decision=False, final_claim="ABSENT", claim_boundary=240)
    result = updates._bootstrap(w.s.control.parent, [], role="gui")
    observed = {"rc": result, "finished": w.s.clock[0], "popens": w.popens}
    (w.s.control / "preapply-absent-observed.json").write_text(json.dumps(observed), encoding="utf-8")
    assert w.s.clock[0] == pytest.approx(240)
    assert result == (0 if initial_missing else 20)
    assert len(ordinary(w)) == (1 if initial_missing else 0)


@pytest.mark.parametrize("initial_missing", [False, True], ids=["PREPARED", "missing"])
def test_live_preapply_owner_never_exceeds_existing_480_cap(scene, monkeypatch, initial_missing):
    w = world(scene, monkeypatch, applied=600, initial_missing=initial_missing,
              decision=False, final_claim="LIVE")
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 20
    assert w.s.clock[0] == pytest.approx(480)
    assert w.popens == []


@pytest.mark.parametrize("claim", ["UNKNOWN", "ABSENT"])
def test_busy_extension_rechecks_live_claim_each_poll(scene, monkeypatch, claim):
    w = world(scene, monkeypatch, decision=False, final_claim=claim, repeated_busy=True,
              claim_boundary=366.941488)
    assert updates._bootstrap(w.s.control.parent, [], role="gui") == 20
    # The claim can change during the mocked one-second root-lock wait.
    # Recheck at its first completed busy poll, rather than at the event instant.
    first_nonlive_poll = min(t for t in w.denials if t >= w.claim_boundary)
    assert w.s.clock[0] == pytest.approx(first_nonlive_poll, rel=0, abs=1e-6)
    assert w.s.clock[0] < 480
    assert ordinary(w) == []
    assert any(w.old_end < denied for denied in w.denials)
