"""The durable candidate and rollback READY windows share one 900-second bound."""
import ast
import copy
import json
from pathlib import Path

import pytest

import auto_update as updates
from kmtech_shared import data_generation as generation
from tests.test_auto_update_recovery_integrity import world
from tests.test_auto_update_trial_supervision import NEW, OLD, scene, stamp
from tests.test_signed_pairrule import identities, signed


WINDOW_FUNCTIONS = (
    "_ready_window_deadline", "wait_for_rollback_ready", "_apply_prepared_once",
    "bootstrap_supervision_deadline", "_bootstrap",
)


def assert_one_ready_window(tree):
    definitions = [n for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "READY_WINDOW_SECONDS"
                           for t in n.targets)]
    assert len(definitions) == 1
    assert isinstance(definitions[0].value, ast.Constant)
    assert definitions[0].value.value == 900
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for name in WINDOW_FUNCTIONS:
        nodes = list(ast.walk(functions[name]))
        assert not any(isinstance(n, ast.Constant) and n.value == 120 for n in nodes)
        assert sum(isinstance(n, ast.Name) and n.id == "READY_WINDOW_SECONDS"
                   for n in nodes) == 2


def source_tree():
    path = Path(updates.__file__)
    assert path.stat().st_size < 1024 * 1024
    return ast.parse(path.read_text(encoding="utf-8-sig"))


def test_ready_window_sites_use_one_named_constant():
    assert_one_ready_window(source_tree())


@pytest.mark.parametrize("site", range(10))
def test_one_stale_window_site_is_rejected(site):
    tree = source_tree()
    assert_one_ready_window(tree)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    references = [n for name in WINDOW_FUNCTIONS for n in ast.walk(functions[name])
                  if isinstance(n, ast.Name) and n.id == "READY_WINDOW_SECONDS"]
    selected = references[site]

    class StaleSite(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(120), node) if node is selected else node

    with pytest.raises(AssertionError):
        assert_one_ready_window(StaleSite().visit(tree))


@pytest.mark.parametrize("rollback", [False, True], ids=["candidate", "rollback"])
def test_lock_retry_keeps_the_original_window_after_120_seconds(scene, rollback):
    s = scene
    if rollback:
        s.state.update(phase="ROLLBACK_PENDING_READY", rollback_at=stamp(0))
        s.write(s.control / "transition.json", s.state)
    s.clock[0] = 180
    assert updates._ready_window_deadline(s.control) == updates.READY_WINDOW_SECONDS
    s.clock[0] = updates.READY_WINDOW_SECONDS
    assert updates._ready_window_deadline(s.control) is None


@pytest.mark.parametrize("rollback", [False, True], ids=["candidate", "rollback"])
def test_supervision_uses_the_same_durable_window(scene, rollback):
    state = dict(scene.state)
    if rollback:
        state.update(phase="ROLLBACK_PENDING_READY", rollback_at=stamp(0))
    assert updates.bootstrap_supervision_deadline(
        state, started=0, now=180, utc_now=stamp(180)) == (updates.READY_WINDOW_SECONDS + 15)


def test_candidate_ready_at_180_seconds_confirms_instead_of_rolling_back(world, monkeypatch, tmp_path):
    w = world
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
        transition_id="9" * 32, nonce="a" * 32, now=w.now())
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
    snapshot = updates.process_snapshot
    started = w.clock

    def delayed_candidate(*args):
        if w.state()["phase"] == "APPLIED_PENDING_READY" and w.clock - started >= 180:
            w.ready()
        return snapshot(*args)

    monkeypatch.setattr(updates, "process_snapshot", delayed_candidate)
    w.auto_ready = True  # A failed candidate also exercises the real rollback consumer.
    rc = w.system()
    (tmp_path / "ready240-candidate-observed.json").write_text(json.dumps({
        "rc": rc, "phase": w.state()["phase"], "active": w.active(),
        "elapsed": w.clock - started, "applied_at": w.state()["applied_at"],
        "rollback_at": w.state().get("rollback_at"),
    }), encoding="utf-8")
    assert rc == 0
    assert w.state()["phase"] == "CONFIRMED"
    assert w.active() == w.candidate
    assert w.clock - started == 180


def test_rollback_ready_at_180_seconds_uses_the_original_rollback_anchor(scene):
    s = scene
    state = {**s.state, "phase": "ROLLBACK_PENDING_READY", "rollback_at": stamp(0)}
    s.write(s.control / "transition.json", state)
    s.write(s.control / "active.json", {"schema": updates.SCHEMA, "sha": OLD})
    s.rows.extend(dict(pid=pid, observable=True, sha=OLD, sid=s.policy["operator_sid"],
                       role=role, ordinary_user=True, created_at=stamp(0))
                  for pid, role in [(101, "gui"), (102, "relay")])
    s.write(s.stage / "ready.json", {**{k: True for k in updates.READY_CHECKS},
        "pid": 101, "nonce": state["nonce"], "transition_id": state["transition_id"],
        "sha": OLD, "ready_at": stamp(180)})
    s.clock[0] = 180
    assert updates.wait_for_rollback_ready(s.control, s.policy) == 0
    result = updates.read_json(s.control / "transition.json")
    assert result["phase"] == "ROLLED_BACK"
    assert result["rollback_at"] == stamp(0)
    assert s.clock[0] == 180


@pytest.mark.parametrize("role", ["gui", "relay"])
def test_bootstrap_launches_one_trial_and_relay_after_120_seconds(scene, monkeypatch, role):
    s = scene
    (s.stage / "trial.json").unlink()
    s.clock[0] = 180
    launch = updates.launch_version
    deadlines = []
    relay = updates._bootstrap_trial_relay

    def bounded_relay(*args, **kwargs):
        deadlines.append(kwargs["deadline"])
        return relay(*args, **kwargs)

    def start(control, sha, arguments, **kwargs):
        pid = launch(control, sha, arguments, **kwargs)
        is_relay = arguments[:1] == ["--container-audit-user-relay"]
        s.rows.append(dict(pid=pid, observable=True, sha=sha, sid=s.policy["operator_sid"],
                           role="relay" if is_relay else "gui", ordinary_user=True,
                           created_at=stamp(s.clock[0])))
        if is_relay:
            state = updates.read_json(s.control / "transition.json")
            proof = {**{k: True for k in updates.READY_CHECKS}, "pid": 101,
                "nonce": state["nonce"], "transition_id": state["transition_id"],
                "sha": NEW, "ready_at": stamp(s.clock[0])}
            _, confirmed, _ = updates.observe_trial_ready(s.control, s.policy, state,
                s.rows, {"pid": 101, "nonce": state["nonce"],
                         "transition_id": state["transition_id"]}, proof, deadline=updates.READY_WINDOW_SECONDS)
            assert confirmed
        return pid

    monkeypatch.setattr(updates, "_bootstrap_trial_relay", bounded_relay)
    monkeypatch.setattr(updates, "launch_version", start)
    arguments = ["--container-audit-user-relay"] if role == "relay" else []
    assert updates._bootstrap(s.control.parent, arguments, role=role) == 0
    assert updates.read_json(s.control / "transition.json")["phase"] == "CONFIRMED"
    assert len(s.launches) == 2
    assert deadlines == [updates.READY_WINDOW_SECONDS]
