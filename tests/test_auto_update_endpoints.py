"""D-16 S/E1-E9: real updater journals and ordinary child admission."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

import auto_update as updates
from kmtech_shared import data_generation as generation
import writer_session_fence as fence

OLD, NEW = "1" * 40, "2" * 40
SID = "S-1-5-21-458"
REPO = Path(updates.__file__).parent
NATIVE_SLEEP = time.sleep


@pytest.fixture
def endpoint(monkeypatch, tmp_path):
    control, stage = tmp_path / "update-control", tmp_path / "stage"
    control.mkdir(); stage.mkdir()
    local = tmp_path / "local"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    policy = dict(operator_sid=SID, operator_local_app_data=str(local),
                  staging_root=str(stage), feed_url="https://example.test/feed", channel="stable")
    updates.write_json_durable(control / "policy.json", policy)
    updates.write_json_durable(control / "active.json", {"schema": updates.SCHEMA, "sha": NEW})
    versions = {OLD: "v2.0.98", NEW: "v2.0.99"}
    for sha, version in versions.items():
        bundle = updates.version_bundle(control, sha)
        (bundle / "app").mkdir(parents=True)
        for name in (*updates.CONTRACT_FILES, *("app/" + name for name in updates.DATA_API_FILES)):
            target = bundle / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / name.removeprefix("app/")).read_bytes())
        (bundle / "app/Container_Audit.py").write_text(f'CURRENT_VERSION = "{version}"\n')
        updates.write_json_durable(bundle / "portable-manifest.json", {
            "schema": "container-audit-portable-tree-v1", "startup_update_protocol": 1,
            "source_commit": sha, "version": version,
            "writer_sink_inventory_contract_sha256": "a" * 64})
    marker = fence.canonical_control_root({"LOCALAPPDATA": str(local)}) / "data-generation" / (SID + ".json")
    marker.parent.mkdir(parents=True, exist_ok=True)
    generation.record_generation(marker, versions[OLD], app_id="container_audit", subject_sid=SID, build_id=OLD)
    state = updates.prepare_transition(previous_sha=OLD, candidate_sha=NEW, packet_sha256="3" * 64,
        forward_pin="4" * 64, rollback_pin="5" * 64, transition_id="6" * 32,
        nonce="7" * 32, now=updates.now_utc())
    state.update(generation_before=updates.read_trial_generation(policy),
        generation_previous_release={"version": versions[OLD], "source_commit": OLD},
        generation_candidate_release={"version": versions[NEW], "source_commit": NEW})
    state = updates.apply_transition(state, writers_absent=True, packet_verified=True,
                                    durable_prepared=True, now=updates.now_utc())
    updates.write_json_durable(control / "transition.json", state)
    monkeypatch.setattr(updates, "control_root", lambda *_: control)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_: True)
    monkeypatch.setattr(updates, "fixed_helper", lambda *a, **k: "")
    monkeypatch.setattr(updates, "update_lock", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [])
    monkeypatch.setattr(updates, "request_apply_task", lambda *_: updates.apply_prepared(control))
    # Time is an OS boundary. No production test hook is added.
    ticks = iter(range(0, 1000000))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    child_source = '''import contextlib, json, os, sys
from pathlib import Path
sys.path.insert(0, REPO_PATH)
import auto_update as u
from kmtech_shared import data_generation as g
control = Path(CONTROL_PATH)
policy = u.read_json(control / "policy.json")
u.control_root = lambda *_: control
u.ordinary_user_context = lambda *_: True
u.runtime_matches = lambda *_: True
u.update_lock = lambda *a, **k: contextlib.nullcontext()
u.process_snapshot = lambda *_: []
u.request_bootstrap = lambda *a, **k: None
sha = Path(__file__).parent.parent.name
gate = u.startup_gate(Path(__file__).parent, sys.argv[1:])
release = u.version_manifest(Path(__file__).parent.parent)
observed = u.read_trial_generation(policy)
decision = g.probe_downgrade([observed["marker_path"]], release["version"],
    app_id="container_audit", subject_sid=policy["operator_sid"], target_build_id=sha)
Path(RESULT_PATH).write_text(json.dumps(dict(sha=sha, gate=gate, status=decision["status"],
    ordinary=not bool(os.environ.get("KMTECH_CA_UPDATE_TRIAL_NONCE")),
    relay="--container-audit-user-relay" in sys.argv, pid=os.getpid())))
'''
    observation = tmp_path / "ordinary-child.json"
    for sha in versions:
        source = child_source.replace("REPO_PATH", repr(str(REPO))).replace("CONTROL_PATH", repr(str(control))).replace("RESULT_PATH", repr(str(observation)))
        (updates.version_bundle(control, sha) / "app/main.py").write_text(source)
    popen = subprocess.Popen
    def native_launch(command, **kwargs):
        command = [sys.executable, "-B", *command[3:]]
        child = popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        out, err = child.communicate(timeout=30)
        assert child.returncode == 0, err[-1500:]
        return child
    native_launch.native = popen
    monkeypatch.setattr(subprocess, "Popen", native_launch)
    return control, stage, policy, state, marker, observation


def assert_ordinary(endpoint, expected, *, role="gui", arguments=None):
    control, _, _, _, _, observation = endpoint
    assert updates.bootstrap(control.parent / "current/app", arguments or [], role=role) == 0
    assert observation.exists(), "next bootstrap did not launch any version"
    result = json.loads(observation.read_text())
    assert result["sha"] == expected
    assert result["gate"] is None, result
    assert result["status"] == "ALLOW", result
    assert result["ordinary"] is True, result


@pytest.mark.parametrize("phase", ["FAILED", "UNKNOWN"])
def test_x1_x3_terminal_next_start_really_launches_allowed_version(endpoint, phase):
    control, _, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": phase})
    assert_ordinary(endpoint, NEW)


def test_x1_x2_rollback_does_not_retest_confirmed_previous_ready(endpoint):
    control, _, _, _, _, _ = endpoint
    updates.apply_prepared(control)  # No bootstrap is present to publish READY.
    assert updates.read_json(control / "transition.json")["phase"] == "ROLLED_BACK"
    assert_ordinary(endpoint, OLD)


@pytest.mark.parametrize("failure", ["task", "no_progress", "authority"])
def test_x4_prepared_failure_launches_current(endpoint, monkeypatch, failure):
    control, stage, _, _, _, _ = endpoint
    (control / "transition.json").unlink()
    updates.write_json_durable(control / "active.json", {"sha": OLD})
    updates.write_json_durable(stage / "prepared.json", {"source_commit": NEW})
    if failure == "task":
        def failed(*_):
            raise OSError("synthetic task request failure")
        monkeypatch.setattr(updates, "request_apply_task", failed)
    elif failure == "no_progress":
        monkeypatch.setattr(updates, "request_apply_task", lambda *_: None)
    else:
        def authority(*a, **k):
            raise OSError("synthetic authority failure")
        monkeypatch.setattr(updates, "fixed_helper", authority)
    assert_ordinary(endpoint, OLD)


@pytest.mark.parametrize("role", ["gui", "relay"])
def test_e7_retained_candidate_starts_in_same_bootstrap(endpoint, role):
    control, _, _, state, marker, _ = endpoint
    generation.record_generation(marker, "v2.0.99", app_id="container_audit", subject_sid=SID, build_id=NEW)
    # Start in the trial so this same bootstrap has saw_trial=True before
    # SYSTEM retains candidate. A fresh bootstrap alone misses the old E7 bug.
    updates.write_json_durable(control / "transition.json", state)
    arguments = ["--container-audit-user-relay"] if role == "relay" else []
    assert_ordinary(endpoint, NEW, role=role, arguments=arguments)
    assert json.loads(endpoint[-1].read_text())["relay"] is False


def test_x7_terminal_recovery_reopens_prepared_path(endpoint):
    control, _, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": "UNKNOWN"})
    assert updates.apply_prepared(control) == 0
    assert updates.read_json(control / "transition.json")["phase"] == "ROLLED_BACK"
    assert updates.startup_action(updates.read_json(control / "transition.json"), prepared_present=True) == "REQUEST_APPLY"


def test_x3_hung_writer_is_preserved_then_recovered_after_logon(endpoint, monkeypatch):
    control, _, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": "UNKNOWN"})
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [{"pid": 456, "observable": False}])
    assert updates.apply_prepared(control) == 20
    assert updates.read_json(control / "active.json")["sha"] == NEW
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [])
    assert updates.apply_prepared(control) == 0
    assert_ordinary(endpoint, OLD)


def test_e9_startup_report_contains_only_allowed_codes(endpoint):
    control, stage, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": "FAILED"})
    assert_ordinary(endpoint, NEW)
    report = json.loads((stage / "startup-support.json").read_text())
    assert report["transition_code"] in updates.PUBLIC_CODES
    assert report["retained_candidate"] is False
    assert "nonconforming_fields" not in report


@pytest.mark.parametrize("defect", ["none", "phase", "pointer", "generation", "old_writer", "unobservable", "cohort"])
def test_terminal_ordinary_admission_requires_every_condition(endpoint, monkeypatch, defect):
    control, _, policy, state, marker, _ = endpoint
    stamp = updates.now_utc()
    state = {**state, "phase": "FAILED"}
    if defect == "phase":
        state["phase"] = "ROLLBACK_PENDING"
    updates.write_json_durable(control / "transition.json", state)
    monkeypatch.setattr(updates, "runtime_matches", lambda *_: True)
    if defect == "pointer":
        updates.write_json_durable(control / "active.json", {"sha": OLD})
    if defect == "generation":
        marker.write_bytes(b"{broken-marker")
    if defect in {"old_writer", "unobservable", "cohort"}:
        row = dict(pid=456, observable=defect != "unobservable", sha=NEW, sid=SID,
                   ordinary_user=True, role="relay", created_at=stamp if defect == "cohort" else "2026-01-01T00:00:00Z")
        monkeypatch.setattr(updates, "process_snapshot", lambda *_: [row])
    monkeypatch.setenv("KMTECH_CA_UPDATE_DEFERRED_AT", stamp)
    monkeypatch.setattr(updates, "request_bootstrap", lambda *a, **k: None)
    # startup_gate is the actual CA consumer. assert_version_writer has none.
    call = lambda: updates.startup_gate(updates.version_bundle(control, NEW) / "app", [])
    if defect in {"none", "cohort"}:
        assert call() is None
    else:
        if defect in {"phase", "pointer"}:
            assert call() == 0  # Routed to bootstrap, never ordinary admission.
        else:
            with pytest.raises((ValueError, OSError)):
                call()


def test_e1_stalled_prepared_journal_uses_locked_ordinary_start(endpoint, monkeypatch):
    control, stage, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": "PREPARED"})
    updates.write_json_durable(control / "active.json", {"sha": OLD})
    updates.write_json_durable(stage / "prepared.json", {"source_commit": NEW})
    monkeypatch.setattr(updates, "request_apply_task", lambda *_: None)
    assert_ordinary(endpoint, OLD)


@pytest.mark.parametrize("record", ["policy.json", "active.json"])
def test_e2_read_failure_is_recorded_before_next_normal_start(endpoint, monkeypatch, record):
    control, stage, _, _, _, _ = endpoint
    (control / "transition.json").unlink()
    updates.write_json_durable(control / "active.json", {"sha": OLD})
    read = updates.read_json
    def denied(path, **kwargs):
        if path.name == record:
            raise PermissionError("synthetic protected read failure")
        return read(path, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(updates, "read_json", denied)
        assert updates.apply_prepared(control) == 0
    assert read(control / "transition.json")["phase"] == "DEFERRED"
    assert_ordinary(endpoint, OLD)
    report = updates.read_json(stage / "startup-support.json")
    assert report["transition_code"] in updates.PUBLIC_CODES
    assert report["retained_candidate"] is False


def hotfix_packet(endpoint, monkeypatch, *, base_sha=OLD):
    """Real ES256, archive validation, contract hashing and protected copying."""
    import update_service
    from tests.test_runtime_file_inventory import packet
    from tests.test_signed_pairrule import signed
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair

    control, stage, _, _, _, _ = endpoint
    hot = "8" * 40
    base = updates.version_bundle(control, base_sha)
    with P256KeyPair.generate() as signer:
        public = json.dumps(signer.public_jwk, sort_keys=True)
        configuration = json.dumps({"manifest_public_key": public}).encode()
        (control.parent / "current/app").mkdir(parents=True, exist_ok=True)
        (control.parent / "current/app/update-manifest-key-config.json").write_bytes(configuration)
        def contents(files):
            for path in base.rglob("*"):
                if path.is_file() and path.name != "portable-manifest.json":
                    files[path.relative_to(base).as_posix()] = path.read_bytes()
            stock = json.loads(files["portable-manifest.json"])
            stock.update(updates.read_json(base / "portable-manifest.json"))
            stock.update(source_commit=hot, version="v2.0.100")
            files["portable-manifest.json"] = json.dumps(stock).encode()
            files["app/Container_Audit.py"] = b'CURRENT_VERSION = "v2.0.100"\n'
            files["app/update-manifest-key-config.json"] = configuration
        with packet(file_change=contents) as archive:
            raw = archive.fp.getvalue()
            current = updates.version_manifest(base, require_version=True)
            candidate = updates.version_identity(lambda name: archive.read("Container_Audit/" + name))
        manifest = dict(schema_version="kmtech-private-update-manifest-v1", manifest_version=1,
            signature_version="es256-v1", app_id="Container_Audit", package_id="Container_Audit",
            channel="stable", source_commit=hot, **signed(current, candidate),
            artifact=dict(name="Container_Audit-v2.0.100.zip", url="https://example.test/hotfix.zip",
                          size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
            archive=dict(format="zip", layout="canonical_portable", top_level="Container_Audit",
                         entrypoint="app/main.py", required_files=["Container_Audit/app/main.py"]),
            rollout=dict(percentage=100, allow_pc_ids=[], deny_pc_ids=[]),
            install=dict(strategy="robocopy_backup_then_mirror", preserve_paths=["config", "logs", "ledger"],
                         restart_executable="Container_Audit.exe"))
        manifest["auto_update"]["to_commit"] = hot
        manifest["auto_update"]["from_commit"] = base_sha
        updates.write_json_durable(stage / "manifest.json", manifest)
        (stage / "manifest.sig").write_bytes(signer.sign_es256(update_service.canonical_manifest_bytes(manifest)))
    (stage / "packet.zip").write_bytes(raw)
    updates.write_json_durable(stage / "prepared.json", {"source_commit": hot})
    @contextlib.contextmanager
    def source(path, **kwargs):
        # Only Windows owner/handle acquisition is doubled for the synthetic SID.
        with path.open("rb") as stream:
            yield stream
    monkeypatch.setattr(updates, "unredirected_source", source)
    return hot


@pytest.mark.parametrize("phase", ["FAILED", "UNKNOWN"])
def test_x7_real_signed_hotfix_applies_after_terminal_recovery(endpoint, monkeypatch, phase):
    control, _, _, state, _, _ = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": phase})
    hot = hotfix_packet(endpoint, monkeypatch)
    written = updates.write_json_durable
    def observe(path, value):
        written(path, value)
        if path == control / "active.json" and value.get("sha") == hot:
            raise SystemExit(0)  # Stop the headless OS harness after actual switch.
    monkeypatch.setattr(updates, "write_json_durable", observe)
    with pytest.raises(SystemExit):
        updates.apply_prepared(control)
    assert updates.read_json(control / "active.json")["sha"] == hot
    assert updates.read_json(control / "transition.json")["phase"] == "APPLIED_PENDING_READY"


def test_x2_retained_candidate_is_previous_for_next_signed_failure(endpoint, monkeypatch):
    control, stage, _, _, marker, _ = endpoint
    generation.record_generation(marker, "v2.0.99", app_id="container_audit", subject_sid=SID, build_id=NEW)
    assert updates.apply_prepared(control) == 20
    assert updates.read_json(control / "transition.json")["retained_candidate"] is True
    hot = hotfix_packet(endpoint, monkeypatch, base_sha=NEW)
    assert updates.apply_prepared(control) == 0
    state = updates.read_json(control / "transition.json")
    assert state["candidate_sha"] == hot
    assert state["previous_sha"] == NEW
    assert state["phase"] == "ROLLED_BACK"
    assert not (stage / "ready.json").exists()
    assert_ordinary(endpoint, NEW)


def test_e8_unknown_generation_does_not_begin_a_trial(endpoint, monkeypatch):
    control, _, _, _, marker, _ = endpoint
    (control / "transition.json").unlink()
    updates.write_json_durable(control / "active.json", {"sha": OLD})
    hotfix_packet(endpoint, monkeypatch)
    marker.write_bytes(b"{unreadable-generation")
    assert updates.apply_prepared(control) == 0
    assert updates.read_json(control / "active.json")["sha"] == OLD
    state = updates.read_json(control / "transition.json")
    assert state["phase"] == "DEFERRED"
    assert state["reason_code"] == "UPDATE_GENERATION_UNKNOWN"


def test_e1_busy_update_lock_reports_fixed_progress_guidance(endpoint, monkeypatch, capsys):
    control, _, _, _, _, _ = endpoint
    @contextlib.contextmanager
    def busy(*a, **k):
        raise RuntimeError("update mutex ownership is busy or abandoned")
        yield
    monkeypatch.setattr(updates, "update_lock", busy)
    assert updates.bootstrap(control.parent / "current/app", [], role="gui") == 20
    report = json.loads(capsys.readouterr().out)
    assert report["reason_code"] == "UPDATE_IN_PROGRESS"
    assert report["guidance"] in updates.SAFE_MESSAGES


@pytest.mark.parametrize("failure", ["task", "no_progress"])
def test_applied_trial_exit_without_system_still_starts_active(endpoint, monkeypatch, failure):
    control, stage, _, state, _, _ = endpoint
    # A stale claim proves no live writer; the native snapshot is empty.
    updates.write_json_durable(stage / "trial.json", {"pid": 456, "nonce": state["nonce"],
                                                        "transition_id": state["transition_id"]})
    def unavailable(*_):
        if failure == "task":
            raise OSError("synthetic SYSTEM task failure")
    monkeypatch.setattr(updates, "request_apply_task", unavailable)
    original = (control / "transition.json").read_bytes()
    assert_ordinary(endpoint, NEW)
    assert (control / "transition.json").read_bytes() == original
    assert updates.read_json(stage / "startup-support.json")["reason_code"] == "UPDATE_SUPERVISION_UNAVAILABLE"


def test_system_return_defers_to_ordinary_active_writer_without_confirmation(endpoint, monkeypatch):
    control, _, _, _, _, _ = endpoint
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [dict(pid=456, observable=True,
        sha=NEW, sid=SID, ordinary_user=True, role="gui", created_at=updates.now_utc())])
    assert updates.apply_prepared(control) == 0
    state = updates.read_json(control / "transition.json")
    assert state["phase"] == "DEFERRED"
    assert state["reason_code"] == "UPDATE_EXISTING_WRITER"
    assert updates.read_json(control / "active.json")["sha"] == NEW


def test_system_return_with_no_writer_settles_once(endpoint):
    control, _, _, _, _, _ = endpoint
    assert updates.apply_prepared(control) == 0
    original = (control / "transition.json").read_bytes()
    assert updates.read_json(control / "transition.json")["phase"] == "ROLLED_BACK"
    assert updates.apply_prepared(control) == 0
    assert (control / "transition.json").read_bytes() == original


@pytest.mark.parametrize("first", ["admission", "apply"])
def test_e1_pointer_switch_and_ordinary_launch_exclude_competing_versions(endpoint, monkeypatch, first):
    """Real bootstrap/apply/ES256/children; OS mutex and Observe are adapters."""
    control, _, policy, state, _, observation = endpoint
    updates.write_json_durable(control / "transition.json", {**state, "phase": "FAILED"})
    updates.write_json_durable(control / "active.json", {"sha": OLD})
    hot = hotfix_packet(endpoint, monkeypatch)
    release = control.parent / "release-children"
    bundle = updates.version_bundle(control, OLD)
    # Keep the real child alive so Observe cannot mistake an exited PID for a writer.
    held = '\nimport time\nwhile not Path(' + repr(str(release)) + ').exists(): time.sleep(0.01)\n'
    (bundle / "app/main.py").write_text((bundle / "app/main.py").read_text() + held)
    # Re-sign the packet with the same held entrypoint for the candidate.
    hot = hotfix_packet(endpoint, monkeypatch)
    mutex = threading.RLock()
    @contextlib.contextmanager
    def locked(*a, **k):
        with mutex:
            yield
    monkeypatch.setattr(updates, "update_lock", locked)
    monkeypatch.setattr(time, "sleep", lambda _: NATIVE_SLEEP(0.01))
    native = subprocess.Popen.native
    children, rows, outcomes = [], [], []
    admitted = threading.Event()
    def launch(command, **kwargs):
        sha = Path(command[3]).parent.parent.name
        child = native([sys.executable, "-B", *command[3:]], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, **kwargs)
        children.append(child)
        rows.append(dict(pid=child.pid, observable=True, sha=sha, sid=SID, ordinary_user=True,
            role="relay" if "--container-audit-user-relay" in command else "gui", created_at=updates.now_utc()))
        if sha == OLD:
            admitted.set()
        return child
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [row for row, child in zip(rows, children) if child.poll() is None])
    written = updates.write_json_durable
    def crash_after_switch(path, value):
        written(path, value)
        if path == control / "active.json" and value.get("sha") == hot:
            raise SystemExit(0)  # Native SYSTEM loss immediately after durable switch.
    monkeypatch.setattr(updates, "write_json_durable", crash_after_switch)
    def system():
        try:
            if first == "admission":
                assert admitted.wait(30)
            outcomes.append(updates.apply_prepared(control))
        except BaseException as error:
            outcomes.append(error)
    worker = threading.Thread(target=system)
    def request(*_):
        if first == "apply":
            raise OSError("SYSTEM supervisor exited")
        if not worker.is_alive():
            worker.start()
    monkeypatch.setattr(updates, "request_apply_task", request)
    try:
        if first == "apply":
            worker.start(); worker.join(30)
            assert not worker.is_alive()
            assert len(outcomes) == 1 and isinstance(outcomes[0], SystemExit)
        assert updates.bootstrap(control.parent / "current/app", [], role="gui") == 0
        if first == "admission":
            worker.join(30)
            assert not worker.is_alive() and outcomes == [0]
        for _ in range(3000):
            if observation.exists():
                break
            NATIVE_SLEEP(0.01)
        expected = OLD if first == "admission" else hot
        result = json.loads(observation.read_text())
        assert result["sha"] == expected and result["gate"] is None and result["status"] == "ALLOW"
        assert {row["sha"] for row in rows} == {expected}
        assert updates.read_json(control / "active.json")["sha"] == expected
    finally:
        admitted.set()
        release.write_text("normal child exit")
        worker.join(30)
        for child in children:
            _, error = child.communicate(timeout=30)
            assert child.returncode == 0, error[-1000:]


def test_x3_real_hung_trial_remains_alive_until_logoff_then_next_start_works(endpoint, monkeypatch):
    control, stage, _, state, marker, _ = endpoint
    stop = control.parent / "logoff"
    native = subprocess.Popen.native
    script = "from pathlib import Path\nimport time\nwhile not Path(" + repr(str(stop)) + ").exists(): time.sleep(0.01)\n"
    child = native([sys.executable, "-B", "-c", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    stamp = updates.now_utc()
    state = {**state, "trial_pid": child.pid, "trial_sha": NEW, "trial_started_at": stamp}
    updates.write_json_durable(control / "transition.json", state)
    updates.write_json_durable(stage / "trial.json", {"pid": child.pid, "nonce": state["nonce"],
                                                        "transition_id": state["transition_id"]})
    row = dict(pid=child.pid, observable=True, sha=NEW, sid=SID, ordinary_user=True,
               role="gui", created_at=stamp)
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: [row] if child.poll() is None else [])
    before = marker.read_bytes()
    try:
        assert updates.apply_prepared(control) == 20
        assert child.poll() is None
        assert updates.read_json(control / "transition.json")["phase"] == "UNKNOWN"
        assert marker.read_bytes() == before
    finally:
        stop.write_text("normal headless logoff")
        _, error = child.communicate(timeout=30)
        assert child.returncode == 0, error[-1000:]
    assert_ordinary(endpoint, NEW)
    assert updates.apply_prepared(control) == 0
    assert_ordinary(endpoint, OLD)
