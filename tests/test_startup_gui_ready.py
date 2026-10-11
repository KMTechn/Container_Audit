"""Daily GUI-ready evidence is optional and runs outside the screen thread."""
import ast
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from threading import Event, Thread
from types import SimpleNamespace

import pytest

import auto_update as updates
import Container_Audit as app
import current_user_onboarding as onboarding
import startup_check_report as report
import user_relay
import writer_session_fence as fence

READY_AT = "2026-10-12T05:00:00+09:00"
BUILD = "a" * 40


@pytest.fixture(autouse=True)
def report_scope(monkeypatch):
    report.finish()
    monkeypatch.setattr(report, "_GUI_READY_STARTED", False)
    yield
    report.finish()


@pytest.fixture
def folder():
    path = Path(os.environ["PROGRAMDATA"]) / "KMTech/start-check"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def workers(monkeypatch):
    pending = []

    class DeferredThread:
        def __init__(self, *, target, args, name, daemon):
            assert daemon and name == "startup-gui-ready-report"
            self.target, self.args = target, args

        def start(self):
            pending.append(self)

    monkeypatch.setattr(report, "Thread", DeferredThread)
    return pending


@pytest.fixture
def flow(monkeypatch, workers):
    events, callbacks = [], []
    root = SimpleNamespace(after=lambda delay, callback: callbacks.append((delay, callback)),
                           withdraw=lambda: events.append("withdraw"),
                           deiconify=lambda: events.append("deiconify"))

    def run():
        events.append("run")
        assert not workers  # No marker work before the first screen event.
        delay, callback = callbacks.pop(0)
        assert delay == 0
        callback()

    window = SimpleNamespace(root=root, run=run,
                             _finalize_application_close=lambda: events.append("close"))
    lease = SimpleNamespace(release=lambda: events.append("release"))

    def prepare(**_kwargs):
        events.append("prepare")
        app._startup_check_observe("release_identity", {"version": app.CURRENT_VERSION, "build_id": BUILD})
        return window, lease

    monkeypatch.setattr(app, "_prepare_gui_startup", prepare)
    monkeypatch.setattr(app, "dispatch_product_mode", lambda _args: None)
    monkeypatch.setattr(updates, "startup_gate", lambda *_args: None)
    monkeypatch.setattr(updates, "trial_context", lambda *_args: None)
    monkeypatch.setattr(updates, "trial_stop_requested", lambda *_args: False)
    return SimpleNamespace(events=events, callbacks=callbacks, window=window)


def read_marker(folder):
    paths = list(folder.glob("*-CA.gui.json"))
    assert len(paths) == 1 and paths[0].name[:8].isdigit()
    raw = paths[0].read_bytes()
    assert raw.endswith(b"\n") and len(raw.splitlines()) == 1
    result = json.loads(raw)
    assert set(result) == {"schema", "app", "version", "build_sha", "pid", "process_start_utc", "ready_at"}
    assert result["schema"] == "app_gui_ready.v1" and result["app"] == "CA"
    assert result["pid"] == os.getpid()
    started = datetime.fromisoformat(result["process_start_utc"])
    ready = datetime.fromisoformat(result["ready_at"])
    assert started.utcoffset() == timedelta(0)
    assert started <= datetime.now(timezone.utc)
    assert ready.utcoffset() == timedelta(hours=9)
    assert paths[0].name == ready.strftime("%Y%m%d") + "-CA.gui.json"
    assert not list(folder.glob("*.tmp"))
    return result


def test_normal_start_writes_one_public_marker_after_screen_event(folder, flow, workers):
    assert app.main([]) == 0
    assert flow.events == ["prepare", "run", "release"]
    assert not list(folder.glob("*.gui.json")) and len(workers) == 1
    startup_path = next(folder.glob("*-CA.json"))
    startup_bytes = startup_path.read_bytes()
    worker = workers.pop()
    worker.target(*worker.args)
    result = read_marker(folder)
    assert result["version"] == app.CURRENT_VERSION and result["build_sha"] == BUILD
    assert startup_path.read_bytes() == startup_bytes
    report.gui_ready(app.CURRENT_VERSION, BUILD)
    assert not workers  # A trial polling loop cannot rewrite the daily marker.


def test_native_creation_time_is_the_same_process_not_the_ready_callback(folder):
    created = report._process_start_utc()
    report._write_gui_ready(app.CURRENT_VERSION, BUILD, READY_AT)
    result = read_marker(folder)
    assert result["process_start_utc"] == created


def test_atomic_replace_preserves_old_marker_until_complete_json_exists(folder, monkeypatch):
    destination = folder / "20261012-CA.gui.json"
    destination.write_bytes(b"previous evidence\n")
    replace, replacements = report.os.replace, []

    def checked_replace(source, target):
        assert target == destination and destination.read_bytes() == b"previous evidence\n"
        raw = Path(source).read_bytes()
        assert len(raw.splitlines()) == 1 and json.loads(raw)["schema"] == "app_gui_ready.v1"
        replacements.append(True)
        replace(source, target)

    monkeypatch.setattr(report.os, "replace", checked_replace)
    report._write_gui_ready(app.CURRENT_VERSION, BUILD, READY_AT)
    assert replacements == [True]
    read_marker(folder)


@pytest.mark.parametrize("failure", ["missing", "open", "replace", "native", "reparse", "relative"])
def test_marker_failure_never_changes_normal_start(folder, flow, workers, monkeypatch, capsys, failure):
    def denied(*_args, **_kwargs):
        raise PermissionError()

    if failure == "missing":
        folder.rmdir()
    elif failure == "open":
        monkeypatch.setattr(Path, "open", denied)
    elif failure == "replace":
        monkeypatch.setattr(report.os, "replace", denied)
    elif failure == "native":
        monkeypatch.setattr(report, "_process_start_utc", denied)
    elif failure == "reparse":
        monkeypatch.setattr(report, "_assert_no_reparse_components", denied)
    else:
        monkeypatch.setenv("PROGRAMDATA", "relative")
    assert app.main([]) == 0 and flow.events == ["prepare", "run", "release"]
    worker = workers.pop()
    worker.target(*worker.args)
    assert not folder.exists() or not list(folder.glob("*.gui.json"))
    assert not folder.exists() or not list(folder.glob("*.tmp"))
    assert not capsys.readouterr().err


def test_thread_start_failure_does_not_change_start_or_raise(folder, flow, workers, monkeypatch, capsys):
    monkeypatch.setattr(report, "Thread", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError()))
    assert app.main([]) == 0 and flow.events == ["prepare", "run", "release"]
    assert not report._GUI_READY_STARTED and not workers
    assert not list(folder.glob("*.gui.json")) and not capsys.readouterr().err


def test_screen_callback_returns_while_native_query_is_still_blocked(folder, monkeypatch):
    entered, release, completed = Event(), Event(), Event()
    created = report._process_start_utc()
    threads = []

    def blocked_native_query():
        entered.set()
        assert release.wait(10)
        return created

    def start_worker(**options):
        target = options.pop("target")
        def complete(*args):
            try:
                target(*args)
            finally:
                completed.set()
        thread = Thread(target=complete, **options)
        threads.append(thread)
        return thread

    monkeypatch.setattr(report, "_process_start_utc", blocked_native_query)
    monkeypatch.setattr(report, "Thread", start_worker)
    try:
        report.gui_ready(app.CURRENT_VERSION, BUILD)
        assert entered.wait(5) and not completed.is_set()
        assert not list(folder.glob("*.gui.json"))
    finally:
        release.set()
        for thread in threads:
            thread.join(10)
    assert completed.is_set() and all(not thread.is_alive() for thread in threads)
    read_marker(folder)


def test_gui_report_bypasses_admission_but_cannot_run_inside_one(folder, monkeypatch, capsys):
    monkeypatch.setattr(fence, "writer_admission", lambda *_args, **_kwargs: pytest.fail("report acquired admission"))
    report._write_gui_ready(app.CURRENT_VERSION, BUILD, READY_AT)
    before = next(folder.glob("*.gui.json")).read_bytes()
    monkeypatch.setattr(fence._WRITER_LOCAL, "depth", 1, raising=False)
    with pytest.raises(fence.WriterFencedError) as rejected:
        report._write_gui_ready(app.CURRENT_VERSION, BUILD, READY_AT)
    assert rejected.value.code == "STARTUP_REPORT_ADMISSION_HELD"
    report._publish_gui_ready(app.CURRENT_VERSION, BUILD, READY_AT)
    assert next(folder.glob("*.gui.json")).read_bytes() == before
    assert not capsys.readouterr().err


def test_trial_staging_ready_bytes_and_durable_queues_are_preserved(
        folder, flow, workers, monkeypatch, tmp_path):
    paths = SimpleNamespace(data_root=tmp_path, events_dir=tmp_path / "events", queue_dir=tmp_path / "queue",
                            ledger_path=tmp_path / "ledger.db", direct_sync_root=tmp_path / "direct_sync")
    paths.events_dir.mkdir()
    paths.queue_dir.mkdir()
    databases = (paths.ledger_path, paths.queue_dir / "direct_sync_relay.sqlite3")
    for path in databases:
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE preserved(value TEXT)")
    before = [path.read_bytes() for path in databases]
    state = {"nonce": "trial-evidence", "transition_id": "trial-transition", "phase": "TRIAL"}
    context = (tmp_path, {"staging_root": str(tmp_path)}, state)
    monkeypatch.setattr(updates, "trial_context", lambda _root: context)
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_args: True)
    monkeypatch.setattr(updates, "now_utc", lambda: "2026-10-11T20:00:00Z")
    monkeypatch.setattr(onboarding, "resolve_current_user_onboarding_paths", lambda _root: paths)
    monkeypatch.setattr(onboarding, "inspect_current_user_state", lambda _paths: {"status": "READY"})
    monkeypatch.setattr(user_relay, "user_relay_status_path", lambda _root: tmp_path / "relay.json")
    monkeypatch.setattr(updates, "optional_record", lambda _path: {"status": "RUNNING", "source_commit": BUILD,
                                                                "update_nonce": state["nonce"], "ordinary_user": True})
    monkeypatch.setattr(updates, "version_manifest", lambda _root: {"source_commit": BUILD})
    assert updates.publish_gui_ready(tmp_path / "app")
    original = (tmp_path / "ready.json").read_bytes()
    assert app.main([]) == 0 and flow.events == ["prepare", "withdraw", "run", "release"]
    assert flow.callbacks[0][0] == 250 and len(workers) == 1
    worker = workers.pop()
    worker.target(*worker.args)
    read_marker(folder)
    assert (tmp_path / "ready.json").read_bytes() == original
    assert [path.read_bytes() for path in databases] == before


@pytest.mark.parametrize("failure", ["not_ready", "readback_failure"])
def test_trial_does_not_publish_daily_ready_before_existing_readiness(
        folder, flow, workers, monkeypatch, failure):
    monkeypatch.setattr(updates, "trial_context", lambda _root: (None, {}, {}))
    def unconfirmed(_root):
        if failure == "readback_failure":
            raise OSError()
        return False
    monkeypatch.setattr(updates, "publish_gui_ready", unconfirmed)
    assert app.main([]) == 0 and "run" in flow.events
    assert not workers and not list(folder.glob("*.gui.json"))
    assert flow.callbacks[0][0] == 250


def test_trial_confirmation_reports_the_existing_screen_when_it_is_shown(folder, flow, workers, monkeypatch):
    contexts = iter([(None, {}, {}), None])
    monkeypatch.setattr(updates, "trial_context", lambda _root: next(contexts))
    assert app.main([]) == 0
    assert flow.events == ["prepare", "withdraw", "run", "deiconify", "release"]
    assert not flow.callbacks and len(workers) == 1
    worker = workers.pop()
    worker.target(*worker.args)
    read_marker(folder)


def test_trial_ready_implementation_is_unchanged_from_g_commit():
    completed = subprocess.run(["git", "-c", "core.autocrlf=false", "show", "eb1da78:auto_update.py"],
                               cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=20)
    assert completed.returncode == 0
    def ready_ast(source):
        return ast.dump(next(node for node in ast.parse(source).body
                             if isinstance(node, ast.FunctionDef) and node.name == "publish_gui_ready"))
    assert ready_ast(completed.stdout.decode("utf-8-sig")) == ready_ast(
        Path(updates.__file__).read_text(encoding="utf-8-sig"))
