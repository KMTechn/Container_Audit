"""M86 owner exit, delegated drain and the installed portable admission."""
from contextlib import contextmanager
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import threading
from types import MethodType, SimpleNamespace
import uuid

import pytest

import auto_update as updates
import Container_Audit as ca
import ca_screen_bridge as screen
import preflight_scan_hold as holds
import runtime_instance
import startup_check_report as startup_report
import tk_serial_ui_lane as lanes
import writer_session_fence as fence
from tests.test_ca_new_screen_entry import entry, _surface
from tests.test_tk_serial_ui_lane import FakeTkRoot
from tests.test_writer_session_fence import _active_payload, _write_active

pytestmark = pytest.mark.usefixtures("owned_tk_workers")


@pytest.fixture(autouse=True)
def _report_scope():
    startup_report.finish()
    yield
    startup_report.finish()


def test_shell_receives_the_app_name_for_its_os_failure_notice(entry, monkeypatch):
    titles = []

    def run_app(_profile, _data, **kwargs):
        window = _surface(sys.modules["webview"])
        window.events.shown.set()
        # The shell owns the OS notice; the adapter supplies its title.
        titles.append(kwargs["title"])
        window.destroy()
        assert kwargs["before_exit"]("SHELL_START_FAILED", 0)
        raise SystemExit(3)

    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
    with pytest.raises(SystemExit):
        ca.main([])
    assert titles == ["이적"] and not entry.releases


@pytest.mark.parametrize("phase", ["install", "attach", "readiness"])
@pytest.mark.parametrize("broken", [False, True])
def test_initialization_failure_drains_real_lanes_and_releases_lease(entry, monkeypatch, tmp_path, phase, broken):
    failure = RuntimeError("synthetic owner initialization failure")
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)

    class Root(FakeTkRoot):
        def after(self, delay, callback, *args):
            if (phase == "install" and delay == screen.WATCH_MS) or (phase == "readiness" and delay == 0):
                raise failure
            return super().after(delay, callback, *args)

        def withdraw(self):
            pass

    root = Root()
    app = SimpleNamespace(root=root, _runtime_data_root=tmp_path,
                          LOOP_CLEANUP_TIMEOUT_SECONDS=ca.ContainerAudit.LOOP_CLEANUP_TIMEOUT_SECONDS,
                          LOOP_CLEANUP_NOTICE_SECONDS=ca.ContainerAudit.LOOP_CLEANUP_NOTICE_SECONDS,
                          _cancel_all_jobs=lambda: None)
    app._cleanup_after_mainloop = MethodType(ca.ContainerAudit._cleanup_after_mainloop, app)
    app.run = MethodType(ca.ContainerAudit.run, app)
    app._ui_lane = lanes.TkSerialUiLane(root)
    app._central_transport_lane = lanes.TkSerialUiLane(root)
    app._preflight_hold_writer_instance = holds.PreflightScanHoldWriter(root, queue_capacity=2)
    workers = [app._ui_lane.worker_thread, app._central_transport_lane.worker_thread,
               app._preflight_hold_writer_instance.thread]
    if broken:
        app._ui_lane.mark_broken(RuntimeError("synthetic broken lane"))
    lease = runtime_instance.acquire_runtime_instance(tmp_path)
    assert lease is not None

    def prepare(**_kwargs):
        with fence.writer_admission("test_sink"):
            return app, lease

    def attach(_processor):
        raise failure

    if phase == "attach":
        entry.bridge.attach_owner = attach
    if phase == "readiness":
        monkeypatch.setattr(updates, "trial_context", lambda _root: object())
    monkeypatch.setattr(ca, "_prepare_gui_startup", prepare)
    monkeypatch.setattr(ca, "stop_all_sounds", lambda: None)

    def run_app(_profile, _data, **kwargs):
        _surface(sys.modules["webview"]).events.shown.set()
        kwargs["owner_main"](entry.bridge)
        assert all(not worker.is_alive() for worker in workers)
        assert kwargs["before_exit"]("SHELL_START_FAILED", 0)
        return 0

    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(RuntimeError) as caught:
            ca.main([])
        assert caught.value is failure
        assert app._loop_cleanup_finished and lease._released
        assert fence._WRITER_EXIT_COUNT == 0
        reopened = runtime_instance.acquire_runtime_instance(tmp_path)
        assert reopened is not None
        reopened.release()
    finally:
        for lane in (app._ui_lane, app._central_transport_lane, app._preflight_hold_writer_instance):
            lane.close_idle()
        lease.release()


@pytest.mark.parametrize("kind", ["ui", "hold"])
def test_lane_pump_initialization_failure_stops_the_started_worker(monkeypatch, kind):
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    failure = RuntimeError("synthetic pump initialization failure")
    owners = []
    original = fence.start_lane_worker

    def start(worker):
        owners.append(worker._target.__self__)
        original(worker)

    class Root(FakeTkRoot):
        def after(self, *_args):
            raise failure

    monkeypatch.setattr(fence, "start_lane_worker", start)
    monkeypatch.setattr(lanes, "start_lane_worker", start)
    try:
        with pytest.raises(RuntimeError) as caught:
            if kind == "ui":
                lanes.TkSerialUiLane(Root())
            else:
                holds.PreflightScanHoldWriter(Root(), queue_capacity=2)
        assert caught.value is failure and len(owners) == 1
        worker = getattr(owners[0], "worker_thread", None) or owners[0].thread
        assert not worker.is_alive()
        assert fence.close_and_wait_writers(0)
    finally:
        for owner in owners:
            owner.close_idle()


@pytest.mark.parametrize("phase", ["INSTALLING", "RESTORING"])
def test_valid_delegated_exit_uses_only_actual_worker_death(monkeypatch, tmp_path, phase):
    root = tmp_path / "delegated"
    authorization = uuid.uuid4().hex
    payload = _active_payload(token=authorization, sources=["screen_shell_fileio"])
    active = _write_active(root, payload)
    saved = json.loads(active.read_bytes())
    saved["status"] = phase
    active.write_text(json.dumps(saved), encoding="utf-8")
    monkeypatch.setattr(fence, "canonical_control_root", lambda *_args: root)
    monkeypatch.setattr(fence, "_named_mutex_held_by_other", lambda _name: True)
    for name, value in ((fence.DELEGATION_TOKEN_ENV, authorization),
                        (fence.DELEGATION_SESSION_ENV, payload["session_id"]),
                        (fence.DELEGATION_ATTEMPT_ENV, payload["attempt_id"]),
                        (fence.DELEGATION_TRANSACTION_ENV, payload["replacement_transaction_id"])):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    # This capability is not a normal writer token/count.
    monkeypatch.setattr(fence, "_WRITER_EXIT_COUNT", 1)
    worker = lanes.TkSerialUiLane(FakeTkRoot())
    worker.mark_broken(RuntimeError("synthetic broken lane"))
    monkeypatch.setattr(fence, "_acquire_named_mutex", lambda *_args: pytest.fail("normal gate was probed"))
    try:
        assert not fence.close_and_wait_writers(0)
        worker.close_idle()
        assert not worker.worker_thread.is_alive()
        assert fence.close_and_wait_writers(0)
        assert fence._WRITER_EXIT_COUNT == 1
        monkeypatch.setenv(fence.DELEGATION_ATTEMPT_ENV, uuid.uuid4().hex)
        assert not fence.close_and_wait_writers(0)
    finally:
        worker.close_idle()


def test_exit_empty_decision_rejects_a_late_real_lane_start(monkeypatch):
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    monkeypatch.setattr(fence, "_WRITER_EXIT_COUNT", 0)
    entered, finish = threading.Event(), threading.Event()
    result, created = [], []

    def probe(*_args):
        entered.set()
        assert finish.wait(5)
        return SimpleNamespace(abandoned=False, release=lambda: None)

    monkeypatch.setattr(fence, "_acquire_named_mutex", probe)
    closer = threading.Thread(target=lambda: result.append(fence.close_and_wait_writers(5)))
    closer.start()
    try:
        assert entered.wait(5)
        with pytest.raises(fence.WriterFencedError) as caught:
            created.append(lanes.TkSerialUiLane(FakeTkRoot()))
        assert caught.value.code == "WRITER_EXIT_CLOSED"
        finish.set()
        closer.join(5)
        assert not closer.is_alive() and result == [True]
        with pytest.raises(fence.WriterFencedError):
            holds.PreflightScanHoldWriter(FakeTkRoot(), queue_capacity=2)
    finally:
        finish.set()
        closer.join(5)
        for worker in created:
            worker.close_idle()


@pytest.mark.parametrize("code", ["WRITER_GATE_ABANDONED", "WRITER_GATE_TIMEOUT"])
@pytest.mark.parametrize("stage", ["portable_gate", "application_gate", "relay_gate"])
def test_real_portable_gate_admission_keeps_support_exit_and_only_abandoned_notice(monkeypatch, tmp_path, code, stage):
    source = Path(ca.__file__).parent / "portable/main.py"
    app_root = tmp_path / "installed/current/app"
    app_root.mkdir(parents=True)
    entry_file = app_root / "main.py"
    entry_file.write_bytes(source.read_bytes())
    assert entry_file.read_bytes() == source.read_bytes()
    installed_application = app_root / "Container_Audit.py"
    installed_application.write_bytes(Path(ca.__file__).read_bytes())
    monkeypatch.setattr(ca, "__file__", str(installed_application))
    control = app_root.parent.parent / "update-control"
    control.mkdir()
    sha = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    candidate = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    staging = tmp_path / "staging"
    staging.mkdir()
    for path, data in ((control / "policy.json", {"operator_sid": "S-1-5-21-401-402-403-1001",
                                                "staging_root": str(staging), "feed_url": "https://invalid.example/feed"}),
                       (control / "active.json", {"sha": sha}),
                       (app_root.parent / "portable-manifest.json", {"source_commit": sha,
                         "startup_update_protocol": 1, "writer_sink_inventory_contract_sha256": fence.WRITER_INVENTORY_SHA256})):
        path.write_text(json.dumps(data), encoding="utf-8")
    if stage != "application_gate":
        (staging / "prepared.json").write_text(json.dumps({"source_commit": candidate}), encoding="utf-8")
    else:
        (Path(os.environ["PROGRAMDATA"]) / "KMTech/start-check").mkdir(parents=True)
    monkeypatch.setattr(sys, "path", list(sys.path))
    arguments = ["--container-audit-user-relay"] if stage == "relay_gate" else ["--ui", "tk"]
    monkeypatch.setattr(sys, "argv", [str(entry_file), *arguments])
    monkeypatch.setattr(updates, "ordinary_user_context", lambda *_args: True)
    monkeypatch.setattr(fence, "_WRITER_EXIT_CLOSED", False)
    records, notices, released, stacks, locks = [], [], [], [], []

    @contextmanager
    def native_lock(*_args, **_kwargs):
        locks.append(True)
        yield
        if stage == "application_gate" and len(locks) == 1:
            (staging / "prepared.json").write_text(json.dumps({"source_commit": candidate}), encoding="utf-8")

    def probe(*_args):
        functions = [frame.function for frame in inspect.stack()]
        if "startup_gate" not in functions:
            return SimpleNamespace(abandoned=False, release=lambda: None)
        stacks.append(functions)
        if code == "WRITER_GATE_TIMEOUT":
            return None
        return SimpleNamespace(abandoned=True, release=lambda: released.append(True))

    class NoticeRoot:
        def __getattr__(self, _name):
            return lambda *_args, **_kwargs: None

    def label(_root, *, text, **_kwargs):
        notices.append(text)
        return SimpleNamespace(pack=lambda **_kwargs: None)

    monkeypatch.setattr(updates, "update_lock", native_lock)
    monkeypatch.setattr(fence, "_acquire_named_mutex", probe)
    monkeypatch.setattr(updates, "emit_support_record", lambda **kwargs: records.append(kwargs))
    monkeypatch.setattr(ca.tk, "Tk", NoticeRoot)
    monkeypatch.setattr(ca.tk, "Label", label)
    monkeypatch.setattr(ca.tk, "Button", lambda *_args, **_kwargs: SimpleNamespace(pack=lambda **_kw: None))
    spec = importlib.util.spec_from_file_location("ca_m86_installed_entry", entry_file)
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    assert portable.main() == 1
    assert len(stacks) == 1 and {"startup_gate", "main", "writer_admission", "_writer_admission"} <= set(stacks[0])
    assert ("_run_application_main" in stacks[0]) == (stage == "application_gate")
    assert len(records) == 1 and records[0]["stage"] == "portable_entrypoint"
    assert records[0]["file"] is sys.stderr and records[0]["error"].code == code
    expected = []
    if stage != "relay_gate" and code == "WRITER_GATE_ABANDONED":
        expected = ["이적 다시 열기 — 한 번 더 여세요"]
    elif stage == "application_gate":
        expected = [startup_report.NOTICE]
    assert notices == expected
    assert released == ([True] if code == "WRITER_GATE_ABANDONED" else [])
    assert fence._WRITER_EXIT_COUNT == 0
