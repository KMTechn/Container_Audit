"""Remembered login uses durable manual admission and keeps held work isolated."""
import datetime
import json
from pathlib import Path
from types import MethodType, SimpleNamespace

import pytest

import Container_Audit as ca
from Container_Audit import ContainerAudit
from worker_registry import WorkerRegistry
from tests.test_container_p0_contracts import _startup_transfer_recovery_app
from tests.test_scanonly_review_regressions import public_scan
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR, ITEM
from tests.test_startup_catalog_notice import startup, _offline_catalog
from tests.test_tk_serial_ui_lane import FakeTkRoot
from tests.test_transfer_hold_transport import seal_runtime

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


def _registry(path, name="tester", *, used=True):
    registry = WorkerRegistry(str(path))
    registry.register(name)
    if used:
        registry.mark_recent(name)
    return registry


def _login(app, registry, path):
    app.save_folder = str(path)
    app.worker_registry = registry
    app.worker_name = ""
    app.worker_role = ""
    app._work_session_identity_bound = False
    app._work_session_recovery_blocked = False
    app.WORK_SESSION_STATE_FILE = "session.json"
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app._work_session_id = ""
    selected = {"name": registry.list_workers()[0] if registry.list_workers() else ""}
    app.worker_entry = SimpleNamespace(get=lambda: selected["name"])
    app._set_worker_entry_value = lambda name: selected.update(name=name)
    app._refresh_worker_entry_options = lambda: None
    app._ensure_worker_login_name = MethodType(ContainerAudit._ensure_worker_login_name, app)
    app._load_session_state = lambda: None
    app._load_current_tray_state = lambda: None
    app._restore_preflight_scan_hold = lambda: True
    app._refresh_transfer_post_review_state = lambda: None
    app._authenticated_protected_admin = False
    app.root.winfo_exists = lambda: True
    screen = {"value": "selection"}
    app.paned_window = SimpleNamespace(winfo_ismapped=lambda: screen["value"] == "work")
    app.show_worker_input_screen = lambda: screen.update(value="selection")
    app.show_validation_screen = lambda: screen.update(value="work")
    return screen, selected


@pytest.mark.parametrize("automatic", [False, True])
def test_remembered_and_manual_start_store_bind_then_recover_and_scan(
    flow, windows, tmp_path, automatic,
):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json")
    screen, _ = _login(app, registry, tmp_path)
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    order = []
    save = app._save_work_session_state
    def saved(state):
        assert not app._work_session_identity_bound
        order.append("save:" + state["phase"])
        return save(state)
    app._save_work_session_state = saved
    def recover():
        assert app._work_session_identity_bound
        assert app._load_work_session_state()["phase"] == "ACTIVE"
        order.append("bound:recovery")
        return True
    app._schedule_startup_transfer_recovery = recover
    if automatic:
        app._start_remembered_worker(registry.recent_worker())
    else:
        app.start_work()
    assert order == ["save:START_PENDING", "save:ACTIVE", "bound:recovery"]
    assert screen["value"] == "work" and app.worker_name == "tester"
    assert app._work_session_identity_bound
    public_scan(app, COMPACT_QR + "|QT=2")
    public_scan(app, ITEM + "-SERIAL-001")
    state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding="utf-8"))
    assert state["worker_name"] == "tester"
    assert state["scanned_barcodes"] == [ITEM + "-SERIAL-001"]
    assert windows == []


@pytest.mark.parametrize("condition", ["first", "unused", "disabled", "removed", "recovery", "current", "registration"])
def test_uncertain_remembered_login_stays_on_selection(flow, windows, tmp_path, condition):
    app = flow(transition=False)
    registry = WorkerRegistry(str(tmp_path / "workers.json"))
    if condition != "first":
        registry = _registry(tmp_path / "workers.json", used=condition != "unused")
    remembered = registry.recent_worker()
    screen, _ = _login(app, registry, tmp_path)
    if condition in {"disabled", "removed"}:
        payload = json.loads(Path(registry.registry_path).read_text(encoding="utf-8"))
        if condition == "disabled":
            payload["workers"][0]["active"] = False
        else:
            payload["workers"] = []
        Path(registry.registry_path).write_text(json.dumps(payload), encoding="utf-8")
    elif condition == "recovery":
        app._work_session_recovery_blocked = True
    elif condition == "current":
        (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).write_text("preserved previous work", encoding="utf-8")
    elif condition == "registration":
        app.transfer_seal_coordinator.client = None
    starts = []
    app.start_work = lambda **kwargs: starts.append(kwargs)
    app._start_remembered_worker(remembered)
    assert screen["value"] == "selection"
    assert app.worker_name == "" and not app._work_session_identity_bound
    assert starts == [] and windows == []


def test_disabled_latest_worker_does_not_fall_back_to_another_person(tmp_path):
    registry = _registry(tmp_path / "workers.json", "earlier")
    registry.register("latest")
    registry.mark_recent("latest")
    payload = json.loads(Path(registry.registry_path).read_text(encoding="utf-8"))
    payload["workers"][1]["active"] = False
    Path(registry.registry_path).write_text(json.dumps(payload), encoding="utf-8")
    assert registry.list_workers() == ["earlier"]
    assert registry.recent_worker() is None


@pytest.mark.parametrize("invalid", ["bad timestamp", "ambiguous", "protected", "malformed"])
def test_uncertain_recent_record_cannot_select_a_different_person(tmp_path, invalid):
    registry = _registry(tmp_path / "workers.json", "earlier")
    payload = json.loads(Path(registry.registry_path).read_text(encoding="utf-8"))
    row = {"name": "latest", "active": True, "last_used_at": "2099-01-01T00:00:00"}
    if invalid == "bad timestamp":
        row["last_used_at"] = "unknown"
    elif invalid == "ambiguous":
        row["last_used_at"] = payload["workers"][0]["last_used_at"]
    elif invalid == "protected":
        row["name"] = ca.PROTECTED_ADMIN_OPERATOR_ID
    else:
        row["active"] = "yes"
    payload["workers"].append(row)
    Path(registry.registry_path).write_text(json.dumps(payload), encoding="utf-8")
    before = Path(registry.registry_path).read_bytes()
    assert registry.recent_worker() is None
    assert Path(registry.registry_path).read_bytes() == before


def test_failed_automatic_session_save_preserves_memory_and_sends_no_held_work(tmp_path, windows):
    app, root, lane, hold, seals, _members, calls = _startup_transfer_recovery_app(
        tmp_path, seal_intent_ids=("seal-1",), hold_active=True,
    )
    registry = _registry(tmp_path / "workers.json", "other-worker")
    screen, selected = _login(app, registry, tmp_path)
    app.transfer_seal_coordinator.client = SimpleNamespace()
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._audit_event_contract = lambda **kwargs: {"event_type": kwargs["event_type"]}
    saves = []
    app._save_work_session_state = lambda state: saves.append(state["phase"]) or False
    original = hold.path.read_bytes()
    remembered_payload = json.loads(Path(registry.registry_path).read_text(encoding="utf-8"))
    # An unsuccessful start retains name history but durably requires selection (sub-167).
    remembered_payload["automatic_start_enabled"] = False
    try:
        app._start_remembered_worker(registry.recent_worker())
        assert saves == ["START_PENDING"]
        assert screen["value"] == "selection" and selected["name"] == "other-worker"
        assert app.worker_name == "" and not app._work_session_identity_bound
        assert not app._startup_transfer_recovery_inflight
        app._run_background_seal_retry()
        root.run_until(lambda: not lane.is_busy())
        assert calls["seal"] == [] and seals.intent_ids == ["seal-1"]
        assert hold.path.read_bytes() == original
        assert json.loads(Path(registry.registry_path).read_text(encoding="utf-8")) == remembered_payload
        assert not WorkerRegistry(registry.registry_path).automatic_start_enabled()
        assert windows == []
    finally:
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")


def test_failed_manual_start_does_not_replace_the_last_successful_worker(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json", "previous")
    registry.register("next")
    screen, selected = _login(app, registry, tmp_path)
    selected["name"] = "next"
    app._begin_or_resume_work_session = lambda: False
    app.start_work()
    assert screen["value"] == "selection" and app.worker_name == ""
    assert registry.recent_worker() == "previous"


def test_removed_last_worker_does_not_start_an_older_registry_row(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json", "previous")
    registry.register("latest")
    screen, selected = _login(app, registry, tmp_path)
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._schedule_startup_transfer_recovery = lambda: True
    selected["name"] = "latest"
    app.start_work()
    assert app._load_work_session_state()["worker_name"] == "latest"
    payload = json.loads(Path(registry.registry_path).read_text(encoding="utf-8"))
    payload["workers"] = [row for row in payload["workers"] if row["name"] != "latest"]
    Path(registry.registry_path).write_text(json.dumps(payload), encoding="utf-8")
    app.worker_name = ""
    app._work_session_identity_bound = False
    screen["value"] = "selection"
    assert registry.recent_worker() == "previous"
    app._start_remembered_worker(registry.recent_worker())
    assert screen["value"] == "selection" and app.worker_name == ""
    assert not app._work_session_identity_bound and windows == []


def test_existing_worker_change_remembers_new_name_for_restart(flow, windows, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json", "previous")
    registry.register("next")
    screen, selected = _login(app, registry, tmp_path)
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._schedule_startup_transfer_recovery = lambda: True
    app._start_remembered_worker(registry.recent_worker())
    app._cancel_all_jobs = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app._reset_master_label_replacement_state = lambda: None
    app.change_worker(_confirmed=True)
    assert screen["value"] == "selection"
    selected["name"] = "next"
    app.start_work()
    assert registry.recent_worker() == "next"
    app.worker_name = ""
    screen["value"] = "selection"
    app._work_session_identity_bound = False
    app._start_remembered_worker(WorkerRegistry(registry.registry_path).recent_worker())
    assert app.worker_name == "next" and screen["value"] == "work"


def test_recent_names_within_the_same_second_remember_the_last_start(tmp_path, monkeypatch):
    registry = _registry(tmp_path / "workers.json", "z-earlier", used=False)
    registry.register("a-later")
    instant = datetime.datetime(2026, 10, 2, 10, 0, 0)
    class Clock(datetime.datetime):
        @classmethod
        def now(cls):
            nonlocal instant
            instant += datetime.timedelta(microseconds=1)
            return instant
    import worker_registry
    monkeypatch.setattr(worker_registry, "datetime", SimpleNamespace(datetime=Clock))
    registry.mark_recent("z-earlier")
    registry.mark_recent("a-later")
    assert registry.recent_worker() == "a-later"


def test_real_constructor_automatically_starts_after_durable_binding(tmp_path, monkeypatch, windows):
    class Root(FakeTkRoot):
        tk = object()
        def run_one(self):
            # Drive startup/lane callbacks, keeping the real 30-second timer
            # pending rather than firing it on every fake pump iteration.
            job = next((job for job in self.jobs if job[1] <= 15), None)
            if job is None:
                return False
            self.jobs.remove(job)
            if job[0] not in self.cancelled:
                job[2](*job[3])
            import threading
            threading.Event().wait(0.001)
            return True
        def __getattr__(self, name):
            if name == "winfo_exists":
                return lambda: not self.destroyed
            return lambda *args, **kwargs: None
    root = Root()
    monkeypatch.setattr(ca.tk, "Tk", lambda: root)
    monkeypatch.setattr(ca, "fit_restored_window_to_work_area", lambda root: None)
    monkeypatch.setattr(ca.tk, "BooleanVar", lambda **kwargs: SimpleNamespace(get=lambda: False))
    from tests.test_w9scanonly_workflow import OfflineSealClient, _resolved
    monkeypatch.setattr(ca, "container_startup_logistics_client", lambda: OfflineSealClient(_resolved(2)))
    monkeypatch.setattr(ca, "start_direct_sync_auto_bootstrap", lambda **kwargs: None)
    setup = ContainerAudit._setup_paths_and_dirs
    def owned_paths(app):
        setup(app)
        _registry(Path(app.config_folder) / app.WORKERS_FILE)
    monkeypatch.setattr(ContainerAudit, "_setup_paths_and_dirs", owned_paths)
    monkeypatch.setattr(ContainerAudit, "load_items", lambda self: [
        {"Item Code": ITEM, "Item Name": "fixture item", "Spec": "fixture spec"},
    ])
    screen = {"value": "selection"}
    selected = {"name": "tester"}
    def selection(app):
        screen["value"] = "selection"
        app.worker_entry_var = SimpleNamespace(set=lambda name: selected.update(name=name))
        app.worker_entry = SimpleNamespace(get=lambda: selected["name"], configure=lambda **kwargs: None)
        app.paned_window = SimpleNamespace(winfo_ismapped=lambda: screen["value"] == "work")
    monkeypatch.setattr(ContainerAudit, "show_worker_input_screen", selection)
    monkeypatch.setattr(ContainerAudit, "show_validation_screen", lambda app: screen.update(value="work"))
    for name in ("_setup_core_ui_structure", "_setup_styles", "_start_audio_feedback_initialization",
                 "_poll_event_log_notice", "_refresh_transfer_post_review_state", "show_status_message"):
        monkeypatch.setattr(ContainerAudit, name, lambda *args, **kwargs: None)
    recovery = ContainerAudit._schedule_startup_transfer_recovery
    admitted = []
    def observe(app):
        admitted.append((app._work_session_identity_bound, app._load_work_session_state()["phase"]))
        return recovery(app)
    monkeypatch.setattr(ContainerAudit, "_schedule_startup_transfer_recovery", observe)
    app = ContainerAudit()
    try:
        assert screen["value"] == "selection" and app.worker_name == ""
        root.run_until(lambda: screen["value"] == "work")
        assert app.worker_name == "tester" and app._work_session_identity_bound
        assert admitted == [(True, "ACTIVE")]
        assert app._load_work_session_state()["worker_name"] == "tester"
        assert windows == []
    finally:
        lane = app._ui_lane
        if lane is not None:
            root.run_until(lambda: not lane.is_busy())
            lane.close_idle()
            root.run_until(lambda: lane.state == "CLOSED")
        app.log_queue.put(None)
        app.log_thread.join(timeout=10)
        assert not app.log_thread.is_alive()


def test_verified_offline_start_remembers_worker_with_no_window(startup, monkeypatch, tmp_path, windows):
    app, _released = startup
    _offline_catalog(monkeypatch, tmp_path)
    registry = _registry(tmp_path / "workers.json")
    screen, _ = _login(app, registry, tmp_path)
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._schedule_startup_transfer_recovery = lambda: True
    result = ca._prepare_gui_startup()
    try:
        app._start_remembered_worker(registry.recent_worker())
        assert app.worker_name == "tester" and screen["value"] == "work"
        assert "회사 서버 품목 목록" in app.info_cards["direct_sync"]["value"].options["text"]
        public_scan(app, COMPACT_QR + "|QT=2")
        public_scan(app, ITEM + "-SERIAL-001")
        assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
        assert windows == []
    finally:
        result[1].release()


@pytest.mark.parametrize("same_bundle,save_failure", [(True, False), (False, False), (True, True)])
def test_automatic_login_keeps_foreign_held_bundle_and_real_transport_guard(
    tmp_path, windows, same_bundle, save_failure,
):
    app, coordinator, intent, hold, master, posts, _session = seal_runtime(tmp_path)
    registry = _registry(tmp_path / "workers.json", "other-worker")
    screen, _ = _login(app, registry, tmp_path)
    app.PREFLIGHT_SCAN_HOLD_FILE = hold.path.name
    app._preflight_hold_store_instance = hold
    held_master = master if same_bundle else master.replace("PHS-SERVER-001", "PHS-OTHER")
    hold.start(worker="tester", master_raw=held_master, scan_epoch=1)
    original = hold.path.read_bytes()
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._project_audit_event_contract = lambda contract: True
    app.computer_id = "fixture-pc"
    if save_failure:
        app._save_work_session_state = lambda state: False
    seen = []
    def recover():
        assert app._work_session_identity_bound
        assert app._load_work_session_state()["phase"] == "ACTIVE"
        seen.append(coordinator.attempt(intent).status)
        return True
    app._schedule_startup_transfer_recovery = recover
    app._start_remembered_worker(registry.recent_worker())
    if save_failure:
        assert seen == [] and screen["value"] == "selection"
        assert app.worker_name == "" and not app._work_session_identity_bound
        assert coordinator.attempt(intent).status == "RETRY_WAIT"
    else:
        assert screen["value"] == "work" and app.worker_name == "other-worker"
        assert seen == ["RETRY_WAIT" if same_bundle else "ACKED"]
    assert len(posts) == (0 if same_bundle else 1)
    assert hold.path.read_bytes() == original
    assert windows == []
