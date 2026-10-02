"""A partial identity transition must never restart as the previous worker."""
import json
from types import MethodType

import pytest

import Container_Audit as ca

from Container_Audit import ContainerAudit
from worker_registry import WorkerRegistry
from tests.test_remembered_worker_start import _login, _registry
from tests.test_w9scanonly_workflow import flow, windows, COMPACT_QR, ITEM
from tests.test_scanonly_review_regressions import public_scan


class Interrupted(BaseException):
    pass


def _started(flow, tmp_path):
    app = flow(transition=False)
    registry = _registry(tmp_path / "workers.json", "previous")
    registry.register("next")
    screen, selected = _login(app, registry, tmp_path)
    app._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, app)
    app._end_work_session = MethodType(ContainerAudit._end_work_session, app)
    app._schedule_startup_transfer_recovery = lambda: True
    app._cancel_all_jobs = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app._reset_master_label_replacement_state = lambda: None
    app._start_remembered_worker(registry.recent_worker())
    assert app.worker_name == "previous"
    return app, registry, screen, selected


def _restart(flow, tmp_path):
    fresh = flow(transition=False, root=tmp_path)
    registry = WorkerRegistry(str(tmp_path / "workers.json"))
    screen, _selected = _login(fresh, registry, tmp_path)
    fresh._begin_or_resume_work_session = MethodType(ContainerAudit._begin_or_resume_work_session, fresh)
    fresh._schedule_startup_transfer_recovery = lambda: True
    fresh._start_remembered_worker(registry.recent_worker())
    return fresh, screen


@pytest.mark.parametrize("point", ["disabled", "closed", "selected", "session_saved", "bound", "started"])
def test_worker_change_interruption_cannot_record_previous_worker(flow, windows, tmp_path, monkeypatch, point):
    app, registry, _screen, selected = _started(flow, tmp_path)
    if point == "disabled":
        disable = registry.disable_automatic_start

        def interrupt_disable():
            disable()
            raise Interrupted()

        monkeypatch.setattr(registry, "disable_automatic_start", interrupt_disable)
    elif point == "closed":
        save = app._save_work_session_state

        def interrupt_close(state):
            result = save(state)
            if state["phase"] == "CLOSED":
                raise Interrupted()
            return result

        monkeypatch.setattr(app, "_save_work_session_state", interrupt_close)
    if point in {"disabled", "closed"}:
        with pytest.raises(Interrupted):
            app.change_worker()
    else:
        app.change_worker()
        selected["name"] = "next"
        if point == "session_saved":
            save = app._save_work_session_state

            def interrupt_start(state):
                result = save(state)
                if state["phase"] == "ACTIVE":
                    assert not app._work_session_identity_bound
                    raise Interrupted()
                return result

            monkeypatch.setattr(app, "_save_work_session_state", interrupt_start)
        elif point == "bound":
            def interrupt_remember(name):
                assert app._work_session_identity_bound
                raise Interrupted()

            monkeypatch.setattr(registry, "mark_recent", interrupt_remember)
        if point in {"session_saved", "bound"}:
            with pytest.raises(Interrupted):
                app.start_work()
        elif point == "started":
            app.start_work()
    fresh, screen = _restart(flow, tmp_path)
    if point == "started":
        assert fresh.worker_name == "next" and screen["value"] == "work"
        public_scan(fresh, COMPACT_QR + "|QT=2")
        public_scan(fresh, ITEM + "-SERIAL-001")
        saved = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
        assert saved["worker_name"] == "next"
    else:
        assert fresh.worker_name == "" and screen["value"] == "selection"
        public_scan(fresh, COMPACT_QR + "|QT=2")
        public_scan(fresh, ITEM + "-SERIAL-001")
        assert not (tmp_path / "current.json").exists()


@pytest.mark.parametrize("replaced", [False, True])
def test_disable_write_failure_aborts_change_before_session_close(flow, windows, tmp_path, monkeypatch, replaced):
    app, registry, _screen, _selected = _started(flow, tmp_path)
    before = (tmp_path / "workers.json").read_bytes()
    write = registry._write_payload

    def failed_write(payload):
        if replaced:
            write(payload)
        raise OSError("simulated disk failure")

    monkeypatch.setattr(registry, "_write_payload", failed_write)
    app.change_worker()
    assert app.worker_name == "previous" and app._work_session_identity_bound
    assert app._load_work_session_state()["phase"] == "ACTIVE"
    if not replaced:
        assert (tmp_path / "workers.json").read_bytes() == before
    fresh, screen = _restart(flow, tmp_path)
    if replaced:
        assert fresh.worker_name == "" and screen["value"] == "selection"
    else:
        assert fresh.worker_name == "previous" and screen["value"] == "work"


@pytest.mark.parametrize("failure", ["hold", "session", "save", "remember"])
def test_failed_start_requires_selection_without_reordering_names(flow, windows, tmp_path, monkeypatch, failure):
    app, registry, _screen, selected = _started(flow, tmp_path)
    before = registry.list_workers()
    selected["name"] = "next"
    if failure == "hold":
        app._restore_preflight_scan_hold = lambda: False
    elif failure == "session":
        app._begin_or_resume_work_session = lambda: False
    elif failure == "save":
        app._save_work_session_state = lambda state: False
    else:
        def failed_remember(name):
            raise OSError("simulated disk failure")

        monkeypatch.setattr(registry, "mark_recent", failed_remember)
    app.start_work()
    assert registry.recent_worker() == "previous" and registry.list_workers() == before
    assert not WorkerRegistry(registry.registry_path).automatic_start_enabled()
    fresh, screen = _restart(flow, tmp_path)
    assert fresh.worker_name == "" and screen["value"] == "selection"


@pytest.mark.parametrize("reason", ["worker_change", "supervisor_end", "logout", "work_end", "app_close"])
def test_session_end_requires_selection_except_same_worker_app_close(flow, windows, tmp_path, reason):
    app, registry, _screen, _selected = _started(flow, tmp_path)
    assert app._end_work_session(reason=reason)
    assert app._load_work_session_state()["phase"] == "CLOSED"
    fresh, screen = _restart(flow, tmp_path)
    if reason == "app_close":
        assert fresh.worker_name == "previous" and screen["value"] == "work"
    else:
        assert fresh.worker_name == "" and screen["value"] == "selection"


def test_activation_audit_failure_requires_selection_with_original_state(flow, windows, tmp_path):
    app, _registry_value, _screen, _selected = _started(flow, tmp_path)
    app._drain_pending_activation_event = lambda: False
    public_scan(app, COMPACT_QR + "|QT=2")
    assert app.worker_name == "" and (tmp_path / "current.json").is_file()
    original = (tmp_path / "current.json").read_bytes()
    fresh, screen = _restart(flow, tmp_path)
    assert fresh.worker_name == "" and screen["value"] == "selection"
    assert (tmp_path / "current.json").read_bytes() == original


def test_registration_keeps_suspension_until_successful_start(tmp_path):
    registry = _registry(tmp_path / "workers.json", "previous")
    before = registry.list_workers()
    registry.disable_automatic_start()
    registry.register("next")
    fresh = WorkerRegistry(registry.registry_path)
    assert not fresh.automatic_start_enabled()
    assert fresh.recent_worker() == "previous"
    assert fresh.list_workers() == before + ["next"]
    fresh.mark_recent("next")
    assert WorkerRegistry(registry.registry_path).automatic_start_enabled()
    assert fresh.recent_worker() == "next"


def test_confirmed_change_disables_start_before_session_end(flow, windows, tmp_path):
    app, registry, _screen, _selected = _started(flow, tmp_path)

    def before_close(*, reason):
        assert not WorkerRegistry(registry.registry_path).automatic_start_enabled()
        assert app._load_work_session_state()["phase"] == "ACTIVE"
        raise Interrupted()

    app._end_work_session = before_close
    with pytest.raises(Interrupted):
        app.change_worker()
    fresh, screen = _restart(flow, tmp_path)
    assert fresh.worker_name == "" and screen["value"] == "selection"


@pytest.mark.parametrize("refused", [True, False])
def test_refused_or_cancelled_change_keeps_same_worker_start(flow, windows, tmp_path, monkeypatch, refused):
    app, registry, _screen, _selected = _started(flow, tmp_path)
    before = (tmp_path / "workers.json").read_bytes()
    app._preflight_context_blocks_mutation = lambda: refused
    monkeypatch.setattr(ca.messagebox, "askyesno", lambda *args, **kwargs: False)
    app.change_worker()
    assert app.worker_name == "previous" and app._work_session_identity_bound
    assert (tmp_path / "workers.json").read_bytes() == before
    fresh, screen = _restart(flow, tmp_path)
    assert fresh.worker_name == "previous" and screen["value"] == "work"
