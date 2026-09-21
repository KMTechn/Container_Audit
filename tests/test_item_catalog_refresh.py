import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

import Container_Audit as app_module
import item_catalog_sync as sync
from item_catalog import ItemCatalog
from tests.test_item_catalog_sync import CATALOG, FakeResponse, _profile
from tests.test_tk_serial_ui_lane import FakeTkRoot
from warning_presenter import WarningPresenter


NEW_CODE = "CCC0000000003"
UPDATED = CATALOG + b"CCC0000000003,Gamma,S3,assets/c.png\r\n"


@pytest.fixture
def refresh_app(tmp_path, monkeypatch):
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    app.root = FakeTkRoot()
    app.data_root = str(tmp_path / "active-data")
    Path(app.data_root).mkdir()
    app.save_folder = str(Path(app.data_root) / "events")
    app.current_tray = app_module.TraySession()
    app.warning_presenter = WarningPresenter()
    app._scan_callback_epoch = 0
    app._update_action_button_states = lambda: None
    app._schedule_pending_transfer_coordinator_work = lambda: None
    app._schedule_focus_return = lambda: None
    messages = []

    def message(kind):
        def record(title, body, **_kwargs):
            assert threading.get_ident() == app.root.owner_thread_id
            messages.append((kind, title, body))
        return record

    for kind in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(app_module.messagebox, kind, message(kind))
    app.show_status_message = lambda *_args, **_kwargs: None
    monkeypatch.setenv(app_module.DATA_ROOT_ENV, app.data_root)
    monkeypatch.setenv(sync.ACTIVE_PATH_ENV, str(tmp_path / "previous.csv"))
    monkeypatch.setattr(sync, "_load_item_catalog_logistics_profile", lambda: _profile())
    responses = [CATALOG]
    requests = []

    def transport(url, **kwargs):
        requests.append((url, kwargs))
        result = responses[-1]
        if isinstance(result, Exception):
            raise result
        return FakeResponse(result)

    # Exercise the real startup preparation, authenticated cache and load path;
    # only the HTTP boundary is replaced, so no request can leave this process.
    monkeypatch.setattr(sync, "_hardened_get", transport)
    monkeypatch.setattr(sync.requests, "get", transport)
    app_module.prepare_startup_item_catalog()
    app.items_data = app.load_items()
    app.item_catalog = ItemCatalog(app.items_data)
    requests.clear()
    return app, messages, responses, requests


def _finish(app):
    app.root.run_until(lambda: not app._ui_lane.is_busy(), timeout=10)
    assert not app.root.destroyed


def test_refresh_adds_new_item_through_startup_path_and_preserves_active_root(
    refresh_app, monkeypatch,
):
    app, messages, responses, requests = refresh_app
    previous_root = app.data_root
    previous_tray = app.current_tray
    calls = []
    startup = app_module.prepare_startup_item_catalog

    def prepare():
        calls.append("startup")
        return startup()

    monkeypatch.setattr(app_module, "prepare_startup_item_catalog", prepare)
    assert app._item_catalog().find_by_code(NEW_CODE) is None
    responses.append(UPDATED)
    assert app._refresh_item_catalog() is True
    _finish(app)
    assert calls == ["startup"] and len(requests) == 1
    assert app._item_catalog().find_by_code(NEW_CODE)["Item Name"] == "Gamma"
    assert len(app.items_data) == 3
    assert app.data_root == os.environ[app_module.DATA_ROOT_ENV] == previous_root
    assert app.current_tray is previous_tray
    assert messages[-1] == (
        "showinfo", "품목 목록 새로 고침 완료", "품목 목록을 새로 받았습니다. 현재 3건입니다.",
    )


@pytest.mark.parametrize("failure", ["cache_fallback", "profile", "snapshot", "missing_file"])
def test_refresh_failure_keeps_current_catalog_and_gives_safe_retry_guidance(
    refresh_app, monkeypatch, failure,
):
    app, messages, responses, requests = refresh_app
    rows, catalog = app.items_data, app.item_catalog
    active_path = os.environ[sync.ACTIVE_PATH_ENV]
    original_root = app.data_root
    if failure == "cache_fallback":
        responses.append(OSError("NETWORK_FAILED C:/private/profile.json"))
    elif failure == "profile":
        def reject():
            raise sync.ItemCatalogSyncError("AUTH_FAILED C:/private/profile.json")
        monkeypatch.setattr(sync, "_load_item_catalog_logistics_profile", reject)
    elif failure == "snapshot":
        responses.append(UPDATED)
        load = app.load_items
        def reject_load(**kwargs):
            sync._forget_verified_catalog_snapshot(os.environ[sync.ACTIVE_PATH_ENV])
            return load(**kwargs)
        monkeypatch.setattr(app, "load_items", reject_load)
    else:
        responses.append(UPDATED)
        monkeypatch.setattr(sync, "_load_item_catalog_logistics_profile", lambda: None)
        load = app.load_items
        def missing_file(**kwargs):
            Path(os.environ[sync.ACTIVE_PATH_ENV]).unlink()
            return load(**kwargs)
        monkeypatch.setattr(app, "load_items", missing_file)
    assert app._refresh_item_catalog() is True
    _finish(app)
    assert app.items_data is rows and app.item_catalog is catalog
    assert app._item_catalog().find_by_code(NEW_CODE) is None
    assert os.environ[sync.ACTIVE_PATH_ENV] == active_path
    assert app.data_root == os.environ[app_module.DATA_ROOT_ENV] == original_root
    kind, title, body = messages[-1]
    assert kind == "showwarning" and title == "품목 목록 새로 고침 실패"
    assert "기존 품목 목록 2건" in body and "다시" in body and "담당자" in body
    assert "FAILED" not in body and "C:/" not in body and "캐시" not in body


@pytest.mark.parametrize("state", [
    "tray", "submission", "scan", "preflight", "durable_hold", "completion_review",
    "replacement", "exchange", "closing",
])
def test_refresh_refuses_in_progress_work_without_loading_or_mutation(refresh_app, state):
    app, messages, responses, requests = refresh_app
    if state == "tray":
        app.current_tray.master_label_code = "ACTIVE"
        app.current_tray.scanned_barcodes = ["AAA0000000001-001"]
    elif state == "submission":
        app._completion_lane_busy = True
    elif state == "scan":
        app._scan_callback_pending = True
    elif state == "preflight":
        app._master_preflight_pending = True
    elif state == "durable_hold":
        path = app._preflight_hold_store().path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("unreadable held work", encoding="utf-8")
    elif state == "completion_review":
        app._active_blocking_completion_snapshot = lambda: object()
    elif state == "replacement":
        app.master_label_replace_state = "awaiting_old_completed"
    elif state == "exchange":
        app.exchange_dialog = SimpleNamespace(winfo_exists=lambda: True)
    else:
        app._ui_close_requested = True
    before = (app.current_tray, list(app.current_tray.scanned_barcodes), app.items_data)
    assert app._refresh_item_catalog() is False
    assert requests == []
    assert (app.current_tray, app.current_tray.scanned_barcodes, app.items_data) == before
    assert "작업" in messages[-1][2] and "다시" in messages[-1][2]


def test_refresh_uses_existing_lane_to_reject_scans_and_duplicate_refresh(refresh_app, monkeypatch):
    app, messages, responses, requests = refresh_app
    entered, release = threading.Event(), threading.Event()
    transport = sync._hardened_get

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return transport(*args, **kwargs)

    monkeypatch.setattr(sync, "_hardened_get", delayed)
    responses.append(UPDATED)
    try:
        assert app._refresh_item_catalog() is True
        assert entered.wait(5)
        assert app._scan_entry_admission_block_reason()
        assert app._refresh_item_catalog() is False
        assert app._item_catalog().find_by_code(NEW_CODE) is None
    finally:
        release.set()
    _finish(app)
    assert len(requests) == 1
    assert app._item_catalog().find_by_code(NEW_CODE) is not None


def test_operations_menu_exposes_manual_catalog_refresh(refresh_app, monkeypatch):
    app, _messages, _responses, _requests = refresh_app
    entries = []
    menu = SimpleNamespace(
        add_command=lambda **kwargs: entries.append(kwargs), add_separator=lambda: None,
        tk_popup=lambda *_args: None, grab_release=lambda: None,
    )
    monkeypatch.setattr(app_module.tk, "Menu", lambda *_args, **_kwargs: menu)
    app.root.winfo_pointerx = app.root.winfo_pointery = lambda: 0
    app._exact_transfer_exchange_blocked = lambda: False
    app._show_operations_menu()
    entry = next(row for row in entries if row["label"] == "품목 목록 새로 고침")
    assert entry["command"] == app._refresh_item_catalog


def test_refresh_discards_result_after_work_session_changes(refresh_app):
    app, messages, responses, requests = refresh_app
    rows, catalog = app.items_data, app.item_catalog
    active_path = os.environ[sync.ACTIVE_PATH_ENV]
    responses.append(UPDATED)
    assert app._refresh_item_catalog() is True
    app._scan_callback_epoch += 1
    _finish(app)
    assert app.items_data is rows and app.item_catalog is catalog
    assert os.environ[sync.ACTIVE_PATH_ENV] == active_path
    assert messages[-1][0] == "showwarning"
