"""Startup uses verified offline data without a modal acknowledgement."""
import hashlib
import json
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import item_catalog_sync as sync
import logistics_runtime_profile
from item_catalog import ItemCatalog
from direct_sync_health import RelayHealth
from tests.test_container_p0_contracts import _health_card
from tests.test_item_catalog_sync import CATALOG, FakeResponse, _profile
from tests.test_scanonly_review_regressions import public_scan, real_notice
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR, ITEM

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


@pytest.fixture
def startup(monkeypatch, tmp_path, flow):
    app = flow(transition=False)
    app.info_cards = {"direct_sync": _health_card()}
    app._direct_sync_health = RelayHealth("idle", 0, 0, 0, "", "", "")
    released = []
    def create_app():
        app.items_data = app.load_items()
        app.item_catalog = ItemCatalog(app.items_data)
        return app
    monkeypatch.setattr(ca, "ContainerAudit", create_app)
    monkeypatch.setattr(ca, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(ca, "acquire_runtime_instance", lambda _root:
                        SimpleNamespace(release=lambda: released.append(True)))
    monkeypatch.setattr(ca, "legacy_label_transition_enabled", lambda: False)
    (tmp_path / "data").mkdir()
    monkeypatch.setenv(ca.DATA_ROOT_ENV, str(tmp_path / "data"))
    for name in (sync.URL_ENV, sync.ACTIVE_PATH_ENV, *sync.BASE_URL_ENV_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(logistics_runtime_profile, "load_logistics_runtime_profile",
                        lambda **_kwargs: _profile())
    return app, released


def _offline_catalog(monkeypatch, tmp_path, *, tamper=False):
    bundled = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    catalog = CATALOG.replace(b"AAA0000000001", ITEM.encode("ascii"))
    bundled.write_bytes(catalog)
    sync.refresh_item_catalog(bundled, cache_path=cache,
                             get=lambda *_args, **_kwargs: FakeResponse(catalog))
    if tamper:
        altered = catalog.replace(b"Alpha", b"Altered")
        cache.write_bytes(altered)
        authority_path = sync._cache_authority_path(cache)
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["catalog_sha256"] = hashlib.sha256(altered).hexdigest()
        authority_path.write_text(json.dumps(authority), encoding="utf-8")
        recovery_path = sync._cache_recovery_path(cache)
        recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
        recovery["catalog_utf8"] = altered.decode("utf-8")
        recovery["authority"]["catalog_sha256"] = hashlib.sha256(altered).hexdigest()
        recovery_path.write_text(json.dumps(recovery), encoding="utf-8")

    def offline(*_args, **_kwargs):
        raise ConnectionError("synthetic startup outage")

    monkeypatch.setattr(ca, "refresh_item_catalog", lambda *_args, **kwargs:
                        sync.refresh_item_catalog(bundled, cache_path=cache,
                                                  get=offline, **kwargs))


def test_verified_offline_start_has_no_window_and_scans_then_updates_connection(
    startup, monkeypatch, tmp_path, windows,
):
    app, _released = startup
    _offline_catalog(monkeypatch, tmp_path)
    result = ca._prepare_gui_startup()
    assert isinstance(result, tuple) and result[0] is app
    result[1].release()
    assert windows == []
    text = app.info_cards["direct_sync"]["value"].options["text"]
    context = sync.get_catalog_attempt_context()
    assert context["catalog_source"] == "VERIFIED_CACHE"
    assert "중앙 품목 목록" in text and "캐시 기준 시각" in text
    assert ca._item_catalog_cache_time_for_display(context["cache_last_modified_utc"]) in text
    label = COMPACT_QR + "|QT=2"
    public_scan(app, label)
    assert app.current_tray.master_label_code == label
    public_scan(app, ITEM + "-SERIAL-001")
    assert app.current_tray.scanned_barcodes == [ITEM + "-SERIAL-001"]
    client = app.transfer_seal_coordinator.client
    client.connection_state = "normal"
    app._apply_direct_sync_health(app._direct_sync_health)
    text = app.info_cards["direct_sync"]["value"].options["text"]
    assert "서버 연결: 정상" in text and "목록 재확인 가능" in text
    assert "새로 받지 못해" not in text
    assert "캐시 기준 시각" in text  # Reconnection alone does not refresh the catalog.
    assert windows == []


def test_invalid_offline_cache_still_blocks_startup(startup, monkeypatch, tmp_path, windows):
    _app, released = startup
    _offline_catalog(monkeypatch, tmp_path, tamper=True)
    assert ca._prepare_gui_startup() == ca.ITEM_CATALOG_STARTUP_EXIT_CODE
    assert released == [True]
    assert windows == ["showerror"]


@pytest.mark.parametrize("reason", ["profile_absent", "transition"])
def test_other_nonblocking_catalog_startup_notices_use_connection_card(
    startup, monkeypatch, tmp_path, windows, reason,
):
    app, _released = startup
    if reason == "profile_absent":
        monkeypatch.setattr(logistics_runtime_profile, "load_logistics_runtime_profile",
                            lambda **_kwargs: None)
        expected = "중앙 연결 설정 필요"
    else:
        monkeypatch.setattr(ca, "legacy_label_transition_enabled", lambda: True)
        def unavailable():
            raise sync.ItemCatalogSyncError("synthetic unavailable catalog",
                                           cause_code=sync.REQUEST_FAILED_NO_CACHE)
        monkeypatch.setattr(ca, "prepare_startup_item_catalog", unavailable)
        expected = "과도기 모드"
    result = ca._prepare_gui_startup()
    assert isinstance(result, tuple) and result[0] is app
    result[1].release()
    assert expected in app.info_cards["direct_sync"]["value"].options["text"]
    assert windows == []


def test_best_time_startup_warning_is_inline_and_preserves_corrupt_original(
    flow, tmp_path, windows,
):
    app = flow(transition=True)
    real_notice(app)
    vars(app).pop("show_status_message", None)
    path = tmp_path / "best_time_records.json"
    original = b"{not-json}"
    path.write_bytes(original)
    app.storage_paths = SimpleNamespace(best_time_records_path=path)
    app._load_best_time_records()
    app.root.run_next()
    assert windows == []
    notice = app._warning_state_presenter().state.active_notice
    assert notice is not None and "최고 기록 확인" in notice.message
    assert "원본을 보존" in notice.message and not notice.blocking
    assert path.read_bytes() == original and app.best_time_records == {}
    app.best_time_store.update_best_time({}, 100)
    assert next(tmp_path.glob("best_time_records.json.bad-*")).read_bytes() == original
