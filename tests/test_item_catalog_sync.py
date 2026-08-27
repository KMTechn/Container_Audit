import hashlib
import json
import logging
from types import SimpleNamespace

import pytest

import item_catalog_sync as sync
import logistics_runtime_profile
from item_catalog_sync import refresh_item_catalog, resolve_catalog_url


CATALOG = (
    b"Item Code,Item Name,Spec,Tray Image\r\n"
    b"AAA0000000001,Alpha,S1,assets/a.png\r\n"
    b"BBB0000000002,Beta,S2,assets/b.png\r\n"
)
PRODUCTION_CATALOG_URL = (
    "https://worker.kmtecherp.com/inbound/api/item-catalog.csv"
)
PRODUCTION_CATALOG_URL_WITH_PORT = (
    "https://worker.kmtecherp.com:443/inbound/api/item-catalog.csv"
)
PROFILE_CATALOG_ORIGIN = "https://server5.autoloop.test:18457"
PROFILE_CATALOG_URL = PROFILE_CATALOG_ORIGIN + sync.CATALOG_PATH
UNAUTHENTICATED_OVERRIDE_URL = "https://worker.example/inbound/api/item-catalog.csv"
SECRET_MARKER = "5d03e2a60134151de181ba304a5cdf2eb5dc21eaef5a6ebadd7354d582d12a2b"
SOURCE_HOST_ID = "factory-source-host"
DEVICE_ID = "factory-device"
UNTRUSTED_AUTHENTICATED_URLS = (
    pytest.param(
        "http://worker.kmtecherp.com/inbound/api/item-catalog.csv",
        id="http",
    ),
    pytest.param(
        "https://worker.example/inbound/api/item-catalog.csv",
        id="foreign-origin",
    ),
    pytest.param(
        "https://worker.kmtecherp.com:444/inbound/api/item-catalog.csv",
        id="unexpected-port",
    ),
    pytest.param(
        "https://worker.kmtecherp.com:/inbound/api/item-catalog.csv",
        id="empty-port",
    ),
    pytest.param(
        "https://operator@worker.kmtecherp.com/inbound/api/item-catalog.csv",
        id="userinfo",
    ),
    pytest.param("https://worker.kmtecherp.com/catalog.csv", id="wrong-path"),
    pytest.param(
        "https://worker.kmtecherp.com/inbound/api/item-catalog.csv?download=1",
        id="query",
    ),
    pytest.param(
        "https://worker.kmtecherp.com/inbound/api/item-catalog.csv#catalog",
        id="fragment",
    ),
)


class FakeResponse:
    def __init__(self, content, *, status_code=200, reason="OK"):
        self.content = content
        self.status_code = status_code
        self.reason = reason

    def raise_for_status(self):
        return None


def _profile(**overrides):
    values = {
        "base_url": sync.DEFAULT_SERVER_BASE_URL,
        "bearer_token": SECRET_MARKER,
        "source_host_id": SOURCE_HOST_ID,
        "device_id": DEVICE_ID,
        "isolated_qualification_authority_id": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture(autouse=True)
def _no_logistics_runtime_profile(monkeypatch):
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: None,
    )


def test_catalog_cause_code_profile_load_failed(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    calls = []

    def fail_profile(*, required):
        raise RuntimeError(f"profile secret must stay hidden: {SECRET_MARKER}")

    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        fail_profile,
    )

    with pytest.raises(sync.ItemCatalogSyncError) as raised:
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            get=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

    assert raised.value.cause_code == sync.PROFILE_LOAD_FAILED
    assert raised.value.diagnostic_context["request_sent"] is False
    assert raised.value.diagnostic_context["pre_send_rejection_code"] == sync.PROFILE_LOAD_FAILED
    assert raised.value.diagnostic_context["exception_type"] == "RuntimeError"
    assert calls == []


def test_catalog_cause_code_profile_incomplete(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(device_id=""),
    )

    with pytest.raises(sync.ItemCatalogSyncError) as raised:
        refresh_item_catalog(bundle, cache_path=tmp_path / "cache.csv")

    assert raised.value.cause_code == sync.PROFILE_INCOMPLETE
    assert raised.value.diagnostic_context["request_sent"] is False
    assert raised.value.diagnostic_context["central_enrolled"] is True
    assert raised.value.diagnostic_context["profile_present"] is True
    assert raised.value.diagnostic_context["pre_send_rejection_code"] == sync.PROFILE_INCOMPLETE


def test_catalog_cause_code_url_not_trusted_without_transport(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    calls = []
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(base_url=PROFILE_CATALOG_ORIGIN),
    )

    with pytest.raises(sync.ItemCatalogSyncError) as raised:
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            url="https://operator@foreign.example.invalid:9443/wrong.csv?secret=query",
            get=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

    assert raised.value.cause_code == sync.URL_NOT_TRUSTED
    assert raised.value.diagnostic_context["catalog_url"] == {
        "scheme": "https",
        "host": "foreign.example.invalid",
        "port": 9443,
        "path": "/wrong.csv",
    }
    assert raised.value.diagnostic_context["request_sent"] is False
    assert raised.value.diagnostic_context["pre_send_rejection_code"] == sync.URL_NOT_TRUSTED
    assert calls == []


def test_catalog_cause_code_request_failed_no_cache(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(base_url=PROFILE_CATALOG_ORIGIN),
    )

    with pytest.raises(sync.ItemCatalogSyncError) as raised:
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("catalog transport failed")
            ),
        )

    assert raised.value.cause_code == sync.REQUEST_FAILED_NO_CACHE
    assert raised.value.diagnostic_context["request_sent"] is True
    assert raised.value.diagnostic_context["http_status_code"] is None
    assert raised.value.diagnostic_context["exception_type"] == "OSError"


@pytest.mark.parametrize(
    "catalog_url",
    (PRODUCTION_CATALOG_URL, PRODUCTION_CATALOG_URL_WITH_PORT),
)
def test_refresh_uses_provisioned_logistics_profile_headers(
    monkeypatch, tmp_path, catalog_url
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    profile_calls = []
    calls = []

    def load_profile(*, required):
        profile_calls.append(required)
        return _profile()

    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        load_profile,
    )

    def fake_get(url, timeout, allow_redirects, headers):
        assert allow_redirects is False
        calls.append((url, timeout, headers))
        return FakeResponse(CATALOG)

    result = refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=catalog_url,
        get=fake_get,
    )

    assert result == cache
    assert profile_calls == [None]
    assert calls == [
        (
            catalog_url,
            2.0,
            {
                "Authorization": f"Bearer {SECRET_MARKER}",
                "X-Logistics-Source-Host-Id": SOURCE_HOST_ID,
                "X-Logistics-Device-Id": DEVICE_ID,
                "X-Logistics-Program": "Container_Audit",
            },
        )
    ]


def test_refresh_passes_profile_tls_ca_bundle_to_requests_verify(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    ca_bundle = tmp_path / "profile" / "tls" / "ca-bundle.pem"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(
            base_url=PROFILE_CATALOG_ORIGIN,
            tls_ca_bundle_path=str(ca_bundle),
        ),
    )
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(CATALOG)

    assert refresh_item_catalog(bundle, cache_path=cache, get=fake_get) == cache
    assert len(calls) == 1
    assert calls[0][0] == PROFILE_CATALOG_URL
    assert calls[0][1]["verify"] == str(ca_bundle)
    assert calls[0][1]["verify"] is not False


@pytest.mark.parametrize("configured_path", [None, "", "   ", False, 0])
def test_refresh_never_disables_tls_verification_when_ca_path_is_absent(
    monkeypatch, tmp_path, configured_path
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    overrides = {"base_url": PROFILE_CATALOG_ORIGIN}
    if configured_path is not None:
        overrides["tls_ca_bundle_path"] = configured_path
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(**overrides),
    )
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(CATALOG)

    assert refresh_item_catalog(bundle, cache_path=cache, get=fake_get) == cache
    assert len(calls) == 1
    assert "verify" not in calls[0][1]
    assert calls[0][1].get("verify", True) is True


def test_runtime_profile_origin_drives_default_catalog_route(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    calls = []
    monkeypatch.setenv(
        sync.URL_ENV,
        "https://foreign.example.invalid/inbound/api/item-catalog.csv",
    )
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(base_url=PROFILE_CATALOG_ORIGIN),
    )

    def fake_get(url, timeout, allow_redirects, headers):
        calls.append((url, timeout, allow_redirects, headers))
        return FakeResponse(CATALOG)

    assert refresh_item_catalog(bundle, cache_path=cache, get=fake_get) == cache
    assert calls == [
        (
            PROFILE_CATALOG_URL,
            2.0,
            False,
            {
                "Authorization": f"Bearer {SECRET_MARKER}",
                "X-Logistics-Source-Host-Id": SOURCE_HOST_ID,
                "X-Logistics-Device-Id": DEVICE_ID,
                "X-Logistics-Program": "Container_Audit",
            },
        )
    ]


def test_runtime_profile_rejects_foreign_origin_without_transport(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    calls = []
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(base_url=PROFILE_CATALOG_ORIGIN),
    )

    with pytest.raises(
        sync.ItemCatalogSyncError,
        match="central item catalog URL is not trusted",
    ):
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            url="https://foreign.example.invalid/inbound/api/item-catalog.csv",
            get=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

    assert calls == []


def test_runtime_profile_preserves_production_catalog_route(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    calls = []
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )

    def fake_get(url, timeout, allow_redirects, headers):
        calls.append((url, timeout, allow_redirects, headers))
        return FakeResponse(CATALOG)

    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL_WITH_PORT,
        get=fake_get,
    ) == cache
    assert calls == [
        (
            PRODUCTION_CATALOG_URL_WITH_PORT,
            2.0,
            False,
            {
                "Authorization": f"Bearer {SECRET_MARKER}",
                "X-Logistics-Source-Host-Id": SOURCE_HOST_ID,
                "X-Logistics-Device-Id": DEVICE_ID,
                "X-Logistics-Program": "Container_Audit",
            },
        )
    ]


def test_runtime_profile_rejects_near_match_origin_without_transport(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    calls = []
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(base_url=PROFILE_CATALOG_ORIGIN),
    )

    with pytest.raises(
        sync.ItemCatalogSyncError,
        match="central item catalog URL is not trusted",
    ):
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            url="https://server5.autoloop.test:18458/inbound/api/item-catalog.csv",
            get=lambda *args, **kwargs: calls.append((args, kwargs)),
        )

    assert calls == []


@pytest.mark.parametrize("url", UNTRUSTED_AUTHENTICATED_URLS)
def test_profile_rejects_untrusted_url_without_transport(
    monkeypatch, tmp_path, caplog, url
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    calls = []

    def unexpected_get(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("transport must not be called")

    with caplog.at_level(logging.WARNING, logger=sync.__name__):
        with pytest.raises(
            sync.ItemCatalogSyncError,
            match="central item catalog URL is not trusted",
        ):
            refresh_item_catalog(
                bundle,
                cache_path=tmp_path / "cache.csv",
                url=url,
                get=unexpected_get,
            )

    assert calls == []
    assert SECRET_MARKER not in caplog.text


def test_absent_profile_preserves_unauthenticated_override(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache.csv"
    bundle.write_bytes(CATALOG)
    profile_calls = []
    calls = []

    def load_profile(*, required):
        profile_calls.append(required)
        return None

    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        load_profile,
    )

    def fake_get(url, timeout, allow_redirects):
        assert allow_redirects is False
        calls.append((url, timeout))
        return FakeResponse(CATALOG)

    result = refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=UNAUTHENTICATED_OVERRIDE_URL,
        get=fake_get,
    )

    assert result == cache
    assert profile_calls == [None]
    assert calls == [(UNAUTHENTICATED_OVERRIDE_URL, 2.0)]


def test_unavailable_profile_fails_closed_without_unauthenticated_transport_or_leak(
    monkeypatch, tmp_path, caplog
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    calls = []

    def unavailable_profile(*, required):
        raise RuntimeError(f"profile unavailable: {SECRET_MARKER}")

    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        unavailable_profile,
    )

    def fake_get(url, timeout, allow_redirects):
        assert allow_redirects is False
        calls.append((url, timeout))
        return FakeResponse(CATALOG)

    with caplog.at_level(logging.WARNING, logger=sync.__name__):
        with pytest.raises(
            sync.ItemCatalogSyncError,
            match="central item catalog profile could not be loaded",
        ) as raised:
            refresh_item_catalog(
                bundle,
                cache_path=tmp_path / "cache.csv",
                url=UNAUTHENTICATED_OVERRIDE_URL,
                get=fake_get,
            )

    assert calls == []
    assert SECRET_MARKER not in caplog.text
    assert "profile unavailable" not in caplog.text
    assert SECRET_MARKER not in str(raised.value)
    assert raised.value.__cause__ is None


def test_authenticated_request_failure_does_not_log_exception_message(
    monkeypatch, tmp_path, caplog
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    calls = []

    def failing_get(url, timeout, allow_redirects, headers):
        assert allow_redirects is False
        calls.append((url, timeout, headers))
        raise OSError(f"transport failed: {SECRET_MARKER}")

    with caplog.at_level(logging.WARNING, logger=sync.__name__):
        with pytest.raises(
            sync.ItemCatalogSyncError,
            match="no last central cache exists",
        ) as raised:
            refresh_item_catalog(
                bundle,
                cache_path=tmp_path / "cache.csv",
                url=PRODUCTION_CATALOG_URL,
                get=failing_get,
            )

    assert calls == [
        (
            PRODUCTION_CATALOG_URL,
            2.0,
            {
                "Authorization": f"Bearer {SECRET_MARKER}",
                "X-Logistics-Source-Host-Id": SOURCE_HOST_ID,
                "X-Logistics-Device-Id": DEVICE_ID,
                "X-Logistics-Program": "Container_Audit",
            },
        )
    ]
    assert SECRET_MARKER not in caplog.text
    assert "transport failed" not in caplog.text
    assert SECRET_MARKER not in str(raised.value)
    assert raised.value.__cause__ is None


def test_redirect_response_is_rejected_and_uses_last_good_cache(
    monkeypatch, tmp_path, caplog
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    cached_catalog = CATALOG.replace(b"Alpha", b"Cached")
    redirected_catalog = CATALOG.replace(b"Alpha", b"Redirected")
    bundle.write_bytes(CATALOG)
    sync._write_authenticated_cache(
        cache,
        cached_catalog,
        url=PRODUCTION_CATALOG_URL,
        source_host_id=SOURCE_HOST_ID,
        device_id=DEVICE_ID,
        bearer_token=SECRET_MARKER,
    )
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    calls = []

    def redirecting_get(url, timeout, allow_redirects, headers):
        calls.append((url, timeout, allow_redirects, headers["Authorization"]))
        return FakeResponse(redirected_catalog, status_code=302)

    with caplog.at_level(logging.WARNING, logger=sync.__name__):
        result = refresh_item_catalog(
            bundle,
            cache_path=cache,
            url=PRODUCTION_CATALOG_URL,
            get=redirecting_get,
        )

    assert result == cache
    assert cache.read_bytes() == cached_catalog
    assert calls == [
        (PRODUCTION_CATALOG_URL, 2.0, False, f"Bearer {SECRET_MARKER}")
    ]
    assert "using the last central cache" in caplog.text


def test_replace_race_returns_cache_created_before_permission_error(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    real_atomic_write = sync._atomic_write

    def write_cache_then_fail(path, payload):
        real_atomic_write(path, payload)
        raise PermissionError("simulated shared-cache replace race")

    monkeypatch.setattr(sync, "_atomic_write", write_cache_then_fail)

    result = refresh_item_catalog(
        bundle,
        cache_path=cache,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    )

    assert result == cache
    assert cache.read_bytes() == CATALOG


def test_central_refresh_success_and_offline_last_good(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache
    assert cache.read_bytes() == CATALOG
    assert SECRET_MARKER not in sync._cache_authority_path(cache).read_text(
        encoding="utf-8"
    )
    assert SECRET_MARKER not in sync._cache_recovery_path(cache).read_text(
        encoding="utf-8"
    )

    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL_WITH_PORT,
        get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    ) == cache
    assert cache.read_bytes() == CATALOG
    assert list(cache.parent.glob("*.tmp")) == []


def test_pre_enrollment_cache_is_not_accepted_after_enrollment(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=UNAUTHENTICATED_OVERRIDE_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache
    assert not sync._cache_authority_path(cache).exists()

    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    with pytest.raises(sync.ItemCatalogSyncError, match="no last central cache exists"):
        refresh_item_catalog(
            bundle,
            cache_path=cache,
            url=PRODUCTION_CATALOG_URL,
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
        )


@pytest.mark.parametrize("mutation", ("identity", "catalog", "program", "mac"))
def test_authenticated_cache_is_bound_to_identity_hash_and_program(
    monkeypatch, tmp_path, mutation
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    profile = _profile()
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: profile,
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache

    if mutation == "identity":
        profile.device_id = "different-device"
    elif mutation == "catalog":
        tampered = CATALOG.replace(b"Alpha", b"Tampered")
        cache.write_bytes(tampered)
        authority_path = sync._cache_authority_path(cache)
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["catalog_sha256"] = hashlib.sha256(tampered).hexdigest()
        authority_path.write_text(json.dumps(authority), encoding="utf-8")
        recovery_path = sync._cache_recovery_path(cache)
        recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
        recovery["catalog_utf8"] = tampered.decode("utf-8")
        recovery["authority"]["catalog_sha256"] = hashlib.sha256(
            tampered
        ).hexdigest()
        recovery_path.write_text(json.dumps(recovery), encoding="utf-8")
    elif mutation == "program":
        authority_path = sync._cache_authority_path(cache)
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["program"] = "Other_program"
        authority_path.write_text(json.dumps(authority), encoding="utf-8")
        recovery_path = sync._cache_recovery_path(cache)
        recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
        recovery["authority"]["program"] = "Other_program"
        recovery_path.write_text(json.dumps(recovery), encoding="utf-8")
    else:
        authority_path = sync._cache_authority_path(cache)
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["cache_hmac_sha256"] = "é"
        authority_path.write_text(json.dumps(authority), encoding="utf-8")
        recovery_path = sync._cache_recovery_path(cache)
        recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
        recovery["authority"]["cache_hmac_sha256"] = "é"
        recovery_path.write_text(json.dumps(recovery), encoding="utf-8")

    with pytest.raises(sync.ItemCatalogSyncError, match="no last central cache exists"):
        refresh_item_catalog(
            bundle,
            cache_path=cache,
            url=PRODUCTION_CATALOG_URL,
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
        )


def test_authenticated_cache_rejects_v1_manifest_and_rotated_token(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    profile = _profile()
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: profile,
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache

    authority_path = sync._cache_authority_path(cache)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority["schema"] = "kmtech.item-catalog.authority.v1"
    authority_path.write_text(json.dumps(authority), encoding="utf-8")
    sync._cache_recovery_path(cache).unlink()
    with pytest.raises(sync.ItemCatalogSyncError):
        refresh_item_catalog(
            bundle,
            cache_path=cache,
            url=PRODUCTION_CATALOG_URL,
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
        )

    authority["schema"] = sync.CACHE_AUTHORITY_SCHEMA
    authority_path.write_text(json.dumps(authority), encoding="utf-8")
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache
    profile.bearer_token = "rotated-catalog-token"
    with pytest.raises(sync.ItemCatalogSyncError):
        refresh_item_catalog(
            bundle,
            cache_path=cache,
            url=PRODUCTION_CATALOG_URL,
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
        )
    assert sync.get_verified_catalog_snapshot(cache) is None
    assert sync.requires_verified_catalog_snapshot(cache)


def test_authenticated_update_recovers_new_catalog_after_token_rotation(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    updated = CATALOG.replace(b"Alpha", b"Updated")
    bundle.write_bytes(CATALOG)
    profile = _profile()
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: profile,
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache
    profile.bearer_token = "rotated-catalog-token"

    real_atomic_write = sync._atomic_write
    primary_authority = sync._cache_authority_path(cache)

    def fail_primary_manifest(path, payload):
        if path == primary_authority:
            raise OSError("simulated power loss before manifest commit")
        real_atomic_write(path, payload)

    monkeypatch.setattr(sync, "_atomic_write", fail_primary_manifest)
    last_good = sync._last_good_cache_path(cache)
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(updated),
    ) == last_good
    assert last_good.read_bytes() == updated
    assert profile.bearer_token not in sync._cache_recovery_path(cache).read_text(
        encoding="utf-8"
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    ) == last_good
    assert last_good.read_bytes() == updated


def test_authenticated_default_transport_ignores_process_proxy_environment(
    monkeypatch, tmp_path
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    observations = []

    class FakeSession:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, _url, **_kwargs):
            observations.append(self.trust_env)
            return FakeResponse(CATALOG)

    monkeypatch.setattr(sync.requests, "Session", FakeSession)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "untrusted.pem"))

    assert refresh_item_catalog(
        bundle,
        cache_path=tmp_path / "cache" / "Item.csv",
        url=PRODUCTION_CATALOG_URL,
    ).is_file()
    assert observations == [False]


def test_default_cache_is_namespaced_by_program(tmp_path):
    cache = sync.default_cache_path({"LOCALAPPDATA": str(tmp_path)})
    assert cache == tmp_path / "KMTech" / "ItemCatalog" / "Container_Audit" / "Item.csv"


def test_cache_hmac_v2_framing_vector_is_stable():
    authority = sync._cache_authority_record(
        CATALOG,
        url=PRODUCTION_CATALOG_URL,
        source_host_id=SOURCE_HOST_ID,
        device_id=DEVICE_ID,
    )
    assert sync._cache_authority_hmac(
        CATALOG,
        authority,
        bearer_token=SECRET_MARKER,
    ) == "5971c2a36c3f1895a2e3d4e6aa636bd0c6a5bd5a36fc5c376c43962ec44e7da3"


def test_catalog_cause_code_snapshot_unavailable_after_verify(monkeypatch, tmp_path):
    import Container_Audit as app_module

    cache = tmp_path / "cache" / "Item.csv"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(CATALOG)
    key = sync._catalog_snapshot_key(cache)
    sync._REQUIRED_VERIFIED_CATALOG_SNAPSHOT_PATHS.add(key)
    sync._forget_verified_catalog_snapshot(cache)
    monkeypatch.setattr(app_module, "refresh_item_catalog", lambda _path: cache)
    try:
        with pytest.raises(sync.ItemCatalogSyncError) as raised:
            app_module.prepare_startup_item_catalog()
    finally:
        sync._REQUIRED_VERIFIED_CATALOG_SNAPSHOT_PATHS.discard(key)
        sync._forget_verified_catalog_snapshot(cache)

    assert raised.value.cause_code == sync.SNAPSHOT_UNAVAILABLE_AFTER_VERIFY


def test_catalog_cause_code_snapshot_parse_failed(monkeypatch, tmp_path):
    import Container_Audit as app_module

    cache = tmp_path / "cache" / "Item.csv"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(CATALOG)
    key = sync._catalog_snapshot_key(cache)
    sync._REQUIRED_VERIFIED_CATALOG_SNAPSHOT_PATHS.add(key)
    sync._remember_verified_catalog_snapshot(cache, b"\xff")
    monkeypatch.setenv(sync.ACTIVE_PATH_ENV, str(cache))
    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    try:
        with pytest.raises(sync.ItemCatalogSyncError) as raised:
            app.load_items()
    finally:
        sync._REQUIRED_VERIFIED_CATALOG_SNAPSHOT_PATHS.discard(key)
        sync._forget_verified_catalog_snapshot(cache)

    assert raised.value.cause_code == sync.SNAPSHOT_PARSE_FAILED
    assert raised.value.diagnostic_context["exception_type"] == "UnicodeDecodeError"


def test_catalog_failure_diagnostic_is_bounded_and_contains_no_secrets(
    monkeypatch,
    tmp_path,
):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    source_host_id = "source-host-secret-6b5ffbe0"
    device_id = "device-id-secret-e90547f4"
    qualification_id = "qualification-secret-faf92280"
    bearer_token = "bearer-secret-e30cf16f"
    profile = _profile(
        base_url=PROFILE_CATALOG_ORIGIN,
        bearer_token=bearer_token,
        source_host_id=source_host_id,
        device_id=device_id,
        isolated_qualification_authority_id=qualification_id,
    )
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: profile,
    )

    class RejectedResponse(FakeResponse):
        def __init__(self):
            super().__init__(
                CATALOG,
                status_code=503,
                reason="Service Unavailable",
            )

        def raise_for_status(self):
            raise OSError(
                f"hidden {bearer_token} {source_host_id} {device_id} {qualification_id}"
            )

    with pytest.raises(sync.ItemCatalogSyncError) as raised:
        refresh_item_catalog(
            bundle,
            cache_path=tmp_path / "cache.csv",
            get=lambda *_args, **_kwargs: RejectedResponse(),
        )

    raised.value.diagnostic_context["unexpected_secret"] = bearer_token
    diagnostic_path = tmp_path / "item_catalog_startup_diagnostic.json"
    sync.write_item_catalog_failure_diagnostic(diagnostic_path, raised.value)
    diagnostic_text = diagnostic_path.read_text(encoding="utf-8")
    diagnostic = json.loads(diagnostic_text)

    assert diagnostic["cause_code"] == sync.REQUEST_FAILED_NO_CACHE
    assert diagnostic["catalog_url"] == {
        "scheme": "https",
        "host": "server5.autoloop.test",
        "port": 18457,
        "path": sync.CATALOG_PATH,
    }
    assert diagnostic["request_sent"] is True
    assert diagnostic["http_status_code"] == 503
    assert diagnostic["http_reason_phrase"] == "Service Unavailable"
    assert diagnostic["pre_send_rejection_code"] is None
    assert diagnostic["central_enrolled"] is True
    assert diagnostic["profile_present"] is True
    assert diagnostic["qualification_authority_id_present"] is True
    assert diagnostic["exception_type"] == "OSError"
    assert "exception_message" not in diagnostic
    assert diagnostic_path.stat().st_size <= 8192
    for secret in (
        bearer_token,
        source_host_id,
        device_id,
        qualification_id,
        "Authorization",
        "Bearer",
    ):
        assert secret not in diagnostic_text


def test_startup_load_items_uses_verified_snapshot_after_cache_tamper(
    monkeypatch, tmp_path
):
    import Container_Audit as app_module

    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache" / "Item.csv"
    bundle.write_bytes(CATALOG)
    monkeypatch.setattr(
        logistics_runtime_profile,
        "load_logistics_runtime_profile",
        lambda required=None: _profile(),
    )
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        url=PRODUCTION_CATALOG_URL,
        get=lambda *_args, **_kwargs: FakeResponse(CATALOG),
    ) == cache
    assert sync.requires_verified_catalog_snapshot(cache)
    assert sync.get_verified_catalog_snapshot(cache) == CATALOG

    monkeypatch.setattr(app_module, "refresh_item_catalog", lambda _path: cache)
    assert app_module.prepare_startup_item_catalog() == str(cache)
    tampered = CATALOG.replace(b"AAA0000000001", b"AAA9999999999")
    cache.write_bytes(tampered)

    app = app_module.ContainerAudit.__new__(app_module.ContainerAudit)
    rows = app.load_items()

    assert [row["Item Code"] for row in rows] == [
        "AAA0000000001",
        "BBB0000000002",
    ]
    assert cache.read_bytes() == tampered
    sync._forget_verified_catalog_snapshot(cache)
    with pytest.raises(
        app_module.ItemCatalogSyncError,
        match="snapshot is unavailable",
    ):
        app_module.prepare_startup_item_catalog()


def test_invalid_response_keeps_bundle_and_url_contract(tmp_path):
    bundle = tmp_path / "bundle.csv"
    cache = tmp_path / "cache.csv"
    bundle.write_bytes(CATALOG)
    assert refresh_item_catalog(
        bundle,
        cache_path=cache,
        get=lambda *_args, **_kwargs: FakeResponse(b"wrong,header\n"),
    ) == bundle
    assert not cache.exists()
    assert resolve_catalog_url({"WORKER_ANALYSIS_SERVER_URL": "https://worker.example/"}) == (
        "https://worker.example/inbound/api/item-catalog.csv"
    )
    assert resolve_catalog_url({"KMTECH_ITEM_CATALOG_URL": "http://test/catalog.csv"}) == "http://test/catalog.csv"
