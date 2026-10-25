"""Initial authenticated fetch budget without changing verified-cache startup."""
import pytest
import requests

import item_catalog_sync as sync
import logistics_runtime_profile
from tests.test_item_catalog_sync import CATALOG, FakeResponse, _profile


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    cache = tmp_path / "cache" / "Item.csv"
    monkeypatch.setattr(logistics_runtime_profile, "load_logistics_runtime_profile",
                        lambda required=None: _profile())
    return bundle, cache


def refresh(catalog, get, **kwargs):
    bundle, cache = catalog
    return sync.refresh_item_catalog(bundle, cache_path=cache, get=get, **kwargs)


def test_first_response_after_two_seconds_can_start(catalog):
    seen = []

    def slow_server(url, **kwargs):
        seen.append(kwargs["timeout"])
        if kwargs["timeout"] < 3:
            raise requests.ReadTimeout()
        return FakeResponse(CATALOG)

    assert refresh(catalog, slow_server) == catalog[1]
    assert seen == [10.0]


def test_first_transport_errors_twice_then_success(catalog, monkeypatch):
    seen, gaps = [], []
    # The product sleep is observed without changing the test runner's clock.
    monkeypatch.setattr(sync, "_first_fetch_pause", gaps.append, raising=False)

    def transport(url, **kwargs):
        seen.append(kwargs["timeout"])
        if len(seen) < 3:
            raise requests.ConnectionError()
        return FakeResponse(CATALOG)

    assert refresh(catalog, transport) == catalog[1]
    assert seen == [10.0] * 3
    assert gaps == [0.25, 0.25]


@pytest.mark.parametrize("failure", ["http", "invalid", "headers-then-read"])
def test_response_or_validation_failure_never_retries(catalog, failure):
    seen = []

    class Response(FakeResponse):
        def raise_for_status(self):
            if failure == "http":
                raise requests.HTTPError(response=self)

        @property
        def content(self):
            if failure == "headers-then-read":
                raise requests.ReadTimeout()
            return b"invalid" if failure == "invalid" else CATALOG

        @content.setter
        def content(self, value):
            pass

    def transport(url, **kwargs):
        seen.append(kwargs["timeout"])
        return Response(CATALOG, status_code=500 if failure == "http" else 200)

    with pytest.raises(sync.ItemCatalogSyncError):
        refresh(catalog, transport)
    assert seen == [10.0]


@pytest.mark.parametrize("recovery", [False, True])
def test_verified_cache_keeps_single_two_second_attempt(catalog, recovery):
    refresh(catalog, lambda *args, **kwargs: FakeResponse(CATALOG))
    if recovery:
        catalog[1].unlink()
    seen = []

    def transport(url, **kwargs):
        seen.append(kwargs["timeout"])
        raise requests.ConnectionError()

    assert refresh(catalog, transport).is_file()
    assert seen == [2.0]


def test_explicit_timeout_stays_unchanged(catalog):
    seen = []

    def transport(url, **kwargs):
        seen.append(kwargs["timeout"])
        raise requests.ConnectionError()

    with pytest.raises(sync.ItemCatalogSyncError):
        refresh(catalog, transport, timeout_seconds=4.0)
    assert seen == [4.0]
