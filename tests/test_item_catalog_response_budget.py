"""Real hardened Session boundary with a network-free HTTPAdapter."""
import threading
from types import SimpleNamespace

import pytest
import requests
from requests.adapters import BaseAdapter
from urllib3.exceptions import ReadTimeoutError

import item_catalog_sync as sync
import logistics_runtime_profile
from tests.test_item_catalog_sync import CATALOG, _profile


class Body:
    def __init__(self, mode, clock):
        self.mode, self.clock = mode, clock
        self.closed = False
        self.reads = 0

    def stream(self, amount, decode_content=True):
        if self.mode == "read-error":
            raise ReadTimeoutError(None, None, "simulated response body timeout")
        if self.mode in ("drip", "overrun"):
            for offset in range(0, len(CATALOG), 4):
                self.clock[0] += 5.0 if self.mode == "drip" else 11.0
                self.reads += 1
                yield CATALOG[offset:offset + 4]
        else:
            self.reads += 1
            yield CATALOG

    def close(self):
        self.closed = True

    def release_conn(self):
        pass


class Adapter(BaseAdapter):
    def __init__(self, clock, *, mode="bytes", status=200, failures=None, late=False):
        self.clock, self.mode, self.status = clock, mode, status
        self.failures, self.late = failures, late
        self.calls, self.bodies = [], []

    def send(self, request, **kwargs):
        self.calls.append({"at": self.clock[0], "timeout": kwargs["timeout"],
                           "stream": kwargs.get("stream", False)})
        if self.failures is not None:
            self.clock[0] += self.failures[min(len(self.calls) - 1, len(self.failures) - 1)]
            raise requests.ConnectionError()
        if self.late:
            self.clock[0] = 41.0
        response = requests.Response()
        response.status_code = self.status
        response.url, response.request = request.url, request
        response.reason = "Service Unavailable" if self.status == 503 else "OK"
        raw = Body(self.mode, self.clock)
        self.bodies.append(raw)
        response.raw = raw
        return response

    def close(self):
        if self.mode == "close-error":
            raise requests.ConnectionError()


@pytest.fixture
def transport(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    cache = tmp_path / "cache" / "Item.csv"
    clock, gaps = [0.0], []
    monkeypatch.setattr(logistics_runtime_profile, "load_logistics_runtime_profile",
                        lambda required=None: _profile(base_url="https://127.0.0.1:9543"))
    monkeypatch.setattr(sync, "_first_fetch_clock", lambda: clock[0])

    def pause(seconds):
        gaps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(sync, "_first_fetch_pause", pause)
    session_type = requests.sessions.Session

    def install(adapter):
        class Session(session_type):
            def __init__(self):
                super().__init__()
                self.mount("https://", adapter)
        monkeypatch.setattr(sync.requests, "Session", Session)

    def refresh(**kwargs):
        return sync.refresh_item_catalog(bundle, cache_path=cache, **kwargs)

    return SimpleNamespace(**locals())


@pytest.mark.parametrize("status", [200, 503])
def test_received_headers_and_body_timeout_never_retry(transport, status):
    adapter = Adapter(transport.clock, mode="read-error", status=status)
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["stream"] is True
    assert transport.gaps == []


def test_session_close_failure_keeps_response_received_proof(transport):
    adapter = Adapter(transport.clock, mode="close-error")
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert len(adapter.calls) == 1
    assert transport.gaps == []


@pytest.mark.parametrize("failures,attempts,elapsed,gaps", [
    ([19.75, 20.0], 2, 40.0, [0.25]),
    ([20.0], 1, 20.25, [0.25]),
    ([0.0], 3, 0.5, [0.25, 0.25]),
], ids=["two-fit", "pause-leaves-less-than-twenty", "immediate-three"])
def test_actual_session_retry_rechecks_after_pause(transport, failures, attempts, elapsed, gaps):
    adapter = Adapter(transport.clock, failures=failures)
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert len(adapter.calls) == attempts
    assert transport.clock[0] == pytest.approx(elapsed)
    assert transport.gaps == gaps


def test_slow_continuous_body_stops_at_total_budget(transport):
    adapter = Adapter(transport.clock, mode="drip")
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert transport.clock[0] == 40.0
    assert len(adapter.calls) == 1 and transport.gaps == []
    assert not transport.cache.exists()


def test_cooperative_budget_allows_only_the_current_read_to_finish(transport, monkeypatch):
    def forbidden_timer(*args, **kwargs):
        pytest.fail("catalog budget must not create a timer")

    monkeypatch.setattr(threading, "Timer", forbidden_timer)
    before = set(threading.enumerate())
    adapter = Adapter(transport.clock, mode="overrun")
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert transport.clock[0] == 44.0
    assert adapter.bodies[0].closed
    assert set(threading.enumerate()) == before
    assert len(adapter.calls) == 1 and transport.gaps == []
    assert not transport.cache.exists()


def test_oversleep_does_not_start_an_attempt_without_twenty_seconds(transport, monkeypatch):
    def oversleep(seconds):
        transport.gaps.append(seconds)
        transport.clock[0] += seconds + 0.01

    monkeypatch.setattr(sync, "_first_fetch_pause", oversleep)
    adapter = Adapter(transport.clock, failures=[19.75])
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert len(adapter.calls) == 1
    assert transport.clock[0] == pytest.approx(20.01)


def test_response_arriving_after_budget_is_not_committed(transport):
    adapter = Adapter(transport.clock, late=True)
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh()
    assert len(adapter.calls) == 1 and transport.gaps == []
    assert not transport.cache.exists()


def test_verified_cache_keeps_original_hardened_request(transport):
    adapter = Adapter(transport.clock)
    transport.install(adapter)
    assert transport.refresh() == transport.cache
    adapter.calls.clear()
    adapter.failures = [0.0]
    assert transport.refresh() == transport.cache
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["timeout"] == 2.0 and adapter.calls[0]["stream"] is False
    assert transport.gaps == []


def test_explicit_timeout_keeps_original_single_request(transport):
    adapter = Adapter(transport.clock, failures=[0.0])
    transport.install(adapter)
    with pytest.raises(sync.ItemCatalogSyncError):
        transport.refresh(timeout_seconds=4.0)
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["timeout"] == 4.0 and adapter.calls[0]["stream"] is False
    assert transport.gaps == []
