"""Intentional detector negatives and import-created resource coverage."""
import sqlite3
import threading

import pytest
import requests

from tests.lock_remote_guard import RemoteWhileLocked

_import_lock = threading.RLock()
_import_connection = sqlite3.connect(":memory:")


class ImportOwner:
    class_lock = threading.RLock()
    def __init__(self):
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(":memory:")


_import_owner = ImportOwner()


@pytest.fixture(scope="module", autouse=True)
def close_import_connections():
    yield
    _import_connection.close()
    _import_owner.connection.close()


@pytest.mark.parametrize("kind", ["thread", "sqlite", "import-thread", "import-sqlite", "owner-thread", "owner-sqlite", "class-thread"])
def test_guard_rejects_locked_http_and_accepts_the_same_unlocked_request(
    kind, tmp_path, monkeypatch, ca_remote_lock_guard,
):
    def send(_session, _request, **_kwargs):
        response = requests.Response()
        response.status_code = 200
        response._content = b"{}"
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    resources = {
        "thread": threading.RLock(), "sqlite": sqlite3.connect(tmp_path / "guard.sqlite3"),
        "import-thread": _import_lock, "import-sqlite": _import_connection,
        "owner-thread": _import_owner.lock, "owner-sqlite": _import_owner.connection,
        "class-thread": ImportOwner.class_lock,
    }
    resource = resources[kind]
    is_connection = "sqlite" in kind
    start = len(ca_remote_lock_guard.events)
    with requests.Session() as session:
        if is_connection:
            resource.execute("BEGIN IMMEDIATE")
        else:
            resource.acquire()
        try:
            with pytest.raises(RemoteWhileLocked):
                session.get("https://guard.invalid")
        finally:
            if is_connection:
                resource.rollback()
            else:
                resource.release()
        failures = [event for event in ca_remote_lock_guard.events[start:]
                    if event["event"] == "remote" and event["locks"]]
        assert len(failures) == 1
        assert failures[0]["locks"][0]["kind"] == ("sqlite transaction" if is_connection else "thread lock")
        # Consume only the explicitly asserted negative event; unexpected locked
        # requests still fail the autouse fixture's strict teardown.
        ca_remote_lock_guard.events.remove(failures[0])
        assert session.get("https://guard.invalid").status_code == 200
        requests_seen = [event for event in ca_remote_lock_guard.events if event["event"] == "remote"]
        assert requests_seen[-1]["locks"] == []
    resources["sqlite"].close()
