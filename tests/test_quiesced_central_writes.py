"""Exercise central transport admission with a real active maintenance fence."""
import copy
import json
from types import SimpleNamespace

import pytest

import writer_session_fence as fence
from tests.test_writer_session_fence import _active_payload, _write_active


@pytest.fixture
def quiesced():
    root = fence.canonical_control_root()
    payload = _active_payload()
    payload["status"] = "PREPARED"
    path = _write_active(root, payload)
    assert fence.active_fence(root)["status"] == "PREPARED"
    yield path
    path.unlink(missing_ok=True)


@pytest.mark.parametrize("command", ["seal", "issue", "release"])
def test_quiesced_transfer_keeps_command_and_retries_same_key(quiesced, command):
    from transfer_client import LogisticsTransferClient, TRANSFER_OPERATION

    calls = []
    session = SimpleNamespace(request=lambda *a, **kw: calls.append((a, kw)) or
                              SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {}}))
    client = LogisticsTransferClient("https://example.invalid", "synthetic-config", "host", session=session)
    context = {"authority_scope_id": "scope", "idempotency_key": "same-key"}
    original = copy.deepcopy(context)
    if command == "seal":
        run = lambda: client.seal_transfer(context)
    elif command == "issue":
        run = lambda: client.issue_operation_lease(authority_scope_id="scope", operation=TRANSFER_OPERATION,
                                                  scan_payload="same-scan", idempotency_key="same-key")
    else:
        run = lambda: client.release_operation_lease(authority_scope_id="scope", operation=TRANSFER_OPERATION,
                                                     token="same-lease", reason="LOCAL_RESET", idempotency_key="same-key")
    with pytest.raises(fence.WriterFencedError):
        run()
    assert calls == []
    assert context == original
    quiesced.unlink()
    run()
    assert len(calls) == 1
    assert calls[0][1]["headers"]["Idempotency-Key"] == "same-key"


@pytest.mark.parametrize("route", ["verifications", "redemptions", "status"])
def test_quiesced_pin_does_not_consume_or_mutate_request(quiesced, monkeypatch, route):
    import container_admin_pin as module
    from tests.test_producer_runtime_client import _credentials

    monkeypatch.setattr(module, "load_credentials_from_json", lambda path: _credentials())
    calls = []
    response_status = 201 if route == "verifications" else 200
    client = module.AdminPinClient("synthetic-path", transport=lambda *a: calls.append(a) or
                                   (response_status, b'{"ok":true}'))
    body = {"request_id": "same-request", "action": "test"}
    before = copy.deepcopy(body)
    with pytest.raises(fence.WriterFencedError):
        client.post(route, body)
    assert calls == []
    assert body == before
    quiesced.unlink()
    assert client.post(route, body) == {"ok": True}
    assert json.loads(calls[0][1]) == before


@pytest.mark.parametrize("pending", [False, True])
def test_quiesced_runtime_lease_keeps_pending_request_for_retry(quiesced, tmp_path, pending):
    from tests.test_producer_runtime_client import _credentials, _LeaseSession
    import producer_runtime_client as client
    import sqlite3

    session = _LeaseSession(failures=1 if pending else 0)
    arguments = dict(db_path=tmp_path / "relay.sqlite3", credentials=_credentials(),
                     producer_install_id="install-test", session=session, now="2026-08-06T00:00:00Z")
    receipt = quiesced.read_bytes()
    before = None
    if pending:
        quiesced.unlink()
        assert client.ensure_runtime_authority(**arguments).error_code
        quiesced.write_bytes(receipt)
        with sqlite3.connect(arguments["db_path"]) as connection:
            before = connection.execute("SELECT pending_request_json FROM direct_sync_runtime_authority").fetchone()[0]
    calls = len(session.calls)
    with pytest.raises(fence.WriterFencedError):
        client.ensure_runtime_authority(**arguments)
    assert len(session.calls) == calls
    if not pending:
        assert not arguments["db_path"].exists()
    else:
        with sqlite3.connect(arguments["db_path"]) as connection:
            assert connection.execute("SELECT pending_request_json FROM direct_sync_runtime_authority").fetchone()[0] == before
    quiesced.unlink()
    assert client.ensure_runtime_authority(**arguments).error_code == ""
    assert len(session.calls) == calls + 1
    if pending:
        assert session.calls[-1][1] == json.loads(before)
