"""CA-owned callbacks, writer admission and ACK transaction around the pinned core."""
from contextlib import closing
import json
import sqlite3

import pytest

import direct_sync_push as push
import producer_runtime_client as client
import writer_session_fence as fence
from kmtech_shared import runtime as core
from tests.test_producer_runtime_client import (
    _credentials, _insert_claimed_row, _LeaseSession, _prepare,
)
from tests.test_writer_session_fence import _active_payload, _write_active


@pytest.mark.parametrize("operation", ["create", "replace", "review", "disable", "release"])
def test_identity_factory_is_resolved_from_the_app_at_call_time(monkeypatch, operation):
    public_jwk = client.generate_public_jwk()
    calls = []

    def identity():
        calls.append(True)
        return "runtime-callback", public_jwk

    monkeypatch.setattr(client, "new_runtime_identity", identity)
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        client.init_runtime_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        scope = client._scope_values(_credentials(), "install-test")
        if operation in {"create", "replace"}:
            state = client._create_state(conn, scope, "2026-08-06T00:00:00Z")
            if operation == "replace":
                state = client._replace_expired_identity(conn, state, "2026-08-07T00:00:00Z")
        else:
            kwargs = dict(relay_id="relay-a", metadata={"producer_install_id": "install-test"},
                          credentials=_credentials(), now="2026-08-06T00:00:00Z")
            if operation == "review":
                client.mark_runtime_operator_review_in_transaction(conn, error_code="review", **kwargs)
            elif operation == "disable":
                client.disable_runtime_authority_in_transaction(conn, **kwargs)
            else:
                client.release_runtime_request_in_transaction(conn, **kwargs)
            state = client._state_row(conn, client._scope_key(scope))
        assert len(calls) == (2 if operation == "replace" else 1)
        assert state["runtime_instance_id"] == "runtime-callback"
        assert json.loads(state["runtime_public_jwk_json"]) == public_jwk
        assert conn.in_transaction


def test_jwk_callbacks_remain_app_owned_and_invalid_points_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(client, "_cng_jwk_thumbprint", lambda jwk: "app-thumbprint")
    db = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db, "relay-a")
    prepared = _prepare(db, "relay-a", _LeaseSession())
    assert prepared.metadata is not None  # Grant binding used the patched thumbprint.
    invalid = dict(prepared.metadata, runtime_public_jwk={
        "kty": "EC", "crv": "P-256", "x": "A" * 43, "y": "A" * 43,
    })
    assert client._metadata_shape_error(invalid) == "runtime_public_jwk is invalid"
    calls = []

    def reject(jwk):
        calls.append(jwk)
        raise ValueError("app validation rejected the key")

    monkeypatch.setattr(client, "normalize_public_jwk", reject)
    assert client._metadata_shape_error(prepared.metadata) == "runtime_public_jwk is invalid"
    assert client.runtime_receipt_result(prepared.metadata, {})[1] == "runtime_lease_metadata_invalid"
    assert calls == [prepared.metadata["runtime_public_jwk"]] * 2


def test_app_ack_transaction_hides_rotation_and_rolls_back_before_retry(tmp_path, monkeypatch):
    db = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db, "relay-a")
    prepared = _prepare(db, "relay-a", _LeaseSession())
    assert prepared.metadata is not None
    rotation = dict(contract_version=client.CONTRACT_VERSION, validation_status="consumed",
                    lease_id="lease-test", fence=prepared.metadata["runtime_fence"],
                    next_request_token="N" * 43, next_request_sequence=2,
                    expires_at="2099-08-06T00:00:00Z")

    def snapshot():
        with closing(sqlite3.connect(db)) as reader:
            return (
                reader.execute("SELECT status, metadata_json FROM direct_sync_relay_batches").fetchone(),
                reader.execute("SELECT next_request_token, next_request_sequence, assigned_relay_id "
                               "FROM direct_sync_runtime_authority").fetchone(),
            )

    before = snapshot()
    original = core.apply_runtime_receipt_in_transaction
    observed = []
    fail = True

    def apply(conn, **kwargs):
        assert conn.in_transaction
        assert kwargs["normalize_public_jwk"] is client.normalize_public_jwk
        assert conn.execute("SELECT status FROM direct_sync_relay_batches").fetchone()[0] == "acked"
        original(conn, **kwargs)
        assert conn.in_transaction
        assert snapshot() == before
        observed.append(True)
        if fail:
            raise RuntimeError("failure after rotation, before ACK commit")

    monkeypatch.setattr(core, "apply_runtime_receipt_in_transaction", apply)
    kwargs = dict(db_path=db, relay_id="relay-a", status="acked",
                  expected_lease_owner="worker", expected_attempt_count=1,
                  runtime_credentials=_credentials(), runtime_lease=rotation)
    with pytest.raises(RuntimeError, match="failure after rotation"):
        push._set_relay_status(**kwargs)
    assert snapshot() == before
    fail = False
    assert push._set_relay_status(**kwargs) is True
    batch, authority = snapshot()
    assert observed == [True, True]
    assert batch[0] == "acked"
    assert "runtime_request_token" not in json.loads(batch[1])
    assert authority == ("N" * 43, 2, None)


@pytest.mark.parametrize("name", [
    "init_runtime_schema", "_create_state", "_replace_expired_identity",
    "apply_runtime_receipt_in_transaction", "mark_runtime_operator_review_in_transaction",
    "release_runtime_request_in_transaction", "disable_runtime_authority_in_transaction",
])
def test_active_writer_fence_denies_shared_sql_before_dispatch(monkeypatch, name):
    active = _write_active(fence.canonical_control_root(), _active_payload())
    before = active.read_bytes()

    def unreachable(*args, **kwargs):
        pytest.fail("shared SQL reached despite the active writer fence")

    monkeypatch.setattr(core, name, unreachable)
    with pytest.raises(fence.WriterFencedError) as error:
        getattr(client, name)()
    assert error.value.code == "ACTIVE_WRITER_FENCE"
    assert active.read_bytes() == before
