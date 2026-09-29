from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import direct_sync_push
import producer_runtime_client as runtime_client
from direct_sync_push import ProducerCredentials, canonical_json, init_relay_queue_schema


from tests.contracts.http_replay import load_contract


@dataclass
class _Response:
    status_code: int
    payload: dict
    headers: dict | None = None

    def json(self):
        return self.payload


class _LeaseSession:
    def __init__(self, *, failures: int = 0):
        self.failures = failures
        self.calls = []

    def post(self, url, **kwargs):
        body = json.loads(bytes(kwargs["data"]).decode("utf-8"))
        self.calls.append((url, body, dict(kwargs["headers"])))
        if len(self.calls) <= self.failures:
            raise TimeoutError("lost lease ACK")
        sequence = int(body.get("runtime_request_sequence") or 0) + 1
        return _Response(
            200,
            {
                "ok": True,
                "status": "ACTIVE",
                "contract_version": runtime_client.CONTRACT_VERSION,
                "operation": "renewed" if "runtime_fence" in body else "issued",
                "lease_id": "lease-test",
                "producer_install_id": "install-test",
                "runtime_instance_id": body["runtime_instance_id"],
                "public_jwk_thumbprint": runtime_client._jwk_thumbprint(body["public_jwk"]),
                "issue_idempotency_key": body["issue_idempotency_key"],
                "fence": int(body.get("runtime_fence") or 1),
                "issued_at": "2026-08-06T00:00:00Z",
                "expires_at": "2099-08-06T00:00:00Z",
                "next_request_token": ("B" if sequence > 1 else "A") * 43,
                "next_request_sequence": sequence,
            },
            {},
        )


class _ExactCloneThenGrantSession(_LeaseSession):
    def __init__(self, *, conflicts: int = 1):
        super().__init__()
        self.conflicts = conflicts

    def post(self, url, **kwargs):
        body = json.loads(bytes(kwargs["data"]).decode("utf-8"))
        if len(self.calls) < self.conflicts:
            self.calls.append((url, body, dict(kwargs["headers"])))
            return _Response(
                409,
                {
                    "ok": False,
                    "status": "conflict",
                    "error": {
                        "code": "EXACT_CLONE_RUNTIME_CONFLICT",
                        "message": (
                            "another runtime identity already holds the active install lease"
                        ),
                        "details": {
                            "producer_install_id": "install-test",
                            "active_lease_id": "lease-active",
                            "active_fence": 1,
                        },
                    },
                    "retryable": False,
                },
                {},
            )
        return super().post(url, **kwargs)


class _StaleTokenSession(_LeaseSession):
    def post(self, url, **kwargs):
        body = json.loads(bytes(kwargs["data"]).decode("utf-8"))
        self.calls.append((url, body, dict(kwargs["headers"])))
        return _Response(
            409,
            {
                "ok": False,
                "status": "conflict",
                "error": {
                    "code": "STALE_RUNTIME_REQUEST_TOKEN",
                    "message": "stale runtime request token",
                },
                "retryable": False,
            },
            {},
        )


class _RelaySession(_LeaseSession):
    def __init__(self, *, source_failures: int = 0, lease_failures: int = 0):
        super().__init__(failures=lease_failures)
        self.source_failures = source_failures
        self.source_calls = []

    def post(self, url, **kwargs):
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            return super().post(url, **kwargs)
        uploaded = json.loads(kwargs["data"]["metadata"])
        self.source_calls.append((uploaded, dict(kwargs["headers"])))
        if len(self.source_calls) <= self.source_failures:
            raise TimeoutError("lost source ACK")
        source_file_id = (
            f"{uploaded['source_host_id']}/{uploaded['producer_role']}/"
            f"{uploaded['stream_name']}/{uploaded['relative_path']}"
        )
        return _Response(
            200,
            {
                "request_id": "request-relay-a",
                "upload_id": "request-relay-a",
                "producer_install_id": "install-test",
                "client_batch_id": uploaded["client_batch_id"],
                "server_source_file_id": source_file_id,
                "committed": True,
                "status": "accepted",
                "projection_disposition": "COMPLETE",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 0, "replayed": 0, "quarantined": 0, "errors": 0},
                "runtime_lease": {
                    "contract_version": runtime_client.CONTRACT_VERSION,
                    "validation_status": "consumed",
                    "lease_id": "lease-test",
                    "fence": uploaded["runtime_fence"],
                    "next_request_token": "R" * 43,
                    "next_request_sequence": uploaded["runtime_request_sequence"] + 1,
                    "expires_at": "2099-08-06T00:00:00Z",
                },
            },
            {},
        )


class _DefinitiveRejectSession(_LeaseSession):
    def __init__(self):
        super().__init__()
        self.source_calls = []

    def post(self, url, **kwargs):
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            return super().post(url, **kwargs)
        uploaded = json.loads(kwargs["data"]["metadata"])
        self.source_calls.append(uploaded)
        return _Response(
            422,
            {
                "committed": False,
                "retryable": False,
                "status": "rejected",
                "error": {"code": "source_file_invalid", "message": "invalid source file"},
            },
            {},
        )


class _GenericLegacyRejectSession(_LeaseSession):
    def __init__(self, error_code: str):
        super().__init__()
        self.error_code = error_code
        self.source_calls = []

    def post(self, url, **kwargs):
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            return super().post(url, **kwargs)
        self.source_calls.append(json.loads(kwargs["data"]["metadata"]))
        return _Response(
            409 if self.error_code == "idempotency_conflict" else 400,
            {
                "committed": False,
                "retryable": False,
                "error": {"code": self.error_code, "message": "source request rejected"},
            },
            {},
        )


class _LegacyReceiptSession(_LeaseSession):
    def __init__(self, *, source_failures: int = 0):
        super().__init__()
        self.source_failures = source_failures
        self.source_calls = []
        self.source_urls = []

    def post(self, url, **kwargs):
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            return super().post(url, **kwargs)
        uploaded = json.loads(kwargs["data"]["metadata"])
        self.source_calls.append(uploaded)
        self.source_urls.append(str(url))
        if len(self.source_calls) <= self.source_failures:
            raise TimeoutError("lost legacy source ACK")
        source_file_id = (
            f"{uploaded['source_host_id']}/{uploaded['producer_role']}/"
            f"{uploaded['stream_name']}/{uploaded['relative_path']}"
        )
        receipt = {
                "request_id": f"request-{uploaded['client_batch_id']}",
                "upload_id": f"request-{uploaded['client_batch_id']}",
                "producer_install_id": "install-test",
                "client_batch_id": uploaded["client_batch_id"],
                "server_source_file_id": source_file_id,
                "committed": True,
                "status": "accepted",
                "projection_disposition": "COMPLETE",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 0, "replayed": 0, "quarantined": 0, "errors": 0},
            }
        if "runtime_request_token" not in uploaded:
            receipt["runtime_lease"] = {
                "contract_version": runtime_client.CONTRACT_VERSION,
                "validation_status": "observed",
                "reason_code": "RUNTIME_LEASE_MISSING_OBSERVED",
            }
        return _Response(200, receipt, {})


def _credentials(
    *, key_id: str = "key-test", runtime_lease_mode: str = "enforce"
) -> ProducerCredentials:
    return ProducerCredentials(
        producer_id="producer-test",
        key_id=key_id,
        secret=b"runtime-client-secret",
        endpoint_url="https://producer.example/api/producer-ingest/v1/source-file",
        runtime_lease_mode=runtime_lease_mode,
    )


def _metadata(relay_id: str) -> dict:
    return {
        "contract_version": "producer-ingest-source-file-v1",
        "producer_install_id": "install-test",
        "client_batch_id": relay_id,
        "idempotency_key": relay_id,
        "source_host_id": "host-test",
        "producer_role": "test-role",
        "manifest_hash": "a" * 64,
        "stream_name": "test-stream",
        "source_system": "test-system",
        "source_transport": "test-transport",
        "relative_path": f"events/{relay_id}.csv",
        "batch_kind": "whole_file",
        "row_count": 0,
        "first_row_number": 0,
        "last_row_number": 0,
        "content_sha256": "b" * 64,
        "byte_length": 0,
    }


def test_idle_liveness_issues_once_and_renews_only_when_due_without_consuming_token(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    session = _LeaseSession()

    issued = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-06T00:00:00Z",
    )
    assert issued.error_code == ""
    assert issued.receipt["server_grant_accepted"] is True
    assert issued.receipt["request_sent"] is True
    assert len(session.calls) == 1
    assert "runtime_request_token" not in session.calls[0][1]

    current = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-06T00:01:00Z",
    )
    assert current.error_code == ""
    assert current.receipt["request_sent"] is False
    assert len(session.calls) == 1
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT next_request_token, next_request_sequence, assigned_relay_id "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
    assert row == ("A" * 43, 1, None)

    explicit_margin_current = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2099-08-05T23:58:01Z",
        renewal_margin_seconds=60,
    )
    assert explicit_margin_current.error_code == ""
    assert explicit_margin_current.receipt["request_sent"] is False
    assert len(session.calls) == 1

    renewed = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2099-08-05T23:58:01Z",
    )
    assert renewed.error_code == ""
    assert renewed.receipt["request_sent"] is True
    assert len(session.calls) == 2
    renewal_body = session.calls[1][1]
    assert renewal_body["runtime_request_token"] == "A" * 43
    assert renewal_body["runtime_request_sequence"] == 1
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT next_request_token, next_request_sequence, assigned_relay_id "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
    assert row == ("B" * 43, 2, None)


def _authority_row(db_path: Path) -> sqlite3.Row:
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM direct_sync_runtime_authority"
        ).fetchone()
    assert row is not None
    return row


def test_exact_clone_conflict_stays_fail_closed_inside_ttl_then_reissues(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    session = _ExactCloneThenGrantSession(conflicts=1)

    first = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:07:27Z",
        ttl_seconds=900,
    )
    assert first.operator_review is True
    assert first.error_code == "EXACT_CLONE_RUNTIME_CONFLICT"
    rejected = _authority_row(db_path)
    assert rejected["status"] == "OPERATOR_REVIEW"
    assert rejected["last_error_code"] == "EXACT_CLONE_RUNTIME_CONFLICT"
    rejected_runtime_id = rejected["runtime_instance_id"]

    still_blocked = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:08:27Z",
        ttl_seconds=900,
    )
    assert still_blocked.operator_review is True
    assert still_blocked.error_code == "EXACT_CLONE_RUNTIME_CONFLICT"
    assert len(session.calls) == 1
    assert _authority_row(db_path)["runtime_instance_id"] == rejected_runtime_id

    recovered = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:22:27Z",
        ttl_seconds=900,
    )
    assert recovered.error_code == ""
    assert recovered.receipt["server_grant_accepted"] is True
    assert recovered.receipt["runtime_instance_id"] != rejected_runtime_id
    assert len(session.calls) == 2
    assert "runtime_request_token" not in session.calls[1][1]
    assert _authority_row(db_path)["status"] == "ACTIVE"


def test_stale_exact_clone_operator_review_reissues_without_reuse_token(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    session = _ExactCloneThenGrantSession(conflicts=0)
    primed = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:00:00Z",
        ttl_seconds=900,
    )
    assert primed.receipt["server_grant_accepted"] is True
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_runtime_authority
            SET status='OPERATOR_REVIEW', last_error_code=?,
                lease_id=NULL, fence=NULL, next_request_token=NULL,
                next_request_sequence=NULL, expires_at=NULL,
                pending_request_json=NULL, pending_issue_idempotency_key=NULL,
                updated_at=?
            """,
            ("EXACT_CLONE_RUNTIME_CONFLICT", "2026-08-19T21:11:01Z"),
        )
        connection.commit()
    leftover_runtime_id = _authority_row(db_path)["runtime_instance_id"]

    recovered = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-20T00:00:00Z",
        ttl_seconds=900,
    )
    assert recovered.error_code == ""
    assert recovered.receipt["server_grant_accepted"] is True
    assert recovered.receipt["runtime_instance_id"] != leftover_runtime_id
    assert recovered.receipt["request_sent"] is True


def test_stale_token_operator_review_stays_fail_closed_after_ttl(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    session = _StaleTokenSession()
    first = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:07:27Z",
        ttl_seconds=900,
    )
    assert first.operator_review is True
    assert first.error_code == "STALE_RUNTIME_REQUEST_TOKEN"

    later = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-20T00:00:00Z",
        ttl_seconds=900,
    )
    assert later.operator_review is True
    assert later.error_code == "STALE_RUNTIME_REQUEST_TOKEN"
    assert len(session.calls) == 1


def test_local_runtime_error_authority_reissues_only_after_retained_server_expiry(
    tmp_path,
):
    local_error_code = "runtime_lease_metadata_invalid_before_source_post"
    db_path = tmp_path / "relay.sqlite3"
    session = _LeaseSession()
    primed = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:00:00Z",
        ttl_seconds=900,
    )
    assert primed.receipt["server_grant_accepted"] is True
    original_runtime_id = _authority_row(db_path)["runtime_instance_id"]
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_runtime_authority
            SET status='OPERATOR_REVIEW', last_error_code=?,
                next_request_token=NULL, next_request_sequence=NULL,
                assigned_relay_id=NULL, pending_request_json=NULL,
                pending_issue_idempotency_key=NULL, expires_at=?, updated_at=?
            """,
            (
                local_error_code,
                "2026-08-19T21:10:00Z",
                "2026-08-19T21:01:00Z",
            ),
        )

    still_blocked = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:09:59Z",
        ttl_seconds=900,
    )
    assert still_blocked.operator_review is True
    assert still_blocked.error_code == local_error_code
    assert len(session.calls) == 1
    assert _authority_row(db_path)["runtime_instance_id"] == original_runtime_id

    recovered = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:10:00Z",
        ttl_seconds=900,
    )
    assert recovered.error_code == ""
    assert recovered.receipt["server_grant_accepted"] is True
    assert recovered.receipt["runtime_instance_id"] != original_runtime_id
    assert "runtime_request_token" not in session.calls[1][1]
    assert _authority_row(db_path)["status"] == "ACTIVE"


@pytest.mark.parametrize(
    "unknown_commit_code",
    ["upload_unhandled_exception", "runtime_lease_metadata_invalid"],
)
def test_unknown_commit_never_reissues_from_stale_retained_expiry(
    tmp_path,
    unknown_commit_code,
):
    db_path = tmp_path / "relay.sqlite3"
    session = _LeaseSession()
    primed = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:00:00Z",
        ttl_seconds=900,
    )
    assert primed.receipt["server_grant_accepted"] is True
    original_runtime_id = _authority_row(db_path)["runtime_instance_id"]
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_runtime_authority
            SET status='OPERATOR_REVIEW', last_error_code=?,
                next_request_token=NULL, next_request_sequence=NULL,
                assigned_relay_id=NULL, pending_request_json=NULL,
                pending_issue_idempotency_key=NULL, expires_at=?, updated_at=?
            """,
            (
                unknown_commit_code,
                "2026-08-19T21:10:00Z",
                "2026-08-19T21:01:00Z",
            ),
        )

    blocked = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-20T21:10:00Z",
        ttl_seconds=900,
    )

    assert blocked.operator_review is True
    assert blocked.error_code == unknown_commit_code
    assert len(session.calls) == 1
    assert _authority_row(db_path)["runtime_instance_id"] == original_runtime_id


@pytest.mark.parametrize(
    ("guard_column", "guard_value"),
    [
        ("lease_id", None),
        ("fence", None),
        ("assigned_relay_id", "relay-still-assigned"),
        ("pending_request_json", "{}"),
        ("pending_issue_idempotency_key", "issue-still-pending"),
        ("next_request_token", "T" * 43),
        ("next_request_sequence", 2),
    ],
)
def test_expired_local_runtime_error_reissue_requires_all_safety_guards(
    tmp_path,
    guard_column,
    guard_value,
):
    db_path = tmp_path / "relay.sqlite3"
    session = _LeaseSession()
    primed = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:00:00Z",
        ttl_seconds=900,
    )
    assert primed.receipt["server_grant_accepted"] is True
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_runtime_authority
            SET status='OPERATOR_REVIEW', last_error_code='runtime_lease_metadata_invalid_before_source_post',
                next_request_token=NULL, next_request_sequence=NULL,
                assigned_relay_id=NULL, pending_request_json=NULL,
                pending_issue_idempotency_key=NULL, expires_at=?, updated_at=?
            """,
            ("2026-08-19T21:10:00Z", "2026-08-19T21:01:00Z"),
        )
        connection.execute(
            f"UPDATE direct_sync_runtime_authority SET {guard_column}=?",
            (guard_value,),
        )

    blocked = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
        now="2026-08-19T21:10:00Z",
        ttl_seconds=900,
    )
    assert blocked.operator_review is True
    assert blocked.error_code == "runtime_lease_metadata_invalid_before_source_post"
    assert len(session.calls) == 1


def _insert_claimed_row(db_path: Path, relay_id: str, *, owner: str = "worker") -> None:
    init_relay_queue_schema(db_path)
    metadata = _metadata(relay_id)
    now = "2026-08-06T00:00:00Z"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO direct_sync_relay_batches(
                relay_id, status, source_file_path, spooled_file_path,
                producer_manifest_path, relative_path, content_sha256,
                byte_length, attempt_count, lease_owner, lease_expires_at,
                next_attempt_at, metadata_json, producer_id, key_id,
                endpoint_url, created_at, updated_at
            ) VALUES(?, 'leased', '', '', '', ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                relay_id,
                metadata["relative_path"],
                metadata["content_sha256"],
                owner,
                "2099-08-06T00:00:00Z",
                now,
                canonical_json(metadata),
                "producer-test",
                "key-test",
                _credentials().endpoint_url,
                now,
                now,
            ),
        )


def _prepare(db_path: Path, relay_id: str, session, *, owner: str = "worker"):
    return runtime_client.prepare_runtime_metadata(
        db_path=db_path,
        relay_id=relay_id,
        metadata=_metadata(relay_id),
        credentials=_credentials(),
        expected_lease_owner=owner,
        expected_attempt_count=1,
        session=session,
        timeout=5,
        now="2026-08-06T00:00:00Z",
    )


def _make_pending_relay(
    db_path: Path,
    tmp_path: Path,
    relay_id: str,
    *,
    attempt_count: int = 0,
    runtime_fencing_policy: str = runtime_client.RUNTIME_FENCING_POLICY_RUNTIME_REQUIRED,
) -> None:
    _insert_claimed_row(db_path, relay_id)
    spool_path = tmp_path / f"{relay_id}.csv"
    spool_path.write_bytes(b"")
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    metadata = _metadata(relay_id)
    metadata["content_sha256"] = empty_sha256
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status='pending', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL,
                next_attempt_at='2000-01-01T00:00:00Z',
                source_file_path=?, spooled_file_path=?, content_sha256=?,
                metadata_json=?, runtime_fencing_policy=?
            WHERE relay_id=?
            """,
            (
                attempt_count,
                str(spool_path),
                str(spool_path),
                empty_sha256,
                canonical_json(metadata),
                runtime_fencing_policy,
                relay_id,
            ),
        )


def _assert_signed_lease_call(call) -> None:
    url, body, headers = call
    assert url.endswith(runtime_client.ENDPOINT_PATH)
    canonical = runtime_client._canonical_request(
        timestamp=headers["X-Producer-Timestamp"],
        nonce=headers["X-Producer-Nonce"],
        producer_id=headers["X-Producer-Id"],
        key_id=headers["X-Producer-Key-Id"],
        body=body,
    )
    expected = hmac.new(
        _credentials().secret, canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert hmac.compare_digest(expected, headers["X-Producer-Signature"])


def test_lease_is_hmac_signed_and_runtime_metadata_is_persisted_all_or_none(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    session = _LeaseSession()

    prepared = _prepare(db_path, "relay-a", session)
    replay = _prepare(db_path, "relay-a", session)

    assert prepared.metadata is not None
    assert replay.metadata == prepared.metadata
    assert len(session.calls) == 1
    _assert_signed_lease_call(session.calls[0])
    assert set(runtime_client.METADATA_FIELDS).issubset(prepared.metadata)
    assert runtime_client._metadata_shape_error(prepared.metadata) == ""
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        batch = connection.execute(
            "SELECT metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()
        state = connection.execute(
            "SELECT * FROM direct_sync_runtime_authority"
        ).fetchone()
    assert json.loads(batch["metadata_json"]) == prepared.metadata
    assert state["assigned_relay_id"] == "relay-a"
    assert state["next_request_token"] is None
    assert state["endpoint_url"] == _credentials().endpoint_url
    assert state["producer_id"] == _credentials().producer_id
    assert state["key_id"] == _credentials().key_id
    assert state["producer_install_id"] == "install-test"


def test_partial_runtime_metadata_fails_closed_before_any_network_call(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    partial = _metadata("relay-a")
    partial["runtime_instance_id"] = "runtime-partial"
    session = _LeaseSession()

    result = runtime_client.prepare_runtime_metadata(
        db_path=db_path,
        relay_id="relay-a",
        metadata=partial,
        credentials=_credentials(),
        expected_lease_owner="worker",
        expected_attempt_count=1,
        session=session,
    )

    assert result.metadata is None
    assert result.operator_review is True
    assert result.error_code == "runtime_lease_metadata_invalid_before_source_post"
    assert session.calls == []


def test_lost_lease_ack_reuses_exact_body_with_a_fresh_hmac_nonce(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    session = _LeaseSession(failures=1)

    first = _prepare(db_path, "relay-a", session)
    second = _prepare(db_path, "relay-a", session)

    assert first.retryable is True
    assert second.metadata is not None
    assert session.calls[0][1] == session.calls[1][1]
    assert session.calls[0][2]["X-Producer-Nonce"] != session.calls[1][2]["X-Producer-Nonce"]
    _assert_signed_lease_call(session.calls[0])
    _assert_signed_lease_call(session.calls[1])


def test_expiring_authority_is_renewed_with_the_current_fence_token_and_sequence(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "seed")
    seed = _prepare(db_path, "seed", _LeaseSession())
    assert seed.metadata is not None
    rotation = {
        "contract_version": runtime_client.CONTRACT_VERSION,
        "validation_status": "consumed",
        "lease_id": "lease-test",
        "fence": seed.metadata["runtime_fence"],
        "next_request_token": "C" * 43,
        "next_request_sequence": 2,
        "expires_at": "2026-08-06T00:00:20Z",
    }
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE direct_sync_relay_batches SET status='acked' WHERE relay_id='seed'")
        runtime_client.apply_runtime_receipt_in_transaction(
            connection,
            relay_id="seed",
            metadata=seed.metadata,
            credentials=_credentials(),
            runtime_lease=rotation,
            now="2026-08-06T00:00:01Z",
        )
        connection.commit()
    _insert_claimed_row(db_path, "relay-renew", owner="worker-renew")
    session = _LeaseSession()

    renewed = runtime_client.prepare_runtime_metadata(
        db_path=db_path,
        relay_id="relay-renew",
        metadata=_metadata("relay-renew"),
        credentials=_credentials(),
        expected_lease_owner="worker-renew",
        expected_attempt_count=1,
        session=session,
        timeout=5,
        now="2026-08-06T00:00:02Z",
    )

    assert renewed.metadata is not None
    renewal_body = session.calls[0][1]
    assert renewal_body["runtime_fence"] == seed.metadata["runtime_fence"]
    assert renewal_body["runtime_request_token"] == "C" * 43
    assert renewal_body["runtime_request_sequence"] == 2
    assert renewal_body["runtime_instance_id"] == seed.metadata["runtime_instance_id"]
    assert renewal_body["public_jwk"] == seed.metadata["runtime_public_jwk"]
    assert renewed.metadata["runtime_request_sequence"] == 3
    _assert_signed_lease_call(session.calls[0])


def test_ack_and_next_token_commit_together_and_status_redaction_removes_tokens(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    prepared = _prepare(db_path, "relay-a", _LeaseSession())
    assert prepared.metadata is not None
    current_token = prepared.metadata["runtime_request_token"]
    next_token = "N" * 43
    rotation = {
        "contract_version": runtime_client.CONTRACT_VERSION,
        "validation_status": "consumed",
        "lease_id": "lease-test",
        "fence": prepared.metadata["runtime_fence"],
        "next_request_token": next_token,
        "next_request_sequence": prepared.metadata["runtime_request_sequence"] + 1,
        "expires_at": "2099-08-06T00:00:00Z",
    }
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE direct_sync_relay_batches SET status='acked' WHERE relay_id='relay-a'"
        )
        runtime_client.apply_runtime_receipt_in_transaction(
            connection,
            relay_id="relay-a",
            metadata=prepared.metadata,
            credentials=_credentials(),
            runtime_lease=rotation,
            now="2026-08-06T00:00:01Z",
        )
        connection.commit()
    with sqlite3.connect(db_path) as connection:
        batch_status = connection.execute(
            "SELECT status FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()[0]
        state = connection.execute(
            "SELECT next_request_token, next_request_sequence, assigned_relay_id "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
    assert batch_status == "acked"
    assert state == (next_token, 2, None)
    artifact = {
        "metadata": runtime_client.redact_runtime_secrets(prepared.metadata),
        "receipt": runtime_client.redact_runtime_secrets(
            {"runtime_lease": rotation, "message": f"rotated to {next_token}"}
        ),
    }
    artifact_text = json.dumps(artifact, sort_keys=True)
    assert current_token not in artifact_text
    assert next_token not in artifact_text
    assert artifact["metadata"]["runtime_request_token"] == "[redacted]"
    assert artifact["receipt"]["runtime_lease"]["next_request_token"] == "[redacted]"
    assert artifact["receipt"]["message"] == "rotated to [redacted]"


def test_real_relay_drain_rotates_authority_in_the_ack_transaction(tmp_path, monkeypatch):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    spool_path = tmp_path / "relay-a.csv"
    spool_path.write_bytes(b"")
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    metadata = _metadata("relay-a")
    metadata["content_sha256"] = empty_sha256
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status='pending', attempt_count=0, lease_owner=NULL, lease_expires_at=NULL,
                next_attempt_at='2000-01-01T00:00:00Z',
                source_file_path=?, spooled_file_path=?, content_sha256=?,
                metadata_json=?
            WHERE relay_id='relay-a'
            """,
            (str(spool_path), str(spool_path), empty_sha256, canonical_json(metadata)),
        )

    session = _RelaySession()
    status_dir = tmp_path / "status"
    observed_transaction = []
    original_apply = direct_sync_push.apply_runtime_receipt_in_transaction

    def apply_while_ack_is_uncommitted(connection, **kwargs):
        observed_transaction.append(
            (
                connection.in_transaction,
                connection.execute(
                    "SELECT status FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
                ).fetchone()[0],
            )
        )
        return original_apply(connection, **kwargs)

    monkeypatch.setattr(
        direct_sync_push,
        "apply_runtime_receipt_in_transaction",
        apply_while_ack_is_uncommitted,
    )
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        status_dir=status_dir,
    )

    assert result is not None and result.success is True
    assert observed_transaction == [(True, "acked")]
    assert len(session.calls) == len(session.source_calls) == 1
    uploaded_metadata = session.source_calls[0][0]
    assert set(runtime_client.METADATA_FIELDS).issubset(uploaded_metadata)
    assert uploaded_metadata["runtime_request_token"] not in json.dumps(result.receipt)
    with sqlite3.connect(db_path) as connection:
        batch = connection.execute(
            "SELECT status, metadata_json, receipt_json FROM direct_sync_relay_batches "
            "WHERE relay_id='relay-a'"
        ).fetchone()
        state = connection.execute(
            "SELECT next_request_token, next_request_sequence, assigned_relay_id "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
    assert batch[0] == "acked"
    assert state == ("R" * 43, 2, None)
    terminal_metadata = json.loads(batch[1])
    assert "runtime_request_token" not in terminal_metadata
    assert terminal_metadata["runtime_request_token_sha256"] == hashlib.sha256(
        uploaded_metadata["runtime_request_token"].encode("utf-8")
    ).hexdigest()
    assert uploaded_metadata["runtime_request_token"] not in json.dumps(
        direct_sync_push.relay_queue_status(db_path)
    )
    status_text = next(status_dir.glob("*.json")).read_text(encoding="utf-8")
    assert uploaded_metadata["runtime_request_token"] not in status_text
    assert "R" * 43 not in status_text
    assert "R" * 43 not in str(batch[2])


def test_runtime_acked_retention_requires_terminal_safe_hash_and_exact_artifact(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-retention")
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=_RelaySession(),
        status_dir=tmp_path / "status",
    )
    assert result is not None and result.success is True
    candidates = direct_sync_push.acked_relay_retention_candidates(db_path)
    assert len(candidates) == 1

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT metadata_json, upload_status_path FROM direct_sync_relay_batches"
        ).fetchone()
    terminal_metadata = json.loads(row[0])
    artifact_path = Path(row[1])
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    token_hash = terminal_metadata["runtime_request_token_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", token_hash)
    assert "runtime_request_token" not in terminal_metadata
    assert artifact["metadata"]["runtime_request_token"] == "[redacted]"
    assert artifact["metadata"]["runtime_request_token_sha256"] == token_hash
    assert "A" * 43 not in artifact_path.read_text(encoding="utf-8")
    pristine_artifact = json.loads(json.dumps(artifact))

    def assert_artifact_mutation_rejected(mutator):
        changed = json.loads(json.dumps(pristine_artifact))
        mutator(changed)
        artifact_path.write_text(json.dumps(changed), encoding="utf-8")
        assert direct_sync_push.acked_relay_retention_candidates(db_path) == ()
        artifact_path.write_text(json.dumps(pristine_artifact), encoding="utf-8")

    assert_artifact_mutation_rejected(
        lambda value: value["metadata"].__setitem__(
            "runtime_request_token_sha256", "f" * 64
        )
    )
    assert_artifact_mutation_rejected(
        lambda value: value["metadata"].__setitem__(
            "runtime_request_sequence", value["metadata"]["runtime_request_sequence"] + 1
        )
    )
    assert_artifact_mutation_rejected(
        lambda value: value["metadata"]["runtime_public_jwk"].__setitem__("x", "A" * 43)
    )
    assert_artifact_mutation_rejected(
        lambda value: value["metadata"].__setitem__("source_host_id", "tampered-host")
    )
    assert_artifact_mutation_rejected(
        lambda value: value["metadata"].__setitem__("runtime_request_token", "Z" * 43)
    )
    assert_artifact_mutation_rejected(
        lambda value: value["receipt"].__setitem__("request_id", "tampered-request")
    )

    with sqlite3.connect(db_path) as connection:
        changed_terminal = dict(terminal_metadata)
        changed_terminal["runtime_request_token_sha256"] = "e" * 64
        connection.execute(
            "UPDATE direct_sync_relay_batches SET metadata_json=?",
            (canonical_json(changed_terminal),),
        )
    assert direct_sync_push.acked_relay_retention_candidates(db_path) == ()


def test_lost_source_ack_retries_exact_metadata_and_idempotency_with_new_hmac_nonce(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    spool_path = tmp_path / "relay-a.csv"
    spool_path.write_bytes(b"")
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    metadata = _metadata("relay-a")
    metadata["content_sha256"] = empty_sha256
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status='pending', attempt_count=0, lease_owner=NULL, lease_expires_at=NULL,
                next_attempt_at='2000-01-01T00:00:00Z',
                source_file_path=?, spooled_file_path=?, content_sha256=?,
                metadata_json=?
            WHERE relay_id='relay-a'
            """,
            (str(spool_path), str(spool_path), empty_sha256, canonical_json(metadata)),
        )
    session = _RelaySession(source_failures=1)

    first = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )
    assert first is not None and first.retryable is True

    idle_liveness = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=session,
    )
    assert idle_liveness.error_code == ""
    assert idle_liveness.receipt["status"] == "ACTIVE"
    assert idle_liveness.receipt["server_grant_accepted"] is True
    assert idle_liveness.receipt["request_in_flight"] is True
    assert idle_liveness.receipt["request_sent"] is False
    assert len(session.calls) == 1
    with sqlite3.connect(db_path) as connection:
        first_snapshot = connection.execute(
            "SELECT metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()[0]
        authority_snapshot = connection.execute(
            "SELECT assigned_relay_id, next_request_token, next_request_sequence "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
        connection.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at='2000-01-01T00:00:00Z' "
            "WHERE relay_id='relay-a'"
        )
    assert authority_snapshot == ("relay-a", None, None)
    second = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )

    assert second is not None and second.success is True
    assert len(session.calls) == 1
    assert len(session.source_calls) == 2
    first_metadata, first_headers = session.source_calls[0]
    second_metadata, second_headers = session.source_calls[1]
    assert first_metadata == second_metadata == json.loads(first_snapshot)
    assert first_metadata["runtime_request_token"] in first_snapshot
    assert first_metadata["idempotency_key"] == second_metadata["idempotency_key"] == "relay-a"
    assert first_headers["X-Producer-Nonce"] != second_headers["X-Producer-Nonce"]


class _CentralSession(_LeaseSession):
    """One server token at a time; a committed batch replays its first receipt."""

    def __init__(self):
        super().__init__()
        self.source_calls = []
        self.committed = {}
        self.token = None
        self.offline = False
        self.drop_next_receipt = False

    def post(self, url, **kwargs):
        if self.offline:
            raise ConnectionRefusedError(10061, "network adapter disabled")
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            response = super().post(url, **kwargs)
            self.token = (
                response.payload["next_request_token"],
                response.payload["next_request_sequence"],
            )
            return response
        uploaded = json.loads(kwargs["data"]["metadata"])
        self.source_calls.append(uploaded)
        batch = uploaded["client_batch_id"]
        if batch in self.committed:
            return _Response(200, self.committed[batch], {})
        presented = (uploaded["runtime_request_token"], uploaded["runtime_request_sequence"])
        if presented != self.token:
            return _Response(
                409,
                {
                    "committed": False,
                    "retryable": False,
                    "error": {"code": "STALE_RUNTIME_REQUEST_TOKEN", "message": "stale"},
                },
                {},
            )
        sequence = uploaded["runtime_request_sequence"] + 1
        self.token = (f"T{sequence}".ljust(43, "x"), sequence)
        self.committed[batch] = {
            "request_id": f"request-{batch}",
            "upload_id": f"request-{batch}",
            "producer_install_id": "install-test",
            "client_batch_id": batch,
            "server_source_file_id": (
                f"{uploaded['source_host_id']}/{uploaded['producer_role']}/"
                f"{uploaded['stream_name']}/{uploaded['relative_path']}"
            ),
            "committed": True,
            "status": "accepted",
            "projection_disposition": "COMPLETE",
            "retryable": False,
            "next_retry_after": None,
            "totals": {"inserted": 0, "replayed": 0, "quarantined": 0, "errors": 0},
            "runtime_lease": {
                "contract_version": runtime_client.CONTRACT_VERSION,
                "validation_status": "consumed",
                "lease_id": "lease-test",
                "fence": uploaded["runtime_fence"],
                "next_request_token": self.token[0],
                "next_request_sequence": sequence,
                "expires_at": "2099-08-06T00:00:00Z",
            },
        }
        if self.drop_next_receipt:
            self.drop_next_receipt = False
            raise ConnectionResetError(10054, "adapter disabled after the server committed")
        return _Response(200, self.committed[batch], {})


def test_rows_left_behind_a_dead_relays_reserved_token_upload_once_after_restart(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    for relay_id in ("relay-a", "relay-b", "relay-c"):
        _make_pending_relay(db_path, tmp_path, relay_id)
    central = _CentralSession()

    def drain(now, target=""):
        return direct_sync_push.drain_one_relay_batch(
            db_path=db_path,
            credentials=_credentials(),
            worker_id="worker-real",
            session=central,
            retry_base_seconds=60,
            now=now,
            target_relay_id=target,
        )

    # The dying relay's row reserves the token; the server commits it and the
    # adapter drops before the receipt returns (unknown commit).
    central.drop_next_receipt = True
    first = drain("2026-08-06T01:47:23Z")
    assert first is not None and first.retryable is True
    # App wakes during the outage aim only at their new rows.
    central.offline = True
    for relay_id in ("relay-b", "relay-c"):
        blocked = drain("2026-08-06T01:55:23Z", relay_id)
        assert blocked is not None and blocked.error_code == "runtime_request_in_flight"
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT assigned_relay_id FROM direct_sync_runtime_authority"
        ).fetchone() == ("relay-a",)

    # The next relay takes the oldest row first, with its exact metadata.
    central.offline = False
    results = [drain("2026-08-06T02:18:00Z") for _ in range(4)]

    assert [result.success for result in results[:3]] == [True, True, True]
    assert results[3] is None
    uploads = [call["client_batch_id"] for call in central.source_calls]
    assert uploads == ["relay-a", "relay-a", "relay-b", "relay-c"]
    assert central.source_calls[0] == central.source_calls[1]
    assert sorted(central.committed) == ["relay-a", "relay-b", "relay-c"]
    with sqlite3.connect(db_path) as connection:
        statuses = dict(
            connection.execute("SELECT relay_id, status FROM direct_sync_relay_batches")
        )
        authority = connection.execute(
            "SELECT status, assigned_relay_id FROM direct_sync_runtime_authority"
        ).fetchone()
    assert statuses == dict.fromkeys(("relay-a", "relay-b", "relay-c"), "acked")
    assert authority == ("ACTIVE", None)


def test_stale_runtime_token_is_operator_review_and_never_leaks_to_status(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "relay-a")
    spool_path = tmp_path / "relay-a.csv"
    spool_path.write_bytes(b"")
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    metadata = _metadata("relay-a")
    metadata["content_sha256"] = empty_sha256
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status='pending', attempt_count=0, lease_owner=NULL, lease_expires_at=NULL,
                next_attempt_at='2000-01-01T00:00:00Z',
                source_file_path=?, spooled_file_path=?, content_sha256=?, metadata_json=?
            WHERE relay_id='relay-a'
            """,
            (str(spool_path), str(spool_path), empty_sha256, canonical_json(metadata)),
        )

    class _StaleSession(_LeaseSession):
        def __init__(self):
            super().__init__()
            self.presented_token = ""

        def post(self, url, **kwargs):
            if str(url).endswith(runtime_client.ENDPOINT_PATH):
                return super().post(url, **kwargs)
            uploaded = json.loads(kwargs["data"]["metadata"])
            self.presented_token = uploaded["runtime_request_token"]
            return _Response(
                409,
                {
                    "committed": False,
                    "retryable": False,
                    "status": "operator_review",
                    "runtime_request_token": self.presented_token,
                    "error": {
                        "code": "STALE_RUNTIME_REQUEST_TOKEN",
                        "message": f"stale authority {self.presented_token}",
                    },
                },
                {},
            )

    session = _StaleSession()
    status_dir = tmp_path / "status"
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        status_dir=status_dir,
    )

    assert result is not None
    assert result.error_code == "STALE_RUNTIME_REQUEST_TOKEN"
    assert result.retryable is False
    assert session.presented_token not in result.error_message
    assert session.presented_token not in json.dumps(result.receipt)
    with sqlite3.connect(db_path) as connection:
        status, metadata_json, receipt_json = connection.execute(
            "SELECT status, metadata_json, receipt_json FROM direct_sync_relay_batches "
            "WHERE relay_id='relay-a'"
        ).fetchone()
        authority = connection.execute(
            "SELECT status, next_request_token, next_request_sequence, assigned_relay_id, "
            "pending_request_json FROM direct_sync_runtime_authority"
        ).fetchone()
    assert status == "operator_review"
    assert authority == ("OPERATOR_REVIEW", None, None, None, None)
    terminal_metadata = json.loads(metadata_json)
    assert "runtime_request_token" not in terminal_metadata
    assert terminal_metadata["runtime_request_token_sha256"] == hashlib.sha256(
        session.presented_token.encode("utf-8")
    ).hexdigest()
    assert session.presented_token not in str(receipt_json)
    assert session.presented_token not in json.dumps(direct_sync_push.relay_queue_status(db_path))
    assert session.presented_token not in next(status_dir.glob("*.json")).read_text(encoding="utf-8")


def test_definitive_noncommitted_rejection_releases_token_for_the_next_row(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-a")
    session = _DefinitiveRejectSession()

    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
    )

    assert result is not None
    assert result.committed is False and result.retryable is False
    presented_token = session.source_calls[0]["runtime_request_token"]
    with sqlite3.connect(db_path) as connection:
        batch_status, metadata_json = connection.execute(
            "SELECT status, metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()
        authority = connection.execute(
            "SELECT status, next_request_token, next_request_sequence, assigned_relay_id, "
            "pending_request_json FROM direct_sync_runtime_authority"
        ).fetchone()
    assert batch_status == "failed_permanent"
    assert "runtime_request_token" not in json.loads(metadata_json)
    assert authority == ("ACTIVE", presented_token, 1, None, None)

    _insert_claimed_row(db_path, "relay-b", owner="worker-b")
    next_preparation = runtime_client.prepare_runtime_metadata(
        db_path=db_path,
        relay_id="relay-b",
        metadata=_metadata("relay-b"),
        credentials=_credentials(),
        expected_lease_owner="worker-b",
        expected_attempt_count=1,
        session=session,
        timeout=5,
    )
    assert next_preparation.metadata is not None
    assert next_preparation.metadata["runtime_request_token"] == presented_token


def test_local_terminal_exception_quarantines_and_clears_reserved_authority(tmp_path, monkeypatch):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-a")
    session = _LeaseSession()

    def fail_locally(*args, **kwargs):
        raise RuntimeError("local parser failure")

    monkeypatch.setattr(direct_sync_push, "upload_source_file", fail_locally)
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
    )

    assert result is not None and result.error_code == "upload_unhandled_exception"
    with sqlite3.connect(db_path) as connection:
        batch_status, metadata_json = connection.execute(
            "SELECT status, metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()
        authority = connection.execute(
            "SELECT status, next_request_token, next_request_sequence, assigned_relay_id, "
            "pending_request_json FROM direct_sync_runtime_authority"
        ).fetchone()
    assert batch_status == "operator_review"
    assert "runtime_request_token" not in json.loads(metadata_json)
    assert authority == ("OPERATOR_REVIEW", None, None, None, None)


def test_enforce_mode_fails_closed_on_committed_legacy_receipt(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-a")
    session = _LegacyReceiptSession()

    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(runtime_lease_mode="enforce"),
        worker_id="worker-real",
        session=session,
    )

    assert result is not None and result.committed is True and result.success is False
    assert result.error_code == "runtime_lease_receipt_missing"
    with sqlite3.connect(db_path) as connection:
        batch_status, metadata_json = connection.execute(
            "SELECT status, metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()
        authority = connection.execute(
            "SELECT status, next_request_token, assigned_relay_id, pending_request_json "
            "FROM direct_sync_runtime_authority"
        ).fetchone()
    assert batch_status == "operator_review"
    assert "runtime_request_token" not in json.loads(metadata_json)
    assert authority == ("OPERATOR_REVIEW", None, None, None)


def test_observe_mode_legacy_receipt_disables_authority_and_future_runtime_metadata(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-a")
    session = _LegacyReceiptSession()
    credentials = _credentials(runtime_lease_mode="observe")

    first = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        worker_id="worker-real",
        session=session,
    )
    assert first is not None and first.success is True
    assert first.receipt["_local_runtime_lease_status"] == "legacy_accepted"
    assert set(runtime_client.METADATA_FIELDS).issubset(session.source_calls[0])
    with sqlite3.connect(db_path) as connection:
        authority = connection.execute(
            "SELECT status, lease_id, fence, next_request_token, next_request_sequence, "
            "assigned_relay_id, pending_request_json FROM direct_sync_runtime_authority"
        ).fetchone()
    assert authority == (runtime_client.LEGACY_DISABLED_STATUS, None, None, None, None, None, None)

    _make_pending_relay(db_path, tmp_path, "relay-b")
    second = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        worker_id="worker-real",
        session=session,
    )
    assert second is not None and second.success is True
    assert len(session.calls) == 1
    assert not set(runtime_client.METADATA_FIELDS).intersection(session.source_calls[1])


def test_legacy_exact_replay_is_receipt_first_in_observe_and_enforce(tmp_path):
    observe_db = tmp_path / "observe.sqlite3"
    _make_pending_relay(
        observe_db,
        tmp_path,
        "relay-observe",
        attempt_count=1,
        runtime_fencing_policy=runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
    )
    with sqlite3.connect(observe_db) as connection:
        legacy_metadata = json.loads(
            connection.execute(
                "SELECT metadata_json FROM direct_sync_relay_batches WHERE relay_id='relay-observe'"
            ).fetchone()[0]
        )
    observe_session = _LegacyReceiptSession()
    observe = direct_sync_push.drain_one_relay_batch(
        db_path=observe_db,
        credentials=_credentials(runtime_lease_mode="observe"),
        worker_id="worker-real",
        session=observe_session,
    )
    assert observe is not None and observe.success is True
    assert observe_session.calls == []
    assert observe_session.source_calls == [legacy_metadata]
    assert not set(runtime_client.METADATA_FIELDS).intersection(legacy_metadata)
    with sqlite3.connect(observe_db) as connection:
        assert connection.execute(
            "SELECT status FROM direct_sync_runtime_authority"
        ).fetchone()[0] == runtime_client.LEGACY_DISABLED_STATUS

    enforce_db = tmp_path / "enforce.sqlite3"
    _make_pending_relay(
        enforce_db,
        tmp_path,
        "relay-enforce",
        attempt_count=1,
        runtime_fencing_policy=runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
    )
    enforce_session = _LegacyReceiptSession()
    enforce = direct_sync_push.drain_one_relay_batch(
        db_path=enforce_db,
        credentials=_credentials(runtime_lease_mode="enforce"),
        worker_id="worker-real",
        session=enforce_session,
    )
    assert enforce is not None and enforce.success is True
    assert enforce_session.calls == []
    assert len(enforce_session.source_calls) == 1
    assert not set(runtime_client.METADATA_FIELDS).intersection(enforce_session.source_calls[0])
    with sqlite3.connect(enforce_db) as connection:
        assert connection.execute(
            "SELECT status FROM direct_sync_runtime_authority"
        ).fetchone()[0] == runtime_client.LEGACY_DISABLED_STATUS


def test_runtime_fencing_policy_migration_is_atomic_and_backfills_only_attempted_rows(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "legacy-relay.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE direct_sync_relay_batches (
                relay_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                source_file_path TEXT NOT NULL, spooled_file_path TEXT NOT NULL,
                producer_manifest_path TEXT NOT NULL, relative_path TEXT NOT NULL,
                content_sha256 TEXT NOT NULL, byte_length INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0, lease_owner TEXT,
                lease_expires_at TEXT, next_attempt_at TEXT, last_error_code TEXT,
                last_error_message TEXT, receipt_json TEXT, upload_status_path TEXT,
                metadata_json TEXT, producer_id TEXT, key_id TEXT, endpoint_url TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )
            """
        )
        for relay_id, attempt_count in (("fresh", 0), ("attempted", 1)):
            connection.execute(
                """
                INSERT INTO direct_sync_relay_batches(
                    relay_id, status, source_file_path, spooled_file_path,
                    producer_manifest_path, relative_path, content_sha256,
                    byte_length, attempt_count, created_at, updated_at
                ) VALUES(?, 'pending', '', '', '', '', ?, 0, ?, ?, ?)
                """,
                (relay_id, "0" * 64, attempt_count, "2026-08-06T00:00:00Z", "2026-08-06T00:00:00Z"),
            )

    original_init_runtime_schema = direct_sync_push.init_runtime_schema

    def fail_after_column_migration(connection):
        assert connection.in_transaction is True
        raise RuntimeError("migration interruption")

    monkeypatch.setattr(direct_sync_push, "init_runtime_schema", fail_after_column_migration)
    with pytest.raises(RuntimeError, match="migration interruption"):
        direct_sync_push.init_relay_queue_schema(db_path)
    with sqlite3.connect(db_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(direct_sync_relay_batches)")}
    assert "runtime_fencing_policy" not in columns

    monkeypatch.setattr(direct_sync_push, "init_runtime_schema", original_init_runtime_schema)
    direct_sync_push.init_relay_queue_schema(db_path)
    with sqlite3.connect(db_path) as connection:
        policies = dict(
            connection.execute(
                "SELECT relay_id, runtime_fencing_policy FROM direct_sync_relay_batches"
            ).fetchall()
        )
    assert policies == {
        "fresh": runtime_client.RUNTIME_FENCING_POLICY_RUNTIME_REQUIRED,
        "attempted": runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
    }


def test_runtime_required_lease_timeout_retries_the_exact_pending_issue_request(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(db_path, tmp_path, "relay-timeout")
    session = _RelaySession(lease_failures=1)

    first = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )
    assert first is not None and first.retryable is True
    assert session.source_calls == []
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        relay = connection.execute(
            "SELECT status, runtime_fencing_policy FROM direct_sync_relay_batches"
        ).fetchone()
        authority = connection.execute(
            "SELECT status, pending_request_json FROM direct_sync_runtime_authority"
        ).fetchone()
        connection.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at='2000-01-01T00:00:00Z'"
        )
    assert relay["status"] == direct_sync_push.RELAY_STATUS_RETRY_WAIT
    assert relay["runtime_fencing_policy"] == runtime_client.RUNTIME_FENCING_POLICY_RUNTIME_REQUIRED
    assert authority["status"] == "PENDING"
    pending_request = json.loads(authority["pending_request_json"])

    second = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(),
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )
    assert second is not None and second.success is True
    assert len(session.calls) == 2
    assert session.calls[0][1] == pending_request == session.calls[1][1]
    assert session.calls[0][2]["X-Producer-Nonce"] != session.calls[1][2]["X-Producer-Nonce"]
    with sqlite3.connect(db_path) as connection:
        relay = connection.execute(
            "SELECT status, runtime_fencing_policy FROM direct_sync_relay_batches"
        ).fetchone()
    assert relay == (
        direct_sync_push.RELAY_STATUS_ACKED,
        runtime_client.RUNTIME_FENCING_POLICY_RUNTIME_REQUIRED,
    )


def test_legacy_lost_ack_replays_exactly_across_mode_and_endpoint_change(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(
        db_path,
        tmp_path,
        "relay-legacy",
        attempt_count=1,
        runtime_fencing_policy=runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
    )
    original_credentials = _credentials(runtime_lease_mode="observe")
    session = _LegacyReceiptSession(source_failures=1)

    first = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=original_credentials,
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )
    assert first is not None and first.retryable is True
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at='2000-01-01T00:00:00Z'"
        )
        policy = connection.execute(
            "SELECT runtime_fencing_policy FROM direct_sync_relay_batches"
        ).fetchone()[0]
    assert policy == runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY

    changed_credentials = ProducerCredentials(
        producer_id=original_credentials.producer_id,
        key_id=original_credentials.key_id,
        secret=original_credentials.secret,
        endpoint_url="https://changed.example/api/producer-ingest/v1/source-file",
        runtime_lease_mode="enforce",
    )
    second = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=changed_credentials,
        worker_id="worker-real",
        session=session,
        retry_base_seconds=1,
    )
    assert second is not None and second.success is True
    assert session.calls == []
    assert session.source_calls[0] == session.source_calls[1]
    assert session.source_urls == [original_credentials.endpoint_url, original_credentials.endpoint_url]
    assert not set(runtime_client.METADATA_FIELDS).intersection(session.source_calls[0])


def test_enforce_quarantines_explicitly_noncommitted_legacy_exact_replay(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _make_pending_relay(
        db_path,
        tmp_path,
        "relay-legacy",
        attempt_count=1,
        runtime_fencing_policy=runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
    )
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(runtime_lease_mode="enforce"),
        worker_id="worker-real",
        session=_DefinitiveRejectSession(),
    )
    assert result is not None and result.success is False
    with sqlite3.connect(db_path) as connection:
        relay_status = connection.execute(
            "SELECT status FROM direct_sync_relay_batches"
        ).fetchone()[0]
        authority_status = connection.execute(
            "SELECT status FROM direct_sync_runtime_authority"
        ).fetchone()[0]
    assert relay_status == direct_sync_push.RELAY_STATUS_OPERATOR_REVIEW
    assert authority_status == "OPERATOR_REVIEW"


@pytest.mark.parametrize("runtime_mode", ["observe", "enforce"])
@pytest.mark.parametrize("error_code", ["metadata_invalid", "idempotency_conflict"])
def test_legacy_terminal_source_rejection_clears_any_assigned_runtime_authority(
    tmp_path, runtime_mode, error_code
):
    db_path = tmp_path / f"{runtime_mode}-{error_code}.sqlite3"
    relay_id = "relay-legacy-assigned"
    _insert_claimed_row(db_path, relay_id)
    prepared = _prepare(db_path, relay_id, _LeaseSession())
    assert prepared.metadata is not None

    spool_path = tmp_path / f"{runtime_mode}-{error_code}.csv"
    spool_path.write_bytes(b"")
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    legacy_metadata = _metadata(relay_id)
    legacy_metadata["content_sha256"] = empty_sha256
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status='pending', attempt_count=1, lease_owner=NULL,
                lease_expires_at=NULL, next_attempt_at='2000-01-01T00:00:00Z',
                source_file_path=?, spooled_file_path=?, content_sha256=?,
                metadata_json=?, runtime_fencing_policy=?
            WHERE relay_id=?
            """,
            (
                str(spool_path),
                str(spool_path),
                empty_sha256,
                canonical_json(legacy_metadata),
                runtime_client.RUNTIME_FENCING_POLICY_LEGACY_EXACT_REPLAY,
                relay_id,
            ),
        )

    session = _GenericLegacyRejectSession(error_code)
    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(runtime_lease_mode=runtime_mode),
        worker_id="worker-real",
        session=session,
    )
    assert result is not None and result.success is False
    assert session.calls == []
    assert session.source_calls == [legacy_metadata]
    with sqlite3.connect(db_path) as connection:
        relay_status = connection.execute(
            "SELECT status FROM direct_sync_relay_batches WHERE relay_id=?",
            (relay_id,),
        ).fetchone()[0]
        authority = connection.execute(
            """
            SELECT status, next_request_token, next_request_sequence,
                   assigned_relay_id, pending_request_json, pending_issue_idempotency_key
            FROM direct_sync_runtime_authority
            """
        ).fetchone()
    expected_relay_status = (
        direct_sync_push.RELAY_STATUS_OPERATOR_REVIEW
        if runtime_mode == "enforce"
        else direct_sync_push.RELAY_STATUS_FAILED_PERMANENT
    )
    assert relay_status == expected_relay_status
    assert authority == ("OPERATOR_REVIEW", None, None, None, None, None)


def test_two_workers_can_reserve_only_one_rotating_token(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    _insert_claimed_row(db_path, "seed")
    seed = _prepare(db_path, "seed", _LeaseSession())
    rotation = {
        "contract_version": runtime_client.CONTRACT_VERSION,
        "validation_status": "consumed",
        "lease_id": "lease-test",
        "fence": seed.metadata["runtime_fence"],
        "next_request_token": "C" * 43,
        "next_request_sequence": 2,
        "expires_at": "2099-08-06T00:00:00Z",
    }
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE direct_sync_relay_batches SET status='acked' WHERE relay_id='seed'")
        runtime_client.apply_runtime_receipt_in_transaction(
            connection,
            relay_id="seed",
            metadata=seed.metadata,
            credentials=_credentials(),
            runtime_lease=rotation,
            now="2026-08-06T00:00:01Z",
        )
        connection.commit()
    _insert_claimed_row(db_path, "relay-a", owner="worker-a")
    _insert_claimed_row(db_path, "relay-b", owner="worker-b")

    def reserve(relay_id, owner):
        return runtime_client.prepare_runtime_metadata(
            db_path=db_path,
            relay_id=relay_id,
            metadata=_metadata(relay_id),
            credentials=_credentials(),
            expected_lease_owner=owner,
            expected_attempt_count=1,
            session=_LeaseSession(),
            timeout=5,
            now="2026-08-06T00:00:02Z",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda args: reserve(*args), [("relay-a", "worker-a"), ("relay-b", "worker-b")]))
    winners = [result for result in results if result.metadata is not None]
    blocked = [result for result in results if result.metadata is None]
    assert len(winners) == len(blocked) == 1
    assert blocked[0].error_code == "runtime_request_in_flight"
    assert winners[0].metadata["runtime_request_token"] == "C" * 43


def test_cloned_relay_databases_apply_server_rotation_and_quarantine_stale_authority(tmp_path):
    # The vector comes from two actual server consume transactions. This test
    # qualifies desktop reservation/receipt handling, not server CAS isolation.
    vector = load_contract("runtime-token.json")
    now = vector["now"]
    grant = vector["grant"]
    first_db = tmp_path / "first.sqlite3"
    _make_pending_relay(first_db, tmp_path, "relay-a")
    scope = runtime_client._scope_values(_credentials(), "install-test")
    with sqlite3.connect(first_db) as connection:
        connection.execute(
            """
            INSERT INTO direct_sync_runtime_authority(
                authority_scope, endpoint_url, producer_id, key_id,
                producer_install_id, runtime_instance_id,
                runtime_public_jwk_json, lease_id, fence,
                next_request_token, next_request_sequence, expires_at,
                status, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """,
            (
                runtime_client._scope_key(scope), scope["endpoint_url"],
                scope["producer_id"], scope["key_id"], scope["producer_install_id"],
                vector["runtime_instance_id"], canonical_json(vector["public_jwk"]),
                grant["lease_id"], grant["fence"], grant["next_request_token"],
                grant["next_request_sequence"], grant["expires_at"], now, now,
            ),
        )
    second_db = tmp_path / "second.sqlite3"
    with sqlite3.connect(first_db) as source, sqlite3.connect(second_db) as target:
        source.backup(target)
    with sqlite3.connect(second_db) as connection:
        metadata = json.loads(connection.execute(
            "SELECT metadata_json FROM direct_sync_relay_batches"
        ).fetchone()[0])
        metadata.update(client_batch_id="relay-b", idempotency_key="relay-b")
        connection.execute(
            "UPDATE direct_sync_relay_batches SET relay_id='relay-b', metadata_json=?",
            (canonical_json(metadata),),
        )

    class VectorSession(_RelaySession):
        def __init__(self, outcome):
            super().__init__()
            self.outcome = outcome

        def post(self, url, **kwargs):
            assert not str(url).endswith(runtime_client.ENDPOINT_PATH), "unexpired grant must be reused"
            response = super().post(url, **kwargs)
            uploaded = self.source_calls[-1][0]
            assert uploaded["runtime_instance_id"] == vector["runtime_instance_id"]
            assert uploaded["runtime_public_jwk"] == vector["public_jwk"]
            assert uploaded["runtime_fence"] == grant["fence"]
            assert uploaded["runtime_request_sequence"] == grant["next_request_sequence"]
            assert uploaded["runtime_request_token"] == grant["next_request_token"]
            if self.outcome["status"] == "accepted":
                response.payload["runtime_lease"] = self.outcome["runtime_lease"]
                return response
            return _Response(409, self.outcome["error"])

    sessions = [VectorSession(outcome) for outcome in vector["outcomes"]]
    results = [
        direct_sync_push.drain_one_relay_batch(
            db_path=db, credentials=_credentials(), worker_id=f"worker-{i}",
            session=session, status_dir=tmp_path/f"status-{i}", now=now,
        )
        for i, (db, session) in enumerate(zip((first_db, second_db), sessions))
    ]
    assert results[0] is not None and results[0].success is True
    assert results[1] is not None and results[1].success is False
    assert results[1].error_code == "STALE_RUNTIME_REQUEST_TOKEN"
    assert len(sessions[0].source_calls) == len(sessions[1].source_calls) == 1
    assert sessions[0].source_calls[0][0]["idempotency_key"] != sessions[1].source_calls[0][0]["idempotency_key"]
    states = []
    batches = []
    for db in (first_db, second_db):
        with sqlite3.connect(db) as connection:
            states.append(connection.execute(
                "SELECT status, next_request_token, next_request_sequence, assigned_relay_id "
                "FROM direct_sync_runtime_authority"
            ).fetchone())
            batches.append(connection.execute("SELECT status FROM direct_sync_relay_batches").fetchone()[0])
    rotation = vector["outcomes"][0]["runtime_lease"]
    assert states[0] == ("ACTIVE", rotation["next_request_token"], rotation["next_request_sequence"], None)
    assert states[1] == ("OPERATOR_REVIEW", None, None, None)
    assert batches == ["acked", "operator_review"]


class _FencedLeaseServer:
    """Expiry, fence and issue-key anchors of the Web runtime-lease service.

    A renewal whose fence is no longer ACTIVE is refused with
    STALE_RUNTIME_FENCE and that answer is anchored to its issue key; a
    proof-less issue gets max(fence)+1 unless another runtime identity still
    holds an ACTIVE lease (EXACT_CLONE_RUNTIME_CONFLICT).
    """

    T0 = datetime(2026, 9, 25, 0, 0, tzinfo=UTC)

    def __init__(self):
        self.now = self.T0
        self.leases = []
        self.anchors = {}
        self.audit = []
        self.calls = []
        self.down = False
        self.lose_ack = False

    def at(self, seconds: int) -> str:
        self.now = self.T0 + timedelta(seconds=seconds)
        return self.now.isoformat().replace("+00:00", "Z")

    def _refuse(self, key, code, fence):
        self.audit.append((code, fence))
        self.anchors[key] = (409, {
            "committed": False,
            "retryable": False,
            "status": "operator_review",
            "error": {"code": code, "message": "runtime lease request refused"},
            "operator_review": {"required": True, "reason_code": code},
        })
        return self.anchors[key]

    def acquire(self, body):
        key = body["issue_idempotency_key"]
        if key in self.anchors:
            return self.anchors[key]
        for lease in self.leases:
            if lease["status"] == "ACTIVE" and lease["expires_at"] <= self.now:
                lease["status"] = "EXPIRED"
        active = next((row for row in self.leases if row["status"] == "ACTIVE"), None)
        identity = (body["runtime_instance_id"], runtime_client._jwk_thumbprint(body["public_jwk"]))
        same_identity = active is not None and active["identity"] == identity
        if "runtime_fence" in body:
            if not same_identity or active["fence"] != body["runtime_fence"]:
                return self._refuse(key, "STALE_RUNTIME_FENCE", body["runtime_fence"])
            if (active["sequence"], active["token"]) != (
                body["runtime_request_sequence"], body["runtime_request_token"]
            ):
                return self._refuse(key, "STALE_RUNTIME_REQUEST_TOKEN", active["fence"])
            lease, operation = active, "renewed"
            lease["sequence"] += 1
        elif active is not None:
            code = "RUNTIME_RENEWAL_PROOF_REQUIRED" if same_identity else "EXACT_CLONE_RUNTIME_CONFLICT"
            return self._refuse(key, code, active["fence"])
        else:
            lease = {
                "fence": max((row["fence"] for row in self.leases), default=0) + 1,
                "identity": identity,
                "status": "ACTIVE",
                "sequence": 1,
            }
            self.leases.append(lease)
            operation = "issued"
        lease["token"] = f"fenced{lease['fence']}x{lease['sequence']:04d}" + "y" * 32
        lease["expires_at"] = self.now + timedelta(seconds=body["ttl_seconds"])
        self.anchors[key] = (200, {
            "ok": True,
            "status": "ACTIVE",
            "contract_version": runtime_client.CONTRACT_VERSION,
            "operation": operation,
            "lease_id": f"lease-fence-{lease['fence']}",
            "producer_install_id": "install-test",
            "runtime_instance_id": identity[0],
            "public_jwk_thumbprint": identity[1],
            "issue_idempotency_key": key,
            "fence": lease["fence"],
            "issued_at": self.now.isoformat().replace("+00:00", "Z"),
            "expires_at": lease["expires_at"].isoformat().replace("+00:00", "Z"),
            "next_request_token": lease["token"],
            "next_request_sequence": lease["sequence"],
        })
        return self.anchors[key]

    def post(self, url, **kwargs):
        assert str(url).endswith(runtime_client.ENDPOINT_PATH)
        body = json.loads(bytes(kwargs["data"]).decode("utf-8"))
        self.calls.append(body)
        if self.down:
            raise ConnectionError("simulated outage")
        status, payload = self.acquire(body)
        if self.lose_ack:
            raise ConnectionError("simulated lost ACK after the server committed")
        return _Response(status, payload, {})

    def active_fence(self):
        return next(
            (row["fence"] for row in self.leases
             if row["status"] == "ACTIVE" and row["expires_at"] > self.now),
            None,
        )


def _liveness(db_path: Path, server: _FencedLeaseServer, seconds: int):
    return runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=_credentials(),
        producer_install_id="install-test",
        session=server,
        now=server.at(seconds),
        ttl_seconds=900,
    )


def _renewal_pending_through_outage(db_path: Path, server: _FencedLeaseServer, ticks) -> dict:
    """Issue fence 1, then tick the relay while the server is unreachable."""

    issued = _liveness(db_path, server, 0)
    assert issued.error_code == "" and issued.receipt["fence"] == 1
    server.down = True
    for seconds in ticks:
        assert _liveness(db_path, server, seconds).operator_review is False
    server.down = False
    renewal = server.calls[-1]
    assert renewal["runtime_fence"] == 1
    assert _authority_row(db_path)["pending_issue_idempotency_key"] == renewal["issue_idempotency_key"]
    return renewal


@pytest.mark.parametrize(
    "outage_ticks",
    [(800,), (100, 400, 790, 820, 880, 930)],
    ids=["renewal-window-outage", "outage-longer-than-ttl"],
)
def test_dead_renewal_after_outage_reissues_next_fence(tmp_path, outage_ticks):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    renewal = _renewal_pending_through_outage(db_path, server, outage_ticks)
    old_runtime_id = renewal["runtime_instance_id"]

    recovered = _liveness(db_path, server, 960)

    assert recovered.error_code == ""
    assert recovered.receipt["fence"] == 2
    assert recovered.receipt["runtime_instance_id"] != old_runtime_id
    assert server.active_fence() == 2
    assert server.audit == [("STALE_RUNTIME_FENCE", 1)]
    replay, issue = server.calls[-2:]
    assert replay == renewal
    assert "runtime_fence" not in issue and "runtime_request_token" not in issue
    row = _authority_row(db_path)
    assert (row["status"], row["fence"], row["pending_request_json"]) == ("ACTIVE", 2, None)
    assert _liveness(db_path, server, 1000).receipt["request_sent"] is False


def test_lost_renewal_ack_replays_same_key_without_reissue(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    assert _liveness(db_path, server, 0).receipt["fence"] == 1
    server.lose_ack = True
    assert _liveness(db_path, server, 800).retryable is True
    server.lose_ack = False
    renewal = server.calls[-1]

    replayed = _liveness(db_path, server, 960)

    assert replayed.error_code == ""
    assert replayed.receipt["fence"] == 1
    assert server.calls[-1] == renewal
    assert len(server.leases) == 1 and server.audit == []
    assert _authority_row(db_path)["status"] == "ACTIVE"


def test_live_clone_is_not_displaced_by_dead_renewal_recovery(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    _renewal_pending_through_outage(db_path, server, (800,))
    server.at(930)
    clone_id, clone_jwk = runtime_client.new_runtime_identity()
    status, clone_grant = server.acquire({
        "runtime_instance_id": clone_id,
        "public_jwk": clone_jwk,
        "issue_idempotency_key": "clone-issue",
        "ttl_seconds": 900,
    })
    assert (status, clone_grant["fence"]) == (200, 2)

    result = _liveness(db_path, server, 960)

    assert result.operator_review is True
    assert result.error_code == "EXACT_CLONE_RUNTIME_CONFLICT"
    assert server.active_fence() == 2
    assert server.leases[-1]["identity"][0] == clone_id
    assert _authority_row(db_path)["status"] == "OPERATOR_REVIEW"


def _stuck_pre_upgrade_review(db_path: Path, server: _FencedLeaseServer) -> dict:
    """The state the previous client stored after the server refused its renewal."""

    renewal = _renewal_pending_through_outage(db_path, server, (800,))
    server.at(960)
    assert server.acquire(renewal)[1]["error"]["code"] == "STALE_RUNTIME_FENCE"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE direct_sync_runtime_authority "
            "SET status='OPERATOR_REVIEW', last_error_code='STALE_RUNTIME_FENCE', updated_at=?",
            ("2026-09-25T00:16:00Z",),
        )
    return renewal


def test_pre_upgrade_stale_renewal_review_recovers_on_first_cycle(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    _stuck_pre_upgrade_review(db_path, server)
    sent_before = len(server.calls)

    recovered = _liveness(db_path, server, 990)

    assert recovered.error_code == ""
    assert recovered.receipt["fence"] == 2
    assert len(server.calls) == sent_before + 1
    assert "runtime_fence" not in server.calls[-1]
    assert _authority_row(db_path)["status"] == "ACTIVE"


def test_stale_renewal_review_bound_to_a_relay_row_stays_fail_closed(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    _stuck_pre_upgrade_review(db_path, server)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE direct_sync_runtime_authority SET assigned_relay_id='relay-bound'")
    before = dict(_authority_row(db_path))
    sent_before = len(server.calls)

    result = _liveness(db_path, server, 990)

    assert result.operator_review is True
    assert result.error_code == "STALE_RUNTIME_FENCE"
    assert len(server.calls) == sent_before
    assert dict(_authority_row(db_path)) == before


def test_row_preparation_after_dead_renewal_attaches_the_next_fence(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _FencedLeaseServer()
    renewal = _renewal_pending_through_outage(db_path, server, (800,))
    _insert_claimed_row(db_path, "relay-a")

    prepared = runtime_client.prepare_runtime_metadata(
        db_path=db_path,
        relay_id="relay-a",
        metadata=_metadata("relay-a"),
        credentials=_credentials(),
        expected_lease_owner="worker",
        expected_attempt_count=1,
        session=server,
        timeout=5,
        now=server.at(960),
        ttl_seconds=900,
    )

    assert prepared.metadata is not None
    assert prepared.metadata["runtime_fence"] == 2
    assert prepared.metadata["runtime_instance_id"] != renewal["runtime_instance_id"]
    assert server.calls[-2] == renewal and server.audit == [("STALE_RUNTIME_FENCE", 1)]
    row = _authority_row(db_path)
    assert (row["status"], row["assigned_relay_id"]) == ("ACTIVE", "relay-a")


class _DataPathServer(_FencedLeaseServer):
    """Adds the Web source-file consume rules one relay drain meets.

    A live fence and token are consumed and rotated. In observe mode a dead
    fence (or a spent token) still commits the exact source and answers
    observed_rejected with its reason; the exact body again returns the
    stored receipt; the same source under another fence is
    409 idempotency_conflict. Enforce refuses a dead fence uncommitted.
    The clock follows the real one because the relay drain reads it.
    """

    def __init__(self, *, mode: str = "observe"):
        super().__init__()
        self.T0 = datetime.now(UTC).replace(microsecond=0)
        self.now = self.T0
        self.mode = mode
        self.stored = {}
        self.source_calls = []
        self.lose_source_ack = False
        self.receipt_mutation = None

    def post(self, url, **kwargs):
        if str(url).endswith(runtime_client.ENDPOINT_PATH):
            return super().post(url, **kwargs)
        uploaded = json.loads(kwargs["data"]["metadata"])
        self.source_calls.append(uploaded)
        if self.down:
            raise ConnectionError("simulated outage")
        status, payload = self._consume(uploaded)
        if self.lose_source_ack:
            raise ConnectionError("simulated lost source ACK after the server committed")
        return _Response(status, json.loads(json.dumps(payload)), {})

    def _consume(self, uploaded):
        batch = uploaded["client_batch_id"]
        if batch in self.stored:
            body, receipt = self.stored[batch]
            if body == uploaded:
                return 200, receipt
            return 409, {
                "committed": False,
                "retryable": False,
                "status": "rejected",
                "error": {"code": "idempotency_conflict", "message": "source already committed"},
            }
        for lease in self.leases:
            if lease["status"] == "ACTIVE" and lease["expires_at"] <= self.now:
                lease["status"] = "EXPIRED"
        active = next((row for row in self.leases if row["status"] == "ACTIVE"), None)
        if active is None or active["fence"] != uploaded["runtime_fence"]:
            code = "STALE_RUNTIME_FENCE"
        elif (active["sequence"], active["token"]) != (
            uploaded["runtime_request_sequence"], uploaded["runtime_request_token"]
        ):
            code = "STALE_RUNTIME_REQUEST_TOKEN"
        else:
            code = ""
        if code:
            self.audit.append((code, uploaded["runtime_fence"]))
            if self.mode == "enforce":
                return 409, {
                    "committed": False,
                    "retryable": False,
                    "status": "operator_review",
                    "error": {"code": code, "message": "runtime request refused"},
                }
            runtime = {
                "contract_version": runtime_client.CONTRACT_VERSION,
                "validation_status": "observed_rejected",
                "reason_code": code,
            }
        else:
            active["sequence"] += 1
            active["token"] = f"fenced{active['fence']}x{active['sequence']:04d}" + "y" * 32
            runtime = {
                "contract_version": runtime_client.CONTRACT_VERSION,
                "validation_status": "consumed",
                "lease_id": f"lease-fence-{active['fence']}",
                "fence": active["fence"],
                "next_request_token": active["token"],
                "next_request_sequence": active["sequence"],
                "expires_at": active["expires_at"].isoformat().replace("+00:00", "Z"),
            }
        receipt = {
            "request_id": f"request-{batch}",
            "upload_id": f"request-{batch}",
            "producer_install_id": "install-test",
            "client_batch_id": batch,
            "server_source_file_id": (
                f"{uploaded['source_host_id']}/{uploaded['producer_role']}/"
                f"{uploaded['stream_name']}/{uploaded['relative_path']}"
            ),
            "committed": True,
            "status": "accepted",
            "projection_disposition": "COMPLETE",
            "retryable": False,
            "next_retry_after": None,
            "totals": {"inserted": uploaded["row_count"], "replayed": 0, "quarantined": 0, "errors": 0},
            "runtime_lease": runtime,
        }
        if self.receipt_mutation is not None:
            self.receipt_mutation(receipt)
        self.stored[batch] = (uploaded, receipt)
        return 200, receipt


def _data_path_cycle(db_path: Path, server: _DataPathServer, seconds: int, tmp_path: Path, *, mode="observe"):
    """One relay tick as the runtime runs it: liveness first, drain only when it passes."""

    credentials = _credentials(runtime_lease_mode=mode)
    live = runtime_client.ensure_runtime_authority(
        db_path=db_path,
        credentials=credentials,
        producer_install_id="install-test",
        session=server,
        now=server.at(seconds),
        ttl_seconds=900,
    )
    if live.error_code:
        return live, None
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at='2000-01-01T00:00:00Z' "
            "WHERE status='retry_wait'"
        )
    return live, direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=server,
        status_dir=tmp_path / "status",
        timeout=5,
    )


def _dead_fence_outage(
    db_path: Path, server: _DataPathServer, tmp_path: Path, *, ticks=(400, 800, 930), mode="observe",
    lose_ack=False,
) -> None:
    """Fence 1; relay-a binds it at t=10 and its source POST fails; the outage runs through the ticks."""

    init_relay_queue_schema(db_path)
    live, drained = _data_path_cycle(db_path, server, 0, tmp_path, mode=mode)
    assert live.receipt["fence"] == 1 and drained is None
    _make_pending_relay(db_path, tmp_path, "relay-a")
    server.lose_source_ack = lose_ack
    server.down = not lose_ack
    assert _data_path_cycle(db_path, server, 10, tmp_path, mode=mode)[1].retryable is True
    server.lose_source_ack = False
    server.down = True
    for seconds in ticks:
        live, drained = _data_path_cycle(db_path, server, seconds, tmp_path, mode=mode)
        assert live.error_code == "" and drained.retryable is True
    server.down = False
    assert _authority_row(db_path)["assigned_relay_id"] == "relay-a"


def _relay_rows(db_path: Path) -> dict:
    with sqlite3.connect(db_path) as connection:
        return {
            relay_id: (status, last_error_code or "")
            for relay_id, status, last_error_code in connection.execute(
                "SELECT relay_id, status, last_error_code FROM direct_sync_relay_batches"
            )
        }


def test_committed_dead_fence_upload_acks_and_the_next_fence_carries_the_next_row(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path)
    old_runtime_id = _authority_row(db_path)["runtime_instance_id"]

    _, recovered = _data_path_cycle(db_path, server, 960, tmp_path)
    reissued, idle = _data_path_cycle(db_path, server, 990, tmp_path)
    _make_pending_relay(db_path, tmp_path, "relay-b")
    _, next_row = _data_path_cycle(db_path, server, 1000, tmp_path)

    assert recovered.success is True and recovered.committed is True
    assert reissued.receipt["fence"] == 2 and idle is None
    assert next_row.success is True
    assert {relay: row[0] for relay, row in _relay_rows(db_path).items()} == {
        "relay-a": "acked", "relay-b": "acked"
    }
    assert sorted(server.stored) == ["relay-a", "relay-b"]
    assert {call["runtime_fence"] for call in server.source_calls if call["client_batch_id"] == "relay-a"} == {1}
    assert server.stored["relay-b"][0]["runtime_fence"] == 2
    assert server.audit == [("STALE_RUNTIME_FENCE", 1)]
    assert [lease["status"] for lease in server.leases] == ["EXPIRED", "ACTIVE"]
    row = _authority_row(db_path)
    assert (row["status"], row["fence"], row["assigned_relay_id"]) == ("ACTIVE", 2, None)
    assert row["runtime_instance_id"] != old_runtime_id
    with sqlite3.connect(db_path) as connection:
        metadata_json, receipt_json = connection.execute(
            "SELECT metadata_json, receipt_json FROM direct_sync_relay_batches WHERE relay_id='relay-a'"
        ).fetchone()
    assert "runtime_request_token" not in json.loads(metadata_json)
    assert json.loads(receipt_json)["_local_runtime_lease_status"] == "dead_fence"


def test_data_path_recovery_before_expiry_consumes_the_same_fence(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path, ticks=(100, 200))

    _, recovered = _data_path_cycle(db_path, server, 300, tmp_path)
    _make_pending_relay(db_path, tmp_path, "relay-b")
    _, next_row = _data_path_cycle(db_path, server, 320, tmp_path)

    assert recovered.success is True and next_row.success is True
    assert server.audit == [] and len(server.leases) == 1
    assert [server.stored[relay][0]["runtime_request_sequence"] for relay in ("relay-a", "relay-b")] == [1, 2]
    assert _authority_row(db_path)["fence"] == 1


def test_lost_source_ack_through_the_outage_replays_the_stored_receipt(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path, lose_ack=True)

    _, replayed = _data_path_cycle(db_path, server, 960, tmp_path)
    reissued, _ = _data_path_cycle(db_path, server, 990, tmp_path)
    _make_pending_relay(db_path, tmp_path, "relay-b")
    _, next_row = _data_path_cycle(db_path, server, 1000, tmp_path)

    assert replayed.success is True and reissued.receipt["fence"] == 2 and next_row.success is True
    assert server.audit == []
    relay_a_calls = [call for call in server.source_calls if call["client_batch_id"] == "relay-a"]
    assert len(relay_a_calls) == 5 and all(call == relay_a_calls[0] for call in relay_a_calls)
    assert {relay: row[0] for relay, row in _relay_rows(db_path).items()} == {
        "relay-a": "acked", "relay-b": "acked"
    }


def test_live_clone_keeps_its_fence_after_the_dead_fence_release(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path)
    server.at(940)
    clone_id, clone_jwk = runtime_client.new_runtime_identity()
    status, clone_grant = server.acquire({
        "runtime_instance_id": clone_id,
        "public_jwk": clone_jwk,
        "issue_idempotency_key": "clone-issue",
        "ttl_seconds": 900,
    })
    assert (status, clone_grant["fence"]) == (200, 2)

    _, recovered = _data_path_cycle(db_path, server, 960, tmp_path)
    refused, skipped = _data_path_cycle(db_path, server, 990, tmp_path)
    _make_pending_relay(db_path, tmp_path, "relay-b")
    still_refused, still_skipped = _data_path_cycle(db_path, server, 1000, tmp_path)

    assert recovered.success is True
    assert refused.error_code == still_refused.error_code == "EXACT_CLONE_RUNTIME_CONFLICT"
    assert skipped is None and still_skipped is None
    assert server.active_fence() == 2 and server.leases[-1]["identity"][0] == clone_id
    assert len(server.leases) == 2
    assert "relay-b" not in {call["client_batch_id"] for call in server.source_calls}
    rows = _relay_rows(db_path)
    assert (rows["relay-a"][0], rows["relay-b"][0]) == ("acked", "pending")
    assert _authority_row(db_path)["status"] == "OPERATOR_REVIEW"


def test_observed_stale_token_upload_stays_in_operator_review(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path, ticks=(100,))
    server.leases[0]["token"] = "clone" + "z" * 38  # a database clone spent relay-a's token

    _, result = _data_path_cycle(db_path, server, 300, tmp_path)

    assert result.committed is True and result.success is False
    assert result.error_code == "STALE_RUNTIME_REQUEST_TOKEN"
    assert _relay_rows(db_path)["relay-a"] == ("operator_review", "STALE_RUNTIME_REQUEST_TOKEN")
    row = _authority_row(db_path)
    assert (row["status"], row["assigned_relay_id"]) == ("OPERATOR_REVIEW", None)
    assert _data_path_cycle(db_path, server, 320, tmp_path)[0].operator_review is True
    assert len(server.leases) == 1 and server.audit == [("STALE_RUNTIME_REQUEST_TOKEN", 1)]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt["totals"].update(inserted=1),
        lambda receipt: receipt.update(server_source_file_id="host-other/role/stream/other.csv"),
        lambda receipt: receipt["runtime_lease"].update(contract_version="producer-runtime-lease.v0"),
    ],
    ids=["totals", "identity", "contract-version"],
)
def test_dead_fence_receipt_that_fails_verification_stays_in_review(tmp_path, mutation):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path)
    server.receipt_mutation = mutation

    _, result = _data_path_cycle(db_path, server, 960, tmp_path)

    assert result.committed is True and result.success is False
    assert _relay_rows(db_path)["relay-a"][0] == "operator_review"
    row = _authority_row(db_path)
    assert (row["status"], row["assigned_relay_id"]) == ("OPERATOR_REVIEW", None)
    assert _data_path_cycle(db_path, server, 990, tmp_path)[0].operator_review is True
    assert len(server.leases) == 1


@pytest.mark.parametrize(
    "authority_change",
    [
        "UPDATE direct_sync_runtime_authority SET assigned_relay_id=NULL",
        "UPDATE direct_sync_runtime_authority SET fence=fence+1",
    ],
    ids=["released", "other-fence"],
)
def test_dead_fence_release_requires_the_row_to_still_hold_that_fence(tmp_path, authority_change):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(authority_change)
        connection.execute("UPDATE direct_sync_relay_batches SET next_attempt_at='2000-01-01T00:00:00Z'")
    server.at(960)

    result = direct_sync_push.drain_one_relay_batch(
        db_path=db_path,
        credentials=_credentials(runtime_lease_mode="observe"),
        session=server,
        status_dir=tmp_path / "status",
        timeout=5,
    )

    assert result.committed is True and result.success is False
    assert result.error_code == "STALE_RUNTIME_FENCE"
    with sqlite3.connect(db_path) as connection:
        status, error_code, receipt_json = connection.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches "
            "WHERE relay_id='relay-a'"
        ).fetchone()
    assert (status, error_code) == ("operator_review", "STALE_RUNTIME_FENCE")
    assert "_local_runtime_lease_status" not in json.loads(receipt_json)
    row = _authority_row(db_path)
    assert (row["status"], row["last_error_code"], row["assigned_relay_id"]) == (
        "OPERATOR_REVIEW", "STALE_RUNTIME_FENCE", None
    )
    assert list(server.stored) == ["relay-a"] and len(server.leases) == 1


def test_enforce_refuses_the_dead_fence_uncommitted_and_stays_in_review(tmp_path):
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer(mode="enforce")
    _dead_fence_outage(db_path, server, tmp_path, mode="enforce")

    _, result = _data_path_cycle(db_path, server, 960, tmp_path, mode="enforce")

    assert result.committed is False and result.error_code == "STALE_RUNTIME_FENCE"
    assert _relay_rows(db_path)["relay-a"] == ("operator_review", "STALE_RUNTIME_FENCE")
    assert server.stored == {}
    assert _authority_row(db_path)["status"] == "OPERATOR_REVIEW"


def test_enforce_client_acks_the_observe_servers_committed_dead_fence_receipt(tmp_path):
    # Registered credentials carry no runtime_lease_mode, so field clients run enforce.
    db_path = tmp_path / "relay.sqlite3"
    server = _DataPathServer()
    _dead_fence_outage(db_path, server, tmp_path, mode="enforce")

    _, recovered = _data_path_cycle(db_path, server, 960, tmp_path, mode="enforce")
    reissued, _ = _data_path_cycle(db_path, server, 990, tmp_path, mode="enforce")
    _make_pending_relay(db_path, tmp_path, "relay-b")
    _, next_row = _data_path_cycle(db_path, server, 1000, tmp_path, mode="enforce")

    assert recovered.success is True and recovered.committed is True
    assert reissued.receipt["fence"] == 2 and next_row.success is True
    assert {relay: row[0] for relay, row in _relay_rows(db_path).items()} == {
        "relay-a": "acked", "relay-b": "acked"
    }
    assert server.audit == [("STALE_RUNTIME_FENCE", 1)]
    assert server.stored["relay-b"][0]["runtime_fence"] == 2
    row = _authority_row(db_path)
    assert (row["status"], row["fence"], row["assigned_relay_id"]) == ("ACTIVE", 2, None)
