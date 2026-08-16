import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

import direct_sync_push as direct_sync_push_module
import direct_sync_runtime
from direct_sync_push import (
    RELAY_STATUS_ACKED,
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_LEASED,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    claim_next_relay_batch,
    relay_queue_status,
)
from producer_runtime_client import RuntimePreparation
import tools.direct_sync_relay_runner as runner_module
from tools.direct_sync_relay_runner import main


def write_manifest(tmp_path):
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": "CONTAINER-PC01",
            "source_host_id": "container-runner-host-1",
            "producer_install_id": "install-container-runner-1",
        },
        "apps": ["ContainerAudit"],
        "streams": [
            {
                "producer_role": "container_audit",
                "stream_name": "container_audit_events",
                "source_system": "container_audit",
                "source_transport": "legacy_transfer_csv",
            }
        ],
    }
    path = tmp_path / "producer_manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return path


def write_credential(tmp_path):
    path = tmp_path / "credential.json"
    path.write_text(
        json.dumps(
            {
                "producer_id": "producer-container-runner",
                "key_id": "key-container-runner",
                "secret": "runner-secret",
                "endpoint_url": "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def write_container_csv(sync_dir, *, name="이적작업이벤트로그_runner_20260622.csv"):
    sync_dir.mkdir(parents=True, exist_ok=True)
    path = sync_dir / name
    path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:00:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-1\"\" }\"\n",
        encoding="utf-8",
    )
    return path


def runner_args(tmp_path, *, scan_dir):
    return [
        "--db-path",
        str(tmp_path / "relay.sqlite3"),
        "--spool-dir",
        str(tmp_path / "spool"),
        "--producer-manifest-path",
        str(write_manifest(tmp_path)),
        "--credential-path",
        str(write_credential(tmp_path)),
        "--upload-status-dir",
        str(tmp_path / "status"),
        "--runtime-status-path",
        str(tmp_path / "runtime" / "status.json"),
        "--log-path",
        str(tmp_path / "logs" / "relay.jsonl"),
        "--scan-source-dir",
        str(scan_dir),
        "--source-glob",
        "이적작업이벤트로그_*.csv",
        "--min-source-file-age-seconds",
        "0",
    ]


def relay_rows(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM direct_sync_relay_batches ORDER BY created_at, relay_id"
        ).fetchall()
    finally:
        conn.close()


def source_scan_state(db_path, source_file):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM direct_sync_source_scan_state WHERE source_file_path = ?",
            (str(source_file.resolve()),),
        ).fetchone()
    finally:
        conn.close()


class AcceptedReceiptResponse:
    status_code = 200
    headers = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class AcceptedReceiptSession:
    def __init__(self):
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        metadata = json.loads(data["metadata"])
        _file_name, file_handle, _content_type = files["file"]
        self.calls.append({"metadata": metadata, "file_bytes": file_handle.read()})
        request_id = f"request-{metadata['client_batch_id']}"
        return AcceptedReceiptResponse(
            {
                "request_id": request_id,
                "upload_id": request_id,
                "client_batch_id": metadata["client_batch_id"],
                "server_source_file_id": (
                    f"{metadata['source_host_id']}/{metadata['producer_role']}/"
                    f"{metadata['stream_name']}/{metadata['relative_path']}"
                ),
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            }
        )


def install_receipt_test_runtime(monkeypatch, session):
    monkeypatch.setattr(
        direct_sync_push_module,
        "prepare_runtime_metadata",
        lambda **kwargs: RuntimePreparation(metadata=dict(kwargs["metadata"])),
    )
    monkeypatch.setattr(direct_sync_push_module, "client_runtime_lease_mode", lambda _credentials: "observe")
    monkeypatch.setattr(
        direct_sync_runtime,
        "ensure_runtime_authority",
        lambda **_kwargs: RuntimePreparation(),
    )
    monkeypatch.setattr(
        runner_module,
        "run_relay_once",
        lambda config, **kwargs: direct_sync_runtime.run_relay_once(config, session=session, **kwargs),
    )


def test_runner_scan_source_dir_enqueues_matching_csv_idempotently(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    (sync_dir / "ignore.txt").write_text("not a csv", encoding="utf-8")
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=0" in output
    assert "direct_sync_scan_no_new_count=1" in output
    assert "direct_sync_scan_failed_source_file=" not in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1
    assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None


def test_runner_scan_source_defers_file_with_active_writer_lock(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    lock_path = Path(f"{csv_path.resolve()}.lock")
    lock_path.write_text("writer-pid", encoding="ascii")
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}

    lock_path.unlink()
    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1


def test_runner_scan_source_defers_lock_younger_than_writer_stale_threshold(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    lock_path = Path(f"{csv_path.resolve()}.lock")
    lock_path.write_text("writer-pid", encoding="ascii")
    active_lock_time = time.time() - runner_module.SOURCE_WRITER_LOCK_STALE_SECONDS + 1
    os.utime(lock_path, (active_lock_time, active_lock_time))
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_enqueue_commit_acknowledgement_loss_preserves_exact_row_and_spool(
    tmp_path, capsys, monkeypatch
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    original_size = csv_path.stat().st_size
    args = runner_args(tmp_path, scan_dir=sync_dir)
    original_connect = direct_sync_push_module._connect_relay_db
    loss = {"armed": True}

    class CommitAcknowledgementLossConnection:
        def __init__(self, inner):
            self._inner = inner
            self._inserted_relay = False

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def execute(self, statement, parameters=()):
            if "insert into direct_sync_relay_batches" in " ".join(statement.lower().split()):
                self._inserted_relay = True
            return self._inner.execute(statement, parameters)

        def commit(self):
            self._inner.commit()
            if self._inserted_relay and loss["armed"]:
                loss["armed"] = False
                raise sqlite3.OperationalError("simulated enqueue commit acknowledgement loss")

    monkeypatch.setattr(
        direct_sync_push_module,
        "_connect_relay_db",
        lambda db_path: CommitAcknowledgementLossConnection(original_connect(db_path)),
    )

    assert main(args) == 0
    assert "direct_sync_relay_status=enqueued" in capsys.readouterr().out
    committed_rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(committed_rows) == 1
    relay_id = committed_rows[0]["relay_id"]
    assert committed_rows[0]["status"] == RELAY_STATUS_PENDING
    committed_spool = Path(committed_rows[0]["spooled_file_path"])
    committed_payload = committed_spool.read_bytes()
    assert hashlib.sha256(committed_payload).hexdigest() == committed_rows[0]["content_sha256"]
    assert len(committed_payload) == committed_rows[0]["byte_length"]
    original_hash = hashlib.sha256(csv_path.read_bytes()).hexdigest()
    assert committed_rows[0]["relative_path"].replace("\\", "/").endswith(
        f"/bytes-0-{original_size}-sha256-{original_hash[:16]}.csv"
    )

    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")
    appended_size = csv_path.stat().st_size

    monkeypatch.setattr(direct_sync_push_module, "_connect_relay_db", original_connect)
    session = AcceptedReceiptSession()
    install_receipt_test_runtime(monkeypatch, session)
    credentials = direct_sync_runtime.load_credentials_from_json(tmp_path / "credential.json")

    result = direct_sync_push_module.drain_one_relay_batch(
        db_path=tmp_path / "relay.sqlite3",
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        target_relay_id=relay_id,
    )

    assert result is not None
    assert result.success is True
    assert len(session.calls) == 1
    assert session.calls[0]["metadata"]["client_batch_id"] == relay_id
    assert session.calls[0]["file_bytes"] == committed_payload
    drained_rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(drained_rows) == 1
    assert drained_rows[0]["relay_id"] == relay_id
    assert drained_rows[0]["status"] == RELAY_STATUS_ACKED

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=enqueued" in output
    recovered_rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(recovered_rows) == 2
    assert recovered_rows[0]["relay_id"] == relay_id
    assert recovered_rows[0]["status"] == RELAY_STATUS_ACKED
    assert recovered_rows[1]["status"] == RELAY_STATUS_PENDING
    assert f"/bytes-{original_size}-{appended_size}-" in recovered_rows[1][
        "relative_path"
    ].replace("\\", "/")
    appended_payload = Path(recovered_rows[1]["spooled_file_path"]).read_text(
        encoding="utf-8"
    )
    assert "BC-2" in appended_payload
    assert "BC-1" not in appended_payload
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    ("lease_expires_at", "damage", "expect_repaired"),
    [
        ("2000-01-01T00:00:00Z", "missing", True),
        ("2000-01-01T00:00:00Z", "corrupt", True),
        ("2999-01-01T00:00:00Z", "missing", False),
        ("2999-01-01T00:00:00Z", "corrupt", False),
    ],
    ids=["stale-missing", "stale-corrupt", "active-missing", "active-corrupt"],
)
def test_runner_repairs_damaged_leased_delta_before_scanning_appended_rows(
    tmp_path, capsys, monkeypatch, lease_expires_at, damage, expect_repaired
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    original_size = csv_path.stat().st_size
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    first = relay_rows(tmp_path / "relay.sqlite3")[0]
    relay_id = first["relay_id"]
    original_spool = Path(first["spooled_file_path"])
    original_payload = original_spool.read_bytes()
    claimed = claim_next_relay_batch(
        db_path=tmp_path / "relay.sqlite3",
        worker_id="active-worker",
        lease_seconds=60,
        now="2099-01-01T00:00:00Z",
    )
    assert claimed is not None
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE direct_sync_relay_batches SET lease_expires_at = ? WHERE relay_id = ?",
            (lease_expires_at, relay_id),
        )
        conn.commit()
        before = dict(
            conn.execute(
                "SELECT * FROM direct_sync_relay_batches WHERE relay_id = ?",
                (relay_id,),
            ).fetchone()
        )
    if damage == "missing":
        original_spool.unlink()
        damaged_payload = None
    else:
        damaged_payload = b"X" * len(original_payload)
        original_spool.write_bytes(damaged_payload)
    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")
    appended_size = csv_path.stat().st_size

    assert main(args) == 0
    output = capsys.readouterr().out
    rows = relay_rows(tmp_path / "relay.sqlite3")
    after = dict(next(row for row in rows if row["relay_id"] == relay_id))

    if expect_repaired:
        assert "direct_sync_relay_status=enqueued" in output
        assert "direct_sync_scan_enqueued_count=1" in output
        assert len(rows) == 2
        assert after["status"] == RELAY_STATUS_PENDING
        assert after["lease_owner"] is None
        assert after["lease_expires_at"] is None
        assert after["attempt_count"] == 1
        assert after["metadata_json"] == before["metadata_json"]
        assert original_spool.read_bytes() == original_payload
        appended = next(row for row in rows if row["relay_id"] != relay_id)
        assert appended["status"] == RELAY_STATUS_PENDING
        assert f"/bytes-{original_size}-{appended_size}-" in appended[
            "relative_path"
        ].replace("\\", "/")

        session = AcceptedReceiptSession()
        install_receipt_test_runtime(monkeypatch, session)
        credentials = direct_sync_runtime.load_credentials_from_json(tmp_path / "credential.json")
        result = direct_sync_push_module.drain_one_relay_batch(
            db_path=tmp_path / "relay.sqlite3",
            credentials=credentials,
            session=session,
            status_dir=tmp_path / "status",
            target_relay_id=relay_id,
        )
        assert result is not None
        assert result.success is True
        assert session.calls[0]["metadata"]["client_batch_id"] == relay_id
        assert session.calls[0]["file_bytes"] == original_payload
    else:
        assert "direct_sync_relay_status=scan_no_new_rows" in output
        assert "direct_sync_scan_enqueued_count=0" in output
        assert len(rows) == 1
        assert after == before
        assert after["status"] == RELAY_STATUS_LEASED
        if damage == "missing":
            assert not original_spool.exists()
        else:
            assert original_spool.read_bytes() == damaged_payload
        assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None


def test_runner_scan_source_deleted_after_eligibility_defers_without_crash(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)
    original_eligibility_check = runner_module._source_file_still_eligible_for_enqueue

    def delete_after_eligibility(path, *inner_args, **inner_kwargs):
        eligible = original_eligibility_check(path, *inner_args, **inner_kwargs)
        if path == csv_path:
            path.unlink()
        return eligible

    monkeypatch.setattr(runner_module, "_source_file_still_eligible_for_enqueue", delete_after_eligibility)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_scan_source_dir_treats_acked_dedupe_as_idempotent_success(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET status = ?", (RELAY_STATUS_ACKED,))
        conn.commit()

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=0" in output
    assert "direct_sync_scan_no_new_count=1" in output
    assert "direct_sync_scan_failed_source_file=" not in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_ACKED] == 1


def test_runner_scan_source_dir_does_not_starve_new_files_behind_acked_rows(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    older = write_container_csv(sync_dir, name="이적작업이벤트로그_001_20260622.csv")
    newer = write_container_csv(sync_dir, name="이적작업이벤트로그_002_20260622.csv")
    now = time.time()
    os.utime(older, (now - 20, now - 20))
    os.utime(newer, (now - 10, now - 10))
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--max-enqueue-files", "1"]

    assert main(args) == 0
    capsys.readouterr()
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?
            WHERE relay_id = (
                SELECT relay_id FROM direct_sync_relay_batches ORDER BY created_at LIMIT 1
            )
            """,
            (RELAY_STATUS_ACKED,),
        )
        conn.commit()

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {
        RELAY_STATUS_ACKED: 1,
        RELAY_STATUS_PENDING: 1,
    }


def test_runner_scan_source_dir_reports_terminal_dedupe_as_blocked(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET status = ?", (RELAY_STATUS_FAILED_PERMANENT,))
        conn.commit()

    assert main(args) == 2
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=existing_terminal_blocked" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert f"direct_sync_scan_failed_source_file={csv_path}" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_FAILED_PERMANENT] == 1
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["scan_attempted_count"] == 1
    assert status["scan_failed_source_file"] == str(csv_path)


def test_runner_scan_source_dir_continues_after_old_terminal_delta(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    old_csv = write_container_csv(sync_dir, name="이적작업이벤트로그_관리자A_20260706.csv")
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute("UPDATE direct_sync_relay_batches SET status = ?", (RELAY_STATUS_FAILED_PERMANENT,))
        conn.commit()

    new_csv = write_container_csv(sync_dir, name="이적작업이벤트로그_관리자A_20260709.csv")
    new_csv.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-07-09T02:00:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"R13-G001\"\" }\"\n",
        encoding="utf-8",
    )
    now = time.time()
    os.utime(old_csv, (now - 120, now - 120))
    os.utime(new_csv, (now - 60, now - 60))

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert "direct_sync_scan_attempted_count=2" in output
    assert "direct_sync_scan_terminal_blocked_count=1" in output
    assert "direct_sync_scan_failed_source_file=" not in output
    counts = relay_queue_status(tmp_path / "relay.sqlite3")["counts"]
    assert counts[RELAY_STATUS_FAILED_PERMANENT] == 1
    assert counts[RELAY_STATUS_PENDING] == 1
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["status"] == "enqueued"
    assert status["scan_terminal_blocked_count"] == 1
    assert status["scan_terminal_blocked_source_files"] == [str(old_csv)]


def test_runner_scan_source_dir_can_drain_after_scan(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]
    calls = []

    def fake_run_relay_once(config, **kwargs):
        calls.append((config, kwargs))
        return {"status": "acked", "last_result": {"relay_id": kwargs.get("target_relay_id", "")}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_run_relay_once)

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=acked" in output
    assert "direct_sync_scan_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert len(calls) == 1
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["status"] == "acked"
    assert status["scan_status"] == "enqueued"
    assert status["scan_enqueued_count"] == 1
    assert status["scan_attempted_count"] == 1
    assert status["last_result"]["scan_status"] == "enqueued"


def test_runner_scan_source_dir_targets_new_delta_when_old_pending_exists(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    old_csv = write_container_csv(sync_dir)
    assert main(runner_args(tmp_path, scan_dir=sync_dir)) == 0
    capsys.readouterr()
    old_relay_id = relay_rows(tmp_path / "relay.sqlite3")[0]["relay_id"]

    current_csv = write_container_csv(sync_dir, name="이적작업이벤트로그_runner_current_20260622.csv")
    calls = []

    def fake_acked_relay_once(config, **kwargs):
        target_relay_id = kwargs.get("target_relay_id") or ""
        calls.append(target_relay_id)
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, target_relay_id),
            )
            conn.commit()
        return {"status": "acked", "last_result": {"relay_id": target_relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=acked" in output
    assert calls
    assert calls[-1] != old_relay_id
    counts = relay_queue_status(tmp_path / "relay.sqlite3")["counts"]
    assert counts[RELAY_STATUS_PENDING] == 1
    assert counts[RELAY_STATUS_ACKED] == 1
    assert source_scan_state(tmp_path / "relay.sqlite3", old_csv) is None
    assert source_scan_state(tmp_path / "relay.sqlite3", current_csv) is not None
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["targeted_drain_results"][-1]["target_relay_id"] == calls[-1]


def test_runner_scan_source_does_not_record_watermark_past_unacked_prefix(
    tmp_path, capsys, monkeypatch
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    first_rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(first_rows) == 1
    old_pending_relay_id = first_rows[0]["relay_id"]

    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")

    calls = []

    def fake_acked_relay_once(config, **kwargs):
        target_relay_id = kwargs.get("target_relay_id") or ""
        calls.append(target_relay_id)
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, target_relay_id),
            )
            conn.commit()
        return {"status": "acked", "last_result": {"relay_id": target_relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(args + ["--drain-after-scan"]) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=acked" in output
    assert calls
    assert calls[-1] != old_pending_relay_id
    counts = relay_queue_status(tmp_path / "relay.sqlite3")["counts"]
    assert counts[RELAY_STATUS_PENDING] == 1
    assert counts[RELAY_STATUS_ACKED] == 1
    assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    source_state_update = status["targeted_drain_results"][-1]["source_scan_state_update"]
    assert source_state_update["status"] == "deferred_unacked_prefix"
    assert source_state_update["durable_sent_byte_count"] == 0


def test_runner_scan_source_content_append_enqueues_new_delta(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert "direct_sync_scan_failed_source_file=" not in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 2
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert "/bytes-0-" in rows[0]["relative_path"].replace("\\", "/")
    assert "/bytes-0-" not in rows[1]["relative_path"].replace("\\", "/")
    second_payload = Path(rows[1]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-2" in second_payload
    assert "BC-1" not in second_payload


def test_runner_scan_source_defers_trailing_partial_csv_row_until_newline(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    csv_path = sync_dir / "이적작업이벤트로그_runner_20260622.csv"
    csv_path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-PART",
        encoding="utf-8",
    )
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}

    with csv_path.open("a", encoding="utf-8", newline="") as file:
        file.write("IAL\"\" }\"\n")

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 1
    payload = Path(rows[0]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-PARTIAL" in payload


def test_runner_scan_source_defers_trailing_cr_until_lf(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    csv_path = sync_dir / "이적작업이벤트로그_runner_20260622.csv"
    csv_path.write_bytes(
        b"timestamp,worker_name,event,details\r\n"
        b"2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-CR\"\" }\"\r"
    )
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_new_rows" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}

    with csv_path.open("ab") as file:
        file.write(b"\n")

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 1
    payload = Path(rows[0]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-CR" in payload


def test_runner_scan_source_complete_prefix_uses_completed_end_byte(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]

    def fake_acked_relay_once(config, **kwargs):
        relay_id = kwargs.get("target_relay_id") or relay_rows(config.db_path)[-1]["relay_id"]
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, relay_id),
            )
            conn.commit()
        return {"status": "acked", "last_result": {"relay_id": relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(args) == 0
    capsys.readouterr()
    first_state = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert first_state is not None

    complete_append = "2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n"
    partial_append = "2026-06-22T00:02:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-PART"
    start_byte = csv_path.stat().st_size
    with csv_path.open("a", encoding="utf-8", newline="") as file:
        file.write(complete_append)
        file.write(partial_append)
    expected_end_byte = start_byte + len(complete_append.encode("utf-8"))
    full_size = csv_path.stat().st_size

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=acked" in output
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 2
    relative_path = rows[1]["relative_path"].replace("\\", "/")
    assert f"/bytes-{start_byte}-{expected_end_byte}-" in relative_path
    assert f"/bytes-{start_byte}-{full_size}-" not in relative_path
    payload = Path(rows[1]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-2" in payload
    assert "BC-PART" not in payload


def test_runner_scan_source_committed_operator_review_delta_blocks_progress(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    first_row = relay_rows(tmp_path / "relay.sqlite3")[0]
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                receipt_json = ?,
                last_error_code = ?
            WHERE relay_id = ?
            """,
            (
                RELAY_STATUS_OPERATOR_REVIEW,
                json.dumps(
                    {
                        "client_batch_id": first_row["relay_id"],
                        "committed": True,
                        "_local_upload_result_committed": True,
                        "totals": {"inserted": 0, "replayed": 0, "quarantined": 1, "errors": 0},
                    }
                ),
                "producer_receipt_contains_quarantine",
                first_row["relay_id"],
            ),
        )
        conn.commit()
    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")

    assert main(args) == 2
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=existing_terminal_blocked" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert f"direct_sync_scan_failed_source_file={csv_path}" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {RELAY_STATUS_OPERATOR_REVIEW: 1}
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 1
    assert "/bytes-0-" in rows[0]["relative_path"].replace("\\", "/")
    assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None


def test_runner_scan_source_uncommitted_operator_review_delta_blocks_progress(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    capsys.readouterr()
    first_row = relay_rows(tmp_path / "relay.sqlite3")[0]
    with sqlite3.connect(tmp_path / "relay.sqlite3") as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                receipt_json = ?,
                last_error_code = ?
            WHERE relay_id = ?
            """,
            (
                RELAY_STATUS_OPERATOR_REVIEW,
                json.dumps({"client_batch_id": first_row["relay_id"], "committed": False}),
                "relay_metadata_invalid",
                first_row["relay_id"],
            ),
        )
        conn.commit()
    with csv_path.open("a", encoding="utf-8") as file:
        file.write("2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n")

    assert main(args) == 2
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=existing_terminal_blocked" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert f"direct_sync_scan_failed_source_file={csv_path}" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {RELAY_STATUS_OPERATOR_REVIEW: 1}
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 1
    assert "/bytes-0-" in rows[0]["relative_path"].replace("\\", "/")
    assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None


def test_runner_scan_source_records_watermark_after_durable_ack(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]

    def fake_acked_relay_once(config, **kwargs):
        relay_id = kwargs.get("target_relay_id") or relay_rows(config.db_path)[0]["relay_id"]
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, relay_id),
            )
            conn.commit()
        return {"status": "acked", "last_result": {"relay_id": relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(args) == 0
    capsys.readouterr()

    state = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert state is not None
    assert state["sent_byte_count"] == csv_path.stat().st_size
    assert state["sent_prefix_sha256"] == runner_module._file_prefix_sha256(csv_path, csv_path.stat().st_size)


def test_runner_restart_rebuilds_watermark_after_ack_write_acknowledgement_loss(
    tmp_path, capsys, monkeypatch
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]
    session = AcceptedReceiptSession()
    install_receipt_test_runtime(monkeypatch, session)
    original_set_relay_status = direct_sync_push_module._set_relay_status
    loss = {"armed": True}

    def commit_ack_then_lose_acknowledgement(**kwargs):
        updated = original_set_relay_status(**kwargs)
        if kwargs.get("status") == RELAY_STATUS_ACKED and loss["armed"]:
            loss["armed"] = False
            raise OSError("simulated ACK write acknowledgement loss")
        return updated

    monkeypatch.setattr(
        direct_sync_push_module,
        "_set_relay_status",
        commit_ack_then_lose_acknowledgement,
    )

    assert main(args) == 1
    assert "direct_sync_relay_status=runtime_error" in capsys.readouterr().out
    rows_after_loss = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows_after_loss) == 1
    assert rows_after_loss[0]["status"] == RELAY_STATUS_ACKED
    assert Path(rows_after_loss[0]["spooled_file_path"]).is_file()
    assert source_scan_state(tmp_path / "relay.sqlite3", csv_path) is None
    assert len(session.calls) == 1

    monkeypatch.setattr(direct_sync_push_module, "_set_relay_status", original_set_relay_status)

    assert main(args) == 0
    capsys.readouterr()
    rebuilt = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert rebuilt is not None
    assert rebuilt["sent_byte_count"] == csv_path.stat().st_size
    assert rebuilt["sent_prefix_sha256"] == runner_module._file_prefix_sha256(
        csv_path, csv_path.stat().st_size
    )
    assert len(relay_rows(tmp_path / "relay.sqlite3")) == 1
    assert len(session.calls) == 1


def test_runner_scan_source_ack_records_spooled_prefix_hash_not_replaced_source(
    tmp_path, capsys, monkeypatch
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    original_bytes = csv_path.read_bytes()
    original_prefix_sha256 = hashlib.sha256(original_bytes).hexdigest()
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]
    calls = {"count": 0}

    def fake_acked_relay_once(config, **kwargs):
        calls["count"] += 1
        relay_id = kwargs.get("target_relay_id") or relay_rows(config.db_path)[-1]["relay_id"]
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, relay_id),
            )
            conn.commit()
        if calls["count"] == 1:
            csv_path.write_text(
                "timestamp,worker_name,event,details\n"
                "2026-06-22T00:02:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-REPLACED\"\" }\"\n",
                encoding="utf-8",
            )
        return {"status": "acked", "last_result": {"relay_id": relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(args) == 0
    capsys.readouterr()
    poisoned_candidate_state = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert poisoned_candidate_state is not None
    assert poisoned_candidate_state["sent_byte_count"] == len(original_bytes)
    assert poisoned_candidate_state["sent_prefix_sha256"] == original_prefix_sha256
    assert poisoned_candidate_state["sent_prefix_sha256"] != runner_module._file_prefix_sha256(
        csv_path,
        poisoned_candidate_state["sent_byte_count"],
    )

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=acked" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 2
    assert "/bytes-0-" in rows[1]["relative_path"].replace("\\", "/")
    payload = Path(rows[1]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-REPLACED" in payload
    assert "BC-1" not in payload


def test_runner_scan_source_replaced_same_name_resets_watermark_and_enqueues_full_file(
    tmp_path, capsys, monkeypatch
):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--drain-after-scan"]

    def fake_acked_relay_once(config, **kwargs):
        relay_id = kwargs.get("target_relay_id") or relay_rows(config.db_path)[-1]["relay_id"]
        with sqlite3.connect(config.db_path) as conn:
            conn.execute(
                "UPDATE direct_sync_relay_batches SET status = ? WHERE relay_id = ?",
                (RELAY_STATUS_ACKED, relay_id),
            )
            conn.commit()
        return {"status": "acked", "last_result": {"relay_id": relay_id}}

    monkeypatch.setattr(runner_module, "run_relay_once", fake_acked_relay_once)

    assert main(args) == 0
    capsys.readouterr()
    first_state = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert first_state is not None
    assert first_state["sent_byte_count"] == csv_path.stat().st_size

    csv_path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:02:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-REPLACED\"\" }\"\n",
        encoding="utf-8",
    )

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=acked" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    rows = relay_rows(tmp_path / "relay.sqlite3")
    assert len(rows) == 2
    assert "/bytes-0-" in rows[1]["relative_path"].replace("\\", "/")
    second_payload = Path(rows[1]["spooled_file_path"]).read_text(encoding="utf-8")
    assert "BC-REPLACED" in second_payload
    assert "BC-1" not in second_payload
    second_state = source_scan_state(tmp_path / "relay.sqlite3", csv_path)
    assert second_state["sent_byte_count"] == csv_path.stat().st_size
    assert second_state["sent_prefix_sha256"] == runner_module._file_prefix_sha256(
        csv_path, csv_path.stat().st_size
    )


def test_runner_scan_source_dir_filters_broad_csv_glob_to_container_logs(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    write_container_csv(sync_dir, name="unrelated.csv")
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--source-glob", "*.csv"]

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_scan_enqueued_count=1" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1


def test_runner_scan_source_dir_rejects_bad_container_csv_header(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    (sync_dir / "이적작업이벤트로그_bad_20260622.csv").write_text(
        "not,timestamp,event,details\n1,2,3,4\n",
        encoding="utf-8",
    )
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 1
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=enqueue_error" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert "direct_sync_scan_failed_source_file=" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_scan_source_dir_skips_symlinked_matching_csv(tmp_path):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    target = tmp_path / "outside.csv"
    target.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:00:00,worker,SCAN_OK,\"{}\"\n",
        encoding="utf-8",
    )
    link = sync_dir / "이적작업이벤트로그_link_20260622.csv"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    assert runner_module._scan_source_files(str(sync_dir), ["*.csv"], 100, min_age_seconds=0) == []


def test_runner_scan_source_dir_defaults_to_skipping_recent_files(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir)
    age_index = args.index("--min-source-file-age-seconds")
    del args[age_index : age_index + 2]

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_files" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_scan_source_dir_skips_files_deleted_during_scan(tmp_path, monkeypatch):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    original_stat = runner_module.Path.stat

    def disappearing_stat(path, *args, **kwargs):
        if path == csv_path:
            raise FileNotFoundError(str(path))
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(runner_module.Path, "stat", disappearing_stat)

    assert runner_module._scan_source_files(str(sync_dir), ["*.csv"], 100, min_age_seconds=0) == []


def test_runner_scan_source_dir_rejects_recursive_or_path_globs(tmp_path):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--source-glob", "**/*.csv"]

    try:
        main(args)
    except SystemExit as exc:
        assert "source glob must be a direct-child file pattern" in str(exc)
        return
    raise AssertionError("expected SystemExit for recursive source glob")


def test_runner_scan_source_dir_handles_no_matching_files(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    args = runner_args(tmp_path, scan_dir=sync_dir)

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_files" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["status"] == "scan_no_files"
    assert status["last_result"]["scan_attempted_count"] == 0


def test_runner_scan_source_dir_skips_recent_files_when_min_age_is_set(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    now = time.time()
    os.utime(csv_path, (now, now))
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--min-source-file-age-seconds", "3600"]

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=scan_no_files" in output
    assert "direct_sync_scan_enqueued_count=0" in output

    old_time = now - 7200
    os.utime(csv_path, (old_time, old_time))

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=1" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 1


def test_runner_revalidates_source_file_age_immediately_before_enqueue(tmp_path, capsys, monkeypatch):
    sync_dir = tmp_path / "sync"
    csv_path = write_container_csv(sync_dir)
    old_time = time.time() - 7200
    os.utime(csv_path, (old_time, old_time))
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--min-source-file-age-seconds", "3600"]

    def fake_scan_source_files(*args, **kwargs):
        os.utime(csv_path, None)
        return [csv_path]

    monkeypatch.setattr(runner_module, "_scan_source_files", fake_scan_source_files)
    monkeypatch.setattr(
        runner_module,
        "enqueue_completed_source_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("revalidated recent file should not enqueue")),
    )

    assert main(args) == 0
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=scan_no_files" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=0" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_runtime_error_returns_failure_exit_code(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    args = runner_args(tmp_path, scan_dir=sync_dir)
    scan_index = args.index("--scan-source-dir")
    del args[scan_index : scan_index + 2]
    glob_index = args.index("--source-glob")
    del args[glob_index : glob_index + 2]
    (tmp_path / "relay.sqlite3").write_text("not a sqlite database", encoding="utf-8")

    assert main(args) == 1
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=runtime_error" in output


@pytest.mark.parametrize(
    ("relay_status", "expected_exit"),
    [
        ("failed_permanent", 2),
        ("operator_review", 2),
        ("retry_wait", 0),
    ],
)
def test_runner_drain_exit_code_reflects_terminal_or_operator_review_status(
    tmp_path,
    capsys,
    monkeypatch,
    relay_status,
    expected_exit,
):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    args = runner_args(tmp_path, scan_dir=sync_dir)
    scan_index = args.index("--scan-source-dir")
    del args[scan_index : scan_index + 2]
    glob_index = args.index("--source-glob")
    del args[glob_index : glob_index + 2]
    monkeypatch.setattr(runner_module, "run_relay_once", lambda config: {"status": relay_status})

    assert main(args) == expected_exit
    output = capsys.readouterr().out
    assert f"direct_sync_relay_status={relay_status}" in output


def test_runner_scan_source_dir_records_backpressure_warning_and_continues(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    write_container_csv(sync_dir, name="이적작업이벤트로그_runner2_20260622.csv")
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--max-active-queue-count", "1"]

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=enqueued" in output
    assert "direct_sync_scan_enqueued_count=2" in output
    assert "direct_sync_scan_attempted_count=2" in output
    assert "direct_sync_scan_failed_source_file=" not in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"][RELAY_STATUS_PENDING] == 2
    status = json.loads((tmp_path / "runtime" / "status.json").read_text(encoding="utf-8"))
    assert status["scan_enqueued_count"] == 2
    assert status["scan_attempted_count"] == 2
    assert status["queue_backpressure"]["status"] == "blocked"


def test_runner_honors_operator_pause_before_scan_enqueue(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    pause_path = tmp_path / "control" / "pause.json"
    pause_path.parent.mkdir(parents=True)
    pause_path.write_text(
        json.dumps(
                {
                    "schema_version": "direct-sync-relay-operator-pause-v1",
                    "status": "paused",
                    "operator_id": "operator-a",
                    "reason_redacted": "sha256:000000000000",
                    "reason_sha256": "0" * 64,
                    "reason_length": 11,
                    "created_at": "2026-06-22T00:00:00Z",
                },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--operator-pause-path", str(pause_path)]

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "direct_sync_relay_status=paused_by_operator" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert "direct_sync_scan_failed_source_file=" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}


def test_runner_invalid_operator_pause_marker_returns_blocked_exit(tmp_path, capsys):
    sync_dir = tmp_path / "sync"
    write_container_csv(sync_dir)
    pause_path = tmp_path / "control" / "pause.json"
    pause_path.parent.mkdir(parents=True)
    pause_path.write_text("{not-json}", encoding="utf-8")
    args = runner_args(tmp_path, scan_dir=sync_dir) + ["--operator-pause-path", str(pause_path)]

    assert main(args) == 2
    output = capsys.readouterr().out

    assert "direct_sync_relay_status=blocked_operator_control" in output
    assert "direct_sync_scan_enqueued_count=0" in output
    assert "direct_sync_scan_attempted_count=1" in output
    assert "direct_sync_scan_failed_source_file=" in output
    assert relay_queue_status(tmp_path / "relay.sqlite3")["counts"] == {}
