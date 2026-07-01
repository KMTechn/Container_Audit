import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

import direct_sync_operator
from tools import direct_sync_relay_operator as operator_cli
from direct_sync_operator import operator_status, pause_relay, resume_relay, retry_dead_relay_batch
from direct_sync_push import (
    RELAY_STATUS_ACKED,
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    RELAY_STATUS_RETRY_WAIT,
    relay_queue_status,
)
from direct_sync_runtime import enqueue_completed_source_file, load_credentials_from_json, run_relay_once
from tests.test_direct_sync_runtime import EchoAcceptedSession, FakeResponse, FakeSession, make_config, write_csv
from tools.direct_sync_relay_operator import main


class RestoreResponse:
    def __init__(self, status_code, body=b"", *, headers=None, payload=None):
        self.status_code = status_code
        self.content = body
        self.headers = dict(headers or {})
        self._payload = payload if payload is not None else {}

    def iter_content(self, chunk_size=1024 * 1024):
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index : index + chunk_size]

    def json(self):
        return self._payload


class RestoreSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, headers, timeout, stream=False, allow_redirects=False):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "timeout": timeout,
                "stream": stream,
                "allow_redirects": allow_redirects,
            }
        )
        return self.response


def _acked_restore_case(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    assert run_relay_once(config, session=EchoAcceptedSession())["status"] == "acked"
    with sqlite3.connect(config.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT spooled_file_path
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (relay_id,),
        ).fetchone()
    return config, relay_id, load_credentials_from_json(config.credential_path), Path(row["spooled_file_path"])


def _set_relay_spool_path(db_path, relay_id, path):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET spooled_file_path = ? WHERE relay_id = ?",
            (str(path), relay_id),
        )
        conn.commit()


def test_operator_atomic_json_write_uses_unique_temp_paths(tmp_path, monkeypatch):
    target = tmp_path / "pause.json"
    temp_paths: list[Path] = []
    real_replace = direct_sync_operator.os.replace

    def capture_replace(src, dst):
        temp_paths.append(Path(src))
        real_replace(src, dst)

    monkeypatch.setattr(direct_sync_operator.os, "replace", capture_replace)

    direct_sync_operator._write_json_atomic(target, {"status": "first"})
    direct_sync_operator._write_json_atomic(target, {"status": "second"})

    assert len({path.name for path in temp_paths}) == 2
    assert all(path.parent == target.parent for path in temp_paths)
    assert all(path.name.startswith("pause.json.tmp.") for path in temp_paths)
    assert json.loads(target.read_text(encoding="utf-8-sig"))["status"] == "second"


def test_operator_cli_report_atomic_json_write_uses_unique_temp_paths(tmp_path, monkeypatch):
    target = tmp_path / "report.json"
    temp_paths: list[Path] = []
    real_replace = operator_cli.os.replace

    def capture_replace(src, dst):
        temp_paths.append(Path(src))
        real_replace(src, dst)

    monkeypatch.setattr(operator_cli.os, "replace", capture_replace)

    operator_cli._write_json_atomic(target, {"status": "first"})
    operator_cli._write_json_atomic(target, {"status": "second"})

    assert len({path.name for path in temp_paths}) == 2
    assert all(path.parent == target.parent for path in temp_paths)
    assert all(path.name.startswith("report.json.tmp.") for path in temp_paths)
    assert json.loads(target.read_text(encoding="utf-8-sig"))["status"] == "second"


def test_operator_status_pause_and_resume_write_redacted_evidence(tmp_path):
    config = make_config(tmp_path)
    audit_log_path = tmp_path / "logs" / "operator.jsonl"
    pause_report_path = tmp_path / "reports" / "pause.json"
    status_report_path = tmp_path / "reports" / "status.json"

    assert (
        main(
            [
                "pause",
                "--operator-pause-path",
                str(config.operator_pause_path),
                "--operator-id",
                "operator-a",
                "--reason",
                "local maintenance",
                "--audit-log-path",
                str(audit_log_path),
                "--report-path",
                str(pause_report_path),
            ]
        )
        == 0
    )
    pause_report = json.loads(pause_report_path.read_text(encoding="utf-8-sig"))
    assert pause_report["status"] == "PASS"
    assert pause_report["pause"]["paused"] is True

    assert (
        main(
            [
                "status",
                "--db-path",
                str(config.db_path),
                "--operator-pause-path",
                str(config.operator_pause_path),
                "--report-path",
                str(status_report_path),
            ]
        )
        == 0
    )
    status_report = json.loads(status_report_path.read_text(encoding="utf-8-sig"))
    assert status_report["status"] == "PASS"
    assert status_report["pause"]["paused"] is True
    assert status_report["queue"]["counts"] == {}

    assert (
        main(
            [
                "resume",
                "--operator-pause-path",
                str(config.operator_pause_path),
                "--operator-id",
                "operator-a",
                "--reason",
                "maintenance complete",
                "--audit-log-path",
                str(audit_log_path),
            ]
        )
        == 0
    )
    assert not Path(config.operator_pause_path).exists()
    audit_bytes = audit_log_path.read_bytes()
    assert b"runtime-secret" not in audit_bytes
    assert b"X-Producer-Signature" not in audit_bytes


@pytest.mark.parametrize(
    ("dead_status", "error_code"),
    [
        (RELAY_STATUS_OPERATOR_REVIEW, "dead_letter_operator_review"),
        (RELAY_STATUS_FAILED_PERMANENT, "dead_letter_failed_permanent"),
    ],
)
def test_operator_status_blocks_when_dead_letter_rows_require_attention(tmp_path, dead_status, error_code):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?
            WHERE relay_id = ?
            """,
            (dead_status, relay_id),
        )

    report = operator_status(db_path=config.db_path, pause_path=config.operator_pause_path)

    assert report["status"] == "BLOCKED"
    assert report["requires_attention"] is True
    assert report["dead_letter_counts"] == {dead_status: 1}
    assert report["error_code"] == error_code
    assert report["queue"]["counts"][dead_status] == 1


def test_operator_status_cli_exits_blocked_when_dead_letter_rows_require_attention(tmp_path, capsys):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?
            WHERE relay_id = ?
            """,
            (RELAY_STATUS_OPERATOR_REVIEW, relay_id),
        )
    report_path = tmp_path / "reports" / "status.json"

    exit_code = main(
        [
            "status",
            "--db-path",
            str(config.db_path),
            "--operator-pause-path",
            str(config.operator_pause_path),
            "--report-path",
            str(report_path),
        ]
    )

    output = capsys.readouterr().out
    persisted = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 2
    assert "direct_sync_operator_status=BLOCKED" in output
    assert persisted["status"] == "BLOCKED"
    assert persisted["requires_attention"] is True
    assert persisted["dead_letter_counts"][RELAY_STATUS_OPERATOR_REVIEW] == 1


def test_operator_status_cli_can_include_runtime_last_failure(tmp_path, capsys):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueue_completed_source_file(config, source_file_path=source_file)
    run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                503,
                {
                    "committed": False,
                    "retryable": True,
                    "error": {"code": "temporary_unavailable", "message": "try later"},
                },
            )
        ),
    )
    report_path = tmp_path / "reports" / "status-with-runtime.json"

    exit_code = main(
        [
            "status",
            "--db-path",
            str(config.db_path),
            "--operator-pause-path",
            str(config.operator_pause_path),
            "--runtime-status-path",
            str(config.runtime_status_path),
            "--report-path",
            str(report_path),
        ]
    )

    output = capsys.readouterr().out
    persisted = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert exit_code == 0
    assert "direct_sync_operator_status=PASS" in output
    assert persisted["queue"]["counts"][RELAY_STATUS_RETRY_WAIT] == 1
    assert persisted["runtime"]["available"] is True
    assert persisted["runtime"]["status"] == "retry_wait"
    assert persisted["runtime"]["payload"]["last_result"]["status"] == "retry_wait"
    assert persisted["runtime"]["payload"]["last_result"]["error_code"] == "temporary_unavailable"


def test_operator_status_cli_redacts_sensitive_runtime_status_payload(tmp_path, capsys):
    config = make_config(tmp_path)
    report_path = tmp_path / "reports" / "status-redacted.json"
    runtime_path = Path(config.runtime_status_path)
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.write_text(
        json.dumps(
            {
                "status": "retry_wait",
                "updated_at": "2026-06-25T00:00:00Z",
                "last_result": {
                    "status": "retry_wait",
                    "error_code": "transport_error",
                    "error_message": (
                        "Authorization: Bearer SHOULD-NOT-LEAK "
                        "X-Producer-Signature: PRODUCER-HMAC-SHA256-V1 RAW-FREEFORM-SIGNATURE; "
                        "secret=RAW-SECRET token=RAW-TOKEN signature=RAW-SIGNATURE "
                        "hmac=RAW-HMAC api_key=RAW-API-KEY password=RAW-PASSWORD"
                    ),
                    "headers": {
                        "X-Producer-Key-Id": "key-container-01",
                        "X-Producer-Signature": "PRODUCER-HMAC-SHA256-V1 SHOULD-NOT-LEAK",
                    },
                    "receipt_json": {"raw": "SHOULD-NOT-LEAK"},
                },
                "raw_payload": "SHOULD-NOT-LEAK",
                "nested": [{"token": "SHOULD-NOT-LEAK"}],
                "content_sha256": "a" * 64,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "status",
            "--db-path",
            str(config.db_path),
            "--operator-pause-path",
            str(config.operator_pause_path),
            "--runtime-status-path",
            str(runtime_path),
            "--report-path",
            str(report_path),
        ]
    )

    capsys.readouterr()
    persisted = json.loads(report_path.read_text(encoding="utf-8-sig"))
    persisted_json = json.dumps(persisted, ensure_ascii=False)
    assert exit_code == 0
    assert persisted["runtime"]["available"] is True
    assert persisted["runtime"]["status"] == "retry_wait"
    assert "SHOULD-NOT-LEAK" not in persisted_json
    assert "RAW-SECRET" not in persisted_json
    assert "RAW-TOKEN" not in persisted_json
    assert "RAW-SIGNATURE" not in persisted_json
    assert "RAW-FREEFORM-SIGNATURE" not in persisted_json
    assert "RAW-HMAC" not in persisted_json
    assert "RAW-API-KEY" not in persisted_json
    assert "RAW-PASSWORD" not in persisted_json
    assert "Authorization: Bearer" not in persisted_json
    assert "X-Producer-Signature:" not in persisted_json
    assert persisted["runtime"]["payload"]["last_result"]["headers"]["X-Producer-Key-Id"] == "key-container-01"
    assert persisted["runtime"]["payload"]["last_result"]["headers"]["X-Producer-Signature"] == "[redacted]"
    assert persisted["runtime"]["payload"]["last_result"]["receipt_json"] == "[redacted]"
    assert persisted["runtime"]["payload"]["raw_payload"] == "[redacted]"
    assert persisted["runtime"]["payload"]["nested"][0]["token"] == "[redacted]"
    assert persisted["runtime"]["payload"]["content_sha256"] == "a" * 64


def test_operator_pause_preserves_mutation_when_audit_write_fails(tmp_path):
    config = make_config(tmp_path)
    audit_parent = tmp_path / "audit-as-file"
    audit_parent.write_text("not a directory", encoding="utf-8")

    report = pause_relay(
        pause_path=config.operator_pause_path,
        operator_id="operator-a",
        reason="local maintenance",
        audit_log_path=audit_parent / "operator.jsonl",
    )

    assert report["status"] == "PASS"
    assert report["operation"] == "pause"
    assert report["audit_write_status"] == "FAIL"
    assert report["audit_write_error_code"] == "operator_audit_write_failed"
    assert Path(config.operator_pause_path).exists()


def test_operator_pause_write_failure_returns_blocked_without_marker(tmp_path):
    pause_parent = tmp_path / "control-as-file"
    pause_parent.write_text("not a directory", encoding="utf-8")

    report = pause_relay(
        pause_path=pause_parent / "pause.json",
        operator_id="operator-a",
        reason="local maintenance",
    )

    assert report["status"] == "BLOCKED"
    assert report["operation"] == "pause"
    assert report["error_code"] == "operator_pause_write_failed"
    assert report["previous_paused"] is False
    assert not (pause_parent / "pause.json").exists()


def test_operator_pause_cli_write_failure_returns_blocked_status(tmp_path, capsys):
    pause_parent = tmp_path / "control-as-file"
    pause_parent.write_text("not a directory", encoding="utf-8")

    exit_code = main(
        [
            "pause",
            "--operator-pause-path",
            str(pause_parent / "pause.json"),
            "--operator-id",
            "operator-a",
            "--reason",
            "local maintenance",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "direct_sync_operator_status=BLOCKED" in output
    assert "direct_sync_operator_operation=pause" in output
    assert "direct_sync_operator_report_status=SKIPPED" in output
    assert not (pause_parent / "pause.json").exists()


def test_operator_resume_blocks_invalid_pause_marker_without_removing_it(tmp_path):
    config = make_config(tmp_path)
    pause_marker = Path(config.operator_pause_path)
    pause_marker.mkdir(parents=True)

    report = resume_relay(
        pause_path=pause_marker,
        operator_id="operator-a",
        reason="maintenance complete",
    )

    assert report["status"] == "BLOCKED"
    assert report["operation"] == "resume"
    assert report["error_code"] == "operator_pause_marker_json_invalid"
    assert report["previous_paused"] is True
    assert report["previous_marker_valid"] is False
    assert pause_marker.is_dir()


def test_operator_resume_blocks_wrong_schema_marker_without_force(tmp_path):
    config = make_config(tmp_path)
    pause_marker = Path(config.operator_pause_path)
    pause_marker.parent.mkdir(parents=True)
    pause_marker.write_text(json.dumps({"schema_version": "wrong"}), encoding="utf-8")

    report = resume_relay(
        pause_path=pause_marker,
        operator_id="operator-a",
        reason="maintenance complete",
    )

    assert report["status"] == "BLOCKED"
    assert report["operation"] == "resume"
    assert report["error_code"] == "operator_pause_marker_schema_invalid"
    assert report["previous_paused"] is True
    assert report["previous_marker_valid"] is False
    assert pause_marker.exists()


def test_operator_resume_force_removes_wrong_schema_marker(tmp_path):
    config = make_config(tmp_path)
    audit_log_path = tmp_path / "logs" / "operator.jsonl"
    pause_marker = Path(config.operator_pause_path)
    pause_marker.parent.mkdir(parents=True)
    pause_marker.write_text(json.dumps({"schema_version": "wrong"}), encoding="utf-8")

    report = resume_relay(
        pause_path=pause_marker,
        operator_id="operator-a",
        reason="maintenance complete",
        audit_log_path=audit_log_path,
        force_invalid_marker=True,
    )

    assert report["status"] == "PASS"
    assert report["operation"] == "resume"
    assert report["previous_paused"] is True
    assert report["previous_marker_valid"] is False
    assert report["forced_invalid_marker"] is True
    assert not pause_marker.exists()
    assert "forced_invalid_marker" in audit_log_path.read_text(encoding="utf-8")


def test_operator_resume_cli_blocks_wrong_schema_marker_without_force(tmp_path, capsys):
    config = make_config(tmp_path)
    pause_marker = Path(config.operator_pause_path)
    pause_marker.parent.mkdir(parents=True)
    pause_marker.write_text(json.dumps({"schema_version": "wrong"}), encoding="utf-8")

    exit_code = main(
        [
            "resume",
            "--operator-pause-path",
            str(pause_marker),
            "--operator-id",
            "operator-a",
            "--reason",
            "maintenance complete",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "direct_sync_operator_status=BLOCKED" in output
    assert pause_marker.exists()


def test_operator_retry_dead_only_allows_failed_permanent_rows(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    failed = run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                400,
                {
                    "committed": False,
                    "retryable": False,
                    "error": {"code": "metadata_invalid", "message": "bad metadata"},
                },
            )
        ),
    )
    assert failed["status"] == "failed_permanent"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_FAILED_PERMANENT] == 1

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="server contract fixed",
        audit_log_path=tmp_path / "logs" / "operator.jsonl",
    )

    assert retry_report["status"] == "PASS"
    assert retry_report["previous_status"] == RELAY_STATUS_FAILED_PERMANENT
    assert retry_report["new_status"] == RELAY_STATUS_PENDING
    with sqlite3.connect(config.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT status, lease_owner, lease_expires_at, next_attempt_at, last_error_code, receipt_json, upload_status_path
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (relay_id,),
        ).fetchone()
    assert row["status"] == RELAY_STATUS_PENDING
    assert row["lease_owner"] is None
    assert row["lease_expires_at"] is None
    assert row["next_attempt_at"] is None
    assert row["last_error_code"] is None
    assert row["receipt_json"] is None
    assert row["upload_status_path"] is None

    acked = run_relay_once(config, session=EchoAcceptedSession())
    assert acked["status"] == "acked"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_ACKED] == 1


def test_operator_restore_spool_downloads_missing_acked_file_from_server(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    assert run_relay_once(config, session=EchoAcceptedSession())["status"] == "acked"
    with sqlite3.connect(config.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT spooled_file_path, content_sha256, byte_length
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (relay_id,),
        ).fetchone()
    spooled_path = Path(row["spooled_file_path"])
    body = spooled_path.read_bytes()
    spooled_path.unlink()
    session = RestoreSession(
        RestoreResponse(
            200,
            body,
            headers={
                "X-Content-SHA256": row["content_sha256"],
                "X-Byte-Length": str(row["byte_length"]),
            },
        )
    )

    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path,
        relay_id=relay_id,
        spool_root=config.spool_dir,
        credentials=load_credentials_from_json(config.credential_path),
        operator_id="operator-a",
        reason="restore deleted local spool",
        audit_log_path=tmp_path / "logs" / "operator.jsonl",
        session=session,
    )

    assert report["status"] == "PASS"
    assert report["operation"] == "restore-spool"
    assert report["restored"] is True
    assert spooled_path.read_bytes() == body
    assert session.calls[0]["stream"] is True
    assert session.calls[0]["allow_redirects"] is False


def test_operator_restore_spool_blocks_guard_violations_without_server_call(tmp_path, monkeypatch):
    session = RestoreSession(RestoreResponse(200, b""))
    config, relay_id, credentials, _spooled_path = _acked_restore_case(tmp_path / "credential")
    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path,
        relay_id=relay_id,
        spool_root=config.spool_dir,
        credentials=replace(credentials, producer_id="wrong-producer"),
        operator_id="operator-a",
        reason="credential mismatch",
        session=session,
    )
    assert report["status"] == "BLOCKED"
    assert report["error_code"] == "relay_credential_binding_mismatch"
    assert session.calls == []

    config, relay_id, credentials, _spooled_path = _acked_restore_case(tmp_path / "outside")
    _set_relay_spool_path(config.db_path, relay_id, tmp_path / "outside-root" / "payload.bin")
    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path,
        relay_id=relay_id,
        spool_root=config.spool_dir,
        credentials=credentials,
        operator_id="operator-a",
        reason="outside root",
        session=session,
    )
    assert report["status"] == "BLOCKED"
    assert report["error_code"] == "spooled_file_outside_spool_root"

    config, relay_id, credentials, spooled_path = _acked_restore_case(tmp_path / "symlink")
    link_path = spooled_path.with_name(f"{spooled_path.name}.link")
    _set_relay_spool_path(config.db_path, relay_id, link_path)
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(path):
        if path == link_path:
            return True
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path,
        relay_id=relay_id,
        spool_root=config.spool_dir,
        credentials=credentials,
        operator_id="operator-a",
        reason="symlink",
        session=session,
    )
    assert report["status"] == "BLOCKED"
    assert report["error_code"] == "spooled_file_symlink"

    config, relay_id, credentials, spooled_path = _acked_restore_case(tmp_path / "mismatch")
    spooled_path.write_bytes(spooled_path.read_bytes() + b"changed\n")
    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path,
        relay_id=relay_id,
        spool_root=config.spool_dir,
        credentials=credentials,
        operator_id="operator-a",
        reason="existing mismatch",
        session=session,
    )
    assert report["status"] == "BLOCKED"
    assert report["error_code"] == "spooled_file_already_exists_mismatch"
    assert session.calls == []


def test_operator_retry_dead_preserves_mutation_when_audit_write_fails(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                400,
                {
                    "committed": False,
                    "retryable": False,
                    "error": {"code": "metadata_invalid", "message": "bad metadata"},
                },
            )
        ),
    )
    audit_parent = tmp_path / "audit-as-file"
    audit_parent.write_text("not a directory", encoding="utf-8")

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="server contract fixed",
        audit_log_path=audit_parent / "operator.jsonl",
    )

    assert retry_report["status"] == "PASS"
    assert retry_report["new_status"] == RELAY_STATUS_PENDING
    assert retry_report["audit_write_status"] == "FAIL"
    assert retry_report["audit_write_error_code"] == "operator_audit_write_failed"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_PENDING] == 1


def test_operator_retry_dead_blocks_spool_digest_read_error(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                400,
                {
                    "committed": False,
                    "retryable": False,
                    "error": {"code": "metadata_invalid", "message": "bad metadata"},
                },
            )
        ),
    )
    monkeypatch.setattr(
        direct_sync_operator,
        "_read_file_digest",
        lambda _path: (_ for _ in ()).throw(PermissionError("denied")),
    )

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="server contract fixed",
    )

    assert retry_report["status"] == "BLOCKED"
    assert retry_report["error_code"] == "spooled_file_unreadable"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_FAILED_PERMANENT] == 1


def test_operator_retry_dead_cli_blocks_spool_digest_read_error(tmp_path, monkeypatch, capsys):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                400,
                {
                    "committed": False,
                    "retryable": False,
                    "error": {"code": "metadata_invalid", "message": "bad metadata"},
                },
            )
        ),
    )
    monkeypatch.setattr(
        direct_sync_operator,
        "_read_file_digest",
        lambda _path: (_ for _ in ()).throw(PermissionError("denied")),
    )

    exit_code = main(
        [
            "retry-dead",
            "--db-path",
            str(config.db_path),
            "--relay-id",
            relay_id,
            "--operator-id",
            "operator-a",
            "--reason",
            "server contract fixed",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "direct_sync_operator_status=BLOCKED" in output
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_FAILED_PERMANENT] == 1


def test_operator_retry_dead_blocks_operator_review_rows(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    reviewed = run_relay_once(
        config,
        session=FakeSession(
            FakeResponse(
                200,
                {
                    "request_id": "request-review",
                    "client_batch_id": relay_id,
                    "committed": True,
                    "status": "accepted",
                    "retryable": False,
                    "next_retry_after": None,
                    "totals": {"inserted": 0, "replayed": 0, "quarantined": 1, "errors": 0},
                },
            )
        ),
    )

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="operator review needs server reconcile",
    )

    assert reviewed["status"] == "operator_review"
    assert retry_report["status"] == "BLOCKED"
    assert retry_report["previous_status"] == "operator_review"
    assert relay_queue_status(config.db_path)["counts"].get("operator_review") == 1


def test_operator_retry_dead_allows_non_committed_operator_review_with_flag(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                receipt_json = ?,
                last_error_code = ?,
                lease_owner = NULL,
                lease_expires_at = NULL
            WHERE relay_id = ?
            """,
            (
                RELAY_STATUS_OPERATOR_REVIEW,
                json.dumps({"client_batch_id": relay_id}),
                "upload_unhandled_exception",
                relay_id,
            ),
        )

    report_path = tmp_path / "retry-operator-review.json"
    exit_code = main(
        [
            "retry-dead",
            "--db-path",
            str(config.db_path),
            "--relay-id",
            relay_id,
            "--operator-id",
            "operator-a",
            "--reason",
            "transient upload exception repaired",
            "--allow-operator-review",
            "--report-path",
            str(report_path),
        ]
    )
    retry_report = json.loads(report_path.read_text(encoding="utf-8-sig"))

    assert exit_code == 0
    assert retry_report["status"] == "PASS"
    assert retry_report["previous_status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert retry_report["new_status"] == RELAY_STATUS_PENDING
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_PENDING] == 1


def test_operator_retry_dead_blocks_committed_operator_review_even_with_flag(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                receipt_json = ?,
                last_error_code = ?,
                lease_owner = NULL,
                lease_expires_at = NULL
            WHERE relay_id = ?
            """,
            (
                RELAY_STATUS_OPERATOR_REVIEW,
                json.dumps({"client_batch_id": relay_id, "committed": True}),
                "committed_receipt_incomplete",
                relay_id,
            ),
        )

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="operator review needs server reconcile",
        allow_operator_review=True,
    )

    assert retry_report["status"] == "BLOCKED"
    assert retry_report["previous_status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert retry_report["error_code"] == "operator_review_committed_receipt_not_retryable"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_OPERATOR_REVIEW] == 1


def test_operator_retry_dead_blocks_ambiguous_committed_operator_review_even_with_flag(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?,
                receipt_json = ?,
                last_error_code = ?,
                lease_owner = NULL,
                lease_expires_at = NULL
            WHERE relay_id = ?
            """,
            (
                RELAY_STATUS_OPERATOR_REVIEW,
                json.dumps({"client_batch_id": relay_id, "committed": "true"}),
                "committed_receipt_incomplete",
                relay_id,
            ),
        )

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="operator review needs server reconcile",
        allow_operator_review=True,
    )

    assert retry_report["status"] == "BLOCKED"
    assert retry_report["previous_status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert retry_report["error_code"] == "operator_review_committed_receipt_not_retryable"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_OPERATOR_REVIEW] == 1


def test_operator_retry_dead_blocks_locally_committed_operator_review_even_without_server_receipt(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]
    reviewed = run_relay_once(config, session=FakeSession(FakeResponse(200, None)))

    retry_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="operator review needs server reconcile",
        allow_operator_review=True,
    )

    assert reviewed["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert retry_report["status"] == "BLOCKED"
    assert retry_report["previous_status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert retry_report["error_code"] == "operator_review_committed_receipt_not_retryable"
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_OPERATOR_REVIEW] == 1


def test_operator_retry_dead_blocks_live_pending_retry_wait_and_missing_rows(tmp_path):
    config = make_config(tmp_path)
    source_file = write_csv(tmp_path)
    enqueued = enqueue_completed_source_file(config, source_file_path=source_file)
    relay_id = enqueued["last_result"]["relay_id"]

    pending_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="not allowed",
    )
    missing_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id="relay-missing",
        operator_id="operator-a",
        reason="not allowed",
    )
    with sqlite3.connect(config.db_path) as conn:
        conn.execute(
            """
            UPDATE direct_sync_relay_batches
            SET status = ?, next_attempt_at = ?
            WHERE relay_id = ?
            """,
            (RELAY_STATUS_RETRY_WAIT, "2999-01-01T00:00:00Z", relay_id),
        )
        conn.commit()
    retry_wait_report = retry_dead_relay_batch(
        db_path=config.db_path,
        relay_id=relay_id,
        operator_id="operator-a",
        reason="not allowed",
    )

    assert pending_report["status"] == "BLOCKED"
    assert pending_report["error_code"] == "relay_status_not_retryable_by_operator"
    assert missing_report["status"] == "BLOCKED"
    assert missing_report["error_code"] == "relay_not_found"
    assert retry_wait_report["status"] == "BLOCKED"
    assert retry_wait_report["previous_status"] == RELAY_STATUS_RETRY_WAIT
    assert operator_status(db_path=config.db_path, pause_path=config.operator_pause_path)["status"] == "PASS"


def test_operator_retry_dead_blocks_unavailable_relay_db(tmp_path):
    corrupt_db_path = tmp_path / "corrupt.sqlite3"
    corrupt_db_path.write_text("not a sqlite database", encoding="utf-8")
    empty_schema_path = tmp_path / "empty.sqlite3"
    sqlite3.connect(empty_schema_path).close()

    for db_path in (corrupt_db_path, empty_schema_path):
        report = retry_dead_relay_batch(
            db_path=db_path,
            relay_id="relay-dead-1",
            operator_id="operator-a",
            reason="operator retry requested",
            audit_log_path=tmp_path / "logs" / f"{db_path.stem}.jsonl",
        )

        assert report["status"] == "BLOCKED"
        assert report["operation"] == "retry-dead"
        assert report["error_code"] == "relay_db_unavailable"
        assert "not a sqlite database" not in json.dumps(report)


def test_operator_status_does_not_create_missing_queue_db(tmp_path):
    db_path = tmp_path / "missing" / "relay.sqlite3"

    report = operator_status(db_path=db_path, pause_path=tmp_path / "control" / "pause.json")

    assert report["status"] == "PASS"
    assert report["queue"]["status"] == "not_initialized"
    assert report["queue"]["counts"] == {}
    assert not db_path.exists()


def test_operator_cli_report_write_failure_keeps_stdout_status(tmp_path, capsys):
    db_path = tmp_path / "missing" / "relay.sqlite3"
    report_parent = tmp_path / "reports-as-file"
    report_parent.write_text("not a directory", encoding="utf-8")

    exit_code = main(
        [
            "status",
            "--db-path",
            str(db_path),
            "--operator-pause-path",
            str(tmp_path / "control" / "pause.json"),
            "--report-path",
            str(report_parent / "status.json"),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "direct_sync_operator_status=PASS" in output
    assert "direct_sync_operator_operation=status" in output
    assert "direct_sync_operator_report_status=FAIL" in output
    assert "direct_sync_operator_report_error_code=operator_report_write_failed" in output
    assert not db_path.exists()


def test_operator_status_blocks_on_unreadable_queue_db(tmp_path):
    db_path = tmp_path / "corrupt.sqlite3"
    db_path.write_text("not a sqlite database", encoding="utf-8")
    report_path = tmp_path / "reports" / "operator-status.json"

    report = operator_status(db_path=db_path, pause_path=tmp_path / "control" / "pause.json")
    exit_code = main(
        [
            "status",
            "--db-path",
            str(db_path),
            "--operator-pause-path",
            str(tmp_path / "control" / "pause.json"),
            "--report-path",
            str(report_path),
        ]
    )

    assert report["status"] == "BLOCKED"
    assert report["queue"]["status"] == "blocked"
    assert report["queue"]["error_code"] == "relay_db_schema_unavailable"
    assert report["queue"]["error_message"] == "relay queue database error: DatabaseError"
    assert "not a sqlite database" not in json.dumps(report)
    assert exit_code == 2
    persisted = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert persisted["status"] == "BLOCKED"
    assert "not a sqlite database" not in json.dumps(persisted)


def test_operator_status_sanitizes_missing_schema_queue_db_error(tmp_path):
    db_path = tmp_path / "empty.sqlite3"
    sqlite3.connect(db_path).close()

    report = operator_status(db_path=db_path, pause_path=tmp_path / "control" / "pause.json")

    assert report["status"] == "BLOCKED"
    assert report["queue"]["error_code"] == "relay_db_schema_unavailable"
    assert report["queue"]["error_message"] == "relay queue database error: OperationalError"
    assert "no such table" not in json.dumps(report)


def test_operator_status_blocks_on_invalid_pause_marker(tmp_path):
    config = make_config(tmp_path)
    Path(config.operator_pause_path).parent.mkdir(parents=True, exist_ok=True)
    Path(config.operator_pause_path).write_text("{not-json}", encoding="utf-8")
    report_path = tmp_path / "reports" / "operator-status.json"

    report = operator_status(db_path=config.db_path, pause_path=config.operator_pause_path)
    exit_code = main(
        [
            "status",
            "--db-path",
            str(config.db_path),
            "--operator-pause-path",
            str(config.operator_pause_path),
            "--report-path",
            str(report_path),
        ]
    )

    assert report["status"] == "BLOCKED"
    assert report["pause"]["paused"] is True
    assert report["pause"]["marker_valid"] is False
    assert exit_code == 2
    persisted = json.loads(report_path.read_text(encoding="utf-8-sig"))
    assert persisted["status"] == "BLOCKED"


def test_operator_status_blocks_on_wrong_schema_pause_marker(tmp_path):
    config = make_config(tmp_path)
    invalid_markers = [
        ({}, "operator_pause_marker_schema_invalid"),
        (
            {
                "schema_version": "wrong-schema",
                "status": "paused",
                "operator_id": "operator-a",
                "reason_redacted": "sha256:123456789abc",
                "reason_sha256": "a" * 64,
                "reason_length": 10,
                "created_at": "2026-06-23T00:00:00Z",
            },
            "operator_pause_marker_schema_invalid",
        ),
        (
            {
                "schema_version": "direct-sync-relay-operator-pause-v1",
                "status": "running",
                "operator_id": "operator-a",
                "reason_redacted": "sha256:123456789abc",
                "reason_sha256": "a" * 64,
                "reason_length": 10,
                "created_at": "2026-06-23T00:00:00Z",
            },
            "operator_pause_marker_status_invalid",
        ),
    ]

    for index, (payload, error_code) in enumerate(invalid_markers):
        pause_path = tmp_path / "control" / f"pause-{index}.json"
        pause_path.parent.mkdir(parents=True, exist_ok=True)
        pause_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

        report = operator_status(db_path=config.db_path, pause_path=pause_path)

        assert report["status"] == "BLOCKED"
        assert report["pause"]["paused"] is True
        assert report["pause"]["marker_valid"] is False
        assert report["pause"]["marker_error_code"] == error_code


def test_operator_status_blocks_on_mismatched_pause_reason_evidence(tmp_path):
    config = make_config(tmp_path)
    pause_path = tmp_path / "control" / "pause-mismatch.json"
    pause_path.parent.mkdir(parents=True, exist_ok=True)
    pause_path.write_text(
        json.dumps(
            {
                "schema_version": "direct-sync-relay-operator-pause-v1",
                "status": "paused",
                "operator_id": "operator-a",
                "reason_redacted": "sha256:123456789abc",
                "reason_sha256": "a" * 64,
                "reason_length": 10,
                "created_at": "2026-06-23T00:00:00Z",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report = operator_status(db_path=config.db_path, pause_path=pause_path)

    assert report["status"] == "BLOCKED"
    assert report["pause"]["paused"] is True
    assert report["pause"]["marker_valid"] is False
    assert report["pause"]["marker_error_code"] == "operator_pause_marker_reason_invalid"
