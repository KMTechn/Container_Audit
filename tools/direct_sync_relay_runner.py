#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run one Container_Audit direct-sync relay cycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from event_log_store import LOCK_STALE_SECONDS as EVENT_LOG_LOCK_STALE_SECONDS  # noqa: E402
from direct_sync_runtime import (  # noqa: E402
    DirectSyncRuntimeConfig,
    enqueue_completed_source_file,
    record_scan_drain_status,
    record_scan_result_status,
    record_scan_status,
    run_relay_once,
)


ALLOWED_SOURCE_PREFIX = "이적작업이벤트로그_"
ALLOWED_SOURCE_SUFFIX = ".csv"
DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS = 30
SOURCE_WRITER_LOCK_STALE_SECONDS = float(EVENT_LOG_LOCK_STALE_SECONDS)
DELTA_PROGRESS_STATUSES = {"pending", "leased", "retry_wait", "acked"}
SCAN_SUCCESS_STATUSES = {"enqueued", "already_queued", "already_acked"}
SCAN_BLOCKED_STATUSES = {
    "paused_by_operator",
    "blocked_operator_control",
    "blocked_queue_backpressure",
    "blocked_disk_pressure",
    "existing_terminal_blocked",
}


class ExistingTerminalDeltaBlocked(Exception):
    pass


def _validate_source_glob(pattern: str) -> str:
    text = str(pattern or "").strip()
    if not text:
        raise SystemExit("source glob must not be empty")
    if "**" in text or "/" in text or "\\" in text:
        raise SystemExit("source glob must be a direct-child file pattern")
    return text


def _is_allowed_source_file(path: Path) -> bool:
    return path.name.startswith(ALLOWED_SOURCE_PREFIX) and path.suffix.lower() == ALLOWED_SOURCE_SUFFIX


def _is_old_enough_source_file(path: Path, min_age_seconds: int, *, now: float | None = None) -> bool:
    min_age = max(0, int(min_age_seconds or 0))
    if min_age == 0:
        return True
    current_time = time.time() if now is None else float(now)
    try:
        return path.stat().st_mtime <= current_time - min_age
    except FileNotFoundError:
        return False


def _source_state_key(path: Path) -> str:
    return str(path.resolve())


def _source_delta_key(path: Path) -> str:
    return hashlib.sha256(_source_state_key(path).encode("utf-8")).hexdigest()[:16]


def _delta_relative_path(path: Path, start_byte: int, end_byte: int, content_sha256: str) -> str:
    source_key = _source_delta_key(path)
    return f"d/{source_key}/bytes-{start_byte}-{end_byte}-sha256-{content_sha256[:16]}.csv"


def _file_prefix_sha256(path: Path, byte_count: int) -> str:
    digest = hashlib.sha256()
    remaining = max(0, int(byte_count))
    with path.open("rb") as handle:
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _scan_state_connect(db_path: str | Path) -> sqlite3.Connection:
    target = Path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS direct_sync_source_scan_state (
            source_file_path TEXT PRIMARY KEY,
            sent_byte_count INTEGER NOT NULL,
            sent_prefix_sha256 TEXT NOT NULL DEFAULT '',
            updated_at_unix REAL NOT NULL
        )
        """
    )
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(direct_sync_source_scan_state)").fetchall()
    }
    if "sent_prefix_sha256" not in columns:
        conn.execute("ALTER TABLE direct_sync_source_scan_state ADD COLUMN sent_prefix_sha256 TEXT NOT NULL DEFAULT ''")
    conn.commit()
    return conn


def _parse_delta_range(relative_path: str, source_file: Path) -> tuple[int, int] | None:
    text = str(relative_path or "").replace("\\", "/")
    prefixes = [
        f"d/{_source_delta_key(source_file)}/bytes-",
        f"legacy_csv_deltas/{_source_delta_key(source_file)}/bytes-",
        f"legacy_csv_deltas/{source_file.name}/bytes-",
    ]
    for prefix in prefixes:
        if text.startswith(prefix):
            range_text = text[len(prefix):].split("-sha256-", 1)[0]
            break
    else:
        return None
    try:
        start_text, end_text = range_text.split("-", 1)
        start_byte = int(start_text)
        end_byte = int(end_text)
    except (TypeError, ValueError):
        return None
    if start_byte < 0 or end_byte <= start_byte:
        return None
    return start_byte, end_byte


def _delta_content_sha256_for_range(source_file: Path, start_byte: int, end_byte: int) -> str | None:
    if source_file.stat().st_size < end_byte:
        return None
    with source_file.open("rb") as handle:
        header = handle.readline()
        data_start = handle.tell()
        if start_byte and start_byte < data_start:
            return None
        handle.seek(start_byte)
        body = handle.read(end_byte - start_byte)
    if len(body) != end_byte - start_byte:
        return None
    delta_content = body if start_byte == 0 else header + body
    return hashlib.sha256(delta_content).hexdigest()


def _read_queued_delta_progress(conn: sqlite3.Connection, source_file: Path) -> tuple[int, str]:
    has_relay_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'direct_sync_relay_batches'"
    ).fetchone()
    if not has_relay_table:
        return 0, ""
    relay_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(direct_sync_relay_batches)").fetchall()
    }
    receipt_select = "receipt_json" if "receipt_json" in relay_columns else "'' AS receipt_json"
    source_delta_key = _source_delta_key(source_file)
    rows = conn.execute(
        f"""
        SELECT source_file_path, relative_path, content_sha256, status, {receipt_select}
        FROM direct_sync_relay_batches
        WHERE relative_path LIKE 'legacy_csv_deltas/%'
           OR relative_path LIKE 'd/%'
        """
    ).fetchall()
    matching_ranges: dict[int, int] = {}
    blocked_ranges: dict[int, int] = {}
    for row in rows:
        source_path = Path(str(row["source_file_path"] or ""))
        if source_path.parent.name != source_delta_key:
            continue
        parsed_range = _parse_delta_range(str(row["relative_path"] or ""), source_file)
        if parsed_range is None:
            continue
        start_byte, end_byte = parsed_range
        delta_hash = _delta_content_sha256_for_range(source_file, start_byte, end_byte)
        if delta_hash and delta_hash == str(row["content_sha256"] or ""):
            if _delta_relay_row_counts_as_progress(row):
                matching_ranges[start_byte] = max(matching_ranges.get(start_byte, 0), end_byte)
            elif _delta_relay_row_blocks_progress(row):
                blocked_ranges[start_byte] = max(blocked_ranges.get(start_byte, 0), end_byte)
    best_end_byte = 0
    while best_end_byte in matching_ranges:
        next_end_byte = matching_ranges[best_end_byte]
        if next_end_byte <= best_end_byte:
            break
        best_end_byte = next_end_byte
    if best_end_byte in blocked_ranges:
        raise ExistingTerminalDeltaBlocked(str(source_file))
    if best_end_byte <= 0:
        return 0, ""
    return best_end_byte, _file_prefix_sha256(source_file, best_end_byte)


def _delta_relay_row_counts_as_progress(row: sqlite3.Row) -> bool:
    status = str(row["status"] or "")
    if status in DELTA_PROGRESS_STATUSES:
        return True
    if status != "operator_review":
        return False
    try:
        receipt = json.loads(str(row["receipt_json"] or "{}"))
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(receipt, dict):
        return False
    return receipt.get("committed") is True or receipt.get("_local_upload_result_committed") is True


def _delta_relay_row_blocks_progress(row: sqlite3.Row) -> bool:
    status = str(row["status"] or "")
    if status == "failed_permanent":
        return True
    if status != "operator_review":
        return False
    try:
        receipt = json.loads(str(row["receipt_json"] or "{}"))
    except (TypeError, json.JSONDecodeError):
        return True
    if not isinstance(receipt, dict):
        return True
    committed = receipt.get("committed")
    local_committed = receipt.get("_local_upload_result_committed")
    return committed is not True and local_committed is not True


def _read_source_scan_state(db_path: str | Path, source_file: Path) -> tuple[int, str]:
    conn = _scan_state_connect(db_path)
    try:
        row = conn.execute(
            "SELECT sent_byte_count, sent_prefix_sha256 FROM direct_sync_source_scan_state WHERE source_file_path = ?",
            (_source_state_key(source_file),),
        ).fetchone()
        explicit_state = (int(row["sent_byte_count"]), str(row["sent_prefix_sha256"] or "")) if row else (0, "")
        queued_state = _read_queued_delta_progress(conn, source_file)
        return queued_state if queued_state[0] > explicit_state[0] else explicit_state
    finally:
        conn.close()


def _record_source_sent_byte_count(
    db_path: str | Path,
    source_file: Path,
    sent_byte_count: int,
    sent_prefix_sha256: str,
) -> None:
    conn = _scan_state_connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO direct_sync_source_scan_state (source_file_path, sent_byte_count, sent_prefix_sha256, updated_at_unix)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_file_path) DO UPDATE SET
                sent_byte_count = excluded.sent_byte_count,
                sent_prefix_sha256 = excluded.sent_prefix_sha256,
                updated_at_unix = excluded.updated_at_unix
            """,
            (_source_state_key(source_file), int(sent_byte_count), sent_prefix_sha256, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def _complete_line_prefix(data: bytes) -> bytes:
    if not data:
        return b""
    if data.endswith(b"\n"):
        return data
    last_newline = data.rfind(b"\n")
    if last_newline < 0:
        return b""
    return data[: last_newline + 1]


def _source_writer_lock_path(source_file: Path) -> Path:
    return Path(f"{source_file.resolve()}.lock")


def _has_active_source_writer_lock(source_file: Path) -> bool:
    lock_path = _source_writer_lock_path(source_file)
    try:
        lock_stat = lock_path.stat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return time.time() - lock_stat.st_mtime <= SOURCE_WRITER_LOCK_STALE_SECONDS


def _build_delta_source_file(config: DirectSyncRuntimeConfig, source_file: Path) -> tuple[Path, str, int, str] | None:
    if _has_active_source_writer_lock(source_file):
        return None
    try:
        source_stat = source_file.stat()
    except OSError:
        return None
    source_size = source_stat.st_size
    source_mtime_ns = source_stat.st_mtime_ns
    sent_byte_count, sent_prefix_sha256 = _read_source_scan_state(config.db_path, source_file)
    if sent_byte_count > 0:
        replaced_or_truncated = not sent_prefix_sha256 or source_size < sent_byte_count
        if not replaced_or_truncated:
            replaced_or_truncated = _file_prefix_sha256(source_file, sent_byte_count) != sent_prefix_sha256
        if replaced_or_truncated:
            sent_byte_count = 0
    if source_size <= sent_byte_count:
        return None

    with source_file.open("rb") as handle:
        header = handle.readline()
        if not header:
            return None
        data_start = handle.tell()
        start_byte = sent_byte_count if sent_byte_count >= data_start else 0
        handle.seek(start_byte)
        delta_body = handle.read()

    try:
        after_stat = source_file.stat()
    except OSError:
        return None
    if after_stat.st_size != source_size or after_stat.st_mtime_ns != source_mtime_ns:
        return None

    complete_delta_body = _complete_line_prefix(delta_body)
    if not complete_delta_body.strip():
        return None
    end_byte = start_byte + len(complete_delta_body)
    if start_byte == 0 and end_byte <= data_start:
        return None

    delta_content = complete_delta_body if start_byte == 0 else header + complete_delta_body
    delta_hash = hashlib.sha256(delta_content).hexdigest()
    try:
        with source_file.open("rb") as handle:
            sent_prefix = handle.read(end_byte)
        after_prefix_stat = source_file.stat()
    except OSError:
        return None
    if after_prefix_stat.st_size != source_size or after_prefix_stat.st_mtime_ns != source_mtime_ns:
        return None
    if len(sent_prefix) != end_byte:
        return None
    sent_prefix_sha256 = hashlib.sha256(sent_prefix).hexdigest()
    delta_source = (
        Path(config.spool_dir)
        / "_scan_delta_inputs"
        / _source_delta_key(source_file)
        / f"bytes-{start_byte}-{end_byte}-sha256-{delta_hash[:16]}.csv"
    )
    delta_source.parent.mkdir(parents=True, exist_ok=True)
    delta_source.write_bytes(delta_content)
    return delta_source, _delta_relative_path(source_file, start_byte, end_byte, delta_hash), end_byte, sent_prefix_sha256


def _scan_source_files(
    scan_source_dir: str,
    patterns: list[str],
    max_files: int,
    min_age_seconds: int = DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS,
    *,
    limit_results: bool = True,
) -> list[Path]:
    root = Path(scan_source_dir)
    if not root.is_dir():
        raise SystemExit(f"scan source dir does not exist: {root}")
    root_resolved = root.resolve()
    scan_patterns = [_validate_source_glob(pattern) for pattern in (patterns or ["*.csv"])]
    seen: set[str] = set()
    files: list[tuple[int, str, Path]] = []
    current_time = time.time()
    for pattern in scan_patterns:
        for path in root.glob(pattern):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat_result = path.stat()
                resolved_path = path.resolve()
            except OSError:
                continue
            if not resolved_path.is_relative_to(root_resolved):
                continue
            if not _is_allowed_source_file(path):
                continue
            min_age = max(0, int(min_age_seconds or 0))
            if min_age and stat_result.st_mtime > current_time - min_age:
                continue
            resolved = str(resolved_path)
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append((stat_result.st_mtime_ns, str(path), path))
    files.sort(key=lambda item: (item[0], item[1]))
    if max(0, max_files) == 0:
        return []
    selected_files = files[: max(0, max_files)] if limit_results else files
    return [path for _, _, path in selected_files]


def _source_file_still_eligible_for_enqueue(
    path: Path,
    scan_source_dir: str,
    min_age_seconds: int,
    *,
    now: float | None = None,
) -> bool:
    try:
        root_resolved = Path(scan_source_dir).resolve()
        if path.is_symlink() or not path.is_file():
            return False
        stat_result = path.stat()
        resolved_path = path.resolve()
    except OSError:
        return False
    if not resolved_path.is_relative_to(root_resolved):
        return False
    if not _is_allowed_source_file(path):
        return False
    min_age = max(0, int(min_age_seconds or 0))
    if min_age:
        current_time = time.time() if now is None else float(now)
        if stat_result.st_mtime > current_time - min_age:
            return False
    return True


def _build_config(args: argparse.Namespace) -> DirectSyncRuntimeConfig:
    return DirectSyncRuntimeConfig(
        db_path=args.db_path,
        spool_dir=args.spool_dir,
        producer_manifest_path=args.producer_manifest_path,
        credential_path=args.credential_path,
        upload_status_dir=args.upload_status_dir,
        runtime_status_path=args.runtime_status_path,
        log_path=args.log_path,
        worker_id=args.worker_id,
        min_free_bytes=args.min_free_bytes,
        retry_base_seconds=args.retry_base_seconds,
        timeout_seconds=args.timeout_seconds,
        operator_pause_path=args.operator_pause_path,
        max_active_queue_count=args.max_active_queue_count,
        max_active_queue_age_seconds=args.max_active_queue_age_seconds,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Container_Audit direct-sync relay runner")
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--spool-dir", required=True)
    parser.add_argument("--producer-manifest-path", required=True)
    parser.add_argument("--credential-path", required=True)
    parser.add_argument("--upload-status-dir", required=True)
    parser.add_argument("--runtime-status-path", required=True)
    parser.add_argument("--log-path", required=True)
    parser.add_argument("--worker-id", default="direct-sync-relay-container-audit")
    parser.add_argument("--min-free-bytes", type=int, default=0)
    parser.add_argument("--retry-base-seconds", type=int, default=60)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--operator-pause-path", default="")
    parser.add_argument("--max-active-queue-count", type=int, default=1000)
    parser.add_argument("--max-active-queue-age-seconds", type=int, default=24 * 60 * 60)
    parser.add_argument("--enqueue-source-file", default="")
    parser.add_argument("--relative-path", default="")
    parser.add_argument("--scan-source-dir", default="")
    parser.add_argument("--source-glob", action="append", default=[])
    parser.add_argument("--max-enqueue-files", type=int, default=100)
    parser.add_argument("--min-source-file-age-seconds", type=int, default=DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS)
    parser.add_argument("--drain-after-scan", action="store_true")
    args = parser.parse_args(argv)
    if args.enqueue_source_file and args.scan_source_dir:
        parser.error("--enqueue-source-file and --scan-source-dir are mutually exclusive")

    config = _build_config(args)
    if args.enqueue_source_file:
        status = enqueue_completed_source_file(
            config,
            source_file_path=args.enqueue_source_file,
            relative_path=args.relative_path,
        )
    elif args.scan_source_dir:
        statuses = []
        enqueued_count = 0
        attempted_count = 0
        no_new_count = 0
        preflight_status = None
        pending_delta_progress: dict[str, tuple[Path, int, str]] = {}
        max_enqueue_files = max(0, int(args.max_enqueue_files or 0))
        for source_file in _scan_source_files(
            args.scan_source_dir,
            args.source_glob,
            args.max_enqueue_files,
            args.min_source_file_age_seconds,
            limit_results=False,
        ):
            if enqueued_count >= max_enqueue_files:
                break
            if not _source_file_still_eligible_for_enqueue(
                source_file,
                args.scan_source_dir,
                args.min_source_file_age_seconds,
            ):
                continue
            try:
                delta = _build_delta_source_file(config, source_file)
            except ExistingTerminalDeltaBlocked:
                attempted_count += 1
                preflight_status = {
                    "status": "existing_terminal_blocked",
                    "scan_failed_source_file": str(source_file),
                    "last_result": {
                        "status": "existing_terminal_blocked",
                        "error_code": "existing_terminal_delta_blocked",
                    },
                }
                break
            if delta is None:
                no_new_count += 1
                continue
            delta_source_file, relative_path, sent_byte_count, sent_prefix_sha256 = delta
            current = enqueue_completed_source_file(
                config,
                source_file_path=delta_source_file,
                relative_path=relative_path,
            )
            attempted_count += 1
            if current["status"] in SCAN_BLOCKED_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                preflight_status = current
                break
            statuses.append(current)
            if current["status"] == "enqueued":
                enqueued_count += 1
                last_result = current.get("last_result") if isinstance(current.get("last_result"), dict) else {}
                relay_id = str(last_result.get("relay_id") or "")
                if relay_id:
                    pending_delta_progress[relay_id] = (source_file, sent_byte_count, sent_prefix_sha256)
            elif current["status"] not in SCAN_SUCCESS_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                break
        scan_status = preflight_status or (
            statuses[-1]
            if statuses
            else {"status": "scan_no_new_rows" if no_new_count else "scan_no_files"}
        )
        scan_status["scan_enqueued_count"] = enqueued_count
        scan_status["scan_attempted_count"] = attempted_count
        scan_status["scan_no_new_count"] = no_new_count
        if scan_status["status"] == "scan_no_files":
            scan_status = record_scan_status(
                config,
                status="scan_no_files",
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
            )
            scan_status["scan_enqueued_count"] = enqueued_count
            scan_status["scan_attempted_count"] = attempted_count
        elif scan_status["status"] == "scan_no_new_rows":
            scan_status = record_scan_status(
                config,
                status="scan_no_new_rows",
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
            )
            scan_status["scan_enqueued_count"] = enqueued_count
            scan_status["scan_attempted_count"] = attempted_count
            scan_status["scan_no_new_count"] = no_new_count
        should_drain = args.drain_after_scan and scan_status["status"] not in {
            *SCAN_BLOCKED_STATUSES,
            "enqueue_error",
        }
        if should_drain:
            status = run_relay_once(config)
            status = record_scan_drain_status(
                config,
                drain_status=status,
                scan_status=scan_status["status"],
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
                scan_failed_source_file=scan_status.get("scan_failed_source_file", ""),
            )
            last_result = status.get("last_result") if isinstance(status.get("last_result"), dict) else {}
            acked_relay_id = str(last_result.get("relay_id") or "")
            if status.get("status") == "acked" and acked_relay_id in pending_delta_progress:
                source_file, sent_byte_count, sent_prefix_sha256 = pending_delta_progress[acked_relay_id]
                _record_source_sent_byte_count(
                    config.db_path,
                    source_file,
                    sent_byte_count,
                    sent_prefix_sha256,
                )
        else:
            if scan_status["status"] == "scan_no_files":
                status = scan_status
            else:
                status = record_scan_result_status(
                    config,
                    scan_result=scan_status,
                    scan_enqueued_count=enqueued_count,
                    scan_attempted_count=attempted_count,
                    scan_failed_source_file=scan_status.get("scan_failed_source_file", ""),
                )
    else:
        status = run_relay_once(config)
    print(f"direct_sync_relay_status={status['status']}")
    if "scan_status" in status:
        print(f"direct_sync_scan_status={status['scan_status']}")
    if "scan_enqueued_count" in status:
        print(f"direct_sync_scan_enqueued_count={status['scan_enqueued_count']}")
    if "scan_attempted_count" in status:
        print(f"direct_sync_scan_attempted_count={status['scan_attempted_count']}")
    if "scan_no_new_count" in status:
        print(f"direct_sync_scan_no_new_count={status['scan_no_new_count']}")
    if status.get("scan_failed_source_file"):
        print(f"direct_sync_scan_failed_source_file={status['scan_failed_source_file']}")
    if status["status"] in {
        "blocked_disk_pressure",
        "blocked_operator_control",
        "blocked_queue_backpressure",
        "existing_terminal_blocked",
        "failed_permanent",
        "operator_review",
    }:
        return 2
    if status["status"] in {"enqueue_error", "runtime_error"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
