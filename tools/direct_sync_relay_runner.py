#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run one Container_Audit direct-sync relay cycle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import stat
import uuid
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from event_log_store import LOCK_STALE_SECONDS as EVENT_LOG_LOCK_STALE_SECONDS  # noqa: E402
from direct_sync_push import (  # noqa: E402
    reset_stale_relay_leases, SourceFileInputError, SOURCE_FILE_ERROR_CODES, source_file_error_boundary,
    _copy_spool_file_atomic, utc_now_text,
    _held_spool_rows, _held_runtime_backlog_rows, _held_spool_request_matches, _set_held_spool_review,
    RUNTIME_METADATA_FIELDS,
)
from direct_sync_runtime import (  # noqa: E402
    DirectSyncRuntimeConfig,
    prepare_credential_config,
    enqueue_completed_source_file,
    record_scan_drain_status,
    record_scan_result_status,
    record_scan_status,
    record_source_scan_failure,
    clear_source_scan_failure,
    run_relay_once,
)
from writer_session_fence import writer_sink  # noqa: E402
from data_generation_guard import DataGenerationBlocked, probe_before_owner_paths, record_before_owner_paths  # noqa: E402
from storage_policy import ensure_user_runtime_directory


ALLOWED_SOURCE_PREFIX = "이적작업이벤트로그_"
ALLOWED_SOURCE_SUFFIX = ".csv"
DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS = 30
SOURCE_WRITER_LOCK_STALE_SECONDS = float(EVENT_LOG_LOCK_STALE_SECONDS)
DELTA_PROGRESS_STATUSES = {"pending", "leased", "retry_wait", "acked"}
DURABLE_DELTA_PROGRESS_STATUSES = {"acked"}
SCAN_SUCCESS_STATUSES = {"enqueued", "already_queued", "already_acked"}
SCAN_BLOCKED_STATUSES = {
    "paused_by_operator",
    "blocked_operator_control",
    "blocked_queue_backpressure",
    "blocked_disk_pressure",
    "existing_terminal_blocked",
}


class _SourceSnapshotChanged(Exception):
    """Retry a moving snapshot on the next scan without declaring a mismatch."""


class ExistingTerminalDeltaBlocked(Exception):
    def __init__(self, source_file: str, *, start_byte=None, end_byte=None, content_sha256=""):
        super().__init__(source_file)
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.content_sha256 = content_sha256


def _count_blocked_source_records(source_file: Path, blocked: ExistingTerminalDeltaBlocked) -> int | None:
    """Read one stable scan snapshot; unknown is never converted to zero."""
    start, end = blocked.start_byte, blocked.end_byte
    if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end:
        return None
    def identity(stat):
        return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns
    try:
        before = source_file.stat()
        with source_file.open("rb") as handle:
            if identity(os.fstat(handle.fileno())) != identity(before) or end > before.st_size:
                return None
            # Four canonical CSV fields, UTF-8 (<=4 bytes/character), CSV quote
            # escaping (<=2 bytes/character). Any longer physical line cannot
            # pass the same csv.reader field-size limit; bound memory first.
            line_limit = csv.field_size_limit() * 4 * 8 + 32
            header = handle.readline(line_limit + 1)
            if len(header) > line_limit or not header.endswith(b"\n"):
                return None
            digest = hashlib.sha256()
            if start:
                digest.update(header)
            handle.seek(start)
            remaining = end - start
            while remaining:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    return None
                digest.update(block)
                remaining -= len(block)
            if digest.hexdigest() != blocked.content_sha256:
                return None
            handle.seek(-1, os.SEEK_END)
            if handle.read(1) not in (b"\n", b"\r"):
                return None
            handle.seek(0)
            def lines():
                first = True
                while True:
                    raw = handle.readline(line_limit + 1)
                    if not raw:
                        return
                    if len(raw) > line_limit:
                        raise ValueError("CSV line exceeds parser field capacity")
                    yield raw.decode("utf-8-sig" if first else "utf-8")
                    first = False
            reader = csv.reader(lines(), strict=True)
            columns = next(reader)
            if columns != ["timestamp", "worker_name", "event", "details"]:
                return None
            boundaries = {0, handle.tell()}
            count = 0
            while True:
                row_start = handle.tell()
                try:
                    row = next(reader)
                except StopIteration:
                    break
                row_end = handle.tell()
                if row_end in (start, end):
                    boundaries.add(row_end)
                if row and len(row) != len(columns):
                    return None
                if row and row_start >= start:
                    count += 1
            if start not in boundaries or end not in boundaries:
                return None
            if identity(os.fstat(handle.fileno())) != identity(before):
                return None
        if identity(source_file.stat()) != identity(before):
            return None
        return count
    except (OSError, UnicodeError, csv.Error, ValueError, StopIteration):
        return None


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


@writer_sink("raw_relay_storage")
def _scan_state_connect(db_path: str | Path) -> sqlite3.Connection:
    target = Path(db_path)
    ensure_user_runtime_directory(target.parent)
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
    if "verified_source_signature" not in columns:
        conn.execute("ALTER TABLE direct_sync_source_scan_state ADD COLUMN verified_source_signature TEXT NOT NULL DEFAULT ''")
    if "prefix_verified_at_unix" not in columns:
        conn.execute("ALTER TABLE direct_sync_source_scan_state ADD COLUMN prefix_verified_at_unix REAL NOT NULL DEFAULT 0")
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
    with source_file_error_boundary():
        if source_file.stat().st_size < end_byte:
            return None
    with source_file_error_boundary(), source_file.open("rb") as handle:
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



def _original_fingerprint_matches(row):
    try:
        metadata = json.loads(row['metadata_json'])
        return (metadata['relative_path'] == row['relative_path']
                and type(metadata['byte_length']) is int
                and metadata['byte_length'] == row['byte_length']
                and metadata['content_sha256'] == row['content_sha256'])
    except (KeyError, TypeError, ValueError):
        return False


def _source_range_for_row(row, source_file, *, source_key=None):
    source_path = Path(str(row['source_file_path'] or ''))
    relative = str(row['relative_path'] or '').replace('\\', '/')
    if source_path == source_file and not relative.startswith(('d/', 'legacy_csv_deltas/')):
        return 0, int(row['byte_length'])
    if source_path.parent.name == (source_key or _source_delta_key(source_file)):
        return _parse_delta_range(row['relative_path'], source_file)
    return None


def _raw_request_overlaps_waiting_delta(conn, row, source_file):
    source_key = _source_delta_key(source_file)
    def scope(candidate):
        try:
            return (candidate['endpoint_url'], candidate['producer_id'], candidate['key_id'],
                    json.loads(candidate['metadata_json'])['producer_install_id'])
        except (KeyError, TypeError, ValueError):
            return None
    original_scope = scope(row)
    for other in conn.execute("SELECT * FROM direct_sync_relay_batches WHERE status IN ('pending','leased','retry_wait') AND relay_id!=?",
                              (row['relay_id'],)):
        if scope(other) != original_scope:
            continue
        bounds = _source_range_for_row(other, source_file, source_key=source_key)
        if bounds is not None and bounds[0] < int(row['byte_length']) and bounds[1] > 0:
            return True
    return False


def _read_delta_progress(
    conn: sqlite3.Connection,
    source_file: Path,
    *,
    include_inflight: bool,
    include_blocked: bool,
) -> tuple[int, str]:
    has_relay_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'direct_sync_relay_batches'"
    ).fetchone()
    if not has_relay_table:
        return 0, ""
    source_delta_key = _source_delta_key(source_file)
    rows = conn.execute(
        """
        SELECT *
        FROM direct_sync_relay_batches
        WHERE relative_path LIKE 'legacy_csv_deltas/%'
           OR relative_path LIKE 'd/%'
           OR source_file_path = ? COLLATE NOCASE
        """,
        (_source_state_key(source_file),),
    ).fetchall()
    held_ids = {item['relay_id'] for item in _held_spool_rows(conn)}
    matching_ranges: dict[int, int] = {}
    blocked_ranges: dict[int, tuple[int, str]] = {}
    for row in rows:
        source_path = Path(str(row["source_file_path"] or ""))
        relative = str(row['relative_path'] or '').replace('\\', '/')
        direct = source_path == source_file and not relative.startswith(('d/', 'legacy_csv_deltas/'))
        if direct:
            try:
                metadata = json.loads(row['metadata_json'])
            except (TypeError, ValueError):
                continue
            recovered = (row['last_error_code'] in {'spooled_file_missing', 'spooled_file_unreadable', 'source_file_unreadable'}
                         and all(name in metadata for name in RUNTIME_METADATA_FIELDS))
            if (not _original_fingerprint_matches(row)
                    or not (row['status'] == 'acked' or recovered or row['relay_id'] in held_ids)):
                continue
        parsed_range = _source_range_for_row(row, source_file, source_key=source_delta_key)
        if parsed_range is None:
            continue
        start_byte, end_byte = parsed_range
        delta_hash = _delta_content_sha256_for_range(source_file, start_byte, end_byte)
        if delta_hash and delta_hash == str(row["content_sha256"] or ""):
            if (
                _delta_relay_row_counts_as_progress(row, include_inflight=include_inflight)
                and _delta_relay_row_has_usable_spool(row)
            ):
                matching_ranges[start_byte] = max(matching_ranges.get(start_byte, 0), end_byte)
            elif include_blocked and _delta_relay_row_blocks_progress(row):
                if end_byte > blocked_ranges.get(start_byte, (0, ""))[0]:
                    blocked_ranges[start_byte] = (end_byte, str(row["content_sha256"]))
    best_end_byte = 0
    for start_byte, end_byte in sorted(matching_ranges.items()):
        if start_byte > best_end_byte:
            break
        best_end_byte = max(best_end_byte, end_byte)
    if include_blocked and best_end_byte in blocked_ranges:
        blocked_end_byte, blocked_hash = blocked_ranges[best_end_byte]
        if blocked_end_byte <= best_end_byte:
            raise ExistingTerminalDeltaBlocked(str(source_file))
        raise ExistingTerminalDeltaBlocked(str(source_file), start_byte=best_end_byte,
                                           end_byte=blocked_end_byte, content_sha256=blocked_hash)
    if best_end_byte <= 0:
        return 0, ""
    return best_end_byte, _file_prefix_sha256(source_file, best_end_byte)


def _read_queued_delta_progress(conn: sqlite3.Connection, source_file: Path) -> tuple[int, str]:
    return _read_delta_progress(conn, source_file, include_inflight=True, include_blocked=True)


def _read_durable_delta_progress(conn: sqlite3.Connection, source_file: Path) -> tuple[int, str]:
    return _read_delta_progress(conn, source_file, include_inflight=False, include_blocked=False)


def _delta_relay_row_counts_as_progress(row: sqlite3.Row, *, include_inflight: bool) -> bool:
    status = str(row["status"] or "")
    if status in DURABLE_DELTA_PROGRESS_STATUSES:
        return True
    if include_inflight and status in DELTA_PROGRESS_STATUSES:
        return True
    return False


def _delta_relay_row_has_usable_spool(row: sqlite3.Row) -> bool:
    status = str(row["status"] or "")
    if status not in {"pending", "leased", "retry_wait"}:
        return True
    try:
        expected_byte_length = int(row["byte_length"])
        spool_path = Path(str(row["spooled_file_path"] or ""))
        if spool_path.stat().st_size != expected_byte_length:
            return False
        return _file_prefix_sha256(spool_path, expected_byte_length) == str(
            row["content_sha256"] or ""
        )
    except (OSError, TypeError, ValueError):
        return False


def _delta_path_is_missing(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        pass
    return False


def _delta_copy_state(path: Path, payload: bytes) -> str:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != len(payload):
            return "conflict"
        return ("matching" if _file_prefix_sha256(path, len(payload)) == hashlib.sha256(payload).hexdigest()
                else "conflict")
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "conflict"


def _missing_terminal_can_reenter(row: sqlite3.Row) -> bool:
    if row["status"] != "failed_permanent" or row["last_error_code"] != "spooled_file_missing":
        return False
    try:
        receipt = json.loads(row["receipt_json"])
    except (TypeError, ValueError):
        return False
    return isinstance(receipt, dict) and all(
        field not in receipt or receipt[field] is False
        for field in ("committed", "_local_upload_result_committed")
    )


def _original_delta_content(source_file: Path, start_byte: int, end_byte: int) -> bytes | None:
    before = _source_scan_signature(source_file)
    if _has_active_source_writer_lock(source_file):
        raise _SourceSnapshotChanged()
    if source_file.stat().st_size < end_byte:
        return None
    with source_file.open("rb") as handle:
        header = handle.readline()
        if start_byte and start_byte < handle.tell():
            return None
        handle.seek(start_byte)
        body = handle.read(end_byte - start_byte)
    if len(body) != end_byte - start_byte:
        return None
    if _source_scan_signature(source_file) != before:
        raise _SourceSnapshotChanged()
    return body if start_byte == 0 else header + body


@writer_sink("raw_relay_storage")
def _publish_missing_delta_copy(path: Path, payload: bytes, *, copy_from: Path | None = None) -> bool:
    ensure_user_runtime_directory(path.parent)
    staging = path.with_name(path.name + ".repair-" + uuid.uuid4().hex + ".tmp")
    try:
        if copy_from is None:
            with staging.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            _copy_spool_file_atomic(copy_from, staging)
        if _delta_copy_state(staging, payload) != "matching":
            return False
        try:
            # A concurrent restoration must never be replaced with our copy.
            os.link(staging, path)
        except FileExistsError:
            pass
        return _delta_copy_state(path, payload) == "matching"
    finally:
        # Only this invocation's staging name; no orphan-directory cleanup.
        staging.unlink(missing_ok=True)


@writer_sink("raw_relay_storage")
def _reconstruct_delta_copies(config: DirectSyncRuntimeConfig, source_file: Path, relay_id: str, *, administrator=False) -> bool:
    conn = _scan_state_connect(config.db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM direct_sync_relay_batches WHERE relay_id = ?", (relay_id,)).fetchone()
        if row is None:
            return False
        held = next((item for item in _held_spool_rows(conn) if item['relay_id'] == relay_id), None)
        authority = None
        if held is not None:
            authority = conn.execute('SELECT * FROM direct_sync_runtime_authority WHERE assigned_relay_id=?',
                                     (relay_id,)).fetchone()
            if not _held_spool_request_matches(row, authority):
                _set_held_spool_review(conn, row)
                conn.commit()
                return False
            if authority['status'] != 'ACTIVE' and not (
                administrator and authority['status'] == 'OPERATOR_REVIEW'
                and authority['last_error_code'] == row['last_error_code']
            ):
                return False
        terminal = row["status"] == "failed_permanent"
        if not (held is not None or _missing_terminal_can_reenter(row) if terminal else row["status"] in {"pending", "retry_wait"}):
            return False
        if held is not None and not _original_fingerprint_matches(row):
            _set_held_spool_review(conn, row)
            conn.commit()
            return False
        parsed = _source_range_for_row(row, source_file)
        if parsed is None:
            return False
        start_byte, end_byte = parsed
        delta = Path(str(row["source_file_path"]))
        spool = Path(str(row["spooled_file_path"]))
        expected_delta = (Path(config.spool_dir) / "_scan_delta_inputs" / _source_delta_key(source_file)
                          / f"bytes-{start_byte}-{end_byte}-sha256-{str(row['content_sha256'])[:16]}.csv")
        direct = delta.resolve() == source_file.resolve()
        if (direct and held is None) or (not direct and delta != expected_delta) or spool != Path(config.spool_dir) / (relay_id + ".csv"):
            if held is not None:
                _set_held_spool_review(conn, row)
                conn.commit()
            return False
        if direct and _raw_request_overlaps_waiting_delta(conn, row, source_file):
            _set_held_spool_review(conn, row)
            conn.commit()
            return False
        payload = _original_delta_content(source_file, start_byte, end_byte)
        if (payload is None or len(payload) != int(row["byte_length"])
                or hashlib.sha256(payload).hexdigest() != row["content_sha256"]):
            if held is not None:
                _set_held_spool_review(conn, row)
                conn.commit()
            return False
        copies = (spool,) if direct else (delta, spool)
        states = [_delta_copy_state(path, payload) for path in copies]
        if "conflict" in states:
            if held is not None:
                _set_held_spool_review(conn, row)
                conn.commit()
            return False
        for path, state in zip(copies, states):
            if state == "missing" and not _publish_missing_delta_copy(
                path, payload, copy_from=delta if path == spool and not direct else None
            ):
                return False
        if (any(_delta_copy_state(path, payload) != "matching" for path in copies)
                or _has_active_source_writer_lock(source_file)
                or _delta_content_sha256_for_range(source_file, start_byte, end_byte) != row["content_sha256"]):
            return False
        if held is not None:
            if authority['status'] == 'OPERATOR_REVIEW':
                changed = conn.execute(
                    "UPDATE direct_sync_runtime_authority SET status='ACTIVE',last_error_code=NULL,updated_at=? "
                    "WHERE assigned_relay_id=? AND status='OPERATOR_REVIEW' AND last_error_code=?",
                    (utc_now_text(), relay_id, row['last_error_code']))
                if changed.rowcount != 1:
                    return False
            conn.execute("UPDATE direct_sync_relay_batches SET status='pending',updated_at=? WHERE relay_id=?",
                         (utc_now_text(), relay_id))
        elif terminal:
            changed = conn.execute(
                """UPDATE direct_sync_relay_batches SET status = 'retry_wait', updated_at = ?
                   WHERE relay_id = ? AND status = 'failed_permanent' AND last_error_code = 'spooled_file_missing'""",
                (utc_now_text(), relay_id),
            )
            if changed.rowcount != 1:
                return False
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()



def _held_runtime_backlog(config, source_files, terminal_sources=()):
    held, waiting = _held_runtime_backlog_rows(config.db_path)
    if not held:
        return None
    originals = {_source_delta_key(Path(path)): Path(path) for path in source_files}
    groups = {}
    for row in waiting:
        path = Path(row['source_file_path'])
        delta = '_scan_delta_inputs' in path.parts
        key = path.parent.name if delta else _source_delta_key(path)
        original = originals.get(key) if delta else path
        bounds = _parse_delta_range(row['relative_path'], original) if original is not None else None
        if bounds is None and not delta:
            bounds = (0, row['byte_length'])
        group = groups.setdefault(key, {'source': original, 'ranges': [], 'fallback': str(path)})
        group['ranges'].append((*bounds, row['content_sha256']) if bounds is not None else None)
    for source in terminal_sources:
        path = Path(source)
        key = path.parent.name if '_scan_delta_inputs' in path.parts else _source_delta_key(path)
        if key in groups:
            continue
        try:
            _read_source_scan_state(config.db_path, path)
        except ExistingTerminalDeltaBlocked as blocked:
            groups[key] = {'source': path, 'ranges': [(blocked.start_byte, blocked.end_byte, blocked.content_sha256)], 'fallback': str(path)}
        except OSError:
            groups[key] = {'source': None, 'ranges': [], 'fallback': str(path)}
    total, known = 0, []
    for group in groups.values():
        source, ranges = group['source'], group['ranges']
        known.append(str(source) if source is not None else group['fallback'])
        if source is None or not ranges or any(value is None for value in ranges):
            total = None
            continue
        try:
            signature = _source_scan_signature(source)
            counts = [_count_blocked_source_records(source, ExistingTerminalDeltaBlocked(
                str(source), start_byte=start, end_byte=end, content_sha256=digest))
                for start, end, digest in ranges]
            # Every range is verified; the earliest suffix subsumes all later ones.
            count = (max(counts) if all(value is not None for value in counts)
                     and _source_scan_signature(source) == signature else None)
        except (OSError, TypeError, ValueError):
            count = None
        total = total + count if total is not None and count is not None else None
    return len(groups), total, known


@writer_sink("raw_relay_storage")
def _review_missing_held_originals(config, source_files):
    originals = {_source_delta_key(Path(path)) for path in source_files}
    conn = _scan_state_connect(config.db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        for row in _held_spool_rows(conn):
            path = Path(row['source_file_path'])
            if (('_scan_delta_inputs' in path.parts and path.parent.name not in originals)
                    or ('_scan_delta_inputs' not in path.parts and not path.is_file())):
                _set_held_spool_review(conn, row)
        conn.commit()
    finally:
        conn.close()


def _repair_held_assignments_before_scan(config, source_file, *, administrator=False):
    conn = _scan_state_connect(config.db_path)
    try:
        held = _held_spool_rows(conn)
    finally:
        conn.close()
    return [row['relay_id'] for row in held
            if _source_range_for_row(row, source_file) is not None
            and (not row['next_attempt_at'] or row['next_attempt_at'] <= utc_now_text())
            and _reconstruct_delta_copies(config, source_file, row['relay_id'], administrator=administrator)]



def _held_review_status(config):
    conn = _scan_state_connect(config.db_path)
    try:
        for row in _held_spool_rows(conn):
            authority = conn.execute('SELECT status,last_error_code FROM direct_sync_runtime_authority WHERE assigned_relay_id=?',
                                     (row['relay_id'],)).fetchone()
            if (authority is not None and authority['status'] == 'OPERATOR_REVIEW'
                    and authority['last_error_code'] == row['last_error_code']):
                return {'status': 'operator_review', 'error_code': authority['last_error_code']}
        return None
    finally:
        conn.close()


def _terminal_source_backlog(config, originals):
    sources, counts = [], []
    for source in originals:
        try:
            _read_source_scan_state(config.db_path, source)
        except ExistingTerminalDeltaBlocked as blocked:
            sources.append(str(source))
            counts.append(_count_blocked_source_records(source, blocked))
        except OSError:
            sources.append(str(source))
            counts.append(None)
    missing = _missing_original_delta_blocks(config, {_source_delta_key(path) for path in originals})
    sources.extend(missing)
    counts.extend([None] * len(missing))
    return sources, counts


def _scan_backlog(config, originals, terminal_sources, counts):
    held = _held_runtime_backlog(config, originals, terminal_sources)
    if held is not None:
        return held[2], held[1]
    return terminal_sources, None if any(value is None for value in counts) else sum(counts)


def _missing_original_delta_blocks(config: DirectSyncRuntimeConfig, available_keys: set[str]) -> list[str]:
    conn = _scan_state_connect(config.db_path)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_sync_relay_batches'").fetchone():
            return []
        rows = conn.execute(
            """SELECT source_file_path, spooled_file_path FROM direct_sync_relay_batches
               WHERE status IN ('pending', 'retry_wait')
                  OR (status = 'failed_permanent' AND last_error_code = 'spooled_file_missing')
               ORDER BY created_at, relay_id"""
        ).fetchall()
    finally:
        conn.close()
    blocked = {}
    for row in rows:
        delta = Path(str(row["source_file_path"] or ""))
        key = delta.parent.name
        if (delta.parent.parent != Path(config.spool_dir) / "_scan_delta_inputs"
                or len(key) != 16 or any(char not in "0123456789abcdef" for char in key)
                or key in available_keys):
            continue
        if _delta_path_is_missing(delta) and _delta_path_is_missing(Path(str(row["spooled_file_path"] or ""))):
            blocked.setdefault(key, str(delta))
    return list(blocked.values())


def _repair_recoverable_delta_spools_before_scan(
    config: DirectSyncRuntimeConfig,
    source_file: Path,
) -> bool:
    reset_stale_relay_leases(db_path=config.db_path)
    conn = _scan_state_connect(config.db_path)
    try:
        has_relay_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'direct_sync_relay_batches'"
        ).fetchone()
        if not has_relay_table:
            return True
        rows = conn.execute(
            """
            SELECT *
            FROM direct_sync_relay_batches
            WHERE relative_path LIKE 'legacy_csv_deltas/%'
               OR relative_path LIKE 'd/%'
            """
        ).fetchall()
        held = _held_spool_rows(conn)
        held_ids = {row['relay_id'] for row in held}
        rows = list({row['relay_id']: row for row in [*rows, *held]}.values())
    finally:
        conn.close()

    repairs: list[tuple[str, Path, str]] = []
    source_delta_key = _source_delta_key(source_file)
    for row in rows:
        source_path = Path(str(row["source_file_path"] or ""))
        parsed_range = _source_range_for_row(row, source_file, source_key=source_delta_key)
        if parsed_range is None:
            continue
        start_byte, end_byte = parsed_range
        status = str(row["status"] or "")
        terminal_missing = status == "failed_permanent" and row["last_error_code"] == "spooled_file_missing"
        both_missing = _delta_path_is_missing(source_path) and _delta_path_is_missing(
            Path(str(row["spooled_file_path"] or ""))
        )
        if row["relay_id"] in held_ids or terminal_missing or (both_missing and status in {"pending", "retry_wait"}):
            if not _reconstruct_delta_copies(config, source_file, str(row["relay_id"])):
                raise ExistingTerminalDeltaBlocked(
                    str(source_file), start_byte=start_byte, end_byte=end_byte,
                    content_sha256=str(row["content_sha256"] or ""),
                )
            continue
        delta_hash = _delta_content_sha256_for_range(source_file, start_byte, end_byte)
        if not delta_hash or delta_hash != str(row["content_sha256"] or ""):
            continue
        if _delta_relay_row_has_usable_spool(row):
            continue
        status = str(row["status"] or "")
        if status == "leased":
            return False
        if status not in {"pending", "retry_wait"}:
            continue
        try:
            expected_byte_length = int(row["byte_length"])
            if source_path.stat().st_size != expected_byte_length:
                return False
            if _file_prefix_sha256(source_path, expected_byte_length) != str(
                row["content_sha256"] or ""
            ):
                return False
        except (OSError, TypeError, ValueError):
            return False
        repairs.append(
            (
                str(row["relay_id"]),
                source_path,
                str(row["relative_path"] or ""),
            )
        )

    for relay_id, source_path, relative_path in repairs:
        repair_status = enqueue_completed_source_file(
            config,
            source_file_path=source_path,
            relative_path=relative_path,
        )
        if repair_status.get("status") not in {"already_queued", "already_acked"}:
            return False
        conn = _scan_state_connect(config.db_path)
        try:
            repaired = conn.execute(
                """
                SELECT spooled_file_path, content_sha256, byte_length, status
                FROM direct_sync_relay_batches
                WHERE relay_id = ?
                """,
                (relay_id,),
            ).fetchone()
        finally:
            conn.close()
        if repaired is None:
            return False
        repaired_status = str(repaired["status"] or "")
        if repaired_status == "leased" and not _delta_relay_row_has_usable_spool(repaired):
            return False
        if repaired_status in {"pending", "retry_wait"} and not _delta_relay_row_has_usable_spool(
            repaired
        ):
            return False
    return True


def _delta_relay_row_blocks_progress(row: sqlite3.Row) -> bool:
    status = str(row["status"] or "")
    return status in {"failed_permanent", "operator_review"}


def _clear_vanished_source_failures(config: DirectSyncRuntimeConfig, scan_source_dir: str, scanned_files: list[Path]) -> None:
    """Drop failure entries whose original is neither scanned now nor on disk.

    A file that still exists under the same name (deferred this round, unreadable
    parent) keeps its entry; a renamed original is gone from its path and is
    cleared. Nothing here deletes or moves a file.
    """
    db_path = Path(config.db_path)
    try:
        db_path.stat()
    except FileNotFoundError:
        return
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_sync_source_scan_failures'"
        ).fetchone():
            return
        entries = conn.execute("SELECT source_key, source_name FROM direct_sync_source_scan_failures").fetchall()
    finally:
        conn.close()
    scanned = {_source_delta_key(path) for path in scanned_files}
    for source_key, source_name in entries:
        if source_key in scanned:
            continue
        candidate = Path(scan_source_dir) / str(source_name)
        if _source_delta_key(candidate) != source_key:
            continue
        try:
            os.lstat(candidate)
        except (FileNotFoundError, NotADirectoryError):
            clear_source_scan_failure(config, source_key=source_key, reason="vanished")
        except OSError:
            continue


def _read_source_scan_state(db_path: str | Path, source_file: Path) -> tuple[int, str]:
    conn = _scan_state_connect(db_path)
    try:
        explicit_state = _read_explicit_source_scan_state(conn, source_file)
        durable_state = _read_durable_delta_progress(conn, source_file)
        if durable_state[0] > explicit_state[0]:
            _write_source_scan_state(conn, source_file, durable_state[0], durable_state[1])
            explicit_state = durable_state
        queued_state = _read_queued_delta_progress(conn, source_file)
        return queued_state if queued_state[0] > explicit_state[0] else explicit_state
    finally:
        conn.close()


def _read_explicit_source_scan_state(conn: sqlite3.Connection, source_file: Path) -> tuple[int, str]:
    row = conn.execute(
        "SELECT sent_byte_count, sent_prefix_sha256 FROM direct_sync_source_scan_state WHERE source_file_path = ?",
        (_source_state_key(source_file),),
    ).fetchone()
    return (int(row["sent_byte_count"]), str(row["sent_prefix_sha256"] or "")) if row else (0, "")


@writer_sink("raw_relay_storage")
def _write_source_scan_state(
    conn: sqlite3.Connection,
    source_file: Path,
    sent_byte_count: int,
    sent_prefix_sha256: str,
) -> None:
    conn.execute(
        """
        INSERT INTO direct_sync_source_scan_state (source_file_path, sent_byte_count, sent_prefix_sha256, updated_at_unix)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(source_file_path) DO UPDATE SET
            sent_byte_count = excluded.sent_byte_count,
            sent_prefix_sha256 = excluded.sent_prefix_sha256,
            updated_at_unix = excluded.updated_at_unix,
            verified_source_signature = '',
            prefix_verified_at_unix = 0
        """,
        (_source_state_key(source_file), int(sent_byte_count), sent_prefix_sha256, time.time()),
    )
    conn.commit()


def _record_source_sent_byte_count(
    db_path: str | Path,
    source_file: Path,
    sent_byte_count: int,
    sent_prefix_sha256: str,
) -> None:
    conn = _scan_state_connect(db_path)
    try:
        _write_source_scan_state(conn, source_file, sent_byte_count, sent_prefix_sha256)
    finally:
        conn.close()


def _record_source_sent_byte_count_after_ack(
    db_path: str | Path,
    source_file: Path,
    requested_sent_byte_count: int,
    requested_sent_prefix_sha256: str,
    target_relay_id: str = "",
) -> dict[str, object]:
    conn = _scan_state_connect(db_path)
    try:
        explicit_state = _read_explicit_source_scan_state(conn, source_file)
        durable_state = _read_durable_delta_progress(conn, source_file)
        if durable_state[0] <= explicit_state[0]:
            target_range = _read_acknowledged_target_delta_range(conn, source_file, target_relay_id)
            if (
                target_range is not None
                and target_range[1] == int(requested_sent_byte_count)
                and (target_range[0] == 0 or explicit_state[0] == target_range[0])
            ):
                _write_source_scan_state(conn, source_file, requested_sent_byte_count, requested_sent_prefix_sha256)
                return {
                    "status": "recorded_from_acked_target",
                    "recorded_sent_byte_count": int(requested_sent_byte_count),
                    "durable_sent_byte_count": durable_state[0],
                    "requested_sent_byte_count": int(requested_sent_byte_count),
                    "requested_prefix_sha256": requested_sent_prefix_sha256,
                    "target_relay_id": str(target_relay_id or ""),
                    "target_start_byte": target_range[0],
                    "target_end_byte": target_range[1],
                }
            return {
                "status": "deferred_unacked_prefix"
                if durable_state[0] < int(requested_sent_byte_count)
                else "unchanged",
                "recorded_sent_byte_count": explicit_state[0],
                "durable_sent_byte_count": durable_state[0],
                "requested_sent_byte_count": int(requested_sent_byte_count),
                "requested_prefix_sha256": requested_sent_prefix_sha256,
            }
        _write_source_scan_state(conn, source_file, durable_state[0], durable_state[1])
        return {
            "status": "recorded",
            "recorded_sent_byte_count": durable_state[0],
            "durable_sent_byte_count": durable_state[0],
            "requested_sent_byte_count": int(requested_sent_byte_count),
            "requested_prefix_sha256": requested_sent_prefix_sha256,
        }
    finally:
        conn.close()


def _read_acknowledged_target_delta_range(
    conn: sqlite3.Connection,
    source_file: Path,
    target_relay_id: str,
) -> tuple[int, int] | None:
    target_relay_id = str(target_relay_id or "").strip()
    if not target_relay_id:
        return None
    row = conn.execute(
        """
        SELECT *
        FROM direct_sync_relay_batches
        WHERE relay_id = ?
        """,
        (target_relay_id,),
    ).fetchone()
    if row is None or not _delta_relay_row_counts_as_progress(row, include_inflight=False):
        return None
    if (Path(row['source_file_path']).resolve() == source_file.resolve()
            and not _original_fingerprint_matches(row)):
        return None
    return _source_range_for_row(row, source_file)


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


# This is only a scheduling hint. Recheck content periodically even when stat
# is unchanged; never use metadata to acknowledge an event or advance a cursor.
_UNCHANGED_SOURCE_RECHECK_SECONDS = 300.0


def _source_scan_signature(source_file: Path) -> str:
    info = source_file.stat()
    return json.dumps((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))


def _source_prefix_recently_verified(config, source_file, signature, source_size) -> bool:
    # The relay is a fresh child process each cycle: keep the scheduling hint
    # beside its existing cursor. Any cursor write invalidates this hint.
    conn = _scan_state_connect(config.db_path)
    try:
        row = conn.execute(
            "SELECT * FROM direct_sync_source_scan_state WHERE source_file_path = ?",
            (_source_state_key(source_file),),
        ).fetchone()
        if (row is None or source_size <= 0 or row["sent_byte_count"] != source_size
                or row["verified_source_signature"] != signature + ":" + row["sent_prefix_sha256"]
                or not 0 <= time.time() - row["prefix_verified_at_unix"] < _UNCHANGED_SOURCE_RECHECK_SECONDS):
            return False
        has_queue = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='direct_sync_relay_batches'"
        ).fetchone()
        if has_queue:
            # Inflight, damaged and blocked deltas must still reach the full
            # repair/progress path. Only settled sources can skip content reads.
            pending = conn.execute(
                "SELECT relay_id, source_file_path, relative_path FROM direct_sync_relay_batches WHERE status != 'acked'"
            ).fetchall()
            held_ids = {item['relay_id'] for item in _held_spool_rows(conn)}
            if any(item['relay_id'] in held_ids and Path(item['source_file_path']).resolve() == source_file.resolve()
                   for item in pending):
                return False
            source_key = _source_delta_key(source_file)
            if any(Path(str(item["source_file_path"] or "")).parent.name == source_key
                   and _parse_delta_range(item["relative_path"], source_file) is not None
                   for item in pending):
                return False
        return _source_scan_signature(source_file) == signature
    finally:
        conn.close()


@writer_sink("raw_relay_storage")
def _record_source_prefix_verification(config, source_file, signature, source_size, prefix_sha256) -> None:
    conn = _scan_state_connect(config.db_path)
    try:
        conn.execute(
            "UPDATE direct_sync_source_scan_state SET verified_source_signature = ?, prefix_verified_at_unix = ? "
            "WHERE source_file_path = ? AND sent_byte_count = ? AND sent_prefix_sha256 = ?",
            (signature + ":" + prefix_sha256, time.time(), _source_state_key(source_file), source_size, prefix_sha256),
        )
        conn.commit()
    finally:
        conn.close()


@writer_sink("raw_relay_storage")
def _build_delta_source_file(
    config: DirectSyncRuntimeConfig,
    source_file: Path,
    no_new_bytes: list[bool] | None = None,
) -> tuple[Path, str, int, str] | None:
    # no_new_bytes receives True only when the original is verified to hold nothing unsent.
    if _has_active_source_writer_lock(source_file):
        return None
    try:
        source_stat = source_file.stat()
        signature = _source_scan_signature(source_file)
    except OSError:
        return None
    if _source_prefix_recently_verified(config, source_file, signature, source_stat.st_size):
        if no_new_bytes is not None:
            no_new_bytes.append(True)
        return None
    if not _repair_recoverable_delta_spools_before_scan(config, source_file):
        return None
    source_size = source_stat.st_size
    source_mtime_ns = source_stat.st_mtime_ns
    sent_byte_count, sent_prefix_sha256 = _read_source_scan_state(config.db_path, source_file)
    prefix_hash = hashlib.sha256()
    if sent_byte_count > 0:
        replaced_or_truncated = not sent_prefix_sha256 or source_size < sent_byte_count
        if not replaced_or_truncated:
            with source_file_error_boundary(), source_file.open("rb") as handle:
                remaining = sent_byte_count
                while remaining:
                    block = handle.read(min(1024 * 1024, remaining))
                    if not block:
                        break
                    prefix_hash.update(block)
                    remaining -= len(block)
            replaced_or_truncated = bool(remaining) or prefix_hash.hexdigest() != sent_prefix_sha256
        if replaced_or_truncated:
            sent_byte_count = 0
            prefix_hash = hashlib.sha256()
    if source_size <= sent_byte_count:
        if _source_scan_signature(source_file) == signature:
            _record_source_prefix_verification(config, source_file, signature, source_size, sent_prefix_sha256)
        if no_new_bytes is not None:
            no_new_bytes.append(True)
        return None

    with source_file_error_boundary(), source_file.open("rb") as handle:
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
    if (after_stat.st_size != source_size or after_stat.st_mtime_ns != source_mtime_ns
            or after_stat.st_ino != source_stat.st_ino or after_stat.st_dev != source_stat.st_dev):
        return None

    complete_delta_body = _complete_line_prefix(delta_body)
    if not complete_delta_body.strip():
        return None
    end_byte = start_byte + len(complete_delta_body)
    if start_byte == 0 and end_byte <= data_start:
        return None

    delta_content = complete_delta_body if start_byte == 0 else header + complete_delta_body
    delta_hash = hashlib.sha256(delta_content).hexdigest()
    if start_byte == 0:
        prefix_hash = hashlib.sha256()
    prefix_hash.update(complete_delta_body)
    sent_prefix_sha256 = prefix_hash.hexdigest()
    delta_source = (
        Path(config.spool_dir)
        / "_scan_delta_inputs"
        / _source_delta_key(source_file)
        / f"bytes-{start_byte}-{end_byte}-sha256-{delta_hash[:16]}.csv"
    )
    try:
        ensure_user_runtime_directory(delta_source.parent)
    except OSError as exc:
        # Recursive mkdir can fail at the shared input root. Only an error
        # naming this source's own subdirectory qualifies for a file skip.
        if exc.filename is None or Path(exc.filename) != delta_source.parent:
            raise
        with source_file_error_boundary("source_delta_write_failed"):
            raise
    with source_file_error_boundary("source_delta_write_failed"):
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
        prepared_credential=getattr(args, "prepared_credential", None),
    )


@writer_sink("raw_relay_runner", probe_only=True)
def main(argv: list[str] | None = None) -> int:
    try:
        from data_generation_guard import warm_runtime_release
        warm_runtime_release()
    except Exception:
        pass
    from auto_update import SupportArgumentParser, emit_support_record
    parser = SupportArgumentParser(description="Container_Audit direct-sync relay runner")
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
    parser.add_argument("--require-runtime-lease-before-scan", action="store_true")
    args = parser.parse_args(argv)
    if args.enqueue_source_file and args.scan_source_dir:
        parser.error("--enqueue-source-file and --scan-source-dir are mutually exclusive")

    from data_generation_guard import resolve_owner_path
    from logistics_runtime_profile import resolve_logistics_profile_path
    files, directories = [], []
    for name, value in vars(args).copy().items():
        if value and name.endswith(('_path', '_file', '_dir')):
            path = resolve_owner_path(value)
            setattr(args, name, str(path))
            (directories if name.endswith('_dir') else files).append(path)
    profile_path = resolve_logistics_profile_path()
    if profile_path.is_file():
        files.append(profile_path)
    try:
        probe_before_owner_paths(Path(args.db_path).parent, file_paths=files, directory_paths=directories)
        if Path(args.credential_path).is_file():
            args.prepared_credential = prepare_credential_config(args.credential_path, data_root=Path(args.db_path).parent)
        config = _build_config(args)
        # Explicit raw queue roots may differ from the GUI root; the shared SID
        # control slot ensures installer probes also observe this process.
        record_before_owner_paths(Path(args.db_path).parent, file_paths=files, directory_paths=directories)
    except DataGenerationBlocked as exc:
        print(str(exc))
        return 1
    if args.require_runtime_lease_before_scan:
        preflight_status = run_relay_once(config)
        preflight_lease = preflight_status.get("runtime_lease")
        if not (
            isinstance(preflight_lease, dict)
            and preflight_lease.get("status") == "ACTIVE"
            and preflight_lease.get("server_grant_accepted") is True
        ):
            print(f"direct_sync_relay_status={preflight_status['status']}")
            return 1
    if args.enqueue_source_file:
        original = Path(args.enqueue_source_file)
        repaired = _repair_held_assignments_before_scan(config, original, administrator=True)
        held, _waiting = _held_runtime_backlog_rows(config.db_path)
        matching = [row for row in held if _source_range_for_row(row, original) is not None]
        if repaired or matching:
            status = run_relay_once(config, target_relay_id=repaired[0] if repaired else '')
            originals = _scan_source_files(str(original.parent), [], args.max_enqueue_files, 0, limit_results=False)
            blocked, counts = _terminal_source_backlog(config, originals)
            blocked, records = _scan_backlog(config, originals, blocked, counts)
            status = record_scan_drain_status(config, drain_status=status, scan_status='scan_no_new_rows',
                scan_enqueued_count=0, scan_attempted_count=1,
                scan_terminal_blocked_count=len(blocked),
                scan_terminal_blocked_record_count=records,
                scan_terminal_blocked_source_files=blocked)
        else:
            status = enqueue_completed_source_file(
                config,
                source_file_path=args.enqueue_source_file,
                relative_path=args.relative_path,
            )
    elif args.scan_source_dir:
        all_originals = _scan_source_files(args.scan_source_dir, [], args.max_enqueue_files, 0, limit_results=False)
        _review_missing_held_originals(config, all_originals)
        statuses = []
        enqueued_count = 0
        attempted_count = 0
        no_new_count = 0
        preflight_status = None
        file_error_status = None
        terminal_blocked_sources: list[str] = []
        terminal_blocked_record_counts: list[int | None] = []
        pending_delta_progress: dict[str, tuple[Path, int, str]] = {}
        max_enqueue_files = max(0, int(args.max_enqueue_files or 0))
        source_files = _scan_source_files(
            args.scan_source_dir,
            args.source_glob,
            args.max_enqueue_files,
            args.min_source_file_age_seconds,
            limit_results=False,
        )
        _clear_vanished_source_failures(config, args.scan_source_dir, source_files)
        for source_file in source_files:
            if enqueued_count >= max_enqueue_files:
                break
            if not _source_file_still_eligible_for_enqueue(
                source_file,
                args.scan_source_dir,
                args.min_source_file_age_seconds,
            ):
                continue
            no_new_bytes: list[bool] = []
            try:
                delta = _build_delta_source_file(config, source_file, no_new_bytes)
            except SourceFileInputError as exc:
                attempted_count += 1
                file_error_status = record_source_scan_failure(
                    config, source_key=_source_delta_key(source_file), source_name=source_file.name, error_code=exc.error_code,
                )
                continue
            except ExistingTerminalDeltaBlocked as blocked:
                attempted_count += 1
                terminal_blocked_sources.append(str(source_file))
                terminal_blocked_record_counts.append(_count_blocked_source_records(source_file, blocked))
                continue
            except Exception:
                attempted_count += 1
                terminal_blocked_sources.append(str(source_file))
                terminal_blocked_record_counts.append(None)
                continue
            if delta is None:
                no_new_count += 1
                if no_new_bytes:
                    clear_source_scan_failure(config, source_key=_source_delta_key(source_file), reason="no_new_bytes")
                continue
            delta_source_file, relative_path, sent_byte_count, sent_prefix_sha256 = delta
            current = enqueue_completed_source_file(
                config,
                source_file_path=delta_source_file,
                relative_path=relative_path,
            )
            attempted_count += 1
            if current["status"] == "enqueue_error" and current.get("error_code") in SOURCE_FILE_ERROR_CODES:
                file_error_status = record_source_scan_failure(
                    config, source_key=_source_delta_key(source_file), source_name=source_file.name,
                    error_code=current["error_code"],
                )
                continue
            if current["status"] == "existing_terminal_blocked":
                terminal_blocked_sources.append(str(source_file))
                terminal_blocked_record_counts.append(None)
                continue
            if current["status"] in SCAN_BLOCKED_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                preflight_status = current
                break
            if current["status"] in SCAN_SUCCESS_STATUSES:
                clear_source_scan_failure(config, source_key=_source_delta_key(source_file))
            statuses.append(current)
            if current["status"] == "enqueued":
                enqueued_count += 1
                last_result = current.get("last_result") if isinstance(current.get("last_result"), dict) else {}
                relay_id = str(last_result.get("relay_id") or "")
                if relay_id:
                    pending_delta_progress[relay_id] = (source_file, sent_byte_count, sent_prefix_sha256)
            elif current["status"] not in SCAN_SUCCESS_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                preflight_status = current
                break
        available_keys = {
            _source_delta_key(path) for path in _scan_source_files(
                args.scan_source_dir, [], args.max_enqueue_files, 0, limit_results=False
            )
        }
        for missing_source in _missing_original_delta_blocks(config, available_keys):
            terminal_blocked_sources.append(missing_source)
            terminal_blocked_record_counts.append(None)
        terminal_blocked_sources, blocked_record_count = _scan_backlog(
            config, all_originals, terminal_blocked_sources, terminal_blocked_record_counts)
        if preflight_status:
            scan_status = preflight_status
        elif file_error_status and (statuses or not terminal_blocked_sources):
            scan_status = file_error_status
            if statuses and "queue" in statuses[-1]:
                scan_status["queue"] = statuses[-1]["queue"]
        elif statuses:
            scan_status = statuses[-1]
        elif terminal_blocked_sources:
            scan_status = {
                "status": "existing_terminal_blocked",
                "scan_failed_source_file": terminal_blocked_sources[0],
                "last_result": {
                    "status": "existing_terminal_blocked",
                    "error_code": "existing_terminal_delta_blocked",
                },
            }
        else:
            scan_status = {"status": "scan_no_new_rows" if no_new_count else "scan_no_files"}
        held_review = _held_review_status(config)
        if held_review is not None:
            scan_status['runtime_lease'] = held_review
        scan_status["scan_enqueued_count"] = enqueued_count
        scan_status["scan_attempted_count"] = attempted_count
        scan_status["scan_no_new_count"] = no_new_count
        scan_status["scan_terminal_blocked_count"] = len(terminal_blocked_sources)
        scan_status["scan_terminal_blocked_record_count"] = blocked_record_count
        if terminal_blocked_sources:
            scan_status["scan_terminal_blocked_source_files"] = terminal_blocked_sources
        if scan_status["status"] == "scan_no_files":
            scan_status = record_scan_status(
                config,
                status="scan_no_files",
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
                scan_terminal_blocked_count=len(terminal_blocked_sources),
                scan_terminal_blocked_record_count=blocked_record_count,
                scan_terminal_blocked_source_files=terminal_blocked_sources,
            )
            scan_status["scan_enqueued_count"] = enqueued_count
            scan_status["scan_attempted_count"] = attempted_count
            scan_status["scan_terminal_blocked_count"] = len(terminal_blocked_sources)
        elif scan_status["status"] == "scan_no_new_rows":
            scan_status = record_scan_status(
                config,
                status="scan_no_new_rows",
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
                scan_terminal_blocked_count=len(terminal_blocked_sources),
                scan_terminal_blocked_record_count=blocked_record_count,
                scan_terminal_blocked_source_files=terminal_blocked_sources,
            )
            scan_status["scan_enqueued_count"] = enqueued_count
            scan_status["scan_attempted_count"] = attempted_count
            scan_status["scan_no_new_count"] = no_new_count
            scan_status["scan_terminal_blocked_count"] = len(terminal_blocked_sources)
        should_drain = args.drain_after_scan and scan_status["status"] not in SCAN_BLOCKED_STATUSES and (
            scan_status["status"] != "enqueue_error" or (file_error_status is not None and preflight_status is None)
        )
        if (args.drain_after_scan and scan_status['status'] == 'existing_terminal_blocked'
                and held_review is None):
            held, _waiting = _held_runtime_backlog_rows(config.db_path)
            should_drain = any(row['status'] == 'pending' for row in held)
        if should_drain:
            targeted_drain_results = []
            status = None
            if pending_delta_progress:
                for relay_id in list(pending_delta_progress):
                    current_status = run_relay_once(config, target_relay_id=relay_id)
                    last_result = (
                        current_status.get("last_result")
                        if isinstance(current_status.get("last_result"), dict)
                        else {}
                    )
                    acked_relay_id = str(last_result.get("relay_id") or "")
                    targeted_result = {
                        "target_relay_id": relay_id,
                        "status": current_status.get("status", ""),
                        "acked_relay_id": acked_relay_id,
                        "error_code": last_result.get("error_code", ""),
                    }
                    if current_status.get("status") == "acked" and acked_relay_id in pending_delta_progress:
                        source_file, sent_byte_count, sent_prefix_sha256 = pending_delta_progress[acked_relay_id]
                        targeted_result["source_scan_state_update"] = _record_source_sent_byte_count_after_ack(
                            config.db_path,
                            source_file,
                            sent_byte_count,
                            sent_prefix_sha256,
                            target_relay_id=acked_relay_id,
                        )
                    targeted_drain_results.append(targeted_result)
                    status = current_status
            if status is None:
                status = run_relay_once(config)
            if targeted_drain_results:
                status = dict(status)
                status["targeted_drain_results"] = targeted_drain_results
            terminal_blocked_sources, terminal_blocked_record_counts = _terminal_source_backlog(config, all_originals)
            terminal_blocked_sources, blocked_record_count = _scan_backlog(
                config, all_originals, terminal_blocked_sources, terminal_blocked_record_counts)
            status = record_scan_drain_status(
                config,
                drain_status=status,
                scan_status=scan_status["status"],
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
                scan_failed_source_file=scan_status.get("scan_failed_source_file", ""),
                scan_terminal_blocked_count=len(terminal_blocked_sources),
                scan_terminal_blocked_record_count=blocked_record_count,
                scan_terminal_blocked_source_files=terminal_blocked_sources,
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
                    scan_terminal_blocked_count=len(terminal_blocked_sources),
                    scan_terminal_blocked_record_count=blocked_record_count,
                    scan_terminal_blocked_source_files=terminal_blocked_sources,
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
    if "scan_terminal_blocked_count" in status:
        print(f"direct_sync_scan_terminal_blocked_count={status['scan_terminal_blocked_count']}")
    if status.get("scan_failed_source_file"):
        emit_support_record({'failed_source_file_path': status['scan_failed_source_file']},
                            stage='relay_runtime')
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
    from auto_update import run_support_main
    raise SystemExit(run_support_main(main, stage='relay_runtime'))
