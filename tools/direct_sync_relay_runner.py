#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Run one Container_Audit direct-sync relay cycle."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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
DEFAULT_MIN_SOURCE_FILE_AGE_SECONDS = 300
SCAN_SUCCESS_STATUSES = {"enqueued", "already_queued", "already_acked"}
SCAN_BLOCKED_STATUSES = {
    "paused_by_operator",
    "blocked_operator_control",
    "blocked_queue_backpressure",
    "blocked_disk_pressure",
    "existing_terminal_blocked",
}


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
        preflight_status = None
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
            current = enqueue_completed_source_file(config, source_file_path=source_file)
            attempted_count += 1
            if current["status"] in SCAN_BLOCKED_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                preflight_status = current
                break
            statuses.append(current)
            if current["status"] == "enqueued":
                enqueued_count += 1
            elif current["status"] not in SCAN_SUCCESS_STATUSES:
                current["scan_failed_source_file"] = str(source_file)
                break
        scan_status = preflight_status or (statuses[-1] if statuses else {"status": "scan_no_files"})
        scan_status["scan_enqueued_count"] = enqueued_count
        scan_status["scan_attempted_count"] = attempted_count
        if scan_status["status"] == "scan_no_files":
            scan_status = record_scan_status(
                config,
                status="scan_no_files",
                scan_enqueued_count=enqueued_count,
                scan_attempted_count=attempted_count,
            )
            scan_status["scan_enqueued_count"] = enqueued_count
            scan_status["scan_attempted_count"] = attempted_count
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
