#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Operate the local Container_Audit direct-sync relay queue."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from direct_sync_operator import (  # noqa: E402
    operator_status,
    pause_relay,
    resume_relay,
    restore_relay_spool_from_server,
    retry_dead_relay_batch,
)
from direct_sync_runtime import load_credentials_from_json  # noqa: E402


def _write_json_atomic(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_name(f"{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(dict(payload), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, target)


def _emit(report: Mapping[str, Any], report_path: str = "") -> int:
    mutable_report = dict(report)
    report_status = "SKIPPED"
    report_error_code = ""
    report_error_message = ""
    if report_path:
        try:
            _write_json_atomic(report_path, mutable_report)
            report_status = "PASS"
        except OSError as exc:
            report_status = "FAIL"
            report_error_code = "operator_report_write_failed"
            report_error_message = f"operator report write failed: {exc.__class__.__name__}"
            mutable_report["report_write_status"] = report_status
            mutable_report["report_write_error_code"] = report_error_code
            mutable_report["report_write_error_message"] = report_error_message
    print(f"direct_sync_operator_status={mutable_report.get('status', 'FAIL')}")
    print(f"direct_sync_operator_operation={mutable_report.get('operation', '')}")
    print(f"direct_sync_operator_report_status={report_status}")
    if report_error_code:
        print(f"direct_sync_operator_report_error_code={report_error_code}")
    status = str(mutable_report.get("status") or "FAIL")
    if report_status == "FAIL":
        return 1
    if status == "PASS":
        return 0
    if status == "BLOCKED":
        return 2
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Container_Audit direct-sync relay operator control")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Report local relay queue and pause state")
    status_parser.add_argument("--db-path", required=True)
    status_parser.add_argument("--operator-pause-path", default="")
    status_parser.add_argument("--runtime-status-path", default="")
    status_parser.add_argument("--report-path", default="")

    pause_parser = subparsers.add_parser("pause", help="Pause local relay enqueue/drain work")
    pause_parser.add_argument("--operator-pause-path", required=True)
    pause_parser.add_argument("--operator-id", required=True)
    pause_parser.add_argument("--reason", required=True)
    pause_parser.add_argument("--audit-log-path", default="")
    pause_parser.add_argument("--report-path", default="")

    resume_parser = subparsers.add_parser("resume", help="Resume local relay enqueue/drain work")
    resume_parser.add_argument("--operator-pause-path", required=True)
    resume_parser.add_argument("--operator-id", required=True)
    resume_parser.add_argument("--reason", required=True)
    resume_parser.add_argument("--audit-log-path", default="")
    resume_parser.add_argument("--report-path", default="")
    resume_parser.add_argument("--force-invalid-marker", action="store_true")

    retry_parser = subparsers.add_parser("retry-dead", help="Move failed_permanent relay batch to pending")
    retry_parser.add_argument("--db-path", required=True)
    retry_parser.add_argument("--relay-id", required=True)
    retry_parser.add_argument("--operator-id", required=True)
    retry_parser.add_argument("--reason", required=True)
    retry_parser.add_argument("--audit-log-path", default="")
    retry_parser.add_argument("--report-path", default="")
    retry_parser.add_argument("--allow-operator-review", action="store_true")

    restore_parser = subparsers.add_parser("restore-spool", help="Restore an ACKED relay spool file from server raw artifact")
    restore_parser.add_argument("--db-path", required=True)
    restore_parser.add_argument("--relay-id", required=True)
    restore_parser.add_argument("--spool-root", required=True)
    restore_parser.add_argument("--credential-path", required=True)
    restore_parser.add_argument("--operator-id", required=True)
    restore_parser.add_argument("--reason", required=True)
    restore_parser.add_argument("--audit-log-path", default="")
    restore_parser.add_argument("--report-path", default="")

    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            return _emit(
                operator_status(
                    db_path=args.db_path,
                    pause_path=args.operator_pause_path,
                    runtime_status_path=args.runtime_status_path,
                ),
                args.report_path,
            )
        if args.command == "pause":
            return _emit(
                pause_relay(
                    pause_path=args.operator_pause_path,
                    operator_id=args.operator_id,
                    reason=args.reason,
                    audit_log_path=args.audit_log_path,
                ),
                args.report_path,
            )
        if args.command == "resume":
            return _emit(
                resume_relay(
                    pause_path=args.operator_pause_path,
                    operator_id=args.operator_id,
                    reason=args.reason,
                    audit_log_path=args.audit_log_path,
                    force_invalid_marker=args.force_invalid_marker,
                ),
                args.report_path,
            )
        if args.command == "retry-dead":
            return _emit(
                retry_dead_relay_batch(
                    db_path=args.db_path,
                    relay_id=args.relay_id,
                    operator_id=args.operator_id,
                    reason=args.reason,
                    audit_log_path=args.audit_log_path,
                    allow_operator_review=args.allow_operator_review,
                ),
                args.report_path,
            )
        if args.command == "restore-spool":
            return _emit(
                restore_relay_spool_from_server(
                    db_path=args.db_path,
                    relay_id=args.relay_id,
                    spool_root=args.spool_root,
                    credentials=load_credentials_from_json(args.credential_path),
                    operator_id=args.operator_id,
                    reason=args.reason,
                    audit_log_path=args.audit_log_path,
                ),
                args.report_path,
            )
    except ValueError as exc:
        return _emit({"status": "FAIL", "operation": args.command, "error_code": "invalid_operator_input", "error_message": str(exc)}, getattr(args, "report_path", ""))
    return _emit({"status": "FAIL", "operation": args.command, "error_code": "unknown_command"}, getattr(args, "report_path", ""))


if __name__ == "__main__":
    raise SystemExit(main())
