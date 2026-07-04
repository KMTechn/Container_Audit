#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a read-only operator-review case report for Container_Audit relay batches."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

REPORT_SCHEMA_VERSION = "container-audit-operator-review-case-report-v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_json(path: str | os.PathLike[str]) -> Any:
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


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


def _write_text_atomic(path: str | os.PathLike[str], text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_name(f"{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
    with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, target)


def _json_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _json_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_detail_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"_parse_error": "detail_json_invalid"}
    return parsed if isinstance(parsed, dict) else {"_parse_error": "detail_json_not_object"}


def _server_source_file_id(case: Mapping[str, Any]) -> str:
    receipt = _json_dict(case.get("receipt"))
    metadata = _json_dict(case.get("metadata"))
    return str(receipt.get("server_source_file_id") or metadata.get("relative_path") or "")


def _relay_id(case: Mapping[str, Any]) -> str:
    status_context = _json_dict(case.get("status_context"))
    metadata = _json_dict(case.get("metadata"))
    receipt = _json_dict(case.get("receipt"))
    return str(
        status_context.get("relay_id")
        or metadata.get("client_batch_id")
        or receipt.get("client_batch_id")
        or ""
    )


def _match_quarantine_rows(
    server_source_file_id: str,
    quarantine_rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if not server_source_file_id:
        return matches
    for row in quarantine_rows:
        event_identity = str(row.get("event_identity") or "")
        if not event_identity.startswith(f"{server_source_file_id}:"):
            continue
        detail = _parse_detail_json(row.get("detail_json"))
        matches.append(
            {
                "id": row.get("id"),
                "event_identity": event_identity,
                "reason": str(row.get("reason") or ""),
                "observed_at": str(row.get("observed_at") or ""),
                "raw_event_name": str(detail.get("raw_event_name") or ""),
                "detail": detail,
            }
        )
    return sorted(matches, key=lambda item: str(item.get("event_identity") or ""))


def _classify_case(quarantine_rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    reasons = {str(row.get("reason") or "") for row in quarantine_rows if row.get("reason")}
    detail_codes: set[str] = set()
    for row in quarantine_rows:
        detail = _json_dict(row.get("detail"))
        for code in _json_list(detail.get("codes")):
            detail_codes.add(str(code))

    if "DISPATCH_KEY_NOT_IN_MANIFEST" in detail_codes:
        return {
            "classification": "manifest_mismatch",
            "final_action_required": "repair_manifest_or_signoff_historical_test_artifact",
            "retry_allowed": False,
            "ack_allowed": False,
            "operator_signoff_required": True,
            "risk": "Retrying before manifest repair can create repeated quarantine or polluted projections.",
        }
    if reasons == {"LEGACY_REPLAY_CONFLICT"}:
        return {
            "classification": "replay_conflict",
            "final_action_required": "signoff_superseded_or_escalate_identity_conflict",
            "retry_allowed": False,
            "ack_allowed": False,
            "operator_signoff_required": True,
            "risk": "Blind retry can duplicate legacy business events already represented by an earlier source file.",
        }
    if reasons:
        return {
            "classification": "operator_review",
            "final_action_required": "manual_root_cause_review",
            "retry_allowed": False,
            "ack_allowed": False,
            "operator_signoff_required": True,
            "risk": "Server accepted the file but did not fully project it; automatic state transition is unsafe.",
        }
    return {
        "classification": "unmatched_operator_review",
        "final_action_required": "find_matching_server_quarantine_rows_before_action",
        "retry_allowed": False,
        "ack_allowed": False,
        "operator_signoff_required": True,
        "risk": "Local receipt indicates review but matching server quarantine evidence was not attached.",
    }


def _build_case(case: Mapping[str, Any], quarantine_rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    metadata = _json_dict(case.get("metadata"))
    receipt = _json_dict(case.get("receipt"))
    totals = _json_dict(receipt.get("totals"))
    source_file_id = _server_source_file_id(case)
    matched_rows = _match_quarantine_rows(source_file_id, quarantine_rows)
    classification = _classify_case(matched_rows)
    reason_counts = dict(Counter(str(row.get("reason") or "") for row in matched_rows if row.get("reason")))
    raw_event_names = sorted({str(row.get("raw_event_name") or "") for row in matched_rows if row.get("raw_event_name")})

    return {
        "relay_id": _relay_id(case),
        "status": "operator_review" if case.get("committed") is True and case.get("success") is False else str(case.get("status") or ""),
        "http_status_code": case.get("status_code"),
        "committed": case.get("committed"),
        "retryable": case.get("retryable"),
        "receipt_status": receipt.get("status"),
        "request_id": receipt.get("request_id"),
        "source_file_id": source_file_id,
        "relative_path": metadata.get("relative_path"),
        "source_file_path": case.get("source_file_path"),
        "content_sha256": metadata.get("content_sha256") or _json_dict(receipt.get("source_file")).get("content_sha256"),
        "row_count": metadata.get("row_count") or _json_dict(receipt.get("source_file")).get("declared_row_count"),
        "totals": {
            "inserted": totals.get("inserted", 0),
            "quarantined": totals.get("quarantined", 0),
            "replayed": totals.get("replayed", 0),
            "errors": totals.get("errors", 0),
        },
        "classification": classification["classification"],
        "final_action_required": classification["final_action_required"],
        "retry_allowed": classification["retry_allowed"],
        "ack_allowed": classification["ack_allowed"],
        "operator_signoff_required": classification["operator_signoff_required"],
        "risk": classification["risk"],
        "quarantine_match_count": len(matched_rows),
        "quarantine_reason_counts": reason_counts,
        "quarantined_event_names": raw_event_names,
        "quarantine_rows": matched_rows,
    }


def build_report(
    case_paths: Iterable[str | os.PathLike[str]],
    quarantine_detail_path: str | os.PathLike[str],
    relay_status_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    quarantine_rows = [row for row in _json_list(_load_json(quarantine_detail_path)) if isinstance(row, dict)]
    cases = [_build_case(_json_dict(_load_json(path)), quarantine_rows) for path in case_paths]
    relay_status = _json_dict(_load_json(relay_status_path)) if relay_status_path else {}
    classifications = Counter(str(case.get("classification") or "") for case in cases)
    blocked_count = sum(1 for case in cases if case.get("operator_signoff_required"))

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "source_files": {
            "case_paths": [str(Path(path)) for path in case_paths],
            "quarantine_detail_path": str(Path(quarantine_detail_path)),
            "relay_status_path": str(Path(relay_status_path)) if relay_status_path else "",
        },
        "summary": {
            "case_count": len(cases),
            "blocked_count": blocked_count,
            "classification_counts": dict(classifications),
            "retry_allowed_count": sum(1 for case in cases if case.get("retry_allowed")),
            "ack_allowed_count": sum(1 for case in cases if case.get("ack_allowed")),
            "relay_status": relay_status.get("status", ""),
            "relay_queue_counts": _json_dict(_json_dict(relay_status.get("queue")).get("counts")),
            "dead_letter_counts": _json_dict(_json_dict(relay_status.get("last_result")).get("dead_letter_counts")),
        },
        "cases": cases,
        "signoff_template": {
            "operator_id": "",
            "signed_at": "",
            "case_relay_id": "",
            "selected_final_action": "",
            "allowed_values": [
                "retain_no_retry_historical_superseded",
                "repair_manifest_then_retry",
                "escalate_identity_conflict",
                "mark_failed_permanent_with_reason",
            ],
            "evidence_reviewed": [],
            "decision_notes": "",
        },
        "policy": {
            "read_only": True,
            "do_not_delete_queue_rows": True,
            "do_not_retry_committed_operator_review_without_repair": True,
            "do_not_ack_without_signed_superseded_or_projection_proof": True,
        },
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    summary = _json_dict(report.get("summary"))
    lines: list[str] = [
        "# Container_Audit TEST1 operator_review case report",
        "",
        f"- Generated: {report.get('generated_at', '')}",
        f"- Cases: {summary.get('case_count', 0)}",
        f"- Blocked until signoff: {summary.get('blocked_count', 0)}",
        f"- Relay status: {summary.get('relay_status', '')}",
        f"- Relay queue counts: `{json.dumps(summary.get('relay_queue_counts', {}), ensure_ascii=False, sort_keys=True)}`",
        "",
        "## Case summary",
        "",
        "| Relay ID | Classification | Inserted | Quarantined | Quarantine reasons | Retry | Ack | Required action |",
        "|---|---|---:|---:|---|---:|---:|---|",
    ]
    for case in _json_list(report.get("cases")):
        totals = _json_dict(case.get("totals"))
        reasons = ", ".join(f"{key}={value}" for key, value in _json_dict(case.get("quarantine_reason_counts")).items())
        lines.append(
            "| {relay} | {classification} | {inserted} | {quarantined} | {reasons} | {retry} | {ack} | {action} |".format(
                relay=case.get("relay_id", ""),
                classification=case.get("classification", ""),
                inserted=totals.get("inserted", 0),
                quarantined=totals.get("quarantined", 0),
                reasons=reasons or "-",
                retry="yes" if case.get("retry_allowed") else "no",
                ack="yes" if case.get("ack_allowed") else "no",
                action=case.get("final_action_required", ""),
            )
        )

    lines.extend(["", "## Case detail", ""])
    for case in _json_list(report.get("cases")):
        lines.extend(
            [
                f"### {case.get('relay_id', '')}",
                "",
                f"- Source file: `{case.get('source_file_id', '')}`",
                f"- Local spool: `{case.get('source_file_path', '')}`",
                f"- Content sha256: `{case.get('content_sha256', '')}`",
                f"- Classification: `{case.get('classification', '')}`",
                f"- Risk: {case.get('risk', '')}",
                f"- Required action: `{case.get('final_action_required', '')}`",
                f"- Quarantined event names: {', '.join(_json_list(case.get('quarantined_event_names'))) or '-'}",
                "",
                "| Quarantine ID | Reason | Event | Observed | Detail key evidence |",
                "|---:|---|---|---|---|",
            ]
        )
        for row in _json_list(case.get("quarantine_rows")):
            detail = _json_dict(row.get("detail"))
            evidence = detail.get("existing_event_identity") or ", ".join(_json_list(detail.get("codes")))
            lines.append(
                f"| {row.get('id', '')} | {row.get('reason', '')} | {row.get('raw_event_name', '')} | {row.get('observed_at', '')} | `{evidence}` |"
            )
        lines.append("")

    lines.extend(
        [
            "## Operator signoff form",
            "",
            "- Operator ID:",
            "- Signed at:",
            "- Relay ID:",
            "- Final action:",
            "- Evidence reviewed:",
            "- Decision notes:",
            "",
            "Allowed final actions:",
            "",
            "- `retain_no_retry_historical_superseded`",
            "- `repair_manifest_then_retry`",
            "- `escalate_identity_conflict`",
            "- `mark_failed_permanent_with_reason`",
            "",
            "Policy: this report is read-only. Do not delete, retry, or ack these rows without signed evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build Container_Audit operator-review case report")
    parser.add_argument("--case", action="append", required=True, help="Path to one operator-review receipt JSON")
    parser.add_argument("--quarantine-detail", required=True, help="Path to server quarantine detail JSON")
    parser.add_argument("--relay-status", default="", help="Path to relay status JSON")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args(argv)

    report = build_report(args.case, args.quarantine_detail, args.relay_status or None)
    _write_json_atomic(args.out_json, report)
    _write_text_atomic(args.out_md, render_markdown(report))
    print(f"operator_review_case_report_json={args.out_json}")
    print(f"operator_review_case_report_md={args.out_md}")
    print(f"operator_review_case_count={report['summary']['case_count']}")
    print(f"operator_review_blocked_count={report['summary']['blocked_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
