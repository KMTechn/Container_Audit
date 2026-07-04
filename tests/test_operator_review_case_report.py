import json

from tools.build_operator_review_case_report import build_report, render_markdown


def _case(relay_id, source_file_id, *, inserted=0, quarantined=0):
    relative_path = source_file_id.split("container-audit-test1/container_audit/container_audit_events/", 1)[-1]
    return {
        "committed": True,
        "metadata": {
            "client_batch_id": relay_id,
            "content_sha256": "a" * 64,
            "relative_path": relative_path,
            "row_count": inserted + quarantined,
        },
        "receipt": {
            "client_batch_id": relay_id,
            "committed": True,
            "request_id": f"request-{relay_id}",
            "server_source_file_id": source_file_id,
            "status": "accepted",
            "totals": {
                "errors": 0,
                "inserted": inserted,
                "quarantined": quarantined,
                "replayed": 0,
            },
        },
        "retryable": False,
        "source_file_path": f"C:/spool/{relay_id}.csv",
        "status_code": 200,
        "status_context": {"relay_id": relay_id},
        "success": False,
    }


def _write_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def test_operator_review_report_classifies_replay_conflict_as_signoff_blocked(tmp_path):
    source_file_id = "container-audit-test1/container_audit/container_audit_events/legacy_csv_deltas/case-a.csv"
    case_path = _write_json(tmp_path / "case-a.json", _case("relay-a", source_file_id, inserted=4, quarantined=2))
    quarantine_path = _write_json(
        tmp_path / "quarantine.json",
        [
            {
                "id": 2,
                "event_identity": f"{source_file_id}:3:0",
                "reason": "LEGACY_REPLAY_CONFLICT",
                "detail_json": json.dumps(
                    {
                        "existing_event_identity": f"{source_file_id}:2:0",
                        "raw_event_name": "MASTER_LABEL_SCANNED_NEW",
                    }
                ),
                "observed_at": "2026-07-04T00:00:00Z",
            },
            {
                "id": 1,
                "event_identity": f"{source_file_id}:2:0",
                "reason": "LEGACY_REPLAY_CONFLICT",
                "detail_json": json.dumps({"raw_event_name": "WORK_START"}),
                "observed_at": "2026-07-04T00:00:00Z",
            },
        ],
    )

    report = build_report([case_path], quarantine_path)
    case = report["cases"][0]

    assert report["summary"]["blocked_count"] == 1
    assert case["classification"] == "replay_conflict"
    assert case["retry_allowed"] is False
    assert case["ack_allowed"] is False
    assert case["quarantine_reason_counts"] == {"LEGACY_REPLAY_CONFLICT": 2}
    assert case["quarantined_event_names"] == ["MASTER_LABEL_SCANNED_NEW", "WORK_START"]


def test_operator_review_report_classifies_dispatch_key_mismatch(tmp_path):
    source_file_id = "container-audit-test1/container_audit/container_audit_events/legacy_csv_deltas/case-b.csv"
    case_path = _write_json(tmp_path / "case-b.json", _case("relay-b", source_file_id, inserted=2, quarantined=1))
    quarantine_path = _write_json(
        tmp_path / "quarantine.json",
        [
            {
                "id": 3,
                "event_identity": f"{source_file_id}:6:0",
                "reason": "MANIFEST_EVENT_VALIDATION_FAILED",
                "detail_json": json.dumps(
                    {
                        "codes": ["MANIFEST_SCHEMA_OK", "DISPATCH_KEY_NOT_IN_MANIFEST", "LEGACY_FALLBACK"],
                        "raw_event_name": "WORK_END",
                        "source_file_id": source_file_id,
                        "validation_status": "DENY",
                    }
                ),
                "observed_at": "2026-07-04T00:00:00Z",
            }
        ],
    )
    relay_status_path = _write_json(
        tmp_path / "relay-status.json",
        {
            "status": "operator_review",
            "queue": {"counts": {"acked": 5, "operator_review": 1}},
            "last_result": {"dead_letter_counts": {"operator_review": 1}},
        },
    )

    report = build_report([case_path], quarantine_path, relay_status_path)
    rendered = render_markdown(report)
    case = report["cases"][0]

    assert report["summary"]["relay_queue_counts"] == {"acked": 5, "operator_review": 1}
    assert case["classification"] == "manifest_mismatch"
    assert case["final_action_required"] == "repair_manifest_or_signoff_historical_test_artifact"
    assert case["retry_allowed"] is False
    assert case["ack_allowed"] is False
    assert "DISPATCH_KEY_NOT_IN_MANIFEST" in rendered
    assert "Policy: this report is read-only" in rendered
