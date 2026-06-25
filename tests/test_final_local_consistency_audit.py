from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "FINAL_LOCAL_CONSISTENCY_AUDIT_20260625.md"
LOCAL_REPORT = ROOT / "docs" / "LOCAL_AUDIT_READINESS_REPORT_20260624.md"
MATRIX = ROOT / "docs" / "PRE_PRODUCTION_VALIDATION_MATRIX_20260625.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_final_local_consistency_audit_records_current_authority_and_gates():
    text = _text(DOC)

    required = [
        "production-cutover-packet-v5-20260625",
        "40AD1FAE1AE540D9E1906327DBD853374868B904F1854731A33D738FB9B9C1A4",
        "797 passed, 1 warning",
        "98 passed",
        "validate_handoff.py",
        "run_decision=continue",
        "loop_state=execution",
        "stop_authorization_status=deny",
    ]

    assert [item for item in required if item not in text] == []


def test_final_local_consistency_audit_marks_legacy_packet_refs_as_history_only():
    text = _text(DOC)

    required = [
        "earlier pre-v5 packet batches",
        "historical_only batch log evidence",
        "not the current scaffold",
        "v2/v3/v4 current scaffold claims are stale",
    ]

    assert [item for item in required if item not in text] == []


def test_current_docs_use_v4_not_legacy_packet_as_authority():
    combined = "\n".join(_text(path) for path in [DOC, LOCAL_REPORT, MATRIX])

    forbidden_current_claims = [
        "v" + "2 evidence packet",
        "production-cutover-packet-v" + "3-20260625",
        "v" + "3 evidence archive hash",
    ]

    assert "production-cutover-packet-v5-20260625" in combined
    assert [claim for claim in forbidden_current_claims if claim in combined] == []


def test_final_local_consistency_audit_preserves_no_side_effect_boundary():
    text = _text(DOC)

    required = [
        "did not run producer POST",
        "did not mutate production/staging DB state",
        "did not run schema `--execute`",
        "did not issue/rotate/revoke producer credentials",
        "did not stop/start scheduled tasks or services",
        "did not pause/resume the relay",
        "did not change or remove Syncthing",
    ]

    assert [item for item in required if item not in text] == []


def test_final_local_consistency_audit_records_loop_defects_and_remaining_blockers():
    text = _text(DOC)

    required = [
        "receipt_only_final_boundary_perceived_stop",
        "event_type=usage_limit",
        "denied terminal production goal completion",
        "current authority is not stale",
        "Approved staging/test HTTPS endpoint",
        "PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md",
        "Operational DB owner approval",
        "Real worker PC/scanner UI run",
        "Minimum 20 real/VM PC concurrent send",
        "Downstream WorkerAnalysisGUI-web or actual receiving program evidence",
        "Syncthing shadow run",
        "rollback rehearsal",
        "operator visibility acceptance",
        "4-8 hour/full-day-volume soak/security",
        "promotion_allowed=true",
        "production_removal_ready=true",
    ]

    assert [item for item in required if item not in text] == []
