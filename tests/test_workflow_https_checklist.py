from pathlib import Path


DOC = Path(__file__).resolve().parents[1] / "docs" / "WORKFLOW_UIUX_HTTPS_E2E_CHECKLIST.md"


def _doc_text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_workflow_https_checklist_exists_and_covers_primary_scenarios():
    text = _doc_text()

    required_ids = [
        "LOGIN-001",
        "LOGIN-002",
        "LOGIN-003",
        "SCAN-001",
        "SCAN-002",
        "SCAN-003",
        "SCAN-004",
        "BTN-UNDO",
        "BTN-RESET",
        "BTN-PARK",
        "BTN-RESTORE",
        "BTN-SUBMIT",
        "AUTO-COMPLETE",
        "REPL-001",
        "REPL-002",
        "EXCH-001",
        "EXCH-002",
        "CLOSE-001",
        "IDLE-001",
        "UPDATE-001",
    ]

    missing = [scenario_id for scenario_id in required_ids if scenario_id not in text]
    assert missing == []


def test_workflow_https_checklist_tracks_actual_ui_callbacks_and_sync_runtime():
    text = _doc_text()

    required_code_refs = [
        "register_worker_from_login",
        "start_work",
        "change_worker",
        "process_barcode",
        "decide_product_scan",
        "undo_last_scan",
        "reset_current_work",
        "park_current_tray",
        "restore_parked_tray",
        "submit_current_tray",
        "complete_tray",
        "initiate_master_label_replacement",
        "_finalize_replacement",
        "show_exchange_dialog",
        "_complete_exchange",
        "_cancel_exchange",
        "validate_endpoint_url",
        "enqueue_completed_source_file",
        "run_relay_once",
        "direct_sync_relay_operator.py status --runtime-status-path",
    ]

    missing = [ref for ref in required_code_refs if ref not in text]
    assert missing == []


def test_workflow_https_checklist_preserves_no_live_side_effect_gate():
    text = _doc_text()

    required_safety_phrases = [
        "Do not run against live `C:\\Sync`",
        "No live production DB mutation",
        "production HTTPS endpoint",
        "direct_sync_relay_install_pack.py --apply",
    ]

    missing = [phrase for phrase in required_safety_phrases if phrase not in text]
    assert missing == []


def test_workflow_https_checklist_includes_downstream_and_dual_run_requirements():
    text = _doc_text()

    required_contracts = [
        "timestamp,worker_name,event,details",
        "container_audit|legacy_transfer_csv|TRAY_COMPLETE",
        "MASTER_LABEL_REPLACEMENT_APPLIED",
        "WorkerAnalysisGUI-web",
        "plan_b_projection",
        "Dual-run validation",
        "Syncthing remains legacy compatibility/archive",
        "HTTPS direct ingest",
    ]

    missing = [contract for contract in required_contracts if contract not in text]
    assert missing == []
