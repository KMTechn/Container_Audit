from pathlib import Path


RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md"


def _runbook_text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_field_runbook_covers_human_ui_button_and_scanner_scenarios():
    text = _runbook_text()

    required = [
        "UI-LOGIN-01",
        "UI-SCAN-01",
        "UI-SCAN-03",
        "UI-BTN-01",
        "UI-BTN-02",
        "UI-BTN-03",
        "UI-BTN-04",
        "UI-AUTO-01",
        "UI-REPL-01",
        "UI-EXCH-01",
        "UI-CLOSE-01",
    ]

    assert [item for item in required if item not in text] == []


def test_field_runbook_covers_https_runtime_and_cutover_gates():
    text = _runbook_text()

    required = [
        "HTTPS-ENQ-01",
        "HTTPS-ACK-01",
        "HTTPS-RETRY-01",
        "HTTPS-REVIEW-01",
        "HTTPS-PAUSE-01",
        "HTTPS-BACKPRESSURE-01",
        "HTTPS-DISK-01",
        "direct_sync_relay_operator.py status --runtime-status-path",
        "Syncthing 제거",
        "no-double-count",
        "P0 cutover gate",
        "최소 20대 실제/VM PC",
        "큐 재시작 후 resume",
    ]

    assert [item for item in required if item not in text] == []


def test_field_runbook_keeps_live_side_effects_behind_explicit_approval():
    text = _runbook_text()

    required = [
        "운영 HTTPS endpoint, 운영 DB, 레거시 archive/Syncthing 경로 변경은 배포 단위 승인 전까지 수행하지 않는다",
        "PC별 수동 승인은 설치 시 self-enrollment로 대체",
        "PC별 별도 key 발급/승인은 요구하지 않는다",
        "direct-sync `--scan-source-dir`는 새 로컬 `events` 폴더만 가리켜야 하며 `C:\\Sync` 또는 Syncthing 공유 폴더를 스캔 소스로 지정하지 않는다",
        "direct_sync_relay_install_pack.py --apply",
        "test endpoint",
        "Stop And Rollback Triggers",
        "Evidence Pack",
    ]

    assert [item for item in required if item not in text] == []


def test_field_runbook_covers_downstream_projection_evidence():
    text = _runbook_text()

    required = [
        "WorkerAnalysisGUI-web",
        "container_audit|legacy_transfer_csv|TRAY_COMPLETE",
        "TRANSFER_LEGACY",
        "process_key=transfer",
        "state_key=packaging_waiting",
        "legacy desktop `WorkerAnalysisGUI`",
    ]

    assert [item for item in required if item not in text] == []
