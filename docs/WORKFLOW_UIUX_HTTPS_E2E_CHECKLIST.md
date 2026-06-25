# Container_Audit Workflow, UI/UX, And HTTPS E2E Checklist

작성일: 2026-06-24
대상: 이적실 `Container_Audit`

이 문서는 실제 작업자가 현장에서 쓰는 버튼/스캔 흐름과 서버 전송 전환을 함께 검증하기 위한 체크리스트다. 기본 원칙은 live `C:\Sync`, production HTTPS endpoint, production DB를 직접 건드리지 않고 temp-root/headless/fixture 검증을 먼저 통과시키는 것이다.

## Safety Rules

- Do not run against live `C:\Sync` unless the field PC, operator, backup, rollback, and test window are explicitly approved.
- Do not run `python Container_Audit.py` as an automated test on an operational PC.
- Do not run `_RUN_AUTO_TEST_`, `TEST_LOG_*`, or parked-tray test commands in a live GUI session.
- Do not run `direct_sync_relay_install_pack.py --apply` or mutate a scheduled task without explicit production approval.
- Use fixture directories, temp SQLite DBs, fake credentials, fake sessions, and dry-run reports before any live HTTPS or production DB test.
- No live production DB mutation is allowed during local verification.

## Human Workflow Scenario Matrix

| ID | Scenario | Primary UI/code entry | Expected evidence | Automation status |
| --- | --- | --- | --- | --- |
| LOGIN-001 | New worker registration from login screen | `register_worker_from_login` | Worker registry accepts a normalized unique name; no active tray is created. | headless contract |
| LOGIN-002 | Existing worker starts work | `start_work` | Log path resolves to `이적작업이벤트로그_[worker]_[date].csv`; session history loads. | headless contract |
| LOGIN-003 | Worker changes while current tray is active | `change_worker` | Active tray is offered for save/delete; no silent data loss. | headless plus manual dialog |
| SCAN-001 | New QR master label starts tray | `process_barcode`, `_process_barcode_logic` | Item code and quantity parse from QR; current tray state is saved before `MASTER_LABEL_SCANNED_NEW` is logged. | headless contract |
| SCAN-002 | Legacy item-code master label starts tray | `process_barcode`, `_process_barcode_logic` | 13-character item code maps through `assets/Item.csv`; state and log ordering match QR flow. | headless contract |
| SCAN-003 | Product barcode accepted | `process_barcode`, `decide_product_scan`, `build_scan_ok_detail` | State save succeeds before `SCAN_OK`; UI count increments; success sound is non-critical. | headless contract plus manual scanner |
| SCAN-004 | Product barcode rejected for format, mismatch, duplicate, or full tray | `decide_product_scan`, `show_fullscreen_warning` | `SCAN_FAIL_*` detail includes expected/scanned data; warning is visible and focus returns. | headless plus manual UI |
| BTN-UNDO | Last scan is undone | `undo_last_scan` | State rollback preserves old scan if save or audit log fails. | headless contract |
| BTN-RESET | Current work is reset | `reset_current_work` | State deletion and `TRAY_RESET` log are ordered so failures preserve current work. | headless contract |
| BTN-PARK | Current tray is parked | `park_current_tray` | Parked state is saved under `config/parked_trays`; current state delete/log rollback is safe. | headless contract |
| BTN-RESTORE | Parked tray is restored by double-click | `on_parked_tray_select`, `restore_parked_tray` | Path stays inside parked directory; invalid/foreign/completed trays are rejected or quarantined. | headless contract plus manual UI |
| BTN-SUBMIT | Partial tray is submitted manually | `submit_current_tray`, `_complete_current_tray_as_partial`, `complete_tray` | `TRAY_COMPLETE` includes `is_partial_submission=true` and barcode list. | headless contract |
| AUTO-COMPLETE | Tray reaches target quantity | `complete_tray`, `build_tray_complete_detail` | `TRAY_COMPLETE` is synchronously durable before UI reset and state deletion. | headless contract |
| REPL-001 | Completed master label replacement same quantity | `initiate_master_label_replacement`, `_finalize_replacement` | Append-only `MASTER_LABEL_REPLACEMENT_APPLIED` supersedes source identity without rewriting raw completion. | headless contract |
| REPL-002 | Completed master label replacement changed quantity | `_handle_additional_item_scan`, `_handle_removed_item_scan`, `_finalize_replacement` | Added/removed product barcodes match new quantity and item code. | headless contract |
| EXCH-001 | Product exchange dialog completes one or more pairs | `show_exchange_dialog`, `_process_exchange_scan`, `_complete_exchange` | `PRODUCT_EXCHANGE_COMPLETED` includes defective/good pairs and evidence hash. | headless contract plus manual dialog |
| EXCH-002 | Product exchange is canceled | `_cancel_exchange` | Cancel event is logged when needed; no partial exchange is projected as complete. | headless contract |
| CLOSE-001 | App closes while tray is active | `on_closing` | Operator chooses save/delete/cancel; failures keep app open or restore state. | headless plus manual dialog |
| IDLE-001 | Worker is idle and resumes | `_check_for_idle`, `_wakeup_from_idle` | Idle time is tracked and included in completion detail. | headless contract plus manual timing |
| UPDATE-001 | Release-mode updater checks for updates | `check_and_apply_updates` | Source mode skips network; release mode requires checksum-bound asset. | unit contract |

## Data Contract Checklist

- Raw CSV header must remain `timestamp,worker_name,event,details`.
- `TRAY_COMPLETE` must include `master_label_code`, `item_code`, `scan_count`, `tray_capacity`, `scanned_product_barcodes`, `product_barcodes`, `work_time_sec`, `error_count`, `total_idle_seconds`, `has_error_or_reset`, `is_partial_submission`, `is_restored_session`, and `is_test_tray`.
- Every details payload must preserve `source_system=container_audit`, `source_transport_or_dataset=legacy_transfer_csv`, `raw_event_name`, `canonical_event_name`, and `dispatch_key`.
- `MASTER_LABEL_REPLACEMENT_APPLIED` must carry source row identity, old/new payload hash, supersedes identity, corrected completion projection, and operator.
- Downstream projection must treat `container_audit|legacy_transfer_csv|TRAY_COMPLETE` separately from packaging `TRAY_COMPLETE`.
- Events not projected into stock/process state must still be raw-auditable or explicitly quarantined.

## Multi-PC And File Integrity Checklist

- Two app instances with the same worker/date must not corrupt a CSV row; if this cannot be guaranteed locally, document the operational rule and server quarantine behavior.
- Distinct PCs must use distinct current state file names; `uuid.getnode()` and hostname fallback collision cases need a fixture or field policy.
- Syncthing conflict-style files must be ignored or quarantined by server/downstream ingestion.
- Appending while a relay scan runs must preserve complete rows only: file-age grace, stable header, byte range, prefix hash, truncation detection, and delta reset must be covered.
- BOM, CRLF, and multiline JSON `details` rows must remain one CSV row.

## HTTPS Direct Communication Checklist

- `validate_endpoint_url` must require HTTPS, the expected endpoint path, no URL username/password, no query/fragment, no localhost, and no private/link-local/reserved targets for production.
- `enqueue_completed_source_file` must spool source files or deltas without storing raw secrets or request signatures.
- `run_relay_once` must handle retryable failures, committed receipts, malformed receipts, lost ACK retry, stale leases, disk pressure, queue backpressure, and operator pause.
- Request signing must bind producer id, key id, canonical request, content hash, byte length, source file identity, and metadata.
- HTTPS direct ingest must be tested as primary target while Syncthing remains legacy compatibility/archive during migration.
- Dual-run validation must prove the same source events through Syncthing/archive and HTTPS/API do not double count.
- Server receipt must include enough identity for downstream DB idempotency and operator reconciliation.
- Operator-visible status must cover credential failure, endpoint failure, paused relay, backpressure, permanent failure, and operator-review rows.
- `direct_sync_relay_operator.py status --runtime-status-path` must surface the relay runtime status and last upload result in the same operator report.

## Downstream Consumer Checklist

- `WorkerAnalysisGUI` desktop analysis must still parse current `이적작업이벤트로그_*` files and `TRAY_COMPLETE`.
- `WorkerAnalysisGUI-web` producer ingest and common projection tests must accept Container_Audit source identity and completion events.
- `plan_b_projection` must keep dispatch keys for `container_audit|legacy_transfer_csv|TRAY_COMPLETE` and `MASTER_LABEL_REPLACEMENT_APPLIED`.
- Replacement correction must project the corrected completion without poisoning the original raw event archive.
- Product exchange, reset, park, idle, and scan-fail events need explicit raw-only vs projected behavior.
