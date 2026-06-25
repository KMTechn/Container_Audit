# Container_Audit Field UI And HTTPS Cutover Runbook

작성일: 2026-06-24
대상: 이적실 `Container_Audit`

이 문서는 로컬/headless 테스트 이후, 실제 작업자와 스캐너가 있는 현장에서 수행할 수 있는 승인 기반 검증 절차다. 운영 `C:\Sync`, 운영 HTTPS endpoint, 운영 DB는 명시 승인 전까지 사용하지 않는다.

## Entry Gates

- 담당자, 테스트 시간대, 대상 PC 목록, 롤백 담당자, 백업 위치가 확정되어야 한다.
- 운영 데이터가 아닌 격리된 test endpoint와 테스트 DB가 준비되어야 한다.
- 테스트 전 각 PC의 `config/container_audit_settings.json`, 작업 로그 폴더, direct-sync credential, producer manifest, runtime status path를 백업한다.
- `direct_sync_relay_install_pack.py --apply`는 별도 production install 승인 없이는 실행하지 않는다.
- Syncthing 제거 검증은 HTTPS 수신 성공, downstream projection 확인, no-double-count 확인 후에만 다음 단계로 진행한다.

## PC 준비

1. 각 PC에서 앱 버전, PC hostname, source_host_id, producer_install_id, 작업자 이름을 기록한다.
2. 각 PC의 runtime status 파일 경로와 operator pause 파일 경로를 확인한다.
3. `direct_sync_relay_operator.py status --runtime-status-path <status.json>` 보고서를 저장한다.
4. relay가 pause 상태이면 사유와 operator id를 기록하고, 테스트 승인 전 resume하지 않는다.
5. 테스트 endpoint credential은 raw secret을 화면 공유나 로그에 노출하지 않는다.

## Human UI Scenarios

| Step | Scenario | Required operator action | Expected evidence |
| --- | --- | --- | --- |
| UI-LOGIN-01 | 신규 작업자 등록 | 로그인 화면에서 작업자 등록 버튼 사용 | 작업자 목록에 정규화된 이름 추가, 활성 tray 없음 |
| UI-LOGIN-02 | 기존 작업자 시작 | 작업자 선택 후 작업 시작 | 당일 `이적작업이벤트로그_[worker]_[date].csv` 생성 |
| UI-SCAN-01 | QR master label 스캔 | 실제 스캐너로 QR master label 입력 | 품목/수량 표시, `MASTER_LABEL_SCANNED_NEW` 로그 |
| UI-SCAN-02 | 제품 바코드 정상 스캔 | 같은 품목 제품 바코드 순차 입력 | 카운트 증가, `SCAN_OK` details에 product barcode |
| UI-SCAN-03 | 오류 바코드 스캔 | 다른 품목, 중복, 형식 오류를 각각 입력 | fullscreen warning, `SCAN_FAIL_*` 로그, focus 복귀 |
| UI-BTN-01 | Undo | Undo 버튼 클릭 | 마지막 scan만 제거, `SCAN_UNDONE` 로그 |
| UI-BTN-02 | Reset | Reset 버튼 클릭 후 확인 | 현재 tray 초기화, `TRAY_RESET` 로그 |
| UI-BTN-03 | Park/Restore | 작업 보관 후 보관 목록 더블클릭 복원 | parked file 생성/삭제, `TRAY_RESTORED_FROM_PARK` 로그 |
| UI-BTN-04 | Partial submit | 일부 수량 상태에서 submit 버튼 클릭 | `TRAY_COMPLETE`에 `is_partial_submission=true` |
| UI-AUTO-01 | Auto complete | 목표 수량까지 스캔 | `TRAY_COMPLETE` durable write 후 UI reset |
| UI-REPL-01 | Master label replacement | 완료 이력에서 교체 버튼 사용 | `MASTER_LABEL_REPLACEMENT_APPLIED` append-only correction |
| UI-EXCH-01 | Product exchange | 제품 교환 dialog에서 불량/정상 쌍 입력 | `PRODUCT_EXCHANGE_COMPLETED` evidence hash |
| UI-CLOSE-01 | Active tray close | 활성 tray 상태에서 창 닫기 | save/delete/cancel 선택과 결과 기록 |

## HTTPS Direct-Sync Scenarios

| Step | Scenario | Required action | Expected evidence |
| --- | --- | --- | --- |
| HTTPS-ENQ-01 | Completed CSV enqueue | 완료 로그 파일을 relay scan 또는 enqueue로 큐에 등록 | relay DB pending row, spooled file hash, no secret in DB |
| HTTPS-ACK-01 | Test endpoint upload accepted | 테스트 endpoint로 `run_relay_once` 실행 | receipt accepted, `server_source_file_id`, row totals match |
| HTTPS-RETRY-01 | Endpoint 503/retryable failure | 테스트 endpoint가 retryable error 반환 | runtime status `retry_wait`, operator report includes last error |
| HTTPS-REVIEW-01 | Committed with quarantine/error | 테스트 endpoint가 committed but quarantined/errors 반환 | `operator_review`, retry blocked until reconcile |
| HTTPS-PAUSE-01 | Operator pause | pause marker 생성 후 enqueue/scan 실행 | `paused_by_operator`, queue unchanged |
| HTTPS-BACKPRESSURE-01 | Queue backpressure | threshold를 낮춘 테스트 config로 scan 실행 | `blocked_queue_backpressure`, failed source file recorded |
| HTTPS-DISK-01 | Disk pressure guard | 테스트 config에서 min_free_bytes를 크게 설정 | `blocked_disk_pressure`, upload not attempted |

## Multi-PC And No-Double-Count

1. Smoke 단계에서는 최소 2대 PC에서 같은 item_code, 서로 다른 master label로 `TRAY_COMPLETE`를 만든다.
2. P0 cutover gate는 최소 20대 실제/VM PC에서 같은 파일명, 같은 작업자명, 중복 재전송, 네트워크 끊김, 재시도, 큐 재시작 후 resume을 포함해 실행한다.
3. 각 PC의 `source_host_id`, `producer_install_id`, `relative_path`, `content_sha256`를 기록한다.
4. 같은 PC의 동일 파일 재전송은 replay 또는 already-acked로 처리되는지 확인한다.
5. 서로 다른 PC의 동일 파일명은 서로 다른 `server_source_file_id`로 취합되는지 확인한다.
6. Syncthing/archive ingest와 HTTPS ingest를 dual-run할 경우 같은 source event가 두 번 process summary에 반영되지 않아야 한다.

## Downstream Checks

- `WorkerAnalysisGUI-web` common projection에서 `container_audit|legacy_transfer_csv|TRAY_COMPLETE`가 `TRANSFER_LEGACY`로 들어갔는지 확인한다.
- `process_state_summary`에서 `process_key=transfer`, `state_key=packaging_waiting`, item_code별 수량이 실제 product barcode 수와 일치해야 한다.
- packaging `TRAY_COMPLETE`와 transfer `TRAY_COMPLETE`가 같은 reducer로 섞이지 않아야 한다.
- legacy desktop `WorkerAnalysisGUI`가 여전히 CSV archive를 읽어야 하는 단계라면 archive read-only 검증만 수행하고 운영 파일을 수정하지 않는다.

## Stop And Rollback Triggers

- CSV header가 중복되거나 깨진 row가 생기면 즉시 중단한다.
- runtime status 또는 operator report가 credential/endpoint 실패 원인을 보여주지 못하면 cutover를 중단한다.
- server receipt totals가 source row count와 맞지 않으면 중단한다.
- downstream projection 수량이 원본 product barcode 수와 다르면 중단한다.
- live `C:\Sync`와 HTTPS/API가 동시에 같은 이벤트를 중복 반영하면 Syncthing 제거를 보류한다.

## Evidence Pack

- PC 목록과 source identity 표
- UI scenario별 시작/종료 시간, 작업자, 로그 파일명
- 각 PC의 CSV 파일 hash와 row count
- relay DB queue counts와 runtime status JSON
- operator status report JSON
- HTTPS receipt JSON
- downstream DB query 결과 또는 dashboard export
- rollback 여부와 최종 승인자
