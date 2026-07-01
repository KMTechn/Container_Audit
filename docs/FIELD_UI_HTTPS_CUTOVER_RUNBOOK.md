# Container_Audit Field UI And HTTPS Cutover Runbook

작성일: 2026-06-24
대상: 이적실 `Container_Audit`

이 문서는 로컬/headless 테스트 이후, 실제 작업자와 스캐너가 있는 현장에서 수행할 수 있는 검증 절차다. 새 배포 버전은 Syncthing 없이 `%LOCALAPPDATA%\KMTech\ContainerAudit\events`에 먼저 저장하고 HTTPS direct-sync가 그 폴더를 업로드한다. PC별 수동 승인은 설치 시 self-enrollment로 대체하지만, 운영 HTTPS endpoint, 운영 DB, 레거시 archive/Syncthing 경로 변경은 배포 단위 승인 전까지 수행하지 않는다.

## Entry Gates

- 담당자, 테스트 시간대, 대상 PC 목록, 롤백 담당자, 백업 위치가 확정되어야 한다.
- 운영 데이터가 아닌 격리된 test endpoint와 테스트 DB가 준비되어야 한다.
- 테스트 전 각 PC의 `config/container_audit_settings.json`, `%LOCALAPPDATA%\KMTech\ContainerAudit` 데이터 루트, direct-sync credential, producer manifest, runtime status path를 백업한다.
- direct-sync `--scan-source-dir`는 새 로컬 `events` 폴더만 가리켜야 하며 `C:\Sync` 또는 Syncthing 공유 폴더를 스캔 소스로 지정하지 않는다.
- 배포용 enrollment token은 설치 패키지/환경으로 제공하며, 각 PC는 `register_container_audit_worker_pc.py --self-enroll`로 PC별 identity와 HMAC key를 자동 등록한다. 이 token은 PC별 승인 절차가 아니라 배포 묶음의 설치 권한이다.
- `direct_sync_relay_install_pack.py --apply`는 승인된 배포 묶음에서 실행한다. PC별 별도 key 발급/승인은 요구하지 않는다.
- Syncthing 제거 검증은 HTTPS 수신 성공, downstream projection 확인, no-double-count 확인 후에만 다음 단계로 진행한다.

## 2026-06-25 One-PC Canary Notes

- 이 PC는 `source_host_id=container-audit-desktop-03pcrd7`, `producer_install_id=container-audit-desktop-03pcrd7-30560f929982`로 self-enroll 등록됐다.
- Windows task `direct-sync-relay-container-audit`는 `%LOCALAPPDATA%\KMTech\ContainerAudit\direct_sync\bin\direct-sync-relay-container-audit.cmd` wrapper를 실행하며 마지막 확인 시 `Last Result=0`, operator status `PASS`, queue `acked=3`다.
- 검증용 이전 CSV/queue/spool/status는 삭제하지 않고 `%LOCALAPPDATA%\KMTech\ContainerAudit\direct_sync\evidence\validation-archive-*` 아래로 보존 이동했다.
- 운영 DB에서 request `b05b28ab-c787-432f-a380-36f0c098fa1e`는 `inserted=1`, `quarantined=0`, source identity populated, source_claim/common projection/summary 생성까지 확인됐다.
- 검증 중 발견된 server-side 결함: 같은 PC에서 같은 item_code의 다른 master label 트레이가 `LEGACY_REPLAY_CONFLICT`가 되는 문제, receipt source identity가 비어 저장되는 문제. live server는 백업 후 최소 패치했고 로컬 회귀 테스트를 추가했다.
- 검증 중 발견된 release-side 결함: 배포 ZIP이 `storage_policy.py`, `storage_utils.py`, `register_container_audit_worker_pc.py`를 필수 파일로 요구하지 않았고, relay scheduled task가 별도 Python 설치에 의존할 수 있었다. release/CI workflow와 update archive 계약은 이제 self-enroll 도구, 저장정책 모듈, `Container_Audit_DirectSync_Relay.exe`, `Container_Audit_DirectSync_Install.exe`, `Container_Audit_Worker_PC_Register.exe`를 필수로 요구하며, `direct_sync_relay_install_pack.py`는 bundled relay exe가 있으면 Python 스크립트 방식 대신 exe를 scheduled task wrapper에 넣는다.
- 검증 중 발견된 field-security 결함: self-enroll token을 임의 URL로 전송할 수 있었고, production apply에서 raw credential secret을 허용할 수 있었으며, manifest/credential/report/DPAPI secret 경로가 Syncthing 폴더를 가리킬 수 있었다. 이제 enrollment URL은 HTTPS same-origin `/api/producer-ingest/v1/enroll`만 허용하고, apply는 `secret_ref` credential만 허용하며, 명시 출력/secret 경로가 `C:\Sync` 하위이면 차단한다. 작업자 이름은 CSV formula/control 문자 시작값도 등록 단계에서 거부한다.
- 릴리스 패키지 로컬 검증: release/update/install/register/runtime/storage 보안 회귀는 193 passed. worker registry 계약 회귀는 12 passed. relay runtime/operator/runner 회귀는 113 passed. 20PC 가상 enqueue와 field runbook 회귀는 5 passed. 임시 PyInstaller smoke에서 `Container_Audit_DirectSync_Relay.exe`, `Container_Audit_DirectSync_Install.exe`, `Container_Audit_Worker_PC_Register.exe` 3개 모두 build 및 `--help` exit code 0을 확인했다.
- downstream 검증 중 발견된 결함: HTTPS direct ingest는 common projection에 들어갔지만 `WorkerAnalysisGUI-web`의 legacy `/api/data`, `/api/realtime`, `/api/trace`, `/api/session_barcodes`, export 경로가 `sessions/raw_events`만 읽어 direct-sync-only DB에서 비어 보이거나 500이 날 수 있었다. `PROJECTION_API_READ_ENABLED=1`일 때 Container_Audit `TRAY_COMPLETE` projection을 legacy session shape로 fallback 제공하고, barcode trace/WID trace/session barcode detail도 projection fallback을 사용하도록 보강했다. production systemd drop-in template도 이 flag를 포함하도록 보강했다. 관련 web 회귀는 90 passed, common projection subset은 6 passed, production template guard는 5 passed.
- 2026-06-25 16:50 KST 추가 canary: 이 PC의 로컬 `%LOCALAPPDATA%\KMTech\ContainerAudit\events` 폴더에 `CODEX_INSTALL_E2E_20260625165019` 테스트 작업 CSV를 생성하고 Windows task를 즉시 실행했다. task `LastTaskResult=0`, relay row `relay-20dc5964e8764a079d8b9a7da8d09093`는 `acked`, receipt request `a30cad4f-ecc6-4874-876f-19872bf0931d`는 `accepted`, totals `inserted=1`, `quarantined=0`, `errors=0`였다. 서버 `/health/ingest`는 이후 `common_ingested_events=76`, `common_event_quarantine=46`, `common_ingest_write_enabled=true`, `projection_api_read_enabled=true`, `common_projection_schema=healthy`를 반환했다. 같은 파일을 다시 스캔해도 `CODEX_INSTALL_E2E` queue row는 1개로 유지되고 scan status는 `scan_no_new_rows`라 로컬 중복 재전송은 발생하지 않았다.
- 2026-06-26 00:02 KST 운영 DB read-only 재검증: `ssh company-server`에서 `/mnt/rebuild/worker-analysis/data/worker_analysis.db`를 SQLite `mode=ro`/`PRAGMA query_only=ON`으로 열어 raw payload 없이 확인했다. `direct_sync_ops_status.py`는 `status=PASS`, missing tables 없음, `producer_ingest_receipts=24`, nonce ledger `37`, source_claim `15`, `common_ingested_events=80`, `common_event_quarantine=46`, `transfer_legacy_projection=8`, `process_state_summary=18`을 반환했다. canary request `a30cad4f-ecc6-4874-876f-19872bf0931d`는 raw artifact 1건, source_claim `direct_receipted` 1건, common `TRAY_COMPLETE` 1건, transfer projection 1건, quarantine 0건으로 연결됐다. 저장 증거는 `C:\company\program\WorkerAnalysisGUI-web\outputs\direct-sync-p0-p2-20260625\current_recheck_20260625_0002kst` 아래에 있다.
- HTTPS edge 확인: `worker.kmtecherp.com` DNS는 Cloudflare 주소를 반환했고, `/health/ingest` TLS 인증서는 `CN=kmtecherp.com`, issuer `Google Trust Services WE1`, HTTP status 200이었다. 2026-06-26 00:02 KST 재확인한 public `/health/ingest`는 `status=healthy`, `schema_ready=true`, `common_ingested_events=80`, `common_event_quarantine=46`, `process_state_summary=18`로 운영 DB read-only count와 일치했다.
- 인증 downstream API 재검증: 2026-06-26 00:35 KST 운영 web 서버를 최신 projection/session fallback과 no-Syncthing dashboard copy로 갱신했다. 서버 내부 인증 probe는 접근 코드를 evidence에 출력하지 않고 `/` 문구가 `로컬 저장소 + HTTPS direct-sync`이며 `C:\Sync`를 포함하지 않음을 확인했다. `/api/data` 당일 이적실 조회는 canary row 1건을 포함했고, selected worker `CODEX_INSTALL_E2E_20260625165019` 조회도 1건만 반환했다. `/api/trace` barcode 조회는 `total_count=1`, `/dashboard/api/barcode_trace`는 transfer projection 1건, `/dashboard/api/bundle_trace?bundle_id=CODEX-INSTALL-E2E-20260625165019`는 WID 기반 transfer projection을 반환했다. 증거 파일은 `C:\company\program\WorkerAnalysisGUI-web\outputs\direct-sync-p0-p2-20260625\current_recheck_20260625_0002kst\server_authenticated_downstream_post_wid_bundle_trace_probe.json`이다. 이 검증은 서버/API 경로 proof이며, 실제 브라우저 화면에서 당일/과거/summary/export/trace를 사람이 확인하는 field-screen signoff는 여전히 필요하다.
- 2026-06-26 01:54 KST 임시 IP 탐색 창: 운영 서버 self-enroll allowlist를 `0.0.0.0/0,::/0`로 열고 nginx producer endpoint 전용 access log에 `CF-Connecting-IP`/`X-Forwarded-For`를 기록하도록 설정했다. 이 PC는 enrollment token 없이 `server_ip_allowlist` 모드로 self-enroll PASS했고, 캡처된 실제 접속 IP는 nginx log 기준 `cf=114.204.147.29`, `xff=114.204.147.29`였다. 증거 파일은 `C:\company\program\Container_Audit\.tmp\self-enroll-open-ip-capture-20260626\worker_pc_registration_no_token_open_allowlist.json`이다. 이 상태는 IP 수집용 임시 상태이며, 배포 승인 전에는 실제 작업자/VPN CIDR로 닫아야 한다.
- 보조 모니터 UI/scanner 검증: 기본 offscreen geometry `1600x900-32000-32000` 캡처는 흰 화면만 저장되어 UI evidence로 폐기했다. 이후 실제 보조 모니터 `1600x900+3880+366`에서 `tools/run_container_audit_ui_validation.py`를 실행했고, report `C:\company\program\Container_Audit\.tmp\ui-validation-secondary-20260625-165416\ui_validation_report.json`는 `PASS`였다. 스크린샷 7장(`login`, `work-start`, `master-label`, `product-scan-1`, `product-scan-2`, `internal-test-log`, `final-state`)은 1600x900 유효 픽셀로 확인했다. 임시 로컬 데이터 루트의 CSV는 7 rows이고 events는 `WORK_START=1`, `MASTER_LABEL_SCANNED_NEW=1`, `SCAN_OK=2`, `TRAY_COMPLETE=2`, `RANDOM_TEST_SESSION_START=1`였다. 이 검증은 실제 스캐너 하드웨어가 아니라 UI 입력 시뮬레이션이므로, 현장 스캐너 sweep은 별도 P0로 남는다.
- 이 canary는 Syncthing을 제거해도 된다는 승인으로 간주하지 않는다. 20PC 동시성, Syncthing shadow no-double-count, 실제 스캐너 UI 전체 시나리오, rollback rehearsal, downstream 화면 검증은 별도 승인된 window에서 계속 필요하다.

## 2026-06-29 This-PC Worker Registration Recheck

- 이 PC `DESKTOP-03PCRD7`는 기존 서버 등록 identity로 재확인했다. `source_host_id=container-audit-desktop-03pcrd7`, `producer_install_id=container-audit-desktop-03pcrd7-30560f929982`, `producer_id=container-audit-desktop-03pcrd7`, `key_id=pending-server-key-desktop-03pcrd7`다.
- 새 임시 install id `container-audit-desktop-03pcrd7-local`로 self-enroll을 시도했을 때 서버가 `producer_identity_conflict`로 거부했다. 따라서 임시 identity는 사용하지 않고, 2026-06-25 canary에서 이미 등록된 기존 identity로 manifest와 credential reference를 복구했다.
- self-enroll 재확인 결과는 `SELF_ENROLLMENT_REGISTERED`, `enrollment_status=already_enrolled`, `server_registration_verified=true`, `secret_bootstrap_verified=true`, `raw_secret_written=false`다. 증거는 `C:\company\program\_e2e_artifacts\this_pc_worker_registration_20260629\container_audit_worker_pc_registration_existing_identity_self_enroll.json`이다.
- 로컬 manifest는 `%LOCALAPPDATA%\KMTech\ContainerAudit\direct_sync\producer_manifest.json`, credential reference는 `%LOCALAPPDATA%\KMTech\ContainerAudit\direct_sync\credential.json`에 있다. credential JSON에는 `wincred:KMTech.DirectSync.ContainerAudit.desktop-03pcrd7` 참조만 있고 원시 secret은 저장하지 않는다.
- Windows task `direct-sync-relay-container-audit`는 존재하고 `Ready` 상태다. 다만 실제 task wrapper가 쓰는 queue DB 기준 operator status는 `BLOCKED`다. queue count는 `acked=3`, `operator_review=1`이며, 증거는 `C:\company\program\_e2e_artifacts\this_pc_worker_registration_20260629\container_audit_operator_status_after_registration_actual_queue.json`이다.
- `operator_review` 1건은 2026-06-26 기존 relay row `relay-7adba429408b49788121c765702b8598`이다. 서버 receipt는 `accepted`, `committed=true`였지만 totals가 `inserted=0`, `quarantined=3`이라 자동 PASS 처리나 임의 재시도/삭제 대상이 아니다. 서버 DB read-only 재확인에서는 raw artifact 1건, source_claim 0건, common event 0건, quarantine reason `MANIFEST_EVENT_VALIDATION_FAILED` 3건이었다. 증거는 `C:\company\program\_e2e_artifacts\this_pc_worker_registration_20260629\container_audit_operator_review_server_readonly_summary.json`이다.
- 이 항목으로 닫힌 것은 "이 PC의 Container_Audit 작업자 PC identity 등록 및 secret bootstrap"뿐이다. P0 field gate, 20PC 증거, direct+legacy no-double-count, rollback, Syncthing retirement는 계속 별도 차단이다.

## PC 준비

1. 각 PC에서 앱 버전, PC hostname, 자동 생성된 source_host_id, producer_install_id, 작업자 이름을 기록한다.
2. 각 PC의 local data root, events 폴더, runtime status 파일 경로와 operator pause 파일 경로를 확인한다.
3. `direct_sync_relay_operator.py status --runtime-status-path <status.json>` 보고서를 저장한다.
4. relay가 pause 상태이면 사유와 operator id를 기록하고, 테스트 승인 전 resume하지 않는다.
5. self-enroll 응답 secret은 WinCred에만 저장되어야 하며 raw secret을 화면 공유, manifest, credential JSON, report 로그에 노출하지 않는다.

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
6. Syncthing/archive ingest와 HTTPS ingest를 dual-run할 경우 legacy archive와 새 local events 경로가 분리되어야 하며, 같은 source event가 두 번 process summary에 반영되지 않아야 한다.

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
- 레거시 archive/Syncthing 경로와 HTTPS/API가 동시에 같은 이벤트를 중복 반영하면 Syncthing 제거를 보류한다.

## Evidence Pack

- PC 목록과 source identity 표
- UI scenario별 시작/종료 시간, 작업자, 로그 파일명
- 각 PC의 CSV 파일 hash와 row count
- relay DB queue counts와 runtime status JSON
- operator status report JSON
- HTTPS receipt JSON
- downstream DB query 결과 또는 dashboard export
- rollback 여부와 최종 승인자
