# Container_Audit 실제 UI 워크스루 검증 패킷

작성일: 2026-06-27

목적: 테스트 코드가 아니라 실제 프로그램 UI를 처음 쓰는 작업자 관점으로 조작하면서 워크플로우 막힘, 문구 혼란, 데이터 저장 문제를 검증한다.

## 현재 실행 상태

`2026-06-27 21:19 KST` 기준 실제 패키징 exe 대상 무인 UI 정상 작업 플로우는 PASS 증거를 확보했다. 이 판정은 현품표 1건, 제품 2건, 자동 완료까지의 정상 경로에 한정한다.

확인된 실행:

- 실행 방식: `pywinauto` + 실제 Windows 키보드 입력 + 실제 패키징 exe
- 대상 exe: `dist\Container_Audit\Container_Audit.exe`
- 화면 위치: 위쪽 보조 모니터 `1600x900+733-1400`
- 로컬 데이터 루트: `.tmp\real-ui-uia-data-20260627-211915`
- 증거 루트: `.tmp\real-ui-uia-run-20260627-211915`
- 결과: `PASS`
- 이벤트 count: `WORK_START=1`, `MASTER_LABEL_SCANNED_NEW=1`, `SCAN_OK=2`, `TRAY_COMPLETE=1`
- 금지 입력: `_RUN_AUTO_TEST_`, `TEST_LOG_*` 미사용
- 저장 위치: `C:\Sync`가 아닌 격리 로컬 데이터 루트 사용
- 원본 입력값 취급: 자동화 드라이버 증거 JSON에는 작업자명, 현품표, 제품 바코드를 원문으로 남기지 않고 SHA-256/길이 또는 요약만 남긴다.

남은 자동화 제한:

- Computer Use 플러그인 bootstrap이 `@oai/sky` package export 경로 문제로 실패했다.
- workspace 임시 bootstrap으로 import 문제는 우회했지만, `Computer Use native pipe is unavailable` 상태였다.
- invalid master/duplicate/fullscreen warning Toplevel은 메인 hwnd 캡처만으로는 보이지 않아 별도 Toplevel 캡처/닫기 보강이 필요하다.
- undo 버튼 자동화는 아직 실패했다. `SCAN_UNDO`가 남지 않았고 이후 재스캔/완료가 막혔다.
- 신규 작업자 dialog는 자동화가 가능하지만 정상 플로우 안정화를 위해 PASS 실행에서는 `--preseed-worker`로 app-local registry를 준비했다. 설치 즉시 개별식별자 자동 생성 정책 검증과는 분리해서 판정한다.
- 자동 UI 드라이버는 포커스가 대상 프로세스가 아닐 때 스캐너 입력 전송을 중단하도록 보강했다. 그래도 Windows 전역 마우스/키보드 입력을 사용하므로 검증용 보조 모니터와 격리된 환경에서만 사용한다.

확정 대체 방법:

- 실제 작업자/검수자가 프로그램 UI를 직접 조작한다.
- Codex는 UI 입력을 대신하지 않고, 각 단계 완료 시점에 대상 창을 캡처하고 이벤트 CSV count를 취합한다.
- 이 방식은 테스트 harness, `_RUN_AUTO_TEST_`, `TEST_LOG_*`, direct method call을 쓰지 않으므로 "실제 처음 사용자 walkthrough" 증거로 사용할 수 있다.
- `--launch-exe`와 `--data-root`를 함께 쓰면 캡처 스크립트가 실행 프로세스에 `CONTAINER_AUDIT_DATA_ROOT`를 주입한다. 따라서 앱이 기본 경로나 Syncthing 폴더가 아니라 지정한 격리 로컬 데이터 루트에 기록하는지 확인할 수 있다.
- 앱 창은 보조 모니터로 띄운다. 이 PC에서 자동 감지된 보조 모니터 시작 geometry는 `1600x900+2600+366`이다.

실행 명령:

```powershell
python tools\manual_real_ui_walkthrough_capture.py `
  --output-root C:\company\program\Container_Audit\.tmp\real-ui-walkthrough-20260627 `
  --data-root C:\company\program\Container_Audit\.tmp\real-ui-walkthrough-20260627\local-data `
  --window-title-pattern "이적 검사 시스템|Container_Audit|이적실|Audit" `
  --prefer-secondary-monitor `
  --launch-exe C:\company\program\Container_Audit\dist\Container_Audit\Container_Audit.exe
```

운영 방식:

1. 프로그램은 보조 모니터에 뜬다.
2. 검수자는 실제 스캐너/키보드/마우스로 UI를 조작한다.
3. 각 단계 화면이 준비되면 터미널에서 `Enter`를 눌러 캡처한다.
4. 건너뛸 단계는 `skip`, 중단은 `stop`을 입력한다.
5. 결과는 `manual_real_ui_walkthrough_report.json`과 `screenshots/*.png`에 저장한다.

## 검증 환경

- 대상 실행 파일: `C:\company\program\Container_Audit\dist\Container_Audit\Container_Audit.exe`
- 격리 데이터 루트: `C:\company\program\Container_Audit\.tmp\real-ui-walkthrough-20260627\local-data`
- 캡처 폴더: `C:\company\program\Container_Audit\.tmp\real-ui-walkthrough-20260627\screenshots`
- 사용자 페르소나: 이적실 프로그램을 처음 쓰는 비전문가 작업자
- 테스트 작업자명: `UAT_신규작업자_20260627`

## 검증 데이터

정상 현품표 예시:

```text
PHS=1|CLC=AAA2270730200|WID=UAT-WO-REALUI-20260627-001|SPC=A14|FPB=A146000306|OBD=2026-06-27|PJT=KMC_LHD|QT=2
```

정상 제품 바코드:

```text
AAA2270730200-REALUI-20260627-0001
AAA2270730200-REALUI-20260627-0002
```

오류 검증용:

```text
INVALID_MASTER_LABEL_REALUI
ZZZ9999999999-REALUI-MISMATCH-0001
AAA2270730200-REALUI-20260627-0001
```

## P0 필수 실제 UI 시나리오

| ID | 시나리오 | 사용자 행동 | 기대 결과 | 캡처명 | 판정 |
|---|---|---|---|---|---|
| P0-01 | 프로그램 실행 | exe 실행 | 로그인 화면 표시 | `01_launch_login.png` | 대기 |
| P0-02 | 기존/신규 작업자 흐름 | 기존 작업자 선택, 신규 등록, 빈 이름, 위험 문자 이름 입력 | 정상 이름만 등록/시작 가능, 위험 입력은 거부 | `02_worker_register_validation.png` | 대기 |
| P0-03 | 작업 시작 | 작업자명 입력 후 `Enter`와 `작업 시작` 버튼 각각 사용 | 두 방식 모두 메인 대기 화면 표시 | `03_main_waiting.png` | 대기 |
| P0-04 | 현품표 스캔 | 정상 현품표 입력 | 품목/목표수량 표시, 제품 스캔 가능 | `04_master_label_loaded.png` | 대기 |
| P0-05 | 제품 1개 스캔 | 정상 제품 1 입력 | 카운트 `1 / 2`, 목록 추가 | `05_product_scan_1.png` | 대기 |
| P0-06 | 자동 완료 | 정상 제품 2 입력 | 트레이 자동 완료, 다음 현품표 대기 | `06_auto_complete.png` | 대기 |
| P0-07 | 로컬 기록 | events CSV 확인 | WORK_START, MASTER_LABEL_SCANNED_NEW, SCAN_OK, TRAY_COMPLETE 존재 | `07_local_events.png` | 대기 |
| P0-08 | 종료/복구 | 진행 중 트레이 저장 후 재실행 | 복구 안내와 이어하기 가능 | `08_exit_restore.png` | 대기 |
| P0-09 | 레거시 품목코드 시작 | QR이 아닌 13자리 품목코드 입력 | `Item.csv`와 매칭되면 현품표처럼 시작 | `09_legacy_item_code_start.png` | 대기 |
| P0-10 | 완료 내구성 | 자동 완료와 부분 제출 각각 수행 | 금일 현황 반영, 화면 초기화, 다음 현품표 대기, 로컬 이벤트 기록 | `10_completion_durability.png` | 대기 |
| P0-11 | 작업자 변경 | 진행 중 작업 상태에서 `작업자 변경` | 저장 안내, 로그인 복귀, 복구 가능 | `11_change_worker_with_active_tray.png` | 대기 |
| P0-12 | Direct Sync 안내/상태 | 작업 완료 후 relay status 확인 | 로컬 저장 우선, Syncthing 의존 없음, 업로드 대기/성공 상태 식별 가능 | `12_direct_sync_status.png` | 대기 |

## P1 버튼·오류 시나리오

| ID | 시나리오 | 사용자 행동 | 기대 결과 | 캡처명 | 판정 |
|---|---|---|---|---|---|
| P1-01 | 제품을 현품표 전에 스캔 | 제품 바코드 먼저 입력 | 잘못된 형식/현품표 필요 안내 | `09_product_before_master.png` | 대기 |
| P1-02 | 잘못된 현품표 | invalid master 입력 | QR 오류, 다시 스캔 가능 | `10_invalid_master.png` | 대기 |
| P1-03 | 중복 제품 | 같은 제품 재스캔 | 중복 오류, 기존 카운트 유지 | `11_duplicate_product.png` | 대기 |
| P1-04 | 품목 불일치 | mismatch 제품 입력 | 품목 불일치 경고, 기존 카운트 유지 | `12_mismatch_product.png` | 대기 |
| P1-05 | 마지막 스캔 취소 | 제품 1개 후 undo | 카운트 감소, 상태 메시지 표시 | `13_undo_last_scan.png` | 대기 |
| P1-06 | 현재 작업 리셋 | 진행 중 리셋 | 확인창 후 현품표 전 상태 | `14_reset_current_work.png` | 대기 |
| P1-07 | 트레이 보류 | 진행 중 보류 | 보류 목록에 표시, 새 현품표 대기 | `15_park_tray.png` | 대기 |
| P1-08 | 보류 복원 | 보류 목록 더블클릭 | 기존 스캔 상태 복원 | `16_restore_parked_tray.png` | 대기 |
| P1-09 | 수동 제출 | 미달 수량에서 제출 | 확인창 후 부분 트레이 완료 | `17_manual_submit.png` | 대기 |
| P1-10 | 개별 제품 교환 | 교환 버튼, 수량, 불량품/양품 스캔 | 교환 완료 가능 | `18_product_exchange.png` | 대기 |
| P1-11 | 완료 현품표 교체 | 교체 버튼 | 진행 중 작업이 있으면 차단, 없으면 교체 흐름 안내 | `19_master_replacement.png` | 대기 |
| P1-12 | 한글 입력 상태 | 한글 입력 후 스캔 | 입력 모드 오류 또는 복구 가능한 안내 | `20_korean_input_mode.png` | 대기 |
| P1-13 | 7분 유휴 | 활동 없이 대기 | `대기 중` 표시, 다음 스캔 시 재개 | `21_idle_resume.png` | 대기 |
| P1-14 | 화면 배율 | `Ctrl` + 마우스 휠 | 로그인/작업 화면 글자, 버튼, 목록이 깨지지 않고 저장 | `22_zoom_scaling.png` | 대기 |
| P1-15 | 트레이 이미지 보기 | 현품표 후 이미지 체크박스 사용 | 이미지 있으면 표시, 없으면 안내만 표시하고 작업은 계속 가능 | `23_tray_image_toggle.png` | 대기 |
| P1-16 | 필수 파일/업데이트 오류 | `Item.csv` 누락 또는 업데이트 실패 상황 확인 | 작업자가 이해 가능한 오류 메시지 | `24_required_file_update_error.png` | 대기 |

## 금지 사항

실제 운영 PC walkthrough에서는 다음을 사용하지 않는다.

- `_RUN_AUTO_TEST_`
- `TEST_LOG_*`
- parked-tray test command
- 테스트 harness가 직접 앱 메서드를 호출하는 방식

이번 검증은 실제 사용자가 보는 UI와 같은 입력 흐름을 보는 것이 목적이다.

## UX 검수 기준

각 화면에서 다음을 확인한다.

- 처음 보는 작업자가 다음 행동을 이해할 수 있는가
- 스캐너 입력 후 포커스가 유지되는가
- 확인창 문구가 데이터 삭제/변경 위험을 충분히 설명하는가
- 오류 후 기존 스캔 수량이 틀어지지 않는가
- 보류/복구/교환/교체가 일반 작업과 섞여 헷갈리지 않는가
- 캡처 화면만 보고도 교육자료로 쓸 수 있는가

## 결함 기록 형식

| ID | 심각도 | 화면 | 증상 | 기대 | 실제 | 수정 여부 | 재검증 |
|---|---|---|---|---|---|---|---|
| VAL-BLOCK-001 | P0/검증환경 | Codex UI 제어 | Computer Use native pipe unavailable로 Codex가 실제 UI를 직접 조작하지 못함 | 공식 Computer Use 경로로 백그라운드/보조 모니터 조작 가능 | 공식 경로 실패. SendKeys류 우회는 사용 금지 | 수동 조작+자동 캡처 절차 준비 완료. 공식 pipe 복구는 별도 | 수동 walkthrough 캡처 후 PASS/FAIL 재판정 |
| VAL-BLOCK-002 | P1/UI 자동화 | 경고 Toplevel | invalid master/duplicate 경고가 별도 Toplevel로 뜨며 메인 hwnd 캡처/닫기 루틴에서 누락됨 | 경고창도 실제 캡처하고 확인 버튼으로 닫힘 | 정상 플로우 PASS를 위해 경고 시나리오를 분리함 | `find_window`/캡처 대상을 Toplevel까지 포함하도록 개선 필요 | 대기 |
| VAL-BLOCK-003 | P1/UI 자동화 | 마지막 스캔 취소 | undo 버튼 자동 클릭 후 `SCAN_UNDO`가 기록되지 않음 | 제품 1개 스캔 후 undo, 재스캔, 제품2 스캔, 완료까지 진행 | `WORK_START`, `MASTER_LABEL_SCANNED_NEW`, `SCAN_OK=1`까지만 기록 | 버튼 child 탐색 또는 좌표 보정 필요 | 대기 |

## 실제 무인 UI PASS 증거

| 항목 | 값 |
|---|---|
| Run | `.tmp\real-ui-uia-run-20260627-211915` |
| Data root | `.tmp\real-ui-uia-data-20260627-211915` |
| Report | `.tmp\real-ui-uia-run-20260627-211915\real_ui_no_human_walkthrough_report.json` |
| Event summary | `.tmp\real-ui-uia-run-20260627-211915\event_csv_summary.json` |
| Evidence index | `.tmp\real-ui-uia-run-20260627-211915\evidence_index.json` |
| Artifact hashes | `.tmp\real-ui-uia-run-20260627-211915\artifact_hashes.sha256` |
| Screenshots | `.tmp\real-ui-uia-run-20260627-211915\screenshots\*.png` |
| 판정 | 정상 작업 플로우 PASS, 오류/undo/보류/교환/교체는 미완료 |

## OUTLINE 반영 기준

실제 UI walkthrough가 완료되면 `Container_Audit(이적실 프로그램)` 문서에 다음 섹션을 추가한다.

1. 실제 검증 요약
2. 신규 작업자 첫 사용 전체 흐름
3. 정상 작업 캡처
4. 실수/오류 대응 캡처
5. 버튼별 실제 동작 캡처
6. PASS/FAIL 검수표
7. 남은 현장 한계와 담당자 확인사항

## OUTLINE 캡처 인덱스 형식

| OUTLINE 캡처명 | 파일명 | 성격 | 확인 기준 |
|---|---|---|---|
| CA-WALK-00 전체 워크플로우 | `00-workflow.png` | 설명용 | 본문 시나리오 순서와 일치 |
| CA-WALK-01 로그인 | `01_launch_login.png` | 실제 walkthrough | 작업자 시작 화면 확인 |
| CA-WALK-02 작업 시작 대기 | `03_main_waiting.png` | 실제 walkthrough | 현품표 입력 대기 상태 확인 |
| CA-WALK-03 현품표 스캔 | `04_master_label_loaded.png` | 실제 walkthrough | 품목/수량 표시, `MASTER_LABEL_SCANNED_NEW` |
| CA-WALK-04 제품 1차 스캔 | `05_product_scan_1.png` | 실제 walkthrough | 카운트 증가, `SCAN_OK` |
| CA-WALK-05 목표 수량 완료 | `06_auto_complete.png` | 실제 walkthrough | 완료 처리, `TRAY_COMPLETE` |
| CA-WALK-06 완료 후 대기 | `10_completion_durability.png` | 실제 walkthrough | 다음 현품표 대기 상태 |
| CA-ERR-01 전체화면 경고 | `11_duplicate_product.png` 또는 오류별 캡처 | 오류 캡처 | 경고 표시와 포커스 복귀 확인 |
| CA-PARK-01 보류 트레이 목록 | `15_park_tray.png` | 실제 walkthrough | 보류/복원 UI 확인 |
| CA-EXCH-01 개별 제품 교환 | `18_product_exchange.png` | 실제 walkthrough | 불량/양품 교환 dialog 확인 |
| CA-REPL-01 완료 현품표 교체 | `19_master_replacement.png` | 실제 walkthrough | 교체 기능 guardrail 확인 |

## PASS/FAIL 표 형식

| ID | 시나리오 | 캡처명 | 기대 결과 | 실제 확인 | 로그/데이터 증거 | 판정 | 조치 |
|---|---|---|---|---|---|---|---|
| UI-LOGIN-01 | 작업자 로그인 | CA-WALK-01 로그인 | 작업자 선택/시작 가능 | 대기 | WORK_START 또는 캡처 | 대기 | 대기 |
| UI-SCAN-01 | 현품표 스캔 | CA-WALK-03 현품표 스캔 | 품목/목표수량 표시 | 대기 | MASTER_LABEL_SCANNED_NEW | 대기 | 대기 |
| UI-SCAN-02 | 제품 스캔 | CA-WALK-04 제품 1차 스캔 | 카운트 증가 | 대기 | SCAN_OK | 대기 | 대기 |
| UI-AUTO-01 | 목표 수량 완료 | CA-WALK-05 목표 수량 완료 | 자동 완료/초기화 | 대기 | TRAY_COMPLETE | 대기 | 대기 |
| UI-ERR-01 | 오류 경고 | CA-ERR-01 전체화면 경고 | 경고 표시 후 입력 복귀 | 대기 | 관련 실패 이벤트 또는 캡처 | 대기 | 대기 |

## 최종 판정 요약 표 형식

| 영역 | PASS 기준 | 결과 | 근거 |
|---|---|---|---|
| 화면 캡처 | 순서별 화면이 선명하고 비어 있지 않음 | 대기 | 캡처 파일명, 해상도 |
| 이벤트 로그 | 기대 이벤트와 row count 일치 | 대기 | CSV 경로, event count |
| 보조 기능 | 보류/교체/교환/경고가 실제 조작 증거와 연결 | 대기 | 캡처 + 이벤트명 |
| 보안 | secret/raw payload/운영 개인정보 미노출 | 대기 | 마스킹 확인 |
| OUTLINE 게시 | 이미지가 attachment URL로 치환되고 순서 유지 | 대기 | 게시 문서 URL |
