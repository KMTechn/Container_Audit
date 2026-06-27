# Container_Audit 남은 외부 검증 Blocker

작성일: 2026-06-27

## 현재 PASS로 확정한 것

- 실제 패키징 exe를 Windows 화면에 띄워 작업자 PC처럼 조작했다.
- 신규 작업자 no-preseed 시작, 현품표 스캔, 제품 스캔, 자동 완료, 경고 복귀, undo, reset, park/restore, 종료/복구, 작업자 변경/복구, 부분 제출, 개별 교환, 완료 현품표 교체를 실제 화면으로 확인했다.
- 최신 live run: `.tmp\real-ui-screen-live_no_preseed-20260627-222219`
- 핵심 이벤트: `WORK_START=1`, `MASTER_LABEL_SCANNED_NEW=1`, `SCAN_OK=2`, `TRAY_COMPLETE=1`
- 스크린샷: 7장 nonblank 확인
- 저장 루트: `C:\Sync`가 아닌 격리 로컬 events 루트 사용
- Outline 사용 설명서 게시 완료: `https://wiki.kmtecherp.com/doc/container_audit-aJEkn1X2yH`

## 2026-06-28 로컬 보강 PASS

- Direct Sync relay가 active writer `.lock`, read 중 size/mtime 변경, trailing partial CSV row를 만나면 해당 주기 전송을 미룬다.
- 완료된 CSV row까지만 delta spool과 end-byte watermark를 만든다.
- ack 후 원본 파일이 같은 이름으로 교체되어도 ack watermark는 spooled 당시 원본 prefix hash를 저장하므로 다음 주기에 full replacement로 재전송할 수 있다.
- 제품 바코드 단계에서 control char, formula prefix, HTML/script, path traversal, 과도한 길이 입력을 fail-closed 처리한다. 실제 라벨 separator(`/`, `&`, `;`, `|`, 따옴표)는 traversal/script/control 문맥이 아니면 허용한다.
- unsafe product barcode는 `SCAN_FAIL_FORMAT`으로 남기되 raw barcode를 로그에 저장하지 않고 SHA-256/길이/사유만 저장한다.
- WorkerAnalysisGUI-web `/api/worker_hourly`는 projection fallback을 사용하고, 화면 표시 local date 기준으로 당일/과거를 필터링하도록 보강됐다.
- 서버 receipt DB에는 declared row count/range가 별도 컬럼으로 남고, row range 의미 검증과 idempotency replay conflict 검증을 수행하도록 보강됐다.
- self-enrollment은 disabled/revoked credential을 자동 재활성화하지 않으며, DB write 실패 시 Defect HMAC registry에 active key가 남지 않도록 보강됐다.
- Defect warehouse received/rejected payload는 manifest identity와 quantity UOM을 downstream에 전달하도록 보강됐다.
- 로컬 검증:
  - `Container_Audit`: focused suite `136 passed`, 1 warning (`pygame/pkg_resources` deprecation)
  - `WorkerAnalysisGUI-web`: ingest/dashboard/credential/projection focused suite `307 passed`
  - `Defect_Inspection`: contract/direct-sync HMAC focused suite `233 passed`

## 남은 P0 Blocker

| ID | 항목 | 왜 남았는가 | 완료 기준 |
|---|---|---|---|
| EXT-001 | 실제 USB/Bluetooth 스캐너 검증 | 이번 run은 실제 Windows 키보드/마우스 입력으로 스캐너 입력을 대체했다. 하드웨어 스캐너의 suffix, 한/영 상태, 포커스 흔들림은 장비가 있어야 확정 가능하다. | 실제 스캐너로 현품표, 제품 2개, 중복, 품목 불일치, 자동완료까지 PASS. |
| EXT-002 | 승인된 HTTPS endpoint receipt | 이 화면 묶음은 로컬 저장과 UI 흐름 검증이다. 승인된 staging/test endpoint에 실제 업로드하지 않았다. | TLS, 프록시 헤더, HMAC, nonce, idempotency, receipt 저장 PASS. |
| EXT-003 | 운영 동일 DB ingest | 운영과 동일한 DB 스키마/권한으로 이번 실제 CSV를 ingest하지 않았다. | receipt, raw artifact, source_claim, common_ingested_events, projection, summary count가 원본 row count와 일치. |
| EXT-004 | 다운스트림 당일/과거/trace/export 화면 | 서버 수신 이후 받는 프로그램 화면을 이번 실제 화면 batch와 연결해 보지 않았다. | 당일 작업, 과거 조회, trace, summary, export가 서버 데이터와 동일. |
| EXT-005 | Syncthing 제거 전 shadow/no-double-count | 배포판은 Syncthing 없는 구조가 기준이지만, 기존 Syncthing/archive와 HTTPS 병행 상황의 중복 집계는 실제 endpoint가 있어야 검증된다. | HTTPS와 legacy/archive 병행 시 같은 작업이 double count 되지 않음. |
| EXT-006 | rollback rehearsal | 실제 relay/service stop, HTTPS 실패, legacy 복귀 절차는 운영 연결 전에는 완료로 주장할 수 없다. | relay pause, service stop, legacy path 복귀, CSV/archive 보존, 재전송 resume 리허설 PASS. |
| EXT-007 | 서버 배포 parity | 2026-06-28 08:07 KST에 `company-server` SSH read-only SHA 확인을 시도했으나 port 22 timeout이었다. 공개 HTTPS health는 healthy지만 파일 SHA/version 대조는 불가했다. | 서버 배포본 `app.py`, `producer_ingest.py`, `direct_sync_ops_status.py` 등 SHA/version이 로컬 검증본과 일치하거나 차이가 승인 문서에 명시됨. |

## 남은 P1 현장 확인

| ID | 항목 | 확인할 내용 |
|---|---|---|
| FIELD-001 | 한글 입력 상태 | 작업자 PC 한/영 상태에서 스캐너 입력이 깨지지 않는지 확인. |
| FIELD-002 | 장시간 유휴 | 7분 이상 대기 후 다음 스캔이 자연스럽게 재개되는지 확인. |
| FIELD-003 | 화면 배율 | 작업자 PC 배율, 해상도, 보조 모니터에서 버튼/목록/경고가 잘리지 않는지 확인. |
| FIELD-004 | 트레이 이미지 보기 | 이미지가 있는 품목과 없는 품목에서 작업이 막히지 않는지 확인. |
| FIELD-005 | 필수 파일/업데이트 오류 | `Item.csv` 누락, 업데이트 실패, 네트워크 오류 메시지가 현장 담당자에게 이해 가능한지 확인. |

## 배포 전 판단

현재 상태는 "로컬 실제 화면 워크플로우와 사용자 설명서 게시 PASS"이다.

아직 "Syncthing 제거 후 프로덕션 배포 ready"로 보려면 EXT-001부터 EXT-007까지 실제 현장/서버 환경에서 PASS가 필요하다.
