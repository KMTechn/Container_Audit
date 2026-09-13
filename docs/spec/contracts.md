# 데이터·상태·통합 계약

[제품·기능 카드](README.md) · [운영](operations.md) · [백로그](BACKLOG.md) · [중앙 통합](../../../Program_Spec_Hub/INTEGRATIONS.md) · [공통 용어](../../../Program_Spec_Hub/GLOSSARY.md)

기준일 2026-09-07, CA HEAD `2e7d9f70341015dacfc3495cb2c4aac027cbcb3e`와 당시 수정 작업 트리를 대상으로 한다. [정확한 소스·증거 경계](README.md#ca-evidence-scope)를 함께 적용한다. 아래는 소스에서 확인한 계약이며 대상 서버의 활성 설정·설치 provider·실행 성공은 별도 증거가 필요하다. 상대 저장소의 조사 HEAD는 [SOURCE-MAP 및 연구](E:/KMTech/spec-hub-research-20260907/Container_Audit/RESEARCH.md)에 있으며 링크 대상이 이후 바뀌면 재대조한다.

## 1. 정본과 버전

CA는 스캔·작업 상태·전송 의도를 소유한다. 중앙 제품 소유·위치·bundle membership·version·receipt 정본은 [Web logistics ledger service](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py)가 소유한다. 관측 이벤트의 수신·투영은 [producer_ingest](../../../WorkerAnalysisGUI-web/producer_ingest.py)와 [common_projection](../../../WorkerAnalysisGUI-web/common_projection.py)가 소유한다. 이벤트 업로드만으로 물류 원장을 확정하거나 역산하지 않는다.

| 계약·저장 형식 | 조사 시 선언 | 소스·적용 한계 |
|---|---|---|
| 배포 계약 lock | bundle `1.0.3`, corrective revision `1`, 최소 installer/verifier `1.0.3.4` | [contract.lock.json](../../contract.lock.json). 소스 선언이며 설치본 동일성은 미확인. `db_schema_supported 0..0`을 모든 로컬 SQLite의 schema version으로 일반화하지 않는다. |
| 물류 API | `logistics-v1` | [transfer_seal.CONTRACT_VERSION](../../transfer_seal.py), [Web API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py) |
| 봉인 intent / 로컬 완료 | `container-audit-transfer-seal-v1` / `container-audit-transfer-completion-v1` | [TransferSealStore](../../transfer_seal.py) |
| 물류 operation lease | `terminal-operation-lease-v1` | [terminal_operation_lease](../../terminal_operation_lease.py). producer runtime lease와 별개. |
| 조회 중 보류 | `container-audit-preflight-scan-hold-v1` | [preflight_scan_hold](../../preflight_scan_hold.py) |
| 제품 교체 / GOOD resolver | `container-audit-member-exchange-v1` / `logistics-good-replacement-source-v1` | [transfer_member_exchange](../../transfer_member_exchange.py) |
| producer 파일 업로드 | `producer-ingest-source-file-v1`, 서명 `PRODUCER-HMAC-SHA256-V1` | [direct_sync_push](../../direct_sync_push.py); lock에는 producer-ingest-v1 capability와 common-event-envelope-v1이 별도로 선언됨. |
| 현재 사용자 최초 등록 | `producer-self-enrollment-v2` | [current_user_onboarding](../../current_user_onboarding.py), [등록·소유 증명](../../tools/register_container_audit_worker_pc.py), [CA-C10](#ca-c10). |
| 설치 lookup 식별자 | `container-audit-install-identity-v1` | MachineGuid+현재 사용자 SID+app 파생이며 possession proof와 별개. [derive_path_independent_install_id](../../tools/register_container_audit_worker_pc.py). |

교체 업무의 상세 정본은 [MEMBER_EXCHANGE_POLICY](../MEMBER_EXCHANGE_POLICY.md), 장기 전송·보존 규칙은 [DIRECT_SYNC_DATA_PLATFORM_NOTES](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md)를 재사용한다. 오래된 [LOGISTICS_RUNTIME_PROFILE](../LOGISTICS_RUNTIME_PROFILE.md)의 machine-profile 및 ACK 설명은 [CA-G03](BACKLOG.md#ca-g03)의 차이가 있으므로 현재 사용자 경로·로컬 완료 기준으로 무조건 적용하지 않는다.

<a id="ca-data"></a>
## 2. 엔터티·식별자·수량·시간

| 항목 | 의미·키·모집단 | 근거 |
|---|---|---|
| 원본 PHS2 | 정확히 `PHS/SRC/ITG/CLC/LBL/HSH`; `ITG/LBL/HSH`로 중앙 identity를 조회하고 `CLC` 품목을 대조. `QT`를 덧붙이거나 목표 60을 추정하지 않음. | [compact 검증 / TransferSourcePreflight](../../transfer_seal.py) |
| product barcode / unit ID | 스캐너 문자열과 중앙 단위 ID는 별개. 완료 때 barcode↔unit을 exact 매핑. `normalize_barcode`는 NFKC·strip·대문자 정규화; GUI 입력 단계의 원문 중복 검사와 같은 단계가 아님. | [product_scan](../../product_scan.py), [TransferSealCoordinator._map_scans](../../transfer_seal.py) |
| bundle / transfer / work group | 중앙 구성원 소유 단위와 이적 묶음·source topology. 단순히 PHS 문자열이나 로컬 tray ID와 같다고 가정하지 않음. | [TransferSealCoordinator._build_command / _build_work_group_command](../../transfer_seal.py), [Web seal service](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py) |
| intent ID / local_completion_id | CA 내구 처리와 로컬 완료의 식별. 중앙 scope/key receipt와 연결하지만 같은 상태나 같은 ID가 아님. | [TransferSealStore.prepare / _ensure_linked_event](../../transfer_seal.py) |
| `(authority_scope_id, idempotency_key)` | 중앙 명령 재생 범위. 같은 key의 다른 fingerprint는 충돌이며 key를 바꿔 우회하지 않음. | [Web replay_or_conflict](../../../WorkerAnalysisGUI-web/logistics_ledger/idempotency.py) |
| authority/plane epoch·entity version | 인증·원장 문맥 및 낙관적 경합 확인 값. member hash는 구성원 동일성 증거로 쓰며 수량으로 대체 불가. | [LogisticsTransferClient.assert_authority](../../transfer_seal.py), [Web ledger](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py) |
| source_file_id / content hash / relay ID | whole-file 전송 identity·내용 버전·큐 항목. 물류 idempotency key와 구분. install/source scope와 함께 수신 중복을 판정. | [build_source_file_plan](../../direct_sync_push.py), [producer_ingest](../../../WorkerAnalysisGUI-web/producer_ingest.py) |
| `tray_capacity` | 현재 PHS2의 중앙 GOOD 목표 수. NG·다른 PHS 제품을 포함하지 않는 검사 대상 모집단. 호환 경로의 fallback 수량을 표준으로 승격하지 않음. | [preflight 및 complete_tray](../../Container_Audit.py) |
| `scan_count` / `barcode_count` | 현재/완료 목록 길이 / distinct barcode 수. `scanned_product_barcodes`와 `product_barcodes`는 호환 소비용 같은 목록이므로 합산하지 않음. | [build_tray_complete_detail](../../event_payloads.py) |
| `qty_uom=piece` | 완료 이벤트의 단위 표기. 물류 UOM은 중앙 bundle 값이며 `EA`, `Pcs`, `piece`의 무조건 환산은 승인된 정의가 없음. | [event_payloads](../../event_payloads.py), [CA-G01](BACKLOG.md#ca-g01) |
| `scan_position` | 1부터의 스캔 순번. 실물 트레이 슬롯·XYZ 좌표·중앙 location ID가 아님. 실제 위치 검사 요구는 미정. | [build_scan_ok_detail](../../event_payloads.py), [CA-G02](BACKLOG.md#ca-g02) |
| `interval_sec`, `work_time_sec`, `total_idle_seconds` | 초 단위 간격·작업시간·유휴시간. 승인 성능 목표나 장비 처리율이 아님. | [event_payloads](../../event_payloads.py) |
| `row_count`, `byte_length` | 업로드 CSV 데이터 행 수·파일 바이트 수. 한 완료 행에 여러 제품이 있으므로 제품 수/트레이 수와 다름. | [build_source_file_plan](../../direct_sync_push.py) |
| `pcs_completed` | Web의 CA 완료 이벤트 barcode 목록 길이, 없거나 0이면 `barcode_count`/`scan_count` fallback. seal ACK 수·현재 재고를 의미하지 않음. | [common_projection._session_row_from_container_audit_projection](../../../WorkerAnalysisGUI-web/common_projection.py) |

CA 이벤트는 `timestamp,worker_name,event,details` CSV에 JSON details를 싣는다. 실제 파일은 `utf-8-sig`, `newline=""`; 내구 호출은 flush/fsync를 수행한다. `TRAY_COMPLETE` details에는 위 수량 외 `master_label_code`, `master_label_fields`, `item_code`, 작업자/시각 문맥, partial/restored/test 플래그와 필요 시 inspection trace·seal 상태를 연결한다. 전체 필드 정본은 [event_payloads](../../event_payloads.py), [ContainerAudit._log_event / _attach_transfer_seal_detail](../../Container_Audit.py), [event_log_store](../../event_log_store.py)다.

이벤트 작업 시각은 로컬 naive ISO 값일 수 있으며 Web은 CA source에 `Asia/Seoul`을 적용해 UTC로 정규화한다. operation lease와 relay 시각은 UTC `Z` 문맥을 사용한다. 발생·로컬 저장·서버 수신·투영·화면 표시 시각은 별개다. CA 세션 변환은 start/end와 event/received 계열 fallback에서 날짜를 만들므로 모든 지표가 동일 업무일 규칙이라는 가정은 금한다. [common_projection 시간 정규화 및 세션 변환](../../../WorkerAnalysisGUI-web/common_projection.py), [terminal_operation_lease.utc_text](../../terminal_operation_lease.py), [direct_sync_push](../../direct_sync_push.py). 자정 경계·시계차·화면 필터 실제 검증은 [CA-G01](BACKLOG.md#ca-g01)이다.

부분 제출·13자리 호환 입력 분기는 현장 원장 표본 확인 전 제거 금지다.
확장 축 ②(제품·바코드 양식 변경)의 정책 adapter 대상으로 보존하며,
현행 계산은 [명시 제품 포트](../../product_identity_port.py)와 [검사 순서 표](product-admission.md)로 분리한다. raw 중복·substring/catalog·기존 결과/오류 계약은 동일하며 새 정책/schema는 없다.
실제 원장 표본의 형식별 발생 여부와 저장 상태 이행·지원 종료를 확인한 뒤 제거를 검토한다.
표준 compact PHS2는 중앙 GOOD 구성원 전량 확인을 유지하고 부족 수량의 부분 제출을 차단한다.

## 3. 완료 상태와 관측 지점

| 관측 지점 | 완료로 확인할 조건 | 그 조건만으로 알 수 없는 것 |
|---|---|---|
| 로컬 입력 보존 | current/hold/parked snapshot 또는 해당 내구 기록 성공 | 중앙 membership·seal 승인 |
| 로컬 업무 완료 | `LINKED` 및 local completion/checkpoint·완료 사건의 해당 경계 확인 | `ACKED`, producer ingest, 다음 공정 소비 |
| 중앙 명령 확정 | scope/key와 exact 결과를 검증한 receipt → seal intent `ACKED` | CSV 업로드 및 분석 화면 최신성 |
| producer 수신·projection | 파일 identity·행 합계·committed 및 `COMPLETE` 등 엄격 receipt 충족 | 물류 seal ACK·모든 소비 API/화면 갱신 |
| 소비 화면 | 해당 API/flag/필터에서 실제 데이터 readback 및 렌더 확인 | 다른 기간·다른 화면·다른 환경에서도 최신이라는 주장 |

위 표는 [TransferSealStore / Coordinator](../../transfer_seal.py), [complete_tray](../../Container_Audit.py), [direct_sync_push receipt 검사](../../direct_sync_push.py), [Web projection](../../../WorkerAnalysisGUI-web/common_projection.py)의 경계를 설명한다. 모든 효과가 한 transaction인 것은 아니며 물류 명령과 producer 전송의 도착 순서를 보장하지 않는다.

<a id="ca-c01"></a>
## CA-C01 로컬 상태·내구성·소유권

- 제품 형식 오류 안내는 길이/제어문자/위험 형식/트레이 설정의 판정 reason에 맞춘 안전한 문구를 일반·held 경로에서 공통 사용한다. 위험 원문은 안내에 삽입하지 않고 감사 detail에는 hash·길이만 남긴다.

- 일반·held 제품의 current JSON atomic write/flush/fsync는 기존 직렬 UI lane worker가 수행한다. Tk는 저장 ACK 뒤에만 목록·수량·receipt·성공음을 한 번 반영하고, 실패하면 이전 목록·파일을 유지한다. 저장 중 다음 입력은 미접수 상태로 입력창에 남고 선행 저장을 추월하지 않는다. held FIFO 제거는 이후 같은 worker의 동기 감사 ACK를 별도로 기다린다. 종료는 진행 중 lane과 held writer를 drain하며, epoch가 바뀐 결과는 새 트레이를 변경하지 않는다.
- 일반 비동기 사건은 원 시각·작업자·대상 CSV·details·멱등 key를 먼저 메모리 FIFO에 보존하고, writer admission을 얻어 `events/_event_outbox/*.json`에 atomic write/flush/fsync한 뒤 접수한다. admission의 5초 mutex timeout·fence 거절 또는 사본 저장 실패는 접수 False이며 원 payload/key를 메모리에 남겨 다음 허가된 쓰기에서 앞 사건부터 재시도한다. admission/fence 규칙은 모든 디스크 쓰기에 그대로 적용된다. writer는 순서대로 동일 key로 내구 CSV append를 재시도하고 성공 뒤 사본을 지운다. append 뒤 응답/정리 실패 및 재시작에도 같은 행을 중복 추가하지 않는다. 실패한 앞 사건을 동기 사건이 추월하지 않으며 완료의 별도 `LOCAL_EVENT_RETRY` 경계는 유지한다.
- outbox 순번은 남은 사본의 최대 순번을 이어받아 단조 증가하므로 시스템 시계 역행·재시작이 원 사건 순서를 바꾸지 않는다.

**방향:** GUI/coordination → 사용자 state·이벤트·intent → 같은 사용자 재시작 복구. [CA-01](README.md#ca-01), [CA-04](README.md#ca-04), [CA-08](README.md#ca-08), [CA-09](README.md#ca-09).

- `TraySession`은 원본 PHS2, 품목/목표, 스캔 목록·시간, preflight/lease 문맥과 복구 플래그를 보존한다. current JSON과 보류 JSON은 [ContainerAudit._current_tray_state_snapshot / _load_current_tray_state](../../Container_Audit.py), [tray_state](../../tray_state.py), [parked_tray_store](../../parked_tray_store.py)가 관리한다. 소유자는 작업자와 컴퓨터 문맥이며 다른 작업자의 같은 현품표 보류도 검사한다.
- preflight hold는 `LOOKUP`, `LOOKUP_FAILED`, `DRAINING`과 FIFO sequence를 저장한다. 부정확한 sequence/schema/context는 오류이며 quarantined snapshot 복구는 별도 동작이다. FAILED hold의 새 작업 전환은 보류0건이라도 인증된 보호 관리자 격리·감사 기록을 요구한다. 일반 작업자 또는 재시작이 파일을 지우거나 다른 PHS2로 덮어쓰지 않는다. [preflight_scan_hold](../../preflight_scan_hold.py), [권한·quarantine 호출자](../../Container_Audit.py).
- seal intent 상태는 `PREPARED`, `COMMAND_READY`, `RETRY_WAIT`, `ACKED`, `OPERATOR_REVIEW`; `LINKED`는 별도 로컬 completion 기록이다. 둘을 한 enum으로 합치지 않는다. command bind 뒤 요청 문맥을 보존하고 completion checkpoint 이후 전송한다. [TransferSealStore](../../transfer_seal.py)
- CSV append는 경로별 process/interprocess lock을 쓰고 내구 모드에서 flush/fsync한다. 완료 재기록은 event type+idempotency key로 기존 행을 확인한 뒤 append한다. 색인·캐시·metadata로 사건의 부재를 판정하지 않고 기존처럼 CSV 전체 내용을 직접 읽는다. 같은 key라도 parsed details가 다르면 거부하며, held 성공/거부 역시 동기 감사 성공 전 FIFO head를 제거하지 않는다. GUI 완료의 prepared checkpoint·재시도 계약 저장·CSV join/fsync는 같은 lane worker에서 순서대로 실행하고 UI 단계만 Tk에 전달한다. 동기 복구 진입점도 같은 저장 순서를 실행한다. SQLite projection receipt와 CSV append 사이 종료 시에도 재생을 판단할 수 있지만 SQLite·JSON·CSV 전체를 하나의 transaction이라고 주장하지 않는다. [append_event_log_entry_idempotent](../../event_log_store.py), [complete_tray](../../Container_Audit.py)
- 취소 실패는 목록 복원, 보류 복원은 대상 저장·감사와 원본 정리 순서, 손상 state는 격리/보존을 따른다. [undo_last_scan / restore_parked_tray](../../Container_Audit.py). 실패·재시작 각 경계의 실행 증거와 백업 복구 요구는 [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06)에 연결한다.

<a id="ca-c02"></a>
## CA-C02 검사 완료 구성원 → CA preflight·lease

**방향:** Inspection → Web canonical GOOD/NG → CA 조회. 생산자는 [Inspection _complete_linked_normal_session](../../../Inspection_worker/core/business_logic.py) 및 [complete_session](../../../Inspection_worker/core/direct_sync_runtime.py), 조회자는 [LogisticsTransferClient / TransferSourcePreflight](../../transfer_seal.py), 서버는 [logistics API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py)다.

| 경로 | 입력·응답에서 보존할 의미 |
|---|---|
| `POST /logistics/api/v1/sessions/{id}/complete` | 검사 완료의 ITG·품목·UOM·실제 GOOD/NG 구성원. CA가 재판정하지 않음. |
| `GET /logistics/api/v1/bundles/resolve` 및 `/phs-labels/resolve` | 원본 exact PHS2 identity, 현재 GOOD member와 unit↔barcode·품목/UOM·version 대조. |
| `POST /logistics/api/v1/operation-leases/issue` | authority scope·plane·epoch·대상 구성원과 요청을 묶은 검증 가능한 물류 operation lease. |

lease는 서명·keyring·binding·기간·membership 검증을 요구한다. 클라이언트 코드의 유효 duration 범위는 60초~24시간이며 실제 서버 발급 기간이나 현장 오프라인 보장 시간을 뜻하지 않는다. [terminal_operation_lease.validate_claims / verify_jws](../../terminal_operation_lease.py). 이미 저장된 로컬 완료가 있으면 `_verified_operation_lease`는 그 `operation_completed_at`으로 저장 lease를 재검증한다. 현재 시각의 만료만 보고 기존 완료를 취소하는 규칙과 다르며, 새 작업에 만료 lease를 사용하는 허가는 아니다. [TransferSealCoordinator._verified_operation_lease](../../transfer_seal.py). 조회 중 입력 보존은 CA-C01, lease 없는 PHS2 및 exact 불일치 차단은 [CA-07](README.md#ca-07)이다. 배포 identity/capability·만료 경계 실제 검증은 [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c03"></a>
## CA-C03 CA → Web 이적 봉인·receipt

**API:** `POST /logistics/api/v1/transfers/seal`, 명령 `SEAL_TRANSFER_BUNDLE`; 재확인은 `GET /logistics/api/v1/receipts/{scope}/{key}`. 클라이언트 [seal_transfer / get_receipt / TransferSealCoordinator](../../transfer_seal.py), 수신 [Web API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py), 원장 [seal service](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py), 멱등 [replay_or_conflict](../../../WorkerAnalysisGUI-web/logistics_ledger/idempotency.py).

- **모듈 경계:** [transfer_client](../../transfer_client.py)는 `LogisticsTransferClient`·`SealAttempt`·`logistics_transfer_client_from_env`, [transfer_store](../../transfer_store.py)는 `TransferSealStore`, [transfer_common](../../transfer_common.py)은 기존 오류·값·owner guard를 소유한다. 기존 `transfer_seal` façade가 같은 객체와 signature를 재노출하며 역방향 import는 없다. coordinator와 그 env factory는 façade에 남고 GUI·member exchange의 기존 import를 유지한다. 저장된 attempt·schema SQL·prepared key/readback·local/central ACK 순서와 HTTP/SQLite transaction 소유는 불변이다.
- **profile 전달:** factory의 profile/legacy client 생성은 기존 `base_url`, `token`, `source_host_id`를 이름 있는 인자로 전달한다. constructor의 positional 호환과 기본값, profile 선택·required/probe 시점, device/ledger fallback은 유지한다. 새 관리 context나 wire 필드를 만들지 않으며 저장된 command/receipt를 현재 profile로 재결속하지 않는다.
- **인증·권한:** HTTPS JSON에 bearer/API token, `X-Logistics-Source-Host-Id`, `X-Logistics-Device-Id`, `X-Logistics-Program=Container_Audit`, `Idempotency-Key`를 사용한다. 서버 machine scope와 클라이언트 authority/plane/epoch가 맞아야 한다. redirect는 차단한다. 작업자 표시 이름은 이 권한을 대체하지 않는다. [LogisticsTransferClient._headers / _request / assert_authority](../../transfer_seal.py), [Web _identity 및 route guards](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py)
- **필수 의미:** scope/key, command type·contract, member IDs/hash/scanned barcodes, 예상 entity versions, source/work-group topology, operation lease를 불변 context에 연결한다. 상세 단일/작업그룹 payload는 `_build_command`, `_build_work_group_command`가 정본이다. 허용되지 않은 partial subset을 임의 생성하지 않는다.
- **원자성:** 중앙 transaction의 membership/소유·seal·receipt 효과는 서버 소유다. 로컬 SQLite `LINKED`, JSON checkpoint, CSV 완료 기록과 중앙 transaction은 분리되어 있다. `local_completion_id`가 있으면 중앙 대기/검토와 로컬 완료를 병행 표시할 수 있다. [complete_tray](../../Container_Audit.py)
- **중복·오류:** 동일 scope/key·동일 fingerprint 재생은 기존 결과를 조회하며 다른 fingerprint는 충돌한다. 전송 응답 유실 또는 committed 오류에서는 receipt를 조회한다. exact receipt 검증 뒤 `ACKED`, retryable은 `RETRY_WAIT`, 영구/정합 문제는 `OPERATOR_REVIEW`로 남긴다. CSV 실패의 `LOCAL_EVENT_RETRY`는 중앙 거부와 별개다. [attempt / record_error / record_receipt](../../transfer_seal.py)
- **순서:** `pending_ids`는 생성 순서·rowid, `drain_pending_through`는 대상까지 FIFO 순회한다. 각 attempt가 실패했다는 이유만으로 모든 뒤 명령을 무조건 막는 전역 strict FIFO라고 일반화하지 않는다. producer queue의 due-time 조건도 별도다.
- **명시적 관리자 재시도(2026-09-08 source 후속):** `retry_operator_review`는 coordinator owner·관리자 세션 재확인·완료 checkpoint/`LINKED`·아직 receipt가 없는 bound review를 요구한다. 명령 hash/key와 서명 lease/제품·완료 시각 검증 후 기존 동기 `_log_event`에 `TRANSFER_SEAL_REVIEW_RETRY_REQUESTED`를 내구 기록해야 요청을 보낸다. 이 사건은 local-only이며 새로운 producer 계약 사건이 아니다. 같은 불변 명령만 재전송하고 새 lease/키/완료 시각을 만들지 않는다. 성공 receipt의 exact membership·scope·원자 lease consumption 검증 뒤 ACKED로 전환하며 과거 review/outbox/audit는 남긴다. 실패한 명시적 재시도는 transport 오류여도 OPERATOR_REVIEW를 유지하고 자동 pending에 넣지 않는다. UI의 현재 review 조회는 ACKED를 제외하지만 전체 review 이력 조회는 유지한다. 정상 관리자 인증은 서버 machine capability를 대체하지 않는다. [구현](../../transfer_seal.py), [lease 기록](../../terminal_operation_lease.py), [UI](../../Container_Audit.py), [정책](../../event_stream_policy.py).
- **수용·잔여:** [CA-12](README.md#ca-12)의 local/central 각각 한 번·원 key 유지·중단 복구와 [CA-G01](BACKLOG.md#ca-g01), [CA-G04](BACKLOG.md#ca-g04). 중앙 ACK 후 포장 소비는 다음 계약의 별도 결과다.
- **실제 후속 범위:** installed `a7d714f6`의 정상 관리자 재시도와 backend `c0c0d51`에서 원 case02는 원 완료 시각07:46:27Z·lease fence1·명령을 유지한 채09:21:22Z receipt1/ACKED가 됐다. [독립 중앙 조회](E:/KMTech/web-integration-20260908/ca-original-retry-central-readback.json)와 [로컬 불변 비교](E:/KMTech/ca-install-qualification-20260908/review03-integrity-after-retry.json)가 이를 입증한다. 같은 시각 새 발급 grant는 기존 적시 완료의 finalization 권한을 대체하지 않으며, 원 완료 시각이 없는 만료 case03의 새 스캔을 허용하는 근거도 아니다.

<a id="ca-c04"></a>
## CA-C04 CA → Web 봉인 전 제품 교체

**API:** `GET /logistics/api/v1/replacements/good-source/resolve`, `POST /logistics/api/v1/bundles/{id}/members/replace`; `REPLACE_BUNDLE_MEMBERS`. [CA client/coordinator](../../transfer_member_exchange.py), [wire client](../../transfer_seal.py), [Web API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py), [replace_bundle_members](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py).

정본 [MEMBER_EXCHANGE_POLICY](../MEMBER_EXCHANGE_POLICY.md)는 동일 품목·UOM, 1~2쌍, 대상 및 각 공여 bundle의 expected version을 같은 명령으로 CAS하는 조건을 규정한다. 공여 PHS는 `EXACTLY_ONE_ACTIVE_MEMBER`; 여러 member이면 `REPLACEMENT_SOURCE_NOT_SINGLETON`으로 차단한다. 1~2쌍 전체 성공 또는 전체 실패이며 기존 제품은 `PROCESS_DAMAGE_HOLD`로 이동한다.

receipt는 pair·exact membership/hash·version 및 `RETAIN_IDENTITY_LABEL`, `target_label_identity_remains_valid=true`, `target_label_membership_bound=false`를 증명해야 한다. 이 조건 없이 원래 실물 라벨이 계속 유효하다고 가정하지 않는다. 중앙 ACK 뒤 로컬 적용 중 종료는 intent와 현재 트레이를 대조해 복구한다. 봉인 뒤 CA 수정은 금지하고 Label의 별도 `REPLACE_SEALED_TRANSFER_MEMBERS` 계약으로 넘긴다. 그 계약은 새 seal revision/token/QR을 만들며 Label F4의 새 전자 QR 재확인까지 CA 작업과 혼동하지 않는다. [Label package_logistics](../../../Label_Match/package_logistics.py), [CA-10](README.md#ca-10).

화면 구성·목록/상태·결과 안내는 [member_exchange_view](../../member_exchange_view.py)가 기존 owner의 Tk thread에서 처리한다. admission·스캔 검증·prepare/attempt·ACK 로컬 적용·lease rotation은 원 owner/coordinator에 남는다. [상태·호출 경계](member-exchange-view.md).

capability의 `max_pairs=2`, `atomic`, `two_bundle_cas` 등은 [logistics_transfer_client_from_env](../../transfer_seal.py)가 대조한다. 실제 설치 서버의 활성 값과 동시 경쟁 결과는 미확인이다. [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c05"></a>
## CA-C05 CA 파일 snapshot → producer ingest·projection

**방향/API:** CA relay → Web `POST /api/producer-ingest/v1/source-file`; multipart metadata+file. [build_source_file_plan / drain_one_relay_batch](../../direct_sync_push.py), [enqueue_completed_source_file](../../direct_sync_runtime.py), [Web producer_ingest_source_file](../../../WorkerAnalysisGUI-web/app.py), [handle_source_file_request](../../../WorkerAnalysisGUI-web/producer_ingest.py).

- **schema·키:** metadata는 contract, install identity, source_file_id, content SHA256, byte_length, row_count, batch identity를 포함한다. whole-file snapshot의 hash/바이트와 큐 상태를 맞춰 전송한다. 새로운 파일 내용은 단순히 이전 relay의 ACK로 생략할 수 없다.
- **권한·lease:** HTTPS의 HMAC·nonce·timestamp 및 producer runtime lease를 사용한다. runtime lease는 writer/producer 권한이며 CA-C02의 물류 operation lease와 다르다. 실제 write flag·등록 상태·provider는 [producer_runtime_client](../../producer_runtime_client.py), [Web route](../../../WorkerAnalysisGUI-web/app.py)의 대상 배포에서 확인해야 한다.
- **runtime core/facade:** 고정 `kmtech_shared.runtime`이 leaf·신원/응답 binding·호출자 transaction의 SQL을 처리한다. `producer_runtime_client`는 공개 함수명·writer guard와 CNG JWK/identity callback, ensure/prepare·transport·복구 정책을 소유한다. relay ACK와 다음 rotating token은 같은 앱 transaction에서 commit/rollback하며 core는 connection/commit을 만들지 않는다. exact-clone은 기존 보수적 TTL, 사전 POST 오류는 저장된 정확 만료·모든 guard를 만족할 때만 reissue하고 unknown-commit은 자동 만료 복구로 바꾸지 않는다.
- **scope 전달:** facade·ensure·prepare는 기존 `_scope_values`의 `credentials`, `producer_install_id`를 이름 있는 인자로 전달하며 positional 호환·기존 문자열 처리를 유지한다. runtime DB의 `authority_scope`는 endpoint/producer/key/install tuple의 기존 canonical 해시로, CA-C03의 물류 authority scope와 다르다. 관리 차원 부재는 기존 legacy 해석을 유지하고 required identity 누락은 계속 실패하며, metadata/HMAC·queued snapshot을 재작성하지 않는다.
- **엄격 ACK:** 2xx만으로 충분하지 않다. committed·identity, request/upload trace의 일치, `status=accepted`, `retryable=false`, error 없음, `next_retry_after=null`, `projection_disposition=COMPLETE`, inserted/replayed/errors/quarantined 행 합계와 `errors=0`, `quarantined=0`을 함께 확인한다. [_committed_receipt_issue 및 응답 분류](../../direct_sync_push.py)
- **부분 효과·오류:** 수신이 commit됐지만 오류/격리/projection 미완료가 있으면 자동 성공으로 바꾸지 않는다. `pending`, `leased`, `retry_wait`, `acked`, `failed_permanent`, `operator_review`로 큐 상태를 구분하고 spool·상태를 보존한다. 일시 오류는 제한된 선형 지연+jitter와 유효 `Retry-After`를 사용하며 `0`도 유효하다. [전송 정본](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md)
- **순서·재시작:** due인 pending/retry_wait 중 `created_at, relay_id` 순서로 `BEGIN IMMEDIATE` claim을 한다. 아직 due가 아닌 앞 항목이 모든 뒤 항목을 막는 전역 strict FIFO는 아니다. stale local lease 복구와 status CAS는 물류 lease 만료 처리와 별개다. [claim_relay_batch / reset_stale_relay_leases](../../direct_sync_push.py)
- **중복·cursor:** 이 경로는 source snapshot·수신 event identity·install/source scope를 사용한다. CA가 소비하는 일반 warehouse response cursor 계약으로 바꾸지 않는다. 서버 projection 재생과 모든 화면 갱신은 각각 확인해야 한다. [producer_ingest](../../../WorkerAnalysisGUI-web/producer_ingest.py), [common_projection](../../../WorkerAnalysisGUI-web/common_projection.py)

- **반복 prefix 확인:** 기존 cursor에 묶인 파일 identity·size·mtime/ctime·검증 hash와 마지막 전체 검증 시각을 저장한다. 관련 delta가 모두 ACK된 source가 같은 파일이면 300초 미만 동안 내용 재읽기를 생략할 수 있지만, metadata로 ACK나 cursor를 전진시키지는 않는다. cursor 변경은 이 힌트를 무효화한다. pending/leased/blocked delta, 파일 교체·truncate·append는 기존 전체 검증/복구 경로를 유지하고, metadata까지 같은 내용 변조도 검증 기한이 지난 다음 실행에서 전체 내용을 다시 확인한다. [direct_sync_relay_runner](../../tools/direct_sync_relay_runner.py)

수용 기준은 [CA-13](README.md#ca-13), 누락·지연 및 보존 요구는 [CA-G01](BACKLOG.md#ca-g01), [CA-G06](BACKLOG.md#ca-g06)이다.

<a id="ca-c06"></a>
## CA-C06 Web 이적 구성원 → Label 포장 소비

**소비 API:** `GET /logistics/api/v1/bundles/resolve?bundle_role=PACKAGE_SOURCE`. Label은 원본 PHS2 `ITG/LBL/HSH`로 현재 TRANSFER와 exact 구성원을 조회하고 최종 포장 명령에서 CAS를 재확인한다. CA가 새 seal QR의 재스캔을 기본 포장 시작 조건으로 강제하지 않는다. [Label resolve_transfer_bundle / resolve_package_source_projection](../../../Label_Match/package_logistics.py), [Label CODEX](../../../Label_Match/CODEX.md), [Web resolve route](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py).

Label의 원본 PHS2 한 번→선택 F4→F3 흐름, F4 뒤 새 전자 QR 확인, 포장 세트/제품 수량, 취소·재고 반환의 차이는 Label 명세 소유다. CA 완료 barcode 수를 포장 세트 수로 재사용하지 않는다. 이 인계의 실제 설치본 결과와 seal lineage 검증은 [CA-G04](BACKLOG.md#ca-g04), [중앙 통합](../../../Program_Spec_Hub/INTEGRATIONS.md)에 연결한다.

<a id="ca-c07"></a>
## CA-C07 Web projection → 분석 API·화면

**정적 소비 사슬:** CA 완료/스캔 CSV → [producer_ingest](../../../WorkerAnalysisGUI-web/producer_ingest.py) → [common_projection](../../../WorkerAnalysisGUI-web/common_projection.py) → [app.projection_dashboard_sessions_df 및 분석 API](../../../WorkerAnalysisGUI-web/app.py) → [dashboard_standard.source.js](../../../WorkerAnalysisGUI-web/static/dashboard_standard.source.js), [index.html](../../../WorkerAnalysisGUI-web/templates/index.html).

`TRAY_COMPLETE`는 `TRANSFER_LEGACY`, 스캔·생명주기 사건은 `TRANSFER_ACTIVITY` 분류를 사용한다. `LEGACY`라는 분류명만으로 현재 producer 경로를 폐기 기능이라고 판정하지 않는다. local-only 사건은 relay 비재귀 scan 경계 밖에 두며 시험·복구 플래그와 source scope를 유지한다. [event_stream_policy](../../event_stream_policy.py), [common_projection](../../../WorkerAnalysisGUI-web/common_projection.py).

CA 세션 변환의 `pcs_completed`는 완료 barcode 수에서 계산되고 해당 변환/목록 조회에 seal `ACKED` 필터가 확인되지 않았다. 따라서 이적 처리 실적을 중앙 봉인 확정량으로 표기할 근거가 부족하다. 물류 snapshot의 현재 재고와도 합산하지 않는다. 표준 dashboard는 이적 처리 수량/트레이·대기 수량을 소비하지만 모든 화면의 집계 경로, 배포 flag, 누락/지연 표시까지 확인한 것은 아니다. [_session_row_from_container_audit_projection / list_container_audit_dashboard_sessions](../../../WorkerAnalysisGUI-web/common_projection.py), [period.transfer 렌더링](../../../WorkerAnalysisGUI-web/static/dashboard_standard.source.js).

**수용 기준:** 동일 source identity의 재생 중복 억제, 해당 기간·품목·작업자 필터의 수량/시간 정의, API→화면 값과 최신성 readback을 확인한다. 이적실 명령 ACK와 다른 지표임을 작업자가 해석할 수 있어야 한다. 허용 반영 지연·업무일 정의·완료 문구 결정은 [CA-G01](BACKLOG.md#ca-g01)과 중앙 지표 담당의 작업이다.

<a id="ca-c08"></a>
## CA-C08 중앙 품목 CSV → CA 검증 캐시

**API:** `GET /inbound/api/item-catalog.csv`. CA [item_catalog_sync.refresh_item_catalog](../../item_catalog_sync.py)와 `ContainerAudit.load_items`가 요청·검증·사용하며, Web [api_item_catalog_csv / _require_item_catalog_csv_reader](../../../WorkerAnalysisGUI-web/blueprints/inbound/__init__.py)가 route와 읽기 권한을 소유한다.

4열 gate·오류 문구·canonical JSON·authority record/HMAC v2·authenticated payload 판정과
sidecar 이름은 고정 `kmtech_shared.catalog` core를 사용한다. CA facade는 program·URL
정규화/동일 authority 판정 함수를 명시 전달한다. 기존 인증 read/write/recovery와
snapshot dict/set, `_atomic_write` writer admission, profile/credential·HTTP·진단·시작 정책은
CA adapter에 남긴다. recovery → CSV → authority 내구 순서와 기존 v2 sidecar bytes는 불변이며
cache migration이나 앱 사이 cache 파일 통합은 없다. factory lock과 shared lock은 별개다.

검증 cache, 실제 사용 snapshot, startup diagnostic을 구분한다. 승인된 snapshot이 사라지거나 UTF-8 parsing이 실패한 경로는 오류다. legacy assets를 읽는 경우의 `utf-8-sig/cp949/euc-kr/utf-8` fallback은 중앙 검증 실패를 무조건 허용하는 정책이 아니다. [load_items](../../Container_Audit.py). API 읽기 권한·실제 갱신 및 유효 cache 허용 기간은 대상 서버 증거가 필요하다. [CA-02](README.md#ca-02), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c09"></a>
## CA-C09 CA ↔ Web 현품표 정합·출력 journal

현품표 후보 조회·교체 준비·교체 조회·print 요청/완료·활성화는 [LogisticsTransferClient의 phs 관련 메서드](../../transfer_seal.py), [PHSReconciliationExchangeCoordinator](../../phs_reconciliation_workflow.py), [PHSLabelExchangeJournal](../../phs_label_workflow.py)와 [Web phs route](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py)가 대응한다. 상세 payload와 지원 route는 이 소스의 정본을 참조하며 제품 member 교체 API와 합치지 않는다.

아래 route는 `/logistics/api/v1` 아래의 클라이언트 선언이다. 후보/정합 기본 경로와 단독 교체 호환 경로를 구분하며 실제 설치 서버의 활성 지원은 [CA-G05](BACKLOG.md#ca-g05)에서 확인한다.

| 호출 | 입력·용도 |
|---|---|
| `GET /phs-work-reconciliations/actions/resolve` | scope·scan payload·process context·limit로 정합 action 조회 |
| `GET /phs-work-instructions/candidates` | scope·업무일·품목·목표 제품 수·limit로 후보 조회; 목표 수는 원본 QR의 QT 추가가 아님 |
| `POST /phs-labels/adopt` | 원본 QR·scope·선택 expected session version을 이용한 기존 라벨 채택 경로 |
| `POST /phs-work-reconciliations/{id}/label-exchange/prepare` | action IDs·expected reconciliation version·멱등 key로 정합 교체 준비 |
| `POST /phs-label-exchanges/prepare` | exchange kind·sources·targets·key를 쓰는 별도 단독 준비 경로 |
| `GET /phs-label-exchanges/{id}` | scope와 exchange ID로 현재 상태 재조회 |
| `POST /phs-label-exchanges/{id}/prints` | label ID·key로 print attempt 요청 |
| `POST /phs-label-print-attempts/{id}/complete` | succeeded와 artifact hash/proof 또는 error code/message 기록 |
| `POST /phs-label-exchanges/{id}/activate` | expected exchange version으로 활성화 요청 |

scope·식별자·권한은 [LogisticsTransferClient](../../transfer_seal.py)가 검사하며 교체 준비/출력 요청의 멱등 key와 활성화 expected version의 역할을 구분한다. 모든 POST가 같은 키 필드를 갖는다고 가정하지 않는다.

**작업계획 변경의 CA 소비 경계(2026-09-11 소스 확인):** CA는 중앙에 게시된 PLANNED 지시 후보를 조회하고 실행 직전 instruction ID/version을 다시 대조한다. 정합 실행은 `EXCHANGE_DATE` 묶음 또는 단일 `SPLIT`/`MERGE`만 허용하며, current-actuals 계획의 `ADD`/`RESIZE`/`CANCEL`을 적용하는 소비자는 아니다. Web의 계획 적용·게시를 CA의 물리 라벨 prepare/print/activate와 구분한다. 일반 검사 목표는 검증된 중앙 GOOD member count이고, 단독 라벨 변경은 기존 canonical PHS2·스캔 목록·트레이 수량을 덮어쓰지 않는다. 열린 CA 트레이로 계획 변경을 자동 push하는 경로는 확인되지 않았으며, 시작 시 품목 cache 갱신을 작업계획 갱신으로 해석하지 않는다. [소스별 확인·배포 미입증 범위](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/PLAN-CONSUMER-AUDIT.md)와 [CA-G05](BACKLOG.md#ca-g05)에 후속을 기록한다.

source/target identity·membership·topology·version 및 action을 대조하고, 중앙 준비 상태와 로컬 출력 journal을 연결한다. 중앙 `PREPARED`, `PRINT_FAILED`, `PRINT_PARTIAL`, `READY`, `COMMITTED` 상태 및 로컬 ACK 대기 상태는 서로 다른 관측값이다. 출력 artifact hash와 `spool_job_id` 등 `_print_proof`를 확인한 뒤 print 완료·활성화 요청을 보낸다. [execute / _validate_exchange / _record_print_failure / _validate_artifact](../../phs_reconciliation_workflow.py).

중앙 commit과 로컬 journal 또는 실물 인쇄는 분산된 효과다. 출력 일부 성공·응답 유실·파일 변조는 재조회/확인과 정확한 journal 재사용으로 처리하고, 취소/재출력 가능 여부를 현재 중앙 상태에서 판단한다. 이 계약의 spool 증거는 실제 종이 배출·부착 증거가 아니다. [CA-11](README.md#ca-11), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c10"></a>
## CA-C10 현재 사용자 등록·설치 식별자·소유 증명

**bootstrap record 순서·ACL:** 새 `container-audit-bootstrap-integrity-v1` 목록은
상대 경로를 `[StringComparer]::Ordinal`로 정렬한다. 검증은 기존 record의 순서를
보존하되 실제 파일과 대소문자까지 같은 path의 일대일 대응, 정수 size, exact SHA256,
원래 aggregate를 모두 요구한다. 중복·누락·추가·대소문자 변조는 거부하며 record를
재발급하지 않는다. 일반/relocated 검증에 같은 순서 규칙을 적용하고 기존 code-root·layout
조건은 유지한다. ACL은 양 엔진에서 Access/Owner/Group과 owner SID·보호 여부·SDDL SHA256을
같이 대조한다. writer 계약/재고와 설치 leaf의 신뢰 pin·권한 판정 의미는 유지한다.

**2026-09-08 실제 복원 관측:** frozen d440의 공개 `RestoreVerifiedReplacement`는 진짜 a79 교체 receipt와 새 controller4e를 구별한 상태로 원 owner 종료/cold boot 뒤 exact a7를 복원했다. native/task0 및 old code/record·Run·동일 user/session relay·업무9/identity3 hash 유지, 재등록/credential 복사 없음은 [CA-O09](operations.md#ca-o09)의 Restore09 원본으로 확인한다. 실제 UAC No의 취소07과 동의 미관측08은 native1/runtime 회복으로 보존한다. 원 f2 receipt의 정상 재설치 후 record drift는 이 새 receipt의 성공으로 해소하거나 덮어쓰지 않는다.

**정상 진입:** [current_user_onboarding._registration_runner](../../current_user_onboarding.py)는 `--self-enroll --require-machine-credential-bundle --credential-scope current_user`로 등록 도구를 호출한다. 승인된 HTTPS origin의 `POST /api/producer-ingest/v2/enroll`을 사용하며 token은 `CONTAINER_AUDIT_ENROLLMENT_TOKEN` process 환경, 공개 CA는 `CONTAINER_AUDIT_ENROLLMENT_TLS_CA_BUNDLE_PATH`로 전달할 수 있다. TLS CA는 정상 등록 후 profile/producer 설정에 보존되는 경로이며 검증 해제나 기본 운영 origin fallback이 아니다.

로컬 identity가 없는 기본 경로는 [derive_path_independent_install_id / _resolve_producer_identity](../../tools/register_container_audit_worker_pc.py)의 MachineGuid+현재 사용자 SID+app+계약 버전으로 `producer_install_id`를 파생하고, 그 값에서 `source_host_id`와 기본 `producer_id`를 파생한다. hostname·설치 폴더·Hyper-V VM ID를 새로 정하는 것으로 이 lookup 식별자가 바뀌지는 않는다. 파일 경로 독립성은 재설치 식별 연속성을 위한 동작이며 서버 소유 증명을 대체하지 않는다. `producer_identity.json`·possession key·credential/epoch와 정상 reattach/관리자 recovery는 별도 상태다.

**실제 거부·정상 복구:** [2026-09-08 일반 설치 실패](E:/KMTech/ca-install-qualification-20260908/REPORT.md)에서 로컬 등록 자료 ABSENT인 복사 VM은 기존 중앙 producer/install 식별자와 같고 새 possession fingerprint는 달랐다. [Web 공개 lineage](E:/KMTech/web-integration-20260908/ca-enrollment-lineage.json)의 기존 active epoch6과 충돌해 `producer_identity_conflict` / `ADMIN_RECOVERY_REQUIRED`로 끝났다. Main의 기존 소유 배정 후 설치된 등록 도구의 `--admin-recovery-secret-file`·current_user 경로로 `ADMIN_RECOVERY_REGISTERED`/epoch7·서버/manifest 검증 true를 확인했다. recovery 직후 `OPERATION_PENDING`과 이후 Web의 범위·기간이 제한된 `SEAL_TRANSFER_BUNDLE` grant 승인은 별도 단계다. secret 파일은 제품이 성공 후 삭제했고 보호 입력의 값은 증거에 포함하지 않는다. 이 후속을 자동 소유권 이전이나 첫 enrollment PASS로 해석하지 않는다. [CA-G09](BACKLOG.md#ca-g09).

**설치 실패 상태:** [현재 canonical](../../INSTALL_CANONICAL_PORTABLE.ps1)의 `container-audit-canonical-portable-install-v2`는 새 `PASS_NEW_VERIFIED` 배치 뒤 후속 실패에서 runtime/current-user preimage만 복원하고 새 verified code가 남으면 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`와 남은 경로 경고를 기록한다. 기존 tree를 실제로 복원하는 교체 실패의 `FAILED_ROLLED_BACK`과 구분한다. 이는 상태 설명 수정이며 코드 삭제·복원 범위나 소유 증명 정책을 바꾸지 않는다. source68dd 동결 후보의 첫 실제 audit는 이전 `FAILED_ROLLED_BACK` 문자열을 그대로 보존하므로 [CA-O09](operations.md#ca-o09)의 관측 범위와 함께 읽는다.

**공개 사후 코드 복원 계약:** 현재 canonical의 `RestoreVerifiedReplacement`는 정확한 successor source/원 replacement receipt SHA·old/new 코드/record/ACL과 현재 사용자 runtime preimage에 결속한다. 과거 install owner/session/prepared 증명을 재사용하지 않고 새 controller session/attempt/transaction으로 현재 quiescence와 fence를 만든다. `code_replacement.transaction_id`는 원 교체, `controller_transaction_id`는 새 소유권이며 기존 replacement/code-restore receipt schema는 바뀌지 않는다. 정상 removal이 보존한 현 owner·업무 자료를 유지한 채 old code를 복원하고, 기존 Run 값을 fence 안에서 복원·검사한 뒤 fence 해제를 확인하고 원 relay 명령으로 process를 시작한다. 재등록·key/credential 복제·중앙 물류 rollback·오래된 DB snapshot 복원은 이 동작에 없다. 다른 historical sibling은 이 transaction의 입력이 아니지만 선택 root 이름은 동일 receipt transaction이어야 하고, 선택 tree나 integrity record drift는 그대로 거부한다. 자세한 지원/실패 상태와 실제 적용 범위는 [CA-O05/O09](operations.md#ca-o05)에 기록한다.

**최종 d440 별도 대상의 실제 등록 경계:** [CA-O10](operations.md#ca-o10)의 c029 VM은 실제 CA 코드/사용자·identity·relay 부재와 ordinary kmadmin session1/medium 및 PlanOnly0를 확인한 fresh-app 대상이며, 복사 OS의 MachineGuid/SID는 유지했다. 최초 정상 Install01은 실제 `producer_identity_conflict`로 native1 / `FAILED_RUNTIME_RESTORED_CODE_RETAINED`였고 exact d440 코드 배치는 `PASS_NEW_VERIFIED`다. 이 실패와 원본13파일을 보존하며 새 Hyper-V GUID나 빈 폴더를 무지원 중앙 등록 PASS로 해석하지 않는다.

Main의 새 QA 소유 배정 뒤 Web이 발행한 단회 recovery를 기존 지원 등록 명령으로 실행한 Recovery01은 ordinary native/task0 / `ADMIN_RECOVERY_REGISTERED`, epoch8이다. 제품이 이 대상에서 만든 실제 current_user fingerprint `bqMrBqbmdGBJjoPnV-JasvUTsdGnMdQKrdXCZrrc3S4`를 그대로 사용했고 producer/source `container-audit-source-20da23dc1c762b3c1055a10e3e2450c1`·install `container-audit-install-87f6d7d8b6e36067490c1d1146fcebeb`, semantic manifest `27c471d693d0de73377beaeeddbbc93aad90ac676b3b2a6c2fa388c37f4b7538`를 확인했다. [Web의14:06:14Z 독립 확인](E:/KMTech/web-integration-20260908/ca-final-recovery-central-readback-01.json)은 recovery 단회 소모와 기존97 receipt의 ID·full row hash/rowid 보존을 입증한다. 기존 key/identity·token·clock·ledger를 시험 도구로 바꾸지 않았으며 `OPERATION_PENDING`은 등록 성공과 별도 권한 상태다. 실제 상태가 회복된 뒤 Install02는 native/task0 / `PASS`·`REUSED_VERIFIED`로 정상 계속했다. [전체 원본·후속 lifecycle](E:/KMTech/ca-final-qualification-20260908/REPORT.md)을 따르며, 기존 Restore09는 원 receipt/VM 범위에서만 재사용하고 이 대상의 무지원 첫 등록 성공으로 승계하지 않는다.
