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

<a id="ca-legacy-transition"></a>
**과도기 모드(`KMTECH_LEGACY_LABEL_TRANSITION`):** 앱 시작 때 HKLM Session Manager Environment 값만 읽어 앞뒤 공백을 뺀 값이 `1`이면 켠다. 프로세스·사용자 범위 값은 보지 않고, 읽기 오류는 끔이며 자동 만료는 없다.
켜짐이면 모든 현품표를 받고, 완료마다 `TRAY_COMPLETE` detail에 분류(`transition_class`)·사유 코드(`transition_reasons`)·중복(`transition_duplicate`)·`source_computer_id`·`source_host_name`·`app_version`을 남긴다. 분류 이름과 공통 사유 코드는 LM과 같고(`PARTIAL_TRANSFER`는 CA만 쓴다), 사유 코드는 대문자 코드 모양(A-Z·0-9·`_`)만 쓴다. 서버가 준 오류 코드는 그 모양으로 바꿔 넣고(예 `temporary-unavailable` → `TEMPORARY_UNAVAILABLE`, 남는 글자가 없으면 `UNKNOWN`), 이전 판이 트레이 상태에 저장한 사유도 첫 완료 때 바꾼다(이미 시도한 완료 contract의 행은 다시 쓰지 않는다).

| 분류 | 뜻 | 사유 코드 예 | `transfer_seal_status` |
|---|---|---|---|
| `LEGACY` | 13자리 품목코드, 옛 QR(v2.0.9 `PHS=1\|CLC\|WID…`처럼 새 시스템 표식 없음, 또는 계보 키 없이 옛 QR 판독기가 읽는 `CLC`·`SPC`·`PHS` 단계 QR — `PHS=2`·`LBL` 값이 있어도) | `ITEM_UNCONFIRMED`, `DUPLICATE_LABEL`, 옛 QR 결함(`DUPLICATE_KEY`·`QT_INVALID`·`FORMAT_INVALID`) | `LEGACY_LOCAL_ONLY` |
| `PHS2_CENTRAL` | 정상 PHS=2가 중앙 사전조회·lease·봉인 흐름으로 완료(기존 그대로) | 없음 | 기존 값(`ACKED` 등) |
| `PHS2_LOCAL` | 정상 PHS=2인데 중앙·엄격 검사가 막음 | 사전조회 실패 코드(끊김 `PHS2_PREFLIGHT_UNAVAILABLE` 포함), 명령 전 봉인 검사 거절 코드(검사 구성원이 아닌 제품 `BARCODE_NOT_IN_SOURCE_BUNDLE` 등), `OPERATION_LEASE_REQUIRED`, `PARTIAL_TRANSFER`, `DUPLICATE_LABEL`, `ITEM_UNCONFIRMED` | `PHS2_LOCAL_ONLY` |
| `PHS2_MALFORMED` | 새 시스템 표식(`PHS=2`, `SRC=KMTECH_INPUT_TAG`, 계보 키 TRF·BND·ITG — 빈 값이어도, `LBL`·`HSH`·`HSH_CORE`·`HSH_LABEL`·`BUNDLE_ID`·`SOURCE_BUNDLE_ID` 값)이 어느 자리에든 있는데(중복 키의 앞 값 포함) 정확한 compact 라벨이 아님 | 결함마다 한 번씩 이 순서로 모두: `DUPLICATE_KEY`, `PHS_EMPTY`, `PHS_MISSING`, `PHS_NOT_2`, `LINEAGE_MISSING`, `QT_INVALID`, `FORMAT_INVALID`, `ITEM_UNCONFIRMED` | `PHS2_MALFORMED_LOCAL_ONLY` |

분류·사유는 Label_Match 와 같은 표를 쓴다(w9transitalign: `label_qr.py`의 공유 블록 — LM `label_transition.py`와 글자까지 같음, 벡터 `tests/transition_label_vectors.json` — LM 저장소에 같은 사본). 키는 대문자로 비교하고 빈 조각(`…|`, `||`)은 버리며, 반복 키는 모든 키(수량 키 QT·QTY·QUANTITY 둘 이상 포함)를 본다. `PHS_EMPTY`는 PHS 빈 값만, `LINEAGE_MISSING`은 SRC·ITG·LBL·HSH 중 하나라도 없음이며, 계보·품목이 다 있는데 정확한 compact 모양(`PHS=2|SRC=KMTECH_INPUT_TAG|ITG|CLC|LBL|HSH` 순서·키 대문자·HSH 16자리 16진수)이 아니면 `FORMAT_INVALID`다(다른 결함이 있으면 따로 세지 않음). 예전의 compact 세부 코드(`PHS2_COMPACT_FORMAT_REQUIRED`·`PHS2_CENTRAL_SOURCE_REQUIRED`·`PHS2_IDENTITY_INVALID`·`PHS2_HASH_PREFIX_INVALID`)는 분류 사유로 쓰지 않는다(중앙 흐름이 돌려주는 `PHS2_LOCAL` 사유는 그대로). 켜짐에서 엄격 해독이 풀지 못한 스캐너 Base64(URL-safe, 엄격 파서가 거절하는 라벨)는 LM 처럼 풀어 읽는다. LM 과 일부러 다른 것: 표식 없는 라벨의 옛 판독 범위(CA 는 CLC 만, JSON 포함), 품목 코드 없는 새 모양(CA 는 제품 품목 검사에 품목 코드가 필요해 그 현품표만 거절, LM 은 받음), 중앙 흐름의 막은 사유.

로컬 세 분류는 완료 때 중앙 조회·봉인 명령·SQLite intent 없이(부분 제출한 PHS2는 사전조회 때 받은 lease가 PREFETCHED로 남는다) 정상 완료와 같은 contract 저장 → 동기 `TRAY_COMPLETE` → 상태 삭제 순서로 끝나고 원장 수량을 바꾸지 않는다. 원문은 `master_label_code`에 남는다. 중앙 확인이 막힌 PHS=2(사전조회 실패·끊김)는 로컬 트레이를 시작하고 조회 중 보류 스캔을 그 트레이로 넘긴다. 단 `OPERATION_LEASE_NOT_YET_VALID`·연결 실패(통신·5xx)는 3초 뒤 같은 issue key로 한 번 더 조회한 뒤에만 로컬로 가고(w9cap1fix, P1-5), 그 조회로 이 PC에 발급된 lease는 [기기 해제](#ca-lease-release)로 돌려준다. 이미 완료한 현품표를 다시 찍으면 경고 뒤 시작해 `DUPLICATE_LABEL`로 기록하고, PHS=2면 중앙에 다시 묻지 않는다(원장에는 첫 건만). 이 회차는 재시작·보류 복원에서 앞 회차의 잔재로 지우지 않고(현품표+시작 시각으로 회차 구분), 재시작 집계도 회차별 intent id로 센다. 쓸 수 없는 QT는 `QT_INVALID`로 남기고 트레이는 기본 60개로 받는다(원장 수량으로 쓰지 않음). 13자리 코드는 같은 품목의 모든 트레이가 공유하므로 중복 판단과 완료 현품표 집합에서 뺀다. 품목 목록에 없는 품목, 중앙 품목 목록 없이 설치 목록으로 시작한 PC의 품목은 `ITEM_UNCONFIRMED`로 받고, PHS=2는 이때 로컬로 간다. 품목 코드(CLC, 새 모양이면 `ITEM`·`ITEM_CODE` 별칭도)가 없는 입력은 제품 품목 검사가 모든 제품을 거절하므로(`missing_item_code`) 켬에서도 그 현품표만 거절한다. lease 있는 정상 PHS=2 도 완료 lane 에서 완료 contract 가 중앙 intent 를 묶기 전(그 전에는 명령을 만들 수 없다)의 봉인 검사 거절은 한 경계에서 로컬로 끝낸다 — 구성원 불일치, 검사 사이에 만료된 lease 등. 드물게 intent 저장 뒤의 재검증이 거절하면 checkpoint 미확인 intent 한 줄이 SQLite에 남지만 명령으로 만들어지지 않는다(전송·재시도 모두 checkpoint 확인이 필요). coordinator 소유/스레드 오류는 로컬로 바꾸지 않고, 중앙 봉인 명령을 이미 보낸 뒤의 미확인·검토 대기는 원장 일관성 때문에 기존대로 잠근다.

**회차 분류 고정(09-29 결정):** 켬에서 시작한 회차는 시작 때 정한 분류를 트레이 상태(`transition_class`)에 저장하고, 재시도·재시작·보류 복원·스위치를 끈 뒤에도 그 분류로 끝낸다. 로컬 세 분류는 나중에 중앙 조회가 되더라도 봉인 명령·원장으로 가지 않는다. `PHS2_CENTRAL`로 시작한 회차도 켬 규칙(부분 제출·명령 전 거절 → `PHS2_LOCAL`)으로 끝난다. 완료 때 정한 분류는 완료 contract 와 함께 동기 기록 전에 저장돼, 재시도는 같은 사건 ID(`tray-complete:<intent id>`)·같은 행(timestamp 포함)이 된다. 분류가 없는 회차(끔에서 시작)는 엄격하고, 스위치를 켠 PC에서 복원하면 완료 때 분류가 정해진다.
꺼짐이면 옛 현품표와 새 시스템 식별값이 있는 PHS=2 아닌 현품표를 트레이 시작에서 거절한다(보류 트레이 스캔 복원 등 기존 경로 유지). 완료 현품표 재사용·목록에 없는 품목·PHS=2 부분 제출은 base처럼 막고 PHS2 흐름은 base와 같다. 켬에서 시작한 트레이는 끈 뒤에도 그 분류로 끝나고, 분류 없는(끔에서 시작했거나 업그레이드 전) 13자리·lease 없는 트레이의 완료 차단만 원인을 안내한다(문구만 다름).
서버 끊김으로 PHS2 보류가 이미 있으면(켜기 전 생긴 보류 포함) 켬에서는 13자리 현품표도 [다음 현품표](README.md#ca-04)로 받는다. [운영 절차](operations.md#ca-legacy-transition-ops), [CA-G17](BACKLOG.md#ca-g17).

## 3. 완료 상태와 관측 지점

작업 시작 시 금일 집계는 `session_history.load_session_history`에서 읽은 로컬 기록이다.
읽지 못한 행·파일은 건너뛰고 정상 자료를 유지하며, 폴더 소실·목록 읽기 오류도
`load_errors`에 기록한다. 오류가 있으면 집계가 0건이어도 GUI 경고로 구별하며
완전한 조회 성공으로 표시하지 않는다. 상세 경로·원인은 기존 진단 출력에만 남긴다.
오류 건수는 읽기/처리 오류 수이며 누락 트레이 수나 중앙 ACK 수가 아니다.

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

- 관리자 PIN의 로컬 파일 효과는 소비된 intent에 원 경로·보류 경로·원 바이트 SHA256을 먼저 fsync한다. 원자 이동 뒤 보류 파일을 검증하고, 불일치하면 덮어쓰기 없이 활성 위치로 복귀한다. 재시작과 오프라인 분리는 저장된 source·target·SHA256을 그대로 재사용하며 `SOURCE_UNMOVED`도 같은 목적지로 재개한다. 복구 `APPLIED` 뒤에는 정상 완료와 같은 메모리 snapshot·입력 잠금 해제를 적용하되 다른 활성 작업은 건드리지 않는다. 원본 변경은 `TARGET_CHANGED`로 남겨 재조회와 새 PIN을 요구하며, 양쪽 경로가 점유된 충돌은 두 원본을 남긴 채 해당 key를 보류한다.
- `APPLIED`는 완료 readback·메모리 정리가 끝났다는 표식이 아니다. 관리자 재조회와 앱 시작에서 같은 key의 보존 바이트·효과·완료 감사를 재검증한 뒤 해당 활성 상태만 정리하며, 완료 효과의 파일 이동·PIN 소비·감사를 반복하지 않는다. PIN intent·사전조회 격리 폴더의 열거 실패는 빈 폴더와 구분하고, 독립 감사의 미복원 격리 key만 보수적으로 보류한다. 미식별 폴더 오류 자체는 전역 잠금을 만들지 않으며 관리자 목록을 다시 열어 재확인한다.
- PRECHECK 격리의 `APPLIED` intent와 격리 원본은 각각 해당 key의 신규 스캔을 막는다. 보류 목록 복원은 기존 원 작업자/관리자 인증을 유지하고 원 FIFO를 활성 hold로 되돌린다. 복원 감사와 key·원본 hash가 결속된 내구 `RESTORED` 기록 뒤에만 intent guard를 해소하며, `RESTORING` 중단은 관리자 재조회로 이어간다. 해소는 원 FIFO의 중앙 재조회·계속 진행이며 새 빈 작업으로 대체하지 않는다. 식별 가능한 손상은 해당 key만, 미식별 원본은 기존 관리자 중앙 조회·감사 결속 전까지 보류한다.

- GUI·relay의 경로 우선순위는 명시 `--data-root`(결정 함수의 `data_root`) → `CONTAINER_AUDIT_DATA_ROOT` → 현재 사용자 HKCU relay Run 등록의 `--data-root` → 기본값이다. onboarding이 exact readback하는 기존 Run 값이 영속 설정이며 별도 중복 설정 파일을 만들지 않는다. 환경 없는 바탕화면·시작 메뉴 실행도 이 설정을 읽고 GUI 초기화·onboarding·재시작 명령을 같은 루트에 고정한다. custom 루트는 events·direct_sync·logistics-profile·bootstrap을 하위에 두며, 기본 설치는 인자 없는 명령과 기존 분리 경로를 유지한다. 등록 부재/정상 기본 등록만 기본값을 허용한다. 손상·읽기 거부된 등록이나 저장된 루트 소실·접근 오류는 기본 루트 생성·전송 없이 안내 후 종료한다. onboarding 보고의 `data_root`는 관측 기록이며 설정 입력이 아니다.

- 제품 형식 오류 안내는 길이/제어문자/위험 형식/트레이 설정의 판정 reason에 맞춘 안전한 문구를 일반·held 경로에서 공통 사용한다. [사유별 다음 행동](product-admission.md#형식-오류-안내의-다음-행동)은 라벨·스캐너 설정 확인 또는 담당자 문의이며, 위험 원문은 안내에 삽입하지 않고 기존 reason·hash·길이 진단을 유지한다. 문구 변경은 거부·수량·저장·ACK 조건을 바꾸지 않는다.

- 일반·held 제품의 current JSON atomic write/flush/fsync는 기존 직렬 UI lane worker가 수행한다. Tk는 저장 ACK 뒤에만 목록·수량·receipt·성공음을 한 번 반영하고, 실패하면 이전 목록·파일을 유지한다. 저장 중 들어온 다음 입력은 입력창에서 바로 꺼내 들어온 순서대로 메모리에 보관하고, 선행 저장이 성공으로 끝나면(경고가 떴으면 확인 뒤) 일반 스캔과 같은 검사로 하나씩 처리한다. 선행 저장을 추월하지 않는다. 선행 저장 실패·예외·epoch 변경, 목표 도달 완료, lane 고장, 다른 처리 중이면 보관 입력은 처리하지 않고 오류음과 `N개 … 다시 스캔` 안내를 낸다. 작업 전환(리셋·보류·복원·현품표 교체·작업자 변경·인계·완료 적용)은 그 전환의 안내 뒤에 같은 오류음·안내를 내고, 정상 종료는 오류음과 안내 창을 보인 뒤 닫는다(진행 중 저장은 기존처럼 마친다). 어떤 경로도 보관 입력을 소리·안내 없이 버리지 않는다. 그 밖에 거절한 입력도 입력창에 남기지 않는다(다음 스캔과 한 줄로 붙지 않음). 예외는 예약된 콜백이 이미 가진 값(스캐너의 두 번째 Enter)뿐이다. 보관 입력은 내구 저장 전이며 성공음·수량은 각자의 저장 ACK 뒤에만 나온다. held FIFO 제거는 이후 같은 worker의 동기 감사 ACK를 별도로 기다린다. 종료는 진행 중 lane과 held writer를 drain하며, epoch가 바뀐 결과는 새 트레이를 변경하지 않는다.
- 일반 비동기 사건은 원 시각·작업자·대상 CSV·details·멱등 key를 먼저 메모리 FIFO에 보존하고, writer admission을 얻어 `events/_event_outbox/*.json`에 atomic write/flush/fsync한 뒤 접수한다. admission의 5초 mutex timeout·fence 거절 또는 사본 저장 실패는 접수 False이며 원 payload/key를 메모리에 남겨 다음 허가된 쓰기에서 앞 사건부터 재시도한다. admission/fence 규칙은 모든 디스크 쓰기에 그대로 적용된다. writer는 순서대로 동일 key로 내구 CSV append를 재시도하고 성공 뒤 사본을 지운다. append 뒤 응답/정리 실패 및 재시작에도 같은 행을 중복 추가하지 않는다. 실패한 앞 사건을 동기 사건이 추월하지 않으며 완료의 별도 `LOCAL_EVENT_RETRY` 경계는 유지한다.
- outbox 순번은 남은 사본의 최대 순번을 이어받아 단조 증가하므로 시스템 시계 역행·재시작이 원 사건 순서를 바꾸지 않는다.

**방향:** GUI/coordination → 사용자 state·이벤트·intent → 같은 사용자 재시작 복구. [CA-01](README.md#ca-01), [CA-04](README.md#ca-04), [CA-08](README.md#ca-08), [CA-09](README.md#ca-09).

- `TraySession`은 원본 PHS2, 품목/목표, 스캔 목록·시간, preflight/lease 문맥과 복구 플래그를 보존한다. current JSON과 보류 JSON은 [ContainerAudit._current_tray_state_snapshot / _load_current_tray_state](../../Container_Audit.py), [tray_state](../../tray_state.py), [parked_tray_store](../../parked_tray_store.py)가 관리한다. 소유자는 작업자와 컴퓨터 문맥이며 다른 작업자의 같은 현품표 보류도 검사한다. 보류 목록은 각 파일을 한 번 검증해 건강한 행과 손상 확인 행을 함께 표시하고 원본을 유지한다. 짝 원본 인계는 두 파일의 바이트·경로·SHA256 기록을 fsync/readback→동기 감사→원본 이동/readback→해제 표지 순서로 결속한다. 기록 소실/손상·원본 해시 변경은 식별한 두 key만 보류하며, 어떤 원본으로도 key를 식별하지 못하면 관리자 스캔·중앙 읽기 전용 조회·내구 보류 전까지 작업대 잠금을 유지한다. 두 현품표는 신규 스캔뿐 아니라 격리/parked/current 복원과 늦은 preflight 활성화에서도 차단하고 원 파일·key를 보존한다. 관리자 격리·짝 인계·미확정 보류·재확인은 승인 때와 실행 때의 로그인 작업자·역할을 대조하고 승인 관리자를 감사에 남긴다.
- PHS2 중복 시작은 현재 parked 파일의 존재만으로 판단하지 않는다. [key 근거 열거](../../parked_tray_store.py)는 원본·격리 사본·원본 없는 marker·짝 기록/해제·stale current·로컬 감사 사건과 parked/current/hold/짝 기록·표지·이벤트 outbox·현품표 교환 journal의 fsync 후 남은 임시파일을 매번 열거한다. 유효한 임시파일도 자동 승격·복원하지 않고 해당 key를 보류한다. 최종 파일이 함께 있으면 둘 다 보존하고 로컬 감사를 남긴다. 내용·파일명으로 key를 모르면 관리자 현품표 확인과 중앙 읽기 전용 조회·감사 결속까지 보류한다. 손상된 필수 JSON 필드의 원 타입은 변환 전에 거부한다. 관리자 해소의 동기 감사가 `False` 또는 예외면 해당 행은 계속 보류하고 재시도할 수 있어야 한다. 인계 기록에 들어 있는 원본 경로는 현재 hold/current 슬롯과 일치해야 한다.
- 보류 폴더의 새 파일 이름은 긴 경로를 켜지 않은 Windows 한도(259자) 안에 들도록 길이를 묶는다. 이름에 넣는 작업자 이름은 16자, 엄격히 읽히지 않는 라벨(`parked_legacy_`)은 20자까지만 쓰고 넘으면 앞부분+SHA-256 7자로 줄인다(원문은 파일 안 필드). 관리자 식별 사본은 `<표시>.identified[-source]-<SHA-256 앞 16자>.json`이고 파일 안에 64자 전체를 결속한다. 그래서 임시 이름(`.<pid 10자리>.<uuid32>.tmp`)까지 포함한 모든 새 쓰기가 보류 폴더 root 88자까지 들어간다(현장 기본 `C:\Users\<20자>\AppData\Local\KMTech\ContainerAudit\parked_trays\`는 79자). 고정 길이인 짝 인계의 `paired_preflight_handoff\stale-current-<64>.json.manager-hold.json` 임시 쓰기는 root 85자까지다. 이전 판이 전체 작업자 이름·전체 SHA-256으로 지은 파일은 옮기거나 이름을 바꾸지 않고 그대로 읽고 이어서 쓴다. 그래도 한도를 넘으면 쓰기 전에 거절하고(`ParkedPathTooLong`, 파일 변경 없음) 관리자 식별 화면은 경로 한도와 그 현품표만 계속 보류한다는 안내를 보인다. [parked_tray_store](../../parked_tray_store.py)
- preflight hold는 `LOOKUP`, `LOOKUP_FAILED`, `DRAINING`과 FIFO sequence를 저장한다. 연결 실패(통신 예외의 `PHS2_PREFLIGHT_UNAVAILABLE`·HTTP 5xx)는 상태를 바꾸지 않고 `LOOKUP`에서 보류 접수와 30초 자동 재조회를 계속하며, 확정 실패와 로컬 예외(`PHS2_PREFLIGHT_LOCAL_ERROR`)만 `LOOKUP_FAILED`로 바꾼다. 끊김 표식은 기존 `error_code`에 내구 저장한다. 활성 hold 1개와 v1 schema·기존 격리 폴더·writer·이벤트 형식을 유지하며 서버 명령을 추가하지 않는다. 대기 수 < 20, 같은 원 작업자, 다른 key, 활성 트레이 없음, lane 한가·poll 없음, 새 현품표 기본 판정을 모두 확인한 뒤 기존 `quarantine`으로 이동하고 `PHS2_PREFLIGHT_HOLD_QUARANTINED`(reason=`offline_next_label`)를 동기 감사한다. 감사 실패는 되돌리고 신규 시작을 허용하지 않는다. 같은 key 대기 현품표의 재스캔은 원 작업자에게만 확인창 없는 `restore_quarantined`·`RESTORED` 감사·재조회를 제공하며 원 FIFO·lease PENDING key를 유지한다. 부정확한 sequence/schema/context는 오류다. FAILED hold의 새 작업 전환은 보류0건이라도 인증된 보호 관리자 격리·감사 기록을 요구한다. 일반 작업자 또는 재시작이 파일을 지우거나 다른 PHS2로 덮어쓰지 않는다. [preflight_scan_hold](../../preflight_scan_hold.py), [권한·quarantine 호출자](../../Container_Audit.py).
- seal intent 상태는 `PREPARED`, `COMMAND_READY`, `RETRY_WAIT`, `ACKED`, `OPERATOR_REVIEW`; `LINKED`는 별도 로컬 completion 기록이다. 둘을 한 enum으로 합치지 않는다. command bind 뒤 요청 문맥을 보존하고 completion checkpoint 이후 전송한다. [TransferSealStore](../../transfer_seal.py)
- CSV append는 경로별 process/interprocess lock을 쓰고 내구 모드에서 flush/fsync한다. 완료 재기록은 event type+idempotency key로 기존 행을 확인한 뒤 append한다. 색인·캐시·metadata로 사건의 부재를 판정하지 않고 기존처럼 CSV 전체 내용을 직접 읽는다. 같은 key라도 parsed details가 다르면 거부하며, held 성공/거부 역시 동기 감사 성공 전 FIFO head를 제거하지 않는다. GUI 완료의 prepared checkpoint·재시도 계약 저장·CSV join/fsync는 같은 lane worker에서 순서대로 실행하고 UI 단계만 Tk에 전달한다. 동기 복구 진입점도 같은 저장 순서를 실행한다. SQLite projection receipt와 CSV append 사이 종료 시에도 재생을 판단할 수 있지만 SQLite·JSON·CSV 전체를 하나의 transaction이라고 주장하지 않는다. [append_event_log_entry_idempotent](../../event_log_store.py), [complete_tray](../../Container_Audit.py)
- 되돌리기(`SCAN_UNDO`)·초기화(`TRAY_RESET`)·현품표 교체 취소(`HISTORICAL_REPLACE_CANCEL`)·제품 교환 취소(`PRODUCT_EXCHANGE_CANCELLED`)는 취소마다 정해지는 사건 ID(`scan-undo:`·`tray-reset:`·`historical-replace-cancel:`·`product-exchange-cancel:` + 해시 40자, `detail.idempotency_key`)로 동기 기록한다. ID는 취소 자체(되돌린 스캔·초기화한 트레이, 교체 세션, 교환 ID)로 정하고 사유는 넣지 않는다. 첫 시도의 timestamp·이벤트 파일·내용을 기억해(되돌리기·초기화는 트레이 상태 `cancel_event_attempts`에 저장, 교체·교환 취소는 재시작하면 없어지는 그 세션 동안 메모리) 재시도는 다른 사유(창 닫기)여도, 다음 날 재시작 뒤에도 같은 파일에 같은 행으로 쓰고, 그 파일에 같은 ID의 행이 있으면 다시 쓰지 않는다. 기록 응답을 잃은 뒤 재시도해도 행은 하나다(sub-04 R8·sub-05 R12·LM 여러 날 재시도 부류, base부터의 결함: Web F3는 같은 현품표의 두 번째 `TRAY_RESET`을 `LEGACY_REPLAY_CONFLICT`로 격리해 그 PC의 전송 줄이 검토로 멈췄다). 완료(`TRAY_COMPLETE`)는 원래부터 완료 contract의 `projection_log_name`·`observed_at`으로 같은 파일·같은 행을 다시 쓴다.
- 취소 실패는 목록 복원, 보류 복원은 대상 저장·감사와 원본 정리 순서, 손상 state는 격리/보존을 따른다. [undo_last_scan / restore_parked_tray](../../Container_Audit.py). 실패·재시작 각 경계의 실행 증거와 백업 복구 요구는 [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06)에 연결한다.
- 미확정 현재 묶음을 관리자가 보류할 때 current snapshot·기존 현품표 보류 중복을 확인하고, 원 snapshot의 parked readback과 동기 `TRAY_PARKED` 감사 뒤 current slot만 비운다. 원본 사건·SQLite intent/key·UNKNOWN은 바꾸지 않고, 같은 현품표의 신규 스캔은 보류 중복 guard로 막는다. `DRAINING` hold와 current의 부분 반영 불일치는 [짝 원본 인계](../../paired_preflight_handoff.py)로만 해제한다. 원 요청/영수증/key는 변경하지 않는다. [CA-G14](BACKLOG.md#ca-g14).
- 로컬 관리자 네 동작(`CA.PRECHECK_HOLD`, `CA.PAIR_RETRY`, `CA.PAIR_HANDOFF`, `CA.TRAY_HOLD`)은 [admin-pin.v1 클라이언트](../../container_admin_pin.py)의 기기 서명 요청으로 웹 개인 PIN을 확인한다. 원본 readback→operation key/intent fsync→서버 redemption→원본·로그인 epoch 재대조→기존 writer→전체 효과 readback·동기 감사 순서를 따른다. 응답 불명확성은 같은 key의 status로 해소하고, 소비되었으나 효과가 증명되지 않으면 해당 key의 intent와 원본을 보존한다. 소비 뒤 자체 중간 쓰기는 같은 key로 readback·재개하며 새 로그인 작업자의 원값과 전송 local_id를 감사한다. 오프라인 보류는 `UNVERIFIED_DETACHING`에서 원본 이전·readback·활성 해제를 완료한 뒤에만 `UNVERIFIED_OPERATOR_HOLD`와 완료 감사를 기록한다. 중단 시 같은 intent로 재개하고 지원하지 않는 원본 형식은 오류로 남긴다. 보류는 승인 효과가 아니며 해당 key만 막는다. 중앙 `CA.CENTRAL_RETRY`는 PIN 적용 대상이 아니다. 실제 서버·GUI 확인은 [CA-G14](BACKLOG.md#ca-g14)에 남긴다.

<a id="ca-c02"></a>
## CA-C02 검사 완료 구성원 → CA preflight·lease

**방향:** Inspection → Web canonical GOOD/NG → CA 조회. 생산자는 [Inspection _complete_linked_normal_session](../../../Inspection_worker/core/business_logic.py) 및 [complete_session](../../../Inspection_worker/core/direct_sync_runtime.py), 조회자는 [LogisticsTransferClient / TransferSourcePreflight](../../transfer_seal.py), 서버는 [logistics API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py)다.

| 경로 | 입력·응답에서 보존할 의미 |
|---|---|
| `POST /logistics/api/v1/sessions/{id}/complete` | 검사 완료의 ITG·품목·UOM·실제 GOOD/NG 구성원. CA가 재판정하지 않음. |
| `GET /logistics/api/v1/bundles/resolve` 및 `/phs-labels/resolve` | 원본 exact PHS2 identity, 현재 GOOD member와 unit↔barcode·품목/UOM·version 대조. |
| `POST /logistics/api/v1/operation-leases/issue` | authority scope·plane·epoch·대상 구성원과 요청을 묶은 검증 가능한 물류 operation lease. |

lease는 서명·keyring·binding·기간·membership 검증을 요구한다. 클라이언트 코드의 유효 duration 범위는 60초~24시간이며 실제 서버 발급 기간이나 현장 오프라인 보장 시간을 뜻하지 않는다. [terminal_operation_lease.validate_claims / verify_jws](../../terminal_operation_lease.py). 이미 저장된 로컬 완료가 있으면 `_verified_operation_lease`는 그 `operation_completed_at`으로 저장 lease를 재검증한다. 현재 시각의 만료만 보고 기존 완료를 취소하는 규칙과 다르며, 새 작업에 만료 lease를 사용하는 허가는 아니다. [TransferSealCoordinator._verified_operation_lease](../../transfer_seal.py). <a id="ca-lease-clock"></a>**시계 허용(w9cap1fix, P1-5):** 이 PC의 확인은 서버와 같게 발급 시각 30초 전까지 받는다(`LEASE_CLOCK_TOLERANCE`, 만료 쪽 허용 없음). 봉인에 싣는 완료 시각은 PC 시각이 발급보다 앞서면(30초 안) 발급 시각으로만 올린다 — 내리지 않고 만료를 넘지 않으며 새 열 없이 보정 폭만 로그에 남긴다. 발급 전 완료를 0초도 받지 않는 서버(537c966)가 이 완료를 거절해 완료 후 관리자 확인이 되지 않게 하기 위해서다. [_lease_completion_time](../../transfer_seal.py). <a id="ca-lease-release"></a>**기기 해제(w9cap1fix, P1-3 CA 몫):** 현품표 스캔 뒤 버린 트레이 — 현재 작업 초기화, 재시작 때 이전 작업 삭제, 과도기 켬의 로컬 전용 전환 — 의 쓰지 않은 lease를 `POST /logistics/api/v1/operation-leases/release`(`terminal-operation-lease-release-v1`, reason `LOCAL_RESET`, `HOLD_CANCELLED`는 CA에서 쓰지 않음)로 배경에서 돌려준다. 보내기 직전 lane 안에서(lease 발급과 같은 직렬 lane) 현재 트레이·그 lease의 완료 기록(issue attempt가 `PREFETCHED`가 아님, 로컬 completion, 봉인 intent·제품 교체 intent — 상태 무관)을 다시 보고, 하나라도 있으면 보내지 않고 지운다. 같은 PC가 같은 현품표를 다시 스캔해 서버가 같은 issue key로 같은 lease를 돌려주면(서버 `issue_in_transaction`의 기기·key 재생) 대기 해제를 지운다. 재시도는 연결 실패·시간 초과·5xx에만 30초 배경 재시도로 같은 key(lease_id+reason에서 정함)·같은 본문으로 하고 3초 한도를 쓴다. 409·400·404(해제 경로 없는 537c966)는 결과 코드만 기록하고 그만둔다. 200(재생 포함)이면 로그만 남기고 로컬 issue attempt는 그대로 둔다 — 새 기록 함수(writer sink)는 설치기의 writer semantics 비교를 바꿔 설치된 판 위 업그레이드를 막는다(`CODE_PRESTATE_WRITER_SEMANTICS_DIFFER`). 이 PC가 그 현품표를 다시 스캔하면 같은 issue key의 서버 서명 재생이 `RELEASED`를 알려 기존 경로로 기록되고 새 lease를 받는다. lease 만료가 지나면 재시도를 멈추고 관리자 화면 몫으로 둔다. 대기 목록은 메모리에만 있어 **앱을 다시 시작하면 재시도하지 않는다**([CA-G18](BACKLOG.md#ca-g18)). 저장하지 않고 종료는 호출하지 않는다(저장 질문이 lane을 비운 뒤라 한 번 더 lane을 돌려야 한다). 해제 실패는 작업을 막지 않는다. [_work_operation_lease_releases](../../Container_Audit.py). 조회 중 입력 보존은 CA-C01, lease 없는 PHS2 및 exact 불일치 차단은 [CA-07](README.md#ca-07)이다. 배포 identity/capability·만료 경계 실제 검증은 [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c03"></a>
## CA-C03 CA → Web 이적 봉인·receipt

완료 orchestration은 [tray_completion](../../tray_completion.py)의 명시 owner 함수로 위임한다.
기존 완료 signature·prepared attempt 객체·generator yield 순서를 유지하고, 최종 state 적용과
notice를 구분한다. scanner/held 감사 ACK·동기 복구·coordinator transaction은 원 소유다.
[경계와 소비자](tray-completion.md)를 따른다.

**API:** `POST /logistics/api/v1/transfers/seal`, 명령 `SEAL_TRANSFER_BUNDLE`; 재확인은 `GET /logistics/api/v1/receipts/{scope}/{key}`. 클라이언트 [seal_transfer / get_receipt / TransferSealCoordinator](../../transfer_seal.py), 수신 [Web API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py), 원장 [seal service](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py), 멱등 [replay_or_conflict](../../../WorkerAnalysisGUI-web/logistics_ledger/idempotency.py).

- **모듈 경계:** [transfer_client](../../transfer_client.py)는 `LogisticsTransferClient`·`SealAttempt`·`logistics_transfer_client_from_env`, [transfer_store](../../transfer_store.py)는 `TransferSealStore`, [transfer_common](../../transfer_common.py)은 기존 오류·값·owner guard를 소유한다. 기존 `transfer_seal` façade가 같은 객체와 signature를 재노출하며 역방향 import는 없다. coordinator와 그 env factory는 façade에 남고 GUI·member exchange의 기존 import를 유지한다. 저장된 attempt·schema SQL·prepared key/readback·local/central ACK 순서와 HTTP/SQLite transaction 소유는 불변이다.
- **profile 전달:** factory의 profile/legacy client 생성은 기존 `base_url`, `token`, `source_host_id`를 이름 있는 인자로 전달한다. constructor의 positional 호환과 기본값, profile 선택·required/probe 시점, device/ledger fallback은 유지한다. 새 관리 context나 wire 필드를 만들지 않으며 저장된 command/receipt를 현재 profile로 재결속하지 않는다.
- **인증·권한:** HTTPS JSON에 bearer/API token, `X-Logistics-Source-Host-Id`, `X-Logistics-Device-Id`, `X-Logistics-Program=Container_Audit`, `Idempotency-Key`를 사용한다. 서버 machine scope와 클라이언트 authority/plane/epoch가 맞아야 한다. redirect는 차단한다. 작업자 표시 이름은 이 권한을 대체하지 않는다. [LogisticsTransferClient._headers / _request / assert_authority](../../transfer_seal.py), [Web _identity 및 route guards](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py)
- **필수 의미:** scope/key, command type·contract, member IDs/hash/scanned barcodes, 예상 entity versions, source/work-group topology, operation lease를 불변 context에 연결한다. 상세 단일/작업그룹 payload는 `_build_command`, `_build_work_group_command`가 정본이다. 허용되지 않은 partial subset을 임의 생성하지 않는다.
- **원자성:** 중앙 transaction의 membership/소유·seal·receipt 효과는 서버 소유다. 로컬 SQLite `LINKED`, JSON checkpoint, CSV 완료 기록과 중앙 transaction은 분리되어 있다. `local_completion_id`가 있으면 중앙 대기/검토와 로컬 완료를 병행 표시할 수 있다. [complete_tray](../../Container_Audit.py)
- **중복·오류:** 동일 scope/key·동일 fingerprint 재생은 기존 결과를 조회하며 다른 fingerprint는 충돌한다. 전송 응답 유실 또는 committed 오류에서는 receipt를 조회한다. exact receipt 검증 뒤 `ACKED`, retryable은 `RETRY_WAIT`, 영구/정합 문제는 `OPERATOR_REVIEW`로 남긴다. CSV 실패의 `LOCAL_EVENT_RETRY`는 중앙 거부와 별개다. [attempt / record_error / record_receipt](../../transfer_seal.py)
- **완료 전 review 재확인:** 현재 트레이의 단일 bound `OPERATOR_REVIEW`는 원 command의 scope/key로 receipt만 조회한다. command 검증·exact receipt·lease 기록·로컬 ACK 저장이 모두 끝나야 완료 흐름을 재개하며 조회/검증 실패는 원 review를 유지한다. 관리자 보류는 중앙 명령이나 완료 수량을 확정하지 않는다. [recheck_operator_review_receipt](../../transfer_seal.py), [CA-G14](BACKLOG.md#ca-g14).
- **순서:** `pending_ids`는 생성 순서·rowid, `drain_pending_through`는 대상까지 FIFO 순회한다. <a id="ca-completion-wait"></a>GUI 완료는 이 순회의 모든 요청에 한 번의 대기 한도(`COMPLETION_SERVER_WAIT_SECONDS` 3초, 요청마다 남은 시간을 timeout으로)를 걸고, 서버가 답하지 않아(시간 초과·연결 실패·5xx·한도 도달) pending으로 남은 첫 의도에서 멈춘다. 그 의도와 뒤 의도(이번 완료의 `PREPARED` 의도 포함)는 durable 순서와 원 key를 그대로 두고 다음 완료(`서버 재확인` 완료 재시도 포함, 같은 한도)·재시작 복구 때 나간다. 로컬 완료 `LINKED`가 이미 있으므로 완료는 진행한다. 서버가 답했지만 pending인 의도(예: 원본 PHS 아직 없음 404)는 뒤 의도를 막지 않는다. 재시작 복구는 한도 없이 기존 요청 timeout을 쓴다. <a id="ca-background-seal-retry"></a>**배경 재전송(w9cap1fix, P1-2):** 대기 intent(`PREPARED`·`COMMAND_READY`·`RETRY_WAIT`)가 남으면 lane이 한가할 때 30초마다(`BACKGROUND_SEAL_RETRY_MS`) 같은 복구 drain을 다시 예약한다. 완료와 같은 3초 한도·같은 FIFO 멈춤·같은 hold 검사를 쓰고(hold가 막으면 보내지 않고 hold 해제가 복구를 예약), 제품 교체 drain은 하지 않는다. 새 완료·재시작 없이 서버 복구 뒤 ACK된다. 대기 건수는 lane이 만든 UI 사본으로만 화면(`서버 전송 대기 N건(자동으로 다시 보냄)`, `저장 전송` 카드 `완료 전송 대기 N건`)에 전한다. 각 attempt가 실패했다는 이유만으로 모든 뒤 명령을 무조건 막는 전역 strict FIFO라고 일반화하지 않는다. producer queue의 due-time 조건도 별도다. [drain_pending_through](../../transfer_seal.py), [bounded_wait](../../transfer_client.py)
- **명시적 관리자 재시도(2026-09-08 source 후속):** `retry_operator_review`는 coordinator owner·관리자 세션 재확인·완료 checkpoint/`LINKED`·아직 receipt가 없는 bound review를 요구한다. 명령 hash/key와 서명 lease/제품·완료 시각 검증 후 기존 동기 `_log_event`에 `TRANSFER_SEAL_REVIEW_RETRY_REQUESTED`를 내구 기록해야 요청을 보낸다. 이 사건은 local-only이며 새로운 producer 계약 사건이 아니다. 같은 불변 명령만 재전송하고 새 lease/키/완료 시각을 만들지 않는다. 성공 receipt의 exact membership·scope·원자 lease consumption 검증 뒤 ACKED로 전환하며 과거 review/outbox/audit는 남긴다. 실패한 명시적 재시도는 transport 오류여도 OPERATOR_REVIEW를 유지하고 자동 pending에 넣지 않는다. UI의 현재 review 조회는 ACKED를 제외하지만 전체 review 이력 조회는 유지한다. 정상 관리자 인증은 서버 machine capability를 대체하지 않는다. [구현](../../transfer_seal.py), [lease 기록](../../terminal_operation_lease.py), [UI](../../Container_Audit.py), [정책](../../event_stream_policy.py).
- **수용·잔여:** [CA-12](README.md#ca-12)의 local/central 각각 한 번·원 key 유지·중단 복구와 [CA-G01](BACKLOG.md#ca-g01), [CA-G04](BACKLOG.md#ca-g04). 중앙 ACK 후 포장 소비는 다음 계약의 별도 결과다.
- **실제 후속 범위:** installed `a7d714f6`의 정상 관리자 재시도와 backend `c0c0d51`에서 원 case02는 원 완료 시각07:46:27Z·lease fence1·명령을 유지한 채09:21:22Z receipt1/ACKED가 됐다. [독립 중앙 조회](E:/KMTech/web-integration-20260908/ca-original-retry-central-readback.json)와 [로컬 불변 비교](E:/KMTech/ca-install-qualification-20260908/review03-integrity-after-retry.json)가 이를 입증한다. 같은 시각 새 발급 grant는 기존 적시 완료의 finalization 권한을 대체하지 않으며, 원 완료 시각이 없는 만료 case03의 새 스캔을 허용하는 근거도 아니다.

관리자 재시도에서 lease 검증 등이 실패하면 UI는 관리자 인증·저장 기록 확인을 안내한다.
내부 예외 문구를 그대로 표시하지 않으며 원 예외·완료 기록·검토 상태와 재전송 조건을 유지한다.

<a id="ca-c04"></a>
## CA-C04 CA → Web 봉인 전 제품 교체

**API:** `GET /logistics/api/v1/replacements/good-source/resolve`, `POST /logistics/api/v1/bundles/{id}/members/replace`; `REPLACE_BUNDLE_MEMBERS`. [CA client/coordinator](../../transfer_member_exchange.py), [wire client](../../transfer_seal.py), [Web API](../../../WorkerAnalysisGUI-web/blueprints/logistics/api.py), [replace_bundle_members](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py).

정본 [MEMBER_EXCHANGE_POLICY](../MEMBER_EXCHANGE_POLICY.md)는 동일 품목·UOM, 1~2쌍, 대상 및 각 공여 bundle의 expected version을 같은 명령으로 CAS하는 조건을 규정한다. 공여 PHS는 `EXACTLY_ONE_ACTIVE_MEMBER`; 여러 member이면 `REPLACEMENT_SOURCE_NOT_SINGLETON`으로 차단한다. 1~2쌍 전체 성공 또는 전체 실패이며 기존 제품은 `PROCESS_DAMAGE_HOLD`로 이동한다.

receipt는 pair·exact membership/hash·version 및 `RETAIN_IDENTITY_LABEL`, `target_label_identity_remains_valid=true`, `target_label_membership_bound=false`를 증명해야 한다. 이 조건 없이 원래 실물 라벨이 계속 유효하다고 가정하지 않는다. 중앙 ACK 뒤 로컬 적용 중 종료는 intent와 현재 트레이를 대조해 복구한다. 봉인 뒤 CA 수정은 금지하고 Label의 별도 `REPLACE_SEALED_TRANSFER_MEMBERS` 계약으로 넘긴다. 그 계약은 새 seal revision/token/QR을 만들며 Label F4의 새 전자 QR 재확인까지 CA 작업과 혼동하지 않는다. [Label package_logistics](../../../Label_Match/package_logistics.py), [CA-10](README.md#ca-10).

현재 교체 intent의 결과 재확인은 원 intent/key에 한정한다. review의 bound 교체는 receipt 조회만 하며, 중앙 ACK 이후 로컬 적용이 `PENDING`일 때만 기존 재조정을 예약한다. 로컬 `OPERATOR_REVIEW`는 계속 관리자 대조 대상으로 남긴다. 관리자 보류는 현재 트레이만 별도 parked owner로 넘기고 중앙/로컬 교체 결과를 바꾸지 않는다. [CA-G14](BACKLOG.md#ca-g14).

화면 구성·목록/상태·결과 안내는 [member_exchange_view](../../member_exchange_view.py)가 기존 owner의 Tk thread에서 처리한다. admission·스캔 검증·prepare/attempt·ACK 로컬 적용·lease rotation은 원 owner/coordinator에 남는다. [상태·호출 경계](member-exchange-view.md).

capability의 `max_pairs=2`, `atomic`, `two_bundle_cas` 등은 [logistics_transfer_client_from_env](../../transfer_seal.py)가 대조한다. 실제 설치 서버의 활성 값과 동시 경쟁 결과는 미확인이다. [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-c05"></a>
## CA-C05 CA 파일 snapshot → producer ingest·projection

**방향/API:** CA relay → Web `POST /api/producer-ingest/v1/source-file`; multipart metadata+file. [build_source_file_plan / drain_one_relay_batch](../../direct_sync_push.py), [enqueue_completed_source_file](../../direct_sync_runtime.py), [Web producer_ingest_source_file](../../../WorkerAnalysisGUI-web/app.py), [handle_source_file_request](../../../WorkerAnalysisGUI-web/producer_ingest.py).

- **schema·키:** metadata는 contract, install identity, source_file_id, content SHA256, byte_length, row_count, batch identity를 포함한다. whole-file snapshot의 hash/바이트와 큐 상태를 맞춰 전송한다. 새로운 파일 내용은 단순히 이전 relay의 ACK로 생략할 수 없다.
- **권한·lease:** HTTPS의 HMAC·nonce·timestamp 및 producer runtime lease를 사용한다. runtime lease는 writer/producer 권한이며 CA-C02의 물류 operation lease와 다르다. 실제 write flag·등록 상태·provider는 [producer_runtime_client](../../producer_runtime_client.py), [Web route](../../../WorkerAnalysisGUI-web/app.py)의 대상 배포에서 확인해야 한다.
- **runtime core/facade:** 고정 `kmtech_shared.runtime`이 leaf·신원/응답 binding·호출자 transaction의 SQL을 처리한다. `producer_runtime_client`는 공개 함수명·writer guard와 CNG JWK/identity callback, ensure/prepare·transport·복구 정책을 소유한다. relay ACK와 다음 rotating token은 같은 앱 transaction에서 commit/rollback하며 core는 connection/commit을 만들지 않는다. exact-clone은 기존 보수적 TTL, 사전 POST 오류는 저장된 정확 만료·모든 guard를 만족할 때만 reissue하고 unknown-commit은 자동 만료 복구로 바꾸지 않는다.
- <a id="ca-lease-dead-renewal"></a>**lease 격리 자동 회복(2026-09-25):** 저장된 갱신 요청(pending, `runtime_fence` 포함)을 같은 issue key로 다시 보내 `STALE_RUNTIME_FENCE`를 받으면 그 fence는 다시 ACTIVE가 되지 않는다는 서버의 확정 답이다. relay 행에 묶인 권한(`assigned_relay_id`)이 없으면 liveness와 행 준비 모두 기존 만료 전이(`_replace_expired_identity`: 새 runtime 신원·새 key의 증명 없는 발급)로 같은 주기에 다시 요청한다. 교정 전 판본이 남긴 같은 조건의 `OPERATOR_REVIEW`도 첫 주기에 풀린다. fence 번호(max+1)와 살아 있는 복제본의 `EXACT_CLONE_RUNTIME_CONFLICT` 거절은 서버가 정하며, 응답을 잃은 갱신은 같은 key 재전송이 저장된 grant를 돌려받는다. `STALE_RUNTIME_REQUEST_TOKEN`·묶인 행·unknown-commit은 자동으로 풀지 않는다(자료 경로는 [아래](#ca-lease-dead-fence-datapath)). 자동으로 풀리지 않는 lease 검토는 relay 상태에 `runtime_lease.status=operator_review`로 남고 전송 카드가 경고 등급의 '서버 반영 멈춤 / 작업 계속 가능 · 관리자에게 알려 주세요'를 보인다. 스캔은 막지 않는다. 서버 계약·`kmtech_shared.runtime`·writer sink 목록은 바꾸지 않는다. [producer_runtime_client](../../producer_runtime_client.py), [direct_sync_health](../../direct_sync_health.py)
- <a id="ca-lease-dead-fence-datapath"></a>**자료 경로 dead fence 회복(2026-09-26):** 행이 묶은 fence N이 끊김 중 만료되면 observe 서버는 같은 본문 재전송의 원본을 커밋하고 `runtime_lease={contract_version, observed_rejected, STALE_RUNTIME_FENCE}` 영수증을 준다. 커밋된 `observed_rejected` 영수증은 observe 서버만 주므로(enforce 서버는 409 미커밋) 클라이언트 모드는 보지 않는다(등록 도구의 자격증명에는 `runtime_lease_mode`가 없어 기본 enforce, w9calmenforce). 2xx·기존 엄격 ACK 검증(identity·trace·totals, `errors=0`, `quarantined=0`)과 contract_version이 맞으면 행을 ACK하고(`_local_runtime_lease_status=dead_fence`), 같은 transaction에서 권한이 이 행·같은 runtime 신원·같은 fence에 ACTIVE로 묶여 있을 때만 기존 만료 전이(`_replace_expired_identity`)로 푼다. 다음 liveness가 증명 없는 발급으로 fence N+1을 받고, 살아 있는 복제본이 있으면 `EXACT_CLONE_RUNTIME_CONFLICT` 검토로 멈춘다. 묶음이 다르면 행·권한 모두 지금처럼 `STALE_RUNTIME_FENCE` 검토다. `STALE_RUNTIME_REQUEST_TOKEN`·검증 실패 영수증·enforce 409(미커밋)·전송 오류와 lost-ACK(같은 본문 재전송)는 그대로다. 같은 원본을 새 fence로 다시 보내지 않는다(observe 서버는 409 `idempotency_conflict`). 교정 전 판본이 이미 검토로 보낸 행·권한은 풀지 않는다. 서버·`kmtech_shared.runtime` 불변, writer sink는 결정 함수 1개 추가(직접 쓰기 0). [direct_sync_push](../../direct_sync_push.py), [producer_runtime_client](../../producer_runtime_client.py)
- **scope 전달:** facade·ensure·prepare는 기존 `_scope_values`의 `credentials`, `producer_install_id`를 이름 있는 인자로 전달하며 positional 호환·기존 문자열 처리를 유지한다. runtime DB의 `authority_scope`는 endpoint/producer/key/install tuple의 기존 canonical 해시로, CA-C03의 물류 authority scope와 다르다. 관리 차원 부재는 기존 legacy 해석을 유지하고 required identity 누락은 계속 실패하며, metadata/HMAC·queued snapshot을 재작성하지 않는다.
- **엄격 ACK:** 2xx만으로 충분하지 않다. committed·identity, request/upload trace의 일치, `status=accepted`, `retryable=false`, error 없음, `next_retry_after=null`, `projection_disposition=COMPLETE`, inserted/replayed/errors/quarantined 행 합계와 `errors=0`, `quarantined=0`을 함께 확인한다. 예외 하나: `RAW_LEGITIMATE`는 서버가 원문 증거로만 두는 행만 올렸을 때 성공이다(w9webrecv, Label_Match의 수명주기 행 규칙과 같은 방식). 올린 모든 행이 stage-1 reducer 없는 원문 전용 카탈로그 사건(`TRAY_RESET`, `MASTER_LABEL_REPLACEMENT_APPLIED`, `PHS_RECONCILIATION_ACTION_RESOLVED`·`_LABEL_EXCHANGED`, `PHS_REPLACEMENT_WAITING_MARKED`, `POST_REVIEW_REQUIRED`, `TRANSFER_WAITING_OBSERVED`, `CONTAINER_AUDIT_OBSERVED`)이거나 이 PC(`source_host_name`이 이 PC 호스트 이름)가 쓴 [과도기](#ca-legacy-transition) `TRAY_COMPLETE`(`transition_class` 있음)이고, 영수증 `event_classifications`가 각각 `RAW_EVIDENCE_ONLY`·`NOT_PROJECTED`·`projection_required=false`·`raw_only_reason_code`(`NO_STAGE1_REDUCER`, 과도기 완료는 `TRANSITION_DUPLICATE_OBSERVED`)로 값과 타입까지 같고(숫자 0은 false가 아님) 사건 이름별 수가 올린 스냅숏(같은 SHA256·바이트)의 행과 같아야 한다. 그 밖의 `RAW_LEGITIMATE`는 지금처럼 실패(검토)다. [_committed_receipt_issue 및 응답 분류](../../direct_sync_push.py)
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

[과도기](#ca-legacy-transition)의 로컬 완료(`LEGACY`·`PHS2_LOCAL`·`PHS2_MALFORMED`)도 같은 CSV 통로로 올라가 `TRANSFER_LEGACY`로 투영된다(Web e356a09 판독: `master_label_code`로 식별을 통과하고 seal 상태·`transition_class`는 읽지 않는다). CA가 물류 명령을 보내지 않으므로 재고·이적·출고 원장에는 들어가지 않는다. `PHS2_LOCAL`의 ITG·LBL은 `inspection_product_index`에 들어가지만 출고 검증은 HSH_CORE·HSH_LABEL까지 있는 행만 읽어 영향이 없다. 대시보드는 분류를 구분하지 못하고, `transfer_legacy_projection`은 13자리 트레이를 품목코드 키로 덮어쓴다. [CA-G17](BACKLOG.md#ca-g17).

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

요청 profile은 `prepare_startup_item_catalog`가 물류 client와 같은 선택([CA-O02](operations.md#ca-o02))으로 `refresh_item_catalog(profile_path=)`에 넘긴다. profile이 없으면 운영 원본으로 무인증 요청을 보내지 않고 `PROFILE_ABSENT`로 로컬/패키지 목록을 반환한다.

실행 중 수동 갱신도 `prepare_startup_item_catalog → refresh_item_catalog → load_items`를 사용한다. `CENTRAL_REFRESH` 결과의 읽기·색인 구성까지 성공한 뒤 메모리 목록/색인을 함께 교체한다. 실패·기존 cache 반환·작업 세대 변경 시 이전 메모리 목록과 활성 CSV 경로를 유지하며 앱을 종료하지 않는다. 시작 시 기존 오류/캐시 정책, 활성 업무 데이터 루트·relay·영속 루트 선택은 바꾸지 않는다. 기존 lane이 갱신 중 새 스캔/동시 갱신을 거부하고, 기존 조회 보류·완료 guard가 진행 중 작업의 목록 교체를 막는다.

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

**은퇴 제거 마감:** canonical의 `CompleteRetiredRemoval`은 관리 `SourceRoot`를 자기결속 검증한 뒤,
별도 `OldSourceRoot`의 manifest·helper/guard pin·writer 계약을 검증한다. 배치할 새 코드가 없는 제거
연산이며 installed의 의미·manifest·aggregate·원 integrity record는 exact old 패키지와 대조한다.
일반 설치/교체의 source↔installed 의미 비교는 유지한다. 기본 은퇴 루트의 removal receipt SHA와
stop marker SHA·request ID·경로·현재 사용자 및 채택 루트를 결속하고 원 marker를 삭제/덮어쓰기하지 않는다.
JSON이나 marker는 정지·승인 증명이 아니다. 현재 Run/relay exact binding, legacy writer 거부,
살아 있는 session authority/delegation, 하위 old helper의 승격·전체 코드 writer 정지 검사를 모두 요구한다.
새 stop 요청은 선행 marker가 없는 채택 루트에만 생성하며 실패 시 exact code/Run과 원 은퇴 정지를 복구한다.

**은퇴 마감의 중단 재개:** `ResumeRetirementReceiptPath/Sha256`은 같은 관리 패키지와 exact old 입력,
현재 사용자·두 루트·원 기록·귀속된 active marker/receipt, 원 owner의 PID/시작 시각과 authority 종료를
검증하는 별도 경로다. 새 session/attempt/authority 아래 진행하며 일반 canonical의 선행 marker 거부를
해제하지 않는다. 불명 상태·다른 owner/attempt·바뀐 marker/receipt·부분 코드 손상은 보존하고 거부한다.
원 PID를 다른 프로세스가 재사용한 경우에도 거부하며, 같은 원 transaction의 동시 재개는 원자 mutex
claim으로 한 개만 받는다. writer admission 안에서 journal·두 marker/receipt·fence SHA를 다시 확인한다.
완료 재확인은 코드/Run/relay/active marker 부재와 원 fence release receipt까지 대조한다.
중앙 identity의 은퇴/재발급이나 원 은퇴 루트 재활성화는 없다. [운영·검증 한계](operations.md#ca-retired-removal).

**예약 writer 식별:** 정식 작업 `direct-sync-relay-container-audit`/`\`만 기존 실행·현재 사용자·1분 TimeTrigger·설정 계약을 만족할 때 canonical이다. qualification 이름과 다른 이름으로 실행하는 명시적 direct-sync/user-relay, hosted flag 없이 `tools/direct_sync_relay_runner.py`를 직접 호출하는 action도 검사 대상이며 활성 비정식 writer는 설치를 차단한다. 다중 action 중 하나라도 해당하면 검사한다. 직접 script Execute 또는 Python(`python*.exe`/`py.exe`, venv 포함)의 인수를 Windows quoting 규칙으로 나눈 뒤 옵션·옵션 값을 건너뛴 첫 script 경로를 정규화하고, 검증된 writer inventory의 Python `.main` route와 대조한다. `-c`/`-m`/stdin 및 도움말·버전 모드는 후속 인자를 script로 보지 않으며, Notepad·탐색기·다른 실행 파일이 같은 경로를 여는 경우도 제외한다. null/빈 trigger·없는 CIM 필드는 예외 대신 비정식 판정/명시적 shape 거부로 처리하고 정상 작업의 normalized binding bytes와 복원 hash 검증은 유지한다. [설치 경계](operations.md#ca-o05)

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
