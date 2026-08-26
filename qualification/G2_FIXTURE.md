# Container_Audit g2/g3 발사 전 fixture

> 상태: **SOURCE-ONLY / NOT RUN / HOLD**
>
> 이 문서는 g2·g3 성공 기록이 아니다. 아래 후보를 실제 비운영 서버에 준비하고, headed 앱에서 물리 스캔과 동일한 UI 이벤트를 실행한 뒤에만 판정할 수 있다.
>
> 기준일: 2026-08-26 (KST)

## 1. 핵심 트랜잭션 1건과 선정 이유

**고정 트랜잭션 `CA-PHS2-EXACT-2-SEAL`**: 작업자 `QUALIFICATION-OPERATOR`가 발사 시 `ACTIVE`로 준비돼 있어야 하는 PHS=2 현품표 한 장을 스캔하고, 그 중앙 work group의 exact membership인 제품 바코드 두 개를 차례로 스캔하여 `SEAL_TRANSFER_BUNDLE` 이적 봉인을 한 번 완료한다. 같은 완료가 로컬 `TRAY_COMPLETE`, producer-ingest receipt, 공통 projection, 대시보드까지 이어지는지를 관찰한다.

이 트랜잭션을 고른 이유는 다음과 같다.

- 앱의 정상 작업면은 `1 / 2 · 현품표 스캔`에서 시작하고 하나의 `scan_entry`가 `<Return>`을 `process_barcode`에 연결한다 (`Container_Audit.py:5921-5939`).
- 첫 현품표가 PHS=2이면 품목 카탈로그 확인 뒤 중앙 preflight로 들어간다 (`Container_Audit.py:7125-7169`). compact PHS=2 형식은 `PHS,SRC,ITG,CLC,LBL,HSH` 여섯 필드만 허용하고 `PHS=2`, `SRC=KMTECH_INPUT_TAG`, 16자리 hex `HSH`를 강제한다 (`transfer_seal.py:307-352`).
- PHS=2 완료는 중앙 membership 수와 실제 스캔 수가 정확히 같아야 하며 동작 자체가 `이적 봉인 및 완료`이다 (`Container_Audit.py:7445-7473`). 두 번째 제품으로 목표 수량에 도달하면 별도 테스트 훅이나 완료 버튼 없이 `complete_tray()`가 자동 호출된다 (`Container_Audit.py:7219-7310`).
- 완료 시 앱은 동기식으로 `TRAY_COMPLETE`를 기록한다 (`Container_Audit.py:7789-7816`). 이 이벤트의 source 계약은 `container_audit / legacy_transfer_csv / TRAY_COMPLETE`이고 (`Container_Audit.py:1179-1186`, `event_contracts.py:7-25`), 서버는 이 조합을 `TRANSFER_LEGACY`로 투영한다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:4753-4807`). 따라서 g2의 실제 UI 트랜잭션과 g3의 서버 관찰값이 한 사건으로 연결된다.

fixture 값 자체는 저장소의 격리 qualification authority가 선언한 source-derived 후보이다 (`tools/isolated_qualification_authority.py:95-118`). 다만 그 파일은 이 후보를 `physical_scanner_proven: false` 및 격리 Sandbox 전용으로 명시한다 (`tools/isolated_qualification_authority.py:202-211`). 이 문서에서는 값을 재사용하되 Sandbox를 기동하거나 그 응답을 g2/g3 증거로 사용하지 않는다.

## 2. 앱 기동 명령과 visible-window 기준

설치 패키지 기준 PowerShell 명령은 인자 없이 다음과 같다.

```powershell
& 'C:\KMTech\Apps\Container_Audit\current\Container_Audit.exe'
```

설치 스크립트가 canonical install root를 `C:\KMTech\Apps\Container_Audit\current`로 고정하고 그 아래 `Container_Audit.exe`를 앱 실행 파일로 선택한다 (`INSTALL_THIS_PC.ps1:3006-3045`).

**visible-window 판정**은 다음 두 항목이 동시에 보이는 headed 최상위 창이다.

1. 창 제목이 `이적 검사 시스템 (`으로 시작하고 `)`로 끝난다. 실제 제목은 `이적 검사 시스템 (<CURRENT_VERSION>)`이다 (`Container_Audit.py:1175-1178`, `Container_Audit.py:1214-1224`).
2. 중앙 로그인 화면에 `작업자 이름` combobox와 `작업 시작` 버튼이 렌더링된다 (`Container_Audit.py:1911-1977`).

콘솔 출력, 프로세스 존재, 로그 파일만으로는 visible-window를 대체하지 않는다. 첫 실행은 중앙 품목 카탈로그를 새로 확인하고 검증 snapshot이 없으면 창 진입 전에 중단한다 (`Container_Audit.py:11242-11261`, `Container_Audit.py:11275-11315`).

## 3. 정확한 입력 widget/key와 source-derived 바코드

### 고정 입력값

| 역할 | 정확한 값 | 소스 |
|---|---|---|
| 작업자 | `QUALIFICATION-OPERATOR` | `tools/isolated_qualification_authority.py:101-103` |
| 품목 | `AAA2270730100` | `tools/isolated_qualification_authority.py:95-96` |
| **실제로 스캔할 ACTIVE PHS=2 현품표** | `PHS=2\|SRC=KMTECH_INPUT_TAG\|ITG=QUAL-ITAG-001\|CLC=AAA2270730100\|LBL=QUAL-WORK-LABEL-001\|HSH=eeeeeeeeeeeeeeee` | `tools/isolated_qualification_authority.py:109-118` |
| 제품 1 | `AAA2270730100-QUAL-SERIAL-001` | `tools/isolated_qualification_authority.py:114-118` |
| 제품 2 | `AAA2270730100-QUAL-SERIAL-002` | `tools/isolated_qualification_authority.py:114-118` |

`QUAL-INPUT-LABEL-001`이 든 source QR은 upstream 완료 input-tag anchor일 뿐 operator가 이 트랜잭션에서 스캔할 현품표가 아니다. operator 입력은 `LBL=QUAL-WORK-LABEL-001`인 위 ACTIVE work-label QR이다. source fixture도 work group/active label을 `ACTIVE`, member count 2, 동일 scan payload로 선언한다 (`tools/isolated_qualification_authority.py:260-361`). 중앙 preflight 뒤 앱은 실제 스캔한 ACTIVE label과 별도로 canonical input-tag QR을 tray의 `master_label_code`로 저장하므로, 아래 projection identity는 source QR이 된다 (`Container_Audit.py:6466-6491`, `Container_Audit.py:6785-6793`, `transfer_seal.py:1240-1261`).

### 실제 UI 입력 시퀀스

키보드형 스캐너는 각 문자열을 `scan_entry`에 넣고 끝에 Enter를 보내는 것으로 고정한다. 붙여넣기, 내부 테스트 명령, 로그 주입, API 직접 호출은 이 시퀀스의 대체물이 아니다.

1. 로그인 화면의 `작업자 이름` combobox에 `QUALIFICATION-OPERATOR`를 입력하고 **Enter**를 누른다. 해당 combobox의 Return이 `start_work`에 연결되어 있다 (`Container_Audit.py:1939-1960`). 작업자는 발사 전에 등록돼 있어야 하며, 실행 중 신규 등록 분기로 fixture를 바꾸지 않는다.
2. 메인 작업면의 `scan_entry`에 ACTIVE PHS=2 현품표 문자열 전체를 넣고 **Enter**를 누른다. `scan_entry`의 Return은 `process_barcode`에 연결되고 입력값을 읽은 직후 entry를 비운다 (`Container_Audit.py:5929-5939`, `Container_Audit.py:7056-7073`).
3. 중앙 preflight가 끝나서 단계 표시가 `2 / 2 · 제품 스캔`, 수량이 `0 / 2`가 될 때까지 기다린다. 앱은 active tray에서 이 단계와 동적 목표 수량을 그린다 (`Container_Audit.py:8112-8124`).
4. 같은 `scan_entry`에 `AAA2270730100-QUAL-SERIAL-001`을 넣고 **Enter**를 누른다. 수량 `1 / 2`와 성공색으로 추가된 최신 스캔 행을 확인한다 (`Container_Audit.py:7219-7310`).
5. 같은 `scan_entry`에 `AAA2270730100-QUAL-SERIAL-002`를 넣고 **Enter**를 누른다. 이 Enter가 이 트랜잭션의 시간 기준 `t0`이며, `2 / 2` 도달로 완료 및 이적 봉인이 자동 시작된다 (`Container_Audit.py:7285-7310`).

순서를 포함한 세 문자열을 그대로 보존한다. 다른 바코드, 중복 바코드, 품목코드가 다른 바코드는 fixture가 아니다.

## 4. 로컬 visible success 판정

g2의 로컬 성공 표시는 **ACKED 전용 완료 notice**로 고정한다.

- notice 제목: `서버 이적 확인 완료`
- notice 본문: `서버 이적 확인이 완료되었습니다.`
- 상태 카드: `완료`(success/green)

`WarningPresenter.server_confirmed`는 오직 `CompletionOutcome.ACKED`에만 참이고, 위 제목·본문도 ACKED 기본값이다 (`warning_presenter.py:103-105`, `warning_presenter.py:127-140`). 앱은 notice title/message를 중앙 notice surface에 렌더링하고 ACKED 또는 LINKED이면 상태 카드를 `완료`로 표시한다 (`Container_Audit.py:8310-8351`, `Container_Audit.py:8426-8431`). 따라서 **상태 카드 `완료`만으로는 부족하며 위 ACKED 제목과 본문까지 동시에 보여야 한다.**

`이적 연계 완료`(LINKED), `서버 이적 확인 대기`, `완료 기록 저장 재시도`, `완료 확인 필요`, 오류/경고 dialog, 또는 스캔 목록이 잠긴 상태는 로컬 성공으로 판정하지 않는다 (`warning_presenter.py:127-163`). receipt ID는 의도적으로 operator notice에 렌더링되지 않으므로 (`warning_presenter.py:53-61`, `warning_presenter.py:166-178`) g3에서 별도 서버/receipt 증거로 수집한다.

현재 이 표시는 실행으로 관찰되지 않았다. 위 문자열은 실행 전 판정 규칙일 뿐이다.

## 5. g3 서버 기대값: receipt / projection row / dashboard surface

`t0`는 제품 2 Enter 입력 시각이다. `t0 + 5분` 이내에 물류 receipt와 `TRAY_COMPLETE`의 transfer 식별자를 맞추고, producer receipt와 `common_ingested_events`/projection의 source-file identity를 맞춰야 한다. dashboard는 event identity를 노출하지 않는 aggregate이므로 같은 날짜·품목의 발사 직전 baseline 대비 정확한 `+2`로 상관한다. 다른 세션이나 기존 aggregate 행은 증거가 아니다.

### 5.1 receipt 기대값

#### A. 물류 seal receipt

앱은 `POST https://server5.autoloop.test:18457/logistics/api/v1/transfers/seal`을 호출하고 lost ACK이면 `GET https://server5.autoloop.test:18457/logistics/api/v1/receipts/{scope_id}/{idempotency_key}`로 같은 receipt를 회수한다. path 근거는 `transfer_seal.py:2170-2218`, origin 근거는 `E:\KMTech\autoloop-20260824\APP_PREQUALIFICATION_MAP.md:99-102`이다. 기대값은 다음과 같다.

| 필드 | 기대값 |
|---|---|
| `contract_version` | `logistics-v1` |
| `command_type` | `SEAL_TRANSFER_BUNDLE` |
| `status` | `COMMITTED` |
| `receipt_id`, `committed_at` | 빈 문자열이 아닌 runtime 값 |
| `authority_scope_id` | `QUALIFICATION-CONTAINER-AUDIT` |
| `event_ids`, `outbox_ids` | 각각 빈 값이 아닌 원소 정확히 1개 |
| `data.atomic` | `true` |
| `data.receipt_contract_version` | `PHS_WORK_GROUP_TRANSFER_V1` |
| `data.source_resolution_basis` | `PHS_WORK_GROUP_EXACT_MEMBERSHIP` |
| `data.item_id`, `data.uom` | `AAA2270730100`, `EA` |
| `data.member_count`, `data.scanned_barcode_count` | `2`, `2` |
| `data.scanned_barcodes` | 위 두 제품 바코드의 exact set |
| `data.members`, `data.sealed_members` | `qual-unit-001` ↔ `AAA2270730100-QUAL-SERIAL-001`, `qual-unit-002` ↔ `AAA2270730100-QUAL-SERIAL-002`의 exact mapping |
| `data.source_bundle_ids`, `data.source_session_ids` | `['QUAL-PHS-SOURCE-001']`, `['QUAL-ITAG-001']` |
| `data.phs_work_group.group_id`, `.label_id` | `QUAL-PHS-WORK-GROUP-001`, `QUAL-WORK-LABEL-001` |
| `data.post_seal_exchange_policy` | `BLOCKED_REQUIRES_TWO_BUNDLE_CAS` |

명령 상수의 소스는 `transfer_seal.py:37-46`이다. 앱은 receipt의 COMMITTED 상태, authority/plane, 하나의 event/outbox, atomic topology, exact membership/barcode mapping을 fail-closed로 검증한다 (`transfer_seal.py:4168-4208`, `transfer_seal.py:4493-4633`). 관찰 시 `receipt.receipt_id = TRAY_COMPLETE.transfer_seal_receipt_id` 및 `receipt.data.transfer_bundle_id = TRAY_COMPLETE.transfer_bundle_id`를 반드시 확인한다. 앱이 두 식별자를 event detail에 붙이는 위치는 `Container_Audit.py:9169-9201`이다.

#### B. producer-ingest accepted receipt

Direct Sync의 정확한 endpoint는 `POST https://server5.autoloop.test:18457/api/producer-ingest/v1/source-file`, stream은 `container_audit_events`, source는 `container_audit / legacy_transfer_csv`이다. path/stream/source 근거는 `direct_sync_push.py:44-51`, origin 근거는 `E:\KMTech\autoloop-20260824\APP_PREQUALIFICATION_MAP.md:99-102`이다. 기대 receipt는 다음을 모두 만족해야 한다.

- `committed=true`, `status="accepted"`, `retryable=false`, `next_retry_after=null`, `error` 없음.
- `request_id`와 `upload_id`가 동일하고 비어 있지 않음.
- `client_batch_id`, `producer_install_id`, `server_source_file_id`가 업로드 plan/source identity와 일치.
- `totals.quarantined=0`, `totals.errors=0`; `inserted + replayed + quarantined + errors =` client upload plan의 `metadata.row_count`, 그리고 `receipt.source_file.declared_row_count`도 같은 값.
- `source_file.content_sha256`가 client metadata의 `content_sha256` 및 연결된 projection source-file hash와 일치.
- `receipt.server_source_file_id = common_ingested_events.source_file_id`이고, 그 행의 `source_row_number`가 이번 `TRAY_COMPLETE` CSV 행을 가리킴.

클라이언트는 `client_batch_id`, `server_source_file_id`, `request_id=upload_id`, accepted/totals 조건을 검증하고 quarantine 또는 error가 한 건이라도 있으면 성공으로 취급하지 않는다 (`direct_sync_push.py:1060-1129`, `direct_sync_push.py:1240-1294`). 서버가 `producer_install_id`와 `source_file.content_sha256`까지 포함해 생성하는 receipt 필드는 `C:\company\program\WorkerAnalysisGUI-web\producer_ingest.py:2553-2605`에 정의돼 있다. 서버는 실제 업로드 SHA-256과 metadata가 다르면 receipt를 commit하기 전에 `content_hash_mismatch`로 거절한다 (`C:\company\program\WorkerAnalysisGUI-web\producer_ingest.py:2379-2384`). 클라이언트가 receipt hash를 자체 비교하지는 않으므로, g3 observer가 upload metadata, accepted receipt, projection의 세 hash를 명시적으로 대조해야 한다. 이 일치와 accepted receipt를 함께 확보한 상태를 quarantine 0 / checksum-identity mismatch 0의 판정으로 삼는다.

### 5.2 projection row 기대값

같은 `TRAY_COMPLETE`가 `transfer_legacy_projection`에 다음 한 행으로 보여야 한다.

| 열 | 기대값 |
|---|---|
| `transfer_id` | `PHS=2\|SRC=KMTECH_INPUT_TAG\|ITG=QUAL-ITAG-001\|CLC=AAA2270730100\|LBL=QUAL-INPUT-LABEL-001\|HSH=aaaaaaaaaaaaaaaa` |
| `item_code` | `AAA2270730100` |
| `latest_status` | `packaging_waiting` |
| `product_piece_qty` | `2` |
| `product_barcodes_json` | 위 제품 1·2의 exact set을 담은 JSON array |
| `last_event_at`, `last_event_id`, `updated_at` | 빈 값이 아닌 이번 실행의 값 |

테이블 열 계약은 `C:\company\program\WorkerAnalysisGUI-web\common_projection.py:1070-1079`에 있다. projector는 `transfer_id`, `bundle_id`, `packaging_set_identity`가 없으면 payload의 `master_label_code`를 `transfer_id`로 쓰고, 제품 바코드 수를 `product_piece_qty`로 하여 `packaging_waiting` 행을 기록한다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:7351-7389`). 원본 `TRAY_COMPLETE` payload는 tray의 canonical `master_label_code`, `item_code`, exact product arrays, `scan_count=2`, `tray_capacity=2`, `quantity_basis=PRODUCT_BARCODE`를 생성한다 (`event_payloads.py:76-140`). 따라서 projection의 `transfer_id`는 operator가 스캔한 WORK-label/`eeee...` QR이 아니라 preflight가 되돌린 INPUT-label/`aaaa...` QR이다.

연결된 `common_ingested_events` 행도 `source_system=container_audit`, `source_transport_or_dataset=legacy_transfer_csv`, `raw_event_name=TRAY_COMPLETE`, `event_projection_class=TRANSFER_LEGACY`, `projection_status=PROJECTED`여야 한다. 대시보드 세션 조회 자체가 이 다섯 조건만을 선택한다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:8719-8769`).

### 5.3 dashboard surface 기대값

보존된 Container observer prequalification이 고정한 비운영 origin은 `https://server5.autoloop.test:18457`이다 (`E:\KMTech\autoloop-20260824\APP_PREQUALIFICATION_MAP.md:99-102`). 그 origin의 정확한 경로와 surface는 다음과 같다.

- health: `GET https://server5.autoloop.test:18457/health/ingest` (`C:\company\program\WorkerAnalysisGUI-web\app.py:2835-2840`)
- read API: `POST https://server5.autoloop.test:18457/dashboard/api/operations_flow` (`C:\company\program\WorkerAnalysisGUI-web\app.py:5041-5065`, `C:\company\program\WorkerAnalysisGUI-web\app.py:5092-5129`)
- headed UI: `GET https://server5.autoloop.test:18457/?workspace=flow&view=flow`, 탭 `공정 현황` (`C:\company\program\WorkerAnalysisGUI-web\templates\index.html:180-185`)
- headed UI 내부 surface: 모드 `이적실`, panel `품목별 진행`, 열 `포장 대기` (`C:\company\program\WorkerAnalysisGUI-web\static\dashboard_enhanced.js:5197-5201`, `C:\company\program\WorkerAnalysisGUI-web\static\dashboard_enhanced.js:5296-5352`, `C:\company\program\WorkerAnalysisGUI-web\static\dashboard_enhanced.js:5381-5457`)

발사 직전 API에 `start_date=end_date=<발사 KST 날짜>`, `item_limit=60`을 보내 baseline을 저장한다. 이 baseline은 `window_mode=event_time_window`이고 `date_filter_not_applied` warning이 없어야 한다. Plan-B schema가 있으면 서버가 그것을 우선 반환하고 날짜 필터를 적용하지 않기 때문이다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:13929-14023`, `C:\company\program\WorkerAnalysisGUI-web\plan_b_golden_store.py:832-886`).

`t0 + 5분` 이내 API의 top-level은 `projection_status=ready`, `window_mode=event_time_window`, `source=common_projection`이어야 하고 `date_filter_applied` warning이 있어야 한다. 그 응답에서 다음 **baseline 대비 변화**가 모두 보여야 한다.

- `item_matrix`: `process=transfer`, `state=packaging_waiting`, `item_code=AAA2270730100` 행의 `quantity`가 정확히 `+2`; 해당 행의 `source=common_projection.common_ingested_events.period_replay`, `projection_snapshot_id=event_time_window`.
- `wip_cards`: key `packaging_waiting`의 `quantity`가 정확히 `+2`; 해당 card의 `source=common_projection.common_ingested_events.period_replay`, `projection_snapshot_id=event_time_window`.
- `process_gaps`: key `transfer_to_packaging`의 `delta`가 정확히 `+2`; 해당 gap의 `source=common_projection.common_ingested_events.period_replay`, `projection_snapshot_id=event_time_window`, 의미는 `Container_Audit TRAY_COMPLETE product-barcode evidence waiting for packaging`.
- headed `공정 현황 > 이적실 > 품목별 진행`에서 `AAA2270730100` 행의 `포장 대기`가 동일하게 `+2`.

서버는 exact product-barcode 배열 길이를 `packaging_waiting` 수량으로 더한다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:8120-8135`). item matrix, WIP card, `transfer_to_packaging` gap을 만드는 필드/문구는 `C:\company\program\WorkerAnalysisGUI-web\common_projection.py:13412-13538`에 있고, 이 상태의 source filter는 `container_audit / TRANSFER_LEGACY / PROJECTED / TRAY_COMPLETE`이다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:13609-13727`). 브라우저 코드는 정확히 `dashboard/api/operations_flow`를 POST한다 (`C:\company\program\WorkerAnalysisGUI-web\static\dashboard_enhanced.js:3851-3889`).

## 6. 선행 조건과 설치 직후 가능 여부

**설치 직후 바로 실행할 수 없다. 준비 필요(HOLD).** 설치기는 완료 뒤에도 `operator_readiness_status=PENDING_FIRST_LAUNCH`, `first_launch_catalog_status=NOT_TESTED`라고 명시한다 (`INSTALL_THIS_PC.ps1:3578-3586`). 다음을 발사 전에 모두 준비하고 readback해야 한다.

1. canonical 경로에 실행 가능한 설치본이 있고, 첫 실행 중앙 catalog 검증을 완료했으며 `AAA2270730100`이 catalog에 존재할 것.
2. 앱의 보호된 logistics profile이 **비운영** full server origin `https://server5.autoloop.test:18457`과 그 authority에 고정돼 있고, operation lease 발급, bundle resolve, transfer seal, receipt recovery가 모두 제공될 것.
3. 그 서버에 정확히 한 candidate가 존재할 것: completed input tag/session, `ACTIVE` work label/group, `AVAILABLE` source bundle, member count/hash가 정확히 2, 두 member가 동일 item/uom/inbound이고 `PHS_GOOD`에 있을 것. 앱 preflight가 active physical label과 exact membership을 검증한다 (`transfer_seal.py:708-880`). source 후보 상태는 `tools/isolated_qualification_authority.py:215-361`에 정의돼 있다.
4. `QUALIFICATION-OPERATOR`가 사전 등록돼 있고, ACTIVE master QR을 담은 실제 물리 라벨과 Enter suffix를 보내는 스캐너가 준비될 것.
5. 이 설치의 Direct Sync relay가 enrolled/current runtime lease 상태로 실행 중이고, `/api/producer-ingest/v1/source-file`에 기록할 수 있을 것.
6. 비운영 서버의 common ingest write, projection read, dashboard UI가 활성화되고, 최소 `operator` 역할의 인증된 headed dashboard observer가 준비될 것. 전역 guard는 비공개 경로에 인증 session을 요구하고 (`C:\company\program\WorkerAnalysisGUI-web\security.py:2287-2334`), 가장 낮은 `worker` profile이 `operator` 역할에 매핑된다 (`C:\company\program\WorkerAnalysisGUI-web\auth_identity.py:20-33`). API read가 꺼져 있으면 operations-flow route는 503을 반환한다 (`C:\company\program\WorkerAnalysisGUI-web\app.py:5092-5129`).
7. 발사 날짜 baseline API가 `window_mode=event_time_window`이고 `date_filter_not_applied`가 없을 것. 이 조건이 아니면 Plan-B 우선 분기이므로 이 fixture의 dashboard 기대값으로 발사하지 않는다.
8. baseline이 `projection_status=empty`이면서 `item_matrix=[]`이거나, `date_filter_applied.count`가 59 이하이거나, 이번 `AAA2270730100 / packaging_waiting` 행이 headed UI의 60-row 응답에 포함됨을 별도로 readback할 것. empty event-time baseline은 `status=empty,count=0` warning을 돌려준다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:13907-13912`). 브라우저의 `item_limit`은 60으로 고정되고 (`C:\company\program\WorkerAnalysisGUI-web\static\dashboard_enhanced.js:17-20`), 서버도 그 global limit로 item rows를 공정/state별 공정하게 절단한다 (`C:\company\program\WorkerAnalysisGUI-web\common_projection.py:13346-13409`).
9. `t0`부터 g3 관찰 종료까지 같은 날짜 범위에 다른 `container_audit / TRAY_COMPLETE`가 들어오지 않는 격리된 관찰 구간일 것. 동일 날짜/품목의 dashboard baseline, client upload metadata hash, receipt와 source-file/event correlation을 함께 기록한다.

저장소의 isolated authority는 health/catalog/bundle-resolve GET과 enroll/runtime-ingest/operation-lease POST를 route하고, unmatched 경로를 404로 닫는다 (`tools/isolated_qualification_authority.py:809-873`). 즉 source 후보 값은 제공하지만 full `transfers/seal` + receipt + dashboard 체인은 제공하지 않는다. 이 작업에서는 Sandbox를 기동하지 않았고 외부 서버를 변경하지 않았다.

## 7. UNKNOWN — 확인 못 한 항목과 이유

1. **위 source-derived candidate가 full 비운영 서버에 현재 materialize돼 있는지: `UNKNOWN — 확인 못 함`.** 저장소에 있는 후보는 isolated authority 전용이며, 그 authority에는 transfer-seal/receipt/dashboard route가 없다. 서버 조회·변경은 이번 source-only 범위 밖이다.
2. **candidate 재생성/rollback 절차와 다음 실행용 fresh identity: `UNKNOWN — 확인 못 함`.** seal은 상태를 소비·변경하는 핵심 트랜잭션이지만, 외부 비운영 authority용 provisioning/reset 명령은 이 앱 소스에서 찾지 못했다. 다른 앱의 R4 NG fixture는 Container_Audit의 completed GOOD membership과 호환되지 않으므로 대용하지 않는다.
3. **물리 라벨 출력물과 실제 스캐너 입력의 검증 상태: `UNKNOWN — 확인 못 함`.** source fixture가 명시적으로 `physical_scanner_proven=false`라고 선언한다 (`tools/isolated_qualification_authority.py:202-211`).
4. **현재 PC의 설치/첫-launch/catalog/relay/runtime-lease 상태: `UNKNOWN — 확인 못 함`.** 이번 작업은 앱 실행, 설치, build, Sandbox 및 서비스 기동을 하지 않은 source-only 준비 작업이다.
5. **dashboard observer의 정확한 계정과 현재 인증 session: `UNKNOWN — 확인 못 함`.** UI/API surface와 path는 서버 소스에서 확인했지만, prequalification도 보존된 기존 session을 `:18457`에 재사용할 수 없다고 명시한다 (`E:\KMTech\autoloop-20260824\APP_PREQUALIFICATION_MAP.md:99-102`).
6. **runtime 생성값: `receipt_id`, logistics `event_ids/outbox_ids`, transfer bundle/seal ID, idempotency key, producer `request_id/upload_id/client_batch_id/server_source_file_id`, event ID, entity versions, timestamps 및 최종 topology hash는 `UNKNOWN — 확인 못 함`.** 실행 전에는 생성되지 않으므로 필드의 존재/관계만 위 기대값으로 고정한다.
7. **producer receipt의 `inserted` 대 `replayed` 개별 수치와 upload batch 전체 row count: `UNKNOWN — 확인 못 함`.** relay 재시도 및 같은 source file의 다른 행 포함 여부에 따라 달라진다. 대신 합계 보존, quarantine 0, errors 0과 이번 event의 projection을 요구한다.
8. **현재 server의 operations-flow 분기와 selected-date item cardinality: `UNKNOWN — 확인 못 함`.** source-only 작업에서는 Plan-B 존재 여부, `window_mode`, `date_filter_applied.count`, 60-row 내 target 포함을 API로 읽지 않았다. §6의 발사 전 readback이 필요하다.
9. **발사 직전 dashboard 절대 aggregate: `UNKNOWN — 확인 못 함`.** 아직 baseline을 읽지 않았고 다른 트랜잭션이 이미 있을 수 있어 절대값을 만들지 않았다. 이번 exact 두 제품에 따른 `+2` 변화로 판정한다.
10. **별도의 누적 `hash_mismatch_count` 필드/대시보드 surface: `UNKNOWN — 확인 못 함`.** 소스에서 그런 필드를 찾지 못했다. 확인된 계약은 hash 불일치 요청을 `content_hash_mismatch`로 거절하고 accepted receipt에 `source_file.content_sha256`를 돌려주는 방식이다. 따라서 이 실행의 동일 hash와 accepted receipt는 요구하되 존재하지 않는 별도 counter를 꾸며내지 않는다.
11. **실행 시 창 제목의 `<CURRENT_VERSION>` 값: `UNKNOWN — 확인 못 함`.** 설치 artifact를 실행하지 않았으므로 visible-window 판정은 소스가 고정한 제목 prefix/suffix와 로그인 widget으로 제한한다.

이 UNKNOWN들이 해소되고 실제 evidence가 수집되기 전에는 g2 또는 g3의 완료 판정을 내리지 않는다.
