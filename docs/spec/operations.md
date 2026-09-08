# 운영·환경·장애 복구

[제품·기능](README.md) · [데이터·통합 계약](contracts.md) · [백로그](BACKLOG.md) · [중앙 준비도](../../../Program_Spec_Hub/READINESS.md)

기준일 2026-09-07. [README의 HEAD·수정 트리·기존 증거 경계](README.md#1-기준과-증거-사용법)를 적용한다. 아래의 현재 동작은 인용 소스의 정적 확인이며 설치·장비·서버 실행 결과가 아니다. 이번 문서 작업의 실행은 **NOT TESTED**이고 과거 실행 결과는 중앙 준비도에 보존한다. 수용 항목은 현행 계약을 확인할 기준이며 미정인 운영 목표는 임의로 정하지 않는다.

<a id="ca-o01"></a>
## CA-O01 실행 구조·시작·권한

작업자 GUI는 [Container_Audit.main / _prepare_gui_startup](../../Container_Audit.py)의 host 모드 분기, 계약·경로 확인, 단일 인스턴스, 조건부 현재 사용자 onboarding, 품목 준비를 거쳐 시작한다. Tkinter UI와 백그라운드 조회/relay가 분리되며, 작업자 이름은 업무 귀속이고 중앙 device/scope 인증은 별도다. [host dispatch](../../container_audit_product_host.py), [worker_registry](../../worker_registry.py), [protected_admin](../../protected_admin.py).

| 경계 | 현행 소스 | 확인할 결과·한계 |
|---|---|---|
| 소스 실행 | `Container_Audit.py`; Windows가 작업자 runtime | 소스 실행을 설치된 후보의 실행으로 세지 않는다. |
| portable 배포 | [portable/launch-container-audit.cmd](../../portable/launch-container-audit.cmd)는 묶음의 `runtime/pythonw.exe -I -B`로 `app/main.py`를 호출 | `app/main.py`는 배포 배치 경로다. 소스 루트에 같은 파일이 있다는 뜻이 아니다. [INSTALL_THIS_PC.ps1](../../INSTALL_THIS_PC.ps1)의 launcher/manifest 검증과 연결한다. |
| 코드 배치 | installer 기본 `C:\KMTech\Apps\Container_Audit\current`, 일반 사용자 RX | 일반 runtime이 코드를 교체하지 않는다. 업데이트 정책은 패키지 소유, 배치는 관리자 installer 소유다. |
| 단일 실행 | [runtime_instance](../../runtime_instance.py)의 canonical data root hash 기반 Windows `Global` mutex | 같은 PC·같은 data root의 중복 GUI를 막는다. 다른 PC까지 같은 mutex로 잠그지 않으며 서버 경쟁은 CAS/lease 계약이다. 비Windows의 no-op은 현장 동시 실행 검증이 아니다. |
| 첫 사용자 준비 | [current_user_onboarding](../../current_user_onboarding.py); frozen Windows 또는 명시 `CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING` | 사용자 state·중앙 등록·relay 시작 요청을 확인한다. `START_REQUESTED`와 onboarding의 `READY`는 relay 업로드·전체 제품 준비 완료를 뜻하지 않는다. |
| 시작 실패·경고 | 중복 실행·잠금 실패·부분 onboarding·품목 검증 실패는 해당 중단 분기 | bootstrap 무결성 기록 **부재**는 경고 후 계속하는 경로가 있고 기록 **불일치**는 차단한다. 모든 무결성 문제가 동일 종료라는 설명은 부정확하다. [시작 메시지·분기](../../Container_Audit.py) |

첫 업무 수용은 같은 사용자·정확한 후보로 정상 시작/중복 시작/부분 준비를 구분하고 current/parked/intent 복구와 실제 작업 가능 여부를 확인하는 것이다. 설치 성공이나 local profile 검사만으로 서버 capability를 입증하지 않는다. [CA-01](README.md#ca-01), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

<a id="ca-o02"></a>
## CA-O02 저장소·설정 우선순위·공급자

| 저장 대상 | 현재 기본 위치·내용 | 소유 근거 |
|---|---|---|
| 업무 state | `%LOCALAPPDATA%\KMTech\ContainerAudit`; `events`, `local_events`, `config`, `parked_trays` | [storage_policy](../../storage_policy.py) |
| 관측 이벤트 | `events/이적작업이벤트로그_[작업자]_[YYYYMMDD].csv`; local-only는 별도 `local_events` | [ContainerAudit._log_event](../../Container_Audit.py), [event_stream_policy](../../event_stream_policy.py) |
| current·조회 보류 | `events/_current_tray_state_[컴퓨터ID].json`, `_preflight_scan_hold_[컴퓨터ID].json` | [현재 상태·hold 경로](../../Container_Audit.py), [preflight_scan_hold](../../preflight_scan_hold.py) |
| relay | `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`; queue DB·spool·status·등록 자료 | [storage_policy](../../storage_policy.py), [direct_sync_runtime](../../direct_sync_runtime.py) |
| 사용자 logistics profile | `%LOCALAPPDATA%\KMTech\Logistics\profiles\Container_Audit\runtime-profile.json` | [resolve_current_user_onboarding_paths](../../current_user_onboarding.py); 사용자 DPAPI를 사용하는 선택 경로 |
| 격리 override | `CONTAINER_AUDIT_DATA_ROOT` 사용 시 relay는 `<data_root>/direct_sync`, 기본 profile은 `<data_root>/logistics-profile/runtime-profile.json` | [storage_policy](../../storage_policy.py), [onboarding paths](../../current_user_onboarding.py) |

`storage_policy`는 명시 `data_root` 인자 → `CONTAINER_AUDIT_DATA_ROOT` → 현재 사용자 기본값 순으로 선택한다. 현재 사용자 home은 우선 `LOCALAPPDATA`, 다음 `USERPROFILE/AppData/Local` 등을 확인한다. 상대/볼륨 루트·Syncthing 경로 및 코드와 같거나 포함 관계인 업무 경로는 허용하지 않는다. 기본 business root와 relay root가 분리되어 있으므로 업무 폴더 한 개만 복사한 상태를 전체 백업으로 보지 않는다.

GUI 설정은 패키지 `config/container_audit_settings.json` 템플릿을 먼저 읽고 사용자 config의 UI 설정을 덮어쓴다. 사용자 `update_settings`는 제거하여 배포 업데이트 권한/provider 정책을 바꾸지 못하게 한다. frozen에서는 내부 시험 설정도 제거한다. 저장은 사용자 config로 한다. [load_app_settings / save_settings / _drop_release_disabled_settings](../../Container_Audit.py), [기본 템플릿](../../config/container_audit_settings.json).

물류 설정에는 선택 경로가 있다. 메인 앱은 명시 `CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH` 또는 발견한 현재 사용자 profile을 복사한 환경과 사용자 DPAPI decryptor로 전달한다. 사용자 profile이 선택되지 않은 경로는 [logistics_runtime_profile._runtime_environment](../../logistics_runtime_profile.py)의 app-scoped machine profile·Machine 환경 그룹·process fallback 규칙을 따른다. Machine 값 한쪽을 process 값으로 메우지 않는다. profile이 없는 허용 호환 경로에서만 [logistics_transfer_client_from_env](../../transfer_seal.py)의 `WORKER_ANALYSIS_LOGISTICS_*` 설정을 사용한다. TEST1의 엄격한 격리 예외는 일반 운영 설정 우회법이 아니다. 비밀 값이나 DPAPI 내용을 명세·진단 출력에 넣지 않는다.

공급자 호환은 [contract.lock.json](../../contract.lock.json)의 bundle/API/capability 선언과 실제 설치 후보를 함께 확인한다. 물류 lease 서명 검증은 [terminal_operation_lease](../../terminal_operation_lease.py)가 `vendor.kmtech_zero_pe`를 import하는 소스 경로다. CA에 Rework의 sibling/provider 선택 규칙을 그대로 적용할 근거는 없다. 현재 설치된 Python/Tcl, vendor·overlay 유무/해시, 서버 flags·인증 scope·TLS 설정·capability는 이 문서 작업에서 확인하지 않았다. 이름이나 HEAD만으로 설치 조합을 추정하지 않는다. [CA-G05](BACKLOG.md#ca-g05).

품목은 중앙 CSV와 검증 cache·복구 cache를 관리한다. 중앙 갱신 실패 시 검증된 cache로 시작하면 캐시 시각 경고를 표시하고 다음 시작에서 갱신을 다시 시도한다. 검증 가능한 cache가 없거나 검증 뒤 snapshot이 사라진 경로는 시작 오류다. [refresh_item_catalog](../../item_catalog_sync.py), [prepare_startup_item_catalog / load_items](../../Container_Audit.py), [CA-C08](contracts.md#ca-c08). 허용 cache 나이와 갱신 지연의 업무 목표는 미정이다.

<a id="ca-o03"></a>
## CA-O03 스캐너·키보드·화면·사운드·출력

| 장비/입력 | 확인한 소스 동작 | 수용 기준·미확인 범위 |
|---|---|---|
| 스캐너 종료 | worker/scan/exchange Entry에 `<Return>` binding; 일반 제품은 `process_barcode`에서 문자열 `strip()` | 지원 스캐너의 실제 접미 Enter·CR/LF·키보드 배열/IME, QR 구분자 전달을 확인해야 한다. Tab·무접미·임의 Unicode 스캐너를 모두 지원한다고 주장하지 않는다. [Entry bindings](../../Container_Audit.py) |
| 입력 형식·연속 스캔 | exact PHS2 6필드, 제품 최대 128자·13자리 품목 코드 포함 조건; preflight 동안 내구 FIFO | 장비의 연속 입력과 조회 실패/재시작에서 접수 여부·순서를 대조한다. 수량 60이나 ERPnext 한도를 제품 요구로 적용하지 않는다. [CA-03~05](README.md#ca-03), [product_scan](../../product_scan.py) |
| 포커스·단축키 | 스캔 Entry 포커스 복귀, notice 확인의 Return/Escape, F8 정합 교체 및 Shift-F8 호환 진입 | 경고·보류 복원·modal 종료 뒤 입력이 잘못된 창에 들어가지 않는지 지원 배율/화면에서 확인한다. 실제 스캐너·200% 배율 전체 성공은 미입증이다. [메인 UI](../../Container_Audit.py), [CA-A02](BACKLOG.md#ca-a02) |
| 인코딩 | 이벤트 CSV는 UTF-8 BOM, 중앙 품목은 검증 snapshot, legacy 품목 파일은 별도 fallback | 한글 작업자·품목과 PHS 구분자, barcode 정규화 단계별 차이를 확인한다. 파일 인코딩이 키보드 장비 인코딩을 입증하지 않는다. [CA-C08](contracts.md#ca-c08), [입력·시간 계약](contracts.md#ca-data) |
| 사운드 | 현재 [native_audio.WavSound](../../native_audio.py)의 Windows `winsound`, one-shot/무한 loop·process-wide stop; 백그라운드 WAV 준비 | `audio_feedback_ready`는 파일 객체 준비 결과이며 실제 스피커 발성 성공이 아니다. 재생 오류·무음·중복 경고·정지와 시각 경고를 실장비에서 확인한다. [초기화/오류 사운드](../../Container_Audit.py) |
| 현품표 출력 | [phs_reconciliation_workflow](../../phs_reconciliation_workflow.py)의 artifact hash·print proof·`spool_job_id`·journal | `PRINT_FAILED/PARTIAL`, 중앙 ACK 대기·재출력 불확실을 구분한다. spool 접수·종이 배출·올바른 라벨 부착은 각각 확인한다. 일반 스캔마다 자동 인쇄하는 기능으로 해석하지 않는다. [CA-C09](contracts.md#ca-c09) |

[CODEX](../../CODEX.md)의 pygame/PyInstaller 중심 기술 설명은 현재 위 사운드·portable 소스와 차이가 있다. 과거 안내를 그대로 장비 검증 기준으로 사용하지 않으며 [CA-G03](BACKLOG.md#ca-g03)에 후속 정합 작업을 남긴다. 프린터 모델/드라이버·용지·스캐너 모델/firmware·지원 배율의 확정 목록은 미확인이다.

<a id="ca-o04"></a>
## CA-O04 장애·오프라인·취소·재시작 인계

아래는 현재 복구 분기와 다음 확인할 결과다. 자동 복구 코드 존재만으로 실행 PASS를 부여하지 않는다. 작업자는 원본 현품표·실물·작업자·컴퓨터·현재 표시를 유지하고, IT/CA 담당은 해당 state·intent·receipt·오류 사유를 연결한다. 고객 데이터나 비밀을 포함한 원본 전체를 보고서에 붙이지 않는다.

| 상황 | 현재 처리·보존할 경계 | 인계·종료 확인 |
|---|---|---|
| 첫 준비 또는 품목 갱신 실패 | onboarding 보고/검증 cache 진단; 유효 cache 없으면 시작 중단 | 같은 사용자·정확한 profile·연결 상태와 cache 분기 확인. [CA-01~02](README.md#ca-01) |
| PHS2 중앙 조회 지연/오프라인 | hold FIFO와 `LOOKUP_FAILED`; 같은 현품표 재시도 | 접수되지 않은 스캔과 보존된 스캔을 구분하고 순서대로 drain. 다른 현품표로 덮어쓰지 않음. [CA-04](README.md#ca-04) |
| lease 없는 신규 완료·부분 집합 | 표준 PHS2 완료 차단; 목록·문맥 유지 | 중앙 GOOD 전량·barcode↔unit·lease binding 확인. 오프라인 무조건 신규 작업 허용이 아님. [CA-07](README.md#ca-07) |
| 유효 lease 이후 중앙 연결 단절 | 내구 intent·`LINKED`·checkpoint와 원 명령으로 후속 시도 | local completion 유무에 맞는 입력 guard 확인. 이미 로컬 완료한 건은 원 key와 완료 시각을 유지해 재조정. [CA-12](README.md#ca-12), [CA-C03](contracts.md#ca-c03) |
| 응답 유실·중앙 정합 충돌 | receipt 조회/원 요청 재생 또는 `OPERATOR_REVIEW` | scope/key/expected version·exact 결과 대조. key 변경·실물 임의 재처리로 충돌을 우회하지 않음. |
| 취소/리셋 쓰기 실패 | 마지막 스캔 취소의 목록 복원·감사 실패 처리, 지연 callback 무효화 | 목록·개수·원본 상태가 일치해야 종료. 리셋은 이미 중앙 확정한 물류의 취소 명령이 아님. [CA-08](README.md#ca-08) |
| 보류·복원 중 종료/손상 | current/parked/hold의 보존·격리·defer; 소유자·같은 현품표 중복 확인 | 복원 대상 내구 저장/감사와 원본 정리 순서를 대조, 유일한 복구 사본 유지. [CA-09](README.md#ca-09) |
| 로컬 CSV·디스크 쓰기 실패 | 완료 기록 실패의 `LOCAL_EVENT_RETRY`, 상태·완료 ID 유지 | 쓰기 가능 복구 후 동일 완료 사건의 중복 억제 확인. JSON·SQLite·CSV를 단일 transaction으로 가정하지 않음. [CA-C01](contracts.md#ca-c01) |
| relay pause·저장 압력·stale claim | queue/status/spool 보존, `blocked_disk_pressure`·backpressure·retry 상태 | 디스크/queue 원인과 operator pause를 구별. receipt 검증 전 spool 삭제 금지. [direct_sync_runtime](../../direct_sync_runtime.py) |
| committed ingest 오류·격리·투영 지연 | 엄격 receipt 미충족은 ACK 성공이 아님; review/영구 실패 구분 | 서버 원본 trace와 행 합계·projection 결과 확인; 단순 HTTP 성공이나 재전송 횟수로 해결 판정하지 않음. [CA-C05](contracts.md#ca-c05) |
| 봉인 전 제품 교체 중 종료/경쟁 | 1~2쌍 CAS·intent·exact receipt 후 로컬 적용 | 전체 구성원/원본 label identity와 중앙·로컬 일치 확인. 부분 로컬 교체 금지. [CA-10](README.md#ca-10) |
| 출력 일부 성공·결과 불명 | print journal·artifact·중앙 exchange 재조회/확인 | 재출력 필요와 이미 출력/활성화 여부 확인, 종이까지 별도 대조. [CA-11](README.md#ca-11) |

장애 인계의 완료 기준은 미해결 상태마다 업무 ID·마지막 내구 경계·중앙 확인 여부·담당·다음 행동이 남고, 복구 후 중복 효과/분실 없이 허용 상태에 도달하는 것이다. 허용 대기시간·교대 인계 책임자·장애 알림 수준은 [CA-G06](BACKLOG.md#ca-g06)의 미정 요구다. 실행 검증은 [CA-G04](BACKLOG.md#ca-g04)와 별개로 추적한다.

<a id="ca-o05"></a>
## CA-O05 설치·교체·재설치·롤백·백업

배포 상태를 바꾸는 절차는 [INSTALL_THIS_PC.ps1](../../INSTALL_THIS_PC.ps1)이 소유한다. 기본 경로 검증, 코드 inventory/manifest hash, writer quiesce/fence, 검증된 기존 portable 교체·복원, uninstall의 복구 사본 처리 분기가 있다. `ReplaceExistingVerifiedPortable`, `ProbeVerifiedReplacementRestore`, `RestoreVerifiedReplacement`, `Uninstall`은 서로 다른 모드다. 이 문서는 명령 실행 지시나 빈 인자로 사용할 예시를 만들지 않는다. 실제 대상·receipt·원본 hash와 기존 실행 권한을 연결한 작업에서만 해당 모드를 선택한다.

업데이트 알림은 [schedule_update_check 및 배포 정책](../../Container_Audit.py)을 따른다. 일반 사용자 설정으로 updater provider/권한을 변경하거나 코드 루트를 덮어쓰지 않는다. 코드 rollback tree는 업무 DB의 rollback과 별개다. 설치/제거/복원 코드의 존재가 재설치 후 current·parked·미전송 자료 보존을 입증하지 않는다. 목표 후보의 설치→첫 업무→종료/재시작→교체/복원→동일 업무 상태 확인은 [CA-G04](BACKLOG.md#ca-g04), [중앙 Q07](../../../Program_Spec_Hub/BACKLOG.md#qualification)에 남아 있다.

백업·복원의 **필요 범위**는 업무 events/local_events, current·parked·hold, seal/lease/member-exchange intent와 출력 journal, relay queue·spool·receipt/status, 사용자 설정·작업자 귀속 자료다. 정확한 파일 위치는 실제 해석된 `storage_paths`와 coordinator store 경로로 확인한다. SQLite의 열린 WAL 등 일관성 경계도 확인해야 하며, 실행 중 파일을 임의 복사하는 방식을 검증된 백업으로 제시하지 않는다. 사용자 DPAPI 자료는 같은 계정/장비 문맥과 복구 정책이 필요하므로 단순 파일 이동으로 인증 복원이 된다고 보지 않는다. [storage_policy](../../storage_policy.py), [current_user_onboarding](../../current_user_onboarding.py), [TransferSealStore](../../transfer_seal.py), [CA-C01](contracts.md#ca-c01).

승인된 백업 주기·보관기간·복원 책임·RPO/RTO·계정/PC 손실 시 복구 방법은 미정이다. 저장 압력을 이유로 current/parked·미확정 intent를 자동 삭제하지 않는다. [DIRECT_SYNC_DATA_PLATFORM_NOTES](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md)의 `acked_retention`은 읽기 전용 현황이고 `acked_relay_retention_candidates`도 삭제 권한이 아니다. ACKED spool/status cleanup은 receipt 재시도 안전성 확인 전까지 유보된 사항이다. [CA-G06](BACKLOG.md#ca-g06).

<a id="ca-o06"></a>
## CA-O06 성능·동시성·최신성의 요구와 한계

| 대상 | 현재 코드의 제한/동작 | 승인 목표·측정 |
|---|---|---|
| 입력 문자열 | 13자리 품목코드, 제품 최대 128자 | 장비별 문자·연속 스캔 처리율 목표/실측 미확인. [product_scan](../../product_scan.py) |
| preflight hold | `_preflight_hold_store`: `max(1, TRAY_SIZE + 8)`; 별도 dispatcher queue는 `max(4, TRAY_SIZE + 12)` | 고정 60개 업무 한도가 아니다. 목표 GOOD 수와 버퍼 용량을 구분. 포화·디스크 지연 실측 미확인. [Container_Audit.py](../../Container_Audit.py) |
| 로컬/중앙 동시 작업 | data-root mutex, 로컬 파일/DB 잠금, 중앙 version CAS·lease | 동시에 운영할 PC 수·허용 경합률/지연 미정. 서버 경합 E2E는 미입증. [runtime_instance](../../runtime_instance.py), [CA-C03~04](contracts.md#ca-c03) |
| relay 저장 압력 | `DirectSyncRuntimeConfig`의 `min_free_bytes`, `max_active_queue_count`, `max_active_queue_age_seconds` 기본 0; 실제 배포값은 별도 | 0을 검증된 무제한 용량이나 승인된 장애 임계치로 해석하지 않음. [direct_sync_runtime](../../direct_sync_runtime.py) |
| lease 시간 | v1 서명 duration 60초~24시간 검증, 기존 완료의 재검증은 저장된 완료 시각 사용 | 실제 발급 기간·허용 offline 업무시간을 확정하는 값이 아님. [terminal_operation_lease](../../terminal_operation_lease.py), [TransferSealCoordinator._verified_operation_lease](../../transfer_seal.py) |
| 수신→화면 최신성 | whole-file relay·projection·API·렌더의 분리, `pcs_completed`는 관측 완료 수량 | 허용 지연/업무일·누락 경고·복구 후 따라잡기 시간 미정, live 측정 없음. [CA-C07](contracts.md#ca-c07) |

통신 timeout·poll 간격·retry 지연은 구현 파라미터이고 작업자 응답시간 SLA가 아니다. 성능/복구 목표 확정은 [CA-G01](BACKLOG.md#ca-g01), [CA-G06](BACKLOG.md#ca-g06), 실제 측정·장비·후속 설치 입증은 [CA-G04](BACKLOG.md#ca-g04)가 담당한다.

<a id="ca-o07"></a>
## CA-O07 2026-09-08 FULL 실패의 환경·fixture 경계

[실패 분석 보고](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/REPORT.md)와 [102개 testcase 색인](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/failure-inventory.tsv)은 원래 VM01 FULL의 회수 원본을 사용한다. 102 FAIL/2,526 PASS/31 SKIP, pytest 자연 종료 1, FULL·일반 export FAILED를 유지한다. forensic 25파일 회수 성공은 정상 export나 qualification PASS가 아니다.

| 관측 | 원인·다음 교정의 범위 |
|---|---|
| PS5 출력 81 실패 | [기존 helper](../../tests/powershell_contracts.py)에 UTF-8 producer와 양쪽 stream의 strict consumer를 구현했다. `-File` 대상은 quoted `-Command`에서 원 script scope로 호출하고 native exit·argument·개행을 보존한다. reader thread에서 stream을 잃는 대신 decode 오류가 호출 thread에서 실패한다. locale 추정·ignore/replace·None fallback은 없다. 실제 guest codepage는 여전히 미확인이다. |
| relay PID 12 실패·24개 잔류 | native base interpreter를 CPython venv launcher 환경으로 직접 실행하며 `os.getpid() == Popen.pid` assertion을 유지한다. context manager가 시작 확인·preimage assertion 전부터 cleanup을 소유하고 초기 relay stdout/stderr를 저장한다. delegated onboarding startup 실패도 소유 child를 종료한다. 원래 VM 잔류 24개와 이번 host child 정리는 별도 근거다. |
| Git provenance 7 실패 | 원래 `.git`의 HEAD/config만 있는 inventory는 불변이다. 새 E checkout은 genuine main history bundle에서 준비한 commit/object/ref/index와 명시된 fixture/doc 변경을 가지며 기존 7개 사례가 PASS했다. 후보 tree·index 및 커밋 전 상태는 [후보 보고](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)에 기록한다. 임의 HEAD나 provenance bypass는 없다. |
| 완료 재시도 일일 집계 1 실패 | 승인된 [clock diff](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/fixture-clock-proposal.patch)를 저장소에 적용해 `date.today()`와 `datetime.now()`를 같은 fixture 시각으로 묶었다. 기존 두 사례는 새 [초기 경계 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/boundary-01/junit.xml)에서 모두 PASS이며 제품 구현·assertion은 동일하다. |
| exact executable fixture 1 실패 | genuine base executable을 복사·hash 대조하고 archive hash·native PID/image path·wrong-image/hash 거부를 유지한다. identity JSON과 child stdout/stderr를 보존한다. 새 host 경계 사례 PASS는 원래 25개 회수 파일에 없던 내부 실패 사유를 소급 입증하지 않는다. |

Main grant `msg_22a3607bde7e`에 따른 [정리 결과](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/CLEANUP-RESULT.md)는 모든 24개 native handle의 birth/SID/session/executable/command hash·parent 및 unknown descendant 부재를 확인한 뒤 interpreter 12개만 직접 종료했다. 원래 로그 25개와 신선한 before identity를 E에 보존했다. PS5 JSON array admission 실패와 뒤이은 launcher 3988 재확인 실패는 FAILED로 남기고, 별도 PSDirect session의 최종 읽기가 24개 부재·closure empty·원래 Explorer 4184 불변을 확인했다. 새 kill/VM 상태 변경 없이 Main의 VM01 해제 판단으로 넘겼으며 원래 FULL FAILED는 그대로다.

2026-09-08 구현·검증 후보의 실제 범위는 [CANDIDATE](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)에 연결한다. 초기 경계 14 PASS, authentic Git 7 PASS와 별도로 긴 E root의 PS5 MAX_PATH 실패(첫 계약 실행 176 PASS/7 FAIL/3 capability SKIP, 짧게 조정한 in-root retry 2 FAIL 후 중단)를 보존한다. 첫 실행의 기록된 native relay PID 34개, retry의 4개에 대한 유한 관측은 active owned 0이다. 독립 검토와 승인된 소스 마감은 [ACCEPTANCE](E:/KMTech/ca-rp-0908/ACCEPTANCE.md)로 후속 연결하며, target FULL·installer/backend qualification·VM access는 이번에도 수행하지 않았다.

최종 [short E/Windows venv 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03.xml)은 **204 PASS / 3 capability SKIP / FAIL·ERROR 0 (207개)**다. 원래 102개 실패 node 중 100 PASS·8.3 alias capability SKIP 2개이며, PID 12개와 Git 7개는 모두 PASS했다. [유한 child 관측](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03-children.json)은 기록된 relay PID 37개 중 active owned 0이다. 원래 FULL FAILED·guest codepage/원래 exact-artifact 내부 사유 미확인·대상 FULL NOT TESTED를 유지한다.

후속 source는 [SUCCESSOR-MANIFEST](E:/KMTech/ca-rp-0908/SUCCESSOR-MANIFEST.json)의 실제 commit/tree와 genuine Git history bundle·object archive로 식별한다. 원래 bundle/patch/archive와 provider cache는 보존한다. 기존 host 실행과의 차이는 정확히 세 명세 경로의 설명이며 전체 문서를 임의로 실행 입력에서 제외한 판정이 아니다. 원래 child 관측의 세부는 **36 ABSENT·1 PID_REUSED_NOT_OWNED**, active owned 0이며 새 live 관측으로 쓰지 않는다. [TARGET-HANDOFF](E:/KMTech/ca-rp-0908/TARGET-HANDOFF.md)의 실제 pinned venv·PS5/PS7/Git 확인, 짧은 소유 output 경로, 원래 207개 node·capability·child 종료 검증 후 Main이 별도 FULL의 자연 종료·원본 양쪽 stream·export/readback을 수용해야 한다. 새 VM 배정·실행은 Main 소유이며 소스 마감만으로 build·설치·GUI·backend 또는 Ready를 올리지 않는다.
