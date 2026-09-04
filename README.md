# Container Audit - 이적 검사 시스템

문서 적용 commit: `dc7c50dd6217e2a373d57704a6b9523862a5d7b8`

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()

KMTech 제조업 이적 검사를 위한 실시간 데스크톱 애플리케이션입니다.

> **📋 문서 구성**
> • **작업자 안내 정본**: [`docs/OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md`](docs/OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md)
> • **저장소·개발 안내**: 이 README
> • **API 문서**: 소스 코드 내 주석 참조

## 📝 프로그램 개요

**이적 검사 시스템**은 제조업 생산 라인에서 완제품의 이적 검사를 수행하고 관련 기록을 관리하는 데스크톱 애플리케이션입니다. 바코드 입력, 중앙 판정, 로컬 복구 기록과 전송 상태 확인을 지원합니다.

### 🎯 핵심 가치
- **이적 데이터 기록**: 작업 이벤트와 복구 정보를 로컬 저장소에 기록
- **스캐너 입력**: USB 바코드 스캐너의 키보드 입력 처리
- **표준 PHS2 작업 플로우**: 원본 물리 PHS2 → 중앙 preflight → exact GOOD member 전량 스캔 → 이적 결과 확인
- **내구 상태 관리**: 진행 중 트레이·보류 입력·전송 재시도 상태를 저장하고 복구

## 🏗️ 시스템 아키텍처

### 애플리케이션 구조

```
Container Audit
├── ContainerAudit (메인 GUI와 작업 흐름)
├── TraySession (현재 트레이 상태)
├── preflight_scan_hold / parked_tray_store (내구 보류 상태)
├── transfer_seal / transfer_member_exchange (exact 이적과 교체)
└── event_log_store / direct_sync_runtime (로컬 증거와 전송 상태)
```

### 핵심 컴포넌트 분석

| 컴포넌트 | 주요 역할 |
|---------|-----------|
| **ContainerAudit** | 메인 GUI와 작업 흐름 조정 |
| **TraySession** | 현재 트레이 데이터 구조 |
| **preflight_scan_hold / parked_tray_store** | preflight 보류 입력과 parked 트레이 보존 |
| **transfer_seal / transfer_member_exchange** | exact member 이적 봉인과 이적 전 1~2쌍 교체 |
| **event_log_store / direct_sync_runtime** | 로컬 이벤트 증거와 DirectSync 전송 상태 관리 |

### 데이터 플로우

```
바코드 입력 → 중앙 preflight·exact 집합 확인 → 내구 로컬 기록 → 중앙 이적 결과 확인
                                      └→ DirectSync 대기열·최근 ACK 별도 표시
```

## 💻 개발 환경

### 시스템 요구사항

**운영체제**: Windows 10 이상
**Python**: 3.11+
**기본 데이터 디렉토리**: `%LOCALAPPDATA%\KMTech\ContainerAudit\events` (로컬 이벤트 저장소)

### 의존성 설치

```bash
# 필수 패키지 설치
pip install -r requirements.txt

# 의존성 목록
requests    # GitHub API 통신
pygame     # 오디오 피드백
Pillow     # 이미지 처리
tkinter    # GUI 프레임워크 (Python 내장)
```

### 개발 명령어

```bash
# 애플리케이션 실행
python Container_Audit.py

# 변경 영역 quick-check
python -m pytest -q -p no:cacheprovider <changed-test-node>
```

일부 entrypoint만 다시 `py_compile`하지 않는다. 최종 전체 회귀는 `main` push의
Full CI가 exact SHA에서 한 번 실행한다.

### 설치와 최초 실행

보존한 정확한 portable packet에서 일반 작업자 계정으로 canonical 설치를
실행한다. 내부 helper는 관리자 쓰기 전용 경로에 코드와 무결성 기록을 배치한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\INSTALL_CANONICAL_PORTABLE.ps1
```

배치 후 일반 작업자 계정으로
`C:\KMTech\Apps\Container_Audit\current\launch-container-audit.cmd`를 실행한다. 앱은 첫 실행에서
서버 승인된 producer identity/manifest/credential, CurrentUser DPAPI logistics
profile, business ledger와 durable queue를 사용자 범위에 만들고 즉시 readback한
뒤 같은 프로세스에서 사용한다. 기존의 완전하고 일치하는 상태는 다시 만들지
않고 재사용하며, 일부만 남거나 값을 확인할 수 없으면 오류 창과 redacted report를
남기고 시작을 중단한다.

- business state: `%LOCALAPPDATA%\KMTech\ContainerAudit`
- DirectSync state: `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`
- logistics profile: `%LOCALAPPDATA%\KMTech\Logistics\profiles\Container_Audit`
- persistent relay: 현재 사용자 권한의
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KMTech.ContainerAudit.Relay`

relay는 hardened `runtime\pythonw.exe -I -B app\main.py --container-audit-user-relay`를 현재 사용자로
실행하고 최대 60초 간격으로 durable queue를 다시 확인한다. SYSTEM AtStartup
task는 설치/실행 계약에 포함되지 않는다.

일반 제거는 앱 창을 닫은 뒤 설치에 사용한 정확한 packet의 바깥 소스 경로에서
같은 작업자 계정으로 실행한다. canonical 명령은 설치/소스 무결성과 소유권을
확인하고 현재 사용자 persistence/relay를 정지한 뒤 필요한 코드 제거만 승격한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\INSTALL_CANONICAL_PORTABLE.ps1 -Uninstall
```

성공은 `uninstall_status=PASS_UNINSTALLED_DATA_PRESERVED`로 표시한다. business data,
credential, reusable key, profile, queue와 서버 등록은 보존한다. 다른 packet이나
알 수 없는 설치 상태, 실행 중인 writer, legacy scheduled writer는 제거를 막는다.
부분 삭제나 후속 실패는 동일 실행의 fence 아래 정확한 코드/무결성 기록과
HKCU/relay 사전 상태를 복구한 뒤 `PASS_EXACT_PREIMAGE_SAFE_TO_RETRY`를 표시한다.
이 표시가 없으면 audit에 기록된 recovery tree와 원본 packet을 보존하고 실패를
해결해야 하며, 수동 fence 삭제나 임의 프로세스 종료로 우회하지 않는다.
재설치는 위 canonical 설치 명령과 현재 사용자 첫 실행을 반복한다.

## 🎯 핵심 기능 상세

### ⚙️ 간편한 작업 플로우
- **표준 PHS2 모드**: 원본 물리 PHS2를 한 번 스캔한 뒤 중앙 preflight가 끝나야 제품 입력을 시작
- **완료 조건**: 중앙 exact GOOD member의 제품 ID↔바코드 집합을 전량 스캔해야 완료하며, 개수만 맞춘 다른 집합이나 부분 제출은 차단
- **현재 이적 제품 교체**: 작업 리더 지시에 따라 이적 확정 전에 같은 입고 lot·품목·UOM·원장 plane의 별도 PHS 양품으로 1~2쌍만 중앙에서 원자적으로 교체

### 🔌 하드웨어 통합 기능
- **바코드 스캐너**: USB 연결 자동 인식, 실시간 바코드 처리
- **오디오 피드백**: `pygame.mixer` 기반 즉시 음성 안내 (성공/오류음)

### 📊 실시간 데이터 처리
- **실시간 현황판**: 진행률, 당일 통계, 평균 작업시간 표시
- **자동 저장**: 트레이 상태 실시간 저장, 예기치 않은 종료시 복구
- **CSV 로깅**: 모든 검사 이벤트를 로컬 이벤트 폴더에 먼저 저장하고 HTTPS 릴레이가 같은 폴더를 업로드

### 🔄 자동 업데이트 시스템
- **서명된 사내 feed**: 배포본은 Ed25519 서명·SHA-256·PC rollout을 검증한 뒤 새 버전을 안내
- **구 설치본 bootstrap**: 저장 설정에 updater 항목이 없는 frozen 설치본도 내장 공개키로 사내 feed를 확인
- **읽기 전용 코드 루트**: 일반 사용자 런타임은 다운로드·mirror·rollback으로 설치 코드를 수정하지 않음
- **관리자 배포**: 새 버전 발견 시 안내만 표시하며 실제 코드 교체와 integrity inventory 생성은 새 패키지의 `INSTALL_THIS_PC.ps1`로 수행
- **명시적 중지 보존**: 환경변수나 설치 설정이 `provider=off`이면 자동 확인을 하지 않음

## 📁 파일 구조 및 데이터 관리

### 필수 시스템 디렉토리
```bash
%LOCALAPPDATA%\KMTech\ContainerAudit/
├── events/                                  # 앱이 직접 쓰는 로컬 이벤트/상태 저장소
│   ├── 이적작업이벤트로그_[작업자]_[날짜].csv  # 이적 작업 로그
│   └── _current_tray_state_[PC].json        # 비정상 종료 복구 상태
├── config/                                  # 사용자 UI 설정/작업자 목록/최고 기록
└── parked_trays/                            # 보류 트레이 상태

%LOCALAPPDATA%\KMTech\DirectSync\container_audit/
├── queue/                                   # HTTPS 릴레이 durable queue
├── spool/
├── status/
└── logs/
```

### 설정 및 자산 파일
```bash
assets/
├── Item.csv          # 제품 DB (필수)
├── *.wav            # 오디오 피드백 파일
└── logo.ico         # 애플리케이션 아이콘

config/
└── container_audit_settings.json  # 읽기 전용 UI 기본값 템플릿
```

## 🔍 API 및 이벤트 시스템

> **현행 로그 계약 주의**
> 현재 `Container_Audit.py`가 로컬 이벤트 폴더에 쓰는 원시 CSV는
> `timestamp,worker_name,event,details` 4개 컬럼이다. 트레이 완료 이벤트는
> `TRAY_COMPLETE`이며, `event_type`, `worker`, `SESSION_COMPLETE` 중심 설명은
> 과거 문서나 분석용 정규화 뷰에서만 사용할 수 있다.

### 주요 이벤트 타입
```python
# 검사 관련 이벤트
SCAN_SUCCESS              # 바코드 스캔 성공
SCAN_DUPLICATE           # 중복 바코드 스캔
SCAN_MISMATCH           # 품목 불일치
TRAY_PRODUCT_SCANNED    # 트레이 제품 스캔

# 세션 관리 이벤트
SESSION_START           # 검사 세션 시작
TRAY_COMPLETE           # 트레이 완료(현행 원시 CSV 완료 이벤트)
SESSION_COMPLETE        # 레거시/정규화 뷰의 완료 이벤트명
SESSION_RESET           # 세션 리셋
TRAY_SUBMIT            # 트레이 제출
SESSION_RESTORED        # 세션 복구

# 개별 제품 교환 이벤트
PRODUCT_EXCHANGE_COMPLETED # 제품 교환 완료

# 현품표 교체 이벤트
MASTER_LABEL_REPLACE_START    # 현품표 교체 시작
HISTORICAL_REPLACE_SUCCESS    # 완료된 현품표 교체 성공
HISTORICAL_REPLACE_CANCEL     # 완료된 현품표 교체 취소

# 시스템 이벤트
UPDATE_CHECK_FOUND      # 업데이트 발견
UPDATE_STARTED          # 업데이트 시작
IDLE_MODE_ON           # 유휴 모드 진입
IDLE_MODE_OFF          # 유휴 모드 해제

# 트레이 관리 이벤트
TRAY_PARKED            # 트레이 보류
TRAY_RESTORED          # 트레이 복구
PARTIAL_TRAY_SUBMITTED # 부분 트레이 제출

# 테스트 관련 이벤트
TEST_TRAY_COMPLETED    # 테스트 트레이 완료
AUTO_TEST_STARTED      # 자동 테스트 시작
```

### 데이터 모델 구조

| 구조·저장소 | 현행 역할 |
|---|---|
| `TraySession` | 현재 PHS2, 스캔 바코드, preflight receipt와 operation lease 등 진행 상태 |
| `PreflightScanHoldStore` | preflight 중 접수한 입력의 내구 FIFO 보류 |
| `ParkedTrayStore` | 작업자별 parked 트레이 보존·복원 |
| `TransferSealStore` | exact member 이적 intent, receipt와 로컬 완료 원장 |
| `TransferMemberExchangeStore` | 이적 확정 전 1~2쌍 교체 명령과 결과 |

## 🔧 데이터 이벤트 처리 아키텍처

### 이벤트 로깅 시스템
```python
def _log_event(self, event_type: str, detail: Dict[str, Any] = None):
    """
    모든 시스템 이벤트를 비동기적으로 로깅합니다.

    현행 원시 CSV 이벤트 구조:
    - timestamp: 이벤트 발생 시간
    - worker_name: 현재 작업자
    - event: 이벤트 타입 (예: TRAY_COMPLETE)
    - details: 이벤트 상세 정보 (JSON 문자열)
    """
```

### CSV 데이터 구조(현행 원시 로그)
```csv
timestamp,worker_name,event,details
2024-12-24T09:15:30.123456,작업자1,SESSION_START,"{""master_label_code"": ""WID20241224091530""}"
2024-12-24T09:16:45.456789,작업자1,SCAN_OK,"{""barcode"": ""8811012345678001"", ""scan_count"": 1}"
2024-12-24T09:45:20.123456,작업자1,TRAY_COMPLETE,"{""master_label_code"": ""WID20241224091530"", ""scan_count"": 60, ""tray_capacity"": 60, ""work_time_sec"": 1790.5}"
```

분석 프로그램에서 `event_type`, `worker`, `item_code`, `scan_count`,
`work_time_sec` 같은 평탄화 컬럼이 필요하면 `details` JSON을 파싱해 만든
정규화 뷰로 다뤄야 한다. 원시 파일 스키마 자체를 과거 확장 컬럼 형식으로
가정하면 안 된다.

### 데이터 흐름 처리
```python
# 1. 바코드 스캔 → 이벤트 생성
process_scan() → _log_event('SCAN_OK')

# 2. 트레이 완료 → 세션 저장
submit_current_tray() → _log_event('TRAY_COMPLETE') → CSV 저장

# 3. 개별 제품 교환 → 교환 로그
_complete_exchange() → _log_event('PRODUCT_EXCHANGE_COMPLETED')

# 4. 예외 상황 → 오류 로그
exception_handler() → _log_event('ERROR_OCCURRED')
```

## ✨ 주요 기능 목록

* **바코드 기반 검사**: 현품표(마스터 라벨) 스캔으로 작업을 시작하고, 개별 제품 바코드를 스캔하여 검사를 진행합니다.

* **exact membership 이적 검사**: 중앙 preflight가 확정한 GOOD 제품 ID↔바코드 집합을 전량 대조합니다.

* **실시간 현황판**: 현재 트레이의 진행 상황, 당일 작업 통계, 평균 작업 시간 등을 실시간으로 확인할 수 있습니다.

* **현재 이적 제품 교체**: 작업 리더 지시에 따라 이적 확정 전 현재 트레이에서 같은 입고 lot·품목·UOM·원장 plane의 별도 PHS 양품으로 기존 제품 1~2쌍을 원자적으로 교체합니다.

* **작업 자동 저장 및 복구**: 예기치 않게 프로그램이 종료되어도 진행 중이던 작업 내용을 복구할 수 있습니다.

* **자동 업데이트**: 프로그램 실행 시 새로운 버전이 있으면 자동으로 감지하고 업데이트를 안내합니다.

* **사용자 맞춤 UI**: `Ctrl` + `마우스 휠` 스크롤로 화면 배율을 조절하여 보기 편한 크기로 설정할 수 있습니다.

---

## 🚀 작업자 안내

현장 절차는 [작업자 안내 정본](docs/OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md)만 따릅니다. 이 README는 아래 안전 경계만 요약합니다.

1. 본인 이름으로 로그인하고 제품보다 먼저 **원본 물리 PHS2**를 한 번 스캔합니다.
2. 중앙 preflight가 끝날 때까지 기다립니다. `중앙 확인 중 · 보류 스캔 N건`은 해당 입력이 보류 저장소에 접수된 상태이므로 다시 찍지 않습니다.
3. 중앙 exact GOOD `member_count`와 제품 ID↔바코드 집합을 실물과 대조하고 그 멤버 전량만 스캔합니다. 같은 품목의 다른 제품으로 개수만 맞춰서는 완료되지 않습니다.
4. 표준 PHS2는 일부 제출할 수 없습니다. 부족하거나 집합이 다르면 현재 트레이와 실물을 그대로 보존하고 담당자에게 알립니다.
5. 작업 리더 지시에 따라 이적 확정 전 교체가 필요한 경우에만 `🔁 현재 이적 제품 교체`에서 같은 입고 lot·품목·UOM·원장 plane의 별도 PHS 양품으로 기존 제품↔새 양품 1~2쌍을 처리합니다. 중앙 결과가 한 쌍이라도 확정되지 않으면 현재 트레이를 유지합니다.
6. `저장 전송`의 `대기 N · 최근 성공 ...`은 DirectSync backlog와 최근 업로드 ACK입니다. 현재 트레이의 `서버 이적 확인이 완료되었습니다.`와 서로 다른 상태입니다.

보류, startup 복구, busy 상태별 재스캔 판단, DirectSync 상세는 정본의 창 제목·화면 문구 표를 확인합니다. 보류된 트레이와 preflight 보류 입력은 삭제된 것이 아닙니다.

### M7 화면 증거 계약

정본은 `E:/KMTech/production-readiness-20260830/HANDOVER/CAPTURE-BUNDLE-V1-CONTRACT.md`이고 스키마 이름은 정확히 `M7 external capture bundle v1`입니다. 외부 묶음은 `E:/requal-evidence/capture-bundle-v1/<app>/<app>__<commit12>__<YYYYMMDDTHHMMSSZ>__<nonce8>/`에 두며, `HANDOVER-INDEX.md`가 가리키는 불변 `indexes/handover-index__<YYYYMMDDTHHMMSSZ>__<nonce8>.json`에서 `app=Container_Audit` 항목을 찾아 bundle `manifest.json`의 `captures[].state_id`로 조회합니다. 저장소 쪽 선언은 창을 열지 않는 `python -B tools/capture_container_operator_ui.py --describe-m7-contract`의 `{schema, app, required_state_ids}` envelope로 확인합니다.

필수 state ID는 `m7_phs2_preflight`, `m7_central_preflight_queue`, `m7_completion_busy`, `m7_recovery_transition`, `m7_direct_sync_backlog_ack`, `m7_exact_good_membership`, `m7_lease_fail_closed`, `m7_transfer_receipt_status`, `m7_partial_atomic_exchange`입니다. 디렉터리·파일명, manifest field와 create-new 순서는 위 정본만 따르며 이 README에는 그 계약을 재정의하거나 미래 digest를 기록하지 않습니다.

현재 상태는 C-1 `external bundle 캡처 대기(재감사 통과 전 '도구 준비됨' 표기 금지)`, C-2·C-3 `미정 — 조직 확정 필요(Q1)`, C-4 `도구 정정 진행(재감사 대기)`입니다. C-5는 코디네이터 직접 확인(D-121, 2026-09-03) 결과, 두 `.tmp/ui-validation-secondary-20260625-165416` 대상과 원래 `.deploy_backups` 대상은 부재하지만 회사 프로그램 아카이브에 9 PNG와 1 JSON이 남아 있어 `부분 존재(아카이브)`입니다. 기존 추적 이미지는 역사 참고로만 유지하고 최종 portable artifact의 외부 승인 묶음으로 교체할 예정입니다.

---

## 💡 유용한 팁 및 주의사항

* **UI 크기 조절**: 화면의 글씨나 버튼이 너무 작거나 크다면, 키보드의 `Ctrl` 키를 누른 상태에서 마우스 휠을 위아래로 움직여 보세요. 자신에게 맞는 크기로 조절할 수 있습니다.

* **오류 발생 시**: 스캔한 바코드가 품목과 맞지 않거나, 이미 스캔한 바코드일 경우 **경고음과 함께 전체 화면에 오류 메시지**가 나타납니다. 내용을 확인하고 '확인' 버튼을 눌러 작업을 계속하세요.

* **휴식 모드**: 검사 중 7분(`IDLE_THRESHOLD_SEC = 420`) 이상 활동이 없으면 프로그램은 자동으로 '대기 중' 상태로 전환됩니다. 아무 바코드나 스캔하면 즉시 다시 작업 상태로 돌아옵니다.

---

## ❓ 문제 해결 (FAQ)

* **Q: 프로그램을 실행했는데 `Item.csv` 파일을 찾을 수 없다고 나옵니다.**
   * A: 프로그램 실행 파일(`Container_Audit.exe`)이 있는 폴더에 `assets` 폴더가 있는지, 그 안에 `Item.csv` 파일이 있는지 확인해주세요.

* **Q: 바코드 스캐너가 작동하지 않습니다.**
   * A: 스캐너가 컴퓨터에 제대로 연결되었는지 확인하세요. 메모장에서 바코드를 스캔했을 때 글자가 입력되는지 테스트해보세요.

* **Q: 이미 완료한 현품표를 다시 스캔하니 '작업 중복' 오류가 발생합니다.**
   * A: 시스템은 동일한 현품표의 중복 작업을 방지합니다. 이미 완료된 작업인지 확인하고, 새로운 현품표로 작업을 시작해주세요.

---

## 📂 파일 구조 및 데이터 관리

* **로그 파일 위치**: 모든 검사 기록 및 이벤트 로그는 `%LOCALAPPDATA%\KMTech\ContainerAudit\events` 폴더에 `이적작업이벤트로그_작업자이름_날짜.csv` 형식으로 저장됩니다.

* **배포 저장 원칙**: 배포 버전은 Syncthing 폴더가 없는 것을 전제로 합니다. `CONTAINER_AUDIT_DATA_ROOT`로 데이터 루트를 바꿀 수 있지만, `C:\Sync` 계열 경로는 기본적으로 거부됩니다.

* **작업자 PC 최초 등록**: 일반 사용자로 실행된 앱의 first-run onboarding이 PC별 `source_host_id`, `producer_install_id`, `producer_id`, `key_id`를 자동 생성·등록하고 CurrentUser DPAPI로 secret을 보호합니다. raw secret은 manifest, credential JSON, report 파일에 저장하지 않습니다.

* **데이터 중요성**: 이 로그 파일들은 모든 작업의 증거 자료이므로 **절대로 임의로 수정하거나 삭제하지 마세요.**

* **설정 파일**: 사용자 UI 설정은 `%LOCALAPPDATA%\KMTech\ContainerAudit\config\container_audit_settings.json`에 저장됩니다. 프로그램 폴더의 같은 이름 파일은 읽기 전용 기본값 템플릿입니다.

* **코드/상태 분리**: 설치 코드 루트는 관리자 배포 전용(RX)이며 로그, 설정, 작업자 목록, 최고 기록, 보류 트레이, 릴레이 상태를 쓰지 않습니다. `CONTAINER_AUDIT_DATA_ROOT`는 코드 루트와 완전히 분리된 절대 경로여야 합니다.

## 🔒 보안 및 규정 준수

### 데이터 보안
- **로컬 데이터 저장**: 모든 데이터는 먼저 로컬 이벤트 폴더에 저장되어 서버 연결 없이도 당일 작업 조회와 복구 가능
- **네트워크 통신**: 배포 전환 후 direct-sync HTTPS 릴레이가 서버 endpoint로 이벤트 CSV를 업로드
- **바코드 검증**: 입력 데이터 검증으로 보안 위협 방지
- **로그 무결성**: CSV 형식으로 변조 탐지 가능

### 규정 준수
- **데이터 추적성**: ISO 9001 품질관리 시스템 요구사항 준수
- **감사 로그**: 모든 검사 활동 타임스탬프와 함께 기록
- **백업 정책**: 일별 로그 파일 자동 분리로 데이터 손실 방지

## 📞 지원 및 문의

### 기술 지원
- **개발팀 이메일**: [기술지원 이메일 주소]
- **GitHub Issues**: https://github.com/KMTechn/Container_Audit/issues
- **문서**: 이 README.md 파일 참조

### 사용자 교육
- **현장 교육**: 신규 작업자 대상 1:1 교육 지원
- **매뉴얼**: 사용자 가이드 섹션 참조
- **FAQ**: 문제 해결 섹션 참조

---

## 📄 라이센스

**Copyright © 2024 KMTech. All rights reserved.**

본 소프트웨어는 KMTech의 독점 소프트웨어입니다.
라이센스 없이 복제, 배포, 수정을 금지합니다.

**🏭 제작**: KMTech 품질관리팀
**📧 연락처**: [연락처 정보]
**🌐 웹사이트**: [회사 웹사이트]
**📌 문서 적용 commit**: `dc7c50dd6217e2a373d57704a6b9523862a5d7b8`
