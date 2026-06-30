# CODEX 작업 안내서

작성 기준: 2026-06-11

이 문서는 Codex가 이 저장소를 빠르게 파악하기 위한 내부 작업 메모다. `README.md`를 대체하지 않고, 실제 코드 기준으로 수정 위치와 실행 주의점을 요약한다.

## 프로젝트 목적

`Container_Audit`는 제조 라인의 이적 검사/트레이 검사를 위한 Windows 데스크톱 앱이다. 작업자는 현품표를 스캔한 뒤 제품 바코드를 순차 스캔하고, 기본 60개 단위의 트레이 완료 내역을 로컬 이벤트 폴더에 CSV로 먼저 남긴다. 배포 전환 기준은 Syncthing 없이 HTTPS direct-sync 릴레이가 그 로컬 이벤트 폴더를 서버로 업로드하는 구조다.

## 주요 기능

- 현품표 스캔 후 품목 정보와 목표 수량을 잡고 제품 바코드를 검증한다.
- 트레이 완료, 부분 제출, 마지막 스캔 취소, 현재 작업 리셋을 처리한다.
- 작업 중인 트레이를 보류/복구하고, 비정상 종료 후 현재 트레이 상태를 복구한다.
- 완료 현품표 교체와 개별 제품 교환 흐름을 지원한다.
- `pygame` 기반 성공/오류 사운드와 Tkinter GUI를 제공한다.
- GitHub Release 기반 자동 업데이트 코드는 `main()`에서 호출된다. 다만 frozen/release 모드가 아니면 업데이트 확인은 즉시 반환한다.
- 기본 데이터 루트는 `%LOCALAPPDATA%\KMTech\ContainerAudit`이며 `events`는 앱 로컬 저장소, `direct_sync`는 HTTPS 릴레이 큐/스풀/상태 저장소다.

## 기술 스택

- Python 3.11+
- Tkinter/ttk
- Pillow, pygame, requests
- CSV/JSON 파일 저장
- Windows/PyInstaller 배포 전제

## 실행 및 검증

```powershell
cd C:\company\program\Container_Audit
pip install -r requirements.txt
python Container_Audit.py
python -m py_compile Container_Audit.py
```

수동 테스트용 입력 후보:

- `_RUN_AUTO_TEST_`
- `TEST_LOG_[수량]`

## 주요 파일

- `Container_Audit.py`: 단일 대형 메인 앱. `ContainerAudit`, `TraySession`, `ProductExchangeSession`, 자동 업데이트 코드가 모두 들어 있다.
- `assets/Item.csv`: 품목 기준 데이터. 바코드 검증 로직의 핵심 입력이다.
- `assets/*.wav`: 성공/오류/조합 사운드.
- `assets/logo.*`, `assets/*LHD*.png`, `assets/*RHD*.png`: UI/배포 자산.
- `config/container_audit_settings.json`: UI 배율, 컬럼 폭 등 런타임 설정.
- `config/validator_settings.json`: 검증 관련 설정 파일 후보.
- `ANALYSIS_GUIDE.txt`, `TEST_CODE.txt`: 기존 분석/테스트 메모.

## 데이터와 설정 위치

- 운영 로그: `%LOCALAPPDATA%\KMTech\ContainerAudit\events\이적작업이벤트로그_[작업자]_[YYYYMMDD].csv`
- 현재 트레이 상태: `%LOCALAPPDATA%\KMTech\ContainerAudit\events\_current_tray_state_[컴퓨터ID].json`
- HTTPS 릴레이 상태/큐: `%LOCALAPPDATA%\KMTech\ContainerAudit\direct_sync`
- 보류 트레이: `config/parked_trays`
- 최고 기록: `config/best_time_records.json`
- 앱 설정: `config/container_audit_settings.json`

## 작업 시 주의점

- direct-sync 장기 보관/취합 관련 수정 전 `DIRECT_SYNC_DATA_PLATFORM_NOTES.md`를 먼저 확인한다.
- 이 앱은 단일 대형 파일 구조라 기능 수정 전 `Container_Audit.py`에서 관련 메서드 묶음을 먼저 찾아야 한다.
- 앱은 기본적으로 로컬 앱 데이터 폴더에 파일을 쓰므로 실제 GUI 실행은 `%LOCALAPPDATA%\KMTech\ContainerAudit`에 로그/상태 파일 생성 부작용이 있다. 테스트 격리는 `CONTAINER_AUDIT_DATA_ROOT`로 별도 루트를 지정한다.
- 배포 버전은 `C:\Sync`와 같은 Syncthing 경로를 기본 저장소로 쓰지 않아야 한다. 코드의 저장 정책은 `storage_policy.py`를 기준으로 확인한다.
- `assets/Item.csv` 형식 변경은 바코드 검증과 UI 표시를 동시에 깨뜨릴 수 있다.
- 기존 `ANALYSIS_GUIDE.txt` 일부 설명은 현재 코드의 상태 파일 위치와 다를 수 있으므로 코드 기준으로 판단한다.
- 사운드 장치가 없거나 `pygame.mixer` 초기화가 실패하면 GUI 실행 흐름이 달라질 수 있다.
- 저장소 상태 메모는 시간 민감 정보다. 작업 전 `git status -sb`와 remote 상태를 새로 확인한다.
