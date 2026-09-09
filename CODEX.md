# CODEX 작업 안내서

작성 기준: 2026-09-09

이 문서는 Codex가 이 저장소를 빠르게 파악하기 위한 내부 작업 메모다. `README.md`를 대체하지 않고, 실제 코드 기준으로 수정 위치와 실행 주의점을 요약한다.

## 프로젝트 목적

`Container_Audit`는 제조 라인의 이적 검사/트레이 검사를 위한 Windows 데스크톱 앱이다. 표준 작업은 검사 전에 발행되어 검사 완료까지 유지된 exact 6필드 PHS2를 중앙 조회하고, 서버가 확정한 GOOD member count만큼 제품 바코드를 순차 스캔한다. PHS2 수량을 기본 60으로 추정하거나 QR에 `QT`를 추가하지 않는다. 배포 전환 기준은 Syncthing 없이 HTTPS direct-sync 릴레이가 로컬 이벤트를 서버로 업로드하는 구조다.

## 주요 기능

- exact PHS2의 `ITG/LBL/HSH`를 중앙 registry와 대조한 뒤 품목·현재 GOOD 목표 수량을 잡고 제품 바코드를 검증한다.
- 트레이 완료, 마지막 스캔 취소, 현재 작업 리셋을 처리한다. 부분 제출 코드는 레거시·시험 경로에 남아 있지만, 표준 compact PHS2 작업은 서버가 확정한 GOOD member 전량을 읽기 전에는 부분 제출을 차단한다.
- 작업 중인 트레이를 보류/복구하고, 비정상 종료 후 현재 트레이 상태를 복구한다.
- seal 전 중앙 PHS2 트레이에서 개별 제품 1~2개를 two-bundle CAS로 원자 교체하며, 원래 PHS2 identity는 유지한다.
- `native_audio.WavSound`의 Windows `winsound` 기반 성공/오류 사운드와 Tkinter GUI를 제공한다. 이미지는 `vendor.kmtech_zero_pe.raster`가 처리한다.
- 배포본은 서명된 업데이트 후보를 확인해 관리자 배포가 필요하다고 안내한다. 일반 사용자 런타임은 코드 루트를 수정하지 않는다. 공개 설치 진입점은 `INSTALL_CANONICAL_PORTABLE.ps1`이며 관리자 코드 배치는 내부 `INSTALL_THIS_PC.ps1`가 담당한다.
- 기본 business state 루트는 `%LOCALAPPDATA%\KMTech\ContainerAudit`, DirectSync 루트는 `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`다.

## 기술 스택

- Python 3.11+ 소스 호환, 현재 portable builder의 Python 3.12.10
- Tkinter/ttk
- requests, chardet, qrcode; 배포 이미지·사운드는 vendored raster와 Windows 표준 API
- CSV/JSON 파일 저장
- Windows canonical portable 설치가 현행 배포 진입점이며 기존 PyInstaller 경로는 별도로 남아 있다.

## 실행 및 검증

```powershell
cd C:\company\program\Container_Audit
python Container_Audit.py
python -B tools/run_repository_tests.py --work-root E:\KMTech\<task>\Container_Audit <changed-test-node>
```

의존성 설치는 1회 환경 준비 단계이며 `quick-check`나 검증 script가 자동으로
실행하지 않는다. 준비가 필요할 때만 별도로 `python -m pip install -r requirements.txt`를 사용한다.

변경된 호출 경로와 실제 소비자를 기준으로 기존 focused 검증을 선택한다. 새 SHA만으로
Full·build·재설치·업무 replay를 반복하지 않는다. 출력·TEMP/TMP·캐시는 해당 E 작업 루트에
격리하고, 실제 GUI·설치·서버 검증은 배정된 대상과 권한이 있을 때만 수행한다.
선택된 여섯 프로그램 qualification은 Main이 마감했으며 accepted `d440b1f7`와 원래 실패
증거는 유지한다. S05 소스 정리는 새 운영 배포나 CONTAINER_AUDIT1–3 변경 권한이 아니다.

수동 테스트용 입력 후보:

- `_RUN_AUTO_TEST_`
- `TEST_LOG_[수량]`

## 주요 파일

- `Container_Audit.py`: 메인 GUI와 업무 조정. `transfer_seal.py`, `transfer_member_exchange.py`, `phs_reconciliation_workflow.py`가 물류 내구 상태·교체 계약을 담당한다.
- `container_audit_product_host.py`: 비GUI relay/onboarding/lifecycle 모드. `tools/direct_sync_relay_runner.py`는 실제 제품 consumer가 있으므로 검증 전용 도구로 취급하지 않는다.
- `tools/build_portable_release_candidate.py`: root Python·vendor·계약 bundle과 실제 import되는 도구를 패키징한다. writer inventory와 hash binding도 설치 consumer가 있으므로 소스 변경 시 정합성을 유지한다.
- `assets/Item.csv`: 품목 기준 데이터. 바코드 검증 로직의 핵심 입력이다.
- `assets/*.wav`: 성공/오류/조합 사운드.
- `assets/logo.*`, `assets/*LHD*.png`, `assets/*RHD*.png`: UI/배포 자산.
- `config/container_audit_settings.json`: 읽기 전용으로 패키징되는 UI 기본값 템플릿. 사용자 설정은 user state에 저장한다.
- `config/validator_settings.json`: 현재 portable builder가 포함하는 설정 자산. 사용 여부 판단에는 패키징 계약도 포함한다.
- `ANALYSIS_GUIDE.txt`, `TEST_CODE.txt`: 기존 분석/테스트 메모.

## 데이터와 설정 위치

- 운영 로그: `%LOCALAPPDATA%\KMTech\ContainerAudit\events\이적작업이벤트로그_[작업자]_[YYYYMMDD].csv`
- 현재 트레이 상태: `%LOCALAPPDATA%\KMTech\ContainerAudit\events\_current_tray_state_[컴퓨터ID].json`
- HTTPS 릴레이 상태/큐: `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`
- 보류 트레이: `%LOCALAPPDATA%\KMTech\ContainerAudit\parked_trays`
- 작업자 목록/최고 기록/앱 설정: `%LOCALAPPDATA%\KMTech\ContainerAudit\config`
- 코드 루트의 `config/container_audit_settings.json`은 읽기 전용 기본값 템플릿이며 런타임에 수정하지 않는다.

## 작업 시 주의점

- direct-sync 장기 보관/취합 관련 수정 전 `DIRECT_SYNC_DATA_PLATFORM_NOTES.md`를 먼저 확인한다.
- 이 앱은 단일 대형 파일 구조라 기능 수정 전 `Container_Audit.py`에서 관련 메서드 묶음을 먼저 찾아야 한다.
- 앱은 기본적으로 로컬 앱 데이터 폴더에 파일을 쓰므로 실제 GUI 실행은 `%LOCALAPPDATA%\KMTech\ContainerAudit`에 로그/상태 파일 생성 부작용이 있다. 테스트 격리는 `CONTAINER_AUDIT_DATA_ROOT`로 별도 루트를 지정한다.
- 설치 코드 루트는 관리자 배포 전용이며 일반 사용자에게 RX로 유지한다. 코드 루트와 같거나 서로 포함하는 `CONTAINER_AUDIT_DATA_ROOT`는 시작 전에 거부한다.
- 배포 버전은 `C:\Sync`와 같은 Syncthing 경로를 기본 저장소로 쓰지 않아야 한다. 코드의 저장 정책은 `storage_policy.py`를 기준으로 확인한다.
- `assets/Item.csv` 형식 변경은 바코드 검증과 UI 표시를 동시에 깨뜨릴 수 있다.
- 기존 `ANALYSIS_GUIDE.txt` 일부 설명은 현재 코드의 상태 파일 위치와 다를 수 있으므로 코드 기준으로 판단한다.
- 사운드 장치 또는 Windows `winsound` 초기화 실패의 실제 현장 영향은 배정된 장비에서만 확인한다. 일반 headless 시험은 오디오와 GUI 호출을 격리한다.
- 저장소 상태 메모는 시간 민감 정보다. 작업 전 `git status -sb`와 remote 상태를 새로 확인한다.
