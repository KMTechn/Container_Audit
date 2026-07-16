# Container Audit v2.0.31 릴리스 노트

작성일: 2026-07-15
대상 태그: `v2.0.31`
상태: 코드 후보 준비 완료, 현장 검증·tag·release 대기

## 릴리스 요약

v2.0.31은 `Inspection_worker v2.0.49`의 작업 중심 UI 원칙을 Container Audit에 적용한 릴리스입니다. 기존 이적 검사 업무와 저장·동기화 계약은 유지하면서, 작업자가 현재 단계와 다음 행동을 더 빠르게 읽을 수 있도록 3분할 화면의 정보 우선순위와 예외 상태 표시를 정리했습니다.

## 작업자 화면 변경

- 좌측 작업 정보, 중앙 핵심 작업, 우측 상태·후속 정보의 3분할 구조를 유지했습니다.
- 중앙에는 현재 단계, 목표 수량과 진행도, 스캔 입력, 단일 경고, 현재 트레이의 실제 스캔 목록, 핵심 작업 버튼을 한 흐름으로 배치했습니다.
- 중앙 스캔 기록은 별도의 복제 표가 아니라 기존 `scanned_listbox`와 기존 데이터 갱신 흐름을 그대로 사용합니다. 정상·중복·담당자 확인 상태 전환에서도 같은 위젯과 목록을 유지합니다.
- 우측은 현재 상태와 스톱워치, 마지막 정상 스캔, 다음 행동을 우선하고 평균·30일 최고 기록은 보조 정보로 낮췄습니다.
- `1366×768`의 1.4배 큰 글씨에서는 날짜·시계와 장식 여백을 제한하고 카드 간격을 줄이며, 비필수 범례를 가역적으로 숨깁니다. 완료 안내가 줄바꿈되어도 중앙 목록과 작업 버튼이 화면 안에 남습니다.
- compact 화면의 담당자 확인 버튼 문구를 짧게 표시하고, 우측 값은 가운데 정렬과 줄바꿈을 적용해 가로·세로 잘림을 방지합니다.

## 경고와 OPERATOR_REVIEW 안전 상태

- 경고는 중앙 알림 영역 한 곳에서 한 번만 표시하며, 마지막 정상 스캔과 현재 트레이 스캔 목록은 오류 뒤에도 유지합니다.
- 중복 스캔, 일반 오류, 완료, 복구, `OPERATOR_REVIEW`가 같은 화면 구조를 사용합니다. 상태 전환은 문구·색상·테두리로 표현하며 별도 작업 화면으로 이동하지 않습니다.
- `OPERATOR_REVIEW`는 완료 판정을 확정할 수 없는 잠금 상태입니다. 스캔 입력과 작업을 변경하는 동작을 막고 현재 트레이와 스캔 목록을 유지합니다.
- `OPERATOR_REVIEW` 잠금 정보는 현재 트레이 상태에 함께 저장되고 재시작 뒤 복원됩니다. 잠금된 트레이는 일반 복구·인계 과정에서 임의로 변경하거나 삭제하지 않습니다.

## 보존한 계약

- 원시 CSV 헤더, 기존 이벤트 이름, 기존 필수 이벤트 필드는 변경하지 않았습니다.
- OP_REVIEW 재시작 복구를 위해 로컬 트레이 JSON에 선택 필드 `pending_operator_review`를 추가하고, 복구 이벤트의 `detail`에 선택 필드 `operator_review_restored`를 추가했습니다. 기존 상태 파일과 기존 필드 판독은 그대로 호환됩니다.
- 바코드 검증, 트레이 완료·보류·복구·교체·교환의 기존 업무 판정은 변경하지 않았습니다.
- direct-sync HTTPS 업로드, 릴레이 도구, 업데이트 archive 구조와 API 계약을 변경하지 않았습니다.
- PyInstaller onedir 배포 구조와 `Container_Audit.exe` 진입점, release config 정제 규칙을 유지합니다.
- 독립 저장소 간 새 런타임 UI 패키지 의존성을 추가하지 않았습니다.

## 확인된 검증 증거

- `python -m py_compile Container_Audit.py responsive_layout.py`: 통과
- `python -m pytest -q tests/test_responsive_layout.py tests/test_operator_ui_structure.py tests/test_option1_center_layout_contract.py`: 41개 통과
- `python -m pytest -q -p no:cacheprovider`: 1,133개 통과, pygame/pkg_resources 비치명 경고 1개
- `1366×768`, 배율 1.4, 대기·정상·중복·담당자 확인·완료·복구 6개 상태 strict 캡처: 6/6 통과
  - 로컬 증거: `tmp/container_large_text_1_4_verified_20260715/manifest.json`
- `1366×768`, 기본 배율 1.0, 같은 6개 상태 회귀 캡처: 6/6 통과
  - 로컬 증거: `tmp/container_default_1_0_regression2_20260715/manifest.json`
- 통합 후보 기본 배율의 `1366×768`, `1440×900`, `1920×1080`, `2560×1080` 4개 크기와 6개 상태 strict 캡처: 24/24 통과
  - 로컬 증거: `tmp/container_operator_ui_strict_integrated_20260715/manifest.json`
- 통합 후보 기본 배율의 `1280×1024`, 보조 모니터 최대화 `2560×1392`와 6개 상태 캡처: 12/12 통과
  - 로컬 증거: `tmp/container_operator_ui_extended_sizes_20260715/manifest.json`
- 통합 후보 배율 1.4의 `1280×1024`, `1440×900`, `2560×1392`와 6개 상태 캡처: 18/18 통과
  - 로컬 증거: `tmp/container_operator_ui_large_text_matrix_20260715/manifest.json`
- 격리된 v2.0.31 PyInstaller 후보: main onedir 및 relay/install/register 실행 파일 빌드 통과
- archive smoke, 정제 release config 및 workflow 필수 파일: 22/22 통과
  - 로컬 ZIP: `tmp/container_release_candidate_v2_0_31_20260715/package/Container_Audit-v2.0.31.zip`
  - 크기: 94,302,528 bytes
  - SHA-256: `8f6b99539e036c5275610f1c1f62a74d73445e3726f3a592080a3f143e877e1d`

`tmp/` 캡처와 ZIP은 로컬 검증 증거이며 승인된 릴리스 자산으로 발행하지 않았습니다. 로컬 패키지는 Python 3.12.10/PyInstaller 6.20.0으로 생성했으므로, 태그 전에는 GitHub workflow의 Python 3.11 환경에서 전체 pytest, `compileall`, release config 검사, PyInstaller archive smoke를 다시 통과해야 합니다.

## 릴리스 빌드 계약

배포 명령의 권위 있는 원본은 `.github/workflows/release.yml`입니다. `Container_Audit.spec`은 같은 main onedir 입력을 기술하지만, 실제 릴리스에서는 workflow가 정제된 `build/release_config`와 `build/release_tools`를 준비한 뒤 명시적 PyInstaller CLI를 실행합니다.

예상 주 산출물은 다음과 같습니다.

- `dist/Container_Audit/Container_Audit.exe`
- `dist/Container_Audit/Container_Audit_DirectSync_Relay.exe`
- `dist/Container_Audit/Container_Audit_DirectSync_Install.exe`
- `dist/Container_Audit/Container_Audit_Worker_PC_Register.exe`
- `dist/Container_Audit/assets/`, `config/`, `tools/` 및 workflow의 필수 런타임 모듈
- `Container_Audit-v2.0.31.zip`
- `Container_Audit-v2.0.31.zip.sha256`
- private update feed를 사용하는 경우 `Container_Audit-v2.0.31.manifest.json`과 64-byte Ed25519 서명 파일

GitHub Release에는 workflow 계약상 ZIP과 SHA-256 파일만 업로드합니다. private manifest와 서명은 설정된 사내 HTTPS update feed로만 발행합니다.

## 외부 릴리스 게이트

다음 항목은 이번 로컬 준비 작업에 포함되지 않았으며, 모두 통과하기 전에는 배포 완료로 간주하지 않습니다.

1. 실제 보조 모니터와 스캐너로 대기·정상·오류·완료·복구·`OPERATOR_REVIEW` 및 재시작 잠금 현장 검증
2. 운영 데이터 루트와 현장 설정을 사용하지 않는 격리 canary 후, ledger·direct-sync 수신 결과 대조
3. 승인된 변경만 포함한 독립 커밋과 깨끗한 worktree 확인
4. 원격 `main` push 전 전체 CI 통과 및 변경 승인
5. `CURRENT_VERSION`과 정확히 같은 `v2.0.31` 태그 생성 승인
6. 태그 workflow의 전체 pytest, release config 검사, PyInstaller 빌드, archive smoke, checksum 성공
7. private update 사용 시 HTTPS artifact URL, manifest URL·공개키, Ed25519 signing key, upload URL·token 및 rollout 설정 검증
8. GitHub Release와 private feed 발행 승인, 한 현장 canary 완료 후 단계적 rollout

이 문서 작성 시점에는 commit, push, tag, GitHub Release, private update publish를 실행하지 않았습니다.
