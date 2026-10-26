REJECT · P1 1 · P2 2 · P3 5

# 독립 검토 — READY 확인 창 900 초 · 다시 기회(retry_shas)

- 대상: `cloud-input/calm-ready900-ca` 머리 `9857626f`, 바탕 `5824fdb4`
- 커밋: `751f650d`(wip) · `f7fa1d2f` · `2b809727` · `fa3be129` · `5867e938` · `9857626f`
- 방식: 읽기만 함. 소스는 하나도 고치지 않음. 이 가지에는 이 파일 하나만 더함.
- 줄 번호는 모두 `9857626f` 기준임.

## 항목 표

| # | 볼 것 | 판정 | 근거 (파일:줄) |
|---|---|---|---|
| 1 | 영구 거절은 서명·해시·검사 실패에만 남는가 | **REJECT (P2)** | `auto_update.py:210-215` · `auto_update.py:2082-2083` · `auto_update.py:2259-2263` |
| 2 | retry_shas 셈 (3 번 · 24 시간 · 900 초 · 잘못된 기록) | ACCEPT (P3 메모 1) | `auto_update.py:188-207` · `auto_update.py:244-265` · `auto_update.py:2313` |
| 3 | 이어받은 창 만료도 셈 · 조기 종료와 안 섞임 · UNKNOWN·세대·포인터 그대로 | ACCEPT (P3 메모 1) | `auto_update.py:2375-2423` · `auto_update.py:355-404` |
| 4 | 되돌림 창도 900 초 · 되돌림 실패는 다시 기회로 안 감 | ACCEPT | `auto_update.py:2143-2144` · `auto_update.py:2173` · `auto_update.py:2403-2407` |
| 5 | 문구·코드가 화면·서버까지 맞게 이어짐 | ACCEPT (P3 메모 2) | `auto_update.py:41-42` · `auto_update.py:996` · `auto_update.py:1064` · `auto_update.py:3205-3222` |
| 6 | 선언 파일 바뀜이 핀 전파뿐인가 | **REJECT (P1)** | `tools/container_writer_sink_inventory.json:594,627,9973` · `tools/derive_container_writer_sinks.py:1810` · `tools/build_portable_release_candidate.py:749` |
| — | 사용자 failed-support 검사(PowerShell 짝)가 따라오지 않음 | **REJECT (P2)** | `tools/bootstrap_integrity.ps1:4097-4103` · `auto_update.py:2074-2081` |

## P1

### P1-1 쓰기 인벤토리에서 `_run_fixed_helper` 가 covered → uncovered 로 떨어졌고, 그대로 선언으로 굳어짐 (항목 6)

- `f7fa1d2f` 는 `_run_fixed_helper` 본문에 두 줄을 더함: `error._preparation_timeout`, `error._preparation_rejection` (`auto_update.py:1868-1873`).
- 인벤토리 도구는 이 함수의 읽기 전용 Observe 경로를 승인할 때 본문의 AST 해시를 고정값으로 대조함 (`tools/derive_container_writer_sinks.py:1810`, 고정값 `dd0da7f5…`). 본문이 바뀐 함수는 다시 감사를 받아야 한다는 설계임.
- Python 3.12(빌드에 쓰는 해석기, `requirements-portable-build-win-py312.lock`)로 직접 계산함:
  - 바탕 `5824fdb4` = `dd0da7f5…` → 일치
  - 머리 `9857626f` = `f3d28c3f…` → 불일치
- 그래서 다시 만든 선언(`2b809727`, `9857626f`)은 다음과 같이 바뀌었음:
  - `caller_guard_reason` 이 빈 값이 됨
  - `coverage_status` = `"uncovered"` (`container_writer_sink_inventory.json:594`)
  - `unsunk_entrypoints` 12 개
  - `uncovered_mutation_function_count: 1` (`:9973`). 바탕에서는 uncovered 가 0 이었음.
- 새로 덮이지 않는 경로는 다음 둘임:
  - `startup_gate → assert_ordinary_recovery → process_snapshot → _run_fixed_helper`
  - `auto_update.main → resolve_lifecycle_context → assert_failed_support_quiescent → process_snapshot → _run_fixed_helper`
- 결과: `tools/build_portable_release_candidate.py:749` 는 `uncovered_direct_mutation_functions != []` 이면 `"writer sink inventory is not release-admissible"` 로 멈춤. 이 가지로는 정식 포장 판을 만들 수 없음.
- `tests/test_canonical_rollback_resume.py:102` 같은 시험도 이 상태에서는 skip 으로 빠짐.
- 따라서 선언 바뀜은 핀 전파만이 아님. 쓰기 울타리 적용 범위가 실제로 줄어든 것이 선언에 기록됨.
- 덧붙여 새로 더한 두 줄은 실제로는 아무 일도 하지 않음(P3-1 참고). 이 두 줄을 빼면 해시가 원래대로 돌아오고 문제도 사라짐. 고침은 이 검토의 범위가 아님.

## P2

### P2-1 PowerShell failed-support 검사가 새 「다시 기회」 상태를 모름 (Python 짝과 어긋남)

- 바탕 코드는 일시 실패 때도 `failed_prepared_sha` 와 `failed_prepared_marker_sha256` 을 채웠음.
- 이제 다시 기회 길에서는 둘 다 `""` 로 비움 (`auto_update.py:2074-2077`). READY 시간 초과도 후보를 `failed_shas` 에 넣지 않음 (`auto_update.py:273-282`).
- Python 쪽 검사 `assert_failed_support_quiescent` 는 `prepared_pending` 을 거침. `prepared_pending` 은 `_preparation_retry_due` 로 900 초 대기와 3 회 소진을 따름 (`auto_update.py:2676-2677`).
- PowerShell 짝 `Assert-BootstrapFailedSupportState` (`tools/bootstrap_integrity.ps1:4097-4103`) 는 이번에 바뀌지 않음. 이 함수는 `sha ∉ failed_shas` 이고 `sha ≠ failed_prepared_sha` 이면 무조건 `failed_support_prepared_pending` 을 던짐.
- 실제로 벌어지는 일:
  1. 후보가 READY 시간 초과로 다시 기회를 받음.
  2. 되돌림 READY 도 실패해 phase 가 `FAILED` 가 됨 (`auto_update.py:2405-2407`).
  3. `prepared.json` 은 지워지지 않으므로 (`auto_update.py:2860`) 그대로 남아 있음.
  4. 관리자가 failed-support 설치로 복구하려 하면 PowerShell 검사가 거절함. 같은 순간 Python 검사는 「대기 중」이라며 통과시킴.
- 바탕에서는 후보가 `failed_shas` 에 있었으므로 이 복구 길이 열려 있었음. 복구 길을 줄인 회귀임.
- 이번 커밋들 어디에도 PowerShell 짝을 맞춘 기록이나 시험이 없음.

### P2-2 「서명·해시·검사 실패만 영구」에서 다른 원인이 영구 거절로 샘 (항목 1)

바탕에는 준비 단계에서 `failed_shas` 에 넣는 길이 아예 없었음. 영구 거절은 `request_rollback` 에서만 생겼음. 이번에 새로 생긴 `elif` (`auto_update.py:2082-2083`) 로 다음 원인들이 SHA 를 영구 거절함.

- **공간 없음 (winerror 112 / ENOSPC)** (`auto_update.py:213-214`)
  - 디스크를 비우면 풀리는 일시 상태임. 그런데도 SHA 를 영구히 막음.
  - 명세(operations.md 「공간 없음 … 즉시 확정 거절」)와는 맞음. 이번 검토 기준(서명·해시·검사만)과는 어긋남.
- **지금 설치된 판의 manifest 를 못 읽는 경우** (`auto_update.py:2259-2263`)
  - `version_manifest(active bundle)` 의 ValueError 를 `_preparation_rejection` 으로 표시함.
  - 문제는 설치된 판 쪽인데, 영구 거절은 상관없는 후보 SHA 가 받음.
- **영구 거절에 쓰는 SHA 를 서명 안 된 곳에서 가져옴**
  - 그 SHA 는 사용자 소유 staging 의 `prepared.json` `source_commit` 에서 읽음 (`auto_update.py:2064`).
  - 서명 실패나 `signed target SHA differs from the packet` 처럼 표지와 서명 내용이 다른 경우에도, 서명되지 않은 표지 SHA 가 영구 목록에 들어감.
  - 이 SHA 를 나중에 정상 서명으로 받아도 `prepare_feed_packet` 이 `FAILED_VERSION_PRESERVED` 를 돌려주고 (`auto_update.py:2744`), 다시는 적용되지 않음.

반대 방향(진짜 서명·해시 실패가 다시 기회로 새는 길)은 다음과 같음.

- Python 이 직접 하는 검증은 모두 거절로 표시함. 해당 함수: `verify_prepared_packet`, `extract_prepared_code`, `manifest_transition_pins`, 후보 `version_manifest`, 서명 키 비교, 바인딩 불일치 (`auto_update.py:2271-2301`, `2339-2354`).
- 도우미 `Verify` 의 FILE_PIN 해시 불일치는 이유가 가려져 `STARTUP_UPDATE_FAILURE` 로 나옴. 이것은 승인된 정책대로 「모름」이며 세 번 다시 기회를 받음. 이 경우에도 적용은 일어나지 않으므로 안전 쪽임.

## P3

- **P3-1 도우미 분류 코드는 실제로는 쓰이지 않음** (`auto_update.py:1868-1873`)
  - 고정 도우미는 실패 기록을 stdout 의 `CONTAINER_AUDIT_UPDATE=` 로만 냄 (`tools/apply_prepared_update.ps1:280-319`). 기록에는 throw 한 메시지 없이 `STARTUP_UPDATE_FAILURE` 만 들어감. stderr 에 `STARTUP_UPDATE_*_DIFFERS` 를 쓰는 곳이 없음.
  - `STARTUP_QUERY_TIMEOUT_UNKNOWN` 은 저장소 어디에도 내보내는 곳이 없음.
  - `_preparation_timeout` 를 읽는 곳도 없음.
  - `tests/test_update_ready_retry.py:239-251,358-372` 는 일어나지 않는 stderr 를 흉내 내어 시험함.
  - 동작은 결국 「모름 = 다시 기회」로 정책과 같음. 다만 이 죽은 코드 때문에 P1-1 이 생겼음.
- **P3-2 시계가 뒤로 가면 예산이 처음부터 다시 시작됨**
  - `first_at` 이 미래이면 `record_retry_chance` 가 그 항목을 버리고 attempts=1 로 다시 시작함 (`auto_update.py:198-201`).
  - `_preparation_retry_due` 는 이 경우 바로 「다시 시도 가능」을 돌려줌 (`auto_update.py:258-260`).
  - 직접 확인: 미래 `first_at` 에 attempts=2 인 기록 → `attempts: 1` 로 바뀜.
  - 기록은 SYSTEM 이 보호하는 파일이라 변조 위험은 낮음. RTC 가 초기화되면 3 번 상한이 풀릴 수 있다는 점만 메모로 남김.
- **P3-3 「기동 실패」를 따로 구별하지 않음** (`auto_update.py:2129`, `2398-2399`, `2410-2423`)
  - 조기 종료는 「trial_pid 가 묶인 뒤 GUI 가 사라짐」 하나로만 판정함.
  - GUI 가 claim 을 쓰기 전에 죽으면 시간 초과로 셈되어 다시 기회를 받음. 명세 문구 「시험 앱 기동 실패 … 즉시 확정 거절」과 다름.
  - 반대로 900 초 동안 작업자가 창을 닫으면 영구 거절됨. 바탕과 같은 동작이지만, 창이 15 분으로 길어져 이런 일이 생길 수 있는 시간도 늘었음.
  - 이어받은 창(opened_here=False)은 UNKNOWN 전환, 세대 판정(`decide_trial_failure`), `recovery_sha` 포인터 선택이 모두 그대로임. 셈이 한 번만 기록되는 것도 확인함 (UNKNOWN 을 다시 처리하는 `auto_update.py:2234` 길에서는 셈하지 않음).
- **P3-4 소진 안내가 기동할 때마다 나옴. 서버로 갈 때 대체 코드를 쓰는 곳이 저장소에 없음**
  - `UPDATE_RETRY_REVIEW_REQUIRED` 는 `emit_support_record` 를 거치므로 `report_once` 로 중복을 걸러 내지 못함 (`auto_update.py:3218-3222`). 24 시간 동안 기동할 때마다 같은 기록을 씀.
  - 준비 단계에서 `Authority` 같은 공통 실패가 나도, 그 순간 `prepared.json` 에 적힌 SHA 의 예산이 줄어듦 (`auto_update.py:2064`, `2077-2079`).
  - 「서버가 모르는 코드면 UPDATE_PREPARATION_FAILED」로 바꾸는 코드는 이 저장소에 없음. 지원 기록은 `startup-support.json` 과 stdout 으로만 나가고, 서버로 보내는 곳이 이 저장소에 없음. 이 부분은 이 저장소만으로는 확인할 수 없음.
  - 문구 자체는 맞음 (아래 근거 참고).
- **P3-5 재시도 간격이 READY 창 상수를 그대로 씀** (`auto_update.py:248`, `264`)
  - 지금은 둘 다 900 초라 맞음. 나중에 창만 바꾸면 재시도 간격도 함께 바뀜. 별도 상수가 아님.

## 항목별로 확인한 것 (ACCEPT 근거)

**항목 2 — retry_shas 셈**

- 3 번 상한: attempts 가 1 → 2 → 3 이 되면 `>= RETRY_ATTEMPT_LIMIT` 로 막음.
- 24 시간: `0 <= age < RETRY_WINDOW_SECONDS` 를 벗어난 항목은 버리고 새 예산(attempts=1)을 시작함. 이 검사가 900 초 간격 검사보다 먼저 오므로, 「24 시간 새 예산이 900 초보다 우선」이 지켜짐 (`auto_update.py:258-262`).
- 잘못된 기록: `type(...) is int` 검사가 bool 을 걸러 냄. 시각이 잘못된 항목은 두 함수가 똑같이 「없는 것」으로 다룸.
- 다른 SHA 기록이 그대로 남는 길: `record_retry_chance` 는 다른 SHA 의 유효한 항목을 보존함. 다음 전환은 `prepare_transition(retry_shas=…)` 로 기록을 넘김 (`auto_update.py:2313`). 그 밖의 전이도 `{**state}` 로 기록을 이어감: confirm · rollback · decide · defer · GENERATION_UNKNOWN.
- 셈이 두 번 오르지 않는 이유: 셈은 ROLLBACK_PENDING 또는 UNKNOWN 으로 바꾸는 같은 쓰기 안에서 한 번만 기록됨. 재시작 뒤에는 다른 분기를 타므로 다시 셈하지 않음.

**항목 4 — 되돌림**

- 되돌림 창은 `rollback_at` 부터 `READY_WINDOW_SECONDS` = 900 초임 (`auto_update.py:2143-2144`).
- 되돌림 실패는 `FAILED` 로 가고 retry 를 기록하지 않음 (`auto_update.py:2173`, `2405-2407`).
- 되돌림 중 예외가 나면 apply_prepared 에서 phase 가 not_applied 가 아니므로 `UNKNOWN` 이 되고, 이때도 retry 를 기록하지 않음 (`auto_update.py:2057`).
- bootstrap 단계 창도 900 초로 맞췄고 상한은 1140 초임 (`auto_update.py:36`, `3258-3264`).
- SYSTEM 적용 예약 작업의 `ExecutionTimeLimit` 은 `PT0S` 라서 900 초 창이 작업 시간 제한에 잘리지 않음 (`auto_update.py:1723`).

**항목 5 — 문구와 코드**

- `RETRY_REVIEW_MESSAGE` 는 확정 문구와 바이트 단위로 같음 (직접 비교 결과 True).
- `support_record({"reason_code":"UPDATE_RETRY_REVIEW_REQUIRED",…})` 의 `guidance` 도 같은 문구로 나옴.
- `PUBLIC_CODES` 와 `SAFE_MESSAGES` 에 모두 등록되어 있음.
- 소진 상태에서 `start_current` 는 원래 코드(예: `UPDATE_PREVIOUS_CONFIRMED`)를 `UPDATE_RETRY_REVIEW_REQUIRED` 로 바꿈. 이때 `transition_code` 는 원래 값을 그대로 둠.

## 실행한 시험

- 실행한 파일 4 개 (이 커밋들이 더하거나 바꾼 READY·retry 시험):
  - `tests/test_update_ready_retry.py`
  - `tests/test_update_ready_window.py`
  - `tests/test_update_ready_lock_retry.py`
  - `tests/test_bootstrap_live_apply_wait.py`
- 결과: **134 passed (304 s)**.
- 실행 환경:
  - Linux 컨테이너, Python 3.12, tkinter 설치.
  - 시험 하네스가 Windows 전용이라 작업 디렉터리 밖에 임시 `sitecustomize` 를 두고 `ctypes.WinDLL`, `ctypes.windll`, `subprocess.CREATE_NO_WINDOW` 만 흉내 냄.
  - 저장소 파일은 고치지 않았음. Windows 실기 결과는 아님.
- 이 4 개 파일은 P1-1(인벤토리)과 P2-1(PowerShell 짝)을 잡지 못함.
- 인벤토리 시험과 포장 시험은 범위 밖이라 돌리지 않음. P1-1 은 AST 해시를 직접 계산하고 선언 JSON 을 직접 읽어 확인함.
