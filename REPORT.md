REJECT · P1 1 · P2 0 · P3 2

검토: 8b9f4c06..cbae5fe8 읽기만. 시험·빌드 실행 0(inventory 해시만 블롭을 읽어 다시 셈). 줄 = cbae5fe8. DSP=direct_sync_push.py, PRC=producer_runtime_client.py, KSR=kmtech_shared/runtime.py, T=tests/test_spool_loss_classification.py.

## 결함
- **P1-1 본문 재열기 소실이 runtime 칸 없는 행에서 PC 보내기 전체 정지로 번짐 (이 diff 의 회귀)**
  - DSP:3348-3354 마지막 else 의 `release` 조건(`not source_post_started and source_file_unreadable`)이 행에 runtime 다섯 칸이 있는지 묻지 않는다. retry_wait 가지(DSP:3333-3335)는 `any(… RUNTIME_METADATA_FIELDS)` 로 묶음.
  - 칸 없는 행 = legacy_exact_replay 행(PRC:824, 앞 회차 POST 전에 고정 → 「받았을 수 있는 행」) · observe+LEGACY_DISABLED 설치의 행(PRC:885).
  - 첫 digest(DSP:3005)는 성공하고 재열기·재읽기(DSP:1596·1603)에서 FileNotFoundError/잠금 외 OSError → retryable False → release → KSR:655 칸 부족 → KSR:600-638 이 설치 scope 를 OPERATOR_REVIEW(`runtime_authority_release_metadata_invalid`)로 둠. 회복 목록(PRC:77-81) 밖 → 다음 회차 ensure 가 operator_review → `run_relay_once`(direct_sync_runtime.py:1347) 보내기 멈춤, 띠 isolated, 관리자 필요.
  - 같은 소실이 첫 digest 에서 나면 `""` 로 그 행만 닫힘(길 따라 행 하나/PC 전체로 갈림). 기준(8b9f4c06)에선 retryable 이라 authority 무관. 새 계약 「해당 행만 닫고」 위반.
  - 시험이 못 잡음: test_body_reopen_*·test_body_digest_*(T:54·78)는 autouse fixture(tests/test_direct_sync_runtime.py:32-55)로 칸 없는 행 + ensure ACTIVE 고정, 행 상태만 봄.
  - 창은 좁다(두 읽기 사이 ms). 중복·유실 0, fail-closed.
  - 고침 제안: else 의 release 를 retry_wait 가지와 같은 칸 검사로 묶고 없으면 `""`. 시험: 칸 없는 행 missing/io 재열기 뒤 authority ≠ OPERATOR_REVIEW, 다음 행 POST 1.
- **P3-1 자가 수선 축소** runner `_repair_recoverable_delta_spools_before_scan`(tools/direct_sync_relay_runner.py:349-441)은 pending/retry_wait 만 되살림. drain 이 소실을 처음 볼 때 닫으므로 (a) scan 뒤·drain 전 소실, (b) `--require-runtime-lease-before-scan`(:886, drain 먼저) 설치에선 전엔 다음 회차 무손실 회복되던 행이 terminal+원본 차단(관리자)이 됨. 계약에 적거나 drain 전 수선 1회.
- **P3-2 보존 배정의 뒤끝(회귀 아님, ANSWER-1)** carried 행이 failed_permanent 로 배정을 쥐면 뒤 행은 모두 `runtime_request_in_flight`(PRC:909-917)로 끝없이 대기(T:146-151 이 단언). 띠는 「영구 실패 1」만 보여 전체 대기가 안 드러나고 retry-dead 는 막힘(direct_sync_operator.py:1011-1024). 해제 길을 문서에.

## 항목
1. 중복·유실 0(P1 밖): 닫힌 행의 원본은 `_delta_relay_row_blocks_progress`(runner:443-445)로 새 delta 를 안 만듦 → 건너뛰기·재전송 0. 기록은 원본에 남아 막힌 수로 셈. carried 행은 preserve 로 release·scrub 0(DSP:2589-2593·2670·2678), 뒤 행 POST 0.
2. 잠김 → terminal 길 없음: PermissionError(winerror 5/32/33)는 첫 digest·재열기·재읽기 모두 retry_wait. POST 시작 뒤 OSError 는 transport_error 재시도(DSP:1623).
3. K/N·띠·상태: failed_permanent → health review(direct_sync_health.py:98-104), 상태 파일 scan_terminal_blocked_*, 공개 block 파일, 띠 「막힌 기록 파일 1개」. 잠김은 retry_wait, 이적 queue 나이는 경고뿐(direct_sync_runtime.py:1028-1031), enqueue 계속.
4. 앞 구간 계약: 같은 원본 terminal 앞 구간 건너뛰기 0. 이번 회차 새 배정만 release, 이어받은 배정 보존 — P1 의 칸 없는 행 말고는 일치.
5. 핀: 5 파일 sha256 = transition after 값. inventory 차이는 줄(-18 = 도우미 18줄, -25 = +7줄)과 sha 뿐. sha(cac3…6c3b6c)를 `_inventory_sha256` 방식으로 다시 세면 맞음, 5곳 같음, 옛 값 잔존 0.
