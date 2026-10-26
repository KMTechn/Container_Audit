Claude Code (모델 식별자는 세션 규칙상 저장소에 쓰지 않음 — 채팅 답변으로 보고)
REJECT · P1 0 · P2 1 · P3 2

# 독립 검토 — 완료 뒤 사후 검토 안내 띠 (calm-postreview-band-ca)

대상 a46210fd..501b099d (1커밋 「Allow scans during completed transfer review notices」). 읽기만, 소스·시험 고침 0. 줄 번호 = 501b099d.

## P2-1 부분 제출 완료 뒤 사후 검토 띠가 곧바로 덮여 사라짐(반복 오류음만 남음)

- 길: tray_completion.py:570-572 `post_review_required`(OPERATOR_REVIEW·로컬 결속) → :907 `present_completed_tray` → :995-998 띠 present. 이때 Container_Audit.py:20178 이 사례 id 를 「보임」 집합에 넣고 :20179 `_start_warning_beep()`(loops=-1)를 켬 → 부분 제출이면 tray_completion.py:931-933 `show_status_message("부분 제출 완료 — …", duration=0)`(실패 가지 :936 도 같음) → Container_Audit.py:21236-21243 비막음 `status.*` 알림이 present 로 띠를 바꿔 끼움(warning_presenter.py:206 은 막는 상태일 때만 거절).
- 결과: 띠, 「확인」 단추(Container_Audit.py:17172-17183 은 code 가 띠일 때만), 빈 Enter·Esc 확인(:15198, :15427)이 모두 사라짐. 사례 id 는 이미 「보임」이라 refresh(:20411-20420)로 다시 뜨지 않고 재시작 때만 다시 보임. 오류음은 다음 스캔(:15606-15607)까지 계속되고, 웹 셸은 「오류음 — 확인할 때까지 반복」(ca_screen_bridge.py:154-156)을 띄우지만 확인할 띠가 없음.
- 바탕: 같은 길에서 띠가 blocking=True 라 status present 가 거절되어 띠가 남음. 이 커밋이 연 회귀.
- 재현(scratchpad 탐침, 저장소 밖): `_completion_app(seal_status="OPERATOR_REVIEW", ledger_succeeds=True)` + local_completion_id 있는 SealAttempt, 스캔 2/3·`is_partial_submission=True`, show_status_message 를 실제 메서드로 연결.
  - 머리: active_notice = `status.success`「부분 제출 완료 — 2개(1개 부족)」, 「보임」 = {'review-case-1'}, 마지막 소리 사건 start_beep.
  - 바탕: active_notice = `transfer.post_review_required`(blocking True)가 그대로 남음.
- 같은 뿌리(따로 세지 않음): 띠가 떠 있는 동안 다른 길의 비막음 show_status_message(:21236-21243)나 4초 status 만료 clear(:21263-21267)도 띠를 지우는데, 반복음은 띠 수명과 묶여 있지 않음. 다음 제품 스캔 뒤 clear(:16184-16186)는 무중단 설계상 받아들일 만함.
- 시험 빈칸: `_completion_app` 이 show_status_message 를 stub(tests/test_warning_presenter_headless_integration.py:195)해서 덮임을 볼 수 없고, 부분 제출 길 시험이 없음.
- 제안(고침 0): 부분 제출 길에서 status 다음에 띠를 present 하거나(또는 show_status_message 가 `transfer.post_review_required` 띠를 바꿔 끼우지 않게), 반복음은 띠가 사라질 때 같이 멈춤. 시험: 실제 show_status_message 로 「부분 제출 + 사후 검토」 → 띠·확인·Enter/Esc 가 남고 다음 스캔이 허용되는지.

## P3-1 Esc 판정만 처리 오류(담당자 확인) 조건이 없음

Container_Audit.py:15196-15203 은 `_notice_blocks_scan() or code == 띠` 라서, `_operator_review_blocks_mutation()`(:17047-17054 = `_ui_lane_fault_blocked` 또는 막는 완료 snapshot)이 참이어도 띠를 닫음. 빈 Enter(:15424-15432)와 웹 셸 확인(ca_screen_bridge.py:182, `_cmd_ack`→`_enter("")` :1084-1088)은 이때 닫지 않음. 탐침: 띠 + `_ui_lane_fault_blocked=True` → Esc 는 "break"·띠 None, 입력 허가는 :15024 로 계속 거절. 띠를 감출 뿐 업무 막음은 안 풀리므로 P3. 막는 완료 snapshot 이 있으면 띠 자체가 present 될 수 없어(warning_presenter.py:206) 실제로 어긋나는 갈래는 처리 오류 하나.

## P3-2 보호 시험 일부가 이 바뀜으로는 실패할 수 없음

tests/test_transfer_post_review_band.py:144-166 의 operation_lease·preflight·exchange 는 술어(`_operation_lease_hold_blocks_scan` Container_Audit.py:12890-12892, `_preflight_context_blocks_mutation` :2686-2698, stub 된 교환 시도)를 직접 부르고 알림 상태를 읽지 않음. 그래서 띠 판정이 어떻게 바뀌어도 GREEN. 실제 스캔 길의 거절(lease :15631·:16055 는 `_process_barcode_logic` 안인데 `_app()` 이 이를 stub, tests/test_notice_scan_refusal.py:45)은 보지 않음. storage 만 `_scan_entry_admission_block_reason` 을 거침. 고칠지는 작성자 몫.

## 항목

1. **ACCEPT** — 판정은 `Notice.blocking` 하나에 기댐. 띠 code 를 만드는 곳은 Container_Audit.py:20151-20165 하나뿐(blocking=False)이고, 부르는 곳은 셋.
   - (a) tray_completion.py:995-998: :570-572 OPERATOR_REVIEW∧로컬 결속이고, 앞 실패 가지가 모두 return False 한 뒤(:594-610 미결속, :783-797 원장 거절)이며, :952 current_tray 교체 다음.
   - (b) refresh :20411-20420: 행은 transfer_store.py:368 `local_completion_id NOT NULL REFERENCES transfer_completion_ledger` 이고, 결속이 없으면 :794-796 이 만들지 않음.
   - (c) 행 없는 안내 :20422-20427·:20329-20336.

   어느 것이든 present 는 is_blocking 이면 거절(warning_presenter.py:206)하고, present_completion 은 띠를 덮음. 의도 막음 여섯은 이렇게 갈림.
   - presenter 를 막는 것: 미결속 완료 = OPERATOR_REVIEW snapshot, 원장 거절 = LOCAL_EVENT_RETRY snapshot.
   - presenter 와 따로인 기준이라 띠·확인이 못 건드리는 것: 로컬 저장(:15026·:2688), 보류 소유권/목표(:15049·:2686-2720), lease(:15631·:16055), 현재 교환(:19076~).

   code 문자열 비교 넷(:15198·:15427·:17173·bridge :175)은 확인 단추·키만 정하고, 입력 허가(:15108-15125, :15018-15064)는 is_blocking 만 봄. 탐침: OPERATOR_REVIEW+결속+원장 거절 → complete_tray False·막음 유지, 사례 행으로 refresh 해도 거절·상태 그대로.
   - 참고(세지 않음): replay 실패(저장소 읽기 실패 :20305-20307 포함)도 띠로 내려감. 시험 :107-113 이 의도로 고정했고, 새 작업의 쓰기는 각자 막음이 있음. 행 없는 안내는 시작 복구의 OPERATOR_REVIEW 결과 전체(:20521-20523)에서도 켜지지만, 미결속이면 복원된 snapshot 이 막고 있어 present 가 거절됨.
2. **REJECT** — P2-1. 그 밖은 맞음.
   - 내구 행은 append-only(transfer_store.py:376-381).
   - 관리자 재시도는 첫 command_bound 행(Container_Audit.py:20205-20206, bridge :407-417) 그대로이고 메뉴 조건(:8861-8873)도 바뀜 없음. 띠가 떠 있어도 재시도가 가능해짐(:20195-20201 is_blocking 검사가 이제 띠 때문에 막지 않음).
   - 재시작: 「보임」 집합은 메모리라 첫 refresh 에 다시 뜸(시험 restarted=True).
3. **ACCEPT** — 띠는 apply_completed_tray_state_steps 가 새 TraySession 으로 바꾼 뒤(tray_completion.py:952) 나오므로 새 스캔은 새 트레이에만 쌓임. 같은 현품표 재스캔은 완료 기억(:868)으로 중복 처리됨. 사후 재시도는 활성 트레이가 없을 때만(Container_Audit.py:20195-20201, authorized :20225-20231) 원 intent 의 저장 명령을 다시 보냄. 수량·세트·완료 판정 코드 바뀜 0.
4. **ACCEPT**(P3-1 단서) — Tk 입력 허가(:15108-15125/:15018-15064)와 웹 셸 scan(ca_screen_bridge.py:768-794)이 같은 `_notice_blocks_scan`·`_notice_button_captures_scan` 을 씀. 띠 표시·확인은 Tk :17172-17183·입력칸 :17212-17218, 웹 셸 :175-184·`_cmd_ack` :1084-1088(빈 Enter 와 같은 문). Esc 만 어긋남.
5. **ACCEPT**(P3-2 단서) — 바뀐 두 기대값(tests/test_warning_presenter_headless_integration.py:433, :490-524)은 둘 다 로컬 결속 사후 검토라서 바로 이 커밋의 목표이고, 롤백 없음·작업자 안전 문구·원시 코드 숨김 단언은 그대로.
   - RED→GREEN: 바탕 + 새 시험 파일 → 7 실패 / 9 통과(9 = 막음 보존 잠금). 머리 → 16 통과.
   - 변이(하나씩 되돌림): blocking=True → 7 실패, Esc → 1, Enter → 1, 확인 단추 → 1, bridge → 4, presenter 막음 거절 삭제 → 3.
   - 부분 제출 길은 덮지 못함(P2-1).
6. **ACCEPT** — 핀 전파뿐.
   - 인벤토리 sha(e7a5bffc…→2bd4a2b4…) 다섯 곳 전파, `_prepare_gui_startup` 줄 23984→23992(+8 = Container_Audit.py 순증 줄 수), 전환 JSON "after" 다섯 개.
   - sha256 계산이 모두 "after" 와 일치. `tools/derive_container_writer_sinks.py --check` → 2bd4a2b4…, `tools/refresh_container_update_declarations.py --check` exit 0, 옛 핀 잔존 0.
   - ca_screen_bridge.py 는 바탕부터 전환 files 목록에 없음 — 이 커밋 밖.

## 실행

- 환경: Linux · Python 3.12 + python3-tk · pytest 9.0.2(scratchpad venv). 저장소 tests/conftest.py 는 Windows 전용(ctypes.WinDLL·LOCALAPPDATA writer fence)이라 `--noconftest -p linux_shim` 으로 돌림. linux_shim 은 scratchpad 플러그인으로, writer_admission 을 빈 문맥으로 바꾸고 LOCALAPPDATA 를 tmp_path 로 둠. 저장소 파일 고침 0.
- 머리: tests/test_transfer_post_review_band.py 16 통과. tests/test_warning_presenter_headless_integration.py + tests/test_notice_scan_refusal.py 49 통과.
- 범위 밖: tests/test_ca_screen_bridge.py 는 실제 Tk UI 고리가 필요해 이 환경에서 바탕·머리 모두 같은 「timed out during UI application」 으로 실패. 판정 근거로 쓰지 않음.
