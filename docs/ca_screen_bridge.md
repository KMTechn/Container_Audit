# 이적 새 화면 이음 — 노트 (w9uiflow1014, APP-SCREENS-1013 ③)

- 바탕: `firstupd-ca-cut-1013` **4fb02da**(v2.0.103 — w9firstupd 10/12 23:58). 가지 `ca-newui-bridge-1013`(E: worktree, push 0). 기준일 조립(10/23–25)에 ACCEPT 고침 머리로 한 번 다시 얹음(주인 레인).
- 화면 원천: 웹 저장소 `static/ui/app/ca/`(가지 web-newui-1014-flow) → `scripts/export_ui_parts.py --app ca` 로 `ui/`(MANIFEST.json · `--check` ok). 꼴 = `ui/app/ca/contract.json`(km-app-contract/1).
- 셸: `shell/` = 셸 v3.8 고정판 19 파일(`shell/SHELL-READY-v3.8.json` SHA256 대조 — 고치지 않음, 고칠 것은 w9appshell1012 에 한 줄).

## 1. 처리 층 파일 바꿈 0
`Container_Audit.py` 와 처리 모듈은 손대지 않았다. 새 파일: `ca_screen_bridge.py`(다리) · `ca_screen_main.py`(새 진입) · `tests/test_ca_screen_bridge.py` · `shell/` · `ui/` · 이 노트.
지금 Tk 화면 진입(`Container_Audit.py main()`)은 그대로 돈다.

## 2. 불변식 1 의 손질 자리 — 파일 대신 다리가 이 인스턴스 · 모듈 이름 자리에서 바꿈
| 자리 | 전(지금) | 후(새 화면) | 시험 |
|---|---|---|---|
| 스캔 입력(입력 칸 위젯 읽기) | `process_barcode()` 가 `scan_entry.get()` | 다리가 같은 `scan_entry` 에 넣고 `process_barcode()` — 지금 시험 `public_scan` 과 같은 문이라 빈 Enter · 띠 선택 중 · 경고 중 · 현품표 확인 중 판정이 그대로. 빈 Enter(막는 알림 확인)는 `command('ack')` = 같은 문에 빈 글 | `test_scan_goes_through_the_existing_door…` · `test_ack_is_the_empty_enter_door…` |
| Tk 모달 PIN | `_prompt_blocked_work_admin_pin` = Toplevel + wait_window | 인스턴스 메서드를 `admin(이름, {admin_id, pin})` 인수로 대신 — 그 동작에 한 번만, state · 답 · 기록에 값 0 | `test_admin_pin_replaces_the_modal_once…` · `test_shell_bridge…`(events.jsonl 에 admin 인수 없음) |
| messagebox · simpledialog · filedialog | 창 | 모듈 이름 자리 = `ScreenDialogs`: show* → 띠(관리자 일 중엔 PIN 판 결과), ask* → `state.sheet`(예/아니오 단추 = `command:choose:ask_yes/no`) + Tk 변수 기다림(지금 대화상자와 같은 중첩 기다림, 그동안 스캔은 미접수), askstring(원 현품표 확인) → 스캔으로 답, 파일 고르기 → 새 화면에 없음(그만두기 + 띠) | `test_question_becomes_a_sheet…` |
| Tk 뿌리 창 | `ContainerAudit()` 가 root 를 띄우고 최대화 | `owner_main` 이 `_HiddenTk`(띄우기 · 앞으로 가져오기 막음)로 지금 시작 점검 `_prepare_gui_startup()` 을 그대로 거침 | 창 시험은 시험 PC(호스트 창 0) |
| 단추 · 운영 메뉴 | Tk 단추 · `_show_operations_menu` 팝업 | 숨긴 Tk 단추 `invoke()`(허용 규칙 · 제출 ↔ 다시 하기 바뀜 그대로), 단추 아닌 것(교환 · 리셋 · 품목 새로 고침 · 관리자 ▾)은 운영 메뉴를 **띄우지 않는 기록 메뉴**로 한 번 돌려 그 항목의 켜짐 · 명령 — 조건을 베끼지 않음 | `test_state_is_the_contract_shape…` · `test_reset_only_from_the_confirm_sheet` |
| 띠 선택 | `_request_inline_choice` 안 Tk 단추 → 지역 `choose` | `command('choose', {id})` → 같은 차례(선택 지움 · 줄 없앰 · 확인 · 콜백 · 초점) | `test_band_choice_runs_the_same_callback…` |
| 소리 | `play_sound`(native_audio) | 그대로 처리 층이 냄 + 마지막 소리 이름만 기록(화면 「소리: …」). 셸에는 `sound=None` 이라 겹쳐 내지 않음 | `test_shell_bridge…`(셸 소리 0) |
| 리셋 | 확인 없음(CA:15860) | 화면 확인 판(마우스로만) 뒤 `command('reset', {id:'confirmed'})` 만, 아니면 거절 | `test_reset_only_from_the_confirm_sheet` |
| F8 판 값 | 교체 패널의 플래그 · `phs_active_label_info_label` · 선택 후보 글 | `_phs_label_exchange_panel_open` 이면 `f8_values` 로 단계 · 다음 할 일 · 기존 판 글을 싣고 바뀜도 알림. 없는 계획 수량 · 받은 시각은 생략 | `test_f8_pane_uses_the_existing_panel_state…` · `test_f8_candidate_text_and_changes…` · `test_f8_reprint_confirms…` |
| 관리자 판 사실 줄 | 보관 제품 · 현재 트레이만, 나머지는 동작 뒤 안내 | `preserve_check` 는 현재 작업 원본 · 보존 사본 이름, `resend_completion` 은 기존 명령이 고르는 첫 `command_bound` 건의 품목 · 수량. 사본 존재 · 보존 성공은 단언하지 않음 | `test_preserve_check_facts…` · `test_resend_completion_facts…` |

## 3. 바뀜 알림 · 수량
- 주인 스레드 0.25초마다 가벼운 지문(트레이 · 알림 · 선택 · 연결 · 보류 수 · 단추 상태)을 견주어 바뀌면 `bridge.push_state(reason='changed')`. 운영 메뉴 · 파일 읽기는 지문에 넣지 않고 `state()` 때만.
- 화면이 보이는 수는 모두 처리 층 값(`work.count · target · remaining · left_kind · list_count`) — 화면은 셈하지 않는다(불변식 6).

## 4. 열린 것(다음 차례)
- 진행 현황(`progress`)은 지금 Tk 패널 원천 `_progress_data`(남은 수량 · 상자 = 회사 서버 값), 오늘 현황(`today`)은 「금일 작업 현황」 원천 `work_summary` · `total_tray_count` 그대로 — 품목별 제품 수는 처리 층에 없어 싣지 않음(화면 「—」).
- F8 판 값(`f8`)의 단계 · 기존 판 안내는 연결됨. 처리 층에 계약의 완전한 계획(전/후 수량 · 새 현품표 장수 · 지시 받은 시각)이 없어 `target` · `plan` · `print_error` 는 생략, 카드는 `how`. 상세 지시/인쇄 카드와 재인쇄 단추의 화면 확인은 남음. `f8_reprint` 명령은 기존 확인 변수와 실행 단추를 그대로 씀.
- 작업자 고르기: 명단 이름만(받은 시각 · 지난번 표시는 다음), 새 이름 등록은 `_register_worker_name` 바로(같은 이름 후보 판은 다음).
- 관리자 판 사실 줄(facts): `quarantine_hold` · `defer_unsettled` · `preserve_check` · `resend_completion` 은 연결됨. `pair_hold` 는 저장된 짝 원본을 다시 읽어 대상을 정하고, `recheck_review` 는 저장된 PIN 요청 목록, `list_paired` 는 인증 뒤 보류 원본 목록을 새로 읽으므로 동작 전 사실 줄은 `[]` 그대로. 동작이 직접 보여 주는 대상 · 결과는 유지.
- 같이 채우기: 서버 계약(목 10/15 초안 · 수 10/14 고정 코드) 뒤 — 그 전엔 `work.cofill = null`.
- 시작 판 고침 문(`_run_application_main` 의 startup_gate · GUI ready 알림)과 새 진입을 어느 쪽으로 둘지: 주인 레인.
- 「끝낸 트레이 회사 서버에 다시 보내기」: 지금 코드는 PIN 이 아니라 관리자 로그인을 봄 — 새 화면 PIN 판으로 대신할지 w9firstupd 답 기다림.
- 창 실물(pywebview · WebView2): 시험 PC 에서(셸 레인 키트 · 호스트 창 0).
