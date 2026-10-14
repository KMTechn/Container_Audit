# 이적 새 화면 이음 — 노트 (w9uiflow1014, APP-SCREENS-1013 ③)

- 바탕: `firstupd-ca-cut-1013` **4fb02da**(v2.0.103 — w9firstupd 10/12 23:58). 가지 `ca-newui-bridge-1013`(E: worktree, push 0). 기준일 조립(10/23–25)에 ACCEPT 고침 머리로 한 번 다시 얹음(주인 레인).
- 화면 원천: 웹 4차 바탕 최종 committed `97efc8e733ba8d73c3d4c8d8a486cad5c3d8d531`의 `static/ui/` → `ui/`(공용 10·이적 62, 총 72파일). 모두 원천 바이트와 같으며 로컬 P2 두 파일은 이 판으로 대체했다. MANIFEST의 원천 SHA·`dirty=false`·파일 해시·부품 지문을 함께 갱신한다. PIN 판 스캔 막이와 보류 전체 수·넘침 안내도 이 사본을 그대로 사용한다.
- 셸: `shell/` = 승인된 검사 `2371be9d`의 셸 v3.16.2 고정판(`shell/SHELL-READY-v3.16.json`의 19개 파일 SHA256·크기와 같음). READY 이름은 유지하고 v3.16.2 승인 바이트를 그대로 싣는다. kit 전용 `tk_ab.py`는 앱 사본에서 제외한다. 사본 바이트를 유지하도록 `shell/** -text`를 적용한다.

## 1. 시작과 셸 끝내기 어댑터 (M84)
기본·`--new-screen`·`--ui web`·모르는 `--ui` 값은 web, `--old-screen`·`--ui tk`는 그 실행만 Tk다. 비상 Tk의 셸 import는 0이다. 다른 셸 import는 try 안에서 처리하며 실패하면 `SHELL_IMPORT_FAILED` 한 줄 뒤 Tk로 간다. 같은 판의 `web_allowed=False`도 Tk를 고른다. 진입에 별도 PID 대기나 자동 재실행은 없다.
웹 창 생성 뒤 실패는 셸이 쓰기 문 닫음·판 표지·destroy·before_exit·끝을 맡는다. 앱의 같은 프로세스 Tk 전환은 없다. 표지 저장 실패도 끝내며 되풀이하지 않는다. 다음에 사람이 켜면 같은 판의 표지로 Tk를 연다. 생성 전 안전한 Tk 길·시작 거절·업무 gate는 유지한다.
`before_exit`는 같은 잠금으로 writer admission과 새 lane 시작을 닫는다. 보통 허가는 writer 허가·mutex가 비고 UI/중앙 전송/보류 쓰기 worker가 실제 죽어야 완료다. 기존 receipt·위임 신원·살아 있는 authority 검증을 통과한 위임/유지보수 허가는 worker 실제 종료만 확인한다. BROKEN도 살아 있으면 미완료다. 이 callback에서 lane 닫기·Tk/owner/lease 정리는 하지 않는다. 120초 상한·5초 확인이며 False면 셸이 `SHELL_EXIT_DEFERRED`로 끝내기를 미룬다. worker 종료는 기존 owner 정리가 맡으며 mainloop 전 초기화 실패에도 실행한다. lane 생성 중 pump 초기화가 실패하면 그 생성자가 기존 close_idle로 멈춘다. 일반 닫기의 bridge.request_exit에는 force 인수가 없다.
셸의 OS 실패 안내에는 `title="이적"`을 넘긴다. 승인된 셸 코드와 앱 진입을 함께 실행하되 WebView·OS 안내·프로세스 끝 경계를 대체해 확인한다. `web_allowed`의 표지 제거에도 `admission_write_guard`를 명시한다. 각 셸의 private FileIO에는 같은 guard를 넘기며 새 probe·remove 쓰기도 허가 안에서 실행한다. 실제 OS 창과 WebView2는 이 시험 범위 밖이다. portable 선행 request_bootstrap admission의 WRITER_GATE_ABANDONED도 「이적 다시 열기 — 한 번 더 여세요」로 안내하며 기존 지원 기록·종료 1을 유지한다. application.main 안에서 처리한 안내는 중복하지 않는다.
보류는 전체 건수와 `overflow`를 유지하고 표시 줄만 50개로 제한한다. 격리·서버 확인 대기에 자리를 먼저 주며, 그 종류만 50개를 넘으면 두 종류가 각각 보이도록 한다. 넘친 목록은 옛 화면에서 확인한다.

## 2. 불변식 1 의 손질 자리 — 파일 대신 다리가 이 인스턴스 · 모듈 이름 자리에서 바꿈
| 자리 | 전(지금) | 후(새 화면) | 시험 |
|---|---|---|---|
| 시작 진입 | `Container_Audit.py`의 기존 시작 확인·업데이트·제품 모드·GUI 준비 | `Container_Audit.py --new-screen`이 같은 관문을 같은 순서로 거친 뒤 셸 주인에게 기존 GUI 시작을 넘김. 관문 종료 값은 그대로, 거절 때 셸 창 0 | `test_ca_new_screen_entry.py` |
| 스캔 입력(입력 칸 위젯 읽기) | `process_barcode()` 가 `scan_entry.get()` | 다리가 같은 `scan_entry` 에 넣고 `process_barcode()` — 지금 시험 `public_scan` 과 같은 문이라 빈 Enter · 띠 선택 중 · 경고 중 · 현품표 확인 중 판정이 그대로. 빈 Enter(막는 알림 확인)는 `command('ack')` = 같은 문에 빈 글 | `test_scan_goes_through_the_existing_door…` · `test_ack_is_the_empty_enter_door…` |
| Tk 모달 PIN | `_prompt_blocked_work_admin_pin` = Toplevel + wait_window | 인스턴스 메서드를 `admin(이름, {admin_id, pin})` 인수로 대신 — 그 동작에 한 번만, state · 답 · 기록에 값 0 | `test_admin_pin_replaces_the_modal_once…` · `test_shell_bridge…`(events.jsonl 에 admin 인수 없음) |
| messagebox · simpledialog · filedialog | 창 | 모듈 이름 자리 = `ScreenDialogs`: show* → 띠(관리자 일 중엔 PIN 판 결과), ask* → `state.sheet`(`modal=true`, `cancel=choose:ask_no`, 예/아니오 단추) + Tk 변수 기다림(그동안 스캔은 미접수). askstring(원 현품표 확인)은 스캔으로 답 · `choose:ask_cancel` 은 `None`. 파일 고르기는 새 화면에 없음(그만두기 + 띠) | `test_question_becomes_a_sheet…` · `test_question_becomes_a_modal_sheet…` · `test_scan_question_modal_cancel…` |
| Tk 뿌리 창 | `ContainerAudit()` 가 root 를 띄우고 최대화 | `owner_main_for`가 `_HiddenTk`(띄우기 · 앞으로 가져오기 막음)로 기존 `_run_gui_application(arguments)`을 부름. 준비·시험판 확인·실행 잠금 해제는 그 함수가 맡음 | `test_ca_new_screen_entry.py`, 창 시험은 시험 PC(호스트 창 0) |
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
- 새 화면 진입은 `Container_Audit.py --new-screen`으로 고정했다. 바로 가기·설치·업데이트 스크립트는 그대로이며 새 화면을 켜는 방법은 기준일 조립 때 주인 레인이 정한다.
- 「끝낸 트레이 회사 서버에 다시 보내기」: 로그인 조건 그대로 · PIN 판 아님 · PIN 으로 바꿈은 처리 층 고침이라 기준일 뒤(주인 레인 10/13 05:41). `_is_preflight_hold_supervisor()` 와 기록 메뉴가 켜진 때만 확인 판의 `command('resend_completion')` 으로 기존 `_retry_transfer_post_review` 를 부른다. `admin('resend_completion', …)` 은 거절한다.
- 창 실물(pywebview · WebView2): 시험 PC 에서(셸 레인 키트 · 호스트 창 0).
- 다시 내보낸 `ui/app/ca/contract.json` 의 sheet 에 `modal` · `cancel` 칸이 포함됨. 이음 시험은 현재 계약의 상태 꼴과 실제 값 · 취소 답을 함께 확인함. 틀의 물음 우선 표시 · PIN/기능 키/빈 Enter 차단 실물 확인은 주인 레인.
