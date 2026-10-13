# 이적 새 화면 이음 — 노트 (w9uiflow1014, APP-SCREENS-1013 ③)

- 바탕: `firstupd-ca-cut-1013` **4fb02da**(v2.0.103 — w9firstupd 10/12 23:58). 가지 `ca-newui-bridge-1013`(E: worktree, push 0). 기준일 조립(10/23–25)에 ACCEPT 고침 머리로 한 번 다시 얹음(주인 레인).
- 화면 원천: 웹 저장소 `static/ui/app/ca/`(가지 web-newui-1014-flow) → `scripts/export_ui_parts.py --app ca` 로 `ui/`. 꼴 = `ui/app/ca/contract.json`(km-app-contract/1). 셸 v3.14의 `events_dropped`(0 이상 정수)를 이음 계약에 추가했으며 MANIFEST의 원천 커밋은 유지하고 `dirty=true`·파일 해시·부품 지문을 갱신했다. 원천 3962eda5의 exporter `--check`로 자료를 확인한다.
- 셸: `shell/` = 셸 v3.14 고정판(`shell/SHELL-READY-v3.14.json`의 19개 파일 SHA256·크기와 같음). kit 전용 `tk_ab.py`는 앱 사본에서 제외한다. 사본 바이트를 유지하도록 `shell/** -text`를 적용한다.

## 1. 기존 시작 진입에 새 화면 플래그
진입은 `Container_Audit.py --new-screen` 한 길이다. `main()`의 시작 확인 기록 → `startup_gate` → `dispatch_product_mode`를 거친 뒤 셸을 부르고, 기존 GUI 시작 부분을 옮긴 `_run_gui_application(arguments)`이 주인 스레드에서 앱을 만든다. 플래그가 없으면 같은 함수에서 기존 `app.run()`을 부른다. 처리 모듈과 시작 관문의 판단은 그대로다.
이음 파일: `ca_screen_bridge.py`(다리) · `tests/test_ca_screen_bridge.py` · `tests/test_ca_new_screen_entry.py` · `shell/` · `ui/` · 이 노트. 별도 진입 `ca_screen_main.py`는 제거했다. 시작 확인의 ContextVar 문맥도 `copy_context()`로 주인 스레드에 넘겨 관문에서 확인한 판·build 신원을 유지한다.
`screen_runner`가 `run_app(write_guard=admission_write_guard)`로 셸 담장을 설치한다. `shell_fileio`의 다섯 함수는 지역 쓰기 하나 동안만 기존 `writer_admission("screen_shell_fileio")`을 얻고 내려놓는다. 허락을 화면·스캔·네트워크 대기 동안 유지하지 않는다. 진단 기록·처리 층 모드의 셸 접수 캐시 쓰기가 거절되면 그 기록만 잃고 화면과 다음 스캔은 계속한다(진단 누락 수 `events_dropped`). 시작에 필요한 journal/UDF 폴더 생성 거절은 셸 v3.14처럼 창 생성 전 실패한다.
쓰기 선언은 셸의 여덟 Python 파일·READY 해시와 실제 이적 담장 설치를 확인한 뒤에만 `shell/shell_fileio.py`의 쓰기를 보호된 것으로 인정한다. 사본·파일 목록·설치 호출·허락 함수가 달라지면 정적 검사를 거절한다. `shell/host.py`의 단독 kit 실행은 제품 바로 가기나 설치 진입이 아니다. 현재 stock 빌더의 새 화면 kit·UI 조립은 별도 수용 범위다.
업데이트 관문에 전달하는 인수에서 플래그를 빼지 않는다. 앱을 만들지 못하면 `fail_owner(CaStartupRefused(code))`로 셸 기다림을 끝내고 기존 종료 값을 돌려준다. 셸 창은 주인이 붙은 뒤 만들어지며 `owner_timeout`은 전달하지 않는다. 앱이 만들어지기 전 messagebox 안내와 시작 거절 함수는 원래 Tk·대화상자 이름으로 호출해 기존 안내를 숨기지 않는다. 주인이 끝나면 Tk·대화상자·거절 함수 이름과 새 화면 실행 상태를 되돌린다.

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
