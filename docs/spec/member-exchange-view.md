# 개별 제품 교체 화면 경계 (CA-1)

`62e9883`의 구현을 기준으로 기록한 분리 경계다. 현행 정책은
[CA-10](README.md#ca-10), [CA-C04](contracts.md#ca-c04),
[교체 정책](../MEMBER_EXCHANGE_POLICY.md)을 따른다.

## 화면과 명령 소유

| 구간 (`Container_Audit.py` 기준 행) | 책임 | 분리 계획 |
| --- | --- | --- |
| `_show_exchange_dialog_after_coordinator_admission` 14880–15082 | owner의 차단 판정 호출, 기존 창 재사용, 위젯/수량/세션 구성, grab/focus | `member_exchange_view.show_exchange_dialog(self)` |
| `_update_exchange_display` 15180–15207 | 두 목록/행/열 폭, 마지막 행 노출, viewport idle 예약 | `member_exchange_view.update_exchange_display(self)` |
| `_update_exchange_status` 15209–15232 | 기존 session 기반 문구 | `member_exchange_view.update_exchange_status(self)` |
| `_finish_central_exchange_pending` 15857–15877 | 재시도 버튼과 pending/review 안내 | `member_exchange_view.finish_central_exchange_pending(self, attempt)` |
| `_finish_central_exchange_failure` 15879–15897 | 버튼과 준비/로컬 적용 실패 안내 | `member_exchange_view.finish_central_exchange_failure(self, attempt)` |
| `_finish_central_exchange_success` 15899–15920 | 이미 적용된 결과 안내, 창/화면 session 초기화 | `member_exchange_view.finish_central_exchange_success(self)` |
| `calculate_exchange_dialog_size` 293–306와 상수 288–290 | 기존 기본 크기/화면 cap 산술 | 같은 view 모듈; 기존 import 재노출 |
| `show_exchange_dialog`, `_schedule_exchange_dialog_admission` | preflight/review/owner/lane admission | 원 owner 유지 |
| `_start_exchange`, `_exchange_target_quantity`, `_on_exchange_scan`, `_process_exchange_scan` | 1–2쌍 입력 검증/스캔 처리 | 원 owner 유지 |
| `_complete_exchange`, `_cancel_exchange`, `_finish_exchange_cancel_ui` | coordinator prepare/attempt, lease, 내구 취소 기록 | 원 owner 유지 |
| ACK 적용/복구/lease rotation | 저장과 중앙 결과 적용 | 기존 coordinator/owner 유지 |

명시 owner를 받는 구체적인 모듈 함수로 이동한다. 기존 owner 메서드는 같은 이름과
signature의 얇은 위임으로 남겨 callback/monkeypatch를 보존한다. layout, font/token,
`_large_text_pane`, tree/wrap helper와 `ProductExchangeSession` 정본을 재사용한다.
새 presenter/controller, worker, Tk 인스턴스 또는 writer를 만들지 않는다.

## 상태와 호출 순서

| 함수 | 읽는 owner 상태/호출 | 쓰는 owner 상태 |
| --- | --- | --- |
| `_show_exchange_dialog_after_coordinator_admission` | `DEFAULT_FONT`, `_apply_tree_row_styles`, `_bind_label_to_container_width`, `_block_unsafe_exact_exchange`, `_cancel_exchange`, `_complete_exchange`, `_exact_transfer_exchange_blocked`, `_invalidate_pending_scan_callbacks`, `_large_text_pane`, `_on_exchange_scan`, `_transfer_member_exchange_blocks_local_action`, `_tree_column_required_width`, `_update_action_button_states`, `current_exchange_session`, `current_tray`, `exchange_cancel_button`, `exchange_complete_button`, `exchange_defective_tree`, `exchange_good_tree`, `exchange_quantity_var`, `exchange_scan_entry`, `exchange_status_label`, `root`, `style` | `_active_transfer_exchange_intent_id`, `_active_transfer_exchange_master_label`, `_active_transfer_exchange_mode`, `current_exchange_session`, `exchange_body`, `exchange_cancel_button`, `exchange_complete_button`, `exchange_defective_tree`, `exchange_dialog`, `exchange_good_tree`, `exchange_quantity_spin`, `exchange_quantity_var`, `exchange_scan_entry`, `exchange_status_label` |
| `_update_exchange_display` | `_insert_tree_row`, `_tree_column_required_width`, `current_exchange_session`, `exchange_defective_tree`, `exchange_good_tree`, `root` | 없음 |
| `_update_exchange_status` | `current_exchange_session`, `exchange_status_label` | 없음 |
| `_finish_central_exchange_pending` | `exchange_complete_button` | 없음 |
| `_finish_central_exchange_failure` | `exchange_complete_button` | 없음 |
| `_finish_central_exchange_success` | `_update_action_button_states`, `current_exchange_session` | `_active_transfer_exchange_intent_id`, `_active_transfer_exchange_master_label`, `_active_transfer_exchange_mode`, `current_exchange_session`, `exchange_dialog`, `exchange_quantity_spin` |

`getattr/hasattr` 읽기는 `exchange_dialog`, `exchange_body`, `exchange_complete_button`도
포함한다. 생성은 session 품목 필드를, 성공 안내는 `session.current_step`을 갱신한다.
표 렌더링은 tree 행/폭을, 상태/결과 안내는 label/button 옵션을 갱신한다.

1. 원 owner admission 완료 후 Tk owner callback에서 local-action/exact-mode guard를 호출한다.
2. scan callback 무효화 뒤 기존 창이면 `winfo_exists → lift → focus_force → action-state`로 종료한다.
3. 신규 창은 `Toplevel → title → geometry → transient → grab_set` 뒤 body/수량/목록/입력/footer를 구성한다.
4. 기존 session을 초기화하고 callback/닫기 protocol을 연결한 뒤 `update_idletasks → viewport 높이 → update_idletasks → 화면 cap geometry → minsize → scan Entry.focus` 순서를 유지한다.
5. 표시 갱신은 두 tree를 다시 채우고 `see`한 뒤 원 root의 `after_idle`로 viewport 노출을 예약한다.
6. 성공은 원 coordinator ACK와 로컬 적용 후 `completed → showinfo → destroy → session/화면 참조 초기화 → action-state`다. 내구 취소 기록은 화면 모듈로 옮기지 않는다.

capability 검사는 기존 client factory와 member-exchange coordinator에 남는다.
화면의 최대 수량 `min(2, scanned count)`와 원 `_exchange_target_quantity`의 1–2 범위,
scan membership 거부, operation lease 필요 조건, prepare/attempt/rotation 순서는 유지한다.
F8/Shift-F8와 운영 메뉴의 기존 admission 진입을 바꾸지 않는다.

## 소비자와 검증 경계

| 소비자 | 영향/보존 방법 |
| --- | --- |
| 기존 테스트의 owner 메서드 monkeypatch | 메서드 이름/호출 지점 유지 |
| `Container_Audit.tk`, `ttk`, `messagebox` monkeypatch | 같은 tkinter 모듈 객체를 import |
| `calculate_exchange_dialog_size` import | 원 모듈에서 같은 함수 재노출; 해당 상수/함수 monkeypatch 소비 없음 |
| `tests/test_operator_widget_transitions.py` | 기존 생성/표시 메서드 유지; 실제 GUI 실행은 별도 배정 |
| `tools/capture_container_operator_ui.py` M7 | 새 view의 문구/생산 파일을 frozen-source 목록에 포함 |
| portable `APP_ROOT_FILES`, PyInstaller `.spec` | 새 root 파일 포함; 정적 import 연결 유지 |
| writer inventory와 Python/PowerShell/session pin | 기존 생성기로 위치/closure 재생성·check; writer 계약 유지 |

검증은 이동 함수 AST, fake-Tk 순서/명령/거부 벡터, 기존 member-exchange/lease/contracts와
CA focused 17선택을 사용한다. 실제 GUI·스캐너·설치·production 및 과거 확대 교환 표의
native 실패는 [CA-G13](BACKLOG.md#ca-g13)의 별도 범위다.
