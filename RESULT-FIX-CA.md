# RESULT-FIX-CA — 이적 D-01 끝 손질 (3차 P3 셋)

기준 HEAD b49ae31 → 커밋 하나(push 0).

- **P3-A** `_hold_or_refuse_entry_scan` 의 `_scan_callback_pending` 갈래: `_notice_scan_injected` 일 때만 `_clear_consumed_scan_entry` 로 칸을 비운다. 평상시 갈래(입력값 유지)는 손 0. 시험: `test_pending_branch_clears_injected_characters_but_keeps_plain_input`.
- **P3-B** 주입 중 configure/delete/insert 실패 → `_mark_scan_unaccepted("스캔을 받지 못했습니다. 다시 스캔하세요")` + 오류 소리, return(빈 Enter 로 흘러 띠를 닫지 않음). 시험: `test_insert_failure_while_injecting_is_unaccepted_not_a_blank_enter` (띠 그대로).
- **P3-C** 코드 확인: 나온다. 모은 글자 길은 `_notice_blocks_scan()` 거짓일 때만 주입되고, 그 사이 띠가 풀리면 `_refuse_entry_scan` 의 `is_blocking` 이 거짓이 되어 띠 글 없이 상태줄만 쓰였다. → 그 경우 `_mark_scan_unaccepted` 로 표지(다리 accepted:False). 시험: `test_invisible_refusal_on_the_collected_path_is_marked_unaccepted`.
- **쓰기 경로 목록**: 마지막 커밋 뒤 `derive_container_writer_sinks.py --check` rc 0 (`--write` 로 재생성해 같은 커밋에 포함).

## 시험
- `tests/test_notice_scan_refusal.py` 30 통과.
- 닿는 41개 중 g09 둘(`test_direct_sync_push`·`test_phs2_master_preflight` 모듈 없음 — 수집 오류, 원래부터)을 뺀 파일을 돌림. 실패는 b49ae31 기준 그대로와 같은 것만(auto_update 1, close_delay_notice 4, observed_scanner_completion 1, field_action_confirmations 1, checkpoint_audit_outbox 1, legacy_label_transition 7, paired_preflight_handoff 1). 커밋 전 보였던 capture_container_operator_ui 5·container_audit_contracts 6 은 커밋 뒤 0(커밋 묶음 검사).
- 알림: `run_capped` 를 이 환경에서 못 찾아 일반 pytest 로 파일 단위 실행(1 GB 상한 미적용).
- 줄 끝 그대로, 비밀·값 출력 0.
