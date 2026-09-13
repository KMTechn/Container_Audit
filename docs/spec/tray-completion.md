# 트레이 완료 orchestration 경계

기준 `ce7e512:Container_Audit.py`에서 코드 이동 전에 기록했다. 신규
`tray_completion.py`는 트레이 완료 한 책임의 기존 generator와 foreground 제출을
명시 owner 인자로 받는다. 새 coordinator·worker·저장소를 만들지 않는다.

| 순서 / 기존 위치 | 소유·저장 결과 적용 | 표시·notice 및 다음 단계 |
| --- | --- | --- |
| scanner / held: `_process_barcode_logic`, `_drain_preflight_hold_head` | current JSON ACK 뒤 스캔 목록·수량 반영; held 동기 CSV 감사 ACK 뒤 FIFO head 제거 | 최종 held ACK·lane idle 후에만 완료 요청; 입력 epoch와 순서는 기존 owner |
| `request_complete_tray` :10240–10456 | preflight/review/교체/PHS2 전량 guard; 원 시각·worker·projection path·목록·lease snapshot | busy 표시 후 기존 `LaneTask` 접수, stale/idle·callback 유지 |
| `_prepare_and_attempt_transfer_seal_snapshot` :12981 | preview → prepare → `on_prepared` → checkpoint 확인 → `drain_pending_through`/attempt | stored attempt를 그대로 완료 단계에 넘김; 중앙 retry·FIFO owner는 기존 coordinator |
| `_prepared_completion_contract_steps` :10179–10238 | intent 일치 확인 → pending contract → yield current JSON 저장 | 실패는 저장을 포함한 `_completion_outcome_steps` 후 기존 오류; 안내 전 내구 경계 유지 |
| `complete_tray` :10458–10461 / `_complete_tray_steps` :10463–10917 | 동기 복구도 같은 runner/generator; `_prepared_transfer_attempt`가 있으면 새 prepare 없이 그 객체 사용 | lane은 `_lane_prechecked=True`로 중복 admission만 생략; 원 guard 유지 |
| `_complete_tray_steps` 전반 | intent mismatch·unlinked review·미확정/증거 회귀 분기; 동일 event 시각/key/worker/detail 보존 | 각 outcome의 원 저장→안내 순서; 미확정이면 트레이/스캔 잠금 유지 |
| completion event | yield 재시도 contract JSON → yield 동기 `TRAY_COMPLETE` → 필요 시 post-review outbox projection | local CSV ACK 실패 시 `LOCAL_EVENT_RETRY`; 성공 표시·카운트 적용 전 반환 |
| completion summary | replay/다른 worker면 CSV에서 집계 재구성; 아니면 완료·test 개수/최고 기록 적용 | stopwatch/idle/undo 및 test 상태 안내는 기존 위치 유지 |
| 최종 state 적용 | pending contract 해제 → 새 `TraySession` → 필요 시 epoch 무효화 → yield current state 삭제 → 실패 감사 | 별도 `apply_completed_tray_state_steps`; notice를 먼저 실행하지 않음 |
| 최종 notice | listbox 정리·summary/UI reset → snapshot publish/삭제 실패 안내 → post-review 안내 | 별도 `present_completed_tray`; 마지막 완료 시각·True는 orchestration에서 유지 |

위 순서는 모든 중앙 ACK가 CSV 뒤에 온다는 뜻이 아니다. foreground transport는 prepared
checkpoint 뒤, 완료 CSV/표시 전에 실행된다. `LINKED`가 있으면 중앙 지연과 로컬 완료를
구분하며 재시도는 원 command/key를 쓴다. held 감사 ACK는 완료 접수보다 먼저다.

## 이동·위임과 소비자

`request_complete_tray`, `_prepared_completion_contract_steps`, `_complete_tray_steps`의
본문 732행을 이동한다. 원 메서드 signature·generator 성격을 유지하는 얇은 위임을 남기고
`complete_tray`의 signature·본문·`_prepared_transfer_attempt` keyword는 그대로 둔다.
새 모듈의 session factory는 owner의 `TraySession`을 명시 전달해 역방향 import를 피한다.
`clock`도 owner의 `datetime` namespace를 명시 전달하므로 lease fixture의 전체 namespace 교체를 유지한다.

동기 완료 소비자는 자동 스캔/legacy 부분 제출/관리자 재시도/복구·합성 시험이고,
foreground 요청 소비자는 live scanner/held 완료/제출/관리자 재시도다.
`_prepare_and_attempt_transfer_seal_snapshot`, `_run_durable_ui_steps`, scanner/preflight,
재시작 restore, outcome 저장/표시, coordinator와 transfer façade는 원 위치에 남는다.

기존 monkeypatch는 owner의 `_prepare_and_attempt_transfer_seal[_snapshot]`, `_log_event`,
`_save_tray_state_snapshot`, `_delete_current_tray_state`, `_complete_tray_steps`,
`request_complete_tray`, `append_event_log_entry[_idempotent]`, `atomic_write_json`와
공유 `datetime.datetime`/Tk 객체와 lease fixture의 전체 `Container_Audit.datetime` 교체를 소비한다. 이동 함수는 owner 메서드를 계속 호출한다.
`TraySession`도 owner가 전달하며 기존 test·runner·conftest를 바꾸지 않는다.

writer sink는 기존 `_save_tray_state_snapshot` (`gui_tray_state_save`),
`_delete_current_tray_state` (`gui_tray_state_delete`), event store/최고 기록 저장과
`TransferSealStore`의 기존 decorator/transaction에 남는다. 신규 helper는 저장 callable을
yield하며 직접 새 I/O를 만들지 않는다. 파생 inventory는 위치/import closure만 갱신하고
Python/PowerShell/session pin을 맞춘다. 설치기·kmtech_shared pin은 불변이다.

APP_ROOT_FILES와 M7 text/binding 목록에 새 모듈을 포함한다. 기존 `.spec`의
`Container_Audit.py` 정적 import 경로로 도달한다. 소비자를 삭제하지 않는 이동이며
owner 줄 감소를 제품 LOC 절감으로 계산하지 않는다.

## 검증 범위

A는 기존 함수 AST·signature/default·예외 문자열과 나머지 owner 메서드를 대조한다.
분리한 두 연속 블록은 다시 인라인해 원본과 비교하고 session factory 치환을 명시한다.
V는 fake Tk/실제 local store로 정상·local ACK 유실·held FIFO·중앙 retry·재시작의
step/store/ACK/notice 순서와 prepared 객체 재사용을 비교한다. 기존 focused 868개에는
scan persistence·observed scanner·atomicity와 CA-0/1의 회귀가 포함된다.
검증 결과는 [CA-2 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6ca2/RESULT.md)에 남긴다.
실제 GUI/스캐너·설치·VM·서버·production 수용과 별개다. CA-0 검토의
`test_phs2_master_preflight.py:659` 15초 stale-result timeout 관찰은 보존한다.