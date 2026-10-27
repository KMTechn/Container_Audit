REJECT · P1 0 · P2 2 · P3 3
검토 모델: Claude (Claude Code) — 세부 모델 이름은 세션 규칙상 저장소에 적지 않고 대화 답에 둠

범위 477c1557..f9fadebb(커밋 1) · 읽기만 · 시험·빌드·앱 실행 0

## P2
1. 인벤토리 지문 바인딩 넷 중 둘만 갱신 — `writer_session_fence.py:107` 핀과 `tools/container_data_generation_transition.json:6` `after_inventory_sha256` 이 옛 95c795…, 같은 파일 `files[]` 의 Container_Audit.py·fence.ps1·contract·inventory after 지문도 옛 값(07dca0a 는 넷을 함께 고침). 입력: 이 트리 그대로 → `tests/test_writer_session_fence.py:281` 깨짐(읽어서 판단), `INSTALL_CANONICAL_PORTABLE.ps1:942`·`:809` 정방향 전이 거절로 후보 설치 불가, 배포 세션 중 PS 담장(3000caf…)을 Python 이 `writer_session_fence.py:355` FENCE_BINDING_INVALID 로 거절. 고침: `tools/refresh_container_update_declarations.py` 로 넷을 한 번에.
2. 품목 안내 뒤 0 끝에서 시작 확인 결과가 READY 로 남음 — `Container_Audit.py:24310` 이 생성 전 READY 를 쓰고 `:24331` 은 까닭 없이 0, main finally 의 finish() 는 revision 이 같아 다시 쓰지 않음(예전엔 `_startup_refusal(None, failed=True)` 가 UNKNOWN_CHECK 로 고침). 입력: Item.csv 없음 + 사람 닫기 → `start-check\YYYYMMDD-CA.json` startable:true + 종료 0, 설치 키트 알림 신호 0. `docs/spec/startup-check.md:49`「생성 중 기존 거부가 발생하면 같은 파일을 고친다」 어김. 고침: return 0 앞에서 note(UNKNOWN_CHECK 또는 전용 코드) + publish() — refused 없이(둘째 안내 없음). 새 시험은 observe 를 가짜로 바꿔 이것을 못 봄.

## P3
1. `Container_Audit.py:1539/1550/1557` 표지가 안내를 실제로 보였는지와 무관 — Tk 안내와 native 가 둘 다 실패하면(드묾) 안내 없이 조용히 0(예전엔 일반 오류 길의 대체 안내 기회가 있었음).
2. `tests/test_startup_item_notice_exit.py:153` 단언에 안 쓰는 `notice-facts.json` 기록 — 디버그 잔재.
3. `docs/spec/operations.md` 「공지·휴식·품목 안내가 함께여도 … 보존」 — 입력 칸 오류 띠까지 넷이면 `ca_screen_bridge.py:217` `alerts[:4]` 가 최근 처리 알림·「확인」 을 여전히 자름(diff 전부터, 알림은 스캔을 막지 않음). 문장에 조건을 적을 것.

## 확인함(문제 없음)
- 정리: 생성자 예외가 writer_admission 블록을 빠져나가 풀림 → `:24331` 0 → finally 에서 app None 이라 instance_lease.release() 한 번, main finally 의 finish·end_gui_entry. 웹은 owner 미시작 → CaStartupRefused(0) → `ca_screen_bridge.py:1420` 0, 옛 Tk 대체 0. 공식 멈춤은 안내 안 poll 또는 닫은 뒤 확인에서 한 번만 consume·기록, 뒤에 재소비 없음.
- 덮기: 표지는 load_items 세 장면(show_errors=True)에서만 서고, 런타임 새로고침(`:1624`)은 show_errors=False. ItemCatalogSyncError·DataGenerationBlocked·WriterFenceError 등은 예전 반환·코드 그대로. 생성자 호출처는 `:24312` 하나.
- 자료: 표지 → `:1305` raise 로 ItemCatalog·업무 화면 전에 멈춤.
- 알림: 무결성 띠는 맨 뒤라 다른 띠를 밀지 않고 자리 나면 다시 보임, 상한 송신 1 + 4 = 5 유지. 옛 Tk 는 `:18847` 그대로(중복 없음). 기존 알림 순서 시험과 맞음.
- 시험: 실제 main → screen_runner/Tk → 시작 준비 → 생성자 → load_items 를 지남(open 만 가짜) 12 경우. 기존 시험 수정 0.
- 인벤토리: Container_Audit.py 19 자리의 줄 이동이 원문과 모두 일치, inventory_sha256 재계산 일치, 새 쓰기 자리 0.
- 참고(diff 밖·예전과 같음): `:1229` relay 자동 준비 스레드는 load_items 전에 시작돼 app None 정리 밖.
