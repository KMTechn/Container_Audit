REJECT · P1 0 · P2 1 · P3 3
검토 모델: 이 커밋의 Co-Authored-By 줄 참조 (저장소 파일에 모델 식별자를 적지 않는 규칙)

범위 (가) 694ba339..f95cf96b · (나) f9fadebb..fe323b93 · 읽기만 · 시험·빌드·설치기·앱 실행 0. 지문은 각 끝의 archive 사본에서 정식 derive·refresh 산출 함수로 맞댐(쓰기 0, 기준 477c155 일치).

## (가) — P2 1 · P3 3
### P2
1. 지문 넷 중 셋만 맞음 — `tools/container_data_generation_transition.json:6` after_inventory_sha256 이 옛 95c795…(지금 인벤토리 92a365…), 같은 파일 files[] 넷(writer_session_fence.py·fence.ps1·contract·inventory)과 source_replacements 둘의 after 도 옛 값. `writer_session_fence.py:107`·ps1·contract 는 맞음. 핀 값은 옳지만 정식 refresh 결과가 아님(돌렸다면 transition 도 바뀜, refresh --check 는 이 파일에서 stale). 입력: 이 트리 후보를 쓰기 의미가 다른 설치판 위에 정방향 설치 → `INSTALL_CANONICAL_PORTABLE.ps1:809`·`:942` 둘 다 거짓 → `:5476` CODE_PRESTATE_WRITER_SEMANTICS_DIFFER, 업데이트 불가. 제거 길은 이 검사를 건너 시험 20 통과에 가려짐. 고침: `tools/refresh_container_update_declarations.py --write` 뒤 --check.

### P3
1. `tests/test_container_writer_sink_inventory.py:1305` 새 시험은 `tests/test_writer_session_fence.py:279-284` 와 같은 세 단언의 중복, 이름(every consumer)과 달리 transition 의 after·files[] 를 안 봐 P2-1 을 못 잡음.
2. `writer_session_fence.py:105` 「derive 가 생성·확인」 은 틀림 — derive(`tools/derive_container_writer_sinks.py:3767`)는 ps1·contract 만, py 핀·transition 은 refresh 몫. 694ba339 퇴보를 낳은 함정 그대로.
3. `tests/test_first_setup_startup_proof.py:182` 거절(pid·module 포함)이 까닭 없이 ValueError 만 봄 — match 없어 다른 ValueError 로도 통과.

### 확인함
- 4d2ea67 = 시험 덧 + `auto_update.py:3156` docstring 뿐, 제품 동작 바꿈 0(assert_ordinary_recovery 는 읽기만, 설명과 맞음). 단언 빼기·느슨하게·건너뛰기 0.
- UNKNOWN 장면은 증명 없으면 `auto_update.py:1616` 에서 거절되는 phase 라 PASS 단언이 증명을 탐. 관찰 패치는 `current_user_onboarding.py:2168` 호출 때 import 라 실제로 잡힘. CONFIRMED·비업데이트 [] 맞음.
- pid(proof[0]≠getpid)·module(__file__ 부모≠app_root)·--onboard-current-user(startup_gate 첫머리에서 비우고 `:3071` 반환) 모두 의도대로.
- 인벤토리 92a365 는 derive 재생성과 바이트 일치. 설치기는 리터럴 핀 없이 manifest·contract 를 읽음(`:521`), preimages 불변 — 다른 낡은 지문 0.

## (나) — 앞 지적 다섯 모두 풀림 · 새 깨짐 0
- P2-1: 넷 + files[] 다섯 + source_replacements 셋 + after_inventory 가 정식 refresh 산출과 바이트 일치(594b3f…), 인벤토리도 derive 재생성과 일치, preimages 불변.
- P2-2: `Container_Audit.py:24344` 가 admission 밖에서 note UNKNOWN_CHECK + publish(refused 없이) → startable:false·UNKNOWN, main finally finish 는 revision 같아 재기록 0, 둘째 안내 0. startup-check.md:49 맞음. 새 시험이 실제 observe 로 파일을 읽어 close·stop 단언.
- P3-1: on_shown 은 Tk update_idletasks 뒤(`:23839`)·native 성공 뒤 nt 에서만(`:23793`, nt 밖 native 는 안 띄움). 둘 다 실패 → 일반 오류 길(시험 있음).
- P3-2 notice-facts.json 지움 · P3-3 operations.md:694 조건 적음.
- 바깥 소비자: 같은 startup_result(`startup_check.py:65`) 봉투를 _write_result 가 재구성, UNKNOWN_CHECK 은 기존 허용 목록, 종료 0 + startable:false 는 UPDATE_PENDING(`:24044`)에 이미 있는 짝, gui.json 안 씀. 저장소 안 다른 reader 0 → 칸·값 맞음.
- 시험 약화 0: report·gui_ready 시험은 고장 주입을 monkeypatch.context 안으로만 옮김.

## 참고
- 두 가지가 477c155 에서 인벤토리를 따로 셈(92a365 / 594b3f) → 합친 트리에서 refresh 다시. 이 커밋은 공통 조상 477c155 위.
