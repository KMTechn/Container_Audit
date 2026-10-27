ACCEPT · P1 0 · P2 0 · P3 4
검토 모델: 이 커밋의 Co-Authored-By 줄 참조 (저장소 파일에 모델 식별자를 적지 않는 규칙)

범위: 477c1557..694ba339 + 부르는 곳(auto_update.py · current_user_onboarding.py · Container_Audit.py `_prepare_gui_startup` · user_relay.py `start_user_relay_process`). 읽기만, 실행 0.

## 확인한 것
1. 같은 함수: startup_gate(auto_update.py:3092)와 register lifecycle(1617-1618 → 3060)이 같은 `_accept_startup_proof`(3021)를 부름. 예전 본문은 지워졌고 복사본 0. active SHA(3024) · trial nonce/claim/pid(3028-3032) · defer phase 집합 · `_utc` · `assert_ordinary_recovery`(G · writer cohort · active 재확인, 3155-3167) 그대로. 운영자 SID 검사가 잠금 안에서 한 번 더 붙음(엄격해질 뿐).
2. 결속: 증명은 모듈 전역 하나뿐, 환경·파일 쓰기 0. PID(3053) · resolve 한 app_root = 실제 auto_update 경로(3056) · control · policy/active/transition과 환경 값 두 개의 해시(3015)가 모두 같고, 재판정(trial.json · cohort 다시 관측)까지 통과해야 받아들임. startup_gate 첫 줄(3065)에서 지우므로 설치 위임 모드(3071)에는 증명 없음.
3. phase: install · inspect · 지원 제거(1576) · startup=False register 는 `operation == 'register' and startup` 에서 갈라져 그대로. 증명 없는 PREPARED 는 예전처럼 1619 에서 거절. failed_support 의 `not startup` 그대로. 새 phase 쓰기 · 새 sink 0. inventory 는 줄 번호만 바뀜(29곳 대조해 맞음). sha 는 세 파일에서 같은 값(다시 계산하지는 않음).
4. 실패: 증명이 틀리면 1619 ValueError → 1671 LIFECYCLE_RECOVERY 로 끝나고, writer_admission(current_user_onboarding.py:2225)보다 앞이라 자료 쓰기 · 지우기 · UNKNOWN 쓰기 0. startup_gate 가 돌려주는 코드는 예전 분기와 같아 스캔을 멈추는 새 길 0.
5. 시험: 실제 startup_gate → `_prepare_gui_startup` → onboard_current_user → resolve_lifecycle_context 를 지나 경로 해석 직전에서 멈춤. 기존 시험 약화 0(test_supported_lifecycle.py 는 docstring 한 줄만 바뀜).

## P3
1. tests/test_first_setup_startup_proof.py:83 — `reached == [active_app]` 는 lifecycle 이 CHANGED/UNKNOWN 을 돌려도 참(application_path 가 이미 active app). PASS 를 단언하지 못함. CONFIRMED/DEFERRED 는 증명 없이도 통과하는 phase 라 증명을 시험하지 않음.
2. 같은 파일 — PID 다름 · 모듈 경로 다름 · `--onboard-current-user` 에서 증명이 지워지는지 단언하는 시험 0. 2번은 코드를 읽어서만 확인함.
3. auto_update.py:3156 — `assert_ordinary_recovery` 설명은 "Caller owns the update lock" 인데 새 재판정(1618 → 3060 → 3042)은 잠금 없이 부름. 읽기만 하고 1649 에서 다시 읽으므로 틀어지는 결과는 못 찾음. 설명이나 잠금 중 하나를 맞출 것.
4. 커밋 설명 — "current_user_onboarding.py 에 startup=True 전달" 은 이 diff 에 없음(477c155 에 이미 current_user_onboarding.py:2174 · Container_Audit.py:24257). 설명을 변경 파일에 맞출 것.

## 확인 필요 (결함 입증 못 함, 등급 없음)
- 증명 전역은 물려가지 않음. 다만 그 입력인 KMTECH_CA_UPDATE_TRIAL_NONCE · DEFERRED_AT 은 첫 설정이 띄우는 relay 로 물려감(current_user_onboarding.py:2367 → user_relay.py:289 Popen 에 env 지정 없음). 자식 relay 는 자기 startup_gate 에서 같은 값으로 받아들여짐(trial 은 relay 만 pid 면제, 3032). 이 길이 이제 pointer≠owner 인 불안정 phase 에서도 열림(전에는 1619 에서 막혀 relay 를 띄우기 전에 멈춤). trial 감독(3355-3373)이 이 relay 를 자기 relay 로 세는 것이 의도인지 명세로 확인.
- current_user_onboarding.py:2175 — startup lifecycle 이 CHANGED/UNKNOWN 이면 첫 설정이 원래 app_root 로 계속 감(diff 전 동작, 범위 밖).
