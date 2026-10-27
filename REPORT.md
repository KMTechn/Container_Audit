ACCEPT · P1 0 · P2 0 · P3 1
검토 모델: Claude Opus 5.5

# 독립 검토 — v2.0.123 마지막 묶음 (477c1557..0725e4cd)

읽기만 함(시험·빌드·설치기·앱·저장소 도구 실행 0). 합침 6개는 remerge-diff로 보고, 묶기 커밋 3deecb5·0725e4c는 전부 읽음. 지문과 줄 번호는 커밋된 바이트를 직접 해시하고 AST로 대조함.

## P3
- writer_session_fence.py:105-106 — efa462e가 충돌을 a5725d9 쪽으로 통째로 풀면서, 746 bba5eb0이 고친 주석(「refresh_container_update_declarations.py가 이 Python 핀을 묶음」)이 옛 글 「derive_container_writer_sinks.py가 만들고 검사함」으로 되돌아감. 실제로 derive는 fence.ps1·contract만 다시 씀(tools/derive_container_writer_sinks.py:3766-3771). 주석대로 derive --write만 돌리면 Python 핀이 낡은 채 남음(746이 막은 꼴). 핀 값은 지금 맞고, 시험 test_current_inventory_binding_matches_every_runtime_consumer가 잡음.

## 1. 합침 손 풀이·묶기 커밋
- 손으로 푼 자리는 여섯 합침 모두 선언 5파일(inventory·fence.ps1·contract·transition·writer_session_fence.py)뿐. .py·.ps1·시험 소스에는 손 풀이 0, 합침에 끼워 넣은 변경 0.
- 3deecb5·0725e4c는 선언 5파일만 바꿈. 묶기 쪽에 시험 기대를 맞춘 커밋은 없음.
- 중간 머리 c9ac66f·efa462e는 한쪽 값을 고른 탓에 fence.ps1:4 핀이 낡은 1e753a…(bootstrap은 a09e…). 0725e4c에서 바로잡힘 — 중간 머리는 출하하지 말 것.

## 2. 같은 자리를 둘 이상이 바꾼 곳
- 소스 파일마다 마지막 내용이 검토받은 가지 머리 하나와 바이트까지 같음: Container_Audit.py·ca_screen_bridge.py = fe323b9, bootstrap_integrity.ps1 = 1dddb0a, current_user_onboarding.py·report_publication.py·register·relay_install_pack·build 목록 = a5725d9.
- auto_update.py 변경 줄 = 746·751·754 diff의 정확한 합집합. 함수 겹침 없음. 751의 Bearer 가림은 754 _failure_details 폴백 앞에서 그대로 쓰임.
- 진입 순서: portable/main.py가 current_user_onboarding → auto_update.startup_gate → Container_Audit 순으로 같은 auto_update 모듈을 씀. report_publication은 stdlib만 import하고 auto_update를 다시 싣지 않아 746의 시작 증명 공유가 유지됨. `-I -B app/auto_update.py` 실행 길은 sys.path 삽입 뒤에 import함. 빌드 목록에 report_publication.py 있음.
- 754는 onboard_current_user 순서를 바꾸지 않아 746 시험 기대가 성립. 설치기는 bootstrap 핀 한 줄(751)만 바뀜. 754 시험이 읽는 onboarding readback 구간은 그대로.

## 3. 정식 선언·지문(마지막 머리)
- inventory 자기 지문 bb5455a5… 재계산 일치, 바이트는 정렬 JSON 그대로. writer_session_fence.py:107·fence.ps1:29·contract:53·transition after_inventory_sha256 모두 bb5455a5….
- bootstrap_integrity.ps1 sha a09e6e54… = 설치기:79 = fence.ps1:4.
- transition files[]·source_replacements에서 저장소 안 경로 143개의 after가 모두 커밋 바이트와 일치. before·순서·개수(871/33)는 불변이고, installed_release_preimages도 두 출시 커밋에서 다시 계산해 일치. 범위 안 옛 지문은 저장소에 0.
- inventory 줄 번호 463곳을 마지막 소스 AST와 대조해 어긋남 0(3deecb5판으로 대조하면 94 — 검사가 살아 있음). PS 변이 자리·shell kit·pinned_unused 해시도 일치.

## 4. 시험 약화
0. 빠진 단언 9줄은 monkeypatch.context 안으로 옮겨진 것. skip·xfail·호스트 제외 추가 0. sink_boundaries의 기대 변경(onboarding writer: 거절 → 진단 칸을 「보고 못 씀」으로 씀)은 754 설계대로이고, 비밀 부재·임시 파일 검사는 남음. 시험 파일마다 마지막 내용이 그 시험을 고친 가지 하나와 같음.
