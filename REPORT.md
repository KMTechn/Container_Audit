ACCEPT · P1 0 · P2 0 · P3 0
검토 모델: 이 커밋의 Co-Authored-By 줄 참조 (저장소 파일에 모델 식별자를 적지 않는 규칙)

범위 f95cf96b..bba5eb0b + 부르는 파일만 · 읽기만 · 시험·빌드·설치기·앱 실행 0. 지문은 bba5eb0b archive 사본에서 정식 `derive_inventory`·`current_bindings` 를 Python 3.12(CI 판)로 불러 맞댐(쓰기 0).

## 앞 지적 (calm-fix2-ca (가)) — 모두 풀림
- P2-1: derive 재생성 = 스냅숏(92a365…). `current_bindings` 산출 = 커밋된 py 핀·fence.ps1·contract·transition 네 파일과 바이트 일치(손 이식 0). after_inventory 92a365 · files[] 넷(fd5afc·3f17c5·f54546·c3f534) · source_replacements 둘 = sha256sum 실측, preimages 불변 → `INSTALL_CANONICAL_PORTABLE.ps1:809`·`:942`·`:1000` 참, `:5476` 안 남. 옛 지문 다섯은 저장소 어디에도 0.
- P3-1: `tests/test_container_writer_sink_inventory.py:1308` 이 `current_bindings` 전체 바이트 대조 = refresh --check 의 바인딩 몫(transition after·files[]·source_replacements·preimages 포함), 실패 때 경로만 냄.
- P3-2: `writer_session_fence.py:105-106` 이 derive(`tools/derive_container_writer_sinks.py:3767` ps1·contract)·refresh(`tools/refresh_container_update_declarations.py:21` 핀 셋 + transition)와 맞음.
- P3-3: `tests/test_first_setup_startup_proof.py:188` 공개 문구 ^…$ match + `:191` 원인 정확 비교. 일곱 경우 코드로 따라감: generation·writer → `auto_update.py:3163`·`:3170`, no_gate·pid → `:3053`, journal·module → `:3056-3057`, system → `:3024` 가 False → `:1619`, 감싸기 `:1671`.

## 새로 깬 것 · 시험 약화 — 0
- 옛 세 핀 단언 → 정규식 1회 일치 + 바이트 같음(같은 힘 이상) + transition 더함. 거절 단언은 ValueError 만 → 문구·원인까지 좁아짐.
- 새 시험의 git 이력(e0c46f41·d3a1ad7b)·LF 바이트 의존은 `tests/test_ca_v2109_generation.py:38`·`tests/test_installed_release_preimages.py:48-60` 에 이미 있음 — 새 의존 아님.

## 참고 (기존, 이 커밋과 무관)
- derive 는 3.11·3.13 에서 `:1496` facade AST 지문으로 멈춤(ast.dump 판 차이) — 3.12 만 정식.
- `derive --check` 는 `:3758` 에서 스냅숏만 보고 돌아가 ps1·contract 핀은 안 봄 — 그 몫은 refresh --check·새 시험.
