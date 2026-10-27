REJECT · P1 2 · P2 2 · P3 4
Claude Opus 5.5
# calm-reportfail-ca 검토 (477c1557..d79a6f7a · 읽기만 · 시험·빌드·실행 0)

## P1
1. auto_update.py:19 — 새 `from report_publication import UNAVAILABLE` 가 23-25줄 `__main__` sys.path 삽입보다 앞. 실제 시작 명령 `pythonw.exe -I -B app\auto_update.py --bootstrap`(portable/launch-container-audit.cmd:4 · 전송 시작 INSTALL_CANONICAL_PORTABLE.ps1:577-579 · tools/bootstrap_integrity.ps1:3327)은 -I(3.11+ 는 -P 포함)라 app 폴더가 sys.path 에 없음 → ModuleNotFoundError → 이 판을 받은 모든 PC 에서 앱·전송 시작 0, 자기 업데이트로도 못 빠져나옴. 포장 검사(_assert_portable_import_closure)는 sys.path 를 직접 넣어 못 잡음. 고침: import 를 25줄 뒤로.
2. tools/register_container_audit_worker_pc.py:1157-1160 — 등록 영수증에 전에 없던 전체 글 비밀 꼴 검사(os.environ) 추가. 대체 글은 진단 칸만 바꾸므로 기계 칸(hostname·endpoint_url·안내 문장·secret_ref 등) 충돌은 그대로 거절. 성공 길 영수증 쓰기(3503 등)가 서버 등록·manifest·credential 쓰기(3409-3410) 뒤라, 이름이 비밀 꼴(TOKEN 등)이고 값(4자+)이 영수증 전용 글과 겹치는 변수가 있는 PC 는 FAILED → 다음 시도는 부분 상태 RECOVERY_REQUIRED(current_user_onboarding.py:1526-1531). 결함과 같은 꼴의 새 멈춤 길. 영수증은 전처럼 mixed_status_record 만 두기.

## P2
1. report_publication.py:66-69 — 셈 파일 실패를 OSError 만 삼킴. 셈 writer 는 writer_sink 라 WriterFencedError(RuntimeError)·_atomic_report_reference ValueError 가 샘. _persist_failure_report 의 protect_diagnostic(current_user_onboarding.py:425-429)은 try 밖 → 실패 글 가림 실패 + 셈 쓰기 비-OSError 이면 원래 실패의 cause·exit code 가 바뀜(attempt 없는 이른 실패는 admission 밖). 항목 3·4 위반, 조건 좁음.
2. current_user_onboarding.py:484-491 — _write_json_atomic_create_new(교체 뒤 복원 READY, 2927)는 손대지 않음 → 진단 칸(relay_autostart/relay_start 의 message 등) 충돌 시 REPORT_PERSISTENCE 실패 → 자동 시작 제거·전송 정지 → 업데이트 복원 FAILED. 회귀 아님, 같은 결함이 업데이트 길에 남음.

## P3
1. report_publication.py:16-22 — report_attempt 를 아무도 안 씀 → 중복 막기 0: 실패 보고 하나가 425 와 464 에서 셈 2. publish_report·DIAGNOSTIC_FIELDS 도 미사용.
2. report_publication.py:47-69 — pid 마다 `.report-unavailable-count-<pid>.json` 이 status 폴더에 쌓이고 정리 0; _LOCK 을 쥔 채 writer_admission 진입(잠금 순서 역전 여지).
3. report_publication.py:30-36 — 빈 값·비문자 진단 칸도 덮어 PASS 제거 영수증에 failure=표지(설치기 확인 칸은 아님).
4. tools/direct_sync_relay_install_pack.py:411-420 — 대체 보고가 status 까지 버림; OSError 면 안 쓴 채 옛 파일 경로를 알림(첫 설정 길 밖).

## 확인(문제 없음)
- 정본 필수 칸(status·server_registration_verified)은 진단 칸 아님 → 표지 0; 필수 칸 충돌은 대체 render 도 같은 검사라 거절·미게시.
- 진짜 실패: 오류 생성자 대체가 status·reason_code 보존 → FAILED·cause 유지.
- 불변식: _write_json_atomic 은 쓰거나 예외 → 표지 길에서 rc0·정본 미게시 0(2423·2531).
- 표지 원자 교체, 새 로그 0, 셈 파일엔 숫자만.
- 배포·지문: APP_ROOT_FILES·인벤토리 closure 에 report_publication 있음; 인벤토리 정규 해시 627e42… = 파일 값·writer_session_fence 핀·fence ps1·contract·transition after_inventory; transition files[]·source_replacements after 모두 현 바이트와 같음; 옛 해시 남은 곳 0; 새 파일 미등재는 기준 ea566d1 에 없던 auto_update.py 와 같은 규칙.
- bc0ba86·3930787 은 tests/ 만, 고침 커밋도 시험 추가만 — 약화 0.
