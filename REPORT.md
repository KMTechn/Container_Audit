REJECT · P1 0 · P2 1 · P3 3
Claude Opus 5.5
# calm-reportfail2-ca 검토 (d79a6f7a..f8ab6ebc · 읽기만 · 시험·빌드·실행 0)

## P2
1. current_user_onboarding.py:467,498 — 새 fallback_tree=mixed_status_record 가 대체 트리 전체를 투영해 relay_autostart.command(_DIAGNOSTIC_KEYS, auto_update.py:1168)가 늘 SUPPORT_FAILURE. 비밀 꼴 env 값(4자+)이 진단·투영 칸에만 걸려 대체가 성공하면 rc0·READY 인데 설치기 INSTALL_CANONICAL_PORTABLE.ps1:7158(command -cne $wanted) → 'Onboarding Run readback failed.'; 교체 복원 READY(2938)는 container_writer_session.ps1:1429 대조 거절 + Python 격리(2940~) 건너뜀. 바탕은 같은 입력에서 쓰기 거절이라 새 멈춤은 아니나 항목 3(진단 칸만 표지) 위반·d79a6f7a 대비 회귀. 고침: READY·제거 길은 fallback_tree 빼기(실패 보고는 이미 mixed 트리).

## P3
1. tools/direct_sync_relay_install_pack.py:413-415 — 대체가 트리를 버리고 status 만; DRY_RUN·APPLYING·APPLY_REQUESTED 는 PUBLIC_CODES 밖이라 status 도 빠지고 nonconforming_fields 만(DRY_RUN 은 rc0). 첫 설정 길 밖.
2. report_publication.py:66-99 — 셈은 프로세스 지역: 새 실행·동시 자식이 폴더 파일을 자기 수로 덮어 누적 아님; create_new FileExistsError·쓰기 OSError 도 게시 전에 셈.
3. tools/register_container_audit_worker_pc.py:1158-1160 — 함수 사이 빈 줄 3.

## 앞 REPORT 항목
- 앞 P1-1 풀림: auto_update.py:26 import 가 22-24 sys.path 넣기 뒤; report_publication 은 표준 모듈만. register_container_audit_worker_pc.py:21-26·direct_sync_relay_install_pack.py:19-21 은 ROOT 넣은 뒤 함수 안 import, current_user_onboarding 도 함수 안.
- 앞 P1-2 풀림: 영수증은 바탕(477c155)처럼 mixed_status_record 만, 새 비밀 검사 0, 읽어 맞추기도 같은 값. label_match 영수증 손 0.
- 앞 P2-1 풀림: _write_counter 가 Exception 모두 삼킴(WriterFencedError·ValueError), 잠금 밖에서 씀.
- 앞 P2-2 풀림: _write_json_atomic_create_new 도 같은 경계(위 P2 참고).
- 앞 P3-1~3 풀림: report_attempt 로 실패 보고 셈 1·publish_report 제거; 폴더당 .report-unavailable-count.json 한 파일 원자 덮어쓰기; 빈 문자열 유지, 비문자는 엄격 검사 거부 때만 표지(report_publication.py:36-39).
- 앞 P3-4 풀림: 공개 코드 status 유지, 못 쓰면 경로 알림 0(남은 것 위 P3-1).

## 확인(문제 없음)
- 대체 글: 진단 문자열·[REDACTED:이름]·짧은값 메모 → 표지(값 0·이름 0). 필수 기계 칸 충돌은 대체도 같은 검사라 거절·미게시·셈 0.
- PRODUCT_METADATA_SECRET_VALUE_REFUSED 는 저장소에 없음. 실제 코드 MACHINE_METADATA_SECRET_DETECTED(auto_update.py:899)·REPORT_UNAVAILABLE 둘 다 기본 목록(report_publication.py:109,138).
- 불변식: _write_json_atomic 은 쓰거나 예외 → rc0 ⇒ 정본 보고 씀; status·server_registration_verified 는 진단·투영 칸 아님 → 표지 0.
- 지문: 인벤토리 정규 해시 4090d4c7… = 파일 값·writer_session_fence 핀·fence ps1·contract·transition after_inventory; transition files[]·source_replacements(33) after 모두 현 바이트와 같음; 옛 627e42… 0; 싱크 줄 번호 표본 맞음.
- 시험: 바뀐 단언은 이 가지에서 생긴 기대를 항목 2·4 에 맞춤 — 바탕 보장 약화 0(영수증 detail int→str 은 바탕 동작에 맞춤).
