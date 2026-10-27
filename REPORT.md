ACCEPT · P1 0 · P2 0 · P3 3
Claude Opus 5.5
# calm-reportfail3-ca 검토 (f8ab6ebc..a5725d9c · 읽기만 · 시험·빌드·실행 0)

## P3
1. tools/register_container_audit_worker_pc.py:1158-1160 — 앞 P3-3 그대로: 함수 사이 빈 줄 3(이 커밋 손 0).
2. report_publication.py:131-137 — 읽기~쓰기 사이 프로세스 간 잠금 0: 두 프로세스가 같은 폴더에 동시 게시 → 둘 다 N 읽고 N+1 씀(하나 잃음). 스레드는 _DELTAS·_FLUSHING 으로 맞음. 보조 셈.
3. report_publication.py:147 — 새 인자 fallback_payload·replace_strings 부르는 곳 0(소스·시험) → 죽은 인자.

## 앞 REPORT 항목
- P2-1 풀림: current_user_onboarding.py:477-482·514-519 fallback_tree 빠짐 → 대체 = 진단 칸(auto_update.py:665, command 없음)만 표지. 설치기 :7158-7181 이 읽는 status·relay_autostart.command·state_readback.base_url·relay_start.*·action 모두 원값. 교체 복원 READY(:2944-2959) relay_autostart 6칸·relay_start 원값, failure "" 유지(report_publication.py:42) → container_writer_session.ps1:1397·1429·1755 통과. 실패 보고는 :447 mixed_status_record 뒤 쓰기라 그대로 표지.
- P3-1 풀림: direct_sync_relay_install_pack.py:411 status_codes, 이 파일이 쓰는 status 전부(BLOCKED·FAIL·APPLYING·PASS·DRY_RUN·APPLY_REQUESTED) 포함.
- P3-2 풀림(위 P3-2 남음): 셈 = 파일 값 + delta → atomic_replace 쓰기, 새 실행 덮어쓰기 0. record_publication 은 게시·readback 뒤(:493·530, pack :426) → OSError·FileExistsError·readback 다름은 셈 0.
- P3-3 안 풀림(위 P3-1).

## 새 깨짐 확인(문제 없음)
- rc0 ⇒ 보고 씀: _write_json_atomic 은 쓰고 readback 또는 예외; record_publication 은 Exception 삼킴(:138) → READY(:2455)·제거(:2563) 결과 그대로.
- 표지·셈 IO: mark_unavailable 은 집합 넣기만(IO 0), 셈 실패는 delta 되돌리고 return → 원 실패 cause·exit code 그대로; pack 은 OSError+대체일 때만 False(앞과 같음).
- 진입 import: auto_update.py:22-26 손 0; report_publication 은 표준 모듈만(json 넣고 re 뺌). 지운 API(report_io·flush_report_counter·counter_writer·fallback_tree) 부르는 곳 0, 필수가 된 unavailable_codes 는 모든 호출이 넘김.
- 지문: 인벤토리 정규 해시 c40e78c8… = 파일 값·writer_session_fence.py:107·fence ps1:29·contract:53·transition after_inventory; transition files[]·source_replacements(33) after 모두 현 바이트와 같음; 옛 4090d4…·옛 파일 해시 0; 줄 번호 표본 맞음; _persist_failure_report direct_callers 빠짐 = lambda 제거.
- 시험: 1→0 두 곳(test_report_publication.py:68·test_report_unavailable_startup.py:108) = 게시 전 실패 셈 0 요구. 투영 시험은 _persist_failure_report 로 옮김(쓰기 단 투영은 P2 고침으로 제거), REDACTED 중첩은 startup:215-234 에 남음; 새 시험은 command 원값·설치기 대조·셈 누적 더함 → 약화 0.
