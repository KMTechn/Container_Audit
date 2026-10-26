ACCEPT · P1 0 · P2 0 · P3 4

# 독립 검토 — relay 정지·설치 대기 상한 (calm-waits-ca)

대상 `cloud-input/calm-waits-ca` f4f1a626 (바탕 b9e4ce8b · 한 커밋). 읽기만, 시험·빌드 실행 0. 줄임: can=INSTALL_CANONICAL_PORTABLE.ps1 · itp=INSTALL_THIS_PC.ps1 · bi=tools/bootstrap_integrity.ps1 · cws=tools/container_writer_session.ps1 · fence=tools/container_writer_fence.ps1 · au=auto_update.py.

## 볼 것
1. **넘김 ○** 늘린 루프는 모두 마감 뒤 기존 throw/UNKNOWN 그대로(relay·quiescence·legacy·CANONICAL_WRITER_*·gate busy·`request_user_relay_stop` UNKNOWN·후보 UNKNOWN 기록). kill·삭제 추가 0. 후보 종료는 원 `normal_stop_started_at` 잔여(au:2271-2272), SYSTEM 작업은 PT0S·AllowHardTerminate false(au:1620).
2. **결속 ○(150)** Python 상수 = 자식+30, au 두 곳 import, PS 150은 시험이 자식+30 단언, 설치기 probe는 Python 식 그대로. 120은 P3-3.
3. **화면 스레드 ○** 기본값 바뀐 정지의 호출자는 removal_main·replacement_lifecycle_restore_main(무화면)뿐, au는 SYSTEM, PS 둘은 콘솔.
4. **stderr ○** `--apply-prepared`(apply_prepared_update.ps1:9·:302) 길 새 출력 0, 정지·제거도 침묵(cws:2060 2>&1 안전). 출력은 restore 봉쇄 1곳(유한 생산자, bi:2446 파일 캡처)과 itp 3곳([Console]::Error, catch 삼킴, 원 결과·예외 보존). itp 실행자는 모두 native 캡처(can·bi에 2>&1 없음, 빈 stderr 검사 0). journal 쓰기 0.
5. **감독 ○** `bootstrap_supervision_deadline` ROLLBACK_PENDING/UNKNOWN 창 = 같은 상수, 480 상한 불변, 명세 60→150 일치.
6. **핀 ○** inventory 자기 해시 재계산 = ad8e5859…, 세 핀 같음, transition after(파일 8종) = blob sha256. 단 P3-4.

## P3
- **P3-1 조정자 적재에 상수 없음(잠재)** bi:2102-2104는 정본의 함수 정의만 싣고 can:32 대입은 싣지 않는다. 상수를 쓰는 세 함수의 호출자는 정본 본문(can:6260·6666·6856→3387·6884)뿐이라 지금 도달 0. 장래 보상이 부르면 `AddSeconds($null)`=0 대기 또는 StrictMode 오류. 미정 시 throw 권함.
- **P3-2 바깥 한도가 새 예산을 깎음(닫힘 유지)** 실패 봉쇄는 생산자의 180 s 위임(cws:1889)을 갱신 없이 재사용(cws:2035-2042): 생산자 봉쇄 ≤150 + 제거 ≤150 직렬. 배치 위임 180–300 s(fence:776 상한) vs itp 입장 120+120(+gate 120). 조정자 900 s(can:257) vs can:6520–7182 단계 상한 합(>900 가능). 만료는 입장 때 거절(fence:861)·OUTCOME_TIMEOUT→보상이라 실패 범주는 같고 예전 성공 실행의 시간은 불변. 다만 실패 보고 누락·조정자 보상과 부모 진행이 겹치는 경우는 diff·명세가 다루지 않음(검증 못 함).
- **P3-3 120 숫자 8곳 복사**(can 5·itp 3), 공유 상수 없음. 시험은 함수 단위 Contains라 Disable-CanonicalWriter·Enter-ContainerPlacementWriterFence의 둘째 자리는 한쪽만 맞아도 통과, `supported_update_gate` WaitOne(120000)은 고정 시험 없음.
- **P3-4 인벤토리 = 핀 전파 + 파생 실행 지점 1** `Invoke-ContainerTimedWait`의 `& $Action`(target_static=false, guarded)이 execution_sites·mutation_scopes·function_guard_proofs에 추가, 계수 121→122·91→92·53→54. 생성기 산출로 일관하나 BACKLOG·명세 설명 없음.

## 참고
- 설치기 relay 정지는 probe ≤150 + 후속 종료 ≤150 = 최대 300 s.
- 정본 대기 8곳은 진단 0(journal 제외 방침) — CA에서 「안전한 길 기록」은 restore 봉쇄·itp 3곳뿐.
