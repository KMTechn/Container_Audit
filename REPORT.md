Claude Code (모델 식별자는 세션 규칙상 저장소에 쓰지 않음 — 채팅 답변으로 보고)
REJECT · P1 0 · P2 1 · P3 1

# 독립 검토 — 서버 명령 408·429 분류 (calm-cmd-committed-ca)

대상 a46210fd..8fd365e3 (490dd092·21d85896·8fd365e3). 읽기만, 시험·빌드 실행 0. 줄 번호 = 8fd365e3.

## P2-1 committed=true 408/429 뒤 receipt GET 이 408/429 면 자동 재전송

- 길: POST seal 408/429 `{committed:true}` → transfer_client.py:762-764 receipt GET → GET 이 JSON 408/429 → :286-295 새 오류(status 429, committed=None, retryable=False)가 except 절 안에서 나와 POST 오류를 덮음 → transfer_seal.py:3298-3301 record_error → transfer_store.py:897-904 의 408/429 제외와 :919 committed 규칙을 둘 다 비켜 `RETRY_WAIT` → 다음 회차 같은 키로 POST 재전송.
- 바탕: 같은 GET 429 는 terminal_client_error → OPERATOR_REVIEW. 이 diff 가 새로 연 길이고, diff 가 넣은 contracts.md:561 「receipt를 확인하지 못하면 OPERATOR_REVIEW … 자동 재전송하지 않는다」와 어긋남. 앞 P2(GET 404)의 형제 길.
- 시험 빈칸: tests/test_command_status_retry.py:93-123 은 GET 404 만 다룸.
- 제안(고침 0): seal_transfer committed 가지에서 exc.status_code∈{408,429} 이면 get_receipt 예외를 잡아 `raise exc from lookup_error`(POST 의 committed 오류 유지). 시험: GET 408/429/503/비JSON 매개 → POST 1회·OPERATOR_REVIEW.

## P3-1 408/429 + OPERATION_LEASE_MACHINE_SCOPE_FORBIDDEN + retryable:true → RETRY_WAIT

transfer_store.py:897-904: 바탕은 이 코드를 retryable 이어도 최종 검토로 봤으나 408/429 제외로 재시도가 됨. 거절이라 원장 위험 0, 현실성 낮음. 고칠지는 작성자 몫.

## 항목

1. **REJECT** — P2-1. 그 밖: 비JSON 408/429 는 바탕도 retryable=True(transfer_client.py:262-277). 2xx 불명(:286, status 2xx)과 RECEIPT_MEMBERSHIP_MISMATCH(transfer_seal.py:3104-3112, 검토 코드)는 이 diff 가 건드리지 않음. GET 404 는 :767 이 POST 오류를 다시 던져 :919 로 검토.
2. **ACCEPT** — :919 가 committed=true 408/429 를 retryable 값과 무관하게 OPERATOR_REVIEW(post review case :940-941, lease record_review transfer_seal.py:3303-3313). committed 없음/false 408/429 는 RETRY_WAIT·같은 키/본문 재전송(시험 :16-50), receipt 있으면 POST 1회로 ACKED(:70-90).
3. **ACCEPT** — Container_Audit.py:20808-20818: 408/429 는 만료 전 pending 유지·settle 안 함 → terminal_operation_lease.py:1109-1113 로 다음 회차·재시작 뒤 같은 키·본문 재요청. 만료 뒤는 EXPIRED_NOT_RETRIED. 풀기 길은 _log_operation_lease_release(:20693-20713, settle+로그)만 부르고 record_review·권한 검토 없음. 400/404/409/412 는 그대로 settle(:20819-20826, 시험 :166-175).
4. **ACCEPT**(P3-1 단서) — 409/412 CAS(transfer_store.py:894-896), 404·408·429 밖 4xx 비retryable(:897-904), 검토 코드·PHS2_·OPERATION_LEASE_ 비retryable(:905-921)은 408/429 에서도 검토 유지(시험 :53-67).
5. **ACCEPT** — 인벤토리·전환 JSON 은 "line"/"after"/inventory sha 만 바뀜. transfer_store.py :919 뒤 +1, Container_Audit._prepare_gui_startup 23984→23987(+3)이 소스와 맞음. 핀 a5535394… = derive_container_writer_sinks.py:632-639 정규 해시 재계산과 일치, "after" = 각 파일 sha256 일치(읽기 계산만).

## 범위 밖(세지 않음, 바탕 동일)

committed=true 5xx 뒤 GET 404, committed=true 408/429 뒤 GET 5xx·비JSON·전송 오류도 RETRY_WAIT. 바탕 그대로이나 contracts.md:561 문구가 뒤 경우까지 덮으므로 P2-1 고칠 때 함께 정하면 됨.
