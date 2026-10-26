ACCEPT · P1 0 · P2 0 · P3 0

# 독립 후속 검토 — committed 봉인 receipt 조회 실패 (calm-cmd2-ca)

대상 8fd365e3..d9657f99 (d9657f99 1개). 읽기만, 시험·빌드 실행 0. 줄 번호 = d9657f99.

## 앞 지적 처리

- P2-1(committed 408/429 뒤 GET 408/429 → RETRY_WAIT): 고침. transfer_client.py:764-768 이 get_receipt 의 모든 예외를 잡아 POST 오류를 `raise exc from lookup_error`.
- 범위 밖 줄(committed 5xx 뒤 GET 404 · committed 408/429 뒤 GET 5xx·비JSON·전송): 고침. transfer_store.py:919-921 이 committed=true 5xx 도 OPERATOR_REVIEW.
- P3-1(408/429 + OPERATION_LEASE_MACHINE_SCOPE_FORBIDDEN + retryable): 그대로(:897-904 무변경, diff 밖·세지 않음).

## 항목

1. **ACCEPT** — 조회 실패: 408·429·5xx JSON(:286-295)·비JSON(:262-277)·3xx 는 TransferSealError, 전송 오류는 :238-241 이 원 예외를 다시 던짐 → 모두 :766 이 잡아 POST 오류(committed=true) 유지. 404 는 None(:283) → :771 이 POST 오류 다시 던짐. 저장 :919 가 retryable 과 무관하게 OPERATOR_REVIEW·검토 사례·임대 record_review(transfer_seal.py:3301-3313), PENDING_STATUSES 밖 → 재전송 0. 복구는 receipt 만 읽는 recheck_operator_review_receipt(transfer_seal.py:3132). 시험 :126-168 = POST 408/429/503 × 조회 408/429/503/비JSON/전송 15경우, POST 1·GET 1·last_error_code SERVER_BUSY·명령/키/완료 불변. :93-123 에 503 × retryable 3 추가(GET 404).
2. **ACCEPT** — :762-763 committed 가 true 아니면 GET 없이 그대로 던짐, :919 는 committed=true 만 봄 → 바탕 그대로 RETRY_WAIT, 저장 command_json·같은 키 재전송(시험 :16-50, 408/429/500 × 없음/false, POST 2회 본문·키 같음).
3. **ACCEPT** — receipt 를 받으면 :769-770 반환 → ACKED, POST 1회(시험 :70-90). 성공 갈래 무변경.
4. **ACCEPT** — contracts.md:561 「committed=True 봉인 408·429·5xx 뒤 receipt 없음 또는 조회 408·429·5xx·비JSON·전송 오류 → POST committed 오류 보존·OPERATOR_REVIEW·자동 재전송 없음」= :764-771 + transfer_store.py:919-921. 코드가 문구보다 넓으나(참고 1) 같은 방향(fail-closed)이라 어긋남으로 세지 않음.
5. **ACCEPT** — JSON 셋은 "line" 34·"after" 9·inventory sha 3 값만 바뀜(구조 비교). line 이동 = transfer_store.py +2 33개, transfer_client.py +4 1개, 두 파일 앵커 43개가 d9657f99 의 def/작업 줄과 맞음. 핀 63fd9291… = derive_container_writer_sinks.py:632-639 정규 해시 재계산과 일치, writer_session_fence.py·.ps1·계약·전환 넷 동일, "after" = 각 파일 sha256 일치(읽기 계산만). member exchange 는 별도 store(transfer_member_exchange.py:281)라 :919 영향 없음.

## 참고(세지 않음)

1. 조회를 보내지 못해도 review: 완료 대기 한도 소진(transfer_client.py:158-163 LOGISTICS_WAIT_LIMIT_REACHED)·hold(:226-231)·assert_authority 실패. 3초 완료 대기 끝에 committed 503 이 오면 GET 0회로 OPERATOR_REVIEW(바탕은 RETRY_WAIT → 재전송). 계약 취지엔 맞으나 문구 목록엔 없고 관리자 검토가 늘 수 있음.
2. 조회 오류 코드는 `__cause__` 에만 남고 저장·검토 사례엔 POST 코드만 남음(시험이 의도로 고정).
3. committed=true 이면서 404·2xx ok:false·retryable:true 4xx 인 POST 는 조회 실패 시 여전히 RETRY_WAIT. 문구 범위(408·429·5xx) 밖, 현실성 낮음.
