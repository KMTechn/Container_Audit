# CA 제품 admission 검사 순서

W5-B2 기준은 `00c5deb1085a5b2c7b95b975fe0443bae56061a5`의 현행 동작이다.
제품 문자열의 prefix13 exact 규칙으로 바꾸지 않으며, generic `label_qr.py`의
관대한 표시/호환 parser를 제품 admission에 적용하지 않는다.

| 순서·경로 | 검사와 현재 의미 | 실패/결과 |
|---|---|---|
| 시작 호환 분기 | QR 분기 밖에서 길이가 `ITEM_CODE_LENGTH=13`인지 확인 후 catalog exact lookup | 기존 시작 오류/품목 없음; 활성 트레이 제품 gate와 별도 |
| 제품 1 | `str(barcode or "")`; 양의 item-code 길이 검증. bool 거부, 기존 int 변환 유지 | 잘못된 길이 설정이 unsafe 이유보다 우선; unsafe이면 raw 대신 SHA256·길이 |
| 제품 2 | unsafe 순서: >128 → 외곽 공백 → C0/DEL → 수식 시작 → HTML/script → 경로 | `SCAN_FAIL_FORMAT`; raw redaction. NFKC/uppercase/strip을 새로 적용하지 않음 |
| 제품 3 | 문자열 길이 > 현재 item-code 길이(기본13) | 이하이면 `barcode_too_short` |
| 제품 4 | 현재 item-code strip 후 존재 → 스캔 기록 list[str] → 양의 capacity | missing item → malformed history → invalid capacity 순서. set으로 변환/허용하지 않음 |
| 제품 5 | 현재 품목이 raw 문자열 어느 위치든 포함 | `SCAN_FAIL_MISMATCH` |
| 제품 6 | 전달된 스캔 목록 안의 raw exact 중복 | `SCAN_FAIL_DUPLICATE`; 대소문자/유니코드 정규화 없음 |
| 제품 7 | 목록 길이 >= capacity | `SCAN_FAIL_TRAY_FULL`; 중복 목록도 길이 그대로 계산 |
| catalog 1 | 품목별 모든 발생 span 검색; 짧은 코드의 **모든** 발생이 더 긴 코드에 포함될 때만 제거 | 별도 발생한 짧은 코드 유지; catalog 삽입 순서 유지 |
| catalog 2 | 코드 중복 제거 후 >1 → 단일 다른 코드 → 그 외 | 모호성 거부 → mismatch → accepted; 0 match도 기본 gate 통과 뒤에는 accepted |

결과의 status/event/detail/한국어 오류 메시지와 일반·held 호출자의 사건·저장·FIFO
ACK 순서는 유지한다. 동일 품목 통과가 중앙 GOOD membership을 증명하지 않으며,
전량 확인·seal/교체 exact version·lease·local/central ACK는 각 기존 조정자가 소유한다.

기록 벡터와 고정 seed 생성 속성 시험은
[test_product_identity_port.py](../../tests/test_product_identity_port.py)에 있다.
정상/내부 substring, 길이12·13·14·128·129, 중첩·별도 substring/다중 match,
raw 중복/초과/오류 우선순위, 한글·전각·결합문자·C0/DEL/C1을 포함한다.
비교 oracle은 baseline의 두 순수 모듈을 동결한
[시험 전용 fixture](../../tests/fixtures/product_admission_w5b2_baseline.py)이며,
새 구현에 맞춰 기대 로직을 바꾸지 않는다. 실제 새 정책·공용 leaf·schema는 후속 요구다.
