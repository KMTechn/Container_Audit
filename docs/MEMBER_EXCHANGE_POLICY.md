# 이적 제품 교체 정책

## 봉인 전

w9scanonly 계약 v1.2의 `SCAN_REGISTER_GOOD` 경로는 카드/단추 → 불량 대상 → 대체품이다.
중앙 요청 전에 로컬 intent·JSON·교환 감사 기록을 내구 저장하고 트레이를 갱신한다.
기존에 스캔한 제품은 대체하고, 미스캔 구성원은 대체품이 그 자리를 채운다. 목표는 같다.

- 검사 단계의 다른 묶음 제품은 자동 이동한다. singleton 제한을 적용하지 않는다.
- 미검사·미등록 대체품은 교환 스캔으로 GOOD 등록한다.
- NG·다른 품목·TRANSFER 봉인/PACKAGE/SHIPPED 구성원은 거절한다.
- 로컬에서 모르면 접수하고 중앙에서 판정한다. UNKNOWN은 성공이나 실패로 바꾸지 않는다.
- 배경 `REPLACE_BUNDLE_MEMBERS`는 기존 인증 context와 CAS를 유지한다. 요청 pair는
  old_barcode/new_barcode, receipt는 server unit/source IDs와 pair별 source kind를 포함한다.
- exact target membership/hash·불량 이동·version·멱등성 증거를 검증한다.
- 기존 singleton 명령 및 lease rotation의 저장·복구는 이전 원장 호환 경로로 유지한다.

## 봉인 후

Container Audit에서는 봉인 후 로컬 목록을 수정하지 않는다. 서버가 발급한 QR에는
`SID/SREV/STK`가 포함되며 서버 receipt의 exact unit↔barcode seal 증거와 일치해야 한다.

포장 프로그램에서 아직 `CREATE_PACKAGE` 전인 `TRANSFER/AVAILABLE`은 별도 중앙 계약
`REPLACE_SEALED_TRANSFER_MEMBERS`로만 1~2개를 교체할 수 있다. 이 명령은 기존 seal을
폐기하고 revision이 증가한 새 token·QR을 발급한다. 이미 PACKAGE가 생성되거나 TRANSFER가
소비된 뒤에는 계속 교체를 차단한다.
