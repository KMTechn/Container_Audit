# 이적 제품 교체 정책

## 봉인 전

현재 이적 트레이는 중앙 원장에서 아직 `PHS/AVAILABLE`이다. 제품 1~2개 교체는
`REPLACE_BUNDLE_MEMBERS` 한 명령으로 처리한다.

- 작업자는 현재 트레이의 교체 대상 제품을 스캔하고 새 양품을 스캔한다.
- 새 양품 resolver는 제품 바코드 하나를 정확히 하나의 PHS·unit에 매핑하며,
  그 공여 PHS의 활성 제품도 정확히 1개여야 한다. 여러 제품이 든 PHS는 교체 후
  기존 인쇄 라벨이 실제 잔량과 달라지므로 중앙 호출 전에 차단한다.
- 대상 PHS와 모든 양품 원본 PHS의 `entity_version`을 같은 명령에서 CAS한다.
- 서버 transaction은 기존 제품을 `PROCESS_DAMAGE_HOLD`로 이동하고 새 양품을 대상
  PHS에 편입한다. 1~2쌍 전체가 성공하거나 전체가 실패한다.
- 중앙 receipt가 exact membership·hash·pair·version을 모두 증명한 뒤에만 로컬
  트레이 목록을 한 번에 교체한다.
- 대상 PHS 현품표는 제품 집합을 인쇄한 라벨이 아니라 `BND/ITG/LBL`로 정본을
  조회하는 identity 라벨이다. 그래도 서버 receipt가
  `RETAIN_IDENTITY_LABEL`·`target_label_identity_remains_valid=true`·
  `target_label_membership_bound=false`를 모두 증명해야 기존 라벨을 계속 사용한다.
- 중앙 ACK 뒤 로컬 반영 중 종료되어도 SQLite intent와 현재 트레이 상태를 대조해
  재시작 시 복구한다.

## 봉인 후

Container Audit에서는 봉인 후 로컬 목록을 수정하지 않는다. 서버가 발급한 QR에는
`SID/SREV/STK`가 포함되며 서버 receipt의 exact unit↔barcode seal 증거와 일치해야 한다.

포장 프로그램에서 아직 `CREATE_PACKAGE` 전인 `TRANSFER/AVAILABLE`은 별도 중앙 계약
`REPLACE_SEALED_TRANSFER_MEMBERS`로만 1~2개를 교체할 수 있다. 이 명령은 기존 seal을
폐기하고 revision이 증가한 새 token·QR을 발급한다. 이미 PACKAGE가 생성되거나 TRANSFER가
소비된 뒤에는 계속 교체를 차단한다.
