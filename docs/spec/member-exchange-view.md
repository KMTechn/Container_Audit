# 스캐너 제품 교환 (w9scanonly)

교환 카드 `KMCMD:EXCHANGE` 또는 기존 단추는 창 없이 불량 대상 → 대체품 순서로 받는다.
완료 클릭과 수량 선택은 제거했다. 다른 명령·현품표는 교환 입력을 취소하고 정상 처리한다.
이미 스캔한 대상은 같은 위치를 교체하고, 미스캔 구성원은 대체품 한 개로 그 자리를 채운다.
목표 수량은 유지한다. 알려진 NG·다른 품목·봉인/포장/출고 구성원은 무시한다.
알 수 없는 대체품은 로컬에서 받아 중앙 `SCAN_REGISTER_GOOD` 명령으로 재검증한다.

현재 상태 JSON과 `transfer_scan_exchanges`의 고정 intent·시각·작업자·PC 증거,
`PRODUCT_EXCHANGE_COMPLETED` 투영을 로컬에 기록한다. checkpoint가 저장되면 교환 입력 모드를 끝내며, CSV 실패 시 대체품을 보존하고 같은 키로 재투영한다. 후속 스캔·교환·완료가 있어도 저장된 교환 키로 복구하며 새 checkpoint를 덮어쓰지 않는다. 기존 목표/lease 증거는 유지하되 교환 후 중앙 봉인은 새 lease를 확보한다. 독립 직렬 전송기가 기존
`REPLACE_BUNDLE_MEMBERS` 전송부로 보낸다. 완료 intent는 관련 교환 ACK 뒤에 lease와
봉인을 진행한다. UNKNOWN은 재시도하며 terminal review는 해당 건만 보존한다.
기존 exact receipt/CAS 및 서명 lease 검증과 관리자 복구 전송부는 유지한다.

교환 Toplevel, 크기 계산, 수량 spin, 별도 입력·완료 버튼의 실행 소비자는 제거했다.
portable builder와 UI capture 목록에서도 해당 화면 모듈을 제외했다.
실제 GUI·서버 수용은 이 구현 레인에서 실행하지 않았다.
