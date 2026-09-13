# Container_Audit 기술 명세

이 문서는 **원본 PHS2의 중앙 GOOD 구성원을 전량 확인하고 이적 결과를 내구 저장하는 Windows 작업자 앱**의 소스 기준선이다. 로컬 완료, 중앙 물류 확정, 분석 전송, 화면 반영을 각각 추적한다. 기능 변경 시 함께 갱신할 규칙은 [AGENTS.md](../../AGENTS.md)에 있다.

[계약·데이터](contracts.md) · [운영·복구](operations.md) · [남은 작업](BACKLOG.md) · [전체 허브](../../../Program_Spec_Hub/README.md) · [통합 관계](../../../Program_Spec_Hub/INTEGRATIONS.md) · [실제 준비도](../../../Program_Spec_Hub/READINESS.md)

**현재 상태 — 2026-09-09 S05:** 선택된 여섯 프로그램 qualification은 Main의 독립 composition 검토로 마감됐다. 최종 frozen `d440b1f7`의 요청 범위 native 수용은 **완료(지원 recovery 포함)**이며, 기본 GUI·cold boot·정상 제거/재설치·사용자 상태 보존의 범위는 [CA-G10](BACKLOG.md#ca-g10)과 [CA-O10](operations.md#ca-o10)을 따른다. 최초 fresh 등록 실패와 과거 아래의 시점별 준비도 판단은 보존한다. 물리 장비·공장 배포는 별도 범위다.

S05는 호출되지 않는 helper와 소비자가 없는 과거 검증 도구를 제거하는 소스 작업이다.
실제 runtime/tool import·패키징·공유 계약을 유지하며, 변경된 동작은 기존 focused
시험으로 확인한다. 새 Full·build·설치·서버 작업을 요구하지 않는다.
[변경·검증 범위](operations.md#ca-o11), [후속 검토](BACKLOG.md#ca-g11)를 따른다.

### 2026-09-12 실제 M06 GOOD1 이적 완료

현행 제품 `0ea7251`의 실제 원본 PHS2·GOOD 멤버 1개를 기존 연결 VM에서 처리했다.
로컬 완료 1건·중앙 봉인 `COMMITTED`·동일 receipt의 `ACKED/attempt1`과 producer
`COMPLETE`를 확인했으며 Main은 실제 Label 인계와 VM 반환을 수용했다.
[업무·복구 근거](operations.md#ca-o12)와 [남은 범위](BACKLOG.md#ca-g12)를 따른다.
Label 이후 연결 업무·성능 분포·다음 실제 작업·별도 큰 글자 교체 행 제한은 남아 있다.

### 2026-09-12 일상 스캔과 상세 정보 분리

개별 제품 교환은 입력·완료/취소를 고정하고 설명·수량·두 행 표를 세로로 이동할 수 있다.
표 자체는 확대 글자 두 행의 최소 높이를 유지하며 긴 barcode는 가로로 접근한다.
1024×768·0.7/2.5의 실제 화면 판정은 [CA-G13](BACKLOG.md#ca-g13)에 남아 있다.

일상 화면은 품목·중앙 확정 목표/현재 개수·스캔 입력·다음 행동을 유지한다.
반복되던 스캐너 준비 안내는 실제 알림 또는 선택한 현품표 교체 작업이 있을 때만 펼친다.
현품표 교체는 운영 작업 → 현품표 교체 또는 기존 F8에서 열며, 조회/교체/복구가 진행 중이면 닫기를 거부한다.
글자 크기로 화면을 재구성해도 열린 교체 화면을 유지하고, 내구 교체 복구가 남으면 교체 진입을 계속 표시한다.
최근 정상 스캔·보조 안내·평균/최고 기록은 우측 `작업 상세`에서 펼친다.
전송 대기/확인 필요 상태는 계속 보이고 시각·진단은 `저장 전송` 카드의 `상세` 또는 운영 메뉴에서 확인한다.
`LINKED`는 `이 PC 저장 완료`, `ACKED`는 완료로 구별한다.
차단 알림·확인/재시도·보류/복원·수량·멤버십·인증·내구 저장 계약은 유지한다.
차단 중 큰 안내도 `아래 안내를 확인하세요`로 전환하고, 확인/해결 뒤 현재 작업의 스캔 안내로 돌아온다.
최종 제품 `0ea7251`은 짧은 우측 영역의 여백을 줄이고 상세 버튼의 기존 배율 글꼴을 상속한다.
호스트 최종 영향 검사104 PASS, 수정 대상 native 배율5 PASS와 이전 native40 PASS/6 FAIL의 구분,
실제1024×768 합성 화면 및 남은 확대 교환 표 행 잘림은
[결과](D:/KMTech/optimization-implementation-20260909/UI-IMPROVEMENT-20260912-1318/Container_Audit/RESULT.md),
[CA-G13](BACKLOG.md#ca-g13), [CA-O03](operations.md#ca-o03)을 따른다.

### 2026-09-10 UI 전수 점검과 idle 후 작업 명령 갱신

2026-09-11 후속 소비자 점검으로 화면에 배치되지 않고 label/state 쓰기·시험 metadata에만 남은 리셋/완료 현품표 교체/개별 제품 교환의 Tk 버튼 세 개를 제거했다. 실제 명령은 기존 운영 작업 메뉴가 열릴 때 현재 상태로 구성하며, 공통 configure helper·F8/Shift-F8·수량·권한·보류/중앙 복구 진입점은 유지한다. [변경과 소비 근거](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/HIDDEN-ACTIONS-CHANGE.md)의 영향 회귀는34 PASS다. 숨은 버튼의 state/text를 가시성 근거로 소비하던 capture M7도 실제 여섯 제어와 운영 메뉴 진입으로 보정했다(기존 capture11 PASS 및 강화한 기존 사례1 PASS). 메뉴 진입 가시성만으로 교환 허용·원자 처리까지 증명하지 않는다. 수정 전 단회 진단은 숨은 교환 버튼 configure에서408.4923ms wall/15.625ms thread CPU를 관측했고 [19개 원본 회수](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/CURRENT-DIAGNOSTIC.md)를 완료했다. 이 값은 원인·반복 성능 이득을 입증하지 않는다. 새 후보의 단회 native 명령 배치 검사는 기존580px의 고정2+2 행 assertion에서1 FAIL/native1로 종료했고 원본과 process0 확인을 보존했다. 실제 요청 폭에 따른 열 수 계약에 맞춰 기존 검사만 요청 크기 확보·포함·겹침 없음·시각적 순서·문구·넓은 행·왕복 안정성으로 보정했다. [정확한7d62910 단회 native 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/NATIVE-ACTION-RESULT.md)는1 PASS/skip0/native0이고 실제580px 배치는3+1이다. 첫 실패와 새 결과28파일 원본·해시, 정상 process0·양쪽 임시 nonce 삭제를 보존했으며 실제 Claude는 제품과 보정 검사에 필수 수정 없음으로 검토했다. 성능 이득·연결 전체 흐름 수용은 여전히 미완료다.

기존 coordinator 작업의 finish는 lane이 busy인 동안 화면을 갱신한다. 그때 비활성화된 운영 작업 버튼이 작업 종료 후 남지 않도록, 기존 idle continuation에서 후속 작업을 먼저 고려한 뒤 현재 action 상태를 다시 계산한다. 종료 요청 뒤에는 이 새 갱신을 건너뛰며, 대기 중인 작업·보류·중앙 복구의 기존 차단 조건은 유지한다. 실제 lane을 사용하는 기존 회귀에 busy/idle와 종료 중 버튼 상태를 추가했으며 최종 영향 검사 **11 PASS**다. [UI 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/ui-audit-20260910/RESULT.md)와 [CA-G13](BACKLOG.md#ca-g13)에 검사 결과·범위와 후속 작업을 기록한다.

별도 탭 대신 아래 화면·상태를 점검 대상으로 관리한다. [소스 호출 목록](D:/KMTech/optimization-implementation-20260909/Container_Audit/ui-audit-20260910/SOURCE-UI-INVENTORY-deduplicated.json)은 e69a0cb의 167개 중복 없는 UI 생성/modal 호출 위치를 포함하며, 내부 helper도 포함하므로 화면 수나 native 수용 수가 아니다.

| UI 영역 | 실제 구성과 주요 분기 | 이번 native 범위 |
| --- | --- | --- |
| 작업자 진입 | 등록/기존 이름 선택, 신규 이름 입력·등록 안내, 작업 시작·변경 | 긴 합성 한글 이름 등록·선택·시작 |
| 좌측 작업 영역 | 작업자·현 작업 카드, 품목 요약 Treeview, 보류 Treeview 전환·복원, 트레이 이미지 선택 | 빈 요약과 긴 작업자 이름; 채워진 행·복원은 후속 |
| 중앙 검사 영역 | 현품표/제품 단계, scan entry, 스캔 Listbox, 경고·확인·복구 안내, 취소/보류/제출/운영 작업 | 빈 대기 화면과 기존 글자 크기 제스처; 업무·오류별 상태는 후속 |
| 현품표 교체 | F8/교체 안내, 후보 선택 Combobox와 조회·재시도·조정 분기 | API 없음 안내만; 중앙 연결 분기는 후속 |
| 우측 상태 영역 | 작업 상태·전송 상태/상세, 소요 시간, 최근 스캔·다음 행동, 평균·최고 기록 | 빈 상태 카드·footer의 가시성 |
| 운영 작업 메뉴 | 전송 상세, 관리자 재시도, 리셋, 완료 현품표/개별 제품 교환 | idle 뒤 일반 클릭으로 메뉴 열림·문구 가시성 |
| 제품 교환 창 | active/legacy 공용 Toplevel, 수량1~2, 불량/양품 표, 상태·입력·완료/취소 | 미수용; 창 열기 시도는 helper 포커스 실패로 근거 제외 |
| 공통 modal | 시작/품목/업데이트 안내, 오류·확인·작업 인수·복원·삭제·종료 분기 | 등록 및 정상 종료 확인만 |
| 내부·대체 UI | inline 안내가 없을 때의 fullscreen 경고, 내부 시험 품목 선택, 별도 update helper | 일반 작업자 수용과 구분; 소스 목록에 보존 |

VM2의 격리된 일반 Tk 진입에서 기존 작업자 상태를 보존하고 메뉴와 대표 빈 화면을 확인한 뒤 정상 종료 native0·owned process0·task Ready/result0·원래1024×768 화면 모드 복원을 확인했다. 이 native 후보는 종료 guard 추가 전 소스이며, 후속 guard는 기존 headless 회귀로 확인한다. 메뉴 popup은 desktop 안에 있으며 root만 캡처한 그림의 잘림은 제품 결함이 아니다. 기존 Ctrl+wheel을 반복했지만 최종 저장 배율은 **1.8**이므로 파일명의 min/max나 제스처 횟수로 전체0.7/2.5 끝점 수용을 주장하지 않는다. 긴 품목/바코드, 채워진 표, 연결된 복구 및 실제 Goal3 전후 성능은 별도 미완료 범위다.

### 2026-09-10 실제 2.5 배율 실패와 후속 배치 수정

Main 배정 VM3에서 accepted `e868837`의 140개 소스 파일을 대조하고 일반 종료 후 저장된 **0.7 / 2.5** 배율을 각각 확인했다. 0.7의 빈 화면, 기본 교환 창의 수량1→2·입력·footer는 관측 범위에서 PASS다. 2.5에서는 1024×768 화면의 복원 창에서 중앙 명령/표가 사라지고, 1920×1080 최대화 및 1296×859 복원 창에서도 명령 문구가 잘렸다. 같은 큰 화면의 빈 교환 창도 하단 버튼이 줄처럼 잘려 **FAILED**다. 두 앱 실행의 정상 종료 native0, 원래 화면 모드·Explorer·네트워크 보존 및 process0/task Ready0 반환은 [VM3 결과](D:/KMTech/optimization-implementation-20260909/parallel-vm-ui/CA/vm3-e868837/VM3-HANDBACK.md)에 고정했다.

후속 소스는 기존 2x 이상 큰 글자 구간의 세 영역을 세로로 이동할 수 있게 하고, 실제 버튼 요청 폭에 따라 열 수를 정한다. 입력에 포커스가 오면 해당 위치를 보여주고, 한 줄 입력 위의 wheel은 바깥 영역을 이동시킨다. 표의 원래 스크롤과 Ctrl+wheel 배율 변경은 유지한다. 크기 계산에는 확장된 내용 높이 대신 실제 viewport 높이를 사용하며 재생성 때 추가 바인딩과 예약 작업을 해제하고, 예약 후 삭제된 입력은 무시한다. 트레이 이미지 선택 문구는 줄바꿈하며 창 크기에 따른 폰트 profile 변경도 반영한다. 우측 평균/최고 카드도 같은 viewport로 접근한다. 교환 창은 입력·완료/취소 행을 확보한 뒤 두 쌍까지의 표에 남은 높이를 배정하고, 기존 열 폭 helper 및 가로/세로 이동을 사용한다. 작은 화면에서 두 행 동시 표시를 보장하는 뜻은 아니며 각 행의 실제 접근을 확인해야 한다. 폰트 상한·수량1~2·교환/멤버십·저장 규칙은 바꾸지 않는다.

수정 후보의 headless 영향 검사와 기존 native 검사에 추가한 좁은 시나리오는 [검토 후 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/large-text-fix-20260910/review-correction/RESULT.md)에 기록한다. 실제 Claude가 f193888을 검토했고 Main은 작은 수정과 native 확인을 지시했다. 42 PASS에는 새 열 수 산술 실행이 포함되지만 실제 Tk 렌더링의 근거는 아니다. 2026-09-11 전용 VM6fcb에서 정확한2b5871c의 일반 Tk 화면을1920×1080 최대화로 직접 확인하고 정상 종료 native0 및 저장 배율2.5를 읽었다. 큰 글자 명령 문구·교환 수량1/2의 입력/footer, 잘못된 코드 안내와 확인 복귀,1280×900 복원 후 세로 이동으로 명령/이미지 선택에 접근한 범위는 관측 완료다. 기존 좁은 native 검사5개는 **PASS**(skip0,3.05초; runner4.218초/native0)이며 투명한 offscreen 위젯 검사와 실제 앱 화면을 구분한다. [전용 VM 결과와 제한](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/UI-RESULT.md)에 전체 그림·소스/runtime·종료 근거를 연결한다. 이후 수집 단계의 메모리 압박/PowerShell 창 소실은 원인 미확정으로 별도 보존하며 새 제품 실패나 검사 실패로 단정하지 않는다. 실제 Claude Opus5 후속 검토는 소스/UI/native 범위 PASS이며 제품 보완·재실행 요구는 없다. native runner PID7052 기록을 바로잡고 원 기록을 보존했다. 2.5 우측 값 글자의 기존 높이 상한으로 일부 값이1.0보다 작게 표시되는 점, 시스템 오류창의 기본 글자 크기와 수량 변경 후 spinbox에 남는 포커스는 공개된 제한이다. 마지막 항목은 기존 F8 연결 흐름에서 관측하며 별도 검사를 추가하지 않는다. 채워진 업무·연결 복구·전체 흐름은 남아 있다. 이전 배율 실패, 전체 UI의 미관측 분기와 Goal3 전후 성능 미완료를 이 소스 수정으로 해소했다고 판단하지 않는다.

### 2026-09-11 트레이 PNG 해독 비용 후속

트레이 표시의 기존 PNG 해독기는 실제 세 트레이 자산의 무필터 행에서도 채널별 필터 계산과 픽셀별 포장을 수행했다. 기존 `RasterImage.from_png_bytes`에 무필터 RGB/RGBA 행의 채널 슬라이스 복사만 추가한다. 원본 자산·픽셀·알파, PNG 검증, 다른 필터, bilinear 크기 변경과 Tk 표시 순서를 유지하며 이미지 캐시는 추가하지 않는다. 품목·경로·파일 내용·표시 크기 변경과 숨김/오류 시 초기화는 기존 표시 함수가 계속 처리한다. vendored 원본 hash와 로컬 변경의 현재 hash를 구분하고 기존 writer inventory·소비자 pin도 맞춘다.

[근거와 비교 계획](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-IMAGE-OPTIMIZATION.md)의 승인된 원본 단회 headless 해독은200.2321ms였으며 실제 VM의383.64ms 미관측 구간 전체 원인이나 최종 UI 이득을 뜻하지 않는다. 정확한 네 자산 픽셀·RGB/RGBA와 필터·오류 거부·실제 표시 함수의 갱신/초기화·PHS 렌더러의 영향 검사22 PASS, 기존 writer inventory/pin 검사3 PASS를 보존한다. 이후 실제 Claude 검토와 동일 계측 native 전후 비교는 아래의 한정된 범위로 수용했으며 [CA-G12](BACKLOG.md#ca-g12)의 전체 목표 미완료 상태를 유지한다.

실제 Claude는 정확한 `2b5127b`의 [독립 소스 검토](D:/KMTech/optimization-implementation-20260909/COORDINATOR-RECOVERY-20260911-1144/ca-tray-decoder-review/REVIEW.md)를 PASS/필수 수정0으로 마감했고 Main이 수용했다. 원본/후보의2,822개 합성 이미지와29개 잘못된 입력, 실제 트레이 픽셀 및140개 source blob을 독립 대조한 범위다. 과거 E의 upstream artifact는 현재 없으며 원본 hash는 보존된 CA `e1b64f3` Git blob으로 확인한다.

이후 배정된 전용 VM의 동일 계측 원본9e→최종2b 단회 pair는 양쪽140 source·일반 로그인/held1/정상1/중복1/정상 저장 종료native0를 확인했다. 실제 KMC_LHD 해독은260.8662→7.5839ms, 기존 전체 이미지 함수는446.7746→217.4882ms였고 완전히 표시된378×138 RGB 픽셀은 동일했다. 응답 해제부터 완전한 이미지·정상001 결과1/3까지의 보수적 경계는0–1152.2920→0–560.2907ms이며, 지속 상태/누락 transient 없음 조건의 경계984.6079–1152.2920→300.0841–560.2907ms와 구분한다. 원본의 중앙 보류 수0 결함, 최종 후보의 일반002 부분 갱신 화면, 일반002 완전 결과 상한63.5051→155.8373ms도 그대로 기록한다. [원본86파일/48그림·계산·자원·한계](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-IMAGE-OPTIMIZATION.md)의 이미지 경로 단회 개선을 전체 UI 성능·p95·최초 안전 입력이나 종합0/6 완료로 해석하지 않는다. guest/수집 작업은13:38:56Z에 반환했고 실제 Claude 결과 검토는 제품·증거 필수 수정0이며, 문서R1에 따라 보고서 선두와 원인 분해를 교정해 전체1/3 가시 차이와 decoder 내부 구간의 이득을 분리했다. Main이 이 한정된 제품·증거 범위를 수용했다. [최종 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-PAIR-RESULT.md)와 [원래 Goal·M06 잔여 인계](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/REMAINING-GOAL-HANDOFF.md)를 따르며 전체0/6은 유지한다.

### 2026-09-11 원래 사용자 결과·연결 업무의 host 준비

수용된 decoder 단위와 문서R1을 유지하고, 원본9e/최종2b·기존50행 catalog·공통 observer/controller를 재사용하는 [유한 실행 설계](D:/KMTech/optimization-implementation-20260909/Container_Audit/remaining-goal-prep-20260911/PLAN.md)를 준비했다. 기존 CPU1,000/파일200 표본을 desktop 근거로 바꾸지 않는다. 새 native 설계는20쌍/40arm, AB/BA 각10쌍이며 입력→첫 의미 있는 표시, 정확한 내구·전체 표시, 실제 다음 접수의 상한을 분리한다. 경험적p95는20개 중19번째 값으로 꼬리 정밀도가 낮고, controller 대기 후 접수는 최초 허용 시각이 아니다. 새 SLA·회귀율은 만들지 않았다.

양쪽140 Git blob과 재사용 입력, 세 실행 파일의 경로만 바꾼 delta 및 parser를 host에서 확인했다. 관측기/제품 로직 변경·guest/서명/분포 실행은 없으며 Main의 실제 방법 검토·자원 배정 후 실행한다. 원8f7의 중복/다른 품목/보류·복원·exact3 봉인 근거는 원 버전 범위로 유지한다. 최종 연결 업무는 upstream의 실제 M06 NG→Rework GOOD→별도 수신 PHS2 GOOD1을 받아 정확한1개 봉인·Label·출하까지 이어야 한다. target1을 보류 시험용3개로 늘리거나 원901–904를 재생하지 않는다. [CA-G12](BACKLOG.md#ca-g12)의 전체 지연 개선·연결 완료와 종합0/6은 여전히 미완료다.

## 1. 기준과 증거 사용법

- 조사·작성일: **2026-09-07**, CA HEAD `2e7d9f70341015dacfc3495cb2c4aac027cbcb3e`, `main` / origin 대비 ahead 49. 당시 `tests/KNOWN-GAPS.md`, `tests/contracts/README.md`, `tests/test_capture_container_operator_ui.py`가 수정 중이고 `docs/capture_validator/`, `tests/capture_validator/`, `tools/validate_capture_bundle_v1.py`가 미추적이었다. HEAD만으로 이 작업 트리나 이전 실행 산출물을 식별할 수 없다. 시작 파일 목록·해시는 [보존 기준](E:/KMTech/spec-hub-build-20260907/Container_Audit/pre-state.json), 이번 문서 검토는 [작성 보고](E:/KMTech/spec-hub-build-20260907/Container_Audit/IMPLEMENTATION.md)에 연결한다.
- 기반 조사: [CA 연구](E:/KMTech/spec-hub-research-20260907/Container_Audit/RESEARCH.md), [소스 위치 색인](E:/KMTech/spec-hub-research-20260907/Container_Audit/SOURCE-MAP.tsv), [교차 의미 대조](E:/KMTech/spec-hub-research-20260907/hub-architecture/CROSS-PROGRAM.md). 아래 링크와 심볼은 현행 소스 또는 그 연구의 정적 확인 범위다. 전체 함수·모든 UI 분기·실제 설치 provider를 망라한 목록은 아니다. 계정 인계 후 기존 세 문서를 보존해 검토하고 운영·백로그를 보완했으며, [재개 시점 보존 목록](E:/KMTech/spec-hub-build-20260907/Container_Audit/resume-pre-state.json)에 문서 외 파일과 index 기준을 따로 남겼다.
- 상세 명세 기준선과 지속 갱신 규칙은 작성·로컬 정적 대조 후 **Main 교차 검토 수용 완료** 상태다. [교차 검토](E:/KMTech/spec-hub-build-20260907/cross-review/REVIEW.md)와 [중앙 S01](../../../Program_Spec_Hub/BACKLOG.md#specification)에 범위와 후속 보완을 연결한다. 기능별 **수용 기준**은 현행 계약에서 도출한 확인 항목이며, 새 사업 규칙이나 새 기능의 승인으로 해석하지 않는다. 요구 자체가 미정인 항목은 [백로그](BACKLOG.md)에 남긴다.

| 판단 축 | 이번 기준선의 판정·적용 범위 |
|---|---|
| 구현 | 아래 인용한 경로·조건의 존재를 정적으로 대조했다. 전체 기능 실행 성공을 주장하지 않는다. |
| 실제 연동 | 정적 송수신 계약 연결은 확인했으나 대상 설치본의 생산→중앙→소비 결과는 이 작업으로 입증하지 않았다. 기존 증거 적용 여부는 중앙 준비도에서 관리한다. |
| 수용 검증 | **NOT TESTED — 이번 문서 작업에서는 앱·테스트·VM·서버를 실행하지 않았다.** 이전 실행 결과를 대체하는 판정이 아니다. |
| 운영 준비 | 설치·실장비·재시작·재설치·롤백·통합 E2E의 정확한 환경별 근거는 [READINESS](../../../Program_Spec_Hub/READINESS.md)가 소유한다. 문서 완성과 별개다. |

**공유 capture validator의 한정된 소스 통합은 Main 수용 완료, Main 단일 커밋 수용 완료**다. [독립 소스 검토](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-independent/REVIEW.md)와 실제 h02의 **238 PASS / 714 ordered phase PASS, FAIL/ERROR/SKIP 0**을 [Main 소스 단위 판단](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/MAIN-DISPOSITION.md)에 연결한다. 원래 두 전체 모듈의 103+135개 선택, 실제 consumer subprocess·exit3·FAIL=0·organization pending 5개 조건과 source/config identity를 유지한 범위다. [이번 적용성 검토](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/PREPARATION.md)는 기존 9개 통합 경로와 admitted source를 대조하고 현재 문서 상태만 보완한다. 준비 워커는 새 실행이나 커밋을 하지 않았다.

[19:16 KST index 분석](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-index-forensic-prepare/MAIN-FORENSIC.md)의 469개 entry/TREE 동일·stat cache 71개 차이와 별도로, Main은 [현재 유한 비교](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-current-custody-prepare/MAIN-current-original238-READBACK.json)의 **7,809 guest·24 host 불일치 0**, 지정 identity 57개 inactive·9개 tree·2개 Ready task·원래 desktop 일치를 수용했다. 이는 고정한 집합/시점의 관측이며 지속적 무변경이나 장비 전체 무활동을 입증하지 않는다. 원래 h01/h02 controller·index byte/read-only 보존 및 최초 Main reader는 **FAILED**, 정확한 index writer와 속성 변경 원인은 **UNPROVEN**으로 남긴다. `closureReady`, `inputsPreserved`, `runtimeAcceptance`, `qualification`은 모두 false다. FULL·exact build/freeze·설치 업무·cold boot·재설치·롤백·실제 통합은 **NOT TESTED**이며 Ready를 올리지 않는다. 상세 범위와 다음 단계는 [CA-G07](BACKLOG.md#ca-g07), [KNOWN-GAPS](../../tests/KNOWN-GAPS.md), [중앙 준비도](../../../Program_Spec_Hub/READINESS.md)에 연결한다.

### 2026-09-08 FULL 실패 분석 후속

위 문서 기준선의 미실행 판정과 별도로, clean `11b4ac514f2c5d1bd012b9ac735bb01632f5ad30`에서 시작한 [FULL 실패 분석](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/REPORT.md)은 회수된 원본 JUnit·phase·stdout의 **102 FAILED / 2,526 PASSED / 31 SKIPPED, 총 2,659개**를 대조했다. 원래 pytest는 자연 종료 1이며 FULL·일반 export는 **FAILED**다. 25개 파일의 안정 표본 회수와 13,167개 expected pin 불일치 0은 전체 테스트 성공이 아니다. runtime에 추가된 `utf_8_sig.cpython-312.pyc` 한 파일도 제품 소스 손상으로 판정하지 않는다.

실패는 PS5 출력 decoding 81개, venv relay PID fixture 12개, commit 없는 Git 문맥 7개, 부분 고정 clock 1개, exact-executable fixture 1개로 분류했다. 마지막 fixture의 내부 실패 사유는 아직 **UNPROVEN**이다. 완료 재시도 두 사례는 host의 변경 없는 소스에서 1 FAIL/1 PASS, E의 clock fixture만 수정한 사본에서 2 PASS였으며 제품·assertion 수정이나 실제 서버/GUI 검증은 없다. [운영 근거](operations.md#ca-o07)와 [CA-G08](BACKLOG.md#ca-g08)에 제안·잔여 검증을 구분한다.

후속 [fixture/environment 후보](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)는 승인된 clock 패치, native Windows interpreter/venv 실행과 첫 assertion 전 cleanup 소유권, base executable 복사, strict UTF-8 PowerShell helper를 구현했다. 제품 코드·PID/hash/진단 수용 조건은 유지한다. 실제 초기 headless 경계 14 PASS와 authentic Git 문맥의 기존 7개 provenance 사례 PASS를 새 근거로 구분하며, 긴 E 경로에서의 계약 실행 실패와 잔여 검증도 후보 보고서에 보존한다. 2026-09-08 replay 계정의 새 검토자가 [독립 소스 수용·마감](E:/KMTech/ca-rp-0908/ACCEPTANCE.md)을 수행했다. 대상 FULL·설치·backend·GUI 검증은 수행하지 않았다.

최종 [short E/Windows venv 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03.xml)은 **204 PASS / 3 capability SKIP / FAIL·ERROR 0 (207개)**다. 원래 102개 실패 node 중 100 PASS·8.3 alias capability SKIP 2개이며, PID 12개와 Git 7개는 모두 PASS했다. [유한 child 관측](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03-children.json)은 기록된 relay PID 37개 중 active owned 0이다. 원래 FULL FAILED·guest codepage/원래 exact-artifact 내부 사유 미확인·대상 FULL NOT TESTED를 유지한다.

독립 검토는 원래 16경로 patch·후보 tree `6c5bf9bbf66bd3c53b765251c76607215083412c`와 481개 archive blob을 대조했다. focused 실행 후 변경은 위 세 명세의 상태 설명이며 실행한 제품·fixture·test blob은 동일하다. 이번 마감의 추가 변경도 같은 세 명세에 한정하므로 207개 focused 시험을 반복 실행하지 않고 기존 host 근거의 범위를 유지한다. 실제 successor commit/tree·bundle/archive·바이트 비교는 [마감 근거](E:/KMTech/ca-rp-0908/SUCCESSOR-MANIFEST.json), 새 대상의 207개 선택과 별도 FULL 요건은 [대상 인계](E:/KMTech/ca-rp-0908/TARGET-HANDOFF.md)에 연결한다. 소스 마감은 대상 수용이나 운영 준비 상승이 아니며 **Ready 0/6**을 유지한다.

2026-09-08 Main이 수용한 `e1db07a9de60564f6bc92d1f52d0332d459d1361`/tree `4271b456449b23810d6302b2865974cac4080fa7`의 **대상 실행 packet 준비**는 [최신 준비 보고](E:/KMTech/ca-target-rp-0908/REPORT.md)에 연결한다. guest E 드라이브를 가정하지 않고 VM01의 짧은 `C:\Qualification\ca207\s`와 별도 `C:\Qualification\cafull\s`를 바인딩했다. source481·genuine Git·신선한 provider admission, 정확한 207 node와 조건부 FULL `tests`, 유한 native child/진단 export 및 Main 독립 readback control을 E에서 준비·host fixture 검증했다. 이번 작업의 제품 시험·VM 접속은 **NOT TESTED**이며 기존 207개 host 시험도 재실행하지 않았다. 실행 입력은 위 커밋의 모든 문서를 포함한 481개 blob으로 동결하고, 현재 세 명세의 준비 상태 설명은 별도 미커밋 문서 차이로 남긴다. 원래 실패와 **Ready 0/6**은 유지한다.

Main의 별도 cleanup 지시에 따라 기존 pytest 소유 24개 identity를 확인하고 interpreter 12개를 외부 종료했다. abort 제어의 launcher 재확인 실패는 보존하며, [독립 최종 readback](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/CLEANUP-RESULT.md)이 **24개 부재·descendant closure empty·원래 Explorer 불변**을 입증했다. VM01 정리와 제품 준비도는 별개이고 FULL 재실행·build·설치·통합 수용은 이 작업에서 수행하지 않았다.

### 2026-09-08 VM01 target207 실행 실패와 후속 실행 준비

[실제 실행 보고](E:/KMTech/ca-execution-rp-0908/REPORT.md)는 replay121678/Fast OFF에서 위 동결 `e1db07a9`의 새 Support **8,539개·stable·불일치0**, genuine source481 Stage, 독립 MainStage **13,665개·PROVEN/stable**을 기록한다. 원래 17 selector의 정확한 **207개 ID를 순서대로 수집**했으나 첫 uninstall fixture 두 사례가 임시 packet의 `INSTALL_CANONICAL_PORTABLE.ps1` 수정에서 `PermissionError`로 실패했다. 원래 `--maxfail=2`에 따라 **0 PASS / 2 FAIL / 0 SKIP, 205개 미실행**이며, capability skip 사유는 이번 실행에서 관측되지 않았다. owner/pytest는 자연 종료1, controller/supervisor는 2다. 과거 host204 PASS/3 SKIP을 새 대상 결과로 승계하지 않는다.

실패용 Export는 **45/45개·9,218,869바이트·stable·누락/overflow0**를 보존했다. 독립 [MAIN-Full](E:/KMTech/ca-target-rp-0908/focused/logs/MAIN-Full.json)은 controller의 실제 image 필드가 `null`이어서 `Base controller argv differs`로 **FAILED**이고 `actual=null`이다. 위 207개/2실패 집계는 회수된 collection·phase·JUnit·actual-result의 별도 진단이며 Main 수용값이 아니다. 마지막 02:47:18.8988799Z 표본은 **13,666개 대조 불일치0·원래81 identity inactive·잔여 lane0·recorded child0**다. 조건부 FULL은 시작하지 않았다.

작은 수정은 [fixture](../../tests/test_zero_touch_installer.py)의 7개 `copy2`를 `copyfile`로 바꾸어 동결 원본 바이트·읽기 전용 속성을 유지하면서 의도적으로 수정하는 임시 복사본만 쓰기 가능하게 한다. [새 회귀](../../tests/test_portable_fixture_source_permissions.py)는 기존 17 selector 밖의 별도 모듈이며 host **RED 1 FAIL → GREEN 1 PASS**, 실제 다른 바이트로 수정하도록 보강한 최종 회귀도 **1 PASS/0.22초**다. 기존 두 영향 사례는 **2 PASS/31.64초**, 기록 relay6개 부재다. 실제 retained handle에서 image를 조회하는 별도 제어 후보의 PS5/PS7 host 검증도 보고서에 연결하며 기존 source·archive/bundle·소비된 제어와 실패 증거는 보존한다.

Main은 두 수정 방식의 독립 검토를 수용했고, [새 genuine Git 후보](E:/KMTech/ca-execution-rp-0908/successor/SUCCESSOR-MANIFEST.json) `68dd0c520ed2b8bd585301999cb35624702a05a5`/tree `5960560260eb3a6226b419cfa24493c154757be0`의 **482개 blob**을 별도 E 사본에 마감했다. [후속 packet](E:/KMTech/ca-execution-rp-0908/successor/PREPARED-INPUTS.json)은 새 `C:\Qualification\ca207n\s`와 조건부 `C:\Qualification\cafulln\s`에 같은 소스를 결속하고, 기존 실패 lane의 564개 파일 pin·실패 task 결과2·총85개 과거 identity를 보존 조건으로 추가했다. 원래 207개 선택과 FULL `tests`·성공 조건은 유지했고 준비 이후 실제 결과는 아래에 구분한다. 이 준비 시점의 C 저장소 HEAD는 `e1db07a9`이고 수정은 미커밋 상태였다. E 후보에는 마감 당시 세 명세도 포함되며 그 뒤의 상태 설명은 별도 문서 차이다.

Main의 후속 배정으로 실행한 `ca207n`의 실제 결과는 **207 PASS / FAIL·ERROR·SKIP 0, 296.59초**다. 원래207 선택·실행 순서·621 phase가 모두 완료됐으며 과거 host3 capability SKIP을 승계하지 않았다. [독립 MAIN-Full](E:/KMTech/ca-execution-rp-0908/successor/packets/focused/logs/MAIN-Full.json)은 **PROVEN/stable**, sourceTestsPassed·controlsPassed·processClosure를 확인했고 14,231개 guest 파일과 기록 child42개 부재를 대조했다. 출력45/45개·9,972,263바이트는 누락0이다. 실제 controller image도 정확한 guest Python 경로로 관측됐다. 이 성공 조건을 Main에 보고한 뒤 별도 `cafulln`의 새 Support·source482 Stage·독립 MainStage가 통과했고 전체 `tests` 실행을 시작했다. 이 시점에는 **새 FULL이 진행 중**이었고 이후 실제 결과는 아래 회수 절에 기록한다. source 시험은 설치·GUI·운영 준비를 뜻하지 않는다. 원래 두 실패 실행과 보존 FAILED, **Ready 0/6**을 유지한다.

### 2026-09-08 긴급 정지 후 재개·정확한 소스 통합

[재개 보고](E:/KMTech/ca-resume-0908/REPORT.md)는 사용자 긴급 정지와 복원을 제품 실패와 구분한다. 실제 C 저장소를 수용된 `68dd0c520ed2b8bd585301999cb35624702a05a5`/tree `5960560260eb3a6226b419cfa24493c154757be0`로 fast-forward했고 기존 두 test 파일이 이 커밋과 일치한다. 이전 작업 트리와 더 최신인 세 상태 문서는 E 사본·범위를 한정한 Git stash로 보존했다. 위의 C HEAD `e1db07a9`·미커밋 설명은 후보 준비 당시 이력이며, 실행에 사용한 E 후보·bundle/archive·제어는 변경하지 않았다.

수용된 focused207은 재실행하지 않았다. 사용자 정지로 사라진 원래 host 실행기의 자연 종료·완전한 외부 stream과 supervisor의 외부 retained-native 종료는 **UNPROVEN**으로 보존한다. 응답 없는 새 읽기 세 건은 정확한 host 관측기만 종료했고, Main의 VM 메모리 상한 조정 후 다른 관측에서 기존 결과를 회수했다. 실제 할당 증가를 관측하지 않았으므로 메모리가 지연 원인이나 해결책이었다는 인과 관계는 **UNPROVEN**이다.

원래 `cafulln`의 전체 `tests` 결과는 **2,638 PASS / 31 SKIP / FAIL·ERROR 0, 648.87초**, 실제 collection/JUnit **2,669개·7,976 phase**다. 원래 파일은 04:29:24Z까지 작성됐으며 새 FULL은 실행하지 않았다. [회수·독립 결과](E:/KMTech/ca-resume-0908/MAIN-Full.json)는 **PROVEN/stable**의 범위를 source test·guest 제어·실제 custody로 한정한다. 출력45/45개·15,368,109바이트, 14,231개 input 대조 불일치0·metadata 문제0, 05:05:04.1286232Z의 task Ready/exit0·remainingLane 없음·기록 child42개 부재를 확인했다. owner/controller는 자연 종료0이며 supervisor의 보고 종료0과 외부 native 종료 미입증을 구분한다. VM01은 Main에 반환했고 Main이 수용했다.

31개 SKIP은 guest에 없는 Windows E-drive 경로 조건이다. 같은 source68dd에서 이 **정확한 31개 ID만** host의 소유 E 경로로 실행한 [별도 JUnit](E:/KMTech/ca-n31/runs/e8006c0e57/junit.xml)은 **31 PASS / FAIL·SKIP 0, 27.14초**다. guest SKIP을 소급 변경하거나 이 fixture 시험을 실제 앱 build 성공으로 해석하지 않는다. 원래 FULL의 native subprocess UTF-8 decode 관련 thread 경고6건과 과거 실패를 보존한다.

Main이 기존 source 공개키와 CPython3.12.10 x64 경로를 배정한 뒤 같은 source68dd의 [실제 portable build](E:/KMTech/ca-build-0908/build-result.json)는 **exit0/9.688초**로 완료됐다. exact dependency7개·writer inventory·묶인 runtime의 isolated import closure, PE46개 전부 Valid/unsigned0, 기존 canonical PlanOnly·helper DryRun을 통과했다. [ZIP](E:/KMTech/ca-build-0908/Container_Audit-68dd0c52-portable.zip)은17,156,131바이트·SHA256 `b8dcd72c0205201eadda5a93d531a767e7ff9552b8519067468d1bfb7de84b40`, 2,283개 파일이며 CRC와 포함 manifest 일치도 확인했다. 첫 PlanOnly의 host 모듈 autoload 실패는 보존했고 기존 repository runner와 같은 Windows PowerShell module 경로를 자식 환경에만 적용한 재검사는 성공했다. source/key/trust·제품 동작은 바꾸지 않았다. [설치 인계](E:/KMTech/ca-build-0908/INSTALL-PREPARATION.md)에 정확한 후보와 다음 Main 배정 조건을 기록한다. **실제 설치·GUI·복구·rollback·통합은 NOT TESTED**, signed feed/키 회전 호환은 UNPROVEN이며 **Ready 0/6**이다.


### 2026-09-08 새 복사 VM의 일반 설치 실패·정상 recovery 후속

위 빌드 당시 미실행 상태 이후, 같은 ZIP/source68dd를 배정된 `KMTech-CA-Qualification-20260908-01`에 전송해 해시 일치·guest PlanOnly·기존 `kmadmin`의 session1/medium integrity·개발 backend의 CA-verified HTTPS200/sourcec04343ce를 확인했다. [첫 일반 설치 원본](E:/KMTech/ca-install-qualification-20260908/REPORT.md)은 실제 top-level canonical 경로와 guest UAC를 사용했으며 코드 배치는 **PROVEN / PASS_NEW_VERIFIED**, 등록은 **FAILED / producer_identity_conflict**다. 06:46:26Z canonical exit1·`FAILED_ROLLED_BACK`으로 종료했고 GUI 업무는 시작하지 않았다.

초기 로컬 등록 자료 6종은 모두 ABSENT였지만, 현행 설치 식별자는 MachineGuid+현재 사용자 SID+app에서 파생된다. VM 복사본·새 Hyper-V ID·빈 앱 폴더만으로 중앙의 새 장치가 되지는 않는다. 새 possession key의 자동 등록을 서버가 거부했고, Main이 기존 epoch6 소유를 이 guest에 배정한 뒤 정상 관리자 recovery와 별도 operation grant로 epoch7을 등록했다. 같은 frozen 후보의 후속 canonical은07:03:06Z **exit0/PASS, REUSED_VERIFIED, READY/REUSED**다. 첫 실패를 fresh PASS로 바꾸지 않는다.

실제 ordinary GUI에서 작업자 등록·작업 시작은 성공했다. 첫 PHS2는 NG 소유 구성원이 섞인 work group 때문에07:17:05Z `PHS_WORK_GROUP_SOURCE_NOT_AVAILABLE`로 거부되어 내구 `LOOKUP_FAILED` hold를 남겼다. Main이 승인한 QA용 정상 보호 관리자 설정·GUI 인증 후 제품의 격리 경로로 원본 hash를 유지했다. 유효한 case02는 ordinary worker로 목표2·부분 제출 거부·중복 거부·보류/정상 앱 재시작/동일 snapshot 복원을 통과하고 정확한2개 GOOD로 로컬 `TRAY_COMPLETE`/`LINKED`를 기록했다. 실제 seal은07:46:27Z Web 전역 JSON validator의 `INVALID_INPUT`으로 `OPERATOR_REVIEW`/attempt1이며 중앙 ACK가 없다. 이벤트 업로드의 성공과 별개다.

새 code가 남는 첫 실패의 상태 혼동은 source `35a0883`에서 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`와 경고로 바로잡고 신규 fresh 실패 회귀1·기존 교체 복원 회귀1 및 기존 inventory check PASS를 확인했다. 원래 frozen68dd ZIP에는 이 수정이 없으며 과거 full 결과를 수정 소스에 승계하지 않는다.

**09:31Z 후속:** 관리자 재시도와 inventory pin 수정이 포함된 별도 source `a7d714f6` 후보는 같은 guest의 정상 canonical 교체로08:49:23Z PASS/REPLACED_VERIFIED다. 실제 관리자 메뉴에서 case02 원 명령을09:21:22Z 재전송해 **ACKED/attempt2**, 원 완료 시각·명령 hash·로컬 완료1·검토 이력1을 유지했다. [Web 독립 조회](E:/KMTech/web-integration-20260908/ca-original-retry-central-readback.json)는 중앙 receipt1·원 lease 소비·같은2개 구성원을 확인했고 Main 수용 뒤 Label에 정상 생성 QR 파일과 bundle 소유를 인계했다. 새 case04는 목표3·일반 취소/재스캔·전량 완료 후 **ACKED/attempt1**이며 [로컬 두 영수증](E:/KMTech/ca-install-qualification-20260908/case04-seal-public-results-02.jsonl)과 [일반 완료 화면](E:/KMTech/ca-install-qualification-20260908/guest-case04-complete.png)을 보존했다. case03은 미착수 만료 lease와 정상 보류 자료를 유지하며 Main이 조정 custody를 맡는다. cold boot·제거/재설치·적용 가능한 exact rollback은 계속 검증 중이다. [계약](contracts.md#ca-c10), [환경·명령·복원 범위](operations.md#ca-o09), [CA-G09](BACKLOG.md#ca-g09). 종합 Ready 판정은 Main의 별도 수용이다.

**11:55Z 최신 실제 후속:** 별도 frozen source `d440b1f7`의 정상 교체로 새 receipt를 만든 뒤 원 owner 종료·cold boot를 거쳐 공개 canonical Restore09가 native/task0, **PASS_RESTORED_VERIFIED_DATA_PRESERVED**다. exact old a7·원 Run/relay·업무9/identity3와 historical68dd를 유지했고 failed-new d440을 보존했다. 취소07/동의 미관측08의 native1 실패는 그대로 남긴다. 복원된 ordinary a7 GUI에서 새 F4 target GOOD2가11:43:40Z **ACKED/attempt1**이며 완료3·전송 대기0이다. Web의 독립 receipt1/exact2 확인 뒤 Label/Web에 bundle을 명시 인계했고, 마지막 복원 후 cold boot의 자동 relay·세 ACKED/업무/identity 보존 및 전송30건 acked를 확인한 VM은 정상 Off로 Main에 반환했다. 실제 화면 보류는 기존 일반 보류1+격리1의 **2건**으로 이전 요약을 정정했다. [정확한 source·receipt·실행 범위](operations.md#ca-o09), [보고서](E:/KMTech/ca-install-qualification-20260908/REPORT.md), [남은 범위](BACKLOG.md#ca-g09)를 따른다. 새 FULL·강제 crash·실장비 검증이나 종합 Ready 판정은 이 결과에 없다.

### 2026-09-08 최종 d440의 별도 fresh-app 대상 수용

Main이 배정한 별도 `c029c9d7-1061-4676-92f7-5307cf3d80de` / `KMTech-CA-Final-Qualification-20260908-01`에서13:23:49Z 실제 코드·CA 사용자/identity 자료·DirectSync·Run·relay·CA task 부재를 확인했다. 기존 frozen d440 ZIP17,162,800B/SHA `6c5a07b5b6122c82c1e51d3ff3ab335c5697320b664e1ee67666245645175493`와 manifest `bb2825f36d5659a40f6ee1275f0a74d66de70651593400d342e041ef0408c3e7`를 사용했다. 복사 OS 식별자를 유지한 최초 ordinary Install01은 실제 producer 소유 충돌로 **native1 / FAILED_RUNTIME_RESTORED_CODE_RETAINED**였으며 원본13파일을 보존한다. Main/Web의 지원 recovery는 제품이 실제 만든 current_user key를 재사용해 **epoch8 / native0**, 후속 Install02는 **native/task0 / PASS·REUSED_VERIFIED**다. Web은 기존97 receipt ID·full row hash/rowid 보존을 독립 확인했다. 이 결과를 무지원 fresh 중앙 등록 PASS로 해석하지 않는다.

기본 launcher의 실제 첫 작업자 `CA-FINAL-QA` 등록·작업 시작, 정상 Off→boot 후 자동 ordinary relay와 저장 작업자 재시작, canonical 제거/재설치 각각 **native/task0** 및 재설치 후 기본 GUI를 확인했다. 정상 close 후의 작업자·설정2파일과 producer identity/credential/manifest3파일은 cold boot와 제거/재설치에서 byte/hash가 일치한다. Windows servicing의26200.8037→9168 변화와 재설치가 새로 만든 integrity record는 별도로 기록했다. 최종 VM은14:43:14Z **정상 Off/uptime0**로 Main에 반환했으며, 현재 요청의 native qualification은 완료다. [실행 보고서](E:/KMTech/ca-final-qualification-20260908/REPORT.md), [정확한 후보·수용·실패 범위](operations.md#ca-o10), [남은 제품 경계](BACKLOG.md#ca-g10)를 따른다. 물리 장비·공장 배포·전체 Ready 판정은 이 완료에 포함하지 않는다.

기존 a7 업무/lifecycle와 d440→a7 공개 Restore09는 원래 candidate·receipt·VM 범위에서 유지한다. Main은 새 VM이라는 이유만으로 같은 교체/복원 cycle을 반복하지 않도록 명시했다. 제품 소스는 변경하지 않았고 테스트·빌드는 재실행하지 않았으며, 새 실패나 관련 동작 변화가 있으면 해당 범위만 다시 판단한다. 이전 fresh 등록 실패·취소·동의 미관측·case03 custody와 F4 downstream 소유권도 그대로 보존한다.

## 2. 사용자·제품 경계와 지원 경로

이적 작업자는 본인 이름을 선택하고 현품표와 제품을 스캔하며, 보류·복구·오류 인계를 수행한다. 관리자는 보호 관리자 기능과 승인된 설치·운영 조치를 담당한다. 작업자 이름 선택은 서버 인증이 아니다. 시작·인증 경계는 [ContainerAudit.start_work / _resolve_worker_login_candidate](../../Container_Audit.py), [protected_admin.py](../../protected_admin.py)에 있다.

CA는 검사 GOOD/NG를 재판정하지 않는다. 검사 완료 구성원은 [Inspection의 _complete_linked_normal_session](../../../Inspection_worker/core/business_logic.py), 제품 소유·위치·버전·멱등 receipt 정본은 [Web logistics ledger](../../../WorkerAnalysisGUI-web/logistics_ledger/service.py), 포장 확정은 [Label package_logistics](../../../Label_Match/package_logistics.py)가 담당한다. ERPnext는 별도 제품이며 그쪽 스캔 요구나 한도를 CA에 적용하지 않는다. 이들 프로그램 전체가 항상 단일 직렬 공정으로 실행된다는 가정도 하지 않는다.

| 지원 구분 | 진입점·조건 | 현재 경계·근거 |
|---|---|---|
| 기본 작업 | `Container_Audit.py:main` → `start_work` → 원본 exact PHS2 | 중앙 registry·GOOD 목표·lease 확인 후 제품 전량 검사. [CA-03](#ca-03), [CA-07](#ca-07) |
| 배포 진입 | canonical portable 설치 후 [launch-container-audit.cmd](../../portable/launch-container-audit.cmd) | 현재 사용자 onboarding과 relay, 보호된 코드 루트. 소스 실행과 패키지 실행의 동일성은 별도 확인. [운영](operations.md#ca-o01) |
| 조건부 제품 교체 | 봉인 전 현재 트레이의 교체 UI | capability·버전·동일 품목/UOM·단일 구성원 공여 PHS 조건. [CA-10](#ca-10) |
| 조건부 현품표 정합 교체 | F8·중앙 후보 선택 | 중앙 journal·Windows 출력·활성화. Shift-F8에는 legacy single fallback 진입이 남아 있다. [CA-11](#ca-11), [ContainerAudit.__init__](../../Container_Audit.py) |
| 호환·시험 | 비compact 현품표/13자리 품목 코드, 과거 부분 제출·교환 분기 | `_process_barcode_logic`와 `submit_current_tray` 등에 코드가 남아 있다. 이를 표준 PHS2 부분 제출 허용으로 해석하지 않는다. 현장 지원 범위 재확인은 [CA-G03](BACKLOG.md#ca-g03). |
| 내부 시험 명령 | `enable_internal_test_commands`가 허용된 개발 실행 | 기본 설정 false, frozen 실행에서는 설정을 제거한다. `_RUN_AUTO_TEST_`, `TEST_LOG_…`는 일반 운영 입력이 아니다. [설정 템플릿](../../config/container_audit_settings.json), `_drop_release_disabled_settings` |
| 관리용 host 모드 | `--container-audit-direct-sync-relay`, `--container-audit-user-relay`, `--onboard-current-user`, `--remove-current-user-setup`, `--restore-current-user-lifecycle-after-replacement` | [dispatch_product_mode](../../container_audit_product_host.py)의 비GUI 경로. 작업자 트레이 기능과 구분한다. |
| 퇴역 운영 경로 | Syncthing / `C:\Sync` | HTTPS direct-sync 운영 저장소에서 제외하며 해당 data root를 거부한다. `legacy`라는 이름의 모든 코드가 폐기됐다는 뜻은 아니다. [storage_policy](../../storage_policy.py), [전송 정책](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md) |

## 3. 정상 흐름과 중단 지점

1. 시작 계약·단일 인스턴스·현재 사용자 준비·품목 갱신 후 작업자를 선택한다. 미완성 onboarding이나 저장 경로 충돌은 시작 실패로 처리한다. [main / _prepare_gui_startup](../../Container_Audit.py), [current_user_onboarding](../../current_user_onboarding.py)
2. 원본 PHS2를 입력한다. 중앙 조회 중 먼저 들어온 제품은 내구 FIFO에 보류한다. 조회 실패 시 같은 PHS2로 재시도하며 다른 현품표로 보류를 덮어쓰지 않는다. [CA-03](#ca-03), [CA-04](#ca-04)
3. 중앙 GOOD 목표만큼 제품을 읽는다. 형식·품목·중복·초과 오류는 증가 완료로 처리하지 않는다. 마지막에는 barcode↔unit 집합과 lease 구성원을 정확히 대조한다. [CA-05](#ca-05), [CA-07](#ca-07)
4. 완료 intent·로컬 `LINKED`·완료 checkpoint를 보존하고 불변 명령을 중앙에 재전송한다. 로컬 완료 ID가 없는 미확정 트레이와 이미 로컬 완료된 중앙 대기 건은 UI 허용 행동이 다르다. [CA-12](#ca-12)
5. 운영 이벤트는 별도 relay가 업로드한다. 중앙 이적 구성원의 포장 소비는 Label의 `PACKAGE_SOURCE` 조회로 이어진다. producer ACK나 대시보드 실적만으로 다음 물류 명령을 확정하지 않는다. [CA-C05](contracts.md#ca-c05), [CA-C06](contracts.md#ca-c06), [CA-C07](contracts.md#ca-c07)

작업 중 수정은 취소·리셋·보류 UI로 처리한다. 통신 실패, 로컬 저장 실패, 중앙 충돌, 출력 불확실은 각각 다른 복구 대상이다. 현품표·실물·작업 ID와 원본 상태를 보존하고 [장애 인계 표](operations.md#ca-o04)를 따른다. 이 문서는 미확정 상태를 무시한 실물 이동을 승인하지 않는다.

## 4. 기능 목록과 상세 카드

| 안정 ID | 업무·대표 심볼 | 관련 계약 |
|---|---|---|
| [CA-01](#ca-01) | 시작·작업자 선택: `main`, `start_work` | [CA-C01](contracts.md#ca-c01) |
| [CA-02](#ca-02) | 품목 준비: `refresh_item_catalog`, `load_items` | [CA-C08](contracts.md#ca-c08) |
| [CA-03](#ca-03) | exact PHS2 조회: `TransferSourcePreflight` | [CA-C02](contracts.md#ca-c02) |
| [CA-04](#ca-04) | 조회 중 입력 보존: `_hold_scan_during_preflight` | [CA-C01](contracts.md#ca-c01) |
| [CA-05](#ca-05) | 제품 스캔: `decide_product_scan` | [수량·입력](contracts.md#ca-data) |
| [CA-06](#ca-06) | 순번·시간·수량 표시: `build_scan_ok_detail` | [수량·입력](contracts.md#ca-data) |
| [CA-07](#ca-07) | 전량·lease 대조: `_map_scans`, `_verified_operation_lease` | [CA-C03](contracts.md#ca-c03) |
| [CA-08](#ca-08) | 취소·리셋: `undo_last_scan`, `reset_current_work` | [CA-C01](contracts.md#ca-c01) |
| [CA-09](#ca-09) | 보류·재시작: `park_current_tray`, `_load_current_tray_state` | [CA-C01](contracts.md#ca-c01) |
| [CA-10](#ca-10) | 봉인 전 제품 교체: `TransferMemberExchangeCoordinator` | [CA-C04](contracts.md#ca-c04) |
| [CA-11](#ca-11) | 현품표 정합·출력: `PHSReconciliationExchangeCoordinator` | [CA-C09](contracts.md#ca-c09) |
| [CA-12](#ca-12) | 로컬 완료·중앙 재확인: `complete_tray`, `TransferSealCoordinator` | [CA-C03](contracts.md#ca-c03) |
| [CA-13](#ca-13) | 전송·상태: `enqueue_completed_source_file`, `drain_one_relay_batch` | [CA-C05](contracts.md#ca-c05), [CA-C07](contracts.md#ca-c07) |

13개는 핵심 업무를 묶은 탐색용 ID이며 기능 총수·완성도 분모가 아니다. 세부 관리자 창, 모든 legacy 교환 분기, 전체 설치 옵션, 장시간 실장비 특성은 추가 조사 대상이다. 각 카드의 담당은 CA 개발 역할이며 교차 계약은 명시된 상대 프로그램 담당과 협업한다. 네 판단 축의 이번 공통 범위는 §1을 적용한다.

<a id="ca-01"></a>
### CA-01 시작·작업자 선택

- **일반 창 배치:** 기본 복원 크기 `1280x820`과 최소 `1024x720`은 해당 monitor의 작업 영역에 실제 client+frame이 들어가는 범위에서 유지한다. 일반 초기화는 같은 UI thread의 `GetWindowRect`·`GetClientRect`·`GetMonitorInfo.rcWork`로 최소/복원 크기를 먼저 맞춘 뒤 기존 최대화 시작을 유지한다. 명시적 `CONTAINER_AUDIT_STARTUP_GEOMETRY`의 signed absolute 배치는 별도 기존 경로다. [화면 수용 범위](operations.md#ca-o03)를 함께 따른다.

- **시작·입력:** 소스/패키지 진입 후 등록된 작업자 이름 또는 보호 관리자 로그인. `main`의 계약 확인·단일 인스턴스·onboarding 준비와 `start_work`가 경계다. [Container_Audit.py](../../Container_Audit.py), [runtime_instance.py](../../runtime_instance.py)
- **검증·저장·결과:** 이름 등록과 보호 관리자 인증을 구분하고 사용자 상태 경로를 준비한다. 복구 대상이 있으면 현재 트레이 복구 흐름으로 진입한다. 작업자 선택만으로 서버 권한을 만들지 않는다. [worker_registry](../../worker_registry.py), [current_user_onboarding](../../current_user_onboarding.py)
- **실패·취소·재시작:** 중복 실행, 부분 onboarding, 읽기 불가능한 보호 상태는 오류를 보존해 진입을 중단한다. 임의 초기화 대신 동일 사용자·원본 상태의 복구 가능성을 확인한다.
- **수용 기준:** 정상 사용자로 준비된 상태를 재사용하고, 불완전 준비·중복 실행을 성공 화면으로 넘기지 않으며, 재시작 후 작업자와 트레이 소유권을 잘못 연결하지 않는다.
- **연결·남은 일:** [CA-C01](contracts.md#ca-c01), [운영 진입](operations.md#ca-o01), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05). [CA-O09](operations.md#ca-o09)는 frozen source68dd의 실제 ordinary 사용자 시작·작업자 등록·QA 보호 관리자 인증 및 WORKER로 복귀를 증명한다. 다른 설치본/사용자 환경에 자동 승계하지 않는다.

<a id="ca-02"></a>
### CA-02 품목 기준 준비

- **시작·입력:** 시작 시 중앙 `/inbound/api/item-catalog.csv`를 갱신하고 검증된 snapshot을 사용한다. [refresh_item_catalog](../../item_catalog_sync.py), [ContainerAudit.load_items](../../Container_Audit.py)
- **공유 core:** `item_catalog_sync` facade가 고정 `kmtech_shared.catalog`의 4열 검증·sidecar 이름·canonical JSON·authority/HMAC 판정을 호출한다. CA의 경로·URL 승인·신원·진단·snapshot·내구 write/recovery 순서는 그대로 소유한다. [CA-C08](contracts.md#ca-c08), [pin·패키징](operations.md#ca-o01).
- **검증·저장·결과:** 검증 캐시와 startup diagnostic을 보존한다. 검증 snapshot이 요구되는 경로에서 snapshot을 잃거나 파싱에 실패하면 오류이며, 무조건 패키지 `assets/Item.csv`로 성공 처리하지 않는다. legacy 파일 경로의 인코딩 fallback과 구분한다.
- **실패·취소·재시작:** 통신·CSV·cache 오류를 진단 사유와 연결한다. 캐시 허용 여부는 `refresh_item_catalog`의 실제 분기를 따르며 임의로 낡은 품목을 정본으로 선택하지 않는다.
- **수용 기준:** 품목 코드·명칭·규격이 검증된 동일 snapshot에서 읽히고, 갱신 실패와 파싱 실패 시 허용/중단 결과가 계약과 일치해야 한다.
- **연결·남은 일:** [CA-C08](contracts.md#ca-c08), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05). 운영 캐시 신선도 목표와 실제 장애 복구 증거는 미정/미확인이다.

<a id="ca-03"></a>
### CA-03 원본 exact PHS2와 중앙 preflight

- **시작·입력:** 제품보다 먼저 `PHS/SRC/ITG/CLC/LBL/HSH`의 정확한 6필드 PHS2를 스캔한다. `QT` 추가·필드 누락·중복을 거부하고 `ITG/LBL/HSH`를 중앙 registry와 맞춘다. [TransferSourcePreflight 및 compact 검증](../../transfer_seal.py)
- **검증·저장·결과:** 품목·UOM·현재 GOOD member와 operation lease를 검증한 결과를 트레이 상태에 연결한다. 목표는 중앙 GOOD 구성원 수이며 60으로 추정하지 않는다. [ContainerAudit._begin_compact_phs2_preflight / _process_barcode_logic](../../Container_Audit.py)
- **실패·취소·재시작:** 조회 실패면 새 트레이 성공으로 전환하지 않는다. 조회 중 입력은 [CA-04](#ca-04)로 보존하고 같은 현품표로 재시도한다. lease·identity가 맞지 않으면 완료를 허용하지 않는다.
- **수용 기준:** 잘못된 6필드·다른 label/hash·불일치 구성원을 차단하고, 실제 중앙 GOOD 수가 표시 목표와 완료 대조의 기준이 되어야 한다.
- **연결·남은 일:** [CA-C02](contracts.md#ca-c02), [CA-G03](BACKLOG.md#ca-g03), [CA-G04](BACKLOG.md#ca-g04). [CA-O09](operations.md#ca-o09)의 actual case01은 NG 소유가 포함된 source를 거부했고 case02는 정상 GOOD2 목표를 표시했다. 이는 지정된 Web sourcec04343ce/guest68dd의 관측이며 [preflight 회귀 소스](../../tests/test_phs2_master_preflight.py) 자체는 실행 결과가 아니다.

<a id="ca-04"></a>
### CA-04 중앙 조회 중 빠른 입력 보존

- **시작·입력:** `_master_preflight_pending` 동안 Enter로 접수된 스캔을 현재 PHS2에 묶어 내구 FIFO에 넣는다. [process_barcode / _hold_scan_during_preflight](../../Container_Audit.py), [preflight_scan_hold.py](../../preflight_scan_hold.py)
- **검증·저장·결과:** `LOOKUP` → `DRAINING` 또는 `LOOKUP_FAILED` 상태와 순서를 snapshot에 남긴다. 보류 접수 확인 뒤 입력창을 정리하며 성공 조회 뒤 순서대로 정상 제품 검증에 넘긴다.
- **화면 최신성:** 보류 저장 성공을 받은 같은 UI callback에서 중앙 안내의 보류 수를 해당 snapshot에 맞춘다. 조회 실패 snapshot은 `중앙 조회 실패`와 남은 개수(0건 포함)를 표시하며, 조회 중 문구나 새 현품표 입력 안내를 남기지 않는다. 표시 갱신은 저장·FIFO·입력 제한을 변경하지 않는다.
- **스캔당 처리:** 새 held 성공은 같은 동기 호출에서 catalog 판정을 한 번 검색해 재사용한다. router와 기본 형식·품목·중복·용량 gate는 다시 확인하며 판정은 callback 밖에 보관하지 않는다. 이미 내구 접수된 head의 감사 재시도는 재검색/목록 재추가 없이 원 receipt를 대조한다.
- **실패·취소·재시작:** 쓰기 실패·가득 찬 보류·context 불일치를 성공 접수로 표시하지 않는다. 실패 조회는 보류0건이어도 다른 현품표·작업자 변경을 차단한다. 같은 현품표 재조회와, 인증된 보호 관리자가 원본을 복원 가능한 격리 목록으로 옮기는 경로를 구분한다. 일반 작업자에게 임의 삭제/취소 경로는 없다. `quarantine`, `restore_quarantined`, `_restore_preflight_scan_hold`, `_quarantine_preflight_hold_for_supervisor`가 담당한다.
- **수용 기준:** 조회 지연·실패·프로세스 종료 뒤 같은 현품표로 돌아오면 접수된 순서와 개수가 보존되고, 미접수 입력은 작업자에게 구별되어야 한다.
- **연결·남은 일:** [CA-C01](contracts.md#ca-c01), [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06). 최대 연속 입력 요구·실측 처리량은 정해지지 않았다.

<a id="ca-05"></a>
### CA-05 제품 바코드 검사

- **시작·입력:** 활성 트레이에서 제품 문자열을 스캔한다. GUI는 외곽 공백을 `strip()`하고, `decide_product_scan`은 전달값의 길이·제어문자·수식/HTML/경로 위험 형식·품목 포함·중복·용량을 검사한다. [product_scan.py](../../product_scan.py), [process_barcode / _process_barcode_logic](../../Container_Audit.py)
- **검증·저장·결과:** 현행 `ITEM_CODE_LENGTH=13`, 제품 문자열 최대 128자이며 품목코드보다 길어야 한다. 기본 판정 통과 뒤 일반·held 입력은 `decide_catalog_product_match`의 같은 모호성/다른 긴 품목 정책과 사건 detail을 사용한다. 일반 경로의 오류 카운터·경고→사건→상태 저장과 held 경로의 경고→동기 감사→FIFO ACK는 각 호출자가 유지한다. 형식 오류는 기존처럼 사건 기록이 경고보다 먼저다. 제품 입력은 기존 직렬 lane worker에서 상태·사건을 내구 저장하고 UI 단계만 Tk에 반영한다. 정상 입력은 current JSON ACK 뒤 목록·수량·성공음을 확정하며 품목·경고·수량 표시를 같은 결과로 한 번 갱신한다. 이후 `SCAN_OK` 접수(held는 동기 감사)가 끝나야 다음 입력/held FIFO ACK와 목표 도달 완료 대조로 이어진다.
- **실패·취소·재시작:** 형식·품목·중복·초과는 개수 증가 없이 경고·실패 사건으로 처리한다. 취소는 [CA-08](#ca-08), 상태 저장 후 복구는 [CA-09](#ca-09)를 따른다. 이 단계의 동일 품목 통과가 중앙 member임을 최종 증명하지는 않는다.
- **수용 기준:** 오류별 목록·수량·경고 상태가 일치하고, 같은 트레이 중복과 초과가 완료량에 더해지지 않아야 한다. 재시작 뒤 마지막 접수 여부를 식별할 수 있어야 한다.
- **연결·남은 일:** [수량·입력 계약](contracts.md#ca-data), [CA-G04](BACKLOG.md#ca-g04), [CA-A01](BACKLOG.md#ca-a01). 128자는 코드 제한이며 ERPnext의 수량 제한과 무관하다.

<a id="ca-06"></a>
### CA-06 순번·수량·작업시간 표시

- **시작·입력:** 정상 스캔마다 순서·간격, 완료 때 barcode 목록·작업시간·오류·유휴시간을 구성한다. [build_scan_ok_detail / build_tray_complete_detail](../../event_payloads.py)
- **검증·저장·결과:** `scan_position`은 1부터의 **입력 순번**, `interval_sec`·`work_time_sec`는 초다. `scan_count`는 현재 목록 수, `tray_capacity`는 목표이며 실물 슬롯 좌표나 중앙 위치 ID가 아니다. UI 최근 입력·수량은 [scan_display](../../scan_display.py)와 메인 화면이 소비한다.
- **실패·취소·재시작:** 취소·복구·부분/시험 상태는 이벤트 플래그와 함께 해석한다. 경고 중 최근 행 가시성은 [기존 관측](../../tests/KNOWN-GAPS.md)에 남은 사용성 후보이며 데이터 유실 확정 결함은 아니다.
- **수용 기준:** 목록 수와 현재 표시가 맞고 초 단위와 순번 의미가 보존되어야 한다. 실제 슬롯 배치 검사 여부는 별도 요구 확정 전 수용 완료로 세지 않는다.
- **연결·남은 일:** [CA-C07](contracts.md#ca-c07), [CA-G01](BACKLOG.md#ca-g01), [CA-G02](BACKLOG.md#ca-g02), [CA-A02](BACKLOG.md#ca-a02).

<a id="ca-07"></a>
### CA-07 전량·exact 구성원 완료 조건

- **시작·입력:** 마지막 제품 또는 완료 요청에서 중앙 목표·스캔 목록·operation lease·버전 문맥을 검증한다. [request_complete_tray / complete_tray](../../Container_Audit.py)
- **검증·저장·결과:** `_map_scans`는 barcode를 unit으로 매핑하고 lease member 집합과 정확히 맞춘다. lease 없는 PHS2, 부족 수량, 비멤버·집합 불일치를 완료 명령으로 넘기지 않는다. [TransferSealCoordinator._verified_operation_lease / _map_scans](../../transfer_seal.py)
- **실패·취소·재시작:** 전량 불일치면 현재 트레이를 유지하고 실물/중앙 구성원을 대조한다. 표준 PHS2 부분 제출은 차단한다. 교체·보류·복구를 통해 허용 조건을 다시 만족시켜야 한다.
- **수용 기준:** 개수만 같은 다른 구성원, 중복 unit, 신규 완료 시 만료/다른 context lease가 거짓 완료를 만들지 않아야 하며, 유효한 exact 집합만 [CA-12](#ca-12)로 이어져야 한다. 이미 기록된 로컬 완료를 복구할 때는 저장된 완료 시각으로 lease를 재검증하는 분기를 구분한다.
- **연결·남은 일:** [CA-C03](contracts.md#ca-c03), [CA-G04](BACKLOG.md#ca-g04). lease 취득 후 통신 단절의 compact PHS2 근거를 별도로 연결한다.

<a id="ca-08"></a>
### CA-08 마지막 스캔 취소·리셋

- **시작·입력:** 활성 작업의 마지막 입력 취소 또는 현재 작업 리셋 요청. [undo_last_scan / reset_current_work](../../Container_Audit.py)
- **검증·저장·결과:** 전이 중 변경 guard를 통과한 후 목록·시간·상태와 감사 사건을 맞춘다. 취소 저장/감사 실패에서는 이전 목록을 복원한다. 리셋은 중앙에 이미 확정된 물류를 되돌리는 명령과 동일하지 않다.
- **실패·취소·재시작:** 진행 중 callback을 무효화해 오래된 입력이 새 트레이에 섞이지 않게 한다. 로컬 기록 실패를 숨긴 채 성공 취소로 끝내지 않으며, 재시작은 보존 상태 기준으로 복구한다.
- **수용 기준:** 정상 취소는 마지막 한 항목만 제거하고, 저장 실패에는 이전 목록·개수가 유지되어야 한다. 리셋 후 지연 callback이 새 작업을 변경하지 않아야 한다.
- **연결·남은 일:** [CA-C01](contracts.md#ca-c01), [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06). 중앙 확정 이후 수정은 별도 계약의 조건으로 판단한다.

<a id="ca-09"></a>
### CA-09 보류·복원·비정상 종료 복구

- **시작·입력:** 진행 트레이 보류, 본인 보류 목록 선택, 재시작 시 current state 발견. [park_current_tray / restore_parked_tray / _load_current_tray_state](../../Container_Audit.py), [parked_tray_store](../../parked_tray_store.py)
- **검증·저장·결과:** 작업자 소유권과 다른 작업자의 같은 현품표 보류 중복을 검사한다. 복원 상태와 복원 사건의 저장, 원본 정리 순서를 관리한다. 완료 상태 재발견 시 완료 intent와 대조한다.
- **실패·취소·재시작:** 손상/불일치 상태는 격리·defer 경로로 보존하며 임의 빈 트레이로 대체하지 않는다. 원본 보류 삭제 전에 복원 내구 경계를 확인한다.
- **수용 기준:** 보류→종료→복원이 barcode·순서·소유권을 유지하고, 어느 쓰기 단계에서 종료해도 유일한 원본을 잃거나 이중 활성 트레이를 만들지 않아야 한다.
- **실제 관측:** [case02 정상 앱 재시작](E:/KMTech/ca-install-qualification-20260908/case02-restarted-before-restore.txt)에서 1/2 상태의 parked JSON은 같은 hash로 남았고, [복원](E:/KMTech/ca-install-qualification-20260908/case02-restored-summary.txt)은 동일 snapshot을 current로 옮겼다. 이 결과는 임의 시점 강제 종료·OS cold boot까지 증명하지 않는다.
- **별도 a7 lifecycle 관측:**09:39 cold boot 자동 relay 시작과09:53 정상 uninstall/reinstall 뒤 업무9·identity3 자료의 hash 보존 및 ordinary worker 화면 완료2·보류2·대기0을 확인했다. 보류 합계는 case03 미착수0스캔1152B와 case01 격리521B이며 case02/04는 ACKED다. 이후 d440 공개 Restore09로 exact a7 복원 및 실제 일반 worker/F4 완료를 확인했다. [CA-O09](operations.md#ca-o09)의 source/OS/시점별 범위를 유지하며 임의 crash 검증으로 합치지 않는다.
- **연결·남은 일:** [CA-C01](contracts.md#ca-c01), [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06). CSV만으로는 이 복구 상태를 재구성할 수 없다.

<a id="ca-10"></a>
### CA-10 봉인 전 제품 1~2쌍 교체

- **시작·입력:** 중앙 `PHS/AVAILABLE` 대상의 손상 제품과 새 GOOD 제품 1~2쌍. 공여 PHS의 활성 구성원은 정확히 하나여야 한다. [정본 교체 정책](../MEMBER_EXCHANGE_POLICY.md)
- **검증·저장·결과:** 품목/UOM·대상/공여 버전을 확인하고 한 `REPLACE_BUNDLE_MEMBERS` transaction으로 처리한다. 손상품은 `PROCESS_DAMAGE_HOLD`, 새 GOOD는 대상 PHS로 이동한다. SQLite intent와 exact receipt를 남기고 receipt 확인 뒤 로컬 목록을 한 번에 교체한다. [transfer_member_exchange](../../transfer_member_exchange.py)
- **실패·취소·재시작:** 충돌·복수 구성원 공여·receipt 불일치는 부분 로컬 교체를 허용하지 않는다. ACK 후 로컬 적용 중 종료하면 저장된 intent와 트레이 상태를 대조한다. 원래 라벨 identity 유지 증거도 필요하다.
- **수용 기준:** 1~2쌍 전체 성공/실패, 중앙·로컬 exact 집합 일치, 동일 키 재생의 단일 효과, 동시 CAS 경쟁의 한쪽 성공을 확인한다. 봉인 후 CA 로컬 목록 수정은 차단되어야 한다.
- **연결·남은 일:** [CA-C04](contracts.md#ca-c04), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05). [server-contract 테스트](../../tests/test_transfer_member_exchange_server_contract.py)는 저장된 HTTP 응답 재생이며 실제 서버 경쟁 검증과 구별한다.

<a id="ca-11"></a>
### CA-11 현품표 정합·출력·활성화

- **시작·입력:** F8 정합 후보/작업 지시 선택 후 중앙 source/target과 현품표 증거를 확인한다. 제품 교체와 별도 업무다. [ContainerAudit._on_phs_label_exchange_shortcut](../../Container_Audit.py), [PHSReconciliationExchangeCoordinator](../../phs_reconciliation_workflow.py)
- **검증·저장·결과:** 중앙 교체 준비 → durable print journal → 서버 발급 출력물 → print proof 등록 → 활성화 순서를 관리한다. 로컬 파일 hash와 `spool_job_id` 등 증거를 검증한다. [phs_label_workflow](../../phs_label_workflow.py)
- **실패·취소·재시작:** `PRINT_FAILED`/`PRINT_PARTIAL`·중앙 ACK 대기·불확실 재출력을 journal로 구별한다. 원본 파일이 바뀌거나 출력 결과가 불명확하면 확인 없이 재출력/활성화를 진행하지 않는다. 중앙 `COMMITTED`와 로컬 상태를 재조회해 복구한다.
- **수용 기준:** 중간 실패 후 동일 교체 건을 복구하고, 일부 출력·ACK 유실에서도 잘못된 라벨 활성화나 무인지 중복 출력이 없어야 한다. spool 성공과 실제 종이 출력·부착은 별도 관측으로 남긴다.
- **연결·남은 일:** [CA-C09](contracts.md#ca-c09), [장비](operations.md#ca-o03), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05). 실물 출력과 legacy fallback의 배포 지원은 미확인이다.

<a id="ca-12"></a>
### CA-12 로컬 완료·중앙 봉인·재확인

- **복원 후 별도 F4 관측:** exact a7를 공개 복원한 ordinary worker는 새 target GOOD2를11:43:39Z 완료하고11:43:40Z ACKED/attempt1/LINKED1을 기록했다. [세 intent 공개 조회](E:/KMTech/ca-install-qualification-20260908/f4-seal-public-results-01.jsonl)는 기존 case02/04도 그대로 유지함을 확인한다. Label용 두 donor는 미사용이며 downstream 교체/포장 결과는 Label/Web 소유의 별도 판정이다.

- **2026-09-08 승인된 source 후속:** frozen 설치의 bound `OPERATOR_REVIEW`에는 정상 재전송 동작이 없었다. Main `msg_9d5415ea3be1`에 따라 운영 메뉴의 관리자 확인 재시도를 구현했다. 활성 트레이가 없는 인증된 관리자만 기존 요청 한 건을 확인하고, 동기 local-only 감사 기록 뒤 같은 command/key/lease/완료 시각을 재전송한다. 실패는 계속 검토 상태이며 자동 재시도에 편입하지 않는다. 수정 후보 `a7d714f6`는 같은 guest에서 정상 canonical `REPLACED_VERIFIED`/exit0이며, 실제 보호 관리자 메뉴와 원래 case02 품목/수량2/작업자 확인창을 관측했다. 중앙 ACK는 아직 미검증이다. [회귀](../../tests/test_supervisor_transfer_review_retry.py), [계약](contracts.md#ca-c03), [CA-G09](BACKLOG.md#ca-g09).

- **2026-09-08 좁은 후속 검증:** 완료 CSV 재생 후 일일 집계는 `_load_session_state`의 현재 날짜를 따른다. 원래 실패 한 건은 lease fixture가 `datetime.now()`만 9월 6일로 고정하고 `date.today()`를 고정하지 않은 원인으로 좁혔다. 기존 assertion을 유지한 두 사례를 E의 일관된 fixture clock으로 실행한 2 PASS는 [CA-G08](BACKLOG.md#ca-g08)의 headless fixture 제안 근거다. 승인된 patch를 적용한 최종 focused 실행에서도 두 사례가 PASS했고 현장 완료/서버 ACK 성공의 증거는 아니다.

- **시작·입력:** [CA-07](#ca-07)의 전량·lease 검증을 만족한 트레이. 고정 작업 시각·작업자·멱등 키·member/version 문맥을 사용한다. [complete_tray](../../Container_Audit.py), [TransferSealStore.prepare / bind_command / confirm_completion_checkpoint](../../transfer_seal.py)
- **검증·저장·결과:** SQLite intent와 `LINKED` 기록, GUI 완료 checkpoint를 확인한 뒤 불변 명령을 보낸다. `TRAY_COMPLETE`는 동기 내구 기록을 사용한다. `ACKED`는 중앙 receipt 검증 결과이며 로컬 완료 ID와 별개다.
- **실패·취소·재시작:** local completion ID도 ACK도 없는 트레이는 잠근다. 이미 `LINKED`인 작업의 중앙 지연/검토가 로컬 완료를 취소하지 않는다. 응답 유실은 원 key receipt 조회·재전송, 영구 충돌은 `OPERATOR_REVIEW`, 로컬 이벤트 실패는 `LOCAL_EVENT_RETRY`로 구별한다. [TransferSealCoordinator.attempt](../../transfer_seal.py), `complete_tray`
- **수용 기준:** lease→intent→checkpoint→중앙 receipt→CSV→화면의 각각을 관측하고, 재시작/응답 유실에서 중앙 이동·로컬 완료가 각각 한 번이며 원 key가 유지되어야 한다. `LINKED`와 `ACKED` 표시/다음 입력 guard가 실제 내구 상태와 일치해야 한다.
- **연결·남은 일:** [CA-C03](contracts.md#ca-c03), [CA-G01](BACKLOG.md#ca-g01), [CA-G04](BACKLOG.md#ca-g04). [transfer_seal 테스트](../../tests/test_transfer_seal.py)의 BND offline fixture를 현장 compact PHS2의 lease 복구 증거로 승계하지 않는다.
- **실제 설치본 후속:** `a7d714f6`/개발 backend `c0c0d51`에서 원 case02의 정상 관리자 감사 재시도는09:21:22Z ACKED/attempt2, 새 case04의 일반 GOOD3 완료는09:25:36Z ACKED/attempt1이다. 각각 로컬 LINKED1이며 원 case02의 기존 review1·명령·완료 시각은 유지됐다. 중앙 case02 receipt1의 독립 조회와 downstream 인계는 [CA-O09](operations.md#ca-o09), 이후 OS/설치 복구는 별도 판정이다.

<a id="ca-13"></a>
### CA-13 이벤트 업로드·전송 상태·분석 소비

- **반복 스캔:** ACK가 끝난 source의 변경 감지와 prefix 내용 검증 주기를 분리한다. 변경이 없으면 마지막 전체 검증 후 300초 미만 동안 읽기를 생략하며, 변경·미완료 delta·검증 기한 경과는 전체 확인으로 돌아간다. 힌트는 프로세스 재시작 뒤에도 기존 cursor와 함께 유지된다. [CA-C05](contracts.md#ca-c05)

- **F4 실제 추가 전송:** 복원 a7의 F4 완료 뒤 GUI 대기0·[relay29건 전부 acked](E:/KMTech/ca-install-qualification-20260908/after-f4-relay-queue.jsonl)를 확인했다. 물류 seal receipt·producer receipt·projection/API·브라우저 표시 범위는 각각 [CA-O09](operations.md#ca-o09)의 증거로 구분하며 queue ACK만으로 소비 화면 수용을 주장하지 않는다.

- **시작·입력:** events CSV를 whole-file snapshot으로 spool/queue에 등록하고 사용자 relay가 HTTPS 업로드한다. [enqueue_completed_source_file](../../direct_sync_runtime.py), [build_source_file_plan / drain_one_relay_batch](../../direct_sync_push.py)
- **검증·저장·결과:** 파일 identity·SHA256·바이트/행수·서명·runtime lease와 엄격한 receipt를 확인해 `acked` 처리한다. local-only/시험 사건은 [event_stream_policy](../../event_stream_policy.py)의 경계로 분리한다. 물류 봉인 command ACK와는 다른 전송이다.
- **실패·취소·재시작:** pause·디스크 압력·stale lease·일시 오류·committed 오류를 구별한다. 재시도 상태와 spool을 보존하며 receipt 검증 전 삭제하지 않는다. 자동 retry와 운영 검토를 혼동하지 않는다.
- **수용 기준:** 같은 snapshot 재전송이 projection 중복을 만들지 않고, receipt의 행 합계·identity·COMPLETE와 UI 상태가 맞아야 한다. 대시보드 반영은 API/화면 readback을 별도로 확인한다.
- **연결·남은 일:** [CA-C05](contracts.md#ca-c05), [CA-C07](contracts.md#ca-c07), [CA-G01](BACKLOG.md#ca-g01), [CA-G04](BACKLOG.md#ca-g04), [CA-G06](BACKLOG.md#ca-g06). 전송 속도·화면 최신성 목표와 운영 측정은 미정이다.
