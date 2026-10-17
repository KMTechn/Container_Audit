## 목표 명세 고칠 목록(10/11)

10/17 sub-290 G55·G56 꼴 relay 재시도·G43 닫음(기준일 115 제어 코드): bootstrap 감독을 내구 단계 시각의 창 끝+15초까지 늘리되 시작+480초로 제한한다. 후보 정상 종료 대기 시작도 내구 기록한다. 같은 GUI claim 뒤 실제 trial relay를 다시 관측하며 bootstrap 프로세스의 nonce마다 최대 3회/간격 2초 이상으로 시작한다. OSError 세 번 실패는 사용자 지원 기록의 `TRIAL_RELAY_START_FAILED`로 남긴다. 멈춤 표지가 있으면 포인터·표지를 보존한 `DEFERRED`·`UPDATE_RELAY_STOP_REQUESTED`로 적용을 미루며 recovery_pending은 두지 않는다. 사용자 시작은 REQUEST_APPLY 없이 현재 화면을 연다. 정식 멈춤 PC는 업데이트 날 전에 onboarding한다. 고정 current 교체 장치와 실제 배포본·현장/VM 수용은 별도 레인 회차이며, 이번 고침은 115 설치본에 들어갈 제어 코드다.

10/17 sub-276 G46 닫음: Observe가 기존 bootstrap 판정에 맞는 GUI·relay launcher를 소유자 조회·역할 분류 전에 제외한다. 되돌림 READY는 실제 relay 하나로만 확인하며 실제 relay 둘·relay 부재는 확인하지 않는다. READY·census 판정 본문과 G41 동시 relay 요청의 단일 실행을 유지한다.

10/17 sub-268 G41·G45: 복구 GUI의 relay 소실과 relay만 살아 있을 때의 GUI 막힘 P1을 수정했다. relay 요청은 원 시작 경계, GUI 요청은 허용 상태·정착 claim·검증된 relay 하나의 생성 경계를 사용한다. 일반 복구 증명·상태 보존·안내+20을 유지하며 SYSTEM guard/READY 소비자와 세대 정착을 격리 회귀로 확인한다. 실제 로그온·pythonw 수용은 별도다.

11/1 P2(sub-268, 정적 잔류): 감독 잃은 ROLLBACK_PENDING에 relay가 남으면 GUI 요청은 ABSENT에서 기존 0, NONE에서 SYSTEM의 writer 거절 뒤 240초 한도로 끝나 화면을 못 띄울 수 있다. 이번 고침 범위 밖이며 안내 문안은 「화면이 안 뜨면 지원에 연락」이다.

10/15 화면 몫: UI `a1b37ce2`·승인 다리 문안·계약 칸·부분 제출 확인/즉시 확정·M124 PIN 분리를 소스에 반영했다. 집중 시험과 남은 한계는 sub-209 RESULT가 정본이며 부분 제출·PIN 좁은 독립 검토 및 실제 화면 수용은 통합 담당에게 인계한다.

11/1 첫 업데이트(v2.0.113) — 작업 임대 갱신(앱+서버 계약, w9mgrweb 과 같이): 지금 이적은 현품표 스캔 때 한 번 발급하며 갱신 길은 없다. v2.0.112는 원 임대 만료 뒤 로컬 완료를 원 명령·실제 시각으로 보내 서버의 안전 재개를 받는 범위다.

10/16 sub-145 후속: 자동 보관 선행 의도와 기존 종료/오류 진단 세 종류를 LOCAL_ONLY로 닫았다. 세 재시작 경계×CSV/outbox 조건은 새 app/store로 검증하며, 복귀 rename 직후 누락 감사와 outbox-only provenance를 기존 형식으로 복구한다. 서버 catalog 변경은 없다.

10/16 identity 분류 보완: 자동 보관 선행 의도 `PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING`와 재시작 복구의 RESTORED·QUARANTINED 감사 호출 세 자리를 기존 같은 종류의 감사와 동일하게 등록한다. 현재 작업자 감사·LOCAL_ONLY 정책과 저장된 identity 재생의 필수 인수 검사를 유지한다.

10/16 G09: 자동 오프라인 보관의 같은 작업자 복귀는 감사 사유·원본 지문을 확인하는 내부 스캔 경로에서 PIN 없이 이어진다. 관리자 격리 원본의 C12 PIN은 유지한다. 기존 FIFO·반환 거절·이동 중단 회귀와 PIN 경계 음성 시험으로 확인한다.

11/1 첫 업데이트 — 작업 임대 갱신(앱+서버 계약, w9mgrweb 과 같이): 지금 이적은 현품표 스캔 때 한 번 발급(Container_Audit.py·transfer_seal.py), 갱신 길 없음, 확인 창·채우는 중이 서버 TTL 을 넘으면 만료

11/1 첫 업데이트 — 공개 -PlanOnly 입구의 실제 실증 시험(관리자 sub-143 P3).

11/1 첫 업데이트 — timeout 0 공유 게시 예산 소진·둘째 게시 실패·중단 장면 시험(관리자 sub-143 P3).

첫 업데이트(11/1): 세 앱 공용 『emitter 항목 단위·서버 정본 바이트 핀』 시험 하나 — 지금 이적 수집 시험은 집합 단언이 남고, 시험 catalog 가 서버 정본 바이트로 안 묶이며, 실제 서버 영수증 대신 대역 영수증(관리자 sub-153 P2 셋, 포장 sub-148 P2 와 합침). 실제 서버 영수증 길은 시험 서버 왕복으로 업데이트 증명 때.

회사 서버 앞단 대응: 고정 User-Agent 공통 적용, 비JSON 403·5xx 코드 안내와 requests 압축 읽기를
오프라인 transport 시험으로 검증한다. 실제 회사 서버 통과·화면 확인은 별도 수용 대상이다.

검사실 잔량표의 이적 거절(R6): 일반 판독·스캔 보관 전 거절, 과도기·끊김·복원과 서버 `RESIDUAL_TAG_NOT_ALLOWED`의 자동 재시도 차단을 소스 회귀로 확인한다. 실제 스캐너·오류음·화면과 서버 결합은 별도 현장 수용 대상이다.

작업자 세션 설치의 바로 가기 전환·원본 복원은 소스에 반영했다. 사용자/공용 known folder를
격리한 PS5.1·PS7 시험으로 확인하며, 실제 화면의 아이콘·최소화 실행과 현장 설치는 미검증이다.
관리자 직접 길의 사용자 프로필 처리는 첫 시작 onboarding 연결이 남는다([운영 절차](operations.md#ca-o05)).

지원 제거의 자료 세대 관문: source 전체 inventory를 검증된 활성 판/build 설치 기록에 결속한다. 고정 A→활성 B 업데이트 뒤 B 지원 제거와 후보 재설치 전 활성 B host 제거를 격리 시험으로 확인한다. 옛 A packet·증명 실패·새 자료 거절·fence 계약은 유지한다. 실제 PC 재설치·TEST1 되돌림 수용은 별도이며 결과 보고서에서 판정한다.

### 7-결정. 정해진 줄 (관리자 10/11 02:51–03:36 — 묶음 계획 FIRST-INSTALL-BUNDLE-1014 §3-7b·§3-7c·§3-8; archplan 이 명세 가지와 합칠 때 덮지 않음)
| # | 정해진 것 |
|---|---|
| CA-5 | **B(등록만) = 이번 묶음**(이름만·승인/PIN 없음·번호는 화면만·로컬 저장 뒤 보냄·숨김 없음 stage_a=false), **A(30일 숨김) = 다음 판**(웹에 30일 숨김 계산이 없음). 조건: 동결 전 격리 웹(플래그 켬) 랩 증명, 플래그 꺼짐(503) 때 깔끔한 안내 + 웹 사전 등록 이름 고르기·멈춤 0, 화 10/13 12:00 점검, 회사 서버 readback 은 10/19 켠 뒤. 웹 계약 = W/w9webux1008/sub-23/RESULT.md |
| CA-1 | 「출고 전 관리자 보충 필요」 표시 = 이번 묶음(UI 고침 한 바퀴, 늦어도 동결 수 10/14 12:00) |
| CA-2 | 후속 설계 v0.2·받기 v0이 초기 결정보다 앞섬. 제품 관리자 입구·기계 배치·PENDING·첫 시작 연결을 w9firstupdsub62에서 구현. 키트 입구·옛 앱 Rollback·랩 수용은 w9setupprep/1차 몫이며 수용 전 현장 판단은 기존 조건 유지 |
| 글자 층 | K1(1곳)·문안 v2 「글자만」 줄 = 이번 묶음(w9fieldfit1008 sub-30 표·apply_changes.py, 개수 맞을 때만) |


- CA-10 글자 층: K1-CA-0058·문안 v2 W17a/W17b/C02f·공통 C05 적용. C01c/C01d의 원인 분기와 C04f의 관리자 상세는 남는다. W17c·공통 C03은 조치 없음이며 비교·저장·전송 값은 유지한다.
- CA-1 소스 구현: 금일 작업 현황의 「출고 전 관리자 보충 필요 N건」·품목별 「보충 N건」과 완료 안내. 새 현품표의 미확인 봉인만 표시하고 해당 ACK 뒤 해제한다. 옛 현품표·테스트 제외. headless 회귀는 [시험](../../tests/test_shipping_supplement_notice.py), 실제 화면·설치·서버 확인은 남는다. 원 완료 기록·수량·관리자 PIN 흐름은 유지한다.
- CA-2 설치 중 중단(판정 ⑬): 지원 입구의 원 authority·자식 PID/생성 시각 확인과 기존 보상은 소스 계약에 포함한다. 전원 끊김 뒤 실제 기계 복원·담장 해제의 랩 수용은 남는다.

- 출처: [목표 명세](README.md) §7 — w9archplan 10/11, 기준 v2.0.102 0f82c54. 아래 기존 줄은 그대로 둔다.
- 누가: 이적 코드 주인 w9firstupd, 설치 설계 w9firstupdrd. 판: 「다음 판」 = 10/14 동결 묶음. 늦은 창 판(v2.0.102)에는 고침을 넣지 않는다.

| # | 종류 | 무엇 | 등급 | 판 | 누가 | ◆ |
|---|---|---|---|---|---|---|
| CA-1 | 바로잡기 | 새 현품표를 이 PC 에만 끝낸 트레이(회사 서버 거절·확인 불가로 이적 기록 없음)는 포장·출고 사슬에서 막힌다(COMPAT-TABLE-1011 :71·:92·:93). → 그 트레이는 화면과 기록에 **「출고 전 관리자 보충 필요」** 를 남긴다. 포장 LM-1·웹 WEB-N1 과 같은 꼴 | P1 | 다음 판(크기는 w9firstupd, LM-1 과 함께) | w9firstupd | — |
| CA-2 | 바로잡기 | **원격 숨김 설치 받기**. 현장 키트가 작업자 일반 세션에서만 돌고, 상승은 제품 안 Windows 허용 창(UAC RunAs)으로 한다(`install-onsite.ps1:68`·`:603`, `bootstrap_integrity.ps1:1753`·`:1787` — TEST1 sub-490 02:02, archrev 02:03). 관리자 원격 숨김 설치 길이 없고, 사용자 9/30 규칙과 어긋난다. 검사 `-WorkerAccount <SID>` 꼴로 맞춘다 | P1 | w9firstupdrd 크기(일 12:00) 뒤 w9mgrcut 이 동결 안/밖 결정. 밖이면 기준일 밤·늦은 창은 허용 창을 누를 사람(또는 Parsec 서비스 방식) | w9firstupdrd 설계 → w9firstupd | — |
| CA-3 | 확인 | 화면 결함 CA-01–05: 고친 코드가 이 판에 있다(조사표 J). 단 CA-04 는 설정이 없을 때의 시작 경고에 「중앙」·「무결성」 이 남았다(다음 판에서 고침). 실제 PC(1366×768·125 %) 캡처로 닫는다. **이적 늦은 창 GO 의 「첫 화면 판정」 이 이 줄이다** | P1 | 지금 판(판정) · 다음 판(CA-04 잔여) | 판정 w9fieldfit1008 · 잔여 w9firstupd | — |
| CA-4 | 확인 | **업데이트 길 증명**: v2.0.102 위에 다음 판을 같은 길로 덮어 깔고, 자료·등록·보낼 것이 남는지 readback(§8-3). 현장 키트의 옛 판 고정(`LEGACY_VERSION` v2.0.4)·재시도 막힘(`RETRY_BLOCKED`) 아래에서 하는 길을 기준일 전 랩에서 한 번(코디 승인 늦은 창 조건 G-d) | P1 | 기준일 전(w9firstupd 계획서 §3) | w9firstupd·w9setupprep | — |
| CA-5 | 구현 | **앱 안 작업자 등록**: 명단에 없는 사람이 그 PC 에서 바로 이름을 등록한다(관리자 승인 없음, 「이름 #번호」, 개인정보 없음, 잘못·대충 입력 방지). B 구현: 이 PC 저장 뒤 바로 선택·회사 서버로 배경 전송·숨김 없음(stage_a=false). A(30일 숨김)는 다음 판이며 B 격리 웹/화면 확인은 별도 | P1(새 사람이 웹 관리자 없이 시작 못 함) | 다음 판(이번 묶음, 사용자 10/08). w9firstupd 가 포장 짝과 크기(일 12:00) 뒤 안/밖 — 밖이면 코디에 알림 | w9firstupd | ◆ |
| CA-6 | 바로잡기 | 작업자 이름 붙이기: 회사 서버 기능 확인이 실패한 것과 꺼진 것을 구분하고, 실행 중에 주기적으로 다시 묻는다(F-04) | P2 | 다음 판 | w9firstupd | — |
| CA-7 | 바로잡기 | 제품 교환을 작업 화면 단추 「제품 교환」 으로 꺼내고(포장과 같이), 메뉴의 「현재 이적 제품 교체」·「개별 제품 교환」 을 그 하나로 합친다(F-35) | P2 | 다음 판 | w9firstupd | — |
| CA-8 | 바로잡기 | 「운영 작업 ▾」 를 나눈다: 작업자 몫(현품표 교체 F8·품목 목록 새로 고침·현재 작업 리셋)은 작업 화면에 두고, 관리자 몫(PIN 동작·인계·짝 보류·원 요청 다시 확인·완료 반영 재시도·전송 상태 상세)은 「관리자 ▾」 로(U7-바, §3-3) | P2 | 다음 판 | w9firstupd | — |
| CA-9 | 빼기 | 옛 앱 안 업데이트 안내(F-70) — 업무 시작 뒤 예약 호출 제거, 설치·업데이트 검증 유지 | P2 | 다음 판 | w9firstupd | ◆ |
| CA-10 | 이름 | §6 표의 낱말을 작업자 화면·안내 글에서 바꾼다. 「교체」/「교환」 은 제품 교환·현품표 교체 둘로만. 옛 현품표 꺼짐 거절 글은 「옛 현품표입니다. 이 PC 는 옛 현품표 받기가 꺼져 있습니다 — 실물을 그대로 두고 관리자에게 알리세요」. 비교·저장·전송에 쓰이는 글은 바꾸지 않는다 | P2 | 다음 판 | w9firstupd | — |
| CA-11 | 바로잡기 | 보호 관리자 코드(F-06)를 개인 관리자 PIN 하나로 합친다(관리자 확인 수단 하나) | P2 | 그 뒤 | w9firstupd | — |
| CA-12 | 빼기 | 보조 현품표 교환(Shift+F8 — 날짜·후보 손 고르기, F-43). F8 길이 현장에서 증명된 뒤에 뺀다 | P2 | 그 뒤 | w9firstupd | — |
| CA-13 | 빼기 | 옛 완료 현품표 교체 길(F-44)과 부르는 곳 없는 옛 다중 교환 도우미(F-45) | P2 | 그 뒤 | w9firstupd | — |
| CA-14 | 확인 | 새 이적 PC 의 하루 생산량이 웹 화면 합계에서 빠지는 문제(옛 이적은 C:\Sync, 새 이적은 HTTPS — COMPAT-TABLE :86 W2). 웹에서 다시 합칠지 사용자에게 묻는다 | P2 | 웹 다음 판 | w9mgrweb | — |

sub-248 제거 P2: 별도 관리 SourceRoot의 실제 canonical을 oldSource 문자열로 찾던 parent 제외를 제거하고, 준비된 source 해시·살아 있는 session authority·실제 PID/조상/시작 시각에 결속한다. 첫 현장 신규 설치 절차는 제거 quiescence에 도달하지 않는다. isolated PS5.1 positive/negative 및 모든 도달 caller 표의 결과·버전·한계는 sub-248 REPORT/COVERAGE-FIX에 기록하며, VM 현장 제거·역사 packet의 변경 없는 지원 및 독립 검토는 별도 남는다.

﻿# 남은 요구·검증·문서·추가 제안

행 6 후속: 암호 API 오류의 자기 판 fallback, 설치 onboarding의 허가 밖 검증, 실제 feed 모양의 64 KiB·공식 bootstrap 비밀 검사 시험을 추가했다. 이 가지의 writer inventory·data-generation transition과 기존 consumer pin은 생성기로 갱신했다. 실제 서명 출시 packet·현장 되돌림 수용은 남는다([운영 범위](operations.md)).

sub-172 새 미완 rollback 계약은 보호 불변 journal/receipt 사본으로 일반 재진입을
지원한다. PS5.1/7 실제 NTFS·코드/Run/task/pointer/relay 회귀와 변조 변경 0을
PROVEN(재진입2 PASS·변조10 PASS)이며 결과는 sub-172 REPORT에서 버전과 한계를 구별한다. G 특례 수용은 없다.
완료 기록은 건수 제한 없이 보존한다. 미완 복구 2건의 거절과 독립 검토·장기 보관 정책은 유지한다.

sub-172 receipt 전달: canonical의 보호 self-path·journal-bound 부모 소비 및 restore evidence 소비를
교정했다. PS5.1/7 post-child RED2→GREEN4, 기존 startup/export 합계34 PASS; 위조·덮어쓰기 거절 유지.
relay 대기·새 미완 rollback 재진입은 아래 소스 회귀 범위다. G 랩 수선과 예행 H의 실제 결과는 아래 sub-172 마감 근거로 구별하며 정식 선언/pin은 재생성하지 않는다.

sub-172 relay 대기: 설치·되돌리기 공통 360초와 timeout 뒤 끝 상태 기록을 교정했고
PS5.1/7 RED4→GREEN4다. G 수선/H의 실제 증명은 아래에 기록하며 새 지원 복구의 native 미완 장애 실증과 독립 검토는 남아 있다.

2026-10-04 sub-172 마감: 정식 소스8ba359f의 PS5.1/7 실제 NTFS 재진입2 PASS와
불일치 변경0의10 PASS를 구별한다. 최종 기존17파일594 PASS/동일한 선언 실패3/SKIP2,
새 실패0이다. 정식 네 선언/bootstrap literal 재생성0, 예행9ca39a8만 선언을 갱신했다.
새 계약이 G를 알아보지 않음(PlanOnly NOT_FOUND/journal0)을 먼저 읽고 제품 밖
지원 함수 수선으로 옛2302/원 Run·task/pointer/보호·일반 relay를 실제 복원했다.
새 packet의 H 설치1회는 native0/PASS/REPLACED_VERIFIED, 실제10구간을 마쳤다.
새 코드/pointer·SYSTEM startup task·비상승 RUNNING relay와 조작0의 시작 화면을
확인했고 지원 업데이트 확인1회는 provider off/후보 없음/적용0이다.
업무82·공용3·Machine2·상위/App/control ACL·형제 manifest 차이0이다.
H 성공으로 미완 rollback 재진입은 guest에서 실행하지 않았다. 그 native 장애 실증,
원 startup task가 있는 복구 preimage, 반복 복구 중단 및 독립 검토는 별도 남아 있다.
전체 suite/실제 update 적용도 NOT TESTED다. 정확한 버전·raw·한계는
[sub-172 REPORT](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-172/REPORT.md)에 있다.

CA-T1: task 주체·trigger를 SID로 해석하는 같은 함수가 세 소비자와 canonical 주체 판정에 적용된다.
PS5.1/7 실제 소비자 회귀에서 이름 표현은 수용하고 다른 SID·해석 실패·action 변조는 거절한다.
정식 선언/pin은 동결 상태이며 예행 F·독립 수용은 [sub-156](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-156/REPORT.md)에서 별도로 확인한다.
특권 경로 소유자의 SID 셋은 설치·relay·업데이트 적용에 동일하게 적용한다. 업데이트의
TrustedInstaller 거절 회귀는 PS5.1/7에서 RED→GREEN이며 helper 로딩 전 신뢰 검사와
hardened BA/원본 owner 결속은 유지한다. IW/LM 같은 부류는 해당 소유 레인에 남는다.

예행 F(205f877): CA-T1의 native task 되읽기는 통과했으나 설치는 FAILED_ROLLED_BACK이다.
CA-R1 소스 교정: startup preimage를 먼저 내구 보관하고 실제 보호 run 경로에 완성된 replacement
receipt를 한 번만 쓴다. startup 초기화는 그 preimage를 재사용하며 기록 덮어쓰기·guard 완화는 없다.
최초 018e013의 추가 self-path 변경은 기존 evidence completion 회귀 2개를 깨뜨렸다.
caller/export 경로 계약을 원복해 순서 교정만 유지하며 실패 증거는 sub-162에 보존한다.
최종 diff에서 self-path 표현을 기준과 완전히 동일하게 복원해 추가 fallback도 제거한다.
예행 G(dac6157): helper native0/REPLACED_VERIFIED로 단일 receipt·startup task·TLS ABSENT는 통과했다.
부모2887의 caller receipt Sha는 FileNotFound, 뒤 rollback917 relay READY timeout으로
AUTOSTART_ROLLBACK_FAILED/native1이다. current dac/2304파일·startup task1·active pointerdac가
남아 old-normal 복원은 FAILED다. public3/business82/Machine2/Run/ACL5/형제 판은 동일하며
늦은 비상승 relay RUNNING은 native 복원 실패를 뒤집지 않는다. direct-child receipt 전달과
지원 복구/독립 검토가 다음 작업이다. 추가 수선·재설치·GUI/update는 실행하지 않았다.
PS5.1/7 회귀는 초기화 실패→지원 preimage 복원→새 run 재설치, 기존 receipt 보존과 위조 거절을
검사한다. 랩 예행 G와 독립 수용은 [sub-162](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-162/REPORT.md)에서 별도로 판정한다.
F의 최초 중복 쓰기 실패(native 73), 실제 9/10구간 및 old2302파일·Run·ACL·비상승 relay
복원 PROVEN, 시작 화면/업데이트 NOT TESTED는 [예행 F](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-156/CA-5TH-REHEARSAL-F.md)를 따른다.

SYSTEM task XML의 unsupported ServiceAccount 요소를 제거했다(trigger/action/주체/조건 불변).
호스트 회귀 PROVEN과 랩 등록·단일 설치 수용은 별도이며
[sub-151 결과](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-151/REPORT.md)에서 실제 실행 범위를 확인한다. IW/LM의 같은 XML 문제는 각 소유 레인에 남는다.
같은 교정은 첫 native 종료/fallback의 요약·부모 journal 전달과 직접 privileged helper의
보호 evidence run 결속을 유지한다. 실제 단일 설치 결과·독립 수용과 소스 회귀를 구별한다.
CA-A2는 누락된 선택 조상을 생성 전에 거절하며 부모/대상 미생성을 PS5.1/7에서 검증했다.
CA-D1의 역사 전수표79행은 AST로 소속22행을 고쳤으며 제품 경로나 guard 변경이 아니다.
예행 E(2012a5c, 2026-10-03)는 교정 XML의 비활성 등록/되읽기/해제와 PlanOnly를 통과했다.
단일 설치는 INSTALL_THIS_PC.ps1:999의 STARTUP_UPDATE_TASK_READBACK_FAILED로 실패했다.
native 73과 원 진단은 canonical/부모 journal에 보존됐고 protected direct binding은 통과했다.
지원 rollback 후 old2302파일·Run·ACL·일반 relay 복원은 PROVEN이다. 비활성 probe의 trigger
계정명 정규화와 literal SID 비교가 원인이라는 추론은 별도 교정/독립 검토에 남는다.
설치 재시도·시작 화면·지원 업데이트 확인0; [실제 9/10구간](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-151/CA-5TH-REHEARSAL-E.md)을 따른다.

설치 증거의 권한 분리는 sub-107 소스 교정 범위다. 최종 컷의 선언/pin·stock과
5차 실제 설치에서 메모리 wrapper 실행, Administrators owner/operator read-only,
상위 trust 거절, 보호 결과의 ordinary export, 최근 5회 보존과 제거/복원 시
updater state 이동과 evidence 자리 보존을 확인한다. 소스 회귀는 실제 상승·예약 작업·relay·설치 성공의
근거가 아니다. [현재 결과와 경계 표](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-107/REPORT.md)를 따른다.

G 외부 입력 부류는 TLS CA·보호 관리자 profile·지원 receipt/password·등록 journal/context를
초기 guard와 실제 reader의 동일 경로로 결속한다. Python 별도 프로세스와 PS5.1/PS7의
허용/REFUSE/UNKNOWN 및 상대 경로 근거, 실제 stock 전진 pair와 남은 수용 범위는
[sub-263 보고서](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-263/REPORT.md)를 따른다.
호스트 실설치·GUI·Run/task·live relay·자격 저장소·VM/서버는 이 교정에서 실행하지 않는다.

Credential locator/nested의 두 단계 admission과 기존 malformed/duplicate BLOCKED 진단을
구분한다. Canonical 최초 G의 세 격리 분기에는 변경·removal·Run·relay·fence 잔류가 없다.
Canonical nested 판정은 기존 product onboarding의 읽기 전용 호출로 모든 설치 변경 앞에
놓고, 같은 해석 결과 digest를 child의 최초 기록 전에 대조한다. 실제 G를 켠 별도 프로세스
RED/GREEN과 PS5.1/PS7 근거는
[sub-272 보고서](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-272/REPORT.md)를 따른다.
native 설치·복원과 최종 수용은 coordinator 독립 확인 범위로 남긴다.
검증 복원도 old packet을 대상으로 같은 초기 locator/nested G와 단계 전 binding 대조를
사용한다. 실제 first reader는 다시 시작하는 old relay이며 lifecycle-restore child 호출은 없다.
sub-270 removal 거절의 일반 rollback도 독립 복원 시도와 finally release/restart로 교정한다.
exact code·실제 G·runtime 증명 실패는 fenced 유지·한국어 화면/감사 안내이며 G를 거절한 code 복원은 0이다.
최종 G에는 옛 판의 읽기 전용 locator/nested 판정도 포함하며, 설치 중 nested marker drift는 fence 유지로 처리한다. 설치 실패 안내·child 출력 감사의 알려진 비밀 환경 값은 고정 표식으로 치환하고 byte 검색으로 확인한다.
지원 절차는 [운영 문서](operations.md#canonical-rollback-support-recovery)에 두고 retained-fence 랩 1회 PROVEN은 coordinator 예행 범위로 남긴다.
Uninstall/retirement/refence 이전 실패의 안내·지원 복구 경로는 자리 지도에 별도로 남긴다.

G 직접 입구/거절 부류: registrar 검증·2PC resume, support operator/profile,
앱 active-work wrapper/report, lifecycle 복구·제거의 판독 전 보호와 온보딩/relay
거절 시 기존 상태 보존을 교정한다. 별도 프로세스 RED/GREEN·선언 재생성·stock·
집중/전체 실패 집합 근거는
[sub-233 보고서](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-233/REPORT.md)를 따른다.
실제 frozen GUI·운영 설치·서버/VM·현장 장비는 이번 host headless 범위에서 NOT TESTED다.
G 교정으로 달라진 두 writer route의 전진 전환은 앱 전용 선언/reader로 한 쌍만
결속한다. 파일 hash·route·sink/guard 위조와 역전환 거절 근거도 같은 보고서에 남긴다.

자료 세대 내림 guard(sub-219)는 두 leaf·같은 판 새 build 하한 교집합의 격리 묶음31 PASS까지 PROVEN이다.
CA의 자료-open 3곳과 restore/reinstall 7곳에 호출을 연결했으며 관련52 PASS와 native
자료 사용 뒤 거절을 확인했다. 기존 d55cc94 집중 시험은308 PASS/2 FAIL; 두 옛 post-data
복원 기대는 G 결정과 충돌하여 기존 exact 단언을 보존한 시험 범위 조정을 코디에게 물었다.
같은 판의 다른 build가 이전 signed 호환 하한을 물려받던 helper 결함은 RED로 확인하고
새 build/더 엄격한 하한과 신뢰 교집합을 기록하도록 두 leaf를 수정했고31 PASS다.
shared 0.3.6/9파일 manifest/lock/bootstrap consumer pin을 채택했다.
diagnostic_log는 미사용 잎이며 UNKNOWN 원인만 비공개 보존한다. 생성 선언·설치기
preimage/pin의 최종 정합성 및 실제 업데이트 수용은 조립 단계에서 확인한다.
기존 0.3.3/7파일 채택 때 새 guarded sink 하나를
표준 재생성했다. d55cc94 stock/native bundled-Python 직접 main·거절은 PASS이고
동일 기준 FULL 비교의 신규 실패0/기존 실패 해결1이다. 새 기준82ce91c 자체의 표준
`--check` PASS 뒤 그 위에 변경을 옮겨 선언/pin3곳/최종 `--check`를 재생성했다.
새 기준 집중 비교는 작업 보고서에 기록한다. 독립 review·H10 정책 결정과
frozen/실제 GUI 설치 수용은 남아 있다.
builder version/최소 호환 판 입력과 기존 ES256 signed private manifest 소비는 관련
3파일 101 PASS이나 실제 private 출시 발행은 미완료다. 재설치 packet의 내장 ES256
호환 증명도 portable reader가 검증한다. 실제 키로 첫 업데이트 packet 발행과
N+1 첫 자료-open → N 재설치 → G ALLOW·자료 보존·READY·relay 전송은 미검증이다.
기존 같은 판/build marker의 자기 판 하한은 이 기능으로 낮추지 않는다. 최초 옛
v2.0.33 위 설치의 일관 백업·수동
복구는 운영 문서/runbook이며 H10 랩·실제 현장 설치/GUI/relay는 NOT TESTED다.
[입구·남은 관문](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-219/ENTRY-POINTS.md),
[함수 근거](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-219/HELPER-READY.md).

명단 2단의 로컬 `worker_id`·`worker_name_snapshot`, UUID 복구 소유, 켜짐 신호에 따른 전송과 고정 재전송은 headless 회귀 대상이다. held-scan ACK 실패의 정상·거부 재생과 모든 신원 호출의 AST 분류·저장본 필수 전달은 [경계 회귀](../../tests/test_event_identity_boundaries.py)로 확인한다. 실제 명단 정정·중지 후 스캐너로 진행 중 완료와 다음 묶음 선택을 확인하는 현장 수용은 별도다. [계약](contracts.md), [회귀](../../tests/test_worker_record_identity.py).

G10 relay 읽기 실패는 실제 마지막 counts/ACK를 유지하고 미확인 안내로 구별한다. 운영 메뉴의 전송 상태 상세에서 최초 실패/미수신의 미확인, 마지막 확인값·확인 시각·읽기 실패, 정상 읽기 복구와 후속 스캔을 소스 회귀로 검증한다. 실제 장애 화면은 랩에 남는다.

portable 등록·관리자 복구 도구는 직접 격리 실행 전에 자기 `app`·bundled `site-packages`를 준비한다. `--help` subprocess 회귀는 import 경계만 검증하며 같은 PC 재설치·키 분실 뒤 실제 서버 복구는 랩 수용에 남는다.

원격 요청과 스캔 내구 저장의 공유 mutex 경합은 로컬 적용 admission으로 분리한다. 등록·시작·온보딩·운영자 spool 복구도 같은 경계를 따른다. 실제 0.3·6·35초 전송기 지연과 공개 스캔 submit→worker→settle, thread/SQLite/native 잠금 중 원격 요청 검출은 headless 소스 회귀 범위다. 실제 화면·스캐너·서버·전원 중단 수용은 별도 확인에 남는다.

스캐너 경고 뒤 UNDO/다음 현품표, 완료 중 FIFO, 교환 CSV 실패/후속 checkpoint 복구, 6칸 교환 완료와 자동 보류 복원 안내와 동기 감사 outbox·checkpoint 결속·CSV 실패/재시작 멱등 재생은 소스 회귀 범위다. 실제 스캐너·소리·화면·중앙 서버 결합은 랩 검증에 남는다.

G10 연결 정상 표시는 성공 envelope 검증 뒤로 옮겼다. 끊김 뒤 redirect·401·403·404·409·`ok:false`·JSON list의 7종은 끊김을 유지한다. 진행 현황·receipt·lease·봉인 공통 경로와 마지막 성공 전송 시각의 소스 회귀를 검증하며 실제 서버 연결/끊김 화면은 랩 검증에 남는다.

[제품·카드](README.md) · [계약](contracts.md) · [운영](operations.md) · [중앙 백로그](../../../Program_Spec_Hub/BACKLOG.md) · [실제 준비도](../../../Program_Spec_Hub/READINESS.md)

미달 완료·취소의 pending 감사 인계/병합, 이전 중첩 기록 재생, 교환 복구 중 감사 반영 진행과 업무 상태의 구별은 소스 회귀로 확인한다. 전원 중단·실제 GUI 종료 및 중앙 거절 뒤 현장 흐름은 별도 랩 검증에 남는다.

미달 UNDO 뒤 원 시각을 유지한 상태 저장·새 프로세스 복구, 교환 선택 취소의 제품 보존, 완료 뒤 UNDO 오류음 호출은 headless 회귀 범위다. 실제 스캐너·오디오 장치 수용은 별도 랩 확인에 남는다.

**현재 상태 — 2026-09-09 S05:** 선택된 여섯 프로그램 qualification은 Main의 독립 composition 검토로 마감됐다. 최종 frozen `d440b1f7`의 요청 범위 native 수용은 **완료(지원 recovery 포함)**이며, 상세 범위는 [CA-G10](#ca-g10)과 [CA-O10](operations.md#ca-o10)을 따른다. 최초 fresh 등록 실패와 아래 과거 시점의 판단을 보존하며 물리 장비·공장 배포는 별도 범위다. 현재 소스 단순화의 변경·검증·독립 검토는 [CA-G11](#ca-g11)에 기록한다.

기준일 2026-09-07. 아래 우선순위와 담당은 정리 제안/책임 역할이며 새 개발 승인·기한·인력 배정이 아니다. P0는 기존 qualification 실패 처리, P1은 계약/운영 판단에 필요한 공백, P2는 요구 미확정 추가 제안이다. 정적 확인, 기존 실행, 이번 문서 검토의 범위는 [README](README.md#ca-evidence-scope)를 따른다.

**이전 validator 문서 작업 이력:** 승인된 다섯 문서의 소스 기준선과 지속 갱신 규칙은 Main 교차 검토 수용을 마쳤다. 당시 후속 작업은 기존 capture validator 통합의 적용성 대조·현재 상태 보완·단일 커밋 검토 준비였으며 제품/test 코드 변경이나 실행을 포함하지 않았다. 해당 조사만으로 별도의 **승인된 제품 기능 미구현**을 확정할 근거는 없다. 추가 아이디어와 찾지 못한 실행 증거를 구현 결함으로 세지 않는다. 대표 13개 기능 카드도 전체 기능 수나 완료율의 분모가 아니다.

2026-09-08 후속 FULL 실패 분석·별도 cleanup과 E의 좁은 fixture 검증은 [CA-G08](#ca-g08)에 기록한다. 앞 문단의 미실행 설명은 이전 validator 문서 작업의 범위이며 이 후속 실행을 포함하지 않는다.

## 문서 작성 진행과 제품 준비도

- 관리자 끄기 요청의 portable 관문 앞 처리·시작 단위 경계·작업자 선택 화면 감시·창 닫힘 뒤 60초 상한은 소스와 headless 회귀로 확인한다. 관리자 SSH·실제 첫 설정·HDD 화면 확인은 별도 현장/랩 검증 대상으로 남긴다([운영](operations.md#관리자-정상-멈춤-요청)).

- **w9cap1fix (P1-2·P1-5·P1-3 CA 몫):** 못 보낸 이적 완료를 새 완료·재시작 없이 30초마다 배경에서 다시 보내고(완료와 같은 3초 한도·FIFO·hold 검사), 화면은 완료 대신 `서버 전송 대기 N건(자동으로 다시 보냄)`, 바닥 한 줄의 보낼 것 수에 완료 전송 대기 수를 합친다([배경 재전송](contracts.md#ca-background-seal-retry)). lease 시각 확인에 서버와 같은 30초 허용, 봉인 완료 시각은 발급 시각 아래로 가지 않게 올리고, 과도기 켬은 발급 전·끊김 조회를 같은 key로 한 번 더 한 뒤에만 로컬로 간다([시계 허용](contracts.md#ca-lease-clock)). 버린 트레이의 쓰지 않은 lease는 서버에 해제 요청한다([기기 해제](contracts.md#ca-lease-release)). [RESULT](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9cap1fix/RESULT.md). 실제 화면·서버 해제 API(w9srvp1fix 판)와의 결합은 랩 몫(NOT VERIFIED).
- <a id="ca-g19"></a>**CA-G19 늦게 커밋된 해제와 같은 PC 재생의 경합 — 확인 필요, 담당 Web·CA:** 해제 요청이 3초에서 끊긴 뒤 서버가 늦게 커밋하는 사이 같은 PC가 같은 현품표를 다시 스캔해 같은 issue key 재생으로 `ACTIVE`를 받으면, 그 트레이 완료는 뒤이어 커밋된 해제 때문에 서버에서 거절될 수 있다(완료 후 관리자 확인, 조용한 유실은 아님). 서버의 발급 재생과 해제가 같은 행 잠금으로 직렬화되는지(`immediate_transaction`) 확인이 필요하다(w9cap1fixrev P2-G).
- <a id="ca-g18"></a>**CA-G18 재시작 뒤 해제 재시도(내구 기록) — 소스 구현:** 기존 lease SQLite에 요청과 최종 결과를 보존하고, 초기화의 상태 삭제 전 요청을 저장한다. 재시작 뒤 원 key·본문으로 재전송하며 사용 중인 lease의 해제는 취소한다. 실제 서버·설치본 수용은 미검증이다.

- **w9caparkpath 1부 (빠른 연속 스캔):** 제품 저장 중 들어온 스캔이 입력창에 남아 다음 스캔과 한 줄로 붙어 제품 1개로 접수되던 결함(w9scanflow F1)을 고쳤다. 저장 중 스캔은 입력창에서 바로 꺼내 순서대로 보관했다가 앞 저장 뒤 처리하고, 처리할 수 없으면(앞 저장 실패·목표 도달 완료·작업 변경·다른 처리 중) 오류음과 `다시 스캔` 안내로 거절한다. `완료 처리 중`에 한 스캔도 오류음과 안내를 낸다(F4). 재검토(w9scanfixrev)가 찾은 정상 종료·ACK 직후 리셋의 조용한 버림도 막아, 보관 스캔을 버리는 모든 경로(작업 전환 12곳·lane 고장·종료)가 오류음과 개수 안내를 낸다. 붙은 값을 제품 검사에서 거절하는 규칙은 넣지 않았다 — 품목 코드 위치가 '어느 위치든'이고 새 판정 정책은 실제 바코드 표본 확정 뒤라는 [제품 admission](product-admission.md) 조건 때문이다. [RED/GREEN·전체 비교](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caparkpath/RESULT.md). 실제 스캐너 속도·화면은 NOT VERIFIED다.

- **w9caparkpath 2부 (보류 파일 경로 260자):** 관리자 보류 표식의 식별 사본 임시 이름이 현장 root(79자)에서 268–302자가 되어 긴 경로가 꺼진 Windows에서 항상 `FileNotFoundError`로 실패하고 그 보류 건이 계속 잠기던 결함, 긴 라벨의 `parked_legacy_` 보류 실패를 고쳤다. 이름의 작업자 16자·라벨 20자 상한과 식별 사본 SHA-256 앞 16자로 모든 새 쓰기가 root 88자까지 들어가고, 이전 이름 파일은 그대로 읽고 이어서 쓴다. 그래도 넘으면 쓰기 전에 평이한 안내로 그 건만 보류한다([이름 길이 규칙](contracts.md#ca-c01)). 현장 PC의 LongPathsEnabled 값은 읽지 않았고 그 설정에 기대지 않는다. [RED/GREEN·전체 비교·같은 부류 조사](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caparkpath/RESULT.md).

- **w9caparkpath 3부 (완료 처리 중 서버 대기, 코디네이터 1820 A):** 완료 처리 중(스캔 거절 구간)에 밀린 이적 의도 전부와 이번 의도를 서버에 동기로 보내, 서버가 멈추면 요청마다 10초가 쌓였다(headless 측정: 정상 0.1초, 응답 없음 10초, 밀린 2건이면 50초). 이제 완료의 중앙 요청 전체에 한 번의 3초 한도를 걸고, 서버가 답하지 않은(시간 초과·연결 실패·5xx) 첫 의도에서 멈춘다. 남은 의도는 durable 순서와 원 key로 다음 완료(`서버 재확인` 포함)·재시작 복구 때 나간다. 로컬 완료 `LINKED`·원장·멱등은 그대로다([규칙](contracts.md#ca-completion-wait)). 남은 경계: 느리지만 답하는 서버는 3초에서 끊겨 다음으로 미뤄지고, 재시작 복구는 여전히 lane에서 밀린 전부를 기존 timeout으로 보낸다. [측정·RED/GREEN](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caparkpath/RESULT.md).
  - **다음 C(목요일 시연 뒤):** 완료 처리 중 스캔을 거절하지 않고 대기열에 받아, 정상 완료 뒤 새 작업에서 순서대로 처리한다. 완료가 잠김·실패·검토로 끝나면 지금처럼 오류음과 `N개 다시 스캔` 안내를 낸다. [제안](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caparkpath/REPORT-1740.md)
  - **다음 B(목요일 시연 뒤):** 중앙 HTTP를 직렬 lane 밖 전송 스레드로 옮기고 command 결속·결과 기록(SQLite)은 lane에 둔다(단일 writer 유지). 완료는 로컬 durable 기록만 기다린다. [제안](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caparkpath/REPORT-1740.md)

- **w9caqueue:** 끊김 표식 `LOOKUP`을 PIN 없이 기존 격리 폴더의 대기 목록으로 옮겨 다음 현품표를 받는다(건수 제한 없음, 승인 효과 없음). 원 작업자 재스캔은 원 FIFO 복원·재조회, 끊김 표식 재시작은 확인창 없이 재조회다. 끊김 중 PIN 격리 메뉴를 끄고 기존 PIN 미확인 복원 거부의 원인·할 일을 바로잡았다. [검증·한계](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caqueue/RESULT.md), [CA-04](README.md#ca-04).

- **w9cadrain2:** 끊김 뒤 drain 거절 경고에 제품 바코드(형식 오류는 원문 대신 보류 순번)와 할 일(상자에서 빼기·한 개만 있는지 확인)을 넣었다. 통신 예외만 `PHS2_PREFLIGHT_UNAVAILABLE`로 보고, 이 PC의 로컬 예외(sqlite 등)는 `PHS2_PREFLIGHT_LOCAL_ERROR`로 이 현품표만 `LOOKUP_FAILED`('PC 처리 오류', 확인=재조회, 관리자 격리)로 둔다. 첫 시작 캐시 없음+끊김의 시작 오류는 계약대로 두고 설치 뒤 연결 상태 첫 시작 1회를 운영 절차로 삼는다. [RED/GREEN·전체 비교·빌드](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9cadrain2/RESULT.md). 보류 시점 CLC 즉시 대조는 후속이고, 여러 현품표 대기는 w9caqueue를 따른다.
- **w9caoffline:** 서버 끊김 중 첫 PHS2 조회 실패가 hold를 `LOOKUP_FAILED`로 바꾸고 입력 전체를 잠그던(관리자 PIN 격리도 끊김 중 불가) 현장 정지를 고쳤다. 연결 실패는 `LOOKUP`을 유지해 이 현품표 제품을 계속 보류 저장하고 30초마다 같은 hold로 자동 재조회하며, 복구되면 사람 조치 없이 기존 판정으로 drain한다. 확정 실패는 지금처럼 이 현품표만 막는다. 조회·끊김 중 현품표 QR이 보류되어 복구 뒤 drain이 멈추던 결함도 막았다. 서버·계약·hold 상태는 바꾸지 않았다. [CA-04](README.md#ca-04), [RED/GREEN·전체 비교·빌드](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caoffline/RESULT.md). 실제 guest 화면·랩 서버 끊김 재연은 NOT VERIFIED다.

- **w9caprofile:** 바로가기 시작의 품목 목록 갱신이 onboarding 사용자 profile을 찾지 못해 기본 운영 host에 무인증 요청(401)·번들 목록으로 떨어지던 결함을 고쳤다. 품목 갱신이 물류 client와 같은 profile 선택을 쓰고, profile이 없으면 요청 없이 기존 목록으로 계속하며 설정 필요·할 일을 보인다. [선택 순서](operations.md#ca-o02), [RED/GREEN·전체 비교·빌드](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caprofile/RESULT.md). 실제 guest 화면·랩 서버 확인은 NOT VERIFIED다.

- **w9caloaderr:** 금일 작업 현황의 읽기 오류를 오류 건수·수량 누락 가능성·관리자 확인 요청 경고로 표시한다. 정상 자료와 정상 0건/성공 문구는 유지하며 폴더 읽기 오류도 구별한다. [RED/GREEN·회귀 근거](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caloaderr/RESULT.md)를 따른다. 실제 GUI 가독성·guest 적용·촬영은 증거 없음이다.

- **w9caretire:** 관리 패키지의 `CompleteRetiredRemoval`이 exact old helper를 호출하여
  기본 루트의 은퇴 marker/receipt·업무·identity를 보존하고 old 코드를 제거한다.
  원 기록에 결속된 중단 재개는 원 owner/authority 종료 후 새 authority를 요구한다.
  일반 marker 부재 거부·Run/relay binding·legacy writer 거부·의미 비교·exact 복원은 유지한다.
  [진입점·한계](operations.md#ca-retired-removal),
  [시험·빌드 근거](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caretire/RESULT.md)를 따른다.
  실제 guest 적용은 NOT VERIFIED이며 배포/공장 수용을 올리지 않는다.

- **w9caclipack:** 기존 relay operator를 portable 외부 도구로 등록한다. 목적지는
  `app/tools/direct_sync_relay_operator.py`이며 묶인 Python·`app/site-packages`와 같은 사용자
  control root의 실행법은 [CA-O01](operations.md#ca-o01) 및
  [operator runbook](../FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md#portable-relay-operator)을 따른다.
  독립 경로/bytes·import 누락 거부·기존 inventory/canonical 의미 보존의
  [검증 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caclipack/RESULT.md)는 소스·packet 범위다.
  실제 설치는 NOT TESTED이며 일반 교체의 구 d69→현재 의미 불일치 거부는 유지한다.
  은퇴 marker를 보존하는 별도 제거 마감은 위 w9caretire 범위다. relay pause만으로 GUI·복구·진행 요청까지
  멈췄다고 판정하지 않으며 배포 보류를 해제하지 않는다.

- **w9cacatalogrefresh:** 실행 중 `운영 작업 ▾ → 품목 목록 새로 고침`을 추가했다. 시작과 같은 로딩 경로·기존 직렬 lane/작업 guard를 사용하며 성공 건수, 실패 시 기존 목록 유지·재시도 안내를 제공한다. RED/GREEN·동일 최종 커밋 전체 3회와 목록/skip 대조는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9cacatalogrefresh/RESULT.md)에 기록한다. 실제 화면·중앙 신규 품목 확인은 미검증이며 [촬영 조작 순서](operations.md#ca-catalog-refresh)를 따른다.
- **w9caautostartroot:** custom 데이터 루트의 HKCU 자동시작·즉시 시작·검증된 교체/설치기 재시작 명령을 같은 루트로 고정하고, custom relay의 루트 소실·접근 오류를 안내 후 중단하도록 수정했다. 기본 명령은 유지한다. [운영 확인·복구](operations.md#ca-custom-root-autostart)를 따른다. 실제 guest 재로그온·오류 대화상자·채택한 데이터셋의 복구/전송 확인은 후속 촬영 레인의 수용 항목이며 이 소스 작업에서 실행하지 않는다.
- **w9cadatarootgui:** 일반 GUI도 기존 HKCU Run의 영속 루트를 읽으며 명시 인자·환경 override·영속 설정·기본값의 우선순위를 공유한다. 환경 없는 launcher/재시작·relay·onboarding 경로와 기본 루트, 루트 소실·권한/설정 오류를 headless 시험으로 검증한다. 실제 guest 바탕화면/시작 메뉴·재로그온·오류창·원본 tail/hold/신원 보존 확인은 미검증이며 [운영 절차](operations.md#ca-custom-root-autostart)를 따른다.

U07 경고·성공 버튼의 [색 규칙](README.md#ca-button-colors)은 normal/active/pressed의 흰 글자 대비 4.5:1 이상을 적용한다. disabled 관례·문구·위젯·바인딩·상태·저장 계약은 유지한다. 실제 모니터/DPI·앱 배율 0.7/2.5·현장 조명 및 교체 두 쌍/footer 확인은 NOT VERIFIED이며 검증 파도 D7과 독립 대비/범위 검토로 넘긴다.

- **U07 검토 중 fake-Tk timeout 관측 — 미해결, 담당 CA:** `316b560`의 `tests/test_scan_persistence_lane.py:318`에서 대기 10초 초과 1건을 관측했고 동일 소스의 해당 두 사례 재실행은 2 PASS였다. 원인은 미확정이며 [실패 원본](D:/KMTech/program-improvement-20260912/work/Container_Audit/w7ca-display/review-tmp/focused/stdout.txt)·[재실행](D:/KMTech/program-improvement-20260912/work/Container_Audit/w7ca-display/review-tmp/focused-retry/stdout.txt)을 보존한다. 해제 조건은 CA가 원인과 재현 조건을 확인하고 기존 assertion·timeout을 유지한 focused pack 및 해당 두 사례 검증으로 해소 근거를 남기는 것이다. 단순 재실행 PASS만으로 해제하지 않으며 이번 수정은 시험을 변경하지 않는다.

U06 제품 형식 오류의 [상황별 다음 행동](product-admission.md#형식-오류-안내의-다음-행동)은 문구에 반영했다. 분류·reason·redaction·수량·일반/held 입력 계약은 유지한다. 실제 경고 영역의 긴 문구 가독성과 물리 스캐너 설정 확인은 NOT VERIFIED이며 배정된 화면·장비 검증 및 독립 문구 검토가 남는다.

현재 스캔 저장·held 감사·GUI 완료의 JSON/CSV 내구 작업은 직렬 worker로 이동했다.
CSV 중복 판단은 전체 내용을 직접 읽으며 색인·metadata 기반 부재 판정은 도입하지 않는다.
합성 callback 시간과 실제 디스크 ACK 시간은 구별한다. 실제 스캐너 연속 입력·저장 지연/실패 안내·종료 drain의 화면 확인과 현장 지연 분포는 남아 있으며 GUI/VM/운영 수용으로 승계하지 않는다.
보류 JSON 전체 검색은 유지한다. 대량 보류의 실사용 건수와 허용 지연을 먼저 확인해야 하며 파일 회전/보관 정책은 이번 소스 변경에 포함하지 않는다.
relay의 변경 없는 ACK 완료 source는 300초 내용 검증 주기 사이에 재읽기를 생략한다. 합성 읽기 바이트 감소와 실제 배포의 CPU/디스크 부하·전송 최신성 수용은 구분한다.
portable direct-sync 자식은 기존 relay startup gate와 writer sink를 거쳐 앱 모듈 없이 실행한다. 프로세스 간 판 확인 캐시는 도입하지 않으며 실제 설치본의 바퀴당 CPU 4초 미만·HDD 적재 시간과 넓은 회귀는 현장 PC inspection6 수용에 남는다.

| 관리 대상 | 당시 상태 | 완료/다음 판단 |
|---|---|---|
| CA 문서 기준선 | 작성·로컬 정적 대조 및 Main 교차 검토 수용 완료 | [AGENTS](../../AGENTS.md), [README](README.md), [contracts](contracts.md), [operations](operations.md), 이 문서가 범위. [IMPLEMENTATION](E:/KMTech/spec-hub-build-20260907/Container_Audit/IMPLEMENTATION.md)·[교차 검토](E:/KMTech/spec-hub-build-20260907/cross-review/REVIEW.md)·[중앙 S01](../../../Program_Spec_Hub/BACKLOG.md#specification). |
| 구현·개발 진행 | 공유 validator 소스 통합의 한정 수용 완료, Main 단일 커밋 수용 완료 | 기존 9개 통합 경로와 명세 5개를 [검토 준비](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/PREPARATION.md)에 연결. 준비 워커의 제품/test/config 코드 변경·staging·commit 없음. |
| 실제 연동·수용 | CA238 한정 수용 및 source68dd FULL 회수·portable build 확인, 목표 설치 조합은 미입증 | 새 전체2,638 PASS/31 SKIP과 별도 host E31 PASS·독립 회수는 [CA-G08](#ca-g08). 원래 FULL102 실패와 보존/reader FAILED, 외부 host 종료 UNPROVEN을 유지한다. |
| 운영 준비 | 설치·실장비·재시작·재설치·롤백·통합 E2E 미완료 | [READINESS](../../../Program_Spec_Hub/READINESS.md)의 기존 판단을 따른다. 문서 완성으로 Ready를 올리지 않음. |

<a id="ca-g01"></a>
## CA-G01 완료·수량·화면 최신성 정의와 근거

- **유형·우선순위·상태:** 요구/지표 확인 공백, P1, 정의 보강 및 실제 검증 대기. 처리 실적을 중앙 봉인 확정량·현재 재고로 오독할 수 있다.
- **현행 근거:** [CA-C03](contracts.md#ca-c03), [CA-C05](contracts.md#ca-c05), [CA-C07](contracts.md#ca-c07) 및 [common_projection의 CA 세션 변환](../../../WorkerAnalysisGUI-web/common_projection.py). `LINKED`, `ACKED`, producer `COMPLETE`, 화면 표시를 구분했고 `pcs_completed`의 조사 경로에 seal ACK 필터가 확인되지 않았다. `EA/Pcs/piece` 동치·업무일/허용 지연은 공통 확정되지 않았다.
- **완료 기준:** 지표마다 원장·모집단·단위·기간/시간대·부분/취소·중복키를 정의하고, 로컬·중앙·수신·화면의 실제 값을 같은 업무 ID로 연결한다. 자정·지연·재생 사례와 허용 최신성 기준을 기록한다. 코드에 ACK 필터가 없다는 사실 자체를 확정 결함으로 단정하지 않는다.
- **담당·의존·다음 행동:** CA+Web 지표 담당/현장 책임자, 중앙 [I02/I03](../../../Program_Spec_Hub/BACKLOG.md#integration). 기존 정의와 대상 화면을 먼저 대조하고 미정 요구를 정한다. 문서/정의 작업은 CA-G07 조사와 독립 가능, 실제 검증은 CA-G04 환경과 연결한다.

<a id="ca-g02"></a>
## CA-G02 위치 검사라는 업무 의미

- **유형·우선순위·상태:** 요구 확인 공백, P1, 현장 정의 대기. 순번 검사를 물리 슬롯 배치 검사로 해석하면 수용 기준이 달라진다.
- **근거:** [CA-06](README.md#ca-06), [event_payloads.build_scan_ok_detail](../../event_payloads.py)의 `scan_position`은 1기준 입력 순번이다. 실물 슬롯 좌표·중앙 location ID를 읽는 필드라는 근거는 없다.
- **완료 기준:** 현장 요구가 입력 순번/실물 배치/중앙 위치 중 무엇인지 명시하고 적용 입력·오류·표시·검증 기준을 연결한다. 새 센서/좌표 기능이 필요한 경우 그때 별도 제안과 범위를 정한다.
- **담당·의존·다음 행동:** 현장 공정 책임자+CA. 현재 트레이 작업 안내와 실제 검사 목적을 확인한다. 코드/VM 작업에 의존하지 않는 요구 정리다.

<a id="ca-g03"></a>
## CA-G03 기존 안내와 현행 지원 경로의 불일치

- **유형·우선순위·상태:** 확인된 문서 불일치/지원 범위 확인, P1. S05에서 CA 소유의 [CODEX](../../CODEX.md), [README](../../README.md), [LOGISTICS_RUNTIME_PROFILE](../LOGISTICS_RUNTIME_PROFILE.md)를 현행 native audio/raster·portable·사용자 profile·LINKED/ACKED 경계로 정정했다.
- **보존한 이력:** 과거 pygame/Pillow·공통 ProgramData profile·별도 profile EXE 안내는 현행 필수 설치 단계가 아니다. 과거 [2026-06 연구](../../../docs/program-research-20260617/container-audit-transfer.md)의 `C:/Sync`·버전은 역사 자료다.
- **범위 확인:** 비compact/부분 제출 코드·Shift-F8 fallback·내부 시험 명령이 존재한다고 일반 운영 지원으로 승격하지 않는다. [지원 경로 표](README.md#ca-supported-entrypoints)와 [CA-C09](contracts.md#ca-c09)를 기준으로 실제 배포/현장 지원 여부를 정리한다.
- **제품 정책 경계:** W5-B2의 [현행 순서·명시 포트](product-admission.md)는 시작13자 호환·substring/catalog 동작을 보존한다. W5-L 공용 leaf 후보 검토와 실제 정책 활성화는 소비자 동등성/샘플·key 호환 요구 확정 뒤의 별도 작업이다.
- **완료 기준:** 해당 기존 문서 소유자가 현행 소스와 역사/호환 조건을 구분해 안내를 정합시키고, 지원 경로·설정·수용 기준·날짜를 연결한다. 새 규칙이나 과거 현장 PASS를 만들지 않는다.
- **담당·의존·다음 행동:** CA 문서 담당+Main. CA 안내 정정은 S05에 포함하며 상위 역사 자료는 보존한다. 비compact/부분 제출 등 현장 지원 범위 재확인은 별도 요구이고 이 정리에서 삭제하거나 승격하지 않았다.

<a id="ca-g04"></a>
## CA-G04 정상·장애·장비·설치 수용 근거 연결

- **w9setupprep sub-85 bootstrap 검토 후속:** 실제 INSTALLING 위임 아래 relay 시작을 해제 뒤로 미루고, launcher PID 대신 보호 active version의 resident PID·fresh status·SID/session/medium token을 확인한다. lifecycle 복구 producer는 승인된 일반 token 경로로 실행하며 위임 네 변수/data root를 메모리에만 전달한다. UAC 안쪽 유한 capture·실제 helper journal/PID binding, escape된 JSON credential 마스킹 및 최종 INCOMPLETE 진단 표기도 교정했다. real-function/native-boundary focused44 PASS와 normal finite wrapper/메모리 환경6 PASS는 host 격리 회귀이며 실제 UAC·token hop·설치5·최종 packet/full suite의 수용을 대신하지 않는다. 독립 재검토·최종 통합 컷 및 랩 결과는 [REPORT](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-84/REPORT.md)에 남긴다.

- **w9cainstallfix3:** trigger/CIM 안전 처리와 직접 script Execute를 유지하며 Python 옵션 앞선 relay runner도 census에 포함한다. 인수의 첫 script는 Python 실행 파일·Windows quoting·옵션 값·정규화 경로와 기존 writer inventory로 판별하고 Notepad/탐색기의 소스 열기는 제외한다. 활성 비정식 writer 차단과 정상 binding hash를 보존한다. P1/P2 RED/GREEN·기존 설치 회귀 및 stock packet/PlanOnly 범위는 [후속 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9cainstallfix3/RESULT.md)에 기록한다. 실제 guest 정식 재설치·UAC·화면 캡처 수용은 후속 캡처 레인에서 확인한다.

- **2026-09-10 일반 복원 창 후속:** accepted `8f7cd08`의 exact 원본 901/902/903은 정상 seal/ACK·보류/닫기/재실행/복원 근거로 수용됐지만, 복원 창 `1944x1182`의 하단 명령 줄 clipping은 별도 실제 관측이다. [고정 수용 기준과 수정 범위](D:/KMTech/optimization-implementation-20260909/Container_Audit/viewport-fix/ACCEPTANCE-BEFORE-EDIT.md)에 따라 일반 복원 rectangle/최소 크기만 실제 monitor 작업 영역에 맞춘다. 기존 startup tests에서 작은 영역·frame·음수 원점의 RED4를 보존했고 영향 검사67 PASS다. 후속 `a97da63`의 일반 복원/최대화 빈 화면은 [실제 GUI 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/vm-candidate-a97da63/GUI-RESULT.md)로 Main 수용을 받았다. 그 범위를 넘어선 전체 UI와 Goal3 전후 사용자 결과 비교는 아직 UNPROVEN이며 Main이 후속 slot을 배정한다. 완료된 업무를 새 SHA 때문에 반복하지 않는다.

- **유형·우선순위·상태:** 실제 검증 공백, P1, 기존 근거 적용성 검토/미실행 범위 대기. 정적 계약 일치와 저장된 응답 재생만으로 현장 동작을 확정할 수 없다.
- **근거:** [CA 연구 S30~31](E:/KMTech/spec-hub-research-20260907/Container_Audit/SOURCE-MAP.tsv), [preflight 테스트](../../tests/test_phs2_master_preflight.py), [transfer seal 테스트](../../tests/test_transfer_seal.py), [교체 server-contract 테스트](../../tests/test_transfer_member_exchange_server_contract.py). BND offline fixture는 compact PHS2 현장 offline 근거가 아니며 저장 HTTP 응답 replay는 실제 서버 CAS 경쟁을 입증하지 않는다. 이번 테스트 파일 실행/수정은 없다.
- **담당·선행:** CA 검증 담당+Main, 필요 시 Inspection/Web/Label 담당. 정확한 소스/dirty 차이·패키지·서버·provider/flags·기존 증거를 먼저 연결하고 CA-G07의 수용 장애를 분리한다. 이미 통과한 시험을 문서 때문에 일괄 재실행하지 않는다.
- **완료 기준:** 아래 적용 시나리오별 소스/환경·로컬/중앙/소비 결과·실제 PASS/FAILED/미실행·원본 증거를 연결하고 필수/비적용 근거를 판정한다. 현재 표는 검증 기준이며 실행 결과가 아니다.

| 범위 | 관측할 수용 결과 | 의존/병렬 가능 |
|---|---|---|
| 정상 공정 | Inspection GOOD 완료→원본 PHS2→CA 전량/lease→seal receipt→Label PACKAGE_SOURCE/F3에서 identity·수량·lineage 일치 | Inspection+Web+Label의 대상 조합 필요 |
| 조회/입력/재시작 | 조회 중 빠른 스캔, 실패·FIFO 포화·재시작 후 동일 PHS2에서 접수 순서/개수 보존 | 격리 local UI/스캐너 범위는 별도 검증 가능 |
| 완료/오프라인/ACK 유실 | lease→intent→checkpoint→receipt/CSV→화면, 원 key·중앙 1회·로컬 1회, 불확실·review 표시와 입력 guard | compact PHS2 및 시간/연결 경계 필요 |
| 취소/보류/저장 실패 | 마지막 취소 롤백, callback 차단, parked 복원 중 종료, 손상 state 격리·소유권·유일 원본 유지 | 격리 저장 실패 시나리오 가능 |
| 두 PC·제품 교체 | 같은 PHS/공여 경쟁에서 한 CAS만 성공, 1~2쌍 원자성·원본 label identity·중복효과 없음 | 양쪽 클라이언트+실제 서버 조합 필요 |
| 출력·사운드·포커스 | print partial/불확실 복구, spool/실물/부착 구분, 경고/무음·포커스·지원 배율·연속 입력 확인 | 장비 요구 CA-G02/G05와 연결 |
| producer·소비 화면 | 재전송/committed 오류·CSV 복구의 receipt 행 합계·projection 중복·기간/수량·API/화면 값 일치 | Web flags·CA-G01 정의 필요 |
| 설치·복원 | 설치 후 첫 업무·cold boot·재설치·교체/롤백 후 current/parked/intent·미전송 상태와 사용자 귀속 일치 | 기존 qualification 권한/대상 고정 필요 |

- **2026-09-08 실제 추가 근거:** 지정 VM의 a7는 정상 cold boot/자동 relay, Uninstall04, Reinstall05와 업무9·identity3 hash 보존·일반 worker 화면을 확인했다. 별도 frozen d440의 새 진짜 교체 receipt·원 owner 종료/cold boot 뒤 공개 Restore09는 native/task0 및 exact a7/Run/relay/업무/identity 복원, failed-new d440·historical68dd 보존이다. 복원 GUI의 F4 target GOOD2도 ACKED/attempt1이며 [CA-O09](operations.md#ca-o09)에 연결한다. 원 f2 record drift와 취소07/동의 미관측08 실패는 유지한다. 강제 crash·실장비·다른 소스/설치본 수용은 이 근거에 없다.

<a id="ca-g05"></a>
## CA-G05 실제 설치 구성·권한·장비 지원 범위

- **유형·우선순위·상태:** 환경/공급자·지원 경로 확인 공백, P1, 미확인. 소스와 설치본이 다른 경로를 선택하면 과거 근거를 적용할 수 없다.
- **근거:** [운영 설정/공급자](operations.md#ca-o02), [장비](operations.md#ca-o03), [contract.lock.json](../../contract.lock.json), [물류 client 생성/capability 검증](../../transfer_seal.py). 사용자 profile·CA 전용 override·legacy 환경, 물류 operation lease와 producer runtime lease, 작업자와 device 권한을 구분한다. onboarding·로더·실제 시작/품목/전송 factory·도구 기본 대상은 같은 사용자 경로를 사용하며 상속된 공용 KM 경로와 ProgramData 기본 파일을 빌리지 않는다(w9setupprep R1). 옛 자료는 보존하며 required는 부재 거절에만 사용한다. 실제 설치본 공존·native DPAPI·GUI·relay·서버·전체 suite/stock 빌더는 별도 NOT TESTED다.
- **완료 기준:** 대상 패키지/수정 트리·Python/Tcl·실제 vendor/overlay·선택된 profile/provider 경로·비밀 제외 scope/epoch·서버 flags/capability·장비 모델/드라이버·지원 UI 경로를 기록하고 관련 기존 증거와 일치 여부를 판정한다. 요청하지 않은 credential/OS 보안 변경을 요구하지 않는다.
- **담당·의존·다음 행동:** CA 배포/운영 담당+Web+Main. 기존 후보 manifest와 보고서부터 확인하고 없는 정보만 후속 확인 범위로 정한다. 구성 대조는 CA-G06 요구 정리와 독립 가능, 실제 현장/VM 접근은 기존 실행 지시에 따른다.
- **2026-09-11 계획 소비 확인:** [소스 audit](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/PLAN-CONSUMER-AUDIT.md)은 CA의 기존 지시 재조회·version 대조와 `EXCHANGE_DATE`/`SPLIT`/`MERGE` 물리 교환 소비를 확인했다. `ADD`/`RESIZE`/`CANCEL` 계획 적용·게시 경로는 Web 소유이며 CA에는 해당 apply 소비자가 없다. 실제 Web 수정→중앙 지시/version→열린 CA 후보 재조회, 날짜/수량 변경 중 active/completed 보존, 오프라인·응답 유실 복구는 배포 조합에서 UNPROVEN이다. 자동 push나 품목 cache를 계획 반영의 근거로 삼지 않는다.

<a id="ca-g06"></a>
## CA-G06 백업·보존·복구시간·성능·인계 요구

- **유형·우선순위·상태:** 운영 요구/검증 공백, P1, 요구 미정. CSV만 백업하거나 ACKED 파일을 자동 정리하면 복구에 필요한 문맥을 잃을 수 있다.
- **근거:** [CA-O04~06](operations.md#ca-o04), [전송 보존 정책](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md). current/parked/hold·SQLite intent/lease·출력 journal·queue/spool/status는 별도 내구 경계이며 `acked_retention`은 cleanup 승인이 아니다. 코드 버퍼·timeout·디스크 임계치는 승인 SLA가 아니다.
- **완료 기준:** 백업 대상/일관성·보관/삭제 조건·복원 책임과 RPO/RTO, 계정/PC 손실 복구, 최대 offline 시간·스캔/전송 처리율·queue 경고·인계 대기를 요구와 실제 측정으로 분리해 확정한다. 복원 시험에서 원 key·완료/미전송 상태·누락/중복 및 사용자 귀속을 확인한다.
- **담당·의존·다음 행동:** 현장 운영/IT+CA+Main. 현재 운영 기대와 기존 복구 자료를 대조한다. 요구 정리는 독립 가능, 복구 실행은 CA-G04·실제 배포 구성은 CA-G05와 연결한다. 미정 숫자·기한·자동 cleanup을 임의 도입하지 않는다.

<a id="ca-g07"></a>
## CA-G07 소스 통합 수용과 보존 실패의 후속 범위

- **유형·우선순위·상태:** 기존 검증/보존 실패는 P0 이력으로 유지한다. [Main 판단](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/MAIN-DISPOSITION.md)은 실제 시험·source/config 보존·현재 유한 수탁을 근거로 **한정된 validator 소스 통합 수용 완료, Main 단일 커밋 수용 완료**로 구분했다. 전체 qualification 수용이나 원래 실패의 해소가 아니다.
- **실제 시험 PROVEN:** [독립 소스 검토](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-independent/REVIEW.md)와 [h02 실제 근거 검토](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-h02-actual-independent/REVIEW.md)의 두 전체 모듈 103+135개는 **238 PASS / 714 ordered setup/call/teardown PASS, FAIL/ERROR/SKIP 0**이다. owner/runner는 자연 종료 0, controller는 자연 종료 2이며 reader thread의 UTF-8 decode warning 4개도 남긴다. 실제 consumer child·exit3·FAIL=0·organization pending 정확히 5개와 기존 oracles를 보존한 결과다.
- **원래 실패 FAILED / 원인 UNPROVEN:** h01의 owner 증거 확보 실패, h02의 index byte/read-only 보존 실패, 최초 Main reader의 conflicting pins로 인한 **guest 읽기 전 실패**는 그대로다. [19:16 KST MAIN-FORENSIC](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-index-forensic-prepare/MAIN-FORENSIC.md)은 469개 path/object ID/mode/stage/flags·TREE bytes 동일, stat cache 71개 차이를 입증했다. 제품 코드 변경은 입증되지 않았으며 정확한 index writer·read-only 변경 원인은 **UNPROVEN**이다. 모든 71개 stat 변화의 필드가 같다고 주장하지 않는다.
- **현재 유한 비교 PROVEN:** [독립 정적 검토](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-current-custody-independent/REVIEW.md) 뒤 Main이 수용한 [실제 readback](E:/KMTech/coordinator-handoff-20260907-01a07992/ca238-current-custody-prepare/MAIN-current-original238-READBACK.json)은 2,672,851 bytes, SHA256 `d916cbcec0892dabb7c771951d21fdc6ff63aea230fe17128e71334b40a88785`다. 7,809 guest·24 host 불일치 0, 지정 identity 57개 inactive, 9개 tree·2개 Ready task·원래 desktop 일치다. 원래 source 94개 중 93개(제품/test/config 80개 포함)는 역사적 identity를 유지한다. 예외는 정확히 `C:\Qualification\vm-test-g6\ca238-g7-h02\work\original238\.git\index` 한 경로다. frozen SHA256 `29484fb1f44e01232dac290c6c4c88b0552a8f28f613b82b80171274b8a7ffdb`/ReadOnly=true와 accepted post-test `b2d03f3f86ce609913070989269bd9d6b5eb73224896299a3b4365ce7dde0f06`/ReadOnly=false는 모두 57,042 bytes이며 각각의 출처로 보존한다. `currentReadback.matches=true`지만 `closureReady`, `inputsPreserved`, `runtimeAcceptance`, `qualification`은 false다. 지속적 provider 무변경·장비 전체 무활동·포괄 보존 성공으로 확대하지 않는다.
- **소스 단위 완료 기준·현재 대조:** [PREPARATION](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/PREPARATION.md)에서 상태 보완 전 기존 9개 통합 경로가 accepted candidate/admitted bytes와 일치하고 원래 238개 순서·설정·consumer 근거가 적용됨을 확인했다. 보완 후 두 integration 안내 문서만 의도적으로 달라지며 나머지 7개 통합 파일과 실행 코드·fixture·config는 그대로다. 기존 명세 5개와 상세 기능/계약/운영 내용은 유지하고 상태 보완의 전후 bytes/diff를 구분한다. Main이 이 소스 단위를 검토해 한 번의 커밋으로 수용한다. 준비 워커는 staging·commit·새 runtime을 실행하지 않았다.
- **담당·의존·다음 행동:** CA 담당+Main, 중앙 [Q01/Q07](../../../Program_Spec_Hub/BACKLOG.md#qualification). Main이 준비된 정확한 14개 경로를 검토·커밋한 뒤 기존 FULL admission과 exact build/freeze, 설치 업무·중앙 도착·restart/cold boot·정상 제거·동일 packet 재설치·rollback·실제 통합 E2E로 연결한다. 후속 FULL의 실제 FAILED는 [CA-G08](#ca-g08)에 기록하며 build·설치·통합 수용은 **NOT TESTED**로 유지한다. [기존 실행/빌드 경로와 남은 기준](E:/KMTech/coordinator-handoff-20260907-01a07992/ca-validator-source-unit-close/worker/NEXT-ROUTE.md)은 계획만 기록한다. 알려진 index metadata 동작을 반복하려고 변경 없는 238개 시험을 재실행할 필요는 없으며 실패 원본/동결 VM source/기존 근거는 불변으로 남긴다.

<a id="ca-g08"></a>
## CA-G08 원래 FULL 102 실패의 교정 후보와 다음 검증

- **유형·우선순위·상태:** P0 환경/fixture 교정의 [독립 소스 수용·16경로 단일 커밋 마감](E:/KMTech/ca-rp-0908/ACCEPTANCE.md) 이후 첫 VM01 target207·MainFull은 **FAILED**로 보존한다. 두 작은 수정 뒤 source482의 새 target207은 **207 PASS/0 FAIL·ERROR·SKIP**, 독립 MainFull도 **PROVEN/stable**이다. 별도 FULL `tests`는 사용자 긴급 정지/복원 뒤 원래 결과를 회수해 **2,638 PASS/31 SKIP/FAIL·ERROR 0**이며 독립 회수 reader도 source/custody 범위 **PROVEN/stable**이다. 원래 FULL은 **FAILED**, 102개 분류와 별도 VM01 cleanup은 완료했다. 제품 결함을 입증한 traceback은 없어 제품 구현과 기존 PID/hash/진단 수용 조건을 유지했다. clean `11b4ac5`의 archive와 모든 생성 근거는 [task root](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/REPORT.md)에 보존했다.
- **확인한 실패:** PS5 pipe encoding 81, venv launcher/interpreter PID fixture 12, commit/object/ref 없는 Git 문맥 7, `datetime.now()`/`date.today()`가 다른 부분 고정 clock 1, exact-executable fixture 1. [전체 색인](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/failure-inventory.tsv)에 node/error/location이 있다. exact-executable 내부 사유와 guest codepage는 미확인으로 유지한다.
- **첫 구체 제안·실제 범위:** [clock fixture diff](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/fixture-clock-proposal.patch)는 `date.today()`를 같은 고정 시각에 맞춘다. 기존 완료 재시도 두 사례는 [baseline 1 FAIL/1 PASS](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/baseline-check.xml), [E 사본 2 PASS](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/clock-candidate-check.xml)이며 assertion·제품 구현은 동일하다. Main 승인으로 이 정확한 patch를 저장소에 적용했고 새 경계 실행에서도 기존 두 사례가 PASS했다. 전체 suite/GUI/서버 수용이 아니다.
- **정리·보존:** [독립 readback](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/CLEANUP-RESULT.md)으로 원래 소유 24개 부재·closure empty·Explorer 불변을 확인해 Main에 VM01 해제를 통지했다. 외부 종료와 두 cleanup 제어 실패 이력을 보존한다. 회수 25개/15,276,300 bytes·expected 13,167 pins 불일치 0과 추가 pyc 한 개는 원래 FULL/일반 export 실패를 덮어쓰지 않는다.
- **구현·focused 검증:** [CANDIDATE](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)의 native interpreter/venv·즉시 cleanup·genuine base executable·strict UTF-8 후보를 구현했다. 초기 경계 14 PASS와 authentic Git checkout의 7개 기존 provenance 사례 PASS를 기록한다. 긴 E 경로의 PS5 native file 실패 7개와 in-root retry 2개는 실패로 보존하며 초기 실행의 3개 capability SKIP도 PASS로 바꾸지 않는다. 전체 변경과 source/index identity, 최종 focused 범위는 후보 보고서를 따른다.
- **최종 focused 결과:** 최종 [short E/Windows venv 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03.xml)은 **204 PASS / 3 capability SKIP / FAIL·ERROR 0 (207개)**다. 원래 102개 실패 node 중 100 PASS·8.3 alias capability SKIP 2개이며, PID 12개와 Git 7개는 모두 PASS했다. [유한 child 관측](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03-children.json)은 기록된 relay PID 37개 중 active owned 0이다. 원래 FULL FAILED·guest codepage/원래 exact-artifact 내부 사유 미확인·대상 FULL NOT TESTED를 유지한다.
- **소스 마감 근거:** replay 계정의 새 검토자가 원래 patch·tree·481개 blob과 실제 JUnit·child/identity 기록을 독립 대조했다. 제품/fixture/test byte 변경 없이 같은 세 명세의 상태만 추가 갱신했고 기존 207개 host 실행을 반복하지 않았다. 정확한 successor commit/tree·새 bundle/archive는 [SUCCESSOR-MANIFEST](E:/KMTech/ca-rp-0908/SUCCESSOR-MANIFEST.json), 원래 207개 node 목록과 실행 요건은 [TARGET-HANDOFF](E:/KMTech/ca-rp-0908/TARGET-HANDOFF.md)를 따른다. 실제 계정 metadata와 native 검토 시각도 E 근거에 남긴다.
- **실제 대상 준비 완료·수용 대기:** Main 수용 `e1db07a`의 source481·genuine bundle/archive와 기존 VM01 control을 바인딩한 [준비 보고](E:/KMTech/ca-target-rp-0908/REPORT.md), [현재 입력 identity](E:/KMTech/ca-target-rp-0908/PREPARED-INPUTS.json), [명령](E:/KMTech/ca-target-rp-0908/NEXT-COMMANDS.md)을 준비했다. guest E를 가정하지 않는 짧은 `C:\Qualification\ca207\s`와 별도 `C:\Qualification\cafull\s`, 새 support admission, 원래 207개 ID, actual collection 기준 FULL `tests`, 제한된 child/identity·raw stream export/Main reader를 연결했다. host control fixture 검증만 수행했고 제품 시험·VM 접속·provider 실행 수용은 **NOT TESTED**다. 구현은 동결 커밋 그대로이며 이번 세 명세의 상태 차이는 실행 packet과 분리한 미커밋 문서 변경이다.
- **실제 target207 실패·회수:** [실행 보고](E:/KMTech/ca-execution-rp-0908/REPORT.md): Support8,539개 stable/불일치0, source481 Stage, 독립 MainStage13,665개 PROVEN 뒤 exact207 collection을 확인했다. 첫 readonly scratch installer 수정에서 **0P/2F/0S**, 원래 maxfail2에 따라 205개 미실행이며 capability skip은 관측하지 못했다. 실패용 Export45/45개·9,218,869바이트는 stable/누락0이다. MainFull은 별도 `controller.executable=null` 때문에 **FAILED/Base controller argv differs**, `actual=null`; 마지막13,666개 보존 대조0불일치·원래81 inactive·잔여 lane0·recorded child0이다. 원래 FULL 실패와 별개로 보존한다.
- **좁은 수정·실제 검증:** 동결 원본을 유지하면서 공통 fixture의 7개 scratch 복사만 `copyfile`로 바꾸고, 원래 17 selector 밖에 [회귀](../../tests/test_portable_fixture_source_permissions.py)를 추가했다. host RED1→GREEN1, 실제 변경 바이트를 쓰는 최종 회귀1 PASS/0.22초 및 기존 두 영향 사례2 PASS/31.64초, 기록 relay6개 부재를 확인했다. 실제 retained handle에서 image를 읽는 별도 E 제어 후보는 PS5/PS7의 host native 확인을 통과했다. Main이 두 수정 방식을 수용한 뒤 [새 후보](E:/KMTech/ca-execution-rp-0908/successor/SUCCESSOR-MANIFEST.json) `68dd0c52`/tree `59605602`·482개 blob과 [새 focused/조건부 FULL packet](E:/KMTech/ca-execution-rp-0908/successor/PREPARED-INPUTS.json)을 준비했다. 기존 실패 ca207의 564개 pin·task 결과2·총85개 과거 identity 보존 조건과 원래 선택·수용 조건을 결속했으며 소비된 제어는 변경하지 않았다. 로컬 pin/구문 확인과 새 guest 수용은 별개이며 후자는 **NOT TESTED**다. 이 준비 시점의 C 변경은 미커밋이었고 E 후보 마감 뒤 준비 상태 설명은 세 명세만의 별도 차이였다.
- **새 실제 focused 수용:** [독립 MAIN-Full](E:/KMTech/ca-execution-rp-0908/successor/packets/focused/logs/MAIN-Full.json)은 actual207 PASS,621 phase,sourceTestsPassed·controlsPassed·processClosure=true와42개 기록 child 부재를 확인했다. 원래 선택·순서가 일치하고 capability SKIP은0이며 과거 host3SKIP을 대신 쓰지 않았다. 45개/9,972,263바이트 회수와 정확한 guest controller image를 확인했고, 만족한 조건을 Main에 보고한 뒤 `cafulln` fresh Support/source482 Stage/독립 MainStage를 통과해 전체 `tests`를 시작했다.
- **긴급 정지 후 재개·통합:** [재개 보고](E:/KMTech/ca-resume-0908/REPORT.md): C 저장소에 수용 커밋 `68dd0c520ed2b8bd585301999cb35624702a05a5`를 통합하고 이전 작업 트리·최신 상태 문서와 E 실행 후보를 보존했다. focused207/FULL을 다시 실행하지 않았다. 지연된 새 host 관측기만 정확한 identity로 중단했고 Main의 메모리 상한 조정 후 기존 결과가 회수됐으나 실제 할당 증가·인과 관계는 미입증이다. 원래 host 자연 종료/외부 EOF와 supervisor의 외부 retained-native 종료는 **UNPROVEN**이며 대체 metadata를 만들지 않았다.
- **전체 실제 결과·독립 회수:** [MAIN-Full](E:/KMTech/ca-resume-0908/MAIN-Full.json)은 2,669 collection/JUnit,7,976 phase, **2,638 PASS/31 SKIP/FAIL·ERROR 0** 및 guest owner/controller 자연 종료0을 확인했다. Export45/45개·15,368,109바이트·불일치/누락0, 마지막05:05:04.1286232Z에 input14,231개 불일치0·metadata 문제0·task Ready/exit0·remainingLane 없음·child42개 ABSENT다. Main은 VM01 반환을 수용했다. 동일 source68dd에서 E-drive 조건의 **정확한 guest SKIP31개가 별도 host E 실행31 PASS/0 SKIP**인 [JUnit](E:/KMTech/ca-n31/runs/e8006c0e57/junit.xml)을 원래 guest SKIP과 구분한다. 원래 subprocess UTF-8 decode thread 경고6건·기존 모든 실패·거부된 scratch cleanup 제한은 보존한다.
- **실제 portable build·artifact 준비:** Main이 기존 source 공개키와 CPython3.12.10 x64를 배정한 뒤 unchanged source68dd의 [기존 builder](E:/KMTech/ca-build-0908/build-result.json)는 자연 종료0/9.688초·stderr0이다. packaged runtime import closure·exact dependency7개·writer inventory, PE46개 Valid/unsigned0, canonical PlanOnly·helper DryRun 종료0을 확인했다. 첫 PlanOnly의 inherited module 경로 실패는 보존했고 repository runner와 같은 Windows module 경로를 자식 환경에만 적용해 성공했다. [ZIP identity](E:/KMTech/ca-build-0908/artifact.json)는17,156,131바이트/2283개 파일·SHA `b8dcd72c0205201eadda5a93d531a767e7ff9552b8519067468d1bfb7de84b40`, CRC·manifest 일치다. 키 생성·trust 변경·signature bypass는 없다.
- **담당·다음 행동:** CA의 source tests·회수·custody·소스 통합·정확한 portable build/로컬 준비는 위 범위에서 완료했고 Main이 중앙 수용과 다음 자원을 소유한다. readonly 원본·source/archive/index·default capture·제품 assertion은 유지했다. [설치 인계](E:/KMTech/ca-build-0908/INSTALL-PREPARATION.md)의 같은 artifact로 Main이 배정할 새 VM/current-user/개발 HTTPS origin에서 실제 설치·업무 GUI·restart/cold boot·uninstall/reinstall·rollback·backend 통합을 검증할 차례이며 모두 **NOT TESTED**다. signed feed/키 회전 호환과 예전 exact-artifact 내부 사유는 미입증이다. VM01은 반환됐으며 새 host 기록만을 위해 source tests를 반복하지 않는다. 중앙 Q01 차이는 Main에 통지하고 **Ready 0/6**은 유지한다.

<a id="ca-g09"></a>
## CA-G09 복사 VM의 등록 충돌과 일반 설치 후속

- 설치·등록 주소 불일치의 READY/재사용 차단은 로컬 가짜 상태로 검증한다.
  실제 재설치·상주 relay·현장 안내창 확인은 별도 랩 수용 범위다. 주소 기록 부재나 판독 실패는 기존 동작을 유지한다.

- **11:55Z 현재 판정:** 지정 VM의 정상 등록 recovery·a7 업무/설치 lifecycle, d440 진짜 교체/취소 회복/공개 Restore09, 복원 a7 F4 target GOOD2 ACK와 마지막 cold boot까지 실제 확인했다. Main은 d440 source review와 Restore09의 exact 증거를 독립 수용했고 Web은 F4 receipt1/exact2를 확인했다. F4는 Label/Web에 명시 인계, VM은 Off로 Main에 반환하여 CA의 적용 가능한 일반 qualification 작업을 완료했다. 이전 bullet의 미실행·실패는 당시 이력이다. 남은 독립 경계는 F4 downstream 교체/포장 수용, case03 expired/unreconciled의 Main custody, 실장비/강제 crash/다른 환경이며 전체 Ready를 임의 승격하지 않는다. [CA-O09](operations.md#ca-o09)와 [최종 실행 보고서](E:/KMTech/ca-install-qualification-20260908/REPORT.md)로 source/artifact·VM 반환·증거 범위를 대조한다.

- **유형·우선순위·상태:** 실제 qualification 후속, P1, 첫 fresh 실패 보존·정상 recovery와 후속 설치 PASS·업무 검증 중. [첫 시도](E:/KMTech/ca-install-qualification-20260908/REPORT.md)의 frozen source68dd/동일 ZIP은 guest PlanOnly·HTTPS·일반 사용자 token·코드 배치까지 통과했으나 registration `producer_identity_conflict`로 canonical exit1 / **FAILED_ROLLED_BACK**다. 위 CA-G08의 설치 NOT TESTED는 빌드 당시 이력이며 현재 결과에 자동 적용하지 않는다.
- **원인·보존할 계약:** 초기 로컬 6종 자료 ABSENT와 새 possession key가 있어도 MachineGuid+SID+app 파생 lookup ID는 기존 중앙 active epoch6과 일치했다. [CA-C10](contracts.md#ca-c10), [Web 공개 lineage](E:/KMTech/web-integration-20260908/ca-enrollment-lineage.json). Main의 기존 소유 배정 후 정상 recovery가 epoch7과 manifest/서버 검증을 통과하고 별도 Web operation grant가 승인됐다. 임의 ID·키 삭제나 인증 우회는 없으며 식별자 파생 정책은 유지한다.
- **복원·현재 소스:** lifecycle rollback 후 Run/relay/등록 자료 부재를 확인했지만 새 verified code는 남는다. 현재 소스는 이 경우의 상태를 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`로 바로잡고 경로 경고를 추가했다. 신규 fresh 실패1·기존 교체 복원1 회귀 PASS이며 frozen 설치본에는 미포함, 전체 exact rollback은 **UNPROVEN**이다. 원래 실패11파일과 성공 후속13파일은 별도로 hash 일치 보존했다.
- **현재 업무·정리:** case01 mixed NG work group을 즉시 GOOD-only 양성 사례로 취급하던 fixture 가정은 Web readback을 근거로 폐기했다. 원래 거부·NG 이력과 hold는 정상 QA supervisor 설정·masked GUI 인증·제품 quarantine으로 보존했고 ordinary WORKER로 돌아왔다. case02 preflight/목표2·부분 제출 거부·중복 거부·보류/정상 앱 재시작/동일 snapshot 복원·정확한2개 GOOD 로컬 완료는 실제 PASS 범위다. 이 흐름에서 안전한 상태를 건너뛰는 새 validator나 임의 파일 조작은 추가하지 않았다.
- **담당·다음 행동·완료 기준:** 일반 후속 설치는 exit0/PASS·READY/REUSED이고 정상 recovery 후 실제 case02 seal은 Web 전역 JSON validator의 `INVALID_INPUT`으로 OPERATOR_REVIEW/attempt1이다. Web은 보호된 실제 command의 거부 predicate와 정상 수정 경계를 확인한다. CA는 원본명령·LINKED/TRAY_COMPLETE를 보존하고 [CA-O09](operations.md#ca-o09)의 중앙 ACK/별도 producer·화면 대조·case03·cold boot·제거/재설치와 적용 가능한 exact rollback을 계속한다. 첫 fresh 실패·seal 실패·미실행을 유지하며 source 회귀·문서 갱신·producer 성공 자체를 종합 Ready나 물류 ACK로 합치지 않는다.
- **확인된 복구 한계·승인 후속:** frozen `TransferSealCoordinator.attempt`는 OPERATOR_REVIEW에서 즉시 반환하고 pending 목록도 제외한다. 기존 UI 재시도는 command bind 전만 지원하므로 Web 수정만으로 이 terminal intent를 정상 same-key 재전송할 수 없다. Main `msg_9d5415ea3be1`의 명시적 승인으로 불변 command/동일 key/정상 receipt 검증을 유지하는 관리자 확인 재시도를 source에 구현했다. 자동 terminal retry·DB 수선·원래 완료 시각 변경은 없다. Web 관측 lease 만료는08:11:34Z이나 원래 완료 시각은 기간 안이다. Web `msg_e3bd2837e6a3`는 현 server가 기존 receipt를 먼저 재생하며 미확정 lease도 원래 완료 시각·서명·fence·상태를 대조해 늦은 제출을 판정한다고 확인했다. 변경 후보 build/정상 설치/실제 원 key ACK는 아직 미실행이며 frozen 실패는 유지한다.
- **09:31Z 실제 해소·남은 범위:** 첫 변경 후보 `fc24bc7`의 stale inventory pin에 의한 PlanOnly 실패를 보존하고 pin3곳을 맞춘 `a7d714f6` ZIP의 정상 교체는 PASS다. 실제 관리자 메뉴의 원 case02 재시도는09:21:22Z ACKED/attempt2이고 원 command/완료 시각·LINKED1/review1 유지 및 중앙 receipt1을 Main/Web이 수용했다. 새 case04 목표3·스캔 취소/재스캔·전량 완료는 ACKED/attempt1/LINKED1이다. 과거 문단의 미실행/실패는 그 시점의 이력으로 남긴다. case02 exact product QR는 Label에 소유 인계했고 재수정하지 않는다. 미착수 case03의 expired/unreconciled lease·정상 보류1152B는 삭제하지 않으며 Main `msg_69014d6df084`가 custody를 맡아 독립 cold boot·제거/재설치·지원되는 rollback을 계속한다. [실제 증거와 잔여](operations.md#ca-o09)를 근거로 판정하며 fresh 실패 자체와 종합 Ready0/6을 성공으로 바꾸지 않는다.
- **09:57~10:45Z lifecycle·복원 후속:** exact a7의 일반 cold boot·자동 relay·uninstall/reinstall·현재 업무/identity 보존은 실제 PASS 범위다. 첫 f2 receipt는 old68dd preimage가 남아도 current a7의 정상 재설치 record hash와 달라 재사용할 수 없다. Main `msg_f47a9cbad540`/`msg_4189c4bb64b6`는 원본 drift를 보존하고 fresh ownership으로 공개 code-only restore를 구현·새 정상 교체/원 owner 종료 후 실제 복원하도록 승인했다. 현재 source의 lower helper5 PASS와 controller fixture 경로 길이 실패/수정 검증을 구분한다. 새 frozen artifact/정상 교체 receipt/old code와 relay의 실제 실행/두 ACKED·미착수 보류·identity 보존이 남으며 설치본 a7의 기존 PASS를 그 후보에 자동 승계하지 않는다.
- **현재 source 결과:** 공개 controller6·lower helper62·기존 canonical/uninstall/inventory64의 해당132사례는 PASS다. 최초 긴 fixture 경로6 FAIL과 정적 호출 수1 FAIL은 원본으로 보존하고 필요한 범위만 수정·재확인했다. [CA-O09](operations.md#ca-o09)의 exact source inventory/실제 a7 writer 의미 대조까지 확인했으며, 다음은 정상 successor 교체로 새 receipt를 확보한 뒤 원 owner 종료/재시작 이후 취소·공개 복원·일반 old runtime과 업무/identity 보존의 실제 수용이다.

<a id="ca-g10"></a>
## CA-G10 최종 frozen d440의 별도 fresh 대상 수용

- **유형·상태:** 최종 산출물 qualification 후속, P1, 요청한 native 수용·근거 정리 **수행 완료(지원 recovery 포함)**. 별도 c029 VM의 실제 CA 부재·exact d440·ordinary PlanOnly0, 지원 등록/설치 계속, 기본 첫 작업자/GUI, 실제 cold boot와 정상 제거/재설치 및 사용자 상태 보존을 [CA-O10](operations.md#ca-o10)과 [최종 보고서](E:/KMTech/ca-final-qualification-20260908/REPORT.md)에 연결한다. 최초 Install01의 자연스러운 ownership 충돌/native1은 **FAILED**로 남기며 무지원 fresh 등록을 PASS로 닫지 않는다.
- **실제 결과·담당:** Main의 새 QA 소유 배정과 Web 단회 recovery로 실제 생성된 current_user key/epoch8을 등록한 뒤 Install02·Uninstall03·Reinstall04는 각각 native/task0다. 실제 빈 작업자 목록에서 CA-FINAL-QA를 등록했고 cold boot/재설치 후 같은 이름으로 기본 GUI를 재개했다. 작업자/설정2·identity3 파일의 exact 보존, 제거 시 코드/Run/process 부재, 재설치 시 exact d440/새 integrity record를 분리 확인했다. VM은14:43:14Z 정상 Off로 Main에 반환했고 CA의 추가 native 실행은 남지 않았다. 임의 identity·token·ledger·clock 수정과 업무 재연은 없다.
- **재사용·남은 제품 경계:** Main이 이미 수용한 d440→a7 Restore09와 변하지 않은 a7 업무 근거는 원래 candidate/receipt/VM 범위로 재사용했다. 새 VM 때문에 같은 교체/복원 cycle이나 FULL/빌드를 반복하지 않았으며,132 affected 사례도 원래 동일 입력 범위의 근거다. 추가 실패나 관련 동작 변화가 없으면 추가 실행은 필요하지 않다. 복사 OS 대상의 최초 등록 실패, `OPERATION_PENDING` 권한 상태, 물리 스캐너/프린터·공장 배포·전체 readiness는 각각 별도 미수용/미검증 경계로 유지하며 CA-G09와 case03/F4의 기존 소유·수용 상태를 바꾸지 않는다.

<a id="ca-g11"></a>
## CA-G11 승인된 S05 소스 단순화

- **W9 시험 감사:** headless 기준선의 실패는 불완전한 idle callback 대역, 외부 basetemp에
  종속된 runner probe, writer 의미 변경을 무시한 구버전 설치 fixture, 관리자 재시도 UI의
  내부 진단 표시로 구분한다. guard·원 assertion을 유지한 수정과 동일 커밋 전체 반복의
  수치·제외 범위는 [감사 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9catestaudit/RESULT.md)에 기록한다.

- **W6 CA-2 완료 orchestration:** [경계](tray-completion.md)에 따라 732행을 명시 owner 함수로 이동하고 최종 state 적용과 notice를 분리했다. 기존 signature·prepared attempt·local ACK·held FIFO·중앙 retry 순서는 유지한다. [구현 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6ca2/RESULT.md)에 AST/순서 벡터·기존 focused·packaging/inventory 근거를 기록한다. stored attempt·ACK/입력 순서·writer pin/packaging은 독립 검토 후 수용하며 실제 GUI·스캐너·설치는 별도 범위다.

- **W6 CA-0 모듈 분리:** HTTP client·`SealAttempt`·profile factory, SQLite Store와 공유 오류/값/owner guard를 별도 모듈로 이동하고 기존 façade import를 유지한다. [모듈 계약](contracts.md#ca-c03)과 [검증 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6ca0/RESULT.md)를 따른다. stored attempt·ACK/입력 순서·writer pin/packaging 소비자의 독립 검토가 후속이며 GUI·설치 수용은 포함하지 않는다. CA-1/CA-2의 후속 구현 근거는 각 경계 문서와 결과를 따른다.
- **W5-S0-CA context 전달:** 기존 profile/legacy client와 runtime scope의 5개 호출을 named 인자로 바꾸고 positional/default·wire·내구 복구를 유지했다. [CA-C03/05](contracts.md#ca-c03), [검증·parity 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w5s0/RESULT.md)의 최종249 PASS·고정 입력8항목 동일·inventory check PASS를 확인했다. 다음은 coordinator diff 검토와 P0 정착 뒤 Web S0, CA+Web 수용 후 LM→DI→IW→RW 인계이며 새 Shared leaf·tenant/line·다중 scope는 포함하지 않는다.
- **X14·E01 시험 격리:** 기존 runner의 D 기본/override·쓰기 감시와 autouse worker
  close/drain을 [시험 격리](operations.md#ca-test-runner)에 정의한다.
  최종 focused·Git clean·생성물/잔류 thread 근거는
  [X14 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x14/RESULT.md)를 따른다.
  제품 shutdown 변경이나 native OS 쓰기 전부의 감시를 의미하지 않는다.
- **W6 H0 runner:** 짧은 `D:\KMTech\t\ca` 기본·240자 후보 경로 사전 계산과
  실행 전후 SHA/dirty/fingerprint 기록은 [시험 격리](operations.md#ca-test-runner)를 따른다.
  검증·남은 독립 검토는 [H0 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6h0/RESULT.md)에 기록한다.
- **X13-B 설치 leaf 채택:** shared 0.3.1/5파일·독립 manifest pin·자급 checker와 portable/PyInstaller·writer source inventory를 결속한다. 신뢰된 bootstrap 검사 뒤 동일 SHA/path 및 Manifest의 세 블록만 위임하며 runtime facade·factory lock·CA lifecycle validator binding을 유지한다. PS5.1/PS7 parity·합성 설치/제거/복원 회귀의 범위와 실제 lifecycle NOT VERIFIED는 [X13-B 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x13b/RESULT.md), [현재 구성](operations.md#ca-o01)을 따른다.
- **X13-B 배열 거부 복원:** 정본 0.3.1 전체 5파일·manifest·독립 pin을 재채택하여 원 CA의 PS5.1 `[manifest]`·PS7 `[[manifest]]` 거부를 복원한다. 0.3.0의 두 FAIL을 보존하고 3중·빈·중첩 빈 배열 회귀 및 검토의 긴 경로 13 FAIL·8.3 조건 2 SKIP을 무수정 짧은 경로에서 재검증한다. 판정·원본·재실행 증거는 [X13-B bump 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x13bbump/RESULT.md)를 따른다.
- **bootstrap cross-engine:** 새 integrity 목록은 상대 경로 ordinal 정렬이며 기존 record는 exact path/size/hash 일대일 대조와 원래 aggregate 검증으로 byte identity를 유지한다. PS5.1/PS7·ko-KR/en-US의 교차 소비, 변조 거부, Access/Owner/Group ACL identity 및 구버전 upgrade 회귀는 [H-CA-PS 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6hcaps/RESULT.md)를 따른다. 이전 PS7 FAIL은 보존하며 실제 설치·관리자 ACL·운영 배포는 별도 범위다.
- **X05-B 고정 버전 교차 검사:** explicit canonical 검증은 앱 `source_commit`의 package/checker를 읽는다. 다른 레인의 정본 HEAD/작업 트리 확장 및 현재 파일의 구문·인코딩·I/O·Git 조회 오류는 고정 대조 후 안내로 격리하며 0.2.0 채택 실패로 처리하지 않는다. pinned byte 불일치는 계속 거부하며 기본 standalone 검사와 factory lock은 그대로다. [P2 회귀·검증 범위](D:/KMTech/program-improvement-20260912/work/Container_Audit/x05bfix/RESULT.md).
- **X05-B runtime 채택:** 0.2.0/4파일 pin·25개 CA facade와 writer inventory를 [CA-C05](contracts.md#ca-c05), [CA-O01](operations.md#ca-o01)에 정의한다. 합성 SQLite/fake transport 회귀·산출물 경로 diff와 미검증 범위는 [X05-B 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x05b/RESULT.md)를 따른다. GUI·서버·운영 설치 수용을 확대하지 않는다.
- **X04-B shared 채택:** raster facade·고정 source/manifest/lock·패키징 검증은
  [CA-O01](operations.md#ca-o01)을 따른다. 실제 배포·GUI·프린터 수용을 확대하지 않는다.
  pin 검사는 앱 QA 진입점으로 자급하며 단독 checkout 회귀를 유지한다.
  정본 checker 갱신 시 기본 수집 밖의 명시 교차 노드로 복사된 검증 함수의 동등성을 확인한다.
  catalog는 정본 0.1.0이 제공하는 leaf만 위임하며, 상태 있는 cache I/O·복구·snapshot의
  추가 공유 여부는 후속 판단이다. 현재 CA adapter 동작은 유지한다([CA-C08](contracts.md#ca-c08)).
- **범위:** 호출되지 않는 UI·업데이트·relay helper, TEST1 transport-pin validator,
  Phase G synthetic report 및 그 보고서 전용 시험을 제거했다. 실제 업무·오류/재시도
  회귀와 runtime/shared provider·설치 consumer는 유지한다.
- **검증·보존:** [CA-O11](operations.md#ca-o11)과
  [RESULT](D:/KMTech/s05-simplification-20260909/Container_Audit/RESULT.md)에 정확한
  base/final commit, focused 명령·결과·한계와 남긴 도구의 이유를 기록한다.
  accepted `d440b1f7`·원래 실패·production CONTAINER_AUDIT1–3은 유지한다.
- **다음 행동:** Main이 이 소스 변경을 독립 검토한다. 이는 마감된 선택 여섯 프로그램
  qualification의 재실행 조건이나 새 배포 승인이 아니다.

<a id="ca-g12"></a>
## CA-G12 스캔 판정·다음 입력 최적화와 실제 VM 업무 수용

- **2026-09-12 실제 M06 CA 구간 완료:** 현행 제품 `0ea7251`로 원본 PHS2의 GOOD1/정확한 멤버 1개를 처리해 로컬 완료 1건, 중앙 봉인 `COMMITTED`, 동일 receipt의 `ACKED/attempt1`, producer accepted/committed/`COMPLETE`를 확인했다. 원본 PHS는 `CONSUMED/v2`, 실제 Label 대상은 `TRANSFER-9BFF9D4E70D69D6E4B16FA9E`의 `AVAILABLE/v1/member1`·active seal/rev1이다. 원래 3개 완료와 upstream 근거를 보존하고 정상 종료·원본76a3 `Saved/0` 반환 뒤 Main이 업무 인계/반환을 수용했다. [결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/M06-final-20260912/RESULT.md), [실제 인계](D:/KMTech/optimization-implementation-20260909/Container_Audit/M06-final-20260912/LABEL-HANDOFF.json), [복구 경계](operations.md#ca-o12)에 최초 등록 충돌·만료 공개 CA·원래 operation grant 만료와 지원된 후속 조치를 남긴다. 이 항목은 CA 단일 업무 구간의 완료이며 Label/Web 이후·새 실제 작업 접수·일반 지연 분포/p95·물리 장비·전체 Goal 완료를 뜻하지 않는다. 이전 단회/실패/성능 한계와 별도1024×768·글자2.5 교체 행 clipping을 유지한다.

- **2026-09-11 잔여 Goal host 준비:** [실행 설계·입력·한계](D:/KMTech/optimization-implementation-20260909/Container_Audit/remaining-goal-prep-20260911/PLAN.md)는 원본9e/최종2b와 기존50행 workload를 고정한다. 원 문서에 native 표본 수가 없음을 확인하고 Main의 설계 지시에 따라 경험적p95가 최대값과 달라지는 최소 짝수20쌍/40arm을 선택했다(AB/BA 각10쌍, 행동별 후보당20개; population p95 보장은 아님). 실제 Return→첫 의미 있는 표시/정확한 내구·전체 표시/다음 실제 접수 상한과 capture·poll·controller pacing을 구분한다. 최초 안전 입력 시각은 UNPROVEN이며 새로운 SLA나 회귀율은 없다. unsigned 첫 block12파일·양쪽140 Git blob·경로만 바꾼 세 파일과 parser를 확인했고, 나머지19 block의 유한 binder는 준비만 했다. 제품/observer 로직 수정·guest·서명·bulk IO·분포 실행은 NOT TESTED다. Main의 실제 방법 검토와 자원 배정 뒤 이 설계를 실행하고, 별도로 실제 M06 최종GOOD1 현품표·멤버십을 받아 봉인→Label→출하를 확인한다. 원8f7 multi-member 보류/복원은 원 증거로 재사용하며 target1 수량 증가·원901–904 재생·선택적 decoder 추가 pair는 없다. 전체0/6을 유지한다.

- **2026-09-11 실제 이미지 전후 pair:** Main 배정6fcb VM에서 동일 observer/controller·서명 fixture·1920×1080으로 원본9e와 최종2b를 한 번씩 실행했다. [원본·계산·의미·자원 보고](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-IMAGE-OPTIMIZATION.md)는86파일/48 원본 PNG·양쪽140 source·실제 focus/admission·held append/ACK1·SCAN_OK2/중복1·정상 app/controller native0와13:38:56Z 전체 guestIO 반환을 보존한다. 해독260.8662→7.5839ms/전체 이미지446.7746→217.4882ms와378×138 전체 픽셀 동일은 이 단회 이미지 경로의 관측 결과다. 응답 해제→완전 이미지+1/3 보수적 상한1152.2920→560.2907ms와 조건부984.6079–1152.2920→300.0841–560.2907ms를 분리하며 전체 전후는 이전 수정도 포함한다. 원본 중앙 held0 결함은 FAILED/제한으로 남기고, current0014의002 행만 갱신된 화면을 완전 결과에서 제외한다. 일반002 완전 결과 상한63.5051→155.8373ms·중복66.8941→67.0157ms로 일반 스캔 향상을 주장하지 않는다. 원본/최종 modal은 기존 행을 가리므로 가시 결과는 이전 non-modal 원본으로 판정한다. 실제 Claude 결과 검토는 제품·증거 필수 수정0이고 Main이 단회 decoder 범위를 수용했다. 문서R1은 보고서 선두/원인 분해에220.057ms PHS finish·442.446ms 후속 drain·29.064ms poll 기여를 명시해 교정했다. [최종 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-PAIR-RESULT.md)와 [원래 목표·M06 인계](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/REMAINING-GOAL-HANDOFF.md)를 보존하며 연결 전체 업무·일반 지연 분포·p95·최초 안전 입력·전체0/6은 미완료다.

- **2026-09-11 decoder 소스 검토 수용:** 실제 Claude의 [정확한2b5127b 독립 검토](D:/KMTech/optimization-implementation-20260909/COORDINATOR-RECOVERY-20260911-1144/ca-tray-decoder-review/REVIEW.md)는 PASS/필수 수정0이며 Main이 수용했다. 2,822개 합성 이미지·29개 잘못된 입력과 실제 트레이 픽셀·140개 blob의 독립 대조는 성능 증거가 아니다. Main이 기존 공통 observer delta도 별도 수용했고 전용 guest의 baseline140/candidate140 검증·134재사용/6delta 복사·native0/세션1 Python0을 확인했다. 당시 Web 자원 반환 뒤 예정한 원본/최종 후보 pair와 결과 검토는 위 항목에서 마감했으며 C1/C2/C3·조건부RF1과 전체0/6을 유지한다.

- **2026-09-11 실제 트레이 이미지 비용 후속:** 기존 PNG 해독기의 무필터 행에만 lossless 채널 슬라이스 복사를 적용한다. 실제 KMC_LHD의921,888회 채널 필터 루프와230,472회 픽셀 포장 루프를 제거하며 다른 필터·bilinear·원본 자산·Tk 표시·업무/내구/권한 경계는 유지한다. 승인된 원본 headless 단회는 해독200.2321ms/resize151.3995ms/encode20.4439ms이며 실제 VM의383.64ms 전체 원인·native 이득·분포가 아니다. 영향22 PASS와 기존 inventory/pin3 PASS, upstream/local vendor provenance, baseline9e/current9d 보존과 동일 계측 비교 계획은 [작업 근거](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/TRAY-IMAGE-OPTIMIZATION.md)에 있다. 실제 Claude 소스/결과 검토와 최종 후보의 matched native 결과는 같은 작업 단위에서 Main의 자원 배정 후 확인한다. 이 시점은 소스·headless 정확성 확인이며 사용자 지연 이득과 종합0/6은 미완료다.

- **2026-09-11 가시 경계 방법 파일럿:** Main이 배정한6fcb VM에서 제품9d3ba8c·baseline9e38334를 고정하고 기존 observer/controller만 보완했다. 입력 전 PIL 부재·native focus guard 실패를 보존한 뒤 실제 Tk 입력칸 focus/state·owner thread를 확인한 corrected 단회는 held1→일반1로2/3, 중복 probe1, hold append/ACK1, observer 오류0·140 source 검증·정상 app/controller native0로 끝났다. [방법·결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/VISIBLE-METHOD-RESULT.md)는 원본40파일/23 PNG, 실제 Return·capture 구간과 부분 갱신 화면, callback·내구·감사·후속 실제 입력을 분리한다. ready-app 자동 구간3.902904s에는 capture1.2498353s와 PNG 저장0.8861156s가 포함되며 수동 준비를 포함한 app319.1340014s·최초 가시 시점·최초 안전 입력·physical scanner·p95/전후 이득과 같지 않다. [실제 Claude 방법 검토](D:/KMTech/optimization-implementation-20260909/COORDINATOR-RECOVERY-20260911-1144/ca-visible-method-review/REVIEW.md)와 Main은 current 단회 방법·보수적 경계를 수용했다. 후속 matched 중복 경고를 계측한다면 RF1에 따라 기존 bounded wait를 내구 SCAN_FAIL_DUPLICATE·scanner-status 변화로 보완하거나 해당 timed predicate를 제외해야 한다. C1 동일 계측/C2 동일 환경/C3 양쪽 경계·분해능 한계를 유지하며47.8–187.2ms 창으로0.020–0.028ms 검색 제거 이득을 주장하지 않는다. 새 분포 실행·제품 변경·공유 backend 변경은 없으며 전체 목표0/6과 연결 업무는 미완료다.

- **2026-09-11 비용 위치·작은 후속 수정:** [단회 current 진단](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/CURRENT-DIAGNOSTIC.md)은2b의 held display414.7681ms 중 숨은 exchange 버튼 configure408.4923ms를 관측했다. 실제19파일 원본/해시·native0/두 제품2/3·정상 저장 종료를 보존한다. 같은 thread CPU는15.625ms이며 OS/Tk 원인·반복 speedup은 UNPROVEN이다. [소비자 audit와 수정](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/HIDDEN-ACTIONS-CHANGE.md)은 업무 소비자가 없는 숨은 Tk 버튼 세 개와 전용 갱신만 제거하고 실제 메뉴·명령 진입점/보류·권한·수량·복구를 유지한다. 기존 영향 회귀34 PASS. 숨은 버튼 proxy를 요구하던 capture M7 소비자는 실제 가시 제어와 운영 메뉴 진입으로 보정했다(기존11 PASS 및 강화 사례1 PASS); 이것으로 교환 업무 자체를 수용하지 않는다. 새 단회 native 명령 배치 검사는 기존580px 고정2+2 assertion에서1 FAIL/native1이며 runner 부재·session1 Python0과 첫 실패를 보존했다. 기존 검사는 요청 폭 기반 열 수 계약에 맞춰 실제 요청 크기·포함·겹침 없음·순서·문구·왕복을 확인하도록 보정했다. Main timing 반환 후 [정확한7d62910 단회 native](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/NATIVE-ACTION-RESULT.md)는1 PASS/skip0/native0이며580px의 실제3+1 배치로 고정2+2 assertion 오류를 분류했다. 첫 실패/새 결과28원본 해시와 정상 종료·nonce cleanup 완료, 실제 Claude의 필수 수정 없음 검토를 보존한다. 성능 이득·연결 전체 흐름은 아직 미완료이고 새 benchmark는 별도 Main timing 배정이 필요하다.

- **상태·범위:** 소스·고정 합성 목표 검증과 accepted `8f7cd08` 원본 업무의 거부·보류·복원·정확한 완료 수용은 완료됐다. 실제 전후 사용자 결과·다음 입력 성능은 UNPROVEN이다. CA-S1a `920831d`는 일반/held의 중복 catalog 정책을 기존 `ProductScanDecision`으로 모으며, 후속 변경은 같은 동기 호출의 held 검색을 2→1회로 줄인다. 기본 gate·오류별 사건/경고·일반 카운터와 held 내구/FIFO 차이는 유지한다.
- **현재 증거:** `9e38334f` baseline 30 PASS, 구조 변경 후 40 PASS, 검색 재사용 후 59 focused PASS. 정상 및 모호/긴 다른 품목, 기본 거부의 catalog 미조회, held 감사 실패 시 원 head 보존·동일 key 재시도와 tail 재개, 완료 전 ACK와 stale input을 검증했다. 1,000 CPU/200 파일 저장 표본의 고정 목표 결과는 [RESULT](D:/KMTech/optimization-implementation-20260909/Container_Audit/RESULT.md), [기준·목표](D:/KMTech/optimization-implementation-20260909/Container_Audit/BASELINE-AND-TARGETS.md), [CA-O06](operations.md#ca-o06)를 따른다.
- **2026-09-10 보류 표시 후속:** 실제 before 화면의 중앙0·상태1·내구1은 보류 callback 뒤 중앙 안내가 갱신되지 않은 문제였다. 두 callback의 기존 renderer 갱신과 실패 snapshot 표시를 수정했고, 기존 회귀에서 실제 문구·보류1·실패0/2·동일 현품표 FIFO 복구와 영향 경로를 포함한 40개 focused 검사가 PASS했다. 초기 RED와 callback 전 표시를 읽은 시험 실패·수정된 RED를 [별도 근거](D:/KMTech/optimization-implementation-20260909/Container_Audit/held-count-fix-20260910/RESULT.md)에 보존한다. 원래 issuer release 68.592585초/한도60초 실패, current 미실행과 실제 성능 UNPROVEN은 유지한다.
- **남은 완료 조건:** Main이 최종 소스 독립 검토 뒤 배정하는 격리 VM에서 고정 observer·목표로 정확한 결과와 다음 실제 입력의 전후 비교를 검증한다. 기존 source export·실패 trace·attempt02 packet은 보존하며 완료된 원 업무를 새 SHA 때문에 반복하지 않는다. Main의 Label/Web handoff 및 전체 입고→출하 연결 수용과 구분하고 종합 최적화 완료로 표시하지 않는다. 생산 CONTAINER_AUDIT1–3과 원 업무·복구 증거는 유지한다.

- **2026-09-11 고정 전후 관측:** 전용6fcb VM의 before9e38334/current2b5871c를 같은 고정 응답·50행 catalog로 각각 한 번 실행했다. 양쪽 모두 실제 held 첫 제품과 다음 일반 제품을 받아2/3·두 행, SCAN_OK2·held append/ACK1·남은 hold0과 정상 native0를 확인했다. held 검색은2→1회, 일반 검색은1회이며 두 trace의 observer 오류는0이다. [고정 pair 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/PAIR-RESULT.md)에 원본·callback 경계·한계와 분석 selector 보정을 보존한다. 단일 관측·서로 다른 idle/수집 시간의 제한으로 실제 사용자 지연 이득/p95와 연결 전체 흐름은 여전히 UNPROVEN이다.

<a id="ca-g13"></a>
## CA-G13 전체 UI 가시성·포커스와 idle 후 명령 복귀

- 전송 상태는 공통 바닥 한 줄, 품목 안내는 기존 row3의 주황 라벨로 표시한다(P1-CA-03). 좁은 높이에서는 첫 문장·단추 행을 유지하고 보조 줄만 접는다. 기존 relay 상세에 목록 시각·client 마지막 성공 전송 시각 두 줄을 추가했다. 실제 화면은 별도 Claude/VM 확인에 남긴다. 최근 정상 스캔·다음 행동(row6)은 항상 표시하며 작업 상세는 평균·30일 최고(row7)만 접는다(P1-CA-01). 기본·복원 설정과 재구성·토글은 창 없는 실제 sidebar builder 회귀로 확인한다. 작업 상세 펼침·접힘, 운영 작업 메뉴의 선택·취소·닫기·팝업 오류, 트레이 이미지 선택의 초점 복귀와 보조 제어 Tab 제외는 창 없는 회귀로 확인한다. 실제 스캐너·VM 화면 확인은 별도 UI 감사에 남긴다([sub-512 결과](D:/KMTech/program-improvement-20260912/work/program/w9scanonly/sub-512/RESULT.md)).
- A3·A4: 메뉴 반환 뒤 열린 다른 창의 초점/grab 보호, 부분 스캔 내용·선택 보존, 겹친 복귀 한 번 실행을 창 없는 회귀로 확인한다. 실제 Windows 메뉴 명령·PIN 입력의 화면 확인은 별도 VM 감사에 남긴다.

- **2026-09-15 사용자 화면 후속 수용:** 현재 작업의 품목명/규격·상세/품목 코드/목표 수량을 별도 줄로 나누고 품목명만 강조한다. 체크된 사진 미표시는 pcwalk 합성 어댑터의 갱신 누락과 제품 `show_validation_screen` 재구성 누락을 구별하여 수정했다. 기준 `730ffa19`+개발후보 SHA2563483f897…, Windows/Python3.12.10 비GUI2+투명·화면밖 native4=6 PASS; 독립 diff 검토 차단사항0, 개발 VM2560×1440/배율1.0에서 줄분리·사진표시·재구성/체크토글 복원·동일2/3 직접 관측 PROVEN([결과](D:/KMTech/program-improvement-20260912/work/crosscut/pcwalk/CA/ui-fix/RESULT.md), [독립 검토](D:/KMTech/program-improvement-20260912/work/crosscut/pcwalk/CA/ui-fix/REVIEW-RESULT.md)). guest pytest/원본 신규회귀RED는 NOT TESTED, 원본·native recovery 실패는 보존한다. 이어 사용자 요청으로 KMC_LHD 사진의 앞면 손글씨/오염을 이미지 생성기로 정리하고 검은 원형 식별 스티커·흰 인쇄를 유지했다([원본·편집·적용](D:/KMTech/program-improvement-20260912/work/crosscut/pcwalk/CA/tray-image-edit/RESULT.md)); LHD 편집본은 사용자 수용·개발 VM 반영 PROVEN, 독립 Pillow pixel golden 대조와 PNG4건 PASS([JUnit](D:/KMTech/t/cau915/31afaf83/junit.xml)). 이어 사용자 "반영해"로 RHD 무문자 파란 원형 스티커/HMC 파란 잉크 도장 v2를 수용해 두 PNG를 교체했다. 독립 Pillow golden 대조 및 PNG4+표시상태1=5 PASS([JUnit](D:/KMTech/t/cau915/ffa0dd14/junit.xml)). 원본과 사용자 거부 v1을 보존하고 읽히지 않는 문자를 임의로 채우지 않는다([승인 파일·근거](D:/KMTech/program-improvement-20260912/work/crosscut/pcwalk/CA/tray-image-edit/other-previews/README.md)). 품목 매핑 변경0; 개발 VM 동일 SHA/원본보존/제품 해독·축소 PROVEN([guest](D:/KMTech/program-improvement-20260912/work/crosscut/pcwalk/CA/tray-image-edit/GUEST-V2-RESULT.json)). 현재 LHD/2·3 상태를 유지했으며 RHD/HMC 실제 품목 화면 전환은 NOT TESTED다. 운영 배포·실업무 수용으로 확대하지 않는다.

- **CA-F1 Escape UX 후보:** 개별 교환 창에는 Escape 닫기가 바인딩되어 있지 않다. 취소 의미와 현장 절차를 확정한 뒤 별도 검토하며, 취소 버튼·창 닫기·정상 완료 후 포커스 복귀 수정에서는 바인딩을 추가하지 않는다. 실제 키 입력 복귀는 검증 파도 CA1-focus에서 확인한다.

- **CA-1 화면 경계:** [member exchange view 분리](member-exchange-view.md)는 기존 UI/command 동작을 유지하는 소스 변경이다. 실제 GUI·스캐너·설치 검증과 아래 확대 표 native 실패의 수용 상태는 별도 범위이며 [구현 근거](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6ca1/RESULT.md)에 headless 검증을 구분한다.

- **2026-09-12 CA-D01 소스 교정:** 개별 교환의 입력·완료/취소는 고정하고 제목/수량/안내/표는 기존 viewport로 세로 접근한다. 실제 heading·rowheight·가로 scrollbar 요청 높이로 두 행 최소 크기를 확보하고 새 행 `see()`·긴 barcode 가로 접근·wheel/PageUp/PageDown·수량 focus 노출을 유지한다. 1024×768의 화면 cap672px 산술과 기존 headless 영향 검사를 실행한다. 0.7/2.5에서 양쪽 두 행 bbox·고정 footer를 확인하는 기존 `real_gui` 검사는 갱신했으며 이 구현 레인에서는 실행하지 않았다. 아래 과거 native 실패는 보존하고 실제 화면 수용은 별도 검증 파도에 남긴다.
- **w1 검증 근거:** [구현 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w1/RESULT.md)의 교환 관련 headless53 PASS, 감사 focused6모듈224 PASS/정상 exit0/잔존 thread0을 확인했다. 원 targeted7노드(일반·held 분리 포함)와 이벤트 재시작·시계 역행·종료 guard를 묶은14 PASS를 별도로 기록한다. 이 결과로 미실행 native bbox/실제 화면을 PASS로 바꾸지 않는다.

- **오류 안내 정합:** 이전 실제 duplicate 화면(`visible-frames-current/0019.png`)은 입력/상태가 차단돼도 큰 안내가 다음 제품 스캔을 지시했다. 차단 중에는 큰 안내도 확인을 지시하고, 해결 뒤 현재 스캔 단계로 복귀하도록 수정했다. 기존 native 중복→확인 회귀에 문구 양방향 검사를 추가했다.

- **후보 정적 후속:** 교체 화면의 열림/보조 모드를 글자 크기 재구성에서 유지하고, 저장된 미완료 교체가 있으면 일반 메뉴가 막혀도 기존 F8 교체 진입을 보이도록 보완했다. 관련 기존 비GUI35 PASS(`tests/6404989d1b`)이며 native 회귀는 실제 배정 시 열기→재구성→조회 중 닫기 거부→복구 진입을 확인한다.

- **2026-09-12 일상 정보 축소 구현:** 최종 제품 `0ea7251`은 반복 안내·현품표 교체 설명·최근 스캔/시간 통계를 조건부 안내와 작업 상세로 옮기고, 전송 대기·확인 필요·로컬 저장/중앙 완료를 구별한다. 기존 상세 버튼 글꼴을 상속하면서 짧은 우측 영역의 여백·예약 폭을 줄였다. 호스트 최종 영향104 PASS, 실제 native 최초40 PASS/6 FAIL 중 우측 잘림5는 동일 배율 사례에서 최종5 PASS다. 최초100ms 기준100.973ms 실패·정리 보완 후1 PASS, dirty-source provenance 실패와 모든 native 중간 실패를 보존했다. 실제 전체 앱 관찰은1024×768 합성 화면이며 사업 receipt/성능/1920 전체 화면 수용이 아니다. [전후 표·검증·custody](D:/KMTech/optimization-implementation-20260909/UI-IMPROVEMENT-20260912-1318/Container_Audit/RESULT.md).
- **남은 한정 항목:** 같은 native 실행의 확대 개별 교환 표는 두 번째 행 bbox93+91이 표 높이154를 넘었다. 교환 생성·화면 크기 제한 함수 AST는 변경 전b0e5d93과 같지만 이 사실만으로 과거 native 상태를 PASS로 추정하지 않는다. 실제1024×768/배율2.5에서 행 전체를 볼 수 있게 하는 별도 조정·검증이 남는다. Pillow 미설치로 collection이 중단된 native 구조 모듈도 미실행이며 호스트104 PASS와 구별한다. VM6fcb는06:38:34Z Saved/할당0으로 반환했고 task 루트·프로세스는 없다.

- **상태·범위:** 사용자 전수 UI 점검 요청으로 [실제 UI 목록](README.md#ca-ui-audit-20260910)을 추가했다. e69a0cb 기반으로 idle 후 운영 작업 버튼 갱신과 기존 종료 요청 flag guard를 두 줄 보완하고 기존 회귀에 실제 lane busy/idle·close 상태를 검사한다. 수량·membership·authorization·내구 저장 조건은 변경하지 않는다.
- **확인 근거:** 최초 불완전 fake coordinator의 AttributeError, 수정된 disabled/normal RED와 종료 중 재활성화 RED를 보존했다. 초기 후보 영향 검사11 PASS, native 일반 클릭으로 운영 메뉴 열림, 대표 빈 화면·긴 합성 작업자 이름·정상 종료 native0 및 최종 guard 검사를 [RESULT](D:/KMTech/optimization-implementation-20260909/Container_Audit/ui-audit-20260910/RESULT.md)에 연결한다. 종료 guard는 native 실행 뒤의 소스 변경이며 이전 후보와 일치하는 실행으로 표시하지 않는다. VM2는 process0/task Ready0/trigger0/원래 화면 모드로 Main에 반환했다. baseline native:null을 task0으로 대체하지 않는다.
- **남은 완료 조건:** 전체0.7/2.5 배율 끝점, 채워진 표·긴 한글 품목/바코드, 교환 dialog의 wrap/가로 접근/입력·footer, F8와 오류·복구·작업 인수/전환을 다음 배정에서 확인한다. 실제 최종 저장 배율1.8, 조기 painting 흔적, helper 포커스로 실패한 교환 진입 시도를 완전한 native 증거로 승격하지 않는다. 화면 해상도를 실행 도중 낮출 때의 최소 창 크기는 초기 실행 작업 영역 맞춤과 구분한다.
- **담당·다음 행동:** CA는 독립 소스 점검과 작은 재현 시나리오를 준비하고 Main은 같은 Claude 검토 및 후속 VM 회전을 조정한다. speculative UI 후보 때문에 다른 프로그램의 현재 slot을 막지 않으며, 기존 CA-G12 Goal3 성능 미완료·실패 자료·accepted 업무를 유지한다.
- **VM3 후속 관측:** e868837의 실제 저장0.7/2.5를 확인했다. 기본 빈 교환 창의 수량1/2·입력·footer는 PASS이며, 2.5의 1024 복원 명령/표 손실, 1920 최대화·1296 복원 문구 잘림, 큰 화면의 빈 교환 footer는 FAILED다. [정상 반환](D:/KMTech/optimization-implementation-20260909/parallel-vm-ui/CA/vm3-e868837/VM3-HANDBACK.md)을 Main이 수용했으며 VM3는 재배정 전 CA 권한이 없다. 이전 VM2 배율1.8과 helper 실패는 별도 보존한다.
- **실패 대응 후보:** 기존 2x 이상 구간의 좌측/중앙 세로 이동·포커스 위치 노출, 실제 요청 폭 기반 명령 재배치, 이미지 선택 줄바꿈, 교환 표의 두 행/스크롤 및 입력·footer 우선 배치를 원본 C에 구현한다. [후속 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/large-text-fix-20260910/RESULT.md)에 정확한 patch·유지 코드 증감·영향 검사와 native 미실행을 기록한다. 기존 native geometry 검사에 좁은 2.5 사례만 추가하며 새 검증 framework나 글자 상한을 만들지 않는다. 이 후보의 Claude 검토와 실제 VM 재검사, 기존 미관측 업무 UI 및 Goal3는 남아 있다.
- **Claude 검토 후 보완:** f193888의 실제 검토와 Main `msg_ad35233ca670`에 따라 기존 열 폭 helper를 재사용하고, profile 변경의 checkbox 폰트·삭제된 focus 대상 guard·한 줄 입력 위 wheel을 보완한다. 같은 관측16의 우측 평균/최고 카드도 사용자 전체 UI 범위에 포함하므로 기존 viewport를 적용한다. F5 scrollbar 자동 숨김은 필수가 아니며 Listbox 경계 handoff는 실제 필요 관측 전 추가하지 않는다. 한 열의 전체 문구 폭, 실제 두 번째 교환 행, 우측 footer·wheel·focus는 [검토 후 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/large-text-fix-20260910/review-correction/RESULT.md)의 좁은 native 시나리오로 확인한다. 42 PASS는 새 산술 실행 근거이며 실제 Tk 렌더링 근거와 구분한다. 빈 font 문자열의 TclError는 미입증이므로 helper 재사용의 근거로 삼지 않는다. 원 검토·실패는 보존한다.
- **2026-09-11 전용 VM 확인:** 정확한2b5871c/정상 kmadmin session1/1920×1080 최대화에서 큰 명령 문구, 빈 교환 수량1/2의 입력/footer, 잘못된 코드의 메인 차단 안내·교환 시스템 오류창·확인 복귀와1280×900 복원 후 세로 접근을 직접 관측했다. 정상 앱 종료 native0·저장2.5 및 기존 native5 PASS(skip0,3.05초; runner4.218초/native0)를 [전용 VM 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/continuation-20260911/UI-RESULT.md)에 연결한다. offscreen geometry와 실제 앱, 이후 수집기 메모리 압박/창 소실을 구분한다. Main은 native5 결과를 수용했고 실제 Claude Opus5 후속 검토는 소스/UI/native 범위 PASS다. 제품 수정·재실행 없이 R1 native runner PID7052 기록을 바로잡고 원 기록을 보존했다. O1의 2.5 우측 값 글자 높이 상한으로 일부 값이1.0보다 작게 표시되는 점과 O3의 시스템 오류창 글자 크기를 제한으로 명시하며, O2 수량 변경 후 spinbox 포커스는 기존 F8 흐름에서 관측한다. native5와 고정 pair의 guest 원본50파일은 해시 검증 후 회수했다. 화면 모드 반환, 긴/채워진 데이터·연결 업무 분기와 CA-G12 성능은 남아 있다.

<a id="ca-a01"></a>
## CA-A01 비멤버 조기 안내 제안

- **유형·우선순위·상태:** 추가 기능 제안, P2, 요구 미확정. 같은 품목의 비멤버를 마지막 exact 검사에서 발견하면 재작업할 수 있다.
- **현재 근거:** [CA-05](README.md#ca-05)에서 품목을 검사하고 [CA-07](README.md#ca-07)에서 최종 exact membership을 대조한다. 이 분리 자체를 미구현 결함으로 확정하지 않는다.
- **착수/완료 기준:** 조기 안내 필요성과 응답 지연·정규화·서명 snapshot 신선도 요구를 정한 뒤 범위를 결정한다. 구현 시 최종 exact 검사·lease/CAS를 유지하고 교체·재시작·offline에서 오탐/누락을 검증해야 한다.
- **담당·의존·다음 행동:** CA+현장, CA-G01/G05/G06. 실제 작업 불편과 허용 지연을 먼저 확인한다. 현재 승인된 개발 항목은 아니다.

<a id="ca-a02"></a>
## CA-A02 경고 중 최근 스캔 행 가시성 제안

- **유형·우선순위·상태:** 사용성 제안, P2, 필요 수준/검증 미확정. 중복 경고 중 최근 행의 가시성이 줄 수 있다.
- **기존 근거:** 수정 중인 [tests/KNOWN-GAPS.md](../../tests/KNOWN-GAPS.md)의 관측과 [scan_display](../../scan_display.py). 데이터 분실 확정 결함이나 이번 재현 결과가 아니다.
- **착수/완료 기준:** 지원 배율/화면 크기·필요한 최근 행 수를 정하고 실제 경고·확인/포커스 복귀·다음 스캔에서 필요한 정보가 읽히는지 확인한다. 기존 capture validator 자료의 적용 범위도 구분한다.
- **담당·의존·다음 행동:** CA UI 담당+현장, CA-G04/G05. 기존 관측을 먼저 검토하고 필요하면 별도 UI 변경 범위를 정한다. 이번 기존 UI/test 수정은 보존한다.

<a id="ca-g14"></a>
## CA-G14 현장 중단 방지의 남은 복구 경계 (w9nb)

- **C05 날짜 교환 확인 대기:** 대상 트레이를 기존 보류로 보존하고 다른 트레이를 받는 소스 경로가 있다. 읽지 못한 journal은 원본·격리 사본·UNKNOWN 기록을 보존하며, 교환 대상 재처리 차단과 COMMITTED/CANCELLED 뒤 복원은 날짜 변경·재시작에도 유지한다. 단독 교환의 보류 파일 복구도 기존 coordinator/lane을 사용한다. 스캔 판정 예외는 대상만 차단하고, 정상 journal의 mtime·크기 캐시는 변경 뒤 다시 읽는다. headless 실패 주입·밤 넘김 검증과 실제 Tk·출력·회사 서버 확인을 구분하며 실제 화면·장비는 별도 확인한다.
- **C06 상태 저장 실패:** 세션/트레이 실패의 동일 루트 저장 확인, 원 슬롯 보존과 UNKNOWN 격리 기록, 트레이 초기화 후 다른 작업, 재시작·날짜 변경 보존, 동일 현품표/전송 차단을 소스로 처리한다. 10분 안 세 건까지 각각 격리하며 네 번째 건부터 PC 작업을 막는다. 관리자 목록은 보존 원본을 표시한다. C02 소유/감사 원본 읽기 실패의 전체 흐름, 미확정 기록의 최종 대조·해소, 독립 저장 위치와 실제 디스크 ACL/화면 확인은 후속이다.

- **w9caqueue 남은 경계:** 활성 hold 1개·대기 최대 20개이며, 대기는 자동 다중 drain 대신 원 작업자가 현품표를 재스캔해 처리한다. 실제 1024×768 창·글꼴 배치, 실제 서버 끊김·lease 만료는 미검증이다. 설치기 활성 작업 probe는 활성/격리 hold를 보지 않고, 끊김 중 작업자 교대도 기존 차단을 유지한다(별도 후속). 과거 `UNVERIFIED_OPERATOR_HOLD`→`HANDED_OFF_UNKNOWN`의 앱 안 최종 해소는 별도 후속이며 이번에는 신규 오프라인 PIN 격리를 차단한다. 촬영 도구 `m7_central_preflight_queue`의 고정 실패 장면도 현재 끊김 화면과 다르다.
- **w9pincaconf 소스·headless 경계:** `APPLIED` 저장 뒤 단회 readback 실패는 관리자 재조회·시작 복구의 완료 효과 재검증과 메모리 정리로 이어간다. PIN intent·사전조회 격리 폴더의 열거 오류는 관리자 재확인 대상으로 구분하고 감사로 식별한 key만 보류한다. 두 실패 경로는 예외 주입 headless 회귀 범위이며 실제 폴더 ACL 장애·Tk 조작은 미검증이다. 네 로컬 PIN 동작은 중단 후 기록된 이동 목적지·원 SHA256을 재사용하며 복구 `APPLIED` 뒤 정상 완료의 입력 해제를 적용한다. 실제 업무 handler의 이동 전·이동 후·검증 후·효과 readback 후 중단을 headless로 주입한다. PRECHECK 격리 `APPLIED` 뒤 같은 key가 재진입하던 기존 결함도 차단하고 원 FIFO 복원·감사 결속 후 재개한다. 복원은 기존 원 작업자/관리자 인증이며 **PIN 분류 후속 필요**다. `TARGET_CHANGED`의 새 PIN 재실행과 parked 임시파일 관리자 경로는 유지한다. 실제 Tk 창, 운영 서버·PC, 실제 프로세스/전원 중단은 별도 검증이다.

- **C01/C03/C04 소스 조치:** 운영 작업에 원 요청 결과 재확인·관리자 보류 후 계속·인계 안내를 연결했다. 정상 조회 실패 hold는 관리자 격리·감사 뒤 새 현품표를 허용하며, 완료/교체 미확정 current는 원 snapshot을 parked readback·감사 뒤 인계한다. 원 intent/key·수량·membership·중앙 결과는 보류로 바꾸지 않는다. 실제 현장 화면·서버 응답은 별도 확인 대상이다.
- **C02 짝 원본 손상/불일치:** `DRAINING`은 중앙 조회 성공과 현재 트레이 활성화 뒤 시작한다. 통신 timeout만으로 hold/current 불일치가 생기는 소스 경로는 없고, 전원 종료·상태 저장 손상·잘못된 원본 조합에서 가능하므로 현장 빈도는 **미측정**이다. 읽을 수 있는 두 원본은 관리자 인증 후 바이트·경로·해시 결속, fsync/readback, 동기 감사, 원본 이동/readback을 마쳐 별도 보류한다. 이후 기록 소실/손상·원본/표지 해시 문제는 식별된 두 key만 보류하고 관리자 행에 원인을 표시한다. key를 식별할 수 없는 경우는 관리자 현품표 두 장의 중앙 읽기 전용 조회와 내구 보류까지 잠근다. stale-current 처음/변경 바이트는 별도 보존한다. 보류된 쌍의 중앙/로컬 부분 반영을 대조하고 최종 해소하는 관리자 동작은 후속 과제이며 자동 종결하지 않는다. 실제 화면·중앙 응답·재시작·디스크 장애는 별도 확인한다.
- **w9cafix5 소스 보완:** 중복 시작 guard와 보류/관리자 목록이 남은 내구 근거를 함께 열거한다. 손상 parked 이동에 따른 guard 소실과 marker-only 우회를 닫고, hold 중첩 필드 원 타입·감사 `False`·원본 경로를 검증한다. key 증거 144조합 및 필수 hold 필드 타입 변종은 headless 회귀이며 실제 Tk·현장 서버/장애는 아직 별도 검증이다. 감사 사건만 남은 미식별 건은 관리자가 두 원 현품표를 스캔해 중앙에서 읽고 별도 감사 사건으로 결속한다.
- **원자 임시파일:** parked/current/hold/짝 기록·표지, 이벤트 outbox, 현품표 교환 journal의 fsync 후 남은 임시파일을 관리자 목록에 연결했다. 읽을 수 있는 빈·key 없는 임시파일은 원 바이트·SHA256을 보존·감사하되 전체 PHS2를 막지 않는다. key 한 개의 관리자 해소는 한 장 스캔·중앙 읽기 전용 조회·감사 후 그 key만 보류하고, 두 key의 짝 흐름은 유지한다. 최종 파일과 함께 남은 임시파일은 별도 감사한다. headless 조합·관리자 분기 시험은 실행했으며 실제 중단 시점·Tk 관리자 조작·현장 디스크 장애는 미검증이다.
- **P1 관리자 신원 결속:** 이 범위의 격리·짝 인계·미확정 보류·짝 원 요청 재확인은 승인 때와 실행 때의 로그인 작업자·역할을 대조하고 관리자 신원을 감사 detail에 함께 남긴다. 일반 작업자 목록에서 타인이 관리자 코드를 입력할 수 있는 앱 전체 본인 확인 정책 공백은 사용자 결정 대기다. 실제 GUI·교차 계정 검증은 별도 확인한다.
- **w9pinca 웹 PIN 소스 연결:** 로컬 네 관리자 동작에 웹 개인 PIN 요청별 확인·소비, 내구 operation intent, 같은 key 상태 재조회, 해당 key 보류를 연결했다. 관리자 로그인만으로 PIN을 건너뛰지 않으며 중앙 retry의 기존 인증은 유지한다. 가짜 서명 서버와 웹 383e6c4 in-process 계약·headless 회귀 결과는 이 작업의 `RESULT.md`에 기록한다. 실제 Tk 입력, 운영 서버, root 잠금 해제와 현장 장애 중단은 별도 확인한다.
- **C06 저장 공간/내구 쓰기:** 용량 부족·권한·outbox 실패는 보존된 current와 원 사건을 쓴 뒤에만 작업을 계속할 수 있다. 현장 관리자의 저장 공간/쓰기 상태 확인·같은 요청 재시도 UI와 정량 경고/보존 요구를 별도 과제로 둔다. 쓰기 실패를 성공으로 표시하거나 로컬 유일본을 지우지 않는다. [CA-G06](#ca-g06).
- **C09 설치·등록 및 C10 품목 시작:** 기존 신원과 검증 cache가 없을 때 자동 새 신원·임의 품목으로 업무를 시작할 근거가 없다. C09는 배포 파도에서 지원 등록/원상태 대조와 관리자 원인별 복구 화면을 다룬다. C10은 정상 네트워크 회복 시 같은 시작 화면에서 중앙 품목 재시도·검증 cache 상태 안내를 별도 설계한다. 두 항목 모두 이번 소스/격리 시험 범위의 운영 PC 접근 대상이 아니다.

<a id="ca-g15"></a>
## CA-G15 별도 관리자 UAC 설치의 현장 확인 (w9cafence)

- **같은 사용자 상승→일반 mutex(w9setupprep-mutex):** 격리 native integrity 차이에서 runtime·writer admission을 필요한 권한으로만 열어 중복 거부·대기/해제·재획득을 확인하고, 실제 접근 거부는 보존한다. 기본 SD·namespace·writer 계약은 유지한다. [진단·RED/GREEN](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-31/REPORT.md)은 소스/host 격리 증거이며 새 packet의 guest 일반 권한 제거·재등록은 **NOT TESTED**다.
- **다른 세션 설치 안내(w9nextfix):** 검증된 교체 전 다른 Windows 세션의 CA 프로세스를 `CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING`으로 분류해 해당 사용자를 로그아웃한 뒤 재설치하도록 안내한다([실패 문구](operations.md#ca-o05)). 같은 세션·제거·복원의 기존 거부는 유지한다. 실제 UAC의 분류 로그 전달과 작업자 문구·로그아웃 후 재설치는 **NOT TESTED**이며 랩 수용에 남긴다.
- **소스·격리 시험 PROVEN:** 작업자 prepared receipt의 SID·LOCALAPPDATA·session/attempt/transaction과 token을 상승 helper가 대조한다. 기본 root의 기존 admission mutex 이름을 계정과 무관하게 사용하며, 잘못된 SID/root·오래된 시도·경쟁 writer를 거부한다. [설치 계약](operations.md#ca-o05)과 [구현 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9cafence/RESULT.md)를 따른다.
- **guest 실물 NOT TESTED:** 정확한 새 packet으로 표준 작업자+별도 관리자 UAC 신규 설치, 같은 관리자 계정 상승, ACL/mutex 교차 계정 접근, 첫 실행의 작업자 HKCU·DPAPI·ledger·relay 소유권을 확인한다. 기존 설치본/기록 보존과 화면 문의 코드도 대조한다. 운영 PC·서버 배포는 별도 권한 범위다.

<a id="ca-g16"></a>
## CA-G16 runtime lease 격리 자동 회복의 남은 경계 (w9calmleasefix)

- **소스·격리 시험 PROVEN:** 갱신이 `STALE_RUNTIME_FENCE`로 거절되면 묶인 행이 없을 때 새 신원 발급으로 같은 주기에 회복하고, 교정 전 저장된 같은 검토도 첫 주기에 풀린다([계약](contracts.md#ca-lease-dead-renewal)). Web 362ae46 lease 서비스를 프로세스 안에 띄운 재현(TTL 3초 축척)에서 margin·long 모두 fence 2로 회복했다.
- **자료 경로 dead fence(w9calmdatapath) 소스·격리 시험 PROVEN:** observe 서버가 커밋한 `STALE_RUNTIME_FENCE`는 클라이언트 모드와 관계없이(운영 자격증명 기본 enforce, w9calmenforce) 행 ACK·권한 만료 전이·fence N+1로 회복한다([계약](contracts.md#ca-lease-dead-fence-datapath)). 가짜 서버 11사례와 Web 362ae46 ingest·lease 하네스로 확인했다.
- **남은 경계:** 교정 전 판본이 이미 검토로 보낸 자료 경로 행·authority와 교정 전 행 준비에서 검토로 간 relay 행은 자동으로 풀지 않는다. enforce 전환 시 자료 경로 409 STALE은 계속 검토로 간다. 실제 HTTPS·nginx 502 경로, 랩 장비·회사 서버에서의 회복과 전송 카드 실제 화면은 NOT TESTED다.

<a id="ca-g17"></a>
## CA-G17 과도기 모드(모두 받고 분류별로 기록)의 남은 경계 (w9catransit)

- **LM 과 맞춘 분류 표(w9transitalign) 사용자 판단 3건:** 읽히는 옛 단계 QR `CLC|SPC|PHS=2`를 LEGACY 로 둘지(현장에 없으면 MALFORMED 가 더 정확), 품목 코드 없는 새 모양을 CA 도 받을지(받으려면 그 트레이의 제품 품목 검사를 LM 처럼 풀어야 함, 지금은 그 현품표만 거절), 품목 목록 밖 정상 PHS=2 를 중앙 전에 로컬로 보내는 기준 차이(LM 은 중앙이 확인). 지금은 권장안(LEGACY·거절 유지·그대로).
- **소스·격리 시험 PROVEN:** 가짜 레지스트리로 HKLM 값 `1`(앞뒤 공백 제거)만 켜짐, 프로세스·사용자 값·읽기 오류는 꺼짐. 꺼짐: 옛·손상 현품표 시작 거절, 완료 현품표·목록 밖 품목·PHS2 부분 제출 거절, PHS2 전량 흐름 base와 동일. 켜짐: 13자리 60개·부분 제출·옛 QR·v2.0.9 QR `LEGACY`, 손상 새 현품표 7종 `PHS2_MALFORMED`, 사전조회 끊김·거절 뒤 보류 스캔을 넘긴 `PHS2_LOCAL`, PHS2 부분 제출·중복·품목 미확인·명령 전 구성원 불일치(실제 seal coordinator) `PHS2_LOCAL`, 정상 PHS2 `PHS2_CENTRAL`, 완료 현품표 재스캔 경고·`중복` 기록(재시작 뒤 포함, 진행 중 회차의 재시작·보류 복원 보존, 같은 제품 두 회차 집계), 중복 키 뒤에 숨은 새 식별값·쓸 수 없는 QT의 `PHS2_MALFORMED`/`QT_INVALID`, 손상 PHS=2 트레이의 재시작·보류 복원, 중앙 품목 목록 없이 시작, 운영 member exchange coordinator를 넣은 상태의 PHS2 다음 레거시 제출·되돌리기·초기화·보류, 재시작 뒤 기록·분류 건수·같은 품목 진행 트레이 보존, relay 실패 중 다음 트레이 진행을 headless로 확인했다. 09-29 결정분: 회차 분류 고정(켬에서 시작한 옛·옛 QR·손상·사전조회 끊김 회차를 끈 뒤 재시작해 끝내도 그 분류, 서버가 돌아와도 중앙 조회·봉인 호출·intent 0), 명령 전 거절 뒤 기록 실패 → 끔 재시작에서 같은 사건 ID·timestamp 한 행, 검사 사이 만료된 lease의 첫 시도 로컬 완료(sub-04 P2-1), 취소 4종 사건 ID와 응답 유실 재시도·다른 사유 재시도·다음 날 재시작 재시도의 한 행(sub-04 R8, sub-05 R12), 서버 오류 코드의 대문자 코드 모양(sub-04 P2-2)·`app_version`, relay의 `RAW_LEGITIMATE` 좁은 인정(과도기 중복·`TRAY_RESET` 등 원문 전용 카탈로그 사건만, 조건이 하나라도 다르거나 다른 PC 행이면 검토 — 웹 sub-02 P1). [계약](contracts.md#ca-legacy-transition), [시험](../../tests/test_legacy_label_transition.py).
- **서버 변경 필요(Web, 표시용):** `transfer_legacy_projection`이 `master_label_code`를 키로 써서 13자리 트레이가 품목별 마지막 한 건으로 덮인다(포장 대기 수량 과소). 대시보드는 `transition_class`·`transition_reasons`·`transition_duplicate`를 읽지 않는다. 로컬 분류는 사건 식별자를 키로 쓰고, PC·날짜·분류별 건수와 일반 이적 실적·포장 대기를 분리 표시해야 한다. 의도한 중복·다른 PC가 먼저 완료한 현품표는 원문·관측(`RAW_EVIDENCE_ONLY`·`TRANSITION_DUPLICATE_OBSERVED`)으로만 받고 그런 행만 든 delta는 `RAW_LEGITIMATE`로 답한다(w9webrecv). F3는 취소 사건의 두 번째 행을 격리하거나 이중 계수했다(CA는 사건 ID로 막음). 이번 작업은 Web을 고치지 않았다.
- **검사 수준 차이:** 제품 검사는 v2.0.9와 같은 품목 포함·중복·개수에 더해 새 판의 입력 안전 검사(128자 초과·공백·제어문자·수식/HTML/경로 형식)와 catalog 모호성 거부를 그대로 쓴다([순서](product-admission.md)). 켜짐에서 목록에 없는 품목은 v2.0.9처럼 막지 않고 `품목 미확인`으로 받는다. 현품표 해석은 v2.0.9처럼 중복 키는 뒤 값, `=` 없는 조각은 건너뛰되 결함을 사유 코드로 남긴다. CLC 없는 입력은 트레이를 만들 수 없어 거절한다.
- **남은 위험:** 같은 제품이 레거시·로컬 기록과 새 체인에 두 번 계수될 수 있다(선반 분리·바코드 대조로 관리). 13자리 현품표는 중복 판단을 못 한다. 중앙 봉인 명령을 보낸 뒤의 미확인·검토 대기는 기존대로 잠근다. 로컬 트레이 도중 사전조회에서 발급된 서버 lease가 있으면 만료까지 남는다. 켜기 전(업그레이드 전)에 시작한 트레이는 분류가 없어 끈 PC에서는 엄격하다. intent 저장 뒤·contract 결속 전의 재검증 거절은 checkpoint 미확인 intent 한 줄을 SQLite에 남긴다(명령으로 만들어지지 않음). 원문 전용 카탈로그 사건 목록은 Web w9webrecv의 CA 분류(`CONTAINER_AUDIT_RAW_LIFECYCLE_EVENTS` 밖)를 따라 적었으므로 웹이 분류를 바꾸면 함께 맞춰야 한다(안 맞으면 검토로 멈춤). `tools/run_container_audit_ui_validation.py`의 기본 `PHS=1` 현품표는 켜짐에서만 시작한다.
- **NOT TESTED:** 실제 PC의 HKLM 값 설정과 창·경고 표시(1024×768 포함), 실제 서버 끊김·거절, 서버의 실제 수신·대시보드 표시와 `RAW_LEGITIMATE` 영수증·사건 ID 승격, 실제 자정·날짜 넘김, 패키지 설치본 실행, 현장 60개 처리 속도, LM과의 분류 합산.

<a id="ca-g18"></a>
## CA-G18 상주 relay가 앱 시작 경고창 동안 사라지던 결함의 남은 경계 (w9carelay)

- **원인(랩 w9labtransit1 09-29 · host 재현):** GUI 시작 전체가 writer 잠금 안에서 돌며 오프라인 품목 경고창(모달)을 띄웠다(10:46:33–10:47:21). 그동안 relay 주기의 상태 쓰기가 5초 대기 뒤 `WRITER_GATE_TIMEOUT`을 루프 밖으로 던져 relay가 끝났다(상태 `RUNNING` 고정, 프로세스 없음). 휴대판 앱 시작은 relay를 다시 띄우지 않았다. 네트워크 오류 자체는 relay를 죽이지 않는다. 기준 4a55e86부터 있던 결함이다.
- **소스·격리 시험:** 상태 쓰기의 잠금 시간 초과·abandoned·파일 오류는 다음 주기에 재시도하고 다음 상태에 남기지만 활성 writer fence·fence 검증 오류는 relay를 종료한다. 앱 시작은 Run 등록·정지 표식 부재·잠금 빔일 때 relay 시작을 요청한다([운영](operations.md#ca-o01)). 자식의 잠금 획득 전 `START_REQUESTED`에서 중복 요청·프로세스 생성은 가능하며 활성 loop 하나만 보장한다. 끊김 8종은 같은 행 재시도다. 빈 spool 3개의 시험은 예약 토큰·배치 ACK 회복만 검증하며, 별도 실제 CSV 3행 시험은 모의 수신기에서 재생 bytes·metadata 일치와 중복 효과 0을 검증한다. 실제 서버 수신 근거는 아니다. [수정·검증 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9carelay2/RESULT.md)
- **남은 경계(발견, 이번에 고치지 않음):** GUI 시작의 배포 무결성 기록 없음 경고창 등은 writer 잠금을 쥐어 그동안 relay·전송 자식이 기다린다(허용된 품목 캐시·설정 부재·과도기 시작 안내는 기존 전송 카드로 옮겨 확인 창을 없앴다)([_prepare_gui_startup](../../Container_Audit.py)). 상주 relay도 `--drain-after-scan`이라 새 줄이 계속 생기면 오래된 `retry_wait` 행은 새 줄이 없는 주기에만 재시도된다(지연). 앱이 켜진 채 relay가 다른 이유로 끝나면 다음 앱 시작이나 로그온까지 기다린다.
- **writer inventory 주입 경로(다음 canonical 업그레이드 주기):** 정적 도구가 주입 호출(onboarding `relay_launcher=start_user_relay_process`, 앱 시작 `launcher or start_user_relay_process`)을 따라가지 못해 GUI 진입점의 `persistent_relay_process_start` 경로가 `known_route_coverage`에 없다. 지금 드러내면 설치본 c3a1230·4a55e86 위 canonical 업그레이드가 `CODE_PRESTATE_WRITER_SEMANTICS_DIFFER`로 거절되므로 유지했다(코디네이터 09-29 판단). 다음 canonical 업그레이드 주기에 도구가 주입 경로를 보게 하고 설치기 전이 pin을 함께 넣는다. 그때까지 이 경로의 근거는 inventory가 아니라 실제 동작 시험(단일 실행 잠금·정지 표식·Run 등록·writer fence)이다.
- **NOT TESTED:** guest에서 같은 절차(오프라인 재실행·경고창 10초 이상)로 relay 생존과 앱 재시작 복구, 설치본 `pythonw` 시작 명령의 실제 프로세스, 회사 서버.

<a id="ca-g19"></a>
## CA-G19 로그온 자동 갱신 실기 수용

sub-238은 같은 소유 scheduler의 SYSTEM/boolean 되읽기와 복원 relay READY 전 완료를 고친다.
격리 helper 회귀는 실제 task 등록·로그온·앞 판 relay 기동·현장 수용을 대신하지 않는다.
저장 protocol 1·기존 phase/필드와 writer admission 불변식은 유지하며 새 설치/배포 권한은 추가하지 않는다.

[읽기 전용 시작 확인](startup-check.md)의 headless 시험은 실물 HDD 10초 상한·로그온 작업·
실제 작업자 계정·원격 알림 수용을 대신하지 않는다. 이 수용은 설치 키트/현장 lane에서 남는다.
평상시 `app_gui_ready.v1` 표지의 필드·원자 교체·실패 시 화면 진행과 기존 trial 표지
바이트 보존은 headless로 검증한다. 실제 로그온 후 표지 수집·건강 판정은 현장 수용으로 남는다.

- **sub-217 지원 제거 controller 재진입:** 보호 원 감사·source/fence/owner 결속과 같은 session의
  배타적 재획득을 추가했다. 실제 public fence/지원 제거/하위 내용 caller AST를 실행한 PS5.1/7
  회귀 14 PASS(기준 실제 `ALREADY_ACTIVE` RED 2)다. 내용 이동 뒤 즉시 controller 종료와 추가
  metadata 이동 중단·live owner·보호 감사 변조/tuple/source/사용자 경로 위조를 확인했다.
  NTFS/hash/원 기록/이동/프로세스 종료/배타적 mutex는 실제이고 ACL/CIM/task/Run/UAC/해제 인증은
  주입 경계다. 실제 설치기 전체·승격 조상 관측/보호 ACL·등록·relay·랩 수용은 NOT TESTED다.

- **sub-217 canonical feed 준비:** 검증된 ZIP 접두로 stock 원문을 읽고, bundled runtime은
  stock `runtime_files`의 정확한 경로·SHA256으로만 denylist 예외를 적용한다.
  실제 ES256 서명·packet SHA·정확한 쌍·공개 준비/압축 해제의 11개 격리 회귀를 추가했다.
  stock 빌더가 목록을 기록한다. 정식 선언/pin 재생성·실제 feed/packet 수용은 아직 별도다.

- **sub-189 내용 소유 제거:** 실제 NTFS에서 PS5.1/7의 개별 이동·중단 재개·None/Read 잠금·
  다른 내용/목록 밖 자료·목록 부재/손상/디렉터리·외부 정션 30 PASS다. scheduler/CIM/보호 JSON
  ACL은 주입 경계이며 실제 외부 지원 caller/승격·task·ACL 제거와 재설치는 NOT TESTED다.

- **sub-189 서명 규칙 이식:** 정확한 서명 쌍·실제 계약 재해시·stock/literal 판 번호·엄격 증가·ASCII feed를 이식했다.
  Windows11/Python3.12.10 격리 focused 170 PASS(새 규칙 19 RED→GREEN), 기존 crypto/READY 복귀 포함.
  선언/pin은 동결이며 실제 feed·SYSTEM·packet 수용은 NOT TESTED다. [이식 보고](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-189/REPORT.md).

- **구현:** 서명된 HTTPS 묶음 준비, 고정 SYSTEM 적용 작업, protected SHA 판/내구 journal,
  GUI/relay 시작 gate, 정확한 양방향 핀과 변경 없는 데이터/API 바이트 확인,
  nonce/SHA/PID/생성 시각과 사용자 저장소·일반 relay READY, 정상 종료 뒤 코드 복귀.
- **기본 상태:** feed/허용 전이 비어 있음, 업무 중 전환 거절. 프로토콜 없는 옛 현장 판의
  첫 이동은 기존 정확한 canonical 설치/복구로 수행해야 하며 자동 READY를 소급해서 가정하지 않는다.
- **PROVEN:** 소스의 순수 결정/변조·역방향·미승인 거절과 flush-before-pointer 실패 주입,
  scheduler 명령 생성·writer inventory 검사. 실제 수명주기 증거는 아니다.
- **지원 전이 후보(w9setupprep sub-68):** 자동 갱신을 재설계 기준 `ca6ab8f` 위로 옮기고
  canonical 사후 복원에도 successor packet의 정확한 역방향 writer 핀을 적용한다.
  실제 old packet(랩 `0d6aec4`, TEST1 `8928228`, 옛 `c3a1230`·`4a55e86`)에서 SHA/계약을
  읽어 새 빌드 입력을 만든다. 호스트에서는 PlanOnly·순수 전이 판정만 확인하며 실제
  설치·코드 복귀·현재 현장 설치 판 식별은 guest/현장 수용으로 남긴다.
- **NOT TESTED:** 랩 guest에서 실제 설치/업그레이드/제거/복구, SYSTEM task ACL·logon race,
  일반 사용자 GUI/relay 및 미완성/장부/outbox 읽기, 후보 기동 실패 뒤 기존 코드 정상 복귀,
  전원 중단 후 재개, GUI 경고창 중 UNKNOWN 보존, 실제 서명 feed/인증·Hiberboot 읽기.
  전체 시험·stock builder와 독립 검토는 코디네이터가 별도 배정한다.
- **다음 행동:** 실제 이전/후속 출시 SHA와 양방향 writer 계약 핀을 승인한 뒤 guest 수용을 수행한다.
  현재 실패 증거와 보호된 preimage/이전 판을 보존하고 실기 수용 전 출시하지 않는다.

## 갱신 기준

CA 설치 Run 사전 바인딩: 후보 설정이 옛 설치 명령을 바꾸던 결함을 수정했다.
소스·격리 회귀는 PROVEN이며 실제 옛 packet 4판의 설치/실패 복귀는 guest 수용으로 남는다.
CA 설치 runtime 종료/복구: 옛 stop receipt 뒤 실제 process exit를 별도로 기다리고
첫 receipt를 보존하며, 최종/rollback relay는 같은 사용자의 일반 토큰을 확인한다.
주입 경계의 종료 지연·잔류/위조 거절과 정상 사용자 시작은 host 회귀 범위다.
원 cfd11e4 랩 실패의 최초 조건은 rollback이 receipt를 덮어써 UNPROVEN이고,
수정판의 실제 shell 토큰·옛 4판 설치/복구는 랩 재설치 수용으로 남긴다.
1a630a0 랩 실패는 정지 관문 PASS 뒤 코드 배치 전 원 오류 상세 소실과 rollback relay
시작의 MethodInvocationException을 각각 보존한다. sub-84는 호출명/Win32 오류 증거와
정확 Run 복원 뒤 다음 로그온 상태를 분리한다. 호스트 주입/선언/stock 증거와 실제
native 시작 진단·재설치 수용은 [sub-84 보고](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-84/REPORT.md)를 따른다.
CA 자동 업데이트 경계: 조상/코드 사전검증과 READY 읽기 경합 처리를 보완했다.
sub-455 D-16은 세대 기록 뒤 READY 실패 시 candidate 유지와 공통 SID marker 선기록을
headless 실제 프로세스로 검증한다. 실제 GUI READY 실패·SYSTEM task·bootstrap 실물은
NOT VERIFIED이며 랩 VM 회차에서 이어 확인한다.
sub-458의 기준판과 후보판에 함께 남는 설치기 focused 실패는 동일 노드·단언·예외 비교를
INHERITED-FAILURES.md에 보존한다. 이 과제에서는 변경하지 않으며 설치기 후속 작업에서 고친다.
극단 offset의 READY 시각도 UTC 표현 가능성을 확인하며, 미확인 증거는 기한/복귀를 중단하지 않는다.
동일 계약 예외의 실제 교환 DDL 누락도 수정했고 root/tools DDL 누락을 기계적으로 검사한다.
합성 경계와 기존 회귀의 증거는 sub-75 보고서이며 실제 안전/위험 배치·SYSTEM·로그온은 NOT TESTED다.

요구 확정·소스 변경·실행 결과가 생긴 담당자는 연결된 기능/계약/운영 항목과 이 문서의 상태·다음 행동을 같은 작업에서 갱신한다. Main에 중앙 INT-02/03/04/09/10, I02/I04 및 Q01/Q07에 미치는 차이를 알린다. 과거 실패·미실행을 삭제하지 않고 새 버전·환경의 근거를 연결한다. [AGENTS의 지속 관리 규칙](../../AGENTS.md)을 적용한다.

## w9scanonly — 2026-10-01 구현 검증 범위

MP-02: 다른 이적 PC의 임대 거절은 해당 트레이 안내·입력 보류·같은 현품표 재조회로 처리한다. 6/7칸 현품표, 다른 트레이 계속, checkpoint 복구와 원 스캔 감사 재생은 `tests/test_scanonly_lease_refusal.py`의 격리 회귀 대상이다. 실제 두 PC·회사 서버의 임대 반납/완료와 화면 위계 확인은 별도 수용에 남는다.

**2026-10-07 통합 컷의 스캔 500ms 꼬리 — 알려진 P2, 미해결.**
코디 결정 `msg_5f9e87a9e36b`는 기준 `1ad99d62` 자체의 quiet2 초과 10/1185·max 724ms(코디 반올림)를 근거로 FF 수용 조건을 바꿨다. 같은 시간대에 기준판과 최종 통합 HEAD를 번갈아 조용히 측정하며, 동일 입력·표본에서 500ms 초과 수와 max가 **둘 다 기준보다 나쁘지 않고 새 P1/P2가 0**이어야 한다. 앞선 통합 4/1184·max 769.971ms 및 421 원가지 `7c184a7`의 4/1184·max 634ms 실패와 최초 FF 중단은 보존한다.
제품의 500ms 목표와 새 스캔의 동기 내구 기록은 유지한다. sub-421의 추가 고침은 계속하며 컷 전에 수용되면 함께 넣는다. P1 고침 419·420·431·429의 독립 확인과 결합 G 재승인·새 stock·교차 측정 관문을 먼저 충족한다. 컷의 소스 SHA·실제 지표·남은 P2는 [통합 컷 기록](D:/KMTech/program-improvement-20260912/work/program/w9scanonly/sub-413/FF-CUT-RECORD.md)에 고정한다.

로컬 QT 시작/완료·미달/UNDO·교환, lease 해제 내구 재전송과 계약 v1.2 요청/receipt를 구현했다.
CA-X03: 교환 검토 행은 같은 트레이의 순서만 대기시키며 다른 트레이의 교환·봉인은 계속 보낸다. 옛 현품표·서버 거절·같은 트레이 대기·ACK 유지와 저장 안내는 [격리 회귀](../../tests/test_scanonly_exchange_review_queue.py)로 확인한다. 옛 현품표 교환의 중앙 행 생성 제거·대체품 사전 거절 자료·실제 화면과 서버 확인은 별도 범위다.
미달 확정의 60초 무입력 만료·절전/잠금 뒤 지연 callback·재시작 잔여 유예는 내구 확정 시각·가짜 시계로 검증한다. 시계 역행 보류와 복귀 직후 만료 UNDO 거절도 headless 회귀 범위다. 실제 Windows S3/모던 스탠바이·스캐너·중앙 서버·종료 화면의 수용은 별도 랩 확인에 남는다.
실제 GUI·서버·VM은 이 레인 권한 밖이므로 미수용이다. 관리자 복구 창은 보존했고
작업자 스캔 흐름의 창은 inline 안내/선택으로 대체했다. 전체 pytest 결과는 구현 보고서를 따른다.

## w9slim2 B18 시험 격리

실제 deployment-session 권한을 획득하는 시험은 case/run별 고유 session/transaction을 공유한다. 제품 fence·이름 도출·canonical vector·최소 mutex 권한은 그대로다. 같은 이름 contender 거절 단언과 Python/PowerShell delegation을 유지한다. Python 3.12.10·Windows PowerShell 5.1 headless 영향 3모듈 82 PASS; 동시 실행 근거와 한계는 [레인 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)를 따른다. 실제 GUI·설치·서버 검증은 이 결과에 포함하지 않는다.

## w9slim2 B01 inventory 표현

PowerShell 분석 결과는 `powershell_execution_inventory` 한 키에 저장한다. 중복 alias `powershell_scheduled_task_guards`를 없애고 두 mutation-site 단언을 정본 키로 옮겼다. detector·schema·source/packet 구분·writer admission·canonical 설치기 의미 projection·old/new/rollback은 유지하며 새 바이트/semantic pin을 세 consumer에 함께 반영한다. 영향 4모듈 115 PASS(Python 3.12.10/PS5.1 headless). 과거 packet byte identity는 달라지므로 새 후보의 stock builder 및 전이 근거는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)를 따른다.

## w9slim2 B05 문서 자산 공유

20260626/27의 바이트 동일 workflow PNG/Mermaid는 20260627 원본을 공유한다. 20260626 문서의 해당 두 링크만 정본으로 바꿨으며 촬영·게시 도구와 다른 화면 자산은 유지했다. 정본 hash·참조 대조는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md); 문서 전용 변경으로 앱 실행은 NOT TESTED.

## w9slim2 B07 시험 통합

CA-T01의 이름 14개와 실제 register→ValueError, CA-T02의 malformed JSON/pipe 7개와 공개 parser→None은 남는 행렬로 모두 이관했다. CA-T03의 실제 ROOT 도출=committed snapshot equality는 기존 readonly/help/check/write CLI 노드에 합쳤다(중복 setup만 제거). 대조표와 독립 사본의 의도한 제품 결함 검출 근거는 [레인 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)를 따른다. 디스크 손상/성공 파싱/QT·legacy/부정 guard·exact bytes 단언은 유지했다.

## 관리자 보류 처리 입력

기존 관리자 ID·가린 PIN 한 폼에 원 동작·선택 대상·원 현품표를 함께 표시한다. 원 요청 다시 조회도 저장된 동일 대상/labels를 표시하고, 제출 뒤 PIN 칸을 비운다. 승인/최종 확인·6자리 검증·서버 잠금/역할/철회·원장 CAS·UNKNOWN·건별 보류는 같은 handler로 유지한다. 손상 원본 식별은 중앙 조회 결과가 PIN 필요 여부를 정하고 오프라인 무 PIN 보류와 코드를 공유하므로 기존 입력을 유지한다(2026-10-01 coordinator 답). Python 3.12.10/PS5.1 headless: 새 폼 5 RED→GREEN, 관련 5파일 793 PASS; 처음 broad 90 FAIL은 두 공용 prompt fixture의 인수 불일치로 원본 보존 후 교정했고 마지막 변경 뒤 같은 pack을 다시 실행했다. [결과·미수용 화면 범위](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md).

## w9slim2 도구 정리

소비자 0을 확인한 두 도구와 전용 시험만 제거했다. 절차에서 참조하는 atomicity probe·sandbox 및 일회성 PE scanner는 보류하고 촬영·문서·게시 도구는 보존한다. 소비자 조사 범위·보존 SHA·stock gate·NOT VERIFIED는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)에 연결한다.

## R29 중앙 PIN 잠금과 root 철회

운영 메뉴의 관리자 PIN 재조회·사전조회 보류 격리는 기존 lane으로 서버 요청과 내구 반영을 옮겼다. 전송 대기 중 화면 이벤트·중복 요청 방지·닫힌 창의 내구 반영은 창 없는 주입 시험으로 확인하며, 실제 PIN 창·메뉴·음성·1366/1920 배율별 맞춤은 별도 화면 수용이 남는다. 다른 관리자 승인 동작은 기존 동기 흐름이며 이번 비동기 전환 범위 밖이다.

격리된 실제 Web HTTP·SQLite와 CA 내구 intent의 7개 성공/거절 경계가 PASS다. 중앙 잠금+root 철회에서 서버 LOCKED/PIN_LOCKED·CA REJECTED·이전 grant REVOKED 및 원본 보존을 확인했고 제품 인증 코드는 변경하지 않았다. 지원 store API로 준비한 격리 source 시험이며 실제 root UI·production 수용은 NOT TESTED. 원 실패·정확한 입력 SHA와 범위는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)를 따른다.

G6 선택 대기의 다음 현품표·카드는 원본 보류/유지 뒤 공개 입력으로 처리한다. 다른 작업자 preflight 원본은 불변이고 그 현품표만 관리자 PIN 인수·격리 대상으로 남는다. headless 회귀와 실제 화면·스캐너 검증은 구분한다.

G8 기기 인증 진행 현황·60초 배경 갱신·끊김 캐시·스캔 복귀·늦은 응답을 구현했다. 실제 화면/장치와 운영 서버 응답은 미검증이며 브랜치 검증은 focused/collect, 전체는 w9next 통합판 범위다.

G10 기존 성공/조합/오류 음원으로 성공·완료·반복 오류를 구별하고 연결·마지막 성공 전송·대기 합계를 기존 카드에 합쳤다. 내구 순서·음원 파일 목록은 유지하며 실제 스피커의 구별과 화면 읽힘은 랩 확인 대상이다.

완료 시험 대역은 `preserve_held_scans` 키워드를 받는 실제 콜백 계약을 따른다. `projected_scan_exchange_keys`는 내구 완료의 교환 키를 SELECT로만 읽는 helper로 분류하며, 기존 writer 32개·owner-first와 읽기 전용/UI-thread 경계 검증은 유지한다.

G 전체 비교의 GUI 직접 예외 표시와 relay 모의의 Git 가로채기를 교정한다: 고정 복구 안내만 UI로 전달하고 모의는 실제 Git identity를 유지한다. 기존 보관/복원 시험 기대와 guard는 약화하지 않는다.
# CA installation follow-up — 2026-10-02

Fifth rehearsal FAILED before app placement: protecting KMTech propagated the
same inherited ACE set to Apps in a new order. The source fix compares sorted
ACE tuples and refreshes the child descriptor after parent persistence; both
intermediate states remain supported. PS5.1/PS7 native NTFS RED/GREEN and the
captured lab intermediate SDDLs pass in an isolated host tree (owner seam only).
Pending: independent review and actual lab acceptance from
the protected-parent/inherited-child state; see [sub-123](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-123/REPORT.md).

In progress: preserve original staged/child failure evidence, recognize exact
TrustedInstaller SID and protect only the two shared ancestors with reviewed B
self-mask reduction. Fourth lab installation FAILED; historical original cause
UNPROVEN, current startup-trust rejection PROVEN by read-only reproduction.
Isolated V5 B is PROVEN under the lab's filtered normal token: creation/legacy
remain usable, ancestor/sealed rename/delete return native5, repeat is unchanged,
and user-owned preclaim is rejected. Rebase onto w9next3925d36 is complete.
Pending: final-source focused/guard/collect, declarations/transition/stock,
independent review and fifth lab acceptance. Compatibility E remains deferred by coordinator
decision. Shared ACL protection is retained after rollback/uninstall; IW/LM
changes and the central hub belong to their owners/coordinator.

First-run preparation ordering is implemented: ordinary preflight admits missing
app parents/reviewed default ancestor ACLs; the elevated path protects the two
shared ancestors before protected app/control/run creation. Pre-run failures use
codes 61–66 and ordinary Korean diagnostics; protected path refusals retain their
original exception chain. Source/memory-ACL regression evidence is recorded in
`D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-111/REPORT.md`.
Native folder creation/ACL application, declarations/stock/packet transition and
fifth lab installation remain NOT TESTED by this subtask.

2026-10-03 sub-127: placement now preserves application/control/evidence ACLs;
native child diagnostics survive evidence failure; rollback attempts independent
steps; a durably recorded dead unplaced installation can finish rollback before
reentry. Source and isolated PS5.1/PS7/NTFS regression are PROVEN with native owner
translation and mocked runtime callbacks explicitly limited. The sub-125 legacy
lab residue is refused because its record is insufficient, per coordinator
decision; execute the separate LAB-REPAIR-PLAN before the next rehearsal. Actual
UAC/privileged ownership, ordinary resident readiness and lab acceptance are
NOT TESTED here. General lifecycle convergence remains a later task; coordinator
owns independent review, fifth rehearsal and shared hub acceptance.

2026-10-03 sub-142: literal shared ancestor recovery admission now uses the same
exact target-shape predicate as preparation; other leaf masks remain unchanged.
Native PS5.1/PS7 admission has 70 PASS with an explicit owner-admission seam.
Formal declarations/pins remain frozen by the task instruction. Rehearsal
declaration regeneration, stock packet, supported lab repair and one installation
are reported separately in sub-142; independent acceptance remains coordinator
owned. This source verification does not prove privileged repair/ordinary relay
readiness or release acceptance.
Ordinary repair admission now validates the actual owning-thread lease; its
PS5.1/PS7 mutex RED/GREEN includes absent/wrong lease rejection before UAC.

2026-10-03 sub-149: central raw-descriptor comparison implemented for ancestor
race readback and startup-task restore. Baseline41ab6b4 has four AI/order
failures; edited source passes the 22-case PS5.1/PS7 regression, including two
owned native ACL checks. Historical hash-only receipts cannot recover ACE order;
The coordinator approved raw-bound new receipts and
AI-only SHA proof for legacy receipts; the existing hash field meaning remains
unchanged and legacy ACE-order differences stay rejected. Receipt readers and
restore guards now share the central comparison. See the sub-149 report and
SDDL-COMPARE-SITES.md for committed evidence and remaining lab limits.
Final rehearsal source c40c267/d49f4c2 has 505 PASS/2 SKIP across 16 isolated
file packs (product/test bytes unchanged by the final docs-only commit).
Stock packet d49f4c2 was built once; 2303-file host ZIP and guest Stage parity
are PROVEN. All five supported repair steps restored the old ordinary relay;
an inherited 65-character receipt-SHA typo was corrected against the preserved
original, with the initial failure retained. Limited PlanOnly passed. The single
installation FAILED at startup task XML registration (LogonType:ServiceAccount),
after placement/aggregate/new raw-bound receipt passed; a separate helper
evidence-root binding failure obscured the native child exit in the outer result.
Rollback restored old 2302-file code, original Run, protected ACLs and Medium
ordinary relay READY. No reinstall or unrelated-class correction was attempted.
Fresh host parent-induced AI and native owner-change regression remain UNPROVEN;
preserved real lab P-to-PAI descriptors and native ACE/protection negatives are
separate evidence. Independent acceptance remains coordinator owned.

## sub-189 이식 상태 (2026-10-04)

서명 쌍/stock version/ASCII feed, 내용 소유 제거, 실제 B를 선택하는 지원 설치와 이종 active 등록, 제한된 원 오류 기록을 이적 구조에 맞췄다. 기존 receipt·protected journal·ordinary relay READY·한국어 복구 끝 상태를 유지한다. A≠B의 native 지원 설치 및 실제 제거 수렴, frozen 선언/pin의 최종 재생성·stock packet gate와 랩 실증은 열린 수용 항목이다. 자체 회귀·범위·실패 보존 및 독립 확인 입력은 sub-189 REPORT.md와 FOR-REVIEW.md에 기록한다.

- sub-189 P2-1: immutable 원 journal/receipt에 보호 authority-link 사슬을 결속하여 반복 중단 재진입을 지원; PS5.1/PS7 두 추가 중단과 동일 tuple 링크 위조 거절 회귀. 정식 선언/pin 재생성 및 native 랩 수용은 별도 담당 레인에 남음.

- sub-189 P2-2: READY 뒤 completion refence 제거; 보호 release/controller/journal 권한은 유지하고 helper 전후 resident PID/READY 재관측. 실제 admission root의 active-fence 부정 사례·완료 뒤 동일 PID 생존·두 추가 중단 뒤 완료 회귀. native 랩 재실증 및 frozen 선언 갱신은 출시 레인에 남음.

- sub-189 형식 교정: 기존 17파일의 shipped UTF-8 BOM 회귀가 bootstrap helper의 누락을 발견; BOM 3바이트 복구(함수 본문 불변), PS5.1 한국어 오류 호환을 유지하며 실패/수정 회귀를 별도 보존.

- sub-189 A==B 회귀: 실제 canonical AST 분기문을 PS5.1/PS7에서 실행해 healthy equal-owner는 기존 current placement, 실제 B가 다르면 C versions placement를 선택함을 확인. lifecycle 27·지원 receipt/NTFS 22·기존 canonical/bootstrap 14와 함께 해석하며 실제 정상 설치기/UAC/managed task의 통합 수용은 랩에 남음.


## 설치 통합 sub-248 (2026-10-05, 독립 확인 전)

w9next 567ff27 + autoupdate 7247634를 merge a63ae29로 통합했다. 양쪽 G와 설치/복구 소비 경계를 보존하고, fresh census가 발견한 기존 Python2/PS5 미보호 자리는 코디 승인 후 기존 admission/byte-pinned library로 교정한다. 사용되지 않는 startup-control 이동 함수는 실제 preimage save/restore 소비 경로로 안전 회귀 의미를 이관한다. 표준 선언 재생성, 세 판 집중 실패 대조, 후보 전체 및 lab-only stock packet 증거와 독립 review는 sub-248 REPORT/FOR-REVIEW에서 최종 판정한다. native VM 설치·출시 키·출시 수용으로 소급하지 않는다.

## 설치 수명주기 판독 sub-273 (2026-10-05)

보호 helper가 보유한 writer admission mutex를 Python 자식의 guarded task query가
재획득하던 설치 거절을 기존 pinned PowerShell reader의 같은 스레드 판독으로 교정한다.
실제 격리 mutex RED와 PS5.1/PS7 첫 설치·잔여 control/task·조회 UNKNOWN 회귀는 PROVEN이다.
실패 summary/감사는 공통 가림 뒤 64 KiB 전문과 지문 참조를 보존하며 안내는 마지막 예외 한 줄 300자다.
onboarding·제거/복원·DirectSync JSON 보고서의 임시 파일 저장 전 가림 누락도 교정하고, 원 오류/child 전문 참조·원자적 create-new·typed 메타데이터와 UTF-8/JSON 예산을 바이트 회귀로 확인한다.
옛 공식 relay 작업은 태그 묶음 전체 정체성이 일치할 때 preimage 뒤 비활성화하고,
current 부재/코드 복원 실패와 독립적으로 원 G가 허용할 때만 Enabled와 원 XML 지문을 복원한다.
암호 저장/대화형 principal은 코디의 랩1/2 증명 및 후보 승인으로 같은 작업 사용자만 허용한다. 예행3/4 실패 시 한 곳의 스위치를 다시 닫는다. 공개 HKCU Run writer는 없다.
원 sub-271 stdout 소실 때문에 원 실패의 직접 세부는 UNPROVEN이며 새 native 설치·GUI·
현장 배포 수용은 NOT TESTED다. 검증/stock 판정은
[sub-273 REPORT](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-273/REPORT.md)를 따른다.

## pythonnet 업데이트 검증 sub-254 (2026-10-16)

canonical 업데이트 ZIP의 pythonnet/runtime 정본 세 파일만 기존 signed packet SHA에 결속된 dist-info/RECORD의 정확한 경로·SHA256·크기로 허용한다. 맨 위 runtime inventory·서명/신뢰·판 하한·PC 허용·전이 승인·디스크 형식은 유지한다. 실제 110 ZIP과 변조/추가 파일 회귀 및 남은 실물 배포 확인은 sub-254 RESULT에 기록한다.

## 설치 launcher 길이 sub-265 (2026-10-05)

통합 시작 45192a6의 상승/finite helper/일반 producer 전달을 private 파일 두 개와
메모리 SHA256으로 바꿨다. 16,000자 전체 명령 bound, 각 파일의 새 DACL,
확인 동안 read handle과 원 helper/library pin·AST filename·result binding을 유지한다.
PS5.1/PS7 transport 회귀70개 PASS, 같은 기존206개는 시작188P·18F에서 입력 병합
후190P·16F로 새 실패0이다. 전체 명령6,917자·인용 확장 상한8,297자다.
미배포 autoupdate의 runtime_files 목록을 별도 pinned runtime-file-inventory.json으로
옮겼다. 기존 manifest 판독3곳을64KiB로 복원하고 공용 helper를 보존하며,
별도 목록에만1MiB 상한·길이/SHA256/구성 검사를 적용한다.
실제 stock feed 준비가 미사용 validator 설정 자산을 거절하는 기존 결함을 확인해
portable 자산 목록 한 항목만 제외했다. source 파일·denylist·예외·필터는 유지한다.
manifest 실제 stock 통과·상한1B 초과 거절, 최종 재생성/check·집중·LF clone stock의
근거는 [sub-265 REPORT](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-265/REPORT.md)와
FOR-REVIEW.md에 기록한다. 실제 UAC·옛 v2.0.33 위 설치·현장 경로/계정 수용은
NOT TESTED이며 coordinator의 랩 예행과 독립 확인에 남긴다.



- sub-233 follow-up: preserve legitimate removal delegation through a single statically fixed, already-admitted G metadata probe with `probe_only=True`; actual marker writing keeps the original decorator. Add process snapshots of data/control file list, size and mtime and missing/equal/newer/UNKNOWN removal checks; retain legacy identity, string profile-path API and invalid-storage BLOCKED diagnostics. Conditional decision `msg_eb3b375df3eb`; targeted eleven cases and standard regen/check PASS on the clean follow-up source; final packet and wider verification are recorded in the task report.

- sub-272 추가: startup 뒤 credential/profile/DPAPI/TLS 첫 판독의 G 재확인과
  catch 감사 저장 실패 격리 구현. 실제 G·PS5.1/PS7·집중 기준선 증거는 해당
  REPORT 최종 커밋에 결합하며, 증거 확정 전 UNPROVEN으로 유지한다.

- sub-393 컷 뒤 — **지원 도구 보호 보고서 위치**: relay operator/runner·등록 일반 status·logistics profile check/install·archive check·protected-admin·portable entrypoint/dependency guard의 원문 보관에 쓸 읽기 보호 ACL 위치를 별도 작업으로 증명한다. 이번 전환은 새 ACL 위치/증명 함수를 만들지 않고 공개 고정 코드·안내와 `REPORT_UNAVAILABLE`을 사용한다. 인증·제품 상태 필드는 보존하고 혼합 파일의 자유 진단 값만 같은 키·타입의 고정 코드로 제한한다.
- sub-393 컷 뒤 — 개발/검증 CLI의 공개 출력 전환: active-work probe·review-case report·release/build/qualification 도구 등은 현장 설치·업데이트·지원 경계 이후에 처리한다. 전수 목록과 source별 근거는 `w9scanonly/sub-393/logs/POSTCUT-BACKLOG.csv`에 둔다.
- sub-393 P2 컷 뒤 — 구조화 값 4부류의 보호 보고서 가림: PS5.1/PS7 실제 private writer 8사례에서 보호 파일에만 조각 128개가 남았고 공개 stdout/stderr·caller audit은 0이었다. 가림 멈춤 규칙 0f에 따라 보호 보고서만 남는 모양은 이번에 고치지 않는다. 파일별 조각 수·크기와 실제 reader ACL 검사 근거는 `w9scanonly/sub-393/logs/STRUCTURED-NATIVE-MEASUREMENTS.json`에 둔다.
- sub-405 P2 컷 뒤 — **설치기 비고급 앞단**: `INSTALL_CANONICAL_PORTABLE.ps1`, `INSTALL_THIS_PC.ps1`, `tools/provision_protected_admin_acl.ps1`의 모르는 인수는 개수만 고정 코드로 거절한다. `tools/apply_prepared_update.ps1`, `tools/container_writer_session.ps1`의 잘못된 Mode도 본문 전 binder가 외부 값을 stderr로 되찍으므로 함께 처리한다. 현재는 공식 wrapper로만 실행한다(코디 10-06 09:0x 판정).

- sub-413 P2 컷 뒤 — fence/evidence 초기화 전 `CODE_PRESTATE_WRITER_SEMANTICS_DIFFER` 거절의 공개 capsule은 계약 0f `REPORT_UNAVAILABLE`·정확 throw 위치/type·exit=1을 유지하지만 개별 고정 실패 코드를 내지 않는다. 코디 10-06 16:0x 승인에 따라 원문 보호 보고서 보완 없이 현장/IT용 코드 노출만 후속 처리한다.

- P2 / sub-431: unfenced inverse의 `INSTALL_THIS_PC.ps1:608`은 main catch 전 `CONTAINER_WRITER_FENCE_PARAMETERS_INVALID` 고정 코드와 PS 스크립트 위치/고정 소스만 되찍힌다(외부 입력 원문0, 기준877도 동일). 1차 msg_78ffa7a6332c에서 기존 PS 인수 처리 P2(msg_cd7f16dd1e09)와 같은 부류로 판정; 공개 경계 확장은 컷 뒤, 이번 rollback 고침에서는 유지.

- P2 / sub-413 컷 뒤: 새 앱에서 드물게 스캔이 1–5초 멈출 수 있음(writer fence 대기 중 CSV drain·fsync 경합); 코디 결정 `msg_12baf9aee551`에 따라 알려진 꼬리를 기록하며 새 스캔의 내구 기록·fsync·500ms 측정 기준은 유지한다.
- P2 / sub-451: `next-logon relay 복원`은 기준 1811fce·ba2d75a 모두 미구현 설계이며 후속 결정으로 남긴다. 현재 I1은 실제 relay READY 증명 실패 시 재봉쇄하고 최초 설치 실패를 보존한다.

### D-16 E1 · apply 시작 증거(23:0x 정정)

시험을 본 같은 bootstrap의 FAILED/UNKNOWN·SETTLED 회복과, 240초 뒤 수정된 지 15분을 넘긴 UNKNOWN claim의 좁은 일반 복귀를 구현한다. 일반 writer 부재·active G ALLOW·prepared 부재와 기존 일반 진입 검증을 유지하고 포인터·시험·READY·CONFIRMED는 쓰지 않는다. LIVE·신선한 UNKNOWN·시각 읽기 실패·G 거절은 진행 안내+20이다. 실제 pythonw/로그온 화면에서 종점 뒤 한 번 시작으로 앱이 열리는지와 SYSTEM 240초 감독은 별도 랩 수용 항목으로 남긴다.

사망한 SYSTEM의 같은 claim은 같은 세션에서 재요청하지 않고 현재 G 허용 판을 일반 실행한다. 지원 코드는 같은 protected claim hash에 대해 한 번 게시하며 다음 로그온의 기존 SYSTEM 작업이 새 claim을 덮어써 재시도한다(1차 결정 msg_c93ef274762a).

### Bootstrap relay 시작의 일시 admission 대기

Run 및 GUI가 만든 bootstrap의 relay 실행은 `WriterFencedError` 중 `WRITER_GATE_TIMEOUT`만 기존 240초 창에서 0.1초씩 쉬며 재시도한다. 각 시도는 기존 launch_version의 admission을 다시 얻으며 시도 사이에는 admission을 보유하지 않는다. 상한은 240초 + 마지막 admission 대기 최대 5초이며 마감 뒤에는 기존 실패 출구를 유지한다. fence 확정·버려진 소유권 등 다른 거절과 GUI 실행 자체의 timeout은 재시도하지 않는다. 포인터·trial claim·READY·CONFIRMED·G 허가·cohort·잠금 순서는 유지한다. bootstrap 밖의 relay launcher admission과 실제 로그온/pythonw 수용은 별도 범위다.

### 매일 갱신·시작 경합의 실기 수용

시작/relay/bootstrap의 유한 갱신 잠금 대기와 현재 G 허용 판 복귀, 실패 prepared의 반복 쓰기 억제, 첫 실행 최종 비교의 잠금 아래 재판독을 구현했다. native 별도 프로세스의 6/30초 경합과 서명 검증 실패 반복은 격리 headless 회귀로 확인하며 실제 HDD 로그온·SYSTEM·pythonw 화면의 수용은 별도 랩에 남는다.

### 늦은 outer catch 의 정리 관문 기본 거절(첫 업데이트)

v2.0.109 검토(sub-109 P2-1)에서 본 드문 길이다. 후보 관문 앞에서 실패하면(예: INSTALL_CANONICAL_PORTABLE.ps1 의 inventory sync 예외) outer catch 의 정리 관문이 아직 없는 변수를 false 로 읽어 통과하고, 남의 relay stop 표지를 지울 수 있다. bootstrap_integrity.ps1 의 persistent compensation 도 같은 꼴이다. relay 정지는 일어나지 않고 PID 는 보존된다. 고치는 꼴은 정리 허용을 기본 거절로 두고 cleanup 때 다시 확인하는 것이며, 회귀는 sync·protection·integrity 실패를 주입한다. v2.0.109 에는 넣지 않았다(드문 길·자료 손 0).

### 공용 PowerShell 사본의 BOM(첫 업데이트)

kmtech_shared/powershell/portable.ps1 과 ps51_module_prologue.ps1 은 non-ASCII 글자가 있는데 UTF-8 BOM 이 없다(v2.0.108 부터 같은 바이트). 한국어 PS5.1(CP949)에서 읽힐 때를 막으려면 첫 업데이트에서 BOM 을 넣고, 공용 사본 핀과 선언을 같이 갱신한다. 포장 v2.0.107 검토(sub-112 N1)에서 같은 꼴을 고쳤다.

### 112 원 임대 만료 뒤 완료 검증 (sub-257)

112 시작 `6847b1a`에 원 내구 완료를 만료된 원 임대 그대로 서버에 보내는 `f334b9b`가 포함되어 있다. sub-257은 구현을 중복 변경하지 않고 서버 기록의 resumed_completion/late_reflection 구분, 반영 후 응답 유실·재시작, 동시 원 요청 재생과 효과 1회를 계약 대역으로 보강했다. 디스크 형식·권한·원장 의미 변경은 없다. 실제 서버·현장 수용은 갱신한 `TEST-PLAN-1017-112.md`의 B·R·E 회차에서 별도 확인한다.

### 작업자 PC 개인 지표 지움(112 소스 반영, 실물 확인 별도)

사용자 결정(10/15 18:10): 작업자 PC 에 개인 지표를 보이지 않는다. 「보류·오늘 현황」 의 「작업 통계」 카드(지금 트레이 N분·오늘 평균·30일 최고)를 뺀다. 112 시작 `6847b1a`에는 `bb62e4b`의 다리 `stats` 칸 생략이 이미 포함되어 있다. sub-257은 세 줄 미송신과 보류·오늘 현황·업무 칸 보존을 전체 state 시험으로 확인하고, 평균·최고 기록을 접고 펼친다는 오래된 계약·운영 설명을 정리했다. 현재 UI 사본과 SHA는 그대로이며 실물 장면 확인은 별도 회차다. v2.0.109 빌드·운영 상태를 바꾸지 않는다.

### C12 변경된 원본의 새 승인이 이전 승인 잠금에 막힘(11/1 첫 업데이트)

관리자 검토 sub-133 F1(P2, 10/16): PIN 소비 뒤 격리 원본 바이트가 바뀌어 `TARGET_CHANGED` 로 거절된 다음 같은 항목을 새 바이트로 다시 승인하려 하면, 이전 승인 두 행이 현품표 잠금 증거로 남아 `Container_Audit.py` 의 잠금 검사(:2248 근처)에서 돌아가 새 PIN 요청에 닿지 못한다 → 그 현품표가 묶인 채 남는다. 거절·원본 보존은 지켜지고, 격리 파일 바이트가 그 사이에 바뀌는 것은 변조·손상 같은 이상일 때뿐이라 기준일 판은 그대로 둔다. 고치는 꼴: 같은 격리 항목·원 소유권·기존 감사 기록에 결속한 명시적 관리자 재승인 길을 만든다 — 이전 소비 승인을 새 바이트에 재사용하지 않고, 이전 승인은 감사와 함께 그 항목만 정리하며, 전역 잠금 검사에서 빼지 않는다.
