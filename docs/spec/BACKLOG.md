# 남은 요구·검증·문서·추가 제안

[제품·카드](README.md) · [계약](contracts.md) · [운영](operations.md) · [중앙 백로그](../../../Program_Spec_Hub/BACKLOG.md) · [실제 준비도](../../../Program_Spec_Hub/READINESS.md)

기준일 2026-09-07. 아래 우선순위와 담당은 정리 제안/책임 역할이며 새 개발 승인·기한·인력 배정이 아니다. P0는 기존 qualification 실패 처리, P1은 계약/운영 판단에 필요한 공백, P2는 요구 미확정 추가 제안이다. 정적 확인, 기존 실행, 이번 문서 검토의 범위는 [README](README.md#1-기준과-증거-사용법)를 따른다.

승인된 다섯 문서의 소스 기준선과 지속 갱신 규칙은 Main 교차 검토 수용을 마쳤다. 후속 작업은 기존 capture validator 통합의 적용성 대조·현재 상태 보완·단일 커밋 검토 준비이며 제품/test 코드 변경이나 실행을 포함하지 않는다. 현재 조사만으로 별도의 **승인된 제품 기능 미구현**을 확정할 근거는 없다. 추가 아이디어와 찾지 못한 실행 증거를 구현 결함으로 세지 않는다. 대표 13개 기능 카드도 전체 기능 수나 완료율의 분모가 아니다.

2026-09-08 후속 FULL 실패 분석·별도 cleanup과 E의 좁은 fixture 검증은 [CA-G08](#ca-g08)에 기록한다. 앞 문단의 미실행 설명은 이전 validator 문서 작업의 범위이며 이 후속 실행을 포함하지 않는다.

## 문서 작성 진행과 제품 준비도

| 관리 대상 | 현재 상태 | 완료/다음 판단 |
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

- **유형·우선순위·상태:** 확인된 문서 불일치/지원 범위 확인, P1, 새 명세에 차이 명시 완료·기존 문서 수정 대기. 오래된 기술/운영 설명이 잘못된 설치·작업 판단을 유발할 수 있다.
- **확인한 차이:** [CODEX](../../CODEX.md)의 pygame/PyInstaller 설명과 현행 [native_audio](../../native_audio.py)·[portable launcher](../../portable/launch-container-audit.cmd)는 다르다. [LOGISTICS_RUNTIME_PROFILE](../LOGISTICS_RUNTIME_PROFILE.md)의 공통 ProgramData profile·중앙 ACK 전 로컬 성공 불허 설명은 현재 [사용자 onboarding](../../current_user_onboarding.py)·[CA-12의 LINKED 분기](README.md#ca-12)와 구분이 필요하다. 과거 [2026-06 연구](../../../docs/program-research-20260617/container-audit-transfer.md)의 `C:/Sync`·버전은 역사 자료다.
- **범위 확인:** 비compact/부분 제출 코드·Shift-F8 fallback·내부 시험 명령이 존재한다고 일반 운영 지원으로 승격하지 않는다. [지원 경로 표](README.md#2-사용자제품-경계와-지원-경로)와 [CA-C09](contracts.md#ca-c09)를 기준으로 실제 배포/현장 지원 여부를 정리한다.
- **완료 기준:** 해당 기존 문서 소유자가 현행 소스와 역사/호환 조건을 구분해 안내를 정합시키고, 지원 경로·설정·수용 기준·날짜를 연결한다. 새 규칙이나 과거 현장 PASS를 만들지 않는다.
- **담당·의존·다음 행동:** CA 문서 담당+Main. 이번 소유 범위는 다섯 문서뿐이므로 기존 CODEX·운영 프로필·상위 역사 자료는 보존했다. Main에 차이를 알리고 해당 문서의 후속 소유 작업으로 넘긴다. CA-G05의 배포 선택 확인은 별도로 진행 가능하다.

<a id="ca-g04"></a>
## CA-G04 정상·장애·장비·설치 수용 근거 연결

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

<a id="ca-g05"></a>
## CA-G05 실제 설치 구성·권한·장비 지원 범위

- **유형·우선순위·상태:** 환경/공급자·지원 경로 확인 공백, P1, 미확인. 소스와 설치본이 다른 경로를 선택하면 과거 근거를 적용할 수 없다.
- **근거:** [운영 설정/공급자](operations.md#ca-o02), [장비](operations.md#ca-o03), [contract.lock.json](../../contract.lock.json), [물류 client 생성/capability 검증](../../transfer_seal.py). 사용자 profile·Machine fallback·legacy 환경, 물류 operation lease와 producer runtime lease, 작업자와 device 권한을 구분한다.
- **완료 기준:** 대상 패키지/수정 트리·Python/Tcl·실제 vendor/overlay·선택된 profile/provider 경로·비밀 제외 scope/epoch·서버 flags/capability·장비 모델/드라이버·지원 UI 경로를 기록하고 관련 기존 증거와 일치 여부를 판정한다. 요청하지 않은 credential/OS 보안 변경을 요구하지 않는다.
- **담당·의존·다음 행동:** CA 배포/운영 담당+Web+Main. 기존 후보 manifest와 보고서부터 확인하고 없는 정보만 후속 확인 범위로 정한다. 구성 대조는 CA-G06 요구 정리와 독립 가능, 실제 현장/VM 접근은 기존 실행 지시에 따른다.

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

- **유형·우선순위·상태:** 실제 qualification 후속, P1, 첫 fresh 실패 보존·정상 recovery와 후속 설치 PASS·업무 검증 중. [첫 시도](E:/KMTech/ca-install-qualification-20260908/REPORT.md)의 frozen source68dd/동일 ZIP은 guest PlanOnly·HTTPS·일반 사용자 token·코드 배치까지 통과했으나 registration `producer_identity_conflict`로 canonical exit1 / **FAILED_ROLLED_BACK**다. 위 CA-G08의 설치 NOT TESTED는 빌드 당시 이력이며 현재 결과에 자동 적용하지 않는다.
- **원인·보존할 계약:** 초기 로컬 6종 자료 ABSENT와 새 possession key가 있어도 MachineGuid+SID+app 파생 lookup ID는 기존 중앙 active epoch6과 일치했다. [CA-C10](contracts.md#ca-c10), [Web 공개 lineage](E:/KMTech/web-integration-20260908/ca-enrollment-lineage.json). Main의 기존 소유 배정 후 정상 recovery가 epoch7과 manifest/서버 검증을 통과하고 별도 Web operation grant가 승인됐다. 임의 ID·키 삭제나 인증 우회는 없으며 식별자 파생 정책은 유지한다.
- **복원·현재 소스:** lifecycle rollback 후 Run/relay/등록 자료 부재를 확인했지만 새 verified code는 남는다. 현재 소스는 이 경우의 상태를 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`로 바로잡고 경로 경고를 추가했다. 신규 fresh 실패1·기존 교체 복원1 회귀 PASS이며 frozen 설치본에는 미포함, 전체 exact rollback은 **UNPROVEN**이다. 원래 실패11파일과 성공 후속13파일은 별도로 hash 일치 보존했다.
- **현재 업무·정리:** case01 mixed NG work group을 즉시 GOOD-only 양성 사례로 취급하던 fixture 가정은 Web readback을 근거로 폐기했다. 원래 거부·NG 이력과 hold는 정상 QA supervisor 설정·masked GUI 인증·제품 quarantine으로 보존했고 ordinary WORKER로 돌아왔다. case02 preflight/목표2·부분 제출 거부·중복 거부·보류/정상 앱 재시작/동일 snapshot 복원·정확한2개 GOOD 로컬 완료는 실제 PASS 범위다. 이 흐름에서 안전한 상태를 건너뛰는 새 validator나 임의 파일 조작은 추가하지 않았다.
- **담당·다음 행동·완료 기준:** 일반 후속 설치는 exit0/PASS·READY/REUSED이고 정상 recovery 후 실제 case02 seal은 Web 전역 JSON validator의 `INVALID_INPUT`으로 OPERATOR_REVIEW/attempt1이다. Web은 보호된 실제 command의 거부 predicate와 정상 수정 경계를 확인한다. CA는 원본명령·LINKED/TRAY_COMPLETE를 보존하고 [CA-O09](operations.md#ca-o09)의 중앙 ACK/별도 producer·화면 대조·case03·cold boot·제거/재설치와 적용 가능한 exact rollback을 계속한다. 첫 fresh 실패·seal 실패·미실행을 유지하며 source 회귀·문서 갱신·producer 성공 자체를 종합 Ready나 물류 ACK로 합치지 않는다.
- **확인된 복구 한계·승인 후속:** frozen `TransferSealCoordinator.attempt`는 OPERATOR_REVIEW에서 즉시 반환하고 pending 목록도 제외한다. 기존 UI 재시도는 command bind 전만 지원하므로 Web 수정만으로 이 terminal intent를 정상 same-key 재전송할 수 없다. Main `msg_9d5415ea3be1`의 명시적 승인으로 불변 command/동일 key/정상 receipt 검증을 유지하는 관리자 확인 재시도를 source에 구현했다. 자동 terminal retry·DB 수선·원래 완료 시각 변경은 없다. Web 관측 lease 만료는08:11:34Z이나 원래 완료 시각은 기간 안이다. Web `msg_e3bd2837e6a3`는 현 server가 기존 receipt를 먼저 재생하며 미확정 lease도 원래 완료 시각·서명·fence·상태를 대조해 늦은 제출을 판정한다고 확인했다. 변경 후보 build/정상 설치/실제 원 key ACK는 아직 미실행이며 frozen 실패는 유지한다.

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

## 갱신 기준

요구 확정·소스 변경·실행 결과가 생긴 담당자는 연결된 기능/계약/운영 항목과 이 문서의 상태·다음 행동을 같은 작업에서 갱신한다. Main에 중앙 INT-02/03/04/09/10, I02/I04 및 Q01/Q07에 미치는 차이를 알린다. 과거 실패·미실행을 삭제하지 않고 새 버전·환경의 근거를 연결한다. [AGENTS의 지속 관리 규칙](../../AGENTS.md)을 적용한다.
