# 남은 요구·검증·문서·추가 제안

[제품·카드](README.md) · [계약](contracts.md) · [운영](operations.md) · [중앙 백로그](../../../Program_Spec_Hub/BACKLOG.md) · [실제 준비도](../../../Program_Spec_Hub/READINESS.md)

**현재 상태 — 2026-09-09 S05:** 선택된 여섯 프로그램 qualification은 Main의 독립 composition 검토로 마감됐다. 최종 frozen `d440b1f7`의 요청 범위 native 수용은 **완료(지원 recovery 포함)**이며, 상세 범위는 [CA-G10](#ca-g10)과 [CA-O10](operations.md#ca-o10)을 따른다. 최초 fresh 등록 실패와 아래 과거 시점의 판단을 보존하며 물리 장비·공장 배포는 별도 범위다. 현재 소스 단순화의 변경·검증·독립 검토는 [CA-G11](#ca-g11)에 기록한다.

기준일 2026-09-07. 아래 우선순위와 담당은 정리 제안/책임 역할이며 새 개발 승인·기한·인력 배정이 아니다. P0는 기존 qualification 실패 처리, P1은 계약/운영 판단에 필요한 공백, P2는 요구 미확정 추가 제안이다. 정적 확인, 기존 실행, 이번 문서 검토의 범위는 [README](README.md#1-기준과-증거-사용법)를 따른다.

**이전 validator 문서 작업 이력:** 승인된 다섯 문서의 소스 기준선과 지속 갱신 규칙은 Main 교차 검토 수용을 마쳤다. 당시 후속 작업은 기존 capture validator 통합의 적용성 대조·현재 상태 보완·단일 커밋 검토 준비였으며 제품/test 코드 변경이나 실행을 포함하지 않았다. 해당 조사만으로 별도의 **승인된 제품 기능 미구현**을 확정할 근거는 없다. 추가 아이디어와 찾지 못한 실행 증거를 구현 결함으로 세지 않는다. 대표 13개 기능 카드도 전체 기능 수나 완료율의 분모가 아니다.

2026-09-08 후속 FULL 실패 분석·별도 cleanup과 E의 좁은 fixture 검증은 [CA-G08](#ca-g08)에 기록한다. 앞 문단의 미실행 설명은 이전 validator 문서 작업의 범위이며 이 후속 실행을 포함하지 않는다.

## 문서 작성 진행과 제품 준비도

현재 스캔 저장·held 감사·GUI 완료의 JSON/CSV 내구 작업은 직렬 worker로 이동했다.
CSV 중복 판단은 전체 내용을 직접 읽으며 색인·metadata 기반 부재 판정은 도입하지 않는다.
합성 callback 시간과 실제 디스크 ACK 시간은 구별한다. 실제 스캐너 연속 입력·저장 지연/실패 안내·종료 drain의 화면 확인과 현장 지연 분포는 남아 있으며 GUI/VM/운영 수용으로 승계하지 않는다.
보류 JSON 전체 검색은 유지한다. 대량 보류의 실사용 건수와 허용 지연을 먼저 확인해야 하며 파일 회전/보관 정책은 이번 소스 변경에 포함하지 않는다.
relay의 변경 없는 ACK 완료 source는 300초 내용 검증 주기 사이에 재읽기를 생략한다. 합성 읽기 바이트 감소와 실제 배포의 CPU/디스크 부하·전송 최신성 수용은 구분한다.

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
- **범위 확인:** 비compact/부분 제출 코드·Shift-F8 fallback·내부 시험 명령이 존재한다고 일반 운영 지원으로 승격하지 않는다. [지원 경로 표](README.md#2-사용자제품-경계와-지원-경로)와 [CA-C09](contracts.md#ca-c09)를 기준으로 실제 배포/현장 지원 여부를 정리한다.
- **완료 기준:** 해당 기존 문서 소유자가 현행 소스와 역사/호환 조건을 구분해 안내를 정합시키고, 지원 경로·설정·수용 기준·날짜를 연결한다. 새 규칙이나 과거 현장 PASS를 만들지 않는다.
- **담당·의존·다음 행동:** CA 문서 담당+Main. CA 안내 정정은 S05에 포함하며 상위 역사 자료는 보존한다. 비compact/부분 제출 등 현장 지원 범위 재확인은 별도 요구이고 이 정리에서 삭제하거나 승격하지 않았다.

<a id="ca-g04"></a>
## CA-G04 정상·장애·장비·설치 수용 근거 연결

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
- **근거:** [운영 설정/공급자](operations.md#ca-o02), [장비](operations.md#ca-o03), [contract.lock.json](../../contract.lock.json), [물류 client 생성/capability 검증](../../transfer_seal.py). 사용자 profile·Machine fallback·legacy 환경, 물류 operation lease와 producer runtime lease, 작업자와 device 권한을 구분한다.
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

- **2026-09-12 CA-D01 소스 교정:** 개별 교환의 입력·완료/취소는 고정하고 제목/수량/안내/표는 기존 viewport로 세로 접근한다. 실제 heading·rowheight·가로 scrollbar 요청 높이로 두 행 최소 크기를 확보하고 새 행 `see()`·긴 barcode 가로 접근·wheel/PageUp/PageDown·수량 focus 노출을 유지한다. 1024×768의 화면 cap672px 산술과 기존 headless 영향 검사를 실행한다. 0.7/2.5에서 양쪽 두 행 bbox·고정 footer를 확인하는 기존 `real_gui` 검사는 갱신했으며 이 구현 레인에서는 실행하지 않았다. 아래 과거 native 실패는 보존하고 실제 화면 수용은 별도 검증 파도에 남긴다.
- **w1 검증 근거:** [구현 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w1/RESULT.md)의 교환 관련 headless53 PASS, 감사 focused6모듈224 PASS/정상 exit0/잔존 thread0을 확인했다. 원 targeted7노드(일반·held 분리 포함)와 이벤트 재시작·시계 역행·종료 guard를 묶은14 PASS를 별도로 기록한다. 이 결과로 미실행 native bbox/실제 화면을 PASS로 바꾸지 않는다.

- **오류 안내 정합:** 이전 실제 duplicate 화면(`visible-frames-current/0019.png`)은 입력/상태가 차단돼도 큰 안내가 다음 제품 스캔을 지시했다. 차단 중에는 큰 안내도 확인을 지시하고, 해결 뒤 현재 스캔 단계로 복귀하도록 수정했다. 기존 native 중복→확인 회귀에 문구 양방향 검사를 추가했다.

- **후보 정적 후속:** 교체 화면의 열림/보조 모드를 글자 크기 재구성에서 유지하고, 저장된 미완료 교체가 있으면 일반 메뉴가 막혀도 기존 F8 교체 진입을 보이도록 보완했다. 관련 기존 비GUI35 PASS(`tests/6404989d1b`)이며 native 회귀는 실제 배정 시 열기→재구성→조회 중 닫기 거부→복구 진입을 확인한다.

- **2026-09-12 일상 정보 축소 구현:** 최종 제품 `0ea7251`은 반복 안내·현품표 교체 설명·최근 스캔/시간 통계를 조건부 안내와 작업 상세로 옮기고, 전송 대기·확인 필요·로컬 저장/중앙 완료를 구별한다. 기존 상세 버튼 글꼴을 상속하면서 짧은 우측 영역의 여백·예약 폭을 줄였다. 호스트 최종 영향104 PASS, 실제 native 최초40 PASS/6 FAIL 중 우측 잘림5는 동일 배율 사례에서 최종5 PASS다. 최초100ms 기준100.973ms 실패·정리 보완 후1 PASS, dirty-source provenance 실패와 모든 native 중간 실패를 보존했다. 실제 전체 앱 관찰은1024×768 합성 화면이며 사업 receipt/성능/1920 전체 화면 수용이 아니다. [전후 표·검증·custody](D:/KMTech/optimization-implementation-20260909/UI-IMPROVEMENT-20260912-1318/Container_Audit/RESULT.md).
- **남은 한정 항목:** 같은 native 실행의 확대 개별 교환 표는 두 번째 행 bbox93+91이 표 높이154를 넘었다. 교환 생성·화면 크기 제한 함수 AST는 변경 전b0e5d93과 같지만 이 사실만으로 과거 native 상태를 PASS로 추정하지 않는다. 실제1024×768/배율2.5에서 행 전체를 볼 수 있게 하는 별도 조정·검증이 남는다. Pillow 미설치로 collection이 중단된 native 구조 모듈도 미실행이며 호스트104 PASS와 구별한다. VM6fcb는06:38:34Z Saved/할당0으로 반환했고 task 루트·프로세스는 없다.

- **상태·범위:** 사용자 전수 UI 점검 요청으로 [실제 UI 목록](README.md#2026-09-10-ui-전수-점검과-idle-후-작업-명령-갱신)을 추가했다. e69a0cb 기반으로 idle 후 운영 작업 버튼 갱신과 기존 종료 요청 flag guard를 두 줄 보완하고 기존 회귀에 실제 lane busy/idle·close 상태를 검사한다. 수량·membership·authorization·내구 저장 조건은 변경하지 않는다.
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

## 갱신 기준

요구 확정·소스 변경·실행 결과가 생긴 담당자는 연결된 기능/계약/운영 항목과 이 문서의 상태·다음 행동을 같은 작업에서 갱신한다. Main에 중앙 INT-02/03/04/09/10, I02/I04 및 Q01/Q07에 미치는 차이를 알린다. 과거 실패·미실행을 삭제하지 않고 새 버전·환경의 근거를 연결한다. [AGENTS의 지속 관리 규칙](../../AGENTS.md)을 적용한다.
