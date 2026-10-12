# 관리자 설치 받기 v0

w9firstupdsub62의 제품 범위는 관리자 입구, 기계 배치, PENDING과 첫 시작 연결이다.
키트 새 입구와 옛 앱 끄기·백업·복원, 관리자 `-Rollback`은 w9setupprep 몫이다.

canonical은 상승 또는 Session 0에서만 `-WorkerAccount <SID 또는 DOMAIN\이름>`와
`-WorkerSurveyInventory <JSON 경로>`를 함께 받는다. inventory에서 해석하는 값은
문자열 `status=READY`, `target_sid`, `target_profile_root` 세 개다. SID는 계정 해석 결과와
같아야 한다. 상승된 SSH 호출자와 같은 SID도 받으며, 프로필은 해당 SID의 ProfileList 값과 같아야 한다.
파일 없음·잘못된 JSON·필드 불일치는 쓰기 전에 공개 실패 한 줄로 거절한다.
나머지 필드는 해석하지 않고 전체 파일 SHA256만 PENDING에 결속한다.
일반 세션에 두 인수 중 하나라도 넘기면 거절하며 인수 없는 일반 길은 기존대로다.

키트 관리자 입구는 패키지 SHA·pins·plan 컴퓨터 이름을 확인하고 작업자 맥락에서
만든 READY inventory를 넘겨야 한다. 인수 없는 직접 관리자 호출은 계속 거절한다.
제품은 기존 INSTALL_THIS_PC 배치·무결성·writer authority를 사용하며 내부 UAC를
추가 요청하지 않는다. 다른 SID의 작업자 프로필과 호출자 HKCU Run은 변경하지 않는다.
같은 SID는 호출자 LOCALAPPDATA가 검증한 프로필과 일치할 때 자기 자료 폴더·HKCU Run·
개인 시작 메뉴/바탕화면 링크를 준비한다. 옛 앱 링크는 보존하며 등록·일반 사용자 relay·
화면 시작은 PENDING을 소비하는 작업자 세션/다음 로그온/첫 시작으로 넘긴다.
개인 준비 실패도 원래 Run·링크를 복원하며 새로 만든 빈 폴더만 지운다.
관리자 기계 배치와 작업자 설치·첫 시작 준비·다음 로그온에서 호출하는 PowerShell은
자식 인수에 `-ExecutionPolicy Bypass`를 명시한다. 기존/배치된 코드 무결성 확인과
지원 제거 자식도 같은 규칙을 따른다. 적용 범위는 자식 프로세스이며 OS·GPO 정책은 변경하지 않는다.
새 공용 시작 메뉴 바로가기는 current의 runtime/pythonw.exe로 앱 main.py를 실행한다.
같은 이름의 기존 링크는 대상·인수·작업 폴더가 이 제품과 같을 때 저장 없이 재사용한다.
다른 링크나 알 수 없는 원본은 변경하지 않고 거절하며 복구 fence를 유지한다.

PENDING 경로는 `%PROGRAMDATA%\KMTech\ContainerAudit\machine-install\pending-onboarding.json`이다.
`container-audit-machine-pending-v1` 기록에 설치 id·판·소스 commit·대상 SID·설치 루트와
inventory SHA256을 결속한다. 관리자/SYSTEM만 쓰고 사용자는 읽는다.
표지와 읽기 ACL을 확정한 뒤 공용 바로가기와 기계 완료 기록을 만들고 fence를 해제한다.
표지 ACL 실패 시 복구 fence를 유지하며 첫 시작 등록을 막는다.
`PASS_MACHINE_WORKER_PENDING`은 기계 배치 결과이며 설치 완료가 아니다.

지정 작업자의 첫 앱 실행은 기존 current-user onboarding의 READY 뒤 HKCU
`Software\KMTech\ContainerAudit\MachineOnboarding`의 `CompletedInstallId`를 기록한다.
첫 실행은 current/app 또는 같은 commit의 versions/<commit>/app만 받으며 두 manifest를 함께 확인한다. 같은 id는 다시 등록하지 않고 새 id는 새 설치로 처리한다. 완료한 id의 표지는 이후 판 갱신을
막지 않는다. 다른 SID·미완료 판 불일치·등록 실패는 완료 기록을 만들지 않으며 원본 표지를
수정하거나 지우지 않는다. 관리자 길에 옛 앱 처리 callback은 없다.
GUI 입구는 기존 업데이트 관문 전에 대상 SID만 읽어 확인하고 다른 계정에는 안내한다.
이 확인은 worker HKCU를 읽거나 쓰지 않으며 onboarding·relay를 시작하지 않는다.
첫 시작 시점에 키트 넘김이 필요하면 받을 자리 = PENDING 표지 소비 직전.

`RestoreVerifiedReplacement`와 `-Uninstall`은 기존 replacement receipt·bootstrap inventory·
supported removal journal을 쓰는 기계 코드 복원/제거다. 작업자 HKCU 복원을 주장하지 않는다.
두 작업은 대상 SID·설치 루트가 맞는 PENDING과 제품의 직접 공용 링크도 정리한다.
변경된 링크와 옛 앱 링크는 보존한다. 설치 전 표지·링크 원바이트와 ACL을 캡처하며,
이후 설치가 실패하면 새 항목을 지우고 원본을 복원한다. 교체 receipt가 있으면 앞 코드 판도
복원한다. 실패 기록 쓰기가 실패해도 보상은 실행한다. 자식 종료·코드·표지/링크·작업자
Run·새 폴더 복원이 모두 확인되면 실패 승인 receipt로 fence를 해제한다. 확인되지 않은
보상만 fence를 유지한다.
격리 시험의 첫 시작은 주입한 onboarding READY와 완료 기록으로 연결을 확인한다.
실제 등록·DPAPI·HKCU·ACL·공용 바로가기 및 옛 앱 복원·켜짐은 랩 VM 실제 설치 회차에서
별도로 검증해야 한다. 키트 `-Rollback` 끝까지의 결과를 제품 fixture PASS로 대신하지 않는다.

### 현재 콘솔 작업자의 자동 선택

`-WorkerAccount`와 `-WorkerSurveyInventory`를 모두 생략한 승격 호출은 현재 활성 콘솔 세션의 explorer 소유 SID가 하나이고 그 SID의 ProfileList가 확인될 때만 받는다. 호출자 SID와 세션이 콘솔 작업자와 같으면 기존 일반 설치·업데이트·지원 재개 길을 유지한다. Session 0 또는 다른 관리자는 그 작업자를 기계 배치 대상으로 결속하고 대화형 완료를 PENDING으로 남긴다. 콘솔 없음·소유자 판정 실패·여러 SID는 쓰기 전에 거절한다. 둘 중 하나만 넘긴 명시적 인수는 계속 거절하며, 두 인수를 넘기면 기존 READY inventory 검증을 유지한다.

기계 배치 실패 시 검증된 앞 코드와 startup control 원본을 함께 복원한 뒤에만 옛 PENDING을 복원한다. 코드·control 원본을 확인하지 못하면 옛 PENDING을 게시하지 않고 기계 복구 fence를 유지한다. 이 fence는 관리자 복구가 끝나기 전 작업자 첫 시작을 막는다.

기계 설치 실패는 기존 `MACHINE_INSTALL_FAILED`·종료 코드 4·공개 JSON 한 줄을 유지하며 `reason_code`와
`summary_message`(`MACHINE_INSTALL_FAILED reason=<고정 코드>`)를 덧붙인다(IA-01). 고정 코드는 남은 기계 fence
`PRIOR_INSTALL_UNFINISHED`, 남은 작업자 fence `WORKER_INSTALL_UNFINISHED`, 비관리자 토큰 `ADMINISTRATOR_REQUIRED`,
기록 방식 차이 `INSTALLED_WRITER_SEMANTICS_DIFFER`, 배치 helper의 허용 목록 `reason_code`(`lifecycle_*`·writer gate·
`STARTUP_UPDATE_*`)와 그 밖의 helper 실패 `PLACEMENT_HELPER_FAILED`, 나머지 `UNCLASSIFIED`뿐이다. 예외 원문·경로·
계정·자식 출력은 싣지 않으며 목록 밖 값은 가린다.

### 기계 배치 실패의 지원 재개

키트 설치/되돌림은 남은 fence를 직접 지우지 않는다. 원래 관리 패킷의 설치기를 이미
승격된 지원 셸에서 `-RecoverMachineInstallation -MachineRecoveryAuditPath <기계 audit>
-MachineRecoveryAuditSha256 <SHA256> -WorkerAccount <작업자 SID>
-WorkerSurveyInventory <READY inventory>`로 호출한다. audit는 기계 상태의
`install-audit/canonical-portable-<run>.json`이다. 이 입구는 audit·사전 상태 파일·원래
패킷·작업자·fence tuple을 읽기로 대조하고 같은 authority를 새로 독점한 뒤 보상을
재시도한다. `MACHINE_PREPARING`과 `MACHINE_INSTALL_FAILED`, 자식 상태
`NOT_STARTED`·`EXITED`·`EXIT_UNPROVEN`만 받는다. 준비 중이거나 자식 종료가 미증명이면,
이미 시작한 모든 자식의 기록된 `process_id`와 UTC `started_at_utc`를 현재 프로세스와
대조하고, 한 번 읽은 Win32_Process의 명령줄에 같은 `-WriterFenceReplacementTransactionId`
인수의 run ID를 가진 살아 있는 프로세스가
0일 때만 보상을 시작한다. 해당 PID가 없거나 시작 시각이 다르면 원래 자식의 종료로
인정한다. PID 미기록도 run ID 프로세스가 0이면 종료로 인정한다. 같은 PID·같은 시각의
자식, 같은 run ID의 손자 프로세스, 살아 있는 원 authority는 거절하며
담장과 원본을 보존한다. 새 배치·보상 자식은 시작 직후 같은 audit 쓰기 경로로 두 값을
기록한다. PID/시각 없는 미증명 자식의 run ID 프로세스가 남으면 `MACHINE_RECOVERY_CHILD_UNRECORDED`,
잘못된 기록은 `MACHINE_RECOVERY_CHILD_IDENTITY_INVALID`, 살아 있는 자식은
`MACHINE_RECOVERY_CHILD_ACTIVE`, 관측 실패는 `MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN`으로
거절한다. 프로세스를 멈추거나 신호를 보내지 않는다. 같은 SID에서 준비한 HKCU는
그 작업자 본인으로만 복원한다. 보상 실패 시 기존과 같이 담장을 유지한다.
버려진 authority mutex는 복구 호출이 대기 없이 획득한 것으로 인정한다. mutex는 0초,
Win32_Process 조회와 각 PID 생성 시각 읽기는 각각 5초 상한이며 대기 반복은 없다.
명령줄은 메모리에서 run ID 맞춤 여부만 확인하고 출력·저장하지 않는다. 부팅 시각은 쓰지 않는다.
전원 끊김 뒤 `ALREADY_ACTIVE`/`ACTIVE_WRITER_FENCE`가 보이면, 기계 상태 폴더
`%ProgramData%/KMTech/ContainerAudit/machine-install`의
`control/writer-session/active.json`에서 `replacement_transaction_id`만 확인한다.
그 값이 `<run>`이며 같은 상태 폴더의 `install-audit/canonical-portable-<run>.json`과
`(Get-FileHash -Algorithm SHA256 -LiteralPath <그 audit 경로>).Hash.ToLowerInvariant()`
결과를 위 복구 인수로 사용한다.
원본 표지·바로가기·Run을 담는 사전 상태 폴더는 관리자·SYSTEM만 읽고 쓴다.
성공 상태 `PASS_MACHINE_RECOVERED`를 확인한 다음 설치 또는 `-Uninstall`을 다시
호출한다. 새 설치 보상은 제품 helper의 검증된 제거로 배치 코드를 없애며 자료는 보존한다.
`PlanOnly`도 같은 SID의 LOCALAPPDATA·개인 바로가기·reparse 읽기 검사를 먼저 실행한다.

제품 기계 입구를 pwsh.exe로 직접 부를 때 제거·보상은 Program Files 아래 실제 Microsoft 서명 엔진과 정본 소스·권한 tuple·살아 있는 부모 사슬·시작 시각을 함께 확인한다. 격리 시험의 최소 환경은 ProgramFiles와 ProgramW6432가 없어도 OS의 Program Files 경로를 읽어 설치기 사본의 자식 환경에 공급하며, 실제 서명·부모 사슬 검증과 기존 상태 보존 단언을 유지한다.
