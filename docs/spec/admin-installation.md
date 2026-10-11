# 관리자 설치 받기 v0

w9firstupdsub62의 제품 범위는 관리자 입구, 기계 배치, PENDING과 첫 시작 연결이다.
키트 새 입구와 옛 앱 끄기·백업·복원, 관리자 `-Rollback`은 w9setupprep 몫이다.

canonical은 상승 또는 Session 0에서만 `-WorkerAccount <SID 또는 DOMAIN\이름>`와
`-WorkerSurveyInventory <JSON 경로>`를 함께 받는다. inventory에서 해석하는 값은
문자열 `status=READY`, `target_sid`, `target_profile_root` 세 개다. SID는 계정 해석 결과와
같고 호출 관리자 SID와 달라야 한다. 프로필은 해당 SID의 ProfileList 값과 같아야 한다.
파일 없음·잘못된 JSON·필드 불일치는 쓰기 전에 공개 실패 한 줄로 거절한다.
나머지 필드는 해석하지 않고 전체 파일 SHA256만 PENDING에 결속한다.
일반 세션에 두 인수 중 하나라도 넘기면 거절하며 인수 없는 일반 길은 기존대로다.

키트 관리자 입구는 패키지 SHA·pins·plan 컴퓨터 이름을 확인하고 작업자 맥락에서
만든 READY inventory를 넘겨야 한다. 인수 없는 직접 관리자 호출은 계속 거절한다.
제품은 기존 INSTALL_THIS_PC 배치·무결성·writer authority를 사용하며 내부 UAC를
추가 요청하지 않는다. 작업자 프로필, 관리자 HKCU Run, 옛 앱과 옛 바로가기를 변경하지 않는다.
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
격리 시험의 첫 시작은 주입한 onboarding READY와 완료 기록으로 연결을 확인한다.
실제 등록·DPAPI·HKCU·ACL·공용 바로가기 및 옛 앱 복원·켜짐은 랩 VM 실제 설치 회차에서
별도로 검증해야 한다. 키트 `-Rollback` 끝까지의 결과를 제품 fixture PASS로 대신하지 않는다.
