# 운영·환경·장애 복구

10/15 화면 동작: 부분 제출 확인은 재시작 때 채우는 중으로 돌아가며, 이미 저장된 결정은 유예 없이 같은 키로 복구·확정한다. C02–C07·검증된 C09는 자기 작업에 한해 PIN 없이 처리하고 C08·수동 결속·격리 복원은 관리자 PIN을 요구한다. 실제 창 동작·장면 판정과 부분 제출/PIN 독립 검토는 통합 뒤 별도 수용한다.

자동 오프라인 보관 원본은 같은 작업자가 재스캔하고 자동 보관 사유와 원본 지문이 동기 감사와 일치할 때만 PIN 없이 FIFO를 복구한다. 관리자 격리 원본·다른 작업자·지문 불일치와 공개 C12 복원은 기존 PIN 경계를 유지한다.

자동 업데이트 출발판은 v2.0.104 이상이다. 업데이트 후보는 설치된 판의 `tools/apply_prepared_update.ps1`이 판정한다. v2.0.103처럼 unsigned 목록이 빈 판만 받는 옛 helper가 깔린 PC는 v2.0.104 이후 자동 업데이트를 `STARTUP_UPDATE_PORTABLE_MANIFEST_DIFFERS`로 거절하며 업무를 멈추지 않는다. 그런 PC는 정식 제거 뒤 새로 설치한다. 자료꼴 호환 하한 v2.0.103은 업데이트 출발판을 뜻하지 않는다.

설치 자식의 fallback 진단은 객체·schema·정수 exit_code를 확인한 뒤 읽는다. 누락·null·배열·손상·64 KiB 초과·미지 형식은 「진단 형식 모름」으로 따로 기록한다. 자식의 원 종료값·출력·이유·최초 실패 참조는 유지하며, 진단 parser 예외가 original_failure를 선점하지 않는다. 정상 옛 fallback은 자식 종료값이 일치할 때만 선택한다. 증거 writer 실패와 task 부재·UNKNOWN 거절은 그대로다.

v2.0.108 기본은 web이며 --new-screen·--ui web도 같은 뜻이다. --old-screen·--ui tk는 그 실행만 Tk를 고른다. 모르는 --ui 값은 기본 길이다. M84 진입에는 PID 대기나 자동 재실행이 없다.
기계 설치의 New-CanonicalMachineShortcut도 앱 폴더\관리용의 「이적 옛 화면 (비상)」 링크를 생성·유지한다. current launcher·작업 폴더·아이콘에 --ui tk를 붙이며 code inventory 밖에 둔다. 소유한 링크만 보상 preimage에 포함하고 다른 파일이 있는 폴더는 건드리거나 recovery journal에 복사하지 않는다. 실제 코드 제거 뒤 machine artifact 제거가 링크와 빈 관리용 폴더도 지우며, 앞 current로 복원한 경우에는 링크를 유지한다. 일반 바로 가기에는 화면 인수가 없어 앱의 web 기본을 따른다.
웹 생성 뒤 시작 실패는 셸의 쓰기 문 닫음·판 표지·destroy·before_exit·끝 한 길이다. 같은 프로세스 Tk 전환·자동 재실행은 없다. 표지 저장 실패도 끝내고 되풀이하지 않는다. 사람이 다음에 켜면 같은 판 web_allowed=False로 Tk를 연다. before_exit 빔은 writer 허가·mutex가 비고 모든 lane worker 실이 죽은 것(BROKEN 포함)이며 다른 정리는 없다. 120초·5초 확인, False면 끝내기를 미룬다. 셸 import try 실패는 SHELL_IMPORT_FAILED→Tk, 비상 Tk 셸 import0. 생성 전·시작 거절·업무 gate는 유지한다.
M86: 셸 OS 실패 안내의 제목은 `title="이적"`이다. mainloop 전 초기화 실패와 lane pump 생성 실패도 기존 owner 정리/close_idle로 worker를 멈춘다. before_exit의 닫힘 표시와 lane 시작은 같은 잠금으로 줄 세워 늦은 시작을 거절한다. 기존 receipt/위임/authority 검증을 통과한 위임·유지보수 허가는 normal 허가 없이 worker 실제 종료만 확인한다. portable 선행 admission의 abandoned 거절도 한 번 더 열기 안내·기존 지원 기록·종료 1을 유지한다. 셸 사본 통합 전 OS 안내 실물은 미검증이다.

단일 실행은 source·portable 진입에서 무거운 import나 시작 gate보다 먼저 기존 data_root Global mutex를 잡는다. 소유자는 사용자 자료 자리의 data_root 해시별 JSON에 PID·실행 파일·프로세스 생성 시각·starting/running/closing을 원자적으로 남기고 끝에 지운다. 이 두 표지 함수만 업무 admission과 분리한 report-only metadata로 선언한다. 두 번째는 PID·실행 파일·생성 시각이 모두 맞는 표지만 믿고 그 PID의 보이는 최상위 창을 앞으로 가져온다(웹 우선). 최소화는 복원하고 전경 거절은 작업 표시줄을 깜박인다. 창이 없으면 상태별 안내 하나가 5초 뒤 닫히며 rc0이다. 두 번째 길에는 Tk·셸·업무 core import가 없다. 실제 OS 창 동작은 현장 확인 범위다.
표지 PID의 실제 실행 파일은 JSON 값 대신 두 번째 프로세스 자신의 실제 실행 파일과 대조한다. 같은 앱 실행 파일을 사용하는 서로 다른 프로세스의 data_root/mutex 소유권까지는 이 검사만으로 구분하지 못한다.
ctypes의 창 활성화·안내·위치 보정은 runtime_instance_win32 한 모듈을 거친다. 호스트 시험은 autouse 기록 대역과 user32 호출 거절 막이를 함께 쓰며, 실제 전경·초점 동작은 A9 회차 몫이다. 수동 현장 qualification의 pywin32 driver는 호스트에서 실행하지 않는다.

앱 소유 Python 원자 바꿈은 atomic_replace 한 모듈에서 WinError 5/32만 총 1.5초 안에 다시 시도한다. 지속 거절은 첫 예외를 그대로 전파하며 준비 파일·읽는 쪽·호출자의 writer admission은 유지한다. C1 제어 JSON은 write-through(REPLACE_EXISTING|WRITE_THROUGH)를 유지하고 C2 준비 파일도 같은 경계를 쓴다. PowerShell의 대응 경계는 bootstrap_integrity의 Invoke-ContainerAtomicReplace이며 Replace backup·CreateNew의 덮어쓰기 거절·write-through 의미를 유지한다. fence의 cold import는 고정 SHA와 확인한 bootstrap 바이트만 평가하며 이미 검증된 함수는 재적재하지 않는다.
바이트 고정 공용·셸의 기존 원자 바꿈은 정본 주인 후속이다. 지킴 시험은 data_generation.py·powershell/data_generation.ps1·raster.py·diagnostic_log.py·shell_fileio.py 다섯 정확한 경로와 SHA만 제외하며 새 직접 바꿈이나 제외 파일 변경을 거절한다. 공용 바이트 일치·writer gate·consumer 단언과 버전 디렉터리 rename은 그대로 유지한다.
첫 거절 뒤에는 native 호출 전에 기한을 다시 확인하며, relay/app 종료의 게시와 대기는 한 기한을 공유한다. PS는 native HRESULT 5/32만 다시 시도한다. 배포 사본의 새 시작·게시 모듈과 `-I` 자식을 집중 시험으로 확인한다.

비상 바로 가기는 InstallRoot(current)의 부모인 앱 폴더의 `관리용\이적 옛 화면 (비상).lnk`에 둔다. 기존 작업자 바로 가기와 대상·작업 폴더·아이콘이 같고 인수는 `--ui tk`이다. 설치·재설치·업데이트의 기존 바로 가기 흐름에서 생성 또는 readback 확인하며, 제거 때 소유 링크와 빈 관리용 폴더만 지운다. 같은 이름의 남의 링크나 다른 파일이 있는 관리용 폴더는 손대지 않고 경고 한 줄을 남긴다. current의 코드 목록·무결성 범위와 예외 규칙은 바뀌지 않는다.
비상 링크·빈 관리용 폴더의 IO 삭제 실패는 일반 링크·pending 제거를 마친 뒤 원 예외로 보고한다. 검증된 기계 제거 부모가 이 독립 단계를 맡으며 단독·거래 복구 helper는 자체 정리를 유지한다. 코드·증거 쓰기와 guard 실패는 계속 즉시 전파하고 전체 PASS로 바꾸지 않는다.

업무·사용자 relay·업데이트 내려받기의 기본 자료 자리는 LOCALAPPDATA다. 사용자 실행은 ProgramData 전체(뿌리·KMTech·다른 형제·명시 relay 경로)에 디렉터리나 조상을 만들지 않는다. OS known folder를 기준으로 기존 부모의 최종 경로를 해석해 대소문자·8.3·정션·확장 경로 접두사를 정규화한다. 환경 매핑은 해석된 거절 경계를 더할 수 있을 뿐 OS 경계를 좁히지 않는다. 필요한 디렉터리가 없거나 known folder를 확인하지 못하면 `MACHINE_RUNTIME_DIRECTORY_NOT_PREPARED`와 관리자 설치를 먼저 완료하라는 안내로 거절한다. 기계 설치기가 owner·ACL을 정해 준비한 디렉터리는 mkdir·owner·ACL 변경 없이 사용한다. 이미 잘못된 owner·ACL의 회복은 이 거절 길이 맡지 않으며 기존 설치 보호 검사는 유지한다.


현재 사본은 승인된 READY `a8183b66`의 v3.16.3이며 19파일과 READY의 바이트를 대조한다. 어댑터는 `web_allowed`에도 쓰기 guard를 명시하며 셸의 private FileIO가 각 쓰기에 같은 허가를 얻는다. 실제 셸 코드의 시작 실패·수동 재시작·worker 종료 대기는 창과 OS 경계만 대체해 시험한다. 실제 창 하나·설치·현장 확인은 별도다. 최종 UI a1b37ce2을 적용했다. v2.0.106은 writer inventory 검사 실패로 소모했고 v2.0.107은 한 번 빌드해 수용되었다. v2.0.108은 A9 결과와 별도 지시 전까지 빌드하지 않는다. 실패 뒤 같은 번호로 다시 빌드하지 않는다.

디렉터리 준비 helper는 바탕 b82의 mkdir 33자리를 그대로 대신한다. inventory는 helper의 디렉터리 전용 AST와 정확한 호출자·인수·admission/probe 분류를 검증하고 각 준비 효과를 호출자에게 돌린다. 부트스트랩 전 준비 1자리는 새 writer admission 없이 유지하며 업무 파일 쓰기에는 이 분류를 적용하지 않는다. release의 실제 writer inventory 검사를 빌드 전에 별도로 통과시킨다.

새 화면 등록은 원장 등록 함수를 직접 호출하며 기존 Tk 등록 창을 열지 않는다. 관리자 PIN·내부 시험 품목 입력의 기존 Tk 모달은 인스턴스 어댑터가 대체한다. 빈 관리자 ID/PIN은 실행 전에 거절하고 사용한 인증의 재입력이 필요하면 웹 경고로 돌려준다. 앱 동작 결과는 명시 True/ok만 성공이며 False·오류 글·거절 알림은 실패, None은 결과 모름이다. 재전송도 이 결과를 그대로 반환하고 완료로 덮지 않는다. 옛 화면의 Tk 모달 구현은 유지한다.
숨긴 Tk 단추는 Python 콜백을 감싸 반환값을 Tcl 변환 전에 보존한다. invoke 반환은 성공 판정에 쓰지 않는다. 매번 실행 여부와 값을 비우고 읽으며 콜백 미실행은 모름이다. 다섯 웹 연결 단추의 최초 바인딩과 제출↔재시도의 명령 갱신도 같은 캡처를 사용한다. 옛 Tk가 받는 원래 콜백 반환은 그대로다. SPEC 18:30의 실제 Tk 경계 회귀는 즉시 withdraw한 뿌리 하나에서만 실행하며 보이는 창·모달은 0이다.


새 화면 보류 목록은 기존 작업자 신원 규칙으로 일반 보류와 사전조회 격리·서버 확인 대기를 읽는다. 격리·대기는 `kind`, `restorable:false`, 품목·현품표 번호·수량의 `label`, 고정 안내의 `note`를 전달하며 복원 명령을 받아도 일반 복원으로 넘기지 않는다. held_count는 실제 전체 건수이고 목록만 50줄로 제한한다. overflow로 넘침을 표시하고 격리·대기 줄에 먼저 자리를 주며 각 종류가 전부 빠지지 않게 한다. 넘친 일반 목록은 옛 화면에서 확인한다. 등록 때 동명이 있으면 현재 명단의 UUID·표시 이름을 후보로 보내고, 선택 직전에 다시 대조해 기존 등록 함수를 부른다. 다른 사람은 구분 이름으로 새로 등록한다. 명단 저장·승인·전송 계약은 그대로다.

새 화면 portable 패킷은 `ca_screen_bridge.py`, `shell/`, `ui/`와 검사 앱 `dceb851d`의 같은 pywebview 6.2.1 의존성을 싣는다. 빌드는 `requirements-portable-build-win-py312.lock`의 정확한 15분포 환경을 요구한다. 셸 v3.16.3 READY SHA256은 `a8183b660932778c08ebdf1ee24f137b4c2540a66207850afeff9990bbfb3198`이다. 배포 경로 이름 `SHELL-READY-v3.16.json`은 유지하고 승인된 v3.16.3 READY를 그대로 담는다. READY의 shell-v3.16.3 접두부만 설치된 shell/ 경로로 매핑하며 원문과 19파일을 바꾸지 않는다. UI는 최종 `a1b37ce25a28f4147f15b3e58b4cc900c8be6f97`에서 정본 exporter로 내보낸 86파일과 MANIFEST를 그대로 적용했다. 86파일 모두 committed 바이트와 대조했다. 매니페스트 원천 SHA·`dirty=false`·파일별 해시·부품 지문을 대조한다. 이 UI 사본에는 별도 로컬 수정을 하지 않는다.

앱 native는 검사와 바이트가 같은 여섯 파일만 허용한다. unsigned 예외는 `_cffi_backend.cp312-win_amd64.pyd`, amd64 `ClrLoader.dll`, `Python.Runtime.dll` 세 개이며 WebView2 Core·WinForms·x64 Loader DLL은 서명 검증 대상이다. 두 설치기의 패킷·설치본 및 자동 업데이트 helper의 manifest 판독은 unsigned 목록이 빈 옛 판 또는 정확히 이 세 경로·SHA인 경우만 받는다. 빌더는 앱 PE 전체 크기·SHA·파일 집합과 설치기·업데이트 helper/빌더/실제 패킷 unsigned pin을 대조하며 빠짐·추가·바이트 변경을 거절한다. 다른 아키텍처 및 WebBrowserInterop 변형은 복사하지 않는다. 패킷의 `--new-screen`, writer guard, 「그래도 닫기」와 기본 `on_force_exit=None` 연결은 AST/바이트로 확인한다. 호스트에서는 실제 창을 띄우지 않고 현장 PC에서 창 동작을 확인한다.

기본 새 화면 이음(`Container_Audit.py`, `--new-screen`은 같은 뜻)은 고정 셸 v3.16.3의 지역 쓰기를 `shell/shell_fileio.py` 한 곳으로 모으고, 각 쓰기 동안 기존 이적 `writer_admission("screen_shell_fileio")`을 얻는다. 진단·셸 접수 캐시 쓰기 거절은 화면과 다음 스캔을 중단하지 않으며 진단 누락 수는 `events_dropped`로 전달한다. 시작용 journal/UDF 폴더 생성이 거절되면 창을 만들기 전에 실패한다. 쓰기 선언은 사본 해시와 실제 담장 설치를 함께 확인한다([이음 계약](../ca_screen_bridge.md)). 실제 창·현장 PC 동작은 별도 확인 범위다.
새 화면 창 X의 답이 늦으면 창을 유지하고 끝내는 중 띠를 보여 준다. 120초 뒤 더 기다리기 또는 그래도 닫기를 고르며, 그래도 닫기에는 저장 중인 것을 잃을 수 있다는 경고를 표시한다. 앱의 별도 스레드용 비상 마무리는 연결하지 않았다. 기존 앱 작업 배수에는 전체 종료 상한이 없으므로 셸의 120초와 구분한다([이음 계약](../ca_screen_bridge.md)).

종료 시 CSV 배경 투영은 1초씩 최대 세 번 기다리고 화면을 닫는다. 예산에 남은 내구 outbox와 checkpoint 감사는 그대로 보존하며 다음 실행에서 원 키·순서로 재생한다. 아직 outbox 원본 저장에 실패한 메모리 감사가 있으면 기존 저장 재시도와 종료 차단을 유지한다. 끊김 복구에서 손상 CSV 꼬리를 제거할 때는 내용 없이 바이트 수와 고정 사유 코드만 기록한다.

CSV append 중 프로세스가 종료되어 남은 잠금은 다음 투영의 경합에서 PID·생성 시각을 확인해 즉시 회수한다. 생성 시각이 일치하는 살아 있는 owner는 잠금 나이와 무관하게 보존한다. 조회 불가 owner·살아 있는 PID-only 옛 형식·읽을 수 없는 기록은 기존 mtime 300초 유예 뒤 회수한다.

canonical 부모는 상승 direct/wrapper helper의 보호 원본 receipt와 restore evidence를 그 실행의
bound evidence root·journal SHA로 읽는다. 일반 caller 사본의 존재를 요구하지 않는다.
startup preimage 두 필드는 한 쌍으로 검증하며 원 preimage.json의 SHA가 같아야 한다.
PS5.1/7 실제 소비자·기존 export/startup 34 PASS, 랩 G 기록은 보존하고 native 복구는 별도 판정이다.

일반 설치는 authority 인계 전에 코드/runtime 변경을 시작하지 않는다. helper가
같은 tuple을 인수한 뒤 배치와 onboarding 결과를 기다리고, 필요한 보상과 readback,
마지막 fence 해제를 맡는다. 기본 launcher는 RunAs이며 이미 상승된 관리자 셸·SSH
토큰에서는 직접 실행한다. 실패 시 두 번째 RunAs로 복구하지 않는다. 승인 횟수는
factory/noncanonical 전용 launcher 주입점 하나에서 계측한다. 수동 지원 복구는
기존 경로를 사용한다.

handover/ready와 결과는 보호된 보통 파일의 SHA, 준비 receipt, 부모 PID·생성 시각과
같은 거래 ID를 확인한다. 원 operator SID만 mutex를 관측할 최소 Synchronize/Modify
권한을 받는다. Modify는 기존 unowned 관측의 ReleaseMutex 반환에 필요하며 소유권은
이동하지 않는다. helper가 사라졌거나 코드·G·Run·writer·전역 relay 복원이 미확인이면
fence를 보존하고 관리자 지원 복구로 나간다. 격리 HKCU 시험 결과는 실제 HKCU/랩
VM 수용 결과와 따로 기록한다.

확정 전 fresh 제거는 보호 handover의 helper PID·생성 시각·명령 SHA를 실제 직계
부모와 대조한 뒤 이번 current의 기록된 파일만 이동한다. 조상 불일치는 파일
변경 전에 거절한다. 이 attempt의 startup preimage만 복원하고 readback하며,
공식 legacy 예약 writer와 다른 버전·설치의 파일은 이 제거 경로에서 변경하지 않는다.

설치와 되돌리기의 resident relay READY 대기는 같은 기본 360초(상한 600초)를 쓴다.
G 요청부터 첫 기록된 READY까지 275.561초라는 관측 상한에 84.439초 여유를 더했다.
시간 초과는 되돌리기의 나머지 기록·끝 상태 저장을 계속하되 실패를 유지한다.
끝의 한국어 한 줄은 코드·Run·시작 작업과 미확인 relay를 구별하며 종료 코드는 0이 아니다.
PS5.1/7 실행 회귀 RED4→GREEN4; 새 native 설치·재진입 수용과 구별한다.

명시·기본 TLS CA, 보호 관리자 profile, replacement/retirement receipt, task 암호 파일,
등록 2PC journal과 qualification context도 실제 선택한 입력 경로의 parent를 최초 G에 포함한다.
TLS/관리자 등 읽기 전용 보안 입력은 probe만 하며 그 폴더에 새 세대 기록을 만들지 않는다.
onboarding은 선택 CA를 등록 runner에도 전달하고 GUI는 승인한 관리자 profile을 인증 reader에
전달한다. PowerShell의 외부 입력은 FileSystem 현재 위치에서 한 번 Full로 해석한 값을
G와 reader가 공유하며 초기 검사는 report/placement ownership/INSTALLING보다 앞에 둔다.
기존 plan-only/dry-run probe와 공용 G/helper/신원 계약은 유지한다. 실제 검증 범위와 실패는
[외부 입력 교정](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-263/REPORT.md)에 기록한다.

기존 credential은 locator parent를 먼저 검사한 뒤 JSON을 한 번 읽고, 실제 secret owner,
TLS CA와 qualification context를 같은 snapshot으로 검사한다. 정상 locator의 하위 경로를
해석할 수 없으면 UNKNOWN으로 끝내며 report를 쓰지 않는다. 깨진 JSON·중복 키는 경로
판정 실패로 바꾸지 않고, 승인된 report owner에 기존 BLOCKED 진단을 남긴다.
Canonical의 첫 일반 G 거절은 fence·mutated 표시 앞에서 끝나므로 removal/Run/relay를
호출하지 않는다. Canonical 설치는 변경 전에 `--onboard-current-user --preflight-only`로
locator와 nested owner를 기존 Python reader로 검사한다. 보안 입력이나 설치 상태를 쓰지
않으며, 결과 digest를 실제 onboarding의 `--expected-input-binding`으로 넘겨 같은 입력인지
최초 기록 전에 비교한다. 깨진 locator·중복 키는 기존 credential BLOCKED 오류 코드로
종료한다. old-target rollback G는 유지하며 실제 native 설치·복원은 아직 NOT TESTED다.
새 stock의 설치 전 preflight는 기존 Get-CodeInventory/Get-InventoryAggregate SHA를
`--installer-source-inventory-sha256`으로 결속한다. source에 설치 후 bootstrap 기록을
만들지 않는다. placement 전 Python admission 실패는 `install_status=FAILED`,
audit `status=FAILED`·`preparation_status=FAILED_PREPARATION_ADMISSION`으로 끝난다.
공개 예외·preparation_failure.code는 고정 준비 실패 코드이며 배치·Run·relay를 시작하지 않는다.
기본 bootstrap CA는 사용자/자료 bootstrap 폴더의 파일이다. source와 install의 app root가
달라도 같은 절대 경로·SHA256을 비교하며, CA 변경은 최초 onboarding 기록 전에 거절한다.
`RestoreVerifiedReplacement`는 fence 전에 old rollback tree(이미 복원됐으면 설치 tree)를
`--target-release-root`로 정확 검증하고 locator와 nested owner에 old version/build G를
적용한다. 같은 digest를 quiescence 직전과 old relay 재시작 직전에 대조한다. 이 경로는
첫 현장 설치 경로와 별도인 지원 복원이며, 사전 거절의 transient authority mutex는
기존 finally에서 놓는다.
preflight는 기존 exact reader의 코드/manifest 검증만 사용한다(ACL 필드를 만들지 않음).
같은 digest의 코드 부분을 실제 ACL 검증 복원 결과와 초기·quiescence 직전·relay 시작
직전에 대조한다. 일반 reader API의 `acl_identity_reader=None`은 거절한다.

일반 rollback의 한 removal 실패는 나머지 code/Run/task 복원 시도를 막지 않는다.
배치 전에 current가 없었고 실패 뒤에도 없으며 current의 Run·relay preimage가 없으면
current G·onboarding reader는 `NOT_APPLICABLE_NO_CURRENT`로 기록한다. 없는 앱 부모는
재생성하거나 다시 상승하지 않는다. 존재하는 부모의 보호 복구는 설치된 current가 없을 때
인증된 source inventory·원 fence·prepared receipt로만 결속하며, current가 있으면 manifest를 요구한다.
이 경우 정확한 Run/task 복원과 fence 해제 뒤 `FAILED_ROLLED_BACK` 실패 감사를 남기므로
바깥 옛 설치 복구가 원 폴더를 되돌릴 수 있다. 배치된 새 코드는 기존 G 검사를 유지한다.
원래 있던 current의 소실·복원 미확인은 이 예외로 통과시키지 않는다.
code·G·HKCU Run·예약 작업의 정확 복원 readback이 모두 검증된 경우에만 fence를 해제하고 옛 relay를 재시작한다. Run/task 복원 실패는 recovery identity를 무효화하며 fence와 지원 복구 기록을 유지한다. 예약 작업 복원은 `Enable-CanonicalWriter`의 증명 객체를 보존하고 그 안의 `readback`을 원 preimage와 대조한다. 작업이 없던 경우에는 복원 단계를 실행하지 않는다.
G·quiescence를 다시 확인하고 기존 exact 복원 evidence로 code를 증명한다. 정확 code와
relay preimage가 증명되면 finally fence 해제·relay 재시작을 시도하고 각 실패를 보존한다.
불일치면 fence를 유지하며 자료·확인 기록 보존과 관리자 지원 복구를 안내한다.
별도 uninstall/retirement 및 refence 이전 실패 경로는 기존 안전 계약을 유지한다.

직접 등록(검증·2PC 복구 포함), relay 운영 명령, 사용자 profile 설치/확인,
앱의 active-work wrapper·review report, lifecycle 복구·제거도 기존 admission 아래
최초 신원/자료 판독 전에 G를 검사한다. 온보딩은 G 뒤에 attempt와 디렉터리를 만든다.
G와 실제 판독은 동일한 빈 값/env/default 및 expanduser·상대 경로·대소문자·링크 해석을
사용한다. 외부 owner 경로도 모두 먼저 probe하고 허용 뒤에만 marker를 기록한다.
profile dry-run은 probe만 수행하여 외부 폴더·marker를 만들지 않는다. owner root의
일반 파일 조상 때문에 자료·marker가 존재할 수 없을 때만 그 외부 root를 기록 없음으로
처리하고 기존 loader의 오류 안내를 유지한다. 다른 parent marker를 대신 읽지 않으며
reparse 조상으로 존재 불가를 확정할 수 없는 경로는 UNKNOWN으로 거절한다.
resident 시작과 scheduled-task install pack은 먼저 읽기 전용 G 판단을 하며,
REFUSE/UNKNOWN은 한국어 안내만 내고 기존 report·relay·Run·예약 작업 상태를 보존한다.
공용 독립 frozen active-work probe는 별도 도구 신원 계약으로 이 앱 판 검사 범위 밖이다.
ea566d1에서 이 교정 후보로의 설치 전진은 앱 전용 G 전환 선언의 정확한 코드 파일
before/after hash와 resident/raw 두 route의 지정 G 변화로만 허용한다. 기존 writer
의미 비교는 유지하며 다른 sink/guard/route, 파일 변경·추가, 역전환은 예외가 아니다.
조립 판의 다른 writer 변화는 기존 exact release-pair 경로에 전체 설치 preimage를 AND로
결속한다. `installed_release_preimages`는 실제 설치된 EA 계보·TEST1 v2.0.99/8928228의
commit·inventory와 stock G source 21개 이름·실제 배포 바이트 SHA(또는 정확 부재)를
한 release 전체로 비교한다. 파일마다 release를 섞거나 같은 판의 다른 build를 쓰는 것은
거절한다. data_generation_guard.py 부재는 8928228의 정확 부재에만 해당한다.
scalar EA before·resident/raw 2-route predicate·기존 files 871 경계는 그대로이며
새 OR·wildcard·G 역전환은 없다. 배포되지 않는 개발 도구 6개는 committed LF hash를
G-PAIR-DIFF에 따로 남기고, files 표 또는 stock zip에 들어오면 범위 회귀가 실패한다.
검증된 replacement receipt의 기존 정확 복원 policy는 별도 경로로 유지한다.
검증 버전·실제 subprocess 결과·제외와 한계는
[G 직접 입구 교정](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-233/REPORT.md)에 기록한다.

지원 packet에 설치용 bootstrap 기록이 없는 사용자 정리는 `--app-root` 설치 packet의 실제 bootstrap inventory와 실행 packet 전체 bytes가 같은 경우에만 진행한다. 매일 업데이트 뒤 current가 A이고 활성 판이 B이면 완전한 policy·pointer·transition과 B의 bootstrap·build·신뢰 키를 확인하여 B inventory와 지원 packet을 대조한다. 옛 A packet·부분 기록·위조·대조 중 변경은 정리 전에 거절한다. 작업자 세션 재설치의 후보 배치 전 제거는 활성 B host를 실행하며 자료 판은 B로 검사한다. 고정 업데이트 helper·작업은 교체하지 않는다. source에 bootstrap 기록을 만들지 않으며 자료 세대 marker를 쓰지 않는다. TEST1 실제 되돌림 수용은 별도다.

자료 세대 보호 helper `kmtech_shared/data_generation.py`와
`kmtech_shared/powershell/data_generation.ps1`은 사용자 자료를 열었던 가장 새 판과
서명 검증된 최소 호환 판을 기록한다. 기록 없음은 ALLOW, 손상·읽기 실패·판 비교
불가·같은 판 다른 build(서명된 명시 호환 없음)는 UNKNOWN 거절이다. 원자 기록 뒤 readback을 확인하며 Python 3.12.10·PS5.1·PS7 새 helper 묶음31 PASS(기존 모듈+RED 재현+host guard)는
helper 근거다. **CA 실제 입구 관련52 PASS, native 자료 사용 뒤 복원 거절 PASS**이며 GUI/relay/onboarding
3곳과 코드 restore/reinstall 7곳에 호출을 연결했다. shared 선언 확대는
허용되었다. G-DECISIONS대로 실제 자료를 처음 여는 경계의 기존 admission 아래에서
자료 root와 기존 control root/SID에 기록하며 launch 직전에 미리 기록하지 않는다.
GUI는 singleton 확인/온보딩 코드 검증 뒤 catalog 자료 직전, onboarding은 코드
무결성 검증 뒤 실제 상태 검사 직전, relay는 raw runner의 첫 queue/profile IO 직전에 기록한다.
resident supervisor는 자료 세대를 기록하지 않고 시작 전 읽기 전용 G 판단과 child의 고정 거절 안내를 사용한다.
자료 root override가 기존 admission control root를 옮기지 않으며 중복 GUI·코드 검증
실패·cycle에 도달하지 않은 relay는 새 기록을 남기지 않는다. portable Python entrypoint를
기존 exact bootstrap inventory로 검증하고 frozen 기본 EXE 검증은 유지한다.
새 `data_generation_marker` sink 하나와 shared leaf의 exact caller 선언을 표준 생성기에
반영했다. raw relay의 명시 queue root가 GUI와 달라도 기존 SID control marker를 함께
써 설치기 probe가 관측한다. source는 clean commit, portable은 기존 bootstrap 코드
검증+version/commit 결속, frozen은 기존 factory package verifier로 build를 확인한다.
기존 d55cc94 집중 시험은308 PASS/2 FAIL이다. 두 실패는 실제 온보딩으로 자료를 연 뒤
다른 옛 build로 복원을 허용하던 기대이며 G 결정과 충돌하여 코디 판단을 기다린다.
새 기준82ce91c 자체의 표준 `--check`는 변경 전 깨끗한 독립 사본에서 PASS였다.
G 변경을 그 기준 위로 옮긴 뒤 표준 `--write`→기존 consumer pin3곳 결속→`--check`가
PASS이며 Python sink216/cross-language217, uncovered/caller 실패/신뢰 예외0이다.
종료 정리 변경을 포함한 새 기준의 집중 비교 근거는 아래 작업 보고서에 기록한다.
새 adapter는 stock builder의 고정 app 목록에도 포함하고 실제 복사 회귀로 검증한다.
builder는 새 metadata helper 사용 전에 기존 공용 pin 검사를 끝낸다. 독립 checker
시험 사본에는 기존 conftest의 lock guard dependency도 함께 복사하여 guard를 유지한다.
명시 호환으로 허용된 같은 판의 다른 build가 자료를 쓰면 marker에 새 build를 기록하고
두 선언의 더 엄격한 하한/신뢰 교집합을 유지한다. 이전 build의 넓은 호환을 그대로
물려주지 않는다. 같은 build와 더 높은 기존 판의 바이트 보존은 유지한다.
[API·현재 한계](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-219/HELPER-READY.md).
[새 기준 검증](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-219/REPORT.md).

출시 때 stock builder는 실제 `CURRENT_VERSION`에서 portable manifest의 `version`을
만들고 `--data-compatible-min-version` 입력을 받는다(누락은 자기 판). 출시 담당자는
자료 의미·독자/복구 호환을 확인한 가장 낮은 판을 private update manifest의
`data_compatible_min_version`에 **기존 ES256 서명 전**에 넣는다. 호환 근거가 없으면
자기 판이다. 이 필드는 canonical manifest bytes 전체의 기존 서명에 포함한다.
`verified_data_compatibility_from_manifest`로 기존 서명·앱/판/floor를 검증한 결과만
명시 호환 필드가 있을 때만 기록 helper의 `compatibility_verified=True`로 전달한다.
기록과 대상의 검증된 commit/서명 manifest hash도 전달하고, 모든 marker를 probe한 뒤
자료를 연다. G 이전 빌드가 marker 없이 연 자료는 보호되지 않는다. unsigned portable manifest의
floor나 CPython Authenticode만으로 호환을 허가하지 않는다. portable 빌더의 선택 인수
`--data-generation-update-manifest`·`--data-generation-update-signature`는 함께 주며,
기존 ES256 서명·앱·실행 판·source_commit·하한을 검증한 선언과 64바이트 서명을
`data_generation_signed_manifest`·`data_generation_signature_hex`로 내장한다.
서명된 하한은 `--data-compatible-min-version`의 unsigned 값보다 우선한다.
인수가 없으면 기존 metadata 바이트를 유지한다. 런타임은 전체 코드 무결성 확인 뒤
설치본의 공개키 설정으로 같은 증명을 검증하고 기존 warmup/cache에 포함한다.
증명 누락·검증 실패·키 부재는 자기 판 하한이며 이미 같은 판/build로 기록한 marker는
뒤늦게 낮추지 않는다. 옛 portable reader는 추가 필드를 무시하고 기존 판/commit을 읽는다.
암호 API의 RuntimeError 등 증명 계산 오류도 자기 판/미검증으로 캐시하고 예외 원문 없이 한 줄 진단한다. 증명은 복귀 권한을 더하므로 실패가 기존 업무 시작을 막지 않는다. 설치기 onboarding도 첫 writer 허가 전에 warmup을 수행한다. 실제 onboarding의 증명 검증 깊이 0과 G 기록, artifact/archive/install/rollout을 포함한 시험 feed의 빌더→공식 bootstrap 크기·비밀 검사→runtime 결속을 좁은 시험으로 확인한다. packaging 복사/import 단계를 고정한 시험이며 전체 출시 packet 수용은 별도다.
하한을 낮추기 전에는 옛 판이 새 업무 자료와 소유·신원 파일을 읽는지 확인해야 한다.
signed floor 변조/서명 없음·미래 floor 거절과 builder
기본값을 포함한 관련 3파일 101 PASS(격리 소스), 실제 출시 서명 발행/stock은 미검증이다.

보호 helper가 writer admission을 보유한 동안의 설치 수명주기 판독은 기존 byte-pinned
PowerShell reader를 같은 스레드에서 호출한다. Python 자식의 같은 mutex 재획득을 피하며
잔여 control·owned task·조회 UNKNOWN의 거절은 유지한다. 실패 분류는 기존 감사 이벤트와
`installation_failure_summary.lifecycle_context_failure`에 남긴다. 외부 JSON은 UTF-8 64KiB
이내에서 읽고 알려진 status/type/reason만 기록한다. 경로·원 예외 문구·자식 stream은
추가하지 않으며 손상/초과 출력은 `CONTEXT_OUTPUT_UNKNOWN`으로 남기고 기존 안내로 거절한다.
제어 기록(policy·active·transition)은 있고 StartupUpdate 작업을 내보내지 못하면(없음·조회 실패) PowerShell reader도
Python reader와 같은 `lifecycle_task_absence_or_unknown` 원인으로 거절한다. 공개 안내·거절은 그대로이며
끊긴 설치를 이 원인만으로 버려진 설치 복구나 새 설치로 바꾸지 않는다(IA-02).

옛 v2.0.33 위 첫 현장 설치는 업무 종료 뒤에 진행한다. 옛 GUI·relay·writer의 정상
정지/ABSENT를 확인한 뒤 exact 옛 코드, 전체 실제 data/DirectSync root와 외부 신원 상태,
자동시작 및 세대 marker/control preimage를 같은 시점에 백업하고 바이트를 대조한다.
백업 뒤 업무·중앙 요청/ACK 변화 0을 확인하기 전에는 되감기 복구를 선택하지 않는다.
새 판 기동 뒤 실패는 기본 새 판 유지/수정판 복구이며, 관리자 수동 되감기는 옛 코드와
백업 자료·등록·marker preimage를 함께 복원하되 현재 유지보수 session/receipt 권한은 유지한다.
기존 control 폴더 전체를 덮어써 현재 권한을 되감지 않는다. 이후 업무가 있거나 상태 UNKNOWN이면
되감기하지 않는다. 구체 경로/지원 복구가 확정되지 않은 단계는 실행하지 않는다.
[첫 설치 runbook 초안·미검증 범위](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-219/CA-FIRST-FIELD-INSTALL-RUNBOOK.md).

시작·작업자 변경 화면에서 공용 명단의 ACTIVE 이름을 고른다. 이 PC에서 최근 성공적으로 시작한 사람이 먼저 보인다. 목록에 없으면 「새 이름 등록」에서 이름만 적고 이 PC 저장 뒤 바로 선택한다. 승인·PIN·숨김은 없다(stage_a=false). 번호는 화면에만 붙인다. 자세한 저장/재시도/동명 절차는 [이름 등록 B](worker-roster-b.md)를 따른다. 정상 빈 명단이나 캐시 부재 때는 기존 로컬 이름에서 한시 선택하고 기억한 이름으로 시작할 수 있다. 행이 있지만 모두 중지되었거나 이름 규칙을 통과하는 ACTIVE 행이 없으면 새 이름을 등록할 수 있다. 보호 관리자 로그인은 `관리자` 단추로 기존 코드를 확인한다. 설치 등록·장비 권한·관리자 개인 PIN은 기존 절차를 따른다.

연결이 끊겨도 마지막 정상 명단을 사용한다. 명단·캐시가 없으면 `명단을 받지 못해 이 PC에 저장된 이름을 씁니다` 안내와 기존 이름 목록을 표시하며 그 목록도 없으면 새 이름을 등록할 수 있다. 손상 캐시 원본은 사용자 config의 `.bad-*`에 보존하고 `roster.last-good.json`으로 복구한다. 조회는 시작·변경 때와 60초마다 배경에서 진행한다. 작업 중 중지를 확인해도 현재 현품표의 완료·보류·재전송·복구는 유지하고 다음 신규 현품표에서 다시 고른다.

명단 이름 정정 뒤에도 진행 중·보류 묶음은 시작 때 이름을 유지한다. 같은 명단 번호로 로그인하면 정정 전 보류를 찾고 복구할 수 있으며 파일을 새 이름으로 옮기지 않는다. 다음 신규 묶음은 최신 이름을 사용한다. 명단 없는 한시 선택은 번호 없이 저장한다. 신원 전송 기능의 켬·끔·조회 실패는 기존 사건의 재전송 자료를 바꾸지 않는다. 보류 제품의 감사 저장 뒤 목록 ACK가 실패해도 재시작·재확인은 같은 감사 행과 처음 저장한 신원을 쓰며 새 작업자 정보로 바꾸지 않는다.

웹 명단 이름은 정규화 뒤 64자까지이며 한 글자·두 글자·외국 이름을 받는다. 경로 문자 `\ / : * ? " < > |`, 맨 앞의 `= + - @`, 빈값·Cc/Cf/Cs/Zl/Zp는 거부한다. 앱은 해당 행만 제외하고 정상 행과 원본 행 수를 유지한다. 기존 PC의 무번호 로컬 이름은 기준 규칙으로 한시 선택하며, 긴 이름의 기존 완료 CSV 경로·금일 집계를 유지하고 해시 경로로 옮기지 않는다.

중앙 응답을 기다리는 동안에도 제품 입력과 로컬 내구 저장은 진행한다. 등록 main·온보딩·시작·운영자 복구는 HTTP 밖으로 admission을 나누고 로컬 적용만 다시 입장한다. 원격 시작은 활성 writer fence에서 거절하며, 응답 뒤 배포 fence가 생겼으면 로컬 적용도 다시 거절하고 원 intent/원본을 유지한다. 지원되지 않는 중첩 writer admission의 원격 호출도 전송 전에 거절한다. 품목 cache와 원본 복구 대상이 대기 중 바뀌면 늦은 응답으로 덮어쓰지 않는다.

시험의 공통 lock/HTTP 장치는 native writer mutex·thread lock·SQLite transaction과 주입 HTTP client를 등록한다. import 때 생성된 앱 객체의 잠금·connection도 같은 실제 자원을 감싸며, 의도적인 부정 시험 외 잠금 중 HTTP는 실패한다. lease 해제의 중복 작업 예약은 짧은 lock에서 하고 전송은 예약 lock 밖에서 한다.

`대기 건수 확인 불가(읽기 실패)`는 이 PC의 relay 상태 읽기 문제다. 마지막 확인 대기 수와 성공 ACK 시각을 유지하며 서버 연결 표시와 구별한다. 카드·운영 메뉴의 상세에서도 이전 읽기 값이 없으면 미확인, 있으면 마지막 확인값·확인 시각과 읽기 실패를 보인다. 정상 읽기가 복구되면 새 실제 값으로 바뀐다.

`진행 현황`은 보기 전용 별도 화면이며 `작업 화면` 단추 또는 스캔으로 돌아간다. 조회가 느려도 작업 스캔은 계속한다. `연결 끊김`이면 마지막 수신 값과 시각을 보여 주며 다음 60초 갱신에서 재조회한다.

`저장 전송` 카드의 `서버 연결: 정상/끊김`은 물류 응답의 관측이며 관측 전에는 `확인 중`이다. 정상 성공 응답을 검증하기 전에는 앞선 끊김을 유지한다. redirect·인증 거절·충돌·receipt 없음만으로 정상으로 바뀌지 않는다. 마지막 성공 전송과 `보낼 것 N건`(사건 큐+미수락 완료)을 함께 본다. 성공음 뒤 더 긴 완료음은 로컬 내구 완료이고 중앙 ACK 여부는 기존 전송 표시로 구별한다. 오류는 반복음이며 다음 정상 입력 또는 안내 확인으로 멈춘다.

스캐너 경고는 다음 스캔이나 Enter로 닫으며 닫는 스캔도 처리한다. 마지막 제품 저장·완료 중 들어온 스캔은 순서대로 다음 트레이에 전달한다. 복구·인수 선택 중 스캔하면 원 작업을 내구 보류한 뒤 그 입력을 처리한다. 전환 선택 중에는 현재 작업을 유지한다. 다른 작업자 보류는 원본 그대로 두고 다른 현품표를 받으며, 해당 현품표의 인수·격리만 관리자 PIN 절차를 따른다. 교환 감사 CSV 재시도 중에는 이미 저장한 대체품과 후속 스캔을 유지하고, 저장된 intent 키로 재투영한다.

미달 확정 뒤 잠금·절전에서 돌아오면 확정 시각부터 60초가 지났는지 1초 주기로 확인한다. 지났으면 다음 현품표 없이 기존 완료를 한 번 전송하고 UNDO는 창 안 만료 안내·오류음으로 거절한다. 30초에 돌아오면 남은 약 30초를 기다린다. 시계가 뒤로 바뀌면 `SHORT_CONFIRMATION_CLOCK_REGRESSION`을 기록하고 이전 관측 시각을 따라잡을 때까지 전송을 보류한다. 스캔·저장 중에는 기존 lane이 끝난 뒤 같은 완료를 전송한다.

보류된 현품표·묶음은 누가 로그인하든 관리자가 해소할 때까지 변경·봉인·교환 전송을 기다린다. 작업자 선택·세션 저장 실패·작업자 변경·활성화/복원 감사 실패 뒤에는 이미 예약되거나 진행 중인 전송도 HTTP 직전 결속·보류를 다시 확인하고 내구 대기로 남는다. 원본을 지우거나 다시 스캔해 전송을 만들지 않는다. 보류 해소 뒤 작업 시작을 저장하면 원 intent와 키로 재개하며, 다른 현품표 작업은 계속한다.

선택이 열린 뒤 저장된 감사가 늘어도 최신 원행을 함께 보류한다. 업무 상태가 달라졌거나 보류 저장이 실패하면 원본과 선택을 유지하며 미접수 안내 뒤 다시 복구한다.

일반 트레이 보류는 단추 한 번으로 parked 상태와 원 감사 outbox를 함께 저장하고 안내·소리로 알린다. CSV 저장 실패에도 보류를 유지하고 다른 현품표 작업을 계속한다. 원행은 즉시 재시도·다음 스캔 전·기동에서 원 ID·시각·작업자·파일로 재생하며 중복 행을 만들지 않는다. UNDO/reset도 checkpoint가 성공하면 유지하며, 미달 취소는 확정과 취소 두 감사를 보존한다. 다음 현품표 스캔 전 `KMCMD:UNDO`는 기존 보류 복원 outbox로 방금 보류한 작업을 복원한다. 다음 현품표 뒤에는 그 보류를 자동 복원하지 않는다. 재시작 뒤에는 기존 보류 목록/현품표 복원을 사용한다. 관리자 preflight 격리의 권한·확인은 유지한다.

상태 저장이 지속 실패한 트레이는 같은 자료 위치의 저장 확인과 격리 기록 검증 후 「현재 작업 초기화」로 따로 보관한다. 완료로 표시하지 않으며, 원 파일과 `events/_storage_failures`의 미확정 snapshot은 그대로 둔다. 관리자 「두 원본 보류 목록」에서 확인하고 자동 재처리하지 않는다. 세션 journal 실패 뒤에는 작업자를 직접 골라 새 내구 세션으로 시작한다. 확인 쓰기·격리 저장 실패 또는 10분 내 네 번째 다른 건에서는 「이 PC 에 저장할 수 없습니다. 지금 트레이 실물을 그대로 두고 다른 작업대로 옮겨 계속하세요. 관리자에게 알리세요.」를 표시한다. 같은 건의 반복은 횟수를 늘리지 않고 밤을 넘겨도 원본과 관리자 확인 대기를 유지한다. 미확정 기록의 최종 대조·해소와 독립 저장 위치는 후속 범위다.

[제품·기능](README.md) · [데이터·통합 계약](contracts.md) · [백로그](BACKLOG.md) · [중앙 준비도](../../../Program_Spec_Hub/READINESS.md)

outbox 저장 실패 중 제품 UNDO 뒤 미달 완료·취소가 이어져도 먼저 저장한 감사는 미달 기록으로 인계·병합되어 재시작에서 원행으로 재생한다. 이전 판의 중첩 상태도 복구한다. 교환 checkpoint 재시도 사이에 기존 감사가 CSV에 반영된 경우는 업무 충돌로 표시하지 않으며, 복구 뒤 제품 입력을 계속한다. 다른 현품표·스캔·업무 상태가 바뀐 경우의 원본 보존과 확인 필요는 유지한다.

현재 S05 소스 단순화와 검증 범위는 [CA-O11](#ca-o11)을 따른다. 아래 과거 실행의
실패·증거·당시 gate는 보존 기록이며 새 SHA마다 반복할 실행 지시가 아니다.

기준일 2026-09-07. [README의 HEAD·수정 트리·기존 증거 경계](README.md#ca-evidence-scope)를 적용한다. 아래의 현재 동작은 인용 소스의 정적 확인이며 설치·장비·서버 실행 결과가 아니다. 이번 문서 작업의 실행은 **NOT TESTED**이고 과거 실행 결과는 중앙 준비도에 보존한다. 수용 항목은 현행 계약을 확인할 기준이며 미정인 운영 목표는 임의로 정하지 않는다.

<a id="ca-test-runner"></a>
## 저장소 시험 격리 (X14·E01·W6 H0)

`python -B tools/run_repository_tests.py <focused-test-node>`의 기본 run은
`D:\KMTech\t\ca\<8자리 무작위 run>`이며 basetemp는 `p`, TEMP/TMP는 `t`다.
`--task-root <부모 경로>`가 `CONTAINER_AUDIT_TEST_TASK_ROOT` 환경변수보다 우선하며
기존 `--work-root`도 같은 별칭이다. 소스 내부/소스를 포함하는 루트는 거부한다.
실행 전에 선택 root부터 실제 fixture leaf(11자리 임시 이름, writer release의
32자리 transaction/64자리 hash, bootstrap staging, standalone child pytest)까지
계산한다. 최장 후보가 UTF-16 240자를 넘으면 경로와 짧은 `--task-root D:\KMTech\t\ca`
사용법을 표시하고 디렉터리 생성/pytest 실행 전에 거부한다. 기본 후보는 218자다.
240자는 운영 여유값이며 모든 Windows API·임의 사용자 fixture의 장경로 보장이 아니다.
링크/junction·subst나 전역 extended-path 접두를 추가하지 않는다.
부모와 자식의 TEMP/TMP·AppData/ProgramData·데이터/설정 및 pytest basetemp·JUnit·로그를
같은 run 아래에 둔다. 테스트별 fixture는 ambient 데이터/profile override를 지우고
격리된 LOCALAPPDATA의 기본 업무/설정 경로를 사용하며 tempfile 캐시도 갱신한다.
CA writer mutex는 기존 fixture/sitecustomize의 경로별 시험 이름을 사용한다.
DI 전용 writer 환경변수는 CA에 적용하지 않는다.

기존 `owned_tk_workers`가 모든 시험에서 finally로 close/drain과 leak assertion을 수행한다.
`isolation.json`의 thread·경계 밖 쓰기 수와 `result.json`의 Git 상태 전후 비교를 확인한다.
JUnit 옆 `result.json`에는 run ID·시작/종료 UTC·선택 명령·Python/PowerShell 버전·실제
task/basetemp drive와 경로 길이 계산을 남긴다. 실행 전후 HEAD SHA·dirty 상태/경로,
내용을 노출하지 않는 diff hash와 소스/runner/fixture/helper 파일 hash를 기록한다.
실행 중 이 fingerprint가 바뀌면 pytest 성공이어도 `UNPROVEN`/exit1로 남긴다.
마지막 runner/공용 환경 변경 뒤 영향받는 검증을 다시 실행해야 하며 기존 증거는 보존한다.
Python audit hook은 runner·pytest·일반 Python 자식의 파일/디렉터리/SQLite 쓰기를
거부·기록하며, 잡힌 예외나 자식 실패라도 runner는 실패를 반환한다.
native executable·`-I` 자식의 OS 쓰기 전부를 감시하는 sandbox는 아니며 제품 종료 정책은 불변이다.
D 쓰기 병목이 확인된 C 예외는 합성 입력·TEMP/TMP·basetemp만 허용하고 로그/JUnit/실패 원본은
D에 보존한 뒤 C 임시 루트를 검증·삭제한다. runner 전체 출력을 C로 옮기는 예외는 아니다.
C 예외의 분리 출력은 기존 직접 pytest 명령에서 C `--basetemp`와 D `--junitxml`/로그를 명시한다.
직접 pytest의 runner probe는 외부 basetemp 대신 `CONTAINER_AUDIT_TEST_TASK_ROOT` 또는
기본 runner 루트 아래에 자기 run을 만든다. 상위 runner의 쓰기 경계가 있으면 그 경계를
우선한다. 긴 외부 basetemp를 짧은 probe 루트와 분리해도 240자 사전 guard는 그대로다.
구버전 shared leaf 부재의 설치 호환 시험은 동일 writer 의미의 합성 후보를 사용하며,
현재 후보와 구버전 writer 의미가 다르면 변경 전 거부하는 계약도 함께 검증한다.

<a id="ca-history-load-warning"></a>
## 금일 작업 현황 읽기 오류

작업자를 선택하고 `작업 시작`을 누를 때 기록을 모두 읽지 못하면
`작업 현황 확인 필요` 경고창이 오류 건수와 수량 누락 가능성을 알린다.
`확인` 후 정상적으로 읽힌 자료로 시작을 계속한다. 표시 수량을 전체 실적으로
단정하지 말고 관리자에게 작업 기록 확인을 요청한다. 상세 경로·예외는 진단 출력에 남는다.
관리자는 선택한 데이터 루트의 events 폴더와 로그 읽기 권한·손상 기록을 확인한다.
자료를 삭제하거나 빈 로그로 덮어쓰지 않는다. 정상 0건은 경고 없이 기존 빈 표를 유지한다.
실제 경고창의 화면 배치·가독성은 headless 검증 범위 밖이다.

<a id="ca-legacy-transition-ops"></a>
## 과도기 모드 켜고 끄기 (관리자)

검사실 잔량표는 과도기 설정과 회사 서버 연결 여부에 관계없이 이적에 사용할 수 없다. 오류음과 「잔량표는 이적에 쓸 수 없습니다 — 검사실로 돌려보내세요」가 나오면 실물을 검사실로 돌려보낸다. 잔량표가 담긴 이전 작업·보류 파일은 그대로 보존하고 복원하지 않는다. 서버가 같은 이유로 거절한 현품표는 자동으로 다시 조회하거나 과도기 로컬 작업으로 시작하지 않는다.

새 시스템 전환 전(D-day 전)에 이 PC가 옛 현품표와 새 현품표를 모두 받아 종류별로 따로 기록해야 할 때 켠다.
관리자 권한으로만 바꿀 수 있고, CA를 다시 시작해야 적용된다. 자동으로 꺼지지 않는다. [계약](contracts.md#ca-legacy-transition)

| 할 일 | 관리자 PowerShell |
|---|---|
| 켜기 | `[Environment]::SetEnvironmentVariable('KMTECH_LEGACY_LABEL_TRANSITION','1','Machine')` |
| 끄기 | `[Environment]::SetEnvironmentVariable('KMTECH_LEGACY_LABEL_TRANSITION',$null,'Machine')` |
| 확인 | `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v KMTECH_LEGACY_LABEL_TRANSITION` |

앞뒤 공백을 뺀 값이 `1`일 때만 켜진다. 사용자 환경 변수나 실행 명령의 환경 값으로는 켜지지 않는다.
바꾼 뒤 CA를 종료하고 다시 실행한다. 켜지면 창 제목과 작업자 칸에 `과도기 모드 — 옛 현품표 받음`이 보인다.

**현장 관리자 안내:** 과도기 모드가 켜진 PC는 검사실 잔량표를 제외하고 품목 코드가 읽히는 현품표면 어떤 것이든 받아 작업을 멈추지 않는다(새 현품표를 서버 확인 뒤 봉인 명령까지 보냈는데 결과를 모를 때의 `서버 재확인` 잠금만 지금과 같다). 옛 현품표(13자리, 옛 QR)는 옛 이적 프로그램처럼 60개에서 자동 완료되고, 60개가 안 되면 `제출`로 끝낸다.
새 현품표(PHS=2)는 서버 확인이 되면 새 시스템대로 이적 장부에 들어간다. 서버가 끊겼거나 확인을 거절했거나 검사 등록 제품이 아닌 것이 섞였거나 수량이 모자라 `제출`했거나 이미 완료한 현품표를 다시 찍었을 때는 막지 않고 이 PC에만 '새 로컬'로 기록한다. 모양은 새 현품표인데 정보가 깨진 것은 '새 형식오류'로 따로 기록한다.
다른 품목 제품과 같은 제품 두 번은 지금처럼 막는다. 이미 완료한 현품표를 다시 찍으면 경고가 뜨고 '중복'으로 기록되니, 같은 제품이 두 번 들어가지 않았는지 확인한다.
옛·새 로컬·새 형식오류 기록은 이 PC와 서버 화면에만 남고 새 재고·이적·출고 장부에는 들어가지 않는다. 옛 현품표는 기존 출고 길을 쓴다. 새 현품표는 회사 서버 봉인이 확인되기 전까지 새 포장·출고로 이어지지 않으므로 관리자에게 보충을 요청한다. 금일 작업 현황에 「출고 전 관리자 보충 필요 N건」과 품목별 「보충 N건」, 완료 안내에 같은 문구가 보인다. 서버 봉인이 늦게 확인되면 해당 건의 표시가 사라진다. 새 형식오류처럼 봉인 의도가 없는 건과 조회 불가 건은 표시를 유지하며, 재시작해도 완료 기록에서 다시 센다. 옛 현품표에는 이 안내를 붙이지 않는다. 트레이를 구분해 보관하고 다른 트레이 작업은 계속한다.
중앙 품목 목록을 받지 못해도 프로그램은 설치 목록으로 시작하고, 그때 시작한 트레이는 '품목 미확인'으로 기록된다. 네트워크가 돌아오면 `운영 작업 ▾ → 품목 목록 새로 고침`을 누른다.

**끄기 전:** 되도록 진행 중·보류 중인 과도기 트레이를 끝낸다. 켬에서 시작한 트레이는 끈 뒤 재시작·보류 복원해도 시작 때 정한 분류(옛·새 로컬·새 형식오류·새 중앙)와 켬 규칙으로 끝나고, 로컬 분류는 새 장부에 들어가지 않는다(회차 분류 고정). 끈 뒤 새로 시작하는 트레이만 엄격 모드다. 켜기 전(업그레이드 전)에 시작한 13자리 트레이·lease 없는 트레이는 끈 PC에서 완료되지 않고 원인을 안내한다(켜면 완료된다).

**하루 건수(PC·날짜별):** 작업자 화면 `금일 작업 현황`의 품목 행 `(옛 N · 새 중앙 N · 새 로컬 N · 새 형식오류 N · 중복 N)`, 또는 이벤트 CSV(`이적작업이벤트로그_[작업자]_[날짜].csv`)의 `TRAY_COMPLETE` 행 `transition_class`·`transition_reasons`·`transition_duplicate`·`source_computer_id`·`app_version`. `중복 N`은 앞 분류 건수에 이미 든 중복 회차 수이고, 부분 제출도 한 건으로 센다. 재시작하면 CSV로 다시 세며 같은 완료의 재전송·재기록은 한 건이다. 서버 대시보드는 아직 분류를 구분하지 않는다([CA-G17](BACKLOG.md#ca-g17)).

<a id="ca-startup-update"></a>
## 로그온 자동 갱신 운영

PowerShell 관측·ACL·고정 helper·새 SYSTEM 로그온 action은 자식 인수에 `-ExecutionPolicy Bypass`를 명시한다. 관리자 기계 배치·작업자 준비의 기존/배치된 코드 무결성 확인과 지원 제거 자식에도 적용한다. OS·레지스트리·GPO 정책은 변경하지 않는다. 작업 관측·설치·제거는 정확한 이전 무정책 action과 새 action만 인정하며 원본 복원 XML을 보존한다. GPO 강제 및 실제 현장 실행은 별도 수용 항목이다.

첫 실행은 자료·원장·자동 시작 준비의 writer admission을 끝낸 뒤 relay를 시작한다. 시작 결과 확인 뒤 admission을 다시 얻어 시도·소유 자료를 재확인하고 환경과 READY 보고를 적용한다. UNKNOWN·실패·canonical 연기의 판정은 유지한다.

갱신 mutex는 작업자 ACL의 SYNCHRONIZE|MUTEX_MODIFY_STATE 권한으로 연다. 앱 시작·bootstrap의 busy는 apply 증거가 없으면 60초, LIVE/UNKNOWN이면 기존 240초 창에서 다시 기다린다. 상한 뒤 active와 실행 판이 같고 G ALLOW·일반 시작 가능한 종점이면 현재 판을 시작하고 `UPDATE_LOCK_WAIT_EXPIRED`를 남긴다. 열기 거절·abandoned·자료/시험/복구 거절은 기존 `UPDATE_IN_PROGRESS`(종료 20) 및 해당 guard를 유지한다. `startup-support.json` 쓰기의 `WriterFencedError`는 `REPORT_UNAVAILABLE`을 기록하고 기존 일반 실행 검증을 계속한다.

설치기의 `auto_update.py --print-logon-task` 자식은 script 실행에서도 앱 루트 기준
모듈 이름으로 writer sink를 식별한다. 앱 밖 정의는 `__main__`을 유지하며,
기존 허용 목록·source·fence 판정과 로그온 작업 JSON/XML 계약을 그대로 적용한다.

READY 실패 뒤 `update-control/transition.json`의 `retained_candidate=true`이면
새 판을 current로 유지한 상태다. `failure_decision.code`가
`TRIAL_GENERATION_ADVANCED`이면 새 판 세대가 기록됐고,
`TRIAL_GENERATION_UNKNOWN`이면 자료 세대를 판정하지 못했다.
다음 시작은 같은 candidate를 사용한다. 판정 불가 자료는 보존하고 지원 담당자가
확인한다. 판정 불가에서는 candidate도 기존 guard가 UNKNOWN으로 중단하며 기동을
보장하지 않는다. 다음 시도에도 같은 고정 지원 복구 안내를 내고 자료와 판정 기록을
보존한다. 임의 옛 판 복귀·marker 삭제·자료 복원으로 우회하지 않는다.
세대가 변하지 않았고 옛 판이 허용된 경우만 이미 확인된 옛 판으로 `ROLLED_BACK` 복귀한다.
GUI와 relay는 같은 판정 함수를 사용한다.
이전 실행이 남긴 업데이트 확인을 이어받으면 자료가 그대로일 때 정상 새 판도 이전 판으로 돌아갈 수 있다. 자동 갱신이 켜져 있으면 다음 시작 때 새 판을 감독하며 다시 적용한다.
10/14 이후에는 PC마다 실제로 실행 중인 판을 확인한다.
지원 절차는 「앱 닫고 다시 열기」다.
준비된 갱신의 SYSTEM 요청 실패 또는 60초 안에 apply 시작 증거가 나타나지 않음은 현재 판을 일반 실행한다.
FAILED/UNKNOWN에서도 active 판이 G ALLOW면 일반 실행하며, writer가 사라진 뒤 SYSTEM이
같은 결정표로 종점을 정착시켜 다음 prepared를 처리한다. 새 판 유지 결정 뒤에도 같은
bootstrap에서 바로 일반 실행한다. 자료 판정 불가 안내는 기존 guard가 담당한다.
APPLIED 후 감독이 없고 trial 자식도 없으면 후보를 일반 실행하고
`UPDATE_SUPERVISION_UNAVAILABLE`을 기록한다. 전환 잠금이 사용 중이면 고정 진행 안내를
내고 다음 시작에서 다시 확인한다. 기존 writer를 종료하거나 사용자 쪽에서 확정하지 않는다.
writer 때문에 미룬 DEFERRED는 recovery_pending=true와 원 phase·실패 코드를 보존한다.
writer 부재 뒤 원 G 결정을 한 번 재개한다. G가 그대로면 이전 판, 올랐으면 후보를
일반 실행하며 정착(false) 전에는 새 prepared를 적용하지 않는다. 재실행은 같은 정착을 유지한다.
사용자 staging의 `startup-support.json`은 허용 코드 `transition_code`와
`retained_candidate`를 포함한다. 예외 문장·외부 입력값을 공개 보고서에 넣지 않는다.

검증 실패한 prepared 원본은 지우지 않고 보호 실패 표식으로 격리한다. 같은 후보/무효 표식의 다음 로그온은 상태를 다시 쓰지 않는다. 첫 실행 비교의 진단 시각만 바뀌면 잠금 아래 재판독으로 통과하며 실제 변경/판독 불가는 현재 코드로 계속하고 지원 코드를 남긴다. 서명·pin·자료·시험·관리자 수동 경로의 거절은 유지한다.

첫 설치는 자료 판 검증 뒤 옛 relay의 작업과 실행 연결을 확인하고 보호 바탕을 준비한다.
옛 relay 작업이 없으면 launcher를 요구하지 않는다. 작업이 있으면 공식 정체성의 정확한
launcher 경로와 실제 파일·재분석 여부를 확인한다. 연결이 맞지 않으면 변경 전에 거절하고
작업과 실행 파일을 보존해 관리자 지원 복구를 요청하도록 안내한다.

지원 `-Uninstall`은 외부 stock 지원 소스를 실행 호스트로 사용한다. 각 current/versions 및
보호 packet의 해시 일치 파일을 `removal-evidence/<UUID>`로 개별 보존 이동한다. 고정 legacy
작업과 실제 경로/SID 및 고정 SYSTEM action이 맞는 StartupUpdate 작업만 제거/부재 확인한다.
목록 없는 폴더·외부 정션·내용이 다른 같은 이름 파일은 그대로 남고 `removed.json`에 경로를
기록한다. 잠긴/관측 불명 파일은 미완으로 남기며 같은 제거를 재실행한다. 업무 자료와 등록,
전송 대기는 보존한다. 잔여 current는 관리자가 보존 이관한 뒤 지원 설치를 다시 실행한다.
일반 제거는 손상·미확인 설치 파일을 설치용 무결성 사전 검증으로 막지 않는다. 실패를 잡은
현재 controller는 자기 제거 receipt의 시각·경로·request ID와 stop 바이트를 정확히 확인한
경우에만 그 실행의 stop을 정리한다. Run·code·relay는 되살리지 않고 원 실패 기록을 남긴다.
다른 실행이나 퇴역의 stop은 정리하지 않는다. 설치·정확 복원·퇴역의 설치 무결성 검증은 유지한다.
내용 제거 중 controller가 종료되면 같은 외부 stock 소스에서 같은 `-Uninstall`을 재실행한다.
설치기가 남긴 보호 removal journal과 원 감사 사본이 정확한 source/fence/owner를 증명할 때만
종료한 controller의 같은 session을 이어간다. 추가 중단도 같은 불변 기록으로 수렴한다.
owner가 살아 있거나 기록·source가 다르면 거절한다. 사용자 감사나 잔류 fence를 임의로 고치지 않는다.
보호 journal을 만들기 전의 중단에는 이 재진입 권한이 없으며 지원 담당자의 확인이 필요하다.

자동 feed는 설치 키로 검증한 manifest의 정확한 양방향 쌍 하나만 권한으로 쓴다.
실제 stock 판 번호·계약 원문 SHA를 사용자 준비와 SYSTEM 적용/재개에서 다시 대조한다.
같은/낮은 판·unsigned 정책 목록·Unicode 호스트·redirect/응답 URL 불일치는 거절한다.
국제 도메인은 ASCII punycode로 설정한다. 판 번호가 없는 옛 stock은 지원 재설치를 안내하며,
feed가 꺼진 기존 실행/relay의 SHA 식별 경로에는 판 번호를 새 전제로 넣지 않는다.
canonical feed ZIP은 `Container_Audit/` 아래 원문으로 준비한다. bundled runtime은
빌더의 `runtime-file-inventory.json`에 기록한 정확한 경로·해시와 실제 ZIP이 일치해야 한다.
stock manifest의 `runtime_file_inventory_sha256`·`runtime_file_inventory_bytes`로
별도 파일의 길이와 SHA256을 먼저 확인하며 그 파일만1MiB 판독 상한을 적용한다.
추가 runtime 파일·해시 불일치·목록 부재나 민감 상태 파일은 `prepared.json` 게시 전에 거절한다.
이 목록도 담는 packet SHA는 기존 설치 키로 서명한 feed manifest에서 인증한다.
portable은 현재 제품 reader가 없는 config/validator_settings.json을 포장하지 않는다.
source 자산은 보존하며 runtime-local denylist·정확 runtime 예외·feed 필터는 바꾸지 않는다.

feed의 내려받기 조각과 세 임시 사본 복사·fsync는 정지 여부를 probe한 뒤 허가 밖에서 수행한다.
현재 트레이 JSON도 허가가 없는 호출에서는 같은 임시 이름·직렬화로 준비하고 fsync한 뒤,
허가→트레이 잠금 순서로 원 파일 digest를 재확인하여 교체한다. 경합은 세 번 다시 준비한 뒤
기존 허가 안 저장으로 돌아가며, 이미 허가를 가진 호출은 기존 경로를 사용한다.
교체 성공 직후 같은 허가 안에서 병합한 상태를 호출자 사본에도 반영한다.
관리자 보류는 그 사본 전체의 저장 재확인과 기존 PIN 원본 결속을 유지한다.
준비 함수는 상속한 허가를 거절한다. checkpoint 감사 staging은 이번 변경에서 허가 안에 유지하며
중단으로 남은 트레이 임시파일은 기존 관리자 증거로 보존한다.
relay 업로드 상태도 허가 밖에서 기존 JSON·비밀 검사·fsync를 마친 뒤, 허가 안에서
현재 claim을 다시 확인하여 교체한다. claim 소실·쓰기 실패는 자기 임시파일만 정리하며,
기존 업로드 결과·오류 코드와 SQLite 상태의 기준 역할을 유지한다.
현품표 교체 대기·관리자 검토의 CSV 투영은 허가 안 append 뒤 열린 파일을 허가 밖에서
fsync하고, 허가를 다시 얻어 inode 동일·크기 유지/증가를 확인한 뒤 SQLite 영수증을 기록한다.
동일 행 재생도 자기 fsync를 거치며, 오류·파일 교체/축소는 영수증 없이 원 pending에서 재시도한다.
이미 허가를 가진 호출과 예외적인 손상 꼬리 복구는 기존 허가 안 내구 경로를 유지한다.
staging probe는 이미 writer 허가를 가진 호출을 거절하며, 세 사본이 모두 완성된 뒤
일반 publish sink가 고정 이름 세 개를 `os.replace`하고 기존 내구 쓰기로 `prepared.json`을 마지막에 게시한다.
SYSTEM의 보호 사본 복사는 기존 일반 sink와 동일 검증·크기 상한·fsync를 유지한다.
공유 복사 helper는 정확히 이 SYSTEM sink와 승인된 staging probe 두 호출자만 선언에 허용한다.
fence는 진행 중인 한 조각/복사의 임시 쓰기를 즉시 중단하지 못하지만 다음 조각/고정 이름 게시를 거절한다.
정지 주체는 staging을 소비하지 않으며, SYSTEM은 살아 있는 relay 등 기존 앱 writer가 있으면 고정 packet 적용을 DEFERRED한다.
시도가 끝나면 성공·실패 모두 자기 `download-<32hex>`와 자기 UUID 임시 사본만 정리한다.
삭제 전 이름·부모 경로를 확인하고 reparse를 거절하며, 남의 시도·임시 사본·고정 이름·prepared.json은 삭제하지 않는다.
임시 사본은 fsync 뒤 교체한다. Windows의 marker 내구 게시가 앞선 NTFS 이름 교체도 내구로 만든다는 기존 순서 가정을 유지한다.

허가 보유 시간과 스캔 쪽 허가 진입 대기는 별도로 평가한다. D: HDD V4 실측에서
허가 보유 최대는 prepared.json 700.91 ms, 조각 4.41 ms, 게시 6.50 ms였고,
다른 프로세스의 스캔 진입 대기는 최대 2743.73 ms였다. K6 수정본의 최대 보유는
85.42 ms, 스캔 진입 대기는 최대 1441.09 ms였으며 두 측정 모두 저장 거절은 0이었다.
보유보다 긴 진입 대기는 active_fence 파일 읽기와 조각 fsync가 같은 HDD를 다투는
경합으로 추정한다(256 MiB/256 KiB 내려받기는 조각 fsync 1024회). 이 결과는
허가 보유와 저장 거절에 대한 근거이며, 스캔 진입 대기 1초 이하를 보장하지 않는다.
실제 write_json_durable sink의 prepared.json 허가 보유는 D: HDD 시험에서 2초 이하를 단언한다.

독립 검토의 잔여 한계도 유지한다. 게시 뒤 자기 시도 정리가 실패하면 relay는 FAILED를
보고하고 시도 폴더가 남을 수 있다. 다음 주기에는 유효한 marker로 PREPARED가 되지만
이전 시도를 쓸어 지우지 않는다. V6(a) 원천 시험은 staging_root 글자 대조에 한정되어
리터럴 updates 경로나 부모 삭제를 포괄하지 않는다(현재 검토에서 해당 삭제는 0건).
이 가지의 생성 선언·핀은 통합 472가 표준 도구로 재생성하고 --check PASS를 확인한다.
V3 재생성 사본의 빌더 read-only PASS는 그 파생 가능성을 확인한 근거다.

관리자 설치기는 기존 보호 코드 배치와 같은 writer delegation 아래서
`versions/<source SHA>`·`update-control`을 보호하고, 지정 작업자 SID의 로그온으로
숨겨진 SYSTEM 작업 `KMTech.ContainerAudit.StartupUpdate.<경로/SID 식별값>`을 등록한다.
작업 action은 OS 고정 PowerShell과 `current/tools/apply_prepared_update.ps1`뿐이다.
작업자는 읽기·실행만 하고 action을 바꿀 수 없다. HKCU Run과 GUI launcher는
고정 일반 권한 bootstrap을 거쳐 준비된 새 판과 진행 중 journal을 먼저 확인한다.
기존 설치의 사전 Run 값은 설치된 설정 유무로 판정한다. 설정이 없는 옛 판의 정확한
main.py relay 명령은 인정하고 설치 성공 뒤 bootstrap 명령으로 바꾼다.
사용자가 바꾼 값·종류·인자와 다른 relay는 거절하며 실패 시 원 Run·relay를 복원한다.
옛 relay의 제거 receipt는 정지 요청 ID·표식과 함께 확인한다. runtime lease가 풀린 뒤
인터프리터가 나갈 때까지 최대 15초 기다리며, 정확한 사전 relay 외 프로세스·UNKNOWN·
실제 잔류를 인정하지 않는다. 첫 제거 receipt는 rollback의 재제거 전에 audit에 보존한다.
최종 설치/복구 relay는 같은 SID·대화형 세션의 일반 토큰으로 시작하고 이를 조회한다.
상승 호출은 기존 desktop shell의 일반 토큰만 사용한다. shell 부재·다른 사용자/세션·
토큰 조회 실패는 거절하며 installer 토큰이나 자격 증명/임시 task로 우회하지 않는다.
primary 복제 권한은 `0x18B`(ASSIGN_PRIMARY·DUPLICATE·QUERY·ADJUST_DEFAULT·ADJUST_SESSIONID)다.
실제 랩의 무해한 PowerShell 자식에서 기존 `11`의 Win32 5와 `0x18B`의 같은 SID/세션·일반 토큰·정상 종료를 확인했다.
제품 시작·복구 수용 범위는 [sub-84/sub-85 보고](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-84/REPORT.md)를 따른다.
canonical의 `failure`는 최초 설치 오류를 보존하고 `rollback.failure`는 복구 오류를
별도로 기록한다. 메시지·인수 원문 없이 호출 이름·Win32 번호·예외 종류·분류를 남긴다.
relay 복구 실패 뒤 Run 종류/값이 정확하고 stop 표식·relay가 없으며 scheduled writer가
복원됐을 때만 `RUN_RESTORED_RELAY_NEXT_LOGON`을 기록하고 다음 로그온 안내를 낸다.
`runtime_restored=false`와 실패 종료는 유지하며 즉시 복구 성공으로 처리하지 않는다.
SYSTEM은 credential/profile을 읽거나 작업자 프로세스를 띄우지 않는다.
설치 시 SYSTEM 실행 경로의 전체 조상과 코드 ACL을 먼저 검증하고, native helper는
다른 helper를 읽기 전에 bootstrap·control·version 경계를 검증한다. 위험한 조상은 설치를
거절하므로 관리자가 승인한 안전한 배치가 필요하다. 승인된 두 shared 조상의 정확한
default/goal ACL 보호 범위는 [자동 갱신 계약](contracts.md#ca-startup-update)을 따른다.
bootstrap 경유 Run은 active version의 실제 relay PID와 신선한 status로 확인한다.
설치 중 onboarding의 PID0은 fence 해제 대기이며 성공 proof가 아니다. 해제 뒤 75초의
resident 확인 실패는 원 status hash·원 오류와 rollback 결과를 보존하고 설치 실패로 남긴다.
일반 사용자에서 시작한 설치 helper의 UAC wrapper는 안쪽의 유한 child만 capture하고,
실제 helper PID의 journal과 outer/wrapper PID를 구분해 bind한다. 유한 자식의 stdout/stderr는
각 1MiB cap·bytes/hash/encoding/redacted/truncated/complete로 기록한다. 이미 일반 사용자로
호출한 lifecycle producer도 outer journal 유무와 관계없이 자체 private root와 final summary를
생성한다. 지속 pythonw stdio는 붙지 않는다. JSON authorization/credential와 escape된 값도 마스킹한다.
유한 lifecycle 진단은 `<lifecycle receipt path>.producer.normal.evidence.<adapterPID>`에 있고,
Highest hop의 안쪽 capture는 그 아래 `normal-producer-capture.evidence.<wrapperPID>`에 있다.
native 준비/시작 실패도 최초 exception chain·Win32 code와 final summary를 이 root에 보존한다.
두 installer의 최종 `installation_evidence_status`와 `evidence-status.json`을 함께 회수한다.
placement child의 첫 native 종료 코드와 bounded fallback 한 줄은 canonical 요약과
부모 journal에 보존한다. 뒤 evidence 결속 실패는 추가 진단이며 첫 실패를 바꾸지 않는다.
직접 높은 권한 helper의 증거 자리도 exact protected control/run, 원 basename/PID와
보호/no-reparse 검사로 결속한다. 성공한 child의 증거가 결속되지 않으면 계속 거절한다.
exact shared ancestor admission에서 선택한 폴더가 없으면 부모/대상 생성 전에
기존 ancestor trust 오류로 거절한다. 읽기 admission은 조상을 만들거나 강화하지 않는다.
journal I/O/ACL/limit 실패는 INCOMPLETE이며 business 결과와 구별한다. 원 오류를 덮거나
부분 진단을 완전한 증거로 수용하지 않는다. 실제 UAC·일반 token lifecycle hop·5차 제품 설치는
[지정 보고](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-84/REPORT.md)의 환경·결과를 확인한다.
READY/trial 읽기 경합은 last_ready_error에 종류만 기록하고 정상 종료·코드 복귀 판단을 계속한다.
형식은 유효해도 UTC로 표현할 수 없는 READY 시각은 미확인으로 처리한다.
원래 기한과 정상 종료·검증된 이전 코드 복귀를 계속하며 사용자 자료를 되돌리지 않는다.

builder `--auto-update-settings <JSON>`은 HTTPS `feed_url`, `channel`,
`approved_transitions`, `profile_auth`, `apply_during_work`를 받는다.
출하 빌더는 이 입력을 필수로 받고 설정 생략·빈 object·빈 feed·승인 정본 SHA 불일치를
출력 생성 전에 거절한다. 승인 파일을 재직렬화하지 않고 원본 바이트로 게시·되읽는다.
실행기의 개발용 빈 설정 동작은 출하 빌더의 입력 승인과 별개다.
`profile_auth=true`는 현재 사용자의 기존 물류 profile을 쓰되 feed와 같은 인증 원본에만
bearer를 전달한다. redirect·cookie 재사용은 거절한다. 새 credential 저장소를 만들지 않는다.
실제 feed·인증은 코디네이터가 정한 뒤 보호된 설치 입력으로 제공한다.
컷 stock의 feed 있음/빈 값 두 판은 같은 committed `update-manifest-key-config.json`을
쓴다. 보관 공개 설정 SHA256 `d7fb6ecb06b23ecf2fceea6c893c8d1162dad302720ab0e97d19dfae6368d1e5`와
원본·packet 바이트 일치를 확인하고 빌더의 공개 키 override 인수는 생략한다.
랩 검증용 공개 키 override로 만든 packet은 현장 컷 stock으로 사용하지 않는다.
자동 갱신의 양방향 승인은 앱 키로 서명한 manifest 안의 정확한 현재/후보 SHA와
실제 writer 계약 해시 두 방향에만 둔다. 별도 설정·다른 키·다른 출발점은 거절한다.
writer 및 데이터/API 계약이 같은 판은 추가 승인 없이 기존 호환 규칙을 따른다.
이 동일 계약 예외는 DDL·직렬화·실제 복구 모듈의 바이트 일치도 요구한다.
데이터/API가 바뀌는 갱신은 정확한 writer 쌍이 있어도 자동 적용하지 않고 지원 관리자 경로로 처리한다.
확인 전 실패는 policy를 바꾸지 않고, CONFIRMED 뒤 역방향 승인만 보호 감사로 남긴다.
프로토콜 1 이전 판이나 다른 공개 키의 최초 전환은 관리자 canonical 설치/복구로
수행하고, 자동 갱신으로 우회하지 않는다.
writer 의미가 바뀌는 첫 지원 설치에는 실제 old packet의 `source_commit`과
`writer_sink_inventory_contract_sha256`, 새 source SHA와 새 inventory 계약 해시로 만든
정방향·역방향 `approved_transitions`를 서명된 외부 manifest에 제공한다. 새 SHA를 wildcard로
대체하지 않으며 정본 설정의 빈 목록은 그대로 유지한다. 정확한 사후 코드 복원은 같은 successor
packet의 역방향 승인과 원 replacement receipt를 함께 사용한다. 핀은 코드 전이만 허용하며
사용자 자료·신원·장부를 과거 snapshot으로 되돌리지 않는다.
옛 releases/latest 경로를 켜지 않는다.

### 현장 옛 판 전환 중 공개 발행 동결

현장 옛 이적 판이 모두 걷힐 때까지(되돌림 기간 포함) 공개 릴리스·태그 push·GitHub latest 변경은 0건으로 유지한다. 새 판은 회사 서버 private feed·설치 패키지로만 전달한다. v2.0.9는 시작 때 `releases/latest` 태그를 문자열로 비교하며 `v2.0.99 > v2.0.9`이면 서명 없는 ZIP을 덮는 업데이트를 제시한다. [릴리스 계약](../../RELEASE_GATE_CONTRACT.md)의 동결을 적용하며, 기존 `--latest=false` 설정은 공개 발행 승인을 대신하지 않는다.

설치 때 HiberbootEnabled를 읽고 policy에 값/읽기 결과만 기록한다.
SYSTEM 로그온 작업의 XML은 SYSTEM SID와 HighestAvailable을 유지하고 선택
LogonType 요소를 생략한다. ServiceAccount는 cmdlet/COM enum이며 XML schema 값이
아니다. trigger/action/조건·Task 1.4는 그대로다. 호스트 schema 회귀와 랩 등록 수용을
구별하며 [전수와 원 실패](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-151/TASK-XML-SITES.md)를 따른다.
2026-10-03 랩 예행 E는 교정 XML을 비활성 등록/해제했으나 단일 설치의 task 되읽기
guard에서 실패했다(native 73 보존, protected helper 결속 통과). 옛 코드/Run/ACL/일반 relay
지원 복원은 PROVEN이며 새 설치의 시작 화면/업데이트 확인은 NOT TESTED다.
[예행 E 증거](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-151/CA-5TH-REHEARSAL-E.md)는
probe의 SID→계정명 되읽기와 설치 실패를 구별하며 실제 설치 task XML은 rollback 전에 수집하지 않았다.
예약 작업의 preimage·기존 작업·등록 뒤 되읽기는 주체와 trigger의 계정 표현을 이 PC에서
SID로 해석해 기대 SID와 비교한다. 해석 실패·다른 SID·다른 action은 거절하고 원 XML을 보존한다.
canonical relay 작업의 주체 판정도 같은 SID 해석을 쓴다. PS5.1/7의 세 소비자 회귀는
소스 검증이며 [예행 F](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-156/CA-5TH-REHEARSAL-F.md)의 native 결과와 구별한다.
일반 보호 경로의 특권 소유자 규칙은 SYSTEM·Administrators·TrustedInstaller의 정확한 SID 셋이다.
설치·relay·업데이트 적용이 같은 pure 함수를 쓰며, helper를 신뢰하기 전 업데이트 검사는
그 함수의 동일한 로컬 사본을 사용한다. hardened 폴더의 정확 BA 소유자 및 원본 receipt/operator
소유자 결속은 유지한다. [전수표](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-156/OWNER-RULE-SITES.md)는 이 두 요구와 형제 앱의 미교정 소비자를 구별한다.
예행 F(205f877, 2026-10-03)는 native 비활성 작업의 SID 판정과 실제 설치의 task 등록·되읽기를 통과했다.
설치 1회는 뒤이은 receipt 결속에서 bootstrap_integrity.ps1:1799의
`Replacement receipt path already exists.`로 FAILED_ROLLED_BACK(native 73, 부모 1)이다.
INSTALL_THIS_PC.ps1:1564의 최초 receipt 작성 뒤 :1588이 같은 경로를 교체 허용 없이 다시 작성한다.
지원 rollback과 독립 old2302파일·Run·ACL·비상승 relay 복원은 PROVEN이다. 시작 화면/업데이트 확인은
NOT TESTED이며 재시도0이다. 원 예외·보호 원본·실제 9/10구간은 위 예행 F 문서에 보존한다.
CA-R1 교정 후 replacement receipt는 startup 설정이 있는 경우 원 startup preimage의 경로·hash를
처음부터 포함해 실제 보호 run 경로에 한 번만 작성한다. startup 변경은 그 뒤에 실행하며 같은
preimage를 사용한다. 새 실행은 새 run/attempt 경로를 사용하고 기존 receipt를 덮어쓰지 않는다.
receipt_path는 원 caller/export 경로를 유지한다. protected destination으로 이 필드를 바꾸면
ordinary export/restore 소비자 검증이 실패하므로 그 변경은 적용하지 않는다.
실패 복원·원 receipt hash/old-new identity 검사는 유지한다. PS5.1/7 소스 회귀와 실제 예행 G의
범위·결과는 [sub-162](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-162/REPORT.md)를 따른다.
예행 G의 설치1회는 helper0/REPLACED_VERIFIED 뒤 부모 caller receipt 부재(OpenRead,
portable.ps1:6/호출2887, inner HRESULT -2147024894)로 실패했다. 뒤 rollback917의
CANONICAL_RELAY_READY_TIMEOUT/native1/AUTOSTART_ROLLBACK_FAILED를 첫 실패와 분리한다.
current dac6157/2304파일·active pointerdac·startup task1이 남았으며 old code 복원은 FAILED다.
public3/business82/Machine2/원 Run144·5 ACL·형제 판 동일과 늦은 Medium ordinary relay RUNNING은
별도 관측이다. 원 rollback tree·startup preimage·보험과 protected 원본을 보존했고 수동
receipt export/추가repair/재설치/GUI/update0이다. 현재 상태의 지원 복구는 다음 작업이다.
켜진 작업자가 이미 있으면 로그온 작업은 DEFERRED로 남기며 업무를 멈추지 않는다.
수명주기 교체/복구는 진행 중 자동 전이나 실행 중 작업이 있으면 거절한다.
기존 policy·pointer·journal·task XML/ACL은 보호된 `.startup-update-install.<attempt>`에
보존하고 교체 실패/정확한 원본 복구에 함께 되돌린다. 제거 시 소유 작업을 등록 해제하고
versions/control은 `.startup-update-uninstall.<attempt>`에 보존한다. 업무 데이터는 건드리지 않는다.

PROVEN 범위는 순수 결정·핀·내구 쓰기 순서와 명령 생성, 코드 inventory 검사다.
실제 task 등록/ACL, 일반 사용자 GUI READY, 로그온 경합, 전원 중단·실패 복귀,
Hiberboot 값 관측은 호스트에서 실행하지 않았다. [CA-G19](BACKLOG.md#ca-g19)가 실기 수용을 관리한다.

<a id="ca-o01"></a>
## CA-O01 실행 구조·시작·권한

설치 키트가 시작 가능 여부를 읽을 때는 [시작 확인 CLI](startup-check.md)의 한 줄 JSON을 사용한다.
읽기 전용 확인의 UNKNOWN은 시작 허가가 아니며 기존 앱의 시작 관문을 대체하지 않는다.
FIRST_RUN_PENDING은 앱이 첫 실행에서 마치는 준비의 알림이며 복구·되돌림·시작 불가로 처리하지 않는다.
첫 화면 이벤트 뒤 기존 결과 폴더에 `YYYYMMDD-CA.gui.json`을 한 줄 원자 기록한다.
실제 프로세스 생성 UTC와 화면 준비 +09:00을 담고, 별도 daemon thread에서 쓴다.
폴더 없음·쓰기/시각 조회 실패는 화면 시작에 영향을 주지 않으며 ACL은 설치 키트가 정한다.

작업 중 작업자 변경은 창 안 `작업자 변경` 단추로 확정하고, 격리 보류 복원은 `보류 묶음 복원` 단추로 확정한다. 선택 중 스캔은 승인을 취소하고 기존 입력 순서로 처리한다. 원 작업자/관리자 권한과 진행 중 작업 차단은 단추 실행 때 다시 검사하며, 저장·감사 실패 때 기존 복구 원본을 유지한다. 출력 불확실 현품표는 실물 확인 후 `실물 확인 후 재출력`을 누른다.

이적 PC는 마지막으로 작업을 시작한 등록·활성 일반 작업자 이름을 기존 작업자 목록에 기억하고, 다음 실행에서 확인 창이나 `작업 시작` 누름 없이 같은 시작 경로로 작업 화면을 연다. 현재 이름은 기존 작업자 표시 영역에 보이며 `작업자 변경`으로 새 이름을 시작하면 그 이름을 기억한다. 첫 실행·기억 없음·이름 중지/제거·PC 연결 설정 필요·세션/현재 트레이/본인 보류 복구 필요·이름 기록 불확실은 선택 화면에 머문다. 세션 시작 저장 실패도 결속과 배경 전송 없이 선택 화면으로 돌아가고 화면 안 안내를 보인다. 검증된 오프라인 품목 캐시와 로컬 연결 설정이 있으면 같은 자동 시작을 사용하며 기존 `저장 전송` 안내를 유지한다.

portable builder의 `APP_ROOT_FILES`는 제품 identity 포트, transfer client/common/store·member exchange view·tray completion과 자동 갱신 bootstrap을 명시한다.
`APP_PACKAGE_DIRS`·데이터 목록·`PORTABLE_INSTALL_ASSETS`와 실제 import에서 파생한
relay/등록/profile 도구 3개와 외부 운영 CLI `tools.direct_sync_relay_operator`를 함께 탑재한다.
CLI의 목적지는 `app/tools/direct_sync_relay_operator.py`다. 새 root 스크립트는 자동 탑재하지 않으며,
manifest의 필수 모듈이 없으면 빌드를 거부한다. [패키지 회귀](../../tests/test_zero_pe_native_dependencies.py)는
제품·vendor·assets·공유 계약·설정·도구의 독립 기대 경로·바이트와 tool import closure를 대조한다.
설치·복구·update preservation용 기존 파일의 제외는 없으며 writer admission은 유지한다.

portable operator CLI는 같은 packet의 `runtime/python.exe -I -B`로 실행하고,
`app`과 `app/site-packages`를 명시적으로 import 경로에 넣는다. 실행 명령은
[운영 runbook](../FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md#portable-relay-operator)을 따른다.
기본 relay는 동일 Windows 사용자의 `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`에서
`control/pause.json`, `queue/direct_sync_relay.sqlite3`, `status/direct_sync_relay_status.json`을 사용한다.
custom data root에서는 해당 데이터 루트의 `direct_sync` 아래 같은 상대 경로를 사용하므로 실제 relay 설정을 먼저 확인한다.
writer admission도 현재 사용자의 같은 `control/writer-session` 루트를 해석하므로 다른 사용자의 marker 경로나
`CONTAINER_AUDIT_DATA_ROOT`만 지정해서 그 사용자의 relay/fence를 제어할 수 없다.
CLI는 frozen-required 목록에 이미 들어 있으므로 외부 도구 등록은 기존 writer inventory와
canonical writer 의미를 바꾸지 않는다. 구 d69 packet과 현재 의미의 차이 및
`CANONICAL_STOP_MARKER_PREEXISTS`는 별개 미해결 항목이며 installer의 두 의미 불일치 거부를 유지한다.
[w9caclipack 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caclipack/RESULT.md)는
소스·후보 packet 검증 근거이며 실제 설치·실제 사용자 pause/resume·전체 client 정지 수용은 아니다.

W6 CA-0/1/2의 client/store·view·완료 orchestration 이동은 기존 writer inventory 생성기 `--write/--check`와 Python fence·
PowerShell fence·session contract의 3개 pin을 함께 갱신한다. M7의 frozen product text/binding
목록도 이동된 client/common/store·member exchange view·tray completion을 포함한다. AST·기록 벡터·headless focused 시험은 소스 근거이며
GUI·설치·VM·서버는 이 분해에서 검증하지 않는다.

writer inventory는 sink의 소스 행 번호도 포함한다. UI 등 앞선 코드의 행 수만 바뀌어도
`python -B tools/derive_container_writer_sinks.py --write`로 재생성하고, 출력 hash를
`writer_session_fence.py`·`tools/container_writer_fence.ps1`·`tools/container_writer_session_contract.json`의
기존 pin 세 곳에 함께 반영한다. `--check`와 snapshot/consumer pin 시험을 통과한 뒤
깨끗한 커밋에서 stock portable builder를 실행한다. builder의 파생 객체·canonical JSON byte
일치 검사는 유지하며, 행 번호 차이를 무시하거나 설치 시 pin을 다시 계산하지 않는다.

`python -B tools/refresh_container_update_declarations.py --write/--check`는 위 생성기를 호출하고
세 consumer pin과 배포 전환 선언의 현재 소스 바이트 바인딩을 함께 갱신/검사한다.
전환 선언의 before·설치된 release preimage·runtime/dependency 바이트 선언은 보존한다.

GUI·온보딩·relay 런타임에서 콘솔 프로그램을 호출할 때는 Windows의
`CREATE_NO_WINDOW`를 지정한다. 소스 실행의 자료 세대 확인용 Git 두 호출도
출력 캡처·종료 코드 처리는 유지하면서 창과 스캐너 입력의 포커스를 가져가지 않는다.
`tests/test_runtime_console_launches.py`가 공개 자료 세대 진입점의 호출 인수와
제품 Python 호출 전수를 검사한다. 설치·빌드·촬영 CLI 예외는 기존 함수와 호출 수로 한정한다.

canonical installer는 초기에 로드하는 bootstrap 자체의 고정 SHA256부터 검증한다.
portable 등록·관리자 복구의 직접 명령 `runtime/python.exe -I -B app/tools/register_container_audit_worker_pc.py`는 도구 자기 위치의 `app`와 `app/site-packages`를 먼저 싣는다. 격리 subprocess `--help`는 경로 준비만 증명하며 실제 등록·서버 복구 수용은 별도다.
기존 `derive_container_writer_sinks.py --write/--check`가 이 pin과 inventory를 함께 갱신/검사하며
bootstrap은 checkout EOL 변환에서 제외해 bytes를 보존한다. bootstrap의 strict path·ancestor/reparse 검사 후 고정 consumer
manifest SHA256과 leaf SHA256을 검증하고 shared PowerShell을 dot-source한다.
source의 `kmtech_shared/powershell/portable.ps1`와 portable의 `app/` 아래 경로를 구분한다.
현재 입력을 다시 hash한 값을 신뢰 pin으로 사용하지 않으며 Python 준비 전 checker를 실행하지 않는다.
`Full`·`Sha` wrapper와 `Manifest`의 required-file/reparse·bounded parse·signature 블록만 위임한다.
CA 필수 12파일·writer 4경로·schema/coverage·9hash·typed metrics·제외 규칙과 검증 순서는 유지한다.
`InstalledManifest`·`Get-StrictFullPath`·writer session/stop/restore/current-user 상태는 CA 소유다.
source admission 뒤의 기존 bootstrap 재로드도 유지하여 lifecycle public-contract validator의
함수 binding을 보존한다. 원본 함수 parity와 pin 거부는 PS5.1/PS7 합성 트리 시험이며
서명 순서/거부 spy와 로컬 CPython 복사본의 실제 signature 조회를 구분한다.
실제 설치/제거/복원·전체 native closure·화면 수용은 별도다.

기존 설치 트리 적격성은 설치된 manifest와 core 파일 집합을 사용하며 새 shared leaf를
요구하지 않는다. `adcaf86`의 0.2.0·writer 계약/재고를 가진 합성 트리가 실제 preflight와
교체를 통과하고, leaf를 포함한 새 트리·원본 rollback을 검증하는 회귀를
PS5.1/PS7의 ko-KR/en-US에서 실행한다. bootstrap 새 발급은 상대 경로의 ordinal
순서를 사용하고, 기존 발급 record는 exact path 일대일 대응 뒤 원래 순서로
size/hash·aggregate를 검증한다. 기존 record를 다시 쓰거나 writer inventory를 바꾸지 않는다.

`test_bootstrap_cross_engine.py`는 고정 `7416378` helper·실제 writer JSON을 사용해
기존 record byte 보존, 양 엔진·ko-KR/en-US 교차 소비, 원본 aggregate와 변조 거부를 검증한다.
파일·디렉터리 ACL identity는 Windows PowerShell의 Access/Owner/Group readback과 대조한다.

**정본 0.3.1 배열 반환 보존:** `Read-KmtechPortableManifest`가 parser의 대입 형태를
유지하여 PS5.1의 `[manifest]`·PS7의 `[[manifest]]`에 원 CA의 readback 거부를 복원한다.
`test_shared_manifest_rejects_array_wrapped_json`은 이 두 벡터와 양 엔진의 3중·빈·중첩 빈 배열을
원 앱 함수와 직접 비교한다. 0.3.0의 두 FAIL 원본과 0.3.1 재실행·짧은 경로 복구 회귀는
[X13-B bump 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x13bbump/RESULT.md)에 보존한다.
기존 PS7 upgrade 실패 원본과 교차 엔진 수정·재실행은
[H-CA-PS 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w6hcaps/RESULT.md)에 구분한다.
실제 lifecycle·관리자 ACL hardening은 이 소스 회귀의 검증 범위 밖이다.

작성자 검증기는 정본 OS 모듈 머리 두 줄의 원본 바이트와 script 첫 명령 위치를
확인한 경우에만 모듈 실행 예외로 인정한다. param이 있으면 그 뒤여야 한다.
공백·대소문자·경로·오류 정책 변경과 추가 module load는 예외로 인정하지 않는다.
진단 로그는 정확히 pin된 미사용 잎일 때만 분석상 제외하며 import·호출은 거절한다.
이 예외는 생성 선언·설치 pin의 갱신이나 실제 설치 수용을 대신하지 않는다.
설치·업데이트·writer library와 독립 ACL/예약 작업/JSON 템플릿은 param 뒤,
첫 OS 명령 전에 같은 두 줄을 직접 가진다. `$PSHOME` 절대 경로의 Utility/Security를
불러와 PS7 부모에서 상속한 PSModulePath에서도 5.1 명령을 푼다. StrictMode/EAP,
업무 동작·공개 출력·종료 코드는 바꾸지 않는다. import 실패는 기존 trap보다 앞에서
즉시 전파되므로 그 실패의 별도 공개 기록은 보장하지 않는다.
bootstrap의 JSON 전송·관리자 helper·일반 사용자 producer 자식 문자열도 같은
두 줄로 시작한다. 전송 byte pin·argv 결속·기존 명령 길이 제한은 유지한다.

`kmtech_shared` 0.3.6은 정본 code `531ac40bfd415c3da3f245a487e8e276a4dc3042`의
9파일(기존 7파일·diagnostic_log·PS 모듈 머리)을 byte 그대로 고정한다. release `dd34e4d`의
manifest SHA256은 `8c310e69a97c613dbfc3405b17e2ca9f15290a4373c98c140510ea16b9d94c84`이며 별도 `kmtech_shared.lock.json`이 이를
결속하며 기존 factory `contract.lock.json`과 독립적이다. portable/PyInstaller 모두
shared module·PowerShell leaf와 manifest/lock을 포함한다. portable builder는 코드 배치 전에
앱의 고정 lock을 사용하는 자급 checker를 실행하며 leaf를 `app/kmtech_shared/powershell/portable.ps1`에 포함한다. 앱 안의 QA 진입점
`python -B qualification/check_kmtech_shared.py --check`는 이 lock의 hash/version으로
manifest schema·source commit·정확한 package 9파일·각 hash/version을 읽기 전용 대조한다.
`--root <CA 또는 portable app 경로>`로 다른 복사본도 검사한다. checker는 저장소 QA 도구로
제품 패키징에는 포함하지 않는다. `tests/test_kmtech_shared.py`는 형제 없는 앱 복사본에서
정상 pin·누락/추가/변조 거부와 기본 수집을 검증하며 lock 오류·단일 runtime identity도 확인한다.
정본 검증 4함수는 `531ac40`의 `manifest/sync_shared.py`와 source가 같다.
diagnostic_log는 패키징만 하며 앱이 import하거나 호출하지 않는다. 모듈 머리 정본도
대조·패키징용이고 앱은 그 파일을 읽거나 dot-source하여 머리를 얻지 않는다.
생성 writer inventory·설치기 preimage/pin의 정합성 갱신은 최종 조립에서 수행한다.
형제 정본과의 교차 대조는 앱 manifest/lock을 먼저 검증한 뒤 `source_commit`의 package bytes와 checker를 `git show`로 읽는다. 이 고정 대조를 모두 통과한 뒤에만 현재 checkout을 확인한다.
정본의 현재 HEAD/작업 트리 변경·추가 파일은 drift 안내이며 앱 판정을 바꾸지 않는다.
현재 파일의 구문·인코딩·I/O·Git 조회 등 확인 실패는 `정본 현재 파일 확인 불가: <사유 한 줄>` 안내로 격리한다. 고정 commit 조회·byte 대조·checker 실패는 계속 FAIL이다. 명시 검사는
`python -B -m pytest tests/integration/check_kmtech_shared_canonical.py`를 실행한다.
이 노드는 기본 파일명 수집에서 제외되며 명시 실행 시 형제 부재를 실패로 처리한다.
`tests/integration/check_kmtech_shared_canonical_regressions.py`의 명시 회귀는 정본 임시 복사본의 SyntaxError·현재 HEAD 조회 실패에서 PASS+안내, 재계산한 manifest/lock으로도 pinned byte 불일치 거부, 형제 없는 standalone PASS를 확인한다.
runtime SQL 7개는 기존 caller-fenced inventory에서 CA의 guarded facade와 core 내부 호출자를 정확히 결속한다. facade와 core가 같은 함수명을 쓰므로 lexical reference 집합도 별도로 고정하며, guard 제거·직접 우회 호출은 admission을 거부한다. `tests/test_shared_runtime_facade.py`는 실제 앱 ACK transaction의 외부 reader 비가시성·실패 rollback/재시도와 앱 callback·활성 writer fence 거부를 확인한다.
W5-S0-CA는 profile/legacy client 생성 2곳과 runtime scope 전달 3곳의 인자 이름을 명시한다.
signature·기본값·profile loader·shared core·복구 정책은 유지하며 writer inventory의 행 위치와 기존 3 consumer pin만 갱신한다.
기준 focused 248 PASS, 최종 같은 6파일과 consumer pin 1노드 249 PASS, 고정 fixture parity 8항목 동일·inventory `--check` exit0을 확인했다.
D 격리의 경계 쓰기/잔류 thread는 최종0이며 [결과·보존 진단](D:/KMTech/program-improvement-20260912/work/Container_Audit/w5s0/RESULT.md)은 source 수용 근거다. GUI·설치·VM·서버 수용은 확대하지 않는다.
shared 기본 시험·앱 시작/배포 runtime은 sibling 저장소나 온라인 검사를 사용하지 않는다.

`vendor.kmtech_zero_pe.raster`는 shared 계산을 상속하는 CA image/canvas facade다.
모든 image factory는 CA class를 반환하며 PNG 저장은 기존 `phs_label_workflow._save_raster_png`
writer admission 아래의 shared `RasterImage.save_png`로 이어진다. writer inventory는 이
정확한 호출자와 shared 파일을 포함한다. 실제 Tk 화면·장비·설치는 별도 검증 범위다.
X04-B renderer·패키징 focused는 100 PASS·잔류 thread0이고, baseline/facade 두 QR
payload의 픽셀·PNG bytes 일치와 해독을 확인했다. [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/x04b/RESULT.md).
catalog leaf 위임 뒤 최종 headless 회귀는 **978 PASS·201.03초·잔류 thread0**:
기존 W1–3 816 + update/writer 전환 92 + zero-PE 39(기존 builder 4 포함) +
현품표 workflow 23 + shared/facade 8이다. 기존 catalog 시험 파일과 zero-PE 동작
assertion은 유지했고 변경된 hash·추가 패키지 목록 기대값만 갱신했다. 이전 코드의 합성
v2 sidecar를 그대로 읽기·쓰기·복구하는 회귀, 정본 checker·writer `--check`·builder admission도 PASS다.

작업자 GUI는 [Container_Audit.main / _prepare_gui_startup](../../Container_Audit.py)의 host 모드 분기, 계약·경로 확인, 단일 인스턴스, 조건부 현재 사용자 onboarding, 품목 준비를 거쳐 시작한다. Tkinter UI와 백그라운드 조회/relay가 분리되며, 작업자 이름은 업무 귀속이고 중앙 device/scope 인증은 별도다. [host dispatch](../../container_audit_product_host.py), [worker_registry](../../worker_registry.py), [protected_admin](../../protected_admin.py).

| 경계 | 현행 소스 | 확인할 결과·한계 |
|---|---|---|
| 소스 실행 | `Container_Audit.py`; Windows가 작업자 runtime | 소스 실행을 설치된 후보의 실행으로 세지 않는다. |
| portable 배포 | [portable/launch-container-audit.cmd](../../portable/launch-container-audit.cmd)는 묶음의 `runtime/pythonw.exe -I -B`로 `app/main.py`를 호출 | `app/main.py`는 배포 배치 경로다. 소스 루트에 같은 파일이 있다는 뜻이 아니다. [INSTALL_THIS_PC.ps1](../../INSTALL_THIS_PC.ps1)의 launcher/manifest 검증과 연결한다. |
| 코드 배치 | installer 기본 `C:\KMTech\Apps\Container_Audit\current`, 일반 사용자 RX | 일반 runtime이 코드를 교체하지 않는다. 업데이트 정책은 패키지 소유, 배치는 관리자 installer 소유다. |
| 단일 실행 | [runtime_instance](../../runtime_instance.py)의 canonical data root hash 기반 Windows `Global` mutex | 같은 PC·같은 data root의 중복 GUI를 막는다. 생성 token의 기본 보안은 유지하며 runtime handle은 SYNCHRONIZE, writer admission의 대기/해제는 SYNCHRONIZE만 요청해 같은 사용자 상승 설치 뒤 일반 권한 탐침의 full-access 거부를 피한다. 실제 접근 거부는 계속 오류다. 다른 PC까지 같은 mutex로 잠그지 않으며 서버 경쟁은 CAS/lease 계약이다. 비Windows의 no-op은 현장 동시 실행 검증이 아니다. |
| 첫 사용자 준비 | [current_user_onboarding](../../current_user_onboarding.py); frozen Windows 또는 명시 `CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING` | 사용자 state·중앙 등록·relay 시작 요청을 확인한다. `START_REQUESTED`와 onboarding의 `READY`는 relay 업로드·전체 제품 준비 완료를 뜻하지 않는다. |
| 상주 relay | 로그온 HKCU Run과 onboarding이 [user_relay](../../user_relay.py)를 시작한다. 앱 시작의 1회 전송 뒤 `ensure_user_relay_running`이 Run 등록·정지 표식 부재·단일 실행 잠금 빔을 확인하면 같은 시작을 요청한다. 휴대판은 onboarding을 건너뛰므로 세션 중 끝난 relay는 이 경로로만 다음 앱 시작에 돌아온다. | 결과는 `status/container_audit_direct_sync_auto_bootstrap.json`의 `resident_relay`(`START_REQUESTED`·`RUNNING`·`NOT_REGISTERED`·`STOP_REQUESTED`·`UNKNOWN`)다. 상태 쓰기의 잠금 시간 초과·abandoned·파일 오류는 다음 주기에 재시도하고 `previous_status_write_error`에 남긴다. 활성 writer fence와 그 밖의 fence 검증 오류는 즉시 relay를 종료한다. `START_REQUESTED`는 업로드 성공이나 기동 예약이 아니며, 자식이 잠금을 잡기 전에는 중복 요청·프로세스 생성이 가능하다. 실행 잠금은 활성 loop 하나를 보장하고 나머지 자식은 종료한다. |
| 시작 실패·경고 | 중복 실행·잠금 실패·부분 onboarding·품목 검증 실패는 해당 중단 분기 | 기존 `gui_startup` 등록의 짧은 쓰기 허가 probe를 반환한 뒤, 경로 선택과 커널 실행 잠금 확인을 본문 허가 전에 진행한다. 중복 실행·잠금 실패 안내(종료 정리 지연 문구 포함)는 본문 쓰기 허가·자료 판 확인·무결성 검증 없이 표시하고 새 실행을 중단한다. 안내 창에서 기다리는 동안 기존 앱의 스캔 저장 허가를 점유하지 않는다. 첫 시작만 기존 순서로 준비하며 준비 실패 시 실행 잠금을 반환한다. bootstrap 무결성 기록 **부재**는 경고 후 계속하는 경로가 있고 기록 **불일치**는 차단한다. 모든 무결성 문제가 동일 종료라는 설명은 부정확하다. [시작 메시지·분기](../../Container_Audit.py) |

첫 업무 수용은 같은 사용자·정확한 후보로 정상 시작/중복 시작/부분 준비를 구분하고 current/parked/intent 복구와 실제 작업 가능 여부를 확인하는 것이다. 설치 성공이나 local profile 검사만으로 서버 capability를 입증하지 않는다. [CA-01](README.md#ca-01), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

### 관리자 정상 멈춤 요청

관리자 SSH 세션(승격·다른 계정 포함)에서 작업자의 실제 자료·relay 루트를 지정한다.
이 끄기 모드는 portable 진입점에서 사용자 업데이트 관문보다 먼저 처리한다.

```text
<설치루트>/runtime/python.exe -I -B <설치루트>/app/main.py --container-audit-user-relay --request-app-stop --data-root <실제자료루트> --direct-sync-root <실제relay루트>
```

설치 정책으로 같은 작업자 계정임이 확인된 경우에만 기본 루트 인수를 생략할 수 있다.
다른 계정이나 설치 정책이 없는 경우 두 루트를 모두 지정해야 한다. 같은 relay `control` 폴더에
`container_audit_app.stop.json`과 기존 relay stop JSON을 원자적으로 쓴다.
GUI는 작업자 선택 화면부터 독립된 1초 감시로 요청을 확인한다. 작업자 변경·닫기 중단·
outbox 원본 미저장으로 창을 유지한 뒤에도 감시한다. 설치 확인·첫 설정·품목 준비는
각 시작 단위가 끝난 경계에서 요청을 확인하고 다음 단위에 들어가지 않는다. 진행 중인
설정 쓰기는 그 단위까지 마치며, 첫 화면 적재 뒤에도 작업자 자동 시작보다 먼저 확인한다.
작업이 없으면 바로 정상 닫기를 시작한다.
작업 중에는 “관리자가 프로그램 종료를 요청했습니다. 지금 트레이를 마친 뒤 [종료]
를 누르세요.”를 계속 표시하며 스캔을 받는다. 요청 기록과 상태 저장은 기존 처리기에서
진행하고, 기록 실패도 스캔을 막지 않는다. 트레이를 마쳐도 자동 종료하지 않는다.
작업자가 기존 [종료]를 누르면 현재 입력 보존·진행 중 저장 정리를 수행하며 저장 실패
시 창을 유지한다. 미룬 요청 파일은 실제 닫기가 끝난 뒤 같은 ID인 경우에만 정리한다.
교환 진행도 정상 종료·작업자 변경과 같은 함수로 확인하며, 미룬 요청을 읽은 relay 루트에서 정리한다. 관리자 대조에서는 격리된 체크포인트를 원본으로 삼고 parked 상태는 작업 제출 때의 스냅숏임을 안내한다.
GUI 프로세스 시작 전의 요청은 기록 후 지우고 무시한다. 앱이 없을 때 남긴
요청으로 다음 실행이 닫히지 않으며, 실행 후 요청해야 위 정상 멈춤 절차로 이어진다.
relay는 진행 중인 cycle을 마치고 멈추며 stop 표식은 기존 재기동 방지 규칙대로 남는다.

창이 닫힌 뒤 남은 정리는 60초까지만 기다린다. HDD의 느린 투영을 기다리는 기존
5초 지연 안내는 유지한다. 정리 전에 `shutdown-stalled.json`을 원자 저장·fsync하고,
정리 완료 때만 지운다. 60초가 지나면 프로세스가 종료 코드 1로 끝나며 표지를 남긴다.
다음 시작은 표지를 읽고 기존 트레이 체크포인트·이벤트 outbox·SQLite intent 복구를
이어 간다. 로그 원본은 CSV fsync와 ACK 전까지 유지하며, 아직 원본도 저장하지 못한
outbox가 있으면 정상 닫기는 창을 유지하므로 이 상한에 들어가지 않는다.

끄기 명령은 요청 전에 귀속된 프로세스 나무를 확인하고, 요청 뒤 최대 150초(셸
120초 + 정리 여유 30초) 안에 나무와 relay 실행 잠금이 모두 없어질 때만
`STOPPED`와 종료 코드 0을 반환한다. 같은 설치의 `current`·`versions/<commit>` runtime
Python·pythonw와 새 화면의 `%LOCALAPPDATA%/KMTech/ContainerAudit/screen/webview2`
및 실제 자료 루트의 옛 `webview2` 프로필을 쓰는 WebView2를 확인한다. 다른 앱의 UDF는 제외한다.
UDF 인수 없는 자식은 살아 있는
부모의 PID·생성 시각·세션으로 묶고 부모 종료 뒤에도 같은 생성 시각의 잔류를 확인한다.
WebView2를 따로 종료하지 않는다. 시간 초과·관측 실패는 `UNKNOWN`과 종료 코드 1이며,
남은 수와 이름·PID만 표시한다. relay `ABSENT`만으로 GUI 종료를 판정하지 않는다.
되돌림 전에는 이 결과와 자료 파일을 확인한다.

밤 업데이트에서 Python 실행 파일 경로가 비면 PID를 다시 읽고, 여전히 비면 0.1초 뒤
한 번 더 읽는다. 사라진 프로세스와 설치 정책의 작업자와 소유 SID가 확실히 다른
프로세스만 건너뛴다. 경로·소유자를 확인하지 못한 이 설치 후보는 기존 관측 실패로
남기며 코드 교체를 진행하지 않는다.
WAL을 사용하는 writable SQLite 연결은 닫기 전에 미완료 거래를 rollback하고
대기 없는 `wal_checkpoint(TRUNCATE)`를 시도한다. BUSY·오류는 종류만 기록하고
연결은 닫는다. 다른 연결이 남아 있으면 `-wal`·`-shm` 소실은 보장하지 않는다.

<a id="ca-o02"></a>
## CA-O02 저장소·설정 우선순위·공급자

| 저장 대상 | 현재 기본 위치·내용 | 소유 근거 |
|---|---|---|
| 업무 state | `%LOCALAPPDATA%\KMTech\ContainerAudit`; `events`, `local_events`, `config`, `parked_trays` | [storage_policy](../../storage_policy.py) |
| 관측 이벤트 | `events/이적작업이벤트로그_[작업자]_[YYYYMMDD].csv`; local-only는 별도 `local_events` | [ContainerAudit._log_event](../../Container_Audit.py), [event_stream_policy](../../event_stream_policy.py) |
| current·조회 보류 | `events/_current_tray_state_[컴퓨터ID].json`, `_preflight_scan_hold_[컴퓨터ID].json` | [현재 상태·hold 경로](../../Container_Audit.py), [preflight_scan_hold](../../preflight_scan_hold.py) |
| relay | `%LOCALAPPDATA%\KMTech\DirectSync\container_audit`; queue DB·spool·status·등록 자료 | [storage_policy](../../storage_policy.py), [direct_sync_runtime](../../direct_sync_runtime.py) |
| 사용자 logistics profile | `%LOCALAPPDATA%\KMTech\Logistics\profiles\Container_Audit\runtime-profile.json` | [resolve_current_user_onboarding_paths](../../current_user_onboarding.py); 사용자 DPAPI를 사용하는 선택 경로 |
| 격리 override | `CONTAINER_AUDIT_DATA_ROOT` 사용 시 relay는 `<data_root>/direct_sync`, 기본 profile은 `<data_root>/logistics-profile/runtime-profile.json` | [storage_policy](../../storage_policy.py), [onboarding paths](../../current_user_onboarding.py) |

`storage_policy`는 명시 `data_root` 인자 → `CONTAINER_AUDIT_DATA_ROOT` → 현재 사용자 기본값 순으로 선택한다. 현재 사용자 home은 우선 `LOCALAPPDATA`, 다음 `USERPROFILE/AppData/Local` 등을 확인한다. 상대/볼륨 루트·Syncthing 경로 및 코드와 같거나 포함 관계인 업무 경로는 허용하지 않는다. 기본 business root와 relay root가 분리되어 있으므로 업무 폴더 한 개만 복사한 상태를 전체 백업으로 보지 않는다.

<a id="ca-retired-removal"></a>
### 기본 루트의 은퇴 제거 마감

기본 루트에서 정상 `--remove-current-user-setup`을 실행한 뒤 다른 기존 custom 루트를 채택하면
기본 relay 루트에 의도된 stop marker와 removal receipt가 남는다. 이를 삭제하거나 기본 루트를 다시
onboarding하지 않는다. 검증된 관리 패키지의 `INSTALL_CANONICAL_PORTABLE.ps1 -CompleteRetiredRemoval`
명령은 별도 exact old 패키지의 하위 제거기를 소비하며, 그 제거기의 legacy receipt 위치/hash 검사를
유지한 채 old 코드만 제거한다. 현재 사용자 자료·신원·은퇴 marker/receipt는 보존한다.

같은 일반 사용자의 기존 HKCU Run에 결속된 채택 데이터 루트를 `CONTAINER_AUDIT_DATA_ROOT`로 지정한다.
관리 패키지 `-SourceRoot`와 old packet `-OldSourceRoot`는 서로 분리된 원본이며 installed old 코드와
old packet의 manifest/aggregate/integrity가 정확히 같아야 한다. 기존 GUI 등 코드 writer는 정상 종료해야
하며, 남아 있는 writer/legacy 작업이나 불명 process 상태를 stop marker만으로 통과시키지 않는다.
필수 입력 `-RetiredRemovalReceiptSha256`은 현재 사용자의
`KMTech\DirectSync\container_audit\status\current_user_removal.json`,
`-RetiredStopMarkerSha256`은 같은 relay 루트의 `control\container_audit_user_relay.stop.json` SHA256이다.
관리자는 보존한 원본을 대조한 뒤 이 값과 exact old packet을 선택한다. hash를 새 승인 증명으로 해석하지 않는다.

정상 결과는 `PASS_RETIRED_REMOVAL_DATA_PRESERVED`이며 코드/Run/relay는 부재, 기본 은퇴 marker는 동일하다.
이후 새 패키지의 일반 canonical 설치를 **같은 채택 루트**로 진행하고 onboarding `REUSED`와 원 identity를
대조한다. 명령이 실패하면 원 code/record·Run 명령과 은퇴 marker를 검증한 exact rollback 여부를 확인한다.
다른 request로 바뀐 marker를 정리하지 않으며 불명 상태는 fence와 원본을 보존한다.

살아 있는 퇴역 마감 시도의 부분 제거는 남은 모든 파일이 exact old inventory의
동일 경로·크기·SHA256인 경우에만 복구한다. 잔여 tree는 그 attempt의
`.current.uninstall.<attempt>` custody에 보존하고 검증된 staging으로 원 code/record를
복원한다. 알 수 없는 파일·변경된 파일·변경된 integrity record는 교체하거나 지우지 않는다.
code 복원 실패에도 Run·귀속된 stop·원 은퇴 쌍 확인을 각각 시도하고 단계별 결과를 기록한다.
정확 code와 runtime preimage가 입증될 때만 fence를 해제해 옛 relay를 다시 시작한다.

퇴역 release authorization이 고정한 audit은 release 완료 전에는 봉인된 바이트를
유지한다. 중단·실패 관측은 원 위치의 `stages.jsonl`에 계속 남고, 일반 설치·업데이트·
일반 제거의 최종 audit에는 기존처럼 `installation_evidence`를 추가한다.

중단된 명령은 자동 성공으로 세지 않는다. 원 `audit_path`의 journal과 SHA256을 보존하고 원 owner 종료를
확인한 뒤, 동일 관리/old 패키지·두 은퇴 pin에 `-ResumeRetirementReceiptPath`와
`-ResumeRetirementReceiptSha256`을 함께 전달한다. 이 경로는 귀속·정지와 원 owner/authority 종료를 다시
검증한 후 새 authority를 만든다. 아직 살아 있는 owner, 변조된 기록, 부분 삭제되어 exact 확인이 불가능한
코드, 내구 기록 전 중단은 거부하며 임의 marker 삭제나 빈 integrity record 생성으로 복구하지 않는다.

검증 범위는 [w9caretire 결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9caretire/RESULT.md)의
소스·격리 lifecycle 시험과 stock builder다. **실제 guest 적용·UAC·실제 등록/서버 결과는 미검증**이며
현장 적용은 별도 판단을 따른다.

<a id="ca-custom-root-autostart"></a>
### custom 데이터 루트의 일반 GUI 실행·자동시작·재시작

현재 사용자 onboarding은 custom 루트를 정규화해 HKCU `Software\Microsoft\Windows\CurrentVersion\Run`의 `KMTech.ContainerAudit.Relay` 명령 끝에 `--data-root "선택한 절대 경로"`를 저장하고 exact readback한다. 이 기존 등록이 영속 루트 설정이며 구버전 `f5cf3c4`의 등록도 그대로 읽는다. `launch-container-audit.cmd` → `app/main.py` → GUI와 사용자 relay의 선택 순서는 **명시 `--data-root` > process `CONTAINER_AUDIT_DATA_ROOT` > 영속 Run 설정 > 기본값**이다. 즉시 relay 시작·검증된 교체 복원도 같은 루트를 명령에 담는다. GUI는 선택한 루트를 현재 프로세스와 자식에 전달하고 user 환경 변수를 영구 변경하지 않는다. 토큰·credential·profile 내용은 Run 명령에 넣지 않는다. 등록이 없거나 정상 기본 등록이면 기존 인자 없는 명령과 business/relay 분리 경로를 유지한다. 기본 business 경로를 명시 override로 지정한 경우에도 기존 override 의미(`direct_sync` 하위 폴더)를 유지한다.

같은 일반 사용자 PowerShell에서 아래 값을 확인한다. Run 값에 실제 채택한 루트가 있고, 그 루트의 `direct_sync\status\current_user_onboarding.json`의 `data_root` 및 `relay_autostart.command`와 일치해야 한다. 보고 파일은 상태 관측용이며 경로를 자동 선택하는 설정 파일이 아니다.

```powershell
(Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').'KMTech.ContainerAudit.Relay'
```

일상 GUI는 별도 환경 설정 없이 바탕화면·시작 메뉴 또는 런처로 시작한다. 같은 사용자의 Run 명령에 채택 루트가 있는지 확인한 뒤 환경 변수를 제거한 shell에서 런처를 두 번 정상 실행/종료하고, 같은 작업자·현재/보류 상태와 해당 루트의 onboarding 보고·relay status를 대조한다. 다음 로그온에서도 같은 값을 확인한다. 명시 override는 담당자가 기존 루트·원본을 확인한 뒤 사용하며 새 폴더 생성은 복구 방법이 아니다.

canonical 설치/제거/검증된 복원 controller는 기존 exact preimage 계약을 유지하므로 **해당 실행의** `CONTAINER_AUDIT_DATA_ROOT`를 채택한 기존 절대 경로로 지정한다. controller 환경과 Run 명령이 다르면 중단한다. 구버전의 인자 없는 Run에서 custom으로 전환할 때는 구버전과 일치하는 환경으로 코드 설치를 마친 뒤 기존 환경의 `--remove-current-user-setup`으로 이전 relay/Run을 정상 해제하고(업무·등록 자료 보존), custom 루트로 onboarding을 재실행해 Run readback을 확인한다. 이 제거 명령은 영속 루트 선택도 해제하므로 재설정 전 환경 없는 GUI를 열지 않는다. 두 루트의 relay를 동시에 실행하지 않는다.

루트 연결 해제·삭제·읽기/쓰기 권한 오류, 등록의 손상·읽기 거부 시 GUI와 relay는 writer 잠금을 해제한 뒤 `이적 검사 데이터 폴더 오류`로 복구 방법을 알리고 exit 1로 멈춘다. 기본 루트로 되돌아가거나 사라진 custom 루트를 빈 데이터셋으로 생성하지 않는다. 화면에 이전 작업자/보류 내역이 나타나거나 전송이 멈추면 작업을 중단하고 Run·실행 명령·onboarding 경로를 대조한다. 원본 데이터/큐를 보존한 채 드라이브·경로·같은 사용자 권한을 복구하고 기존 등록으로 다시 시작한다. 등록 자체가 손상됐다면 담당자가 보존된 onboarding 보고와 원본을 대조한 후 정확한 루트를 명시해 복구한다. 기존 relay를 정상 종료한 뒤 같은 Run 명령 재시작 또는 재로그온으로 root/status를 다시 확인한다. credential·DB를 기본 루트에 복사하거나 재등록으로 우회하지 않는다.

GUI 설정은 패키지 `config/container_audit_settings.json` 템플릿을 먼저 읽고 사용자 config의 UI 설정을 덮어쓴다. 사용자 `update_settings`는 제거하여 배포 업데이트 권한/provider 정책을 바꾸지 못하게 한다. frozen에서는 내부 시험 설정도 제거한다. 저장은 사용자 config로 한다. [load_app_settings / save_settings / _drop_release_disabled_settings](../../Container_Audit.py), [기본 템플릿](../../config/container_audit_settings.json).

물류 설정은 [default_logistics_profile_path](../../logistics_runtime_profile.py)를 onboarding·시작 client·품목·전송 client·등록/설치/점검 도구가 함께 따른다. ① process `CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH` ② 현재 Windows 사용자의 `%LOCALAPPDATA%\KMTech\Logistics\profiles\Container_Audit\runtime-profile.json` 순서이며, LOCALAPPDATA가 없으면 기존 사용자 home 대체 규칙을 사용한다. 채택한 custom data root가 있으면 기존 `<data-root>\logistics-profile\runtime-profile.json`을 유지한다. 명시 CA 경로가 없거나 불량이면 기존 오류로 거절하며, optional 기본 파일이 없으면 설정 없음으로 처리한다. `KM_LOGISTICS_REQUIRED`는 설정 부재를 거절하는 용도만 남고 경로를 선택하지 않는다. Machine에서 상속된 process `KM_LOGISTICS_PROFILE_PATH`와 PC 공용 ProgramData 파일은 자기 설정이 없어도 암묵 선택하지 않으며 읽기·수정·삭제 대상이 아니다. first-run은 CA 전용 경로와 required만 process에 적용한다. 바로가기의 비frozen·first-run 비활성 시작과 무인자 client도 같은 자기 경로를 사용한다. 과거 PC 설정을 명시 점검/설치하려면 도구에 `--profile-path`(등록 도구는 `--logistics-profile-path`)를 지정한다. 업데이트 조회의 기존 CA 전용/사용자 선택은 그대로다. profile이 없는 허용 호환 경로의 `WORKER_ANALYSIS_LOGISTICS_*` 환경 모드와 TEST1 격리 분기는 변경하지 않았다. 비밀 값이나 DPAPI 내용을 명세·진단에 넣지 않는다. [runtime 시험](../../tests/test_logistics_runtime_profile.py)·[사용자 시작 시험](../../tests/test_current_user_profile_startup.py)은 상속값·공용 기본 파일·자기 설정 부재/불량에서 실제 factory와 옛 파일 보존을 확인한다. 실제 설치본 공존은 NOT TESTED다.

공급자 호환은 [contract.lock.json](../../contract.lock.json)의 bundle/API/capability 선언과 실제 설치 후보를 함께 확인한다. 물류 lease 서명 검증은 [terminal_operation_lease](../../terminal_operation_lease.py)가 `vendor.kmtech_zero_pe`를 import하는 소스 경로다. CA에 Rework의 sibling/provider 선택 규칙을 그대로 적용할 근거는 없다. 현재 설치된 Python/Tcl, vendor·overlay 유무/해시, 서버 flags·인증 scope·TLS 설정·capability는 이 문서 작업에서 확인하지 않았다. 이름이나 HEAD만으로 설치 조합을 추정하지 않는다. [CA-G05](BACKLOG.md#ca-g05).

품목은 중앙 CSV와 검증 cache·복구 cache를 관리한다. 중앙 갱신 실패 시 검증된 cache로 시작하면 작업 화면의 주황 품목 안내 라벨에 캐시 기준 시각과 갱신 실패 안내를 표시한다(확인 창·누름 없음). 기존 연결 표시가 정상으로 돌아오면 목록 재확인 가능 안내로 바뀌며, 실제 목록은 `운영 작업 → 품목 목록 새로 고침` 성공 또는 다음 시작의 갱신 뒤에만 새것으로 취급한다. 선택된 profile이 없으면 인증이 필요한 운영 품목 원본(`worker.kmtecherp.com`, 기본값)에 요청하지 않는다. 로컬 cache 또는 패키지 목록으로 시작하고 진단에 `request_sent=false`·`pre_send_rejection_code=PROFILE_ABSENT`를 남기며 같은 라벨의 `회사 서버 연결 설정 필요` 안내에서 작업 계속 가능과 할 일(이 Windows 사용자로 설치·초기 설정 재실행 후 재시작)을 알린다. 명시한 다른 origin의 무인증 override는 기존대로다. 검증 가능한 cache가 없거나 검증 뒤 snapshot이 사라진 경로는 시작 오류다(창: 네트워크·설정 확인 뒤 다시 실행, 계속되면 IT 담당자 문의). 그래서 설치·업그레이드 뒤 첫 시작은 서버에 연결된 상태에서 한 번 해 검증 cache를 만든다. [refresh_item_catalog](../../item_catalog_sync.py), [prepare_startup_item_catalog / load_items](../../Container_Audit.py), [CA-C08](contracts.md#ca-c08). 허용 cache 나이와 갱신 지연의 업무 목표는 미정이다.

<a id="ca-catalog-refresh"></a>
### 실행 중 품목 목록 새로 고침

시작할 때 회사 서버가 403을 보내면 「회사 서버가 요청을 거절했습니다(코드 403)」,
5xx는 「회사 서버 오류(코드 N)」로 안내한다. 관리자 확인과 물류의 비JSON 오류도 같은 HTTP 코드를 보여 준다.
거절 안내만으로 요청 적용 여부를 확정하지 않으며 기존 원 요청·영수증 재확인 절차를 따른다.

1. 현재 트레이를 완료하거나 보류하고 조회·제출·교체 처리가 끝날 때까지 기다린다.
2. `운영 작업 ▾ → 품목 목록 새로 고침`을 누른다. `품목 목록을 확인하고 있습니다. 잠시 기다려 주세요.`가 표시된다. 작업 중이면 기존 작업을 먼저 처리하고 다시 누르라는 안내가 나온다.
3. `품목 목록 새로 고침 완료`와 `품목 목록을 새로 받았습니다. 현재 N건입니다.`를 확인한 뒤 새 품목의 현품표를 읽는다. 실패하면 기존 N건을 그대로 사용하며 네트워크 확인 후 다시 누른다. 계속 실패하면 담당자에게 이 PC의 중앙 연결 설정 확인을 요청한다. `중앙 연결 설정 필요`가 나오면 요청을 보내지 않은 것이다. 기존 N건으로 작업을 계속하고 설치 담당자에게 이 Windows 사용자로 설치(초기 설정) 재실행을 요청한 뒤 다시 시작한다.

일반 작업자도 실행할 수 있으며 재시작·새 화면·자동 주기 갱신은 필요 없다. 이전 cache만 반환한 경우 최신 목록 성공으로 표시하지 않는다. 현재 선택된 데이터 루트와 기존 작업·보류·전송 상태는 유지한다. 실제 화면·중앙 신규 품목 확인은 별도 촬영 레인에서 검증한다.

<a id="ca-o03"></a>
## CA-O03 스캐너·키보드·화면·사운드·출력

제품 형식 오류는 [현장 안내](../OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md#제품-형식-오류가-나타나면)의 라벨·스캐너 설정 확인 또는 담당자 문의를 따른다. 짧은 제품 바코드는 제품 라벨 확인 후 다시 스캔하고, 같은 오류가 계속되면 담당자에게 라벨 형식을 확인한다. 길이 초과·위험 형식·트레이 설정 오류에 반복 스캔을 지시하지 않으며, 원문 redaction과 기존 입력 잠금/확인 동작은 유지한다. U06의 fake-Tk 문구 비교는 실제 글꼴 배치·스캐너 입력 확인을 대신하지 않는다.

제품 교환은 [스캐너 경계](member-exchange-view.md)에 따라 창·수량 선택·완료 클릭 없이 진행한다. 명령 카드는 모든 스캔 파서 전에 가른다. 미달은 제품 1개 이상 뒤 같은 현품표로 확정하며, 바로 앞 동일 라벨 3초 이내 중복만 무시한다. 부족 수와 다른 소리를 표시하고 유예 중 UNDO로 원 기록을 남긴 채 재개한다. 현대·과도기 미달의 HELD 기록은 로컬 JSON/intent에 먼저 저장하고 CSV에는 아직 쓰지 않는다. 다음 현품표/로그아웃/종료 또는 확정 뒤 60초 무입력으로 보류를 풀 때 원 id/time/worker의 TRAY_COMPLETE CSV를 멱등 저장한 뒤 중앙 전송을 허용한다. 재시작은 내구 확정 시각으로 남은 유예를 복원하고 60초가 지났으면 즉시 투영·전송한다. HELD 중 UNDO는 CSV 행 없이 로컬 JSON/intent에 취소와 원 증거를 남긴다. 관리자 운영·복구 전용 삭제/격리/PIN 창은 수동 판단을 유지한다.


일상 안내 band는 필요한 알림/현품표 교체 때 펼친다. 최근 정상 스캔·다음 행동은 항상 표시하고, 작업 상세는 평균·30일 최고만 접고 펼친다.
작업 상세 열기·닫기, 운영 작업 메뉴 선택·취소·닫기, 트레이 이미지 체크 뒤에는 스캔 칸으로 초점을 예약한다. 좌우 보조 단추와 운영 작업 단추·이미지 체크 상자는 Tab 이동에서 빠진다. 차단 안내가 있으면 기존 초점 보호를 따르며 스캔 칸·대화상자·관리자 PIN 입력의 Tab 설정은 유지한다.
확인·PIN·교환 창이 초점이나 grab을 가지면 예약 복귀는 그 창의 입력을 유지한다. 작업 상세를 연속으로 여닫아도 스캔 칸의 입력 중인 글자는 보존하고 마지막 복귀 한 번만 처리한다.
전송 세부는 `운영 작업 → 전송 상태 상세`에서 확인한다. 닫은 뒤 기존 비차단 스캔 초점 복귀를 유지한다. 작업 화면에는 공통 바닥 한 줄과 필요할 때만 표시하는 주황 품목 안내가 있으며 저장 전송 카드·상세 단추는 없다.
교체 화면 닫기는 진행 중인 조회/교체/복구/차단 상태를 해제하지 않는다.
현품표 날짜 교환 확인이 남으면 「트레이 보류」로 실물을 따로 보관하고 다음 트레이를 계속한다. 현재 작업 리셋·작업자 변경도 해당 트레이를 먼저 안전하게 보류한다. 다음 현품표를 찍기 전에 현재 트레이를 보류하며, 기존 스캔 대기열의 순서는 유지한다. 같은 현품표는 교환 확인 전까지 받지 않으며, 밤을 넘겨도 보류 목록과 원 기록이 남는다. 교환 복구 후 기존 보류 복원으로 이어간다. 읽지 못한 교환 기록은 원 파일과 격리 사본을 관리자 확인 때까지 보존하고, 사본이나 보류 저장 실패 안내가 나오면 현재 실물을 유지한다. 스캔 판정 실패는 대상 트레이의 입력만 멈추며, 다른 현품표는 기존 처리로 넘긴다.
글자 크기 재구성 후 열린 교체 화면과 선택한 모드를 유지하며, 내구 복구가 남으면 메뉴 차단 중에도 `F8로 복구` 진입을 보여 준다.
가시성 수집기는 접힌 내용 대신 실제 상세 진입점을 검사하며, 알림이 필요한 상태는 계속 필수로 검사한다.
최종 제품 `0ea7251`은 상세 제어의 `Secondary.TButton` 배율 글꼴을 상속하고, 짧은 우측 영역에서는 여백과 버튼의 예약 폭을 줄인다.
실제 VM은1024×768이었으며 합성 대기/진행/중복/로컬 완료/중앙 완료/대기와 상세·메뉴를 열어 확인했다.
전체 앱 이미지는aa7ce0a/40054b6, 최종 제어 배치는0ea7251의 기존 native 배율5 PASS로 구분한다.
원 native40 PASS/6 FAIL과 Pillow 미설치 collection 오류를 보존했다. 확대 교환 표 행 잘림1은 별도 미해결 항목이다.
모든 task 프로세스·루트를 정리하고 네 아카이브를 D에 해시 검증한 뒤 VM6fcb를06:38:34Z Saved/할당0으로 반환했다.
[당일 결과와 원 실패](D:/KMTech/optimization-implementation-20260909/UI-IMPROVEMENT-20260912-1318/Container_Audit/RESULT.md)를 따른다.

| 장비/입력 | 확인한 소스 동작 | 수용 기준·미확인 범위 |
|---|---|---|
| 일반 복원 창 | 실제 monitor `rcWork`에서 client와 frame을 함께 맞추고 작은 작업 영역에서는 최소 크기도 제한한다. 충분히 큰 화면의 기본 크기·최대화 시작·명시적 signed 배치는 유지한다. | 복원/최대화 빈 다음-현품표 화면에서 명령 4개·상태 줄 전체와 버튼 중심이 작업 영역 안에 있고 Entry·경고 band가 사용 가능해야 한다. [8f7 실제 clipping 관측](D:/KMTech/optimization-implementation-20260909/Container_Audit/vm-gui-20260910T0205/VIEWPORT-DIAGNOSIS.md)과 [수정 전 고정 기준](D:/KMTech/optimization-implementation-20260909/Container_Audit/viewport-fix/ACCEPTANCE-BEFORE-EDIT.md)을 보존한다. 새 source의 실제 빈 화면 확인은 Main의 별도 VM slot 전까지 UNPROVEN이며 DPI 원인을 단정하지 않는다. |
| 스캐너 종료 | worker/scan/exchange Entry에 `<Return>` binding; 일반 제품은 `process_barcode`에서 문자열 `strip()` | 지원 스캐너의 실제 접미 Enter·CR/LF·키보드 배열/IME, QR 구분자 전달을 확인해야 한다. Tab·무접미·임의 Unicode 스캐너를 모두 지원한다고 주장하지 않는다. [Entry bindings](../../Container_Audit.py) |
| 입력 형식·연속 스캔 | exact PHS2 6필드, 제품 최대 128자·13자리 품목 코드 포함 조건; preflight 동안 내구 FIFO | 장비의 연속 입력과 조회 실패/재시작에서 접수 여부·순서를 대조한다. 수량 60이나 ERPnext 한도를 제품 요구로 적용하지 않는다. [CA-03~05](README.md#ca-03), [product_scan](../../product_scan.py) |
| 포커스·단축키 | 스캔 Entry 포커스 복귀, notice 확인의 Return/Escape, F8 정합 교체 및 Shift-F8 호환 진입 | 경고·보류 복원·modal 종료 뒤 입력이 잘못된 창에 들어가지 않는지 지원 배율/화면에서 확인한다. 실제 스캐너·200% 배율 전체 성공은 미입증이다. [메인 UI](../../Container_Audit.py), [CA-A02](BACKLOG.md#ca-a02) |
| 인코딩 | 이벤트 CSV는 UTF-8 BOM, 중앙 품목은 검증 snapshot, legacy 품목 파일은 별도 fallback | 한글 작업자·품목과 PHS 구분자, barcode 정규화 단계별 차이를 확인한다. 파일 인코딩이 키보드 장비 인코딩을 입증하지 않는다. [CA-C08](contracts.md#ca-c08), [입력·시간 계약](contracts.md#ca-data) |
| 사운드 | 현재 [native_audio.WavSound](../../native_audio.py)의 Windows `winsound`, one-shot/무한 loop·process-wide stop; 백그라운드 WAV 준비 | `audio_feedback_ready`는 파일 객체 준비 결과이며 실제 스피커 발성 성공이 아니다. 재생 오류·무음·중복 경고·정지와 시각 경고를 실장비에서 확인한다. [초기화/오류 사운드](../../Container_Audit.py) |
| 현품표 출력 | [phs_reconciliation_workflow](../../phs_reconciliation_workflow.py)의 artifact hash·print proof·`spool_job_id`·journal | 가상·파일 출력 기본 프린터/용지 거절은 관리자 안내 후 그 건만 인쇄 대기. 60초 제출 초과는 UNKNOWN으로 보류하며 화면·다음 스캔·종료는 계속한다. `PRINT_FAILED/PARTIAL`, 중앙 ACK 대기·재출력 불확실을 구분한다. spool 접수·종이 배출·올바른 라벨 부착은 각각 확인한다. 일반 스캔마다 자동 인쇄하는 기능으로 해석하지 않는다. [CA-C09](contracts.md#ca-c09) |

기본 프린터 안내가 나오면 현재 Windows 기본 프린터를 실제 라벨 프린터로 확인하고 관리자에게 알린다. Windows의 기본 프린터 관리가 켜져 있으면 PDF 사용 뒤 기본값이 바뀔 수 있다. UNKNOWN은 성공으로 바꾸지 않으며 실물 확인 후 기존 재인쇄 절차를 따른다. 이전 인쇄가 아직 프린터 대기열에 있다는 안내가 나오면 대기열을 확인하고 이전 제출이 끝난 뒤 다시 누른다. 그동안 다른 현품표와 스캔은 계속할 수 있다. 비라벨 안내의 현재 프린터 이름은 화면에만 보이고 기록은 고정 문구다. 실행 중 늦게 온 결과의 `.print-*.json`은 진단 자료이며 원 교체 기록의 성공이나 자동 재인쇄 승인이 아니다.

[CODEX](../../CODEX.md)의 pygame/PyInstaller 중심 기술 설명은 현재 위 사운드·portable 소스와 차이가 있다. 과거 안내를 그대로 장비 검증 기준으로 사용하지 않으며 [CA-G03](BACKLOG.md#ca-g03)에 후속 정합 작업을 남긴다. 프린터 모델/드라이버·용지·스캐너 모델/firmware·지원 배율의 확정 목록은 미확인이다.

<a id="ca-o04"></a>
## CA-O04 장애·오프라인·취소·재시작 인계

`운영 작업 → 관리자 확인 다시 조회`와 `보류 묶음 격리 후 다른 작업 계속`은 서버 응답을 기다리는 동안 화면 이벤트를 계속 처리한다. 기존 예/아니오 확인·관리자 PIN을 입력한 뒤 처리하며, 기존 요청의 서버 상태 확인이 필요한 경우에는 그 결과 뒤에 기존 PIN 창을 연다. 처리 중 다시 누르면 기존 확인 중 안내를 보인다. 정상 종료는 기존 lane drain으로 내구 처리를 마친다. 창이 없어졌으면 결과 화면만 생략하고 원 intent·감사·이동 기록은 남긴다.

정상 종료 대기가 60초를 넘으면 “종료가 끝나지 않았습니다. 창을 그대로 두고 관리자에게 알리세요.”를 한 번 표시한다. 종료 대기와 처리 줄 BROKEN 상태는 바꾸지 않으며 강제 종료하지 않는다. 지연 사건의 선택적 로그 쓰기 실패는 안내만 남긴다.

이전 판 미달 UNDO 뒤 시각 오류로 격리된 `.bad` 원본은 보존하고, `short_confirmations`의 대응 `CANCELLED.undo_state`를 원 작업자·현품표·스캔 목록/시각과 대조해 검증한 뒤 관리자 지원으로 복원한다. 대응 원본이 없거나 검증되지 않으면 해당 작업의 보류를 유지한다.

QT 누락 검증으로 이미 `OPERATOR_REVIEW`가 된 로컬 완료는 수정판에서 기존 관리자 확인 재시도로 원 명령·키·완료 시각을 유지해 전송한다. 자동 재시도 목록에는 편입하지 않는다.

제품 교환이 관리자 검토에 남으면 같은 현품표의 뒤 교환과 해당 트레이 봉인은 대기한다. 다른 현품표의 교환·봉인은 재시작 없이 계속 전송한다. 옛 현품표 교환의 검토 행도 보존하며 다른 트레이를 막지 않는다. 「제품 교환 저장됨·회사 서버 확인 중」은 이 PC의 저장 안내이며 회사 서버 확인 완료를 뜻하지 않는다.

PIN 소비 뒤 파일 이동 중 종료하면 `관리자 확인 다시 조회`에서 같은 operation key의 `moving` 경로·SHA256을 확인한다. 원 위치에 남았으면 기록된 목적지로 이동하며 새 timestamp 목적지를 만들지 않는다. 옮긴 바이트가 원본과 같으면 남은 효과와 감사 readback을 마치고 정상 완료와 같은 입력 잠금·메모리 정리를 적용한다. 다르면 활성 자리로 되돌린 뒤 `TARGET_CHANGED`를 안내한다. 활성 자리가 이미 차 있으면 두 파일을 보존하고 이 key만 보류한다. 새 PIN은 변경된 원본의 동작을 다시 선택할 때 받는다. 단 C12 복원이 `TARGET_CHANGED` 로 거절되면 그 항목은 잠긴 채 남는다(기준일 판 한계 — 11/1 첫 업데이트에서 고침). 이때 현장 관리자는 원본을 지우거나 옮기지 말고 개발 지원에 연락하며, 지원은 격리 원본·이동 목적지 두 파일이 보존됐는지 먼저 확인한다.

`APPLIED` 저장 직후 읽기 실패로 화면이 잠겨도 `관리자 확인 다시 조회` 또는 앱 시작에서 원 key의 완료 효과와 감사를 대조해 입력 정리를 이어간다. 이미 적용된 파일 이동이나 PIN 소비를 반복하지 않는다. 보류 폴더 목록을 읽지 못하면 관리자 인계 목록에 폴더별 원인을 표시한다. 확인된 현품표는 보류하고 다른 현품표를 진행하며, 잠시 뒤 같은 목록을 다시 열어 재확인한다.

사전조회 격리 후 같은 현품표의 신규 시작은 완료된 PIN intent와 격리 파일로 차단한다. 보류 목록에서 원 작업자 또는 관리자가 복원하면 원 FIFO를 활성 hold로 옮기고 복원 감사·key 결속을 저장한 뒤 같은 현품표를 중앙에서 다시 조회한다. 복원 중단은 `관리자 확인 다시 조회`에서 이어간다. 복원에 웹 PIN을 추가하지 않았으며 PIN action 분류는 후속이다. 원본만 남은 손상·미식별 건은 관리자 인계 목록에서 중앙 조회와 감사 결속으로 해당 현품표만 보류한다.

완료의 [저장 결과 적용·notice](tray-completion.md)는 기존 내구 generator 순서를 유지한다.
prepared checkpoint → 기존 중앙 attempt → 완료 계약/CSV ACK → state 적용/표시와,
최종 held 감사 ACK 뒤 완료 접수·동일 command 재시작/중앙 retry를 각각 보존한다.

처리 중 오류 뒤에는 고장 기록과 원본 격리, 옛 처리기 종료를 확인한 경우에만
“처리 중 오류로 이 트레이를 따로 보관했습니다. 관리자 확인 대기 — 다음 트레이를
계속하세요.”를 표시한다. 격리 건은 UNKNOWN이며 보류 목록에서도 다시 처리하지
않는다. 관리자에게 원본과 기록을 넘기고 다음 현품표를 스캔한다. 기록·격리 실패나
옛 처리기 미종료, 10분 안 세 번째 또는 같은 현품표의 두 번째 고장이면 현 작업을
멈춘 채 관리자에게 문의한다. 실제 화면·장치 수용은 headless 시험과 구분한다.

- W2 B03 headless 검증 묶음은 기존 803개에 [경고·완료 표시 통합시험](../../tests/test_warning_presenter_headless_integration.py) 13개를 포함한다(총 816개). 저장 실패·감사 순서·표시/목록 보존 assertion을 유지하며 실제 GUI 검증과 구분한다.

- 일반/held 스캔의 상태 저장·감사, 제품 입력의 유휴 해제·오류 기록, GUI 완료 checkpoint와 CSV fsync는 기존 직렬 lane worker에서 실행한다. 수량·성공음은 상태 저장 ACK 뒤 반영하며 완료는 내구 기록 후 확정한다. 저장 중 들어온 다음 입력은 입력창에서 꺼내 순서대로 보관했다가 저장 뒤 처리하고, 처리할 수 없으면 오류음과 `다시 스캔` 안내로 거절한다(입력창에 남겨 다음 스캔과 붙이지 않는다). `완료 처리 중`에 한 스캔도 오류음과 안내를 낸다. 리셋·보류 등 작업 전환과 정상 종료에서도 보관 스캔을 조용히 버리지 않는다(전환 안내 뒤 안내, 종료는 안내 창 뒤 닫기). 완료 처리 중 중앙 이적 전송은 한 번의 3초 한도 안에서만 기다린다. 서버가 답하지 않으면 로컬 완료로 끝내고 밀린 전송은 다음 완료·재시작 때 원 key로 순서대로 보낸다([규칙](contracts.md#ca-completion-wait)). 정상 종료는 lane→held writer→event writer 순서로 진행 중 저장을 정리하며, 새 epoch에 오래된 결과를 적용하지 않는다. 동기 복구·시작/설정 등 다른 저장 경로가 모두 비동기로 전환된 것은 아니다.

- 일반 이벤트 저장 실패는 200ms UI 상태 확인을 통해 저장 실패·재시도 안내를 표시하고, writer는 대기/재시작 때 `events/_event_outbox`의 원 payload를 재생한다. writer admission의 5초 mutex timeout·fence 거절로 사본 저장에 진입하지 못하거나 사본 쓰기가 실패한 경우도 접수는 False이며 메모리에 원 payload/key와 순서를 유지하고 저장 공간 확인·PC 종료 금지를 안내한다. 메모리에만 남은 사건이 있으면 정상 종료를 거부하고 writer 재시도를 계속한다. admission을 다시 얻거나 사본 저장만 성공한 시점에는 복구 완료를 표시하지 않으며, 원 사건의 내구 CSV append(동일 key의 기존 행이면 fsync)와 사본 정리가 모두 성공한 뒤에만 표시한다. 사본이 내구 저장된 append 실패는 재시작 복구 가능하며, 전원 차단 시 메모리만 남은 사건까지 보존한다고 주장하지 않는다.

- 최고 기록은 양의 유한 시간만 표시한다. 잘못된 값은 제외하고 시작 시 안내하며, 정리/새 기록으로 덮어쓰기 전에 설정 폴더의 `best_time_records.json.bad-*`에 손상 원본을 보존한다. 읽기/정리 저장 실패 시 원본을 유지한다.

아래는 현재 복구 분기와 다음 확인할 결과다. 자동 복구 코드 존재만으로 실행 PASS를 부여하지 않는다. 작업자는 원본 현품표·실물·작업자·컴퓨터·현재 표시를 유지하고, IT/CA 담당은 해당 state·intent·receipt·오류 사유를 연결한다. 고객 데이터나 비밀을 포함한 원본 전체를 보고서에 붙이지 않는다.

| 상황 | 현재 처리·보존할 경계 | 인계·종료 확인 |
|---|---|---|
| 첫 준비 또는 품목 갱신 실패 | onboarding 보고/검증 cache 진단; 유효 cache 없으면 시작 중단 | 같은 사용자·정확한 profile·연결 상태와 cache 분기 확인. [CA-01~02](README.md#ca-01) |
| PHS2 중앙 조회 지연/오프라인 | 연결 실패(통신·5xx)는 hold `LOOKUP`·끊김 표식 저장·제품 입력 계속·현재 현품표 30초 자동 재조회. 다음 현품표를 스캔하면 원본·FIFO를 기존 보류 목록으로 이동·감사(PIN 없음, 승인 효과 없음). 대기 건수 제한은 없으며 조회 중·조건 불충족은 미접수 | 현재 현품표는 연결되면 자동 drain. 대기는 **연결되면 그 현품표를 다시 스캔**한다(원 작업자, 확인창 없음). 제품은 다시 스캔하지 않는다. 보류 목록의 `서버 확인 대기`·CLC/LBL 끝 4자리·제품 수와 안내의 대기 수로 구별한다. drain 거절 경고의 바코드(형식 오류는 보류 순번)로 해당 제품을 찾아 뺀다. 재시작도 끊김 표식 hold는 자동 재조회. [CA-04](README.md#ca-04) |
| 사전조회 실패로 다른 현품표 작업 필요 | 끊김 표식 중에는 PIN 격리 메뉴가 꺼진다. 안내대로 다음 현품표를 스캔한다. 확정 거절·PC 로컬 오류의 `LOOKUP_FAILED`는 기존 온라인 관리자 PIN·격리·동기 감사 유지 | 과거 PIN 미확인 보류는 복원 거부 사유에 PIN을 명시한다. 연결 후 `관리자 확인 다시 조회`에서 확인하고, 미확정 인계가 남으면 원본을 보존해 IT 담당자에게 인계한다. 이 현품표는 계속 보류하고 다른 현품표 작업을 진행한다. [CA-G14](BACKLOG.md#ca-g14) |
| 로컬 관리자 PIN 확인 실패·응답 불명 | 관리자 ID·가린 6자리 PIN을 같은 동작/원본/작업자에 결속하고, 요청 intent를 fsync한 뒤 서버 소비 상태를 같은 key로 다시 조회 | 화면의 `관리자 확인 다시 조회`에서 원 효과를 확인한다. `이 건만 보류하고 다른 작업 계속`은 `UNVERIFIED_DETACHING` 기록 뒤 형식별 원본 이전·readback·활성 해제를 수행하고 성공한 경우에만 완료 감사와 `UNVERIFIED_OPERATOR_HOLD`를 기록한다. 중단 뒤 재시작은 같은 intent로 이어가며 실패·미지원 형식은 원인 표시와 잠금을 유지한다. 해당 key의 원본·intent는 남고 다른 현품표는 분리 확인 뒤 시작한다. PIN 잠금은 root 웹 해제, root 자신의 잠금은 서버 CLI 인계. 중앙 retry에는 이 PIN을 요구하지 않는다. [CA-C01](contracts.md#ca-c01) 잠김·장비 제한·모르는 거절도 같은 보류 선택을 제공한다. PIN 회복 뒤 같은 작업자로 관리자 확인 다시 조회를 선택하면 원 요청과 보존 원본을 유지한 채 기존 승인·완료 경로로 정리한다. |
| `DRAINING` hold/current 불일치·인계 기록 손상 | 운영 작업에서 관리자 코드 확인 → 두 원본 바이트·SHA256 내구 기록/readback → 동기 감사 → 원본 이동/readback; 이후 기록/원본/표지별 재검증 | 단계 실패·부분 이동이라도 두 key가 식별되면 그 쌍만 보류하고 다른 현품표를 허용한다. 기록이 사라져도 원본/표지를 고아 쌍 행으로 표시한다. 관리자 행에서 원 key 영수증 재확인·이 건만 보류를 선택한다. key를 전혀 식별할 수 없으면 두 원 현품표 스캔→중앙 읽기 전용 조회→별도 내구 보류 전까지 작업대 잠금을 유지한다. 바뀐 stale-current는 처음/변경 바이트를 모두 보존·감사하고 이 건만 보류한다. 실제 화면·중앙 결과는 별도 검증한다. [CA-G14](BACKLOG.md#ca-g14) |
| lease 없는 신규 완료·부분 집합 | 표준 PHS2 완료 차단; 목록·문맥 유지 | 중앙 GOOD 전량·barcode↔unit·lease binding 확인. 오프라인 무조건 신규 작업 허용이 아님. [CA-07](README.md#ca-07) |
| 유효 lease 이후 중앙 연결 단절 | 내구 intent·`LINKED`·checkpoint와 원 명령으로 후속 시도. 복구 뒤 새 완료·재시작 없이 lane이 한가할 때 30초마다 3초 한도로 자동 재전송([배경 재전송](contracts.md#ca-background-seal-retry)), 화면은 `서버 전송 대기 N건` | local completion 유무에 맞는 입력 guard 확인. 이미 로컬 완료한 건은 원 key와 완료 시각을 유지해 재조정. [CA-12](README.md#ca-12), [CA-C03](contracts.md#ca-c03) |
| 응답 유실·중앙 정합 충돌 | receipt 조회/원 요청 재생 또는 `OPERATOR_REVIEW` | scope/key/expected version·exact 결과 대조. key 변경·실물 임의 재처리로 충돌을 우회하지 않음. |
| 완료·중앙 제품 교체 미확정으로 현재 작업대 정지 | 운영 작업에서 원 scope/key의 결과 재확인 또는 관리자 인증 후 원 current snapshot의 parked readback·감사 인계 | 다른 현품표는 계속하고 원 현품표 신규 시작은 차단. 복원 시 같은 요청·스캔·영수증으로 대조하며 조회 실패를 성공으로 표시하지 않음. [CA-G14](BACKLOG.md#ca-g14) |
| 취소/리셋 쓰기 실패 | checkpoint 실패면 목록 복원, CSV 실패면 저장된 동작 유지·감사 outbox 재생, 지연 callback 무효화 | 목록·개수·원본 상태가 일치해야 종료. 리셋은 이미 중앙 확정한 물류의 취소 명령이 아님. [CA-08](README.md#ca-08) |
| 보류·복원 중 종료/손상 | current/parked/hold의 파일별 바이트·구조 검증, 보존·격리·defer; 소유자·같은 현품표 중복 확인 | 손상 parked는 건강한 목록을 비우지 않고 파일명·원인을 표시한다. 관리자 중앙 재조회·이 건 보류 후 원본을 유지한다. 복원 대상 내구 저장/감사와 원본 정리 순서를 대조한다. [CA-09](README.md#ca-09) |
| 손상 parked 또는 원본 없는 관리자 marker | 보류 목록의 확인 필요 행 → 관리자 원 현품표 스캔 또는 표시된 label 확인 → 중앙 읽기 전용 조회 → 동기 감사·marker readback | 손상 parked 복원은 원 바이트를 제자리 보존한다. 원본이 없어도 marker가 같은 key의 신규 시작을 막는다. 감사 실패면 완료 안내 없이 같은 행에서 다시 시도한다. 보류 폴더 경로가 Windows 한도를 넘어 식별 기록을 쓸 수 없으면 그 사실과 '이 현품표만 계속 보류'를 안내하고 원본을 그대로 둔다([이름 길이 규칙](contracts.md#ca-c01)). 다른 식별된 현품표는 계속한다. |
| 원자 저장 중단의 `.json.<pid>.<uuid>.tmp` 또는 교환 journal `.json.<random>.tmp` | parked 보류 목록 또는 관리자 짝 원본 목록에서 원본 SHA256·key·최종 파일 유무 확인. key 한 개면 현품표 한 장 스캔→중앙 읽기 전용 조회→동기 감사→그 key만 보류; 두 key면 기존 짝 흐름. | current/hold/parked/짝 표지와 이벤트 outbox·교환 journal의 임시파일은 최종 파일로 자동 승격하거나 복원하지 않는다. 최종 파일이 있으면 별도 격리 감사한다. 읽을 수 있는 빈·key 없는 임시파일은 원 바이트·SHA256을 보존·감사하며 전체 PHS2를 막지 않는다. 읽기 자체가 실패한 근거는 관리자 확인 전까지 보류한다. |
| 로컬 CSV·디스크 쓰기 실패 | 완료 기록 실패의 `LOCAL_EVENT_RETRY`, 상태·완료 ID 유지 | 쓰기 가능 복구 후 동일 완료 사건의 중복 억제 확인. JSON·SQLite·CSV를 단일 transaction으로 가정하지 않음. [CA-C01](contracts.md#ca-c01) |
| relay pause·저장 압력·stale claim | queue/status/spool 보존, `blocked_disk_pressure`·backpressure·retry 상태 | 디스크/queue 원인과 operator pause를 구별. receipt 검증 전 spool 삭제 금지. [direct_sync_runtime](../../direct_sync_runtime.py) |
| 상주 relay 부재(`container_audit_user_relay.json`이 `RUNNING`에서 멈춤, relay 프로세스 없음) | 앱을 정상 종료 후 다시 실행하고 시작 보고의 `resident_relay`가 `START_REQUESTED`·`RUNNING`인지 확인 | 토큰을 잡은 가장 오래된 `retry_wait` 행이 같은 metadata로 먼저 재전송되고 나머지는 새 토큰으로 간다(서버 행 중복 없음). 앱 전송은 새 행만 겨냥하므로 작업이 이어지면 새 줄이 없는 relay 주기에 따라잡는다. `STOP_REQUESTED`·`NOT_REGISTERED`면 설치·제거 절차를 확인하고 표식이나 Run 값을 임의로 고치지 않는다. [CA-G18](BACKLOG.md#ca-g18) |
| committed ingest 오류·격리·투영 지연 | 엄격 receipt 미충족은 ACK 성공이 아님; review/영구 실패 구분 | 서버 원본 trace와 행 합계·projection 결과 확인; 단순 HTTP 성공이나 재전송 횟수로 해결 판정하지 않음. [CA-C05](contracts.md#ca-c05) |
| 봉인 전 제품 교체 중 종료/경쟁 | 1~2쌍 CAS·intent·exact receipt 후 로컬 적용 | 전체 구성원/원본 label identity와 중앙·로컬 일치 확인. 부분 로컬 교체 금지. [CA-10](README.md#ca-10) |
| 출력 일부 성공·결과 불명 | print journal·artifact·중앙 exchange 재조회/확인 | 재출력 필요와 이미 출력/활성화 여부 확인, 종이까지 별도 대조. [CA-11](README.md#ca-11) |

장애 인계의 완료 기준은 미해결 상태마다 업무 ID·마지막 내구 경계·중앙 확인 여부·담당·다음 행동이 남고, 복구 후 중복 효과/분실 없이 허용 상태에 도달하는 것이다. 허용 대기시간·교대 인계 책임자·장애 알림 수준은 [CA-G06](BACKLOG.md#ca-g06)의 미정 요구다. 실행 검증은 [CA-G04](BACKLOG.md#ca-g04)와 별개로 추적한다.

<a id="ca-o05"></a>
## CA-O05 설치·교체·재설치·롤백·백업

설치 기록과 등록에 사용한 서버 주소가 다르면 「설치 주소가 바뀌었습니다. 관리자에게 알려 주세요.」로
시작을 중단한다. 이미 완료한 기계 설치나 상주 relay가 있어도 새 시작에서 재사용하지 않는다.
관리자가 설치·등록 대상을 확인해야 하며 자료·대기열 삭제나 자동 재등록은 하지 않는다.
주소 기록이 없는 옛 설치는 비교를 건너뛴다. 기존 상주 relay의 종료 정책은 유지한다.

설치된 입구·상주 전송 프로그램의 readback을 통과한 뒤 작업자 바로 가기를 준비한다.
작업자 세션 설치기는 그 사용자의 바탕화면·시작 메뉴를 처리하고, 기존 권한 상승 helper의
기계 단계는 공용 바탕화면·공용 시작 메뉴를 처리한다. 대상이 이 앱의 설치 루트 아래이며
그 파일이 없는 `.lnk`만 그 자리에서 `current/launch-container-audit.cmd`로 바꾼다.
다른 앱·다른 설치 루트·존재하는 파일을 가리키는 바로 가기는 보존한다. 공용에 이 앱의
바로 가기가 없으면 「이적 검사」를 두 공용 폴더에 만든다(같은 이름의 다른 바로 가기는 보존).
앱 아이콘 `app/assets/logo.ico`와 최소화 창 상태를 사용하며 인수는 비워 둔다.

원 대상·인수·아이콘은 `worker-shortcuts-<설치 루트 식별값>.json`에, 원 `.lnk` 바이트는
그 JSON 옆 `.preimages` 폴더에 변경 전에 보존한다. 사용자 기록은 업무 루트의 `install-audit`,
공용 기록은 보호된 `update-control/worker-shortcuts`에 둔다. 옛 실행 파일을 복원하는 되돌림이나
제거 뒤에는 원 바이트를 복원하고 새로 만든 링크는 삭제한다. 앞 portable 판도 같은 입구를
쓰는 복원은 링크를 유지한다. 설치 뒤 사람이 다른 대상으로 바꾼 링크는 덮어쓰지 않고
복구 미확인으로 남긴다. 관리자 직접 설치의 사용자 프로필 처리는 첫 시작 onboarding에서
`Install-BootstrapWorkerShortcuts(..., 'User')`를 받을 자리이며 이 변경의 구현 범위에는 없다.
PS5.1·PS7 검증은 격리 known folder에서만 수행하며 실제 화면·현장 설치는 별도 확인한다.

| 설치 코드 배치 전 실패 코드 | 작업자 안내·조치 |
|---|---|
| `CONTAINER_PLACEMENT_OTHER_SESSION_RUNNING` | 같은 PC 의 다른 Windows 사용자 세션에서 이적 검사 프로그램이 실행 중입니다. 그 사용자를 로그아웃한 뒤 다시 설치하세요. |

검증된 교체의 전 세션 프로세스 확인에서 상승 자식과 다른 Windows 세션의 제품
프로세스가 확인되면 코드 교체 전에 이 코드로 중단한다. 기존 상승 로그의
`PREFLIGHT_FAILED`로 부모에게 전달하며 문의 코드·기록 보존·다른 업무 계속 안내를
유지한다. 같은 세션만 남았거나 세션을 확인하지 못한 경우의 거부와 제거·복원
경로는 기존대로다. 실제 다른 세션 로그아웃 후 재설치는 [CA-G15](BACKLOG.md#ca-g15)의
현장 확인에 포함한다.

공개 canonical 설치는 작업자 계정에서 prepared receipt에 작업자 SID·LOCALAPPDATA
루트와 session/attempt/transaction을 기록한다. 상승 helper는 그 receipt의 SHA와
등록된 SID 프로필 경로를 대조해 같은 작업자의 fence root를 선택하고, 해당 root의
기존 `Local\KMTech.ContainerAudit.WriterAdmission.v1` admission 이름을 유지한다.
잘못된 SID·root·만료 시도·경쟁 writer는 코드 배치 전에 중단한다. 이 조치의
PowerShell 격리 시험은 **PROVEN**, 표준 사용자에서 별도 관리자로 UAC 승격하는
guest 실물 설치와 ACL 접근은 **NOT TESTED**다. 기존 HKCU·DPAPI·업무 원장·relay는
작업자 계정에 남는다. 중단 메시지는 원인과 작업자/PC/attempt에서 파생한 문의 코드,
재확인·보류 안내를 제공하며 기존 설치본과 기록을 보존한다. 파일 접근·ACL·경로·상승 결과 로그 쓰기/읽기·결과 로그 없는 자식 비정상 종료와 분류되지 않은 오류를 각각 안전 코드와 문의 코드로 안내한다. 로그 쓰기 실패는 상승 자식의 전용 종료 코드로 전달하며 기존 설치본·fence 거부·롤백 경계는 유지한다. [CA-G15](BACKLOG.md#ca-g15).

예약 작업 census는 정식/qualification 작업 이름, 명시된 direct-sync/user-relay 실행 모드 또는 `tools/direct_sync_relay_runner.py` 직접 호출 action으로 writer 후보를 식별한다. 직접 script Execute는 유지하며, 인수에서 script를 찾는 경우에는 Python/py/venv 실행 파일을 확인한다. Windows quoting과 `-u`/`-B` 등 옵션·옵션 값을 처리한 첫 script 경로를 작업 디렉터리 기준으로 정규화해 기존 검증된 writer inventory의 Python `.main` route 목록과 비교하며 다중 action도 검사한다. `-c`/`-m`/stdin·도움말·버전 모드의 후속 인자와 Notepad·탐색기·다른 실행 파일이 같은 소스를 여는 작업은 제외한다. null/빈 trigger 및 CIM 속성 부재는 안전하게 정규화하며, 잘못된 writer가 활성 상태이면 `NONCANONICAL_WRITER_ENABLED`로 계속 차단한다. 정식 writer의 이름·루트 TaskPath·실행/사용자/trigger 계약과 기존 binding SHA256을 유지한다. PS5.1 모의 목록과 설치기 회귀는 [분류 시험](../../tests/test_scheduled_writer_classification.py)으로 고정하며 실제 guest 재설치는 별도 수용이다.

배포 상태를 바꾸는 절차는 [INSTALL_THIS_PC.ps1](../../INSTALL_THIS_PC.ps1)이 소유한다. 기본 경로 검증, 코드 inventory/manifest hash, writer quiesce/fence, 검증된 기존 portable 교체·복원, uninstall의 복구 사본 처리 분기가 있다. `ReplaceExistingVerifiedPortable`, `ProbeVerifiedReplacementRestore`, `RestoreVerifiedReplacement`, `Uninstall`은 서로 다른 모드다. 이 문서는 명령 실행 지시나 빈 인자로 사용할 예시를 만들지 않는다. 실제 대상·receipt·원본 hash와 기존 실행 권한을 연결한 작업에서만 해당 모드를 선택한다.

**현재 소스의 공개 사후 복원:** [canonical controller](../../INSTALL_CANONICAL_PORTABLE.ps1)의 `-RestoreVerifiedReplacement -RestoreReceiptPath <실제 원본 경로> -RestoreReceiptSha256 <원본 SHA256>`는 교체를 만든 정확한 successor packet에서 실행한다. 새 session/attempt/controller transaction·현재 시각 prepared receipt·writer fence를 만들고 현재 사용자의 정상 removal/quiescence 뒤 기존 lower helper의 receipt-bound 코드 복원을 호출한다. 입력 receipt의 교체 transaction은 새 controller transaction과 별도로 기록한다. 현재 Run 값의 원본은 fresh fence 안에서 복원·검사하고, fence 해제를 확인한 뒤 기존 relay의 정확한 명령으로 process를 시작한다. onboarding·재등록·credential/업무 DB 복사는 하지 않는다. `PENDING` 또는 정확한 `RESTORED` 상태만 지원하고, code root 부재인 `DISPLACED`·legacy scheduled writer·code/record/ACL/선택 경로 drift는 거부한다. 완료 상태는 `PASS_RESTORED_VERIFIED_DATA_PRESERVED`; 실패 뒤 검증된 surviving code에서 runtime만 회복한 경우 `FAILED_RESTORE_RUNTIME_RECOVERED`이며 성공으로 해석하지 않는다. 코드 상태를 확인할 수 없으면 writer fence를 유지한다.

사후 복원은 `.current.rollback.<receipt transaction>`·`.current.failed.<동일 transaction>`과 current만 읽고 이동한다. 관계없는 과거 rollback/failed tree는 보존하며 선택된 경로 충돌, parent 경로/ACL, 선택 tree의 recursive reparse·manifest·aggregate·integrity record hash 검사는 유지한다. 성공 교체의 `READY_PUBLIC_CANONICAL_RESTORE`는 이 공개 경로가 준비되었다는 상태이며 실제 guest 복원 수용은 아래 CA-O09에서 따로 기록한다.

업데이트 알림은 [schedule_update_check 및 배포 정책](../../Container_Audit.py)을 따른다. 일반 사용자 설정으로 updater provider/권한을 변경하거나 코드 루트를 덮어쓰지 않는다. 코드 rollback tree는 업무 DB의 rollback과 별개다. 설치/제거/복원 코드의 존재가 재설치 후 current·parked·미전송 자료 보존을 입증하지 않는다. 목표 후보의 설치→첫 업무→종료/재시작→교체/복원→동일 업무 상태 확인은 [CA-G04](BACKLOG.md#ca-g04), [중앙 Q07](../../../Program_Spec_Hub/BACKLOG.md#qualification)에 남아 있다.

백업·복원의 **필요 범위**는 업무 events/local_events, current·parked·hold, seal/lease/member-exchange intent와 출력 journal, relay queue·spool·receipt/status, 사용자 설정·작업자 귀속 자료다. 정확한 파일 위치는 실제 해석된 `storage_paths`와 coordinator store 경로로 확인한다. SQLite의 열린 WAL 등 일관성 경계도 확인해야 하며, 실행 중 파일을 임의 복사하는 방식을 검증된 백업으로 제시하지 않는다. 사용자 DPAPI 자료는 같은 계정/장비 문맥과 복구 정책이 필요하므로 단순 파일 이동으로 인증 복원이 된다고 보지 않는다. [storage_policy](../../storage_policy.py), [current_user_onboarding](../../current_user_onboarding.py), [TransferSealStore](../../transfer_seal.py), [CA-C01](contracts.md#ca-c01).

승인된 백업 주기·보관기간·복원 책임·RPO/RTO·계정/PC 손실 시 복구 방법은 미정이다. 저장 압력을 이유로 current/parked·미확정 intent를 자동 삭제하지 않는다. [DIRECT_SYNC_DATA_PLATFORM_NOTES](../../DIRECT_SYNC_DATA_PLATFORM_NOTES.md)의 `acked_retention`은 읽기 전용 현황이고 `acked_relay_retention_candidates`도 삭제 권한이 아니다. ACKED spool/status cleanup은 receipt 재시도 안전성 확인 전까지 유보된 사항이다. [CA-G06](BACKLOG.md#ca-g06).

<a id="ca-o06"></a>
## CA-O06 성능·동시성·최신성의 요구와 한계

| 대상 | 현재 코드의 제한/동작 | 승인 목표·측정 |
|---|---|---|
| 입력 문자열 | GUI 기본 최소 길이 13, 제품 최대 128자; catalog matcher 자체는 가변 길이·중첩/독립 출현을 지원 | 장비별 문자·연속 스캔 처리율 목표/실측 미확인. [product_scan](../../product_scan.py), [item_catalog](../../item_catalog.py) |
| preflight hold | `_preflight_hold_store`: `max(1, TRAY_SIZE + 8)`; 별도 dispatcher queue는 `max(4, TRAY_SIZE + 12)` | 고정 60개 업무 한도가 아니다. 목표 GOOD 수와 버퍼 용량을 구분. 포화·디스크 지연 실측 미확인. [Container_Audit.py](../../Container_Audit.py) |
| 로컬/중앙 동시 작업 | data-root mutex, 로컬 파일/DB 잠금, 중앙 version CAS·lease | 동시에 운영할 PC 수·허용 경합률/지연 미정. 서버 경합 E2E는 미입증. [runtime_instance](../../runtime_instance.py), [CA-C03~04](contracts.md#ca-c03) |
| relay 저장 압력 | `DirectSyncRuntimeConfig`의 `min_free_bytes`, `max_active_queue_count`, `max_active_queue_age_seconds` 기본 0; 실제 배포값은 별도 | 0을 검증된 무제한 용량이나 승인된 장애 임계치로 해석하지 않음. [direct_sync_runtime](../../direct_sync_runtime.py) |
| relay 반복 prefix | ACK 완료 source의 파일 identity·size·mtime/ctime와 cursor hash가 같으면 마지막 전체 검증 후 300초 미만 재읽기 생략; SQLite 힌트로 새 child 실행에서도 유지 | cursor 변경 시 무효화. 미완료/손상 delta는 매번 기존 복구 경로, 변경 파일은 전체 검사. 같은 metadata의 변조는 기한 후 다음 실행에서 확인하며 즉시 탐지라고 주장하지 않음. [CA-C05](contracts.md#ca-c05) |
| portable 코드 판 확인 | 전체 파일 무결성과 version/build 결속의 성공 결과를 프로세스마다 기억. GUI·상주 relay·raw runner 첫 자료 admission 전에 전체 확인 | 실패는 재확인하고 자료 guard가 거절한다. 실행 중 디스크 코드 변경은 다음 프로세스에서 확인하며, 자료 세대 marker는 매번 판정한다. 실제 현장 HDD의 허가 보유 시간은 미측정. |
| portable relay 자식 시작 | direct-sync 모드만 기존 product host의 `startup_gate(role="relay")` 뒤 runner를 실행하며 `Container_Audit`를 적재하지 않는다. 별도 자식 프로세스·원 인자·writer sink·상태/로그/종료 코드 계약 유지 | 판 확인의 프로세스 간 캐시는 없다. 실제 설치본의 바퀴당 CPU 4초 미만과 HDD 적재 시간은 현장 측정 대상이다. |
| lease 시간 | v1 서명 duration 60초~24시간 검증, 기존 완료의 재검증은 저장된 완료 시각 사용 | 실제 발급 기간·허용 offline 업무시간을 확정하는 값이 아님. [terminal_operation_lease](../../terminal_operation_lease.py), [TransferSealCoordinator._verified_operation_lease](../../transfer_seal.py) |
| 수신→화면 최신성 | whole-file relay·projection·API·렌더의 분리, `pcs_completed`는 관측 완료 수량 | 허용 지연/업무일·누락 경고·복구 후 따라잡기 시간 미정, live 측정 없음. [CA-C07](contracts.md#ca-c07) |

통신 timeout·poll 간격·retry 지연은 구현 파라미터이고 작업자 응답시간 SLA가 아니다. 성능/복구 목표 확정은 [CA-G01](BACKLOG.md#ca-g01), [CA-G06](BACKLOG.md#ca-g06), 실제 측정·장비·후속 설치 입증은 [CA-G04](BACKLOG.md#ca-g04)가 담당한다.

2026-09-09 최적화는 원본 `9e38334f`의 합성 normal/held, catalog 50/1,000개 기준을 먼저 측정했다. [고정 기준·목표](D:/KMTech/optimization-implementation-20260909/Container_Audit/BASELINE-AND-TARGETS.md)는 handler CPU와 실제 파일 저장 companion을 분리하며, field SLA나 실제 VM paint/네트워크 latency를 주장하지 않는다. CA-S1a `920831d` 이후 같은 호출의 held 검색 재사용은 59 focused PASS와 고정 CPU/파일 저장 회귀 목표를 충족했다. 새 held 시험의 disk ACK와 UI callback을 혼동한 최초 2 FAIL도 E 증거에 보존했다. 검색은 held 한 건 2→1회, 8건 16→8회이며 저장/SCAN_OK/ACK 횟수는 같다. [전후 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/RESULT.md)와 실제 VM Computer Use 전체 업무 수용 [CA-G12](BACKLOG.md#ca-g12)를 구분한다.

2026-09-11 [잔여 native 실행 준비](D:/KMTech/optimization-implementation-20260909/Container_Audit/remaining-goal-prep-20260911/PLAN.md)는 기존 local 목표를 유지하며20쌍/40arm의 행동별 경험적 분포를 별도로 설계했다. 동일50행 입력·원본9e/최종2b·AB/BA 순서와 기존3ms/문자·50ms poll을 고정하고 startup/로그인과 실제 Return 이후를 분리한다. 경험적p95는19/20순위이며 population 꼬리 보장이 아니고, 다음 실제 접수 상한에는 controller 대기가 포함되어 최초 허용 시간으로 해석하지 않는다. 정확한 전체 표시와 내구 결과를 함께 확인하며 실패·timeout·부분 갱신·부하 차이를 제외해 성공 표본을 채우지 않는다. unsigned 입력·경로 delta와 parser만 host에서 확인했으며 실제 측정·guest·서명·전송은 미실행이다. Main이 방법 검토와 실제 충돌 자원을 배정하고, 별도 정상 연결 업무는 진짜 M06 수신GOOD1·중앙 봉인 ACK·후속 Label/Web 영수증을 사용한다.

<a id="ca-o07"></a>
## CA-O07 2026-09-08 FULL 실패의 환경·fixture 경계

- `tk_serial_ui_lane`/PHS2 preflight headless fixture는 assertion 실패에도 `finally`에서 소유 lane·hold writer를 drain/close하고 잔존 thread를 검사한다. `TaskHandle.join(timeout)`의 bool은 작업 완료만 뜻하므로 테스트는 별도로 UI 적용(hold 파일과 최신 snapshot 일치 포함)을 기다린다. 제품 lane은 non-daemon이며 정상 창닫기의 기존 drain 순서를 유지한다.

화면 `mainloop`의 예외·직접 반환·종료 접수 후 조기 반환도 새 접수를 닫고 기존 Tk 소유 결과 pump로 lane·보류 writer를 정리한 뒤 감사 writer를 기다린다. 5초는 종료 지연 표시를 남기는 시점이며 유한 작업은 결과 적용과 worker 종료까지 계속 기다린다. 원 예외와 `SystemExit` 코드는 정리 오류로 덮어쓰지 않으며 이미 정상 종료한 자원을 다시 닫지 않는다. Tk가 이미 파괴되어 늦은 표시를 적용하지 못해도 기존 checkpoint·감사 outbox·중앙 전송 intent를 삭제하지 않는다. 배경 thread가 끝나기 전에는 실행 mutex handle을 유지한다. 영구 정지는 데이터 루트의 `shutdown-stalled.json`으로 표시하며 같은 PID/실행 파일이 살아 있을 때 재실행 안내를 바꾼다. 창이 닫히고 앱이 다시 안 켜지면 PC를 재시작한다. 표시 생성·삭제는 일반 writer sink이며 정상 시작에서 삭제 실패는 시작을 막지 않는다. 재시작은 기존 내구 복구 경로를 사용하며 정리 완료를 중앙 ACK로 해석하지 않는다. 동기 파일 I/O 자체의 실행 시간 상한은 보장하지 않는다.

[실패 분석 보고](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/REPORT.md)와 [102개 testcase 색인](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/failure-inventory.tsv)은 원래 VM01 FULL의 회수 원본을 사용한다. 102 FAIL/2,526 PASS/31 SKIP, pytest 자연 종료 1, FULL·일반 export FAILED를 유지한다. forensic 25파일 회수 성공은 정상 export나 qualification PASS가 아니다.

| 관측 | 원인·다음 교정의 범위 |
|---|---|
| PS5 출력 81 실패 | [기존 helper](../../tests/powershell_contracts.py)에 UTF-8 producer와 양쪽 stream의 strict consumer를 구현했다. `-File` 대상은 quoted `-Command`에서 원 script scope로 호출하고 native exit·argument·개행을 보존한다. reader thread에서 stream을 잃는 대신 decode 오류가 호출 thread에서 실패한다. locale 추정·ignore/replace·None fallback은 없다. 실제 guest codepage는 여전히 미확인이다. |
| relay PID 12 실패·24개 잔류 | native base interpreter를 CPython venv launcher 환경으로 직접 실행하며 `os.getpid() == Popen.pid` assertion을 유지한다. context manager가 시작 확인·preimage assertion 전부터 cleanup을 소유하고 초기 relay stdout/stderr를 저장한다. delegated onboarding startup 실패도 소유 child를 종료한다. 원래 VM 잔류 24개와 이번 host child 정리는 별도 근거다. |
| Git provenance 7 실패 | 원래 `.git`의 HEAD/config만 있는 inventory는 불변이다. 새 E checkout은 genuine main history bundle에서 준비한 commit/object/ref/index와 명시된 fixture/doc 변경을 가지며 기존 7개 사례가 PASS했다. 후보 tree·index 및 커밋 전 상태는 [후보 보고](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)에 기록한다. 임의 HEAD나 provenance bypass는 없다. |
| 완료 재시도 일일 집계 1 실패 | 승인된 [clock diff](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/fixture-clock-proposal.patch)를 저장소에 적용해 `date.today()`와 `datetime.now()`를 같은 fixture 시각으로 묶었다. 기존 두 사례는 새 [초기 경계 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/boundary-01/junit.xml)에서 모두 PASS이며 제품 구현·assertion은 동일하다. |
| exact executable fixture 1 실패 | genuine base executable을 복사·hash 대조하고 archive hash·native PID/image path·wrong-image/hash 거부를 유지한다. identity JSON과 child stdout/stderr를 보존한다. 새 host 경계 사례 PASS는 원래 25개 회수 파일에 없던 내부 실패 사유를 소급 입증하지 않는다. |

Main grant `msg_22a3607bde7e`에 따른 [정리 결과](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-failure-triage/CLEANUP-RESULT.md)는 모든 24개 native handle의 birth/SID/session/executable/command hash·parent 및 unknown descendant 부재를 확인한 뒤 interpreter 12개만 직접 종료했다. 원래 로그 25개와 신선한 before identity를 E에 보존했다. PS5 JSON array admission 실패와 뒤이은 launcher 3988 재확인 실패는 FAILED로 남기고, 별도 PSDirect session의 최종 읽기가 24개 부재·closure empty·원래 Explorer 4184 불변을 확인했다. 새 kill/VM 상태 변경 없이 Main의 VM01 해제 판단으로 넘겼으며 원래 FULL FAILED는 그대로다.

2026-09-08 구현·검증 후보의 실제 범위는 [CANDIDATE](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/CANDIDATE.md)에 연결한다. 초기 경계 14 PASS, authentic Git 7 PASS와 별도로 긴 E root의 PS5 MAX_PATH 실패(첫 계약 실행 176 PASS/7 FAIL/3 capability SKIP, 짧게 조정한 in-root retry 2 FAIL 후 중단)를 보존한다. 첫 실행의 기록된 native relay PID 34개, retry의 4개에 대한 유한 관측은 active owned 0이다. 독립 검토와 승인된 소스 마감은 [ACCEPTANCE](E:/KMTech/ca-rp-0908/ACCEPTANCE.md)로 후속 연결하며, target FULL·installer/backend qualification·VM access는 이번에도 수행하지 않았다.

최종 [short E/Windows venv 실행](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03.xml)은 **204 PASS / 3 capability SKIP / FAIL·ERROR 0 (207개)**다. 원래 102개 실패 node 중 100 PASS·8.3 alias capability SKIP 2개이며, PID 12개와 Git 7개는 모두 PASS했다. [유한 child 관측](E:/KMTech/coordinator-handoff-20260907-01a07992/repo-parallel-0826/ca-fixture-candidate/focused-03-children.json)은 기록된 relay PID 37개 중 active owned 0이다. 원래 FULL FAILED·guest codepage/원래 exact-artifact 내부 사유 미확인·대상 FULL NOT TESTED를 유지한다.

후속 source는 [SUCCESSOR-MANIFEST](E:/KMTech/ca-rp-0908/SUCCESSOR-MANIFEST.json)의 실제 commit/tree와 genuine Git history bundle·object archive로 식별한다. 원래 bundle/patch/archive와 provider cache는 보존한다. 기존 host 실행과의 차이는 정확히 세 명세 경로의 설명이며 전체 문서를 임의로 실행 입력에서 제외한 판정이 아니다. 원래 child 관측의 세부는 **36 ABSENT·1 PID_REUSED_NOT_OWNED**, active owned 0이며 새 live 관측으로 쓰지 않는다. 이전 [TARGET-HANDOFF](E:/KMTech/ca-rp-0908/TARGET-HANDOFF.md)는 이력으로 보존하고 guest E 경로 혼용을 해결한 [최신 control·명령·입력 준비](E:/KMTech/ca-target-rp-0908/REPORT.md)를 현재 실행 인계로 사용한다. 새 VM 배정·실행은 Main 소유이며 소스 마감만으로 build·설치·GUI·backend 또는 Ready를 올리지 않는다.

최신 packet은 VM01의 기존 E-backed 가상 디스크 안에서 focused `C:\Qualification\ca207`와 조건부 FULL `C:\Qualification\cafull`을 별도 새 lane으로 사용한다. 동일 `e1db07a`의 archive/bundle을 각 `s`에 재구성하고 481개 source byte·실제 commit/tree/ref/index를 대조한다. Main의 새 support 관측 없이 과거 provider hash를 사용하지 않으며, 이전 57개 identity와 원래 FULL 24개의 native birth도 새 admission에서 부재를 확인한다. 과거 추가 `utf_8_sig.cpython-312.pyc`는 정확히 그 경로의 현재 존재·hash만 별도 기록하며 원래 보존 FAILED와 writer UNPROVEN을 유지한다. 실제 target의 profile/SID·Explorer birth·task/provider 경로가 다르면 중단하며 다른 VM에 자동 치환하지 않는다.

원래 owner/observer와 native exit·default capture를 유지하고 45개 고정 export의 합계 상한은 250 MiB다. exact-artifact의 identity/wrong-image/wrong-hash JSON·양쪽 child stream, native venv identity, relay launch 기록을 유한 이름으로만 회수하며 scratch tree 전체를 순회하지 않는다. Main은 native PID/경로를 새로 확인해 ABSENT·PID 재사용·active·UNPROVEN을 구별하고, 실제 focused 207개 ID/phase/skip와 source 보존을 수용한 뒤에만 별도 FULL을 시작한다. FULL 선택은 `tests`, 수집 수는 실제 실행 결과가 정본이다. PS5/PS7 경로·JSON·native ownership와 Git/index·진단의 host control fixture 근거는 준비 보고서에 있으며, 그 준비 시점의 VM/provider admission·제품 실행·FULL 수용은 모두 **NOT TESTED**였다. 후속 실제 실행은 아래 CA-O08과 구분하며 **Ready 0/6**을 유지한다.

<a id="ca-o08"></a>
## CA-O08 VM01 target207의 readonly fixture·image 관측 실패

[실행 보고](E:/KMTech/ca-execution-rp-0908/REPORT.md)의 실제 VM01 admission은 Support8,539개·불일치0·stable, source481 genuine Git Stage와 MainStage13,665개 PROVEN이다. 모든 원본 source 파일을 readonly로 유지한 상태에서 `_portable_release_fixture`가 `copy2`로 복사한 임시 installer도 readonly가 되어, 첫 두 사례의 fixture customization이 `PermissionError`로 끝났다. 207개 수집은 원래 ID 순서와 일치했지만 실제 결과는 **0P/2F/0S, 205개 미실행**, owner/pytest 자연 종료1, supervisor/controller2다. guest PS5의 실제 version은 5.1.26100.7920, input/output codepage949·`$OutputEncoding`20127·culture ko-KR로 기록했다. 이 metadata만으로 예전 decoding81개나 exact-artifact의 내부 원인을 새로 입증하지 않는다.

45/45개·9,218,869바이트의 실패용 Export는 누락/overflow0과 표본 간 일치를 확인했다. 별도 MainFull은 `controller.executable=null`을 정확한 image로 인정하지 않아 **FAILED/Base controller argv differs**이며 `actual=null`이다. argv/cwd는 기대값과 일치하지만 설정한 실행 경로를 실제 image 관측으로 대체하지 않는다. 마지막 Main 표본(2026-09-08T02:47:18.8988799Z)은 source/provider13,666개 불일치0, 원래81 identity inactive, 잔여 lane0·recorded child0이다. 새 kill·task 재시작·provider/VM 설정 변경은 없고 원래 lane·출력은 보존했다.

작은 수정은 공통 fixture의 7개 원본 바이트를 `copyfile`로 임시 packet에 복사한다. 원본 readonly를 풀거나 source hash 검사를 완화하지 않는다. 별도 회귀의 host RED1→GREEN1, 실제 변경 바이트 쓰기를 확인하는 최종 회귀1 PASS/0.22초와 기존 두 영향 사례2 PASS/31.64초, 기록된 relay6개 부재를 [보고·근거](E:/KMTech/ca-execution-rp-0908/REPORT.md)에 남겼다. 별도 E 제어 후보는 이미 보유한 native handle의 `QueryFullProcessImageName` 결과를 사용하며 PS5/PS7에서 실제 image·자연 종료·양쪽 EOF 및 invalid handle 거부를 확인했다. 소비된 제어와 원래 image/native/수용 기준은 보존했다.

Main의 두 수정 방식 수용 뒤 새 [source482 identity](E:/KMTech/ca-execution-rp-0908/successor/SUCCESSOR-MANIFEST.json) `68dd0c520ed2b8bd585301999cb35624702a05a5`를 genuine Git E 사본·bundle/archive로 마감했다. [실행 명령](E:/KMTech/ca-execution-rp-0908/successor/NEXT-COMMANDS.md)은 focused `C:\Qualification\ca207n`과 조건부 FULL `C:\Qualification\cafulln`의 새 packet을 사용한다. 제어 차이는 수용된 image 관측, 경로·task·source482 결속과 기존 실패 `ca207`의 564개 파일·task 결과2·4개 추가 native identity 보존에 한정한다. passive observer·진단 수집·원래207 선택·FULL `tests`와 조건은 유지한다. 두 packet의 해시 결속과 PS5/PS7 구문을 로컬 확인했으며 과거 host suite·image fixture·dependency 설치는 반복하지 않았다. 새 실제 Support hash는 아직 없고 Main의 이 입력 경로 배정 후에만 새 관측·guest 실행으로 진행한다. 현재 C 미커밋 변경과 E 동결 후보를 구분하며 E 후보 마감 뒤 상태 설명은 세 명세의 별도 문서 차이다. 새 guest 결과·별도 FULL·build·설치·재시작·재설치·rollback·backend E2E는 **NOT TESTED**, Ready0/6이다.

위 준비 이후 Main `msg_be980d15a1b6`가 같은 작업의 후속 실행을 배정했다. 실제 focused Support SHA는 `dadb04bcc71dbe0705c9b5d732d95fff33bf7bebc7c579f8e9d04639a123093e`, 원래207 결과는 **207 PASS/0 FAIL·ERROR·SKIP, 296.59초**다. [MAIN-Full](E:/KMTech/ca-execution-rp-0908/successor/packets/focused/logs/MAIN-Full.json) SHA `83e582eb3c7389cfb0a78d86a43cae0c38f180ef433c0c03b19766d7d745f8cd`는 PROVEN/stable·sourceTestsPassed·controlsPassed·processClosure와621 phase,42개 기록 child 부재를 확인했다. controller의 실제 image 조회도 guest에서 성공했으며 설정 경로로 대체한 판정이 아니다. 회수45개·9,972,263바이트/누락0과 source·기존 실패 보존을 확인했다. 충족된 조건과 pin을 Main에 보고한 뒤 별도 FULL의 fresh Support SHA `b17cb8c5576df4cd9e1cb9778237a3ce635187be13c2b35e6757472b3eaf8837`, source482 Stage·독립 MainStage가 통과했고 전체 `tests` 실행 중이다. 원래 실패는 유지하며 이 새 FULL의 결과와 설치·GUI·backend E2E 수용은 별개다.

사용하지 않는 E 구문 검사 도구 두 개는 삭제했다. 성공한 host 회귀의 임시 `readonly-green`·`readonly-green-r2` 출력 정리는 실행 전 자동 승인 검토가 거부해 남아 있으며, 실제 Windows 삭제/AccessDenied는 관측되지 않았다. 범위를 줄인 명령도 사전 거부됐고 ACL·읽기 전용 속성·동일 root 안의 링크·소비자 관측을 [기존 보고](E:/KMTech/ca-execution-rp-0908/REPORT.md)에 남겼다. 이 임시 정리 제한을 실제 제품 시험의 실패로 합치지 않으며 원래 실패·source·회수 증거를 보존한다.

사용자 긴급 정지 후 [재개 작업](E:/KMTech/ca-resume-0908/REPORT.md)은 원래 실행을 보존하고 source68dd/tree5960을 C 저장소에 통합했다. 이후 상태 문서 차이는 실행 입력과 구분한다. 원래 full-Start host 제어는 start와 0바이트 stdout/stderr만 있고 exit 기록이 없어 자연 종료·외부 EOF와 supervisor의 외부 retained-native 종료를 **UNPROVEN**으로 유지한다. 새 관측기 세 건의 중단은 정확한 host image/PID/birth 확인 뒤에만 수행했다. Main이 동적 메모리 상한을 4→10GiB로 조정했으나 실제 할당 증가는 관측하지 않았고 지연 원인·해결의 인과 관계는 미입증이다. guest 테스트 재시작·host 입력·worker의 VM lifecycle/보안 변경은 없었다.

실제 UTC **04:53:15.0572011Z**에 기존 guest 파일 회수가 성공했다. 원래 전체 결과는 **2,638 PASS/31 SKIP/FAIL·ERROR 0, 2,669 collection/JUnit·7,976 phase**이며 최종 guest 파일은 04:29:24Z까지 작성됐다. 기존 Export는45/45개·15,368,109바이트·표본 간 일치·누락/overflow0, 새 Export host21208은 04:57:31.3329354Z 자연 종료0·양쪽 EOF를 확인했다. 기존 독립 reader를 재사용한 [회수 결과](E:/KMTech/ca-resume-0908/MAIN-Full.json)는 원래 source/provider·export·task/action·guest identity·owner/pytest/controller·collection/order/phase/JUnit·fixture/child 검사를 유지했다. 빠진 외부 기록만 명시적 UNPROVEN/null로 남겼으며 대체 natural-Full metadata를 만들지 않았다.

마지막 05:05:04.1286232Z guest 표본은14,231개 대조 불일치0·metadata 문제0, task Ready/exit0, remainingLane 없음, 기록 child42개 ABSENT다. Main이 실제 custody 반환을 수용해 VM01을 다른 lane에 배정했으며 CA는 추가 guest 호출을 하지 않는다. E-drive 조건의 정확한31개 guest SKIP은 동일 source68dd의 별도 host E 검증에서31 PASS/0 SKIP이지만 guest 결과는 유지한다. 원래 native `mklink`/`icacls` 출력을 text로 읽는 fixture 주변 UTF-8 decode thread 경고6건도 보존하며 nested native 진단 출력이 완전하다고 주장하지 않는다. 실제 설치·GUI·restart/rollback·backend E2E는 별도 **NOT TESTED**다.

CA portable builder의 기존 [준비 검사](E:/KMTech/ca-resume-0908/BUILD-PREREQUISITES.json) 뒤 Main `msg_1e237ec7d437`가 host CPython3.12.10 x64와 source `Container_Audit.py:420`의 기존 update 공개키 VALUE를 배정했다. clean source68dd에서 [실제 build](E:/KMTech/ca-build-0908/build-result.json)는05:22:27.615257Z 자연 종료0/9.688초·stderr0이며 runtime 필수 파일·exact dependency7개·writer inventory·tool module3개를 포함한 실제 묶음 runtime import closure가 통과했다. 공개키 구성 SHA `276c6431a56f2c861f422d2842ad560ce5a6f1b4edb8cf0aceb67d9d379d2574`는 기존 trust를 묶은 결과이며 키 생성·서명 검증 완화는 없다.

기존 PE scanner는46개 모두 Valid/unsigned0/other0이다. [기존 installer 사전 검사](E:/KMTech/ca-build-0908/installer-preflight-winps-results.json)는 canonical PlanOnly와 helper DryRun 자연 종료0/0·stderr0, registry 변경/identity 생성 없음, source2283개 aggregate SHA `66562e4f21f91bf6d24109a03f096da088452545209bd0cc319096ddd4aceeea`를 기록했다. 첫 PlanOnly는 inherited PowerShell7 module 경로에서 Security module autoload 실패였고 그 원본을 보존했다. repository runner의 Windows PowerShell module 경로를 자식 process에만 적용한 뒤 성공했으며 source·machine 설정·signature 정책을 바꾸지 않았다.

[ZIP identity](E:/KMTech/ca-build-0908/artifact.json)는17,156,131바이트·SHA `b8dcd72c0205201eadda5a93d531a767e7ff9552b8519067468d1bfb7de84b40`, 2283개/48,805,144 uncompressed bytes, CRC와 manifest 일치를 확인한다. [다음 설치 준비](E:/KMTech/ca-build-0908/INSTALL-PREPARATION.md)는 같은 후보의 top-level installer와 Main이 새로 배정할 VM/current-user/개발 HTTPS origin을 요구한다. host 설치·GUI·default server 접속은 없었다. 실제 설치·업무·persistence/cold boot·uninstall/reinstall·rollback·backend E2E는 **NOT TESTED**, signed feed/키 회전 호환은 **UNPROVEN**, Ready0/6이다.

<a id="ca-o09"></a>
## CA-O09 새 복사 VM의 일반 설치·업무·복원 검증

**최신 실제 범위 — 2026-09-08 11:55Z:** 아래 초기 실패·미실행 문단은 각 시점의 이력이다. 전용 VM의 ordinary `kmadmin`/session1에서 a7의 cold boot·제거/재설치, 별도 d440의 정상 교체, 원 owner 종료와 cold boot 이후 공개 receipt-bound 복원, 복원된 a7 GUI의 실제 F4 GOOD2 완료와 마지막 복원 후 cold boot까지 확인했다. Main은 d440 source review와 Restore09의 실제 복원을 독립 수용했다. 최종 installed source는 `a7d714f6aefdb2a5a1ad039b58a43443ec0b571c`이며 d440은 보존된 successor/failed-new 후보다. VM은 정상 Off로 Main에 반환했고 F4 bundle은 Label/Web에 명시 인계했다. 아래 PASS를 다른 설치본·강제 crash·실장비·전체 제품 Ready로 승계하지 않는다. 최종 custody와 중앙 조회는 [실행 보고서](E:/KMTech/ca-install-qualification-20260908/REPORT.md)에 연결한다.

**동결 successor와 진짜 교체:** source `d440b1f7b7af0d7c177bd6382eecf8cbde3c48f6`/tree `ff60f8fa7e9cb21e74099f226b875ccbb9dde8c4`, [ZIP](E:/KMTech/ca-late-rollback-20260908/Container_Audit-d440b1f7-portable.zip)17,162,800B/SHA `6c5a07b5b6122c82c1e51d3ff3ab335c5697320b664e1ee67666245645175493`, manifest `bb2825f36d5659a40f6ee1275f0a74d66de70651593400d342e041ef0408c3e7`다. build/import/CRC·PE46/46 Valid·host PlanOnly/helper DryRun·guest PlanOnly를 통과했다. C 검토 파일과 frozen E 파일의 LF/CRLF 차이는 [정확한 byte 결합](E:/KMTech/ca-install-qualification-20260908/d440-source-checkout-byte-binding.json)으로 구별한다. 첫 Install06 task는 qualification launcher 복사 누락으로 native 실행 전 실패했고 보존했다. 별도 Install06Retry02는11:05:29~11:07:40Z native/task0, `PASS/REPLACED_VERIFIED`; 업무9·identity3·Run이 유지됐다.

새 원 receipt `canonical-portable-20260908T110547188Z-ae5703eab2d14240b47b26ed32477d67-replacement.json`은2866B/SHA `3650c68bf2fca476ccae0443cc619e339d48553bac9bc50b64200fde35f1a0b5`, 교체 transaction `a79f4980b9c247249dcfc7d254095be3`다. 현재 a7 exact preimage를 진짜 교체로 확보했으며 drift가 있는 과거 f2 receipt를 수정·재사용하지 않았다. normal shutdown/cold boot의 최종 boot11:13:03Z 뒤 같은 사용자 d440 relay8520의 자동 시작을 확인했고, 원 installer owner는 종료된 상태였다.

| 공개 복원 실제 시도 | 결과와 보존 범위 |
|---|---|
| RestoreCancel07,11:14:59~11:17:01Z | 실제 UAC No, native/task1, `FAILED_RESTORE_RUNTIME_RECOVERED`/PENDING/NOT_STARTED; exact d440·Run·업무9/identity3·두 ACKED 유지, relay2360 회복, fence/stop 부재. [35파일 보존](E:/KMTech/ca-install-qualification-20260908/restore-cancel-07/copy-inventory.json). |
| Restore08,11:21:55~11:24:27Z | UAC 동의 화면을 관측하지 못했고 Yes 입력 없음, native/task1·RunAs 취소·같은 회복 상태, exact d440/relay1296 유지. 검은 화면의 원인을 display timeout으로 확정하지 않는다. [38파일 보존](E:/KMTech/ca-install-qualification-20260908/restore-08/copy-inventory.json). |
| Restore09,11:26:55~11:28:21Z | 같은 frozen source/원 receipt, 새 controller transaction `4e06ff7445a6447c9b8f5df6c58dab87`, 실제 UAC Yes; native/task0, **PASS_RESTORED_VERIFIED_DATA_PRESERVED / RESTORED_VERIFIED / RESTORED**. [43파일/665,913B](E:/KMTech/ca-install-qualification-20260908/restore-09/copy-inventory.json), hash 불일치0·제한 ACL. |

[독립 exact tree 조회](E:/KMTech/ca-install-qualification-20260908/restore09-exact-tree-binding.json)는 current a7·failed-new d440·historical old68dd 모두 원 receipt와 일치함을 확인한다. code-restore receipt SHA `a782e1c81f5ac3c9db31a5789c71d1081914dd5dde813068d9cf38e8c06583f7`; a7 integrity `d10c379049582d7d2fd31564cbf1eedc589b7e7088d17d93d5c093cfef72f463`. [runtime 조회](E:/KMTech/ca-install-qualification-20260908/restore09-runtime-boundary.json)는 원 Run·quoted command의 relay8728/session1, fence/stop 부재를, [보존 비교](E:/KMTech/ca-install-qualification-20260908/restore09-preservation-comparison.json)는 업무9/identity3 불일치0을 증명한다. 기존 Run 복원·검사는 fence 안, relay 시작은 해제 뒤다. 재등록·credential 복사·업무 DB snapshot 덮어쓰기는 없다.

**복원된 앱의 F4 실제 업무:** ordinary GUI9124/작업자 `CA-QA-20260908`는 기존 완료2와 대기0을 표시했다. Web의 기존 scoped grant 정상 갱신 후 `PHS-label-f4-88ebd40268fb-target`/품목 `AAA2287570200`/IIN `IIN-20260908-00A471B1`의 target GOOD LFT001/LFT002만 스캔해11:43:39Z 완료,11:43:40Z **ACKED/attempt1/LINKED1/review0**다. [실제 세 영수증](E:/KMTech/ca-install-qualification-20260908/f4-seal-public-results-01.jsonl)의 새 receipt는 `receipt_2f01c421829248f3ad2e691df8c4bea2`, transfer는 `TRANSFER-AD72156897B5E03BD5526D90`, lease는 `operation-lease-8a6db9bb-233c-443b-aec9-4ee6b4c27e5f`다. [완료 화면](E:/KMTech/ca-install-qualification-20260908/guest-f4-completed.png)은 완료3·대기0, [relay](E:/KMTech/ca-install-qualification-20260908/after-f4-relay-queue.jsonl)는29건 모두 acked다. QR는 제품 DB에서 readonly backup으로 파일에만 보존했고316B/SHA `a8dc1ed8b9f210aeaddfeb05b2840c4f9e82b6ca57b768bc4e1b637e02966e8d`, [보호된 업무 증거47파일/736,568B](E:/KMTech/ca-install-qualification-20260908/after-f4-business/copy-inventory.json)는 hash 불일치0이다. 두 donor는 CA가 사용하지 않았다.

**독립 중앙 확인과 인계:** Web의 [active-WAL readonly 조회](E:/KMTech/web-integration-20260908/residual-restored-and-f4-readback.json)는 F4 receipt1 COMMITTED·원 target CONSUMEDv2·transfer AVAILABLEv1·동일2-member hash·lease 소비11:43:40Z·두 singleton donor AVAILABLEv1 보존을 확인했다.11:51:58Z CA는 Label/Web/Main에 실제 제품 QR 파일과 `TRANSFER-AD72156897B5E03BD5526D90` 소유를 명시 인계했다(`msg_afcf1138111d`, `msg_f0953083bff6`, `msg_7cc2b4166ad4`). 그 뒤 교체/포장·donor 소비·실물 인쇄 결과는 downstream의 별도 관측이다. Web 공동 파일의 Inspection residual 결과를 CA 증거로 합치지 않는다.

**복원 후 마지막 cold boot·VM 반환:** 정상 GUI 종료 확인 전 첫 shutdown precheck는 GUI 존재로 거부했고 실제 전원 변경은 없었다. 확인창 수락 뒤 GUI0, normal shutdown11:47:51Z/Off11:48:26Z/Start11:48:46Z, 최종 boot11:48:47.221889Z이며 same kmadmin/session1 relay8424가11:49:05.880Z 자동 시작했다. [보존 비교](E:/KMTech/ca-install-qualification-20260908/restored-coldboot04-preservation-comparison.json)는 source/manifest/Run·업무9/identity3·세 ACKED 결과 유지와 GUI 부재·새 boot·relay session1 등10항목 모두 true다. [runtime](E:/KMTech/ca-install-qualification-20260908/after-restored-coldboot04-runtime.json)의 old a7 record 및 fence/stop 부재도 유지됐다. [최종 custody48파일/742,288B](E:/KMTech/ca-install-qualification-20260908/settled-vm-custody/copy-inventory.json)는 제한 ACL/hash 불일치0이고 [최종 전송](E:/KMTech/ca-install-qualification-20260908/settled-vm-relay-queue.jsonl)은30건 모두 acked다. 마지막 normal shutdown11:53:30Z 뒤 [실제 Off11:54:48Z](E:/KMTech/ca-install-qualification-20260908/final-vm-custody-off.json)를 관측하고11:55:16Z Main에 VM custody를 반환했다(`msg_dfca50fb34c7`). 반환 이후 guest 호출은 없다.

**화면 보류 수 정정:** 이전 cold boot/reinstall screenshot과 복원 후 [보류 목록](E:/KMTech/ca-install-qualification-20260908/guest-f4-preserved-parked-list.png)은 모두 **2건**이다. 이는 case03 일반 보류1(0스캔/1152B)과 case01 사전조회 격리1(0스캔/521B)이며 각 원 hash가 그대로다. 이전 보고서의 화면 보류1 표현은 일반 보류 파일 수와 화면 합계를 혼동한 것으로 정정하며 데이터 증가로 해석하지 않는다. case03 expired/unreconciled 조정 custody는 Main에 남는다.

위 빌드 이후 [실제 시도와 원본](E:/KMTech/ca-install-qualification-20260908/REPORT.md)은 source `68dd0c520ed2b8bd585301999cb35624702a05a5` / tree `5960560260eb3a6226b419cfa24493c154757be0`와 동일 ZIP을 사용한다. 동결 입력·설치본은 바꾸지 않았으며 source207/FULL·별도 E31을 반복하지 않았다. 아래 별도 상태 설명 수정은 현재 저장소 소스에만 적용한다.

| 관측 범위 | 실제 값·판정 |
|---|---|
| 대상·사용자 | Main이 전용 배정한 VM `3c5da10e-1a66-4dc8-92c8-f922a7a1ff93`, `KMTech-CA-Qualification-20260908-01`; E-backed 원본 export 복사본, Windows11 Pro26200. 기존 `KMTECH-GEN-01\kmadmin`, console session1, medium integrity·비승격을 실제 관측했다. |
| 초기 앱 상태 | canonical code·business/relay state·CA task/process 부재; onboarding이 관측한 identity/credential/manifest/profile/secret/registration-report 6종도 ABSENT. 중앙 identity 신규성은 별도이며 결과적으로 충돌했다. |
| 전송·정상 준비 | ZIP17,156,131B·원본 SHA 일치·2283파일; guest top-level PlanOnly exit0. IP172.22.130.13, Main의 기존18443 허용 추가, DNS100.107.44.33·TCP 연결·공개 CA 검증 HTTPS200/sourcec04343ce를 확인했다. |
| 실제 명령 | guest `C:\Qualification\ca-install-20260908\portable\INSTALL_CANONICAL_PORTABLE.ps1`에 같은 SourceRoot, `-InstallRoot C:\KMTech\Apps\Container_Audit\current`, task evidence JSON, `-ServerBaseUrl https://desktop-03pcrd7.taile4847b.ts.net:18443`. [정확한 호출](E:/KMTech/ca-install-qualification-20260908/apply-controls/apply-canonical.ps1). test-only flag·서명 우회·독립 코드 helper apply는 사용하지 않았다. |
| 코드 배치 | ordinary interactive task가 정상 helper UAC를 요청했고 assigned guest 키보드로 승인했다. elevated helper는06:45:45Z `PASS`, canonical은 `PASS_NEW_VERIFIED`; 설치 integrity aggregate `66562e4f21f91bf6d24109a03f096da088452545209bd0cc319096ddd4aceeea`. 전체 설치 PASS와 구분한다. |
| 등록·canonical 결과 | registration2·onboarding4·canonical1,06:46:26Z `FAILED_ROLLED_BACK`. `producer_identity_conflict` / `ADMIN_RECOVERY_REQUIRED`, 신규 possession key와 기존 active epoch6의 key가 다르다. [CA-C10](contracts.md#ca-c10). |
| rollback 한계 | 제품은 runtime/current-user lifecycle 복원 true를 기록했다.06:51:20Z Run relay 값·identity/credential/manifest와 설치본 process는 없고 apply task Ready, 새 code root·integrity record는 남았다. 이 상태를 exact 설치 전 부재 복원이나 전체 rollback qualification PASS로 해석하지 않는다. |

원본 실패11파일/15,250B를 E로 회수해 전송 hash 불일치0을 확인했다. 보호된 token은 파일→process 환경으로만 전달하고 값은 증거에 넣지 않는다. Main `msg_874f9cd5907d`가 기존 epoch6 소유를 이 guest에 배정한 뒤 Web의 정상 recovery authorization을 보호 경로로 전달했다. 설치된 도구의 실제 current_user recovery는06:58:52Z `ADMIN_RECOVERY_REGISTERED`, epoch7, 서버·admin recovery·manifest 검증 true, secret 파일 삭제 true다. wrapper의 native exit 값은 null로 남아 있으므로 임의 exit0으로 보충하지 않는다. [제품 recovery 원본](E:/KMTech/ca-install-qualification-20260908/recovery-01/worker_pc_registration.json)과 Web 승인 관측은 성공이며, 그 직후 OPERATION_PENDING과 별도 operation grant 승인(만료09:01:04Z)을 구분한다.

동일 후보의 [일반 후속 호출](E:/KMTech/ca-install-qualification-20260908/continuation-controls/apply-canonical02.ps1)은07:01:45~07:03:06Z 자연 종료0, `PASS`·`REUSED_VERIFIED`·`READY/REUSED`, exact relay launch PROVEN이다. 실제 잔류 relay PID6232와 stop marker 부재를 관측했고13파일/30,033B를 E로 회수해 hash 불일치0이다. 자동 시작은 `PROVEN_NON_REBOOT_APPROXIMATION`이며 cold boot를 증명하지 않는다.

일반 installed launcher의 GUI PID8428/session1에서 실제 작업자 `CA-QA-20260908` 등록·WORK_START를 확인했다. guest 화면과 ordinary session 창 관측으로 확인했으며 host 입력은 없다. 준비된 [실제 API 생성 두 업무 입력](E:/KMTech/web-integration-20260908/CA-BUSINESS-FIXTURES.json)의 case01을07:17:05Z 입력했을 때 `PHS_WORK_GROUP_SOURCE_NOT_AVAILABLE`로 거부되었다. [실제 내구 hold와 로컬 사건](E:/KMTech/ca-install-qualification-20260908/case01-preflight-failure.txt)의 `preflight-b91da26a3dba7ba35512eb844e723e9a`는 LOOKUP_FAILED/items0이며 제품 스캔·seal은 없다. Web의 정상 source 준비 경계 확인 뒤 계속하며 전량/NG 제외·중앙 seal ACK·producer/화면 대조·restart/cold boot·제거/재설치·exact rollback은 미완료다.

**case01 원인·지원 복구:** Web의 [실제 transfer GET](E:/KMTech/web-integration-20260908/ca-transfer-source-readback.json)은 mixed work group에 NG 소유1개가 남아409이며 case02는 GOOD2개200이다. 첫 case01을 즉시 GOOD-only 양성 사례로 소비한다는 fixture 가정은 폐기하고 원본 mixed/NG 이력은 유지했다. 이 fresh guest에는 기본 보호 관리자 profile이 없어 일반 작업자만으로 target 전환이 불가능했다. Main `msg_7c614350c3f2`의 QA supervisor 설정 승인 뒤 원래 source68dd의 `tools/install_protected_admin.py`(blob `e8a7d60c74338ad0b17e68cf5454d8db0843cc91`, SHA `a834bb6dacb028409cf8e4b0cdc6d0b3dccff82fc071316f82848018f1c89e29`)의 정상 `install_protected_admin_profile`을 보호 파일 입력 adapter로 실행했다. 6자리 QA 전용 입력은 guest private 경로에서 생성·보호하고 값·argv·로그·화면으로 회수하지 않았다. Windows/서버 credential은 변경하지 않았다.

이 관리 도구는 frozen portable app/tools에 포함되지 않아 동일 원래 소스를 guest qualification controls에 별도로 배치했고 설치본은 수정하지 않았다. [실제 provision](E:/KMTech/ca-install-qualification-20260908/qa-admin-provision-readback.txt)은07:36:16Z native exit0, 기본 `C:\ProgramData\KMTech\ContainerAudit\protected\protected_admin.json` 설치다. 제품의 PBKDF2·native ACL/경로/readback 검사와 System/Admin FullControl·kmadmin SID Read 보호 ACL을 적용했다. GUI 정상 종료가 [원본 close-handoff](E:/KMTech/ca-install-qualification-20260908/case01-after-normal-close.txt)를 기록한 뒤 ordinary session1의 실제 masked 로그인·보호 관리자 인증·격리 확인을 거쳤다. [quarantine](E:/KMTech/ca-install-qualification-20260908/quarantine-summary.txt)의 `PHS2_PREFLIGHT_HOLD_QUARANTINED`는 원본521B/SHA `833485fd05453e92a70c3a2859defa846bdaac671ecf0c05b774545279deaa7f` 및 canonical snapshot hash를 보존한다. 사용자 변경 UI로 WORKER 역할에 복귀했다.

**case02 실제 업무·복구:** 정상 PHS2 목표2에서 첫 GOOD1개를 스캔하고 [부분 제출 거부](E:/KMTech/ca-install-qualification-20260908/guest-case02-partial-rejected.png)를 확인했다. 당시 seal intent0이다. 보류1240B/SHA `cceb126dc5173ecc8cd4d695ba29b302f63b80d29707ff948164331c993718a9`는 정상 앱 종료·새 GUI PID8008 시작 뒤 그대로 남았고, 원본 PHS2를 다시 읽어 제품 복원 확인 후 같은 JSON을 current로 옮겼다. 첫 제품 재입력은 1/2 상태에서 중복 거부되고 최종 다른 GOOD를 입력해 로컬 `TRAY_COMPLETE`/`LINKED`와 화면 완료1을 기록했다.

**중앙 거부와 별도 전송:** 실제 명령 `container-seal:7e0b2f72c5a491766914bc5389da4515fd65bedb4e2dfb01966211f1bc7851f4`는07:46:27Z `INVALID_INPUT`으로 거부되어 intent `transfer-intent-7e0b2f72c5a491766914bc5389da4515`가 `OPERATOR_REVIEW`/attempt1·checkpoint1이다. [원본 readback](E:/KMTech/ca-install-qualification-20260908/case02-seal-readback-02.txt), [실제 경고 화면](E:/KMTech/ca-install-qualification-20260908/guest-case02-seal-rejected.png). Web은 logistics handler 이전 전역 JSON validator를 원인 경계로 확인했다. 동일 명령 재전송·intent 편집 없이 protected E DB backup 및22파일/468,505B를 hash 불일치0으로 보존해 Web이 읽기 전용 진단한다. 로컬 완료를 중앙 ACK·Label 포장 가능으로 승격하지 않는다.

실제 producer WORK_START receipt `93a90ec7-ddac-4454-af34-5572edbc0158`은 client HTTP200/committed/projected1과 [Web 독립 receipt·projection·화면 API](E:/KMTech/web-integration-20260908/ca-work-start-server-readback.json)가 일치한다. browser 렌더링은 이 근거에 없다. case02 완료 업로드 `cc26c2f1-c4d4-49af-a6e3-71cf26ba9781`도 client HTTP200/committed·SCAN_OK1/TRAY_COMPLETE1이며 중앙 seal 거부와 독립이다. case03 정상 GOOD-only fixture는 준비됐으나 아직 CA 미소비이고 cold boot·제거/재설치·exact replacement rollback은 **NOT TESTED**다.

**현재 소스의 작은 수정:** fresh 코드 배치 뒤 runtime 복원만 된 실패를 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`와 경고로 기록한다. 기존 실패 원본·동결 후보는 그대로다. [새 fresh 실패 회귀](../../tests/test_canonical_installation_callers.py)는 RED1 뒤 실제 상태를 고쳐 GREEN1/3.83초이고, 같은 제품 코드의 기존 교체 tree 복원 회귀도1 PASS다. 중간 실행의 새 회귀1 FAIL은 PowerShell 경고 줄바꿈에 대한 test 문자열 비교 문제로 보존했고 whitespace 정규화 후 그 사례만 재검사했다. 기존 writer inventory는 stale 확인 뒤 installer 줄 위치10개·파생 hash만 갱신했으며 [최종 check](E:/KMTech/ca-install-qualification-20260908/writer-inventory-final.txt) exit0, writer/권한 의미 변경은 없다. full suite 재실행·새 설치본 build는 없으며 이 로컬 근거를 frozen guest 수용과 합치지 않는다.

**08:19Z 공유 backend 교체 대기 경계:** Main 요청으로 새 scan/onboarding/recovery 변이를 중지했다. GUI8008·relay6232와 case02 review를 유지하고, case03은 master 사전조회만 완료해 목표3/제품0 상태다. live relay SQLite는12건 모두 acked, pending/inflight0이다. 일반 종료·cold boot·제거/재설치로 미해결 업무 custody를 버리지 않았다. Web의 [독립 완료 readback](E:/KMTech/web-integration-20260908/ca-completion-server-readback.json)은 case02 producer2행/4660B, SCAN_OK65/TRAY_COMPLETE66 PROJECTED와 정상 `/api/data`의1트레이/완료2개를 확인했다. 이 API 근거에 browser 렌더링·물류 seal ACK는 포함되지 않는다.

**관리자 재시도 source 검증:** [CA-C03](contracts.md#ca-c03)에 기술한 승인 후속을 구현했다. [초기 10건](E:/KMTech/ca-install-qualification-20260908/retry-unit-01.xml)은7 PASS/3 FAIL이며 실패는 test fixture SQL 변경의 commit 누락이었다. fixture 수정과 실제 GUI handler 경계 추가 뒤 [12 PASS](E:/KMTech/ca-install-qualification-20260908/retry-unit-02.xml), 관련5파일 [185 PASS/3 FAIL](E:/KMTech/ca-install-qualification-20260908/retry-focused-01.xml)을 기록했다. 후자의3 FAIL은 새 coordinator method/공유 transport helper를 반영하지 않은 정적 writer census였으며 owner-first·실제 writer 추적을 유지해 갱신한 [경계·이벤트70 PASS](E:/KMTech/ca-install-qualification-20260908/retry-boundary-02.xml)로 해소했다. 만료 후 원래 완료 시각·동일 명령 재전송, 감사 실패/인증 변경/command tamper/checkpoint 누락/ACK 상태 차단, transport/CAS/불일치 receipt의 review 유지가 포함된다. source unit 근거이며 변경 후보의 guest/backend 수용은 아직 없다.

writer inventory는 실제 source에서 다시 파생한 `f14e79d910c389a2e05bf48efad773b7afcd867b0c26afa95a3bf6b03039c141`이다. snapshot/누락 검사와 기존 old/new inventory 전환·real child admission/rollback 회귀는 [4 PASS/18.29초](E:/KMTech/ca-install-qualification-20260908/retry-inventory-01.xml)다. coordinator 공개 변이 진입점은 새 명시적 동작으로25→26이며 기존 owner-first와 private transport helper guard를 유지한다. source 증거를 이전 frozen inventory 또는 실제 새 설치 결과로 바꿔 쓰지 않는다.

**별도 변경 후보의 실제 preflight 실패:** source `fc24bc7e87cc3de3449ea9a72f41551ce4fcfe78`/tree `a7a2c978c03fe1208d34415ba13bf7af443765fc`의 [새 ZIP](E:/KMTech/ca-review-recovery-20260908/Container_Audit-fc24bc7e-portable.zip)은17,161,048B/SHA `8041abfd497b78971081bd81cccd91fea254b1ead18ae04558d75af25c84116c`, build/import closure/CRC PASS다. 하지만 [정상 canonical PlanOnly](E:/KMTech/ca-review-recovery-20260908/validation.log)는 public writer contract의 이전 inventory pin 때문에 exit1로 거부되었다. guest에는 배치하지 않았고 실패 후보를 보존했다. 파생 inventory만 바꾸고 Python/PowerShell fence·공개 contract의 기존 pin3곳을 맞추지 않은 packaging 불일치이며 pin을 새 파생값으로 맞추고 다시 검증한다. guard·권한·writer membership을 완화하는 변경은 아니다.

pin3곳 수정 뒤 기존 public contract 정상·오류 hash 회귀는 [2 PASS/1.82초](E:/KMTech/ca-install-qualification-20260908/retry-pins-01.xml)이며 [파생 inventory check](E:/KMTech/ca-install-qualification-20260908/retry-pins-inventory-check.txt)는 같은 `f14e79...`로 exit0이다. Main `msg_80e40e78d0d5`로 정상 backend `c0c0d5165f1543ec2603734ad28190772a9dd306` 교체 후 업무 재개가 승인되었다. case03은 제품0/완료 없음 상태로 lease `operation-lease-e7b42098-8902-4089-94ec-c0c5083a3884`가08:30:39Z 만료되어, 원래 완료 시각을 가진 case02의 늦은 재시도와 구별한다. 이 미시작 건을 정상 완료로 표시하거나 시각을 수정하지 않는다.

**변경 후보 정상 교체 PASS:** source `a7d714f6aefdb2a5a1ad039b58a43443ec0b571c`/tree `5e8228c2f6ef3acb329ebb3d0760ee46d7e13f77`의 [ZIP](E:/KMTech/ca-review-recovery-20260908/candidate-02/Container_Audit-a7d714f6-portable.zip)은17,161,046B/SHA `4b6a5d475ee6c6d5f6cc95d932dab04c0507615611f1c9e09fc4f6b48eeacde2`다. build/import/CRC, native46/46 Valid, host canonical PlanOnly/helper DryRun와 실제 guest PlanOnly가 통과했다. GUI 정상 저장·종료 뒤08:46:39~08:49:23Z ordinary session1에서 canonical exit0/**PASS/REPLACED_VERIFIED**, relay11364의 정확한 실행·비재부팅 자동 시작 근거를 확인했다. [교체 증거18파일/42,298B](E:/KMTech/ca-install-qualification-20260908/replacement-03/copy-inventory.json)는 hash 불일치0으로 보존했고 receipt SHA `b18abcc29d309b7672a94d5cf5d02421d168ece29b153b15e3f2606fed66ffac`다. case02 intent는 교체 직후 원래 key/command·attempt1·INVALID_INPUT·OPERATOR_REVIEW 그대로다. cold boot와 실제 rollback은 이 PASS에 포함되지 않는다.

case03은 같은 작업자 로그인의 정상 `이전 작업 복구 → 아니오: 보류하고 새 작업`으로 [보존](E:/KMTech/ca-install-qualification-20260908/case03-normal-deferred.txt)했다. `parked_recovery_CA-QA-20260908_d05aef8b4cc5d5f1.json`1152B/SHA `e0b7e338db9b62372c6c7b9e5573f6f311cfd7b4a6d4acfc2e98bf603f30fd34`, 제품0·원래 lease/identity를 유지하며 다른 작업자 takeover/영구 삭제는 하지 않았다. 새 GUI396에서 보호 관리자 정상 인증 후 [실제 메뉴](E:/KMTech/ca-install-qualification-20260908/guest-review03-supervisor-menu.png)와 원래 품목 `AAA2270740200`/수량2/작업자 `CA-QA-20260908` 확인창을 관측했다. 09:03Z에는 아직 재시도 POST 전이며, 기존09:01:04Z operation grant 만료가 기존 lease의 늦은 완료 제출/새 case04 발급에 미치는 경계를 Web에 확인 중이다. 새 [GOOD3 case04](E:/KMTech/web-integration-20260908/CA-BUSINESS-FIXTURE-04.json)는 준비됐으나 아직 입력·lease 발급 전이다.

**09:31Z 원 완료 복구·새 업무 성공:** Web의 동일 producer/scope 정상 발급 grant 갱신09:17:02~11:00Z readback 후, 실제 installed `a7d714f6` 관리자 확인창에서09:21:22Z 원 case02를 한 번 재시도했다. [불변 비교](E:/KMTech/ca-install-qualification-20260908/review03-integrity-after-retry.json)는 ACKED/attempt2·원 command SHA `703bcd14c264bca8604564fdb6f8f99c33c10644c7ac70589a35cd710ba0b14d`·원 완료07:46:27Z·LINKED1/review1 보존을 확인한다. 실제 local-only 감사 `TRANSFER_SEAL_REVIEW_RETRY_REQUESTED`1건 뒤 정상 결과창 `중앙 반영 확인`을 관측했다. [Web 독립 exactc0 조회](E:/KMTech/web-integration-20260908/ca-original-retry-central-readback.json)는 `receipt_f43584fde58c42aab4f6369935cdca6b`1건, 기존 lease/fence1/원 기간 유지·CONSUMED, source CONSUMEDv2와 TRANSFER AVAILABLEv1/원2개를 확인했다. Main은 이 milestone을 수용했고09:30Z Label/Web/Main에 exact 제품 출력 QR316B/SHA `7cebab602abf4ffffa9e419058c619979bd9a74ff11c517d8f4a56a1a5cbeb22` 파일 경로로 bundle `TRANSFER-A80D17528B6D4E261F78BBB7` 소유를 인계했다. opaque token은 본문에 기록하지 않는다.

case04는09:24Z 목표3 preflight 후 제품1/2 스캔·일반 Undo로 [제품1만 유지](E:/KMTech/ca-install-qualification-20260908/case04-after-undo.jsonl), 제품2 재스캔·제품3으로09:25:36Z 완료했다. [실제 두 완료](E:/KMTech/ca-install-qualification-20260908/case04-seal-public-results-02.jsonl)에서 새 case04는 ACKED/attempt1·`receipt_ac2fa8261c054ee89dd524dbfd46244e`·member3·LINKED1/review0이며 [GUI](E:/KMTech/ca-install-qualification-20260908/guest-case04-complete.png)는 서버 이적 확인 완료·품목별 완료1을 표시한다. 원 case03은 EXPIRED_UNRECONCILED/fence1·제품0 그대로이고 Main이 조정 custody를 맡았다. [후속 보존38파일/640,226B](E:/KMTech/ca-install-qualification-20260908/after-business-04/copy-inventory.json)는 readonly DB466,944B와 영수증/이벤트/보류 자료를 hash 불일치0·제한 ACL로 보관한다.

일반 GUI 자연 종료 뒤 [preboot state](E:/KMTech/ca-install-qualification-20260908/before-cold-boot-state.json)는 같은 kmadmin/session1 relay11364·source a7d714f6를 확인했고 [대기열](E:/KMTech/ca-install-qualification-20260908/before-cold-boot-relay-queue-02.jsonl)은22건 모두 acked다.09:32:26Z 기존 사용자 Interactive/Limited `shutdown.exe /s /t 0`은 exit0/User32 1074로 정상 종료를 시작했으며 Windows가 기존 업데이트를 적용했다. 강제 종료 없이 실제 Off를 확인한 뒤09:35:07Z 동일 VM만 다시 켰다. 후속 cold boot 자동 시작·OS 버전·데이터 보존, 제거/재설치·적용 가능한 exact rollback은 아직 별도 검증 중이다.

**09:57Z 실제 일반 lifecycle 후속:** 자연 Windows update 후 최종 boot09:36:55Z/Windows11 26200.9168·25H2, 동일 kmadmin/session1에서 relay9544가09:37:47Z 자동 시작했다. [cold boot 비교](E:/KMTech/ca-install-qualification-20260908/cold-boot-public-comparison.json)는 source/manifest/Run 동일·업무9파일 hash 불일치0이다. 이 초기 reader의 `gui`7324는 읽기용 임시 Python process까지 포함한 분류 오류이며 [정상 실행 후 화면](E:/KMTech/ca-install-qualification-20260908/guest-cold-boot-restored-work.png)의 실제 GUI3788과 구별한다. 일반 worker 로그인 후 두 품목 완료 각1·보류2·전송 대기0을 확인했다.

같은 a7 packet의 ordinary canonical Uninstall04는09:45:22~09:47:58Z exit0/**PASS_UNINSTALLED_DATA_PRESERVED**, code/Run/relay 부재이고 [업무9·identity3 비교](E:/KMTech/ca-install-qualification-20260908/uninstall04-preservation-comparison.json)는 불일치0이다. Reinstall05는09:51:02~09:53:41Z exit0/**PASS/PASS_NEW_VERIFIED**, READY/REUSED·원 producer/install/epoch7이며 relay7052/session1을 확인했다. [재설치 비교](E:/KMTech/ca-install-qualification-20260908/reinstall05-preservation-comparison.json)는 manifest/Run 동일·업무9/identity3 불일치0이고 [일반 GUI6736 화면](E:/KMTech/ca-install-qualification-20260908/guest-reinstall05-restored-work.png)도 완료2·보류2·대기0이다. 두 ACKED seal의 공개 필드와 case03 보류1152B/SHA `e0b7e338db9b62372c6c7b9e5573f6f311cfd7b4a6d4acfc2e98bf603f30fd34`를 유지했다. uninstall23파일/627109B, reinstall27파일/634706B와 [추가 custody41파일/658072B](E:/KMTech/ca-install-qualification-20260908/final-custody/copy-inventory.json)를 hash 불일치0·제한 ACL로 보존했다. 이 재설치 뒤의 독립 cold boot는 이 시점에 미실행이다.

**10:32Z 승인된 코드 복원 공백 수정:** 원 f2 교체 receipt의 old68dd tree/record는 여전히 일치하지만 정상 재설치가 current a7 integrity record를 새로 생성해 기존 receipt.new의 record SHA와 다르다. [실제 읽기 결과](E:/KMTech/ca-install-qualification-20260908/original-replacement-current-tree-binding.json)를 보존하며 기존 receipt나 record를 맞춰 쓰지 않는다. Main은 새 수정 후보의 정상 교체로 현재 a7의 진짜 exact preimage를 새로 확보하고, 원 설치 owner 종료 후 공개 canonical 복원을 실제 검증하도록 승인했다. 현재 소스 구현과 [lower helper5 PASS](E:/KMTech/ca-install-qualification-20260908/public-restore-bootstrap-01.xml)는 실제 새 후보 build/guest 복원과 별개다. 첫 controller6 FAIL은 긴 E fixture root가 release 경로265자를 만든 실패이며 짧은 새 root에서 같은 대상 검증 중이다. 원 실패 로그와 새 source 차이, 새 artifact·transaction·실제 old code/relay/업무/identity 검증을 [보고서](E:/KMTech/ca-install-qualification-20260908/REPORT.md)에 따로 연결한다.

**후속 source 검증:** 짧은 E root의 [실제 controller6 PASS/131.10초](E:/KMTech/ca-install-qualification-20260908/public-restore-controller-02.xml)는 새 owner·repeat·원 receipt/source/history 보존·fence 해제 후 같은 raw relay 명령, receipt/record drift 거부, 취소·displacement 실패·코드 복원 후 evidence 실패를 확인한다. 기존 canonical/uninstall/inventory 전환·guard 회귀는 [63 PASS/1 FAIL](E:/KMTech/ca-install-qualification-20260908/public-restore-regression-01.xml)였으며 새 public child 호출로 늘어난 정적 census21→22/기존 helper6→7을 실제 파생 결과에 맞춘 뒤 [그 사례1 PASS](E:/KMTech/ca-install-qualification-20260908/public-restore-inventory-02.xml)다. 나머지 lower helper 회귀 [57 PASS](E:/KMTech/ca-install-qualification-20260908/public-restore-bootstrap-regression-02.xml)까지 해당132사례가 통과했다. source inventory/세 pin `be19f9523d4596641a733a9d5fe077058f85acea98d7985a6970dcd05e2cde4e`의 check와 [실제 a7 대비 writer 의미 동일](E:/KMTech/ca-install-qualification-20260908/public-restore-a7-semantics.json)을 확인했다. 과거 FULL은 재실행하지 않았다. 새로운 guest qualification controller는 Windows PS5 native stderr가 child catch/finally를 중단하지 않도록 기존 Start-Process Hidden/file redirection·그 process의 Handle/WaitForExit/Refresh/native ExitCode를 사용하며 과거 성공 wrapper는 변경하지 않았다.10:48:48Z VM은 정상 Off/예약 유지이고, 새 후보 실제 교체/복원은 아직 미실행이다.

<a id="ca-o10"></a>
## CA-O10 최종 frozen d440의 별도 fresh 대상 준비·수용

**최종 native 수용 범위 — 14:43Z:** [최종 후보 인계](E:/KMTech/resume-after-input-20260908/CA-FINAL-FRESH-TASK.md)와 Main의 후속 범위에 따라 실제 qualification을 마쳤다. 기존 source `d440b1f7b7af0d7c177bd6382eecf8cbde3c48f6`/tree `ff60f8fa7e9cb21e74099f226b875ccbb9dde8c4`, ZIP17,162,800B/SHA `6c5a07b5b6122c82c1e51d3ff3ab335c5697320b664e1ee67666245645175493`, manifest `bb2825f36d5659a40f6ee1275f0a74d66de70651593400d342e041ef0408c3e7`를 사용했다. 기존132 affected 사례와 build/import/CRC/PE46/host 준비는 동일 입력의 당시 근거로 재사용하며 새 FULL/빌드는 없다. source d440 이후96776cd는 명세4개만 바뀐 착수 기준선이며 이번에도 제품 소스는 바꾸지 않았다. 최초 fresh-app 등록 실패와 지원 recovery 후의 성공을 아래에서 구분한다.

| 실제 관측 | 후보·환경·결과와 한계 |
|---|---|
| 새 대상 provenance | Main [READY-OFF](E:/KMTech/ca-final-qualification-vm-20260908/READY-OFF.json): `c029c9d7-1061-4676-92f7-5307cf3d80de`, `KMTech-CA-Final-Qualification-20260908-01`, E-backed VHD24,733,810,688B/SHA `c069c43b703c2649178df91ae92e3964e54278ea9d070a4c1c5af19f59388c26`, empty DVD/분리 network. Main이13:21:29Z 정상 시작해 [분리 boot](E:/KMTech/ca-final-qualification-vm-20260908/START-DISCONNECTED.json)를 허용했다. 원래3c5 VM은 Main 소유/미접근이다. |
| 원래 앱 prestate | [13:23:49Z 관측](E:/KMTech/ca-final-qualification-20260908/guest-fresh-prestate03.json): Win11Pro26200/boot13:21:30Z, 기존 kmadmin SID ending1000, canonical code·ContainerAudit 사용자/identity·DirectSync·Run·relay·CA task 부재. 관측 PSDirect는 session0이며 ordinary token은 아래 별도 근거다. 복사 OS identity는 유지되므로 새 중앙 producer 등록을 입증하지 않는다. |
| 정상 task-local staging | [전송](E:/KMTech/ca-final-qualification-20260908/guest-packet-stage.json): exact ZIP/manifest/source/tree·2,283파일·공개 CA hash 일치, token65B는 kmadmin/SYSTEM/Administrators만 접근한다. 게스트 `C:/Qualification/ca-final-20260908`의 원본/증거/temp/input 준비이며 E-backed VHD 안이다. 제품 code/data ACL preconditioning은 없다. |
| ordinary Plan01 | [compact 원본 조회](E:/KMTech/ca-final-qualification-20260908/plan01-readback-compact.json):13:27:25~13:27:27Z, triggerless Interactive/Limited, kmadmin/session1/medium `S-1-16-8192`/비승격, controller6268/native2448, native/task0. 실제 packaged canonical에 explicit HTTPS18443 origin과 `-PlanOnly`; stdout443B/stderr0·registry_changed=false, 코드/앱 상태는 계속 부재. HTTPS 연결·설치 성공을 주장하지 않는다. |
| 실제 연결/최초 Install01 | Main의13:38:44Z 기존 Default Switch 연결 이후 공개 CA 검증 HTTPS18443/accepted `0ffe194f74357fef5de9413bc11184d21f4ce243` HTTP200. ordinary kmadmin/session1/medium controller2888/native8196,13:41:55~13:48:42Z, 실제 guest UAC Yes. [최초 native1](E:/KMTech/ca-final-qualification-20260908/install01-progress05.json)은 `producer_identity_conflict` / `FAILED_RUNTIME_RESTORED_CODE_RETAINED`; 코드 `PASS_NEW_VERIFIED`와 runtime restoration/code retention은 별도 결과다. [원본13파일/598,365B/hash mismatch0](E:/KMTech/ca-final-qualification-20260908/install01-original/copy-inventory.json)을 보존한다. |
| 지원 Recovery01/Install02 | Main의 새 QA 소유 배정과 Web 새 단회 recovery를 정상 지원 명령으로 실행해14:00:09~14:00:14Z ordinary native/task0 / `ADMIN_RECOVERY_REGISTERED`·epoch8. 제품이 실제 생성한 current_user key를 유지했고 [독립 Web14:06:14Z readback](E:/KMTech/web-integration-20260908/ca-final-recovery-central-readback-01.json)은 기존97 receipt ID/full row hash/rowid 보존을 확인했다. `OPERATION_PENDING`은 별도 권한 상태다. [Install02](E:/KMTech/ca-final-qualification-20260908/install02-progress01.json)는14:04:18~14:04:46Z native/task0 / `PASS`·`REUSED_VERIFIED`, exact d440/manifest·integrity record `7a99ca26024aad4c0eed4748abd5aab1ea0dee473d0bc5458e60230d040b77c5`, aggregate `bbc00737bba661c3b4360a20dca8be459e17269014a9c1834c2d81a607f5d887`를 유지했다. |
| 기본 GUI/실제 첫 작업자 | ordinary 기본 launcher·기본 LOCALAPPDATA 경로에서 실제 빈 목록→신규 등록 CA-FINAL-QA→성공 안내→작업 시작의 [일반 준비 화면](E:/KMTech/ca-final-qualification-20260908/guest-ui01-worker-ready.png)을 관측했다. 사업용 QR/이전 거래를 재연하지 않았다. 정상 close가 저장한193B 설정과183B worker registry가 보존 baseline이며 실행 중115B 설정과 구분한다. |
| 실제 cold boot/자동 시작 | [정상 Off14:26:41Z](E:/KMTech/ca-final-qualification-20260908/coldboot01-off-readback03.json)→정상 Start-VM→Windows servicing의 planned restart 뒤 boot14:28:34Z. [비교](E:/KMTech/ca-final-qualification-20260908/coldboot01-comparison.json)는 kmadmin/session1 자동 relay8704, source/manifest/원 record/Run 및 작업자·설정2/identity3 파일의 exact byte/hash 보존을 확인한다. OS는 자연스럽게26200.8037→9168로 바뀌었고 [System1074/6006/6005](E:/KMTech/ca-final-qualification-20260908/coldboot01-events.json)에 정상 종료/servicing을 보존했다. 저장된 이름으로 [GUI 재개](E:/KMTech/ca-final-qualification-20260908/guest-ui02-ready.png)도 확인했다. |
| ordinary Uninstall03 | [14:32:34~14:34:27Z native/task0](E:/KMTech/ca-final-qualification-20260908/uninstall03-progress03.json), controller9188/native2744, 실제 guest UAC Yes, `PASS_UNINSTALLED_DATA_PRESERVED` / `REMOVED`. [별도 비교](E:/KMTech/ca-final-qualification-20260908/uninstall03-comparison.json)는 코드·Run·설치 process 부재와5개 사용자 파일 exact 보존을 확인한다. 남은 과거 onboarding READY 파일을 현재 설치 상태로 오해하지 않는다. 원본21파일/618,828B를 보존했다. |
| ordinary Reinstall04/기본 GUI | [14:35:45~14:37:59Z native/task0](E:/KMTech/ca-final-qualification-20260908/reinstall04-progress02.json), controller4052/native8312, 실제 guest UAC Yes, `PASS` / `PASS_NEW_VERIFIED`. [비교](E:/KMTech/ca-final-qualification-20260908/reinstall04-comparison.json)는 같은 source/manifest/aggregate/Run, relay2768와 사용자5파일 exact 보존/epoch8 재사용을 확인한다. 새 integrity record는 `a186a4852c00db512cabc46be2dcb441fc3cd7cc2a4def32ca6ccbe2891e0bcc`이며 원 record 보존이나 새 rollback receipt로 부르지 않는다. 새 record 자체의 추가 cold boot는 미실행이고 같은 d440의 앞선 실제 boot 범위를 재사용한다. [기존 작업자 기본 GUI](E:/KMTech/ca-final-qualification-20260908/guest-ui03-ready.png)를 열어 정상 close했다. |
| 최종 정지/인계 | [14:40:34Z CA 검증 HTTP200](E:/KMTech/ca-final-qualification-20260908/network02-readback.json)은 같은 accepted backend source를 확인한다. [최종 close 뒤 상태](E:/KMTech/ca-final-qualification-20260908/final-before-shutdown.json)는 GUI 부재·ordinary relay2768만 존재하며, 정상 `shutdown.exe /s /t 0` 후 [14:43:14Z 실제 Off/uptime0](E:/KMTech/ca-final-qualification-20260908/final-vm-readback01.json)로 Main에 반환했다. [최종 원본56파일/1,234,636B](E:/KMTech/ca-final-qualification-20260908/final-guest-evidence/copy-inventory.json)는 제한 ACL/hash mismatch0이다. 원3c5 VM·생산·ERPnext·host GUI/input은 접근하지 않았다. |

기존 credential 함수의 module-private 접근 실패와 absent Run 속성 reader 오류는 제품 변경 전 task control 실패이며 원본을 보존하고 원인을 고쳤다. Plan 결과의 PowerShell `Get-Content` 확장 메타데이터가27,584,307B JSON을 만든 별도 reader 문제도 보존했다. 크기 검사로 전체 대화 출력을 막았고2,442B compact는 같은 관측의 native/task/user 필드와 실제 line value만 추린 것이다. PlanOnly를 다시 실행하지 않았으며 후속 reader는 plain .NET string을 사용한다. 실행 중 native stdout의 공유 잠금 때문에 실패한 reader는 process 종료 뒤에만 원본 line을 읽도록 고쳤으며 제품 child를 재실행하지 않았다. 첫 정상 shutdown 중 controller가 종료돼 task `1073807364`/최종 native marker 없음은 native0으로 바꾸지 않고 실제 OS 이벤트/Off로 판정했다. 최종 task reader의 null trigger를1로 세는 필드는 trigger 근거에서 제외했다. 자세한 명령·공개 lineage·원본·실패·scope는 [REPORT](E:/KMTech/ca-final-qualification-20260908/REPORT.md)를 따른다.

Main reply `msg_0b2fc814c41b`에 따라 원래 d440→a7 공개 Restore09와 변하지 않은 업무 근거를 원 candidate/receipt/VM 범위에서 재사용했다. 새 VM만을 이유로 추가 a7/d440 교체·복원 cycle은 수행하지 않았다. 현재 요청의 native 실행은 끝났지만 최초 무지원 fresh 등록은 실제 FAILED이며, 지원 recovery 결과와 합쳐 자동 등록 PASS를 만들지 않는다. 새 실패나 관련 동작 변화가 생긴 경우에만 실제 보존 preimage/receipt를 사용하는 공개 복원 필요성을 다시 판단한다. 물리 스캐너/프린터·공장 배포·전체 readiness와 case03/F4 downstream custody는 별도 범위다. [CA-G10](BACKLOG.md#ca-g10).


<a id="ca-o11"></a>
## CA-O11 2026-09-09 S05 소스 단순화

- CA-F01은 제품 호출·import가 없는 main의 `_write_update_download`/`_verify_update_checksum`과 그 전용 시험만 제거했다. 실제 portable source closure84개(제품 tool3개 포함)·grep으로 소비자0을 재확인했다. 후보 checksum 판정과 `update_service.verify_update_checksum`, runtime 배포를 거부하는 `download_and_apply_update`/`_build_updater_script`는 유지하며 writer inventory에서 삭제된 sink만 정리한다.

선택된 여섯 프로그램 qualification은 Main의 독립 composition 검토로 마감됐다.
이번 작업은 clean `f3702837c085737686f195230d36be4dbe8ca201`에서 시작한 CA 소스
정리이며 accepted `d440b1f7` 설치본·runtime·원래 실패·실행 산출물을 변경하지 않았다.

- **제거 근거:** 전체 tracked 소스의 import·이름/문자열·GUI binding·CLI·CI·패키징을
  대조해 호출되지 않는 UI layout/column/최고 기록 helper, 업데이트
  URL/hash helper, relay backpressure hard-block helper와 퇴역 topology 반환을 제거했다.
  실제 backpressure 경고·drain·disk 차단·업데이트 검증·화면 layout 경로는 유지한다.
- **보고서 도구:** `tools/direct_sync_phase_g_container_audit_runtime_report.py`와
  `tools/validate_test1_manifest_transport.py` 및 그 전용 두 test 모듈을 제거했다.
  Phase G는 직접 relay 시험과 겹치는 synthetic report이며, TEST1 validator는 현재
  consumer 없는 pins/build-evidence 결속 도구다. Web의 옛 Phase G 실행 문서는
  역사 근거로 보존하고 Main에 경로 영향을 보고했다.
- **실제 consumer:** portable 도구 closure는 `direct_sync_relay_runner.py`,
  `install_logistics_runtime_profile.py`, `register_container_audit_worker_pc.py`의
  세 경로로 유지한다. `kmtech_factory_contracts`, `vendor/kmtech_zero_pe`, release
  검증·capture validator·운영 진단은 제거하지 않았다. installer가 사용하는 writer
  inventory는 기존 derivation으로 갱신하고 Python/PowerShell/계약 hash를 결속했다.
- **검증 범위:** headless 기존 layout·현품표 교체·relay 오류/복구·업데이트 검증과
  writer inventory 정합성 및 실제 source/lease 경로의 focused 시험을 사용한다.
  Windows host Python 3.12.10에서 **236 PASS / 8 real_gui deselected**, 별도
  writer inventory consumer hash 확인 **1 PASS**이며 FAIL/ERROR/SKIP은 없다.
  명령·실제 결과·환경·한계와 final commit은
  [RESULT](D:/KMTech/s05-simplification-20260909/Container_Audit/RESULT.md)에 기록한다.
  새 Full·native build·설치·업무 replay·서버 검증은 **NOT TESTED**이며 이 소스
  정리의 자동 gate가 아니다. production CONTAINER_AUDIT1–3은 no-change다.

[CODEX](../../CODEX.md), [README](../../README.md),
[release 안내](../../RELEASE_GATE_CONTRACT.md),
[profile 안내](../LOGISTICS_RUNTIME_PROFILE.md)는 현재 경로와 적용 가능한 검증으로
정정했다. Main 독립 소스 검토는 [CA-G11](BACKLOG.md#ca-g11)에 연결한다.

<a id="ca-o12"></a>
## CA-O12 2026-09-12 실제 M06 GOOD1 이적과 기존 연결 복구

- **수용 경계:** 현행 제품 `0ea7251`·앱 SHA256 `76B21C347C7D56203ECB2CBB0AEC0A5FF334FF7EB6842F23B4BE5C1B0FCC2DB3`로 원본 PHS2와 멤버 `AAA2270710000901` 1개를 정상 GUI에 입력했다. local 완료·lease 완료는 각각 1건이며 intent `transfer-intent-956969133254cd85b028713d02224ded`는 `ACKED/attempt1`이다. 중앙 receipt `receipt_b2307da63bdd4b92b08e30b7c3aceed9`는 `COMMITTED`이고 로컬 receipt와 정확히 같다. 원본 3개 완료의 전체 로컬 행과 중앙 receipt는 실행 전후 동일하다.
- **중앙·인계:** 기존 scope `TEST1-OPT-20260909-02/authority3/plane1`과 backend `e46dd947`에서 PHS `phs_0ef8d963f98c4621bf48683fda85aed3`는 `AVAILABLE/v1`에서 `CONSUMED/v2`로 바뀌었다. 대상 `TRANSFER-9BFF9D4E70D69D6E4B16FA9E`는 `AVAILABLE/v1/member1`, active `transfer-seal_da62e8b9b5014e6d93d8e5057dcb4661/rev1`이다. 실제 물리 PHS2와 반환된 seal QR의 보호 파일 경로·크기·해시 및 원래 unit/member/receipt 결속은 [LABEL-HANDOFF.json](D:/KMTech/optimization-implementation-20260909/Container_Audit/M06-final-20260912/LABEL-HANDOFF.json)에 있다. QR 본문·자격 증명은 명세에 복사하지 않는다.
- **최초 등록 실패와 재배정:** 최초6fcb VM에는 기존 연결 프로필이 없었다. 승인된 정상 등록은 `ADMIN_RECOVERY_REQUIRED/producer_identity_conflict`로 업무 입력 전에 실패했다. 실패·생성된 possession key를 보존하고 새 identity 복구 없이 Main 재배정으로 원본 연결76a3를 사용했다. 최초 VM은 생성 task root만 회수 후 제거하고 `Saved/0`으로 반환했다.
- **기존 연결 복구:** 원본76a3의 kmadmin/session1·profile·credential·producer/device/install identity와 runtime을 유지했다. 만료된 공개 CA는 같은 공개 키의 유효 인증서로 기존 신뢰 파일만 갱신하고 이전 파일을 보존했다. 최초 PHS 조회의 `OPERATION_LEASE_MACHINE_SCOPE_FORBIDDEN`은 Main의 실제 조회에서 원래 grant 만료로 확인됐다. Main이 같은 grant/identity/scope를 정상 관리 진입점으로 갱신한 뒤, 앱에 유지된 같은 PHS2를 확인 버튼으로 한 번 재시도했다. 재등록·인증 우회·PHS 재붙여넣기·업무 replay·backend 재시작은 수행하지 않았다. Main의 이후 Label grant 갱신과 이 시점의 보존 확인을 구분한다.
- **producer와 반환:** 새 relay 1건은 `ACKED/attempt1`, accepted/committed/`COMPLETE`, inserted4/replayed0/errors0/quarantined0이며 최종17개 queue 행이 모두 ACKED다. 정상 GUI native0 종료, Python0·생성 task0·기존98 task 보존/running0, hold 없음/parked0을 확인했다. 현재140 source/기존 runtime을 검증하고 변경 전34개 source와 작업 증거를 D에 해시 검증 후 회수했다. 게스트 task root만 일반 삭제하고 원본76a3는 `2026-09-12T07:51:10.5988147Z`에 `Saved/0`으로 반환했다. Main은 [실제 handoff·반환](D:/KMTech/optimization-implementation-20260909/Container_Audit/M06-final-20260912/MAIN-M06-HANDOFF-ACCEPTANCE.md)을 수용했으며 이후 게스트 접근은 새 배정 범위다.
- **화면·성능 한계:** 실제1920×1080 최대화 화면에서 M06 목표1·중앙 확인·입력 포커스와 완료 후 품목 집계1·다음 현품표 입력 포커스를 직접 관측했다. 자동 완료는 현재 목록을 비우므로 중간1/1 행 화면·새 실제 작업 접수·최초 안전 입력 시각은 증명하지 않는다. WMI 키보드 호출 반환 시각은 실제 Return/최초 화면 시각이 아니며 단회 결과는 p50/p95나 물리 스캐너·프린터 수용이 아니다. 기존 UI host104/native5 PASS를 재사용하고 별도1024×768·글자2.5 교체 행 clipping, 원래 실패와 성능 분포 후속은 유지한다. 새 suite/build·target1 교체/보류·추가 재고는 실행하지 않았다.

실제 환경·최초 실패·지원 복구·시각 원본·완료/전송·VM 보존·문서 검증은
[RESULT](D:/KMTech/optimization-implementation-20260909/Container_Audit/M06-final-20260912/RESULT.md)에 연결한다.
이 CA 구간 수용으로 Label/Web 이후 연결 업무나 원래 전체 Goal을 완료 처리하지 않는다.

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

## w9slim2 소비자 없는 도구

현재 tracked source·명세·빌더·inventory와 다른 저장소의 committed source 및 최근 절차를 대조해 실행 소비자가 없는 `authenticated_o3_gate.py`와 그 전용 시험, `kill_exact_probe.py`를 제거했다. 원본과 SHA는 레인 tmp/logs에 보존한다. `container_atomicity_rest_probe.py`·`sandbox_container_sac/run.ps1`·`scan_portable_pe.ps1`는 절차 참조 또는 근거 불충분으로 보류하며, 촬영·문서·게시 도구는 유지한다. 현재 packet의 curated 목록에는 제거 대상이 없고 패키징 선택자는 바꾸지 않았다. 실제 stock packet gate와 보류 근거는 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)를 따른다.

## R29 중앙 PIN 경계 시험

고정 Web committed source `56c32028ce6b30ccf774e7cc635e3e4b377266ed`의 실제 Flask 서명 HTTP 진입점·SQLite 저장소와 CA 승인 진입점·내구 intent를 함께 사용했다. 성공 2건과 틀린 PIN·중앙 ADMIN 잠금·root 철회·역할 없음·잠금+root 철회 5건의 7 PASS를 확인했다. ADMIN 잠금은 서로 다른 3장치에서 5회씩 실패하여 실제 15회 한계를 충족하며 새 장치에서도 서버 `PIN_LOCKED` 감사와 CA REJECTED를 확인한다. 철회된 이전 grant는 REVOKED로 남고 redeem 거절, 원 recovery 파일 보존·PIN 미저장을 단언한다. 권한 상태 준비는 지원 store API를 이용한 격리 fixture이며 실제 root UI·production·네트워크 배포 수용은 NOT TESTED. 초기 fixture/입력 실패와 잘못된 10회 oracle을 지우지 않고 [결과](D:/KMTech/program-improvement-20260912/work/Container_Audit/w9slim2/RESULT.md)에 연결한다.

G 시작 거절 대화상자는 REFUSE/UNKNOWN에 맞는 고정 한국어 원인·복구 안내만 전달한다. 임의 예외 진단은 작업자 대화상자에 전달하지 않는다. 전체 비교에서 드러난 relay 모의는 read-only Git 신원 확인을 보존하며, 실제 자료 경계/호환 판정은 동일하다.
배포 PowerShell 파일에 비ASCII가 있으면 UTF-8 BOM을 유지한다(현장 Windows PowerShell 5.1 코드 페이지와 무관한 판독).
소리 초기화·재생·정지 실패는 고정 AUDIO_*_FAILED 코드로만 기록하며 저장·로그·감사 투영·완료·종료 처리를 계속한다.

# Installation follow-up evidence — 2026-10-02

설치 상승 wrapper·그 안의 finite helper·일반 토큰 producer wrapper는 기존 private
evidence root에 CreateNew로 만든 두 transport 파일(UTF-8 source와 JSON argv)을 쓴다.
각 파일은 내용을 쓰기 전에 새 DACL로 보호하며 owner 변경은 하지 않는다. caller가
게시 전 메모리 bytes의 SHA256을 짧은 bootstrap에 결속한다. bootstrap은 leaf/ancestor
reparse를 거절하고 FileShare.Read handle을 유지한 채 한 번 읽어 hash를 확인한다.
확인한 bytes만 파싱·실행하며 source의 기존 filename metadata와 독립 pin은 유지한다.
일반 사용자 finite producer는 같은 ACL의 추가 verifier 파일을 쓰며 짧은 `-Command`가
그 파일의 reparse·크기·읽기 완전성·SHA256을 확인한 bytes만 실행한다. 실행 파일과
옵션을 포함한 명령은 `CreateProcessWithTokenW`의 1,024 UTF-16 단위 한도에서 NUL
한 단위를 예약한 1,023 이하이다. API 호출 전에 넘는 명령은 고정 코드
`NORMAL_PRODUCER_COMMAND_TOO_LONG`과 길이 수치만 기록하고 거절한다. 비밀은 기존
허용 환경 override에만 있으며 relay의 `StartLimited` 명령·토큰·세션 확인은 그대로다.
그 밖의 launcher는 16,000자 이하이고 기존 30,000자 encoded 보조 guard도 유지한다.
완료·실패·취소의 finally에서 자기 transport 파일만 정리한다.
정리 실패는 원 오류/rollback을 덮지 않고 private 파일과 불완전 evidence를 보존한다.
상승 helper·bootstrap library·writer fence helper와 일반 토큰 API는 한 번 읽은
바이트의 SHA256을 확인하고 그 바이트를 파싱·평가한다. 실행 동안 source handle을
독점 보유하지 않는다. 높은 권한의 stage journal·stream·summary·placement log·
replacement/restore 결과는 `C:\KMTech\Apps\Container_Audit\update-control\installation-evidence\run-<guid>`에 둔다.
폴더 소유자는 Administrators, SYSTEM/Administrators만 쓰며 operator는 읽기만 한다.
일반 부모의 사전 검사는 앱 부모 부재와 두 공유 조상의 검토된 기본 ACL 모양을
지원 상승 단계로 넘긴다. 사용자 소유·재분석 지점·지원 모양 밖의 쓰기 권한은
한국어 한 줄로 거절한다. 높은 권한 단계는 증거 생성 전에 두 조상
`C:\KMTech`·`C:\KMTech\Apps`에만 비재귀 강화 B를 적용하고, 앱 부모를
보호된 DACL로 생성·신뢰 재검사한 뒤 control/store/run을 만든다. 이미 목표
모양이면 확인만 하며 뒤의 writer-fence 획득 후 B도 ACL을 다시 바꾸지 않는다.
공유 조상 보호는 제거·되돌리기로 원래 권한에 복귀하지 않는다.
준비 중 메모리에 모은 단계 경계·전후 SDDL은 run 생성 직후 `preparation.json`에
내구 기록한다. run 생성 전 실패는 높은 권한의 사용자 쓰기 가능 대체 경로를
만들지 않고 종료 코드 61(지원 밖 ACL), 62(재분석), 63(소유자), 64(앱 부모 생성),
65(control/증거 생성), 66(기타)로 돌아온다. 일반 부모가 자신의 journal에
`PREPARATION_FAILED`와 `INSTALLATION_PREPARATION_*` 한국어 진단을 기록하며,
이 경우 원 ErrorRecord는 회수하지 못했다고 표시한다. 기존 보호 경로 검사
실패는 원 ErrorRecord를 먼저 가림·상한 적용해 기록하고 inner exception을 보존한다.
관리자 단계가 시작할 때 최근 5회만 남긴다. 일반 부모가 보호된 원본을 읽고
자신의 operator evidence/결과 경로에 요약·필요한 결과 사본을 쓴다.

제거 목록에서 `update-control\installation-evidence`는 최근 5회 증거로 보존한다.
updater의 나머지 control 항목과 `versions`는 기존 보호된 startup uninstall
preimage로 이동한다. 되돌리기는 그 state를 원 control에 복귀시키고, 진행 중인
증거와 보존 증거의 경로·바이트는 바꾸지 않는다. 목적지 항목이 이미 있으면 거절한다.
실제 제거/되돌리기와 5차 설치에서의 위치 전이는 **NOT TESTED**이며
[sub-107 보고서](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-107/REPORT.md)의
버전·시험 범위·예외를 따른다. published pin/선언은 최종 컷에서 별도로 갱신한다.

The2136233 lab fourth installation FAILED_ROLLED_BACK before onboarding/relay.
The old0d tree/Run and absent CA relay were restored; harmless0x18B child proof
does not prove an actual CA relay start. Current read-only stage diagnostic V1
reproduced startup ancestor trust rejection, independently of its lost historical
exception: lab/TEST1 shared ancestors inherit AU self Modify; C:\ owner is
TrustedInstaller. V1's empty-preimage failure is a diagnostic defect, preserved
and corrected only in a new frozen V2.

Shared protection is a one-way pre-placement step on the two declared ancestors;
rollback comparisons must separate this intentional ACL change from preserved
code/data/identity/Run state. Uninstall retains protection for other SYSTEM
consumers; restoration requires the supported coordinated procedure. Unsupported
ACL shapes stop with a plain Korean path/reason, without broad reset or recursion.
Source evidence tests:27 checks PASS for finite child bytes/private ACLs/redacted
failures;34 memory checks PASS for exact privileged owner SIDs and B shape/guard
behavior. [V5 lab result](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-66/CA-STAGE-ACL-DIAG-V5.md)
and JSON SHA301aa20353919a85086c2630cf9407d0c5372521974e2626896ed6363d762e08
prove B's exact SDDL/guard, creation/legacy preservation, six native5 denial
boundaries, unchanged repeat and user-owned preclaim rejection under the verified
same-SID/session1/medium filtered token. Actual shared-ancestor repair and fifth
installation remain NOT TESTED. The frozen diagnostic's no-BOM Korean text
defect is preserved; shipped installers/bootstrap now retain UTF8 BOM and an
actual PS5 file-decoding/rejection regression. No field-wide claim follows from
the two observed Windows machines or this account's filtered administrator token.

### Shared ancestor inheritance propagation — 2026-10-02

Admission and target readback compare sorted ACE tuples (SID, mask, allow/deny,
inheritance, propagation, inherited), with exact owner/group and protection state.
After protecting the parent, the child is read again: equal permissions with a
different ACE order are admitted; changed permissions/identity/protection stop.
The fresh descriptor supplies both the write and the before-SDDL evidence.
Both default, either intermediate state and both protected are supported.
Native NTFS RED on the original helper and GREEN on PS5.1/PS7 cover propagation,
unchanged legacy/sibling effective rights, normal writes/rename, repeat and an
external permission change. The non-elevated host test translates owner admission
only; real privileged ownership and the next lab installation are NOT TESTED.
The first-run fixture maps only canonical paths and preserves an already mapped
run, including a short C: basetemp; its original six fixture failures are retained.
[Evidence and candidate](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-123/REPORT.md).

### Placement ACL scope and failed installation recovery — 2026-10-03

Placement retains the protected application parent and admits existing control
directories through the protected creator. Only placed code trees are hardened;
update-control, evidence, user data and unknown siblings are excluded. Native
child exit and redacted output are retained before evidence persistence. A failed
helper emits one bounded JSON stdout diagnostic: 71 for evidence persistence,
72 for a failed native child, 73 for another helper failure. Canonical captures it
in its own journal; original exceptions remain distinct from recording failures.

Rollback attempts parent protection, supported product removal, exact Run restore
and marker cleanup independently, recording every result. Protection uses the
same nonrecursive creator; an ordinary caller's repair is admitted inside the
pinned elevation wrapper under its held writer authority. Existing code/fence
readback still gates release and ordinary relay readiness gates recovery success.

A new installer durably flushes a reentry record before runtime mutation and
updates it after completed removal and before placement. It records owner PID
and UTC start, exact fence/prepared tuple and hashes, delegation hash (no token),
old metadata hashes and Run preimage, removal completion and marker hash.
Reentry supports intact old code with completed removal and uncompleted placement,
no scheduled writer, absent Run/relays, dead PID and a newly claimed old authority.
PID reuse, existing/inaccessible mutexes, missing/ambiguous records, changed code
or tuples stop with one Korean diagnostic. It completes rollback and proves the
old ordinary relay ready before normal installation. Ordinary evidence retains
the established operator-owned ACL; elevated evidence remains machine protected.
This is a narrow rollback finisher, not general lifecycle convergence.
The ordinary repair preflight validates its explicit held authority lease on the
owning thread; only the separate elevated wrapper probes foreign ownership.
Actual same-thread mutex tests cover valid, absent and wrong leases on both PS
engines while stopping before UAC. The shared argument formatter also works
when capture is called from canonical rather than the placement helper.

PROVEN on Windows 11/Python 3.12.10/PS 5.1.26100.9444 and PS 7.6.5: baseline
c75853e native placement/evidence RED; corrected native ACL preservation and parent
repair, fallback capture, continued rollback and durable-record reentry GREEN.
Native owner admission/assignment are translated only in owned D: fixtures;
registry/relay/UAC callbacks are isolated in reentry tests. PS 7 JSON reads preserve
UTC wire strings using DateKind String when available. Original fixture failures
are retained. Actual privileged ownership, UAC, lab installation/GUI and release
acceptance remain NOT TESTED. The legacy sub-125 lab build has no qualifying
reentry record and is deliberately refused; its separate lab repair plan is not
a product hash exception. [Evidence and limits](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-127/REPORT.md).

### Shared ancestor recovery admission — 2026-10-03

Strict relay/evidence, installation and startup-update admission use the existing
ancestor ACE-set/Administrators-owner/protection/reparse check for the literal
`C:\KMTech` and `C:\KMTech\Apps`. Read-only `ProtectedAncestor` admission requires
the protected target; it cannot prepare missing/default folders or write ACLs.
Other paths retain their existing strict leaf masks and rejection diagnostics.
The updater retains its initial code trust check before loading bootstrap, then
rechecks with the validated library's exact ancestor admission before proceeding.

PS5.1/PS7 native D: fixtures cover both literal leaves, supported recovery
admission, default/extra-write/user-owner/reparse rejection, unchanged ACLs and
strict rejection of a matching shape at another path (70 PASS; unchanged owner
admission is translated for the non-elevated host). Old committed helpers reject
the supported shape. Rehearsal-only declarations/packet and lab repair/install
evidence are separate from the formal source change; see
[the task report](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-142/REPORT.md).

### ACL descriptor readback — 2026-10-03

Get-BootstrapAclComparisonKey ignores only native DACL AI bookkeeping and ACE
order for the supported all-Allow models; mixed Allow/Deny order stays exact.
Shared-ancestor admission still checks its exact supported model; task
restore still checks exact XML. PS5.1/PS7 executable task-restore regression
changes the original AI/order failures to PASS and rejects owner/group,
protection, ACE/inherited flag, other control and invalid-descriptor drift.
Owned native D: ACE addition and protection removal remain rejected. This
evidence does not prove reproduction of the lab's parent-induced AI transition,
privileged ownership, lab repair or installation. Raw hash-only receipt recovery
uses exact raw SHA or AI-only raw SHA proof; it cannot recover legacy ACE order.
New receipts retain raw SDDL alongside the unchanged hash. PS5.1/PS7 and Python
receipt regressions cover AI/order admission, legacy conservative rejection,
raw-hash binding and all permission negatives. Formal declaration regeneration
remains zero; the canonical receipt reader changes but its bootstrap pin remains
frozen until the separately committed rehearsal declaration refresh.

### 끝나지 않은 되돌리기 이어 하기 — sub-172 소스 계약

고친 설치기의 보호 control/rollback-continuations/transaction 자리에는 최초 receipt의
바이트 그대로인 사본과 SHA, 최초 자기 경로, 옛·새 manifest, 원 Run/relay 증명,
owner PID/시작 시각과 session/attempt를 묶은 불변 journal을 한 번만 쓴다. 최근 실행
증거 회전과 별도로 남기며 완료 표식도 한 번만 작성한다. canonical 준비/release와
복구 journal의 시각은 기존 fence JSON 문자열 파서를 써 PS5.1/7의 wire 값이 같다.

같은 successor packet으로 설치기를 다시 실행하면 원 owner가 종료했고 원 receipt,
양쪽 전체 코드/record/ACL, startup preimage, source와 operator가 모두 같은지 먼저
검사한다. PlanOnly는 VERIFIED_PENDING만 보고한다. 실제 재진입은 기존 authority와
placement admission 안에서 원 receipt가 가리키는 옛 트리, 정확한 Run, task/pointer,
옛 일반 사용자 relay를 복원한다. 코드가 이미 복원된 경우도 남은 단계를 확인하며
완료 표식 뒤 다음 PlanOnly는 NOT_FOUND다. 불일치는 기록·트리 변경 전에 한국어로
거절한다. 기록 자체를 다시 쓰거나 guard를 우회하지 않는다.

G처럼 고치기 전 installer의 기록만 있는 상태는 이 계약의 입력이 아니다. 공개
legacy receipt self-path 규칙은 그대로이고, 새 journal로 검증된 사본만 최초 binding
경로와 구별한다. 완료 기록은 건수 제한 없이 검증해 보존하고 미완 복구가 둘 이상이면 거절한다. 기록은 자동 정리하지 않는다. 독립 native 랩 수용과 장기간 보관 정책은 별도 확인이 필요하다.

2026-10-04 실제 랩 근거는 [sub-172 REPORT](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-172/REPORT.md),
[G 수선 결과](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-172/LAB-REPAIR-RESULT-G.md),
[H 예행](D:/KMTech/program-improvement-20260912/work/program/w9setupprep/sub-172/CA-5TH-REHEARSAL-H.md)로 구별한다.
G는 새 계약 journal이 없어 NOT_FOUND였고 제품 밖 기존 지원 함수로 원2302/Run/task/pointer/보호/일반 relay를 복원했다.
예행 packet9ca39a8의 H 설치1회는 native0/PASS/REPLACED_VERIFIED이며 실제 보호 child receipt 소비를 확인했다.
원 보호 G receipt와 보험 사본은 유지했고 새 H 보호 parent/helper raw는 D에 byte/SHA 차이0으로 회수했다.
비상승 SID1000/session1/integrity8192 relay RUNNING, 일반 세션 시작 화면/조작0,
지원 check_for_updates1회/provider off/후보 없음/적용0을 확인했다. 외부 feed 조회/실제 업데이트 적용의 증명은 아니다.
H 성공으로 native 미완 rollback 이어 하기를 실행하지 않았으며 그 장애 경로와 독립 검토는 여전히 별도다.
현재 새 복구 수용 범위는 원 startup task 부재/retired writer 부재/원 relay0~1이다.
반복 복구가 fresh controller 생성 뒤 중단된 경우의 native 검증은 없으며 fail-closed 한계를 독립 검토에 남긴다.

## sub-189 지원 설치 운영 경계 (2026-10-04)

A≠B일 때 INSTALL_CANONICAL_PORTABLE.ps1이 실제 B를 from으로 선택하며, direct helper의 current 통째 교체는 거절한다. 새 C와 기존 A/B를 검증하고 보호 receipt를 제어 게시보다 먼저 만든다. 부분 게시/후속 실패는 같은 receipt 복원으로 C를 보존하고 원 policy/active/transition/task와 사용자 Run·relay를 복원한다. 보호 기록에 없는 bytes나 권한 변화는 수용하지 않는다. 미완 복구는 정확한 successor packet과 protected 원 기록이 있어야 이어 간다.

NTFS 함수 회귀의 코드 이동·hash·반복 복원은 실제다. Task Scheduler/CIM/ACL/승격/사용자 token 관측은 시험 seam이며 실제 PC의 A≠B→C 성공·실패·전원 단절 수용은 아직 NOT TESTED다. 첫 설치/A=B 경로의 기존 집중 회귀를 재검증하고, 배포 전 랩에서 옛 판 위 설치 1회 및 내용 소유 제거 수렴 1회를 진행한다. 정식 선언·pin·서명 쌍 재생성은 coordinator 수용 단계로 남긴다.

### sub-189 P2-1 검증 범위

PS5.1/PS7 owned NTFS fixture에서 최초 미완 복구 뒤 controller를 두 번 더 중단하고 같은 원 receipt/journal로 VERIFIED_PENDING에 재진입한다. 실제 Python admission root는 PS의 canonical control root와 일치시킨다. 보호 ACL/registry/task/token 관측은 seam이며 native 상승·전원 단절은 NOT TESTED다. D 경합 timeout은 C의 같은 90초 조건으로 대조하며 실패 로그를 보존한다.

### sub-189 P2-2 검증 범위

fixture Python canonical_control_root는 PS의 L/c와 같다. ordinary persistent relay의 실제 status admission은 active fence에서 종료됨을 부정 사례로 확인한다. completion helper 지연과 구판 completion fence 게시 직후의 2초 scheduling cut로 기존 결함을 노출하고, 수정 판은 같은 ordinary relay PID가 완료 뒤 두 주기 이상 생존함을 확인한다. 최초 중단 뒤 추가 중단 2회→완료도 확인한다. PS5.1/PS7 owned NTFS·process는 실제, 보호 ACL/registry/COM/token 관측은 seam; native UAC/전원 단절은 NOT TESTED.


## 설치 통합의 읽기 전용 수명주기 검사 (sub-248)

canonical의 PlanOnly/설치 상태 분류보다 앞선 검사는 처음 검증한 bootstrap library 안에서 같은 프로세스로 실행한다. 설치 namespace/stock identity·control·trust 설정·실제 task XML의 read-only 관측을 확인하며 거절 시 원래 지원 제거 안내를 유지한다. JSON은 중복 key, 잘못된 key 대소문자, 비객체, 손상/1MiB 초과와 잘못된 판 식별자를 거절하고, 확인 뒤 control을 다시 읽어 의미상 동일함을 검사한다. 실제 query의 subprocess 경로는 기존 auto_update_control admission이 spawn 전에 거절한다. pinned library ScriptBlock은 이미 승인된 변수 기호에 결속하며 원 bytes/hash/AST 검증을 계속 적용한다. 설치/복원/G 및 host/native 증거의 범위는 sub-248 REPORT와 COVERAGE-FIX에 기록한다.

퇴역 child 실패 전문은 앱 공통 `ConvertTo-KmtechRedactedSinkText`를 호출한 뒤
실패 요약에 보존한다. #31 원문 0은 공통 capture 교정과 조립 뒤에만 보증한다.
공통 함수 공급 전 퇴역 진단 두 회귀는 조립 뒤 확인 대상이며 대역·skip으로 숨기지 않는다.

봉인 플래그가 켜진 퇴역 release의 공통 catch도 audit 본문 저장을 건너뛰며,
원 실패는 자기 stages.jsonl에 남긴다. 일반 catch의 감사 기록은 유지한다.
퇴역 마감은 인정 없는 비활성 noncanonical 작업 배열도 거절한다.
공식 옛 비활성 작업의 허용은 공통 정체성·전환 기록 판정 연결 후 조립 확인 대상이다.

## Portable manifest 판독 크기

설치된 portable manifest 확인, placement release 확인, 기존 task 제거와 공유
portable helper의 manifest 판독 상한은 기존64KiB다. runtime 목록은 고정
`runtime-file-inventory.json`으로 분리하고 manifest에는 그 SHA256과 크기만 둔다.
별도 파일도 manifest 이전 지표에 포함하며 stock에 bootstrap-integrity.json은 넣지 않는다.
약288KiB 목록의 여유3.6배인1MiB 상한은 별도 목록 판독에만 적용한다.
각 상한을1바이트라도 넘으면 JSON 해석이나 후속 변경 전에 거절한다.
receipt·relay status·writer contract·pin과 공유 helper의 기존 바이트는 보존한다.
실제 최종 stock과 PS5.1/PS7 경계 회귀의 증거는
sub-265 REPORT에 기록하며 실제 task 제거/전체 설치의 랩 수용과 구분한다.

## 설치 실패 기록과 공식 옛 relay (sub-273)

Canonical journal의 봉인은 outer catch·실패 보상·감사 진단 기록 뒤 마지막에
수행하며 audit 게시까지 기존 authority를 유지한다. 최종 audit/evidence에는 동일한 journal 부분 파일 SHA256을 게시하고
그 뒤 journal에 줄을 덧붙이지 않는다. 성공·실패·부분 파일 회전 경로를 PS5.1/7
실제 기록 함수로 확인하며 관리자 승인·현장 설치 검증은 별도다.

공통 redactor는 모든 sink 직전에 ENV 원문/escape와 JSON 비밀 필드를 가리고 typed 메타데이터·지문·경로를 보존한다. 64 KiB는 잘림 표식을 포함한다. child는 디스크에 원문을 쓰지 않고 RAM에서 가린 뒤 저장한다. 32 MiB RAM 입력 초과는 전문 불가를 명시하고 부분 원문을 저장하지 않는다. journal은 64 KiB 부분 파일 최대16개와 지문 참조를 쓴다.

onboarding·제거·복원 보고서와 DirectSync 보고서도 임시 파일 생성 전에 같은 가림과 유효 JSON 상한을 적용한다. 실패의 원 예외/child 출력은 보호된 별도 JSON과 SHA256 참조로 보존하며 저장 실패를 원 오류로 바꾸지 않는다. 사용자 예외는 가린 마지막 줄 300자와 별도의 가린 전문을 가진다. owner artifact의 내부 경로·지문 비교는 그대로 두고, 보고서 직렬화에서는 경로/지문 이름에 `_path`/`_sha256`를 붙여 공통 메타데이터 계약을 지킨다.

공식 공개 태그의 정체성 묶음과 완전 일치한 옛 relay 예약 작업만 보호된 원 XML/Enabled preimage 후 비활성화한다. 성공 시 비활성화된 작업을 보존하고 새 Run만 활성화한다. 실패 복원은 current/code 복원 결과와 독립적이며 기존 G와 새 relay 부재 확인 뒤 원 작업 Enabled를 자격 없이 복원하고 원 XML SHA256을 확인한다. G 거절은 비활성화를 유지하고 한국어 복구 안내를 남긴다. source-mode/미공개 태그 Run은 공개 묶음에 포함하지 않는다. actual guest 로그오프/로그온과 예약 실행은 코디 예행 몫이며 격리 함수 회귀와 구별한다.

코디가 랩1/2 통과를 확인한 후보에서는 같은 사용자 Password/InteractiveToken도 공식 정체성 묶음으로 인정한다. 실패 설치 복원·성공 설치의 옛 작업 비활성/동시 enabled0은 예행3/4에서 확인하며 실패 시 단일 스위치를 닫는다. 정체성은 XML만 읽으며 guest 실측 계약대로 RunLevel 없음은 LeastPrivilege, SYSTEM LogonType 없음은 ServiceAccount, 사용자 LogonType 없음은 ABSENT로 정규화한다. 명시/생략 XML의 지문은 같고, 미지 값은 거절한다.

The sub-276 guest export is retained separately as `tests/fixtures/official_legacy_relay_guest_v2_0_33.xml` with SHA-256 and proof limits in its `.provenance.json`. Both PowerShell engines compare all 13 normalized identity fields through the full fingerprint, and compare omitted SYSTEM LogonType/RunLevel against explicit ServiceAccount/LeastPrivilege. This export proves scheduler XML normalization; failed official registration and absent wrapper/launcher leave full installation and business relay execution unproven. Author and non-well-known SID fields use the approved fixture placeholders.

Guest XML also omits Settings.Enabled. The shared writer adapter passes `observed_enabled` from the scheduler object; State uses an actual bool when XML omits the element, rejects missing/non-bool observations and contradictions, and refreshes the observation after transitions. No enabled default is guessed. The guest regression provides isolated bool observations separately from the measured XML.



### G read-only removal admission (sub-233, 2026-10-05)

The removal entrypoint checks the resolved owner markers inside its existing `current_user_setup_removal` admission. This single caller passes `admission_source` to the G probe; its fixed `probe_only=True` invocation of the original body returns before directory creation or marker publication, and does not request the unrelated marker-writer capability. Marker recording and every other probe retain their original writer decorator. A static regression fixes the sole caller inside that admission, and separate child-process regressions compare data/control file lists, sizes and mtimes and exercise missing, equal, newer and UNKNOWN markers. This narrow exception was conditionally approved in `msg_eb3b375df3eb`; shared helpers, syntax guards and sink identities remain unchanged.

Registration retains string profile-path arguments after shared resolution. Invalid storage configuration reads no owner payload and retains the BLOCKED report contract; an optional report write first probes its actual parent root and the ambient control marker under registration admission.


<a id="canonical-rollback-support-recovery"></a>
## Canonical rollback 중단과 관리자 지원 복구

새 설치에서 코드 배치 뒤 onboarding·검증·child 실패가 나면 실제 자료 세대 표시로 확정 시점을 먼저 확인한다. 새 판 version·build_id의 표시가 있으면 새 코드를 보존하고, 남은 검증된 current의 reader로 자료 세대와 locator·nested owner를 다시 확인한다. 설치 기록이 없는 transport stock을 설치된 reader처럼 실행하지 않는다. Run·stop·writer preimage와 자료 호환 확인을 마친 경우에만 `FAILED_RUNTIME_RESTORED_CODE_RETAINED`와 `rollback.runtime_restored=true`를 기록한다. 확정 전의 `FAILED_ROLLED_BACK`은 기록된 새 바이트 제거와 이전 코드·runtime 복원 readback을 모두 증명해야 한다. 공통 옛 판 복원 wrapper가 이 출구를 소비한다. 자료 세대 REFUSE·UNKNOWN이나 복원 불확실 상태에서는 fence와 옛 판 백업을 보존한다.

설치 실패와 각 복구 단계의 실패는 같은 시도의 보호 보고서에 따로 남긴다. product child의 전체 공개 실패 레코드에 있는 보호 보고서 경로·SHA256도 이 보호 실패 체인에서 보존한다. 공개 출력은 고정 코드·안내와 원자 게시한 보고서 경로·SHA256만 사용한다. 이 변경은 새 재개 명령을 추가하지 않는다.

설치·검증된 코드 교체의 rollback은 removal 실패를 기록한 뒤에도 코드 복원, Run 복원, 중지 표시 복원, 예약 writer 복원을 각각 시도한다. 옛 코드의 정확한 복원 근거, 실제 G의 허용 결과, Run·중지 표시·남은 relay의 일치가 모두 확인된 경우에만 해당 설치 시도의 fence 해제와 옛 relay 재시작을 반드시 시도한다. 최종 G는 기존 PS old-target 검사와 기존 product의 읽기 전용 `--target-release-root` 판정을 함께 사용하여 옛 relay가 처음 읽는 locator·nested owner까지 확인한다. 초기 검사 뒤 설치 중 marker가 바뀐 경우에도 이 확인 없이 실행을 재개하지 않는다. 단계별 성공·실패는 `rollback.steps`에 남으며 앞선 오류 코드와 실패 기록을 지우지 않는다. G가 거절한 코드 복원은 실행하지 않는다.

확인에 실패한 관리자 설치 화면과 설치 감사 로그의 `rollback.operator_message`에는 다음 문구를 표시한다: “이 PC의 코드, 자료 호환 여부 또는 실행 상태를 확인하지 못해 작업을 안전하게 멈췄습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요. 확인 없이 중지 표시를 지우거나 앱을 다시 실행하지 마세요.” 이때 fence와 relay 정지를 유지한다. 로그의 `rollback.support_recovery_procedure`는 이 절을 가리킨다.

지원 담당자는 기존 설치 감사 기록, replacement receipt·restore evidence, code integrity record와 자료를 먼저 보존한다. `rollback.steps`에서 실패한 단계와 실제 G의 REFUSE/UNKNOWN을 구분하고, 검증된 code·receipt의 원래 경로/해시 및 runtime preimage를 대조한다. 자료 호환 확인 실패에는 기록을 수정하거나 낮은 판으로 강행하지 않고 호환되는 검증 코드와 기존 지원 복원 진입점을 사용한다. 공개 코드 복원 진입점은 `INSTALL_CANONICAL_PORTABLE.ps1 -RestoreVerifiedReplacement`이며 기존 receipt·정확한 old code·사용자/경로·live session authority 검사를 그대로 적용한다. 다른 설치 시도의 active fence를 이 명령이 임의로 회수하지 않는다.

원 설치 시도의 authority가 사라진 채 fence가 남은 경우에는 현장에서 fence 파일을 지우거나 delegation/receipt를 만들어 진행하지 않는다. coordinator에게 보존한 기록과 실패 단계만 전달하고 지원 authority 회수 및 검증된 복구 실행을 요청한다. 종료 조건은 코드 신원·G·runtime 일치, 권한이 확인된 fence 해제, 옛 relay readback 및 업무 수량·소속 보존이다. 이 retained-fence 지원 절차의 실제 랩 1회 PROVEN은 1차 coordinator의 예행 범위이며 이 가지의 headless 격리 시험으로 대체하지 않는다; 아직 실제 랩 수용은 UNPROVEN이다.

실패 안내와 감사는 공통 가림 계약을 따른다. canonical sink wrapper는 `ConvertTo-KmtechRedactedSinkText`, relay 설치기 wrapper는 `redact_for_sink`와 공통 JSON 가림 함수를 호출한다. 이름으로 판정한 비밀 환경 값·민감 JSON 필드를 쓰기 전에 가리고, UTF-8 출력 전체는 표식 포함 65,536바이트 이내로 보존한다. relay 설치기 JSON은 전체 envelope를 제한하고 유효한 JSON으로 저장한다. true·false·null·경로·일반 digest 메타데이터와 원 실패 코드·단계 결과를 유지한다. 실제 값이나 child 출력 전문을 운영 문서에 복사하지 않는다.

### 실행 후 관리자 인증 또는 TLS 자료 판 거절

실행 후에도 관리자 PIN, 품목 새로 고침, relay 재시작과 업데이트 확인은
자격 자료를 실제로 읽는 시점의 자료 판을 확인한다. 다른 판의 앱이 owner
기록을 높이면 기존 창이 열려 있어도 판독·복호·TLS 전송을 진행하지 않는다.
“이 PC의 자료 판을 확인할 수 없습니다” 또는 호환 판 거절 안내가 나오면
자료와 설치 기록을 보존하고 관리자에게 호환 앱 확인을 요청한다. marker나
중지 표시를 지워서 우회하지 않는다. 기존 준비 입력도 첫 판독 전에 재확인한다.

복구 중 audit 저장이 실패해도 원 오류를 유지하고 다른 복원 단계를 계속
시도한다. 별도 evidence에 저장 실패 단계·대상·예외 종류 기록을 시도하고,
둘 다 저장할 수 없으면 UNAVAILABLE 상태를 남긴다. 봉인된 퇴역 audit는
다시 쓰지 않는다. 코드·G·runtime 정합이 증명되어야 fence와 relay를 복귀한다.

공식 옛 relay 되돌림은 보호 preimage XML의 SHA256을 먼저 검증한 뒤, live 작업의 정체성 지문과 enabled를 원 상태와 대조한다. 스케줄러의 기록용 XML 필드 변화는 복원 실패로 판정하지 않는다.

공식 옛 relay 탐색은 빈 결과와 단일 작업을 평탄한 항목으로 반환한다. 같은 이름의 작업이 둘 이상이면 퇴역 admission이 정체성을 추측하지 않고 거절한다.

공식 옛 relay 전환은 기존 `status/current_user_onboarding.json` 설치 결과의 `official_legacy_relay_transition` 필드에 보호 preimage 경로·SHA256·정체성·설치 경로·작업자 SID를 남긴다. 설치 완료 전 새 READY 결과에도 같은 포인터를 기록하며, 이후 onboarding 결과 갱신은 이 필드를 보존한다. 별도 퇴역 시도의 새 증거 폴더에서 이전 preimage를 찾지 않는다. 퇴역 admission은 이 포인터로만 보호 JSON·XML의 SHA256과 정체성을 검증하고 live 작업이 disabled인지 확인한다. 포인터 없음·변조·enabled·unknown은 거절한다.

조립 진단의 가림은 공통 계약 c82c9bdccd16bb0caa0e423fb7578278646ba0e40ac18bd58291c00e70946ccf의 1–3절과 벡터 18개(3106bccafd881396b7bbf1a6b3356ccd41853e4a74bbd7b6918ac2b6a599bfc7)를 따른다. 이름이 _TRANSACTION_ID/_SESSION_ID/_ATTEMPT_ID로 끝나는 env 값은 엄격 UUID/32·64 hex인 경우에만 비밀 판정에서 제외한다. _PID는 양의 1–10자리 숫자, _START는 windows-filetime/linux-startticks와 양의 1–25자리 숫자, _MUTEX는 Local/Global 및 제한된 mutex 이름인 경우에만 제외하며 명시 비밀 이름에는 예외를 적용하지 않는다. 같은 예외는 원 바이트를 유지하는 machine metadata의 쓰기 전 비밀 검사에도 적용한다. Save의 필드별 예외는 없다. 지원 제거 child의 최초 원인은 공통 가림된 removal_child_failure와 독립 stage evidence에 보존한다. 계약 5절의 text_generator는 head + fill_char × fill_bytes + tail로 구성하며 긴 assignment 두 개는 83,200바이트 입력을 사용한다.

무결성·replacement receipt·writer release/prepared·옛 relay preimage/transition pointer·update-control·current-user READY/lifecycle 기록은 인증 metadata다. 원 JSON/LF를 잘라내거나 가리지 않으며 공통 정책이 고른 알려진 비밀 값이 있으면 temp를 열기 전에 거절한다. failure-* evidence, 설치 pack report, audit의 진단 필드와 최종 출력은 공통 가림과 바이트 상한을 적용한다.

공통 텍스트 가림은 예외 접두나 JSON mapping 뒤의 민감 assignment도 별도로 검사하고 값 전체를 가린 뒤 64 KiB로 제한한다. 설치기 캡처는 32 MiB RAM 입력 관문을 넘으면 부분 원문을 기록하지 않으며, 그 아래 입력은 가림 뒤에 제한한다. 접두 두 형태와 긴 unquoted assignment 두 형태는 Python·PS5.1·PS7 및 실제 stdout/stderr 캡처의 원문 조각 개수 0으로 회귀 검증한다.

예외 접두 뒤 민감 값이 `{`·`[`로 시작하는 텍스트도 mapping·list·중첩 구조 전체를 가린다. quote/escape와 괄호 종류를 따라 짝 맞는 끝까지 소비하고, 닫힘 누락·잘림·짝 불일치는 레코드 끝까지 가린 뒤 제한한다. 공개 sink에 원문 조각이 닿는 이 공통 함수 교정은 공개 레코드의 자유 문장 금지와 함께 적용한다.

공통 계약 0f의 구조화 값 벡터 4개(556c1826975f0c73f1a945be802ce761715274dce83cecdba02cd0093f77438c)는 기존 필수 가림 벡터 18개와 별도로 공개·보호 sink를 판정한다. 이적의 기존 지원 stdout와 JSON 진단 출력에 닿는 부류는 P1로 같은 공통 함수에서 고친다. 이후 보호 보고서에만 남는 새 모양은 P2로 BACKLOG에 기록하여 컷 뒤로 미룬다. JSON의 진단 문자열도 가린 뒤 직렬화하여 구조와 가림 뒤 제한 순서를 유지한다.

<a id="ca-installer-public-failure"></a>
### 설치 자식의 공개 실패 줄

공통 계약 0절의 `public_record`/`ConvertTo-KmtechPublicRecord`와 공개 벡터 6개(767ece42ad23dbbcacee4bb98509b35749655017664476ae3d05d852784eb5a5)를 따른다. onboarding·읽기 전용 preflight·제거·교체 lifecycle 복구의 실패는 `CONTAINER_AUDIT_INSTALLER_FAILURE=` 뒤 compact JSON 레코드 하나다. 고정 코드·단계·안내, 예외 형식 이름, 모듈·함수·줄과 허용된 식별자만 공개한다. 데이터 세대의 거부·미확인도 기존 고정 안내를 각각 `DATA_GENERATION_REFUSED`·`DATA_GENERATION_UNKNOWN`으로 전달하여 읽기·변경 차단을 유지한다. 예외 문장·child 출력·자유 문장·중첩 원인 객체는 공개하지 않는다. 형식에 맞지 않는 값은 빼고 `nonconforming_fields`와 `PUBLIC_FIELD_NONCONFORMING`을 남긴다.

onboarding/removal/lifecycle의 사용자 경로와 update-control에는 작업 사용자·관리자만 읽는다는 기존 ACL 증명이 없다. 공개 실패 줄은 `REPORT_UNAVAILABLE`을 표시하고 원문을 새 파일에 쓰지 않는다. 혼합 상태 보고서는 같은 키·타입을 유지하며 자유 진단 필드만 `SUPPORT_FAILURE`로 저장한다. 실패 보고서와 공개 줄은 원인 예외의 형식 이름과 가장 안쪽 앱 프레임의 모듈·함수·줄 번호를 보존한다. 원인 예외에 traceback이 없으면 바깥 예외의 앱 프레임을 사용하며, 예외 문장·지역 변수·파일 경로는 위치 필드에 넣지 않는다. 보고서 게시 실패에도 공개 줄의 위치 정보는 유지한다. identity/profile/credential/receipt/queue/lease/status와 설치기 인증·재개 bindings는 원 값을 보존한다. 알려진 비밀 값이 machine metadata에 섞이면 기존 공통 검사로 temp를 열기 전에 거절한다. preflight는 진단 보고서를 만들려고 자료를 변경하지 않는다.

설치기 private evidence는 기존 `Initialize-InstallationEvidence`/`Set-InstallationEvidenceAcl`의 보호 root를 같은 프로세스와 같은 시도에서 재사용한다. 원문은 공통 가림과 UTF-8 64 KiB 상한 뒤 임시 파일에 쓰고 flush·기존 ACL 검증·원자 이름 변경·실제 바이트 SHA256 readback을 마친다. 해당 writer가 만든 객체와 같은 참조일 때만 공개 `report_path`/`report_sha256`을 포함한다. caller가 예외 Data에 넣은 경로·옛 참조·게시 실패에는 `REPORT_UNAVAILABLE`을 표시한다. 새 ACL 위치나 새 ACL 증명 함수는 만들지 않는다.

보호 진단 JSON의 65,536바이트 상한은 이스케이프·필수 필드·writer가 덧붙이는 LF까지 포함한 최종 UTF-8 저장 바이트로 판정한다. Python `serialize_json_for_sink`와 PowerShell `Write-InstallationOriginalFailure`/private `ConvertTo-CanonicalAuditJson`은 직렬화 크기를 확인하며 진단 문자열만 더 줄여 유효 JSON·앞뒤 원인 맥락·잘림 표식을 유지한다. 상태·인증 metadata는 이 진단 상한의 대상이 아니며 원 바이트와 비밀 검사를 유지한다. onboarding의 replace/create-new 실패 보고서는 원 예외 대신 기존 `SUPPORT_FAILURE` 코드와 원 metadata를 기록한다.

현장 지원 도구의 (가) 출력은 `CONTAINER_AUDIT_SUPPORT=`, lower helper는 `CONTAINER_AUDIT_INSTALL_HELPER=`, canonical 설치기는 `CONTAINER_AUDIT_INSTALL_CANONICAL=`, 적용기는 `CONTAINER_AUDIT_UPDATE=` 뒤 compact JSON으로 내보낸다. 같은 보호 writer가 없는 도구의 원문은 버린다. 기존 고정 문구와 우리 코드가 계산한 개수·상태 코드·ID·시각·버전·SHA는 safe_messages/allowed_codes에 등록하며 그 출력 형식은 유지한다. authenticated task-spec/lifecycle/onboarding-input/Observe 프로토콜은 기존 수신·검증 계약을 유지한다.

| 코드/단계 | 고정 안내 |
| --- | --- |
| ARGUMENT_INVALID / argument_parse | 입력 항목을 확인하고 다시 실행하세요. |
| SUPPORT_FAILURE / runtime_profile_check, runtime_profile_install, protected_admin_install, update_archive_check, registration, relay_install | 설정 파일과 설치 경로를 확인하고 다시 실행하세요. |
| SUPPORT_FAILURE / relay, bootstrap, portable, onboarding/removal | 자료를 보존하고 관리자 지원 복구를 요청하세요. |
| lifecycle 고정 분류 / STARTUP_UPDATE_FAILURE | 기존 설치 상태와 예약 작업을 확인하고 관리자 지원 복구를 요청하세요. |

구조화 값 부류 4개(556c1826975f0c73f1a945be802ce761715274dce83cecdba02cd0093f77438c)는 필수 가림 벡터 18개와 별도다. 새 조각이 공개 sink에 남으면 P1로 고치고, 기존 보호 보고서에만 남으면 P2 BACKLOG에 기록한다.

Writer fence 거절은 공개 실패 레코드에서도 기존 프로세스 종료 코드 23과 등록된 원인 코드(`ACTIVE_WRITER_FENCE`, `FENCE_BINDING_INVALID` 등)를 보존한다. 그 밖의 설치 실패는 기존 종료 코드 4를 유지한다. 예외 문장은 공개하지 않으며 미등록 writer 코드 문구는 보호 전문에만 남기고 공개 고정 코드 `WRITER_FENCE_FAILED`를 쓴다. 설치기 reader는 등록된 원인 코드와 4/23 조합 및 실제 자식 종료 코드가 일치하는지 확인한 뒤 고정 코드로 중단한다.

배포 집합의 PowerShell 파일에 비ASCII 문자열이 있으면 UTF-8 BOM을 포함한다. Windows PowerShell 5.1의 cp949 기본 판독에서도 UTF-8로 감지되어 한국어 안내와 구문을 보존해야 한다. G after 해시와 고정 선언·pin은 BOM을 포함한 committed LF 바이트를 기준으로 확인한다.

설치기는 제공된 wrapper로만 실행하며 PowerShell 진입점에 인수를 손으로 입력하지 않는다. 모르는 인수·잘못된 Mode의 앞단 binder 출력 제한은 컷 뒤 항목이다.

알려진 P2: 새 앱에서 드물게 스캔이 1–5초 멈출 수 있음(writer fence 대기 중 CSV drain·fsync 경합); `msg_12baf9aee551`에 따른 컷 뒤 개선 대상이며 새 스캔의 내구 기록·fsync는 유지한다.

### D-16 E1 · apply 시작 증거(23:0x 정정)

60초는 SYSTEM apply 시작 claim이 없는 상한이다. Authority 뒤 보호 apply-claim에 PID·native creation identity를 기록한다. LIVE/UNKNOWN 소유자는 기존240초 창에서 기다리며 느린90초 apply 동안 일반 실행을 시작하지 않는다. 정상 종료는 기존 guarded sink로 claim을 SETTLED 기록해 증거를 보존한다. 시험을 본 같은 bootstrap도 FAILED/UNKNOWN에서 claim이 NONE/ABSENT이고 일반 writer가 없으며 active G ALLOW·prepared 부재이면 현재 판을 일반 실행한다. 240초 뒤에도 UNKNOWN이면 update_lock 안에서 claim과 수정 시각을 다시 확인한다. 수정된 지 15분을 넘긴 claim만 같은 writer·G·prepared 조건으로 `UPDATE_SUPERVISION_UNAVAILABLE` 일반 실행을 허용하며 같은 claim hash의 지원 코드는 한 번 기록한다. LIVE·신선한 UNKNOWN·시각 읽기 실패·G 거절은 진행 안내+20을 유지한다. 이 복귀는 포인터·시험·READY·CONFIRMED를 쓰지 않는다.

사망한 SYSTEM의 같은 claim은 같은 세션에서 재요청하지 않고 현재 G 허용 판을 일반 실행한다. 지원 코드는 같은 protected claim hash에 대해 한 번 게시하며 다음 로그온의 기존 SYSTEM 작업이 새 claim을 덮어써 재시도한다(1차 결정 msg_c93ef274762a).

### Bootstrap relay 시작의 일시 admission 대기

Run 및 GUI가 만든 bootstrap의 relay 실행은 `WriterFencedError` 중 `WRITER_GATE_TIMEOUT`만 기존 240초 창에서 0.1초씩 쉬며 재시도한다. 각 시도는 기존 launch_version의 admission을 다시 얻으며 시도 사이에는 admission을 보유하지 않는다. 상한은 240초 + 마지막 admission 대기 최대 5초이며 마감 뒤에는 기존 실패 출구를 유지한다. fence 확정·버려진 소유권 등 다른 거절과 GUI 실행 자체의 timeout은 재시도하지 않는다. 포인터·trial claim·READY·CONFIRMED·G 허가·cohort·잠금 순서는 유지한다. bootstrap 밖의 relay launcher admission과 실제 로그온/pythonw 수용은 별도 범위다.

Rollback continuation의 기록된 owner PID가 현재 프로세스에 있어도 UTC 시작 시각이 기록과 다르면 PID 재사용으로 보고 재개한다(R-PID, 1차 결정 2026-10-08). 같은 시작 시각이면 기존 AllowLiveOwner·Depth 0 조건에서만 허용하고, 그 밖에는 `ROLLBACK_OWNER_ALIVE`로 거부한다. 시작 시각을 읽을 수 없으면 `ROLLBACK_OWNER_START_UNREADABLE`로 거부한다. 고정 코드와 보호 보고서 규칙을 적용하며 lineage·receipt·manifest 검증은 그대로 유지한다.

관리자 원격 설치는 [관리자 설치 받기 v0](admin-installation.md)을 따른다. 키트의 READY inventory와 대상 계정이 없으면 거절한다. 기계 배치 뒤 작업자 첫 onboarding이 필요하며, 옛 앱 Rollback·랩 VM 실제 설치 수용은 제품 격리 시험과 별도로 판정한다.

설치 도중 전원이 끊기거나 자식 종료가 미증명인 기계 기록도 같은 지원 입구로 재개한다.
원 authority(버려진 mutex 포함), audit의 자식 PID·생성 시각과 같은 run ID의 살아 있는 프로세스 0을 먼저 확인한다. PID 미기록도 run ID 프로세스가 0이면 복구하며, 살아 있는 자식/손자·관측 실패는 담장과 원본을 유지한다. 명령줄 출력·부팅 시각 사용·대기 반복은 없다. 담장을 직접 지우거나 자식을 종료하지 않는다. audit를 모르면 active fence의 replacement_transaction_id로 install-audit/canonical-portable-<run>.json을 찾는다([지원 입구](admin-installation.md#기계-배치-실패의-지원-재개)).

셸 v3.16.3 수동 복구(M121): 일반 웹 시작 실패 첫 회에는 다음 수동 실행도 웹, 같은 판 두 번째 실패에는 다음 수동 실행이 Tk다. RUNTIME_MISSING이면 다음 수동 실행부터 Tk다. 앱은 web_allowed와 before_exit에 위임하며 표지를 따로 해석하거나 다시 띄우지 않는다. 이는 옛 M84 S1①의 첫 실패 뒤 Tk 기대를 대체한다.


앱 소유 screen-startup.jsonl은 webview.start 진입/반환/예외 종류·경과 ms와 owner 예외 종류를 구분한다. before_exit에는 host 오류 종류·page READY·고정 code/cause를 기록한다. 메시지·stack·입력값·경로는 기록하지 않는다. 기존 screen_shell_fileio writer admission을 대기0으로 시도하고 바쁨/거절/기록 실패는 복구를 막지 않으며 루트 생성이나 report-only 예외를 추가하지 않는다. 로그는 256 KiB에서 더 기록하지 않는다.

run_app에는 셸 기본값과 같은 data/webview2를 udf로 명시한다. EBWebView가 없으면 실제 watchdog 90초, 있으면 30초다. native 시작 판정은 셸 run_app에 위임한다.
