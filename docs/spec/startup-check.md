# 시작 가능 여부 읽기 전용 확인

설치된 같은 packet에서 `runtime/python.exe -I -B app/startup_check.py --json`을 실행한다.
현재 작업자 계정에서 확인하며 stdout은 `app_startup_check.v1` JSON 한 줄이다.
종료는 READY 0, 확인된 시작 불가 10, 못 읽음·예외·10초 예산 초과 20이다.
이 확인은 실행 허가를 발급하지 않는다. 실제 앱의 기존 시작 관문이 최종 판정한다.

필드는 `schema`, `app`(CA), `version`, `build_sha`, `startable`, `status`,
`reasons`, `category`, `categories`, `checked_at`(+09:00)이다. 경로·계정 식별자·
오류 원문·자격 정보는 담지 않는다. `category`는 첫 시작 불가 묶음이며,
시작 가능하면 READY다. `categories`는 겹치는 묶음을 순서대로 담는다.
ALREADY_RUNNING만 있으면 시작 가능 여부를 바꾸지 않는다.
까닭→묶음의 정본은 [startup_check.py](../../startup_check.py)의 `REASON_CATEGORIES`다.

기존 업데이트 인계 조건, writer fence 읽기, 설치 inventory, 자료 판 하한·build·표지,
계정 설정 읽기, 인증된 품목 캐시·복구본, relay 자동 시작 명령을 재사용한다.
품목 캐시가 없어도 기존 과도기 스위치가 켜져 있으면 시작 가능하다.
프로세스 목록은 로컬 Windows API로 관찰하며 실행 잠금을 잡지 않는다.
설치 inventory의 경로·크기·집계와 manifest·앱 진입점·확인 CLI의 hash를 대조한다.
큰 runtime 파일 전체 hash는 다시 계산하지 않으며 이 관찰 결과를 기존 전체 검증 cache에 넣지 않는다.
단계와 inventory 항목마다 10초 예산을 확인한다. 실물 HDD 상한 검증은 별도 현장 시험이다.

CLI는 GUI를 import하지 않고 디렉터리·보고서·표지·SQLite·pyc를 만들지 않는다.
네트워크, writer admission, named mutex, bootstrap·relay 실행도 없다.
HTTP 라이브러리의 import 시 loopback 기능 검사까지 포함해 CLI 판정 범위에서는 소켓 생성을 막는다.
저장·전환·등록이 필요하면 기존 설치·복구 절차에서 수행한다.
현장 시작과 알림·관리자 원격 조치는 설치 키트 실행기가 담당한다.

## 앱 시작 길의 관찰·기록 (G)

`main`은 화면 전에 관찰을 시작한다. CLI를 다시 실행하지 않고 기존 관문이 이미 읽고
판정한 결과를 받아 같은 JSON을 만든다. 정상 시작은 GUI 생성 전, writer admission 밖에서
기록한다. 같은 정상 결과는 다시 쓰지 않으며 생성 중 기존 거부가 발생하면 같은 파일을 고친다.
설치기가 만든 `%PROGRAMDATA%\KMTech\start-check\YYYYMMDD-CA.json`에 임시 파일→
`os.replace`로 한 줄을 원자 기록한다. 폴더를 만들지 않는다. 폴더 없음·쓰기 실패는 조용히 넘어간다.
이 파일은 실행 허가·자료 판 표지가 아니다. ACL과 알림·SSH 원격 고침은 설치 키트 몫이다.

G0: 기존 거부의 종료 코드만 유지한다. 원자 저장 후 한 줄을 제한된 길이로 다시 읽어
바이트 일치를 확인한 경우에만 그 거부 화면을 닫기 단추 하나의 Tk 안내로 바꾼다.
폴더 없음·저장 실패·읽기 실패·불일치면 기존 구체 messagebox를 그대로 사용한다.
거부 안내를 바꾸기 전에는 이전 저장 성공 여부와 관계없이 다시 저장·확인한다.
「이 PC 는 지금 새 프로그램을 열 수 없습니다. 관리자에게 알렸습니다. 다른 작업대로 옮겨 주세요.」
경고 후 계속, bootstrap 복구 인계, 이미 실행 중인 경우의 기존 흐름을 따른다.
새 관찰이 실패해 UNKNOWN이면 기존 시작 흐름을 계속하고 기존 관문이 최종 판정한다.
품목 목록 거부는 ITEM_CATALOG_UNAVAILABLE에 고정 세부 코드 하나를 더한다. 403은
ITEM_CATALOG_HTTP_403, 다른 HTTP 오류는 ITEM_CATALOG_HTTP_ERROR, 시간 초과는
ITEM_CATALOG_TIMEOUT, 연결 실패는 ITEM_CATALOG_UNREACHABLE이다. 기존 고정 원인은
ITEM_CATALOG_{REQUEST_FAILED_NO_CACHE,PROFILE_LOAD_FAILED,PROFILE_INCOMPLETE,PROFILE_ABSENT,
URL_NOT_TRUSTED,SNAPSHOT_UNAVAILABLE_AFTER_VERIFY,SNAPSHOT_PARSE_FAILED}로 보존한다.
값·원문은 넣지 않는다. REASON_CATEGORIES가 K1 허용 목록이며 미등록 원인은 UNKNOWN_CATALOG다.
G 결과와 H 화면 준비 표지의 두 고정 report sink만 admission 예외로 등록한다.
다른 sink의 `report_only` 사용과 기존 admission 안의 결과 쓰기는 거부한다.
관찰 추가로 네트워크·writer 허가·mutex를 획득하지 않는다.

**시험 전용** `KMTECH_START_CHECK_TEST_CATEGORY`에 고정 묶음 이름을 넣으면 결과만 강제한다.
기본은 꺼짐이다. 설치기·업데이트는 이 변수를 설정하지 않는다. 주입 자체가 새 거부를 만들지 않는다.
기존 거부 상태를 함께 준비해야 안내 창을 시험할 수 있다. UNKNOWN 주입은 평소 시작을 계속한다.
기존 커밋의 main과 종료·준비 순서를 대조하는 headless G0 시험, 가짜 Tk 안내, 원자 쓰기·
쓰기 실패·UNKNOWN·주입 시험은 소스 증거다. 실물 TEST1/REWORK1과 HDD 시간은 현장 lane에서 남는다.

## 평상시 화면 준비 표지 (H)

첫 화면 이벤트에서 `%PROGRAMDATA%\KMTech\start-check\YYYYMMDD-CA.gui.json`을 예약한다.
프로세스마다 한 번, daemon thread에서 `startup_check_report._write_gui_ready`가 임시 파일→
`os.replace`로 JSON 한 줄을 쓴다. 화면 스레드는 native 조회·디스크 쓰기를 기다리지 않는다.
필드는 `schema`(app_gui_ready.v1), `app`(CA), `version`, `build_sha`, `pid`,
`process_start_utc`(Windows GetProcessTimes의 실제 생성 시각, UTC), `ready_at`(+09:00)뿐이다.
판·SHA는 기존 시작 판정의 값을 전달한다. 폴더 없음·쓰기·thread 시작 실패는 조용히 넘어간다.
폴더·ACL 생성은 설치 키트 몫이다. 업데이트 시험은 기존 staging `ready.json`을 그대로 쓰고,
성공한 준비 표지만 H에 예약한다. 오래 걸리는 report worker를 join하거나 writer admission을 잡지 않는다.
