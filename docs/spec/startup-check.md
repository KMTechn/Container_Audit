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
