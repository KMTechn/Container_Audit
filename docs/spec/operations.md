# 운영·환경·장애 복구

[제품·기능](README.md) · [데이터·통합 계약](contracts.md) · [백로그](BACKLOG.md) · [중앙 준비도](../../../Program_Spec_Hub/READINESS.md)

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

<a id="ca-o01"></a>
## CA-O01 실행 구조·시작·권한

portable builder의 `APP_ROOT_FILES`는 제품 identity 포트, transfer client/common/store·member exchange view·tray completion을 포함한 root Python 57개를 명시한다.
`APP_PACKAGE_DIRS`·데이터 목록·`PORTABLE_INSTALL_ASSETS`와 실제 import에서 파생한
relay/등록/profile 도구 3개를 함께 탑재한다. 새 root 스크립트는 자동 탑재하지 않으며,
manifest의 필수 모듈이 없으면 빌드를 거부한다. [패키지 회귀](../../tests/test_zero_pe_native_dependencies.py)는
제품·vendor·assets·공유 계약·설정·도구를 포함한 146개의 경로·바이트와 tool import closure를 대조한다.
설치·복구·update preservation용 기존 파일의 제외는 없으며 writer admission은 유지한다.

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

canonical installer는 초기에 로드하는 bootstrap 자체의 고정 SHA256부터 검증한다.
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

`kmtech_shared` 0.3.1은 정본 code `1be471f04b40bc2feef6d5a9f1478ddbb2336050`의
5개 파일(catalog·raster·runtime·__init__·powershell/portable.ps1)을 byte 그대로 고정한다. 별도 `kmtech_shared.lock.json`이 manifest SHA256을
결속하며 기존 factory `contract.lock.json`과 독립적이다. portable/PyInstaller 모두
shared module·PowerShell leaf와 manifest/lock을 포함한다. portable builder는 코드 배치 전에
앱의 고정 lock을 사용하는 자급 checker를 실행하며 leaf를 `app/kmtech_shared/powershell/portable.ps1`에 포함한다. 앱 안의 QA 진입점
`python -B qualification/check_kmtech_shared.py --check`는 이 lock의 hash/version으로
manifest schema·source commit·정확한 package 5파일·각 hash/version을 읽기 전용 대조한다.
`--root <CA 또는 portable app 경로>`로 다른 복사본도 검사한다. checker는 저장소 QA 도구로
제품 패키징에는 포함하지 않는다. `tests/test_kmtech_shared.py`는 형제 없는 앱 복사본에서
정상 pin·누락/추가/변조 거부와 기본 수집을 검증하며 lock 오류·단일 runtime identity도 확인한다.
정본 검증 4함수는 `1be471f`의 `manifest/sync_shared.py`와 source가 같다.
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
| 단일 실행 | [runtime_instance](../../runtime_instance.py)의 canonical data root hash 기반 Windows `Global` mutex | 같은 PC·같은 data root의 중복 GUI를 막는다. 다른 PC까지 같은 mutex로 잠그지 않으며 서버 경쟁은 CAS/lease 계약이다. 비Windows의 no-op은 현장 동시 실행 검증이 아니다. |
| 첫 사용자 준비 | [current_user_onboarding](../../current_user_onboarding.py); frozen Windows 또는 명시 `CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING` | 사용자 state·중앙 등록·relay 시작 요청을 확인한다. `START_REQUESTED`와 onboarding의 `READY`는 relay 업로드·전체 제품 준비 완료를 뜻하지 않는다. |
| 시작 실패·경고 | 중복 실행·잠금 실패·부분 onboarding·품목 검증 실패는 해당 중단 분기 | bootstrap 무결성 기록 **부재**는 경고 후 계속하는 경로가 있고 기록 **불일치**는 차단한다. 모든 무결성 문제가 동일 종료라는 설명은 부정확하다. [시작 메시지·분기](../../Container_Audit.py) |

첫 업무 수용은 같은 사용자·정확한 후보로 정상 시작/중복 시작/부분 준비를 구분하고 current/parked/intent 복구와 실제 작업 가능 여부를 확인하는 것이다. 설치 성공이나 local profile 검사만으로 서버 capability를 입증하지 않는다. [CA-01](README.md#ca-01), [CA-G04](BACKLOG.md#ca-g04), [CA-G05](BACKLOG.md#ca-g05).

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

<a id="ca-custom-root-autostart"></a>
### custom 데이터 루트의 자동시작·재시작

현재 사용자 onboarding은 custom 루트를 정규화해 HKCU `Software\Microsoft\Windows\CurrentVersion\Run`의 `KMTech.ContainerAudit.Relay` 명령 끝에 `--data-root "선택한 절대 경로"`를 저장하고 exact readback한다. 즉시 relay 시작·검증된 교체 복원·설치기 fence 해제 후 재시작도 같은 인자를 사용한다. 다음 로그온에 process/user 환경 변수가 없어도 인자가 우선하며, 토큰·credential·profile 내용은 명령에 넣지 않는다. override가 없는 기본 설치의 명령과 business/relay 분리 경로는 그대로다. 기본 business 경로를 명시 override로 지정한 경우에도 기존 override 의미(`direct_sync` 하위 폴더)를 유지한다.

같은 일반 사용자 PowerShell에서 아래 값을 확인한다. Run 값에 실제 채택한 루트가 있고, 그 루트의 `direct_sync\status\current_user_onboarding.json`의 `data_root` 및 `relay_autostart.command`와 일치해야 한다. 보고 파일은 상태 관측용이며 경로를 자동 선택하는 설정 파일이 아니다.

```powershell
(Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').'KMTech.ContainerAudit.Relay'
```

GUI 수동 시작·onboarding 재실행·canonical 설치/제거/검증된 복원은 **해당 실행의** `CONTAINER_AUDIT_DATA_ROOT`를 채택한 기존 절대 경로로 설정한 뒤 같은 PowerShell에서 수행한다. GUI가 Run 값에서 경로를 자동 발견하거나 user 환경을 영구 변경하지는 않는다. 기존 루트의 존재·원본 상태를 먼저 확인하며, 새 경로 채택은 빈 폴더를 만들어 오류를 숨기는 복구 방법이 아니다. canonical controller는 활성 환경과 Run 명령이 다르면 기존 exact preimage 검증으로 중단한다. 구버전의 인자 없는 Run에서 전환할 때는 구버전과 일치하는 환경으로 코드 설치를 마친 뒤 기존 환경의 `--remove-current-user-setup`으로 이전 relay/Run을 정상 해제하고(업무·등록 자료 보존), custom 루트로 onboarding을 재실행해 Run readback을 확인한다. 두 루트의 relay를 동시에 실행하지 않는다.

루트 연결 해제·삭제·읽기/쓰기 권한 오류 시 custom relay는 `이적 검사 데이터 폴더 오류`를 알리고 exit 1로 멈춘다. 기본 루트로 되돌아가거나 사라진 custom 루트를 빈 데이터셋으로 생성하지 않는다. 화면에 이전 작업자/보류 내역이 나타나거나 전송이 멈추면 작업을 중단하고 Run·실행 명령·onboarding 경로를 대조한다. 원본 데이터/큐를 보존한 채 드라이브·경로·같은 사용자 권한을 복구하고, 정확한 루트로 GUI/onboarding을 시작해 Run을 갱신한다. 기존 relay를 정상 종료한 뒤 같은 Run 명령 재시작 또는 재로그온으로 root/status를 다시 확인한다. credential·DB를 기본 루트에 복사하거나 재등록으로 우회하지 않는다.

GUI 설정은 패키지 `config/container_audit_settings.json` 템플릿을 먼저 읽고 사용자 config의 UI 설정을 덮어쓴다. 사용자 `update_settings`는 제거하여 배포 업데이트 권한/provider 정책을 바꾸지 못하게 한다. frozen에서는 내부 시험 설정도 제거한다. 저장은 사용자 config로 한다. [load_app_settings / save_settings / _drop_release_disabled_settings](../../Container_Audit.py), [기본 템플릿](../../config/container_audit_settings.json).

물류 설정에는 선택 경로가 있다. 메인 앱은 명시 `CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH` 또는 발견한 현재 사용자 profile을 복사한 환경과 사용자 DPAPI decryptor로 전달한다. 사용자 profile이 선택되지 않은 경로는 [logistics_runtime_profile._runtime_environment](../../logistics_runtime_profile.py)의 app-scoped machine profile·Machine 환경 그룹·process fallback 규칙을 따른다. Machine 값 한쪽을 process 값으로 메우지 않는다. profile이 없는 허용 호환 경로에서만 [logistics_transfer_client_from_env](../../transfer_seal.py)의 `WORKER_ANALYSIS_LOGISTICS_*` 설정을 사용한다. TEST1의 엄격한 격리 예외는 일반 운영 설정 우회법이 아니다. 비밀 값이나 DPAPI 내용을 명세·진단 출력에 넣지 않는다.

공급자 호환은 [contract.lock.json](../../contract.lock.json)의 bundle/API/capability 선언과 실제 설치 후보를 함께 확인한다. 물류 lease 서명 검증은 [terminal_operation_lease](../../terminal_operation_lease.py)가 `vendor.kmtech_zero_pe`를 import하는 소스 경로다. CA에 Rework의 sibling/provider 선택 규칙을 그대로 적용할 근거는 없다. 현재 설치된 Python/Tcl, vendor·overlay 유무/해시, 서버 flags·인증 scope·TLS 설정·capability는 이 문서 작업에서 확인하지 않았다. 이름이나 HEAD만으로 설치 조합을 추정하지 않는다. [CA-G05](BACKLOG.md#ca-g05).

품목은 중앙 CSV와 검증 cache·복구 cache를 관리한다. 중앙 갱신 실패 시 검증된 cache로 시작하면 캐시 시각 경고를 표시하고 다음 시작에서 갱신을 다시 시도한다. 검증 가능한 cache가 없거나 검증 뒤 snapshot이 사라진 경로는 시작 오류다. [refresh_item_catalog](../../item_catalog_sync.py), [prepare_startup_item_catalog / load_items](../../Container_Audit.py), [CA-C08](contracts.md#ca-c08). 허용 cache 나이와 갱신 지연의 업무 목표는 미정이다.

<a id="ca-o03"></a>
## CA-O03 스캐너·키보드·화면·사운드·출력

제품 형식 오류는 [현장 안내](../OUTLINE_CONTAINER_AUDIT_USER_MANUAL_20260627.md#제품-형식-오류가-나타나면)의 라벨·스캐너 설정 확인 또는 담당자 문의를 따른다. 짧은 제품 바코드는 제품 라벨 확인 후 다시 스캔하고, 같은 오류가 계속되면 담당자에게 라벨 형식을 확인한다. 길이 초과·위험 형식·트레이 설정 오류에 반복 스캔을 지시하지 않으며, 원문 redaction과 기존 입력 잠금/확인 동작은 유지한다. U06의 fake-Tk 문구 비교는 실제 글꼴 배치·스캐너 입력 확인을 대신하지 않는다.

개별 교환 화면은 [view 모듈](../../member_exchange_view.py)로 위임하며, 기존 owner callback·grab/focus·화면 크기 계산을 유지한다. [호출 순서와 소비자](member-exchange-view.md)를 따른다.
취소 버튼·창 닫기·정상 완료로 개별 교환 창이 닫히면 기존 `_schedule_focus_return`으로 스캔 입력 포커스를 복귀하며, 차단 경고가 있으면 기존 helper가 복귀를 보류한다.

- 개별 교환 창은 화면 높이−96px cap 안에서 입력·완료/취소를 고정한다. 설명·수량·표는 세로 scrollbar/wheel/PageUp/PageDown으로 접근하고 수량에 포커스하면 자동 노출한다. 두 행/heading/가로 scrollbar의 최소 높이를 확보하며 글자나 정보를 줄이지 않는다. 확대/축소 native bbox 검사는 `tests/test_operator_widget_transitions.py`의 기존 교환 사례를 사용한다(이 구현 레인에서는 NOT TESTED).

2026-09-12 UI 변경은 일상 안내 band와 작업 상세를 접고, 알림/현품표 교체 및 사용자가 연 상세만 펼친다.
`저장 전송` 카드의 `상세`는 Tab으로 접근하고 닫은 뒤 비차단 상태에서 스캔 포커스로 복귀한다.
교체 화면 닫기는 진행 중인 조회/교체/복구/차단 상태를 해제하지 않는다.
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
| 현품표 출력 | [phs_reconciliation_workflow](../../phs_reconciliation_workflow.py)의 artifact hash·print proof·`spool_job_id`·journal | `PRINT_FAILED/PARTIAL`, 중앙 ACK 대기·재출력 불확실을 구분한다. spool 접수·종이 배출·올바른 라벨 부착은 각각 확인한다. 일반 스캔마다 자동 인쇄하는 기능으로 해석하지 않는다. [CA-C09](contracts.md#ca-c09) |

[CODEX](../../CODEX.md)의 pygame/PyInstaller 중심 기술 설명은 현재 위 사운드·portable 소스와 차이가 있다. 과거 안내를 그대로 장비 검증 기준으로 사용하지 않으며 [CA-G03](BACKLOG.md#ca-g03)에 후속 정합 작업을 남긴다. 프린터 모델/드라이버·용지·스캐너 모델/firmware·지원 배율의 확정 목록은 미확인이다.

<a id="ca-o04"></a>
## CA-O04 장애·오프라인·취소·재시작 인계

완료의 [저장 결과 적용·notice](tray-completion.md)는 기존 내구 generator 순서를 유지한다.
prepared checkpoint → 기존 중앙 attempt → 완료 계약/CSV ACK → state 적용/표시와,
최종 held 감사 ACK 뒤 완료 접수·동일 command 재시작/중앙 retry를 각각 보존한다.

- W2 B03 headless 검증 묶음은 기존 803개에 [경고·완료 표시 통합시험](../../tests/test_warning_presenter_headless_integration.py) 13개를 포함한다(총 816개). 저장 실패·감사 순서·표시/목록 보존 assertion을 유지하며 실제 GUI 검증과 구분한다.

- 일반/held 스캔의 상태 저장·감사, 제품 입력의 유휴 해제·오류 기록, GUI 완료 checkpoint와 CSV fsync는 기존 직렬 lane worker에서 실행한다. 수량·성공음은 상태 저장 ACK 뒤 반영하며 완료는 내구 기록 후 확정한다. 저장 중 미접수된 다음 입력은 입력창에 유지된다. 정상 종료는 lane→held writer→event writer 순서로 진행 중 저장을 정리하며, 새 epoch에 오래된 결과를 적용하지 않는다. 동기 복구·시작/설정 등 다른 저장 경로가 모두 비동기로 전환된 것은 아니다.

- 일반 이벤트 저장 실패는 200ms UI 상태 확인을 통해 저장 실패·재시도 안내를 표시하고, writer는 대기/재시작 때 `events/_event_outbox`의 원 payload를 재생한다. writer admission의 5초 mutex timeout·fence 거절로 사본 저장에 진입하지 못하거나 사본 쓰기가 실패한 경우도 접수는 False이며 메모리에 원 payload/key와 순서를 유지하고 저장 공간 확인·PC 종료 금지를 안내한다. 메모리에만 남은 사건이 있으면 정상 종료를 거부하고 writer 재시도를 계속한다. admission을 다시 얻거나 사본 저장만 성공한 시점에는 복구 완료를 표시하지 않으며, 원 사건의 내구 CSV append(동일 key의 기존 행이면 fsync)와 사본 정리가 모두 성공한 뒤에만 표시한다. 사본이 내구 저장된 append 실패는 재시작 복구 가능하며, 전원 차단 시 메모리만 남은 사건까지 보존한다고 주장하지 않는다.

- 최고 기록은 양의 유한 시간만 표시한다. 잘못된 값은 제외하고 시작 시 안내하며, 정리/새 기록으로 덮어쓰기 전에 설정 폴더의 `best_time_records.json.bad-*`에 손상 원본을 보존한다. 읽기/정리 저장 실패 시 원본을 유지한다.

아래는 현재 복구 분기와 다음 확인할 결과다. 자동 복구 코드 존재만으로 실행 PASS를 부여하지 않는다. 작업자는 원본 현품표·실물·작업자·컴퓨터·현재 표시를 유지하고, IT/CA 담당은 해당 state·intent·receipt·오류 사유를 연결한다. 고객 데이터나 비밀을 포함한 원본 전체를 보고서에 붙이지 않는다.

| 상황 | 현재 처리·보존할 경계 | 인계·종료 확인 |
|---|---|---|
| 첫 준비 또는 품목 갱신 실패 | onboarding 보고/검증 cache 진단; 유효 cache 없으면 시작 중단 | 같은 사용자·정확한 profile·연결 상태와 cache 분기 확인. [CA-01~02](README.md#ca-01) |
| PHS2 중앙 조회 지연/오프라인 | hold FIFO와 `LOOKUP_FAILED`; 같은 현품표 재시도 | 접수되지 않은 스캔과 보존된 스캔을 구분하고 순서대로 drain. 다른 현품표로 덮어쓰지 않음. [CA-04](README.md#ca-04) |
| lease 없는 신규 완료·부분 집합 | 표준 PHS2 완료 차단; 목록·문맥 유지 | 중앙 GOOD 전량·barcode↔unit·lease binding 확인. 오프라인 무조건 신규 작업 허용이 아님. [CA-07](README.md#ca-07) |
| 유효 lease 이후 중앙 연결 단절 | 내구 intent·`LINKED`·checkpoint와 원 명령으로 후속 시도 | local completion 유무에 맞는 입력 guard 확인. 이미 로컬 완료한 건은 원 key와 완료 시각을 유지해 재조정. [CA-12](README.md#ca-12), [CA-C03](contracts.md#ca-c03) |
| 응답 유실·중앙 정합 충돌 | receipt 조회/원 요청 재생 또는 `OPERATOR_REVIEW` | scope/key/expected version·exact 결과 대조. key 변경·실물 임의 재처리로 충돌을 우회하지 않음. |
| 취소/리셋 쓰기 실패 | 마지막 스캔 취소의 목록 복원·감사 실패 처리, 지연 callback 무효화 | 목록·개수·원본 상태가 일치해야 종료. 리셋은 이미 중앙 확정한 물류의 취소 명령이 아님. [CA-08](README.md#ca-08) |
| 보류·복원 중 종료/손상 | current/parked/hold의 보존·격리·defer; 소유자·같은 현품표 중복 확인 | 복원 대상 내구 저장/감사와 원본 정리 순서를 대조, 유일한 복구 사본 유지. [CA-09](README.md#ca-09) |
| 로컬 CSV·디스크 쓰기 실패 | 완료 기록 실패의 `LOCAL_EVENT_RETRY`, 상태·완료 ID 유지 | 쓰기 가능 복구 후 동일 완료 사건의 중복 억제 확인. JSON·SQLite·CSV를 단일 transaction으로 가정하지 않음. [CA-C01](contracts.md#ca-c01) |
| relay pause·저장 압력·stale claim | queue/status/spool 보존, `blocked_disk_pressure`·backpressure·retry 상태 | 디스크/queue 원인과 operator pause를 구별. receipt 검증 전 spool 삭제 금지. [direct_sync_runtime](../../direct_sync_runtime.py) |
| committed ingest 오류·격리·투영 지연 | 엄격 receipt 미충족은 ACK 성공이 아님; review/영구 실패 구분 | 서버 원본 trace와 행 합계·projection 결과 확인; 단순 HTTP 성공이나 재전송 횟수로 해결 판정하지 않음. [CA-C05](contracts.md#ca-c05) |
| 봉인 전 제품 교체 중 종료/경쟁 | 1~2쌍 CAS·intent·exact receipt 후 로컬 적용 | 전체 구성원/원본 label identity와 중앙·로컬 일치 확인. 부분 로컬 교체 금지. [CA-10](README.md#ca-10) |
| 출력 일부 성공·결과 불명 | print journal·artifact·중앙 exchange 재조회/확인 | 재출력 필요와 이미 출력/활성화 여부 확인, 종이까지 별도 대조. [CA-11](README.md#ca-11) |

장애 인계의 완료 기준은 미해결 상태마다 업무 ID·마지막 내구 경계·중앙 확인 여부·담당·다음 행동이 남고, 복구 후 중복 효과/분실 없이 허용 상태에 도달하는 것이다. 허용 대기시간·교대 인계 책임자·장애 알림 수준은 [CA-G06](BACKLOG.md#ca-g06)의 미정 요구다. 실행 검증은 [CA-G04](BACKLOG.md#ca-g04)와 별개로 추적한다.

<a id="ca-o05"></a>
## CA-O05 설치·교체·재설치·롤백·백업

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
| lease 시간 | v1 서명 duration 60초~24시간 검증, 기존 완료의 재검증은 저장된 완료 시각 사용 | 실제 발급 기간·허용 offline 업무시간을 확정하는 값이 아님. [terminal_operation_lease](../../terminal_operation_lease.py), [TransferSealCoordinator._verified_operation_lease](../../transfer_seal.py) |
| 수신→화면 최신성 | whole-file relay·projection·API·렌더의 분리, `pcs_completed`는 관측 완료 수량 | 허용 지연/업무일·누락 경고·복구 후 따라잡기 시간 미정, live 측정 없음. [CA-C07](contracts.md#ca-c07) |

통신 timeout·poll 간격·retry 지연은 구현 파라미터이고 작업자 응답시간 SLA가 아니다. 성능/복구 목표 확정은 [CA-G01](BACKLOG.md#ca-g01), [CA-G06](BACKLOG.md#ca-g06), 실제 측정·장비·후속 설치 입증은 [CA-G04](BACKLOG.md#ca-g04)가 담당한다.

2026-09-09 최적화는 원본 `9e38334f`의 합성 normal/held, catalog 50/1,000개 기준을 먼저 측정했다. [고정 기준·목표](D:/KMTech/optimization-implementation-20260909/Container_Audit/BASELINE-AND-TARGETS.md)는 handler CPU와 실제 파일 저장 companion을 분리하며, field SLA나 실제 VM paint/네트워크 latency를 주장하지 않는다. CA-S1a `920831d` 이후 같은 호출의 held 검색 재사용은 59 focused PASS와 고정 CPU/파일 저장 회귀 목표를 충족했다. 새 held 시험의 disk ACK와 UI callback을 혼동한 최초 2 FAIL도 E 증거에 보존했다. 검색은 held 한 건 2→1회, 8건 16→8회이며 저장/SCAN_OK/ACK 횟수는 같다. [전후 결과](D:/KMTech/optimization-implementation-20260909/Container_Audit/RESULT.md)와 실제 VM Computer Use 전체 업무 수용 [CA-G12](BACKLOG.md#ca-g12)를 구분한다.

2026-09-11 [잔여 native 실행 준비](D:/KMTech/optimization-implementation-20260909/Container_Audit/remaining-goal-prep-20260911/PLAN.md)는 기존 local 목표를 유지하며20쌍/40arm의 행동별 경험적 분포를 별도로 설계했다. 동일50행 입력·원본9e/최종2b·AB/BA 순서와 기존3ms/문자·50ms poll을 고정하고 startup/로그인과 실제 Return 이후를 분리한다. 경험적p95는19/20순위이며 population 꼬리 보장이 아니고, 다음 실제 접수 상한에는 controller 대기가 포함되어 최초 허용 시간으로 해석하지 않는다. 정확한 전체 표시와 내구 결과를 함께 확인하며 실패·timeout·부분 갱신·부하 차이를 제외해 성공 표본을 채우지 않는다. unsigned 입력·경로 delta와 parser만 host에서 확인했으며 실제 측정·guest·서명·전송은 미실행이다. Main이 방법 검토와 실제 충돌 자원을 배정하고, 별도 정상 연결 업무는 진짜 M06 수신GOOD1·중앙 봉인 ACK·후속 Label/Web 영수증을 사용한다.

<a id="ca-o07"></a>
## CA-O07 2026-09-08 FULL 실패의 환경·fixture 경계

- `tk_serial_ui_lane`/PHS2 preflight headless fixture는 assertion 실패에도 `finally`에서 소유 lane·hold writer를 drain/close하고 잔존 non-daemon thread를 검사한다. `TaskHandle.join(timeout)`의 bool은 작업 완료만 뜻하므로 테스트는 별도로 UI 적용(hold 파일과 최신 snapshot 일치 포함)을 기다린다. 제품 lane은 non-daemon을 유지한다.

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
