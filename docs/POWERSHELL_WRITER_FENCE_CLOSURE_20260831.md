# PowerShell writer-fence detector closure — 2026-08-31

## 결론

직접 실행 가능했던 `INSTALL_THIS_PC.ps1` production placement 경로를 `canonical_code_placement` writer sink로 등록하고, exact session/attempt/replacement-transaction/delegation-token과 활성 session authority가 없으면 승격과 첫 mutation 전에 거부하도록 닫았다. 검출기는 portable builder의 `PORTABLE_INSTALL_ASSETS`에서 배포 PowerShell 자산을 자동 파생하고, 새 `.ps1` 자산에 guard 계약이 없으면 release gate를 거부한다.

최종 구현 pin은 `f7f8944bd1b44af6551783c7b761b4d702935b35`, tree는 `2b1c8bf28bba0ddb0e0789930677c9a4b3e62f4f`, inventory contract는 `7b9e73b17fe047bad4450be5350b4b3752793be416df6c85e64edff4b5cbe81d`다. 새 packet은 `E:\d5`다.

## detector 맹점 목록과 판정

아래의 “존재”는 먼저 배포 대상 5개 PowerShell 자산을 기준으로 하며, 필요하면 저장소 내 비배포 도구도 별도로 적었다. “정적 검출”은 실행 primitive가 보인다는 뜻이지, 동적으로 만들어지는 최종 target/payload의 의미까지 증명한다는 뜻은 아니다.

| 실행/포함 형태 | 실제 존재 | 위험 | 정적 검출 판정과 현재 처리 |
|---|---|---|---|
| 직접 실행 PowerShell script/helper | **있음**. `INSTALL_THIS_PC.ps1`에 26개 writer site가 있고 종전에는 직접 production 실행이 가능했다. | **높음**. UAC 승격 뒤 ACL·copy/move/remove를 수행한다. | **가능**. 배포 `.ps1` 목록을 builder에서 파생하고 mutation이 있는 새 자산은 등록된 entry guard가 없으면 실패한다. 현재 helper는 `canonical_code_placement` sink다. |
| `.ps1` dot-sourcing | **6개**. 세 entrypoint가 두 helper library를 dot-source한다. | 임의/변조 target이면 **높음**. 알려진 현재 library는 top-level mutation이 없지만 함수 호출 시 writer다. | operator 자체와 알려진 target symbol은 **가능**. 포함된 5개 자산의 내용도 함께 스캔한다. runtime 계산 target의 실제 파일 identity는 일반적으로 **해결 불가**다. |
| `Import-Module`, `Import-PSSession`, `using module`, implicit module auto-load | 명시적 import는 **0개**. implicit command resolution 가능성은 PowerShell 자체에 존재한다. | module initializer/remote command import이면 중~높음. | 명시적 import primitive는 dot-source 계열로 **검출 가능**하고 gate에 고정했다. implicit auto-load target과 설치된 외부 module 내용은 **완전 해결 불가**다. |
| `Start-Process` / `Invoke-Item` / 표준 alias | `Start-Process` **3개**, `Invoke-Item` **0개**. | 외부 writer/process면 **높음**. | 명시 cmdlet과 `saps`, `start`, `Invoke-Item`, `ii`는 **검출 가능**. runtime alias 재정의의 실제 의미는 **해결 불가**다. |
| `Invoke-Expression` / `IEX` | **0개**. | 문자열이 writer code면 **매우 높음**. | primitive는 **검출 가능**하고 unfenced이면 거부한다. decoded/computed payload는 일반적으로 **해결 불가**다. |
| `&` call operator | **18개**. native ACL, PowerShell/Python child, predicate/scriptblock 호출이 섞여 있다. | target에 따라 낮음~**높음**; process/native writer면 높음. | operator는 **검출 가능**. `$variable` target의 runtime 값과 command redefinition은 **완전 해결 불가**다. `2>&1` redirection은 call operator로 오분류하지 않는다. |
| bare `.ps1`/`.psm1`/`.exe`/`.cmd`/`.bat`/`.com` 또는 알려진 native command 직접 실행 | 배포 자산의 bare 실행은 **0개**; 현재 external 실행은 주로 `&`/`Start-Process`다. | 직접 script/native writer면 **높음**. | 정적 extension, 상대 script 경로, 알려진 `powershell/pwsh/cmd/schtasks/sc` 계열은 **검출 가능**. 임의 extensionless command가 alias/function/module인지 executable인지 전부 판별하는 것은 **불가**다. |
| COM/WMI/CIM process creation | **1개**. canonical `StartRaw`의 `Win32_Process.Create`다. 일반 COM 생성은 0개다. | **높음**. | explicit CIM/WMI create, `[wmiclass]`, `-ComObject`, `GetTypeFromProgID`는 보수적으로 **검출 가능**. 계산된 ProgID/method와 외부 COM 구현 의미는 **해결 불가**다. |
| .NET `System.Diagnostics.Process.Start` / instance `.Start()` | 배포 자산은 **0개**. 비배포 `tools/sandbox_container_sac/guest.ps1`에는 instance start가 **1개** 있으나 Sandbox는 실행하지 않았다. | 배포 경로에 들어오면 **높음**. | explicit static type, `Process::new`, `ProcessStartInfo`+`.Start()`는 **검출 가능**. reflection으로 숨긴 type/method는 reflective 잔여 위험이다. |
| Win32 native process API / P/Invoke | 배포 자산은 **0개**. | `CreateProcess*`, `ShellExecute*`, `WinExec`이면 **높음**. | 알려진 API 이름은 `native_process_api`로 **검출 가능**. 계산된 export, ordinal, native wrapper 내부 동작은 **해결 불가**다. |
| Task Scheduler COM API / scheduled-job API | Scheduler COM은 **0개**; ScheduledTask cmdlet mutation은 기존 **7개**다. | 지속 writer 등록/실행이면 **높음**. | `Schedule.Service`, task-definition method와 기존 ScheduledTask wrapper는 **검출 가능**. 계산된 COM dispatch는 잔여 위험이다. |
| service control cmdlet/`sc.exe`/WMI/.NET/PInvoke | 배포 자산은 **0개**. | SYSTEM service 생성·변경이면 **매우 높음**. | 알려진 cmdlet, `sc.exe`, `Win32_Service`, `ServiceController`, SCM API 이름은 **검출 가능**. 동적 native export/unknown wrapper는 **해결 불가**다. |
| reflection, scriptblock `.Invoke`, PowerShell SDK/runspace, job/event action | explicit reflection/runspace는 **0개**; 동적 call operator 18개와 self-test의 encoded child process 1개가 있다. | payload가 writer면 **매우 높음**. | `GetMethod`/`Invoke`, `ScriptBlock::Create`, `AddScript`/`BeginInvoke`, `RunspaceFactory`, `Invoke-Command`, job/event-action cmdlet은 **검출 가능**. 실제 동적 payload는 **해결 불가**다. |
| encrypted/downloaded/generated code, runtime alias/function replacement, unknown module | 현재 pin에서 위험한 실체는 **확인하지 못함**. | 실체가 생기면 **높음**. | 일반적인 정적 완전 검출은 **불가**. primitive가 보이면 거부하지만, primitive 자체까지 runtime에 생성되거나 알려지지 않은 module 안에 숨으면 inventory만으로 폐쇄할 수 없다. runtime admission과 byte pin/review가 필요하다. |

Python 쪽은 기존 detector가 `subprocess`, `os.exec/spawn/system/startfile/popen`, `asyncio.create_subprocess_*`의 알려진 호출을 sink로 본다. `ctypes`/computed `getattr`/unknown extension 내부 process creation은 여전히 정적으로 완전 해결할 수 없는 잔여 위험이며, 이번 PowerShell closure가 그 사실을 바꾸지는 않는다.

## helper fence

- production (`-DryRun` 아님, guarded test override 아님)은 `WriterFenceHelperPath`, helper SHA-256, 32-hex session/attempt/transaction, 64-hex delegation token을 모두 요구한다.
- helper path는 exact sibling `tools/container_writer_fence.ps1`이어야 하고 bytes가 전달된 manifest pin과 일치해야 한다.
- `Enter-ContainerWriterDelegatedOperation`은 admission mutex 안에서 활성 fence, live authority mutex, exact tuple, allowed status, delegation hash, `canonical_code_placement` source, expiry를 재검증한다.
- 비승격 process에서 preflight를 한 뒤 UAC 경계를 넘고, 승격 child가 다시 exact lease를 얻어 restore/uninstall/install/ACL/file placement 전체 동안 보유한다. `finally`에서 lease를 반환한다.
- canonical installer의 install과 later restore 두 helper call이 같은 exact tuple/token을 전달한다. session recovery도 기존 exact delegation을 재사용하거나 임시 exact delegation을 만들고 helper/fence bytes를 read-lock한 채 실행한다.
- packet helper 직접 실행 검증은 production args 없이 내부 exit code **1**로 첫 mutation/elevation 전에 거부됐다.

## 재전수와 이전 수치 대조

| 지표 | 이전 v6 | 현재 v7 | 차이 |
|---|---:|---:|---:|
| Python closure modules | 87 | 87 | 0 |
| Python sink functions | 166 | 166 | 0 |
| Python direct-mutator functions | 122 | 122 | 0 |
| Python external-process sites | 9 | 9 | 0 |
| Python external-control literal sites | 4 | 4 | 0 |
| PowerShell writer sinks | 0 (미모델링) | 1 | **+1** |
| cross-language sinks | 166 | 167 | **+1** |
| PowerShell mutation scopes | 미기록 | 31 | +31 신규 지표 |
| PowerShell direct mutation sites | 미기록 | 55 | +55 신규 지표 |
| PowerShell execution boundaries | 미기록 | 28 | +28 신규 지표 |
| ScheduledTask cmdlet sites | 7 | 7 | 0 |
| uncovered Python mutators | 0 | 0 | 0 |
| PowerShell guard failures | 0 | 0 | 0 |

현재 28개 PowerShell execution boundary의 실제 분포는 `call_operator=18`, `dot_source=6`, `start_process=3`, `com_wmi_process_create=1`이다. 현재 pin에 0개인 정적 유형도 detector와 주입 테스트에는 포함된다.

- 이전 inventory: schema v6, `d4708bcaae436cbba313b9c6809b0ea2c8ffc7f2ee6637063720c4d2a2db3062`
- 새 inventory: schema v7, `7b9e73b17fe047bad4450be5350b4b3752793be416df6c85e64edff4b5cbe81d`
- `INSTALL_THIS_PC.ps1`: `canonical_code_placement`, guard `Enter-ContainerPlacementWriterFence`, 26 writer sites, guard line 709

## 종류별 주입 검증

각 fixture는 `INSTALL_THIS_PC.ps1`에 unfenced primitive를 넣고 derived snapshot을 만든 다음 실제 portable builder의 `_assert_writer_sink_inventory` gate를 별도 process로 호출했다. 모든 행에서 내부 gate exit code는 **1**이었고 `writer sink inventory is not release-admissible`을 확인했다. 그 뒤 같은 primitive를 등록된 fixture guard 뒤로 되돌려 `powershell_guard_failures=0`을 확인했다.

| 주입 사례 | 기대 failure kind | gate exit | 되돌린 뒤 failures |
|---|---|---:|---:|
| direct helper entrypoint | `script_entrypoint` | 1 | 0 |
| `.ps1` dot-source | `dot_source` | 1 | 0 |
| `Import-Module` | `dot_source` | 1 | 0 |
| `Start-Process` | `start_process` | 1 | 0 |
| `Invoke-Item` | `start_process` | 1 | 0 |
| `Invoke-Expression` | `invoke_expression` | 1 | 0 |
| `& $runtimeCommand` | `call_operator` | 1 | 0 |
| bare `powershell.exe -File` | `native_command` | 1 | 0 |
| relative `.\fixture.ps1` | `native_command` | 1 | 0 |
| `Win32_Process.Create` | `com_wmi_process_create` | 1 | 0 |
| generic `New-Object -ComObject` | `com_wmi_process_create` | 1 | 0 |
| `.NET Process.Start` | `dotnet_process_start` | 1 | 0 |
| Win32 `CreateProcessW` | `native_process_api` | 1 | 0 |
| `Schedule.Service` | `scheduler_com` | 1 | 0 |
| `New-Service` | `service_control_api` | 1 | 0 |
| reflection `.Invoke()` | `reflective_invocation` | 1 | 0 |
| runspace `.BeginInvoke()` | `reflective_invocation` | 1 | 0 |

주입 test process 자체는 `17 passed`, exit code **0**이었다. 별도로 새 shipped `.ps1` 자산을 builder 목록에 넣되 guard 계약을 등록하지 않은 사례와, 등록된 helper의 guard line 앞에 직접 file mutation을 넣은 사례도 gate failure로 고정했다.

## 테스트와 exit code

- `python tools/derive_container_writer_sinks.py --check`: inventory hash 출력, exit code **0**.
- `tests/test_container_writer_sink_inventory.py`: **28 passed**, exit code **0**.
- writer-session + zero-touch focused: **50 passed**, exit code **0**.
- 17종 주입: 각 내부 gate exit **1**, 되돌림 failure 0; pytest **17 passed**, outer exit code **0**.
- 권위 있는 최종 전체 suite (`--basetemp E:\bt\ca11599-full`): **2226 passed, 4 skipped**, 233.52초, exit code **0**. baseline 2203 passed 대비 23 passed 증가했고 process가 정상 종료했으므로 pass 뒤 hang이 아니다.
- skip 4개: 이 volume에 8.3 alias가 없어 2개, 비승격 process라 Windows ACL integration 2개.

비권위 시도도 숨기지 않는다.

- C: code-root 아래 basetemp 실행: 경로 격리 정책 때문에 41 failed, exit **1**; 테스트 위치 오류였다.
- 긴 E: basetemp 최종 실행: 2225 passed/4 skipped/1 failed, exit **1**; upload-status 경로가 Win32 경로 길이를 넘었다. 같은 test를 짧은 E: path에서 격리 재실행해 1 passed/exit **0**, 그 뒤 전체 suite도 짧은 path에서 exit **0**으로 재확정했다.

## 새 pin과 packet

- implementation commits: `219db560579bb96480d428d27ae0e85de7d9f523`, 최종 확장 pin `f7f8944bd1b44af6551783c7b761b4d702935b35`
- final source tree: `2b1c8bf28bba0ddb0e0789930677c9a4b3e62f4f`
- packet: `E:\d5`
- manifest aggregate: **2,278 files / 48,433,875 bytes** before manifest
- independently rechecked core pins: **10/10**
- helper SHA-256: `d7968cec8e0398560ae2da79d1a7d4b609c9a8a5dbea7d2b11d6ea249c9a45b6`
- writer-fence helper SHA-256: `1277eb46684dec2364fe35e9c00b76d6d0f6b81de4992041f3aa37a56bc20b1f`
- writer-session adapter SHA-256: `4541cdd428e42a35c5ea18ad22016689da5aa7c2c40d091851603cab6a8a4681`
- writer-session contract SHA-256: `62878de7b03fa6aaa6f1955d6f8b0eb7a4de24530d2d459b3355d9cc49d6655c`
- inventory file SHA-256: `d567e4d586c02364f91dac4c8d9c1b380e86dcb14aac4621eeaa4b4fde9eb1a6`
- inventory contract SHA-256: `7b9e73b17fe047bad4450be5350b4b3752793be416df6c85e64edff4b5cbe81d`
- packet validation: aggregate/pins/inventory/5 PowerShell parses exit **0**; writer session self-test **58/58 PASS**, system mutation 0, exit **0**.

첫 packet build는 공개키 파일 경로를 값으로 넘겨 exit **1**이었고, 생성된 partial `E:\d5`를 검증 후 삭제했다. 공개키 문서의 `manifest_public_key` 값 자체를 넘긴 최종 build는 exit **0**이다.

## UNKNOWN / residual risk

1. 계산된 command target, decoded/encrypted/downloaded payload, runtime alias/function replacement, implicit external module auto-load, computed COM ProgID/method, reflection/PInvoke ordinal 및 unknown native/module 내부 동작은 정적 inventory로 완전 해결할 수 없다. primitive가 보이는 경우는 거부하지만 primitive 자체가 runtime에 생성되면 잔여 위험이다.
2. PowerShell 검출은 lexical scanner다. 배포 자산 목록은 builder에서 자동 파생하지만 완전한 PowerShell parser·동적 call graph·dominance 증명은 아니며, multiline/here-string/control-flow와 함수 호출 순서를 모두 의미론적으로 증명하지 못한다.
3. 알려진 dot-source target을 포함해 현재 5개 shipped asset은 함께 스캔하고 packet manifest가 byte-pin한다. 그러나 사용자가 변조된, manifest 검증을 거치지 않은 script copy 자체를 실행하면 script가 자기 guard를 제거할 수 있으므로 그 경우는 보증 범위 밖이다.
4. 비배포 test/build PowerShell은 product inventory에 포함되지 않는다. 새 파일이 `PORTABLE_INSTALL_ASSETS`에 들어오면 자동으로 스캔·미등록 guard 거부되지만, 배포 계약 밖 파일의 writer 여부는 이 inventory가 증명하지 않는다.
5. 회사 서버·공장 PC에는 접속하지 않았고 Windows Sandbox도 기동하지 않았다. 실제 UAC 승인, hardened production ACL/file placement, 공장 runtime과의 end-to-end는 이번 로컬 검증에서 실행하지 않았으므로 UNKNOWN이다.
6. 8.3 alias와 elevated ACL integration 4개는 환경 제약으로 skip됐다. 해당 platform-specific readback은 UNKNOWN으로 남는다.
