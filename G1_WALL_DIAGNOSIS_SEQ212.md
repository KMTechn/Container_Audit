# Container_Audit g1 wall re-diagnosis (seq212)

## 결론

현재 `v2.0.93`에 대해 **SAC/CI와 무관한 g1 제품 벽은 아직 확정되지 않았다**. `v2.0.91`과
`v2.0.93`의 두 대표 실행 모두 `Container_Audit_DirectSync_Relay.exe`가 실제로 실행되기 전에
CI3077로 세 번 차단됐고, 그 결과 설치기의 fail-closed 대기문이
`INSTALL_THIS_PC.ps1:3541`에서 `APPLIED_UNPROVEN`을 낸 것이다. 새로 증명된 SAC-OFF guest에서는
이 CI 원인은 무효이므로, 같은 `APPLIED_UNPROVEN`을 현재 제품 벽으로 계속 기록할 수 없다.

`v2.0.91` 소스에는 별도의 SAC 비의존 결함, 즉 설치기 프로세스에만 있던
`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`이 SYSTEM 예약 작업 경계를 넘지 못하는 결함이 있었다.
그러나 그 결함은 `v2.0.93` 커밋 `5f043eaeeb9f5e5eb16da4aaa025505adae28881`에서 수정됐고,
CI3077 때문에 수정된 relay가 한 번도 실행되지 않아 대표 runtime 성패는 아직 `UNPROVEN`이다.
따라서 다음 정확한 상태는 **`NO_CONFIRMED_POST_SAC_PRODUCT_WALL / G1_UNPROVEN_AT_RUNTIME_LEASE_BOUNDARY`**다.

## (a) 기록된 차단 사유 재분류

| 기록/관측 | 분류 | 근거와 현재 효력 |
|---|---|---|
| v2.0.90 Windows PowerShell 5.1 `File.Replace(..., $null, ...)` 실패 | SAC와 무관한 제품 결함, 수정·통과 완료 | 커밋 `879eb9f87f88b352ce1b0b173712a9b801d5a2c1`이 `NullString.Value`를 사용한다. v2.0.91 대표 실행이 이 이전 stop을 통과했으므로 현재 벽이 아니다. |
| v2.0.91 `APPLIED_UNPROVEN`, current runtime lease 120초 내 미증명 | 대표 실행 결과는 SAC/CI 파생, 따라서 현재 벽 분류 무효 | raw CI 파일의 record 87/92/97이 각각 `cmd.exe`가 정확한 relay EXE를 load하려다 CI3077로 차단됐음을 기록한다. 시간은 `05:39:43Z`, `05:40:01Z`, `05:41:01Z`이고 installer timeout 직전까지 이어진다. 기존 파생 파일의 `NO_RESOLVABLE_FILE_PATH`는 raw event message와 모순되며 raw event가 지배한다. |
| v2.0.91 process-only CA trust가 SYSTEM task에 전달되지 않음 | SAC와 무관한 실제 제품 결함, v2.0.93에서 수정 완료, 대표 runtime은 미증명 | v2.0.91 wrapper는 `TEMP`/`TMP`만 기록했다. no-credential read-only 재현에서는 기본 Requests trust가 `SSLError`, 같은 CA를 명시하면 HTTP 200이었다. 다만 v2.0.91 대표 run에서 relay 자체가 CI로 차단됐으므로 이 결함을 그 physical stop의 직접 원인으로 귀속할 수는 없다. |
| v2.0.93 relay CI3077 3회 및 동일 `:3541 APPLIED_UNPROVEN` | SAC/CI 파생, 새 자격 대상에서는 무효 | seq205 record 87/92/97이 relay EXE 차단을 직접 증명한다. relay가 CA-backed transport나 lease 요청을 실행하기 전 차단됐으므로 CA 전달 수정의 성공/실패를 판정하지 못한다. 새 physical-32 SAC-OFF 증거는 watermark 이후 CI3077/3076/3089=0을 증명했다. |
| v2.0.93 `Container_Audit.exe` Application Control 알림과 app launch 미도달 | SAC/CI 파생 관측 + downstream 미시험 | 새 SAC-OFF 자격 대상에서 정책 차단 사유는 무효다. g1 exit 0 전의 app start 시도는 g2 증거가 아니며, 실제 앱 window는 여전히 `NOT TESTED`. |

주요 raw evidence:

- `E:\KMTech\autoloop-20260824\Container_Audit\seq198-v2.0.91-track-a\out\policy-final-code-integrity-events.json:54,172,290`
- `E:\KMTech\autoloop-20260824\Container_Audit\seq198-v2.0.91-track-a\out\installer.log`
- `E:\KMTech\autoloop-20260824\Container_Audit\seq205-v2.0.93-track-a\RESULT.json`
- `E:\KMTech\autoloop-20260824\Container_Audit\seq205-v2.0.93-track-a\REPORT.md`

## (b) 남은 진짜 g1 벽과 소스 위치

확정된 남은 제품 벽은 없다. 다음 Track A가 반드시 판정해야 할 **경계**는 frozen v2.0.93의
`INSTALL_THIS_PC.ps1:3537-3541`이다.

- `INSTALL_THIS_PC.ps1:2906-2935`: 새 runtime status에서 authorized manifest, ACTIVE lease,
  server grant, producer/runtime/lease IDs, 미래 expiry를 120초 안에 모두 요구한다.
- `INSTALL_THIS_PC.ps1:3537-3541`: 위 증명이 없으면 task를 멈추고 `APPLIED_UNPROVEN`으로 fail closed한다.
- `INSTALL_THIS_PC.ps1:3544-3546`: lease 경계를 통과한 뒤 처음 만나는 아직 미시험 gate는 Start Menu
  shortcut ownership readback이다.

따라서 `:3541`은 현재 **관측 지점**이지 SAC-OFF에서도 재현된 벽이 아니다. 새 SAC-OFF run에서
relay 실행이 증명된 뒤에도 같은 경계가 실패해야만 그때의 runtime status/error를 근거로 새 제품 벽을
확정할 수 있다.

## (c) 근본 원인 판정

### 확정

1. 두 physical `APPLIED_UNPROVEN` 실행에서 lease가 생기지 않은 직접 원인은 relay EXE의 CI3077
   load 차단이다. v2.0.91에서도 raw record 87/92/97이 정확한 파일 경로를 포함하므로
   “v2.0.91은 CI 이전 문제였다”는 전제는 raw evidence와 맞지 않는다.
2. v2.0.91 소스의 CA-context 손실은 독립적으로 존재한 제품 결함이다. Track A launcher는 CA 변수를
   installer child에 상속했지만, old scheduled-task wrapper는 `TEMP`/`TMP`만 썼다. Requests는
   `producer_runtime_client.py:425-434`에서 credential에 별도 CA path가 없으면 environment/default trust를
   사용한다.
3. v2.0.93은 `INSTALL_THIS_PC.ps1:1639-1671`에서 두 CA 변수만 bounded validation하고,
   `:1890-1892`, `:1999-2005`에서 relay wrapper에 runner보다 먼저 기록한다. frozen ZIP 안의 installer도
   동일한 코드를 포함한다.

### manifest hash 대소문자 `-cne` 감사

`INSTALL_THIS_PC.ps1:2914`의 case-sensitive 비교는 canonical 경로에서는 false mismatch를 만들지 않는다.

- PowerShell canonical hash는 `:469-474`에서 lowercase로 생성된다.
- enrollment response hash는 `:1504`에서 lowercase로 정규화되고 registration report에는 그 canonical
  hash가 `:1568`에 기록된다.
- wait에 전달되는 `$authorizedManifestHash`도 `:3482`에서 lowercase다.
- relay의 `manifest_hash()`는 `direct_sync_push.py:230-231`의 `hashlib.sha256(...).hexdigest()`이며 lowercase다.
- upload metadata 경로도 `direct_sync_runtime.py:239`에서 `.lower()`한다.

그러므로 현 frozen v2.0.93에 이 비교를 바꾸는 것은 근거 없는 수정이다. 다만 다음 run에서 실제
`manifest hash differs`가 관측되면 두 hash의 비밀 아닌 canonical 값과 생성 경로를 함께 보존해야 한다.

### 미확정

CI가 제거된 guest에서 v2.0.93 CA 전달 수정이 실제 SYSTEM relay와 현재 서버 lease까지 통과하는지는
확정하지 못했다. seq201의 source/focused-test 증거는 fix 구현을 지지하지만 representative runtime
proof를 대체하지 않는다.

## frozen 후보와 현재 checkout의 분리

다음 Track A의 유효 입력은 immutable v2.0.93이다.

- ZIP: `Container_Audit-v2.0.93.zip`
- bytes: `111,229,179`
- SHA-256: `97F3DCE47A241DB779F329D687A1129F8BB55AD63200242BBB10CFEADCDF6790`
- commit/tree/tag object: `5f043eaeeb9f5e5eb16da4aaa025505adae28881` /
  `de6d700aea8742e6d1e915f3a0c43e2fc43938ea` /
  `211f31c3e67455abf2b7fa19730c8867df1e6030`
- independent verifier: PASS, 1,111 archive entries, exact manifest membership and byte parity PASS.

현재 checkout `HEAD=a7de9fe` (`seq177-profile-readback-fix`)은 v2.0.93 source가 아니다. merge-base는
`8db6dbf`이고, 이 checkout은 `879eb9f`와 `5f043ea`를 모두 포함하지 않으며
`Container_Audit.py:298`도 `v2.0.90`이다. 현재 파일에는 여전히
`INSTALL_THIS_PC.ps1:491`의 bare `$null` File.Replace와 `:1956-1959`의 TEMP/TMP-only wrapper가 있다.
따라서 이 checkout에서 새 후보를 만들면 이미 수정된 두 결함을 재도입한다. 다음 Track A는 반드시
위 exact frozen v2.0.93을 사용해야 하며, source 통합 의도는 별도로 결정돼야 한다.

## (d) 수정/커밋/테스트

제품 소스 수정과 커밋은 하지 않았다. post-SAC runtime 결과가 없고 v2.0.93에는 이미 최소 CA-context
fix가 들어 있어, 추가 수정은 추측이 되기 때문이다. 브리프의 offline read-only 지시에 따라 테스트나
제품 실행도 새로 하지 않았다.

검토한 기존 증거에서 commit `5f043ea`의 결과는 focused installer **41 passed, 2 deselected**,
qualification routing **1 passed**, relay/runtime **200 passed, 1 skipped**, release **142 passed**다. 이는
source regression/local freeze 증거일 뿐 g1 representative runtime PASS가 아니다.

## (e) 다음 Track A 판정 항목

1. 위 exact v2.0.93 ZIP을 fresh SAC-OFF guest에서 공개 설치 명령으로 한 번 실행한다.
2. 제품 실행 직전 watermark와 `VerifiedAndReputablePolicyState=0`을 기록하고, watermark 이후
   CI3077/3076/3089=0 및 Defender 1116/1117/1121/1122=0을 확인한다. CI가 다시 나오면 제품 lease
   판정이 아니라 qualification-policy regression이다.
3. relay task의 등록뿐 아니라 실제 wrapper 시작과 relay process 실행을 증명한다. CA 값 자체가 아니라
   허용된 변수 이름 2개와 `local_test_task_environment_persisted=true`, launcher status, task result를
   bounded evidence로 남긴다.
4. `direct_sync_relay_status.json`을 bounded copy해 LastWriteTime, `status`, `error_code`, manifest hash,
   runtime lease의 `ACTIVE/server_grant_accepted/IDs/expires_at`을 보존한다. secret/token은 수집하지 않는다.
5. 판정은 다음과 같다.
   - installer exit 0 + 위 lease 조건 충족: `:3541` 통과; 이어 `:3544-3546` shortcut gate를 판정한다.
   - relay가 실행됐고 `runtime_error`가 기록됨: 그 exact error/source를 새 제품 벽으로 진단한다.
   - relay가 실행됐지만 status가 없음: wrapper/runner exit와 status-write 경로를 원인 후보로 좁힌다.
   - `manifest hash differs` 즉시 실패: canonical 양쪽 hash와 생성 경로를 보존해 case가 아닌 실제
     identity 차이를 판정한다.
6. 정책 §5.4상 g1 PASS는 공개 설치 명령의 실제 exit 0일 때만 부여한다. task 존재나 unit test로
   대체하지 않는다.

## (f) UNKNOWN

- SAC-OFF guest에서 v2.0.93 relay가 실제 실행되고 CA-backed HTTPS lease를 얻는지.
- 다음 실행 시 서버가 반환할 runtime lease와 그 시점의 server readiness.
- 실제 SYSTEM wrapper/task result, runtime status/error, launcher status.
- lease 경계 뒤 `INSTALL_THIS_PC.ps1:3544-3546` shortcut ownership gate의 성패.
- g1 exit 0 이후 앱 process/window, g2 UI transaction, g3 server/dashboard, g4/g5/g6 결과.
- 현재 `seq177-profile-readback-fix` checkout에 `879eb9f`/`5f043ea`를 어떤 순서와 authority로
  통합할지. 이 작업에서는 통합하지 않았다.
- v2.0.91의 CA-context 결함이 CI가 없었을 때 그 physical run의 다음 실제 stop이었을지는 알 수 없다;
  그 run에서는 relay가 실행되지 않았다.

