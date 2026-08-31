# PowerShell writer-fence lifetime closure — 2026-08-31

## 결론

교차 검증 3회차가 지적한 두 문제에 동의했고 둘 다 닫았다. 종전 검출기는 등록된 entry guard가 파일에 하나라도 있으면 함수 내부 sink 전부 또는 guard line 뒤 sink를 guarded로 판정했으며, release line과 함수의 실제 호출 순서를 보지 않았다. 새 v8 inventory는 release-bounded lifetime과 direct intra-file call graph를 명시적으로 계산하고, guard 전 함수 호출 및 release 뒤 sink를 실제 portable release gate의 내부 종료 코드 **1**로 고정한다.

승인 대상으로 제시하는 새 구현 pin은 `46900d489d639917e4390067265060caafbe93d6`, tree는 `6bfd46758c77067c2c378c157c7418a428efb595`, packet은 `E:\d7`이다. 이 문서는 packet 생성·검증 뒤 추가한 비제품 증거 문서이므로 packet source pin에는 포함되지 않는다.

## (a) 두 지적의 이해와 조치

### 1. lexical guard 판정

지적 근거는 정확했다. 이전 `tools/derive_container_writer_sinks.py`의 `_powershell_site_guard`는 entry guard가 유효할 때 아래 둘 중 하나만 만족하면 site를 guarded로 돌려줬다.

- site가 어떤 함수 정의 안에 있다.
- top-level site line이 최초 guard line 이상이다.

이 방식은 함수 정의가 guard 앞에 있어도 호출이 guard 뒤라면 정상인 경우와, 그 함수를 guard 전에 호출하는 위험한 경우를 구분하지 못했다. 또한 release 뒤 top-level sink도 guard line보다 뒤라는 이유로 통과시켰다. 따라서 `powershell_guard_failures=[]`와 `uncovered=0`만으로 lifetime을 증명한다는 종전 주장은 성립하지 않았다.

조치는 다음과 같다.

- `INSTALL_THIS_PC.ps1`은 `Enter-ContainerPlacementWriterFence`부터 `Exit-ContainerWriterAdmission` 직전까지만 held lifetime으로 인정한다.
- `INSTALL_CANONICAL_PORTABLE.ps1`은 `Enter-ContainerWriterSessionAuthority`부터 `Exit-ContainerWriterSessionAuthority` 직전까지만 인정한다.
- release-bounded entrypoint는 top-level guard와 release가 각각 정확히 하나이고 release가 guard 뒤에 있어야 유효하다.
- direct top-level site는 guard line과 release line 사이에 **엄격히** 있어야 한다. guard/release와 같은 line도 보수적으로 거부한다.
- 함수 site는 같은 파일의 direct callsite를 찾아 safe, unsafe, 명시적 non-production root를 각각 전파한다. 안전한 호출 경로가 있더라도 guard 전 또는 release 뒤 호출 경로가 하나라도 있으면 함수 전체를 unguarded로 판정한다.
- 호출되지 않거나 direct call graph로 증명되지 않는 entrypoint 함수 sink는 자동으로 guarded가 되지 않는다.
- `tools/container_writer_session.ps1`의 exact `if ($Mode -ceq 'selftest')` 경로만 `Invoke-ContainerWriterSessionSelfTest`의 non-production root로 명시했다. 현재 inventory는 이 함수 하나를 `non_production_only=true`로 기록하며, 생산 경로로 도달하는 18개 proof는 18/18 guarded다.
- native API/reflection의 주변 context가 guard line에 site를 잘못 귀속시키지 않도록 실제 primitive가 있는 code line에 귀속하도록 보정했다.

현재 v8 inventory에는 PowerShell function proof 31개가 있고, 그중 production-reachable 18개는 18/18 guarded, non-production-only는 selftest 1개다. library-only proof는 entrypoint lifetime으로 가장하지 않으며 기존 byte-pin/runtime admission 경계에 남는다.

### 2. post-release 음성 테스트 부재

이 지적에도 동의했다. 종전 17종 fixture의 positive control은 acquire 뒤 sink만 만들었고 release 자체가 없었다. 따라서 scanner가 release 뒤 sink를 놓쳐도 테스트가 통과했다.

positive fixture를 실제 구조처럼 `try/finally`와 `Exit-ContainerWriterAdmission`을 갖도록 바꿨다. 별도 `test_powershell_post_release_mutation_fails_release_gate`는 release 뒤 `Remove-Item`을 주입하고, derived failure가 release line 뒤 top-level `filesystem_mutation`인지 확인한 다음 portable builder의 `_assert_writer_sink_inventory`를 별도 process로 호출해 내부 exit **1**과 `writer sink inventory is not release-admissible`을 확인한다.

## (b) 추가·보강한 테스트

`tests/test_container_writer_sink_inventory.py`에 아래를 고정했다.

1. `test_powershell_mutation_function_called_before_guard_fails_release_gate`
   - mutation 함수 정의 뒤 guard 전에 호출한다.
   - function proof가 unsafe로 전파되어 `filesystem_mutation` failure가 생기는지 확인한다.
   - 실제 release gate subprocess exit **1**을 확인한다.
2. `test_powershell_post_release_mutation_fails_release_gate`
   - 정상 acquire/release 뒤 top-level mutation을 둔다.
   - site line이 recorded release line 뒤인지 확인한다.
   - 실제 release gate subprocess exit **1**을 확인한다.
3. 기존 17종 PowerShell primitive parameterized test
   - positive fixture에 실제 release를 추가했다.
   - unfenced 각 case의 내부 gate exit **1**과 admitted lifetime 안으로 되돌린 뒤 failure 0을 계속 확인한다.
4. current-inventory assertion
   - 두 release-bounded entrypoint의 exact release command/line, session adapter의 process-lifetime contract, production proof 18/18 guarded, selftest non-production proof를 고정한다.

최종 집중 실행 결과는 `EARLY_FUNCTION_GATE gate_exit=1`, `POST_RELEASE_GATE gate_exit=1`, 기존 17종 각각 `gate_exit=1`, outer pytest **19 passed**, exit code **0**이다. 로그는 `.tmp/fence-lifetime-20260831/negative-gates.out.txt`에 있다.

## (c) 전체 suite와 실제 exit code

권위 실행은 짧은 E: basetemp를 사용했다.

```text
python -m pytest -q -p no:cacheprovider --basetemp E:\bt\caLF11d4b6
2228 passed, 4 skipped in 243.15s
FULL_SUITE_EXIT=0
```

skip 4개는 E: volume의 8.3 alias 부재 2개와 비승격 process의 Windows ACL integration 2개다. 전체 stdout은 `.tmp/fence-lifetime-20260831/full-suite-authoritative.out.txt`, stderr는 같은 디렉터리의 `full-suite-authoritative.err.txt`이며 stderr 크기는 0 byte다.

비권위 첫 실행도 숨기지 않는다. system temp 아래의 긴 C: basetemp로 실행했을 때 3 failed / 2226 passed / 3 skipped, exit **1**이었다. 두 authenticated O3 test는 증거 경로가 E:인지 명시적으로 요구했고, install-registration test는 긴 경로에서 upload status path가 빈 경로로 귀결됐다. 세 test를 짧은 E: basetemp에서 먼저 재실행해 3 passed / exit **0**을 얻은 뒤, 같은 짧은 E: 조건으로 전체 suite를 다시 처음부터 끝까지 실행해 위 exit **0**을 확정했다.

추가 검증:

- `python tools/derive_container_writer_sinks.py --check`: inventory contract `d45398eefc8404f0aaff4f89e414b303723bd7b902626005c693ba532c6dfd55`, exit **0**.
- 전체 suite 안에서 inventory test 30개를 포함해 모두 통과했다.

## (d) 새 pin과 packet

- source commit: `46900d489d639917e4390067265060caafbe93d6`
- source tree: `6bfd46758c77067c2c378c157c7418a428efb595`
- packet: `E:\d7`
- packet build exit: **0**
- manifest-before-manifest metrics: **2,278 files / 48,501,230 bytes**; 독립 재계산 일치
- manifest source commit/tree: Git object와 각각 일치
- core file pins: **10/10** SHA-256 일치
- PowerShell parse: shipped 5개 **5/5**, validation exit **0**
- inventory schema: `container-audit-writer-sink-inventory-v8`
- inventory file SHA-256: `3c67876bbf2990db2dbbcac5921bfdb1c2f1131d6b198f4022a1e59344615d93`
- inventory contract SHA-256: `d45398eefc8404f0aaff4f89e414b303723bd7b902626005c693ba532c6dfd55`
- installer SHA-256: `1fdf0f656cf94f6e56a15153c7c0e6343cda4a5c310914d787762857459b22c4`
- placement helper SHA-256: `9265d12bda00ee5cfa6ff7377780041d0b67c1db3b39e0f3a6b4bd85a5b80581`
- bootstrap integrity helper SHA-256: `07059b4fe6fd387c014ad478486f61b90f8f8e0795f9528ece2f663abd39529b`
- writer-fence helper SHA-256: `a0a9dac659261c9eb2924594d075d691863402e52de7517a66bf748160040aeb`
- writer-session adapter SHA-256: `9f80154e396e510f1ef9b17f5c027c36cc80b89c4811cfc22539a487465269de`
- writer-session contract SHA-256: `ec695c2bec0a7f55111675c22bceaab33e42d64aec4006324392cb65bba7982f`
- packet writer-session selftest: **58/58 PASS**, `system_mutation_attempted=false`, count 0, exit **0**

첫 custom static-validation wrapper는 PowerShell에서 따옴표 없는 `HEAD^{commit}`/`HEAD^{tree}`를 잘못 전달해 source identity 비교만 거짓 실패했다. packet metrics, 10/10 pins, inventory, parse는 그 실행에서도 통과했고, `git rev-parse HEAD`와 `git show -s --format=%T HEAD`를 사용한 수정 검증은 모든 항목과 process exit **0**을 확인했다. packet 자체를 다시 만들거나 덮어쓰지는 않았다.

## (e) UNKNOWN / residual risk

1. scanner는 여전히 완전한 PowerShell parser·동적 call graph·dominance engine이 아니다. 이번 변경은 exact top-level lifetime과 direct intra-file function calls를 닫았지만 computed call target, call operator의 runtime target, alias/function replacement, implicit module dispatch, cross-module 호출 의미, 복잡한 multiline/here-string control flow는 완전 증명하지 못한다.
2. dot-sourced library 함수는 배포 inventory와 packet byte pin에 포함되고 runtime admission을 요구하지만, 모든 cross-file caller를 정적으로 연결한 것은 아니다. library-only proof를 production entrypoint lifetime proof로 보고하지 않는 이유다.
3. explicit selftest 예외는 exact top-level `if ($Mode -ceq 'selftest')`와 exact function 이름에만 적용된다. 현재 pin의 selftest는 58/58 PASS와 system mutation 0을 보였지만, 향후 동적 dispatch로 바뀌는 경우 별도 의미 분석 없이는 자동 증명할 수 없다.
4. 회사 서버·공장 PC에는 접속하지 않았고 Windows Sandbox도 기동하지 않았다. 실제 UAC 승인, hardened production ACL/file placement, 공장 runtime end-to-end는 실행하지 않았으므로 UNKNOWN이다.
5. E: volume 8.3 alias integration 2개와 elevated Windows ACL integration 2개는 환경 제약으로 skip돼 UNKNOWN이다.
6. packet selftest는 system mutation 0인 로컬 contract test다. 실제 production writer workload에서 release 직전/직후의 동시성 및 동적 external command target은 이번 작업에서 실행하지 않았다.

`E:\d5`는 교차 검증 지적을 포함하는 이전 packet이므로 폐기 대상이며, 승인 근거로 사용하지 않는다. push는 수행하지 않았다.
