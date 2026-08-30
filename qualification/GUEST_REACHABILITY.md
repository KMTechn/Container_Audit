# Sandbox guest → host nonproduction server5 wiring

최초 판정/배선 시각: 2026-08-26 (Asia/Seoul)
실행 이력 사실 정정: 2026-08-31 (Asia/Seoul)

대상 task-root:
`E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction`

최초 문서 범위는 다음 Container Track A용 `.wsb`, guest bootstrap, exact staged inputs, guest-side strict hostname TLS readiness의 정적 배선이었다. 그 최초 배선 작업 자체에서는 Windows Sandbox와 제품을 실행하지 않았지만, 아래에 기록한 후속 실행 증거 때문에 이 문서를 현재 시점의 `NOT TESTED` 또는 launch `0` 근거로 사용해서는 안 된다. 제품 소스와 공장 PC는 이 사실 정정에서 변경하거나 접속하지 않았다.

> **사실 정정:** 2026-08-26 `FIRST_LAUNCH_REPORT.md`는 fresh Windows Sandbox `launch_count=1`, installer exit `0`, app launch 도달을 이미 기록했다. 2026-08-30에는 별도 fresh reachability-only guest에서 아래 `SERVER5_GUEST_READY=PASS` 한 줄을 실제 관측했고, 2026-08-31 enrollment rehearsal의 최종 guest도 strict DNS/TCP/TLS/HTTP readiness를 다시 PASS한 뒤 v1 enrollment에서 멈췄다. 따라서 과거의 “한 번도 실행되지 않음”, `Windows Sandbox launch: 0`, integrated guest `NOT TESTED` 서술은 더 이상 사실이 아니다.

## 결론

guest 경로를 실제 다음 task-root에 배선했다.

`guest vNIC` → `host 100.107.44.33` → `TCP 18457` → 실제 `WorkerAnalysisGUI-web` HTTPS listener

새 `track-a.wsb`는 networking을 켜고 새 task-root의 `launcher`, `stage`, `out`을 각각 기존 guest 경로 `C:\TrackA\launcher`, `C:\TrackA\stage`, `C:\TrackA\out`에 매핑한다. 보정된 `guest.ps1`은 매 fresh guest에서 exact hosts 항목과 canonical private CA Root 신뢰를 다시 적용한 뒤, 제품 byte 실행 전에 DNS + literal TCP + OS trust/hostname TLS + leaf pin + Root-store pin + no-redirect HTTP 200을 하나의 strict 관측으로 검사한다.

성공 관측은 생기는 즉시 `C:\TrackA\out\server5-guest-ready.stream.txt`에 정확히 한 줄 append되고 같은 한 줄이 console에도 출력된다. 결과 JSON을 마지막에 쓸 때까지 보류하지 않는다(M14). 이 한 줄은 2026-08-30 23:17 KST에 실제로 관측됐다. 보존 파일은 `E:\KMTech\production-readiness-20260830\RESEARCH\_TEST1-SANDBOX-REHEARSAL.evidence\run-ctx_a298cb013646\sandbox-out\server5-guest-ready.stream.txt`이고, 303 bytes, SHA-256 `0994122FB8958D8C41887C28B402B4CF96DD0E6439AF99243A926F1ABF373C13`이다.

## (a) 무엇을 배선했는가

### 1. next task-root `.wsb`

생성 파일:
`E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\track-a.wsb`

| 설정 | 배선 |
|---|---|
| `Networking` | `Enable` — guest virtual NIC 활성화 |
| launcher | host `...\seq217-evidence-streaming-correction\launcher` → guest `C:\TrackA\launcher`, read-only |
| stage | host `...\seq217-evidence-streaming-correction\stage` → guest `C:\TrackA\stage`, read-only |
| out | host `...\seq217-evidence-streaming-correction\out` → guest `C:\TrackA\out`, writable |
| boot | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\TrackA\launcher\guest.ps1` |

`.wsb`는 998 bytes, SHA-256
`3F4315DBF3FF9CF96035612D999C681363CCDDD5216876A254E565A7B2B7ABC9`이며 XML parse가 성공했다. folder mapping은 파일 전달 경로이고 socket/port mapping이 아니다. 실제 socket 경로는 networking-enabled guest vNIC에서 host Tailscale IPv4의 listener로 직접 간다.

### 2. exact-name stage/launcher payload

경로 길이를 먼저 측정했다. 축약·개명·junction·SUBST·reparse를 사용하지 않았다.

```text
PATHLEN=114 PATH=E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\stage\Container_Audit-v2.0.93.zip
PATHLEN=121 PATH=E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\stage\Container_Audit-v2.0.93.zip.sha256
PATHLEN=106 PATH=E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\stage\private-ca.cert.pem
PATHLEN=99 PATH=E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\launcher\guest.ps1
```

| task-root input | bytes | SHA-256 | 판정 |
|---|---:|---|---|
| `stage\Container_Audit-v2.0.93.zip` | 111,229,179 | `97F3DCE47A241DB779F329D687A1129F8BB55AD63200242BBB10CFEADCDF6790` | seq214 immutable input과 byte-identical |
| `stage\Container_Audit-v2.0.93.zip.sha256` | 94 | `B043C261D407B141001D4FC8BCCCB9D757DC3CE0F860AE1F4A914A8BA5E30FA7` | exact filename/sidecar 유지 |
| `stage\private-ca.cert.pem` | 1,258 | `C8150985F313A794FB23CCBCFD75DFC32B3BB3A85E75831C50ED2AC379BD370A` | canonical `WorkerAnalysisGUI-web\server-5\certs` PEM과 byte-identical |
| `launcher\TRACK_A_DEFENDER_EVENT_CALLER_v2.ps1` | 11,877 | `8A7CE58D35E32FC787454367CA29FFCE0E00591FB6A230774B8F4D5101D4B533` | seq214과 byte-identical |
| `launcher\TRACK_A_DEFENDER_EVENT_COLLECTOR_v2.ps1` | 22,978 | `4C95619E35B193E36FB7B82F200EFC1B1D71125796B26FD01E215A7A6D921C58` | seq214과 byte-identical |

제품 ZIP, sidecar, PEM의 이름·바이트·layout을 바꾸지 않았다(M22). 생성한 빈 `out`은 `.wsb` writable mapping과 guest 증거를 위한 task-root/harness-owned directory뿐이다. guest의 제품 소유 install/log/cache/runtime/lease/receipt/evidence 경로는 미리 만들지 않았다.

### 3. fresh guest hosts + Root 재적용

보정된 boot script:
`E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\launcher\guest.ps1`

- literal IPv4 `100.107.44.33:18457`에 5초 bounded TCP connect 후 실패 시 제품 전에 중단: `guest.ps1:817-832`.
- fresh guest hosts에 exact 항목 `100.107.44.33 server5.autoloop.test` append: `guest.ps1:834-836`.
- mapped canonical PEM을 `certutil.exe -f -addstore Root`로 LocalMachine Root에 재적용하고 nonzero면 중단: `guest.ps1:838-841`.
- 같은 exact PEM path를 `REQUESTS_CA_BUNDLE`과 `SSL_CERT_FILE`에 설정: `guest.ps1:842-843`.
- 이 순서 뒤 strict guest probe를 실행하고, 통과한 뒤에만 relay/product 단계로 이동: `guest.ps1:845-853`.

fresh Sandbox는 폐기형이므로 hosts/Root를 이전 physical 33 상태에 의존하지 않는다. 다음 guest가 매번 bootstrap에서 다시 적용한다.

### 4. strict hostname TLS 통합

`Invoke-Server5GuestReadiness` (`guest.ps1:182-293`)는 certificate bypass 없이 다음을 모두 요구한다.

1. `[Net.Dns]::GetHostAddresses('server5.autoloop.test')`의 IPv4 set에 `100.107.44.33` 포함.
2. 앞서 수행한 exact literal TCP connect가 성공.
3. LocalMachine Root store에서 canonical CA DER SHA-256
   `0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C` readback.
4. exact IPv4 socket 위 `SslStream.AuthenticateAsClient('server5.autoloop.test', ..., Tls12, false)` 성공. custom certificate callback은 사용하지 않으므로 OS chain trust와 hostname/SAN 검사가 둘 다 켜져 있다.
5. peer leaf DER SHA-256이
   `AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F`와 일치.
6. global `ServerCertificateValidationCallback`이 null임을 확인한 뒤, redirect를 끈 exact `GET https://server5.autoloop.test:18457/health/ingest`의 HTTP status `200` 및 final URI exact match.
7. 전부 통과한 시점에 `AppendAllText` 한 번으로 readiness stream 한 줄을 즉시 flush/close하고 console에도 같은 줄 출력: `guest.ps1:278-280`.

guest script는 Windows PowerShell `5.1.26100.9168` parser에서 `PARSE_OK`였고, 현재 68,312 bytes, SHA-256
`3896A93673B106FFBCD50E532EF915BDB040C2DCB45C5A3BDEBF8E806923A036`이다.

### 5. 최초 문서 작성 당시 host listener readback

2026-08-26 최초 문서 작성 때 변경 없이 read-only로 확인한 listener는 다음과 같았다.

- `100.107.44.33:18457`, `Listen`, owning PID `24072`.
- PID `24072`는 `python.exe -u E:\KMTech\autoloop-20260824\WorkerAnalysisGUI-web\seq138-crl-leaf-activation\runtime\run_https.py`.
- 당시 issued leaf의 subject는 `CN=server5.autoloop.test`, issuer는 canonical nonproduction CA이고 DER SHA-256은 위 pinned leaf hash와 일치했다.

최초 배선 작업은 host listener에 HTTP request를 보내지 않았다. 후속 2026-08-30/31 Sandbox 실행은 이 문서에 별도로 정정한 strict HTTP readiness와 enrollment 요청을 실제 수행했다.

## (b) 실제 관측된 정확한 한 줄

2026-08-30 fresh guest의 `out\server5-guest-ready.stream.txt`와 guest console에서 다음 한 줄을 실제 관측했다.

```text
SERVER5_GUEST_READY=PASS RESOLVED_IPV4=100.107.44.33 TCP=1 TLS_VALID=1 HTTP=200 FINAL_URI=https://server5.autoloop.test:18457/health/ingest LEAF_DER_SHA256=AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F ROOT_DER_SHA256=0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C
```

이 line은 조건을 하나라도 만족하지 못하면 출력되지 않는다. 부분 성공을 PASS로 serialize하지 않는다. 이 line은 guest reachability/trust readiness일 뿐 receipt accepted, projection row, dashboard API/화면 반영을 요구하는 g3 PASS가 아니며 `/health/ingest` 200을 g3 증거로 승격하지 않는다.

## (c) 후속 실행으로 확인된 것과 아직 안 되는 것

- **실행 이력:** `E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction\FIRST_LAUNCH_REPORT.md`는 2026-08-26 fresh guest `1`, retry `0`, installer exit `0`, app launch 도달을 기록한다. 2026-08-30에는 위 exact PASS line을 fresh reachability-only guest에서 관측했다.
- **2026-08-31 재관측:** enrollment rehearsal의 final guest stream `E:\KMTech\production-readiness-20260830\RESEARCH\_SANDBOX-ENROLLMENT-REHEARSAL.evidence\run-ctx_7f0bafca0e8c\attempt-3\out\sandbox-rehearsal.stream.txt`도 strict readiness `HTTP=200`과 동일 leaf/Root pin을 PASS했다. 그 후 제품 v2.0.93의 v1 enrollment가 `HTTP 400 manifest_invalid / STREAM_CATALOG_NOT_CLOSED`로 중단되어 lease/source-file/receipt는 실행되지 않았다. 이는 reachability 실패가 아니라 후속 PRODUCT 계약 불일치다.
- task-root에는 이 작업 범위인 `.wsb`와 guest bootstrap이 배선됐지만 host-side Track A `launch.ps1`는 생성/retarget하지 않았다. 전체 transaction을 발사하는 coordinator-owned host wrapper는 이 `.wsb`를 선택하고 기존 protected relay를 공급해야 한다.
- 최초 배선 작업에서는 strict readiness 이후의 installer, main window, catalog, seal/receipt recovery, projection, authenticated dashboard API/headed UI를 실행하지 않았다. 후속 2026-08-26 실행은 installer/app에 도달했고, 2026-08-31 실행은 enrollment 400에서 멈췄다. 어느 증거도 g2/g3/g4/g5/g6를 자동으로 PROVEN으로 만들지 않는다.
- PID `24072`는 2026-08-26의 역사적 관측값일 뿐이다. 2026-08-31 enrollment rehearsal 직전 container listener는 PID `35980`이었고, 다음 발사 때 다시 바뀔 수 있으므로 매번 exact listener/PID를 읽어야 한다.

## (d) UNKNOWN

- 2026-08-30 관측에서는 resolver IPv4 set에 `100.107.44.33`이 포함됐고 exact HTTP/final URI 및 Root/leaf pin은 위 한 줄로 확인됐다. guest IPv4/default gateway와 HNS/WinNAT flow 세부는 여전히 UNKNOWN이다.
- 실제 negotiated TLS version과 전체 peer chain build transcript는 UNKNOWN이다. 다만 TLS hostname/OS trust, leaf pin, Root-store pin, no-redirect HTTP 200은 실제 PASS line으로 확인됐다.
- 다음 launch 순간 listener가 계속 2026-08-31 관측 PID `35980`인지, leaf/CA가 같은 bytes인지 UNKNOWN이다. pinned 값과 다르면 probe는 PASS를 출력하지 않고 중단한다.
- 2026-08-31 rehearsal에서는 protected relay가 exit `0`, stdout/stderr `0` characters로 성공했다. 다음 launch에서 사용할 wrapper/task-root와 relay 시점은 매 실행 preflight 전까지 UNKNOWN이다.
- `seal`, receipt recovery, catalog authentication/fixture, projection row, dashboard API 및 headed dashboard의 실제 g2/g3 business-state readiness는 UNKNOWN이다.
- 공장/프로덕션 환경 상태는 접속하지 않았으므로 UNKNOWN이다.

## 변경/검증 수치

- 이 문서 이후 확인된 Windows Sandbox launch: 최소 `5` (`2026-08-26` 1회 + `2026-08-30` reachability 1회 + `2026-08-31` enrollment rehearsal 3회)
- 2026-08-26 제품 installer exit `0` / app launch 도달: `1`
- 2026-08-30 strict server HTTP readiness PASS: `1`
- 2026-08-31 strict server HTTP readiness 재-PASS: `1`
- factory/production access: `0`
- 제품 소스 변경: `0`
- `.wsb` XML parse errors: `0`
- guest PowerShell 5.1 parse errors: `0`
- staged/copied exact-input hash mismatches: `0/5`
