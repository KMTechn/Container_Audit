# Sandbox guest → host nonproduction server5 wiring

판정/배선 시각: 2026-08-26 (Asia/Seoul)

대상 task-root:
`E:\KMTech\autoloop-20260824\Container_Audit\seq217-evidence-streaming-correction`

범위: 다음 Container Track A용 `.wsb`, guest bootstrap, exact staged inputs, guest-side strict hostname TLS readiness. Windows Sandbox와 제품은 실행하지 않았고, 제품 소스·서버·공장 PC는 변경하거나 접속하지 않았다.

## 결론

guest 경로를 실제 다음 task-root에 배선했다.

`guest vNIC` → `host 100.107.44.33` → `TCP 18457` → 실제 `WorkerAnalysisGUI-web` HTTPS listener

새 `track-a.wsb`는 networking을 켜고 새 task-root의 `launcher`, `stage`, `out`을 각각 기존 guest 경로 `C:\TrackA\launcher`, `C:\TrackA\stage`, `C:\TrackA\out`에 매핑한다. 보정된 `guest.ps1`은 매 fresh guest에서 exact hosts 항목과 canonical private CA Root 신뢰를 다시 적용한 뒤, 제품 byte 실행 전에 DNS + literal TCP + OS trust/hostname TLS + leaf pin + Root-store pin + no-redirect HTTP 200을 하나의 strict 관측으로 검사한다.

성공 관측은 생기는 즉시 `C:\TrackA\out\server5-guest-ready.stream.txt`에 정확히 한 줄 append되고 같은 한 줄이 console에도 출력된다. 결과 JSON을 마지막에 쓸 때까지 보류하지 않는다(M14). Sandbox를 금지한 이번 작업에서는 그 runtime 한 줄을 관측하지 않았으며, 다음 authorized launch에서만 PASS/FAIL이 판정된다.

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

### 5. 현재 host listener readback

변경 없이 read-only로 확인한 현재 listener는 다음과 같다.

- `100.107.44.33:18457`, `Listen`, owning PID `24072`.
- PID `24072`는 `python.exe -u E:\KMTech\autoloop-20260824\WorkerAnalysisGUI-web\seq138-crl-leaf-activation\runtime\run_https.py`.
- 현재 issued leaf의 subject는 `CN=server5.autoloop.test`, issuer는 canonical nonproduction CA이고 DER SHA-256은 위 pinned leaf hash와 일치한다.

이번 작업은 host listener에 HTTP request를 보내지 않았다. 사용자가 제공한 host TCP 도달 확인과 listener/process readback만 사용했다.

## (b) 다음 발사에서 나올 정확한 한 줄

성공 시 `out\server5-guest-ready.stream.txt`와 guest console에 다음 한 줄이 생긴다.

```text
SERVER5_GUEST_READY=PASS RESOLVED_IPV4=100.107.44.33 TCP=1 TLS_VALID=1 HTTP=200 FINAL_URI=https://server5.autoloop.test:18457/health/ingest LEAF_DER_SHA256=AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F ROOT_DER_SHA256=0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C
```

이 line은 조건을 하나라도 만족하지 못하면 출력되지 않는다. 부분 성공을 PASS로 serialize하지 않는다. 이 line은 guest reachability/trust readiness일 뿐 receipt accepted, projection row, dashboard API/화면 반영을 요구하는 g3 PASS가 아니며 `/health/ingest` 200을 g3 증거로 승격하지 않는다.

## (c) 아직 안 되는 것

- Sandbox 기동이 금지되어 있었으므로 새 `.wsb`와 boot script의 integrated guest 실행은 **NOT TESTED**다. 따라서 위 exact PASS line은 아직 실제 guest에서 관측되지 않았다.
- task-root에는 이 작업 범위인 `.wsb`와 guest bootstrap이 배선됐지만 host-side Track A `launch.ps1`는 생성/retarget하지 않았다. 전체 transaction을 발사하는 coordinator-owned host wrapper는 이 `.wsb`를 선택하고 기존 protected relay를 공급해야 한다.
- strict readiness 이후의 installer, main window, catalog, seal/receipt recovery, projection, authenticated dashboard API/headed UI는 이번 작업에서 실행하지 않았다. g2/g3/g4/g5/g6는 이 배선으로 PROVEN이 되지 않는다.
- 현재 PID `24072`는 다음 launch 때 바뀔 수 있다. 발사 직전 host preflight에서 exact listener/PID를 다시 읽어야 한다.

## (d) UNKNOWN

- 다음 fresh guest가 실제로 반환할 resolver 전체 IPv4 set, guest IPv4/default gateway, HNS/WinNAT flow 세부는 UNKNOWN이다.
- 다음 guest의 실제 negotiated TLS version, peer chain build transcript, LocalMachine Root store readback 결과, exact HTTP response/final URI는 runtime 전까지 UNKNOWN이다. script는 이를 PASS line의 필수 조건으로 만들었지만 아직 실행하지 않았다.
- 다음 launch 순간 listener가 계속 PID `24072`인지, leaf/CA가 같은 bytes인지 UNKNOWN이다. pinned 값과 다르면 probe는 PASS를 출력하지 않고 중단한다.
- coordinator가 사용할 host launch wrapper/task-root, protected relay 시점과 token 공급 성공 여부는 이 guest-wiring 작업 밖이어서 UNKNOWN이다.
- `seal`, receipt recovery, catalog authentication/fixture, projection row, dashboard API 및 headed dashboard의 실제 g2/g3 business-state readiness는 UNKNOWN이다.
- 공장/프로덕션 환경 상태는 접속하지 않았으므로 UNKNOWN이다.

## 변경/검증 수치

- Windows Sandbox launch: `0`
- 제품 실행: `0`
- server HTTP request: `0`
- factory/production access: `0`
- 제품 소스 변경: `0`
- `.wsb` XML parse errors: `0`
- guest PowerShell 5.1 parse errors: `0`
- staged/copied exact-input hash mismatches: `0/5`
