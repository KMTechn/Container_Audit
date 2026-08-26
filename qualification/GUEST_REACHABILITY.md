# Sandbox guest → host nonproduction server5 reachability

판정 시각: 2026-08-26 (Asia/Seoul)

대상: 최신 완료 Container Track A physical 33 (`seq214-v2.0.93-track-a`)와 현재 host listener

범위: read-only 구성/증거 확인. Windows Sandbox, 제품, server request, 공장 PC는 실행·접속하지 않았다.

## 결론

현재 연결은 `.wsb` folder mapping이나 port forwarding이 아니다. `.wsb`가 guest networking을 켜고, guest가 host 소유 Tailscale IPv4 `100.107.44.33`의 TCP `18457`로 직접 접속한다. host에서는 실제 `WorkerAnalysisGUI-web` 앱을 import하는 HTTPS wrapper가 바로 `100.107.44.33:18457`에 bind되어 있다.

`server5.autoloop.test`는 현재 guest bootstrap이 hosts 파일에 `100.107.44.33 server5.autoloop.test`를 추가해 해석한다. 따라서 별도 DNS가 확인된 상태가 아니라 **hosts 항목이 현재 경로에 필요하며, 이미 physical 33 harness가 처리했다.** Sandbox는 폐기형이므로 다음 fresh guest에서도 다시 추가해야 한다.

canonical private CA도 같은 bootstrap에서 이미 처리한다. host canonical PEM과 byte-identical한 파일을 read-only `stage` mapping으로 guest에 전달하고, guest가 `certutil -f -addstore Root`로 신뢰 저장소에 넣은 뒤 `REQUESTS_CA_BUNDLE`과 `SSL_CERT_FILE`도 그 파일로 설정한다. Physical 33의 import exit은 `0`이었다. 남은 것은 설정 결손이 아니라, 세 요소를 한 번에 증명하는 **guest-side strict hostname TLS 관측 한 줄**과 다음 transaction task root에 대한 `.wsb` 재배선이다.

## (a) 무엇을 확정했는가 — 소스/설정 근거

### 1. guest에서 host `18457`까지의 경로

최신 완료 Container Track A의 설정은 다음과 같다.

| 항목 | 확정 내용 | 근거 |
|---|---|---|
| Sandbox networking | enabled | `E:\KMTech\autoloop-20260824\Container_Audit\seq214-v2.0.93-track-a\track-a.wsb:3` |
| launcher mapping | host `...\launcher` → guest `C:\TrackA\launcher`, read-only | 같은 파일 `:6` |
| stage mapping | host `...\stage` → guest `C:\TrackA\stage`, read-only | 같은 파일 `:7` |
| output mapping | host `...\out` → guest `C:\TrackA\out`, writable | 같은 파일 `:8` |
| boot entry | mapped `C:\TrackA\launcher\guest.ps1` 실행 | 같은 파일 `:10` |

Microsoft의 `.wsb` 정의에서도 `Networking=Enable`은 host에 virtual switch를 만들고 guest virtual NIC를 연결하며, `MappedFolders`는 host folder를 guest path에 공유한다. 따라서 위 세 folder mapping은 파일 전달 경로일 뿐 socket/port mapping이 아니다. 참고: [Use and configure Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

Guest harness는 hostname보다 먼저 IPv4 literal에 대해 5초 bounded TCP connect를 수행한다.

- `TcpClient`가 `100.107.44.33`, port `18457`로 접속: `...\seq214-v2.0.93-track-a\launcher\guest.ps1:636-650`
- 실패 시 `GUEST_TCP_DIRECT_UNREACHABLE`로 중단: 같은 파일 `:651`
- Physical 33 결과는 `guest_tcp_direct_reached=true`: `...\seq214-v2.0.93-track-a\RESULT.json:28`

Host 쪽 구성과 현재 readback은 서로 일치한다.

- `container` profile은 port `18457`을 선택: `E:\KMTech\autoloop-20260824\WorkerAnalysisGUI-web\seq138-crl-leaf-activation\runtime\start-server.ps1:43-52`
- bind host/port/TLS cert/key는 `100.107.44.33`, selected port, issued leaf, private key: 같은 파일 `:116-119`
- wrapper는 profile working directory에서 시작되고, listener가 정확한 address/process인지 확인한다: 같은 파일 `:177,187-190`
- wrapper는 `from app import app` 후 configured address에 `eventlet.listen`, TLS wrap, WSGI serve한다: `...\runtime\run_https.py:14,17-29`
- 이 조사 시 host에는 `100.107.44.33:18457` listener가 정확히 1개 있었고 PID `29172`의 `python.exe ...\run_https.py`였다. `100.107.44.33/32`는 host `Tailscale` interface의 `Preferred` IPv4였다.
- 기존 activation 증거도 `100.107.44.33:18457` → PID `29172`, leaf DER SHA-256 `AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F`를 기록한다: `...\seq138-crl-leaf-activation\REPORT.md:52-59`.

따라서 관측 가능한 경로는 다음과 같다.

`Sandbox guest vNIC` → `Windows Sandbox host virtual switch/network path` → `host network stack` → `host Tailscale 100.107.44.33/32` → `local TCP 18457 listener` → `TLS wrapper` → `WorkerAnalysisGUI-web app`

별도 host `portproxy`, host DNS 변경, `.wsb` port mapping은 이 경로에 없다.

### 2. `server5.autoloop.test` 이름 해석

현재 경로는 guest-local hosts entry를 사용한다.

- direct TCP가 성공한 뒤 guest hosts 파일에 정확히 `100.107.44.33 server5.autoloop.test`를 append하고 `hosts_target`을 기록한다: `...\seq214-v2.0.93-track-a\launcher\guest.ps1:653-655`.
- 이어서 installer에 정확한 origin `https://server5.autoloop.test:18457`을 넘긴다: 같은 파일 `:688-700`.
- Physical 33 raw result는 `guest_tcp_direct_reached=true`, `hosts_target="100.107.44.33"`, `installer_exit=0`을 기록한다: `...\seq214-v2.0.93-track-a\out\guest-result.json:9-11,140`.
- 요약 결과는 installer exit `0`과 runtime-lease gate pass까지 기록한다: `...\seq214-v2.0.93-track-a\RESULT.json:28-35`.

판정은 **hosts가 현재 설계에 필요하고 이미 bootstrap에서 처리됨**이다. `.wsb`에는 DNS 설정이 없고 physical 33에도 독립 `Resolve-DnsName` 결과는 없다. 그러므로 외부/host DNS가 이 이름을 이미 제공한다고 바꾸어 말할 근거는 없다. 다만 hosts append 이후 hostname origin을 받은 installer가 exit `0`으로 runtime-lease/shortcut gate를 통과했으므로, 현재 bootstrap 순서가 실제 transaction에서 사용 가능했다는 후속 증거는 있다.

### 3. canonical private CA의 guest trust 경로

현재 경로는 다음 순서로 확정된다.

1. Canonical input: `E:\KMTech\autoloop-20260824\WorkerAnalysisGUI-web\server-5\certs\private-ca.cert.pem`.
2. Track A staged copy: `...\seq214-v2.0.93-track-a\stage\private-ca.cert.pem`.
3. 두 파일은 각각 `1,258` bytes이고 PEM SHA-256이 모두 `C8150985F313A794FB23CCBCFD75DFC32B3BB3A85E75831C50ED2AC379BD370A`이다. Host preflight도 이 exact size/hash를 pin한다: `...\seq214-v2.0.93-track-a\launch.ps1:319-321`.
4. `.wsb` stage mapping으로 guest `C:\TrackA\stage\private-ca.cert.pem`에 read-only 전달된다: `...\track-a.wsb:7`.
5. Guest는 `certutil.exe -f -addstore Root C:\TrackA\stage\private-ca.cert.pem`을 실행하고 nonzero이면 fail한다: `...\launcher\guest.ps1:657-660`.
6. 같은 PEM path를 `REQUESTS_CA_BUNDLE`과 `SSL_CERT_FILE`에 설정한다: 같은 파일 `:661-662`.
7. Physical 33 결과는 `ca_import_exit=0`, `installer_exit=0`, `runtime_lease_gate_passed=true`를 기록한다: `...\RESULT.json:29-34`.

현재 listener leaf는 issuer `CN=Autoloop Server 5 Nonproduction CA 2026-08-26`, subject/SAN `server5.autoloop.test`, DER SHA-256 `AB365E17...B95F`이다. Canonical CA의 DER SHA-256은 `0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C`이다. 기존 strict verifier는 이 CA 하나만 load하고 hostname checking/CERT_REQUIRED로 `https://server5.autoloop.test:18457`에 TLS 1.3, HTTP `200`, 같은 leaf hash를 확인했다: `E:\KMTech\autoloop-20260824\WorkerAnalysisGUI-web\seq150-canonical-ca-publication\REPORT.md:25-33`. 이것은 host-side 선행 증거이며 physical 33 guest의 strict TLS transcript를 대신하지 않는다.

이미 되는 부분은 **정확한 CA bytes의 stage 전달, guest Root import exit `0`, requests 계열 CA 환경변수 설정, 그 뒤 hostname-configured installer exit `0`/runtime-lease gate pass**이다. 아직 증명되지 않은 부분은 physical 33 guest가 본 peer leaf/chain과 exact Root-store readback이다.

## (b) 실제로 실행/변경한 것과 결과

- `G2G3_ENVIRONMENT_BRIEF.md`와 physical 33/seq214, seq138, seq150의 설정·증거를 read-only로 확인했다.
- `Get-NetTCPConnection -State Listen -LocalPort 18457`: listener `1`, local address `100.107.44.33`, PID `29172`, state `Listen`.
- `Get-CimInstance Win32_Process`: PID `29172`, `python.exe`, command line `...\seq138-crl-leaf-activation\runtime\run_https.py`.
- `Get-NetIPAddress -IPAddress 100.107.44.33`: interface `Tailscale`, IPv4 prefix `/32`, state `Preferred`.
- canonical/staged CA: 각 `1,258` bytes, PEM SHA-256 둘 다 `C8150985F313A794FB23CCBCFD75DFC32B3BB3A85E75831C50ED2AC379BD370A`.
- current leaf: subject `CN=server5.autoloop.test`, matching DNS SAN, issuer canonical CA, DER SHA-256 `AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F`.
- Windows Sandbox launch `0`, product execution `0`, server HTTP request `0`, factory/production access `0`, host/network/server mutation `0`.
- 제품 소스 변경 `0`. 생성한 tracked 산출물은 이 문서 `1`개뿐이다.

## (c) 아직 준비되지 않은 것과 이유 — 최소 목록

1. **다음 Track A task-root의 `.wsb` wiring**: 현재 `seq214` `.wsb`는 완료된 physical 33의 `launcher/stage/out` 절대 경로에 고정돼 있다. `seq217-evidence-streaming-correction\launcher\guest.ps1`에는 아직 대응 `.wsb`가 없다. 다음 transaction은 새 task-root의 세 mapping을 같은 guest path로 가리키고 corrected launcher 및 exact canonical CA를 stage해야 한다. 이것은 포트/방화벽 결손이 아니라 새 transaction packaging 항목이다.
2. **fresh guest의 ephemeral bootstrap 재실행**: hosts 및 Root-store 변경은 종료된 physical 33 guest와 함께 사라졌다. 다음 guest가 같은 두 명령을 다시 실행해야 한다. 현재 script block 자체는 검증된 상태다.
3. **한 줄짜리 guest strict-TLS 증거**: physical 33은 direct TCP와 CA import exit `0`을 각각 증명했지만, hostname resolution + peer identity + CA validation + HTTP status를 한 transcript로 남기지 않았다. 이것이 세 항목에 남은 유일한 통합 관측 gap이다.

필요하지 않은 작업: host DNS/hosts/firewall/portproxy/Tailscale 변경, 새 listener, 새 CA, 제품 소스 수정. 현재 readback과 physical 33은 이를 요구하지 않는다.

## (d) 다음 Track A에서의 정확한 준비 판정 기준

제품 byte 실행 전에, hosts append와 Root import 뒤 **certificate bypass 없이** exact hostname으로 검사한다. 성공 판정은 다음 조건을 모두 확인한 뒤 아래 한 줄을 그대로 출력한 경우뿐이다.

- `server5.autoloop.test`의 resolved IPv4 set에 `100.107.44.33` 포함
- `100.107.44.33:18457` TCP connect 성공
- OS trust validation과 hostname/SAN validation을 켠 TLS handshake 성공
- peer leaf DER SHA-256이 `AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F`
- Root store에서 canonical CA DER SHA-256 `0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C` readback
- redirect/bypass 없이 `GET https://server5.autoloop.test:18457/health/ingest`가 final URI 그대로 HTTP `200`

```text
SERVER5_GUEST_READY=PASS RESOLVED_IPV4=100.107.44.33 TCP=1 TLS_VALID=1 HTTP=200 FINAL_URI=https://server5.autoloop.test:18457/health/ingest LEAF_DER_SHA256=AB365E17B3FB82C0425FBDB6264D25DFCB6F249C06641291B911495643C7B95F ROOT_DER_SHA256=0B5F5874DC1531BFD65F559347463108F0F2773990740EBDA46078655CB4435C
```

이 한 줄은 reachability/trust 준비 증거일 뿐이며, receipt accepted, projection row, dashboard API/화면 반영을 요구하는 g3 PASS가 아니다. `/health/ingest`의 `200`을 g3 증거로 승격하지 않는다.

## (e) UNKNOWN — 확인하지 못한 것

- Physical 33 당시 Windows Sandbox 내부 guest IPv4, default gateway, HNS/WinNAT flow table은 보존되지 않았다. virtual switch/vNIC 이후의 내부 구현 세부는 UNKNOWN이다. 이는 direct TCP reachability 판정을 바꾸지 않는다.
- Physical 33의 독립 `Resolve-DnsName`/`[Net.Dns]` 출력은 없다. hosts append 성공과 후속 hostname transaction은 확인되지만 실제 resolver answer transcript는 UNKNOWN이다.
- Physical 33 guest의 peer certificate chain, leaf hash, negotiated TLS version, strict hostname-validation transcript는 UNKNOWN이다.
- Physical 33 guest Root store의 exact scope/thumbprint readback은 UNKNOWN이다. 확인된 값은 `certutil -addstore Root` exit `0`이다.
- SYSTEM scheduled task가 실제로 읽은 exact CA path는 `UNPROVEN`이다: `...\seq214-v2.0.93-track-a\RESULT.json:37-38`.
- 다음 Track A의 최종 task-root, `.wsb` 절대 mapping, launch 시점 listener PID는 아직 정해지지 않아 UNKNOWN이다. PID는 readiness line 직전 host preflight에서 다시 읽어야 한다.
- 이 문서는 server route별 인증/fixture/business-state readiness를 검사하지 않았다. `seal`, receipt recovery, projection 및 headed dashboard의 g2/g3 충족 여부는 UNKNOWN이며 별도 환경 트랙의 책임이다.
