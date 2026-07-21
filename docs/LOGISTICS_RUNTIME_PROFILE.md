# Container Audit 중앙 물류 PC 프로필

중앙 이적·제품 교체를 필수로 운영하는 PC는 공통 machine profile v1을 설치한다.
기본 위치는 `%ProgramData%\KMTech\Logistics\runtime-profile.json`이다. JSON에는 토큰을
저장하지 않고 `bearer_token_ref=dpapi:secrets/bearer-token.dpapi`만 기록한다. 토큰은
고정 entropy를 사용한 Windows machine-scope DPAPI blob이며, 설치 폴더 ACL은
SYSTEM/Administrators 전체 권한과 지정 작업 계정 읽기 권한만 남긴다.

관리자 PowerShell 예시:

```powershell
$secureToken = Read-Host 'PC 전용 bearer token' -AsSecureString
$tokenPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
  $env:KM_LOGISTICS_INSTALL_BEARER_TOKEN = `
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPtr)
  .\KMTech_Logistics_Profile_Install.exe --base-url https://worker.example.com `
    --authority-scope PLANT-01 --authority-epoch 7 --plane-epoch 3 `
    --device-id CONTAINER-PC-01 --source-host-id CONTAINER-PC-01 `
    --reader-principal 'KMTECH\container-operator' --dry-run
  .\KMTech_Logistics_Profile_Install.exe --base-url https://worker.example.com `
    --authority-scope PLANT-01 --authority-epoch 7 --plane-epoch 3 `
    --device-id CONTAINER-PC-01 --source-host-id CONTAINER-PC-01 `
    --reader-principal 'KMTECH\container-operator'
} finally {
  Remove-Item Env:KM_LOGISTICS_INSTALL_BEARER_TOKEN -ErrorAction SilentlyContinue
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPtr)
}
[Environment]::SetEnvironmentVariable(
  'KM_LOGISTICS_PROFILE_PATH',
  'C:\ProgramData\KMTech\Logistics\runtime-profile.json',
  'Machine'
)
[Environment]::SetEnvironmentVariable('KM_LOGISTICS_REQUIRED', '1', 'Machine')
.\KMTech_Logistics_Profile_Check.exe
```

`KM_LOGISTICS_PROFILE_PATH`와 `KM_LOGISTICS_REQUIRED`는 반드시 `/M` Machine 값으로
같이 설치한다. 둘 중 하나라도 Machine에 있으면 동명 process 값은 사용하지 않는다.
토큰을 명령줄 인자, JSON, 로그, 설치 report에 넣지 않는다. 회전은 새 PC 전용 토큰을
환경변수로 주입하고 `--replace`로 명시한다.

`KM_LOGISTICS_REQUIRED=1`에서는 프로필 누락·평문 토큰·HTTP/loopback URL·scope/epoch/
plane 불일치·인증 또는 capability probe 실패 시 Tk와 백그라운드 retry를 시작하기 전에
프로그램이 차단된다. 환경변수 기반 기존 설정은 필수 모드가 아닐 때만 호환된다.

## 10~30대 전환 순서

1. 서버의 scope/authority epoch/plane epoch와 PC별 token, `device_id`,
   `source_host_id`, 승인 작업 계정을 먼저 확정한다. PC 식별자는 중복시키지 않는다.
2. 1대에서 dry-run, 실제 설치, Check, 이적 1건과 제품 교체 1건을 확인한다.
3. 2~3대가 동시에 서로 다른 이적을 처리하고, 같은 교체 후보를 경쟁시키는 시험을 한다.
   중앙 CAS에서 한 요청만 승인되고 나머지는 재조회/충돌로 끝나야 한다.
4. 5대 단위로 배포한다. 토큰 자체는 수집하지 않고 PC ID, scope/epoch, Check 결과만
   배포 증적으로 남긴다.
5. 전체 전환 뒤 음수 재고, 제품의 중복 active owner, idempotency receipt 누락,
   `REPLACEMENT_SOURCE_NOT_SINGLETON` 이외의 donor 소비 오류가 0인지 확인한다.

토큰이나 epoch를 회전할 때만 `--replace`를 사용한다. 교체 뒤 Check가 실패하면 앱을
시작하지 않는다. 긴급 복귀도 먼저 Machine 필수 게이트 변경 승인을 받은 뒤 수행하고,
DPAPI 파일 삭제는 마지막 별도 승인 단계로 둔다.
