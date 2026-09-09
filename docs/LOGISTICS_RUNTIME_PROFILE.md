# Container Audit 중앙 물류 PC 프로필

현행 canonical portable 설치는 현재 사용자 onboarding을 통해
`%LOCALAPPDATA%\KMTech\Logistics\profiles\Container_Audit\runtime-profile.json`과
사용자 DPAPI 자격증명을 준비한다. `CONTAINER_AUDIT_DATA_ROOT`로 격리한 실행에서는
`<data_root>/logistics-profile/runtime-profile.json`을 사용한다. 실제 선택 순서와
시작 경계는 [CA-O02](spec/operations.md#ca-o02),
[current_user_onboarding.py](../current_user_onboarding.py),
[logistics_runtime_profile.py](../logistics_runtime_profile.py)를 따른다.

## 호환 machine profile

현재 사용자 profile을 선택하지 않은 경로에는 app-scoped machine profile과
Machine 환경 그룹, 허용된 process fallback이 남아 있다. 과거 공통
`%ProgramData%\KMTech\Logistics\runtime-profile.json`과 별도
`KMTech_Logistics_Profile_Install.exe`/`Check.exe` 예제를 현행 portable 설치의
필수 단계로 사용하지 않는다. 현재 패키지는 실제 import되는 Python helper를 포함한다.

machine profile을 사용하는 배정에는 `KM_LOGISTICS_PROFILE_PATH`와
`KM_LOGISTICS_REQUIRED`의 Machine 그룹을 함께 확인한다. Machine 값 일부를
process 환경으로 보충하지 않는다. JSON에는 평문 토큰을 넣지 않고 DPAPI 참조를
기록하며, machine-scope DPAPI와 SYSTEM/Administrators 및 지정 계정의 ACL 경계를
유지한다. 토큰을 명령줄, 로그, report에 기록하지 않는다. profile·토큰·epoch·ACL
변경에는 해당 대상의 실제 배포/보안 권한이 필요하며, 이 문서는 변경 권한이 아니다.

## 시작 검증과 업무 상태

필수 profile 모드에서는 프로필 누락·평문 토큰·HTTP/loopback URL·scope/epoch/plane
불일치를 Tk와 백그라운드 retry 시작 전에 검사한다. 로컬 profile/DPAPI 확인과 서버의
authenticated capability 확인은 서로 다른 관측이다. 로컬 확인만으로 서버 준비를
판정하지 않는다.

중앙 ACK가 아직 없어도 내구 저장된 로컬 완료는 `LINKED`로 남을 수 있다.
`ACKED`는 exact 중앙 receipt 검증 후의 상태이며, 이 두 상태를 같은 성공으로
취급하지 않는다. 물리 이적과 다음 공정 판단은 [CA-C03](spec/contracts.md#ca-c03),
[CA-12](spec/README.md#ca-12)의 계약을 따른다. 서버 장애 중 복구 가능한 로컬
자료와 실패 증거를 보존하고 임의 재전송·identity 초기화·DPAPI 삭제를 하지 않는다.

선택된 여섯 프로그램 qualification과 accepted `d440b1f7`는 Main의 기존 수용 범위로
유지한다. 새 SHA마다 profile 재설치나 업무 replay를 요구하지 않는다. 배정된 새 배포,
관련 동작 변화 또는 실제 실패가 있을 때 그 범위의 기존 검증과 관측을 사용한다.
CONTAINER_AUDIT1–3은 별도 명시 권한이 없는 production no-change 대상이다.
