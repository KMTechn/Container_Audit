# 이름 등록 B (CA-5)

목록에 없는 이름은 「목록에 없으면 『새 이름 등록』을 누르세요」로 안내한다. 같은 화면의 기존 「새 이름 등록」 단추가 등록 창을 연다.

작업자 고르기 화면의 「새 이름 등록」에서 이름만 받는다. 앞뒤 공백·NFC·Zs·연속 공백을 정리하고 1–64 code point를 허용한다. 제어 문자·경로 문자·첫 글자 `= + - @`와 보호 관리자 이름/6자리 코드는 거부한다. 승인·PIN·추가 개인정보는 없다. 번호는 선택 화면의 「이름 #번호」에만 표시하며 기록·CSV·전송 이름에는 붙이지 않는다. 미확정 이름은 「이름 #임시순번」으로 표시한다. **stage_a=false**, 숨김·30일 계산은 없다.

`roster.registrations.json`은 현장·내구 순번·작업자 행·등록/복귀 요청·임시 UUID 대응·v2 명단을 checksum으로 묶어 원자 저장한다. flush/fsync 후에만 새 이름을 고를 수 있다. 저장 실패는 입력을 유지하고 다른 이름 선택·스캔을 막지 않는다. 손상 원본은 `.bad-*`에 보존하고 새 UUID로 대체하지 않는다. 격리 이동이 거부되면 손상 원본을 제자리에 보존하고 해당 등록 기록을 사용하지 않는다. 시작·기존 명단 선택은 계속하며 선택 화면 안내와 `WORKER_REGISTRATION_QUARANTINE_UNAVAILABLE` 기록으로 관리자 확인을 요청한다. v1 명단의 정상 캐시·기존 로컬 이름은 호환 경로로 유지한다.

생산자 HTTPS/HMAC으로 `/api/worker-roster/v2/query`와 `/api/worker-roster/v2/register`를 호출한다. v2 query는 현장 ID만 보낸다. create는 mode·authority_scope_id·request_id·display_name·action_at·temp_uuid, return은 temp_uuid 대신 existing_worker_id를 보낸다. 설치/host·관리자 필드는 보내지 않는다. B·temporary_identity_ingest 둘 다 true 또는 `worker_roster_v2_stage_b` ID가 확인된 뒤에만 register를 보낸다. HTTP와 사람 응답 대기는 UI 스레드/쓰기 허가 밖이며, 로그인 세대·시도 번호를 확인한 뒤 로컬 적용만 다시 허가를 얻는다.

request_id·temp_uuid·본문·action_at은 재시작/응답 유실에도 그대로이고 nonce만 새로 발급한다. 연결 실패·503(ROSTER_V2_REGISTER_DISABLED 포함)·429·5xx는 보낼 것을 유지한다. 빈 JSON·HTML·계약과 맞지 않는 오류 코드 등 검증하지 못한 400도 원 요청으로 다시 보낸다. 검증된 400 INVALID_REQUEST만 「관리자 확인 필요」로 보존하며 미래 5분을 넘은 action_at은 나중에 다시 보낸다. 설치 단위 오류는 그 전송 회차만 끝내며 항목 오류는 다음 이름으로 넘어간다. 409는 원 오류/요청을 「관리자 확인 필요」로 보존하고 UUID를 재발급하지 않는다. 대응 조회만으로 409 표시를 풀지 않으며 대응된 이름이 원 요청 이름과 같아질 때 푼다. return의 WORKER_DISABLED/WORKER_NOT_FOUND는 종결하고 그 사람의 선택만 막는다. 새 빈 명단을 받아도 로컬 등록 이름·종결 복귀 이름을 기존 PC 이름 목록으로 다시 넣지 않는다.

정규화 동명은 같은 등록 창 안에서 한 번 확인한다. 같은 사람은 기존 UUID 복귀, 미확정이면 같은 temp_uuid 선택과 create에 종속된 복귀 intent를 함께 저장한다. 대응 저장 뒤에 원 복귀 시각/요청 ID로 return 본문을 최초 저장한다. 다른 사람은 구분 이름으로 새 등록한다. 회사 서버가 붙인 최종 이름/번호와 모든 query의 temp_links를 내구 저장한다. 낮은 명단 판은 최신 상태를 덮지 못한다. DISABLED는 로컬 대기 복귀보다 우선한다.

대응된 중앙 UUID는 새 묶음부터 사용한다. 진행·보류·저장된 command와 당시 이름은 바꾸지 않는다. 복구 소유 비교에는 검증된 임시 대응만 사용한다. B 신호가 꺼지면 미확정 UUID를 전송 신원에 넣지 않고 이름만 보낸다. 기존 신원 전송 결정/명령 재전송은 저장본 그대로다.

랩 확인은 담당 레인이 별도로 한다: 1366×768/125%에서 등록·동명 선택을 보고, B 켬/끔·503과 끊김/재시작을 점검한 뒤 느린 등록 중 스캔 순서 및 다음 묶음 신원을 readback 한다. 회사 서버/실제 GUI/설치·웹 랩은 이 브랜치의 headless 결과로 증명하지 않는다.
