ACCEPT · P1 0 · P2 0 · P3 3
Claude Opus 5.5

# 독립 검토 477c1557..1dddb0ab
읽기만. 시험·빌드·설치기·앱 실행 0. 가림 순수 함수만 AST로 떼어 격리 Python에서 전후 비교(가짜 값). pwsh 없음 → PS는 읽어서 판정.

## 1 가림
- Bearer·Basic·대소문자 섞임 × 헤더·`=`·Proxy-/X-Authorization·키 뒤/스킴 뒤 줄바꿈·탭·앞뒤 진단: 전 Python 두 sink 값 남음 → 후 0. JSON·글 속 JSON·dict repr은 전후 0. 사슬 셋째·stdout(str)·stderr(bytes) 0.
- Python은 span 끝만 늘림 → 넓히기만. 「(Bearer)」「Bearer」「Basic」「AUTHORIZATION check unavailable」 그대로. 종류·errno·winerror·exit_code 보존.

## 2 같은 꼴
- 소비 정규식 auto_update.py:806 = bootstrap_integrity.ps1:755, 언어마다 1곳. Convert 함수 정의는 bootstrap 1곳, INSTALL_CANONICAL은 핀만.
- 결과 글자는 다름(전부터): PS catch-all(:769)이 키부터 줄 끝까지 지움, Python은 키·뒤 진단 보존. 자격 값 0은 같음.
- catch-all 뒤로 옮김은 필요: 앞이면 「Authorization: Bearer⏎<값>」 PS 누출(이번에 닫힘).
- BOM·LF 유지, 비ASCII 추가 0, 괄호·따옴표 균형.

## 3 지문
- 인벤토리 734b345e…: 자기 해시·정규 바이트 일치. 차이는 auto_update.py ≥802·bootstrap ≥765 줄 +7뿐(293건).
- 734b345e…: writer_session_fence.py:107·container_writer_fence.ps1:29·contract.json:53·transition:6. a09e6e54…: INSTALL_CANONICAL:79·fence.ps1:4 = 파일.
- transition files[]·source_replacements after: 저장소에 있는 143건 모두 머리 바이트와 같음. 옛 핀 해시 7개 git grep 0. refresh --check 미실행, 값 대조로 갈음.

## 4 꼴
_failure_details 칸·순서·_truncated·상한·exit·안내 문구 diff 0.

## 5 시험
- test_installation_recovery_independence.py:184: 모듈 이름을 auto_update로 바꿔 probe_only 등록명(writer_session_fence.py:719)과 맞춤. 전 이름은 import 때 WRITER_PROBE_ONLY_SINK_NOT_ALLOWED(:789). 단언 그대로·sys.modules 복원 → 약화 아님, 복구.
- 새 PS 시험은 powershell.exe/pwsh.exe 있는 곳에서만 돈다.

## 찾은 것
- P3-1 auto_update.py:806 · bootstrap_integrity.ps1:755 — `\s+`가 접힘 공백 없이 CR/LF를 넘고 `=*(?!…)`가 `이름=`을 패딩으로 봄: 「Authorization: Bearer⏎Traceback (most…」→「…[REDACTED:field] (most…」(줄 합쳐져 failure_user_line 바뀜; PS는 catch-all까지 겹쳐 다음 줄 전체 사라짐), 「Authorization: Basic realm="x"」→ realm= 사라짐. 과잉 가림, 노출 아님. 시험은 `winerror=` 줄만 봄.
- P3-2 auto_update.py:805 — bearer|basic만: 「Authorization: Token·Negotiate <값>」 Python 두 sink 값 남음. token68 밖 글자 뒤(「Bearer abc:def」→「:def」)·큰따옴표 목록 속 「"Authorization: Basic <값>"」(_failure_text)도 남음. 모두 전부터. 키가 authorization이면 스킴 무관 `\s+token68` 소비 제안.
- P3-3 bootstrap_integrity.ps1:769 — 순서 이동으로 이론상 준 꼴: 「pin=xAuthorization: Bearer <값>」 전엔 PS가 가렸으나 이제 값 남음(읽기 판정, Python 전후 같음). 현실 입력 아님.
