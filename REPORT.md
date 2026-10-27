ACCEPT · P1 0 · P2 1 · P3 2
검토 모델: Claude Opus 5.5

# 독립 검토 — v2.0.123 합침 묶음 (09ae23aa..477c1557)

읽기만 함(시험·빌드·설치기·앱 실행 0). 합침마다 remerge-diff(CR 무시)로 손 풀이만 보고, 새 재료 e77e87b..07dca0a는 전부 읽음.

## P2
- **품목 파일 안내 3곳은 공식 stop을 받아도 시작이 끝나지 않음.** `load_items`(Container_Audit.py:1529·1539·1548)가 `_show_visible_startup_notice()`의 True를 버리고 `root.destroy()` 뒤 `[]`를 돌려줌 → `__init__`의 `tk.BooleanVar`(:1311)에서 RuntimeError → 웹이면 옛 Tk로 넘어가(ca_screen_bridge.py:1414→1443) 같은 안내를 다시 띄우고, 아니면 `main`의 `_startup_refusal(None, failed=True)`(:23996)가 「프로그램 시작 확인」을 띄움. 멈춤 요청은 첫 안내가 이미 소비했으므로 뒤 안내는 사람이 닫을 때까지 남고, `request_app_stop`은 150 초 뒤 UNKNOWN. 122(messagebox)보다 나빠지진 않았지만 2번 기준을 다섯 안내 중 셋이 못 지킴(평소에도 둘째 안내가 뜸, 기존). 고침: True면 전용 예외로 `_prepare_gui_startup`이 `return 0`(브리지 fallback 제외), 또는 소비한 stop을 기억해 뒤 안내가 바로 True.

## P3
1. ca.css의 122 되돌림이 「1280×945 글자 3」보다 넓음: 머리글 flex-wrap과 cofill grid·막대 static은 `@media (601–1365px)` 글자 3 전체(:332, 높이 무관)에 걸리고, 높이 ≥800의 ui1028 머리글 grid는 모두 지워짐(:342). frame.css:627 큰 글자 2·3 이동 단추 보이기도 122 고침(4e1de5d)이 자동 합침으로 들어옴. 규격 README 글(큰 글자 머리글·막대 122)과는 맞지만 1270×730·1024×768 글자 3은 122 배치로 그려짐 → 설명을 고치거나 media를 좁힐 것.
2. 무결성 띠(ca_screen_bridge.py:184)가 공지 띠 앞에서 `alerts[:4]`(:217) 한 칸을 씀 → 공지·휴식·품목 안내가 함께면 최근 처리 알림(「확인」)이 잘림. 맨 끝이나 4칸 밖으로.

## 확인함(문제 없음)
1. `_apply_prepared_once`·`bootstrap_supervision_deadline`(e325c0f): READY 900·다시 기회와 멈춤 기다림 150(`RELAY_NORMAL_STOP_TIMEOUT_SECONDS`) 모두 유지. 900+150 < 상한 1140, 여유 90 초 = ptimeout 단독(240+150<480). `_alerts`(b4fb0d1): 송신 띠 앞붙임과 사후 검토 줄 둘 다, contract maxItems 5. fitList(c74db6f): 안내 비움→넘침 잼→넘칠 때만 1줄, 화면 크기 무관. 나머지 셋은 충돌 없이 pstart/pheld 위에 dialog가 얹힘(read_retry·relay 띠 유지).
2. 막는 창: 웹 주인은 `startup_notice_tk`=원래 tk.Tk, 끝나면 되돌림. 남은 `_show_startup_notice`는 `startup_refusal` 감싸기가 Tk를 되돌린 뒤 불려 숨은 모달 0. 멈춤 감시는 Toplevel에, 닫기·Enter·주인 X 모두 root.destroy→finally에서 owner.destroy(실패 삼킴). Tk 생성 실패는 native 30 초. 무결성 없음은 창 없이 웹 warn 띠(단추 없음·초점 안 뺏음)·Tk 오른쪽 안내 자리, 스캔 계속. 불일치 거절 유지. 지원 출력에 원래 글·보고서 경로.
3. tokens.css·scan.js = 웹 바이트(scan.js는 pgsrs 제어 문자 + 「다시 스캔하세요」), 나머지 ui1028 + P3-1. MANIFEST 101행 해시 일치.
4. .120/.112 표지 → .123 ALLOW. .123 floor=.123 → 옛 판 REFUSE.
5. MOVEMENT_EXCLUSIONS 4줄 SHA = 지금 이동 명령 글(CP:4465·7572, TP:1471·2601), 모두 해시·시각 되읽기, 와일드카드 0. call_operator 29번째 = TP:801 `& $Action`, guarded(Enter-ContainerPlacementWriterFence). SID fixture는 import 원천(auto_update)에 묶음. b1f8155(상한 1140·`code` 속성·pheld 43dffad 분류)도 약화 0, 상한 자르기는 test_auto_update_trial_supervision이 봄.
6. inventory_sha256 95c795c3 = fence.py·fence.ps1·contract, bootstrap 1e753a7c 일치. transition after 143건·인벤토리 파일 해시 일치. 파이썬 sink 270/270·직접 변경 191/191 줄 번호 일치, uncovered 0·guard 실패 0.
