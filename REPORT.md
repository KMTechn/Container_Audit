Opus 5.5 (claude-opus-5-5)
ACCEPT · P1 0 · P2 1 · P3 2

검토: a46210f..24f000c(sub-694) 읽기만. 시험·빌드 실행 0. inventory 해시만 일회용 스크립트로 블롭을 읽어 다시 셈. 줄 번호 = 24f000c. CA=Container_Audit.py, ELS=event_log_store.py.

## 결함
- **P2-1 (기존, diff 밖, 108 과 같은 꼴)** checkpoint 없는 일반 행(SCAN_OK 등 `_write_event_log_entry` CA:18421)은 outbox 사본이 하나뿐인 내구본. 순서: stage(ELS:93-97) → drain 의 CSV PermissionError(ELS:135, 사본 남음) → 사본 격리 → 다음 flush 는 `_unstaged` 가 비어 다시 만들지 않음(ELS:78) · glob 0 → 행은 메모리 `_staged_payloads`(ELS:95)에만 있고, 재시작하면 사라짐. 재생성은 같은 payload 를 다시 stage 할 때만 돎. 제안: drain 시작 때 `_staged_paths` 가운데 사라졌고 ACK 안 된 것을 메모리 사본으로 다시 stage. 이번 회귀 아님 → 후속.
- **P3-1 거짓 실패 안내** 배경 flush 의 recover(CA:18023)와 drain(CA:18025) 사이에 다른 drain(SCAN_OK through CA:18454 · 그 밖 CA:18456 · reset CA:16680 · park CA:21386)이 같은 사본을 먼저 ACK 하면, 이 flush 의 projected 에 key 가 없음 → CA:4297 raise → CA:18033 빨간 「로그 저장 실패」 + log_write_errors 기록. 다음 flush 에서 다시 stage(멱등이라 중복 0)하고 풀림. 손실 0, 1주기 오탐. 고치기 전에는 바로 지웠음.
- **P3-2 순서** 다시 만든 사본은 새 sequence(ELS:92)를 받아, 잠김 동안 뒤에 쌓인 행보다 늦게 CSV 에 씀(사본이 사라진 때만). timestamp 열은 그대로.

## 항목
1. **ACCEPT**(checkpoint 감사) CA:4288-4297, ELS:81-91. (a) CSV 실패 → 사본 사라짐 → 다음 flush: stat 가 FNF → 다시 만듦. 아직 잠겨 있으면 raise 로 checkpoint 유지. (b) recover 뒤·drain 앞 사라짐: key 없음 → 유지 → 다음 번 다시 만듦. (c) 다시 만들 때 atomic_write 실패: `_unstaged` 머리에 남음 → CA:18026 False. (d) ACK 직전 사라짐(ELS:179-183): fsync 뒤라 행은 CSV 에 있음. (e) 새 save 가 앞 pending 을 합침(CA:4176-4181) → reset·undo 감사도 남음. 남은 구멍 = P2-1.
2. **ACCEPT** 중복 0: 다시 쓰는 길은 모두 `append_event_log_entry_idempotent`(ELS:432, 경로·프로세스 잠금 아래 key 검사)를 지남. 격리됐다 되살아나 사본이 둘이어도 두 번째는 False. 시험 1 이 두 번 flush 뒤 행 1 을 확인. 순서는 P3-2.
3. **ACCEPT** 정상 길: flush 마다 recover 가 다시 stage(사본 있으면 dedupe, 없으면 다시 만듦) → 같은 drain 이 투영하거나 멱등 False → key 있음 → 지움. key 는 stage(CA:4225-4228)와 같은 함수·같은 문자열. 영원히 남는 길 없음. 잠깐 남는 길 = P3-1. 두 번 투영해도 CSV 행은 1.
4. **ACCEPT** raise 는 flush 의 try(CA:18029) 안에서만 남. CA:5164·16680·21386 은 반환값을 안 씀. 배경은 direct sync 만 다음 성공까지 미룸(CA:18055). tray.pending 이 남는 것은 지금의 CSV 잠김 계약(CA:4176)과 같음. 스캔·완료·수량·세트 길은 바뀐 데 없음. stat 은 `_lock` 안에서 한 번 읽을 뿐.
5. **ACCEPT** inventory 는 line·sha 밖에 차이 0. sha(d60f…56a0)를 `_inventory_sha256` 방식으로 다시 세면 맞음. 줄 이동 CA +10 · ELS +9, def 17건 확인. uncovered 0·[] 그대로. 전이 json 의 after 6건 = 블롭 sha256. 새 코드는 stat·읽기·raise 뿐이라 mutation site 0(`_clear_projected_checkpoint_audits` direct 0 그대로). 문서(README·BACKLOG)의 「같은 flush」 표현은 코드와 맞음(P3-1 의 원인).
