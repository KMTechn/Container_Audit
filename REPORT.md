ACCEPT · P1 0 · P2 0 · P3 2

검토: 24f000c..1702e7e(sub-698) 읽기만. 시험·빌드 실행 0, 해시만 일회용 스크립트로 git 블롭을 읽어 셈. 줄 = 1702e7e. ELS=event_log_store.py, CA=Container_Audit.py.

## 결함
- **P3-1 감지가 `_lock` 안 O(N)** ELS:111-120 은 drain 마다 `_staged_paths` 전부를 `_lock` 을 쥔 채 stat. 일반 행은 행마다 flush(CA:18074)라 CSV 가 오래 잠겨 사본 N 개가 쌓이면 행마다 stat N 번, 그동안 스캔 길 `stage()`(ELS:63·71)가 기다림. 멈춤은 아니나 잠김이 길수록 늘어남. 제안: 잠금 밖 glob 한 번 → 집합 차로 빠진 것만 잠금 안에서 다시 확인.
- **P3-2 문서 정밀도** BACKLOG 「기존 사본으로 재저장 · 새 파일 이름 추가 안 함」— 실제는 같은 꼴의 새 이름(새 sequence+uuid, ELS:92-93)이라 앞 P3-2 순서 뒤바뀜 그대로. 「재저장 실패 뒤 재시작 재생에도 한 행」은 재시작 전 재시도가 성공했을 때만 참(실패 중 재시작은 0 행, operations.md:1049 범위).

앞 지적: P2-1 고쳐짐(1). P3-1(다른 drain 이 먼저 ACK → CA:4297 → 거짓 안내)·P3-2 그대로, diff 밖.

## 항목
1. **ACCEPT** CSV 실패(사본·`_staged_paths` 남음) → 격리 → 다음 비중첩 drain: stat FNF → 원문을 `_unstaged` 에 → 쓴 뒤에만 popleft(ELS:94-97). 쓰기 실패면 `_unstaged` 에 남고 `has_unstaged` 로 종료 거부(CA:17981). 단계마다 CSV·사본·메모리 중 한 곳. 남은 구멍 순서: (가) 격리 뒤 다음 drain 전 프로세스 끝(충돌·전원·강제 종료) — 감지 전엔 메모리뿐. 창 = writer 주기 1 s(잠금 파일 대기 최대 10 s). 닫기 마감 3 s 를 넘기면 drain 이 다시 만들기 전에 돌아와(ELS:104) 감지 없이 닫힘. (나) 다시 쓰기 실패 중 프로세스 끝(문서가 보존 주장 안 함). (다) 같은 drain 에서 다시 만든 뒤 재격리 — 읽기 FNF 를 ACK 로 봄(ELS:137-138) → flush True·종료 통과. 내용 기반 격리가 되풀이되면 조용히 사라짐(전과 같음, 회귀 아님).
2. **ACCEPT** 투영은 모두 `append_event_log_entry_idempotent`(ELS:101, CA:18454·18456). 루프가 pop 해 한 번만 옮기고 같은 payload 는 한 `_lock` 아래 dedupe(ELS:80-89) → 사본 1. 예약+append(ELS:131-153)·unlink+pop(ELS:176-196)이 각각 한 잠금 구간이라 루프는 둘 다 보거나 못 봄. fsync 중 격리 → 다시 만든 사본은 False. 시험 1 이 격리 복귀(사본 2)+다른 인스턴스 ACK 뒤 재생성까지 1 행·glob 0 확인. encoded 는 stage·`__init__`·ACK 가 같아 되풀이 재생성 없음.
3. **ACCEPT** 사본이 다 있으면 stat 뿐 → 동작 같음(비용 P3-1). nested 그대로. `through` drain 은 다시 만든 사본이 더 큰 sequence 라 자기 target 에서 멈춤 → 기다림 0. 다시 만든 사본은 ACK 가 지움 → 영원히 남는 길 0. 그 내용만 계속 못 쓰면 FIFO 머리(ELS:78)에서 뒤 행을 막으나 기존 stage 실패와 같은 꼴.
4. **ACCEPT** 새 raise 는 drain 안 → 기존 try(CA:18015·18449) 안. 다시 쓰기 실패 때 `stage()` 실패는 같은 폴더라 새 행도 원래 실패하던 경우 → 같은 안내·False. 스캔은 저장(CA:16174)·표시 뒤 로그(CA:16209). 종료 거부는 의도(operations.md:1049). 바뀐 시험 clears_only_after_projection 은 CSV 행 단언과 함께라 맞음.
5. **ACCEPT** `-shm` 은 WAL 색인(내구 자료 없음), 빈 `-wal` = 없음(SQLite 가 무시). 비어 있지 않은 WAL·.db·.json·.csv 는 바이트 비교, 빈↔비어 있지 않음 바뀜도 key 차로 걸림. 메타 시험이 WAL 바뀜 검출 확인. 이름 끝 필터에 걸릴 업무 파일 없음.
6. **ACCEPT** inventory 차이 = line 21 건(ELS:110 뒤 +10)·sha 뿐, ELS 항목 24 건 모두 맞는 def·연산. `_inventory_sha256` 다시 셈 = 38b2…409d, 핀 3 곳·전이 after_inventory 같음. 전이 after 8 건 = 블롭 sha256, before 그대로. 새 코드는 stat·메모리뿐 → mutation site 0.
