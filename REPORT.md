REJECT · P1 0 · P2 1 · P3 1

# 후속 검토 — calm-band2-ca (501b099d..68a86c6c, 1커밋)

읽기만 · 시험/빌드 실행 0 · 줄 = 68a86c6c, 따로 적지 않으면 Container_Audit.py.

## P2-1 띠가 떠 있으면 상태 문구가 모두 버려져 거절·정지 안내가 안 보임 (이 커밋이 연 회귀)

- show_status_message 는 띠면 바로 return(:21241-21243)함. 그래서 저장 정지 강제 문구(:21236-21237)도 함께 버려짐.
- 띠는 비막음이라 _refuse_entry_scan(:15228-15240)이 _show_scan_refusal 을 건너뛰고 status 로만 알리는데, 그 status 가 버려짐. render(:17130)도 비막음 띠에서는 거절 글을 지움.
- 사라지는 문구:
  - 입장 거절 전부(:15024-15063, 처리 오류·저장 정지·처리 중)
  - 처리 오류 정지(:1660)
  - 제품 길의 저장 정지·보류 중복·상태 저장 실패(:16074·:16078·:16178)
  - 부분 제출 기록 실패(tray_completion.py:936)
- 결과: 거절은 바르게 되지만 Tk 화면에는 「트레이 완료는 이 PC에 저장했지만…」 띠만 남음. 반복음은 이미 띠 소리라 새 신호가 없고, 제품 길은 :15606 이 소리를 먼저 끄므로 아무 소리도 안 남. 저장 정지 중에는 띠 문구와 사실이 어긋남.
- 새 시험 projection_saved=False 는 띠만 단언해서 이 버림을 굳힘.
- 제안(고침 0): 띠일 때도 거절·DANGER 문구를 띠 아래에 붙임(_refuse_entry_scan·render :17130). 또는 duration=0·DANGER 문구는 버리지 않음.

## P3-1 Tk 「확인」 단추는 처리 오류 중에도 띠를 닫음 (바탕부터 있음)

- render(:17184)는 처리 오류여도 띠면 확인 단추를 NORMAL 로 둠.
- 단추 command·Esc·Return(:12391·:12406·:15188)은 조건 없이 _acknowledge_active_notice 를 부름.
- 웹은 같은 때 확인을 숨김(ca_screen_bridge.py:182).
- README 새 문장 「처리 오류 중 … Esc … 로 닫지 않는다」는 입력칸 Esc 에만 맞음. 업무 막음은 풀리지 않음.

## 항목

1. **부분 수용**(P2-1 단서) — 띠 보존과 반복음은 맞고, 위 P2-1 회귀가 남음.
   - 띠 보존: 덮던 세 길이 모두 막힘 — 부분 제출(tray_completion.py:907 뒤 :931/:936), 다른 비막음 status(:21241), 4초 만료(:21283-21286). 띠를 바꿔 끼울 수 있는 비막음 present 는 status 와 띠 자신 둘뿐.
   - 반복음 묶기:
     - 띠 present 가 플래그를 세움(:20191). render 가 띠가 아닌 알림을 보면 소리를 멈춤(:17091-17094). 막는 경고가 뒤에 오면 소리를 넘겨받음(:17023-17026, present :17539 → beep :17541).
     - 띠가 사라지는 길마다 소리도 멈춤: 확인(:17383·:17386), 제품 스캔(:16185-16186), 현품표 활성(:13187 → :17506·:17508), 완료 snapshot(:17439-17443·:5055-5059). 소리만 남는 길 0.
2. **ACCEPT** — 다음 제품 스캔 clear(:16184-16186)와 입장 판정(:15018-15125) 바뀜 0. tray_completion.py 바뀜 0. 수량·완료 판정 손 0.
3. **ACCEPT** — 입력칸 Esc(:15196-15203) = 띠 ∧ ¬_operator_review_blocks_mutation.
   - 빈 Enter(:15424-15431)와 같음. 웹 확인은 _enter("") 라 Enter 와 같음.
   - 막는 알림 쪽은 _notice_blocks_scan 이 이미 같은 조건을 품으므로 바뀜 0.
   - 이제 None 이 흘러가는 root <Escape>(:16745)는 부분 제출 확인 때만 동작함.
4. **ACCEPT** — _use_real_notice_methods 가 인스턴스 stub(tests/test_warning_presenter_headless_integration.py:195·203·205-206)을 지워 실제 show_status_message·render·beep 을 씀. 가짜는 소리·위젯뿐.
   - 빈칸: Tk 단추 길, 띠 아래 거절 문구가 보이는지는 시험이 없음.
   - 옛 P3-2: band 단언 한 줄(:164)만 더해짐.
5. **ACCEPT** — 핀 전파뿐.
   - 다섯 파일 sha256 이 전환 JSON "after" 와 일치.
   - inventory_sha256 을 도구 규칙(정렬 JSON, 자기 칸 뺌)으로 따로 계산해 04f0b9cf… 일치. 다섯 곳 전파, 옛 핀 잔존 0.
   - _prepare_gui_startup 23992→24011(+19 = 순증 줄 수).
