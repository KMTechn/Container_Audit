REJECT · P1 1 · P2 1 · P3 4

# 독립 검토 — 제거 실패 되돌림 (calm-uninst-ca)

대상 a46210fd..60399913(한 커밋). 읽기만, 시험·빌드 실행 0. 줄임: itp=INSTALL_THIS_PC.ps1 · can=INSTALL_CANONICAL_PORTABLE.ps1.

## P1
1. 공개 제거 보상이 옛 relay 작업을 무조건 켠다. can catch 제거 분기가 journal 복원 뒤 `Restore-CanonicalRemovalScheduledTasks`(can:7419)를 새로 부르고, 이 함수는 evidence에 `direct-sync-relay-container-audit.json`이 있으면 `$task.Enabled=$true`(can:4488). 설치가 옛 relay를 꺼 둔 PC(Disable-CanonicalOfficialLegacyRelay)에서 작업 단계 뒤 실패하면, 자식이 enabled=false로 정확히 되돌린 것(itp:2605)을 부모가 다시 켠다 → 제거 전에 없던 상태, 되살린 Run과 함께 writer 둘. 기록(itp:2321)은 신원 확인(itp:2325)보다 먼저라 REMOVAL_TASK_IDENTITY_UNKNOWN(남의 작업) 거절도 그 작업을 켠다. 항목 1·3 위반, operations「relay 다시 시작 안 함」과도 어긋남.

## P2
2. 자식의 손상 판정이 공개 결과에 오르지 않는다. 공개 제거는 자식에 MachineControlRoot를 넘기지 않아(can:6683) 자식 로컬 되돌림과 부모 journal 보상이 겹친다. 자식만 실패하면(작업 충돌·readback, ACL, 폴더 메타) 자식 rollback.json은 ROLLBACK_FAILED인데 부모는 runtime_restored=true(can:7467)이고 안내는「같은 제거를 다시 실행」이다. 부모도 실패하면 같은 rollback.json을 Save로 덮어 자식 failure_types가 사라지고(can:7484), journal 복원이 throw하면 새 GUID 폴더에 써서(can:7480) removal-evidence/<attempt> 규약과 다르다.

## P3
3. 되돌림이 저장한 모든 폴더의 시각·속성을 바뀌었는지와 무관하게 다시 쓴다(itp:2612). Common 바로가기 부모(공용 바탕화면·시작 메뉴)도 포함되고, 아무것도 옮기지 않은 실패에서도 쓴다.
4. 재개는 같은 transaction id를 쓰는데(can:6051) journal 결속이 run_id뿐이다(can:4363). 재개 실패 때 앞 시도 evidence에서 파일을 되옮기고(Run은 재개 시점 snapshot=부재), journal이 둘이면 AMBIGUOUS가 거짓 손상이 된다.
5. 성공한 제거도 evidence/.restore-preimage에 code·control 전체 사본을 남긴다(용량 두 배, 정리 없음).
6. `official` 분기(itp:2593)는 닿지 않고, 정의되지 않은 Invoke-LabelOfficialLegacyTaskTransition을 부른다(Label 복사 잔재).

## 확인됨(항목별)
- 1: 자식 preimage는 이미 있던 계획 파일과 검증된 바로가기만 담는다. 없던 파일은 만들지 않고, 바이트가 다르면 덮지 않고 CONFLICT→손상. 표식은 evidence_root가 같을 때만 지운다. 부모 바로가기 복원도 같은 규칙(P1·P3 예외).
- 2: 자료 루트는 계획·journal·preimage 어디에도 없다. 안내 문구는 SafeMessages에 있고 Data 플래그로 공개 기록에 실린다. 반환은 0이 아님.
- 3: 신원 거절(변조·다른 manifest·미등록 코드)은 보상이 no-op(journal 없음·preimage 빈 배열·Run 같음)이라 불변(P1 예외). 자기 Run 문자열만 다르면 성공 시험이 유지된다.
- 4: Run은 kind/data가 다를 때만 Restore하고 다시 읽어 비교한다(can:7456).
- 5: inventory self-sha·fence.ps1·contract·writer_session_fence.py·transition 핀이 일치하고, transition after 해시=head 바이트. uncovered 0·guard 실패 0, 새 사이트는 모두 guarded.
