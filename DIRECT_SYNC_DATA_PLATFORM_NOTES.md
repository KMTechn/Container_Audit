# Direct Sync Data Platform Notes

작성 기준: 2026-06-30

이 파일은 이적/트레이 검사 프로그램이 서버 취합/direct-sync 장기 구조와 맞물릴 때 유지해야 할 사항이다.

## 이 프로그램의 역할

- `Container_Audit`는 이적 검사 scan, 트레이 완료, 부분 제출, 보류/복구, 제품 교환 이벤트를 만든다.
- 이벤트는 로컬 event log와 direct-sync queue/spool에 먼저 남고, relay가 서버로 업로드한다.
- 이 프로그램의 로컬 이벤트는 서버 projection 오류나 네트워크 장애 시 재생 가능한 원천 기록이다.

## 꼭 유지할 사항

- Spool 파일과 상태 row는 서버 receipt 확정 전까지 재시도 가능한 상태를 유지한다.
- Relay id 기반 deterministic retry jitter를 유지한다.
- 서버 `Retry-After`가 유효하면 producer가 보존해야 한다. `0`도 유효한 즉시 재시도 값이다.
- 서버가 이미 commit한 non-2xx는 무한 retry로 되돌리지 말고 operator review 계열로 분리한다.
- Tray/product exchange payload는 서버 barcode trace projection이 index와 fallback 양쪽에서 읽을 수 있도록 기존 barcode 배열과 provenance를 깨지 않는다.
- 보류 트레이/현재 트레이 복구 파일은 운영 내구성의 일부다. 장기 용량 절감을 이유로 자동 삭제하면 안 된다.

## 미룬 작업

- terminal acked spool/status retention은 receipt 재시도 안전성 검증 전까지 자동 cleanup 대상으로 보지 않는다.

## 현재 리포트/가드레일

- `direct_sync_push.py`의 `relay_queue_status()`는 `acked_retention`을 출력한다. ACKED spool/status 용량과 누락 상태를 보여주는 read-only 리포트이며 cleanup 승인이 아니다.
- `acked_relay_retention_candidates()`는 full receipt validation, status artifact 일치, spool hash/byte 검증을 통과한 보존 검토 후보만 반환한다. 반환 결과도 삭제 권한이 아니다.

## 관련 검증

```powershell
cd C:\company\program\Container_Audit
python -m pytest -q -p no:cacheprovider tests\test_direct_sync_push.py
```
