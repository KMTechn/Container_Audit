# Phase 0 Preflight Command Packet

작성일: 2026-06-25
대상: `Container_Audit` HTTPS direct-sync 전환 전 운영 서버 read-only 기준선 수집

## Safety Boundary

- This packet is read-only against production application state.
- It does not send producer data and does not run authenticated upload.
- It does not run schema `--execute`, service stop/start, scheduled task changes, credential issue/rotation, or Syncthing changes.
- It may only write evidence files under the approved evidence archive directory.
- Raw HMAC secrets, producer credentials, raw receipt JSON, and full raw payloads must not be placed in the evidence archive.

## Evidence Destination

Use a fresh evidence directory for each approved staging or production run.

Current local scaffold:

```text
.agents/agent-loop/runs/container-audit-e2e-20260624/evidence/production-cutover-packet-v5-20260625/00_freeze_manifest/phase0-preflight
```

For a real server run, replace `EVIDENCE_DIR` with the approved server-side evidence path created for that change window.

## Read-Only Command Packet

Run only after DB owner, app owner, field operator, and rollback owner confirm Phase 0 may collect read-only evidence.

```bash
set -euo pipefail

APP=/root/WorkerAnalysisGUI-web
DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db
EVIDENCE_DIR=/mnt/rebuild/worker-analysis/evidence/container-audit-phase0-preflight-$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$EVIDENCE_DIR"
cd "$APP"

python3 scripts/direct_sync_ops_status.py --db "$DB" \
  > "$EVIDENCE_DIR/direct_sync_ops_status.before.json"

curl -fsS https://worker.kmtecherp.com/health \
  > "$EVIDENCE_DIR/health.before.json"

curl -sS https://worker.kmtecherp.com/health/ingest \
  > "$EVIDENCE_DIR/health_ingest.before.json" || true

curl -sS -i -X OPTIONS https://worker.kmtecherp.com/api/producer-ingest/v1/source-file \
  > "$EVIDENCE_DIR/producer_ingest_options.before.txt"

sha256sum "$DB" > "$EVIDENCE_DIR/db.sha256.before.txt"

python3 - <<'PY' > "$EVIDENCE_DIR/db_readonly_counts.before.json"
from pathlib import Path
import json
import shutil
import sqlite3

db = Path("/mnt/rebuild/worker-analysis/data/worker_analysis.db")
root = Path("/mnt/rebuild/worker-analysis")
tables = [
    "sessions",
    "raw_events",
    "common_ingested_events",
    "common_event_quarantine",
    "producer_ingest_receipts",
    "producer_ingest_nonces",
    "producer_ingest_raw_artifacts",
    "source_claim",
    "source_claim_history",
    "transfer_legacy_projection",
    "packaging_set_projection",
    "process_state_summary_sources",
]

out = {
    "db_path": str(db),
    "db_size_bytes": db.stat().st_size,
    "wal_size_bytes": Path(str(db) + "-wal").stat().st_size if Path(str(db) + "-wal").exists() else 0,
    "free_bytes": shutil.disk_usage(root).free,
    "backup_space_ok": shutil.disk_usage(root).free > db.stat().st_size * 2,
    "table_counts": {},
    "missing_tables": [],
}

conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
try:
    conn.execute("PRAGMA query_only=ON")
    existing = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    for table in tables:
        if table not in existing:
            out["missing_tables"].append(table)
            continue
        out["table_counts"][table] = conn.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        ).fetchone()[0]
finally:
    conn.close()

print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
PY

python3 - <<'PY' > "$EVIDENCE_DIR/redaction_check.before.json"
from pathlib import Path
import json
import re

root = Path("/mnt/rebuild/worker-analysis/evidence")
pattern = re.compile(r"(hmac|secret|token|api[_-]?key|credential|bearer)", re.I)
hits = []
for path in root.rglob("*"):
    if not path.is_file():
        continue
    name = str(path)
    if pattern.search(name):
        hits.append(name)

print(json.dumps({
    "status": "PASS" if not hits else "REVIEW",
    "path_marker_hits": hits[:20],
    "note": "This scans artifact paths only; do not store raw secret material in evidence files.",
}, ensure_ascii=False, indent=2, sort_keys=True))
PY

find "$EVIDENCE_DIR" -maxdepth 1 -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$EVIDENCE_DIR/phase0_artifact_hashes.sha256"

printf 'phase0_preflight=COMPLETE evidence_dir=%s\n' "$EVIDENCE_DIR"
```

## PASS Criteria

- `producer_ingest_options.before.txt` shows `OPTIONS 200` and `Allow: OPTIONS, POST`.
- `health.before.json` is reachable.
- `health_ingest.before.json` is captured even if the status is `503`.
- `direct_sync_ops_status.before.json` records current direct-sync readiness and blockers.
- `db_readonly_counts.before.json` records DB size, WAL size, free space, row counts, and missing direct-sync tables.
- `db.sha256.before.txt` records the DB SHA-256 before any schema work.
- `phase0_artifact_hashes.sha256` hashes all Phase 0 artifacts.
- No producer upload, schema mutation, service change, credential operation, or Syncthing change is executed.

## Stop Conditions

- `DB` path does not match `/mnt/rebuild/worker-analysis/data/worker_analysis.db`.
- `backup_space_ok` is false.
- `direct_sync_ops_status.before.json` cannot be captured.
- FQDN `OPTIONS` fails or does not expose `POST`.
- Any command would require producer credential material.
- Any evidence file contains raw HMAC secret, bearer token, producer secret, raw receipt JSON, or full raw payload.
