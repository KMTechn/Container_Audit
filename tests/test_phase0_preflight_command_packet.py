from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "docs" / "PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "00_freeze_manifest"
    / "PHASE0_PREFLIGHT_COMMAND_PACKET.md"
)


def _packet_text() -> str:
    return PACKET.read_text(encoding="utf-8")


def _bash_block() -> str:
    text = _packet_text()
    match = re.search(r"```bash\n(?P<body>.*?)\n```", text, flags=re.S)
    assert match is not None
    return match.group("body")


def test_phase0_preflight_packet_preserves_readonly_safety_boundary():
    text = _packet_text()

    required = [
        "This packet is read-only against production application state.",
        "does not send producer data",
        "does not run authenticated upload",
        "does not run schema `--execute`, service stop/start, scheduled task changes, credential issue/rotation, or Syncthing changes",
        "It may only write evidence files under the approved evidence archive directory.",
        "Raw HMAC secrets, producer credentials, raw receipt JSON, and full raw payloads must not be placed",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_preflight_command_packet_collects_required_readonly_artifacts():
    block = _bash_block()

    required = [
        "APP=/root/WorkerAnalysisGUI-web",
        "DB=/mnt/rebuild/worker-analysis/data/worker_analysis.db",
        "scripts/direct_sync_ops_status.py --db \"$DB\"",
        "https://worker.kmtecherp.com/health",
        "https://worker.kmtecherp.com/health/ingest",
        "-X OPTIONS https://worker.kmtecherp.com/api/producer-ingest/v1/source-file",
        "sha256sum \"$DB\"",
        "sqlite3.connect(f\"file:{db}?mode=ro\", uri=True)",
        "PRAGMA query_only=ON",
        "backup_space_ok",
        "phase0_artifact_hashes.sha256",
        "redaction_check.before.json",
    ]

    assert [item for item in required if item not in block] == []


def test_phase0_preflight_command_packet_has_no_mutating_operations_in_bash_block():
    block = _bash_block()

    forbidden = [
        "-X POST",
        "--execute",
        "systemctl",
        "service ",
        "schtasks",
        "syncthing",
        "plan_c_apply_additive_schema.py",
        "producer_secret",
        "hmac_secret",
    ]

    assert [item for item in forbidden if item.lower() in block.lower()] == []


def test_phase0_preflight_packet_defines_pass_criteria_and_stop_conditions():
    text = _packet_text()

    required = [
        "PASS Criteria",
        "`producer_ingest_options.before.txt` shows `OPTIONS 200` and `Allow: OPTIONS, POST`",
        "`health_ingest.before.json` is captured even if the status is `503`",
        "`direct_sync_ops_status.before.json` records current direct-sync readiness and blockers",
        "`db.sha256.before.txt` records the DB SHA-256 before any schema work",
        "Stop Conditions",
        "`backup_space_ok` is false",
        "Any command would require producer credential material",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_preflight_evidence_packet_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md`",
        "`direct_sync_ops_status.before.json`",
        "`producer_ingest_options.before.txt`",
        "`phase0_artifact_hashes.sha256`",
        "Do not place raw HMAC secrets",
    ]

    assert [item for item in required if item not in text] == []
