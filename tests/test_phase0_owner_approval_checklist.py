from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs" / "PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md"
EVIDENCE_PLACEHOLDER = (
    ROOT
    / ".agents"
    / "agent-loop"
    / "runs"
    / "container-audit-e2e-20260624"
    / "evidence"
    / "production-cutover-packet-v5-20260625"
    / "00_freeze_manifest"
    / "PHASE0_OWNER_APPROVAL_CHECKLIST.md"
)


def _checklist_text() -> str:
    return CHECKLIST.read_text(encoding="utf-8")


def test_phase0_owner_checklist_requires_all_relevant_owners():
    text = _checklist_text()

    required = [
        "DB owner",
        "App owner",
        "Field operator",
        "Security/credential owner",
        "Downstream owner",
        "Rollback owner",
        "Change coordinator",
        "All owner signoff entries must be stored as redacted text",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_owner_checklist_binds_approved_inputs_and_readonly_actions():
    text = _checklist_text()

    required = [
        "`APP` must be `/root/WorkerAnalysisGUI-web`",
        "`DB` must be `/mnt/rebuild/worker-analysis/data/worker_analysis.db`",
        "Approved FQDN must be `https://worker.kmtecherp.com`",
        "Producer route check is `OPTIONS` only",
        "EVIDENCE_DIR` must be a fresh approved archive path",
        "scripts/direct_sync_ops_status.py --db \"$DB\"",
        "`GET /health` capture",
        "`GET /health/ingest` capture",
        "`OPTIONS /api/producer-ingest/v1/source-file` capture",
        "SQLite read-only row counts using `mode=ro` and `PRAGMA query_only=ON`",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_owner_checklist_does_not_authorize_mutating_operations():
    text = _checklist_text()

    required_forbidden_scope = [
        "`POST /api/producer-ingest/v1/source-file` or any producer data upload",
        "Authenticated HMAC canary",
        "plan_c_apply_additive_schema.py",
        "schema `--execute`",
        "DB write/update/delete",
        "`COMMON_INGEST_WRITE_ENABLED` change",
        "Credential issue, key rotation, key revocation",
        "direct_sync_relay_install_pack.py --apply",
        "service start/stop",
        "scheduled task creation/change",
        "Syncthing configuration change",
        "`C:\\Sync` mutation",
        "Syncthing removal",
    ]
    unconditional_allow_claims = [
        "authorizes producer POST",
        "authorizes schema `--execute`",
        "authorizes Syncthing removal",
        "promotion_allowed=true",
        "production_removal_ready=true",
    ]

    assert [item for item in required_forbidden_scope if item not in text] == []
    assert [claim for claim in unconditional_allow_claims if claim in text] == []


def test_phase0_owner_checklist_defines_stop_conditions_and_later_phase_gate():
    text = _checklist_text()

    required = [
        "Pre-Run Stop Conditions",
        "Any required owner signoff is missing.",
        "`APP`, `DB`, FQDN, route, or evidence directory differs from the approved values.",
        "The evidence directory already contains previous run artifacts.",
        "raw HMAC secret, producer secret, bearer token, or private credential material",
        "Known missing direct-sync tables may be captured by Phase 0 as blocker evidence.",
        "They do not authorize Phase 1 schema work or producer upload.",
        "phase0_readonly_pass",
        "phase0_blocked_before_mutation",
        "Neither outcome approves Phase 1 schema apply, staging/production canary POST, 20-PC run, shadow run, rollback rehearsal, or Syncthing retirement.",
    ]

    assert [item for item in required if item not in text] == []


def test_phase0_owner_checklist_evidence_placeholder_is_present():
    text = EVIDENCE_PLACEHOLDER.read_text(encoding="utf-8")

    required = [
        "Source document: `docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md`",
        "DB owner signoff",
        "Security/credential owner signoff",
        "Change coordinator signoff",
        "Do not place raw HMAC secrets",
        "does not authorize producer POST",
        "Syncthing removal",
    ]

    assert [item for item in required if item not in text] == []
