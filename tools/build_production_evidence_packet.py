#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Create a redaction-safe production cutover evidence packet scaffold."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SOURCE_DOCS = [
    "docs/THREE_AGENT_PRODUCTION_CUTOVER_PLAN_20260625.md",
    "docs/OPERATIONAL_CHANGE_WINDOW_RUNBOOK_20260625.md",
    "docs/PRE_PRODUCTION_VALIDATION_MATRIX_20260625.md",
    "docs/LOCAL_AUDIT_READINESS_REPORT_20260624.md",
    "docs/OPERATIONAL_DB_READONLY_AUDIT_20260625.md",
    "docs/COMPANY_SERVER_READONLY_PRECHECK_20260625.md",
    "docs/PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md",
    "docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
    "docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
    "docs/PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md",
    "docs/PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md",
    "docs/PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md",
    "docs/PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md",
    "docs/FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md",
    "docs/PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md",
    "docs/PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md",
    "docs/PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md",
    "docs/PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md",
    "docs/PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md",
    "docs/PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md",
    "docs/PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md",
]

PACKET_DIRECTORIES = [
    "00_freeze_manifest",
    "01_schema_backup_and_apply",
    "02_post_schema_readiness",
    "03_one_pc_canary",
    "04_field_ui_scanner",
    "05_twenty_pc_concurrency",
    "06_downstream_today_past_export",
    "07_syncthing_shadow_no_double_count",
    "08_rollback_rehearsal",
    "09_operator_visibility",
    "10_soak_and_security",
    "11_final_signoff",
]

DIRECTORY_GUIDANCE = {
    "00_freeze_manifest": [
        "production freeze manifest",
        "FQDN OPTIONS response",
        "DB/WAL size and disk free-space proof",
        "release config checker output",
    ],
    "01_schema_backup_and_apply": [
        "expected_db_sha256",
        "backup DB path and SHA-256",
        "apply_additive_schema_report.json",
        "legacy row counts before and after",
    ],
    "02_post_schema_readiness": [
        "direct_sync_ops_status.after.json",
        "health_ingest.after.json",
        "missing_tables and missing_columns empty proof",
    ],
    "03_one_pc_canary": [
        "redacted request id, key id, nonce fingerprint, and idempotency key fingerprint",
        "receipt hash",
        "raw artifact reference and hash",
        "source_claim and projection reconciliation counts",
    ],
    "04_field_ui_scanner": [
        "operator checklist",
        "scanner UI screenshots or video references",
        "CSV/event hashes for login, scans, undo, reset, park/restore, replacement, exchange, close/recover",
    ],
    "05_twenty_pc_concurrency": [
        "20 PC identity table with secrets redacted",
        "per-PC CSV hash and row count",
        "replay, network interruption, queue restart, and resume evidence",
    ],
    "06_downstream_today_past_export": [
        "today/past/trace/summary screenshots",
        "export checksum and row count",
        "dashboard/API totals compared with receipt totals",
    ],
    "07_syncthing_shadow_no_double_count": [
        "direct HTTPS receipt evidence",
        "Syncthing/archive ingest evidence",
        "source_claim history",
        "projection parity report",
    ],
    "08_rollback_rehearsal": [
        "relay pause evidence",
        "scheduled task or service stop rehearsal",
        "legacy path verification",
        "queued upload resume without duplicate projection",
    ],
    "09_operator_visibility": [
        "status/report output",
        "last failure",
        "next retry",
        "operator review row and rollback state",
    ],
    "10_soak_and_security": [
        "4-8 hour or full-day-volume soak metrics",
        "malicious input UI/CSV/HTTPS/DB/dashboard/export evidence",
        "fault injection evidence for timeout, 500/503, DNS/TLS, DB lock, disk pressure, spool/status corruption",
    ],
    "11_final_signoff": [
        "owner signoff record",
        "promotion_allowed=true only after all gates pass",
        "production_removal_ready=true only after Syncthing retirement gate passes",
        "evidence archive hash",
    ],
}

APPROVAL_PACKET_PLACEHOLDERS = {
    "00_freeze_manifest": [
        (
            "PHASE0_PREFLIGHT_COMMAND_PACKET.md",
            "docs/PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        ),
        (
            "PHASE0_OWNER_APPROVAL_CHECKLIST.md",
            "docs/PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        ),
        (
            "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE.md",
            "docs/PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md",
        ),
    ],
    "01_schema_backup_and_apply": [
        (
            "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET.md",
            "docs/PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "02_post_schema_readiness": [
        (
            "PHASE2_POST_SCHEMA_READINESS_PACKET.md",
            "docs/PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md",
        ),
    ],
    "03_one_pc_canary": [
        (
            "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET.md",
            "docs/PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "04_field_ui_scanner": [
        (
            "FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md",
            "docs/FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md",
        ),
    ],
    "05_twenty_pc_concurrency": [
        (
            "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET.md",
            "docs/PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "06_downstream_today_past_export": [
        (
            "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET.md",
            "docs/PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "07_syncthing_shadow_no_double_count": [
        (
            "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET.md",
            "docs/PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "08_rollback_rehearsal": [
        (
            "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET.md",
            "docs/PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "09_operator_visibility": [
        (
            "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET.md",
            "docs/PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "10_soak_and_security": [
        (
            "PHASE9_SOAK_SECURITY_APPROVAL_PACKET.md",
            "docs/PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md",
        ),
    ],
    "11_final_signoff": [
        (
            "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET.md",
            "docs/PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md",
        ),
    ],
}

APPROVAL_PLACEHOLDER_EXTRA_EVIDENCE = {
    "PHASE0_PREFLIGHT_COMMAND_PACKET.md": [
        "`phase0_execution_inputs.json`",
        "`tools/check_phase0_execution_inputs.py` PASS output",
        "`direct_sync_ops_status.before.json`",
        "`producer_ingest_options.before.txt`",
        "`phase0_artifact_hashes.sha256`",
    ],
    "PHASE0_OWNER_APPROVAL_CHECKLIST.md": [
        "`phase0_execution_inputs.json`",
        "DB owner signoff",
        "Security/credential owner signoff",
        "Change coordinator signoff",
    ],
    "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE.md": [
        "run metadata with change id",
        "`tools/check_phase0_execution_inputs.py` PASS output",
        "owner checklist reference and command packet reference",
        "command result transcript rows",
        "`direct_sync_ops_status.before.json`",
        "`phase0_artifact_hashes.sha256`",
        "`phase0_readonly_pass` or `phase0_blocked_before_mutation`",
    ],
    "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET.md": [
        "DB owner signoff",
        "App owner signoff",
        "Rollback owner signoff",
        "Security owner signoff",
        "reference to filled Phase 0 transcript",
        "`apply_additive_schema_report.json`",
    ],
    "PHASE2_POST_SCHEMA_READINESS_PACKET.md": [
        "`direct_sync_ops_status.after.json`",
        "`health_ingest.after.json`",
        "`post_schema_readonly_counts.after.json`",
        "`post_schema_readiness_hashes.sha256`",
        "`schema_ready=true`, `missing_tables=[]`, and `missing_columns={}`",
        "counts are zero before any canary",
    ],
    "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET.md": [
        "credential owner signoff",
        "one `producer_install_id`, one `source_host_id`",
        "field operator signoff",
        "DB owner signoff for Phase 2 PASS",
        "redacted request metadata",
        "receipt summary",
        "nonce/idempotency evidence",
        "does not authorize 20-PC testing",
    ],
    "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET.md": [
        "at least 20 distinct `source_host_id`, `producer_install_id`, and `key_id` rows",
        "same Korean filename",
        "same worker name",
        "duplicate resend",
        "network interruption",
        "queue restart",
        "redacted server receipt summaries",
        "DB reconciliation for receipt, nonce, raw artifact, source_claim, common_ingested_events, projection, summary, and quarantine deltas",
        "Syncthing/archive shadow observation proving no double count",
        "does not authorize producer POST upload outside the approved 20-PC window",
    ],
    "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET.md": [
        "WorkerAnalysisGUI-web URL or actual receiving program",
        "today view",
        "past lookup",
        "trace",
        "summary",
        "export workflow",
        "DB identity hash",
        "source roster with PC identities",
        "trace evidence linking downstream row to receipt, source_claim, source PC identity, raw artifact hash, and source CSV hash",
        "export evidence with file name, SHA-256, row count",
        "Syncthing/archive observation proving no downstream double count",
    ],
    "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET.md": [
        "legacy archive path observation",
        "no config mutation",
        "direct-vs-archive conflict policy",
        "`source_claim`, `source_claim_history`",
        "direct HTTPS receipt evidence",
        "Syncthing/archive observation",
        "authoritative path",
        "duplicate classification",
        "downstream today/past/trace/summary/export evidence showing unchanged single-count totals",
        "rollback availability note",
        "does not authorize producer POST upload outside the approved staging/test window",
    ],
    "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET.md": [
        "rollback owner signoff",
        "relay pause/resume",
        "task/service roster",
        "legacy path verification",
        "relay pause evidence",
        "scheduled task/service stop evidence",
        "HTTPS failure/fallback evidence",
        "CSV/archive preservation evidence",
        "queued upload resume evidence",
        "DB reconciliation for receipt, raw artifact, source_claim, common event, projection, summary, and quarantine counts",
        "downstream today/past/trace/summary/export totals",
    ],
    "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET.md": [
        "field/operator owner signoff",
        "status/report",
        "runtime status path",
        "queue DB path",
        "receipt summary path",
        "DB owner read-only reconciliation query bundle",
        "healthy state evidence",
        "retryable fault evidence",
        "credential fault evidence",
        "DNS/TLS/proxy fault evidence",
        "disk/spool/status corruption evidence",
        "operator-review evidence",
        "downstream trace evidence",
        "rollback visibility evidence",
    ],
    "PHASE9_SOAK_SECURITY_APPROVAL_PACKET.md": [
        "app owner command bundle",
        "security owner checklist",
        "field/operator roster",
        "DB owner read-only reconciliation query bundle",
        "downstream target",
        "rollback owner abort criteria",
        "credential lifecycle evidence",
        "clock drift evidence",
        "malicious input evidence",
        "fault injection evidence",
        "soak metrics",
        "dashboard browser XSS",
    ],
    "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET.md": [
        "final owner signoff record",
        "evidence archive hash",
        "Phase 0 read-only preflight PASS",
        "Phase 4 20-PC concurrency PASS",
        "Phase 6 Syncthing shadow PASS",
        "Phase 9 soak/security PASS",
        "backup/retention PASS",
        "release package PASS",
        "dashboard browser XSS PASS",
        "`promotion_allowed=true` owner signature only after all evidence is present",
        "`production_removal_ready=true` owner signature only after Syncthing retirement gate passes",
        "exact Syncthing retirement action",
    ],
}

README = """# Production Cutover Evidence Packet

This packet is a scaffold only. It does not authorize production writes.

Rules:

- Do not store raw HMAC secrets, producer credentials, bearer tokens, raw receipt JSON, or full raw payloads here.
- Store hashes, redacted identifiers, aggregate counts, screenshots with secrets hidden, and owner signoff records.
- Keep Syncthing enabled as shadow/rollback until the final signoff manifest says promotion_allowed=true and production_removal_ready=true.
- Stop if any hard stop condition in the three-agent plan or operational change-window runbook occurs.
"""


def _rel(path: str) -> Path:
    return ROOT / path


def _validate_source_docs() -> list[str]:
    missing = [doc for doc in SOURCE_DOCS if not _rel(doc).is_file()]
    if missing:
        raise ValueError("missing source docs: " + ", ".join(missing))
    return SOURCE_DOCS


def _write_approval_placeholder(
    directory_path: Path,
    filename: str,
    source_doc: str,
    guidance: list[str],
) -> None:
    lines = [
        f"# {filename.removesuffix('.md').replace('_', ' ').title()} Evidence Placeholder",
        "",
        f"Source document: `{source_doc}`",
        "",
        "Collect these only after owner approval:",
        "",
    ]
    lines.extend(
        f"- {item}" for item in APPROVAL_PLACEHOLDER_EXTRA_EVIDENCE.get(filename, [])
    )
    lines.extend(f"- {item}" for item in guidance)
    lines.extend(
        [
            "",
            "Do not place raw HMAC secrets, producer secrets, bearer tokens, raw receipt JSON, full raw payloads, full barcode dumps, private passwords, private contact details, or unredacted production customer data in this folder.",
            "",
            "This placeholder does not authorize producer POST upload, credential lifecycle changes, relay pause/resume, service stop/start, schema `--execute`, production DB mutation, Syncthing config changes, Syncthing folder removal, or Syncthing removal.",
            "",
        ]
    )
    (directory_path / filename).write_text("\n".join(lines), encoding="utf-8")


def build_evidence_packet(output_dir: str | Path) -> Path:
    output = Path(output_dir)
    source_docs = _validate_source_docs()

    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory already exists and is not empty")

    output.mkdir(parents=True, exist_ok=True)
    for directory in PACKET_DIRECTORIES:
        directory_path = output / directory
        directory_path.mkdir()
        guidance = DIRECTORY_GUIDANCE[directory]
        guidance_lines = ["# Expected Evidence", ""]
        guidance_lines.extend(f"- {item}" for item in guidance)
        guidance_lines.append("")
        guidance_lines.append("Do not store raw secrets, raw receipt JSON, or full raw payloads here.")
        guidance_lines.append("")
        (directory_path / "EXPECTED_EVIDENCE.md").write_text(
            "\n".join(guidance_lines),
            encoding="utf-8",
        )
        for filename, source_doc in APPROVAL_PACKET_PLACEHOLDERS[directory]:
            _write_approval_placeholder(directory_path, filename, source_doc, guidance)

    manifest = {
        "schema_version": "container-audit-production-evidence-packet-v1",
        "created_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "current_decision": "BLOCKED_UNTIL_APPROVAL_AND_EVIDENCE",
        "endpoint": "https://worker.kmtecherp.com/api/producer-ingest/v1/source-file",
        "source_docs": source_docs,
        "agents": {
            "agent_a_server_db_ingest": [
                "operational DB backup/hash gate",
                "additive schema readiness",
                "authenticated canary receipt reconciliation",
            ],
            "agent_b_producer_field_security": [
                "worker PC/scanner UI scenarios",
                "credential lifecycle",
                "20-PC concurrency, malicious input, fault, and soak evidence",
            ],
            "agent_c_downstream_shadow_rollback": [
                "today/past/trace/summary/export validation",
                "Syncthing shadow no-double-count proof",
                "rollback rehearsal and retirement signoff",
            ],
        },
        "required_direct_sync_objects": [
            "producer_ingest_receipts",
            "producer_ingest_nonces",
            "producer_ingest_raw_artifacts",
            "source_claim",
            "source_claim_history",
            "transfer_legacy_projection",
            "packaging_set_projection",
            "process_state_summary_sources",
            "defect_hmac_chain_state",
            "defect_hmac_chain_review_audit",
        ],
        "packet_directories": PACKET_DIRECTORIES,
        "directory_guidance": DIRECTORY_GUIDANCE,
        "approval_packet_placeholders": {
            directory: [
                {"filename": filename, "source_doc": source_doc}
                for filename, source_doc in placeholders
            ]
            for directory, placeholders in APPROVAL_PACKET_PLACEHOLDERS.items()
        },
        "hard_stop_summary": [
            "backup or expected_db_sha256 verification fails",
            "direct_sync_ops_status remains BLOCKED after schema step",
            "producer POST writes receipt without nonce/raw artifact/source_claim/summary reconciliation",
            "replay, retry, or Syncthing shadow creates duplicate projection",
            "raw secret, HMAC key, receipt JSON, or raw payload appears in evidence output",
            "operator cannot identify last failure, next retry, review row, and rollback state",
        ],
        "syncthing_retirement_gate": {
            "promotion_allowed": False,
            "production_removal_ready": False,
            "required_results": [
                "one-PC canary PASS",
                "20-PC ingest PASS",
                "source_claim unresolved conflict count is 0",
                "downstream today/past/trace/summary/export totals PASS",
                "Syncthing shadow no-double-count PASS",
                "rollback rehearsal PASS",
                "operator visibility PASS",
                "soak/security PASS",
                "backup/retention PASS",
                "release package PASS",
                "dashboard browser XSS PASS",
                "owner signoff PASS",
            ],
        },
    }

    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "README.md").write_text(README, encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a Container_Audit production evidence packet scaffold"
    )
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    try:
        output = build_evidence_packet(args.output_dir)
    except ValueError as exc:
        print(f"production_evidence_packet=FAIL reason={exc}", file=sys.stderr)
        return 2

    print(f"production_evidence_packet=PASS output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
