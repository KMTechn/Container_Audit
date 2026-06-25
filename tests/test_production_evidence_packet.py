import json

import pytest

from tools import build_production_evidence_packet


def test_build_production_evidence_packet_creates_required_scaffold(tmp_path):
    output = tmp_path / "evidence-packet"

    result = build_production_evidence_packet.build_evidence_packet(output)

    assert result == output
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "container-audit-production-evidence-packet-v1"
    assert manifest["current_decision"] == "BLOCKED_UNTIL_APPROVAL_AND_EVIDENCE"
    assert manifest["endpoint"] == "https://worker.kmtecherp.com/api/producer-ingest/v1/source-file"
    assert manifest["syncthing_retirement_gate"]["promotion_allowed"] is False
    assert manifest["syncthing_retirement_gate"]["production_removal_ready"] is False

    for directory in build_production_evidence_packet.PACKET_DIRECTORIES:
        assert (output / directory).is_dir()
        guidance = (output / directory / "EXPECTED_EVIDENCE.md").read_text(encoding="utf-8")
        assert "Do not store raw secrets" in guidance

    assert "directory_guidance" in manifest
    assert "approval_packet_placeholders" in manifest
    assert "docs/PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md" in manifest["source_docs"]
    assert "00_freeze_manifest" in manifest["directory_guidance"]
    assert "release config checker output" in manifest["directory_guidance"]["00_freeze_manifest"]
    assert "source_claim history" in manifest["directory_guidance"]["07_syncthing_shadow_no_double_count"]
    assert (
        manifest["approval_packet_placeholders"]["11_final_signoff"][0]["source_doc"]
        == "docs/PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md"
    )


def test_build_production_evidence_packet_binds_three_agent_ownership(tmp_path):
    output = tmp_path / "evidence-packet"

    build_production_evidence_packet.build_evidence_packet(output)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert "agent_a_server_db_ingest" in manifest["agents"]
    assert "agent_b_producer_field_security" in manifest["agents"]
    assert "agent_c_downstream_shadow_rollback" in manifest["agents"]
    assert "producer_ingest_receipts" in manifest["required_direct_sync_objects"]
    assert "source_claim_history" in manifest["required_direct_sync_objects"]
    assert "defect_hmac_chain_review_audit" in manifest["required_direct_sync_objects"]
    assert "soak/security PASS" in manifest["syncthing_retirement_gate"]["required_results"]
    assert "backup/retention PASS" in manifest["syncthing_retirement_gate"]["required_results"]
    assert "release package PASS" in manifest["syncthing_retirement_gate"]["required_results"]
    assert "dashboard browser XSS PASS" in manifest["syncthing_retirement_gate"]["required_results"]


def test_build_production_evidence_packet_references_existing_authority_docs(tmp_path):
    output = tmp_path / "evidence-packet"

    build_production_evidence_packet.build_evidence_packet(output)

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    for doc in build_production_evidence_packet.SOURCE_DOCS:
        assert doc in manifest["source_docs"]
        assert build_production_evidence_packet.ROOT.joinpath(doc).is_file()


def test_build_production_evidence_packet_fails_closed_for_nonempty_output(tmp_path):
    output = tmp_path / "evidence-packet"
    output.mkdir()
    (output / "existing.txt").write_text("operator evidence", encoding="utf-8")

    with pytest.raises(ValueError, match="not empty"):
        build_production_evidence_packet.build_evidence_packet(output)


def test_build_production_evidence_packet_readme_warns_against_secret_evidence(tmp_path):
    output = tmp_path / "evidence-packet"

    build_production_evidence_packet.build_evidence_packet(output)

    readme = (output / "README.md").read_text(encoding="utf-8")
    assert "does not authorize production writes" in readme
    assert "Do not store raw HMAC secrets" in readme
    assert "promotion_allowed=true" in readme
    assert "production_removal_ready=true" in readme


def test_build_production_evidence_packet_creates_phase_approval_placeholders(tmp_path):
    output = tmp_path / "evidence-packet"

    build_production_evidence_packet.build_evidence_packet(output)

    expected = {
        "00_freeze_manifest": [
            "PHASE0_PREFLIGHT_COMMAND_PACKET.md",
            "PHASE0_OWNER_APPROVAL_CHECKLIST.md",
            "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE.md",
        ],
        "03_one_pc_canary": ["PHASE3_ONE_PC_CANARY_APPROVAL_PACKET.md"],
        "04_field_ui_scanner": ["FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md"],
        "10_soak_and_security": ["PHASE9_SOAK_SECURITY_APPROVAL_PACKET.md"],
        "11_final_signoff": ["PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET.md"],
    }

    for directory, filenames in expected.items():
        for filename in filenames:
            placeholder = (output / directory / filename).read_text(encoding="utf-8")
            assert "Source document:" in placeholder
            assert "does not authorize producer POST upload" in placeholder
            assert "Syncthing removal" in placeholder


def test_build_production_evidence_packet_phase0_placeholders_include_input_checker(tmp_path):
    output = tmp_path / "evidence-packet"

    build_production_evidence_packet.build_evidence_packet(output)

    preflight = (output / "00_freeze_manifest" / "PHASE0_PREFLIGHT_COMMAND_PACKET.md").read_text(
        encoding="utf-8"
    )
    transcript = (
        output / "00_freeze_manifest" / "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE.md"
    ).read_text(encoding="utf-8")

    assert "phase0_execution_inputs.json" in preflight
    assert "tools/check_phase0_execution_inputs.py" in preflight
    assert "tools/check_phase0_execution_inputs.py" in transcript
