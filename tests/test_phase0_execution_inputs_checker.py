import json

import pytest

from tools import check_phase0_execution_inputs


def _write_inputs(tmp_path, **overrides):
    evidence_root = tmp_path / "evidence-root"
    payload = {
        "change_id": "CHG-20260625-001",
        "run_id": "phase0-readonly-20260625T010203Z",
        "server_host": "worker.kmtecherp.com",
        "app_path": "/root/WorkerAnalysisGUI-web",
        "db_path": "/mnt/rebuild/worker-analysis/data/worker_analysis.db",
        "fqdn": "https://worker.kmtecherp.com",
        "producer_route_method": "OPTIONS",
        "producer_route_path": "/api/producer-ingest/v1/source-file",
        "evidence_root": str(evidence_root),
        "evidence_subdir": "00_freeze_manifest/phase0-preflight",
        "operator": "field operator",
        "reviewer": "change reviewer",
        "redaction_policy_accepted": True,
        "owners": {
            "db": True,
            "app": True,
            "field": True,
            "security": True,
            "downstream": True,
            "rollback": True,
            "change_coordinator": True,
        },
    }
    payload.update(overrides)
    path = tmp_path / "phase0_execution_inputs.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path, evidence_root


def test_phase0_execution_inputs_checker_accepts_valid_empty_preflight_inputs(tmp_path):
    path, evidence_root = _write_inputs(tmp_path)
    (evidence_root / "00_freeze_manifest" / "phase0-preflight").mkdir(parents=True)

    check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


def test_phase0_execution_inputs_checker_rejects_missing_owner_signoff(tmp_path):
    path, _ = _write_inputs(
        tmp_path,
        owners={
            "db": True,
            "app": True,
            "field": True,
            "security": True,
            "downstream": True,
            "rollback": False,
            "change_coordinator": True,
        },
    )

    with pytest.raises(ValueError, match="owners not signed: rollback"):
        check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


def test_phase0_execution_inputs_checker_rejects_post_route_or_wrong_path(tmp_path):
    path, _ = _write_inputs(tmp_path, producer_route_method="POST")

    with pytest.raises(ValueError, match="producer_route_method"):
        check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


def test_phase0_execution_inputs_checker_rejects_nonempty_evidence_subdir(tmp_path):
    path, evidence_root = _write_inputs(tmp_path)
    evidence_dir = evidence_root / "00_freeze_manifest" / "phase0-preflight"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "old-output.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


def test_phase0_execution_inputs_checker_rejects_secret_material(tmp_path):
    path, _ = _write_inputs(tmp_path, producer_secret="do-not-store")

    with pytest.raises(ValueError, match="forbidden"):
        check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"headers": {"X-Producer-Signature": "PRODUCER-HMAC-SHA256-V1 SHOULD-NOT-LEAK"}},
        {"signature": "SHOULD-NOT-LEAK"},
        {"authorization": "Bearer SHOULD-NOT-LEAK"},
        {"note": "hmac=SHOULD-NOT-LEAK"},
        {"note": "api_key=SHOULD-NOT-LEAK"},
        {"note": "password=SHOULD-NOT-LEAK"},
    ],
)
def test_phase0_execution_inputs_checker_rejects_signature_and_auth_material(tmp_path, overrides):
    path, _ = _write_inputs(tmp_path, **overrides)

    with pytest.raises(ValueError, match="forbidden"):
        check_phase0_execution_inputs.validate_phase0_execution_inputs(path)


def test_phase0_execution_inputs_checker_cli_passes_valid_inputs(tmp_path, capsys):
    path, _ = _write_inputs(tmp_path)

    result = check_phase0_execution_inputs.main(["--inputs-json", str(path)])

    assert result == 0
    assert "phase0_execution_inputs_check=PASS" in capsys.readouterr().out
