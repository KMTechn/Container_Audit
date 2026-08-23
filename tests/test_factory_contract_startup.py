import json
from pathlib import Path

import pytest

import Container_Audit as app
from kmtech_factory_contracts import CONTRACT_BUNDLE_SHA256, FactoryContractError
from kmtech_factory_contracts.build_cli import prepare_identity
from kmtech_factory_contracts.installer import offline_preflight
from kmtech_factory_contracts.package import create_build_manifest, write_json


ROOT = Path(__file__).resolve().parents[1]
CMD_TASK_ACTION = (
    "C:/Windows/System32/cmd.exe /d /q /c "
    "C:/ProgramData/KMTech/DirectSync/container_audit/bin/"
    "direct-sync-relay-container-audit.cmd"
)
FALSE_VBS_TASK_ACTION = (
    "wscript.exe //B //NoLogo "
    "C:/ProgramData/KMTech/DirectSync/container_audit/bin/"
    "direct-sync-relay-container-audit.vbs"
)


def test_factory_contract_startup_accepts_synced_lock_and_bundle():
    lock = app.verify_factory_contract_startup()

    assert lock["app_id"] == "container_audit"
    assert lock["contract_bundle_version"] == "1.0.3"
    assert lock["contract_bundle_sha256"] == CONTRACT_BUNDLE_SHA256


def test_generated_container_contract_uses_cmd_without_task_action_mismatch(tmp_path):
    stage_root = tmp_path / "stage"
    prepare_identity(
        repository=ROOT,
        stage_root=stage_root,
        app_id="container_audit",
        app_version=app.CURRENT_VERSION,
        db_schema_current=0,
        development=True,
    )
    manifest = create_build_manifest(
        stage_root,
        expected_files=(
            "build-compatibility.json",
            "build-identity.json",
            "contract.lock.json",
        ),
        built_at_utc="2026-08-23T00:00:00Z",
    )
    write_json(stage_root / "build-manifest.json", manifest)
    generated = json.loads(
        (stage_root / "build-compatibility.json").read_text(encoding="utf-8")
    )

    assert generated["resources"]["task_action"] == CMD_TASK_ACTION
    assert manifest["contract_bundle_sha256"] == generated["contract_bundle_sha256"]

    installed = json.loads(json.dumps(generated))
    installed["app_id"] = "defect_inspection"
    installed["app_version"] = "v0.2.59"
    assert installed["resources"]["task_name"] == generated["resources"]["task_name"]

    same_action = offline_preflight(candidate=generated, installed_builds=[installed])
    same_action_codes = {issue["code"] for issue in same_action["issues"]}
    assert "TASK_ACTION_MISMATCH" not in same_action_codes

    installed["resources"]["task_action"] = FALSE_VBS_TASK_ACTION
    stale_action = offline_preflight(candidate=generated, installed_builds=[installed])
    stale_action_codes = {issue["code"] for issue in stale_action["issues"]}
    assert "TASK_ACTION_MISMATCH" in stale_action_codes


@pytest.mark.parametrize(
    ("field", "value", "error_code"),
    [
        ("contract_bundle_sha256", "0" * 64, "CONTRACT_HASH_MISMATCH"),
        ("contract_bundle_version", "999.0.0", "CONTRACT_VERSION_MISMATCH"),
    ],
)
def test_factory_contract_startup_rejects_hash_or_version_tamper(
    tmp_path,
    field,
    value,
    error_code,
):
    payload = json.loads((ROOT / "contract.lock.json").read_text(encoding="utf-8"))
    payload[field] = value
    tampered_lock = tmp_path / "contract.lock.json"
    tampered_lock.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FactoryContractError) as caught:
        app.verify_factory_contract_startup(tampered_lock)

    assert caught.value.code == error_code


def test_main_fails_before_runtime_when_factory_contract_gate_fails(monkeypatch):
    failure = FactoryContractError("CONTRACT_TEST_FAILURE", "fixture rejection")

    def reject_contract():
        raise failure

    monkeypatch.setattr(app, "verify_factory_contract_startup", reject_contract)

    with pytest.raises(FactoryContractError) as caught:
        app.main()

    assert caught.value is failure


def test_authoritative_pyinstaller_paths_include_factory_contract_data():
    spec = (ROOT / "Container_Audit.spec").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    verifier = (ROOT / "tools" / "verify_frozen_release_artifact.py").read_text(
        encoding="utf-8"
    )

    assert (
        "('kmtech_factory_contracts/bundle', 'kmtech_factory_contracts/bundle')"
        in spec
    )
    assert "('contract.lock.json', '.')" in spec
    assert "PyInstaller" not in workflow
    assert "build_cli prepare" not in workflow
    assert "build_cli manifest" not in workflow
    assert "verify_staged_package" in verifier
    assert "expected_contract_sha256=expected_contract_sha256" in verifier
