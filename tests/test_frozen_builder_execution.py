import hashlib
import json
from pathlib import Path

import pytest

from tests.frozen_builder_contracts import COMMIT, TAG_OBJECT, TREE, FrozenBuilderHarness
from tests.workflow_contracts import CONTRACT_SHA

pytestmark = pytest.mark.native_e_drive


@pytest.mark.parametrize("fault,message", [
    ("python_authority", "python authority refused"),
    ("windows_authority", "Windows authority refused"),
    ("existing_output", "fresh absent path"),
    ("generated_input", "Generated build input must be absent"),
    ("not_bare", "must be a bare Git repository"),
    ("dirty", "must be clean"),
    ("origin", "exact supplied local bare mirror"),
    ("branch", "exact local main"),
    ("main", "exact candidate commit"),
    ("tag_object", "exact same FINAL intended tag object"),
    ("lightweight", "must be an annotated tag object"),
    ("peel", "must peel to exact HEAD"),
    ("pyinstaller_version", "exactly PyInstaller 6.20.0"),
    ("parser_exit", "Canonical FINAL intended annotated tag parsing failed"),
    ("parser_identity", "Canonical tag parser disagrees"),
])
def test_builder_rejects_unqualified_input_before_identity_and_compiler(native_e_path, fault, message):
    harness = FrozenBuilderHarness(native_e_path, fault)
    result, observed = harness.run()
    assert result.returncode != 0
    assert message in observed["error"]
    assert not (harness.output / "FINAL_RELEASE_IDENTITY.json").exists()
    assert not any("PyInstaller" in call["arguments"] for call in observed["calls"])
    assert not (harness.output / "local-artifact-qualification-receipt.json").exists()


@pytest.mark.parametrize("fault,message", [
    ("compiler", "Main Container_Audit PyInstaller build failed"),
    ("native_dependency", "low-risk native dependency removal failed"),
    ("post_smoke_write", "Bootstrap integrity record file count is invalid"),
    ("python_drift", "Python executable changed"),
    ("windows_drift", "Windows PowerShell Desktop 5.1 identity changed"),
    ("identity_file_drift", "FINAL_RELEASE_IDENTITY.json changed"),
    ("verifier", "complete release gate"),
])
def test_builder_failure_never_reaches_qualification(native_e_path, fault, message):
    harness = FrozenBuilderHarness(native_e_path, fault)
    result, observed = harness.run()
    assert result.returncode != 0
    assert message.lower() in observed["error"].lower()
    assert "frozen_candidate_build=LOCAL_ARTIFACT_QUALIFICATION_PASS" not in result.stdout
    assert not any(call["kind"] == "local_gate" for call in observed["calls"])
    if fault != "verifier":
        assert not (harness.output / "local-artifact-qualification-receipt.json").exists()


def test_builder_calls_sealed_pipeline_and_records_exact_artifact_identity(native_e_path):
    harness = FrozenBuilderHarness(native_e_path)
    result, observed = harness.run()
    assert result.returncode == 0, observed["error"]
    assert "frozen_candidate_build=LOCAL_ARTIFACT_QUALIFICATION_PASS" in result.stdout
    calls = observed["calls"]
    children = [call["arguments"] for call in calls if call["kind"] == "child"]
    compilers = [args for args in children if "PyInstaller" in args]
    assert len(compilers) == 7
    assert compilers[0][-1] == "Container_Audit.spec"
    names = {args[args.index("--name") + 1] for args in compilers[1:]}
    assert names == {"Container_Audit_DirectSync_Install", "Container_Audit_Qualification_Authority",
                     "Container_Audit_Protected_Admin_Install", "KMTech_Logistics_Profile_Install",
                     "KMTech_Logistics_Profile_Check", "KMTechActiveWorkProbe"}
    python_path = str(harness.root / "sealed python.exe")
    assert all(args[0] == python_path for args in children if "-m" in args or any(str(a).endswith(".py") for a in args[1:]))
    kinds = [call["kind"] for call in calls]
    assert kinds.count("python_authority") == 1
    assert kinds.count("windows_authority") == 1
    assert kinds.count("python_recheck") == 1
    assert kinds.count("windows_recheck") == 2
    acl = [args for args in children if "-DryRun" in args]
    assert len(acl) == 1
    assert acl[0] == [str(harness.root / "sealed powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-File", str(harness.output / "dist/Container_Audit/PROVISION_PROTECTED_ADMIN_ACL.ps1"), "-DryRun"]
    assert kinds.index("windows_recheck") < next(i for i, call in enumerate(calls) if call["arguments"] == acl[0])
    version_check = next(args for args in children if "-c" in args)
    assert version_check[2] == "import importlib.metadata as m; assert m.version('pyinstaller') == '6.20.0', m.version('pyinstaller')"
    verification = [args for args in children if "kmtech_factory_contracts.build_cli" in args and "verify" in args]
    assert len(verification) == 2
    for args in verification:
        assert args.count("--expected-contract-sha256") == 1
        assert args[args.index("--expected-contract-sha256") + 1] == CONTRACT_SHA
    artifact_verification = [args for args in children if "tools/verify_frozen_release_artifact.py" in args]
    assert len(artifact_verification) == 1
    artifact_args = artifact_verification[0]
    assert artifact_args.count("--expected-contract-sha256") == 1
    assert artifact_args[artifact_args.index("--expected-contract-sha256") + 1] == CONTRACT_SHA
    post_smoke = children[children.index(next(args for args in children if "tools/check_update_archive.py" in args)):]
    assert all("-B" in args for args in post_smoke if args[0] == python_path)
    assert "-I" in next(args for args in post_smoke if any(str(a).endswith("direct_sync_relay_operator.py") for a in args))
    assert kinds[-1] == "local_gate"
    identity_path = harness.output / "FINAL_RELEASE_IDENTITY.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    receipt = json.loads((harness.output / "local-artifact-qualification-receipt.json").read_text(encoding="utf-8"))
    assert identity["schema_version"] == "container-audit-final-release-identity-v2"
    assert receipt["schema_version"] == "container-audit-local-artifact-qualification-v2"
    assert receipt["factory_contract_sha256"] == CONTRACT_SHA
    assert identity["tag_object_sha"] == receipt["tag_object_sha"] == TAG_OBJECT
    assert identity["peeled_commit_sha"] == receipt["source_commit"] == COMMIT
    assert identity["source_tree"] == receipt["source_tree"] == TREE
    assert receipt["windows_powershell"] == identity["windows_powershell"]
    assert identity["windows_powershell"] == {
        "executable": str(harness.root / "sealed powershell.exe"),
        "system_directory": next(call["arguments"][1] for call in calls if call["kind"] == "windows_authority"),
        "file_type": "File", "is_reparse_point": False, "sha256": "5" * 64,
        "size": 42, "psedition": "Desktop", "powershell_version": "5.1.1",
        "version_major": 5, "version_minor": 1, "file_product_version": "5.1.1",
    }
    assert receipt["final_release_identity_sha256"] == hashlib.sha256(identity_path.read_bytes()).hexdigest()
    archive = harness.output / receipt["zip_name"]
    assert receipt["zip_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert receipt["zip_size"] == archive.stat().st_size
    main = harness.output / "dist/Container_Audit/Container_Audit.exe"
    assert receipt["main_exe_sha256"] == hashlib.sha256(main.read_bytes()).hexdigest()
