import ast
from pathlib import Path

import update_service


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"
WRAPPER_PATH = ROOT / "tools" / "active_work_probe.py"
PROBE_FILES = (
    "KMTechActiveWorkProbe.exe",
    "KMTechActiveWorkProbe.independent.build-identity.json",
    "KMTechActiveWorkProbe.integrated.build-identity.json",
)
def test_active_work_probe_wrapper_is_only_the_canonical_cli_entrypoint():
    source = WRAPPER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    assert len(imports) == 1
    assert imports[0].module == "kmtech_factory_contracts.active_work_probe.cli"
    assert [(alias.name, alias.asname) for alias in imports[0].names] == [("main", None)]
    assert "sys.path" not in source
    assert "WorkerAnalysisGUI-web" not in source
    assert "copy" not in source.lower()


def test_frozen_release_verifier_proves_both_probe_identity_scopes():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    verifier = (ROOT / "tools" / "verify_frozen_release_artifact.py").read_text(
        encoding="utf-8"
    )

    assert "tools/verify_frozen_release_artifact.py" in workflow
    assert "PyInstaller" not in workflow
    assert "BUILD_IDENTITY_FILENAMES" in verifier
    assert '"independent": ["Container_Audit"]' in verifier
    assert '"integrated": list(ALL_APPS)' in verifier
    assert 'identity.get("probe_source_commit") != expected_commit' in verifier
    assert 'identity.get("probe_artifact_sha256") != artifact_hash' in verifier


def test_probe_artifacts_are_manifested_and_required_by_the_exact_update_zip():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    verifier = (ROOT / "tools" / "verify_frozen_release_artifact.py").read_text(
        encoding="utf-8"
    )

    for name in PROBE_FILES:
        archive_name = f"Container_Audit/{name}"
        assert archive_name in update_service.REQUIRED_UPDATE_ARCHIVE_FILES

    assert "PROBE_ARTIFACT_FILENAME" in verifier
    assert "BUILD_IDENTITY_FILENAMES" in verifier
    assert "verify_staged_package" in verifier
    assert "REQUIRED_MANIFEST_EXPECTED_FILES" in verifier
    assert "expected_archive_files" in verifier
    assert "safe_extract_update_zip" in verifier
