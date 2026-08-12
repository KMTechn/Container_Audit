from pathlib import Path

import update_service


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_NAME = "Container_Audit_Protected_Admin_Install.exe"
ACL_SCRIPT_NAME = "PROVISION_PROTECTED_ADMIN_ACL.ps1"
PROVISIONING_DOC_NAME = "PROTECTED_ADMIN_PROVISIONING.md"


def test_release_contract_contains_source_free_protected_admin_bundle() -> None:
    required = update_service.REQUIRED_UPDATE_ARCHIVE_FILES
    assert {
        f"Container_Audit/{INSTALLER_NAME}",
        f"Container_Audit/{ACL_SCRIPT_NAME}",
        f"Container_Audit/{PROVISIONING_DOC_NAME}",
    } <= required
    assert not any("install_protected_admin.py" in name for name in required)

    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    release_workflow = (
        ROOT / ".github" / "workflows" / "release.yml"
    ).read_text(encoding="utf-8")

    # Full CI owns regression observation only. Rebuilding the release bundle
    # there would duplicate the locally qualified artifact without a unique signal.
    assert "python -m pytest" in ci_workflow
    assert "PyInstaller" not in ci_workflow
    assert "tools/install_protected_admin.py" not in ci_workflow

    # The tag workflow observes hosted CI without gating, then verifies the
    # already qualified source-free package without rebuilding its payloads.
    hosted_step_name = "- name: Record hosted CI status without release gating"
    assert hosted_step_name in release_workflow
    hosted_step = release_workflow[
        release_workflow.index(hosted_step_name) :
        release_workflow.index("- name: Check release version")
    ]
    assert "-f status=completed" not in hosted_step
    assert "WAIVED_NOT_TESTED" in hosted_step
    assert "hosted_ci_observation=" in hosted_step
    assert "run_attempt" in hosted_step
    assert "conclusion" in hosted_step
    assert "throw" not in hosted_step.lower()
    assert "python -m pytest" not in release_workflow
    assert "PyInstaller" not in release_workflow
    assert "tools/install_protected_admin.py" not in release_workflow
    assert "tools/verify_frozen_release_artifact.py" in release_workflow


def test_acl_wrapper_never_accepts_or_transports_the_protected_code() -> None:
    script = (ROOT / "tools" / "provision_protected_admin_acl.ps1").read_text(
        encoding="utf-8"
    )
    lowered = script.casefold()
    assert INSTALLER_NAME in script
    assert "--reader-principal" in script
    assert "--profile-path" in script
    assert "--dry-run" in script
    assert "start-transcript" not in lowered
    assert "protected_admin_code" not in lowered
    assert "--code" not in lowered
    parameter_block = script.split(")", 1)[0].casefold()
    assert all(
        marker not in parameter_block
        for marker in ("code", "credential", "password", "secret")
    )


def test_provisioning_document_requires_hidden_interactive_entry() -> None:
    document = (ROOT / "docs" / "PROTECTED_ADMIN_PROVISIONING.md").read_text(
        encoding="utf-8"
    )
    assert INSTALLER_NAME in document
    assert ACL_SCRIPT_NAME in document
    assert "-DryRun" in document
    assert "-ReaderPrincipal" in document
    assert "명령행 인자" in document
    assert "환경 변수" in document
    assert "PowerShell transcript" in document
