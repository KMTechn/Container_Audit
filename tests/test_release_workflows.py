import base64
import json
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import update_service


def _release_workflow_required_assets(text):
    match = re.search(r"\$required = @\((?P<body>.*?)\)\s+foreach", text, flags=re.DOTALL)
    assert match is not None
    return frozenset(re.findall(r'"([^"]+)"', match.group("body")))


def test_ci_and_release_workflows_package_clean_release_config():
    root = Path(__file__).resolve().parents[1]
    for workflow_name in ("ci.yml", "release.yml"):
        text = (root / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        assert "python tools/check_release_config.py --config-dir build/release_config" in text
        assert '--add-data "build/release_config;config"' in text
        assert "build/release_tools" in text
        assert '--add-data "build/release_tools;tools"' in text
        assert '--add-data "config;config"' not in text
        assert '--add-data "tools;tools"' not in text
        assert "python -m pip install -r requirements.txt" in text
        assert "python -m pip install -r requirements-dev.txt" in text
        assert "python -m pip install pyinstaller" not in text
        assert "python -m pytest -q -p no:cacheprovider" in text
        assert "python -m PyInstaller" in text
        assert "Container_Audit_DirectSync_Install" in text
        assert "Container_Audit_DirectSync_Relay" in text
        assert "Container_Audit_Worker_PC_Register" in text
        assert "KMTech_Logistics_Profile_Install" in text
        assert "KMTech_Logistics_Profile_Check" in text
        assert "CENTRAL_LOGISTICS_PC_ROLLOUT.md" in text
        assert "tools/register_container_audit_worker_pc.py" in text
        assert "tools/install_logistics_runtime_profile.py" in text
        assert "tools/check_logistics_runtime_profile.py" in text
        assert '--add-data "storage_policy.py;."' in text
        assert '--add-data "storage_utils.py;."' in text
        assert '--add-data "logistics_runtime_profile.py;."' in text
        assert 'python tools/check_update_archive.py --zip-path "$zipPath" --destination "$smokeDir"' in text
        assert 'python tools/check_release_config.py --config-dir "$releaseConfigDir"' in text
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert _release_workflow_required_assets(release_text) == update_service.REQUIRED_UPDATE_ARCHIVE_FILES
    assert "Expand-Archive" not in release_text
    assert "- name: Smoke check release archive" in release_text
    assert "Get-FileHash -LiteralPath $zipPath -Algorithm SHA256" in release_text
    assert '"$($hash.Hash.ToLowerInvariant())  $zipPath" | Set-Content -LiteralPath "$zipPath.sha256" -Encoding ascii' in release_text
    assert "kmtech-private-update-manifest-v1" in release_text
    assert 'app_id = "Container_Audit"' in release_text
    assert "PRIVATE_UPDATE_ARTIFACT_BASE_URL" in release_text
    assert "PRIVATE_UPDATE_ARTIFACT_BASE_URL must use HTTPS." in release_text
    assert "PRIVATE_UPDATE_ARTIFACT_BASE_URL must not include userinfo." in release_text
    assert "PRIVATE_UPDATE_ARTIFACT_BASE_URL must not include fragments." in release_text
    assert "PRIVATE_UPDATE_ARTIFACT_BASE_URL must not contain query strings." in release_text
    assert "not GitHub release storage" in release_text
    assert ".githubusercontent.com" in release_text
    assert "PRIVATE_UPDATE_ROLLOUT_PERCENTAGE" in release_text
    assert "PRIVATE_UPDATE_ROLLOUT_PERCENTAGE must be an integer from 0 to 100." in release_text
    assert "PRIVATE_UPDATE_ALLOW_PC_IDS" in release_text
    assert "PRIVATE_UPDATE_DENY_PC_IDS" in release_text
    assert "ConvertTo-CanonicalPcIds" in release_text
    assert "^[a-z0-9][a-z0-9._-]{0,63}$" in release_text
    assert "must not overlap" in release_text
    assert "$artifactUrl = \"$baseUrl/$zipPath\"" in release_text
    assert "releases/download" not in release_text
    assert "legacy_sha256_url" in release_text
    assert "required_files = $required" in release_text
    assert "percentage = $rolloutPercentage" in release_text
    assert "Container_Audit-${{ github.ref_name }}.manifest.json" in release_text
    assert "- name: Sign private update manifest" in release_text
    assert "PRIVATE_UPDATE_MANIFEST_SIGNING_KEY" in release_text
    assert "- name: Publish private update feed" in release_text
    assert "COMPANY_UPDATE_UPLOAD_TOKEN" in release_text
    assert "COMPANY_UPDATE_UPLOAD_ORIGIN_IP" in release_text
    assert "--resolve" in release_text
    assert "PRIVATE_UPDATE_APP_SLUG: container_audit" in release_text
    assert "curl.exe" in release_text
    assert "PRIVATE_UPDATE_MANIFEST_URL" in release_text
    assert "PRIVATE_UPDATE_MANIFEST_PUBLIC_KEY" in release_text
    assert 'provider = "private_manifest"' in release_text
    assert 'provider = "github"' in release_text
    assert "PRIVATE_UPDATE_MANIFEST_URL and PRIVATE_UPDATE_MANIFEST_PUBLIC_KEY must be set together." in release_text
    upload_block = release_text[release_text.index("- name: Create Release and Upload Asset"):]
    assert "Container_Audit-${{ github.ref_name }}.manifest.json" not in upload_block


def test_release_workflow_requires_explicit_private_feed_publish_opt_in():
    root = Path(__file__).resolve().parents[1]
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    explicit_opt_in = "${{ steps.private_feed.outputs.enabled == 'true' }}"

    assert "PRIVATE_UPDATE_FEED_PUBLISH_MODE: ${{ vars.ENABLE_PRIVATE_UPDATE_FEED_PUBLISH }}" in release_text
    assert "id: private_feed" in release_text
    assert 'ENABLE_PRIVATE_UPDATE_FEED_PUBLISH must be exactly \'true\', \'false\', or unset.' in release_text
    assert '$enabled = if ($privateFeedMode -ceq "true") { "true" } else { "false" }' in release_text
    assert '"enabled=$enabled" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append' in release_text
    assert release_text.count("PRIVATE_UPDATE_FEED_PUBLISH_MODE: ${{ steps.private_feed.outputs.enabled }}") == 2
    assert '$publishPrivateFeed = $privateFeedMode -ceq "true"' in release_text
    assert 'if ($env:PRIVATE_UPDATE_FEED_PUBLISH_MODE -ceq "true")' in release_text
    assert release_text.count(f"if: {explicit_opt_in}") == 2
    assert "if: ${{ vars.PRIVATE_UPDATE_ARTIFACT_BASE_URL != '' }}" not in release_text
    assert 'provider = "github"' in release_text
    assert 'provider = "private_manifest"' in release_text

    sign_block = release_text[
        release_text.index("- name: Sign private update manifest"):
        release_text.index("- name: Publish private update feed")
    ]
    publish_block = release_text[
        release_text.index("- name: Publish private update feed"):
        release_text.index("- name: Create Release and Upload Asset")
    ]
    assert f"if: {explicit_opt_in}" in sign_block
    assert f"if: {explicit_opt_in}" in publish_block
    assert "canary_release.outputs" not in sign_block
    assert "canary_release.outputs" not in publish_block

    assert "id: canary_release" in release_text
    assert (
        "PRIVATE_UPDATE_CANARY_PRERELEASE: "
        "${{ vars.PRIVATE_UPDATE_CANARY_PRERELEASE }}"
    ) in release_text
    assert (
        "PRIVATE_UPDATE_CANARY_PRERELEASE must be exactly 'true', 'false', or unset."
        in release_text
    )
    assert (
        '$enabled = if ($canaryMode -ceq "true") { "true" } else { "false" }'
        in release_text
    )
    release_block = release_text[
        release_text.index("- name: Create Release and Upload Asset") :
    ]
    assert (
        "prerelease: ${{ steps.canary_release.outputs.enabled == 'true' }}"
        in release_block
    )
    assert "prerelease: false" not in release_block
    assert (
        "make_latest: ${{ steps.canary_release.outputs.make_latest }}"
        in release_block
    )


def test_private_feed_pc_id_lists_are_canonical_deduplicated_and_fail_closed():
    root = Path(__file__).resolve().parents[1]
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    start = release_text.index("function ConvertTo-CanonicalPcIds {")
    end = release_text.index('$artifactUrl = "$baseUrl/$zipPath"', start)
    parser_script = textwrap.dedent(release_text[start:end]) + """
[ordered]@{
  allow = @($allowPcIds)
  deny = @($denyPcIds)
} | ConvertTo-Json -Compress
"""
    powershell = next(
        (
            executable
            for name in ("pwsh", "powershell", "powershell.exe")
            if (executable := shutil.which(name))
        ),
        None,
    )
    assert powershell is not None

    def run_parser(allow, deny):
        env = os.environ.copy()
        env["PRIVATE_UPDATE_ALLOW_PC_IDS"] = allow
        env["PRIVATE_UPDATE_DENY_PC_IDS"] = deny
        encoded = base64.b64encode(parser_script.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )

    accepted = run_parser(" TEST1, test1\nLINE-A_01 ", " BLOCKED-1,blocked-1 ")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    parsed = json.loads(accepted.stdout.strip())
    assert parsed == {"allow": ["test1", "line-a_01"], "deny": ["blocked-1"]}

    invalid = run_parser("test1,bad token", "")
    assert invalid.returncode != 0
    assert "invalid PC id token" in invalid.stderr

    overlap = run_parser("TEST1", "test1")
    assert overlap.returncode != 0
    assert "must not overlap" in overlap.stderr


def test_canary_prerelease_gate_accepts_only_exact_lowercase_values(tmp_path):
    root = Path(__file__).resolve().parents[1]
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    start = release_text.index("- name: Resolve canary prerelease mode")
    end = release_text.index("\n      - name:", start + 1)
    step = release_text[start:end]
    script = textwrap.dedent(step.split("        run: |\n", 1)[1]).strip()
    powershell = next(
        (
            executable
            for name in ("pwsh", "powershell", "powershell.exe")
            if (executable := shutil.which(name))
        ),
        None,
    )
    assert powershell is not None
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def run_gate(value):
        output = tmp_path / "github-output.txt"
        output.unlink(missing_ok=True)
        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(output)
        if value is None:
            env.pop("PRIVATE_UPDATE_CANARY_PRERELEASE", None)
        else:
            env["PRIVATE_UPDATE_CANARY_PRERELEASE"] = value
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        return completed, output.read_text(encoding="utf-8-sig") if output.exists() else ""

    for value, expected, expected_latest in (
        (None, "false", "legacy"),
        ("false", "false", "legacy"),
        ("true", "true", "false"),
    ):
        completed, output = run_gate(value)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert f"enabled={expected}" in output
        assert f"make_latest={expected_latest}" in output

    for invalid in ("TRUE", "False", "1", " true "):
        completed, output = run_gate(invalid)
        assert completed.returncode != 0
        assert output == ""
        assert "must be exactly" in completed.stderr


def test_ci_workflow_tests_supported_python_minors():
    root = Path(__file__).resolve().parents[1]
    ci_text = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^permissions:\n\s+contents: read$", ci_text)
    assert "matrix:" in ci_text
    assert "python-version: ['3.11', '3.12']" in ci_text
    assert "python-version: ${{ matrix.python-version }}" in ci_text


def test_release_workflow_pins_actions_running_with_release_write_permission():
    root = Path(__file__).resolve().parents[1]
    release_text = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    uses_values = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", release_text)

    assert uses_values
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in uses_values)
    assert "softprops/action-gh-release@v2" not in release_text


def test_ci_workflow_pins_external_actions():
    root = Path(__file__).resolve().parents[1]
    ci_text = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    uses_values = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", ci_text)

    assert uses_values
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in uses_values)
    assert "actions/checkout@v4" not in ci_text
    assert "actions/setup-python@v5" not in ci_text


def test_dev_toolchain_is_pinned_in_requirements_dev():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements-dev.txt").read_text(encoding="utf-8")

    assert "pytest==9.0.2" in requirements
    assert "pyinstaller==6.20.0" in requirements
