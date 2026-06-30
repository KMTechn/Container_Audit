import hashlib
import stat
import zipfile

import pytest

import update_service


def _write_required_update_members(zip_ref, *, omit=()):
    omitted = set(omit)
    for name in sorted(update_service.REQUIRED_UPDATE_ARCHIVE_FILES - omitted):
        zip_ref.writestr(name, name.encode("utf-8"))


def _private_update_manifest(*, version="v2.0.10", sha256="a" * 64, url=None):
    return {
        "schema_version": "kmtech-private-update-manifest-v1",
        "manifest_version": 1,
        "app_id": "Container_Audit",
        "package_id": "Container_Audit",
        "channel": "stable",
        "version": version,
        "artifact": {
            "name": f"Container_Audit-{version}.zip",
            "url": url or f"https://updates.example/Container_Audit-{version}.zip",
            "size_bytes": 123,
            "sha256": sha256,
        },
        "archive": {
            "format": "zip",
            "top_level": "Container_Audit",
            "entrypoint": "Container_Audit.exe",
            "required_files": ["Container_Audit/Container_Audit.exe"],
        },
        "install": {
            "strategy": "robocopy_backup_then_mirror",
            "preserve_paths": ["config/container_audit_settings.json"],
        },
        "rollout": {
            "percentage": 100,
            "allow_pc_ids": [],
            "deny_pc_ids": [],
        },
    }


def test_update_service_uses_semantic_version_order():
    assert update_service.parse_version_tag("v2.10.0") == (2, 10, 0)
    assert update_service.is_newer_version("v2.10.0", "v2.9.9") is True
    assert update_service.is_newer_version("v2.0.9", "v2.0.10") is False
    assert update_service.is_newer_version("v2.0.10-hotfix", "v2.0.9") is False
    assert update_service.is_newer_version("v2.0.10", "current") is False


def test_update_service_finds_matching_zip_checksum_asset():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
            },
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload) == (
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
    )


def test_update_service_finds_matching_zip_asset_digest_without_checksum_asset():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
                "digest": f"sha256:{'c' * 64}",
            },
        ]
    }

    assert update_service.find_release_asset_update_info(payload, expected_version="v2.0.10") == {
        "download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "checksum_url": "",
        "sha256": "c" * 64,
    }


def test_update_service_rejects_matching_zip_without_checksum_or_digest():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
            },
        ]
    }

    assert update_service.find_release_asset_update_info(payload, expected_version="v2.0.10") is None


def test_update_service_finds_exact_tagged_asset_when_multiple_zips():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.9.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.9/Container_Audit-v2.0.9.zip",
            },
            {
                "name": "Container_Audit-v2.0.9.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.9/Container_Audit-v2.0.9.zip.sha256",
            },
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
            },
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload, expected_version="v2.0.10") == (
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
    )


def test_update_service_skips_ambiguous_or_non_matching_zip_assets():
    ambiguous = {
        "assets": [
            {"name": "Container_Audit-v2.0.10.zip", "browser_download_url": "https://example.invalid/app.zip"},
            {"name": "Container_Audit-v2.0.10-copy.zip", "browser_download_url": "https://example.invalid/app-copy.zip"},
        ]
    }
    non_matching = {
        "assets": [
            {"name": "Container_Audit-v2.0.9.zip", "browser_download_url": "https://example.invalid/old.zip"},
            {"name": "Container_Audit-v2.0.9.zip.sha256", "browser_download_url": "https://example.invalid/old.zip.sha256"},
        ]
    }

    assert update_service.find_release_asset_urls(ambiguous) == (None, None)
    assert update_service.find_release_asset_urls(non_matching, expected_version="v2.0.10") == (None, None)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/app.zip",
        "https://user:pass@github.com/KMTechn/Container_Audit/releases/download/v2.0.10/app.zip",
        "https://example.invalid/KMTechn/Container_Audit/releases/download/v2.0.10/app.zip",
        "https://github.com/KMTechn/Container_Audit/archive/refs/tags/v2.0.10.zip",
    ],
)
def test_update_service_rejects_untrusted_release_asset_urls(url):
    with pytest.raises(ValueError, match="릴리스 asset URL|GitHub"):
        update_service.validate_release_asset_url(url)


def test_update_service_verifies_private_manifest_signature_and_candidate():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    manifest = {
        "schema_version": "kmtech-private-update-manifest-v1",
        "manifest_version": 1,
        "app_id": "Container_Audit",
        "package_id": "Container_Audit",
        "channel": "stable",
        "version": "v2.0.10",
        "artifact": {
            "name": "Container_Audit-v2.0.10.zip",
            "url": "https://updates.example/Container_Audit-v2.0.10.zip",
            "size_bytes": 123,
            "sha256": "a" * 64,
        },
        "archive": {
            "format": "zip",
            "top_level": "Container_Audit",
            "entrypoint": "Container_Audit.exe",
            "required_files": ["Container_Audit/Container_Audit.exe"],
        },
        "install": {
            "strategy": "robocopy_backup_then_mirror",
            "preserve_paths": ["config/container_audit_settings.json"],
        },
        "rollout": {
            "percentage": 100,
            "allow_pc_ids": [],
            "deny_pc_ids": [],
        },
    }
    signature = private_key.sign(update_service.canonical_manifest_bytes(manifest))

    update_service.verify_update_manifest_signature(manifest, signature, public_key_hex)
    candidate = update_service.update_candidate_from_private_manifest(
        manifest,
        current_version="v2.0.9",
        expected_channel="stable",
    )

    assert candidate == {
        "download_url": "https://updates.example/Container_Audit-v2.0.10.zip",
        "version": "v2.0.10",
        "sha256": "a" * 64,
        "provider": "private_manifest",
        "archive_policy": {
            "top_level": "Container_Audit",
            "required_files": ["Container_Audit/Container_Audit.exe"],
        },
    }


@pytest.mark.parametrize(
    "artifact_url",
    [
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://raw.githubusercontent.com/KMTechn/update-feed/main/Container_Audit-v2.0.10.zip",
    ],
)
def test_update_service_rejects_private_manifest_github_hosted_artifact_url(artifact_url):
    manifest = {
        "schema_version": "kmtech-private-update-manifest-v1",
        "manifest_version": 1,
        "app_id": "Container_Audit",
        "package_id": "Container_Audit",
        "channel": "stable",
        "version": "v2.0.10",
        "artifact": {
            "name": "Container_Audit-v2.0.10.zip",
            "url": artifact_url,
            "size_bytes": 123,
            "sha256": "b" * 64,
        },
        "archive": {
            "format": "zip",
            "top_level": "Container_Audit",
            "entrypoint": "Container_Audit.exe",
            "required_files": ["Container_Audit/Container_Audit.exe"],
        },
        "install": {
            "strategy": "robocopy_backup_then_mirror",
            "preserve_paths": ["config/container_audit_settings.json"],
        },
        "rollout": {
            "percentage": 100,
            "allow_pc_ids": [],
            "deny_pc_ids": [],
        },
    }

    with pytest.raises(ValueError, match="GitHub"):
        update_service.update_candidate_from_private_manifest(
            manifest,
            current_version="v2.0.9",
            expected_channel="stable",
        )


def test_update_service_rejects_private_manifest_fragment_artifact_url():
    manifest = _private_update_manifest(
        url="https://updates.example/Container_Audit-v2.0.10.zip#token=raw-secret"
    )

    with pytest.raises(ValueError):
        update_service.update_candidate_from_private_manifest(
            manifest,
            current_version="v2.0.9",
            expected_channel="stable",
        )


@pytest.mark.parametrize(
    "query",
    [
        "sig=raw",
        "signature=raw",
        "X-Amz-Signature=raw",
        "X-Goog-Signature=raw",
    ],
)
def test_update_service_rejects_signed_credential_query_keys(query):
    with pytest.raises(ValueError, match="장기 인증 토큰"):
        update_service.assert_https_update_url(
            f"https://updates.example/Container_Audit-v2.0.10.zip?{query}",
            require_zip=True,
        )


def test_update_service_rejects_release_asset_url_fragment():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip#token=raw-secret",
            },
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload, expected_version="v2.0.10") == (None, None)


def test_update_service_rejects_release_asset_signed_credential_query():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip?X-Amz-Signature=raw",
            },
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload, expected_version="v2.0.10") == (None, None)


def test_update_service_rejects_boolean_integer_fields():
    manifest = _private_update_manifest()
    manifest["artifact"]["size_bytes"] = True
    with pytest.raises(ValueError, match="size"):
        update_service.update_candidate_from_private_manifest(
            manifest,
            current_version="v2.0.9",
            expected_channel="stable",
        )

    manifest = _private_update_manifest()
    manifest["rollout"]["percentage"] = True
    with pytest.raises(ValueError, match="percentage"):
        update_service.update_candidate_from_private_manifest(
            manifest,
            current_version="v2.0.9",
            expected_channel="stable",
        )


def test_update_service_private_manifest_rollout_blocks_and_allowlists_current_pc(monkeypatch):
    manifest = _private_update_manifest(sha256="c" * 64)
    manifest["rollout"]["percentage"] = 0
    monkeypatch.setenv(update_service.UPDATE_PC_ID_ENV, "line-a-pc-01")

    assert update_service.update_candidate_from_private_manifest(
        manifest,
        current_version="v2.0.9",
        expected_channel="stable",
    ) is None

    manifest["rollout"]["allow_pc_ids"] = [" LINE-A-PC-01 "]
    candidate = update_service.update_candidate_from_private_manifest(
        manifest,
        current_version="v2.0.9",
        expected_channel="stable",
    )

    assert candidate["download_url"] == "https://updates.example/Container_Audit-v2.0.10.zip"
    assert candidate["sha256"] == "c" * 64
    assert candidate["archive_policy"]["required_files"] == ["Container_Audit/Container_Audit.exe"]


def test_update_service_skips_assets_with_untrusted_urls():
    payload = {
        "assets": [
            {"name": "Container_Audit-v2.0.10.zip", "browser_download_url": "http://example.invalid/app.zip"},
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/app.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload, expected_version="v2.0.10") == (None, None)


@pytest.mark.parametrize(
    "asset_url",
    [
        "https://github.com/Other/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Other/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.9/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
        "https://objects.githubusercontent.com/github-production-release-asset/fixture/Container_Audit-v2.0.10.zip",
    ],
)
def test_update_service_skips_assets_not_bound_to_expected_repo_tag_and_name(asset_url):
    payload = {
        "assets": [
            {"name": "Container_Audit-v2.0.10.zip", "browser_download_url": asset_url},
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert update_service.find_release_asset_urls(payload, expected_version="v2.0.10") == (None, None)


def test_update_service_verifies_sha256_file(tmp_path):
    zip_path = tmp_path / "update.zip"
    zip_path.write_bytes(b"zip-bytes")
    good_hash = hashlib.sha256(b"zip-bytes").hexdigest()
    bad_hash = hashlib.sha256(b"other").hexdigest()

    update_service.verify_update_checksum(zip_path, f"{good_hash}  update.zip")
    with pytest.raises(ValueError, match="일치하지 않습니다"):
        update_service.verify_update_checksum(zip_path, f"{bad_hash}  update.zip")


def test_update_service_binds_sha256_file_to_expected_release_asset_name(tmp_path):
    zip_path = tmp_path / "download.tmp"
    zip_path.write_bytes(b"zip-bytes")
    good_hash = hashlib.sha256(b"zip-bytes").hexdigest()

    update_service.verify_update_checksum(
        zip_path,
        f"{good_hash}  Container_Audit-v2.0.10.zip",
        expected_filename="Container_Audit-v2.0.10.zip",
    )

    with pytest.raises(ValueError, match="체크섬"):
        update_service.verify_update_checksum(
            zip_path,
            f"{good_hash}  Container_Audit-v2.0.9.zip",
            expected_filename="Container_Audit-v2.0.10.zip",
        )
    with pytest.raises(ValueError, match="체크섬"):
        update_service.verify_update_checksum(
            zip_path,
            f"{good_hash}  releases/Container_Audit-v2.0.10.zip",
            expected_filename="Container_Audit-v2.0.10.zip",
        )
    with pytest.raises(ValueError, match="단일 항목"):
        update_service.verify_update_checksum(
            zip_path,
            f"{good_hash}  Container_Audit-v2.0.10.zip\n{good_hash}  other.zip",
            expected_filename="Container_Audit-v2.0.10.zip",
        )


def test_update_service_safe_extracts_normal_zip(tmp_path):
    zip_path = tmp_path / "update.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        _write_required_update_members(zip_ref)

    extracted = update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert (extracted / "Container_Audit" / "Container_Audit.exe").read_bytes() == b"Container_Audit/Container_Audit.exe"
    assert (
        extracted / "Container_Audit" / "tools" / "direct_sync_relay_runner.py"
    ).read_bytes() == b"Container_Audit/tools/direct_sync_relay_runner.py"


def test_update_service_safe_extract_enforces_manifest_archive_policy(tmp_path):
    zip_path = tmp_path / "update.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        _write_required_update_members(zip_ref)

    with pytest.raises(ValueError, match="archive.top_level"):
        update_service.safe_extract_update_zip(
            zip_path,
            tmp_path / "wrong-top-level",
            archive_policy={
                "top_level": "Other_App",
                "required_files": ["Container_Audit/Container_Audit.exe"],
            },
        )

    with pytest.raises(ValueError, match="manifest 필수 파일"):
        update_service.safe_extract_update_zip(
            zip_path,
            tmp_path / "missing-policy-required",
            archive_policy={
                "top_level": "Container_Audit",
                "required_files": [
                    "Container_Audit/Container_Audit.exe",
                    "Container_Audit/not-in-archive.txt",
                ],
            },
        )


@pytest.mark.parametrize(
    "members",
    [
        {
            "Container_Audit/Container_Audit.exe": b"exe",
            "Container_Audit/tools/direct_sync_relay_runner.py": b"runner",
            "README.txt": b"extra",
        },
        {
            "Container_Audit.exe": b"exe",
            "tools/direct_sync_relay_runner.py": b"runner",
        },
    ],
)
def test_update_service_rejects_archive_with_invalid_top_level_layout(tmp_path, members):
    zip_path = tmp_path / "bad-layout.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        for name, content in members.items():
            zip_ref.writestr(name, content)

    with pytest.raises(ValueError, match="최상위 Container_Audit"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")


def test_update_service_rejects_archive_missing_required_files(tmp_path):
    zip_path = tmp_path / "missing-required.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")

    with pytest.raises(ValueError, match="필수 파일"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")


@pytest.mark.parametrize(
    "missing_member",
    [
        "Container_Audit/assets/KMC_LHD.png",
        "Container_Audit/config/container_audit_settings.json",
        "Container_Audit/tools/direct_sync_relay_install_pack.py",
        "Container_Audit/tools/register_container_audit_worker_pc.py",
        "Container_Audit/Container_Audit_DirectSync_Install.exe",
        "Container_Audit/Container_Audit_DirectSync_Relay.exe",
        "Container_Audit/Container_Audit_Worker_PC_Register.exe",
        "Container_Audit/direct_sync_runtime.py",
        "Container_Audit/storage_policy.py",
        "Container_Audit/storage_utils.py",
    ],
)
def test_update_service_rejects_archive_missing_runtime_assets_or_modules(tmp_path, missing_member):
    zip_path = tmp_path / "missing-runtime-member.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        _write_required_update_members(zip_ref, omit={missing_member})

    with pytest.raises(ValueError, match="필수 파일"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")


@pytest.mark.parametrize(
    "member_name",
    [
        "Container_Audit/direct_sync_relay.sqlite3",
        "Container_Audit/direct_sync_relay.sqlite3-wal",
        "Container_Audit/relay_spool/batch.csv",
        "Container_Audit/status/direct_sync_upload_status_abcdef123456.json",
        "Container_Audit/receipts/request-1.upload",
        "Container_Audit/logs/relay.jsonl",
        "Container_Audit/config/producer_credential.json",
        "Container_Audit/config/parked_trays/parked_tray_1.json",
        "Container_Audit/config/worker_registry.json",
        "Container_Audit/config/best_time_records.json",
        "Container_Audit/config/validator_settings.json",
        "Container_Audit/이적작업이벤트로그_홍길동_20260622.csv",
    ],
)
def test_update_service_rejects_archive_with_runtime_local_or_sensitive_members(tmp_path, member_name):
    zip_path = tmp_path / "runtime-local.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        _write_required_update_members(zip_ref)
        zip_ref.writestr(member_name, b"runtime-local")

    with pytest.raises(ValueError, match="현장 런타임/민감 상태 파일"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")


def test_update_service_rejects_duplicate_archive_members(tmp_path):
    zip_path = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zip_ref.writestr("Container_Audit/Container_Audit.exe", b"shadow")

    with pytest.raises(ValueError, match="중복 경로"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_case_insensitive_archive_member_collisions(tmp_path):
    zip_path = tmp_path / "case-collision.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")
        zip_ref.writestr("container_audit/tools/direct_sync_relay_runner.py", b"shadow")

    with pytest.raises(ValueError, match="중복 경로"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_file_directory_archive_collisions(tmp_path):
    zip_path = tmp_path / "file-directory-collision.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools", b"not-a-directory")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")

    with pytest.raises(ValueError, match="파일/폴더 경로 충돌"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_zip_symlink_members(tmp_path):
    zip_path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("Container_Audit/link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")
        zip_ref.writestr(link, "target")

    with pytest.raises(ValueError, match="링크 항목"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


@pytest.mark.parametrize(
    "member_name",
    [
        "Container_Audit/CON.txt",
        "Container_Audit/tools/LPT1",
        "Container_Audit/tools/bad:name.txt",
        "Container_Audit/tools/trailing-dot.",
        "Container_Audit/tools/trailing-space ",
        "Container_Audit/tools/control-\x01.txt",
    ],
)
def test_update_service_rejects_windows_unsafe_archive_members(tmp_path, member_name):
    zip_path = tmp_path / "windows-unsafe.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")
        zip_ref.writestr(member_name, b"unsafe")

    with pytest.raises(ValueError, match="Windows 파일명|안전하지 않은 경로"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_archive_with_too_many_entries(tmp_path):
    zip_path = tmp_path / "too-many.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")
        zip_ref.writestr("Container_Audit/extra.txt", b"extra")

    with pytest.raises(ValueError, match="너무 많은 항목"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted", max_entries=2)

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_archive_with_oversized_member(tmp_path):
    zip_path = tmp_path / "oversized-member.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"toolarge")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")

    with pytest.raises(ValueError, match="허용 크기"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted", max_member_size=3)

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


def test_update_service_rejects_archive_with_oversized_uncompressed_total(tmp_path):
    zip_path = tmp_path / "oversized-total.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr("Container_Audit/Container_Audit.exe", b"exe")
        zip_ref.writestr("Container_Audit/tools/direct_sync_relay_runner.py", b"runner")

    with pytest.raises(ValueError, match="압축 해제 크기"):
        update_service.safe_extract_update_zip(
            zip_path,
            tmp_path / "extracted",
            max_member_size=10,
            max_total_uncompressed_size=8,
        )

    assert not (tmp_path / "extracted" / "Container_Audit").exists()


@pytest.mark.parametrize("member_name", ["../evil.txt", "Container_Audit/../../evil.txt"])
def test_update_service_rejects_unsafe_zip_members(tmp_path, member_name):
    zip_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        zip_ref.writestr(member_name, b"evil")

    with pytest.raises(ValueError, match="안전하지 않은 경로"):
        update_service.safe_extract_update_zip(zip_path, tmp_path / "extracted")

    assert not (tmp_path / "evil.txt").exists()
