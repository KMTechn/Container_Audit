import hashlib
import stat
import zipfile

import pytest

import update_service


def _write_required_update_members(zip_ref, *, omit=()):
    omitted = set(omit)
    for name in sorted(update_service.REQUIRED_UPDATE_ARCHIVE_FILES - omitted):
        zip_ref.writestr(name, name.encode("utf-8"))


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
        "Container_Audit/direct_sync_runtime.py",
    ],
)
def test_update_service_rejects_archive_missing_runtime_assets_or_modules(tmp_path, missing_member):
    zip_path = tmp_path / "missing-runtime-member.zip"
    with zipfile.ZipFile(zip_path, "w") as zip_ref:
        _write_required_update_members(zip_ref, omit={missing_member})

    with pytest.raises(ValueError, match="필수 파일"):
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
