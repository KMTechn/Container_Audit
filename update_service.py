from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlparse
import zipfile


WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
DEFAULT_MAX_UPDATE_ARCHIVE_ENTRIES = 20_000
DEFAULT_MAX_UPDATE_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_UPDATE_ARCHIVE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DENIED_UPDATE_ARCHIVE_PATH_SEGMENTS = frozenset(
    {
        ".syncthing",
        "archive",
        "direct_sync_spool",
        "logs",
        "parked_trays",
        "raw_artifacts",
        "receipts",
        "relay_spool",
        "runtime",
        "spool",
        "status",
        "syncthing",
        "upload_status",
    }
)
DENIED_UPDATE_ARCHIVE_FILE_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".jsonl",
    ".log",
    ".sqlite",
    ".sqlite-shm",
    ".sqlite-wal",
    ".sqlite3",
    ".sqlite3-shm",
    ".sqlite3-wal",
    ".tmp",
    ".upload",
)
DENIED_UPDATE_ARCHIVE_BASENAMES = frozenset(
    {
        ".env",
        "credential.json",
        "credentials.json",
        "best_time_records.json",
        "direct_sync_credential.json",
        "direct_sync_credentials.json",
        "producer_credential.json",
        "producer_credentials.json",
        "status.json",
        "validator_settings.json",
        "worker_registry.json",
    }
)
DENIED_UPDATE_ARCHIVE_BASENAME_PATTERNS = (
    re.compile(r"direct_sync_upload_status_[0-9a-f]+\.json", flags=re.IGNORECASE),
    re.compile(r".*(credential|hmac|private[_-]?key|secret|token).*\.json", flags=re.IGNORECASE),
    re.compile(r"이적작업이벤트로그_.*\.csv", flags=re.IGNORECASE),
)
REQUIRED_UPDATE_ARCHIVE_FILES = frozenset(
    {
        "Container_Audit/Container_Audit.exe",
        "Container_Audit/assets/Item.csv",
        "Container_Audit/assets/logo.ico",
        "Container_Audit/assets/logo.png",
        "Container_Audit/assets/success.wav",
        "Container_Audit/assets/error.wav",
        "Container_Audit/assets/KMC_LHD.png",
        "Container_Audit/assets/KMC_RHD.png",
        "Container_Audit/assets/HMC_LHD_RHD.png",
        "Container_Audit/config/container_audit_settings.json",
        "Container_Audit/tools/direct_sync_relay_runner.py",
        "Container_Audit/tools/direct_sync_relay_install_pack.py",
        "Container_Audit/tools/direct_sync_relay_operator.py",
        "Container_Audit/tools/register_container_audit_worker_pc.py",
        "Container_Audit/tools/install_logistics_runtime_profile.py",
        "Container_Audit/tools/check_logistics_runtime_profile.py",
        "Container_Audit/Container_Audit_DirectSync_Install.exe",
        "Container_Audit/Container_Audit_DirectSync_Relay.exe",
        "Container_Audit/Container_Audit_Worker_PC_Register.exe",
        "Container_Audit/KMTech_Logistics_Profile_Install.exe",
        "Container_Audit/KMTech_Logistics_Profile_Check.exe",
        "Container_Audit/CENTRAL_LOGISTICS_PC_ROLLOUT.md",
        "Container_Audit/direct_sync_push.py",
        "Container_Audit/direct_sync_runtime.py",
        "Container_Audit/direct_sync_operator.py",
        "Container_Audit/storage_policy.py",
        "Container_Audit/storage_utils.py",
        "Container_Audit/logistics_runtime_profile.py",
    }
)
ALLOWED_RELEASE_ASSET_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
DEFAULT_RELEASE_OWNER = "KMTechn"
DEFAULT_RELEASE_REPO = "Container_Audit"
UPDATE_PROVIDER_ENV = "CONTAINER_AUDIT_UPDATE_PROVIDER"
UPDATE_MANIFEST_URL_ENV = "CONTAINER_AUDIT_UPDATE_MANIFEST_URL"
UPDATE_MANIFEST_SIGNATURE_URL_ENV = "CONTAINER_AUDIT_UPDATE_MANIFEST_SIGNATURE_URL"
UPDATE_MANIFEST_PUBLIC_KEY_ENV = "CONTAINER_AUDIT_UPDATE_MANIFEST_PUBLIC_KEY"
UPDATE_CHANNEL_ENV = "CONTAINER_AUDIT_UPDATE_CHANNEL"
UPDATE_PROVIDER_OFF = "off"
UPDATE_PROVIDER_GITHUB = "github"
UPDATE_PROVIDER_PRIVATE_MANIFEST = "private_manifest"
UPDATE_MANIFEST_SCHEMA_VERSION = "kmtech-private-update-manifest-v1"
UPDATE_MANIFEST_VERSION = 1
UPDATE_DEFAULT_CHANNEL = "stable"
UPDATE_APP_ID = "Container_Audit"
UPDATE_PC_ID_ENV = "CONTAINER_AUDIT_UPDATE_PC_ID"
UPDATE_ALLOWED_INSTALL_STRATEGIES = {"manual", "robocopy_backup_then_mirror", "replace_exe", "none"}
UPDATE_SECRET_QUERY_KEYS = {
    "access_token",
    "api_key",
    "client_secret",
    "github_token",
    "pat",
    "private_key",
    "sig",
    "signature",
    "token",
}
UPDATE_SECRET_QUERY_PREFIXES = ("x_amz_", "x_goog_")
DIRECT_GITHUB_ARTIFACT_HOSTS = frozenset(
    {
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
GITHUB_UPDATE_HOSTS = frozenset({"api.github.com", "github.com", "www.github.com"})


def parse_version_tag(version: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(version).strip(), flags=re.IGNORECASE)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_newer_version(latest_version: str, current_version: str) -> bool:
    latest_parts = parse_version_tag(latest_version)
    current_parts = parse_version_tag(current_version)
    if latest_parts is None or current_parts is None:
        return False
    return latest_parts > current_parts


def validate_release_asset_url(
    url: str,
    *,
    owner: str = "",
    repo: str = "",
    tag: str = "",
    asset_name: str = "",
) -> str:
    text = str(url or "").strip()
    parsed = urlparse(text)
    if parsed.scheme.lower() != "https":
        raise ValueError("릴리스 asset URL은 HTTPS여야 합니다.")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("릴리스 asset URL에 호스트가 없습니다.")
    if parsed.username or parsed.password:
        raise ValueError("릴리스 asset URL에 사용자 정보가 포함될 수 없습니다.")
    if parsed.fragment:
        raise ValueError("릴리스 asset URL에 fragment가 포함될 수 없습니다.")
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.lower().replace("-", "_")
        if normalized_key in UPDATE_SECRET_QUERY_KEYS or normalized_key.startswith(UPDATE_SECRET_QUERY_PREFIXES):
            raise ValueError("릴리스 asset URL에 장기 인증 토큰을 직접 포함할 수 없습니다.")
    host = parsed.hostname.lower()
    if host not in ALLOWED_RELEASE_ASSET_HOSTS:
        raise ValueError("릴리스 asset URL은 GitHub 릴리스 다운로드 호스트여야 합니다.")
    if host == "github.com" and "/releases/download/" not in parsed.path:
        raise ValueError("GitHub 릴리스 asset URL 형식이 올바르지 않습니다.")
    strict_parts = [str(part or "").strip() for part in (owner, repo, tag, asset_name)]
    if any(strict_parts):
        if not all(strict_parts):
            raise ValueError("릴리스 asset URL strict 검증에는 owner, repo, tag, asset_name이 모두 필요합니다.")
        if host != "github.com":
            raise ValueError("릴리스 browser_download_url은 github.com 릴리스 asset URL이어야 합니다.")
        path_parts = [unquote(part) for part in parsed.path.strip("/").split("/")]
        expected_parts = [strict_parts[0], strict_parts[1], "releases", "download", strict_parts[2], strict_parts[3]]
        if path_parts != expected_parts:
            raise ValueError("GitHub 릴리스 asset URL이 기대한 저장소, 태그 또는 파일명과 일치하지 않습니다.")
    return text


def assert_https_update_url(url: str, *, require_zip: bool = False) -> str:
    text = str(url or "").strip()
    parsed = urlparse(text)
    if parsed.scheme.lower() != "https" or not parsed.netloc or not parsed.hostname:
        raise ValueError("업데이트 URL은 HTTPS 절대 URL이어야 합니다.")
    if parsed.username or parsed.password:
        raise ValueError("업데이트 URL에 사용자 정보를 포함할 수 없습니다.")
    if parsed.fragment:
        raise ValueError("업데이트 URL에 fragment가 포함될 수 없습니다.")
    if require_zip and not parsed.path.lower().endswith(".zip"):
        raise ValueError("업데이트 artifact URL은 ZIP 파일이어야 합니다.")
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.lower().replace("-", "_")
        if normalized_key in UPDATE_SECRET_QUERY_KEYS or normalized_key.startswith(UPDATE_SECRET_QUERY_PREFIXES):
            raise ValueError("업데이트 URL에 장기 인증 토큰을 직접 포함할 수 없습니다.")
    return text


def is_direct_github_artifact_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if host in {"github.com", "www.github.com"} and "/releases/download/" in path:
        return True
    if host == "api.github.com" and "/releases/assets/" in path:
        return True
    return host in DIRECT_GITHUB_ARTIFACT_HOSTS


def is_github_hosted_update_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    return host in GITHUB_UPDATE_HOSTS or host.endswith(".githubusercontent.com")


def validate_relative_manifest_path(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"업데이트 manifest {field_name}은 비어 있지 않은 상대 경로여야 합니다.")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"업데이트 manifest {field_name}은 상대 경로여야 합니다.")
    if any(part in {"", ".", ".."} or ":" in part for part in normalized.split("/")):
        raise ValueError(f"업데이트 manifest {field_name}에 안전하지 않은 경로가 포함되어 있습니다.")


def canonical_update_pc_id() -> str:
    pc_id = os.environ.get(UPDATE_PC_ID_ENV) or os.environ.get("COMPUTERNAME") or socket.gethostname()
    text = str(pc_id or "").strip().lower()
    if not text:
        raise ValueError("업데이트 rollout에는 PC ID가 필요합니다.")
    return text


def rollout_bucket(app_id: str, channel: str, version: str, pc_id: str) -> int:
    seed = f"{app_id}|{channel.lower()}|{version}|{pc_id.strip().lower()}".encode("utf-8")
    return int(hashlib.sha256(seed).hexdigest()[:8], 16) % 100


def rollout_allows_current_pc(manifest: Mapping[str, Any]) -> bool:
    rollout = manifest.get("rollout")
    if not isinstance(rollout, Mapping):
        raise ValueError("업데이트 manifest rollout이 올바르지 않습니다.")
    for key in ("allow_pc_ids", "deny_pc_ids"):
        values = rollout.get(key)
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError(f"업데이트 manifest rollout.{key}는 문자열 목록이어야 합니다.")
    percentage = rollout.get("percentage")
    if type(percentage) is not int or not 0 <= percentage <= 100:
        raise ValueError("업데이트 manifest rollout.percentage 값이 올바르지 않습니다.")
    pc_id = canonical_update_pc_id()
    deny_pc_ids = {item.strip().lower() for item in rollout["deny_pc_ids"] if item.strip()}
    allow_pc_ids = {item.strip().lower() for item in rollout["allow_pc_ids"] if item.strip()}
    if pc_id in deny_pc_ids:
        return False
    if pc_id in allow_pc_ids:
        return True
    if percentage == 0:
        return False
    if percentage == 100:
        return True
    return rollout_bucket(str(manifest["app_id"]), str(manifest["channel"]), str(manifest["version"]), pc_id) < percentage


def release_asset_name_from_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    path_parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    return path_parts[-1] if path_parts else ""


def _version_from_zip_asset_name(name: str) -> str:
    match = re.fullmatch(r"Container_Audit-(v?\d+\.\d+\.\d+)\.zip", str(name or ""), flags=re.IGNORECASE)
    return match.group(1) if match else ""


def find_release_asset_urls(
    latest_release_data: Mapping[str, Any],
    expected_version: str = "",
) -> tuple[str | None, str | None]:
    zip_assets: list[Mapping[str, Any]] = []
    checksum_assets: dict[str, str] = {}
    for asset in latest_release_data.get("assets", []):
        if not isinstance(asset, Mapping):
            continue
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if not name or not url:
            continue
        try:
            url = validate_release_asset_url(url)
        except ValueError:
            continue
        if name.endswith(".zip"):
            zip_assets.append({**asset, "browser_download_url": url})
        elif name.endswith(".sha256"):
            checksum_assets[name] = url
    if expected_version:
        expected_zip_name = f"Container_Audit-{str(expected_version).strip()}.zip"
        matching_zip_assets = [asset for asset in zip_assets if str(asset.get("name") or "") == expected_zip_name]
        if len(matching_zip_assets) != 1:
            return None, None
        zip_asset = matching_zip_assets[0]
    elif len(zip_assets) == 1:
        zip_asset = zip_assets[0]
    else:
        return None, None
    zip_name = str(zip_asset.get("name") or "")
    release_tag = str(expected_version or "").strip() or _version_from_zip_asset_name(zip_name)
    checksum_name = f"{zip_name}.sha256"
    checksum_url = checksum_assets.get(checksum_name)
    if not release_tag or not checksum_url:
        return None, None
    try:
        zip_url = validate_release_asset_url(
            str(zip_asset.get("browser_download_url") or ""),
            owner=DEFAULT_RELEASE_OWNER,
            repo=DEFAULT_RELEASE_REPO,
            tag=release_tag,
            asset_name=zip_name,
        )
        checksum_url = validate_release_asset_url(
            checksum_url,
            owner=DEFAULT_RELEASE_OWNER,
            repo=DEFAULT_RELEASE_REPO,
            tag=release_tag,
            asset_name=checksum_name,
        )
    except ValueError:
        return None, None
    return zip_url, checksum_url


def sha256_from_release_asset_digest(asset: Mapping[str, Any]) -> str:
    digest = str(asset.get("digest") or "").strip().lower()
    prefix = "sha256:"
    if digest.startswith(prefix) and re.fullmatch(r"[a-f0-9]{64}", digest[len(prefix):]):
        return digest[len(prefix):]
    return ""


def find_release_asset_update_info(
    latest_release_data: Mapping[str, Any],
    expected_version: str = "",
) -> dict[str, str] | None:
    zip_assets: list[Mapping[str, Any]] = []
    checksum_assets: dict[str, str] = {}
    for asset in latest_release_data.get("assets", []):
        if not isinstance(asset, Mapping):
            continue
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if not name or not url:
            continue
        try:
            url = validate_release_asset_url(url)
        except ValueError:
            continue
        if name.endswith(".zip"):
            zip_assets.append({**asset, "browser_download_url": url})
        elif name.endswith(".sha256"):
            checksum_assets[name] = url

    if expected_version:
        expected_zip_name = f"Container_Audit-{str(expected_version).strip()}.zip"
        matching_zip_assets = [asset for asset in zip_assets if str(asset.get("name") or "") == expected_zip_name]
        if len(matching_zip_assets) != 1:
            return None
        zip_asset = matching_zip_assets[0]
    elif len(zip_assets) == 1:
        zip_asset = zip_assets[0]
    else:
        return None

    zip_name = str(zip_asset.get("name") or "")
    release_tag = str(expected_version or "").strip() or _version_from_zip_asset_name(zip_name)
    checksum_name = f"{zip_name}.sha256"
    checksum_url = checksum_assets.get(checksum_name, "")
    if not release_tag:
        return None
    try:
        zip_url = validate_release_asset_url(
            str(zip_asset.get("browser_download_url") or ""),
            owner=DEFAULT_RELEASE_OWNER,
            repo=DEFAULT_RELEASE_REPO,
            tag=release_tag,
            asset_name=zip_name,
        )
        if checksum_url:
            checksum_url = validate_release_asset_url(
                checksum_url,
                owner=DEFAULT_RELEASE_OWNER,
                repo=DEFAULT_RELEASE_REPO,
                tag=release_tag,
                asset_name=checksum_name,
            )
    except ValueError:
        return None

    expected_sha256 = sha256_from_release_asset_digest(zip_asset)
    if not expected_sha256 and not checksum_url:
        return None
    return {
        "download_url": zip_url,
        "checksum_url": checksum_url,
        "sha256": expected_sha256,
    }


def _plain_checksum_filename(filename: str) -> bool:
    text = str(filename or "")
    return bool(text) and "/" not in text and "\\" not in text and text not in {".", ".."}


def parse_sha256_checksum(checksum_text: str, *, expected_filename: str = "") -> str:
    expected = str(expected_filename or "").strip()
    matches: list[str] = []
    hash_line_count = 0
    for raw_line in str(checksum_text or "").splitlines():
        parts = raw_line.strip().split()
        if not parts:
            continue
        digest = parts[0]
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", digest):
            continue
        hash_line_count += 1
        if not expected:
            matches.append(digest.lower())
            continue
        if len(parts) != 2:
            continue
        filename = parts[1].lstrip("*")
        if _plain_checksum_filename(filename) and filename == expected:
            matches.append(digest.lower())
    if expected and hash_line_count != 1:
        raise ValueError("릴리스 SHA256 체크섬은 기대한 ZIP 파일명에 대한 단일 항목이어야 합니다.")
    if len(matches) == 1:
        return matches[0]
    raise ValueError("릴리스 SHA256 체크섬 형식이 올바르지 않습니다.")


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sha256(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Fa-f0-9]{64}", value.strip()) is not None


def verify_update_file_hash(path: str | Path, expected_sha256: str) -> None:
    if not is_sha256(str(expected_sha256 or "").strip()):
        raise ValueError("업데이트 ZIP SHA256 검증에는 64자 예상 해시가 필요합니다.")
    actual = file_sha256(path)
    if actual.lower() != str(expected_sha256).strip().lower():
        raise ValueError("업데이트 ZIP SHA256 체크섬이 일치하지 않습니다.")


def verify_update_checksum(zip_path: str | Path, checksum_text: str, *, expected_filename: str = "") -> None:
    expected = parse_sha256_checksum(checksum_text, expected_filename=expected_filename or Path(zip_path).name)
    actual = file_sha256(zip_path)
    if actual.lower() != expected:
        raise ValueError("업데이트 ZIP SHA256 체크섬이 일치하지 않습니다.")


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_update_manifest_signature(manifest: Mapping[str, Any], signature: bytes, public_key_hex: str) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValueError("cryptography가 업데이트 manifest 서명 검증에 필요합니다.") from exc
    try:
        public_key = bytes.fromhex(str(public_key_hex or "").strip())
    except ValueError as exc:
        raise ValueError("업데이트 manifest 공개키 형식이 올바르지 않습니다.") from exc
    if len(public_key) != 32:
        raise ValueError("업데이트 manifest 공개키 길이가 올바르지 않습니다.")
    if len(signature) != 64:
        raise ValueError("업데이트 manifest 서명 길이가 올바르지 않습니다.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            canonical_manifest_bytes(manifest),
        )
    except InvalidSignature as exc:
        raise ValueError("업데이트 manifest 서명 검증에 실패했습니다.") from exc


def archive_policy_from_manifest(archive: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "top_level": archive.get("top_level"),
        "required_files": list(archive.get("required_files") or []),
    }


def update_candidate_from_private_manifest(
    manifest: Mapping[str, Any],
    *,
    current_version: str,
    expected_channel: str = UPDATE_DEFAULT_CHANNEL,
) -> dict[str, Any] | None:
    if manifest.get("schema_version") != UPDATE_MANIFEST_SCHEMA_VERSION:
        raise ValueError("지원하지 않는 업데이트 manifest 형식입니다.")
    if manifest.get("manifest_version") != UPDATE_MANIFEST_VERSION:
        raise ValueError("지원하지 않는 업데이트 manifest 버전입니다.")
    if manifest.get("app_id") != UPDATE_APP_ID:
        raise ValueError("다른 프로그램용 업데이트 manifest입니다.")
    if manifest.get("package_id") != UPDATE_APP_ID:
        raise ValueError("업데이트 manifest package_id가 일치하지 않습니다.")
    manifest_channel = str(manifest.get("channel") or "").strip().lower()
    if not manifest_channel:
        raise ValueError("업데이트 manifest channel이 비어 있습니다.")
    if manifest_channel != str(expected_channel or UPDATE_DEFAULT_CHANNEL).strip().lower():
        return None
    latest_version = str(manifest.get("version") or "").strip()
    if not parse_version_tag(latest_version):
        raise ValueError("업데이트 manifest version 형식이 올바르지 않습니다.")
    if not is_newer_version(latest_version, current_version):
        return None

    artifact = manifest.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ValueError("업데이트 manifest artifact가 올바르지 않습니다.")
    artifact_name = str(artifact.get("name") or "").strip()
    expected_name = f"{UPDATE_APP_ID}-{latest_version}.zip"
    if artifact_name != expected_name:
        raise ValueError("업데이트 manifest artifact 이름이 릴리스 버전과 일치하지 않습니다.")
    if type(artifact.get("size_bytes")) is not int or artifact["size_bytes"] < 1:
        raise ValueError("업데이트 manifest artifact.size_bytes 값이 올바르지 않습니다.")
    artifact_url = assert_https_update_url(str(artifact.get("url") or ""), require_zip=True)
    if is_github_hosted_update_url(artifact_url):
        raise ValueError("private manifest artifact URL은 GitHub-hosted 업데이트 저장소가 아니어야 합니다.")
    expected_sha256 = str(artifact.get("sha256") or "").strip().lower()
    if not is_sha256(expected_sha256):
        raise ValueError("업데이트 manifest artifact.sha256 값이 올바르지 않습니다.")

    archive = manifest.get("archive")
    if not isinstance(archive, Mapping):
        raise ValueError("업데이트 manifest archive가 올바르지 않습니다.")
    if archive.get("format") != "zip":
        raise ValueError("업데이트 manifest archive.format은 zip이어야 합니다.")
    validate_relative_manifest_path(str(archive.get("entrypoint") or ""), "archive.entrypoint")
    required_files = archive.get("required_files")
    if not isinstance(required_files, list) or not required_files or not all(isinstance(item, str) for item in required_files):
        raise ValueError("업데이트 manifest archive.required_files가 올바르지 않습니다.")
    for item in required_files:
        validate_relative_manifest_path(item, "archive.required_files[]")
    if archive.get("top_level") is not None:
        validate_relative_manifest_path(str(archive.get("top_level") or ""), "archive.top_level")

    install = manifest.get("install")
    if not isinstance(install, Mapping):
        raise ValueError("업데이트 manifest install이 올바르지 않습니다.")
    if install.get("strategy") not in UPDATE_ALLOWED_INSTALL_STRATEGIES:
        raise ValueError("업데이트 manifest install.strategy가 올바르지 않습니다.")
    preserve_paths = install.get("preserve_paths", [])
    if not isinstance(preserve_paths, list) or not all(isinstance(item, str) for item in preserve_paths):
        raise ValueError("업데이트 manifest install.preserve_paths가 올바르지 않습니다.")
    for item in preserve_paths:
        validate_relative_manifest_path(item, "install.preserve_paths[]")

    if not rollout_allows_current_pc(manifest):
        return None
    return {
        "download_url": artifact_url,
        "version": latest_version,
        "sha256": expected_sha256,
        "provider": UPDATE_PROVIDER_PRIVATE_MANIFEST,
        "archive_policy": archive_policy_from_manifest(archive),
    }


def _normalized_archive_path(member_name: str) -> str:
    return str(member_name or "").replace("\\", "/").rstrip("/").casefold()


def _validate_archive_path_collisions(file_names: list[str]) -> None:
    normalized_seen: set[str] = set()
    normalized_files: set[str] = set()
    normalized_entries: set[str] = set()
    for name in file_names:
        normalized = _normalized_archive_path(name)
        if not normalized:
            continue
        if normalized in normalized_seen:
            raise ValueError("업데이트 ZIP에 중복 경로가 포함되어 있습니다.")
        normalized_seen.add(normalized)
        normalized_entries.add(normalized)
        if not name.endswith("/"):
            normalized_files.add(normalized)

    for file_path in normalized_files:
        prefix = f"{file_path}/"
        if any(entry.startswith(prefix) for entry in normalized_entries):
            raise ValueError("업데이트 ZIP에 파일/폴더 경로 충돌이 포함되어 있습니다.")


def _runtime_local_archive_member_issue(member_name: str) -> str:
    normalized = str(member_name or "").replace("\\", "/").rstrip("/")
    if not normalized:
        return ""
    parts = [part for part in normalized.split("/") if part]
    lowered_parts = [part.casefold() for part in parts]
    for segment in lowered_parts[1:]:
        if segment in DENIED_UPDATE_ARCHIVE_PATH_SEGMENTS:
            return f"runtime-local path segment is not allowed: {segment}"
    basename = lowered_parts[-1] if lowered_parts else ""
    if basename in DENIED_UPDATE_ARCHIVE_BASENAMES:
        return f"runtime-local file is not allowed: {basename}"
    if any(basename.endswith(suffix) for suffix in DENIED_UPDATE_ARCHIVE_FILE_SUFFIXES):
        return f"runtime-local file suffix is not allowed: {basename}"
    original_basename = parts[-1] if parts else ""
    if any(pattern.fullmatch(original_basename) for pattern in DENIED_UPDATE_ARCHIVE_BASENAME_PATTERNS):
        return f"runtime-local file pattern is not allowed: {original_basename}"
    return ""


def _validate_update_archive_runtime_local_denylist(file_names: list[str]) -> None:
    denied = []
    for name in file_names:
        issue = _runtime_local_archive_member_issue(name)
        if issue:
            denied.append(f"{name} ({issue})")
    if denied:
        raise ValueError("업데이트 ZIP에 현장 런타임/민감 상태 파일이 포함되어 있습니다: " + ", ".join(denied[:5]))


def validate_update_archive_layout(members: list[str], archive_policy: Mapping[str, Any] | None = None) -> None:
    file_names = [str(member or "").replace("\\", "/") for member in members if str(member or "").strip()]
    if not file_names:
        raise ValueError("업데이트 ZIP이 비어 있습니다.")
    _validate_archive_path_collisions(file_names)
    _validate_update_archive_runtime_local_denylist(file_names)
    top_level = {name.split("/", 1)[0] for name in file_names}
    if top_level != {"Container_Audit"}:
        raise ValueError("업데이트 ZIP은 최상위 Container_Audit 폴더 하나만 포함해야 합니다.")
    present_files = {name.rstrip("/") for name in file_names if not name.endswith("/")}
    missing = sorted(REQUIRED_UPDATE_ARCHIVE_FILES - present_files)
    if missing:
        raise ValueError("업데이트 ZIP에 필수 파일이 없습니다: " + ", ".join(missing))
    if archive_policy:
        policy_top_level = str(archive_policy.get("top_level") or "").replace("\\", "/").rstrip("/")
        if policy_top_level and top_level != {policy_top_level}:
            raise ValueError("업데이트 ZIP이 manifest archive.top_level과 일치하지 않습니다.")
        policy_required = {
            str(item or "").replace("\\", "/").rstrip("/")
            for item in archive_policy.get("required_files") or []
        }
        policy_missing = sorted(item for item in policy_required if item and item not in present_files)
        if policy_missing:
            raise ValueError("업데이트 ZIP에 manifest 필수 파일이 없습니다: " + ", ".join(policy_missing))


def _is_zip_symlink(member: zipfile.ZipInfo) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_windows_archive_path(member_name: str) -> None:
    path = str(member_name or "").rstrip("/")
    for segment in path.split("/"):
        if not segment or segment in {".", ".."}:
            raise ValueError("업데이트 ZIP에 안전하지 않은 경로가 포함되어 있습니다.")
        if ":" in segment or any(ord(char) < 32 for char in segment):
            raise ValueError("업데이트 ZIP에 안전하지 않은 Windows 파일명이 포함되어 있습니다.")
        if segment.endswith((" ", ".")):
            raise ValueError("업데이트 ZIP에 안전하지 않은 Windows 파일명이 포함되어 있습니다.")
        reserved_base = segment.split(".", 1)[0].upper()
        if reserved_base in WINDOWS_RESERVED_NAMES:
            raise ValueError("업데이트 ZIP에 안전하지 않은 Windows 파일명이 포함되어 있습니다.")


def safe_extract_update_zip(
    zip_path: str | Path,
    destination: str | Path,
    *,
    max_entries: int = DEFAULT_MAX_UPDATE_ARCHIVE_ENTRIES,
    max_member_size: int = DEFAULT_MAX_UPDATE_ARCHIVE_MEMBER_BYTES,
    max_total_uncompressed_size: int = DEFAULT_MAX_UPDATE_ARCHIVE_TOTAL_BYTES,
    archive_policy: Mapping[str, Any] | None = None,
) -> Path:
    destination_path = Path(destination).resolve()
    destination_path.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        member_names: list[str] = []
        members = zip_ref.infolist()
        if len(members) > max_entries:
            raise ValueError("업데이트 ZIP에 너무 많은 항목이 포함되어 있습니다.")
        total_uncompressed_size = 0
        for member in members:
            member_name = str(member.filename or "")
            if not member_name or "\\" in member_name:
                raise ValueError("업데이트 ZIP에 안전하지 않은 경로가 포함되어 있습니다.")
            _validate_windows_archive_path(member_name)
            if _is_zip_symlink(member):
                raise ValueError("업데이트 ZIP에 지원하지 않는 링크 항목이 포함되어 있습니다.")
            if member.file_size > max_member_size:
                raise ValueError("업데이트 ZIP에 허용 크기를 초과한 파일이 포함되어 있습니다.")
            total_uncompressed_size += member.file_size
            if total_uncompressed_size > max_total_uncompressed_size:
                raise ValueError("업데이트 ZIP 압축 해제 크기가 허용 한도를 초과했습니다.")
            target_path = (destination_path / member_name).resolve()
            if not target_path.is_relative_to(destination_path):
                raise ValueError("업데이트 ZIP에 안전하지 않은 경로가 포함되어 있습니다.")
            member_names.append(member_name)
        validate_update_archive_layout(member_names, archive_policy=archive_policy)
        zip_ref.extractall(destination_path)
    return destination_path
