from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlparse
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
        "Container_Audit/direct_sync_push.py",
        "Container_Audit/direct_sync_runtime.py",
        "Container_Audit/direct_sync_operator.py",
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


def verify_update_checksum(zip_path: str | Path, checksum_text: str, *, expected_filename: str = "") -> None:
    expected = parse_sha256_checksum(checksum_text, expected_filename=expected_filename or Path(zip_path).name)
    actual = file_sha256(zip_path)
    if actual.lower() != expected:
        raise ValueError("업데이트 ZIP SHA256 체크섬이 일치하지 않습니다.")


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


def validate_update_archive_layout(members: list[str]) -> None:
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
        validate_update_archive_layout(member_names)
        zip_ref.extractall(destination_path)
    return destination_path
