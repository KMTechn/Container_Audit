import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import csv
import datetime
import os
import sys
import threading
import time
import json
import re
from typing import List, Dict, Optional, Any
from PIL import Image, ImageTk
from dataclasses import dataclass, field
import queue
import pygame
import uuid
import requests
import subprocess
import random
import tempfile
import shutil
from pathlib import Path

from container_audit_test_harness import parse_internal_test_command
from best_time_records import BestTimeRecordStore
from direct_sync_auto_bootstrap import start_direct_sync_auto_bootstrap, start_session_direct_sync
from event_contracts import plan_b_event_detail, stable_hash
from event_log_store import append_event_log_entry
from event_payloads import (
    build_master_label_replacement_detail,
    build_scan_ok_detail,
    build_tray_complete_detail,
    product_barcodes_from_completion,
)
from item_catalog import ItemCatalog
from label_qr import (
    canonical_master_label_key,
    inspection_master_item_code,
    normalize_master_label_input,
    parse_new_format_qr,
    parse_positive_quantity,
)
from parked_tray_store import ParkedTrayStore, sanitize_filename
from product_scan import SCAN_DUPLICATE, SCAN_FORMAT_ERROR, SCAN_MISMATCH, SCAN_TRAY_FULL, decide_product_scan
from product_exchange import (
    ProductExchangeSession,
    apply_exchange_scan,
    build_exchange_completion_detail,
    build_exchange_pairs,
    validate_exchange_completion,
)
from replacement_log_lookup import collect_replacement_superseded_hashes, find_replacement_source_entry, replacement_log_file_paths
from replacement_workflow import (
    REPLACEMENT_AWAIT_ADDITIONAL,
    REPLACEMENT_AWAIT_REMOVED,
    REPLACEMENT_FINALIZE,
    REPLACEMENT_REJECT_ITEM_CODE,
    REPLACEMENT_REJECT_NEW_QTY,
    REPLACEMENT_REJECT_OLD_QTY,
    compare_replacement_quantities,
)
from session_history import load_session_history
from storage_policy import build_container_audit_storage_paths, ensure_container_audit_storage_dirs
from storage_utils import atomic_write_json
from tray_state import (
    TrayStateValidationError,
    quarantine_tray_state_file,
    tray_session_from_state,
    tray_session_to_state,
    validate_tray_state,
)
from update_service import (
    UPDATE_CHANNEL_ENV,
    UPDATE_DEFAULT_CHANNEL,
    UPDATE_MANIFEST_PUBLIC_KEY_ENV,
    UPDATE_MANIFEST_SIGNATURE_URL_ENV,
    UPDATE_MANIFEST_URL_ENV,
    UPDATE_PROVIDER_ENV,
    UPDATE_PROVIDER_GITHUB,
    UPDATE_PROVIDER_OFF,
    UPDATE_PROVIDER_PRIVATE_MANIFEST,
    assert_https_update_url,
    find_release_asset_update_info,
    find_release_asset_urls,
    is_github_hosted_update_url,
    is_sha256,
    is_newer_version,
    parse_sha256_checksum,
    parse_version_tag,
    release_asset_name_from_url,
    safe_extract_update_zip,
    update_candidate_from_private_manifest,
    validate_release_asset_url,
    verify_update_file_hash,
    verify_update_checksum,
    verify_update_manifest_signature,
)
from worker_registry import WorkerRegistry

# ####################################################################
# # 자동 업데이트 기능
# ####################################################################
REPO_OWNER = "KMTechn"
REPO_NAME = "Container_Audit"
CURRENT_VERSION = "v2.0.26"
MAX_UPDATE_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_UPDATE_CHECKSUM_BYTES = 64 * 1024
UPDATER_BATCH_UNSAFE_CHARS = set('%"&|<>^\r\n')

def _parse_version_tag(version: str) -> Optional[tuple[int, int, int]]:
    return parse_version_tag(version)

def _is_newer_version(latest_version: str, current_version: str) -> bool:
    return is_newer_version(latest_version, current_version)


def _safe_int_mapping(value: Any) -> Dict[str, int]:
    if not isinstance(value, dict):
        return {}
    safe: Dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            continue
        safe[key] = item
    return safe


def normalize_update_settings(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    normalized: Dict[str, str] = {}
    for key in ("provider", "manifest_url", "manifest_signature_url", "manifest_public_key", "channel"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            normalized[key] = value.strip()
    return normalized


def normalize_app_settings(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    settings: Dict[str, Any] = {}
    scale_factor = raw.get("scale_factor")
    if isinstance(scale_factor, (int, float)) and not isinstance(scale_factor, bool):
        settings["scale_factor"] = max(0.7, min(2.5, float(scale_factor)))
    column_widths = _safe_int_mapping(raw.get("column_widths_validator"))
    if column_widths:
        settings["column_widths_validator"] = column_widths
    sash_positions = _safe_int_mapping(raw.get("paned_window_sash_positions"))
    if sash_positions:
        settings["paned_window_sash_positions"] = sash_positions
    internal_test_commands = raw.get("enable_internal_test_commands")
    if isinstance(internal_test_commands, bool):
        settings["enable_internal_test_commands"] = internal_test_commands
    update_settings = normalize_update_settings(raw.get("update_settings"))
    if update_settings:
        settings["update_settings"] = update_settings
    return settings


def _release_runtime_mode() -> bool:
    return bool(getattr(sys, "frozen", False))


def _drop_release_disabled_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    if _release_runtime_mode():
        settings.pop("enable_internal_test_commands", None)
    return settings


def _find_release_asset_urls(
    latest_release_data: Dict[str, Any],
    expected_version: str = "",
) -> tuple[Optional[str], Optional[str]]:
    return find_release_asset_urls(latest_release_data, expected_version=expected_version)

def _verify_update_checksum(zip_path: str, checksum_text: str, *, expected_filename: str = "") -> None:
    verify_update_checksum(zip_path, checksum_text, expected_filename=expected_filename)


def _get_update_provider() -> str:
    settings = _load_update_settings()
    return str(os.environ.get(UPDATE_PROVIDER_ENV) or settings.get("provider") or UPDATE_PROVIDER_OFF).strip().lower()


def _get_update_channel() -> str:
    settings = _load_update_settings()
    return str(os.environ.get(UPDATE_CHANNEL_ENV) or settings.get("channel") or UPDATE_DEFAULT_CHANNEL).strip().lower()


def _update_settings_path() -> str:
    path_resolver = globals().get("resource_path")
    relative_path = os.path.join("config", "container_audit_settings.json")
    if callable(path_resolver):
        return path_resolver(relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


def _load_update_settings() -> Dict[str, str]:
    try:
        with open(_update_settings_path(), "r", encoding="utf-8") as handle:
            return normalize_update_settings(json.load(handle).get("update_settings"))
    except Exception:
        return {}


def _get_update_manifest_url() -> str:
    settings = _load_update_settings()
    return str(os.environ.get(UPDATE_MANIFEST_URL_ENV) or settings.get("manifest_url") or "").strip()


def _get_update_manifest_signature_url(manifest_url: str) -> str:
    settings = _load_update_settings()
    return str(os.environ.get(UPDATE_MANIFEST_SIGNATURE_URL_ENV) or settings.get("manifest_signature_url") or "").strip() or f"{manifest_url}.sig"


def _get_update_manifest_public_key() -> str:
    settings = _load_update_settings()
    return str(os.environ.get(UPDATE_MANIFEST_PUBLIC_KEY_ENV) or settings.get("manifest_public_key") or "").strip()


def _check_github_release_for_updates() -> Optional[Dict[str, str]]:
    api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
    response = requests.get(api_url, timeout=5)
    response.raise_for_status()
    latest_release_data = response.json()
    if not isinstance(latest_release_data, dict):
        raise ValueError("GitHub latest release 응답 형식이 올바르지 않습니다.")
    latest_version = str(latest_release_data.get('tag_name') or "").strip()
    if not latest_version:
        raise ValueError("GitHub latest release tag_name이 없습니다.")
    if not _is_newer_version(latest_version, CURRENT_VERSION):
        return None
    update_info = find_release_asset_update_info(latest_release_data, expected_version=latest_version)
    if update_info:
        expected_sha256 = str(update_info.get("sha256") or "").strip().lower()
        checksum_url = str(update_info.get("checksum_url") or "").strip()
        if not expected_sha256 and checksum_url:
            checksum_response = requests.get(checksum_url, stream=True, timeout=30)
            checksum_response.raise_for_status()
            checksum_text = _read_update_checksum_response(checksum_response)
            expected_sha256 = parse_sha256_checksum(
                checksum_text,
                expected_filename=release_asset_name_from_url(update_info["download_url"]),
            )
            checksum_url = ""
        if not is_sha256(expected_sha256):
            return None
        return {
            "download_url": update_info["download_url"],
            "version": latest_version,
            "checksum_url": checksum_url,
            "sha256": expected_sha256,
            "provider": UPDATE_PROVIDER_GITHUB,
        }
    download_url, checksum_url = _find_release_asset_urls(latest_release_data, expected_version=latest_version)
    if download_url:
        print("업데이트 확인 중 오류 발생: SHA256 체크섬 asset 또는 GitHub asset digest를 찾을 수 없습니다.")
    return None


def _check_private_manifest_for_updates() -> Optional[Dict[str, Any]]:
    manifest_url = _get_update_manifest_url()
    if not manifest_url:
        print(f"업데이트 확인 생략: {UPDATE_MANIFEST_URL_ENV} 환경변수가 설정되지 않았습니다.")
        return None
    public_key_hex = _get_update_manifest_public_key()
    if not public_key_hex:
        raise ValueError("private_manifest updater requires a manifest public key")
    assert_https_update_url(manifest_url)
    if is_github_hosted_update_url(manifest_url):
        raise ValueError("private_manifest updater manifest URL must not point to GitHub-hosted update storage")
    response = requests.get(manifest_url, timeout=5)
    response.raise_for_status()
    manifest = response.json()
    if not isinstance(manifest, dict):
        raise ValueError("업데이트 manifest 응답 형식이 올바르지 않습니다.")
    signature_url = _get_update_manifest_signature_url(manifest_url)
    assert_https_update_url(signature_url)
    if is_github_hosted_update_url(signature_url):
        raise ValueError("private_manifest updater signature URL must not point to GitHub-hosted update storage")
    signature_response = requests.get(signature_url, timeout=5)
    signature_response.raise_for_status()
    verify_update_manifest_signature(manifest, signature_response.content, public_key_hex)
    return update_candidate_from_private_manifest(
        manifest,
        current_version=CURRENT_VERSION,
        expected_channel=_get_update_channel(),
    )


def _check_update_candidate() -> Optional[Dict[str, Any]]:
    provider = _get_update_provider()
    if provider in {"", UPDATE_PROVIDER_OFF, "disabled", "none"}:
        return None
    if provider in {"private", "manifest", UPDATE_PROVIDER_PRIVATE_MANIFEST}:
        return _check_private_manifest_for_updates()
    if provider == UPDATE_PROVIDER_GITHUB:
        return _check_github_release_for_updates()
    raise ValueError(f"지원하지 않는 업데이트 provider입니다: {provider}")


def _safe_check_update_candidate() -> Optional[Dict[str, Any]]:
    try:
        return _check_update_candidate()
    except (requests.exceptions.RequestException, ValueError, TypeError) as e:
        print(f"업데이트 확인 중 오류 발생: {e}")
        return None


def _validate_updater_batch_value(name: str, value: str) -> str:
    text = str(value or "")
    if not text:
        raise ValueError(f"업데이트 스크립트 {name} 값이 비어 있습니다.")
    if any(char in UPDATER_BATCH_UNSAFE_CHARS for char in text):
        raise ValueError(f"업데이트 스크립트 {name} 값에 안전하지 않은 배치 문자가 포함되어 있습니다.")
    return text


def _write_update_download(response: Any, zip_path: str, *, max_bytes: int = MAX_UPDATE_DOWNLOAD_BYTES) -> None:
    content_length = str(getattr(response, "headers", {}).get("Content-Length") or "").strip()
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise ValueError("업데이트 ZIP 다운로드 크기가 허용 한도를 초과했습니다.")
        except ValueError as exc:
            if "허용 한도" in str(exc):
                raise
    bytes_written = 0
    try:
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    raise ValueError("업데이트 ZIP 다운로드 크기가 허용 한도를 초과했습니다.")
                f.write(chunk)
    except Exception:
        try:
            os.remove(zip_path)
        except OSError:
            pass
        raise


def _read_update_checksum_response(response: Any, *, max_bytes: int = MAX_UPDATE_CHECKSUM_BYTES) -> str:
    content_length = str(getattr(response, "headers", {}).get("Content-Length") or "").strip()
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise ValueError("업데이트 SHA256 체크섬 크기가 허용 한도를 초과했습니다.")
        except ValueError as exc:
            if "허용 한도" in str(exc):
                raise
    chunks: list[bytes] = []
    bytes_read = 0
    for chunk in response.iter_content(chunk_size=4096):
        if not chunk:
            continue
        bytes_read += len(chunk)
        if bytes_read > max_bytes:
            raise ValueError("업데이트 SHA256 체크섬 크기가 허용 한도를 초과했습니다.")
        chunks.append(bytes(chunk))
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("업데이트 SHA256 체크섬 파일을 UTF-8로 읽을 수 없습니다.") from exc


def check_for_updates():
    """설정된 provider에서 최신 업데이트 후보를 확인합니다."""
    candidate = _safe_check_update_candidate()
    if not candidate:
        return None, None, None
    return candidate["download_url"], candidate["version"], candidate.get("checksum_url")

def download_and_apply_update(
    url,
    checksum_url=None,
    *,
    expected_sha256=None,
    archive_policy=None,
    allow_source_mode: bool = False,
):
    """업데이트 .zip 파일을 다운로드하고, 압축 해제 후 적용 스크립트를 실행합니다."""
    update_temp_root = ""
    updater_launched = False
    try:
        if not checksum_url and not expected_sha256:
            raise ValueError("업데이트 SHA256 체크섬 URL 또는 예상 해시가 필요합니다.")
        if expected_sha256 and not is_sha256(str(expected_sha256).strip()):
            raise ValueError("업데이트 SHA256 예상 해시 형식이 올바르지 않습니다.")
        if not allow_source_mode and not _release_runtime_mode():
            raise ValueError("소스 실행 모드에서는 자동 업데이트를 적용하지 않습니다.")
        download_url = assert_https_update_url(url, require_zip=True) if expected_sha256 else validate_release_asset_url(url)
        verified_checksum_url = validate_release_asset_url(checksum_url) if checksum_url else ""
        update_temp_root = tempfile.mkdtemp(prefix="container_audit_update_", dir=os.environ.get("TEMP", "C:\\Temp"))
        zip_path = os.path.join(update_temp_root, "update.zip")
        response = requests.get(download_url, stream=True, timeout=120)
        response.raise_for_status()
        _write_update_download(response, zip_path)
        if verified_checksum_url:
            checksum_response = requests.get(verified_checksum_url, stream=True, timeout=30)
            checksum_response.raise_for_status()
            checksum_text = _read_update_checksum_response(checksum_response)
            _verify_update_checksum(
                zip_path,
                checksum_text,
                expected_filename=release_asset_name_from_url(download_url),
            )
        else:
            verify_update_file_hash(zip_path, str(expected_sha256))
        temp_update_folder = os.path.join(update_temp_root, "extracted")
        safe_extract_update_zip(zip_path, temp_update_folder, archive_policy=archive_policy)
        os.remove(zip_path)
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        updater_script_path = os.path.join(update_temp_root, "updater.bat")
        extracted_content = os.listdir(temp_update_folder)
        if len(extracted_content) == 1 and os.path.isdir(os.path.join(temp_update_folder, extracted_content[0])):
            new_program_folder_path = os.path.join(temp_update_folder, extracted_content[0])
        else:
            new_program_folder_path = temp_update_folder
        with open(updater_script_path, "w", encoding='utf-8') as bat_file:
            bat_file.write(
                _build_updater_script(
                    executable_name=os.path.basename(sys.executable),
                    application_path=application_path,
                    new_program_folder_path=new_program_folder_path,
                    update_temp_root=update_temp_root,
                    current_pid=os.getpid(),
                )
            )
        subprocess.Popen([updater_script_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
        updater_launched = True
        sys.exit(0)
    except Exception as e:
        if update_temp_root and not updater_launched:
            shutil.rmtree(update_temp_root, ignore_errors=True)
        root_alert = tk.Tk()
        root_alert.withdraw()
        messagebox.showerror("업데이트 실패", f"업데이트 적용 중 오류가 발생했습니다.\n\n{e}\n\n프로그램을 다시 시작해주세요.", parent=root_alert)
        root_alert.destroy()


def _build_updater_script(
    *,
    executable_name: str,
    application_path: str,
    new_program_folder_path: str,
    update_temp_root: str,
    current_pid: int | None = None,
) -> str:
    executable_name = _validate_updater_batch_value("executable_name", executable_name)
    application_path = _validate_updater_batch_value("application_path", application_path)
    new_program_folder_path = _validate_updater_batch_value("new_program_folder_path", new_program_folder_path)
    update_temp_root = _validate_updater_batch_value("update_temp_root", update_temp_root)
    backup_path = os.path.join(update_temp_root, "backup")
    preserve_path = os.path.join(update_temp_root, "preserve_config")
    restart_path = os.path.join(application_path, executable_name)
    pid_to_stop = int(current_pid or os.getpid())
    return f"""@echo off
chcp 65001 > nul
set "APP_PATH={application_path}"
set "NEW_PATH={new_program_folder_path}"
set "BACKUP_PATH={backup_path}"
set "PRESERVE_PATH={preserve_path}"
set "UPDATE_TEMP_ROOT={update_temp_root}"
set "RESTART_PATH={restart_path}"
set "CURRENT_PID={pid_to_stop}"
echo.
echo ==========================================================
echo  프로그램을 업데이트합니다. 이 창을 닫지 마세요.
echo ==========================================================
echo.
echo 잠시 후 프로그램이 자동으로 종료됩니다...
timeout /t 3 /nobreak > nul
taskkill /F /PID %CURRENT_PID% > nul 2> nul
echo.
echo 기존 파일을 백업합니다...
if exist "%BACKUP_PATH%" rmdir /s /q "%BACKUP_PATH%"
robocopy "%APP_PATH%" "%BACKUP_PATH%" /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto BACKUP_FAILED
echo.
echo 로컬 설정을 보존합니다...
if exist "%PRESERVE_PATH%" rmdir /s /q "%PRESERVE_PATH%"
if exist "%APP_PATH%\\config\\container_audit_settings.json" robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "container_audit_settings.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto PRESERVE_FAILED
if exist "%APP_PATH%\\config\\worker_registry.json" robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "worker_registry.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto PRESERVE_FAILED
if exist "%APP_PATH%\\config\\best_time_records.json" robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "best_time_records.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto PRESERVE_FAILED
if exist "%APP_PATH%\\config\\parked_trays" robocopy "%APP_PATH%\\config\\parked_trays" "%PRESERVE_PATH%\\config\\parked_trays" /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto PRESERVE_FAILED
echo.
echo 새 파일로 교체합니다...
robocopy "%NEW_PATH%" "%APP_PATH%" /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK
echo.
echo 로컬 설정을 복원합니다...
if exist "%PRESERVE_PATH%\\config\\container_audit_settings.json" robocopy "%PRESERVE_PATH%\\config" "%APP_PATH%\\config" "container_audit_settings.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK
if exist "%PRESERVE_PATH%\\config\\worker_registry.json" robocopy "%PRESERVE_PATH%\\config" "%APP_PATH%\\config" "worker_registry.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK
if exist "%PRESERVE_PATH%\\config\\best_time_records.json" robocopy "%PRESERVE_PATH%\\config" "%APP_PATH%\\config" "best_time_records.json" /COPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK
if exist "%PRESERVE_PATH%\\config\\parked_trays" robocopy "%PRESERVE_PATH%\\config\\parked_trays" "%APP_PATH%\\config\\parked_trays" /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK
echo.
echo 임시 업데이트 파일을 삭제합니다...
rmdir /s /q "%UPDATE_TEMP_ROOT%"
echo.
echo ========================================
echo  업데이트 완료!
echo ========================================
echo.
echo 3초 후에 프로그램을 다시 시작합니다.
timeout /t 3 /nobreak > nul
start "" "%RESTART_PATH%"
del "%~f0"
exit /b 0

:ROLLBACK
echo.
echo 업데이트 파일 복사에 실패했습니다. 백업을 복원합니다...
robocopy "%BACKUP_PATH%" "%APP_PATH%" /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP > nul
if errorlevel 8 goto ROLLBACK_FAILED
echo 복원 작업이 끝났습니다. 프로그램을 직접 다시 실행해주세요.
pause
exit /b 1

:ROLLBACK_FAILED
echo.
echo 백업 복원에 실패했습니다. 백업 폴더를 확인해주세요: %BACKUP_PATH%
pause
exit /b 1

:PRESERVE_FAILED
echo.
echo 로컬 설정 보존에 실패해 업데이트를 중단합니다.
pause
exit /b 1

:BACKUP_FAILED
echo.
echo 기존 파일 백업에 실패해 업데이트를 중단합니다.
pause
exit /b 1
            """

def check_and_apply_updates():
    if not _release_runtime_mode():
        return
    candidate = _safe_check_update_candidate()
    if candidate:
        _prompt_and_apply_update(candidate)


def _prompt_and_apply_update(candidate, parent=None):
    download_url = candidate["download_url"]
    new_version = candidate["version"]
    root_alert = parent
    created_alert_root = None
    if root_alert is None:
        created_alert_root = tk.Tk()
        created_alert_root.withdraw()
        root_alert = created_alert_root
    try:
        if messagebox.askyesno(
            "업데이트 발견",
            f"새로운 버전({new_version})이 발견되었습니다.\n지금 업데이트하시겠습니까? (현재: {CURRENT_VERSION})",
            parent=root_alert,
        ):
            download_and_apply_update(
                download_url,
                checksum_url=candidate.get("checksum_url"),
                expected_sha256=candidate.get("sha256"),
                archive_policy=candidate.get("archive_policy"),
            )
    finally:
        if created_alert_root is not None:
            created_alert_root.destroy()


def schedule_update_check(parent):
    if not _release_runtime_mode():
        return

    def worker():
        candidate = _safe_check_update_candidate()
        if not candidate:
            return
        try:
            parent.after(0, lambda: _prompt_and_apply_update(candidate, parent=parent))
        except tk.TclError:
            return

    threading.Thread(target=worker, name="container-audit-update-check", daemon=True).start()

# ####################################################################
# # 데이터 클래스 및 유틸리티
# ####################################################################
@dataclass
class TraySession:
    master_label_code: str = ""
    item_code: str = ""
    item_name: str = ""
    item_spec: str = ""
    scanned_barcodes: List[str] = field(default_factory=list)
    scan_times: List[datetime.datetime] = field(default_factory=list)
    tray_size: int = 60
    mismatch_error_count: int = 0
    total_idle_seconds: float = 0.0
    stopwatch_seconds: float = 0.0
    start_time: Optional[datetime.datetime] = None
    has_error_or_reset: bool = False
    is_test_tray: bool = False
    is_partial_submission: bool = False
    is_restored_session: bool = False


def resource_path(relative_path: str) -> str:
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# ####################################################################
# # 메인 어플리케이션
# ####################################################################
class ContainerAudit:
    APP_TITLE = f"이적 검사 시스템 ({CURRENT_VERSION})"
    DEFAULT_FONT = 'Malgun Gothic'
    TRAY_SIZE = 60
    SETTINGS_DIR = 'config'
    PARKED_TRAY_DIR = os.path.join(SETTINGS_DIR, 'parked_trays')
    SETTINGS_FILE = 'container_audit_settings.json'
    WORKERS_FILE = 'worker_registry.json'
    IDLE_THRESHOLD_SEC = 420
    ITEM_CODE_LENGTH = 13
    SOURCE_SYSTEM = "container_audit"
    SOURCE_TRANSPORT_OR_DATASET = "legacy_transfer_csv"
    SCAN_CONTRACT_VERSION = "container_audit_legacy_v1"
    AUDIO_ENABLED_ENV = "CONTAINER_AUDIT_AUDIO_ENABLED"
    
    COLOR_BG = "#F3F6FA"
    COLOR_SIDEBAR_BG = "#FFFFFF"
    COLOR_CARD_BG = "#F8FAFC"
    COLOR_SURFACE_ALT = "#EEF3F8"
    COLOR_TEXT = "#172033"
    COLOR_TEXT_SUBTLE = "#667085"
    COLOR_PRIMARY = "#2563EB"
    COLOR_PRIMARY_HOVER = "#1D4ED8"
    COLOR_PRIMARY_SOFT = "#DBEAFE"
    COLOR_SUCCESS = "#16A34A"
    COLOR_SUCCESS_HOVER = "#15803D"
    COLOR_DANGER = "#DC2626"
    COLOR_DANGER_HOVER = "#B91C1C"
    COLOR_IDLE = "#F59E0B"
    COLOR_IDLE_BG = "#FFF7ED"
    COLOR_IDLE_TEXT = "#92400E"
    COLOR_BORDER = "#D7DEE8"
    COLOR_BORDER_STRONG = "#AEB8C6"
    COLOR_VELVET = "#991B1B"
    COLOR_INPUT_BG = "#FFFFFF"
    DEFAULT_RESTORED_GEOMETRY = "1280x820"
    MIN_WINDOW_WIDTH = 1024
    MIN_WINDOW_HEIGHT = 720

    def __init__(self):
        startup_geometry = os.getenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", "").strip()
        self.root = tk.Tk()
        if startup_geometry:
            self.root.withdraw()
        self.root.title(self.APP_TITLE)
        self.root.minsize(self.MIN_WINDOW_WIDTH, self.MIN_WINDOW_HEIGHT)
        if startup_geometry:
            self.root.geometry(startup_geometry)
            self.root.update_idletasks()
            self.root.deiconify()
        else:
            self.root.geometry(self.DEFAULT_RESTORED_GEOMETRY)
            self.root.update_idletasks()
            try:
                self.root.state('zoomed')
            except tk.TclError:
                self.root.geometry(self.DEFAULT_RESTORED_GEOMETRY)
        self.root.configure(bg=self.COLOR_BG)
        try:
            self.root.iconbitmap(resource_path(os.path.join('assets', 'logo.ico')))
        except Exception as e:
            print(f"아이콘 로드 실패: {e}")

        self.success_sound = self.error_sound = None
        self.audio_feedback_ready = False
        self.audio_feedback_error = ""
        self.audio_feedback_init_started = False
        self.root.after(250, self._start_audio_feedback_initialization)

        if getattr(sys, 'frozen', False): self.application_path = os.path.dirname(sys.executable)
        else: self.application_path = os.path.dirname(os.path.abspath(__file__))
        
        self._setup_paths_and_dirs()
        self._direct_sync_bootstrap_thread = start_direct_sync_auto_bootstrap(
            app_root=self.application_path,
            direct_sync_root=self.direct_sync_program_data_root,
            scan_source_dir=self.direct_sync_scan_source_dir,
        )
        self.worker_registry = WorkerRegistry(os.path.join(self.config_folder, self.WORKERS_FILE))
        self.parked_tray_store = ParkedTrayStore(self.parked_trays_dir)

        self.settings = self.load_app_settings()
        self.scale_factor = self.settings.get('scale_factor', 1.0)
        self.paned_window_sash_positions: Dict[str, int] = self.settings.get('paned_window_sash_positions', {})
        self.column_widths: Dict[str, int] = self.settings.get('column_widths_validator', {})
        self.internal_test_commands_enabled = self.settings.get('enable_internal_test_commands') is True
        
        self.best_time_records: Dict[str, float] = {} # 날짜별 최고 기록 저장
        self._load_best_time_records()
        
        self.worker_name = ""
        self.completed_master_labels: set = set()
        self.current_tray = TraySession()
        self._scan_callback_epoch = 0
        self._idle_check_epoch = 0
        self.current_exchange_session = ProductExchangeSession()
        self.items_data = self.load_items()
        self.item_catalog = ItemCatalog(self.items_data)
        
        self.work_summary: Dict[str, Dict[str, Any]] = {}
        self.completed_tray_times: List[float] = []
        self.total_tray_count = 0
        self.tray_last_end_time: Optional[datetime.datetime] = None
        self.info_cards: Dict[str, Dict[str, ttk.Widget]] = {}
        self.logo_photo_ref = None
        self.is_idle = False
        self.last_activity_time: Optional[datetime.datetime] = None
        self.show_tray_image_var = tk.BooleanVar(value=False)

        # 현품표 교체 관련 상태 변수
        self.master_label_replace_state: Optional[str] = None
        self.replacement_context: Dict[str, Any] = {}

        self.status_message_job: Optional[str] = None
        self.clock_job: Optional[str] = None
        self.stopwatch_job: Optional[str] = None
        self.idle_check_job: Optional[str] = None
        self.focus_return_job: Optional[str] = None
        self.log_write_errors: List[str] = []
        self.last_log_write_error: Optional[str] = None
        
        self.log_queue: queue.Queue = queue.Queue()
        self.log_file_path: Optional[str] = None
        self.log_thread = threading.Thread(target=self._event_log_writer, daemon=True)
        self.log_thread.start()
        
        try:
            self.computer_id = hex(uuid.getnode())
        except Exception:
            import socket
            self.computer_id = socket.gethostname()
        self.CURRENT_TRAY_STATE_FILE = f"_current_tray_state_{self.computer_id}.json"
        
        self._setup_core_ui_structure()
        self._setup_styles()
        self.show_worker_input_screen()
        
        self.root.bind('<Control-MouseWheel>', self.on_ctrl_wheel)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    ####################################################################
    # 30일 최고 기록 관리
    ####################################################################

    def _audio_feedback_enabled(self):
        value = os.getenv(self.AUDIO_ENABLED_ENV, "on").strip().lower()
        return value not in {"0", "false", "no", "off", "disabled"}

    def _start_audio_feedback_initialization(self):
        if getattr(self, "audio_feedback_init_started", False) or not self._audio_feedback_enabled():
            return
        self.audio_feedback_init_started = True

        def initialize_audio():
            success_sound = error_sound = None
            error_message = ""
            try:
                pygame.init()
                pygame.mixer.init()
                success_sound = pygame.mixer.Sound(resource_path('assets/success.wav'))
                error_sound = pygame.mixer.Sound(resource_path('assets/error.wav'))
            except Exception as exc:
                error_message = str(exc)

            def finish():
                self.success_sound = success_sound
                self.error_sound = error_sound
                self.audio_feedback_ready = success_sound is not None and error_sound is not None
                self.audio_feedback_error = error_message
                if error_message:
                    print(f"사운드 피드백 초기화 오류: {error_message}")

            try:
                self.root.after(0, finish)
            except tk.TclError:
                pass

        threading.Thread(target=initialize_audio, name="container-audit-audio-init", daemon=True).start()

    def _load_audio_feedback(self):
        self._start_audio_feedback_initialization()
    def _load_best_time_records(self):
        """설정 폴더에서 30일 최고 기록 파일을 불러옵니다."""
        self.best_time_file_path = os.path.join(self.config_folder, 'best_time_records.json')
        self.best_time_store = BestTimeRecordStore(self.best_time_file_path)
        self.best_time_records = self.best_time_store.load()

    def _save_best_time_records(self):
        """현재 최고 기록 데이터를 파일에 저장합니다."""
        try:
            self.best_time_store.save(self.best_time_records)
        except Exception as e:
            print(f"최고 기록 저장 실패: {e}")

    def _cleanup_old_records(self):
        """30일이 지난 오래된 기록을 삭제합니다."""
        if not self.best_time_records: return
        self.best_time_records = self.best_time_store.cleanup(self.best_time_records)

    def _update_best_time_records(self, new_time: float):
        """새로운 완료 시간을 받아 최고 기록을 갱신하고 저장합니다."""
        self.best_time_records = self.best_time_store.update_best_time(self.best_time_records, new_time)
            
    def _setup_paths_and_dirs(self):
        """애플리케이션에서 사용하는 주요 경로와 디렉터리를 설정하고 생성합니다."""
        self.storage_paths = build_container_audit_storage_paths(application_path=self.application_path)
        ensure_container_audit_storage_dirs(self.storage_paths)
        self.data_root = str(self.storage_paths.data_root)
        self.save_folder = str(self.storage_paths.events_dir)
        self.direct_sync_scan_source_dir = str(self.storage_paths.events_dir)
        self.direct_sync_program_data_root = str(self.storage_paths.direct_sync_root)
        self.config_folder = os.path.join(self.application_path, self.SETTINGS_DIR)
        self.parked_trays_dir = os.path.join(self.application_path, self.PARKED_TRAY_DIR)
        os.makedirs(self.config_folder, exist_ok=True)
        os.makedirs(self.parked_trays_dir, exist_ok=True)

    def load_app_settings(self) -> Dict[str, Any]:
        path = os.path.join(self.config_folder, self.SETTINGS_FILE)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return _drop_release_disabled_settings(normalize_app_settings(json.load(f)))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def save_settings(self):
        try:
            path = os.path.join(self.config_folder, self.SETTINGS_FILE)
            previous_settings = self.load_app_settings()
            current_settings = {
                'scale_factor': self.scale_factor,
                'column_widths_validator': self.column_widths,
                'paned_window_sash_positions': self.paned_window_sash_positions,
            }
            if "update_settings" in previous_settings:
                current_settings["update_settings"] = previous_settings["update_settings"]
            if not _release_runtime_mode():
                current_settings['enable_internal_test_commands'] = bool(getattr(self, 'internal_test_commands_enabled', False))
            atomic_write_json(path, current_settings, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"설정 저장 오류: {e}")

    def load_items(self) -> List[Dict[str, str]]:
        item_path = resource_path(os.path.join('assets', 'Item.csv'))
        encodings_to_try = ['utf-8-sig', 'cp949', 'euc-kr', 'utf-8']
        for encoding in encodings_to_try:
            try:
                with open(item_path, 'r', encoding=encoding) as file:
                    items = list(csv.DictReader(file))
                    return items
            except UnicodeDecodeError:
                continue
            except FileNotFoundError:
                messagebox.showerror("오류", f"필수 파일 없음: {item_path}\n'assets' 폴더에 Item.csv가 있는지 확인하세요.")
                self.root.destroy()
                return []
            except Exception as e:
                messagebox.showerror("파일 읽기 오류", f"'{item_path}' 파일을 읽는 중 예상치 못한 오류가 발생했습니다:\n{e}")
                self.root.destroy()
                return []
        messagebox.showerror("인코딩 감지 실패", f"'{os.path.basename(item_path)}' 파일의 인코딩 형식을 알 수 없습니다.")
        self.root.destroy()
        return []

    def _item_catalog(self) -> ItemCatalog:
        items_data = getattr(self, "items_data", [])
        catalog = getattr(self, "item_catalog", None)
        if catalog is None or getattr(catalog, "source_id", None) != id(items_data):
            catalog = ItemCatalog(items_data)
            self.item_catalog = catalog
        return catalog

    def _parked_store(self) -> ParkedTrayStore:
        store = getattr(self, "parked_tray_store", None)
        parked_dir = getattr(self, "parked_trays_dir", "")
        if store is None or str(getattr(store, "directory", "")) != str(parked_dir):
            store = ParkedTrayStore(parked_dir)
            self.parked_tray_store = store
        return store

    def _remember_completed_master_label(self, master_label: str) -> None:
        if not master_label:
            return
        if not hasattr(self, "completed_master_labels"):
            self.completed_master_labels = set()
        self.completed_master_labels.add(master_label)
        self.completed_master_labels.add(canonical_master_label_key(master_label))

    def _is_completed_master_label(self, master_label: str) -> bool:
        if not master_label:
            return False
        completed_labels = getattr(self, "completed_master_labels", set())
        if master_label in completed_labels:
            return True
        candidate_key = canonical_master_label_key(master_label)
        if candidate_key in completed_labels:
            return True
        return any(canonical_master_label_key(label) == candidate_key for label in completed_labels)

    def _setup_core_ui_structure(self):
        status_bar = tk.Frame(
            self.root,
            bg=self.COLOR_SIDEBAR_BG,
            bd=0,
            relief=tk.FLAT,
            highlightbackground=self.COLOR_BORDER,
            highlightthickness=1,
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = tk.Label(status_bar, text="준비", anchor=tk.W, bg=self.COLOR_SIDEBAR_BG, fg=self.COLOR_TEXT)
        self.status_label.pack(side=tk.LEFT, padx=10, pady=4)
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.left_pane = ttk.Frame(self.paned_window, style='Sidebar.TFrame')
        self.center_pane = ttk.Frame(self.paned_window, style='TFrame')
        self.right_pane = ttk.Frame(self.paned_window, style='Sidebar.TFrame')
        self.paned_window.add(self.left_pane, weight=1)
        self.paned_window.add(self.center_pane, weight=3)
        self.paned_window.add(self.right_pane, weight=1)
        self.paned_window.bind("<Configure>", self._clamp_paned_sashes_to_width, add="+")
        self.worker_input_frame = ttk.Frame(self.root, style='TFrame')

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_scaling()

    def apply_scaling(self):
        base=10; s,m,l,xl,xxl = (int(factor*self.scale_factor) for factor in [base,base+2,base+8,base+20,base+60])
        button_padding = (int(16*self.scale_factor), int(9*self.scale_factor))
        self.style.configure('TFrame', background=self.COLOR_BG)
        self.style.configure('Sidebar.TFrame', background=self.COLOR_SIDEBAR_BG)
        self.style.configure('Card.TFrame', background=self.COLOR_CARD_BG, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('Idle.TFrame', background=self.COLOR_IDLE_BG, relief='solid', borderwidth=1, bordercolor="#FED7AA")
        self.style.configure('TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Sidebar.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Idle.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Subtle.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Card.Subtle.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Idle.Subtle.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, s))
        self.style.configure('Value.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Card.Value.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Idle.Value.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Title.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(xl * 1.5), 'bold'))
        self.style.configure('ItemInfo.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, l, 'bold'))
        self.style.configure('MainCounter.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, xxl, 'bold'))
        self.style.configure('TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_PRIMARY, foreground='white', focuscolor=self.COLOR_PRIMARY)
        self.style.map('TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#1E40AF'), ('active', self.COLOR_PRIMARY_HOVER), ('!active', self.COLOR_PRIMARY)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Corner.TButton', font=(self.DEFAULT_FONT, l, 'bold'), borderwidth=0, padding=(5, 5))
        self.style.map('Corner.TButton', background=[('!active', self.COLOR_BG), ('active', self.COLOR_SURFACE_ALT)], foreground=[('!active', self.COLOR_TEXT_SUBTLE), ('active', self.COLOR_TEXT)])
        self.style.configure('Secondary.TButton', font=(self.DEFAULT_FONT, s, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background='#64748B', foreground='white')
        self.style.map('Secondary.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#334155'), ('active', '#475569'), ('!active', '#64748B')], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Success.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_SUCCESS, foreground='white')
        self.style.map('Success.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#166534'), ('active', self.COLOR_SUCCESS_HOVER), ('!active', self.COLOR_SUCCESS)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Warning.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_IDLE, foreground='white')
        self.style.map('Warning.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#B45309'), ('active', '#D97706'), ('!active', self.COLOR_IDLE)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Danger.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_DANGER, foreground='white')
        self.style.map('Danger.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#991B1B'), ('active', self.COLOR_DANGER_HOVER), ('!active', self.COLOR_DANGER)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('TCheckbutton', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.map('TCheckbutton', indicatorcolor=[('selected', self.COLOR_PRIMARY), ('!selected', self.COLOR_BORDER)], foreground=[('active', self.COLOR_TEXT), ('!active', self.COLOR_TEXT)])
        self.style.configure('VelvetCard.TFrame', background=self.COLOR_VELVET, relief='solid', borderwidth=1, bordercolor="#7F1D1D")
        self.style.configure('Velvet.Subtle.TLabel', background=self.COLOR_VELVET, foreground='white', font=(self.DEFAULT_FONT, s))
        self.style.configure('Velvet.Value.TLabel', background=self.COLOR_VELVET, foreground='white', font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Treeview.Heading', font=(self.DEFAULT_FONT, m, 'bold'), background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT, relief='flat', bordercolor=self.COLOR_BORDER)
        self.style.configure('Treeview', rowheight=int(28 * self.scale_factor), font=(self.DEFAULT_FONT, m), background=self.COLOR_CARD_BG, fieldbackground=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER)
        self.style.map('Treeview', background=[('selected', self.COLOR_PRIMARY)], foreground=[('selected', 'white')])
        self.style.configure('Vertical.TScrollbar', background='#CBD5E1', troughcolor=self.COLOR_SURFACE_ALT, bordercolor=self.COLOR_SURFACE_ALT, arrowcolor=self.COLOR_TEXT_SUBTLE, relief='flat')
        self.style.map('Vertical.TScrollbar', background=[('active', '#94A3B8')])
        self.style.configure('TEntry', fieldbackground=self.COLOR_INPUT_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER, insertcolor=self.COLOR_PRIMARY)
        self.style.configure('TSpinbox', fieldbackground=self.COLOR_INPUT_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER, arrowsize=int(14*self.scale_factor))
        self.style.configure('TLabelframe', background=self.COLOR_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, relief='solid')
        self.style.configure('TLabelframe.Label', background=self.COLOR_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s, 'bold'))
        self.style.configure('TPanedwindow', background=self.COLOR_BORDER)
        self.style.configure('Big.Horizontal.TProgressbar', troughcolor='#E2E8F0', background=self.COLOR_PRIMARY, bordercolor='#E2E8F0', lightcolor=self.COLOR_PRIMARY, darkcolor=self.COLOR_PRIMARY, thickness=int(22 * self.scale_factor))
        if hasattr(self, 'status_label'):
            self.status_label.configure(font=(self.DEFAULT_FONT, s), bg=self.COLOR_SIDEBAR_BG, fg=self.COLOR_TEXT)

    def on_ctrl_wheel(self, event):
        self.scale_factor += 0.1 if event.delta > 0 else -0.1
        self.scale_factor = max(0.7, min(2.5, self.scale_factor))
        self.apply_scaling()
        if self.worker_name:
            self.show_validation_screen()
        else:
            self.show_worker_input_screen()

    def _clear_main_frames(self):
        self.worker_input_frame.pack_forget()
        self.paned_window.pack_forget()

    def show_worker_input_screen(self):
        self._clear_main_frames()
        self.worker_input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for widget in self.worker_input_frame.winfo_children(): widget.destroy()
        self.worker_input_frame.grid_rowconfigure(0, weight=1)
        self.worker_input_frame.grid_columnconfigure(0, weight=1)
        center_frame = ttk.Frame(self.worker_input_frame, style='TFrame')
        center_frame.grid(row=0, column=0)
        try:
            logo_path = resource_path(os.path.join('assets', 'logo.png'))
            logo_img = Image.open(logo_path)
            max_width = 400 * self.scale_factor
            logo_img_resized = logo_img.resize((int(max_width), int(max_width * (logo_img.height / logo_img.width))), Image.Resampling.LANCZOS)
            self.logo_photo_ref = ImageTk.PhotoImage(logo_img_resized)
            ttk.Label(center_frame, image=self.logo_photo_ref, style='TLabel').pack(pady=(40, 20))
        except Exception as e:
            print(f"로고 로드 실패: {e}")
        ttk.Label(center_frame, text=self.APP_TITLE, style='Title.TLabel').pack(pady=(20, 60))
        ttk.Label(center_frame, text="작업자 이름", style='TLabel', font=(self.DEFAULT_FONT, int(12*self.scale_factor))).pack(pady=(10, 5))
        workers = self.worker_registry.list_workers()
        self.worker_entry_var = tk.StringVar(value=workers[0] if workers else "")
        self.worker_entry = ttk.Combobox(
            center_frame,
            textvariable=self.worker_entry_var,
            values=workers,
            state='normal',
            width=25,
            font=(self.DEFAULT_FONT, int(18*self.scale_factor), 'bold'),
            justify='center',
        )
        self.worker_entry.pack(ipady=int(12*self.scale_factor))
        self.worker_entry.bind('<Return>', self.start_work)
        self.worker_entry.focus()
        button_container = ttk.Frame(center_frame, style='TFrame')
        button_container.pack(pady=60)
        ttk.Button(button_container, text="신규 등록", command=self.register_worker_from_login, style='Secondary.TButton', width=16).pack(side=tk.LEFT, padx=10, ipady=int(10*self.scale_factor))
        ttk.Button(button_container, text="작업 시작", command=self.start_work, style='TButton', width=20).pack(side=tk.LEFT, padx=10, ipady=int(10*self.scale_factor))

    def _refresh_worker_entry_options(self):
        if hasattr(self, 'worker_entry') and hasattr(self.worker_entry, 'configure'):
            self.worker_entry.configure(values=self.worker_registry.list_workers())

    def _register_worker_name(self, worker_name: str, parent=None) -> Optional[str]:
        worker_name = WorkerRegistry.normalize_name(worker_name)
        try:
            return self.worker_registry.register(worker_name)
        except ValueError as exc:
            messagebox.showerror("작업자 등록 오류", str(exc), parent=parent or self.root)
            return None

    def register_worker_from_login(self):
        worker_name = WorkerRegistry.normalize_name(self.worker_entry_var.get() if hasattr(self, 'worker_entry_var') else "")
        if not worker_name:
            worker_name = simpledialog.askstring("신규 작업자 등록", "등록할 작업자 이름을 입력하세요.", parent=self.root)
        registered = self._register_worker_name(worker_name, parent=self.root)
        if not registered:
            return
        self.worker_entry_var.set(registered)
        self._refresh_worker_entry_options()
        messagebox.showinfo("작업자 등록", f"{registered} 작업자를 등록했습니다.", parent=self.root)

    def _ensure_worker_login_name(self, worker_name: str) -> Optional[str]:
        worker_name = WorkerRegistry.normalize_name(worker_name)
        if not worker_name:
            messagebox.showerror("오류", "작업자 이름을 입력해주세요.")
            return None
        if self.worker_registry.has_worker(worker_name):
            return worker_name
        should_register = messagebox.askyesno(
            "신규 작업자 등록",
            f"등록되지 않은 작업자입니다.\n\n작업자: {worker_name}\n\n신규 작업자로 등록하시겠습니까?",
            parent=self.root,
        )
        if not should_register:
            return None
        registered = self._register_worker_name(worker_name, parent=self.root)
        if registered:
            self._refresh_worker_entry_options()
            messagebox.showinfo("작업자 등록", f"{registered} 작업자를 등록했습니다.", parent=self.root)
        return registered

    def start_work(self, event=None):
        worker_name = self._ensure_worker_login_name(self.worker_entry.get())
        if not worker_name:
            return
        worker_registry = getattr(self, "worker_registry", None)
        if worker_registry is not None:
            try:
                worker_name = worker_registry.mark_recent(worker_name)
            except ValueError as exc:
                messagebox.showerror("작업자 기록 오류", str(exc), parent=self.root)
                return
            self._refresh_worker_entry_options()
        self.worker_name = worker_name
        self._load_session_state()
        self._load_current_tray_state()
        if not self.worker_name:
            return
        self._log_event('WORK_START', detail={'message': f"작업자 '{self.worker_name}'이(가) 작업을 시작했습니다."})
        if not self.root.winfo_exists(): return
        if not self.paned_window.winfo_ismapped():
            self.show_validation_screen()

    def change_worker(self):
        msg = "작업자를 변경하시겠습니까?"
        if self.current_tray.master_label_code:
            msg += "\n\n진행 중인 작업은 다음 로그인 시 복구할 수 있도록 저장됩니다."
        if messagebox.askyesno("작업자 변경", msg):
            if self.current_tray.master_label_code:
                if not self._save_current_tray_state():
                    messagebox.showerror("작업 저장 실패", "진행 중인 트레이 상태를 저장하지 못해 작업자를 변경하지 않습니다.")
                    return
                if not self._log_event('WORK_PAUSE', detail={'message': f"Worker '{self.worker_name}' changed."}, synchronous=True):
                    messagebox.showerror("작업 중지 기록 실패", "진행 중인 트레이의 중지 기록을 남기지 못해 작업자를 변경하지 않습니다.")
                    return
            if self.master_label_replace_state:
                if not self._log_master_label_replacement_cancel(reason="worker_change"):
                    messagebox.showerror("교체 취소 기록 실패", "현품표 교체 취소 기록을 남기지 못해 작업자를 변경하지 않습니다.")
                    return
            exchange_session = getattr(self, "current_exchange_session", ProductExchangeSession())
            if exchange_session.defective_barcodes or exchange_session.good_barcodes:
                if not self._cancel_exchange(reason="worker_change"):
                    messagebox.showerror("교환 취소 기록 실패", "제품 교환 취소 기록을 남기지 못해 작업자를 변경하지 않습니다.")
                    return
            self._cancel_all_jobs()
            self.worker_name = ""
            self.current_tray = TraySession()
            self._invalidate_pending_scan_callbacks()
            self._reset_master_label_replacement_state()
            self.show_worker_input_screen()

    def _load_session_state(self):
        history = load_session_history(
            save_folder=self.save_folder,
            worker_name=self.worker_name,
            today=datetime.date.today(),
            tray_size=self.TRAY_SIZE,
        )
        self.log_file_path = history.log_file_path
        self.total_tray_count = history.total_tray_count
        self.completed_tray_times = history.completed_tray_times
        self.completed_master_labels = set(history.completed_master_labels)
        self.work_summary = history.work_summary
        self.tray_last_end_time = None
        for error in history.load_errors:
            print(error)
        if any(self.work_summary):
            self.show_status_message(f"금일 작업 현황을 불러왔습니다. (총 {self.total_tray_count} 파렛트)", self.COLOR_PRIMARY)

    def _save_current_tray_state(self) -> bool:
        if not self.current_tray.master_label_code: return False
        state = self._current_tray_state_snapshot()
        return self._save_tray_state_snapshot(state)

    def _save_tray_state_snapshot(self, state: Dict[str, Any]) -> bool:
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        try:
            atomic_write_json(state_path, state, indent=4)
            return True
        except Exception as e:
            print(f"현재 트레이 상태 저장 실패: {e}")
            return False

    def _current_tray_state_snapshot(self) -> Dict[str, Any]:
        state = tray_session_to_state(self.current_tray, worker_name=self.worker_name)
        last_activity_time = getattr(self, "last_activity_time", None)
        if getattr(self, "is_idle", False) and last_activity_time:
            idle_duration = max(0.0, (datetime.datetime.now() - last_activity_time).total_seconds())
            state["total_idle_seconds"] = float(state.get("total_idle_seconds") or 0.0) + idle_duration
        return state

    def _load_current_tray_state(self):
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        if not os.path.exists(state_path): return
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                saved_state = json.load(f)
            validate_tray_state(saved_state, default_tray_size=self.TRAY_SIZE)
        except Exception as e:
            print(f"현재 트레이 상태 로드 실패: {e}")
            quarantined_path = self._quarantine_current_tray_state(str(e))
            self.current_tray = TraySession()
            path_notice = f"\n격리 파일: {quarantined_path}" if quarantined_path else ""
            messagebox.showwarning("오류", f"이전 작업 상태 파일을 로드하는데 실패했습니다. 원본 파일은 격리했습니다. ({e}){path_notice}")
            return

        try:
            saved_worker = saved_state.get('worker_name')
            saved_master_label = saved_state.get('master_label_code')
            if saved_master_label and self._is_completed_master_label(saved_master_label):
                self.current_tray = TraySession()
                if not self._delete_current_tray_state():
                    quarantined_path = self._quarantine_current_tray_state("completed tray state delete failed")
                    self._log_event(
                        'TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE',
                        detail={
                            'master_label_code': saved_master_label,
                            'quarantined_path': quarantined_path,
                        },
                    )
                    path_notice = f"\n격리 파일: {quarantined_path}" if quarantined_path else ""
                    messagebox.showwarning("작업 상태 정리 실패", f"이미 완료된 이전 작업 상태 파일을 삭제하지 못했습니다.{path_notice}")
                    return
                if not self._log_event(
                    'TRAY_STATE_DISCARDED_AFTER_COMPLETION',
                    detail={'master_label_code': saved_master_label},
                    synchronous=True,
                ):
                    restore_ok = self._save_tray_state_snapshot(saved_state)
                    if restore_ok:
                        messagebox.showerror("작업 기록 실패", "완료된 이전 작업 상태 정리 기록을 남기지 못해 상태 파일을 보존합니다.")
                    else:
                        messagebox.showerror("작업 기록 실패", "완료된 이전 작업 상태 정리 기록을 남기지 못했고 상태 파일 복원에도 실패했습니다. 상태 폴더를 확인하세요.")
                    return
                return
            if saved_worker == self.worker_name:
                msg = f"이전에 마치지 못한 트레이 작업을 이어서 시작하시겠습니까?\n\n· 품목: {saved_state.get('item_name', '알 수 없음')}\n· 스캔 수: {len(saved_state.get('scanned_barcodes', []))}개"
                if messagebox.askyesno("이전 작업 복구", msg):
                    if not self._log_event(
                        'TRAY_RESTORE',
                        detail={'message': 'Same worker restored their session.'},
                        synchronous=True,
                    ):
                        self.current_tray = TraySession()
                        messagebox.showerror("작업 기록 실패", "이전 작업 복구 기록을 남기지 못해 상태 파일을 보존합니다.")
                        return
                    self._restore_tray_from_state(saved_state)
                else:
                    if not self._log_saved_tray_discarded(
                        saved_state,
                        reason='restore_declined_same_worker',
                        discarded_worker_name=str(saved_worker or ""),
                    ):
                        messagebox.showerror("작업 기록 실패", "이전 작업 삭제 기록을 남기지 못해 상태 파일을 보존합니다.")
                        return
                    if not self._delete_current_tray_state():
                        messagebox.showerror("작업 삭제 실패", "현재 트레이 상태 파일을 삭제하지 못했습니다.")
                        return
                    self.current_tray = TraySession()
            else:
                msg = f"이전 작업자 '{saved_worker}'님이 마치지 않은 작업이 있습니다.\n\n이 작업을 이어서 진행하시겠습니까?"
                response = messagebox.askyesnocancel("작업 인수 확인", msg)
                if response is True:
                    self.current_tray = tray_session_from_state(
                        saved_state,
                        session_factory=TraySession,
                        default_tray_size=self.TRAY_SIZE,
                    )
                    if not self._save_current_tray_state():
                        self.current_tray = TraySession()
                        messagebox.showwarning("작업 저장 경고", "인수한 작업 상태의 작업자 정보를 저장하지 못해 작업을 복구하지 않습니다.")
                        return
                    takeover_detail = {'previous_worker': saved_worker, 'new_worker': self.worker_name, 'item_name': saved_state.get('item_name')}
                    if not self._log_event('TRAY_TAKEOVER', detail=takeover_detail, synchronous=True):
                        rollback_ok = self._save_tray_state_snapshot(saved_state)
                        self.current_tray = TraySession()
                        if rollback_ok:
                            messagebox.showerror("작업 기록 실패", "작업 인수 기록을 남기지 못해 이전 작업 상태를 보존합니다.")
                        else:
                            messagebox.showerror("작업 기록 실패", "작업 인수 기록을 남기지 못했고 이전 작업 상태 복원에도 실패했습니다. 상태 파일을 확인하세요.")
                        return
                    self._invalidate_pending_scan_callbacks()
                    self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)
                elif response is False:
                    if messagebox.askyesno("작업 삭제", "이전 작업을 영구적으로 삭제하시겠습니까?\n(이 작업은 복구할 수 없습니다.)"):
                        if not self._log_saved_tray_discarded(
                            saved_state,
                            reason='restore_takeover_declined_delete_confirmed',
                            discarded_worker_name=str(saved_worker or ""),
                        ):
                            messagebox.showerror("작업 기록 실패", "이전 작업 삭제 기록을 남기지 못해 상태 파일을 보존합니다.")
                            return
                        if not self._delete_current_tray_state():
                            messagebox.showerror("작업 삭제 실패", "현재 트레이 상태 파일을 삭제하지 못했습니다.")
                            return
                        self.current_tray = TraySession()
                        self.show_status_message(f"'{saved_worker}'님의 이전 작업이 삭제되었습니다.", self.COLOR_DANGER)
                    else:
                        self.worker_name = ""
                        self.current_tray = TraySession()
                        self.show_worker_input_screen()
                else:
                    self.worker_name = ""
                    self.current_tray = TraySession()
                    self.show_worker_input_screen()
        except Exception as e:
            print(f"현재 트레이 상태 로드 실패: {e}")
            messagebox.showwarning("오류", f"이전 작업 상태 파일을 로드하는데 실패했습니다. ({e})")

    def _restore_tray_from_state(self, state: Dict[str, Any]):
        self.current_tray = tray_session_from_state(
            state,
            session_factory=TraySession,
            default_tray_size=self.TRAY_SIZE,
        )
        self._invalidate_pending_scan_callbacks()
        self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)

    def _quarantine_current_tray_state(self, reason: str) -> Optional[str]:
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        if not os.path.exists(state_path):
            return None
        try:
            quarantined_path = quarantine_tray_state_file(state_path)
            print(f"임시 트레이 상태 파일 격리: {quarantined_path} ({reason})")
            return str(quarantined_path)
        except Exception as e:
            print(f"임시 트레이 상태 파일 격리 실패: {e}")
            return None

    def _log_current_tray_discarded(self, *, reason: str, synchronous: bool = False) -> bool:
        if not self.current_tray.master_label_code:
            return False
        return self._log_event(
            'TRAY_DISCARDED_BY_OPERATOR',
            detail={
                'reason': reason,
                'master_label_code': self.current_tray.master_label_code,
                'item_code': self.current_tray.item_code,
                'item_name': self.current_tray.item_name,
                'scan_count': len(self.current_tray.scanned_barcodes),
                'is_partial_submission': self.current_tray.is_partial_submission,
            },
            synchronous=synchronous,
        )

    def _log_saved_tray_discarded(
        self,
        saved_state: Dict[str, Any],
        *,
        reason: str,
        discarded_worker_name: str,
    ) -> bool:
        return self._log_event(
            'TRAY_DISCARDED_BY_OPERATOR',
            detail={
                'reason': reason,
                'master_label_code': saved_state.get('master_label_code'),
                'item_code': saved_state.get('item_code'),
                'item_name': saved_state.get('item_name'),
                'scan_count': len(saved_state.get('scanned_barcodes') or []),
                'discarded_worker_name': discarded_worker_name,
            },
            synchronous=True,
        )

    def _delete_current_tray_state(self) -> bool:
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        if os.path.exists(state_path):
            try:
                os.remove(state_path)
            except Exception as e:
                print(f"임시 트레이 상태 파일 삭제 실패: {e}")
                return False
        return True

    def show_validation_screen(self):
        self._clear_main_frames()
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for pane in [self.left_pane, self.center_pane, self.right_pane]:
            for widget in pane.winfo_children(): widget.destroy()
        self._create_left_sidebar_content(self.left_pane)
        self._create_center_content(self.center_pane)
        self._create_right_sidebar_content(self.right_pane)
        self.root.after(50, self._set_initial_sash_positions)
        self._start_clock()
        self._start_idle_checker()
        self._update_all_summaries()
        self._update_parked_trays_list()
        if self.current_tray.master_label_code:
            self._update_current_item_label()
            for i, barcode in enumerate(self.current_tray.scanned_barcodes, start=1):
                self.scanned_listbox.insert(0, f"({i}) {barcode}")
            if self.current_tray.scanned_barcodes:
                self.undo_button['state'] = tk.NORMAL
            self._update_center_display()
            self._start_stopwatch(resume=True)
        else:
            self._reset_ui_to_waiting_state()
        self.scan_entry.focus()

    def _get_pane_layout_metrics(self, total_width: int) -> Dict[str, int]:
        total_width = max(1, int(total_width or 1))
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        left_min = int(260 * scale)
        right_min = int(260 * scale)
        center_min = int(520 * scale)
        side_target = self._clamped_int(total_width * 0.20, left_min, int(380 * scale))
        right_target = self._clamped_int(total_width * 0.18, right_min, int(360 * scale))

        if total_width <= left_min + center_min + right_min:
            left_width = max(1, int(total_width * 0.28))
            right_width = max(1, total_width - int(total_width * 0.72))
            center_width = max(1, total_width - left_width - right_width)
            return {
                "left_width": left_width,
                "center_width": center_width,
                "right_width": right_width,
                "left_min": left_min,
                "center_min": int(360 * scale),
                "right_min": right_min,
            }

        available_for_center = total_width - side_target - right_target
        if available_for_center < center_min:
            deficit = center_min - available_for_center
            side_target = max(left_min, side_target - deficit // 2)
            right_target = max(right_min, right_target - (deficit - deficit // 2))
        center_width = max(center_min, total_width - side_target - right_target)
        return {
            "left_width": side_target,
            "center_width": center_width,
            "right_width": max(right_min, total_width - side_target - center_width),
            "left_min": left_min,
            "center_min": center_min,
            "right_min": right_min,
        }

    def _set_initial_sash_positions(self):
        self.paned_window.update_idletasks()
        try:
            total_width = self.paned_window.winfo_width()
            if total_width <= 1:
                self.root.after(50, self._set_initial_sash_positions)
                return
            metrics = self._get_pane_layout_metrics(total_width)
            sash_0_pos = metrics["left_width"]
            sash_1_pos = metrics["left_width"] + metrics["center_width"]
            self.paned_window.sashpos(0, sash_0_pos)
            self.paned_window.sashpos(1, sash_1_pos)
        except tk.TclError as e:
            print(f"Could not set initial sash position (ignorable): {e}")

    def _clamp_paned_sashes_to_width(self, event=None):
        if not (hasattr(self, 'paned_window') and self.paned_window.winfo_ismapped()):
            return
        try:
            total_width = self.paned_window.winfo_width()
            if total_width <= 1:
                return
            metrics = self._get_pane_layout_metrics(total_width)
            left_min = metrics["left_min"]
            center_min = metrics["center_min"]
            right_min = metrics["right_min"]
            if total_width <= left_min + center_min + right_min:
                sash_0_pos = max(1, int(total_width * 0.28))
                sash_1_pos = max(sash_0_pos + 1, int(total_width * 0.72))
            else:
                sash_0_pos = self.paned_window.sashpos(0)
                sash_1_pos = self.paned_window.sashpos(1)
                max_sash_0 = max(1, total_width - right_min - center_min)
                sash_0_pos = max(left_min, min(sash_0_pos, max_sash_0))
                min_sash_1 = sash_0_pos + center_min
                max_sash_1 = max(min_sash_1 + 1, total_width - right_min)
                sash_1_pos = max(min_sash_1, min(sash_1_pos, max_sash_1))
            if abs(self.paned_window.sashpos(0) - sash_0_pos) > 1:
                self.paned_window.sashpos(0, sash_0_pos)
            if abs(self.paned_window.sashpos(1) - sash_1_pos) > 1:
                self.paned_window.sashpos(1, sash_1_pos)
        except tk.TclError:
            return

    def _bind_label_to_container_width(
        self,
        label: ttk.Label,
        container: ttk.Widget,
        *,
        padding: int = 0,
        min_wraplength: int = 80,
    ) -> None:
        def update_wraplength(event=None):
            try:
                width = container.winfo_width()
                if width <= 1:
                    return
                label.configure(wraplength=max(min_wraplength, width - padding))
            except tk.TclError:
                return

        container.bind("<Configure>", update_wraplength, add="+")
        self.root.after(0, update_wraplength)

    @staticmethod
    def _clamped_int(value: float, minimum: int, maximum: int) -> int:
        return max(minimum, min(maximum, int(round(value))))

    def _get_scanned_listbox_metrics(
        self,
        center_width: int,
        center_height: int,
        list_height: int = 0,
    ) -> Dict[str, int]:
        try:
            scale = float(getattr(self, "scale_factor", 1.0))
        except (TypeError, ValueError):
            scale = 1.0
        scale = max(0.7, min(2.5, scale))

        center_width = max(1, int(center_width or 1))
        center_height = max(1, int(center_height or 1))
        list_height = max(0, int(list_height or 0))

        horizontal_pad = self._clamped_int(center_width * 0.045, int(12 * scale), int(36 * scale))
        top_pady = self._clamped_int(center_height * 0.025, int(8 * scale), int(28 * scale))
        if center_height < 620:
            top_pady = min(top_pady, int(14 * scale))

        list_reference_height = list_height if list_height > 1 else max(140, center_height - int(330 * scale))
        if list_reference_height < 180:
            target_rows = 6
        elif list_reference_height < 320:
            target_rows = 8
        elif list_reference_height < 520:
            target_rows = 12
        else:
            target_rows = 16

        row_px = max(24.0, min(42.0, list_reference_height / target_rows))
        base_font = (16 if center_height < 620 else 18) * scale
        candidate_font = max(base_font, row_px * 0.58)

        available_text_width = max(160, center_width - horizontal_pad * 2 - 12)
        width_limited_font = available_text_width / (34 * 0.62)
        minimum_font = 14 * scale
        maximum_font = min(24 * scale, max(minimum_font, width_limited_font))
        font_size = self._clamped_int(candidate_font, int(round(minimum_font)), int(round(maximum_font)))

        estimated_row_height = max(22, int(round(font_size * 1.65)))
        visible_rows = self._clamped_int(list_reference_height / estimated_row_height, 5, 18)
        return {
            "font_size": font_size,
            "horizontal_pad": horizontal_pad,
            "top_pady": top_pady,
            "visible_rows": visible_rows,
        }

    def _schedule_scanned_listbox_layout_refresh(self, event=None) -> None:
        if getattr(self, "_scanned_listbox_layout_job", None):
            return
        root = getattr(self, "root", None)
        if root is None:
            self._apply_scanned_listbox_layout()
            return
        try:
            self._scanned_listbox_layout_job = root.after_idle(self._apply_scanned_listbox_layout)
        except AttributeError:
            try:
                self._scanned_listbox_layout_job = root.after(0, self._apply_scanned_listbox_layout)
            except AttributeError:
                self._apply_scanned_listbox_layout()
        except tk.TclError:
            return

    def _apply_scanned_listbox_layout(self, event=None) -> None:
        self._scanned_listbox_layout_job = None
        listbox = getattr(self, "scanned_listbox", None)
        if listbox is None:
            return
        try:
            if hasattr(listbox, "winfo_exists") and not listbox.winfo_exists():
                return
            parent_frame = getattr(self, "_scanned_listbox_parent_frame", None) or getattr(listbox, "master", None)
            if parent_frame is None:
                return
            center_width = parent_frame.winfo_width()
            center_height = parent_frame.winfo_height()
            list_height = listbox.winfo_height()
        except (tk.TclError, AttributeError, TypeError):
            return
        if center_width <= 1 or center_height <= 1:
            return

        self._apply_center_layout(parent_frame, center_width, center_height)
        metrics = self._get_scanned_listbox_metrics(center_width, center_height, list_height)
        metrics_key = (
            metrics["font_size"],
            metrics["horizontal_pad"],
            metrics["top_pady"],
            metrics["visible_rows"],
        )
        if metrics_key == getattr(self, "_scanned_listbox_layout_metrics", None):
            return
        self._scanned_listbox_layout_metrics = metrics_key

        try:
            listbox.configure(
                font=(self.DEFAULT_FONT, metrics["font_size"]),
                height=metrics["visible_rows"],
                justify='center',
            )
            listbox.grid_configure(
                padx=metrics["horizontal_pad"],
                pady=(metrics["top_pady"], 0),
            )
        except (tk.TclError, AttributeError):
            return

    def _get_center_layout_metrics(self, center_width: int, center_height: int) -> Dict[str, int]:
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        center_width = max(1, int(center_width or 1))
        center_height = max(1, int(center_height or 1))
        compact_height = center_height < 700
        horizontal_pad = self._clamped_int(center_width * 0.035, int(16 * scale), int(44 * scale))
        item_top = self._clamped_int(center_height * 0.012, int(6 * scale), int(14 * scale))
        item_bottom = self._clamped_int(center_height * 0.022, int(8 * scale), int(24 * scale))
        count_top = self._clamped_int(center_height * 0.010, int(6 * scale), int(14 * scale))
        count_bottom = self._clamped_int(center_height * 0.020, int(8 * scale), int(22 * scale))
        progress_bottom = self._clamped_int(center_height * 0.018, int(8 * scale), int(20 * scale))
        entry_ipady = self._clamped_int(center_height * 0.016, int(10 * scale), int(18 * scale))
        button_top = self._clamped_int(center_height * 0.024, int(12 * scale), int(30 * scale))
        button_pad_x = self._clamped_int(center_width * 0.010, int(6 * scale), int(14 * scale))
        list_minsize = self._clamped_int(center_height * (0.31 if compact_height else 0.36), int(140 * scale), int(360 * scale))
        entry_font = self._clamped_int(center_height * 0.036, int(24 * scale), int(34 * scale))
        count_font = self._clamped_int(center_height * 0.090, int(52 * scale), int(76 * scale))
        return {
            "horizontal_pad": horizontal_pad,
            "item_top": item_top,
            "item_bottom": item_bottom,
            "count_top": count_top,
            "count_bottom": count_bottom,
            "progress_bottom": progress_bottom,
            "entry_ipady": entry_ipady,
            "button_top": button_top,
            "button_pad_x": button_pad_x,
            "list_minsize": list_minsize,
            "entry_font": entry_font,
            "count_font": count_font,
        }

    def _apply_center_layout(self, parent_frame=None, center_width: int = 0, center_height: int = 0) -> None:
        parent_frame = parent_frame or getattr(self, "_center_content_frame", None)
        if parent_frame is None:
            return
        try:
            center_width = center_width or parent_frame.winfo_width()
            center_height = center_height or parent_frame.winfo_height()
        except (tk.TclError, AttributeError):
            return
        if center_width <= 1 or center_height <= 1:
            return
        metrics = self._get_center_layout_metrics(center_width, center_height)
        action_layout_band = 3 if center_width >= 1080 else 2 if center_width >= 720 else 1
        metrics_key = tuple(metrics.values()) + (action_layout_band,)
        if metrics_key == getattr(self, "_center_layout_metrics", None):
            return
        self._center_layout_metrics = metrics_key
        try:
            parent_frame.grid_rowconfigure(4, weight=3, minsize=metrics["list_minsize"])
            if hasattr(self, "current_item_label"):
                self.current_item_label.grid_configure(pady=(metrics["item_top"], metrics["item_bottom"]))
            if hasattr(self, "main_count_label"):
                self.main_count_label.configure(font=(self.DEFAULT_FONT, metrics["count_font"], 'bold'))
                self.main_count_label.grid_configure(pady=(metrics["count_top"], metrics["count_bottom"]))
            if hasattr(self, "main_progress_bar"):
                self.main_progress_bar.grid_configure(
                    pady=(0, metrics["progress_bottom"]),
                    padx=max(12, metrics["horizontal_pad"] - 8),
                )
            if hasattr(self, "scan_entry"):
                self.scan_entry.configure(font=(self.DEFAULT_FONT, metrics["entry_font"], 'bold'))
                self.scan_entry.grid_configure(ipady=metrics["entry_ipady"], padx=metrics["horizontal_pad"])
            button_frame = getattr(self, "_center_button_frame", None)
            if button_frame is not None:
                button_frame.grid_configure(pady=(metrics["button_top"], 0))
                self._layout_center_action_buttons(center_width, metrics["button_pad_x"])
        except (tk.TclError, AttributeError):
            return

    def _layout_center_action_buttons(self, center_width: int = 0, pad_x: int = 8) -> None:
        button_frame = getattr(self, "_center_button_frame", None)
        buttons = getattr(self, "_center_action_buttons", [])
        if button_frame is None or not buttons:
            return
        try:
            if center_width <= 0:
                center_width = button_frame.winfo_width()
            groups = getattr(self, "_center_action_groups", [])
            if groups:
                if center_width >= 1080:
                    group_columns = 3
                elif center_width >= 720:
                    group_columns = 2
                else:
                    group_columns = 1

                for group in groups:
                    group["frame"].grid_forget()
                for column in range(max(6, len(groups))):
                    button_frame.grid_columnconfigure(column, weight=0, uniform="")
                for index, group in enumerate(groups):
                    group["frame"].grid(
                        row=index // group_columns,
                        column=index % group_columns,
                        sticky='nsew',
                        padx=pad_x,
                        pady=(0, max(4, int(8 * self.scale_factor))),
                    )
                    button_frame.grid_columnconfigure(index % group_columns, weight=1, uniform="center_action_groups")
                    self._layout_center_action_group_buttons(group, center_width // max(1, group_columns), pad_x)
                return

            if center_width >= 1080:
                columns = len(buttons)
            elif center_width >= 620:
                columns = 3
            else:
                columns = 2
            for index, button in enumerate(buttons):
                button.grid_forget()
                button.grid(
                    row=index // columns,
                    column=index % columns,
                    sticky='ew',
                    padx=pad_x,
                    pady=(0, max(4, int(6 * self.scale_factor))),
                )
            for column in range(len(buttons)):
                button_frame.grid_columnconfigure(
                    column,
                    weight=1 if column < columns else 0,
                    uniform="center_actions" if column < columns else "",
                )
        except (tk.TclError, AttributeError):
            return

    def _layout_center_action_group_buttons(self, group: dict, group_width: int, pad_x: int = 8) -> None:
        buttons = group.get("buttons", [])
        if not buttons:
            return
        group_key = group.get("key", "")
        inner_frame = group.get("button_frame")
        if inner_frame is None:
            return
        try:
            if group_key == "primary":
                columns = 1
            elif group_key == "danger":
                columns = 1 if group_width < 720 else 2
            else:
                columns = min(len(buttons), 2 if group_width >= 360 else 1)

            for button in buttons:
                button.grid_forget()
            for column in range(max(3, len(buttons))):
                inner_frame.grid_columnconfigure(column, weight=0, uniform="")
            for index, button in enumerate(buttons):
                button.grid(
                    row=index // columns,
                    column=index % columns,
                    sticky='ew',
                    padx=max(2, pad_x // 2),
                    pady=(0, max(4, int(6 * self.scale_factor))),
                )
                inner_frame.grid_columnconfigure(index % columns, weight=1, uniform=f"center_{group_key}_actions")
        except (tk.TclError, AttributeError):
            return

    def _configure_widget_options(self, widget, **kwargs) -> None:
        if widget is None:
            return
        try:
            widget.configure(**kwargs)
            return
        except AttributeError:
            pass
        except tk.TclError:
            return
        try:
            widget.config(**kwargs)
            return
        except AttributeError:
            pass
        except tk.TclError:
            return
        try:
            for key, value in kwargs.items():
                widget[key] = value
        except (TypeError, KeyError, tk.TclError):
            return

    def _widget_exists(self, widget) -> bool:
        if widget is None:
            return False
        try:
            return bool(widget.winfo_exists())
        except (AttributeError, tk.TclError):
            return True

    def _update_action_button_states(self) -> None:
        active_tray = bool(getattr(getattr(self, "current_tray", None), "master_label_code", ""))
        scanned_count = len(getattr(getattr(self, "current_tray", None), "scanned_barcodes", []) or [])
        replacement_active = bool(getattr(self, "master_label_replace_state", None))
        exchange_dialog_open = self._widget_exists(getattr(self, "exchange_dialog", None))

        self._configure_widget_options(getattr(self, "reset_button", None), state=tk.NORMAL if active_tray else tk.DISABLED)
        self._configure_widget_options(getattr(self, "park_button", None), state=tk.NORMAL if active_tray else tk.DISABLED)
        self._configure_widget_options(getattr(self, "undo_button", None), state=tk.NORMAL if scanned_count else tk.DISABLED)
        self._configure_widget_options(
            getattr(self, "submit_tray_button", None),
            state=tk.NORMAL if active_tray and scanned_count else tk.DISABLED,
        )

        if replacement_active:
            self._configure_widget_options(
                getattr(self, "replace_master_label_button", None),
                text="교체 취소",
                style='Danger.TButton',
                state=tk.NORMAL,
            )
        else:
            self._configure_widget_options(
                getattr(self, "replace_master_label_button", None),
                text="🔄 완료 현품표 교체",
                style='Secondary.TButton',
                state=tk.DISABLED if active_tray or exchange_dialog_open else tk.NORMAL,
            )

        self._configure_widget_options(
            getattr(self, "exchange_button", None),
            text="교환 창 보기" if exchange_dialog_open else "🔁 개별 제품 교환",
            state=tk.DISABLED if active_tray or replacement_active else tk.NORMAL,
        )

    def _apply_left_sidebar_layout(self) -> None:
        parent_frame = getattr(self, "_left_sidebar_frame", None)
        if parent_frame is None:
            return
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        try:
            if getattr(self, "show_tray_image_var", None) is not None and self.show_tray_image_var.get():
                parent_frame.grid_rowconfigure(0, weight=3)
                parent_frame.grid_rowconfigure(1, weight=2, minsize=int(180 * scale))
            else:
                parent_frame.grid_rowconfigure(0, weight=1)
                parent_frame.grid_rowconfigure(1, weight=0, minsize=int(42 * scale))
        except (tk.TclError, AttributeError):
            return

    def _get_right_sidebar_layout_metrics(self, sidebar_height: int) -> Dict[str, int]:
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        sidebar_height = max(1, int(sidebar_height or 1))
        card_gap = self._clamped_int(sidebar_height * 0.012, int(6 * scale), int(14 * scale))
        card_minsize = self._clamped_int(sidebar_height * 0.115, int(78 * scale), int(140 * scale))
        legend_pad_y = self._clamped_int(sidebar_height * 0.016, int(8 * scale), int(18 * scale))
        return {"card_gap": card_gap, "card_minsize": card_minsize, "legend_pad_y": legend_pad_y}

    def _apply_right_sidebar_layout(self, event=None) -> None:
        parent_frame = getattr(self, "_right_sidebar_frame", None)
        if parent_frame is None:
            return
        try:
            height = parent_frame.winfo_height()
        except (tk.TclError, AttributeError):
            return
        if height <= 1:
            return
        metrics = self._get_right_sidebar_layout_metrics(height)
        metrics_key = (metrics["card_gap"], metrics["card_minsize"], metrics["legend_pad_y"])
        if metrics_key == getattr(self, "_right_sidebar_layout_metrics", None):
            return
        self._right_sidebar_layout_metrics = metrics_key
        try:
            for row in range(2, 6):
                parent_frame.grid_rowconfigure(row, weight=1, minsize=metrics["card_minsize"], uniform="info_cards")
            for card in getattr(self, "info_cards", {}).values():
                card["frame"].grid_configure(pady=(0, metrics["card_gap"]))
            legend_frame = getattr(self, "_legend_frame", None)
            if legend_frame is not None:
                legend_frame.configure(padding=(0, metrics["legend_pad_y"]))
        except (tk.TclError, AttributeError):
            return

    @staticmethod
    def _tree_available_width(tree: ttk.Treeview) -> int:
        parent_frame = tree.master
        available_width = parent_frame.winfo_width()
        for child in parent_frame.winfo_children():
            if isinstance(child, ttk.Scrollbar) and child.winfo_ismapped():
                available_width -= child.winfo_width()
                break
        return max(1, available_width)

    def _apply_tree_row_styles(self, tree: ttk.Treeview) -> None:
        tree.tag_configure('even', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT)
        tree.tag_configure('odd', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT)

    @staticmethod
    def _insert_tree_row(tree: ttk.Treeview, parent: str, index: str, *, values, iid=None, tags=()):
        try:
            return tree.insert(parent, index, values=values, iid=iid, tags=tags)
        except TypeError:
            return tree.insert(parent, index, values=values, iid=iid)

    def _adjust_summary_tree_columns(self, event=None):
        if not (hasattr(self, 'summary_tree') and self.summary_tree.winfo_exists()):
            return
        available_width = self._tree_available_width(self.summary_tree)
        if available_width <= 1:
            return
        if available_width < 420:
            headings = {"item_name_spec": "품목", "item_code": "코드", "count": "완료"}
            widths = {
                "item_name_spec": int(available_width * 0.42),
                "item_code": int(available_width * 0.34),
                "count": available_width - int(available_width * 0.42) - int(available_width * 0.34),
            }
        else:
            headings = {"item_name_spec": "품목명", "item_code": "품목코드", "count": "완료 수량"}
            count_width = max(100, min(150, int(available_width * 0.22)))
            code_width = max(130, min(210, int(available_width * 0.32)))
            widths = {
                "item_name_spec": max(1, available_width - code_width - count_width),
                "item_code": code_width,
                "count": count_width,
            }
        for col_id, heading in headings.items():
            self.summary_tree.heading(col_id, text=heading)
            self.summary_tree.column(col_id, width=max(1, widths[col_id]), stretch=tk.NO)

    def _adjust_parked_tree_columns(self, event=None):
        if not (hasattr(self, 'parked_tree') and self.parked_tree.winfo_exists()):
            return
        available_width = self._tree_available_width(self.parked_tree)
        if available_width <= 1:
            return
        if available_width < 380:
            item_heading, count_heading = "품목", "수량"
            count_width = max(58, int(available_width * 0.32))
        else:
            item_heading, count_heading = "품목명", "스캔 수량"
            count_width = max(128, min(180, int(available_width * 0.30)))
        count_width = min(count_width, max(1, available_width - 1))
        self.parked_tree.heading('item_name', text=item_heading)
        self.parked_tree.heading('scan_count', text=count_heading)
        self.parked_tree.column('scan_count', width=count_width, stretch=tk.NO)
        self.parked_tree.column('item_name', width=max(1, available_width - count_width), stretch=tk.NO)

    def _create_left_sidebar_content(self, parent_frame):
        self._left_sidebar_frame = parent_frame
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        top_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        top_frame.grid(row=0, column=0, sticky='nsew', pady=(0, 10))
        top_frame.grid_columnconfigure(0, weight=1)
        header_frame = ttk.Frame(top_frame, style='Sidebar.TFrame')
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        worker_info_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        worker_info_frame.grid(row=0, column=0, sticky='ew', padx=(0, 10))
        worker_info_frame.grid_columnconfigure(0, weight=1)
        self.worker_info_label = ttk.Label(
            worker_info_frame,
            text=f"작업자: {self.worker_name}",
            style='Sidebar.TLabel',
            justify='left',
        )
        self.worker_info_label.grid(row=0, column=0, sticky='w')
        self._bind_label_to_container_width(self.worker_info_label, worker_info_frame, padding=8)
        buttons_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        buttons_frame.grid(row=0, column=1, sticky='e')
        ttk.Button(buttons_frame, text="작업자 변경", command=self.change_worker, style='Secondary.TButton').pack(side=tk.LEFT, padx=(0, 5))
        self.summary_title_label = ttk.Label(
            top_frame,
            text="누적 작업 현황",
            style='Subtle.TLabel',
            font=(self.DEFAULT_FONT, int(14*self.scale_factor),'bold'),
            justify='left',
        )
        self.summary_title_label.grid(row=1, column=0, sticky='ew', pady=(0,10))
        self._bind_label_to_container_width(self.summary_title_label, top_frame, padding=8)
        tree_frame = ttk.Frame(top_frame)
        tree_frame.grid(row=2, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(2, weight=2)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        cols = ('item_name_spec', 'item_code', 'count')
        self.summary_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', style='Treeview')
        self.summary_tree.heading('item_name_spec', text='품목명')
        self.summary_tree.heading('item_code', text='품목코드')
        self.summary_tree.heading('count', text='완료 수량')
        
        # 기존의 고정 너비/minwidth/stretch 설정을 제거하고 anchor만 남깁니다.
        self.summary_tree.column('item_name_spec', anchor='w')
        self.summary_tree.column('item_code', anchor='w')
        self.summary_tree.column('count', anchor='center')
        self._apply_tree_row_styles(self.summary_tree)

        self.summary_tree.grid(row=0, column=0, sticky='nsew')
        sb1 = ttk.Scrollbar(tree_frame, orient='vertical', command=self.summary_tree.yview)
        self.summary_tree['yscrollcommand'] = sb1.set
        sb1.grid(row=0, column=1, sticky='ns')

        # tree_frame의 크기가 변경될 때마다 컬럼 너비를 조절하는 함수를 호출하도록 바인딩합니다.
        tree_frame.bind('<Configure>', self._adjust_summary_tree_columns)

        self.parked_title_label = ttk.Label(
            top_frame,
            text="보류 중인 트레이 (더블클릭으로 복원)",
            style='Subtle.TLabel',
            font=(self.DEFAULT_FONT, int(12*self.scale_factor),'bold'),
            justify='left',
        )
        self.parked_title_label.grid(row=3, column=0, sticky='ew', pady=(20,10))
        self._bind_label_to_container_width(self.parked_title_label, top_frame, padding=8)
        parked_tree_frame = ttk.Frame(top_frame)
        parked_tree_frame.grid(row=4, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(4, weight=1)
        parked_tree_frame.grid_columnconfigure(0, weight=1)
        parked_tree_frame.grid_rowconfigure(0, weight=1)
        parked_cols = ('item_name', 'scan_count')
        self.parked_tree = ttk.Treeview(parked_tree_frame, columns=parked_cols, show='headings', style='Treeview', height=4)
        self.parked_tree.heading('item_name', text='품목명')
        self.parked_tree.heading('scan_count', text='스캔 수량')
        self.parked_tree.column('item_name', anchor='w', stretch=tk.YES)
        self.parked_tree.column('scan_count', width=100, anchor='center', stretch=tk.NO)
        self._apply_tree_row_styles(self.parked_tree)
        self.parked_tree.grid(row=0, column=0, sticky='nsew')
        sb2 = ttk.Scrollbar(parked_tree_frame, orient='vertical', command=self.parked_tree.yview)
        self.parked_tree['yscrollcommand'] = sb2.set
        sb2.grid(row=0, column=1, sticky='ns')
        parked_tree_frame.bind('<Configure>', self._adjust_parked_tree_columns)
        self.parked_tree.bind("<Double-1>", self.on_parked_tray_select)
        bottom_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        bottom_frame.grid(row=1, column=0, sticky='nsew')
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_rowconfigure(1, weight=1)
        self.tray_image_checkbox = ttk.Checkbutton(bottom_frame, text="🖼️ 트레이 이미지 보기", variable=self.show_tray_image_var, command=self._update_tray_image_display, style='TCheckbutton')
        self.tray_image_checkbox.grid(row=0, column=0, sticky='w', pady=(10, 5))
        self.tray_image_label = ttk.Label(bottom_frame, background=self.COLOR_SIDEBAR_BG, anchor='center')
        self.tray_image_label.grid(row=1, column=0, sticky='nsew', pady=(0, 10))
        self._apply_left_sidebar_layout()

    def _create_center_content(self, parent_frame):
        self._center_content_frame = parent_frame
        self._center_layout_metrics = None
        parent_frame.grid_rowconfigure(4, weight=2, minsize=int(140 * self.scale_factor))
        parent_frame.grid_columnconfigure(0, weight=1)
        self._scanned_listbox_parent_frame = parent_frame
        self._scanned_listbox_layout_job = None
        self._scanned_listbox_layout_metrics = None
        scanned_metrics = self._get_scanned_listbox_metrics(720, 720, 300)
        self.current_item_label = ttk.Label(
            parent_frame,
            text="",
            style='ItemInfo.TLabel',
            justify='center',
            anchor='center',
        )
        self.current_item_label.grid(row=0, column=0, sticky='ew', pady=(10, 20))
        self._bind_label_to_container_width(self.current_item_label, parent_frame, padding=60, min_wraplength=240)
        self.main_count_label = ttk.Label(parent_frame, text=f"0 / {self.TRAY_SIZE}", style='MainCounter.TLabel', anchor='center')
        self.main_count_label.grid(row=1, column=0, sticky='ew', pady=(10, 20))
        self.main_progress_bar = ttk.Progressbar(parent_frame, orient='horizontal', mode='determinate', maximum=self.TRAY_SIZE, style='Big.Horizontal.TProgressbar')
        self.main_progress_bar.grid(row=2, column=0, sticky='ew', pady=(0, 20), padx=20)
        vcmd = (self.root.register(self._validate_barcode_input), '%P')
        self.scan_entry = tk.Entry(parent_frame, justify='center', font=(self.DEFAULT_FONT, int(30*self.scale_factor), 'bold'), bd=1, relief=tk.SOLID, bg=self.COLOR_INPUT_BG, fg=self.COLOR_TEXT, insertbackground=self.COLOR_PRIMARY, selectbackground=self.COLOR_PRIMARY, selectforeground='white', highlightbackground=self.COLOR_PRIMARY_SOFT, highlightcolor=self.COLOR_PRIMARY, highlightthickness=2, validate='key', validatecommand=vcmd)
        self.scan_entry.grid(row=3, column=0, sticky='ew', ipady=int(15*self.scale_factor), padx=30)
        self.scan_entry.bind('<Return>', self.process_barcode)
        self.scanned_listbox = tk.Listbox(parent_frame, font=(self.DEFAULT_FONT, scanned_metrics["font_size"]), relief=tk.SOLID, bd=1, bg=self.COLOR_CARD_BG, fg=self.COLOR_TEXT, highlightbackground=self.COLOR_BORDER, highlightcolor=self.COLOR_PRIMARY, highlightthickness=1, justify='center', selectbackground=self.COLOR_PRIMARY, selectforeground='white', activestyle='none', height=scanned_metrics["visible_rows"])
        self.scanned_listbox.grid(row=4, column=0, sticky='nsew', pady=(scanned_metrics["top_pady"], 0), padx=scanned_metrics["horizontal_pad"])
        parent_frame.bind('<Configure>', self._schedule_scanned_listbox_layout_refresh, add="+")
        self.scanned_listbox.bind('<Configure>', self._schedule_scanned_listbox_layout_refresh, add="+")
        self.root.after(0, self._apply_scanned_listbox_layout)
        button_frame = ttk.Frame(parent_frame)
        self._center_button_frame = button_frame
        button_frame.grid(row=5, column=0, sticky='ew', pady=(30, 0), padx=20)

        primary_group = ttk.LabelFrame(button_frame, text="주요 작업", style='TLabelframe', padding=(8, 8))
        support_group = ttk.LabelFrame(button_frame, text="보조 작업", style='TLabelframe', padding=(8, 8))
        danger_group = ttk.LabelFrame(button_frame, text="고위험 작업", style='TLabelframe', padding=(8, 8))
        primary_button_frame = ttk.Frame(primary_group, style='TFrame')
        support_button_frame = ttk.Frame(support_group, style='TFrame')
        danger_button_frame = ttk.Frame(danger_group, style='TFrame')
        primary_button_frame.grid(row=0, column=0, sticky='ew')
        support_button_frame.grid(row=0, column=0, sticky='ew')
        danger_button_frame.grid(row=0, column=0, sticky='ew')
        primary_group.grid_columnconfigure(0, weight=1)
        support_group.grid_columnconfigure(0, weight=1)
        danger_group.grid_columnconfigure(0, weight=1)

        self.submit_tray_button = ttk.Button(primary_button_frame, text="✅ 트레이 제출", command=self.submit_current_tray, style='Success.TButton')
        self.undo_button = ttk.Button(support_button_frame, text="↩️ 마지막 스캔 취소", command=self.undo_last_scan, state=tk.DISABLED, style='Secondary.TButton')
        self.park_button = ttk.Button(support_button_frame, text="⏸️ 트레이 보류", command=self.park_current_tray, style='Warning.TButton')
        self.reset_button = ttk.Button(danger_button_frame, text="현재 작업 리셋", command=self.reset_current_work, style='Danger.TButton')
        self.replace_master_label_button = ttk.Button(danger_button_frame, text="🔄 완료 현품표 교체", command=self.initiate_master_label_replacement, style='Secondary.TButton')
        self.exchange_button = ttk.Button(danger_button_frame, text="🔁 개별 제품 교환", command=self.show_exchange_dialog, style='Secondary.TButton')
        self._center_action_buttons = [
            self.reset_button,
            self.undo_button,
            self.park_button,
            self.replace_master_label_button,
            self.exchange_button,
            self.submit_tray_button,
        ]
        self._center_action_groups = [
            {"key": "primary", "frame": primary_group, "button_frame": primary_button_frame, "buttons": [self.submit_tray_button]},
            {"key": "support", "frame": support_group, "button_frame": support_button_frame, "buttons": [self.undo_button, self.park_button]},
            {
                "key": "danger",
                "frame": danger_group,
                "button_frame": danger_button_frame,
                "buttons": [self.reset_button, self.replace_master_label_button, self.exchange_button],
            },
        ]
        self._layout_center_action_buttons(720, int(8 * self.scale_factor))
        self._update_action_button_states()

    def _create_right_sidebar_content(self, parent_frame):
        self._right_sidebar_frame = parent_frame
        self._right_sidebar_layout_metrics = None
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        self.date_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(18*self.scale_factor),'bold'))
        self.date_label.grid(row=0, column=0, pady=(0,5))
        self.clock_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(24*self.scale_factor),'bold'))
        self.clock_label.grid(row=1, column=0, pady=(0,20))
        self.info_cards = {
            'status': self._create_info_card(parent_frame, "⏰ 현재 작업 상태"), 'stopwatch': self._create_info_card(parent_frame, "⏱️ 현재 트레이 소요 시간"),
            'avg_time': self._create_info_card(parent_frame, "📊 평균 완료 시간"), 'best_time': self._create_info_card(parent_frame, "🥇 30일 최고 기록")
        }
        card_order = ['status', 'stopwatch', 'avg_time', 'best_time']
        for i, card_key in enumerate(card_order):
            self.info_cards[card_key]['frame'].grid(row=i + 2, column=0, sticky='nsew', pady=(0, 10))
        best_time_card = self.info_cards['best_time']
        best_time_card['frame'].config(style='VelvetCard.TFrame')
        best_time_card['label'].config(style='Velvet.Subtle.TLabel')
        best_time_card['value'].config(style='Velvet.Value.TLabel')
        parent_frame.grid_rowconfigure(len(self.info_cards) + 2, weight=0)
        legend_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame', padding=(0,15))
        self._legend_frame = legend_frame
        legend_frame.grid(row=len(self.info_cards)+3, column=0, sticky='sew')
        ttk.Label(legend_frame, text="범례:", style='Subtle.TLabel').pack(anchor='w')
        ttk.Label(legend_frame, text="🟩 스캔 성공", style='Sidebar.TLabel', foreground=self.COLOR_SUCCESS).pack(anchor='w')
        ttk.Label(legend_frame, text="🟨 휴식/대기", style='Sidebar.TLabel', foreground="#B8860B").pack(anchor='w')
        parent_frame.bind('<Configure>', self._apply_right_sidebar_layout, add="+")
        self.root.after(0, self._apply_right_sidebar_layout)

    def _create_info_card(self, parent: ttk.Frame, label_text: str) -> Dict[str, ttk.Widget]:
        card = ttk.Frame(parent, style='Card.TFrame', padding=20)
        label = ttk.Label(card, text=label_text, style='Card.Subtle.TLabel', justify='center')
        label.pack(anchor='center')
        self._bind_label_to_container_width(label, card, padding=40)
        value_label = ttk.Label(card, text="-", style='Card.Value.TLabel')
        value_label.pack(expand=True, anchor='center')
        return {'frame': card, 'label': label, 'value': value_label}

    def _validate_barcode_input(self, p_text: str) -> bool:
        if not p_text:
            return True
        if re.search(r'[ㄱ-ㅎㅏ-ㅣ가-힣]', p_text):
            self.show_fullscreen_warning("입력 모드 오류", "한글이 입력되었습니다. 한/영 키를 눌러주세요.", self.COLOR_DANGER)
            return False
        return True

    def _schedule_focus_return(self, delay_ms: int = 1000):
        if self.focus_return_job:
            self.root.after_cancel(self.focus_return_job)
        self.focus_return_job = self.root.after(delay_ms, self._return_focus_to_scan_entry)

    def _return_focus_to_scan_entry(self):
        try:
            if hasattr(self, 'scan_entry') and self.scan_entry.winfo_exists() and self.root.focus_get() != self.scan_entry:
                self.scan_entry.focus_set()
            self.focus_return_job = None
        except Exception as e:
            print(f"포커스 설정 오류: {e}")

    def _update_current_item_label(self, instruction: str = ""):
        if not (hasattr(self, 'current_item_label') and self.current_item_label.winfo_exists()): return

        # 현품표 교체 상태 메시지 표시
        if self.master_label_replace_state == 'awaiting_old_completed':
            self.current_item_label['text'] = "완료된 현품표 교체: 교체할 기존 현품표를 스캔하세요."
            self.current_item_label['foreground'] = self.COLOR_PRIMARY
            return
        elif self.master_label_replace_state == 'awaiting_new_replacement':
            self.current_item_label['text'] = "완료된 현품표 교체: 적용할 새로운 현품표를 스캔하세요."
            self.current_item_label['foreground'] = self.COLOR_SUCCESS
            return
        elif self.master_label_replace_state == 'awaiting_additional_items':
            needed = self.replacement_context.get('items_needed', 0)
            scanned = len(self.replacement_context.get('additional_items', []))
            self.current_item_label['text'] = f"수량 추가: {needed - scanned}개 더 추가 스캔하세요. (총 {needed}개)"
            self.current_item_label['foreground'] = self.COLOR_PRIMARY
            return
        elif self.master_label_replace_state == 'awaiting_removed_items':
            needed = self.replacement_context.get('items_to_remove_count', 0)
            scanned = len(self.replacement_context.get('removed_items', []))
            self.current_item_label['text'] = f"수량 제외: {needed - scanned}개 더 제외 스캔하세요. (총 {needed}개)"
            self.current_item_label['foreground'] = self.COLOR_DANGER
            return

        # 기본 작업 상태 메시지
        if self.current_tray.master_label_code:
            name_part = f"현재 품목: {self.current_tray.item_name} ({self.current_tray.item_code})"
            spec_part = f" - {self.current_tray.item_spec}" if self.current_tray.item_spec else ""
            if not instruction:
                if not self.current_tray.scanned_barcodes:
                    instruction = "\n첫 번째 제품을 스캔하세요."
                else:
                    instruction = "\n다음 제품을 스캔하세요."
            self.current_item_label['text'] = f"{name_part}{spec_part}{instruction}"
            self.current_item_label['foreground'] = self.COLOR_TEXT
        else:
            self.current_item_label['text'] = "현품표 라벨을 스캔하여 작업을 시작하세요."
            self.current_item_label['foreground'] = self.COLOR_TEXT_SUBTLE
    
    def _sanitize_filename(self, filename: str) -> str:
        return sanitize_filename(filename)
    
    def process_barcode(self, event=None):
        """UI의 스캔 엔트리에서 바코드를 읽어 로직을 실행합니다."""
        raw_barcode = self.scan_entry.get().strip()
        self.scan_entry.delete(0, tk.END)
        # Use after(0) to allow the UI to update before potentially blocking logic
        scan_epoch = getattr(self, "_scan_callback_epoch", 0)
        self.root.after(0, self._process_barcode_if_current, raw_barcode, scan_epoch)

    def _invalidate_pending_scan_callbacks(self) -> None:
        self._scan_callback_epoch = int(getattr(self, "_scan_callback_epoch", 0)) + 1

    def _process_barcode_if_current(self, raw_barcode: str, scan_epoch: int) -> None:
        if scan_epoch != getattr(self, "_scan_callback_epoch", 0):
            return
        self._process_barcode_logic(raw_barcode)

    def _process_barcode_logic(self, raw_barcode: str):
        """바코드 데이터를 받아 실제 처리 로직을 수행합니다."""
        if not raw_barcode: return

        # 현품표 교체 모드 처리
        if self.master_label_replace_state:
            if self.master_label_replace_state in ['awaiting_old_completed', 'awaiting_new_replacement']:
                self._handle_historical_replacement_scan(raw_barcode)
            elif self.master_label_replace_state == 'awaiting_additional_items':
                self._handle_additional_item_scan(raw_barcode)
            elif self.master_label_replace_state == 'awaiting_removed_items':
                self._handle_removed_item_scan(raw_barcode)
            return
        self._update_last_activity_time()
        
        # --- 테스트 기능 트리거 ---
        test_command = (
            parse_internal_test_command(raw_barcode)
            if getattr(self, 'internal_test_commands_enabled', False)
            else None
        )
        if test_command:
            if test_command.action == "generate_test_logs":
                self._generate_test_logs(count=test_command.count)
            elif test_command.action == "create_parked_trays":
                threading.Thread(
                    target=self._create_test_parked_trays,
                    args=(test_command.item_code, test_command.count),
                    daemon=True,
                ).start()
            elif test_command.action == "run_auto_test":
                self.root.after(0, self._prompt_for_test_item)
            elif test_command.action == "error":
                messagebox.showerror("오류", f"보류 데이터 생성 코드 형식 오류입니다.\n{test_command.error_message}")
            return

        # --- 현품표 스캔 로직 ---
        if not self.current_tray.master_label_code:
            barcode = normalize_master_label_input(raw_barcode)
            qr_data = self._parse_new_format_qr(barcode)

            if qr_data:
                if self._is_completed_master_label(barcode):
                    self.show_fullscreen_warning("현품표 중복", f"이미 완료 처리된 현품표입니다.", self.COLOR_DANGER)
                    return

                parked_filepath = self._parked_store().existing_label_path_any_worker(master_label=barcode)

                if parked_filepath and os.path.exists(parked_filepath):
                    try:
                        parked_state = ParkedTrayStore.load(parked_filepath)
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        parked_state = {}
                    parked_worker = str(parked_state.get("worker_name") or "")
                    if parked_worker and parked_worker != self.worker_name:
                        self.show_fullscreen_warning("보류 작업 중복", f"다른 작업자 '{parked_worker}'님의 보류 작업에 같은 현품표가 있습니다.", self.COLOR_DANGER)
                        return
                    if messagebox.askyesno("보류 작업 발견", "이 현품표는 보류 중인 작업입니다.\n이 작업을 복원하시겠습니까?"):
                        self.restore_parked_tray(str(parked_filepath))
                    return
                try:
                    item_code = inspection_master_item_code(qr_data)
                    tray_quantity = parse_positive_quantity(qr_data, default=self.TRAY_SIZE)
                    if not item_code:
                        self.show_fullscreen_warning("QR코드 오류", "QR코드에 고객사 코드(CLC)가 없습니다.", self.COLOR_DANGER)
                        return
                    if tray_quantity is None:
                        self.show_fullscreen_warning("QR코드 오류", "QR코드 수량(QT)은 1 이상의 숫자여야 합니다.", self.COLOR_DANGER)
                        return
                    
                    matched_item = self._item_catalog().find_by_code(item_code)
                    if not matched_item:
                        self.show_fullscreen_warning("품목 없음", f"코드 '{item_code}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                        return
                    
                    self.current_tray = TraySession(
                        master_label_code=barcode, item_code=item_code, tray_size=tray_quantity,
                        item_name=matched_item.get('Item Name', ''), item_spec=matched_item.get('Spec', '')
                    )
                    event_name = 'MASTER_LABEL_SCANNED_NEW'
                    event_detail = qr_data
                except Exception as e:
                    self.show_fullscreen_warning("QR코드 분석 오류", f"새로운 현품표 QR코드를 해석하는 중 오류가 발생했습니다.\n{e}", self.COLOR_DANGER)
                    return
            else:
                if len(barcode) != self.ITEM_CODE_LENGTH:
                    self.show_fullscreen_warning("작업 시작 오류", f"잘못된 형식의 바코드입니다.\n{self.ITEM_CODE_LENGTH}자리 품목코드 또는 신규 QR을 스캔하세요.", self.COLOR_DANGER)
                    return
                
                matched_item = self._item_catalog().find_by_code(barcode)
                if not matched_item:
                    self.show_fullscreen_warning("품목 없음", f"현품표 코드 '{barcode}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                    return
                
                self.current_tray = TraySession(
                    master_label_code=barcode, item_code=barcode, tray_size=self.TRAY_SIZE,
                    item_name=matched_item.get('Item Name', ''), item_spec=matched_item.get('Spec', '')
                )
                event_name = 'MASTER_LABEL_SCANNED_OLD'
                event_detail = {'master_label_code': barcode}

            self.current_tray.stopwatch_seconds = 0
            self.current_tray.start_time = datetime.datetime.now()
            if not self._save_current_tray_state():
                self.current_tray = TraySession()
                self.show_status_message("현품표 상태 저장에 실패했습니다. 작업을 시작하지 않습니다.", self.COLOR_DANGER)
                return
            if not self._log_event(event_name, detail=event_detail, synchronous=True):
                if not self._delete_current_tray_state():
                    messagebox.showerror("작업 상태 정리 실패", "현품표 시작 기록 실패 후 현재 작업 상태 파일을 삭제하지 못했습니다.")
                self.current_tray = TraySession()
                self.show_status_message("현품표 시작 기록 저장에 실패했습니다. 작업을 시작하지 않습니다.", self.COLOR_DANGER)
                return
            # 현품표 스캔 시 이미지 자동 표시
            self.show_tray_image_var.set(True)
            self._update_tray_image_display()
            self._update_current_item_label()
            self._update_center_display()
            self._start_stopwatch()
            return
            
        # --- 제품 스캔 로직 ---
        scan_decision = decide_product_scan(self.current_tray, raw_barcode, item_code_length=self.ITEM_CODE_LENGTH)
        if scan_decision.status == SCAN_FORMAT_ERROR:
            if scan_decision.event_name:
                self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            self.show_fullscreen_warning("바코드 형식 오류", f"제품 바코드는 {self.ITEM_CODE_LENGTH}자리보다 길어야 합니다.", self.COLOR_DANGER); return
        if scan_decision.status == SCAN_MISMATCH:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("품목 코드 불일치!", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {self.current_tray.item_code}]", self.COLOR_DANGER)
            self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            self._save_current_tray_state()
            return
        if scan_decision.status == SCAN_DUPLICATE:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("바코드 중복!", f"제품 바코드 '{raw_barcode}'는 이미 스캔되었습니다.", self.COLOR_DANGER)
            self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            self._save_current_tray_state()
            return
        if scan_decision.status == SCAN_TRAY_FULL:
            self.show_fullscreen_warning("트레이 수량 초과", "현재 트레이는 이미 목표 수량에 도달했습니다. 트레이 완료 처리를 먼저 진행하세요.", self.COLOR_DANGER)
            self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            self._save_current_tray_state()
            return
        matching_codes = list(dict.fromkeys(self._item_catalog().matching_codes_in_barcode(raw_barcode)))
        if len(matching_codes) > 1:
            self.current_tray.mismatch_error_count += 1
            self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("품목 코드 모호", "제품 바코드에 여러 품목 코드가 포함되어 있습니다.", self.COLOR_DANGER)
            self._log_event(
                "SCAN_FAIL_AMBIGUOUS_ITEM_CODE",
                detail={
                    "expected": self.current_tray.item_code,
                    "scanned": raw_barcode,
                    "matching_item_codes": matching_codes,
                },
            )
            self._save_current_tray_state()
            return
        if len(matching_codes) == 1 and matching_codes[0] != self.current_tray.item_code:
            self.current_tray.mismatch_error_count += 1
            self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("품목 코드 불일치!", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {self.current_tray.item_code}]", self.COLOR_DANGER)
            self._log_event(
                "SCAN_FAIL_MISMATCH",
                detail={
                    "expected": self.current_tray.item_code,
                    "scanned": raw_barcode,
                    "matched_item_code": matching_codes[0],
                },
            )
            self._save_current_tray_state()
            return
        
        now = datetime.datetime.now()
        interval = max(0.0, (now - self.current_tray.scan_times[-1]).total_seconds()) if self.current_tray.scan_times else 0.0
        self.add_scanned_barcode(raw_barcode, now, interval)
        if not self._save_current_tray_state():
            self.current_tray.scanned_barcodes.pop()
            self.current_tray.scan_times.pop()
            self.scanned_listbox.delete(0)
            self._update_center_display()
            self._update_current_item_label()
            if not self.current_tray.scanned_barcodes:
                self.undo_button['state'] = tk.DISABLED
            self.show_status_message("스캔 상태 저장에 실패했습니다. 스캔을 반영하지 않습니다.", self.COLOR_DANGER)
            return
        self._log_event(
            'SCAN_OK',
            detail=build_scan_ok_detail(
                raw_barcode,
                interval_sec=interval,
                scan_position=len(self.current_tray.scanned_barcodes),
                scan_contract_version=self.SCAN_CONTRACT_VERSION,
            ),
        )
        
        if len(self.current_tray.scanned_barcodes) >= self.current_tray.tray_size:
            self.complete_tray()

    def add_scanned_barcode(self, barcode: str, scan_time: datetime.datetime, interval: float):
        if self.success_sound: self.success_sound.play()
        self.current_tray.scanned_barcodes.append(barcode)
        self.current_tray.scan_times.append(scan_time)
        count = len(self.current_tray.scanned_barcodes)
        row_text = f"({count}) {barcode}"
        self.scanned_listbox.insert(0, row_text)
        self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SUCCESS, 'fg': 'white'})
        self.root.after(
            400,
            self._reset_scanned_barcode_highlight,
            self.scanned_listbox,
            row_text,
            getattr(self, "_scan_callback_epoch", 0),
        )
        self._update_center_display()
        self._update_current_item_label()
        self.undo_button['state'] = tk.NORMAL

    def _reset_scanned_barcode_highlight(self, listbox, row_text: str, scan_epoch: int):
        if scan_epoch != getattr(self, "_scan_callback_epoch", 0):
            return
        if listbox is not getattr(self, "scanned_listbox", None):
            return
        try:
            if not listbox.winfo_exists():
                return
            for index in range(listbox.size()):
                if listbox.get(index) == row_text:
                    listbox.itemconfig(index, {'bg': self.COLOR_SIDEBAR_BG, 'fg': self.COLOR_TEXT})
                    return
        except tk.TclError:
            return

    def _completion_time_eligible_for_best_time(self, detail: Dict[str, Any]) -> bool:
        if (
            detail.get("has_error_or_reset") is not False
            or detail.get("is_partial_submission") is not False
            or detail.get("is_restored_session") is not False
            or detail.get("is_test_tray") is not False
        ):
            return False
        scan_count = detail.get("scan_count")
        tray_capacity = detail.get("tray_capacity")
        work_time = detail.get("work_time_sec")
        if (
            isinstance(scan_count, bool)
            or isinstance(tray_capacity, bool)
            or not isinstance(scan_count, int)
            or not isinstance(tray_capacity, int)
            or tray_capacity <= 0
            or scan_count != tray_capacity
            or isinstance(work_time, bool)
            or not isinstance(work_time, (int, float))
            or float(work_time) <= 0
        ):
            return False
        return float(work_time) / tray_capacity >= 5.0

    def complete_tray(self):
        is_test = self.current_tray.is_test_tray
        has_error = self.current_tray.has_error_or_reset
        is_partial = self.current_tray.is_partial_submission
        is_restored = self.current_tray.is_restored_session
        master_label = self.current_tray.master_label_code

        try:
            master_label_fields = self._parse_new_format_qr(master_label) or {}
            log_detail = build_tray_complete_detail(
                self.current_tray,
                master_label_fields=master_label_fields,
                end_time=datetime.datetime.now(),
            )
        except Exception as e:
            print(f"트레이 완료 기록 생성 실패: {e}")
            self.show_status_message("트레이 완료 기록 생성에 실패했습니다. 작업 상태를 보존합니다.", self.COLOR_DANGER)
            return False
        if not self._log_event('TRAY_COMPLETE', detail=log_detail, synchronous=True):
            self.show_status_message("트레이 완료 기록 저장에 실패했습니다. 작업 상태를 보존합니다.", self.COLOR_DANGER)
            return False

        self._stop_stopwatch(); self._stop_idle_checker(); self.undo_button['state'] = tk.DISABLED

        if not is_test and self._parse_new_format_qr(master_label):
            self._remember_completed_master_label(master_label)

        item_code = self.current_tray.item_code
        if item_code not in self.work_summary: self.work_summary[item_code] = {'name': self.current_tray.item_name, 'spec': self.current_tray.item_spec, 'count': 0, 'test_count': 0}
        
        if is_test: 
            self.work_summary[item_code]['test_count'] += 1
            self.show_status_message(f"테스트 트레이 완료!", self.COLOR_SUCCESS)
        else:
            self.work_summary[item_code]['count'] += 1
            if not is_partial: self.total_tray_count += 1
            
            # 조건에 맞는 경우 최고 기록 갱신
            if self._completion_time_eligible_for_best_time(log_detail):
                work_time = float(log_detail["work_time_sec"])
                self.completed_tray_times.append(work_time) # 주간 평균 계산을 위해 유지
                try:
                    self._update_best_time_records(work_time) # 30일 최고 기록 갱신
                except Exception as e:
                    print(f"최고 기록 갱신 실패: {e}")

            if is_partial: self.show_status_message(f"'{self.current_tray.item_name}' 부분 트레이 제출 완료!", self.COLOR_PRIMARY)
            else: self.show_status_message(f"'{self.current_tray.item_name}' 1 파렛트 완료!", self.COLOR_SUCCESS)
            
        self.current_tray = TraySession()
        self._invalidate_pending_scan_callbacks()
        if self._delete_current_tray_state() is False:
            self._log_event(
                'TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION',
                detail={
                    'master_label_code': master_label,
                    'item_code': item_code,
                },
            )
            self.show_status_message("트레이는 완료되었지만 임시 상태 파일 삭제에 실패했습니다.", self.COLOR_DANGER)
        self.scanned_listbox.delete(0, tk.END)
        self._update_all_summaries()
        self._reset_ui_to_waiting_state()
        self.tray_last_end_time = datetime.datetime.now()
        return True

    def _reset_ui_to_waiting_state(self):
        # UI 리셋 시 이미지 체크박스 해제
        self.show_tray_image_var.set(False)
        self._update_current_item_label()
        if self.info_cards.get('stopwatch'): self.info_cards['stopwatch']['value']['text'] = "00:00"
        
        self.is_idle = True # 프로그램 내부 상태를 유휴 상태로 설정
        
        self._set_idle_style(is_idle=True)
        self._update_center_display()
        self._update_tray_image_display()

    def undo_last_scan(self):
        self._update_last_activity_time()
        if not self.current_tray.scanned_barcodes: return
        last_barcode = self.current_tray.scanned_barcodes.pop()
        last_scan_time = self.current_tray.scan_times.pop()
        self.scanned_listbox.delete(0)
        if not self._save_current_tray_state():
            self.current_tray.scanned_barcodes.append(last_barcode)
            self.current_tray.scan_times.append(last_scan_time)
            row_text = f"({len(self.current_tray.scanned_barcodes)}) {last_barcode}"
            self.scanned_listbox.insert(0, row_text)
            if hasattr(self.scanned_listbox, 'itemconfig'):
                self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SUCCESS, 'fg': 'white'})
            self._update_center_display()
            self._update_current_item_label()
            self.show_status_message("스캔 취소 상태 저장에 실패했습니다. 기존 스캔을 유지합니다.", self.COLOR_DANGER)
            self._schedule_focus_return()
            return
        self._update_center_display()
        if not self._log_event('SCAN_UNDO', detail={'undone_barcode': last_barcode}, synchronous=True):
            self.current_tray.scanned_barcodes.append(last_barcode)
            self.current_tray.scan_times.append(last_scan_time)
            row_text = f"({len(self.current_tray.scanned_barcodes)}) {last_barcode}"
            self.scanned_listbox.insert(0, row_text)
            if hasattr(self.scanned_listbox, 'itemconfig'):
                self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SUCCESS, 'fg': 'white'})
            restore_saved = self._save_current_tray_state()
            self._update_center_display()
            self._update_current_item_label()
            self.undo_button['state'] = tk.NORMAL
            if not restore_saved:
                messagebox.showerror("작업 기록 실패", "스캔 취소 기록을 남기지 못했고 기존 스캔 상태 복원 저장에도 실패했습니다. 상태 파일을 확인하세요.")
            self.show_status_message("스캔 취소 기록 저장에 실패했습니다. 기존 스캔을 유지합니다.", self.COLOR_DANGER)
            self._schedule_focus_return()
            return
        self.show_status_message(f"'{last_barcode}' 스캔이 취소되었습니다.", self.COLOR_DANGER)
        self._update_current_item_label()
        if not self.current_tray.scanned_barcodes: self.undo_button['state'] = tk.DISABLED
        self._schedule_focus_return()

    def reset_current_work(self):
        self._update_last_activity_time()
        if self.current_tray.master_label_code and messagebox.askyesno("확인", "현재 진행중인 작업을 초기화하시겠습니까?"):
            reset_detail = {
                'master_label_code': self.current_tray.master_label_code,
                'scan_count_at_reset': len(self.current_tray.scanned_barcodes),
            }
            state_snapshot = self._current_tray_state_snapshot()
            if self._delete_current_tray_state() is False:
                self._log_event('TRAY_RESET_STATE_DELETE_FAILED', detail=reset_detail)
                messagebox.showerror("작업 삭제 실패", "현재 트레이 상태 파일을 삭제하지 못해 현재 작업을 유지합니다.")
                self.show_status_message("현재 작업 상태 파일 삭제에 실패했습니다. 현재 작업을 유지합니다.", self.COLOR_DANGER)
                return
            if not self._log_event('TRAY_RESET', detail=reset_detail, synchronous=True):
                restore_ok = self._save_tray_state_snapshot(state_snapshot)
                message = "초기화 기록을 남기지 못해 현재 작업을 유지합니다."
                if not restore_ok:
                    message += "\n현재 작업 상태 파일 복구에도 실패했습니다. 프로그램을 종료하기 전에 작업 상태를 다시 확인하세요."
                messagebox.showerror("작업 기록 실패", message)
                self.show_status_message("초기화 기록 저장에 실패했습니다. 현재 작업을 유지합니다.", self.COLOR_DANGER)
                return
            self._stop_stopwatch(); self._stop_idle_checker(); self.is_idle = False
            self.current_tray = TraySession()
            self._invalidate_pending_scan_callbacks()
            self.scanned_listbox.delete(0, tk.END)
            self._update_all_summaries(); self.undo_button['state'] = tk.DISABLED
            self._reset_ui_to_waiting_state()
            self.show_status_message("현재 작업이 초기화되었습니다.", self.COLOR_DANGER)
            self._schedule_focus_return()

    def submit_current_tray(self):
        self._update_last_activity_time()
        if not self.current_tray.master_label_code or not self.current_tray.scanned_barcodes:
            self.show_status_message("제출할 스캔 내역이 없습니다.", self.COLOR_TEXT_SUBTLE); return
        if messagebox.askyesno("트레이 제출 확인", f"현재 {len(self.current_tray.scanned_barcodes)}개 스캔되었습니다.\n이 트레이를 완료로 처리하시겠습니까?"):
            self._complete_current_tray_as_partial()
        self._schedule_focus_return()

    def _complete_current_tray_as_partial(self) -> bool:
        was_partial = self.current_tray.is_partial_submission
        self.current_tray.is_partial_submission = True
        if self.complete_tray():
            return True
        self.current_tray.is_partial_submission = was_partial
        return False

    def _update_all_summaries(self):
        self._update_summary_title()
        self._update_summary_list()
        self._update_avg_time()
        self._update_best_time()
        self._update_center_display()

    def _update_summary_title(self):
        if hasattr(self, 'summary_title_label') and self.summary_title_label.winfo_exists():
            self.summary_title_label.config(text=f"금일 작업 현황 (총 {self.total_tray_count} 파렛트)")

    def _update_summary_list(self):
        if not (hasattr(self, 'summary_tree') and self.summary_tree.winfo_exists()): return
        for i in self.summary_tree.get_children(): self.summary_tree.delete(i)
        for row_index, (item_code, data) in enumerate(sorted(self.work_summary.items())):
            count_display = f"{data.get('count', 0)} 파렛트"
            if data.get('test_count', 0) > 0: count_display += f" (테스트: {data['test_count']})"
            item_name_spec = f"{data.get('name', '')}"
            tag = 'even' if row_index % 2 == 0 else 'odd'
            self._insert_tree_row(self.summary_tree, '', 'end', values=(item_name_spec, item_code, count_display), tags=(tag,))

    def _update_avg_time(self):
        card = self.info_cards.get('avg_time')
        if not card or not card['value'].winfo_exists(): return
        if self.completed_tray_times:
            avg = sum(self.completed_tray_times) / len(self.completed_tray_times)
            card['value']['text'] = f"{int(avg // 60):02d}:{int(avg % 60):02d}"
        else:
            card['value']['text'] = "-"

    def _update_best_time(self):
        card = self.info_cards.get('best_time')
        if not card or not card['value'].winfo_exists(): return
        
        if self.best_time_records:
            # self.best_time_records 딕셔너리의 모든 값 중에서 최소값을 찾음
            best_time = min(self.best_time_records.values())
            card['value']['text'] = f"{int(best_time // 60):02d}:{int(best_time % 60):02d}"
        else:
            card['value']['text'] = "-"

    def _update_center_display(self):
        if not (hasattr(self, 'main_count_label') and self.main_count_label.winfo_exists()): return
        count = len(self.current_tray.scanned_barcodes)
        target_size = self.current_tray.tray_size if self.current_tray.master_label_code else self.TRAY_SIZE
        self.main_count_label['text'] = f"{count} / {target_size}"
        self.main_progress_bar['maximum'] = target_size
        self.main_progress_bar['value'] = count
        self._update_action_button_states()

    def _start_clock(self):
        if self.clock_job:
            self.root.after_cancel(self.clock_job)
            self.clock_job = None
        self._update_clock()

    def _update_clock(self):
        if not self.root.winfo_exists(): return
        now = datetime.datetime.now()
        if hasattr(self, 'date_label') and self.date_label.winfo_exists(): self.date_label['text'] = now.strftime('%Y-%m-%d')
        if hasattr(self, 'clock_label') and self.clock_label.winfo_exists(): self.clock_label['text'] = now.strftime('%H:%M:%S')
        self.clock_job = self.root.after(1000, self._update_clock)

    def _start_stopwatch(self, resume=False):
        if self.is_idle:
            self.is_idle = False
            self._set_idle_style(is_idle=False)
        if not resume:
            self.current_tray.stopwatch_seconds = 0
            self.current_tray.start_time = datetime.datetime.now()
        self._update_last_activity_time()
        if self.stopwatch_job: self.root.after_cancel(self.stopwatch_job)
        self._update_stopwatch()

    def _stop_stopwatch(self):
        if self.stopwatch_job: self.root.after_cancel(self.stopwatch_job); self.stopwatch_job = None

    def _update_stopwatch(self):
        if not self.root.winfo_exists() or self.is_idle: return
        mins, secs = divmod(int(self.current_tray.stopwatch_seconds), 60)
        if self.info_cards.get('stopwatch') and self.info_cards['stopwatch']['value'].winfo_exists():
            self.info_cards['stopwatch']['value']['text'] = f"{mins:02d}:{secs:02d}"
        self.current_tray.stopwatch_seconds += 1
        self.stopwatch_job = self.root.after(1000, self._update_stopwatch)

    def _start_idle_checker(self, *, activity_time: Optional[datetime.datetime] = None):
        self.last_activity_time = activity_time or datetime.datetime.now()
        if self.idle_check_job: self.root.after_cancel(self.idle_check_job)
        self._idle_check_epoch = int(getattr(self, "_idle_check_epoch", 0)) + 1
        self.idle_check_job = self.root.after(1000, self._check_for_idle, self._idle_check_epoch)

    def _stop_idle_checker(self):
        self._idle_check_epoch = int(getattr(self, "_idle_check_epoch", 0)) + 1
        if self.idle_check_job: self.root.after_cancel(self.idle_check_job); self.idle_check_job = None

    def _update_last_activity_time(self):
        activity_time = datetime.datetime.now()
        if self.is_idle:
            self._wakeup_from_idle(activity_time=activity_time)
        self.last_activity_time = activity_time

    def _check_for_idle(self, idle_epoch: Optional[int] = None):
        if idle_epoch is not None and idle_epoch != getattr(self, "_idle_check_epoch", 0):
            return
        if not self.root.winfo_exists() or self.is_idle: return
        if not self.current_tray.master_label_code:
            self.idle_check_job = self.root.after(1000, self._check_for_idle, getattr(self, "_idle_check_epoch", 0)); return
        if not self.last_activity_time:
            self.idle_check_job = self.root.after(1000, self._check_for_idle, getattr(self, "_idle_check_epoch", 0)); return
        time_since = (datetime.datetime.now() - self.last_activity_time).total_seconds()
        if time_since > self.IDLE_THRESHOLD_SEC:
            self._stop_stopwatch()
            self.is_idle = True
            self._set_idle_style(is_idle=True)
            self._log_event('IDLE_START', detail={'threshold_sec': self.IDLE_THRESHOLD_SEC})
            self._save_current_tray_state()
        else:
            self.idle_check_job = self.root.after(1000, self._check_for_idle, getattr(self, "_idle_check_epoch", 0))

    def _wakeup_from_idle(self, *, activity_time: Optional[datetime.datetime] = None):
        if not self.is_idle: return
        if not self.current_tray.master_label_code:
            self.is_idle = False
            self._set_idle_style(is_idle=False)
            self._start_idle_checker(activity_time=activity_time)
            return
        self.is_idle = False
        activity_time = activity_time or datetime.datetime.now()
        if self.last_activity_time:
            idle_duration = (activity_time - self.last_activity_time).total_seconds()
            self.current_tray.total_idle_seconds += idle_duration
            self._log_event('IDLE_END', detail={'duration_sec': f"{idle_duration:.2f}"})
            self._save_current_tray_state()
        self._set_idle_style(is_idle=False)
        self._start_idle_checker()
        self._start_stopwatch(resume=True)
        self.show_status_message(f"작업 재개.", self.COLOR_SUCCESS)

    def _set_idle_style(self, is_idle: bool):
        if not (hasattr(self, 'info_cards') and self.info_cards): return
        card_style = 'Idle.TFrame' if is_idle else 'Card.TFrame'
        label_style = 'Idle.Subtle.TLabel' if is_idle else 'Card.Subtle.TLabel'
        value_style = 'Idle.Value.TLabel' if is_idle else 'Card.Value.TLabel'
        for key in ['status', 'stopwatch', 'avg_time']:
            if self.info_cards.get(key):
                card = self.info_cards[key]
                card['frame']['style'] = card_style
                card['label']['style'] = label_style
                card['value']['style'] = value_style
        status_widget = self.info_cards['status']['value']
        if is_idle:
            status_widget['text'] = "대기 중"; status_widget['foreground'] = self.COLOR_TEXT
            self.show_status_message(f"휴식 상태입니다. 스캔하여 작업을 재개하세요.", self.COLOR_IDLE, duration=10000)
        else:
            status_widget['text'] = "작업 중"; status_widget['foreground'] = self.COLOR_SUCCESS

    def _on_column_resize(self, event: tk.Event, tree: ttk.Treeview, name: str):
        if tree.identify_region(event.x, event.y) == "separator":
            self.root.after(10, self._save_column_widths, tree, name)
            self._schedule_focus_return()

    def _save_column_widths(self, tree: ttk.Treeview, name: str):
        for col_id in tree["columns"]: self.column_widths[f'{name}_{col_id}'] = tree.column(col_id, "width")
        self.save_settings()

    def _start_warning_beep(self):
        if self.error_sound:
            self.error_sound.play(loops=-1)

    def _stop_warning_beep(self):
        if self.error_sound:
            self.error_sound.stop()

    def show_fullscreen_warning(self, title: str, message: str, color: str):
        self._start_warning_beep()
        popup = tk.Toplevel(self.root); popup.title(title); popup.attributes('-fullscreen', True)
        popup.configure(bg=color); popup.grab_set()
        def on_popup_close():
            self._stop_warning_beep(); popup.destroy()
            self._schedule_focus_return()
        title_font = (self.DEFAULT_FONT, int(60*self.scale_factor), 'bold')
        msg_font = (self.DEFAULT_FONT, int(30*self.scale_factor), 'bold')
        tk.Label(popup, text=title, font=title_font, fg='white', bg=color).pack(pady=(100, 50), expand=True)
        tk.Label(popup, text=message, font=msg_font, fg='white', bg=color, wraplength=self.root.winfo_screenwidth() - 100, justify=tk.CENTER).pack(pady=20, expand=True)
        btn = tk.Button(popup, text="확인 (클릭)", font=msg_font, command=on_popup_close, bg='white', fg=color, relief='flat', padx=20, pady=10)
        btn.pack(pady=50, expand=True); btn.focus_set()

    def _cancel_all_jobs(self):
        if self.clock_job: self.root.after_cancel(self.clock_job); self.clock_job = None
        if self.status_message_job: self.root.after_cancel(self.status_message_job); self.status_message_job = None
        if self.stopwatch_job: self._stop_stopwatch()
        if self.idle_check_job: self._stop_idle_checker()
        if self.focus_return_job: self.root.after_cancel(self.focus_return_job); self.focus_return_job = None
        self._stop_warning_beep()

    def on_closing(self):
        if messagebox.askokcancel("종료", "프로그램을 종료하시겠습니까?"):
            deleted_current_state_for_close = False
            if self.worker_name and self.current_tray.master_label_code:
                if messagebox.askyesno("작업 저장", "진행 중인 트레이를 저장하고 종료할까요?"):
                    if not self._save_current_tray_state():
                        messagebox.showerror("작업 저장 실패", "진행 중인 트레이 상태를 저장하지 못해 프로그램을 종료하지 않습니다.")
                        return
                else:
                    if not self._log_current_tray_discarded(reason='close_without_saving', synchronous=True):
                        messagebox.showerror("작업 기록 실패", "저장하지 않고 종료한 작업 기록을 남기지 못해 프로그램을 종료하지 않습니다.")
                        return
                    if not self._delete_current_tray_state():
                        messagebox.showerror("작업 삭제 실패", "현재 트레이 상태 파일을 삭제하지 못해 프로그램을 종료하지 않습니다.")
                        return
                    deleted_current_state_for_close = True
            if getattr(self, "master_label_replace_state", None):
                if not self._log_master_label_replacement_cancel(reason="app_close"):
                    messagebox.showerror("교체 취소 기록 실패", "현품표 교체 취소 기록을 남기지 못해 프로그램을 종료하지 않습니다.")
                    return
                self._reset_master_label_replacement_state()
            exchange_session = getattr(self, "current_exchange_session", ProductExchangeSession())
            if exchange_session.defective_barcodes or exchange_session.good_barcodes:
                if not self._cancel_exchange(reason="app_close"):
                    return
            if self.worker_name:
                if not self._log_event('WORK_END', detail={'message': 'User closed the program.'}, synchronous=True):
                    restore_notice = ""
                    if deleted_current_state_for_close and self.current_tray.master_label_code:
                        if self._save_current_tray_state():
                            restore_notice = "\n\n삭제했던 현재 트레이 상태 파일을 복구했습니다."
                        else:
                            restore_notice = "\n\n삭제했던 현재 트레이 상태 파일 복구에도 실패했습니다. 상태 폴더를 확인하세요."
                    messagebox.showerror("작업 종료 기록 실패", f"작업 종료 기록을 남기지 못해 프로그램을 종료하지 않습니다.{restore_notice}")
                    return
            if hasattr(self, 'paned_window') and self.paned_window.winfo_exists():
                try:
                    num_panes = len(self.paned_window.panes())
                    if num_panes > 1: self.paned_window_sash_positions = {str(i): self.paned_window.sashpos(i) for i in range(num_panes - 1)}
                except tk.TclError as e: print(f"종료 시 sash 위치 저장 오류: {e}")
            self.save_settings(); self._cancel_all_jobs(); self.log_queue.put(None)
            if self.log_thread.is_alive(): self.log_thread.join(timeout=1.0)
            pygame.quit()
            self.root.destroy()

    def _event_log_writer(self):
        while True:
            try:
                queued_item = self.log_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                if queued_item is None:
                    break
                if isinstance(queued_item, dict) and 'log_entry' in queued_item:
                    log_file_path = queued_item.get('log_file_path')
                    log_entry = queued_item['log_entry']
                else:
                    log_file_path = self.log_file_path
                    log_entry = queued_item
                if not log_file_path:
                    time.sleep(0.1)
                    self.log_queue.put(queued_item)
                    continue
                append_event_log_entry(log_file_path, log_entry)
            except Exception as e:
                error_message = f"로그 파일 쓰기 오류: {e}"
                self._record_log_write_error(error_message)
                print(error_message)
            finally:
                if hasattr(self.log_queue, "task_done"):
                    self.log_queue.task_done()

    def _record_log_write_error(self, message: str) -> None:
        error_message = str(message or "").strip()
        if not error_message:
            return
        if not hasattr(self, "log_write_errors") or self.log_write_errors is None:
            self.log_write_errors = []
        self.last_log_write_error = error_message
        self.log_write_errors.append(error_message)

    def _log_event(
        self,
        event_type: str,
        detail: Optional[Dict] = None,
        synchronous: bool = False,
        canonical_event_name: Optional[str] = None,
    ) -> bool:
        if not self.worker_name: return False
        if not self.log_file_path: return False
        try:
            enriched_detail = self._plan_b_event_detail(
                event_type,
                detail or {},
                canonical_event_name=canonical_event_name,
            )
            details_json = json.dumps(enriched_detail, ensure_ascii=False, allow_nan=False) if enriched_detail else ''
        except (TypeError, ValueError) as e:
            print(f"로그 상세 직렬화 오류: {e}")
            return False
        log_entry = { 'timestamp': datetime.datetime.now().isoformat(), 'worker_name': self.worker_name, 'event': event_type, 'details': details_json }
        if synchronous:
            try:
                if hasattr(self, "log_queue") and hasattr(self.log_queue, "join"):
                    self.log_queue.join()
                append_event_log_entry(self.log_file_path, log_entry, durable=True)
                if event_type in {"TRAY_COMPLETE", "PRODUCT_EXCHANGE_COMPLETED"}:
                    self._trigger_session_direct_sync(event_type)
                return True
            except Exception as e:
                error_message = f"로그 파일 쓰기 오류: {e}"
                self._record_log_write_error(error_message)
                print(error_message)
                return False
        self.log_queue.put({'log_file_path': self.log_file_path, 'log_entry': log_entry})
        return True

    def _trigger_session_direct_sync(self, reason: str) -> None:
        app_root = getattr(self, "application_path", "")
        direct_sync_root = getattr(self, "direct_sync_program_data_root", "")
        scan_source_dir = getattr(self, "direct_sync_scan_source_dir", "")
        if not (app_root and direct_sync_root and scan_source_dir):
            return
        try:
            start_session_direct_sync(
                app_root=app_root,
                direct_sync_root=direct_sync_root,
                scan_source_dir=scan_source_dir,
                reason=reason,
            )
        except Exception as exc:
            print(f"direct-sync session trigger failed: {exc}")

    def _plan_b_event_detail(
        self,
        event_type: str,
        detail: Dict[str, Any],
        *,
        canonical_event_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        return plan_b_event_detail(
            event_type,
            detail,
            source_system=self.SOURCE_SYSTEM,
            source_transport_or_dataset=self.SOURCE_TRANSPORT_OR_DATASET,
            canonical_event_name=canonical_event_name,
        )

    @staticmethod
    def _stable_hash(data: Dict[str, Any]) -> str:
        return stable_hash(data)

    def show_status_message(self, message: str, color: Optional[str] = None, duration: int = 4000):
        if self.status_message_job: self.root.after_cancel(self.status_message_job)
        self.status_label['text'] = message; self.status_label['fg'] = color or self.COLOR_TEXT
        self.status_message_job = self.root.after(duration, self._reset_status_message)

    def _reset_status_message(self):
        if hasattr(self, 'status_label') and self.status_label.winfo_exists():
            self.status_label['text'] = "준비"; self.status_label['fg'] = self.COLOR_TEXT

    def _clear_tray_image_label(self, text: str = "", foreground: Optional[str] = None) -> None:
        if not (hasattr(self, 'tray_image_label') and self.tray_image_label.winfo_exists()):
            return
        self.tray_image_label.image = None
        options: Dict[str, Any] = {"image": "", "text": text}
        if foreground is not None:
            options["foreground"] = foreground
        self.tray_image_label.config(**options)

    def _update_tray_image_display(self):
        if not (hasattr(self, 'tray_image_label') and self.tray_image_label.winfo_exists()): return
        self._apply_left_sidebar_layout()
        if self.show_tray_image_var.get():
            if self.current_tray.item_code:
                item_info = self._item_catalog().find_by_code(self.current_tray.item_code)
                if item_info and 'Tray Image' in item_info and item_info['Tray Image']:
                    try:
                        parent_frame = self.tray_image_label.master
                        max_w = parent_frame.winfo_width() - 20
                        max_h = (self.left_pane.winfo_height() // 2) - 40
                        if max_w < 20: max_w = 250
                        if max_h < 20: max_h = 250
                        img_path = resource_path(item_info['Tray Image'])
                        img = Image.open(img_path)
                        original_width, original_height = img.size
                        ratio = min(max_w / original_width, max_h / original_height)
                        new_width = int(original_width * ratio)
                        new_height = int(original_height * ratio)
                        resized_img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                        photo = ImageTk.PhotoImage(resized_img)
                        self.tray_image_label.config(image=photo, text="")
                        self.tray_image_label.image = photo
                    except Exception as e:
                        self._clear_tray_image_label(f"이미지 오류:\n{e}", self.COLOR_DANGER)
                else:
                    self._clear_tray_image_label("이 품목의\n트레이 이미지가\n등록되지 않았습니다.", self.COLOR_TEXT_SUBTLE)
            else:
                self._clear_tray_image_label("현품표를 먼저\n스캔해주세요.", self.COLOR_TEXT_SUBTLE)
        else:
            self._clear_tray_image_label("")
        self._schedule_focus_return()

    def park_current_tray(self, *, confirm: bool = True) -> bool:
        """현재 진행 중인 트레이를 보류 목록으로 이동시킵니다."""
        if not self.current_tray.master_label_code:
            self.show_status_message("보류할 작업이 없습니다.", self.COLOR_DANGER)
            return False

        if confirm and not messagebox.askyesno("트레이 보류 확인", "현재 작업을 잠시 보류하고 다른 작업을 시작하시겠습니까?"):
            return False

        master_label = self.current_tray.master_label_code

        try:
            state_snapshot = self._current_tray_state_snapshot()
            parked_path = self._parked_store().save_state(
                state_snapshot,
                worker_name=self.worker_name,
                master_label=master_label,
            )
            if not self._delete_current_tray_state():
                try:
                    ParkedTrayStore.delete(parked_path)
                except Exception as rollback_error:
                    print(f"보류 파일 롤백 실패: {rollback_error}")
                messagebox.showerror("오류", "현재 작업 상태 파일을 삭제하지 못해 보류 처리를 중단했습니다.")
                return False

            try:
                parked_logged = self._log_event(
                    'TRAY_PARKED',
                    detail={
                        'master_label_code': self.current_tray.master_label_code,
                        'item_code': self.current_tray.item_code,
                        'item_name': self.current_tray.item_name,
                        'scan_count': len(self.current_tray.scanned_barcodes),
                        'tray_capacity': self.current_tray.tray_size,
                    },
                    synchronous=True,
                )
            except Exception as log_error:
                print(f"보류 감사 로그 기록 실패: {log_error}")
                parked_logged = False

            if not parked_logged:
                try:
                    ParkedTrayStore.delete(parked_path)
                except Exception as rollback_error:
                    print(f"보류 파일 롤백 실패: {rollback_error}")
                restore_ok = self._save_tray_state_snapshot(state_snapshot)
                message = "보류 기록을 남기지 못해 보류 처리를 중단했습니다."
                if not restore_ok:
                    message += "\n현재 작업 상태 파일 복구에도 실패했습니다. 프로그램을 종료하기 전에 작업 상태를 다시 확인하세요."
                messagebox.showerror("오류", message)
                return False

            self.current_tray = TraySession()
            self._invalidate_pending_scan_callbacks()
            self.scanned_listbox.delete(0, tk.END)
            self._reset_ui_to_waiting_state()
            self._update_all_summaries()

            self._update_parked_trays_list()
            self.show_status_message("작업을 보류 처리했습니다. 새 현품표를 스캔하세요.", self.COLOR_PRIMARY)
            return True

        except Exception as e:
            messagebox.showerror("오류", f"작업 보류 중 오류가 발생했습니다: {e}")
            return False

    def _update_parked_trays_list(self):
        """parked_trays 폴더를 읽어 UI 목록을 갱신합니다."""
        if not hasattr(self, 'parked_tree'): return

        for i in self.parked_tree.get_children():
            self.parked_tree.delete(i)

        try:
            self._quarantine_invalid_parked_tray_files()
            for row_index, summary in enumerate(self._parked_store().list_for_worker(self.worker_name)):
                tag = 'even' if row_index % 2 == 0 else 'odd'
                self._insert_tree_row(self.parked_tree, '', 'end', values=(summary.item_name, f"{summary.scan_count} 개"), iid=str(summary.path), tags=(tag,))
        except Exception as e:
            print(f"보류 목록 갱신 중 오류: {e}")

    def _quarantine_invalid_parked_tray_files(self):
        store = self._parked_store()
        if not store.directory.exists():
            return
        for path in sorted(store.directory.glob("parked_*.json")):
            try:
                state = ParkedTrayStore.load(path)
                validate_tray_state(state, default_tray_size=getattr(self, "TRAY_SIZE", 60))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TrayStateValidationError):
                try:
                    quarantined_path = quarantine_tray_state_file(path)
                except Exception as quarantine_error:
                    print(f"손상된 보류 작업 파일 격리 실패: {quarantine_error}")
                    continue
                if hasattr(self, "show_status_message"):
                    self.show_status_message(f"손상된 보류 작업 파일을 격리했습니다: {quarantined_path}", getattr(self, "COLOR_DANGER", "red"))

    def on_parked_tray_select(self, event):
        """보류 목록에서 트레이를 더블 클릭했을 때 실행됩니다."""
        selected_item_iid = self.parked_tree.focus()
        if not selected_item_iid: return
        filepath = selected_item_iid
        self.restore_parked_tray(filepath)

    def _is_parked_tray_path(self, filepath: str) -> bool:
        try:
            parked_dir = self._parked_store().directory.resolve()
            candidate_path = Path(filepath).resolve()
        except (OSError, RuntimeError, ValueError):
            return False
        return candidate_path.is_relative_to(parked_dir)

    def restore_parked_tray(self, filepath: str):
        """파일 경로를 받아 보류된 트레이를 복원합니다."""
        if not self._is_parked_tray_path(filepath):
            messagebox.showwarning("복원 실패", "보류 작업 폴더 밖의 파일은 복원할 수 없습니다. 목록을 갱신합니다.")
            self._update_parked_trays_list()
            return
        try:
            saved_state = ParkedTrayStore.load(filepath)
            validate_tray_state(saved_state, default_tray_size=self.TRAY_SIZE)
        except FileNotFoundError:
                messagebox.showwarning("복원 실패", "선택한 보류 작업 파일을 찾을 수 없습니다. 목록을 갱신합니다.")
                self._update_parked_trays_list()
                return
        except (UnicodeDecodeError, json.JSONDecodeError, TrayStateValidationError) as e:
            try:
                quarantined_path = quarantine_tray_state_file(filepath)
                messagebox.showerror("오류", f"보류 작업 파일이 손상되어 격리했습니다.\n\n{e}\n\n격리 파일: {quarantined_path}")
            except Exception as quarantine_error:
                messagebox.showerror("오류", f"작업 복원 중 오류가 발생했고 격리에도 실패했습니다: {quarantine_error}")
            self._update_parked_trays_list()
            return
        parked_worker = str(saved_state.get("worker_name") or "")
        if parked_worker and parked_worker != self.worker_name:
            messagebox.showwarning("복원 실패", "다른 작업자의 보류 작업은 복원할 수 없습니다. 목록을 갱신합니다.")
            self._update_parked_trays_list()
            return
        parked_master_label = str(saved_state.get("master_label_code") or "")
        if parked_master_label and self._is_completed_master_label(parked_master_label):
            try:
                ParkedTrayStore.delete(filepath)
            except Exception:
                quarantined_path = quarantine_tray_state_file(filepath)
                messagebox.showwarning("복원 실패", f"이미 완료된 보류 작업이라 복원하지 않고 격리했습니다.\n\n격리 파일: {quarantined_path}")
            else:
                messagebox.showwarning("복원 실패", "이미 완료된 보류 작업이라 복원하지 않고 삭제했습니다.")
            self._update_parked_trays_list()
            return
        discard_current_for_restore = False
        if self.current_tray.master_label_code:
            res = messagebox.askyesnocancel("작업 전환 확인", "현재 진행 중인 작업이 있습니다. 이 작업을 보류하고 선택한 작업을 불러오시겠습니까?\n\n('아니오'를 누르면 현재 작업은 삭제됩니다.)")
            if res is True:
                if not self.park_current_tray():
                    return
            elif res is None: # Cancel
                return
            else:
                discard_current_for_restore = True

        state_path: Optional[Path] = None
        previous_state_exists = False
        previous_state_bytes: Optional[bytes] = None
        try:
            state_path = Path(self.save_folder) / self.CURRENT_TRAY_STATE_FILE
            if state_path.exists():
                previous_state_exists = True
                previous_state_bytes = state_path.read_bytes()
        except (OSError, TypeError, AttributeError):
            state_path = None
            previous_state_exists = False
            previous_state_bytes = None

        def rollback_current_state_file() -> None:
            if state_path is None:
                return
            if previous_state_exists and previous_state_bytes is not None:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                rollback_path = state_path.with_name(f"{state_path.name}.rollback.{os.getpid()}.{uuid.uuid4().hex}")
                rollback_path.write_bytes(previous_state_bytes)
                os.replace(rollback_path, state_path)
            else:
                try:
                    state_path.unlink()
                except FileNotFoundError:
                    pass

        try:
            restored_tray = tray_session_from_state(
                saved_state,
                session_factory=TraySession,
                default_tray_size=self.TRAY_SIZE,
            )
            restored_state = tray_session_to_state(restored_tray, worker_name=self.worker_name)
            if not self._save_tray_state_snapshot(restored_state):
                raise RuntimeError("복원한 보류 작업의 현재 상태 저장에 실패했습니다.")
            if discard_current_for_restore:
                if not self._log_current_tray_discarded(reason='restore_parked_overwrite_current', synchronous=True):
                    rollback_errors: List[str] = []
                    try:
                        rollback_current_state_file()
                    except OSError as rollback_error:
                        rollback_errors.append(f"현재 상태 복원 실패: {rollback_error.__class__.__name__}")
                    rollback_notice = f"\n\n{'; '.join(rollback_errors)}" if rollback_errors else ""
                    messagebox.showerror("작업 기록 실패", f"현재 작업 삭제 기록을 남기지 못해 보류 작업을 복원하지 않습니다.{rollback_notice}")
                    self._update_parked_trays_list()
                    return
            try:
                ParkedTrayStore.delete(filepath)
            except Exception as delete_error:
                if state_path is not None:
                    try:
                        rollback_current_state_file()
                    except OSError as rollback_error:
                        raise RuntimeError("보류 작업 파일 삭제에 실패했고 현재 상태 롤백에도 실패했습니다.") from rollback_error
                raise RuntimeError("보류 작업 파일 삭제에 실패했습니다. 현재 작업 상태를 복원 전으로 되돌렸습니다.") from delete_error
            restore_detail = {
                'master_label_code': restored_tray.master_label_code,
                'item_code': restored_tray.item_code,
                'item_name': restored_tray.item_name,
                'scan_count': len(restored_tray.scanned_barcodes),
                'tray_capacity': restored_tray.tray_size,
            }
            if not self._log_event(
                'TRAY_RESTORED_FROM_PARK',
                detail=restore_detail,
                synchronous=True,
                canonical_event_name='TRAY_RESTORED',
            ):
                rollback_errors: List[str] = []
                if state_path is not None:
                    try:
                        rollback_current_state_file()
                    except OSError as rollback_error:
                        rollback_errors.append(f"현재 상태 복원 실패: {rollback_error.__class__.__name__}")
                try:
                    atomic_write_json(filepath, saved_state, indent=4, ensure_ascii=False)
                except Exception as restore_error:
                    rollback_errors.append(f"보류 파일 복구 실패: {restore_error.__class__.__name__}")
                rollback_notice = f"\n\n{'; '.join(rollback_errors)}" if rollback_errors else ""
                messagebox.showerror("작업 기록 실패", f"보류 작업 복원 기록을 남기지 못해 복원을 취소했습니다.{rollback_notice}")
                self._update_parked_trays_list()
                return
            self.current_tray = restored_tray
            self._invalidate_pending_scan_callbacks()
            self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)
            
            self.show_validation_screen()

            # 복원 후 이미지 자동 표시
            self.show_tray_image_var.set(True)
            self._update_tray_image_display()

            self.show_status_message(f"'{self.current_tray.item_name}' 작업을 다시 시작합니다.", self.COLOR_SUCCESS)

        except Exception as e:
            messagebox.showerror("오류", f"작업 복원 중 오류가 발생했습니다: {e}")
            
    # ####################################################################
    # # [추가된 부분] 테스트 및 자동화 기능
    # ####################################################################

    def _generate_test_logs(self, count: int):
        """지정된 수량만큼 식별 가능한 테스트 로그를 생성합니다."""
        if not self.items_data:
            self.show_fullscreen_warning("오류", "품목 데이터(Item.csv)가 없습니다.", self.COLOR_DANGER)
            return

        if not self.current_tray.master_label_code:
            random_item = random.choice(self.items_data)
            self.current_tray = TraySession(
                item_code = random_item.get('Item Code', ''),
                item_name = random_item.get('Item Name', ''),
                item_spec = random_item.get('Spec', ''),
                tray_size = self.TRAY_SIZE,
                master_label_code = f"PHS=1|CLC={random_item.get('Item Code', '')}|WID=TEST-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}|SPC=A14|FPB=A146000306|OBD={datetime.date.today().strftime('%Y-%m-%d')}|PJT=KMC_TEST|QT={self.TRAY_SIZE}",
                is_test_tray = True
            )
            self._log_event('RANDOM_TEST_SESSION_START', detail={'item_code': self.current_tray.item_code})
            self._update_current_item_label()
            self._update_center_display()
            self._start_stopwatch()
            self.root.update_idletasks()

        original_tray_info = self.current_tray
        items_to_generate = count
        self.show_status_message(f"테스트 로그 {count}개 생성 중...", self.COLOR_PRIMARY)
        self.root.update_idletasks()

        while items_to_generate > 0:
            remaining_space = original_tray_info.tray_size - len(self.current_tray.scanned_barcodes)
            scans_for_this_tray = min(items_to_generate, remaining_space)

            for i in range(scans_for_this_tray):
                barcode = f"TEST-{self.current_tray.item_code}-{datetime.datetime.now().strftime('%f')}-{i}"
                self.add_scanned_barcode(barcode, datetime.datetime.now(), 0.1)
                self.root.update()
                time.sleep(0.01)

            items_to_generate -= scans_for_this_tray

            if len(self.current_tray.scanned_barcodes) >= original_tray_info.tray_size and items_to_generate > 0:
                self.complete_tray()
                self.root.update_idletasks()
                time.sleep(0.5)

                self.current_tray = TraySession(
                    item_code=original_tray_info.item_code,
                    item_name=original_tray_info.item_name,
                    item_spec=original_tray_info.item_spec,
                    tray_size=original_tray_info.tray_size,
                    master_label_code=f"PHS=1|CLC={original_tray_info.item_code}|WID=RSTEST-{datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')}|SPC=A14|FPB=A146000306|OBD={datetime.date.today().strftime('%Y-%m-%d')}|PJT=KMC_RESTART|QT={original_tray_info.tray_size}",
                    is_test_tray=True
                )
                self._update_current_item_label()
                self._update_center_display()
                self._start_stopwatch()
                self.root.update_idletasks()

        if self.current_tray.master_label_code and self.current_tray.scanned_barcodes:
            if not self._complete_current_tray_as_partial():
                return
        self.show_status_message(f"테스트 로그 {count}개 생성을 완료했습니다.", self.COLOR_SUCCESS)

    def _create_test_parked_trays(self, item_code: str, count: int):
        """지정된 품목과 수량으로 테스트용 보류 트레이를 생성합니다."""
        matched_item = self._item_catalog().find_by_code(item_code)
        if not matched_item:
            self.show_status_message(f"오류: 품목코드 '{item_code}'를 찾을 수 없습니다.", self.COLOR_DANGER)
            return
        
        self.show_status_message(f"테스트 보류 데이터 {count}개 생성 중...", self.COLOR_PRIMARY)
        for i in range(count):
            scanned_count = random.randint(1, self.TRAY_SIZE -1)
            master_label = f"CLC={item_code}|QT=60|LOT=TESTLOT{i}|DATE={datetime.date.today().strftime('%Y%m%d')}"
            
            state = {
                'worker_name': self.worker_name,
                'master_label_code': master_label,
                'item_code': item_code,
                'item_name': matched_item.get('Item Name', ''),
                'item_spec': matched_item.get('Spec', ''),
                'scanned_barcodes': [f"{item_code}-TEST-BARCODE-{j}" for j in range(scanned_count)],
                'scan_times': [datetime.datetime.now().isoformat() for _ in range(scanned_count)],
                'tray_size': self.TRAY_SIZE,
                'mismatch_error_count': 0, 'total_idle_seconds': 0.0, 'stopwatch_seconds': random.uniform(30, 300),
                'start_time': datetime.datetime.now().isoformat(),
                'has_error_or_reset': False, 'is_test_tray': True, 'is_partial_submission': False
            }
            
            self._parked_store().save_state(
                state,
                worker_name=self.worker_name,
                master_label=master_label,
            )
        
        self.show_status_message(f"테스트 보류 데이터 {count}개 생성 완료.", self.COLOR_SUCCESS)
        self._update_parked_trays_list()

    def _prompt_for_test_item(self):
        """자동 테스트를 실행할 품목을 선택하는 대화 상자를 표시합니다."""
        if not self.items_data:
            messagebox.showerror("오류", "자동 테스트를 실행할 품목 데이터가 없습니다.")
            return
        if self.current_tray.master_label_code:
            messagebox.showwarning("경고", "진행 중인 작업이 있습니다. 자동 테스트를 실행하려면 현재 작업을 완료하거나 리셋해주세요.")
            return

        popup = tk.Toplevel(self.root)
        popup.title("자동 테스트 시작")
        popup.geometry("400x200")
        popup.transient(self.root)
        popup.grab_set()

        ttk.Label(popup, text="테스트할 품목을 선택하세요:").pack(pady=10)
        
        item_map = {f"{item['Item Name']} ({item['Item Code']})": item['Item Code'] for item in self.items_data}
        item_names = list(item_map.keys())
        
        combo = ttk.Combobox(popup, values=item_names, state="readonly", width=50)
        combo.pack(pady=5, padx=10)
        if item_names:
            combo.current(0)
            
        def start_test():
            selected_display_name = combo.get()
            if selected_display_name:
                item_code = item_map[selected_display_name]
                popup.destroy()
                threading.Thread(target=self._run_auto_test_sequence, args=(item_code,), daemon=True).start()

        ttk.Button(popup, text="테스트 시작", command=start_test).pack(pady=20)
        
    def _run_auto_test_sequence(self, item_code: str):
        """선택된 품목에 대해 전체 작업 흐름을 자동으로 시뮬레이션합니다."""
        try:
            self.show_status_message("자동 테스트 시작...", self.COLOR_PRIMARY)
            time.sleep(2)

            # 1. 현품표 스캔 시뮬레이션 (직접 TraySession 생성)
            self.show_status_message("1. 현품표 스캔 시뮬레이션", self.COLOR_PRIMARY)
            master_label = f"CLC={item_code}|QT={self.TRAY_SIZE}|LOT=AUTOTEST|DATE={datetime.date.today().strftime('%Y%m%d')}"

            # 품목 정보 찾기
            matched_item = self._item_catalog().find_by_code(item_code)
            if not matched_item:
                raise ValueError(f"자동 테스트 중 품목코드 '{item_code}'를 찾지 못했습니다.")

            # is_test_tray=True로 설정하여 테스트 세션을 직접 생성
            self.current_tray = TraySession(
                master_label_code=master_label,
                item_code=item_code,
                tray_size=self.TRAY_SIZE,
                item_name=matched_item.get('Item Name', ''),
                item_spec=matched_item.get('Spec', ''),
                is_test_tray=True  # 테스트 트레이임을 명시
            )

            # 기존 process_barcode 함수가 하던 UI 업데이트 및 스톱워치 시작을 수동으로 호출
            self.show_tray_image_var.set(True)
            self._update_tray_image_display()
            self._update_current_item_label()
            self._update_center_display()
            self._start_stopwatch()
            self._save_current_tray_state()
            time.sleep(1)

            # 2. 제품 5개 스캔
            self.show_status_message("2. 제품 스캔 시뮬레이션 (5개)", self.COLOR_PRIMARY)
            for i in range(5):
                product_barcode = f"{item_code}-AUTOTEST-{uuid.uuid4().hex[:8]}"
                self._process_barcode_logic(product_barcode)
                time.sleep(0.3)
            
            # 3. 마지막 스캔 취소
            self.show_status_message("3. 마지막 스캔 취소", self.COLOR_PRIMARY)
            self.undo_last_scan()
            time.sleep(1)

            # 4. 취소된 제품 다시 스캔
            self.show_status_message("4. 취소된 제품 재스캔", self.COLOR_PRIMARY)
            product_barcode = f"{item_code}-AUTOTEST-RESCAN-{uuid.uuid4().hex[:8]}"
            self._process_barcode_logic(product_barcode)
            time.sleep(1)

            # 5. 작업 보류
            self.show_status_message("5. 작업 보류", self.COLOR_PRIMARY)
            self.park_current_tray(confirm=False)
            time.sleep(1)

            # 6. 보류된 작업 복원
            self.show_status_message("6. 보류 작업 복원", self.COLOR_PRIMARY)
            parked_filepath = self._parked_store().existing_label_path(
                worker_name=self.worker_name,
                master_label=master_label,
            )
            if os.path.exists(parked_filepath):
                self.restore_parked_tray(str(parked_filepath))
            else:
                raise FileNotFoundError("자동 테스트 중 보류된 파일을 찾지 못했습니다.")
            time.sleep(1)
            
            # 7. 나머지 제품 스캔
            remaining_scans = self.current_tray.tray_size - len(self.current_tray.scanned_barcodes)
            self.show_status_message(f"7. 나머지 {remaining_scans}개 제품 스캔", self.COLOR_PRIMARY)
            for i in range(remaining_scans):
                product_barcode = f"{item_code}-AUTOTEST-FINAL-{uuid.uuid4().hex[:8]}"
                self._process_barcode_logic(product_barcode)
                time.sleep(0.2)
            
            self.show_status_message("자동 테스트 완료!", self.COLOR_SUCCESS, duration=5000)

        except Exception as e:
            print(f"자동 테스트 오류: {e}")
            messagebox.showerror("자동 테스트 실패", f"자동 테스트 중 오류가 발생했습니다:\n{e}")

    def run(self):
        self.root.mainloop()

    # ===================================================================
    # 현품표 교체 (완료된 작업 대상) 관련 기능들
    # ===================================================================

    def _parse_new_format_qr(self, qr_data: str) -> Optional[Dict[str, str]]:
        """현품표 QR 코드를 파싱합니다."""
        return parse_new_format_qr(qr_data)

    def initiate_master_label_replacement(self):
        """현품표 교체 프로세스를 시작합니다."""
        if self.current_tray.master_label_code:
            messagebox.showwarning("작업 중 오류", "진행 중인 작업이 있을 때는 현품표를 교체할 수 없습니다.")
            return

        if self.master_label_replace_state:
            self.cancel_master_label_replacement()
        else:
            if not self._log_event('HISTORICAL_REPLACE_START', synchronous=True):
                messagebox.showerror("교체 시작 기록 실패", "현품표 교체 시작 기록을 남기지 못했습니다. 다시 시도해주세요.")
                return
            self._invalidate_pending_scan_callbacks()
            self.master_label_replace_state = 'awaiting_old_completed'
            self.show_status_message("교체할 '완료된' 현품표를 스캔하세요.", self.COLOR_PRIMARY)
            self._update_current_item_label()
            self._update_action_button_states()
            self._schedule_focus_return()

    def cancel_master_label_replacement(self) -> bool:
        """현품표 교체 프로세스를 취소하고 상태와 컨텍스트를 초기화합니다."""
        if self.master_label_replace_state:
            if not self._log_master_label_replacement_cancel(reason="operator_cancel"):
                messagebox.showerror("교체 취소 기록 실패", "현품표 교체 취소 기록을 남기지 못했습니다. 상태를 유지합니다.")
                return False
            self._reset_master_label_replacement_state()
            self.show_status_message("현품표 교체가 취소되었습니다.", self.COLOR_TEXT_SUBTLE)
            self._update_current_item_label()
            self._update_action_button_states()
        return True

    def _log_master_label_replacement_cancel(self, *, reason: str) -> bool:
        context = self.replacement_context
        return self._log_event(
            'HISTORICAL_REPLACE_CANCEL',
            detail={
                'reason': reason,
                'state': self.master_label_replace_state,
                'old_label': context.get('old_label'),
                'new_label': context.get('new_label'),
                'additional_count': len(context.get('additional_items') or []),
                'removed_count': len(context.get('removed_items') or []),
            },
            synchronous=True,
        )

    def _reset_master_label_replacement_state(self):
        self.master_label_replace_state = None
        self.replacement_context = {}
        self._update_action_button_states()

    def _handle_historical_replacement_scan(self, barcode: str):
        """현품표 교체 프로세스의 초기 스캔(기존/신규 현품표)을 처리합니다."""
        barcode = normalize_master_label_input(barcode)
        if self.master_label_replace_state == 'awaiting_old_completed':
            self.replacement_context['old_label'] = barcode
            self.master_label_replace_state = 'awaiting_new_replacement'
            self.show_status_message("확인. 적용할 '새로운' 현품표를 스캔하세요.", self.COLOR_SUCCESS)
            self._update_current_item_label()

        elif self.master_label_replace_state == 'awaiting_new_replacement':
            new_data = self._parse_new_format_qr(barcode)
            if not new_data:
                self.show_fullscreen_warning("스캔 오류", "유효한 현품표 QR 형식이 아닙니다.", self.COLOR_DANGER)
                self.cancel_master_label_replacement()
                return

            old_label = self.replacement_context.get('old_label', '')
            if barcode == old_label or canonical_master_label_key(barcode) == canonical_master_label_key(old_label):
                self.show_fullscreen_warning("스캔 오류", "기존과 동일한 현품표입니다.", self.COLOR_DANGER)
                return
            if self._is_completed_master_label(barcode):
                self.show_fullscreen_warning("현품표 중복", "이미 완료 처리된 현품표입니다.", self.COLOR_DANGER)
                return

            self.replacement_context['new_label'] = barcode
            self.replacement_context['new_data'] = new_data
            self._perform_historical_master_label_swap()

    def _perform_historical_master_label_swap(self):
        """모든 로컬 로그 파일을 검색하여 교체할 기록을 찾습니다."""
        old_label = self.replacement_context.get('old_label')

        # 1. 검사실 로그 파일 검색 (HTTPS-direct 로컬 이벤트 폴더)
        inspection_folder = getattr(self, 'save_folder', '') or str(
            build_container_audit_storage_paths(application_path=getattr(self, 'application_path', None)).events_dir
        )
        try:
            if not os.path.exists(inspection_folder):
                messagebox.showerror("오류", f"검사실 로그 폴더 '{inspection_folder}'를 찾을 수 없습니다.")
                self.cancel_master_label_replacement()
                return

            all_log_files = self._replacement_log_file_paths(inspection_folder)
        except FileNotFoundError:
            messagebox.showerror("오류", f"검사실 로그 폴더 '{inspection_folder}'를 찾을 수 없습니다.")
            self.cancel_master_label_replacement()
            return

        # 2. 각 로그 파일을 순회하며 old_label을 찾습니다.
        found_log_info = None
        superseded_hashes = collect_replacement_superseded_hashes(all_log_files, stable_hash_func=self._stable_hash)
        for log_path in all_log_files:
            found_log_info = self._find_log_in_file(log_path, old_label, superseded_hashes=superseded_hashes)
            if found_log_info:
                break

        # 3. 검색 결과에 따라 다음 단계를 진행합니다.
        if found_log_info:
            self.replacement_context.update(found_log_info)
            self._compare_quantities_and_proceed()
        else:
            messagebox.showwarning("기록 없음", f"모든 검사실 로그 파일에서 해당 현품표({old_label})의 완료 기록을 찾을 수 없습니다.")
            self.cancel_master_label_replacement()

    @staticmethod
    def _replacement_log_file_paths(folder: str) -> List[str]:
        return replacement_log_file_paths(folder)

    def _find_log_in_file(
        self,
        file_path: str,
        old_label: str,
        *,
        superseded_hashes: set[str] | None = None,
    ) -> Optional[Dict]:
        """지정된 파일에서 old_label에 해당하는 로그를 찾아 관련 정보를 반환합니다."""
        return find_replacement_source_entry(
            file_path,
            old_label,
            stable_hash_func=self._stable_hash,
            superseded_hashes=superseded_hashes,
        )

    def _compare_quantities_and_proceed(self):
        """수량을 비교하고 다음 단계를 결정하는 로직입니다."""
        decision = compare_replacement_quantities(
            self.replacement_context['original_details'],
            self.replacement_context['new_data'],
        )
        if decision.action == REPLACEMENT_REJECT_ITEM_CODE:
            if decision.old_label_item_code and decision.old_label_item_code != decision.expected_item_code:
                message = (
                    "기존 완료 로그의 품목코드와 기존 현품표 품목코드가 다릅니다.\n"
                    f"[완료 로그: {decision.expected_item_code} / 기존 현품표: {decision.old_label_item_code}]"
                )
            else:
                message = (
                    "새 현품표 품목코드가 기존 완료 작업과 다릅니다.\n"
                    f"[기존: {decision.expected_item_code} / 신규: {decision.new_item_code}]"
                )
            messagebox.showwarning("품목 불일치", message)
            self.cancel_master_label_replacement()
            return
        self.replacement_context['expected_item_code'] = decision.expected_item_code

        if decision.action == REPLACEMENT_REJECT_NEW_QTY:
            messagebox.showwarning("수량 오류", "새 현품표 수량(QT)은 1 이상의 숫자여야 합니다.")
            self.cancel_master_label_replacement()
            return
        if decision.action == REPLACEMENT_REJECT_OLD_QTY:
            messagebox.showwarning("수량 오류", "기존 완료 기록에서 수량을 확인할 수 없어 현품표 교체를 진행할 수 없습니다.")
            self.cancel_master_label_replacement()
            return

        self.replacement_context['old_qty'] = decision.old_qty
        self.replacement_context['new_qty'] = decision.new_qty

        if decision.action == REPLACEMENT_FINALIZE:
            self._finalize_replacement()
        elif decision.action == REPLACEMENT_AWAIT_ADDITIONAL:
            self.replacement_context['items_needed'] = decision.items_needed
            self.replacement_context['additional_items'] = []
            self.master_label_replace_state = 'awaiting_additional_items'
            self._update_current_item_label()
        elif decision.action == REPLACEMENT_AWAIT_REMOVED:
            self.replacement_context['items_to_remove_count'] = decision.items_to_remove_count
            self.replacement_context['removed_items'] = []
            self.master_label_replace_state = 'awaiting_removed_items'
            self._update_current_item_label()

    def _handle_additional_item_scan(self, barcode: str):
        """추가할 제품 스캔을 처리하는 함수"""
        ctx = self.replacement_context
        expected_item_code = ctx.get('expected_item_code')
        if len(barcode) <= self.ITEM_CODE_LENGTH:
            self.show_fullscreen_warning("바코드 형식 오류", f"제품 바코드는 {self.ITEM_CODE_LENGTH}자리보다 길어야 합니다.", self.COLOR_DANGER)
            return
        if expected_item_code and expected_item_code not in barcode:
            self.show_fullscreen_warning("품목 코드 불일치", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {expected_item_code}]", self.COLOR_DANGER)
            return
        matching_codes = self._item_catalog().matching_codes_in_barcode(barcode)
        if len(set(matching_codes)) > 1:
            self.show_fullscreen_warning("품목 코드 모호", "제품 바코드에 여러 품목 코드가 포함되어 있습니다.", self.COLOR_DANGER)
            return
        if len(set(matching_codes)) == 1 and expected_item_code and matching_codes[0] != expected_item_code:
            self.show_fullscreen_warning("품목 코드 불일치", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {expected_item_code}]", self.COLOR_DANGER)
            return
        if barcode in product_barcodes_from_completion(ctx['original_details']):
            self.show_fullscreen_warning("중복 스캔", "이미 기존 작업에 포함된 바코드입니다.", self.COLOR_DANGER)
            return
        if barcode in ctx.get('additional_items', []):
            self.show_fullscreen_warning("중복 스캔", "이미 추가 목록에 스캔된 바코드입니다.", self.COLOR_DANGER)
            return

        ctx['additional_items'].append(barcode)
        if self.success_sound:
            self.success_sound.play()

        if len(ctx['additional_items']) >= ctx['items_needed']:
            self._finalize_replacement()
        else:
            self._update_current_item_label()

    def _handle_removed_item_scan(self, barcode: str):
        """제외할 제품 스캔을 처리하는 함수"""
        ctx = self.replacement_context
        if barcode not in product_barcodes_from_completion(ctx['original_details']):
            self.show_fullscreen_warning("스캔 오류", "기존 작업에 포함되지 않은 바코드입니다.", self.COLOR_DANGER)
            return
        if barcode in ctx.get('removed_items', []):
            self.show_fullscreen_warning("중복 스캔", "이미 제외 목록에 스캔된 바코드입니다.", self.COLOR_DANGER)
            return

        ctx['removed_items'].append(barcode)
        if self.success_sound:
            self.success_sound.play()

        if len(ctx['removed_items']) >= ctx['items_to_remove_count']:
            self._finalize_replacement()
        else:
            self._update_current_item_label()

    def _finalize_replacement(self):
        """모든 정보가 준비되면 최종적으로 찾았던 로그 파일을 수정하고 저장합니다."""
        try:
            ctx = self.replacement_context
            log_file_path = ctx['found_log_file']
            row_index = ctx['found_row_index']
            source_file_id = ctx.get('found_source_file_id') or os.path.basename(log_file_path)
            correction_payload = build_master_label_replacement_detail(
                original_details=ctx['original_details'],
                old_label=ctx['old_label'],
                new_label=ctx['new_label'],
                source_system=self.SOURCE_SYSTEM,
                source_transport_or_dataset=self.SOURCE_TRANSPORT_OR_DATASET,
                source_file_id=source_file_id,
                source_row_number=row_index,
                source_byte_offset=ctx.get('found_source_byte_offset'),
                operator=self.worker_name,
                stable_hash_func=self._stable_hash,
                old_row_hash=ctx.get('found_row_hash') or ctx.get('original_row_hash'),
                old_qty=ctx.get('old_qty'),
                new_qty=ctx.get('new_qty'),
                additional_items=ctx.get('additional_items') or [],
                removed_items=ctx.get('removed_items') or [],
            )
            if not self._log_event('MASTER_LABEL_REPLACEMENT_APPLIED', detail=correction_payload, synchronous=True):
                messagebox.showerror("교체 기록 실패", "현품표 교체 correction 이벤트 저장에 실패했습니다. 상태를 유지합니다.")
                return

            messagebox.showinfo("교체 완료", "현품표 교체 증거가 append-only correction 이벤트로 기록되었습니다.")
            self._remember_completed_master_label(ctx['old_label'])
            self._remember_completed_master_label(ctx['new_label'])
            self._update_all_summaries()
            self._reset_master_label_replacement_state()
            self._update_current_item_label()

        except Exception as e:
            messagebox.showerror("파일 쓰기 오류", f"수정된 로그 저장 중 오류: {e}")

    # ==================== 개별 제품 교환 관련 함수들 ====================

    def show_exchange_dialog(self):
        """개별 제품 교환 다이얼로그를 표시합니다."""
        if self.current_tray.master_label_code:
            messagebox.showwarning("작업 중", "진행 중인 트레이 작업이 있습니다.\n트레이를 제출한 후 개별 제품 교환을 사용하세요.")
            return
        self._invalidate_pending_scan_callbacks()
        existing_dialog = getattr(self, "exchange_dialog", None)
        if existing_dialog is not None:
            try:
                if existing_dialog.winfo_exists():
                    existing_dialog.lift()
                    existing_dialog.focus_force()
                    self._update_action_button_states()
                    return
            except tk.TclError:
                pass
            self.exchange_dialog = None

        # 교환 다이얼로그 창 생성
        exchange_dialog = tk.Toplevel(self.root)
        exchange_dialog.title("개별 제품 교환")
        exchange_dialog.geometry("800x600")
        exchange_dialog.transient(self.root)
        exchange_dialog.grab_set()

        # 메인 프레임
        main_frame = ttk.Frame(exchange_dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 제목
        title_label = ttk.Label(main_frame, text="개별 제품 교환",
                               font=(self.DEFAULT_FONT, 16, 'bold'))
        title_label.pack(pady=(0, 20))

        # 수량 선택 프레임
        quantity_frame = ttk.Frame(main_frame)
        quantity_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(quantity_frame, text="교환할 수량:",
                 font=(self.DEFAULT_FONT, 12, 'bold')).pack(side=tk.LEFT)

        self.exchange_quantity_var = tk.IntVar(value=1)
        quantity_spin = ttk.Spinbox(quantity_frame, from_=1, to=10,
                                   textvariable=self.exchange_quantity_var, width=5,
                                   font=(self.DEFAULT_FONT, 12))
        self.exchange_quantity_spin = quantity_spin
        quantity_spin.pack(side=tk.LEFT, padx=(10, 5))

        ttk.Label(quantity_frame, text="개",
                 font=(self.DEFAULT_FONT, 12)).pack(side=tk.LEFT)

        # 상태 라벨
        self.exchange_status_label = ttk.Label(main_frame,
                                             text="교환할 수량을 선택한 후 불량품을 스캔하세요.",
                                             font=(self.DEFAULT_FONT, 12))
        self.exchange_status_label.pack(pady=10)

        # 목록 프레임
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_columnconfigure(1, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)

        # 불량품 목록
        defective_frame = ttk.LabelFrame(list_frame, text="스캔된 불량품", padding=10)
        defective_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))

        self.exchange_defective_tree = ttk.Treeview(defective_frame, columns=('no', 'barcode'), show='headings', height=8)
        self.exchange_defective_tree.heading('no', text='순번')
        self.exchange_defective_tree.heading('barcode', text='불량품 바코드')
        self.exchange_defective_tree.column('no', width=50, anchor='center')
        self.exchange_defective_tree.column('barcode', anchor='w')
        self._apply_tree_row_styles(self.exchange_defective_tree)
        self.exchange_defective_tree.pack(fill=tk.BOTH, expand=True)

        # 양품 목록
        good_frame = ttk.LabelFrame(list_frame, text="스캔된 양품", padding=10)
        good_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))

        self.exchange_good_tree = ttk.Treeview(good_frame, columns=('no', 'barcode'), show='headings', height=8)
        self.exchange_good_tree.heading('no', text='순번')
        self.exchange_good_tree.heading('barcode', text='양품 바코드')
        self.exchange_good_tree.column('no', width=50, anchor='center')
        self.exchange_good_tree.column('barcode', anchor='w')
        self._apply_tree_row_styles(self.exchange_good_tree)
        self.exchange_good_tree.pack(fill=tk.BOTH, expand=True)

        # 스캔 입력 프레임
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(scan_frame, text="바코드 스캔:",
                 font=(self.DEFAULT_FONT, 12, 'bold')).pack(side=tk.LEFT)

        self.exchange_scan_entry = ttk.Entry(scan_frame, font=(self.DEFAULT_FONT, 14), width=30)
        self.exchange_scan_entry.pack(side=tk.LEFT, padx=(10, 0))
        self.exchange_scan_entry.bind('<Return>', self._on_exchange_scan)

        # 버튼 프레임
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        self.exchange_complete_button = ttk.Button(button_frame, text="교환 완료",
                                                  command=self._complete_exchange,
                                                  state=tk.DISABLED,
                                                  style='Success.TButton')
        self.exchange_complete_button.pack(side=tk.LEFT, padx=(0, 10))

        self.exchange_cancel_button = ttk.Button(button_frame, text="취소",
                                               command=self._cancel_exchange,
                                               style='Secondary.TButton')
        self.exchange_cancel_button.pack(side=tk.LEFT, padx=(0, 10))

        # 교환 세션 초기화
        self.current_exchange_session = ProductExchangeSession()
        self.exchange_dialog = exchange_dialog
        self._update_action_button_states()
        exchange_dialog.protocol("WM_DELETE_WINDOW", self._cancel_exchange)

        # 스캔 엔트리에 포커스
        self.exchange_scan_entry.focus()

    def _start_exchange(self):
        """교환을 시작합니다. (첫 스캔 시 자동 호출)"""
        quantity = self._exchange_target_quantity()
        if quantity is None:
            return False

        self.current_exchange_session.target_quantity = quantity
        self.current_exchange_session.current_step = "scan_defective"
        self._configure_widget_options(getattr(self, "exchange_quantity_spin", None), state=tk.DISABLED)

        self._update_exchange_status()
        return True

    def _exchange_target_quantity(self) -> Optional[int]:
        try:
            raw_quantity = self.exchange_quantity_var.get()
        except (tk.TclError, TypeError, ValueError):
            return None
        if isinstance(raw_quantity, bool):
            return None
        try:
            quantity = int(raw_quantity)
        except (TypeError, ValueError):
            return None
        if quantity < 1 or quantity > 10:
            return None
        return quantity

    def _on_exchange_scan(self, event):
        """엔터키 누를 때 호출되는 함수"""
        barcode = self.exchange_scan_entry.get().strip()
        if barcode:
            self._process_exchange_scan(barcode)
            self.exchange_scan_entry.delete(0, tk.END)

    def _process_exchange_scan(self, barcode: str):
        """교환 스캔을 처리합니다."""
        session = self.current_exchange_session

        # 세션이 시작되지 않았으면 자동으로 시작
        if session.current_step == "not_started":
            if not self._start_exchange():
                messagebox.showwarning("수량 미설정", "교환할 수량을 먼저 설정해주세요.")
                return

        if session.current_step not in ["scan_defective", "scan_good"]:
            return

        result = apply_exchange_scan(
            session,
            barcode,
            item_catalog=self._item_catalog(),
            item_code_length=self.ITEM_CODE_LENGTH,
        )
        if result.status == "error":
            messagebox.showerror(result.title, result.message)
            return
        if result.status == "warning":
            messagebox.showwarning(result.title, result.message)
            return
        if result.status != "accepted":
            return
        if result.play_success_sound and self.success_sound:
            self.success_sound.play()

        # UI 업데이트
        self._update_exchange_display()
        self._update_exchange_status()

        # 모든 교환 완료 시 버튼 활성화
        if result.complete_ready:
            self.exchange_complete_button.config(state=tk.NORMAL)

    def _update_exchange_display(self):
        """교환 목록 디스플레이를 업데이트합니다."""
        session = self.current_exchange_session

        # 불량품 목록 업데이트
        for item in self.exchange_defective_tree.get_children():
            self.exchange_defective_tree.delete(item)

        for i, barcode in enumerate(session.defective_barcodes):
            tag = 'even' if i % 2 == 0 else 'odd'
            self._insert_tree_row(self.exchange_defective_tree, '', 'end', values=(i+1, barcode), tags=(tag,))

        # 양품 목록 업데이트
        for item in self.exchange_good_tree.get_children():
            self.exchange_good_tree.delete(item)

        for i, barcode in enumerate(session.good_barcodes):
            tag = 'even' if i % 2 == 0 else 'odd'
            self._insert_tree_row(self.exchange_good_tree, '', 'end', values=(i+1, barcode), tags=(tag,))

    def _update_exchange_status(self):
        """교환 상태 메시지를 업데이트합니다."""
        session = self.current_exchange_session

        if session.current_step == "scan_defective":
            remaining = session.target_quantity - len(session.defective_barcodes)
            if remaining > 0:
                status = f"불량품을 스캔하세요. (남은 수량: {remaining}개)"
            else:
                status = "불량품 스캔 완료. 이제 양품을 스캔하세요."

        elif session.current_step == "scan_good":
            remaining = session.target_quantity - len(session.good_barcodes)
            if remaining > 0:
                status = f"양품을 스캔하세요. (남은 수량: {remaining}개)"
            else:
                status = "모든 스캔이 완료되었습니다. '교환 완료' 버튼을 클릭하세요."
        else:
            status = "교환할 수량을 선택한 후 불량품을 스캔하세요."

        if session.item_name:
            status = f"품목: {session.item_name} | " + status

        self.exchange_status_label.config(text=status)

    def _cancel_exchange(self, *, reason: str = "operator_cancel") -> bool:
        """진행 중인 제품 교환을 취소하고 필요한 감사 로그를 남깁니다."""
        session = self.current_exchange_session
        has_scans = bool(session.defective_barcodes or session.good_barcodes)
        if has_scans:
            detail = {
                "exchange_id": session.exchange_id,
                "item_code": session.item_code,
                "item_name": session.item_name,
                "item_spec": session.item_spec,
                "target_quantity": session.target_quantity,
                "current_step": session.current_step,
                "defective_count": len(session.defective_barcodes),
                "good_count": len(session.good_barcodes),
                "defective_barcodes": list(session.defective_barcodes),
                "good_barcodes": list(session.good_barcodes),
                "reason": reason,
            }
            if not self._log_event("PRODUCT_EXCHANGE_CANCELLED", detail=detail, synchronous=True):
                messagebox.showerror("교환 취소 기록 실패", "제품 교환 취소 기록 저장에 실패했습니다. 교환 상태를 유지합니다.")
                return False

        self.current_exchange_session = ProductExchangeSession()
        dialog = getattr(self, "exchange_dialog", None)
        if dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass
        self.exchange_dialog = None
        self.exchange_quantity_spin = None
        self._update_action_button_states()
        return True

    def _complete_exchange(self):
        """제품 교환을 완료합니다."""
        session = self.current_exchange_session
        if session.current_step == "completed":
            return

        validation = validate_exchange_completion(session)
        if validation.status != "accepted":
            messagebox.showwarning(validation.title, validation.message)
            return

        if hasattr(self, "exchange_complete_button"):
            self.exchange_complete_button.config(state=tk.DISABLED)
        session.exchange_pairs = build_exchange_pairs(session)

        # 로그 기록
        if not self._log_event('PRODUCT_EXCHANGE_COMPLETED', detail=build_exchange_completion_detail(session), synchronous=True):
            if hasattr(self, "exchange_complete_button"):
                self.exchange_complete_button.config(state=tk.NORMAL)
            messagebox.showerror("교환 기록 실패", "제품 교환 완료 기록 저장에 실패했습니다. 교환 완료 처리를 중단합니다.")
            return
        session.current_step = "completed"

        messagebox.showinfo("교환 완료",
                          f"{len(session.exchange_pairs)}개의 제품 교환이 완료되었습니다.\n\n"
                          f"품목: {session.item_name}\n"
                          f"불량품 → 양품 교환")

        # 다이얼로그 닫기
        dialog = getattr(self, "exchange_dialog", None)
        if dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass
        self.exchange_dialog = None
        self.exchange_quantity_spin = None
        self.current_exchange_session = ProductExchangeSession()
        self._update_action_button_states()

def main():
    app = ContainerAudit()
    app.root.after(500, lambda: schedule_update_check(app.root))
    app.run()


if __name__ == "__main__":
    main()
