import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter import font as tkfont
import copy
import csv
import datetime
import hashlib
import io
import os
import sys
import threading
import time
import json
import re
from typing import List, Dict, Optional, Any, Callable, Mapping, Sequence
from dataclasses import dataclass, field
import queue
import uuid
import subprocess
import random
import tempfile
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from runtime_dependency_guard import install_charset_normalizer_block

install_charset_normalizer_block()

import requests

from container_audit_product_host import dispatch_product_mode
from native_audio import WavSound, stop_all_sounds
from vendor.kmtech_zero_pe.raster import RasterImage
from vendor.kmtech_zero_pe.release_signature import validate_public_key_config
from kmtech_factory_contracts import load_and_verify_contract_lock
from container_audit_test_harness import parse_internal_test_command
from best_time_records import BestTimeRecordStore
from current_user_onboarding import (
    CurrentUserOnboardingError,
    LOGISTICS_PROFILE_PATH_ENV,
    ONBOARDING_EXIT_CODE,
    onboard_current_user,
    resolve_current_user_onboarding_paths,
)
from direct_sync_auto_bootstrap import (
    DirectSyncWakeResult,
    start_direct_sync_auto_bootstrap,
    start_session_direct_sync,
)
from direct_sync_health import (
    RelayHealth,
    read_relay_health,
    relay_health_card_model,
    relay_health_detail_model,
)
from event_contracts import plan_b_event_detail, stable_hash
from event_log_store import (
    EventLogOutbox,
    append_event_log_entry,
    append_event_log_entry_idempotent,
)
from event_stream_policy import LOCAL_ONLY_EVENT_TYPES, local_only_event_log_path
from event_payloads import (
    build_master_label_replacement_detail,
    build_scan_ok_detail,
    build_tray_complete_detail,
    product_barcodes_from_completion,
)
from item_catalog import ItemCatalog
from item_catalog_sync import (
    ACTIVE_PATH_ENV,
    ItemCatalogSyncError,
    SNAPSHOT_PARSE_FAILED,
    SNAPSHOT_UNAVAILABLE_AFTER_VERIFY,
    get_catalog_attempt_context,
    get_verified_catalog_snapshot,
    refresh_item_catalog,
    requires_verified_catalog_snapshot,
    write_item_catalog_failure_diagnostic,
    write_item_catalog_startup_diagnostic,
)
from legacy_state_migration import migrate_legacy_code_root_state
from logistics_runtime_profile import (
    PROFILE_PATH_ENV as LOGISTICS_RUNTIME_PROFILE_PATH_ENV,
    REQUIRED_ENV as LOGISTICS_RUNTIME_REQUIRED_ENV,
    load_logistics_runtime_profile,
    unprotect_current_user_secret,
)
from label_qr import (
    canonical_master_label_key,
    inspection_master_item_code,
    normalize_master_label_input,
    parse_new_format_qr,
    parse_positive_quantity,
)
from parked_tray_store import ParkedTrayStore
from preflight_scan_hold import (
    HOLD_DRAINING,
    HOLD_LOOKUP,
    HOLD_LOOKUP_FAILED,
    PreflightHoldConflict,
    PreflightHoldError,
    PreflightHoldFull,
    PreflightHoldSnapshot,
    PreflightScanHoldStore,
    PreflightScanHoldWriter,
    QuarantinedPreflightHold,
)
from phs_label_workflow import (
    PHSLabelExchangeCoordinator,
    PHSLabelExchangeJournal,
    PHSLabelRenderer,
    PHSLabelWorkflowError,
)
from product_identity_port import is_start_item_code
from product_scan import (
    SCAN_ACCEPTED,
    SCAN_DUPLICATE,
    SCAN_FORMAT_ERROR,
    SCAN_MISMATCH,
    SCAN_TRAY_FULL,
    ProductScanDecision,
    decide_catalog_product_match,
    decide_product_scan,
)
import member_exchange_view
import tray_completion
from member_exchange_view import (
    EXCHANGE_DIALOG_DEFAULT_WIDTH,
    EXCHANGE_DIALOG_DEFAULT_HEIGHT,
    EXCHANGE_DIALOG_SCREEN_MARGIN,
    calculate_exchange_dialog_size,
)
from product_exchange import (
    ProductExchangeSession,
    apply_exchange_scan,
    build_exchange_completion_detail,
    build_exchange_pairs,
    validate_exchange_completion,
)
from protected_admin import (
    PROTECTED_ADMIN_DISPLAY_NAME,
    PROTECTED_ADMIN_OPERATOR_ID,
    display_operator_name,
    is_protected_admin_code,
    is_protected_admin_candidate,
    persistent_operator_name,
    redact_protected_admin_identity,
    sanitize_persistent_value,
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
from scan_display import compact_scan_value, format_scan_list_row
from responsive_layout import (
    center_layout_metrics as calculate_center_layout_metrics,
    pane_layout_metrics as calculate_pane_layout_metrics,
    right_sidebar_metrics as calculate_right_sidebar_metrics,
    scanned_list_metrics as calculate_scanned_list_metrics,
    select_layout_profile,
    worker_login_layout_metrics as calculate_worker_login_layout_metrics,
)
from runtime_instance import acquire_runtime_instance
from session_history import load_session_history
from style_tokens import StyleProfile, build_style_tokens
from storage_policy import build_container_audit_storage_paths, ensure_container_audit_storage_dirs
from storage_utils import atomic_write_json
from tk_serial_ui_lane import (
    DRAIN_TO_DURABLE_HANDOFF,
    DRAIN_TO_TERMINAL,
    LANE_BROKEN,
    LANE_BUSY,
    LANE_CLOSED,
    LANE_DRAINING,
    LaneTask,
    TkSerialUiLane,
)
from writer_session_fence import writer_sink
from tray_state import (
    ACTIVATION_EVENT_STATE_KEY,
    ACTIVATION_EVENT_STATE_SCHEMA_VERSION,
    COMPLETION_EVENT_STATE_KEY,
    COMPLETION_EVENT_STATE_SCHEMA_VERSION,
    OPERATOR_REVIEW_STATE_KEY,
    OPERATOR_REVIEW_STATE_SCHEMA_VERSION,
    PARKED_RESTORE_STATE_KEY,
    PARKED_RESTORE_STATE_SCHEMA_VERSION,
    TrayStateValidationError,
    quarantine_tray_state_file,
    tray_session_from_state,
    tray_session_to_state,
    validate_tray_state,
)
from work_session_state import (
    WORK_SESSION_PHASE_ACTIVE,
    WORK_SESSION_PHASE_CLOSED,
    WORK_SESSION_PHASE_END_PENDING,
    WORK_SESSION_PHASE_START_PENDING,
    WORK_SESSION_STATE_SCHEMA_VERSION,
    WorkSessionStateError,
    validate_work_session_state,
)
from terminal_operation_lease import (
    TRANSFER_OPERATION,
    OperationLeaseError,
    OperationLeaseManager,
    OperationLeaseStore,
    PinnedOperationLeaseKeyring,
    normalize_keyring,
)
from transfer_seal import (
    SealAttempt,
    TransferSealCoordinator,
    TransferSealError,
    TransferSealStore,
    logistics_transfer_client_from_env,
    normalize_barcode,
    source_identity_from_label,
    transfer_seal_coordinator_from_env,
    transfer_operation_lease_binding,
    validate_compact_phs2_fields,
    validate_compact_phs2_preflight,
)
from transfer_member_exchange import (
    DISMISSIBLE_PREFLIGHT_STATUSES,
    MemberExchangeAttempt,
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
)
from update_service import (
    UPDATE_AUTOMATIC_INSTALL_STRATEGY,
    UPDATE_CHANNEL_ENV,
    UPDATE_DEFAULT_CHANNEL,
    UPDATE_MANIFEST_PUBLIC_KEY_ENV,
    UPDATE_MANIFEST_SIGNATURE_URL_ENV,
    UPDATE_MANIFEST_URL_ENV,
    UPDATE_PROVIDER_ENV,
    UPDATE_PROVIDER_GITHUB,
    UPDATE_PROVIDER_OFF,
    UPDATE_PROVIDER_PRIVATE_MANIFEST,
    UPDATE_REQUIRED_PRESERVE_PATHS,
    UPDATE_RESTART_EXECUTABLE,
    assert_https_update_url,
    find_release_asset_update_info,
    find_release_asset_urls,
    is_github_hosted_update_url,
    is_sha256,
    is_newer_version,
    parse_sha256_checksum,
    release_asset_name_from_url,
    update_candidate_from_private_manifest,
    validate_release_asset_url,
    verify_update_manifest_signature,
)
from worker_registry import WorkerRegistry
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    Notice,
    NoticeSeverity,
    WarningPresenter,
    notice_for_completion,
)


FACTORY_CONTRACT_APP_ID = "container_audit"


def _factory_contract_lock_path() -> Path:
    runtime_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return runtime_root / "contract.lock.json"


def verify_factory_contract_startup(lock_path=None):
    resolved_lock_path = (
        Path(lock_path) if lock_path is not None else _factory_contract_lock_path()
    )
    return load_and_verify_contract_lock(
        resolved_lock_path,
        expected_app_id=FACTORY_CONTRACT_APP_ID,
    )


_TK_GEOMETRY_RE = re.compile(
    r"^(?P<width>[0-9]{3,5})x(?P<height>[0-9]{3,5})"
    r"(?P<left>[+-][0-9]{1,6})(?P<top>[+-][0-9]{1,6})$"
)


def parse_startup_geometry(value: str) -> tuple[int, int, int, int]:
    """Parse capture startup geometry as absolute virtual-screen coordinates."""

    match = _TK_GEOMETRY_RE.fullmatch(str(value).strip())
    if match is None:
        raise ValueError(f"invalid startup geometry: {value!r}")
    return tuple(int(match.group(name)) for name in ("width", "height", "left", "top"))


def _position_tk_root_absolute(root: Any, left: int, top: int) -> None:
    """Place Tk's native top-level at absolute virtual-screen coordinates."""

    if os.name != "nt":
        return

    import ctypes
    from ctypes import wintypes

    ga_root = 2
    swp_nosize = 0x0001
    swp_nozorder = 0x0004
    swp_noactivate = 0x0010
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
    user32.GetAncestor.restype = wintypes.HWND
    user32.SetWindowPos.argtypes = (
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    )
    user32.SetWindowPos.restype = wintypes.BOOL
    hwnd = user32.GetAncestor(wintypes.HWND(int(root.winfo_id())), ga_root)
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    flags = swp_nosize | swp_nozorder | swp_noactivate
    if not user32.SetWindowPos(hwnd, 0, int(left), int(top), 0, 0, flags):
        raise ctypes.WinError(ctypes.get_last_error())


def _get_tk_root_work_area(root: Any):
    """Read work, outer and client bounds in the owning UI thread's DPI context."""

    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class MonitorInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
            ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD),
        ]

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
    user32.GetAncestor.restype = wintypes.HWND
    user32.MonitorFromWindow.argtypes = (wintypes.HWND, wintypes.DWORD)
    user32.MonitorFromWindow.restype = wintypes.HANDLE
    user32.GetMonitorInfoW.argtypes = (wintypes.HANDLE, ctypes.POINTER(MonitorInfo))
    user32.GetMonitorInfoW.restype = wintypes.BOOL
    for name in ("GetWindowRect", "GetClientRect"):
        function = getattr(user32, name)
        function.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
        function.restype = wintypes.BOOL
    hwnd = user32.GetAncestor(wintypes.HWND(int(root.winfo_id())), 2)  # GA_ROOT
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    monitor = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
    info = MonitorInfo()
    info.cbSize = ctypes.sizeof(info)
    outer, client = wintypes.RECT(), wintypes.RECT()
    if not (monitor and user32.GetMonitorInfoW(monitor, ctypes.byref(info))
            and user32.GetWindowRect(hwnd, ctypes.byref(outer))
            and user32.GetClientRect(hwnd, ctypes.byref(client))):
        raise ctypes.WinError(ctypes.get_last_error())
    return (
        (info.rcWork.left, info.rcWork.top, info.rcWork.right, info.rcWork.bottom),
        (outer.left, outer.top, outer.right, outer.bottom),
        (client.right, client.bottom),
    )


def fit_restored_window_to_work_area(root: Any) -> None:
    """Keep the ordinary restored client plus its actual frame inside rcWork."""

    bounds = _get_tk_root_work_area(root)
    if bounds is None:
        return
    work, outer, client = bounds
    frame = tuple(outer[i + 2] - outer[i] - client[i] for i in range(2))
    available = tuple(work[i + 2] - work[i] - frame[i] for i in range(2))
    if min(client) <= 0 or min(frame) < 0 or min(available) <= 0:
        raise OSError("Invalid window/client/work-area bounds")
    size = tuple(min(value, limit) for value, limit in zip(client, available))
    position = tuple(
        max(work[i], min(outer[i], work[i + 2] - size[i] - frame[i]))
        for i in range(2)
    )
    # Tk geometry and minsize are client pixels. Lower the minimum first;
    # never mix physical DWM rectangles or the app's text scale into this fit.
    root.minsize(*(min(value, limit) for value, limit in zip(root.minsize(), available)))
    if size != client:
        root.geometry(f"{size[0]}x{size[1]}")
    root.update_idletasks()
    if position != outer[:2]:
        _position_tk_root_absolute(root, *position)
        root.update_idletasks()


def apply_startup_geometry(
    root: Any,
    geometry: str,
    *,
    absolute_positioner: Any = None,
) -> tuple[int, int, int, int]:
    """Size with Tk, then correct its negative-offset semantics while hidden."""

    parsed = parse_startup_geometry(geometry)
    _width, _height, left, top = parsed
    root.geometry(geometry)
    root.update_idletasks()
    positioner = absolute_positioner or _position_tk_root_absolute
    positioner(root, left, top)
    root.update_idletasks()
    return parsed


def container_startup_logistics_client():
    """Load current-user credentials without making startup depend on the server."""

    explicit_user_profile = os.getenv(LOGISTICS_PROFILE_PATH_ENV, "").strip()
    if not explicit_user_profile and not os.environ.get("PYTEST_CURRENT_TEST"):
        try:
            app_root = (
                Path(sys.executable).resolve().parent
                if getattr(sys, "frozen", False)
                else Path(__file__).resolve().parent
            )
            candidate = resolve_current_user_onboarding_paths(app_root)
            if candidate.logistics_profile_path.is_file():
                explicit_user_profile = str(candidate.logistics_profile_path)
        except Exception:
            explicit_user_profile = ""
    if explicit_user_profile:
        values = dict(os.environ)
        values[LOGISTICS_RUNTIME_PROFILE_PATH_ENV] = explicit_user_profile
        values[LOGISTICS_RUNTIME_REQUIRED_ENV] = "1"
        return logistics_transfer_client_from_env(
            probe_required=False,
            environ=values,
            profile_decryptor=unprotect_current_user_secret,
        )
    return logistics_transfer_client_from_env(probe_required=False)

# ####################################################################
# # 자동 업데이트 기능
# ####################################################################
REPO_OWNER = "KMTechn"
REPO_NAME = "Container_Audit"
CURRENT_VERSION = "v2.0.99"
SAFE_TRANSFER_PREFLIGHT_RETRY_CODES = frozenset(
    {"PHS_LABEL_REPLACEMENT_AMBIGUOUS"}
)
PHS_REPLACEMENT_REQUIRED_NOTICE = (
    "현품표 교체 필요. 작업은 계속할 수 있습니다. "
    "현재 현품표를 교체 대기로 분리해 주세요."
)
# Two large-text trees need enough vertical space for both headings and at
# least one complete recovery row.  Below this logical height the sidebar
# keeps the same work context and exposes the trees through one state switch.
LEFT_SIDEBAR_SWITCH_LOGICAL_HEIGHT = 1030.0
MAX_UPDATE_CHECKSUM_BYTES = 64 * 1024
UPDATE_BOOTSTRAP_MANIFEST_URL = (
    "https://worker.kmtecherp.com/static/update-feed/channels/"
    "container_audit/stable/latest.json"
)
UPDATE_BOOTSTRAP_MANIFEST_SIGNATURE_URL = UPDATE_BOOTSTRAP_MANIFEST_URL + ".sig"
# Legacy bridge: deployed update feeds still carry RFC 8032 Ed25519 signatures.
# Keep this public key readable until the operator-supplied ES256 JWK ceremony is complete.
UPDATE_BOOTSTRAP_MANIFEST_PUBLIC_KEY = (
    "10d3baf546e05daaa0bbbbdd3f69630c90a245293a1690e2cfa47071292ac4a2"
)
UPDATE_PACKAGED_KEY_CONFIG_FILENAME = "update-manifest-key-config.json"
UPDATE_PACKAGED_KEY_CONFIG_SCHEMA = "container-audit-update-key-config-v1"
UPDATE_PACKAGED_KEY_CONFIG_MAX_BYTES = 16 * 1024
RUNTIME_UPDATE_BOOTSTRAP_MESSAGE = (
    "코드 루트는 읽기 전용입니다. 앱은 업데이트를 직접 적용하지 않습니다.\n"
    "관리자가 검증된 새 배포 패키지의 INSTALL_THIS_PC.ps1로 교체 설치해 주세요."
)


class RuntimeCodeDeploymentDisabledError(RuntimeError):
    """Raised when legacy in-process code deployment is invoked."""


def _default_automatic_install_policy() -> Dict[str, Any]:
    return {
        "strategy": UPDATE_AUTOMATIC_INSTALL_STRATEGY,
        "preserve_paths": list(UPDATE_REQUIRED_PRESERVE_PATHS),
        "restart_executable": UPDATE_RESTART_EXECUTABLE,
    }

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

def _get_update_provider() -> str:
    settings = _load_update_settings()
    configured = os.environ.get(UPDATE_PROVIDER_ENV)
    if configured is None:
        configured = settings.get("provider")
    if configured is not None:
        return str(configured).strip().lower() or UPDATE_PROVIDER_OFF
    if _release_runtime_mode():
        return UPDATE_PROVIDER_PRIVATE_MANIFEST
    return UPDATE_PROVIDER_OFF


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
            payload = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return normalize_update_settings(payload.get("update_settings"))


def _get_update_manifest_url() -> str:
    settings = _load_update_settings()
    return str(
        os.environ.get(UPDATE_MANIFEST_URL_ENV)
        or settings.get("manifest_url")
        or UPDATE_BOOTSTRAP_MANIFEST_URL
    ).strip()


def _get_update_manifest_signature_url(manifest_url: str) -> str:
    settings = _load_update_settings()
    configured = str(
        os.environ.get(UPDATE_MANIFEST_SIGNATURE_URL_ENV)
        or settings.get("manifest_signature_url")
        or ""
    ).strip()
    if configured:
        return configured
    if manifest_url == UPDATE_BOOTSTRAP_MANIFEST_URL:
        return UPDATE_BOOTSTRAP_MANIFEST_SIGNATURE_URL
    return f"{manifest_url}.sig"


def _get_update_manifest_public_key() -> str:
    settings = _load_update_settings()
    configured = os.environ.get(UPDATE_MANIFEST_PUBLIC_KEY_ENV)
    if configured is None:
        configured = settings.get("manifest_public_key")
    if configured:
        return str(configured).strip()
    packaged = _load_packaged_update_manifest_public_key()
    return packaged or UPDATE_BOOTSTRAP_MANIFEST_PUBLIC_KEY


def _load_packaged_update_manifest_public_key() -> str:
    """Read the public-only key bundle injected by the portable build."""

    path = Path(__file__).resolve().with_name(UPDATE_PACKAGED_KEY_CONFIG_FILENAME)
    if not path.exists():
        return ""
    try:
        if not path.is_file() or path.stat().st_size > UPDATE_PACKAGED_KEY_CONFIG_MAX_BYTES:
            raise ValueError("packaged update key config is missing, non-regular, or oversized")
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("packaged update key config is unreadable") from exc
    if not isinstance(document, dict) or set(document) != {"schema", "manifest_public_key"}:
        raise ValueError("packaged update key config fields are invalid")
    if document.get("schema") != UPDATE_PACKAGED_KEY_CONFIG_SCHEMA:
        raise ValueError("packaged update key config schema is invalid")
    configured = document.get("manifest_public_key")
    if isinstance(configured, dict):
        normalized = json.dumps(
            configured,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    elif isinstance(configured, str):
        normalized = configured.strip()
    else:
        raise ValueError("packaged update public key config is invalid")
    validate_public_key_config(normalized)
    return normalized


def _private_update_request_kwargs(url: str) -> Dict[str, Any]:
    """Bind same-origin private update discovery to the enrolled CA explicitly."""

    request_kwargs: Dict[str, Any] = {"allow_redirects": False}
    try:
        app_root = (
            Path(sys.executable).resolve().parent
            if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parent
        )
        profile_path = os.getenv(LOGISTICS_PROFILE_PATH_ENV, "").strip()
        if not profile_path:
            profile_path = str(
                resolve_current_user_onboarding_paths(app_root).logistics_profile_path
            )
        profile = load_logistics_runtime_profile(
            required=False,
            profile_path=profile_path,
            decryptor=unprotect_current_user_secret,
        )
        if profile is None:
            return request_kwargs
        requested = urlsplit(str(url or ""))
        enrolled = urlsplit(str(profile.base_url or ""))
        if (
            requested.scheme.lower(),
            requested.netloc.lower(),
        ) != (
            enrolled.scheme.lower(),
            enrolled.netloc.lower(),
        ):
            return request_kwargs
        ca_bundle_path = str(profile.tls_ca_bundle_path or "").strip()
        if ca_bundle_path:
            request_kwargs["verify"] = ca_bundle_path
    except Exception:
        # Update discovery is optional; onboarding and catalog startup retain
        # their own fail-closed profile validation.
        return request_kwargs
    return request_kwargs


def _check_github_release_for_updates() -> Optional[Dict[str, Any]]:
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
            "install_policy": _default_automatic_install_policy(),
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
    response = requests.get(
        manifest_url,
        timeout=5,
        **_private_update_request_kwargs(manifest_url),
    )
    response.raise_for_status()
    manifest = response.json()
    if not isinstance(manifest, dict):
        raise ValueError("업데이트 manifest 응답 형식이 올바르지 않습니다.")
    signature_url = _get_update_manifest_signature_url(manifest_url)
    assert_https_update_url(signature_url)
    if is_github_hosted_update_url(signature_url):
        raise ValueError("private_manifest updater signature URL must not point to GitHub-hosted update storage")
    signature_response = requests.get(
        signature_url,
        timeout=5,
        **_private_update_request_kwargs(signature_url),
    )
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
    install_policy=None,
    target_version=None,
    allow_source_mode: bool = False,
):
    """Reject the retired runtime code-deployment path.

    Signed update discovery remains available, but only the administrator-run
    bootstrap may place code or regenerate the immutable-root inventory.
    """
    raise RuntimeCodeDeploymentDisabledError(RUNTIME_UPDATE_BOOTSTRAP_MESSAGE)


def _build_updater_script(
    *,
    current_pid: int,
    source_path: str,
    application_path: str,
    backup_partial_path: str,
    backup_path: str,
    temp_path: str,
    restart_path: str,
    evidence_path: str,
    preserve_paths: List[str],
    preserve_json_path: str,
    preserve_verifier_path: str,
    process_stop_guard_path: str,
    target_version: str,
    direct_sync_coordinator_path: str = "",
    direct_sync_state_path: str = "",
    direct_sync_task_name: str = "",
    direct_sync_launcher_path: str = "",
) -> str:
    raise RuntimeCodeDeploymentDisabledError(RUNTIME_UPDATE_BOOTSTRAP_MESSAGE)


def check_and_apply_updates():
    if not _release_runtime_mode():
        return
    candidate = _safe_check_update_candidate()
    if candidate:
        _prompt_and_apply_update(candidate)


def _prompt_and_apply_update(candidate, parent=None):
    new_version = candidate["version"]
    root_alert = parent
    created_alert_root = None
    if root_alert is None:
        created_alert_root = tk.Tk()
        created_alert_root.withdraw()
        root_alert = created_alert_root
    try:
        messagebox.showinfo(
            "관리자 업데이트 필요",
            f"새로운 버전({new_version})이 확인되었습니다. (현재: {CURRENT_VERSION})\n\n"
            + RUNTIME_UPDATE_BOOTSTRAP_MESSAGE,
            parent=root_alert,
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
    preflight_scan_receipts: Dict[str, str] = field(default_factory=dict)
    tray_size: int = 60
    mismatch_error_count: int = 0
    total_idle_seconds: float = 0.0
    stopwatch_seconds: float = 0.0
    start_time: Optional[datetime.datetime] = None
    has_error_or_reset: bool = False
    is_test_tray: bool = False
    is_partial_submission: bool = False
    is_restored_session: bool = False
    canonical_input_tag_qr: str = ""
    active_label_qr_payload: str = ""
    active_label_id: str = ""
    active_label_business_date: str = ""
    active_label_worker_code: str = ""
    operation_lease_id: str = ""


class _LocalValueVar:
    """Small test/headless stand-in for Tk variables."""

    def __init__(self, value: Any = None):
        self._value = value

    def get(self):
        return self._value

    def set(self, value: Any):
        self._value = value


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
    SETTINGS_FILE = 'container_audit_settings.json'
    WORKERS_FILE = 'worker_registry.json'
    IDLE_THRESHOLD_SEC = 420
    ITEM_CODE_LENGTH = 13
    SOURCE_SYSTEM = "container_audit"
    SOURCE_TRANSPORT_OR_DATASET = "legacy_transfer_csv"
    SCAN_CONTRACT_VERSION = "container_audit_legacy_v1"
    AUDIO_ENABLED_ENV = "CONTAINER_AUDIT_AUDIO_ENABLED"
    EVENT_LOG_CLOSE_JOIN_TIMEOUT_SECONDS = 1.0
    EVENT_LOG_CLOSE_MAX_JOIN_ATTEMPTS = 3
    
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
    # Button-only backgrounds keep white labels above 4.5:1 in enabled states.
    COLOR_SUCCESS_BUTTON_BG = "#15803D"
    COLOR_SUCCESS_BUTTON_HOVER = "#166534"
    COLOR_SUCCESS_BUTTON_PRESSED = "#14532D"
    COLOR_WARNING_BUTTON_BG = "#B45309"
    COLOR_WARNING_BUTTON_HOVER = "#92400E"
    COLOR_WARNING_BUTTON_PRESSED = "#78350F"
    COLOR_BORDER = "#D7DEE8"
    COLOR_BORDER_STRONG = "#AEB8C6"
    COLOR_VELVET = "#991B1B"
    COLOR_INPUT_BG = "#FFFFFF"
    DEFAULT_RESTORED_GEOMETRY = "1280x820"
    MIN_WINDOW_WIDTH = 1024
    MIN_WINDOW_HEIGHT = 720

    def __init__(self):
        # Validate the protected local profile before Tcl, but defer network
        # readiness to the durable operation/replay path so recovery can open
        # during a server outage.
        startup_logistics_client = container_startup_logistics_client()
        startup_geometry = os.getenv("CONTAINER_AUDIT_STARTUP_GEOMETRY", "").strip()
        self._transfer_coordinator_ui_owner_thread_id = threading.get_ident()
        self.root = tk.Tk()
        if startup_geometry:
            self.root.withdraw()
        self.root.title(self.APP_TITLE)
        self.root.minsize(self.MIN_WINDOW_WIDTH, self.MIN_WINDOW_HEIGHT)
        if startup_geometry:
            apply_startup_geometry(self.root, startup_geometry)
            self.root.deiconify()
        else:
            self.root.geometry(self.DEFAULT_RESTORED_GEOMETRY)
            self.root.update_idletasks()
            try:
                fit_restored_window_to_work_area(self.root)
            except OSError as exc:
                print(f"Window work-area fit unavailable: {exc}")
            try:
                self.root.state('zoomed')
            except tk.TclError:
                pass  # Retain the fitted normal geometry when zoom is unavailable.
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
        self._post_review_refresh_required = False
        self._transfer_post_review_refresh_pending = False
        self._transfer_post_review_refresh_inflight = False
        self._presented_post_review_case_ids: set[str] = set()
        transfer_seal_db_path = (
            Path(self.data_root) / "transfer_seal" / "transfer_seal.db"
        )
        operation_lease_manager = OperationLeaseManager(
            OperationLeaseStore(transfer_seal_db_path),
            PinnedOperationLeaseKeyring(
                transfer_seal_db_path.parent / "operation_lease_keyring.json"
            ),
        )
        self.transfer_seal_coordinator = TransferSealCoordinator(
            TransferSealStore(
                transfer_seal_db_path,
                ui_thread_id_provider=self._transfer_coordinator_ui_thread_id,
            ),
            startup_logistics_client,
            operation_lease_manager,
            owner_thread_id_provider=self._transfer_coordinator_owner_thread_id,
        )
        self.transfer_member_exchange_coordinator = TransferMemberExchangeCoordinator(
            TransferMemberExchangeStore(
                self.transfer_seal_coordinator.store.db_path,
                ui_thread_id_provider=self._transfer_coordinator_ui_thread_id,
            ),
            self.transfer_seal_coordinator.client,
            getattr(self.transfer_seal_coordinator, "operation_lease_manager", None),
            owner_thread_id_provider=self._transfer_coordinator_owner_thread_id,
        )
        self._exact_transfer_exchange_history_snapshot: Optional[bool] = None
        self._transfer_member_exchange_attempt_snapshot: Dict[str, Any] = {
            "known": False,
            "master_label": "",
            "attempt": None,
        }
        self._precommand_operator_review_store_snapshot: Optional[
            Dict[str, Any]
        ] = None
        self.phs_label_exchange_coordinator = PHSLabelExchangeCoordinator(
            PHSLabelExchangeJournal(
                Path(self.data_root)
                / "phs_label_exchange"
                / "phs_label_exchange_recovery.json"
            ),
            self.transfer_seal_coordinator.client,
            renderer=PHSLabelRenderer(Path(self.data_root) / "labels"),
        )
        # The first lane checkpoint also publishes read-only UI snapshots and
        # replays replacement receipts, even when no central client is active.
        self._startup_transfer_recovery_pending = True
        self._startup_transfer_recovery_inflight = False
        self._startup_transfer_recovery_waiting_for_hold = False
        self._startup_transfer_recovery_task_handle = None
        self._member_exchange_reconcile_pending = False
        self._member_exchange_reconcile_inflight = False
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
        self.worker_role = ""
        self._authenticated_protected_admin = False
        self.completed_master_labels: set = set()
        self.current_tray = TraySession()
        self._scan_callback_epoch = 0
        self._master_preflight_epoch = 0
        self._master_preflight_pending = False
        self._master_preflight_queue: queue.Queue = queue.Queue(maxsize=1)
        self._master_preflight_poll_job: Optional[str] = None
        self._ui_lane: Optional[TkSerialUiLane] = None
        self._completion_lane_busy = False
        self._completion_task_handle = None
        self._preflight_hold_store_instance: Optional[PreflightScanHoldStore] = None
        self._preflight_hold_writer_instance: Optional[PreflightScanHoldWriter] = None
        self._preflight_hold_snapshot: Optional[PreflightHoldSnapshot] = None
        self._preflight_hold_draining = False
        self._preflight_hold_append_pending = False
        self._preflight_completion_due = False
        self._preflight_scan_input_locked = False
        self._ui_close_requested = False
        self._direct_sync_health_generation = 0
        self._direct_sync_health_pending = False
        self._direct_sync_health_queue: queue.Queue = queue.Queue(maxsize=1)
        self._direct_sync_health_job: Optional[str] = None
        self._direct_sync_health_poll_job: Optional[str] = None
        self._direct_sync_health: Optional[RelayHealth] = None
        self._direct_sync_wake_results: queue.Queue = queue.Queue()
        self._direct_sync_wake_error_code = ""
        self._phs_label_refresh_pending = False
        self._phs_label_exchange_pending = False
        self._phs_label_recovery_deferred = False
        self._phs_label_candidate_pending = False
        self._phs_reconciliation_resolve_pending = False
        self._phs_label_candidates: List[Dict[str, Any]] = []
        self._phs_reconciliation_scan_armed = False
        self._phs_reconciliation_context: Optional[Dict[str, Any]] = None
        self._phs_reconciliation_execution_guard: Optional[Dict[str, Any]] = None
        self._phs_replacement_notice_pairs: set[
            tuple[str, str, str]
        ] = set()
        self._tray_state_persist_lock = threading.RLock()
        self._work_session_persist_lock = threading.RLock()
        self._idle_check_epoch = 0
        self.current_exchange_session = ProductExchangeSession()
        self._active_transfer_exchange_mode = False
        self._active_transfer_exchange_master_label = ""
        self._active_transfer_exchange_intent_id = ""
        self.items_data = self.load_items()
        self.item_catalog = ItemCatalog(self.items_data)
        
        self.work_summary: Dict[str, Dict[str, Any]] = {}
        self.completed_tray_times: List[float] = []
        self.total_tray_count = 0
        self.tray_last_end_time: Optional[datetime.datetime] = None
        self.info_cards: Dict[str, Dict[str, ttk.Widget]] = {}
        self.logo_photo_ref = None
        self._last_normal_scan_display_item_code = ""
        self.is_idle = False
        self.last_activity_time: Optional[datetime.datetime] = None
        self.show_tray_image_var = tk.BooleanVar(value=False)

        # 현품표 교체 관련 상태 변수
        self.master_label_replace_state: Optional[str] = None
        self.replacement_context: Dict[str, Any] = {}

        self.status_message_job: Optional[str] = None
        self._status_message_generation = 0
        self.clock_job: Optional[str] = None
        self.stopwatch_job: Optional[str] = None
        self.idle_check_job: Optional[str] = None
        self.focus_return_job: Optional[str] = None
        self._responsive_style_refresh_job: Optional[str] = None
        self.warning_presenter = WarningPresenter()
        self._pending_operator_review_snapshot: Optional[CompletionOutcomeSnapshot] = None
        self._pending_activation_event_contract: Optional[Dict[str, Any]] = None
        self._pending_parked_restore_contract: Optional[Dict[str, Any]] = None
        self._work_session_id = ""
        self._work_session_recovery_blocked = False
        self._warning_beep_active = False
        self.log_write_errors: List[str] = []
        self.last_log_write_error: Optional[str] = None
        
        self.log_queue: queue.Queue = queue.Queue()
        self._event_log_outbox_instance = EventLogOutbox(Path(self.save_folder) / "_event_outbox")
        self._event_log_notice = None
        self.log_file_path: Optional[str] = None
        self._event_log_close_requested = False
        self.log_thread = threading.Thread(target=self._event_log_writer, daemon=True)
        self.log_thread.start()
        
        try:
            self.computer_id = hex(uuid.getnode())
        except Exception:
            import socket
            self.computer_id = "host-" + hashlib.sha256(
                socket.gethostname().encode("utf-8")
            ).hexdigest()[:16]
        self.CURRENT_TRAY_STATE_FILE = f"_current_tray_state_{self.computer_id}.json"
        self.WORK_SESSION_STATE_FILE = f"_work_session_state_{self.computer_id}.json"
        self.PREFLIGHT_SCAN_HOLD_FILE = (
            f"_preflight_scan_hold_{self.computer_id}.json"
        )
        self._work_session_recovery_blocked = not self._reconcile_work_session_state()
        
        self._setup_core_ui_structure()
        self._setup_styles()
        self.root.bind('<Configure>', self._schedule_responsive_style_refresh, add="+")
        self.show_worker_input_screen()
        self._poll_event_log_notice()
        
        self.root.bind('<Control-MouseWheel>', self.on_ctrl_wheel)
        self.root.bind('<F8>', self._on_phs_label_exchange_shortcut, add="+")
        self.root.bind(
            '<Shift-F8>',
            self._show_phs_label_legacy_single_fallback,
            add="+",
        )
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    ####################################################################
    # 30일 최고 기록 관리
    ####################################################################

    def _audio_feedback_enabled(self):
        if os.getenv("KMTECH_TEST_SILENT_AUDIO", "").strip().lower() in {"1", "true", "yes", "on"}:
            return False
        if os.getenv("SDL_AUDIODRIVER", "").strip().lower() == "dummy":
            return False
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
                success_sound = WavSound(resource_path('assets/success.wav'))
                error_sound = WavSound(resource_path('assets/error.wav'))
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
        self.best_time_file_path = str(self.storage_paths.best_time_records_path)
        self.best_time_store = BestTimeRecordStore(self.best_time_file_path)
        self.best_time_records = self.best_time_store.load()
        if self.best_time_store.load_warning:
            self.root.after(0, messagebox.showwarning, "최고 기록 확인", self.best_time_store.load_warning)

    def _save_best_time_records(self):
        """현재 최고 기록 데이터를 파일에 저장합니다."""
        try:
            self.best_time_store.save(self.best_time_records)
        except Exception as e:
            print(f"최고 기록 저장 실패: {e}")

    def _update_best_time_records(self, new_time: float):
        """새로운 완료 시간을 받아 최고 기록을 갱신하고 저장합니다."""
        self.best_time_records = self.best_time_store.update_best_time(self.best_time_records, new_time)
            
    def _setup_paths_and_dirs(self):
        """애플리케이션에서 사용하는 주요 경로와 디렉터리를 설정하고 생성합니다."""
        self.storage_paths = build_container_audit_storage_paths(application_path=self.application_path)
        ensure_container_audit_storage_dirs(self.storage_paths)
        self.data_root = str(self.storage_paths.data_root)
        self.save_folder = str(self.storage_paths.events_dir)
        self.local_events_folder = str(self.storage_paths.local_events_dir)
        self.direct_sync_scan_source_dir = str(self.storage_paths.events_dir)
        self.direct_sync_program_data_root = str(self.storage_paths.direct_sync_root)
        self.config_folder = str(self.storage_paths.config_dir)
        self.parked_trays_dir = str(self.storage_paths.parked_trays_dir)
        self.settings_template_path = os.path.join(
            self.application_path,
            self.SETTINGS_DIR,
            self.SETTINGS_FILE,
        )
        self.legacy_state_migration = migrate_legacy_code_root_state(
            application_path=self.application_path,
            config_dir=self.config_folder,
            parked_trays_dir=self.parked_trays_dir,
        )

    def load_app_settings(self) -> Dict[str, Any]:
        user_path = os.path.join(self.config_folder, self.SETTINGS_FILE)
        template_path = str(getattr(self, "settings_template_path", "") or "").strip()
        merged: Dict[str, Any] = {}
        if template_path:
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    merged.update(normalize_app_settings(json.load(f)))
            except (FileNotFoundError, UnicodeError, json.JSONDecodeError, OSError):
                pass
        try:
            with open(user_path, 'r', encoding='utf-8') as f:
                user_settings = normalize_app_settings(json.load(f))
        except (FileNotFoundError, UnicodeError, json.JSONDecodeError, OSError):
            user_settings = {}
        # Update authority/provider settings are immutable deployment policy.
        # Runtime state may override UI preferences, never the packaged policy.
        user_settings.pop("update_settings", None)
        merged.update(user_settings)
        return _drop_release_disabled_settings(merged)

    @writer_sink("gui_settings_save")
    def save_settings(self):
        try:
            path = os.path.join(self.config_folder, self.SETTINGS_FILE)
            current_settings = {
                'scale_factor': self.scale_factor,
                'column_widths_validator': self.column_widths,
                'paned_window_sash_positions': self.paned_window_sash_positions,
            }
            if not _release_runtime_mode():
                current_settings['enable_internal_test_commands'] = bool(getattr(self, 'internal_test_commands_enabled', False))
            atomic_write_json(path, current_settings, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"설정 저장 오류: {e}")

    def load_items(self) -> List[Dict[str, str]]:
        item_path = os.environ.get(ACTIVE_PATH_ENV) or resource_path(os.path.join('assets', 'Item.csv'))
        verified_payload = get_verified_catalog_snapshot(item_path)
        if requires_verified_catalog_snapshot(item_path):
            if verified_payload is None:
                raise ItemCatalogSyncError(
                    "central item catalog snapshot is unavailable after verification",
                    cause_code=SNAPSHOT_UNAVAILABLE_AFTER_VERIFY,
                )
            try:
                return list(
                    csv.DictReader(
                        io.StringIO(verified_payload.decode("utf-8"), newline="")
                    )
                )
            except (UnicodeError, csv.Error) as exc:
                raise ItemCatalogSyncError(
                    "central item catalog snapshot could not be parsed",
                    cause_code=SNAPSHOT_PARSE_FAILED,
                    diagnostic_context={
                        **get_catalog_attempt_context(),
                        "exception_type": type(exc).__name__,
                    },
                ) from exc
        encodings_to_try = ['utf-8-sig', 'cp949', 'euc-kr', 'utf-8']
        for encoding in encodings_to_try:
            try:
                with open(item_path, 'r', encoding=encoding) as file:
                    items = list(csv.DictReader(file))
                    return items
            except UnicodeDecodeError:
                continue
            except FileNotFoundError:
                print(f"필수 품목 파일 없음: {item_path}")
                messagebox.showerror(
                    "필수 파일 없음",
                    "품목 정보를 불러오는 데 필요한 파일을 찾을 수 없습니다. "
                    "관리자에게 문의하세요.",
                )
                self.root.destroy()
                return []
            except Exception as e:
                print(f"품목 파일 읽기 실패: {item_path}: {e.__class__.__name__}: {e}")
                messagebox.showerror(
                    "파일 읽기 오류",
                    "품목 정보를 읽지 못했습니다. 프로그램을 다시 시작한 뒤 "
                    "계속되면 관리자에게 문의하세요.",
                )
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

    def _handle_ui_lane_fault(self, exc: BaseException) -> None:
        print(f"UI lane failure: {exc.__class__.__name__}")
        try:
            self.show_status_message(
                "처리 실행기를 안전하게 중지했습니다. 현재 작업을 보존하고 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._update_action_button_states()
        except (AttributeError, tk.TclError):
            pass

    def _transfer_coordinator_owner_thread_id(self) -> Optional[int]:
        lane = getattr(self, "_ui_lane", None)
        return getattr(lane, "worker_thread_id", None)

    def _transfer_coordinator_ui_thread_id(self) -> Optional[int]:
        return getattr(self, "_transfer_coordinator_ui_owner_thread_id", None)

    def _transfer_coordinator_owner_provider(
        self,
    ) -> Callable[[], Optional[int]]:
        explicit_provider = getattr(
            self,
            "_explicit_transfer_coordinator_owner_thread_id_provider",
            None,
        )
        if callable(explicit_provider):
            return explicit_provider
        return self._transfer_coordinator_owner_thread_id

    def _ui_task_lane(self) -> TkSerialUiLane:
        lane = getattr(self, "_ui_lane", None)
        if lane is None or getattr(lane, "state", "") == "CLOSED":
            lane = TkSerialUiLane(
                self.root,
                poll_ms=15, generation_provider=lambda: getattr(self, "_scan_callback_epoch", 0),
                on_runner_fault=self._handle_ui_lane_fault,
            )
            self._ui_lane = lane
        return lane

    def _preflight_hold_store(self) -> PreflightScanHoldStore:
        filename = str(
            getattr(
                self,
                "PREFLIGHT_SCAN_HOLD_FILE",
                f"_preflight_scan_hold_{getattr(self, 'computer_id', 'host')}.json",
            )
        )
        save_root = str(getattr(self, "save_folder", "") or "").strip()
        if not save_root:
            save_root = str(
                Path(str(getattr(self, "log_file_path", "") or ".")).parent
            )
        path = Path(save_root) / filename
        capacity = max(1, int(getattr(self, "TRAY_SIZE", 60) or 60) + 8)
        store = getattr(self, "_preflight_hold_store_instance", None)
        if (
            store is None
            or Path(getattr(store, "path", "")) != path
            or int(getattr(store, "capacity", 0)) != capacity
        ):
            store = PreflightScanHoldStore(path, capacity=capacity)
            self._preflight_hold_store_instance = store
        return store

    def _preflight_hold_quarantine_directory(self) -> Path:
        return Path(str(getattr(self, "parked_trays_dir", "") or ".")) / (
            "preflight_hold_quarantine"
        )

    def _is_preflight_hold_supervisor(self) -> bool:
        return bool(
            str(getattr(self, "worker_role", "") or "").upper() == "ADMIN"
            or getattr(self, "_authenticated_protected_admin", False)
        )

    def _is_preflight_hold_quarantine_path(self, filepath: str) -> bool:
        try:
            quarantine_root = self._preflight_hold_quarantine_directory().resolve()
            candidate = Path(filepath).resolve()
        except (OSError, RuntimeError, ValueError):
            return False
        return candidate.is_relative_to(quarantine_root)

    def _quarantined_preflight_holds(
        self,
    ) -> tuple[QuarantinedPreflightHold, ...]:
        current_worker = persistent_operator_name(
            str(getattr(self, "worker_name", "") or "")
        )
        supervisor = self._is_preflight_hold_supervisor()
        return tuple(
            held
            for held in PreflightScanHoldStore.list_quarantined(
                self._preflight_hold_quarantine_directory()
            )
            if supervisor or held.snapshot.worker == current_worker
        )

    @staticmethod
    def _preflight_hold_ownership_detail(
        snapshot: PreflightHoldSnapshot,
        *,
        snapshot_hash: str,
        reason: str,
        quarantine_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        detail: Dict[str, Any] = {
            "contract_version": "container-audit-preflight-hold-ownership-v1",
            "preflight_id": snapshot.preflight_id,
            "scan_epoch": snapshot.scan_epoch,
            "worker": snapshot.worker,
            "master_raw": snapshot.master_raw,
            "state": snapshot.state,
            "held_scan_count": len(snapshot.items),
            "snapshot_hash": snapshot_hash,
            "reason": str(reason or "").strip(),
        }
        if quarantine_path is not None:
            detail["quarantine_file"] = quarantine_path.name
        return detail

    def _quarantine_preflight_hold_for_supervisor(
        self,
        *,
        reason: str,
        confirm: bool = True,
    ) -> bool:
        if not self._is_preflight_hold_supervisor():
            messagebox.showwarning(
                "보류 묶음 격리 권한",
                "사전조회 보류 묶음 격리는 관리자 확인이 필요합니다.",
                parent=getattr(self, "root", None),
            )
            return False
        store = self._preflight_hold_store()
        try:
            snapshot = store.load()
        except PreflightHoldError:
            messagebox.showerror(
                "보류 묶음 확인 필요",
                "사전조회 보류 파일을 읽지 못해 격리하지 않습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        current_master = str(
            getattr(getattr(self, "current_tray", None), "master_label_code", "")
            or ""
        )
        if current_master:
            messagebox.showerror(
                "보류 묶음 격리 차단",
                "제품 반영이 시작된 보류 묶음은 현재 트레이와 함께 복구해야 합니다. "
                "현재 작업을 저장하고 같은 작업자로 다시 시작하세요.",
                parent=getattr(self, "root", None),
            )
            return False
        if confirm and not messagebox.askyesno(
            "보류 묶음 격리 확인",
            f"중앙 조회 보류 {len(snapshot.items)}건을 복원 가능한 격리 목록으로 "
            "옮기고 새 작업을 시작하시겠습니까?",
            parent=getattr(self, "root", None),
        ):
            return False
        try:
            quarantined = store.quarantine(
                self._preflight_hold_quarantine_directory(),
                reason=reason,
            )
        except (OSError, PreflightHoldError) as exc:
            print(f"사전조회 보류 격리 실패: {exc.__class__.__name__}")
            messagebox.showerror(
                "보류 묶음 격리 실패",
                "보류 묶음을 안전하게 옮기지 못했습니다. 기존 보류 상태를 유지합니다.",
                parent=getattr(self, "root", None),
            )
            return False
        detail = self._preflight_hold_ownership_detail(
            quarantined.snapshot,
            snapshot_hash=quarantined.snapshot_hash,
            reason=reason,
            quarantine_path=quarantined.path,
        )
        audit_key = (
            "preflight-hold-quarantine:"
            f"{quarantined.snapshot.preflight_id}:{quarantined.snapshot_hash}"
        )
        try:
            audited = bool(
                self._log_event(
                    "PHS2_PREFLIGHT_HOLD_QUARANTINED",
                    detail=detail,
                    synchronous=True,
                    idempotency_key=audit_key,
                    deduplicate=True,
                )
            )
        except Exception:
            audited = False
        if not audited:
            try:
                store.restore_quarantined(quarantined.path)
            except Exception as rollback_error:
                print(
                    "사전조회 보류 격리 감사 롤백 실패: "
                    f"{rollback_error.__class__.__name__}"
                )
            messagebox.showerror(
                "보류 묶음 격리 기록 실패",
                "격리 감사 기록을 남기지 못해 새 작업을 시작하지 않습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        self._preflight_hold_snapshot = None
        self._preflight_hold_draining = False
        self._master_preflight_pending = False
        self._set_preflight_scan_input_locked(False)
        if hasattr(self, "_update_parked_trays_list"):
            self._update_parked_trays_list()
        self.show_status_message(
            "사전조회 보류 묶음을 복원 가능한 목록으로 옮겼습니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )
        self._schedule_startup_transfer_recovery()
        return True

    def restore_quarantined_preflight_hold(self, filepath: str) -> bool:
        if not self._is_preflight_hold_quarantine_path(filepath):
            messagebox.showwarning(
                "보류 묶음 복원 실패",
                "격리 목록 폴더 밖의 파일은 복원할 수 없습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        store = self._preflight_hold_store()
        try:
            snapshot = PreflightScanHoldStore.load_path(filepath)
        except PreflightHoldError:
            messagebox.showerror(
                "보류 묶음 복원 실패",
                "선택한 격리 보류 파일을 읽지 못했습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        current_worker = persistent_operator_name(
            str(getattr(self, "worker_name", "") or "")
        )
        if snapshot.worker != current_worker and not self._is_preflight_hold_supervisor():
            messagebox.showwarning(
                "보류 묶음 작업자 확인",
                "원래 작업자 또는 관리자로 로그인해야 복원할 수 있습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        if store.exists() or self._preflight_context_blocks_mutation():
            messagebox.showwarning(
                "보류 묶음 복원 차단",
                "현재 사전조회 보류 묶음을 먼저 해결해야 합니다.",
                parent=getattr(self, "root", None),
            )
            return False
        if getattr(getattr(self, "current_tray", None), "master_label_code", ""):
            messagebox.showwarning(
                "보류 묶음 복원 차단",
                "현재 트레이를 먼저 보류하거나 완료해야 합니다.",
                parent=getattr(self, "root", None),
            )
            return False
        if not messagebox.askyesno(
            "보류 묶음 복원 확인",
            f"격리된 중앙 조회 보류 {len(snapshot.items)}건을 활성 보류 상태로 "
            "되돌리시겠습니까?",
            parent=getattr(self, "root", None),
        ):
            return False
        try:
            restored = store.restore_quarantined(filepath)
            if restored.state == HOLD_DRAINING:
                restored = store.mark_failed(
                    error_code="PHS2_QUARANTINE_RESTORE_REVIEW"
                )
        except (OSError, PreflightHoldError) as exc:
            self._set_preflight_scan_input_locked(
                self._preflight_context_blocks_mutation()
            )
            self._update_action_button_states()
            print(f"사전조회 보류 복원 실패: {exc.__class__.__name__}")
            messagebox.showerror(
                "보류 묶음 복원 실패",
                "격리 보류 묶음을 활성 상태로 되돌리지 못했습니다.",
                parent=getattr(self, "root", None),
            )
            return False
        restored_hash = store.snapshot_hash(restored)
        detail = self._preflight_hold_ownership_detail(
            restored,
            snapshot_hash=restored_hash,
            reason="supervisor_restore",
            quarantine_path=Path(filepath),
        )
        audit_key = (
            "preflight-hold-restore:"
            f"{restored.preflight_id}:{restored_hash}"
        )
        try:
            audited = bool(
                self._log_event(
                    "PHS2_PREFLIGHT_HOLD_RESTORED",
                    detail=detail,
                    synchronous=True,
                    idempotency_key=audit_key,
                    deduplicate=True,
                )
            )
        except Exception:
            audited = False
        if not audited:
            try:
                store.quarantine(
                    self._preflight_hold_quarantine_directory(),
                    reason="restore_audit_failed",
                )
            except Exception as rollback_error:
                print(
                    "사전조회 보류 복원 감사 롤백 실패: "
                    f"{rollback_error.__class__.__name__}"
                )
            self._set_preflight_scan_input_locked(
                self._preflight_context_blocks_mutation()
            )
            self._update_action_button_states()
            messagebox.showerror(
                "보류 묶음 복원 기록 실패",
                "복원 감사 기록을 남기지 못해 격리 상태를 유지합니다.",
                parent=getattr(self, "root", None),
            )
            return False
        if restored.worker != current_worker:
            self._preflight_hold_snapshot = None
            self._preflight_hold_draining = False
            self._master_preflight_pending = False
            self._set_preflight_scan_input_locked(True)
            messagebox.showinfo(
                "보류 묶음 복원 완료",
                f"원래 작업자 '{display_operator_name(restored.worker)}'로 다시 로그인해 "
                "같은 현품표를 재확인하세요.",
                parent=getattr(self, "root", None),
            )
            return True
        self._preflight_hold_snapshot = restored
        self._set_preflight_scan_input_locked(True)
        self.show_fullscreen_warning(
            "중앙 조회 재확인 필요",
            "격리 보류 묶음을 복원했습니다. 확인을 누르면 같은 현품표로 다시 조회합니다.",
            self.COLOR_DANGER,
        )
        if hasattr(self, "_update_parked_trays_list"):
            self._update_parked_trays_list()
        return True

    def _preflight_hold_writer(self) -> PreflightScanHoldWriter:
        writer = getattr(self, "_preflight_hold_writer_instance", None)
        if writer is None or getattr(writer, "_closed", False):
            writer = PreflightScanHoldWriter(
                self.root,
                queue_capacity=max(4, int(getattr(self, "TRAY_SIZE", 60) or 60) + 12),
                poll_ms=10,
            )
            self._preflight_hold_writer_instance = writer
        return writer

    def _set_preflight_scan_input_locked(self, locked: bool) -> None:
        self._preflight_scan_input_locked = bool(locked)
        entry = getattr(self, "scan_entry", None)
        if entry is None:
            return
        should_disable = bool(
            locked
            or getattr(self, "_completion_lane_busy", False)
            or getattr(self, "_ui_close_requested", False)
        )
        try:
            entry.configure(state=tk.DISABLED if should_disable else tk.NORMAL)
        except (AttributeError, tk.TclError):
            pass

    def _preflight_context_blocks_mutation(self) -> bool:
        snapshot = getattr(self, "_preflight_hold_snapshot", None)
        memory_gate = bool(
            getattr(self, "_master_preflight_pending", False)
            or getattr(self, "_preflight_hold_draining", False)
            or isinstance(snapshot, PreflightHoldSnapshot)
        )
        if memory_gate:
            return True
        try:
            return self._preflight_hold_store().exists()
        except (OSError, PreflightHoldError, TypeError, ValueError):
            # If the durable ownership check itself cannot be completed, do
            # not let a mutation race an unreadable active-hold location.
            return True

    def _reject_mutation_during_preflight_hold(self) -> bool:
        if not self._preflight_context_blocks_mutation():
            return False
        self.show_status_message(
            "중앙 조회 보류 묶음 처리 중입니다. 이번 작업은 접수되지 않았습니다.",
            self.COLOR_DANGER,
            duration=0,
        )
        self._schedule_focus_return()
        return True

    def _capture_mutation_finish_identity(self) -> Dict[str, Any]:
        """Capture the stable Tk-owned identity used by mutating finishes."""

        tray = getattr(self, "current_tray", None)
        scans = getattr(tray, "scanned_barcodes", None)
        return {
            "tray": tray,
            "master_label_code": str(
                getattr(tray, "master_label_code", "") or ""
            ),
            "canonical_input_tag_qr": str(
                getattr(tray, "canonical_input_tag_qr", "") or ""
            ),
            "active_label_qr_payload": str(
                getattr(tray, "active_label_qr_payload", "") or ""
            ),
            "active_label_id": str(
                getattr(tray, "active_label_id", "") or ""
            ),
            "item_code": str(getattr(tray, "item_code", "") or ""),
            "tray_size": int(getattr(tray, "tray_size", 0) or 0),
            "scans_object": scans,
            "scans": tuple(scans) if isinstance(scans, list) else None,
            "operation_lease_id": str(
                getattr(tray, "operation_lease_id", "") or ""
            ),
            "worker_name": persistent_operator_name(
                getattr(self, "worker_name", "")
            ),
            "scan_epoch": int(getattr(self, "_scan_callback_epoch", 0) or 0),
            "resolve_pending": bool(
                getattr(self, "_phs_reconciliation_resolve_pending", False)
            ),
            "refresh_pending": bool(
                getattr(self, "_phs_label_refresh_pending", False)
            ),
            "preflight_pending": bool(
                getattr(self, "_master_preflight_pending", False)
            ),
            "preflight_draining": bool(
                getattr(self, "_preflight_hold_draining", False)
            ),
            "hold_pending": bool(self._preflight_context_blocks_mutation()),
        }

    def _mutation_finish_can_apply(
        self,
        captured: Optional[Mapping[str, Any]],
        *,
        operation: str,
        expected_preflight_hold: Optional[PreflightHoldSnapshot] = None,
    ) -> bool:
        """Fence late Tk applies against a new hold or changed tray identity."""

        current = getattr(self, "current_tray", None)
        scans = getattr(current, "scanned_barcodes", None)
        identity_matches = bool(
            isinstance(captured, Mapping)
            and current is captured.get("tray")
            and str(getattr(current, "master_label_code", "") or "")
            == str(captured.get("master_label_code") or "")
            and str(getattr(current, "canonical_input_tag_qr", "") or "")
            == str(captured.get("canonical_input_tag_qr") or "")
            and str(getattr(current, "active_label_qr_payload", "") or "")
            == str(captured.get("active_label_qr_payload") or "")
            and str(getattr(current, "active_label_id", "") or "")
            == str(captured.get("active_label_id") or "")
            and str(getattr(current, "item_code", "") or "")
            == str(captured.get("item_code") or "")
            and int(getattr(current, "tray_size", 0) or 0)
            == int(captured.get("tray_size") or 0)
            and scans is captured.get("scans_object")
            and (
                captured.get("scans") is None
                or tuple(scans or ()) == tuple(captured.get("scans") or ())
            )
            and str(getattr(current, "operation_lease_id", "") or "")
            == str(captured.get("operation_lease_id") or "")
            and persistent_operator_name(getattr(self, "worker_name", ""))
            == str(captured.get("worker_name") or "")
            and int(getattr(self, "_scan_callback_epoch", 0) or 0)
            == int(captured.get("scan_epoch") or 0)
            and bool(
                getattr(self, "_phs_reconciliation_resolve_pending", False)
            )
            == bool(captured.get("resolve_pending"))
            and bool(getattr(self, "_phs_label_refresh_pending", False))
            == bool(captured.get("refresh_pending"))
            and bool(getattr(self, "_master_preflight_pending", False))
            == bool(captured.get("preflight_pending"))
            and bool(getattr(self, "_preflight_hold_draining", False))
            == bool(captured.get("preflight_draining"))
        )
        hold_pending = bool(self._preflight_context_blocks_mutation())
        preflight_owner = False
        if expected_preflight_hold is not None and hold_pending:
            try:
                durable_hold = self._preflight_hold_store().load()
            except (OSError, PreflightHoldError, TypeError, ValueError):
                durable_hold = None
            preflight_owner = bool(
                isinstance(durable_hold, PreflightHoldSnapshot)
                and durable_hold.preflight_id
                == expected_preflight_hold.preflight_id
                and durable_hold.master_raw == expected_preflight_hold.master_raw
                and durable_hold.worker == expected_preflight_hold.worker
                and getattr(self, "_master_preflight_pending", False)
            )
        if identity_matches and (not hold_pending or preflight_owner):
            return True

        reasons = []
        if hold_pending and not preflight_owner:
            reasons.append("active_preflight_hold")
        if not identity_matches:
            reasons.append("captured_identity_changed")
        print(
            f"{operation} finish discarded as stale: "
            + ",".join(reasons or ["unknown"])
        )
        if hold_pending and not preflight_owner:
            self._reject_mutation_during_preflight_hold()
        return False

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
        self.status_label = tk.Label(status_bar, text="스캐너 준비", anchor=tk.W, bg=self.COLOR_SIDEBAR_BG, fg=self.COLOR_TEXT)
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

    def _button_style_padding(self, tokens, content_height: int) -> tuple[int, int]:
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        if scale >= 1.2 and content_height / scale < 620:
            # Natural-width center actions fit the four-column 1366 layout at
            # this padding while retaining the requested 17 pt label font.
            return min(tokens.spacing.lg, 12), min(tokens.spacing.sm, 7)
        return tokens.spacing.lg, tokens.spacing.sm

    def _responsive_style_signature_for_size(
        self,
        content_width: int,
        content_height: int,
    ) -> tuple[Any, ...]:
        profile = select_layout_profile(content_width, content_height, self.scale_factor)
        tokens = build_style_tokens(StyleProfile(profile.name), self.scale_factor)
        return (
            profile.name,
            round(float(self.scale_factor), 4),
            self._button_style_padding(tokens, content_height),
        )

    def _schedule_responsive_style_refresh(self, event=None) -> None:
        event_widget = getattr(event, "widget", None)
        if event_widget is not None and event_widget is not self.root:
            return
        try:
            content_width = max(1, int(getattr(event, "width", 0) or self.root.winfo_width()))
            content_height = max(1, int(getattr(event, "height", 0) or self.root.winfo_height()))
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return
        signature = self._responsive_style_signature_for_size(content_width, content_height)
        if signature == getattr(self, "_responsive_style_signature", None):
            return
        if getattr(self, "_responsive_style_refresh_job", None):
            return
        try:
            self._responsive_style_refresh_job = self.root.after_idle(
                self._refresh_responsive_styles_if_needed
            )
        except (AttributeError, tk.TclError):
            self._refresh_responsive_styles_if_needed()

    def _refresh_responsive_styles_if_needed(self) -> None:
        self._responsive_style_refresh_job = None
        try:
            content_width = max(1, int(self.root.winfo_width()))
            content_height = max(1, int(self.root.winfo_height()))
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return
        signature = self._responsive_style_signature_for_size(content_width, content_height)
        if signature != getattr(self, "_responsive_style_signature", None):
            self.apply_scaling()
            self._apply_left_sidebar_layout()
            # The right context values are configured directly rather than
            # exclusively through ttk styles.  Reapply them after the root
            # token profile changes so compact tokens cannot survive a
            # compact -> wide transition behind an otherwise identical
            # sidebar-metrics cache key.
            self._right_sidebar_layout_metrics = None
            self._apply_right_sidebar_layout(
                generation=getattr(self, "_right_widget_generation", 0)
            )

    def _font_linespace_px(self, size: int, *, weight: str = "normal") -> int:
        """Measure a Tk font in device pixels, with a headless-safe fallback."""

        normalized_size = max(1, int(size))
        try:
            measured_font = tkfont.Font(
                root=self.root,
                family=self.DEFAULT_FONT,
                size=normalized_size,
                weight=weight,
            )
            return max(1, int(measured_font.metrics("linespace")))
        except (AttributeError, RuntimeError, tk.TclError, TypeError, ValueError):
            return max(1, int(round(normalized_size * 1.65)))

    def apply_scaling(self):
        try:
            content_width = max(1, int(self.root.winfo_width()))
            content_height = max(1, int(self.root.winfo_height()))
        except (AttributeError, TypeError, ValueError, tk.TclError):
            content_width, content_height = 1440, 900
        profile = select_layout_profile(content_width, content_height, self.scale_factor)
        tokens = build_style_tokens(StyleProfile(profile.name), self.scale_factor)
        self._responsive_style_signature = (
            profile.name,
            round(float(self.scale_factor), 4),
            self._button_style_padding(tokens, content_height),
        )
        self.style_tokens = tokens
        s = tokens.fonts.caption
        m = tokens.fonts.body
        l = tokens.fonts.item_title
        xl = tokens.fonts.stage_title
        xxl = tokens.fonts.counter
        button_padding = self._button_style_padding(tokens, content_height)
        tree_row_padding = max(6, int(round(4 * self.scale_factor)))
        tree_row_height = max(
            tokens.components.row_height,
            self._font_linespace_px(m) + tree_row_padding,
        )
        sidebar_tree_font = (
            max(11, min(s, 13))
            if profile.name == "compact"
            else max(11, s)
        )
        sidebar_tree_row_height = max(
            26,
            self._font_linespace_px(sidebar_tree_font) + tree_row_padding,
        )
        self._left_tree_minimum_one_row_height = (
            self._font_linespace_px(sidebar_tree_font, weight="bold")
            + sidebar_tree_row_height
            + max(14, int(round(9 * self.scale_factor)))
        )
        self.style.configure('TFrame', background=self.COLOR_BG)
        self.style.configure('Sidebar.TFrame', background=self.COLOR_SIDEBAR_BG)
        self.style.configure('Card.TFrame', background=self.COLOR_CARD_BG, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('SecondaryCard.TFrame', background=self.COLOR_SURFACE_ALT, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('Idle.TFrame', background=self.COLOR_IDLE_BG, relief='solid', borderwidth=1, bordercolor="#FED7AA")
        self.style.configure('RelayAttention.TFrame', background=self.COLOR_IDLE_BG, relief='solid', borderwidth=1, bordercolor="#F59E0B")
        self.style.configure('TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Sidebar.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.sidebar))
        self.style.configure('Idle.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Subtle.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Card.Subtle.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('SecondaryCard.Subtle.TLabel', background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Idle.Subtle.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, s))
        self.style.configure('RelayAttention.Subtle.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, s))
        self.style.configure('Value.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.section_title, 'bold'))
        self.style.configure('Card.Value.TLabel', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.section_title, 'bold'))
        self.style.configure('SecondaryCard.Value.TLabel', background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.body, 'bold'))
        self.style.configure('Idle.Value.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.section_title, 'bold'))
        self.style.configure('RelayAttention.Value.TLabel', background=self.COLOR_IDLE_BG, foreground=self.COLOR_IDLE_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.body, 'bold'))
        self.style.configure('Title.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, xl, 'bold'))
        self.style.configure('Stage.TLabel', background=self.COLOR_BG, foreground=self.COLOR_PRIMARY, font=(self.DEFAULT_FONT, tokens.fonts.body, 'bold'))
        self.style.configure('ItemInfo.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, l, 'bold'))
        self.style.configure('MainCounter.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, xxl, 'bold'))
        self.style.configure('TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_PRIMARY, foreground='white', focuscolor=self.COLOR_PRIMARY)
        self.style.map('TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#1E40AF'), ('active', self.COLOR_PRIMARY_HOVER), ('!active', self.COLOR_PRIMARY)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Corner.TButton', font=(self.DEFAULT_FONT, l, 'bold'), borderwidth=0, padding=(5, 5))
        self.style.map('Corner.TButton', background=[('!active', self.COLOR_BG), ('active', self.COLOR_SURFACE_ALT)], foreground=[('!active', self.COLOR_TEXT_SUBTLE), ('active', self.COLOR_TEXT)])
        self.style.configure('Secondary.TButton', font=(self.DEFAULT_FONT, s, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background='#64748B', foreground='white')
        self.style.map('Secondary.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#334155'), ('active', '#475569'), ('!active', '#64748B')], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Success.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_SUCCESS_BUTTON_BG, foreground='white')
        self.style.map('Success.TButton', background=[('disabled', '#CBD5E1'), ('pressed', self.COLOR_SUCCESS_BUTTON_PRESSED), ('active', self.COLOR_SUCCESS_BUTTON_HOVER), ('!active', self.COLOR_SUCCESS_BUTTON_BG)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Warning.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_WARNING_BUTTON_BG, foreground='white')
        self.style.map('Warning.TButton', background=[('disabled', '#CBD5E1'), ('pressed', self.COLOR_WARNING_BUTTON_PRESSED), ('active', self.COLOR_WARNING_BUTTON_HOVER), ('!active', self.COLOR_WARNING_BUTTON_BG)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Danger.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_DANGER, foreground='white')
        self.style.map('Danger.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#991B1B'), ('active', self.COLOR_DANGER_HOVER), ('!active', self.COLOR_DANGER)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('Review.TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=button_padding, borderwidth=0, relief='flat', background=self.COLOR_PRIMARY, foreground='white')
        self.style.map('Review.TButton', background=[('disabled', '#CBD5E1'), ('pressed', '#1E3A8A'), ('active', self.COLOR_PRIMARY_HOVER), ('!active', self.COLOR_PRIMARY)], foreground=[('disabled', '#F8FAFC'), ('!disabled', 'white')])
        self.style.configure('TCheckbutton', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.map('TCheckbutton', indicatorcolor=[('selected', self.COLOR_PRIMARY), ('!selected', self.COLOR_BORDER)], foreground=[('active', self.COLOR_TEXT), ('!active', self.COLOR_TEXT)])
        self.style.configure('VelvetCard.TFrame', background=self.COLOR_SURFACE_ALT, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('Velvet.Subtle.TLabel', background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Velvet.Value.TLabel', background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, tokens.fonts.body, 'bold'))
        self.style.configure('Treeview.Heading', font=(self.DEFAULT_FONT, m, 'bold'), background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT, relief='flat', bordercolor=self.COLOR_BORDER)
        self.style.configure('Treeview', rowheight=tree_row_height, font=(self.DEFAULT_FONT, m), background=self.COLOR_CARD_BG, fieldbackground=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER)
        self.style.map('Treeview', background=[('selected', self.COLOR_PRIMARY)], foreground=[('selected', 'white')])
        self.style.configure('Sidebar.Treeview.Heading', font=(self.DEFAULT_FONT, sidebar_tree_font, 'bold'), background=self.COLOR_SURFACE_ALT, foreground=self.COLOR_TEXT, relief='flat', bordercolor=self.COLOR_BORDER)
        self.style.configure('Sidebar.Treeview', rowheight=sidebar_tree_row_height, font=(self.DEFAULT_FONT, sidebar_tree_font), background=self.COLOR_CARD_BG, fieldbackground=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER)
        self.style.map('Sidebar.Treeview', background=[('selected', self.COLOR_PRIMARY)], foreground=[('selected', 'white')])
        self.style.configure('Vertical.TScrollbar', background='#CBD5E1', troughcolor=self.COLOR_SURFACE_ALT, bordercolor=self.COLOR_SURFACE_ALT, arrowcolor=self.COLOR_TEXT_SUBTLE, relief='flat')
        self.style.map('Vertical.TScrollbar', background=[('active', '#94A3B8')])
        self.style.configure('TEntry', fieldbackground=self.COLOR_INPUT_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER, insertcolor=self.COLOR_PRIMARY)
        self.style.configure('TSpinbox', fieldbackground=self.COLOR_INPUT_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, lightcolor=self.COLOR_BORDER, darkcolor=self.COLOR_BORDER, arrowsize=max(12, tokens.fonts.body))
        self.style.configure('TLabelframe', background=self.COLOR_BG, foreground=self.COLOR_TEXT, bordercolor=self.COLOR_BORDER, relief='solid')
        self.style.configure('TLabelframe.Label', background=self.COLOR_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s, 'bold'))
        self.style.configure('TPanedwindow', background=self.COLOR_BORDER)
        self.style.configure('Big.Horizontal.TProgressbar', troughcolor='#E2E8F0', background=self.COLOR_PRIMARY, bordercolor='#E2E8F0', lightcolor=self.COLOR_PRIMARY, darkcolor=self.COLOR_PRIMARY, thickness=tokens.components.progress_thickness)
        self.style.configure('Inactive.Horizontal.TProgressbar', troughcolor=self.COLOR_BG, background=self.COLOR_BG, bordercolor=self.COLOR_BG, lightcolor=self.COLOR_BG, darkcolor=self.COLOR_BG, thickness=tokens.components.progress_thickness)
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
        login_layout_job = getattr(self, "_worker_login_layout_job", None)
        if login_layout_job:
            try:
                self.root.after_cancel(login_layout_job)
            except (AttributeError, tk.TclError):
                pass
            self._worker_login_layout_job = None
        self.worker_input_frame.pack_forget()
        self.paned_window.pack_forget()

    def _get_worker_login_layout_metrics(
        self,
        content_width: int = 0,
        content_height: int = 0,
    ) -> Dict[str, Any]:
        if content_width <= 1 or content_height <= 1:
            for widget in (getattr(self, "worker_input_frame", None), getattr(self, "root", None)):
                try:
                    candidate_width = int(widget.winfo_width())
                    candidate_height = int(widget.winfo_height())
                except (AttributeError, TypeError, ValueError, tk.TclError):
                    continue
                if candidate_width > 1 and candidate_height > 1:
                    content_width = candidate_width
                    content_height = candidate_height
                    break
        metrics = calculate_worker_login_layout_metrics(
            max(1, content_width),
            max(1, content_height),
            getattr(self, "scale_factor", 1.0),
        )
        return {
            "profile": metrics.profile,
            "short_height": metrics.short_height,
            "horizontal_pad": metrics.horizontal_pad,
            "logo_max_width": metrics.logo_max_width,
            "logo_max_height": metrics.logo_max_height,
            "logo_pad_y": metrics.logo_pad_y,
            "title_pad_y": metrics.title_pad_y,
            "field_label_pad_y": metrics.field_label_pad_y,
            "entry_ipady": metrics.entry_ipady,
            "button_pad_y": metrics.button_pad_y,
            "button_pad_x": metrics.button_pad_x,
            "button_ipady": metrics.button_ipady,
            "estimated_content_height": metrics.estimated_content_height,
        }

    def _schedule_worker_login_layout_refresh(self, event=None) -> None:
        if getattr(self, "_worker_login_layout_job", None):
            return
        try:
            self._worker_login_layout_job = self.root.after_idle(self._apply_worker_login_layout)
        except AttributeError:
            try:
                self._worker_login_layout_job = self.root.after(0, self._apply_worker_login_layout)
            except AttributeError:
                self._apply_worker_login_layout()
        except tk.TclError:
            return

    def _apply_worker_login_layout(self, event=None) -> None:
        self._worker_login_layout_job = None
        center_frame = getattr(self, "_worker_login_center_frame", None)
        if center_frame is None:
            return
        try:
            if hasattr(center_frame, "winfo_exists") and not center_frame.winfo_exists():
                return
            width = int(self.worker_input_frame.winfo_width())
            height = int(self.worker_input_frame.winfo_height())
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return
        if width <= 1 or height <= 1:
            try:
                width = int(self.root.winfo_width())
                height = int(self.root.winfo_height())
            except (AttributeError, TypeError, ValueError, tk.TclError):
                return
        metrics = self._get_worker_login_layout_metrics(width, height)
        metrics_key = tuple(metrics.items())
        if metrics_key == getattr(self, "_worker_login_layout_metrics_key", None):
            return
        self._worker_login_layout_metrics_key = metrics_key
        self._worker_login_layout_metrics = metrics

        try:
            center_frame.grid_configure(padx=metrics["horizontal_pad"])
            logo_label = getattr(self, "_worker_login_logo_label", None)
            if logo_label is not None:
                logo_label.pack_configure(pady=metrics["logo_pad_y"])
            self._worker_login_title_label.pack_configure(pady=metrics["title_pad_y"])
            self._worker_login_name_label.pack_configure(pady=metrics["field_label_pad_y"])
            self.worker_entry.pack_configure(ipady=metrics["entry_ipady"])
            self._worker_login_button_container.pack_configure(pady=metrics["button_pad_y"])
            for button in self._worker_login_buttons:
                button.pack_configure(
                    padx=metrics["button_pad_x"],
                    ipady=metrics["button_ipady"],
                )
        except (AttributeError, tk.TclError):
            return

        logo_source = getattr(self, "_worker_login_logo_source", None)
        logo_label = getattr(self, "_worker_login_logo_label", None)
        if logo_source is None or logo_label is None:
            return
        source_width = max(1, int(logo_source.width))
        source_height = max(1, int(logo_source.height))
        target_width = min(metrics["logo_max_width"], source_width)
        target_height = max(1, int(round(target_width * source_height / source_width)))
        if target_height > metrics["logo_max_height"]:
            target_height = metrics["logo_max_height"]
            target_width = max(1, int(round(target_height * source_width / source_height)))
        logo_size = (target_width, target_height)
        if logo_size == getattr(self, "_worker_login_logo_size", None):
            return
        try:
            resized = logo_source.resized(*logo_size, resample="bilinear")
            self.logo_photo_ref = resized.to_tk_photo_image(master=logo_label)
            logo_label.configure(image=self.logo_photo_ref)
            self._worker_login_logo_size = logo_size
        except Exception as exc:
            print(f"로고 크기 조정 실패: {exc}")

    def show_worker_input_screen(self):
        self._clear_main_frames()
        self.worker_role = ""
        self.worker_input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for widget in self.worker_input_frame.winfo_children(): widget.destroy()
        self.worker_input_frame.grid_rowconfigure(0, weight=1)
        self.worker_input_frame.grid_columnconfigure(0, weight=1)
        center_frame = ttk.Frame(self.worker_input_frame, style='TFrame')
        center_frame.grid(row=0, column=0)
        self._worker_login_center_frame = center_frame
        self._worker_login_layout_job = None
        self._worker_login_layout_metrics_key = None
        self._worker_login_logo_source = None
        self._worker_login_logo_label = None
        self._worker_login_logo_size = None
        self._authenticated_protected_admin = False
        try:
            logo_path = resource_path(os.path.join('assets', 'logo.png'))
            self._worker_login_logo_source = RasterImage.from_png(logo_path)
            self._worker_login_logo_label = ttk.Label(center_frame, style='TLabel')
            self._worker_login_logo_label.pack()
        except Exception as e:
            print(f"로고 로드 실패: {e}")
        self._worker_login_title_label = ttk.Label(center_frame, text=self.APP_TITLE, style='Title.TLabel')
        self._worker_login_title_label.pack()
        self._worker_login_name_label = ttk.Label(
            center_frame,
            text="작업자 이름",
            style='TLabel',
            font=(self.DEFAULT_FONT, int(12*self.scale_factor)),
        )
        self._worker_login_name_label.pack()
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
        self.worker_entry.pack()
        self.worker_entry.bind('<Return>', self.start_work)
        self.worker_entry.bind('<KeyRelease>', self._update_worker_input_mask)
        self.worker_entry.bind('<<ComboboxSelected>>', self._update_worker_input_mask)
        self._update_worker_input_mask()
        self.worker_entry.focus()
        button_container = ttk.Frame(center_frame, style='TFrame')
        self._worker_login_button_container = button_container
        button_container.pack()
        register_button = ttk.Button(
            button_container,
            text="신규 등록",
            command=self.register_worker_from_login,
            style='Secondary.TButton',
            width=16,
        )
        start_button = ttk.Button(
            button_container,
            text="작업 시작",
            command=self.start_work,
            style='TButton',
            width=20,
        )
        self._worker_login_buttons = [register_button, start_button]
        register_button.pack(side=tk.LEFT)
        start_button.pack(side=tk.LEFT)
        self._apply_worker_login_layout()
        self.worker_input_frame.bind('<Configure>', self._schedule_worker_login_layout_refresh)
        self.root.after(0, self._apply_worker_login_layout)

    def _refresh_worker_entry_options(self):
        if hasattr(self, 'worker_entry') and hasattr(self.worker_entry, 'configure'):
            self.worker_entry.configure(values=self.worker_registry.list_workers())

    def _set_worker_entry_value(self, value: str) -> None:
        if hasattr(self, "worker_entry_var"):
            self.worker_entry_var.set(value)
        elif hasattr(self, "worker_entry") and hasattr(self.worker_entry, "set"):
            self.worker_entry.set(value)
        self._update_worker_input_mask()

    def _update_worker_input_mask(self, event=None) -> None:
        entry = getattr(self, "worker_entry", None)
        if entry is None or not hasattr(entry, "configure"):
            return
        try:
            value = str(entry.get() or "").strip()
        except (AttributeError, tk.TclError):
            value = ""
        if value != PROTECTED_ADMIN_DISPLAY_NAME:
            self._authenticated_protected_admin = False
        mask = "●" if value.isascii() and value.isdecimal() else ""
        try:
            entry.configure(show=mask)
        except (TypeError, tk.TclError):
            pass

    def _resolve_worker_login_candidate(self, worker_name: str) -> Optional[str]:
        candidate = WorkerRegistry.normalize_name(worker_name)
        if is_protected_admin_candidate(candidate):
            if not is_protected_admin_code(candidate):
                self._authenticated_protected_admin = False
                messagebox.showerror(
                    "인증 오류",
                    "관리자 코드를 확인할 수 없습니다. 보호 프로필과 입력값을 확인하세요.",
                    parent=self.root,
                )
                return None
            self._authenticated_protected_admin = True
            self._set_worker_entry_value(PROTECTED_ADMIN_DISPLAY_NAME)
            return PROTECTED_ADMIN_OPERATOR_ID
        if (
            candidate == PROTECTED_ADMIN_DISPLAY_NAME
            and getattr(self, "_authenticated_protected_admin", False)
        ):
            return PROTECTED_ADMIN_OPERATOR_ID
        if candidate in {PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME}:
            messagebox.showerror(
                "인증 오류",
                "보호된 관리자는 관리자 코드를 다시 입력해야 합니다.",
                parent=self.root,
            )
            return None
        return candidate

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
            worker_name = simpledialog.askstring(
                "신규 작업자 등록",
                "등록할 작업자 이름을 입력하세요.",
                parent=self.root,
                show="●",
            )
        if is_protected_admin_candidate(worker_name):
            resolved = self._resolve_worker_login_candidate(worker_name)
            if resolved == PROTECTED_ADMIN_OPERATOR_ID:
                messagebox.showinfo(
                    "관리자 인증",
                    "보호된 관리자 인증을 확인했습니다. 작업 시작을 누르세요.",
                    parent=self.root,
                )
            return
        registered = self._register_worker_name(worker_name, parent=self.root)
        if not registered:
            return
        self.worker_entry_var.set(registered)
        self._refresh_worker_entry_options()
        messagebox.showinfo("작업자 등록", f"{registered} 작업자를 등록했습니다.", parent=self.root)

    def _ensure_worker_login_name(self, worker_name: str) -> Optional[str]:
        worker_name = self._resolve_worker_login_candidate(worker_name)
        if worker_name is None:
            return None
        if not worker_name:
            messagebox.showerror("오류", "작업자 이름을 입력해주세요.")
            return None
        if (
            worker_name == PROTECTED_ADMIN_OPERATOR_ID
            and getattr(self, "_authenticated_protected_admin", False)
        ):
            return worker_name
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
        protected_admin_authenticated = bool(
            worker_name == PROTECTED_ADMIN_OPERATOR_ID
            and getattr(self, "_authenticated_protected_admin", False)
        )
        worker_registry = getattr(self, "worker_registry", None)
        if worker_registry is not None and not protected_admin_authenticated:
            try:
                worker_name = worker_registry.mark_recent(worker_name)
            except ValueError as exc:
                messagebox.showerror("작업자 기록 오류", str(exc), parent=self.root)
                return
            self._refresh_worker_entry_options()
        self.worker_name = worker_name
        self.worker_role = "ADMIN" if protected_admin_authenticated else "WORKER"
        self._load_session_state()
        self._load_current_tray_state()
        if not self.worker_name:
            return
        if not self._restore_preflight_scan_hold():
            self.current_tray = TraySession()
            self.worker_name = ""
            self.worker_role = ""
            self.show_worker_input_screen()
            return
        # Durable hold ownership is restored before the first shared-lane task
        # can inspect or mutate either transfer coordinator.
        self._schedule_startup_transfer_recovery()
        if not self._begin_or_resume_work_session():
            self.current_tray = TraySession()
            self.worker_name = ""
            self.worker_role = ""
            messagebox.showerror(
                "작업 시작 기록 대기",
                "작업 세션과 감사 outbox를 함께 저장하거나 투영하지 못했습니다. "
                "상태를 보존했으니 다시 시도하고 계속되면 관리자에게 문의하세요.",
                parent=self.root,
            )
            self.show_worker_input_screen()
            return
        if not self.root.winfo_exists(): return
        if not self.paned_window.winfo_ismapped():
            self.show_validation_screen()
        self._refresh_transfer_post_review_state()

    def change_worker(self):
        if self._preflight_context_blocks_mutation():
            self.show_status_message(
                "중앙 조회 보류 묶음을 먼저 재확인해야 작업자를 변경할 수 있습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if self._phs_label_exchange_blocks_tray_transition("작업자 변경"):
            return
        if self._transfer_member_exchange_blocks_local_action("작업자 변경"):
            return
        msg = "작업자를 변경하시겠습니까?"
        if self.current_tray.master_label_code:
            msg += "\n\n진행 중인 작업은 다음 로그인 시 복구할 수 있도록 저장됩니다."
        if messagebox.askyesno("작업자 변경", msg):
            if self.current_tray.master_label_code:
                if not self._save_current_tray_state():
                    messagebox.showerror("작업 저장 실패", "진행 중인 트레이 상태를 저장하지 못해 작업자를 변경하지 않습니다.")
                    return
                if not self._log_event(
                    'WORK_PAUSE',
                    detail={
                        'message': (
                            f"Worker '{persistent_operator_name(self.worker_name)}' changed."
                        )
                    },
                    synchronous=True,
                ):
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
            if not self._end_work_session(reason="worker_change"):
                messagebox.showerror(
                    "작업 종료 기록 대기",
                    "작업 세션 종료 상태와 감사 outbox를 함께 저장하거나 투영하지 "
                    "못해 작업자를 변경하지 않습니다.",
                )
                return
            self._cancel_all_jobs()
            self.worker_name = ""
            self.worker_role = ""
            self._authenticated_protected_admin = False
            self.current_tray = TraySession()
            self._invalidate_pending_scan_callbacks()
            self._reset_master_label_replacement_state()
            self.show_worker_input_screen()

    def _load_session_state(self):
        history = load_session_history(
            save_folder=self.save_folder,
            worker_name=persistent_operator_name(self.worker_name),
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
        lock = getattr(self, "_tray_state_persist_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._tray_state_persist_lock = lock
        with lock:
            if not self.current_tray.master_label_code:
                return False
            state = self._current_tray_state_snapshot()
            return self._save_tray_state_snapshot(state)

    def _current_tray_save_operation(self) -> Callable[[], bool]:
        """Freeze the UI-owned state before handing its write to the lane."""
        if not self.current_tray.master_label_code:
            return lambda: False
        state = self._current_tray_state_snapshot()
        return lambda: self._save_tray_state_snapshot(state)

    @writer_sink("gui_tray_state_save")
    def _save_tray_state_snapshot(self, state: Dict[str, Any]) -> bool:
        lock = getattr(self, "_tray_state_persist_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._tray_state_persist_lock = lock
        with lock:
            try:
                state_path = os.path.join(
                    self.save_folder,
                    self.CURRENT_TRAY_STATE_FILE,
                )
                atomic_write_json(state_path, state, indent=4)
                return True
            except Exception as e:
                print(f"현재 트레이 상태 저장 실패: {e}")
                return False

    @staticmethod
    def _activation_event_contract_from_state(
        state: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        payload = state.get(ACTIVATION_EVENT_STATE_KEY)
        if payload is None:
            return None
        return {
            "schema_version": int(payload["schema_version"]),
            "event_type": str(payload["event_type"]),
            "idempotency_key": str(payload["idempotency_key"]),
            "observed_at": str(payload["observed_at"]),
            "projection_log_name": str(payload["projection_log_name"]),
            "projection_worker_name": str(payload["projection_worker_name"]),
            "master_label_code": str(payload["master_label_code"]),
            "event_detail": dict(payload["event_detail"]),
        }

    def _active_activation_event_contract(self) -> Optional[Dict[str, Any]]:
        payload = getattr(self, "_pending_activation_event_contract", None)
        return dict(payload) if isinstance(payload, Mapping) else None

    def _activation_event_contract(
        self,
        *,
        event_type: str,
        event_detail: Mapping[str, Any],
        master_label_code: str,
        observed_at: datetime.datetime,
    ) -> Dict[str, Any]:
        projection_worker = persistent_operator_name(self.worker_name)
        if not projection_worker:
            raise ValueError("activation projection worker is missing")
        projection_path = self._completion_projection_log_path()
        return {
            "schema_version": ACTIVATION_EVENT_STATE_SCHEMA_VERSION,
            "event_type": str(event_type),
            "idempotency_key": f"tray-activation:{uuid.uuid4().hex}",
            "observed_at": observed_at.isoformat(),
            "projection_log_name": projection_path.name,
            "projection_worker_name": projection_worker,
            "master_label_code": str(master_label_code),
            "event_detail": dict(sanitize_persistent_value(dict(event_detail))),
        }

    def _project_activation_event_contract(
        self,
        contract: Mapping[str, Any],
    ) -> bool:
        try:
            projection_path = self._completion_projection_log_path(
                str(contract["projection_log_name"])
            )
            return self._log_event(
                str(contract["event_type"]),
                detail=dict(contract["event_detail"]),
                synchronous=True,
                idempotency_key=str(contract["idempotency_key"]),
                event_timestamp=str(contract["observed_at"]),
                log_file_path_override=str(projection_path),
                deduplicate=True,
                worker_name_override=str(contract["projection_worker_name"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._record_log_write_error(
                f"현품표 시작 감사 outbox 투영 오류: {exc}"
            )
            return False

    def _drain_pending_activation_event(self) -> bool:
        """Project and clear one activation outbox row without losing it.

        A failed CSV projection leaves the complete contract embedded in the
        current tray snapshot.  A crash after CSV fsync but before marker clear
        is reconciled by the idempotent event/key pair on the next start.
        """

        contract = self._active_activation_event_contract()
        if contract is None:
            return True
        if not self._project_activation_event_contract(contract):
            return False
        self._pending_activation_event_contract = None
        if self._clear_persisted_activation_event(contract):
            return True
        self._pending_activation_event_contract = contract
        print(
            "현품표 시작 감사 outbox 정리 실패: CSV는 durable 하며 "
            "다음 저장 또는 재시작에서 idempotent 재확인합니다."
        )
        return True

    def _clear_persisted_activation_event(
        self,
        contract: Mapping[str, Any],
    ) -> bool:
        lock = getattr(self, "_tray_state_persist_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._tray_state_persist_lock = lock
        with lock:
            try:
                state_path = Path(self.save_folder) / self.CURRENT_TRAY_STATE_FILE
                with state_path.open("r", encoding="utf-8") as f_handle:
                    persisted = json.load(f_handle)
                persisted_contract = self._activation_event_contract_from_state(
                    persisted
                )
                if persisted_contract != dict(contract):
                    return False
                persisted.pop(ACTIVATION_EVENT_STATE_KEY, None)
                validate_tray_state(
                    persisted,
                    default_tray_size=self.TRAY_SIZE,
                )
                return self._save_tray_state_snapshot(persisted)
            except (AttributeError, OSError, TypeError, ValueError):
                return False

    def _reconcile_activation_event_from_state(
        self,
        state: Dict[str, Any],
    ) -> bool:
        contract = self._activation_event_contract_from_state(state)
        self._pending_activation_event_contract = contract
        if contract is None:
            return True
        if not self._project_activation_event_contract(contract):
            return False
        self._pending_activation_event_contract = None
        if self._clear_persisted_activation_event(contract):
            state.pop(ACTIVATION_EVENT_STATE_KEY, None)
            return True
        self._pending_activation_event_contract = contract
        print(
            "복구된 현품표 시작 감사 outbox 정리 실패: CSV는 durable 하며 "
            "상태 marker를 보존합니다."
        )
        return True

    def _audit_event_contract(
        self,
        *,
        event_type: str,
        event_detail: Mapping[str, Any],
        idempotency_key: str,
        observed_at: datetime.datetime,
        projection_worker_name: str = "",
        canonical_event_name: str = "",
    ) -> Dict[str, Any]:
        projection_worker = persistent_operator_name(
            projection_worker_name or self.worker_name
        )
        if not projection_worker:
            raise ValueError("audit projection worker is missing")
        projection_path = self._completion_projection_log_path()
        return {
            "schema_version": 1,
            "event_type": str(event_type),
            "canonical_event_name": str(canonical_event_name or ""),
            "idempotency_key": str(idempotency_key),
            "observed_at": observed_at.isoformat(),
            "projection_log_name": projection_path.name,
            "projection_worker_name": projection_worker,
            "event_detail": dict(sanitize_persistent_value(dict(event_detail))),
        }

    def _project_audit_event_contract(self, contract: Mapping[str, Any]) -> bool:
        try:
            projection_path = self._completion_projection_log_path(
                str(contract["projection_log_name"])
            )
            canonical_event_name = str(
                contract.get("canonical_event_name") or ""
            )
            return self._log_event(
                str(contract["event_type"]),
                detail=dict(contract["event_detail"]),
                synchronous=True,
                canonical_event_name=canonical_event_name or None,
                idempotency_key=str(contract["idempotency_key"]),
                event_timestamp=str(contract["observed_at"]),
                log_file_path_override=str(projection_path),
                deduplicate=True,
                worker_name_override=str(contract["projection_worker_name"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._record_log_write_error(f"감사 outbox 투영 오류: {exc}")
            return False

    @staticmethod
    def _parked_restore_contract_from_state(
        state: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        payload = state.get(PARKED_RESTORE_STATE_KEY)
        if payload is None:
            return None
        return {
            "schema_version": int(payload["schema_version"]),
            "operation_id": str(payload["operation_id"]),
            "parked_source_name": str(payload["parked_source_name"]),
            "parked_source_sha256": str(payload["parked_source_sha256"]),
            "restored_master_label_code": str(
                payload["restored_master_label_code"]
            ),
            "projection_events": [
                {
                    "schema_version": int(event["schema_version"]),
                    "event_type": str(event["event_type"]),
                    "canonical_event_name": str(
                        event.get("canonical_event_name") or ""
                    ),
                    "idempotency_key": str(event["idempotency_key"]),
                    "observed_at": str(event["observed_at"]),
                    "projection_log_name": str(event["projection_log_name"]),
                    "projection_worker_name": str(
                        event["projection_worker_name"]
                    ),
                    "event_detail": dict(event["event_detail"]),
                }
                for event in payload["projection_events"]
            ],
        }

    def _active_parked_restore_contract(self) -> Optional[Dict[str, Any]]:
        payload = getattr(self, "_pending_parked_restore_contract", None)
        if not isinstance(payload, Mapping):
            return None
        return self._parked_restore_contract_from_state(
            {PARKED_RESTORE_STATE_KEY: payload}
        )

    def _build_parked_restore_contract(
        self,
        *,
        parked_path: Path,
        restored_state: Mapping[str, Any],
        restore_detail: Mapping[str, Any],
        discard_detail: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        operation_id = f"parked-restore:{uuid.uuid4().hex}"
        observed_at = datetime.datetime.now()
        projection_events: List[Dict[str, Any]] = []
        if discard_detail is not None:
            projection_events.append(
                self._audit_event_contract(
                    event_type="TRAY_DISCARDED_BY_OPERATOR",
                    event_detail=discard_detail,
                    idempotency_key=f"{operation_id}:discard",
                    observed_at=observed_at,
                )
            )
        projection_events.append(
            self._audit_event_contract(
                event_type="TRAY_RESTORED_FROM_PARK",
                canonical_event_name="TRAY_RESTORED",
                event_detail=restore_detail,
                idempotency_key=f"{operation_id}:restore",
                observed_at=observed_at,
            )
        )
        return {
            "schema_version": PARKED_RESTORE_STATE_SCHEMA_VERSION,
            "operation_id": operation_id,
            "parked_source_name": parked_path.name,
            "parked_source_sha256": hashlib.sha256(
                parked_path.read_bytes()
            ).hexdigest(),
            "restored_master_label_code": str(
                restored_state.get("master_label_code") or ""
            ),
            "projection_events": projection_events,
        }

    def _cleanup_parked_restore_source(
        self,
        contract: Mapping[str, Any],
    ) -> bool:
        try:
            source_name = str(contract["parked_source_name"])
            source_path = self._parked_store().directory / source_name
            if not self._is_parked_tray_path(str(source_path)):
                return False
            if not source_path.exists():
                return True
            source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
            if source_sha256 != str(contract["parked_source_sha256"]):
                self._record_log_write_error(
                    "보류 복원 source hash가 outbox와 일치하지 않습니다."
                )
                return False
            ParkedTrayStore.delete(source_path)
            return True
        except (KeyError, OSError, TypeError, ValueError) as exc:
            self._record_log_write_error(
                f"보류 복원 source 정리 오류: {exc.__class__.__name__}"
            )
            return False

    def _clear_persisted_parked_restore(
        self,
        contract: Mapping[str, Any],
    ) -> bool:
        lock = getattr(self, "_tray_state_persist_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._tray_state_persist_lock = lock
        with lock:
            try:
                state_path = Path(self.save_folder) / self.CURRENT_TRAY_STATE_FILE
                with state_path.open("r", encoding="utf-8") as f_handle:
                    persisted = json.load(f_handle)
                persisted_contract = self._parked_restore_contract_from_state(
                    persisted
                )
                if persisted_contract != dict(contract):
                    return False
                persisted.pop(PARKED_RESTORE_STATE_KEY, None)
                validate_tray_state(
                    persisted,
                    default_tray_size=self.TRAY_SIZE,
                )
                return self._save_tray_state_snapshot(persisted)
            except (AttributeError, KeyError, OSError, TypeError, ValueError):
                return False

    def _drain_pending_parked_restore(self) -> bool:
        contract = self._active_parked_restore_contract()
        if contract is None:
            return True
        for event in contract["projection_events"]:
            if not self._project_audit_event_contract(event):
                return False
        if not self._cleanup_parked_restore_source(contract):
            return False
        self._pending_parked_restore_contract = None
        if self._clear_persisted_parked_restore(contract):
            return True
        self._pending_parked_restore_contract = contract
        print(
            "보류 복원 감사 outbox 정리 실패: projection/source cleanup은 "
            "durable 하며 다음 재시작에서 idempotent 재확인합니다."
        )
        return True

    def _reconcile_parked_restore_from_state(
        self,
        state: Dict[str, Any],
    ) -> bool:
        contract = self._parked_restore_contract_from_state(state)
        self._pending_parked_restore_contract = contract
        if contract is None:
            return True
        if not self._drain_pending_parked_restore():
            return False
        if self._active_parked_restore_contract() is None:
            state.pop(PARKED_RESTORE_STATE_KEY, None)
        return True

    def _work_session_state_path(self) -> Optional[Path]:
        save_folder = str(getattr(self, "save_folder", "") or "").strip()
        state_file = str(
            getattr(self, "WORK_SESSION_STATE_FILE", "") or ""
        ).strip()
        if not save_folder or not state_file:
            return None
        return Path(save_folder) / state_file

    def _load_work_session_state(self) -> Optional[Dict[str, Any]]:
        state_path = self._work_session_state_path()
        if state_path is None or not state_path.exists():
            return None
        if state_path.stat().st_size > 64 * 1024:
            raise WorkSessionStateError("work session state is too large")
        with state_path.open("r", encoding="utf-8") as f_handle:
            state = json.load(f_handle)
        return validate_work_session_state(state)

    @writer_sink("gui_work_session_save")
    def _save_work_session_state(self, state: Mapping[str, Any]) -> bool:
        state_path = self._work_session_state_path()
        if state_path is None:
            return False
        lock = getattr(self, "_work_session_persist_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._work_session_persist_lock = lock
        with lock:
            try:
                normalized = validate_work_session_state(state)
                atomic_write_json(
                    state_path,
                    normalized,
                    indent=2,
                    ensure_ascii=False,
                    trailing_newline=True,
                )
                return True
            except (OSError, TypeError, ValueError) as exc:
                self._record_log_write_error(
                    f"작업 세션 journal 저장 오류: {exc.__class__.__name__}"
                )
                return False

    def _reconcile_work_session_state(self) -> bool:
        if self._work_session_state_path() is None:
            return True
        try:
            state = self._load_work_session_state()
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, WorkSessionStateError) as exc:
            self._record_log_write_error(
                f"작업 세션 journal 검증 오류: {exc.__class__.__name__}"
            )
            return False
        if state is None:
            self._work_session_id = ""
            return True
        phase = state["phase"]
        if phase in {
            WORK_SESSION_PHASE_START_PENDING,
            WORK_SESSION_PHASE_END_PENDING,
        }:
            if not self._project_audit_event_contract(state["pending_event"]):
                return False
            state["pending_event"] = None
            state["phase"] = (
                WORK_SESSION_PHASE_ACTIVE
                if phase == WORK_SESSION_PHASE_START_PENDING
                else WORK_SESSION_PHASE_CLOSED
            )
            if not self._save_work_session_state(state):
                return False
            phase = state["phase"]
        self._work_session_id = (
            state["session_id"] if phase == WORK_SESSION_PHASE_ACTIVE else ""
        )
        return True

    def _begin_or_resume_work_session(self) -> bool:
        if self._work_session_state_path() is None:
            return self._log_event(
                "WORK_START",
                detail={
                    "message": (
                        f"작업자 '{persistent_operator_name(self.worker_name)}'이(가) "
                        "작업을 시작했습니다."
                    )
                },
                synchronous=True,
            )
        if not self._reconcile_work_session_state():
            self._work_session_recovery_blocked = True
            return False
        try:
            previous = self._load_work_session_state()
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, WorkSessionStateError):
            self._work_session_recovery_blocked = True
            return False
        actor = persistent_operator_name(self.worker_name)
        if (
            previous is not None
            and previous["phase"] == WORK_SESSION_PHASE_ACTIVE
            and previous["worker_name"] == actor
        ):
            self._work_session_id = previous["session_id"]
            self._work_session_recovery_blocked = False
            return True
        session_suffix = uuid.uuid4().hex
        session_id = f"work-session:{session_suffix}"
        observed_at = datetime.datetime.now()
        pending_event = self._audit_event_contract(
            event_type="WORK_START",
            event_detail={
                "message": f"작업자 '{actor}'이(가) 작업을 시작했습니다.",
                "work_session_id": session_id,
            },
            idempotency_key=f"work-session-start:{session_suffix}",
            observed_at=observed_at,
            projection_worker_name=actor,
        )
        state = {
            "schema_version": WORK_SESSION_STATE_SCHEMA_VERSION,
            "session_id": session_id,
            "previous_session_id": (
                str(previous.get("session_id") or "") if previous else ""
            ),
            "worker_name": actor,
            "worker_role": str(self.worker_role or "WORKER"),
            "phase": WORK_SESSION_PHASE_START_PENDING,
            "started_at": observed_at.isoformat(),
            "ended_at": "",
            "pending_event": pending_event,
        }
        if not self._save_work_session_state(state):
            return False
        if not self._reconcile_work_session_state():
            self._work_session_recovery_blocked = True
            return False
        self._work_session_recovery_blocked = False
        return True

    def _end_work_session(self, *, reason: str) -> bool:
        if self._work_session_state_path() is None:
            return self._log_event(
                "WORK_END",
                detail={"message": "User closed the program.", "reason": reason},
                synchronous=True,
            )
        if not self._reconcile_work_session_state():
            self._work_session_recovery_blocked = True
            return False
        try:
            state = self._load_work_session_state()
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, WorkSessionStateError):
            self._work_session_recovery_blocked = True
            return False
        actor = persistent_operator_name(self.worker_name)
        if (
            state is None
            or state["phase"] != WORK_SESSION_PHASE_ACTIVE
            or state["worker_name"] != actor
        ):
            return True
        session_suffix = state["session_id"].removeprefix("work-session:")
        observed_at = datetime.datetime.now()
        state["phase"] = WORK_SESSION_PHASE_END_PENDING
        state["ended_at"] = observed_at.isoformat()
        state["pending_event"] = self._audit_event_contract(
            event_type="WORK_END",
            event_detail={
                "message": "User ended the work session.",
                "reason": reason,
                "work_session_id": state["session_id"],
            },
            idempotency_key=f"work-session-end:{session_suffix}",
            observed_at=observed_at,
            projection_worker_name=actor,
        )
        if not self._save_work_session_state(state):
            return False
        if not self._reconcile_work_session_state():
            self._work_session_recovery_blocked = True
            return False
        self._work_session_recovery_blocked = False
        return True

    def _active_operator_review_snapshot(self) -> Optional[CompletionOutcomeSnapshot]:
        pending = getattr(self, "_pending_operator_review_snapshot", None)
        if pending is not None and pending.outcome is CompletionOutcome.OPERATOR_REVIEW:
            return pending
        completion = self._warning_state_presenter().state.completion
        if completion is not None and completion.outcome is CompletionOutcome.OPERATOR_REVIEW:
            return completion
        return None

    def _active_blocking_completion_snapshot(self) -> Optional[CompletionOutcomeSnapshot]:
        """Return the durable completion result that still owns this tray."""

        pending = getattr(self, "_pending_operator_review_snapshot", None)
        if pending is not None and pending.blocks_completion:
            return pending
        completion = self._warning_state_presenter().state.completion
        if completion is not None and completion.blocks_completion:
            return completion
        return None

    def _operator_review_state_payload(self) -> Optional[Dict[str, Any]]:
        # Keep the historic JSON key for backward compatibility.  It now also
        # persists retryable completion states, because a restart must not
        # release a tray whose transfer or local completion record is unsettled.
        snapshot = self._active_blocking_completion_snapshot()
        if snapshot is None:
            return None
        tray = self.current_tray
        return {
            "schema_version": OPERATOR_REVIEW_STATE_SCHEMA_VERSION,
            "outcome": snapshot.outcome.value,
            "item_name": str(tray.item_name or ""),
            "master_label": str(tray.master_label_code or ""),
            "scan_count": len(tray.scanned_barcodes),
            "target_count": int(tray.tray_size),
            "message": str(snapshot.message or "담당자 확인이 필요한 서버 판정입니다."),
            "receipt_id": str(snapshot.receipt_id or ""),
            "error_code": str(snapshot.error_code or ""),
        }

    @staticmethod
    def _completion_event_contract_from_state(
        state: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        payload = state.get(COMPLETION_EVENT_STATE_KEY)
        if payload is None:
            return None
        return {
            "schema_version": int(payload["schema_version"]),
            "event_type": str(payload["event_type"]),
            "idempotency_key": str(payload["idempotency_key"]),
            "observed_at": str(payload["observed_at"]),
            "projection_log_name": str(payload["projection_log_name"]),
            "projection_worker_name": str(payload["projection_worker_name"]),
            "transfer_intent_id": str(payload["transfer_intent_id"]),
            "was_restored_session": bool(payload["was_restored_session"]),
            "log_may_have_been_attempted": bool(
                payload["log_may_have_been_attempted"]
            ),
            "transfer_detail": dict(payload["transfer_detail"]),
        }

    def _active_completion_event_contract(self) -> Optional[Dict[str, Any]]:
        payload = getattr(self, "_pending_completion_event_contract", None)
        return dict(payload) if isinstance(payload, Mapping) else None

    def _operator_review_snapshot_from_state(
        self,
        state: Dict[str, Any],
    ) -> Optional[CompletionOutcomeSnapshot]:
        payload = state.get(OPERATOR_REVIEW_STATE_KEY)
        if payload is None:
            return None
        outcome = CompletionOutcome(str(payload["outcome"]))
        return CompletionOutcomeSnapshot(
            outcome=outcome,
            item_name=str(payload["item_name"]),
            master_label=str(payload["master_label"]),
            scan_count=int(payload["scan_count"]),
            target_count=int(payload["target_count"]),
            message=str(payload["message"]),
            receipt_id=str(payload["receipt_id"]),
            error_code=str(payload["error_code"]),
        )

    def _restore_operator_review_from_state(self, state: Dict[str, Any]) -> bool:
        completion_event = self._completion_event_contract_from_state(state)
        self._pending_completion_event_contract = completion_event
        snapshot = self._operator_review_snapshot_from_state(state)
        presenter = self._warning_state_presenter()
        if snapshot is None and completion_event is not None:
            transfer_detail = completion_event.get("transfer_detail") or {}
            log_was_attempted = bool(
                completion_event.get("log_may_have_been_attempted")
            )
            snapshot = CompletionOutcomeSnapshot(
                outcome=(
                    CompletionOutcome.LOCAL_EVENT_RETRY
                    if log_was_attempted
                    else CompletionOutcome.RETRY_WAIT
                ),
                item_name=str(self.current_tray.item_name or ""),
                master_label=str(self.current_tray.master_label_code or ""),
                scan_count=len(self.current_tray.scanned_barcodes),
                target_count=max(
                    len(self.current_tray.scanned_barcodes),
                    int(self.current_tray.tray_size or 0),
                ),
                message=(
                    "완료 기록 저장 도중 프로그램이 종료되었습니다. "
                    "트레이를 잠근 채 동일 완료 기록을 재확인해야 합니다."
                    if log_was_attempted
                    else "이적 요청 준비 뒤 프로그램이 종료되었습니다. "
                    "트레이를 잠근 채 동일 이적 요청을 서버에서 재확인해야 합니다."
                ),
                receipt_id=str(transfer_detail.get("transfer_seal_receipt_id") or ""),
                error_code=(
                    "TRAY_COMPLETE_EVENT_RECOVERY_REQUIRED"
                    if log_was_attempted
                    else "TRAY_COMPLETE_TRANSFER_RECOVERY_REQUIRED"
                ),
            )
        if snapshot is None:
            self._pending_operator_review_snapshot = None
            self._pending_completion_event_contract = None
            presenter.clear_completion()
            return False
        self._pending_operator_review_snapshot = snapshot
        presenter.present_completion(snapshot)
        if snapshot.outcome is CompletionOutcome.OPERATOR_REVIEW:
            self._start_warning_beep()
        else:
            self._stop_warning_beep()
        return True

    def _current_tray_state_snapshot(self) -> Dict[str, Any]:
        state = tray_session_to_state(self.current_tray, worker_name=self.worker_name)
        activation_event = self._active_activation_event_contract()
        if activation_event is not None:
            state[ACTIVATION_EVENT_STATE_KEY] = activation_event
        parked_restore = self._active_parked_restore_contract()
        if parked_restore is not None:
            state[PARKED_RESTORE_STATE_KEY] = parked_restore
        completion_event = self._active_completion_event_contract()
        if completion_event is not None:
            state[COMPLETION_EVENT_STATE_KEY] = completion_event
        operator_review = self._operator_review_state_payload()
        if operator_review is not None:
            state[OPERATOR_REVIEW_STATE_KEY] = operator_review
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
            saved_worker_raw = str(saved_state.get('worker_name') or '').strip()
            saved_worker_safe = persistent_operator_name(saved_worker_raw)
            if saved_worker_safe != saved_worker_raw:
                saved_state['worker_name'] = saved_worker_safe
                if not self._save_tray_state_snapshot(saved_state):
                    messagebox.showwarning(
                        "이전 작업 확인 필요",
                        "이전 작업자 정보를 안전하게 변환하지 못했습니다. 관리자에게 문의하세요.",
                    )
                    return
            if not self._reconcile_activation_event_from_state(saved_state):
                self.current_tray = TraySession()
                self.worker_name = ""
                messagebox.showerror(
                    "현품표 시작 기록 복구 실패",
                    "저장된 현품표 시작 감사 기록을 복구하지 못했습니다. "
                    "상태와 감사 outbox를 보존했으니 관리자에게 문의하세요.",
                )
                return
            if not self._reconcile_parked_restore_from_state(saved_state):
                self.current_tray = TraySession()
                self.worker_name = ""
                messagebox.showerror(
                    "보류 작업 복구 기록 대기",
                    "저장된 보류 작업 복구 기록을 투영하거나 source를 정리하지 "
                    "못했습니다. 상태와 감사 outbox를 보존했으니 관리자에게 "
                    "문의하세요.",
                )
                return
        except Exception as e:
            print(f"현재 트레이 상태 로드 실패: {e}")
            quarantined_path = self._quarantine_current_tray_state(str(e))
            self.current_tray = TraySession()
            if quarantined_path:
                print(f"현재 트레이 상태 격리 위치: {quarantined_path}")
            messagebox.showwarning(
                "이전 작업 확인 필요",
                "이전 작업 상태를 불러오지 못해 안전하게 분리했습니다. "
                "관리자에게 문의하세요.",
            )
            return

        try:
            saved_worker = persistent_operator_name(saved_state.get('worker_name'))
            current_worker_persistent = persistent_operator_name(self.worker_name)
            saved_master_label = saved_state.get('master_label_code')
            saved_operator_review = self._operator_review_snapshot_from_state(saved_state)
            saved_completion_event = self._completion_event_contract_from_state(
                saved_state
            )
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
            if saved_worker == current_worker_persistent:
                msg = (
                    "이전에 마치지 못한 트레이 작업을 이어서 시작하시겠습니까?\n\n"
                    f"· 품목: {saved_state.get('item_name', '알 수 없음')}\n"
                    f"· 스캔 수: {len(saved_state.get('scanned_barcodes', []))}개\n\n"
                    "예: 계속 작업 / 아니오: 보류하고 새 작업 / 취소: 로그인 화면"
                )
                restore_required = (
                    saved_operator_review is not None
                    or saved_completion_event is not None
                )
                recovery_choice = (
                    True
                    if restore_required
                    else messagebox.askyesnocancel("이전 작업 복구", msg)
                )
                if recovery_choice is None:
                    self.current_tray = TraySession()
                    self.worker_name = ""
                    self.worker_role = ""
                    self._authenticated_protected_admin = False
                    return
                if recovery_choice is True:
                    restore_detail = {
                        'message': 'Same worker restored their session.',
                    }
                    if restore_required:
                        restore_detail['operator_review_restored'] = True
                    if not self._log_event(
                        'TRAY_RESTORE',
                        detail=restore_detail,
                        synchronous=True,
                    ):
                        self.current_tray = TraySession()
                        messagebox.showerror("작업 기록 실패", "이전 작업 복구 기록을 남기지 못해 상태 파일을 보존합니다.")
                        return
                    self._restore_tray_from_state(saved_state)
                else:
                    if not self._defer_saved_recovery_state(saved_state):
                        messagebox.showerror(
                            "작업 보류 실패",
                            "이전 작업을 보류 상태로 안전하게 옮기지 못했습니다. "
                            "현재 상태를 보존했으니 다시 복구하거나 관리자에게 문의하세요.",
                        )
                        return
                    if hasattr(self, "_update_parked_trays_list"):
                        self._update_parked_trays_list()
                    if hasattr(self, "show_status_message"):
                        self.show_status_message(
                            "이전 작업을 보류했습니다. 보류 목록에서 다시 복구할 수 있습니다.",
                            self.COLOR_PRIMARY,
                        )
            else:
                saved_worker_display = display_operator_name(saved_worker)
                msg = f"이전 작업자 '{saved_worker_display}'님이 마치지 않은 작업이 있습니다.\n\n이 작업을 이어서 진행하시겠습니까?"
                response = messagebox.askyesnocancel("작업 인수 확인", msg)
                if response is True:
                    previous_operator_review = getattr(
                        self,
                        "_pending_operator_review_snapshot",
                        None,
                    )
                    previous_completion_event = getattr(
                        self,
                        "_pending_completion_event_contract",
                        None,
                    )
                    self.current_tray = tray_session_from_state(
                        saved_state,
                        session_factory=TraySession,
                        default_tray_size=self.TRAY_SIZE,
                    )
                    self._pending_operator_review_snapshot = saved_operator_review
                    self._pending_completion_event_contract = saved_completion_event
                    if not self._save_current_tray_state():
                        self._pending_operator_review_snapshot = previous_operator_review
                        self._pending_completion_event_contract = (
                            previous_completion_event
                        )
                        self.current_tray = TraySession()
                        messagebox.showwarning("작업 저장 경고", "인수한 작업 상태의 작업자 정보를 저장하지 못해 작업을 복구하지 않습니다.")
                        return
                    takeover_detail = {
                        'previous_worker': saved_worker,
                        'new_worker': current_worker_persistent,
                        'item_name': saved_state.get('item_name'),
                    }
                    try:
                        takeover_logged = bool(
                            self._log_event(
                                'TRAY_TAKEOVER',
                                detail=takeover_detail,
                                synchronous=True,
                            )
                        )
                    except Exception as exc:
                        print(f"작업 인수 기록 실패: {exc}")
                        takeover_logged = False
                    if not takeover_logged:
                        try:
                            rollback_ok = self._save_tray_state_snapshot(saved_state)
                        except Exception as exc:
                            print(f"작업 인수 상태 롤백 실패: {exc}")
                            rollback_ok = False
                        self._pending_operator_review_snapshot = previous_operator_review
                        self._pending_completion_event_contract = (
                            previous_completion_event
                        )
                        self.current_tray = TraySession()
                        if rollback_ok:
                            messagebox.showerror("작업 기록 실패", "작업 인수 기록을 남기지 못해 이전 작업 상태를 보존합니다.")
                        else:
                            messagebox.showerror("작업 기록 실패", "작업 인수 기록을 남기지 못했고 이전 작업 상태 복원에도 실패했습니다. 상태 파일을 확인하세요.")
                        return
                    self._restore_operator_review_from_state(saved_state)
                    self._invalidate_pending_scan_callbacks()
                    self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)
                elif response is False:
                    if (
                        saved_operator_review is not None
                        or saved_completion_event is not None
                    ):
                        messagebox.showwarning(
                            "삭제 불가",
                            "담당자 확인이 필요한 트레이는 삭제할 수 없습니다. "
                            "담당자 확인 후 기존 작업자가 다시 로그인해 주세요.",
                        )
                        self.worker_name = ""
                        self.current_tray = TraySession()
                        self.show_worker_input_screen()
                        return
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
                        self.show_status_message(f"'{saved_worker_display}'님의 이전 작업이 삭제되었습니다.", self.COLOR_DANGER)
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
            messagebox.showwarning(
                "이전 작업 확인 필요",
                "이전 작업 상태를 불러오지 못했습니다. 관리자에게 문의하세요.",
            )

    def _restore_tray_from_state(self, state: Dict[str, Any]):
        self.current_tray = tray_session_from_state(
            state,
            session_factory=TraySession,
            default_tray_size=self.TRAY_SIZE,
        )
        restored_operator_review = self._restore_operator_review_from_state(state)
        self._invalidate_pending_scan_callbacks()
        if not restored_operator_review:
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

    @writer_sink("gui_tray_state_delete")
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
        self._create_left_sidebar_content(self._large_text_pane(self.left_pane))
        self._create_center_content(self._large_text_pane(self.center_pane))
        self._create_right_sidebar_content(self._large_text_pane(self.right_pane))
        self.root.after(50, self._set_initial_sash_positions)
        self._start_clock()
        self._start_idle_checker()
        self._update_all_summaries()
        self._update_parked_trays_list()
        if self.current_tray.master_label_code:
            self._reconcile_pending_local_member_exchanges()
            self._update_current_item_label()
            self.scanned_listbox.delete(0, tk.END)
            for i, barcode in enumerate(self.current_tray.scanned_barcodes, start=1):
                self.scanned_listbox.insert(0, self._format_scanned_list_row(i, barcode))
            if self.current_tray.scanned_barcodes:
                self.undo_button['state'] = tk.NORMAL
            self._sync_last_normal_scan_from_active_tray()
            self._update_center_display()
            self._start_stopwatch(resume=True)
            self.root.after_idle(self._update_tray_image_display)
        else:
            self._reset_ui_to_waiting_state()
        self.scan_entry.focus()
        self.root.after(100, self._schedule_phs_label_exchange_recovery)

    def _large_text_pane(self, parent, *, force=False):
        # The existing 2x+ tier deliberately keeps enlarged text. Give its
        # overflowing content a viewport instead of reducing that preference.
        if not force and getattr(self, "scale_factor", 1.0) < 2.0:
            return parent
        pane_style = parent.cget('style')
        viewport = ttk.Frame(parent, style=pane_style)
        viewport.pack(fill=tk.BOTH, expand=True)
        background = self.COLOR_SIDEBAR_BG if pane_style == 'Sidebar.TFrame' else self.COLOR_BG
        canvas = tk.Canvas(viewport, highlightthickness=0, background=background)
        scrollbar = ttk.Scrollbar(viewport, orient='vertical', command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        content = ttk.Frame(canvas, style=pane_style)
        content._layout_viewport = canvas
        window = canvas.create_window(0, 0, window=content, anchor='nw')
        pending = None
        pending_focus = None
        event_root = parent.winfo_toplevel()

        def resize():
            nonlocal pending
            pending = None
            width = max(1, canvas.winfo_width())
            height = max(canvas.winfo_height(), content.winfo_reqheight())
            canvas.itemconfigure(window, width=width, height=height)
            canvas.configure(scrollregion=(0, 0, width, height))

        def belongs(widget):
            return widget is canvas or str(widget).startswith(str(content) + '.') or widget is content

        def schedule(event):
            nonlocal pending
            if belongs(event.widget) and pending is None:
                pending = self.root.after_idle(resize)

        def reveal(widget):
            nonlocal pending_focus
            pending_focus = None
            if not belongs(widget) or widget is canvas:
                return
            try:
                top = widget.winfo_rooty() - content.winfo_rooty()
                bottom = top + widget.winfo_height()
            except tk.TclError:
                return  # A focused child can be removed while this pane survives.
            visible_top = canvas.canvasy(0)
            height = canvas.winfo_height()
            if top < visible_top or bottom > visible_top + height:
                target = top if top < visible_top else bottom - height
                canvas.yview_moveto(max(0, target) / max(1, content.winfo_height()))

        def schedule_reveal(event):
            nonlocal pending_focus
            if belongs(event.widget):
                if pending_focus is not None:
                    self.root.after_cancel(pending_focus)
                pending_focus = self.root.after_idle(reveal, event.widget)

        def wheel(event):
            if (not belongs(event.widget) or not event.delta or event.state & 4
                    or event.widget.winfo_class() in {'Listbox', 'TSpinbox'}):
                return
            if event.widget.winfo_class() == 'Treeview':
                if not force:
                    return
                first, last = event.widget.yview()
                if (event.delta > 0 and first > 0) or (event.delta < 0 and last < 1):
                    return
            canvas.yview_scroll(-3 if event.delta > 0 else 3, 'units')
            return 'break'

        def page(event):
            if force and belongs(event.widget):
                canvas.yview_scroll(-1 if event.keysym == 'Prior' else 1, 'pages')
                return 'break'

        bindings = [
            (sequence, event_root.bind(sequence, callback, add='+'))
            for sequence, callback in (
                ('<Configure>', schedule), ('<FocusIn>', schedule_reveal), ('<MouseWheel>', wheel),
                ('<Prior>', page), ('<Next>', page),
            )
        ]

        def dispose(event):
            if event.widget is content:
                if pending is not None:
                    self.root.after_cancel(pending)
                if pending_focus is not None:
                    self.root.after_cancel(pending_focus)
                for sequence, binding in bindings:
                    event_root.unbind(sequence, binding)

        content.bind('<Destroy>', dispose, add='+')
        content._reveal_widget = reveal
        pending = self.root.after_idle(resize)
        return content

    @staticmethod
    def _pane_viewport_height(frame):
        return getattr(frame, '_layout_viewport', frame).winfo_height()

    def _get_pane_layout_metrics(self, total_width: int) -> Dict[str, int]:
        total_height = 768
        for widget in (getattr(self, "paned_window", None), getattr(self, "root", None)):
            try:
                candidate = int(widget.winfo_height())
            except (AttributeError, TypeError, ValueError, tk.TclError):
                continue
            if candidate > 1:
                total_height = candidate
                break
        metrics = calculate_pane_layout_metrics(
            total_width,
            total_height,
            getattr(self, "scale_factor", 1.0),
        )
        return {
            "profile": metrics.profile,
            "left_width": metrics.left_width,
            "center_width": metrics.center_width,
            "right_width": metrics.right_width,
            "left_min": metrics.left_min,
            "center_min": metrics.center_min,
            "right_min": metrics.right_min,
            "compressed": metrics.compressed,
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
            self._paned_layout_signature = (
                total_width,
                metrics["profile"],
                sash_0_pos,
                sash_1_pos,
            )
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
            desired_sash_0 = metrics["left_width"]
            desired_sash_1 = metrics["left_width"] + metrics["center_width"]
            layout_signature = (
                total_width,
                metrics["profile"],
                desired_sash_0,
                desired_sash_1,
            )
            layout_changed = layout_signature != getattr(self, "_paned_layout_signature", None)
            if metrics["compressed"] or layout_changed:
                # Reapply the pure profile widths whenever the actual content
                # size/scale changes. This makes compact -> wide -> compact
                # deterministic and keeps the calculated center allocation in
                # compressed large-text layouts instead of replacing it with
                # the legacy 28/72 percentages.
                sash_0_pos = desired_sash_0
                sash_1_pos = desired_sash_1
            else:
                sash_0_pos = self.paned_window.sashpos(0)
                sash_1_pos = self.paned_window.sashpos(1)
                max_sash_0 = max(1, total_width - right_min - center_min)
                sash_0_pos = max(left_min, min(sash_0_pos, max_sash_0))
                min_sash_1 = sash_0_pos + center_min
                max_sash_1 = max(min_sash_1 + 1, total_width - right_min)
                sash_1_pos = max(min_sash_1, min(sash_1_pos, max_sash_1))
            self._paned_layout_signature = layout_signature
            if self.paned_window.sashpos(0) != sash_0_pos:
                self.paned_window.sashpos(0, sash_0_pos)
            if self.paned_window.sashpos(1) != sash_1_pos:
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

    def _schedule_notice_message_wrap_refresh(self, event=None, *, generation=None) -> None:
        current_generation = getattr(self, "_center_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        label = getattr(self, "notice_message_label", None)
        if label is None:
            return
        event_widget = getattr(event, "widget", None)
        if event_widget is not None and event_widget is not label:
            return
        if getattr(self, "_notice_message_wrap_job", None):
            return
        root = getattr(self, "root", None)
        if root is None:
            self._apply_notice_message_wraplength(current_generation)
            return
        try:
            self._notice_message_wrap_job = root.after_idle(
                self._apply_notice_message_wraplength,
                current_generation,
            )
        except AttributeError:
            try:
                self._notice_message_wrap_job = root.after(
                    0,
                    self._apply_notice_message_wraplength,
                    current_generation,
                )
            except AttributeError:
                self._apply_notice_message_wraplength(current_generation)
        except tk.TclError:
            return

    def _apply_notice_message_wraplength(self, generation=None) -> None:
        self._notice_message_wrap_job = None
        current_generation = getattr(self, "_center_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        generation = current_generation
        label = getattr(self, "notice_message_label", None)
        if label is None:
            return
        try:
            if hasattr(label, "winfo_exists") and not label.winfo_exists():
                return
            label_width = int(label.winfo_width())
        except (AttributeError, TypeError, ValueError, tk.TclError):
            return
        if label_width <= 1:
            return
        # The label's own allocation is the only reliable width after the
        # title and acknowledgement columns take their state-dependent space.
        # Keep a border/glyph gutter so requested width never exceeds the live
        # column viewport.  Tk's requested label width can be a few pixels
        # wider than wraplength across Windows DPI/font-rendering variants, so
        # four pixels was not sufficient on the GitHub Windows runner.
        wraplength = max(80, label_width - 8)
        metrics_key = (generation, label_width, wraplength)
        if metrics_key == getattr(self, "_notice_message_wrap_metrics", None):
            return
        try:
            label.configure(wraplength=wraplength)
            self._notice_message_wrap_metrics = metrics_key
        except (AttributeError, tk.TclError):
            return

    @staticmethod
    def _clamped_int(value: float, minimum: int, maximum: int) -> int:
        return max(minimum, min(maximum, int(round(value))))

    def _center_vertical_scale(self, center_height: int) -> float:
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        if scale >= 1.2 and center_height / scale < 620:
            return min(scale, 1.2)
        return scale

    def _get_scanned_listbox_metrics(
        self,
        center_width: int,
        center_height: int,
        list_height: int = 0,
    ) -> Dict[str, int]:
        metrics = calculate_scanned_list_metrics(
            center_width,
            center_height,
            list_height,
            getattr(self, "scale_factor", 1.0),
        )
        return {
            "font_size": metrics.font_size,
            "header_font_size": metrics.header_font_size,
            "horizontal_pad": metrics.horizontal_pad,
            "top_pady": metrics.top_pady,
            "header_bottom_pady": metrics.header_bottom_pady,
            "visible_rows": metrics.visible_rows,
        }

    def _schedule_scanned_listbox_layout_refresh(self, event=None, *, generation=None) -> None:
        current_generation = getattr(self, "_center_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        if getattr(self, "_scanned_listbox_layout_job", None):
            return
        root = getattr(self, "root", None)
        if root is None:
            self._apply_scanned_listbox_layout()
            return
        try:
            self._scanned_listbox_layout_job = root.after_idle(
                self._apply_scanned_listbox_layout,
                current_generation,
            )
        except AttributeError:
            try:
                self._scanned_listbox_layout_job = root.after(
                    0,
                    self._apply_scanned_listbox_layout,
                    current_generation,
                )
            except AttributeError:
                self._apply_scanned_listbox_layout(current_generation)
        except tk.TclError:
            return

    def _apply_scanned_listbox_layout(self, generation=None) -> None:
        self._scanned_listbox_layout_job = None
        current_generation = getattr(self, "_center_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        generation = current_generation
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
            center_height = self._pane_viewport_height(parent_frame)
            list_height = listbox.winfo_height()
        except (tk.TclError, AttributeError, TypeError):
            return
        if center_width <= 1 or center_height <= 1:
            return

        self._apply_center_layout(
            parent_frame,
            center_width,
            center_height,
            generation=generation,
        )
        metrics = self._get_scanned_listbox_metrics(center_width, center_height, list_height)
        metrics_key = (
            generation,
            metrics["font_size"],
            metrics["header_font_size"],
            metrics["horizontal_pad"],
            metrics["top_pady"],
            metrics["header_bottom_pady"],
            metrics["visible_rows"],
        )
        if metrics_key == getattr(self, "_scanned_listbox_layout_metrics", None):
            return

        try:
            listbox.configure(
                font=(self.DEFAULT_FONT, metrics["font_size"]),
                height=metrics["visible_rows"],
                justify='center',
            )
            listbox.grid_configure(
                padx=metrics["horizontal_pad"],
                pady=(0, 0),
            )
            header = getattr(self, "scanned_list_header_label", None)
            if header is not None:
                header.configure(
                    font=(self.DEFAULT_FONT, metrics["header_font_size"], 'bold')
                )
                header.grid_configure(
                    padx=metrics["horizontal_pad"],
                    pady=(metrics["top_pady"], metrics["header_bottom_pady"]),
                )
            scrollbar = getattr(self, "scanned_list_scrollbar", None)
            if scrollbar is not None:
                scrollbar.grid_configure(padx=(0, metrics["horizontal_pad"]))
            self._scanned_listbox_layout_metrics = metrics_key
        except (tk.TclError, AttributeError):
            return

    def _format_scanned_list_row(self, position: int, raw_barcode: str) -> str:
        """Return a compact display row while retaining the raw tray value."""

        tray = getattr(self, "current_tray", None)
        item_code = getattr(tray, "item_code", "") if tray is not None else ""
        return format_scan_list_row(position, raw_barcode, item_code=item_code)

    def _format_last_normal_scan_value(self, raw_barcode: str) -> str:
        """Compact the visible value while the presenter retains its raw scan."""

        if not raw_barcode:
            return "-"
        tray = getattr(self, "current_tray", None)
        active_item_code = getattr(tray, "item_code", "") if tray is not None else ""
        item_code = active_item_code or getattr(self, "_last_normal_scan_display_item_code", "")
        return compact_scan_value(raw_barcode, item_code=item_code)

    def _get_center_layout_metrics(self, center_width: int, center_height: int) -> Dict[str, int]:
        metrics = calculate_center_layout_metrics(
            center_width,
            center_height,
            getattr(self, "scale_factor", 1.0),
        )
        return {
            "profile": metrics.profile,
            "horizontal_pad": metrics.horizontal_pad,
            "item_top": metrics.item_top,
            "item_bottom": metrics.item_bottom,
            "count_top": metrics.count_top,
            "count_bottom": metrics.count_bottom,
            "progress_bottom": metrics.progress_bottom,
            "entry_ipady": metrics.entry_ipady,
            "warning_band_height": metrics.warning_band_height,
            "button_top": metrics.button_top,
            "button_pad_x": metrics.button_pad_x,
            "list_minsize": metrics.list_minsize,
            "entry_font": metrics.entry_font,
            "count_font": metrics.count_font,
            "notice_title_font": metrics.notice_title_font,
            "notice_message_font": metrics.notice_message_font,
            "action_columns": metrics.action_columns,
        }

    def _apply_center_layout(
        self,
        parent_frame=None,
        center_width: int = 0,
        center_height: int = 0,
        *,
        generation=None,
    ) -> None:
        parent_frame = parent_frame or getattr(self, "_center_content_frame", None)
        if parent_frame is None:
            return
        current_generation = getattr(self, "_center_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        generation = current_generation
        try:
            center_width = center_width or parent_frame.winfo_width()
            center_height = center_height or self._pane_viewport_height(parent_frame)
        except (tk.TclError, AttributeError):
            return
        if center_width <= 1 or center_height <= 1:
            return
        metrics = self._get_center_layout_metrics(center_width, center_height)
        self._layout_center_action_buttons(center_width, metrics["button_pad_x"])
        # Action wording changes at 960 px even when all geometry metrics stay
        # identical.  Include that derived state so a slow sash drag cannot
        # leave compact/full labels cached on the wrong side of the boundary.
        compact_action_labels = 1 < int(center_width) < 960
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        compact_notice_message = scale >= 1.2 and center_height / scale < 620
        metrics_key = (
            generation,
            compact_action_labels,
            compact_notice_message,
            *metrics.values(),
        )
        if metrics_key == getattr(self, "_center_layout_metrics", None):
            return
        try:
            parent_frame.grid_rowconfigure(4, weight=0, minsize=metrics["warning_band_height"])
            parent_frame.grid_rowconfigure(5, weight=3, minsize=metrics["list_minsize"])
            hero_frame = getattr(self, "_center_hero_frame", None)
            if hero_frame is not None:
                hero_frame.grid_configure(pady=(metrics["item_top"], metrics["item_bottom"]))
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
            if hasattr(self, "notice_frame"):
                self.notice_frame.grid_configure(padx=metrics["horizontal_pad"])
            if hasattr(self, "notice_title_label"):
                self.notice_title_label.configure(
                    font=(self.DEFAULT_FONT, metrics["notice_title_font"], 'bold')
                )
            if hasattr(self, "notice_message_label"):
                self.notice_message_label.configure(
                    font=(self.DEFAULT_FONT, metrics["notice_message_font"])
                )
                self.notice_message_label.grid_configure(
                    padx=4 if compact_notice_message else 8
                )
            button_frame = getattr(self, "_center_button_frame", None)
            if button_frame is not None:
                button_frame.grid_configure(pady=(metrics["button_top"], 0))
            self._center_layout_metrics = metrics_key
            self._apply_notice_visibility()
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
            center_frame = getattr(self, "_center_content_frame", None)
            center_height = self._pane_viewport_height(center_frame) if center_frame is not None else 1080
            vertical_scale = self._center_vertical_scale(center_height)
            self._refresh_action_button_labels(center_width)
            required_width = max(button.winfo_reqwidth() for button in buttons) + 2 * pad_x
            columns = max(1, min(len(buttons), (int(center_width) - 40) // max(1, required_width)))
            signature = (tuple(buttons), columns, pad_x, vertical_scale)
            if signature == getattr(self, '_center_action_layout_signature', None):
                return
            for index, button in enumerate(buttons):
                button.grid_forget()
                button.grid(
                    row=index // columns,
                    column=index % columns,
                    sticky='ew',
                    padx=pad_x,
                    pady=(0, max(4, int(6 * vertical_scale))),
                )
            for column in range(len(buttons)):
                button_frame.grid_columnconfigure(
                    column,
                    weight=1 if column < columns else 0,
                    uniform="center_actions" if column < columns else "",
                )
            self._center_action_layout_signature = signature
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

    def _use_compact_action_labels(self) -> bool:
        frame = getattr(self, "_center_content_frame", None)
        if frame is None:
            return False
        try:
            width = int(frame.winfo_width())
        except (tk.TclError, AttributeError, TypeError, ValueError):
            return False
        return 1 < width < 960

    def _action_button_labels(
        self,
        *,
        compact: bool,
        operator_review: bool,
        precommand_retry: bool = False,
    ) -> Dict[str, str]:
        if compact:
            return {
                "undo": "스캔 취소",
                "park": "보류",
                "submit": (
                    "재시도"
                    if precommand_retry
                    else "확인"
                    if operator_review
                    else "제출"
                ),
                "operations": "운영 작업",
            }
        return {
            "undo": "스캔 취소",
            "park": "트레이 보류",
            "submit": (
                "사전검증 재시도"
                if precommand_retry
                else "담당 확인"
                if operator_review
                else "트레이 제출"
            ),
            "operations": "운영 작업 ▾",
        }

    def _refresh_action_button_labels(self, center_width: int) -> None:
        completion = self._warning_state_presenter().state.completion
        operator_review = bool(
            completion is not None and completion.outcome is CompletionOutcome.OPERATOR_REVIEW
        )
        precommand_retry = (
            self._precommand_operator_review_retry_context() is not None
        )
        labels = self._action_button_labels(
            compact=1 < int(center_width or 0) < 960,
            operator_review=operator_review,
            precommand_retry=precommand_retry,
        )
        for key, widget_name in (
            ("undo", "undo_button"),
            ("park", "park_button"),
            ("submit", "submit_tray_button"),
            ("operations", "operations_button"),
        ):
            self._configure_widget_options(getattr(self, widget_name, None), text=labels[key])

    def _update_action_button_states(self) -> None:
        active_tray = bool(getattr(getattr(self, "current_tray", None), "master_label_code", ""))
        scanned_count = len(getattr(getattr(self, "current_tray", None), "scanned_barcodes", []) or [])
        blocking_completion = self._active_blocking_completion_snapshot()
        operator_review = blocking_completion is not None
        retryable_completion = bool(
            blocking_completion is not None
            and blocking_completion.operator_retryable
        )
        precommand_retry = (
            self._precommand_operator_review_retry_context() is not None
        )
        lane = getattr(self, "_ui_lane", None)
        transfer_lane_busy = bool(lane is not None and lane.is_busy())
        # Preserve the conservative exact-mode latch independently of menu widgets.
        self._exact_transfer_exchange_blocked()
        phs_transition_blocked = self._phs_label_exchange_transition_pending()
        compact_labels = self._use_compact_action_labels()
        labels = self._action_button_labels(
            compact=compact_labels,
            operator_review=operator_review,
            precommand_retry=precommand_retry,
        )
        if retryable_completion:
            if blocking_completion.outcome is CompletionOutcome.LOCAL_EVENT_RETRY:
                labels["submit"] = "완료 기록 재시도" if not compact_labels else "기록 재시도"
            else:
                labels["submit"] = "서버 재확인" if not compact_labels else "재확인"

        if bool(getattr(self, "_completion_lane_busy", False)):
            labels["submit"] = "완료 처리 중"
            for key, widget_name in (
                ("undo", "undo_button"),
                ("park", "park_button"),
                ("submit", "submit_tray_button"),
                ("operations", "operations_button"),
            ):
                self._configure_widget_options(
                    getattr(self, widget_name, None),
                    text=labels[key],
                    state=tk.DISABLED,
                )
            for widget_name in (
                "change_worker_button",
                "phs_label_exchange_button",
                "phs_label_legacy_fallback_button",
                "phs_label_candidate_load_button",
            ):
                self._configure_widget_options(
                    getattr(self, widget_name, None),
                    state=tk.DISABLED,
                )
            return

        preflight_context_locked = self._preflight_context_blocks_mutation()
        mutation_state = (
            tk.DISABLED
            if operator_review or phs_transition_blocked or preflight_context_locked
            else tk.NORMAL
        )
        self._configure_widget_options(
            getattr(self, "park_button", None),
            text=labels["park"],
            state=mutation_state if active_tray else tk.DISABLED,
        )
        self._configure_widget_options(
            getattr(self, "undo_button", None),
            text=labels["undo"],
            state=mutation_state if scanned_count else tk.DISABLED,
        )
        self._configure_widget_options(
            getattr(self, "submit_tray_button", None),
            state=(
                tk.NORMAL
                if active_tray
                and scanned_count
                and not phs_transition_blocked
                and not preflight_context_locked
                and (not operator_review or retryable_completion or precommand_retry)
                else tk.DISABLED
            ),
            text=labels["submit"],
            style='Review.TButton' if operator_review else 'Success.TButton',
            command=(
                self._retry_precommand_operator_review_completion
                if precommand_retry
                else self.submit_current_tray
            ),
        )
        self._configure_widget_options(
            getattr(self, "operations_button", None),
            text=labels["operations"],
            state=(
                tk.DISABLED
                if operator_review
                or phs_transition_blocked
                or preflight_context_locked
                or transfer_lane_busy
                else tk.NORMAL
            ),
        )
        self._configure_widget_options(
            getattr(self, "change_worker_button", None),
            state=(
                tk.DISABLED
                if operator_review or phs_transition_blocked or preflight_context_locked
                else tk.NORMAL
            ),
        )

        single_available = self._phs_label_exchange_available_for_tray()
        reconciliation_available = (
            self._phs_reconciliation_exchange_available()
        )
        phs_available = single_available or reconciliation_available
        phs_busy = bool(
            getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_reconciliation_resolve_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        )
        self._configure_widget_options(
            getattr(self, "phs_label_exchange_button", None),
            text="현품표 교체",
            state=(
                tk.NORMAL
                if phs_available
                and not operator_review
                and not preflight_context_locked
                and not phs_busy
                else tk.DISABLED
            ),
        )
        self._configure_widget_options(
            getattr(self, "phs_label_legacy_fallback_button", None),
            state=(
                tk.NORMAL
                if single_available
                and reconciliation_available
                and not operator_review
                and not preflight_context_locked
                and not phs_busy
                and not phs_transition_blocked
                else tk.DISABLED
            ),
        )
        self._configure_widget_options(
            getattr(self, "phs_label_candidate_load_button", None),
            state=(
                tk.NORMAL
                if phs_available
                and not operator_review
                and not preflight_context_locked
                and not phs_busy
                else tk.DISABLED
            ),
        )
        candidate_selected = bool(
            str(
                getattr(
                    getattr(self, "phs_label_candidate_var", None),
                    "get",
                    lambda: "",
                )()
                or ""
            ).strip()
        )
        recovery_pending = False
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        if phs_available and coordinator is not None:
            try:
                recovery = coordinator.journal.load()
                recovery_pending = bool(
                    recovery
                    and str(recovery.get("status") or "").strip().upper()
                    not in {"COMMITTED", "CANCELLED"}
                    and (
                        str(recovery.get("workflow_kind") or "")
                        == "RECONCILIATION"
                        or (
                            single_available
                            and str(
                                recovery.get("canonical_input_tag_qr") or ""
                            ).strip()
                            == str(
                                getattr(
                                    self.current_tray,
                                    "master_label_code",
                                    "",
                                )
                                or ""
                            ).strip()
                        )
                    )
                )
            except Exception:
                recovery_pending = True
        self._phs_label_exchange_recovery_visible = recovery_pending
        self._configure_widget_options(
            getattr(self, "phs_label_exchange_execute_button", None),
            state=(
                tk.NORMAL
                if phs_available
                and not operator_review
                and not preflight_context_locked
                and not phs_busy
                and (
                    candidate_selected
                    or recovery_pending
                    or bool(
                        getattr(
                            self,
                            "_phs_reconciliation_context",
                            None,
                        )
                    )
                )
                else tk.DISABLED
            ),
        )
        self._refresh_phs_active_label_info()
        self._apply_notice_visibility()

    def _phs_reconciliation_exchange_available(self) -> bool:
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        reconciliation = getattr(coordinator, "reconciliation", None)
        return bool(
            reconciliation is not None and reconciliation.available
        )

    @staticmethod
    def _phs_replacement_notice_pair(
        context: Optional[Mapping[str, Any]],
    ) -> Optional[tuple[str, str]]:
        scan = (
            context.get("scan")
            if isinstance(context, Mapping)
            and isinstance(context.get("scan"), Mapping)
            else {}
        )
        if scan.get("replacement_required") is not True:
            return None
        old_label_id = str(scan.get("scanned_label_id") or "").strip()
        new_label_id = str(scan.get("active_label_id") or "").strip()
        if not old_label_id or not new_label_id or old_label_id == new_label_id:
            return None
        return old_label_id, new_label_id

    def _phs_replacement_waiting_session_id(
        self,
        context: Optional[Mapping[str, Any]],
    ) -> str:
        scan = (
            context.get("scan")
            if isinstance(context, Mapping)
            and isinstance(context.get("scan"), Mapping)
            else {}
        )
        tray = getattr(self, "current_tray", None)
        payloads = (
            scan.get("active_qr_payload"),
            context.get("_scanned_payload")
            if isinstance(context, Mapping)
            else None,
            getattr(tray, "active_label_qr_payload", ""),
            getattr(tray, "canonical_input_tag_qr", ""),
            getattr(tray, "master_label_code", ""),
        )
        for payload in payloads:
            parsed = self._parse_new_format_qr(str(payload or "")) or {}
            try:
                fields = validate_compact_phs2_fields(parsed)
            except TransferSealError:
                continue
            session_id = str(fields["ITG"]).strip()
            if session_id:
                return session_id
        return ""

    @staticmethod
    def _phs_replacement_waiting_locations(
        context: Optional[Mapping[str, Any]],
    ) -> list[str]:
        locations: set[str] = set()
        if isinstance(context, Mapping):
            scan = (
                context.get("scan")
                if isinstance(context.get("scan"), Mapping)
                else {}
            )
            for value in (
                context.get("location_code"),
                context.get("current_location"),
                scan.get("location_code"),
                scan.get("current_location"),
            ):
                normalized = str(value or "").strip()
                if normalized:
                    locations.add(normalized)
            for action in list(context.get("actions") or []):
                if not isinstance(action, Mapping):
                    continue
                for member in list(action.get("process_membership") or []):
                    if not isinstance(member, Mapping):
                        continue
                    normalized = str(
                        member.get("location_code") or ""
                    ).strip()
                    if normalized:
                        locations.add(normalized)
        return sorted(locations or {"PHS_GOOD"})

    def _mark_phs_replacement_waiting(
        self,
        context: Optional[Mapping[str, Any]],
        pair: tuple[str, str],
        *,
        master_label: str = "",
        operator: Optional[str] = None,
        projection_log_file_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        session_id = self._phs_replacement_waiting_session_id(context)
        if not session_id:
            raise ValueError("PHS replacement waiting session is unavailable")
        process_context = (
            str(context.get("process_context") or "transfer").strip()
            if isinstance(context, Mapping)
            else "transfer"
        )
        tray = getattr(self, "current_tray", None)
        normalized_projection_path = str(
            projection_log_file_path
            if projection_log_file_path is not None
            else getattr(self, "log_file_path", "")
            or ""
        ).strip()
        if not normalized_projection_path:
            raise OSError("replacement waiting event log is unavailable")
        row = self._transfer_seal_runtime().store.mark_phs_replacement_waiting(
            session_id=session_id,
            old_label_id=pair[0],
            new_label_id=pair[1],
            process_context=process_context,
            location_codes=self._phs_replacement_waiting_locations(context),
            operator=persistent_operator_name(
                operator
                if operator is not None
                else getattr(self, "worker_name", "")
            ),
            master_label=str(
                master_label
                or getattr(tray, "master_label_code", "")
                or ""
            ),
            projection_log_file_path=normalized_projection_path,
        )
        result = dict(row)
        self._project_phs_replacement_waiting_row(result)
        return result

    def _project_phs_replacement_waiting_row(
        self,
        row: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Idempotently project one SQLite marker to its append-only CSV log."""

        result = dict(row)
        try:
            event_detail = json.loads(
                str(
                    result.get("outbox_payload_json")
                    or result.get("evidence_json")
                    or ""
                )
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                "durable replacement waiting evidence is invalid"
            ) from exc
        if not isinstance(event_detail, dict):
            raise ValueError("durable replacement waiting evidence is invalid")
        event_type = str(event_detail.get("event_type") or "").strip()
        idempotency_key = str(
            event_detail.get("idempotency_key") or ""
        ).strip()
        projection_log_file_path = str(
            result.get("projection_log_file_path") or ""
        ).strip()
        if (
            event_type != "PHS_REPLACEMENT_WAITING_MARKED"
            or not idempotency_key
            or not projection_log_file_path
        ):
            raise ValueError("durable replacement waiting projection is incomplete")
        enriched_detail = self._plan_b_event_detail(event_type, event_detail)
        log_entry = {
            "timestamp": str(
                event_detail.get("observed_at")
                or datetime.datetime.now().isoformat()
            ),
            "worker_name": persistent_operator_name(
                event_detail.get("operator")
                or getattr(self, "worker_name", "")
                or ""
            ),
            "event": event_type,
            "details": json.dumps(
                sanitize_persistent_value(enriched_detail),
                ensure_ascii=False,
                allow_nan=False,
            ),
        }
        append_event_log_entry_idempotent(
            projection_log_file_path,
            log_entry,
            event_type=event_type,
            idempotency_key=idempotency_key,
            durable=True,
        )
        store = self._transfer_seal_runtime().store
        receipt = store.record_replacement_waiting_projection(
            str(result.get("intent_id") or ""),
            projection_log_file_path=projection_log_file_path,
        )
        self._trigger_session_direct_sync(event_type)
        result["projection_id"] = str(receipt["projection_id"])
        return result

    def _drain_phs_replacement_waiting_projections(self) -> int:
        store = self._transfer_seal_runtime().store
        pending = store.pending_replacement_waiting_projections()
        for row in pending:
            self._project_phs_replacement_waiting_row(dict(row))
        return len(pending)

    def _work_phs_replacement_waiting_marker(
        self,
        context: Optional[Mapping[str, Any]],
        *,
        master_label: str = "",
        operator: str = "",
        projection_log_file_path: str = "",
    ) -> Dict[str, Any]:
        """Persist one marker on the shared lane without touching Tk state."""

        pair = self._phs_replacement_notice_pair(context)
        if pair is None:
            return {
                "ready": True,
                "notice_key": None,
                "context": dict(context) if isinstance(context, Mapping) else None,
            }
        session_id = self._phs_replacement_waiting_session_id(context)
        notice_key = (session_id, pair[0], pair[1])
        try:
            self._mark_phs_replacement_waiting(
                context,
                pair,
                master_label=master_label,
                operator=operator,
                projection_log_file_path=projection_log_file_path,
            )
        except Exception as exc:
            return {
                "ready": False,
                "notice_key": notice_key,
                "context": dict(context) if isinstance(context, Mapping) else None,
                "pair": pair,
                "error": exc,
            }
        return {
            "ready": True,
            "notice_key": notice_key,
            "context": dict(context) if isinstance(context, Mapping) else None,
        }

    def _finish_phs_replacement_waiting_marker(
        self,
        outcome: Optional[Mapping[str, Any]],
    ) -> tuple[bool, bool]:
        """Publish a lane marker result and show any Tk-only failure notice."""

        if not isinstance(outcome, Mapping):
            return False, False
        if not bool(outcome.get("ready")):
            pair = outcome.get("pair")
            error = outcome.get("error")
            if (
                isinstance(pair, tuple)
                and len(pair) == 2
                and isinstance(error, Exception)
            ):
                self._log_phs_replacement_waiting_failure(
                    context=(
                        outcome.get("context")
                        if isinstance(outcome.get("context"), Mapping)
                        else None
                    ),
                    pair=(str(pair[0]), str(pair[1])),
                    error=error,
                )
            self._show_phs_replacement_waiting_storage_block()
            return False, False
        notice_key = outcome.get("notice_key")
        if notice_key is None:
            return True, False
        if not isinstance(notice_key, tuple) or len(notice_key) != 3:
            return False, False
        seen = getattr(self, "_phs_replacement_notice_pairs", None)
        if not isinstance(seen, set):
            seen = set()
            self._phs_replacement_notice_pairs = seen
        newly_marked = notice_key not in seen
        seen.add(notice_key)
        return True, newly_marked

    def _show_phs_replacement_waiting_storage_block(self) -> None:
        self.show_fullscreen_warning(
            "현품표 교체 대기 저장 실패",
            "현품표 교체 대기 기록을 안전하게 저장하지 못했습니다. "
            "현재 현품표 상태를 변경하지 않았습니다. 작업을 계속하지 말고 "
            "저장 장치 상태를 확인한 뒤 다시 시도하세요.",
            self.COLOR_DANGER,
        )

    def _ensure_phs_replacement_waiting_marked(
        self,
        context: Optional[Mapping[str, Any]],
        *,
        master_label: str = "",
    ) -> tuple[bool, bool]:
        """Return ``(ready, newly_marked)`` without mutating workflow state."""

        pair = self._phs_replacement_notice_pair(context)
        if pair is not None:
            notice_key = (
                self._phs_replacement_waiting_session_id(context),
                pair[0],
                pair[1],
            )
            seen = getattr(self, "_phs_replacement_notice_pairs", None)
            if isinstance(seen, set) and notice_key in seen:
                return True, False
        outcome = self._work_phs_replacement_waiting_marker(
            context,
            master_label=master_label,
            operator=str(getattr(self, "worker_name", "") or ""),
            projection_log_file_path=str(
                getattr(self, "log_file_path", "") or ""
            ),
        )
        return self._finish_phs_replacement_waiting_marker(outcome)

    def _show_phs_replacement_required_notice(self) -> None:
        self.show_status_message(
            PHS_REPLACEMENT_REQUIRED_NOTICE,
            self.COLOR_IDLE,
            duration=10000,
        )

    def _log_phs_replacement_waiting_failure(
        self,
        *,
        context: Optional[Mapping[str, Any]],
        pair: tuple[str, str],
        error: Exception,
    ) -> None:
        session_id = self._phs_replacement_waiting_session_id(context)
        detail = {
            "contract_version": (
                "container-audit-phs-replacement-waiting-v1"
            ),
            "event_type": "PHS_REPLACEMENT_WAITING_MARK_FAILED",
            "session_id": session_id or None,
            "old_label_hash": hashlib.sha256(
                pair[0].encode("utf-8")
            ).hexdigest(),
            "new_label_hash": hashlib.sha256(
                pair[1].encode("utf-8")
            ).hexdigest(),
            "process_context": (
                str(context.get("process_context") or "transfer").strip()
                if isinstance(context, Mapping)
                else "transfer"
            ),
            "location_codes": self._phs_replacement_waiting_locations(
                context
            ),
            "exception_type": error.__class__.__name__,
        }
        logger = getattr(self, "_log_event", None)
        logged = False
        if callable(logger):
            try:
                logged = bool(
                    logger(
                        "PHS_REPLACEMENT_WAITING_MARK_FAILED",
                        detail=detail,
                        synchronous=True,
                    )
                )
            except Exception:
                logged = False
        if not logged:
            print(
                "PHS replacement waiting evidence write failed: "
                f"{error.__class__.__name__}"
            )

    def _show_phs_replacement_required_notice_once(
        self,
        context: Optional[Mapping[str, Any]],
    ) -> bool:
        ready, newly_marked = self._ensure_phs_replacement_waiting_marked(
            context
        )
        if not ready or not newly_marked:
            return False
        self._show_phs_replacement_required_notice()
        return True

    def _capture_phs_reconciliation_progress(self) -> Dict[str, Any]:
        tray = self.current_tray
        scans_object = getattr(tray, "scanned_barcodes", None)
        return {
            "tray": tray,
            "master_label_code": str(
                getattr(tray, "master_label_code", "") or ""
            ),
            "scans_object": scans_object,
            "scans": (
                tuple(scans_object)
                if isinstance(scans_object, list)
                else None
            ),
            "tray_size": int(getattr(tray, "tray_size", 0) or 0),
            "resolve_pending": bool(
                getattr(self, "_phs_reconciliation_resolve_pending", False)
            ),
            "refresh_pending": bool(
                getattr(self, "_phs_label_refresh_pending", False)
            ),
            "preflight_pending": bool(
                getattr(self, "_master_preflight_pending", False)
            ),
            "hold_pending": bool(self._preflight_context_blocks_mutation()),
        }

    def _phs_reconciliation_progress_unchanged(
        self,
        captured: Optional[Mapping[str, Any]],
    ) -> bool:
        if not isinstance(captured, Mapping):
            return False
        current = self.current_tray
        scans_before = captured.get("scans")
        return bool(
            current is captured.get("tray")
            and str(getattr(current, "master_label_code", "") or "")
            == str(captured.get("master_label_code") or "")
            and getattr(current, "scanned_barcodes", None)
            is captured.get("scans_object")
            and int(getattr(current, "tray_size", 0) or 0)
            == int(captured.get("tray_size") or 0)
            and bool(
                getattr(self, "_phs_reconciliation_resolve_pending", False)
            )
            == bool(captured.get("resolve_pending"))
            and bool(getattr(self, "_phs_label_refresh_pending", False))
            == bool(captured.get("refresh_pending"))
            and bool(getattr(self, "_master_preflight_pending", False))
            == bool(captured.get("preflight_pending"))
            and bool(self._preflight_context_blocks_mutation())
            == bool(captured.get("hold_pending"))
            and (
                scans_before is None
                or tuple(getattr(current, "scanned_barcodes", []))
                == tuple(scans_before)
            )
        )

    def _apply_phs_label_exchange_snapshot(
        self,
        *,
        captured_tray: TraySession,
        captured_master_label: str,
        updated_tray: TraySession,
        force_persist: bool,
    ) -> bool:
        current = getattr(self, "current_tray", None)
        if (
            current is not captured_tray
            or str(getattr(current, "master_label_code", "") or "")
            != captured_master_label
        ):
            return False
        field_names = (
            "canonical_input_tag_qr",
            "active_label_qr_payload",
            "active_label_id",
            "active_label_business_date",
            "active_label_worker_code",
        )
        before = {
            field_name: getattr(current, field_name, "")
            for field_name in field_names
        }
        after = {
            field_name: getattr(updated_tray, field_name, "")
            for field_name in field_names
        }
        changed = before != after
        if changed:
            for field_name, value in after.items():
                setattr(current, field_name, value)
        if not changed and not force_persist:
            return True
        try:
            persisted = bool(self._save_current_tray_state())
        except Exception as exc:
            print(
                "현품표 교체 current state 저장 실패: "
                f"{exc.__class__.__name__}"
            )
            persisted = False
        if persisted:
            return True
        for field_name, value in before.items():
            setattr(current, field_name, value)
        return False

    def _phs_label_exchange_available_for_tray(self) -> bool:
        tray = getattr(self, "current_tray", None)
        if tray is None or not getattr(tray, "master_label_code", ""):
            return False
        fields = self._parse_new_format_qr(
            str(
                getattr(tray, "active_label_qr_payload", "")
                or tray.master_label_code
            )
        )
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        return bool(
            isinstance(fields, dict)
            and str(fields.get("PHS") or "").strip() == "2"
            and str(fields.get("ITG") or "").strip()
            and str(fields.get("LBL") or "").strip()
            and str(fields.get("HSH") or "").strip()
            and coordinator is not None
            and coordinator.available
        )

    def _phs_label_exchange_transition_pending(self) -> bool:
        if (
            getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_reconciliation_resolve_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        ):
            return True
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        if coordinator is None:
            return False
        try:
            recovery = coordinator.journal.load()
        except Exception:
            return True
        if (
            recovery
            and str(recovery.get("status") or "").strip().upper()
            not in {"COMMITTED", "CANCELLED"}
            and str(recovery.get("workflow_kind") or "")
            == "RECONCILIATION"
        ):
            return True
        tray = getattr(self, "current_tray", None)
        if tray is None or not getattr(tray, "master_label_code", ""):
            return False
        return bool(
            recovery
            and str(recovery.get("status") or "").strip().upper()
            not in {"COMMITTED", "CANCELLED"}
            and str(recovery.get("canonical_input_tag_qr") or "").strip()
            == str(tray.master_label_code or "").strip()
        )

    def _phs_label_exchange_blocks_tray_transition(self, action: str) -> bool:
        if not self._phs_label_exchange_transition_pending():
            return False
        self.show_status_message(
            "현품표 날짜 교환의 중앙 ACK/출력/활성화 복구가 끝날 때까지 "
            f"{action} 작업을 진행할 수 없습니다.",
            self.COLOR_DANGER,
            duration=8000,
        )
        self._schedule_focus_return()
        return True

    def _refresh_phs_active_label_info(self) -> None:
        label = getattr(self, "phs_active_label_info_label", None)
        if label is None:
            return
        tray = getattr(self, "current_tray", None)
        reconciliation = getattr(
            self, "_phs_reconciliation_context", None
        )
        if getattr(self, "_phs_label_exchange_recovery_visible", False):
            text = "미완료 현품표 교체 · F8로 복구"
        elif isinstance(reconciliation, Mapping):
            summaries = (
                self.phs_label_exchange_coordinator.reconciliation
                .target_summaries(reconciliation)
            )
            text = (
                f"서버 교체 지시 · {len(summaries)}장 · "
                + " / ".join(summaries[:3])
                + " · F8 실행"
            )
        elif (
            self._phs_reconciliation_exchange_available()
            and not getattr(
                self, "_phs_legacy_single_fallback_mode", False
            )
        ):
            text = "F8 → 현재/완료 이적 현품표 스캔 → F8 실행"
        elif not self._phs_label_exchange_available_for_tray():
            text = "현품표 교체 API 설정이 없습니다."
        else:
            business_date = str(
                getattr(tray, "active_label_business_date", "") or ""
            ).strip()
            worker_code = str(
                getattr(tray, "active_label_worker_code", "") or ""
            ).strip()
            details = " · ".join(
                value
                for value in (
                    business_date,
                    worker_code,
                    f"{int(getattr(tray, 'tray_size', 0) or 0)} Pcs",
                )
                if value
            )
            text = f"현재 사용 중 · {details}" if details else "현재 PHS2"
            text += " · 단축키 F8"
        try:
            label.configure(text=text)
        except (tk.TclError, AttributeError):
            pass

    def _on_phs_label_exchange_shortcut(self, _event=None):
        if self._warning_state_presenter().state.is_blocking:
            self._render_warning_state()
        elif self._reject_mutation_during_preflight_hold():
            pass
        elif any(getattr(self, name, False) for name in (
            "_phs_label_exchange_pending", "_phs_label_candidate_pending",
            "_phs_reconciliation_resolve_pending", "_phs_label_refresh_pending",
        )):
            self._schedule_focus_return()
        elif getattr(self, "_phs_reconciliation_context", None):
            self._execute_selected_phs_label_exchange()
        elif self._phs_label_exchange_transition_pending():
            self._execute_selected_phs_label_exchange()
        elif (
            self._phs_label_exchange_available_for_tray()
            or self._phs_reconciliation_exchange_available()
        ):
            self._toggle_phs_label_exchange_panel()
        else:
            self.show_status_message(
                "중앙 현품표 reconciliation 교체 API 설정이 없습니다.",
                self.COLOR_DANGER,
                duration=6000,
            )
            self._schedule_focus_return()
        return "break"

    def _set_phs_label_exchange_panel_mode(
        self, *, reconciliation_mode: bool
    ) -> None:
        """Keep central reconciliation separate from legacy manual SINGLE input."""

        self._phs_legacy_single_fallback_mode = not reconciliation_mode

        def set_visible(widget, visible: bool) -> None:
            if widget is None:
                return
            try:
                if visible:
                    widget.grid()
                elif hasattr(widget, "grid_remove"):
                    widget.grid_remove()
                else:
                    widget.grid_forget()
            except (tk.TclError, AttributeError):
                return

        set_visible(
            getattr(self, "phs_reconciliation_instruction_label", None),
            reconciliation_mode,
        )
        set_visible(
            getattr(self, "phs_label_legacy_single_controls_frame", None),
            not reconciliation_mode,
        )
        set_visible(
            getattr(self, "phs_label_candidate_combo", None),
            not reconciliation_mode,
        )
        set_visible(
            getattr(self, "phs_label_legacy_fallback_button", None),
            reconciliation_mode
            and self._phs_label_exchange_available_for_tray(),
        )

    def _show_phs_label_legacy_single_fallback(self, _event=None):
        """Expose the legacy SINGLE controls only as an explicit fallback."""

        busy = bool(
            getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        )
        operator_review = self._active_blocking_completion_snapshot() is not None
        transition_pending = self._phs_label_exchange_transition_pending()
        if busy or operator_review or transition_pending:
            self.show_status_message(
                "진행 중인 현품표 교체 또는 복구를 먼저 완료하세요.",
                self.COLOR_DANGER,
                duration=6000,
            )
            self._schedule_focus_return()
            return "break"
        if not self._phs_label_exchange_available_for_tray():
            self.show_status_message(
                "현재 사용 중인 현품표에는 보조 날짜 교환을 사용할 수 없습니다.",
                self.COLOR_DANGER,
                duration=6000,
            )
            self._schedule_focus_return()
            return "break"
        panel = getattr(self, "phs_label_exchange_frame", None)
        try:
            if panel is not None:
                panel.grid()
                self._phs_label_exchange_panel_open = True
        except (tk.TclError, AttributeError):
            self.show_status_message(
                "보조 날짜 교환 화면을 열 수 없습니다.",
                self.COLOR_DANGER,
                duration=6000,
            )
            self._schedule_focus_return()
            return "break"
        self._phs_reconciliation_scan_armed = False
        self._phs_reconciliation_context = None
        self._phs_reconciliation_execution_guard = None
        self._set_phs_label_candidates([])
        self._configure_widget_options(
            getattr(self, "phs_label_exchange_execute_button", None),
            text="선택 교환 실행",
        )
        self._set_phs_label_exchange_panel_mode(reconciliation_mode=False)
        self._refresh_phs_active_label_info()
        self._update_action_button_states()
        self.show_status_message(
            "보조 기능입니다. 현재 사용 중인 현품표의 교환 작업일과 "
            "후보를 선택하세요.",
            self.COLOR_PRIMARY,
            duration=8000,
        )

        def focus_target_date() -> None:
            target = getattr(self, "phs_label_target_date_entry", None)
            try:
                if target is not None:
                    target.focus_set()
                    target.selection_range(0, tk.END)
            except (tk.TclError, AttributeError):
                self._schedule_focus_return()

        root = getattr(self, "root", None)
        try:
            if root is not None:
                root.after(0, focus_target_date)
            else:
                focus_target_date()
        except (tk.TclError, AttributeError):
            focus_target_date()
        return "break"

    def _toggle_phs_label_exchange_panel(self) -> None:
        panel = getattr(self, "phs_label_exchange_frame", None)
        if panel is None:
            return
        reconciliation_mode = self._phs_reconciliation_exchange_available()
        legacy_single_available = self._phs_label_exchange_available_for_tray()
        if not (legacy_single_available or reconciliation_mode):
            self.show_status_message(
                "중앙 현품표 교체 API 설정이 없습니다.",
                self.COLOR_DANGER,
                duration=6000,
            )
            self._schedule_focus_return()
            return
        self._set_phs_label_exchange_panel_mode(
            reconciliation_mode=reconciliation_mode
        )
        self._phs_label_exchange_panel_open = True
        try:
            if panel.winfo_ismapped():
                self._phs_reconciliation_scan_armed = reconciliation_mode
            else:
                panel.grid()
                self._phs_reconciliation_scan_armed = reconciliation_mode
                if reconciliation_mode:
                    self.show_status_message(
                        "현재 또는 완료된 이적 현품표를 스캔하면 서버가 적용할 "
                        "교체 지시를 조회합니다.",
                        self.COLOR_PRIMARY,
                        duration=8000,
                    )
                else:
                    self.show_status_message(
                        "현재 사용 중인 현품표의 교환 작업일과 후보를 선택하세요.",
                        self.COLOR_PRIMARY,
                        duration=8000,
                    )
        except (tk.TclError, AttributeError):
            return
        self._schedule_focus_return()

    def _close_phs_label_exchange_panel(self) -> None:
        if (
            self._warning_state_presenter().state.is_blocking
            or getattr(self, "_phs_reconciliation_context", None)
            or self._phs_label_exchange_transition_pending()
            or any(getattr(self, name, False) for name in (
                "_phs_label_exchange_pending", "_phs_label_candidate_pending",
                "_phs_reconciliation_resolve_pending", "_phs_label_refresh_pending",
            ))
        ):
            self.show_status_message(
                "진행 중인 현품표 교체 또는 복구를 먼저 완료하세요.",
                self.COLOR_DANGER,
            )
            return
        self._phs_reconciliation_scan_armed = False
        self._phs_label_exchange_panel_open = False
        self.phs_label_exchange_frame.grid_remove()
        self.show_status_message("현품표 교체 화면을 닫았습니다.", self.COLOR_PRIMARY)
        self._schedule_focus_return()

    def _set_phs_label_candidates(
        self, candidates: Sequence[Mapping[str, Any]]
    ) -> None:
        self._phs_label_candidates = [dict(value) for value in candidates]
        values = [
            (
                f"{value.get('business_date')} · "
                f"{value.get('worker_code')} · "
                f"{int(value.get('target_qty_pcs') or 0)} Pcs"
            )
            for value in self._phs_label_candidates
        ]
        combo = getattr(self, "phs_label_candidate_combo", None)
        variable = getattr(self, "phs_label_candidate_var", None)
        try:
            if combo is not None:
                combo.configure(values=values)
            if variable is not None:
                variable.set(values[0] if values else "")
        except (tk.TclError, AttributeError):
            pass

    def _load_phs_label_exchange_candidates(self) -> None:
        if (
            not self._phs_label_exchange_available_for_tray()
            or getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        ):
            self._schedule_focus_return()
            return
        business_date = str(
            getattr(
                getattr(self, "phs_label_target_date_var", None),
                "get",
                lambda: "",
            )()
            or ""
        ).strip()
        self._phs_reconciliation_context = None
        tray = self.current_tray
        self._phs_label_candidate_pending = True
        self._set_phs_label_candidates([])
        self._update_action_button_states()
        self.show_status_message(
            "동일 품목·member-count의 중앙 PLANNED 작업지시를 조회합니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )

        def worker() -> None:
            try:
                candidates = (
                    self.phs_label_exchange_coordinator.list_candidates(
                        tray, business_date
                    )
                )
                error = None
            except Exception as exc:
                candidates = []
                error = exc

            def finish() -> None:
                self._phs_label_candidate_pending = False
                if tray is not self.current_tray:
                    self._update_action_button_states()
                    self._schedule_focus_return()
                    return
                self._set_phs_label_candidates(candidates)
                if error is not None:
                    code = getattr(error, "code", "PHS_TARGET_LOOKUP_FAILED")
                    print(f"현품표 교환 대상 조회 실패: {code}: {error}")
                    self.show_status_message(
                        "교환 가능한 작업지시를 확인하지 못했습니다. "
                        "네트워크를 확인한 뒤 다시 시도하세요.",
                        self.COLOR_DANGER,
                        duration=8000,
                    )
                elif candidates:
                    self.show_status_message(
                        f"교환 가능한 중앙 작업지시 {len(candidates)}건을 "
                        "확인했습니다.",
                        self.COLOR_PRIMARY,
                        duration=6000,
                    )
                else:
                    self.show_status_message(
                        "해당 날짜에 동일 품목·member-count의 PLANNED 후보가 없습니다.",
                        self.COLOR_DANGER,
                        duration=8000,
                    )
                self._update_action_button_states()
                self._schedule_focus_return()

            try:
                self.root.after(0, finish)
            except (tk.TclError, AttributeError):
                self._phs_label_candidate_pending = False

        threading.Thread(
            target=worker,
            name="container-audit-phs-label-candidates",
            daemon=True,
        ).start()

    def _selected_phs_label_candidate(self) -> Optional[Dict[str, Any]]:
        variable = getattr(self, "phs_label_candidate_var", None)
        selected = str(
            getattr(variable, "get", lambda: "")() or ""
        ).strip()
        combo = getattr(self, "phs_label_candidate_combo", None)
        try:
            index = int(combo.current()) if combo is not None else -1
        except (tk.TclError, AttributeError, TypeError, ValueError):
            index = -1
        if 0 <= index < len(getattr(self, "_phs_label_candidates", [])):
            return dict(self._phs_label_candidates[index])
        for index_value, candidate in enumerate(
            getattr(self, "_phs_label_candidates", [])
        ):
            display = (
                f"{candidate.get('business_date')} · "
                f"{candidate.get('worker_code')} · "
                f"{int(candidate.get('target_qty_pcs') or 0)} Pcs"
            )
            if display == selected:
                return dict(candidate)
        return None

    def _set_phs_reconciliation_context(
        self,
        context: Optional[Mapping[str, Any]],
    ) -> None:
        self._phs_reconciliation_context = (
            dict(context) if isinstance(context, Mapping) else None
        )
        if context is None:
            self._phs_reconciliation_execution_guard = None
            self._set_phs_label_candidates([])
            self._configure_widget_options(
                getattr(self, "phs_label_exchange_execute_button", None),
                text="선택 교환 실행",
            )
            self._set_phs_label_exchange_panel_mode(
                reconciliation_mode=self._phs_reconciliation_exchange_available()
            )
            self._refresh_phs_active_label_info()
            self._update_action_button_states()
            return
        summaries = (
            self.phs_label_exchange_coordinator.reconciliation
            .target_summaries(context)
        )
        combo = getattr(self, "phs_label_candidate_combo", None)
        variable = getattr(self, "phs_label_candidate_var", None)
        try:
            if combo is not None:
                combo.configure(values=tuple(summaries))
            if variable is not None:
                variable.set(summaries[0] if summaries else "")
        except (tk.TclError, AttributeError):
            pass
        self._phs_label_candidates = []
        self._configure_widget_options(
            getattr(self, "phs_label_exchange_execute_button", None),
            text="서버 지시 교체 실행",
        )
        self._set_phs_label_exchange_panel_mode(reconciliation_mode=True)
        self._refresh_phs_active_label_info()
        self._update_action_button_states()

    def _intercept_phs_reconciliation_scan(
        self,
        raw_barcode: str,
    ) -> bool:
        if not getattr(self, "_phs_reconciliation_scan_armed", False):
            return False
        payload = normalize_master_label_input(raw_barcode)
        fields = self._parse_new_format_qr(payload)
        if not fields or str(fields.get("PHS") or "").strip() != "2":
            return False
        try:
            validate_compact_phs2_fields(fields)
        except TransferSealError:
            self.show_status_message(
                "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 다시 스캔하세요.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return True
        if self._reject_mutation_during_preflight_hold():
            return True
        # F8 arms exactly one reconciliation scan.  Leaving this armed after a
        # valid capture would steal later, ordinary PHS2 scans from the normal
        # transfer workflow.
        self._phs_reconciliation_scan_armed = False
        if (
            getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_label_exchange_pending", False)
        ):
            self.show_status_message(
                "현품표 교체 조회 또는 실행이 이미 진행 중입니다.",
                self.COLOR_PRIMARY,
                duration=4000,
            )
            self._schedule_focus_return()
            return True
        reconciliation = getattr(
            getattr(self, "phs_label_exchange_coordinator", None),
            "reconciliation",
            None,
        )
        if reconciliation is None or not reconciliation.available:
            self.show_status_message(
                "중앙 현품표 교체 기능을 사용할 수 없습니다.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return True

        self._phs_label_candidate_pending = True
        self._phs_reconciliation_resolve_pending = True
        progress_before = self._capture_phs_reconciliation_progress()
        finish_identity = self._capture_mutation_finish_identity()
        payload_snapshot = str(payload)
        marker_master_label = str(
            getattr(self.current_tray, "master_label_code", "") or ""
        )
        marker_operator = str(getattr(self, "worker_name", "") or "")
        marker_log_path = str(getattr(self, "log_file_path", "") or "")
        lane = self._ui_task_lane()
        self._set_phs_reconciliation_context(None)
        self.show_status_message(
            "스캔 현품표의 이적 교체 작업을 중앙에서 조회합니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )
        self._schedule_focus_return()

        def work() -> Dict[str, Any]:
            context = reconciliation.resolve(payload_snapshot)
            marker_outcome = None
            if self._phs_replacement_notice_pair(context) is not None:
                apply_ready = self._call_transfer_ui_sync(
                    lambda: self._mutation_finish_can_apply(
                        finish_identity,
                        operation="phs-reconciliation-resolve",
                    )
                )
                if apply_ready:
                    marker_outcome = (
                        self._work_phs_replacement_waiting_marker(
                            context,
                            master_label=marker_master_label,
                            operator=marker_operator,
                            projection_log_file_path=marker_log_path,
                        )
                    )
            else:
                marker_outcome = {"ready": True, "notice_key": None}
            return {
                "context": context,
                "marker_outcome": marker_outcome,
            }

        def finish(outcome: Dict[str, Any]) -> None:
            context = outcome.get("context")
            if not isinstance(context, dict):
                raise TypeError("reconciliation lane result has no context")
            preserved = self._phs_reconciliation_progress_unchanged(
                progress_before
            )
            apply_ready = self._mutation_finish_can_apply(
                finish_identity,
                operation="phs-reconciliation-resolve",
            )
            self._phs_reconciliation_resolve_pending = False
            self._phs_label_candidate_pending = False
            if not preserved or not apply_ready:
                if not self._preflight_context_blocks_mutation():
                    self.show_status_message(
                        "현품표 조회 중 현재 이적 작업 상태가 변경되어 결과를 "
                        "적용하지 않았습니다.",
                        self.COLOR_DANGER,
                        duration=8000,
                    )
                self._update_action_button_states()
                self._schedule_focus_return()
                return
            marker_ready, marker_new = (
                self._finish_phs_replacement_waiting_marker(
                    outcome.get("marker_outcome")
                )
            )
            if not marker_ready:
                self._set_phs_reconciliation_context(None)
                self._phs_reconciliation_execution_guard = None
                self._update_action_button_states()
                self._schedule_focus_return()
                return
            self._set_phs_reconciliation_context(context)
            self._phs_reconciliation_execution_guard = (
                self._capture_phs_reconciliation_progress()
            )
            summaries = reconciliation.target_summaries(context)
            if marker_new:
                self._show_phs_replacement_required_notice()
            else:
                self.show_status_message(
                    f"서버 교체 지시 {len(summaries)}장을 확인했습니다. "
                    "F8로 출력·교체를 계속하세요.",
                    self.COLOR_PRIMARY,
                    duration=8000,
                )
            try:
                self._log_event(
                    "PHS_RECONCILIATION_ACTION_RESOLVED",
                    detail={
                        "reconciliation_id": context[
                            "reconciliation"
                        ]["reconciliation_id"],
                        "action_ids": list(
                            context["selection"]["action_ids"]
                        ),
                        "exchange_kind": context[
                            "expected_exchange_kind"
                        ],
                        "target_count": len(summaries),
                        "local_progress_preserved": True,
                    },
                )
            except Exception:
                pass
            self._update_action_button_states()
            self._schedule_focus_return()

        def fail(exc: BaseException) -> None:
            print(
                "현품표 reconciliation 조회 lane 실패: "
                f"{exc.__class__.__name__}"
            )
            self._phs_reconciliation_resolve_pending = False
            self._phs_label_candidate_pending = False
            self.show_status_message(
                "현품표 교체 작업을 확인하지 못했습니다. F8로 다시 시도하세요.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._update_action_button_states()
            self._schedule_focus_return()

        admission = lane.submit(
            LaneTask(
                name="phs-reconciliation-resolve",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted:
            self._phs_reconciliation_resolve_pending = False
            self._phs_label_candidate_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._schedule_focus_return()
            return True
        self._phs_reconciliation_resolve_task_handle = admission.handle
        return True

    def _execute_selected_phs_label_exchange(self) -> None:
        if self._reject_mutation_during_preflight_hold():
            return
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        try:
            recovery = (
                coordinator.journal.load()
                if coordinator is not None
                else {}
            )
        except Exception:
            self.show_status_message(
                "이전 현품표 교체 상태를 확인하지 못했습니다. 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        reconciliation_pending = bool(
            recovery
            and str(recovery.get("status") or "").strip().upper()
            not in {"COMMITTED", "CANCELLED"}
            and str(recovery.get("workflow_kind") or "")
            == "RECONCILIATION"
        )
        if (
            getattr(self, "_phs_reconciliation_context", None)
            or reconciliation_pending
        ):
            self._execute_phs_reconciliation_exchange(
                recovery_only=reconciliation_pending
                and not getattr(
                    self, "_phs_reconciliation_context", None
                )
            )
            return
        if (
            not self._phs_label_exchange_available_for_tray()
            or getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        ):
            self._schedule_focus_return()
            return
        candidate = self._selected_phs_label_candidate()
        coordinator = self.phs_label_exchange_coordinator
        if candidate is None:
            try:
                recovery = coordinator.journal.load()
            except Exception:
                self.show_status_message(
                    "이전 현품표 교체 상태를 확인하지 못했습니다. 관리자에게 문의하세요.",
                    self.COLOR_DANGER,
                    duration=8000,
                )
                self._schedule_focus_return()
                return
            if not recovery or str(recovery.get("status") or "").upper() in {
                "COMMITTED",
                "CANCELLED",
            }:
                self.show_status_message(
                    "먼저 중앙 작업지시 후보를 조회하고 선택하세요.",
                    self.COLOR_DANGER,
                    duration=6000,
                )
                self._schedule_focus_return()
                return
            candidate = (
                dict(recovery.get("target_instruction"))
                if isinstance(recovery.get("target_instruction"), dict)
                else None
            )
        tray = self.current_tray
        captured_master_label = str(tray.master_label_code or "")
        tray_snapshot = copy.deepcopy(tray)
        candidate_snapshot = copy.deepcopy(candidate)
        finish_identity = self._capture_mutation_finish_identity()
        confirm_reprint = bool(
            getattr(
                getattr(self, "phs_label_reprint_confirm_var", None),
                "get",
                lambda: False,
            )()
        )
        lane = self._ui_task_lane()
        self._phs_label_exchange_pending = True
        self._update_action_button_states()
        self.show_status_message(
            "현품표 날짜 교환을 시작했습니다. 스캔 포커스와 현재 트레이 "
            "진행은 유지됩니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )
        self._schedule_focus_return()

        def work() -> tuple[Any, TraySession]:
            result = coordinator.execute_single(
                tray_snapshot,
                candidate_snapshot,
                persist_tray=None,
                defer_local_refresh=True,
                confirm_ambiguous_reprint=confirm_reprint,
                status_callback=None,
            )
            return result, tray_snapshot

        def finish(outcome: tuple[Any, TraySession]) -> None:
            result, updated_tray = outcome
            apply_ready = self._mutation_finish_can_apply(
                finish_identity,
                operation="phs-label-exchange",
            )
            self._phs_label_exchange_pending = False
            if not apply_ready:
                self._update_action_button_states()
                self._schedule_focus_return()
                return
            local_ready = self._apply_phs_label_exchange_snapshot(
                captured_tray=tray,
                captured_master_label=captured_master_label,
                updated_tray=updated_tray,
                force_persist=bool(result.success),
            )
            refresh_confirmed = False
            if result.success and local_ready:
                try:
                    coordinator.confirm_local_refresh_applied(
                        exchange_id=result.exchange_id,
                    )
                    refresh_confirmed = True
                except Exception as exc:
                    print(
                        "현품표 교체 local refresh 완료 기록 실패: "
                        f"{exc.__class__.__name__}"
                    )
            success = bool(
                result.success and local_ready and refresh_confirmed
            )
            if success:
                self._set_phs_label_candidates([])
                try:
                    self.phs_label_reprint_confirm_var.set(False)
                except (tk.TclError, AttributeError):
                    pass
                try:
                    self._log_event(
                        "PHS_LABEL_DATE_EXCHANGED",
                        detail={
                            "exchange_id": result.exchange_id,
                            "canonical_input_tag_qr": (
                                tray.canonical_input_tag_qr
                            ),
                            "active_label_id": tray.active_label_id,
                            "active_label_business_date": (
                                tray.active_label_business_date
                            ),
                            "active_label_worker_code": (
                                tray.active_label_worker_code
                            ),
                            "local_progress_preserved": True,
                        },
                    )
                except Exception:
                    pass
                color = self.COLOR_SUCCESS
            else:
                color = self.COLOR_DANGER
            self.show_status_message(
                (
                    "현품표 날짜 교환을 완료했습니다. 현재 트레이 진행은 유지됩니다."
                    if success
                    else "현품표 날짜 교환을 완료하지 못했습니다. F8로 복구하거나 관리자에게 문의하세요."
                ),
                color,
                duration=10000,
            )
            self._update_current_item_label()
            self._update_center_display()
            self._update_action_button_states()
            self._schedule_focus_return()
            if (
                success
                and tray is self.current_tray
                and not getattr(self, "_ui_close_requested", False)
                and len(tray.scanned_barcodes) >= int(tray.tray_size or 0)
            ):
                self.root.after(0, self.request_complete_tray)

        def fail(exc: BaseException) -> None:
            print(f"현품표 날짜 교환 lane 실패: {exc.__class__.__name__}")
            self._phs_label_exchange_pending = False
            self.show_status_message(
                "현품표 날짜 교환을 완료하지 못했습니다. F8로 복구하거나 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._update_action_button_states()
            self._schedule_focus_return()

        admission = lane.submit(
            LaneTask(
                name="phs-label-exchange",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted:
            self._phs_label_exchange_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._schedule_focus_return()
            return
        self._phs_label_exchange_task_handle = admission.handle

    def _confirm_phs_reconciliation_ambiguous_reprint(
        self,
        *,
        already_confirmed: bool,
    ) -> Optional[bool]:
        if already_confirmed:
            return True
        journal = getattr(
            getattr(self, "phs_label_exchange_coordinator", None),
            "journal",
            None,
        )
        load_recovery = getattr(journal, "load", None)
        if not callable(load_recovery):
            return False
        try:
            recovery = load_recovery()
        except Exception as exc:
            print(
                "현품표 교체 복구 정보 읽기 실패: "
                f"{exc.__class__.__name__}: {exc}"
            )
            self.show_status_message(
                "현품표 교체 복구 정보를 읽지 못했습니다. "
                "F8로 다시 시도하거나 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._schedule_focus_return()
            return None
        if not isinstance(recovery, Mapping):
            return False
        if (
            str(recovery.get("workflow_kind") or "").strip().upper()
            != "RECONCILIATION"
            or str(recovery.get("status") or "").strip().upper()
            != "LOCAL_PRINT_STARTING"
        ):
            return False
        try:
            approved = bool(
                messagebox.askyesno(
                    "실물 현품표 재출력 확인",
                    "이전 실행이 실제 프린터 제출 중 종료되어 출력 여부가 "
                    "불확실합니다.\n\n실물 라벨을 확인했습니다. 같은 target "
                    "현품표를 재출력할까요?\n\n"
                    "키보드: Y 승인 / N 취소",
                    parent=self.root,
                    default=messagebox.NO,
                )
            )
        except (tk.TclError, AttributeError) as exc:
            print(
                "현품표 재출력 확인 창 표시 실패: "
                f"{exc.__class__.__name__}: {exc}"
            )
            self.show_status_message(
                "현품표 재출력 확인 창을 열지 못했습니다. 다시 시도하거나 "
                "관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._schedule_focus_return()
            return None
        if not approved:
            self.show_status_message(
                "미완료 현품표 교체를 보존했습니다. 실물 라벨을 확인한 뒤 "
                "F8로 다시 복구할 수 있습니다.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return None
        try:
            self.phs_label_reprint_confirm_var.set(True)
        except (tk.TclError, AttributeError):
            pass
        return True

    def _execute_phs_reconciliation_exchange(
        self,
        *,
        recovery_only: bool = False,
    ) -> None:
        if self._reject_mutation_during_preflight_hold():
            return
        coordinator = getattr(
            getattr(self, "phs_label_exchange_coordinator", None),
            "reconciliation",
            None,
        )
        if (
            coordinator is None
            or not coordinator.available
            or getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        ):
            self._schedule_focus_return()
            return
        context = (
            None
            if recovery_only
            else getattr(self, "_phs_reconciliation_context", None)
        )
        if context is None and not recovery_only:
            self.show_status_message(
                "먼저 F8을 누르고 현재 또는 완료된 이적 현품표를 스캔하세요.",
                self.COLOR_DANGER,
                duration=7000,
            )
            self._schedule_focus_return()
            return
        confirm_reprint = bool(
            getattr(
                getattr(self, "phs_label_reprint_confirm_var", None),
                "get",
                lambda: False,
            )()
        )
        confirm_reprint_result = (
            self._confirm_phs_reconciliation_ambiguous_reprint(
                already_confirmed=confirm_reprint,
            )
        )
        if confirm_reprint_result is None:
            return
        confirm_reprint = confirm_reprint_result
        execution_guard = getattr(
            self,
            "_phs_reconciliation_execution_guard",
            None,
        )
        if (
            context is not None
            and execution_guard is not None
            and not self._phs_reconciliation_progress_unchanged(
                execution_guard
            )
        ):
            self._set_phs_reconciliation_context(None)
            self.show_status_message(
                "조회 후 현재 이적 작업이 바뀌어 교체 실행을 취소했습니다. "
                "F8로 현품표를 다시 스캔하세요.",
                self.COLOR_IDLE,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        snapshot = self._capture_phs_reconciliation_progress()
        finish_identity = self._capture_mutation_finish_identity()
        context_snapshot = copy.deepcopy(context)
        lane = self._ui_task_lane()
        self._phs_label_exchange_pending = True
        self._update_action_button_states()
        self.show_status_message(
            "서버 지시에 따라 새 현품표 출력·교체를 진행합니다. "
            "현재 이적 작업은 그대로 유지됩니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )
        self._schedule_focus_return()

        def work() -> Any:
            return coordinator.execute(
                context_snapshot,
                confirm_ambiguous_reprint=confirm_reprint,
                status_callback=None,
            )

        def finish(result: Any) -> None:
            apply_ready = self._mutation_finish_can_apply(
                finish_identity,
                operation="phs-reconciliation-exchange",
            )
            self._phs_label_exchange_pending = False
            if not apply_ready:
                self._update_action_button_states()
                self._schedule_focus_return()
                return
            preserved = self._phs_reconciliation_progress_unchanged(
                snapshot
            )
            if not preserved:
                self.show_status_message(
                    "현품표 교체 중 현재 이적 작업 상태가 변경됐습니다. "
                    "추가 교체를 중지하고 관리자에게 문의하세요.",
                    self.COLOR_DANGER,
                    duration=10000,
                )
            elif result.success:
                self._set_phs_reconciliation_context(None)
                try:
                    self.phs_label_reprint_confirm_var.set(False)
                except (tk.TclError, AttributeError):
                    pass
                try:
                    self._log_event(
                        "PHS_RECONCILIATION_LABEL_EXCHANGED",
                        detail={
                            "exchange_id": result.exchange_id,
                            "status": result.status,
                            "local_progress_preserved": True,
                        },
                    )
                except Exception:
                    pass
                self.show_status_message(
                    "현품표 교체를 완료했습니다. 현재 이적 작업은 유지됩니다.",
                    self.COLOR_SUCCESS,
                    duration=10000,
                )
            else:
                journal_context = (
                    result.journal_state.get(
                        "reconciliation_context"
                    )
                    if isinstance(result.journal_state, Mapping)
                    else None
                )
                if isinstance(journal_context, Mapping):
                    self._set_phs_reconciliation_context(
                        journal_context
                    )
                self.show_status_message(
                    "현품표 교체를 완료하지 못했습니다. F8로 복구하거나 관리자에게 문의하세요.",
                    self.COLOR_DANGER,
                    duration=10000,
                )
            self._update_current_item_label()
            self._update_center_display()
            self._update_action_button_states()
            self._schedule_focus_return()

        def fail(exc: BaseException) -> None:
            print(f"현품표 reconciliation lane 실패: {exc.__class__.__name__}")
            self._phs_label_exchange_pending = False
            self.show_status_message(
                "현품표 교체를 완료하지 못했습니다. F8로 복구하거나 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._update_action_button_states()
            self._schedule_focus_return()

        admission = lane.submit(
            LaneTask(
                name="phs-reconciliation-exchange",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted:
            self._phs_label_exchange_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._schedule_focus_return()
            return
        self._phs_label_exchange_task_handle = admission.handle

    def _schedule_phs_label_exchange_recovery(self) -> None:
        if (
            getattr(self, "_phs_label_exchange_pending", False)
            or getattr(self, "_ui_close_requested", False)
        ):
            return
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        if coordinator is None:
            self._phs_label_recovery_deferred = False
            return
        try:
            recovery = coordinator.journal.load()
        except Exception as exc:
            print(
                "현품표 교환 복구 정보 읽기 실패: "
                f"{exc.__class__.__name__}: {exc}"
            )
            self.show_status_message(
                "현품표 교환 복구 정보를 읽지 못했습니다. "
                "F8로 다시 시도하거나 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._phs_label_recovery_deferred = False
            return
        if (
            recovery
            and str(recovery.get("status") or "").strip().upper()
            not in {"COMMITTED", "CANCELLED"}
            and str(recovery.get("workflow_kind") or "")
            == "RECONCILIATION"
        ):
            self._phs_label_recovery_deferred = False
            context = recovery.get("reconciliation_context")
            if isinstance(context, Mapping):
                self._set_phs_reconciliation_context(context)
            self._execute_phs_reconciliation_exchange(
                recovery_only=True
            )
            return
        if not self._phs_label_exchange_available_for_tray():
            self._phs_label_recovery_deferred = False
            return
        if (
            not recovery
            or str(recovery.get("status") or "").strip().upper()
            in {"COMMITTED", "CANCELLED"}
            or str(recovery.get("canonical_input_tag_qr") or "").strip()
            != str(self.current_tray.master_label_code or "").strip()
        ):
            self._phs_label_recovery_deferred = False
            return
        if self._preflight_context_blocks_mutation():
            if not getattr(self, "_phs_label_recovery_deferred", False):
                self._reject_mutation_during_preflight_hold()
            self._phs_label_recovery_deferred = True
            try:
                self.root.after(100, self._schedule_phs_label_exchange_recovery)
            except (tk.TclError, AttributeError):
                pass
            return
        self._phs_label_recovery_deferred = False
        tray = self.current_tray
        captured_master_label = str(tray.master_label_code or "")
        tray_snapshot = copy.deepcopy(tray)
        finish_identity = self._capture_mutation_finish_identity()
        lane = self._ui_task_lane()
        self._phs_label_exchange_pending = True
        self._update_action_button_states()
        self.show_status_message(
            "미완료 현품표 날짜 교환을 중앙 ACK에서 복구하고 있습니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )

        def work() -> tuple[Any, TraySession]:
            result = coordinator.recover_for_tray(
                tray_snapshot,
                persist_tray=None,
                defer_local_refresh=True,
                status_callback=None,
            )
            return result, tray_snapshot

        def finish(outcome: tuple[Any, TraySession]) -> None:
            result, updated_tray = outcome
            apply_ready = self._mutation_finish_can_apply(
                finish_identity,
                operation="phs-label-recovery",
            )
            self._phs_label_exchange_pending = False
            if not apply_ready:
                self._update_action_button_states()
                self._schedule_focus_return()
                return
            local_ready = False
            refresh_confirmed = False
            if result is not None:
                local_ready = self._apply_phs_label_exchange_snapshot(
                    captured_tray=tray,
                    captured_master_label=captured_master_label,
                    updated_tray=updated_tray,
                    force_persist=bool(result.success),
                )
                if result.success and local_ready:
                    try:
                        coordinator.confirm_local_refresh_applied(
                            exchange_id=result.exchange_id,
                        )
                        refresh_confirmed = True
                    except Exception as exc:
                        print(
                            "현품표 교체 복구 local refresh 완료 기록 실패: "
                            f"{exc.__class__.__name__}"
                        )
                success = bool(
                    result.success and local_ready and refresh_confirmed
                )
                self.show_status_message(
                    (
                        "이전 현품표 교체를 복구했습니다. 현재 트레이 진행은 유지됩니다."
                        if success
                        else "이전 현품표 교체를 복구하지 못했습니다. 관리자에게 문의하세요."
                    ),
                    self.COLOR_SUCCESS if success else self.COLOR_DANGER,
                    duration=10000,
                )
            else:
                success = False
            self._update_current_item_label()
            self._update_center_display()
            self._update_action_button_states()
            self._schedule_focus_return()
            if (
                success
                and tray is self.current_tray
                and not getattr(self, "_ui_close_requested", False)
                and len(tray.scanned_barcodes) >= int(tray.tray_size or 0)
            ):
                self.root.after(0, self.request_complete_tray)

        def fail(exc: BaseException) -> None:
            print(f"현품표 교체 복구 lane 실패: {exc.__class__.__name__}")
            self._phs_label_exchange_pending = False
            self.show_status_message(
                "이전 현품표 교체를 복구하지 못했습니다. 관리자에게 문의하세요.",
                self.COLOR_DANGER,
                duration=10000,
            )
            self._update_action_button_states()
            self._schedule_focus_return()

        admission = lane.submit(
            LaneTask(
                name="phs-label-recovery",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted:
            self._phs_label_exchange_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._schedule_focus_return()
            if (
                admission.reason == "busy"
                and not getattr(self, "_ui_close_requested", False)
            ):
                self._phs_label_recovery_deferred = True
                try:
                    self.root.after(
                        100,
                        self._schedule_phs_label_exchange_recovery,
                    )
                except (tk.TclError, AttributeError):
                    pass
            return
        self._phs_label_exchange_task_handle = admission.handle

    def _show_operations_menu(self) -> None:
        """Show secondary and destructive actions without growing the center pane."""

        if self._warning_state_presenter().state.is_blocking:
            self._render_warning_state()
            return
        active_tray = bool(getattr(getattr(self, "current_tray", None), "master_label_code", ""))
        replacement_active = bool(getattr(self, "master_label_replace_state", None))
        exchange_dialog_open = self._widget_exists(getattr(self, "exchange_dialog", None))
        lane = getattr(self, "_ui_lane", None)
        transfer_lane_busy = bool(lane is not None and lane.is_busy())
        exact_exchange_blocked = self._exact_transfer_exchange_blocked()
        scanned_count = len(
            getattr(getattr(self, "current_tray", None), "scanned_barcodes", []) or []
        )
        active_transfer_exchange_available = bool(
            exact_exchange_blocked
            and active_tray
            and scanned_count
            and not transfer_lane_busy
        )

        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(
            label="전송 상태 상세",
            command=self._show_direct_sync_status_details,
        )
        menu.add_command(
            label="현품표 교체 (F8)",
            command=self._on_phs_label_exchange_shortcut,
        )
        menu.add_command(
            label="완료 작업 중앙 반영 재시도 (관리자)",
            command=self._retry_transfer_post_review,
            state=(
                tk.NORMAL
                if self._is_preflight_hold_supervisor()
                and not active_tray
                and not transfer_lane_busy
                and not replacement_active
                else tk.DISABLED
            ),
        )
        menu.add_separator()
        menu.add_command(
            label="현재 작업 리셋",
            command=self.reset_current_work,
            state=tk.NORMAL if active_tray else tk.DISABLED,
        )
        menu.add_separator()
        menu.add_command(
            label=(
                "현품표 교체 취소"
                if replacement_active
                else (
                    "중앙 교체 절차 필요"
                    if exact_exchange_blocked
                    else "완료 현품표 교체"
                )
            ),
            command=self.initiate_master_label_replacement,
            state=(
                tk.NORMAL
                if replacement_active
                or (
                    not exact_exchange_blocked
                    and not transfer_lane_busy
                    and not active_tray
                    and not exchange_dialog_open
                )
                else tk.DISABLED
            ),
        )
        menu.add_command(
            label=(
                "현재 이적 제품 교체"
                if active_transfer_exchange_available
                else "중앙 교환 절차 필요"
                if exact_exchange_blocked
                else "개별 제품 교환"
            ),
            command=self.show_exchange_dialog,
            state=(
                tk.NORMAL
                if active_transfer_exchange_available and not replacement_active
                else tk.DISABLED
                if active_tray
                or replacement_active
                or exact_exchange_blocked
                or transfer_lane_busy
                else tk.NORMAL
            ),
        )
        button = getattr(self, "operations_button", None)
        try:
            x = button.winfo_rootx()
            y = button.winfo_rooty() + button.winfo_height()
            menu.tk_popup(x, y)
        except (tk.TclError, AttributeError):
            try:
                menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
            except (tk.TclError, AttributeError):
                return
        finally:
            try:
                menu.grab_release()
            except tk.TclError:
                pass

    def _show_left_sidebar_view(self, view: str) -> None:
        """Switch the compact left context without rebuilding either tree."""

        if view not in {"summary", "parked"}:
            return
        self._left_sidebar_view = view
        self._sync_left_sidebar_switch()
        self._apply_left_sidebar_layout()
        try:
            self._schedule_focus_return()
        except (tk.TclError, AttributeError):
            pass

    def _toggle_left_sidebar_view(self) -> None:
        current = getattr(self, "_left_sidebar_view", "summary")
        self._show_left_sidebar_view("summary" if current == "parked" else "parked")

    def _sync_left_sidebar_switch(self) -> None:
        button = getattr(self, "left_context_switch_button", None)
        if button is None:
            return
        view = getattr(self, "_left_sidebar_view", "summary")
        count = max(0, int(getattr(self, "_parked_tray_count", 0) or 0))
        text = "현재·기록 보기" if view == "parked" else f"보류 {count}건 보기"
        try:
            button.configure(text=text, style="Secondary.TButton")
        except (tk.TclError, AttributeError):
            pass

    def _update_parked_recovery_affordance(self) -> int:
        """Keep the compact recovery entry point truthful after list refreshes."""

        count = 0
        tree = getattr(self, "parked_tree", None)
        if tree is not None:
            try:
                count = len(tree.get_children())
            except (tk.TclError, AttributeError, TypeError):
                count = 0
        title = getattr(self, "parked_title_label", None)
        if title is not None:
            try:
                title.configure(text=f"보류 작업 {count}건 (더블클릭으로 복원)")
            except (tk.TclError, AttributeError):
                pass
        self._parked_tray_count = count
        self._sync_left_sidebar_switch()
        return count

    def _apply_left_sidebar_layout(self) -> None:
        parent_frame = getattr(self, "_left_sidebar_frame", None)
        if parent_frame is None:
            return
        scale = max(0.7, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        previous_compact_height = getattr(self, "_left_sidebar_compact", None)
        try:
            parent_width = int(parent_frame.winfo_width())
            parent_height = int(self._pane_viewport_height(parent_frame))
            compact_large_text = scale >= 1.2 and 1 < parent_width < 420
            compact_height = (
                parent_height > 1
                and parent_height / scale < LEFT_SIDEBAR_SWITCH_LOGICAL_HEIGHT
            )
            tray_image_checkbox = getattr(self, "tray_image_checkbox", None)
            if tray_image_checkbox is not None:
                tray_image_checkbox.configure(
                    text="트레이 이미지" if compact_large_text else "트레이 이미지 보기",
                    wraplength=max(60, parent_width - 50),
                    font=(self.DEFAULT_FONT, self.style_tokens.fonts.body),
                )
            if getattr(self, "show_tray_image_var", None) is not None and self.show_tray_image_var.get():
                parent_frame.grid_rowconfigure(0, weight=3)
                parent_frame.grid_rowconfigure(1, weight=2, minsize=int(180 * scale))
            else:
                parent_frame.grid_rowconfigure(0, weight=1)
                parent_frame.grid_rowconfigure(1, weight=0, minsize=int(42 * scale))

            top_frame = getattr(self, "_left_top_frame", None)
            switch_frame = getattr(self, "_left_view_switch_frame", None)
            summary_title = getattr(self, "summary_title_label", None)
            summary_frame = getattr(self, "_summary_tree_frame", None)
            parked_title = getattr(self, "parked_title_label", None)
            parked_frame = getattr(self, "_parked_tree_frame", None)
            if any(
                value is None
                for value in (
                    top_frame,
                    switch_frame,
                    summary_title,
                    summary_frame,
                    parked_title,
                    parked_frame,
                )
            ):
                return

            for row in (2, 3, 4, 5):
                top_frame.grid_rowconfigure(row, weight=0, minsize=0)
            view = getattr(self, "_left_sidebar_view", "summary")
            if view not in {"summary", "parked"}:
                view = "summary"
                self._left_sidebar_view = view

            header_frame = getattr(self, "_left_header_frame", None)
            worker_info_frame = getattr(self, "_worker_info_frame", None)
            worker_buttons_frame = getattr(self, "_worker_buttons_frame", None)
            current_work_frame = getattr(self, "_current_work_frame", None)
            current_work_title = getattr(self, "current_work_title_label", None)
            fonts = getattr(getattr(self, "style_tokens", None), "fonts", None)
            roomy_sidebar_font = int(
                getattr(fonts, "sidebar", max(12, int(13 * scale)))
            )
            roomy_name_font = int(
                getattr(fonts, "section_title", max(14, int(15 * scale)))
            )
            roomy_detail_font = int(
                getattr(fonts, "caption", max(11, int(12 * scale)))
            )

            if compact_height:
                if header_frame is not None and worker_info_frame is not None and worker_buttons_frame is not None:
                    header_frame.grid_columnconfigure(0, weight=1)
                    header_frame.grid_columnconfigure(1, weight=0)
                    header_frame.grid_configure(pady=(0, 8))
                    worker_info_frame.grid(row=0, column=0, sticky="ew")
                    worker_buttons_frame.grid(row=0, column=1, sticky="e", padx=(8, 0), pady=0)
                    self.worker_info_label.configure(
                        text=display_operator_name(self.worker_name),
                        font=(self.DEFAULT_FONT, max(12, int(11 * scale)), "bold"),
                    )
                    self.change_worker_button.configure(
                        text="변경",
                        style="Secondary.TButton",
                        width=4,
                    )
                if current_work_frame is not None:
                    current_work_frame.configure(padding=8)
                    current_work_frame.grid_configure(pady=(0, 8))
                if current_work_title is not None:
                    current_work_title.grid_remove()
                self.current_work_name_label.configure(
                    font=(self.DEFAULT_FONT, max(15, int(13 * scale)), "bold")
                )
                self.current_work_name_label.grid_configure(pady=(0, 2))
                self.current_work_detail_label.configure(
                    font=(self.DEFAULT_FONT, max(12, int(10 * scale)))
                )
                self.current_work_spec_label.configure(
                    font=(self.DEFAULT_FONT, max(12, int(10 * scale)))
                )
                switch_frame.grid(row=2, column=0, sticky="ew", pady=(0, 8))
                summary_title.grid_remove()
                parked_title.grid_remove()
                if view == "parked":
                    summary_frame.grid_remove()
                    parked_frame.grid(row=3, column=0, sticky="nsew")
                    self.root.after_idle(self._adjust_parked_tree_columns)
                else:
                    parked_frame.grid_remove()
                    summary_frame.grid(row=3, column=0, sticky="nsew")
                    self.root.after_idle(self._adjust_summary_tree_columns)
                top_frame.grid_rowconfigure(
                    3,
                    weight=1,
                    minsize=max(
                        92,
                        int(72 * scale),
                        int(getattr(self, "_left_tree_minimum_one_row_height", 0) or 0),
                    ),
                )
            else:
                if header_frame is not None and worker_info_frame is not None and worker_buttons_frame is not None:
                    header_frame.grid_columnconfigure(0, weight=1)
                    header_frame.grid_columnconfigure(1, weight=0)
                    header_frame.grid_configure(pady=(0, 12))
                    worker_info_frame.grid(row=0, column=0, sticky="ew")
                    worker_buttons_frame.grid(row=1, column=0, sticky="ew", padx=0, pady=(6, 0))
                    self.worker_info_label.configure(
                        text=f"작업자: {display_operator_name(self.worker_name)}",
                        font=(self.DEFAULT_FONT, roomy_sidebar_font),
                    )
                    self.change_worker_button.configure(
                        text="작업자 변경",
                        style="Secondary.TButton",
                        width=0,
                    )
                if current_work_frame is not None:
                    current_work_frame.configure(padding=12)
                    current_work_frame.grid_configure(pady=(0, 14))
                if current_work_title is not None:
                    current_work_title.grid(row=0, column=0, sticky="ew")
                self.current_work_name_label.configure(
                    font=(self.DEFAULT_FONT, roomy_name_font, "bold")
                )
                self.current_work_name_label.grid_configure(pady=(3, 2))
                self.current_work_detail_label.configure(
                    font=(self.DEFAULT_FONT, roomy_detail_font)
                )
                self.current_work_spec_label.configure(
                    font=(self.DEFAULT_FONT, roomy_detail_font)
                )
                switch_frame.grid_remove()
                summary_title.grid(row=2, column=0, sticky="ew", pady=(0, 10))
                summary_frame.grid(row=3, column=0, sticky="nsew")
                parked_title.grid(row=4, column=0, sticky="ew", pady=(20, 10))
                parked_frame.grid(row=5, column=0, sticky="nsew")
                top_frame.grid_rowconfigure(3, weight=2, minsize=0)
                top_frame.grid_rowconfigure(5, weight=1, minsize=0)
                self.root.after_idle(self._adjust_summary_tree_columns)
                self.root.after_idle(self._adjust_parked_tree_columns)
            self._left_sidebar_compact = compact_height
            if (
                previous_compact_height is None
                or bool(previous_compact_height) != compact_height
            ):
                self._update_operator_context()
            self._sync_left_sidebar_switch()
        except (tk.TclError, AttributeError):
            return

    def _get_right_sidebar_layout_metrics(self, sidebar_height: int) -> Dict[str, Any]:
        sidebar_width = 320
        parent_frame = getattr(self, "_right_sidebar_frame", None)
        try:
            candidate = int(parent_frame.winfo_width())
            if candidate > 1:
                sidebar_width = candidate
        except (AttributeError, TypeError, ValueError, tk.TclError):
            pass
        metrics = calculate_right_sidebar_metrics(
            sidebar_width,
            sidebar_height,
            getattr(self, "scale_factor", 1.0),
        )
        context_value_font = metrics.context_value_font
        if context_value_font <= 0:
            try:
                root_width = max(1, int(self.root.winfo_width()))
                root_height = max(1, int(self.root.winfo_height()))
            except (AttributeError, TypeError, ValueError, tk.TclError):
                root_width, root_height = 1440, 900
            root_profile = select_layout_profile(
                root_width,
                root_height,
                getattr(self, "scale_factor", 1.0),
            )
            root_tokens = build_style_tokens(
                StyleProfile(root_profile.name),
                getattr(self, "scale_factor", 1.0),
            )
            context_value_font = int(root_tokens.fonts.section_title)
        return {
            "profile": metrics.profile,
            "short_large_text": metrics.short_large_text,
            "content_sized_cards": metrics.content_sized_cards,
            "outer_padding": metrics.outer_padding,
            "card_gap": metrics.card_gap,
            "card_minsize": metrics.card_minsize,
            "primary_card_minsize": metrics.primary_card_minsize,
            "secondary_card_minsize": metrics.secondary_card_minsize,
            "follow_up_minsize": metrics.follow_up_minsize,
            "legend_pad_y": metrics.legend_pad_y,
            "legend_visible": metrics.legend_visible,
            "date_font": metrics.date_font,
            "clock_font": metrics.clock_font,
            "date_gap": metrics.date_gap,
            "clock_gap": metrics.clock_gap,
            "card_padding": metrics.card_padding,
            "context_padding": metrics.context_padding,
            "secondary_card_padding": metrics.secondary_card_padding,
            "value_font": metrics.value_font,
            "secondary_value_font": metrics.secondary_value_font,
            "context_value_font": context_value_font,
        }

    def _apply_right_sidebar_layout(self, event=None, *, generation=None) -> None:
        parent_frame = getattr(self, "_right_sidebar_frame", None)
        if parent_frame is None:
            return
        current_generation = getattr(self, "_right_widget_generation", 0)
        if generation is not None and generation != current_generation:
            return
        generation = current_generation
        try:
            height = self._pane_viewport_height(parent_frame)
        except (tk.TclError, AttributeError):
            return
        if height <= 1:
            return
        metrics = self._get_right_sidebar_layout_metrics(height)
        metrics_key = (generation, *metrics.values())
        if metrics_key == getattr(self, "_right_sidebar_layout_metrics", None):
            return
        try:
            parent_frame.configure(padding=(metrics["outer_padding"], metrics["outer_padding"]))
            parent_frame.grid_rowconfigure(5, weight=0, minsize=0)
            date_label = getattr(self, "date_label", None)
            if date_label is not None:
                date_label.configure(font=(self.DEFAULT_FONT, metrics["date_font"], 'bold'))
                date_label.grid_configure(pady=(0, metrics["date_gap"]))
            clock_label = getattr(self, "clock_label", None)
            if clock_label is not None:
                clock_label.configure(font=(self.DEFAULT_FONT, metrics["clock_font"], 'bold'))
                clock_label.grid_configure(pady=(0, metrics["clock_gap"]))
            for row in (2, 3, 4):
                parent_frame.grid_rowconfigure(
                    row,
                    weight=1,
                    minsize=metrics["primary_card_minsize"],
                    uniform="" if metrics["content_sized_cards"] else "primary_info_cards",
                )
            parent_frame.grid_rowconfigure(6, weight=0, minsize=0)
            parent_frame.grid_rowconfigure(7, weight=0, minsize=0)
            compact = metrics["content_sized_cards"]
            self.style.configure(
                'SidebarDetail.Secondary.TButton',
                padding=(6, 2),
            )
            for name in ('work_details_button', 'direct_sync_details_button'):
                button = getattr(self, name, None)
                if button is not None:
                    button.configure(style=(
                        'SidebarDetail.Secondary.TButton' if compact else 'Secondary.TButton'
                    ))
            work_details = getattr(self, 'work_details_button', None)
            if work_details is not None:
                work_details.grid_configure(pady=(0, 0 if compact else metrics['card_gap']))
            sync_details = getattr(self, 'direct_sync_details_button', None)
            if sync_details is not None:
                sync_details.pack_configure(pady=(0 if compact else 6, 0))
            for key in ("status", "direct_sync", "stopwatch"):
                card = getattr(self, "info_cards", {}).get(key)
                if card:
                    card["frame"].configure(padding=0 if compact else metrics["card_padding"])
                    card["frame"].grid_configure(pady=(0, 0 if compact else metrics["card_gap"]))
                    caption = card.get("label")
                    if caption is not None:
                        caption.configure(
                            font=(self.DEFAULT_FONT, 10)
                            if metrics["content_sized_cards"] else "",
                        )
                    card["value"].configure(
                        font=(self.DEFAULT_FONT, metrics["value_font"], 'bold'),
                        anchor='center',
                        justify='center',
                    )
            direct_sync_card = getattr(self, "info_cards", {}).get("direct_sync")
            if direct_sync_card:
                direct_sync_card["value"].configure(
                    font=(self.DEFAULT_FONT, metrics["secondary_value_font"], 'bold')
                )
            context_frame = getattr(self, "_right_context_frame", None)
            if context_frame is not None:
                context_frame.configure(padding=0 if compact else metrics["context_padding"])
                context_frame.grid_configure(pady=(0, metrics["card_gap"]))
            for caption in getattr(self, "_right_context_captions", ()):
                caption.configure(
                    font=(self.DEFAULT_FONT, 10)
                    if metrics["content_sized_cards"] else "",
                )
            context_value_font = metrics["context_value_font"]
            if context_value_font <= 0:
                token_fonts = getattr(getattr(self, "style_tokens", None), "fonts", None)
                context_value_font = int(
                    getattr(token_fonts, "section_title", max(13, int(15 * self.scale_factor)))
                )
            last_scan_value = getattr(self, "last_scan_value_label", None)
            if last_scan_value is not None:
                last_scan_value.configure(
                    font=(self.DEFAULT_FONT, context_value_font, 'bold'),
                    anchor='center',
                    justify='center',
                )
                last_scan_value.grid_configure(
                    pady=(0, 2) if metrics["content_sized_cards"] else
                    (3 if metrics["short_large_text"] else 4, 6 if metrics["short_large_text"] else 12)
                )
            context_separator = getattr(self, "_right_context_separator", None)
            if context_separator is not None:
                context_separator.grid_configure(
                    pady=(0, 2 if metrics["content_sized_cards"] else
                          6 if metrics["short_large_text"] else 10)
                )
            follow_up = getattr(self, "follow_up_label", None)
            if follow_up is not None:
                follow_up.configure(
                    font=(self.DEFAULT_FONT, context_value_font, 'bold'),
                    anchor='center',
                    justify='center',
                )
                follow_up.grid_configure(pady=(0 if metrics["content_sized_cards"] else
                                              3 if metrics["short_large_text"] else 4, 0))
            for key in ("avg_time", "best_time"):
                card = getattr(self, "info_cards", {}).get(key)
                if card:
                    card["frame"].configure(padding=0 if compact else metrics["secondary_card_padding"])
                    # Compact cards need compact captions too: the root's
                    # larger caption font wraps the best-time title and pushes
                    # both required values below the short sidebar.
                    caption = card.get("label")
                    if caption is not None:
                        caption.configure(
                            font=(self.DEFAULT_FONT, 10)
                            if not metrics["legend_visible"] else "",
                        )
                    card["value"].configure(
                        font=(self.DEFAULT_FONT, metrics["secondary_value_font"], 'bold'),
                        anchor='center',
                        justify='center',
                    )
            # Cache only after every widget in this generation accepted the
            # metrics.  A configure event during reconstruction must not make
            # a partially styled generation look complete.
            self._right_sidebar_layout_metrics = metrics_key
            self._apply_work_details_visibility()
        except (tk.TclError, AttributeError):
            return

    @staticmethod
    def _tree_available_width(tree: ttk.Treeview) -> int:
        try:
            tree_width = int(tree.winfo_width())
        except (AttributeError, TypeError, ValueError, tk.TclError):
            tree_width = 0
        if tree_width > 1:
            # Treeview already excludes its sibling scrollbar.  Keep a small
            # border gutter so the final heading never extends into the edge.
            return max(1, tree_width - 4)

        parent_frame = tree.master
        available_width = parent_frame.winfo_width()
        for child in parent_frame.winfo_children():
            try:
                is_scrollbar = child.winfo_class() == "TScrollbar"
            except (AttributeError, tk.TclError):
                try:
                    is_scrollbar = isinstance(child, ttk.Scrollbar)
                except TypeError:
                    is_scrollbar = False
            if is_scrollbar:
                try:
                    scrollbar_width = int(child.winfo_width())
                    if scrollbar_width <= 1:
                        scrollbar_width = int(child.winfo_reqwidth())
                except (AttributeError, TypeError, ValueError, tk.TclError):
                    scrollbar_width = 0
                available_width -= max(0, scrollbar_width)
                break
        return max(1, available_width - 4)

    def _apply_tree_row_styles(self, tree: ttk.Treeview) -> None:
        tree.tag_configure('even', background=self.COLOR_CARD_BG, foreground=self.COLOR_TEXT)
        tree.tag_configure('odd', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT)

    @staticmethod
    def _insert_tree_row(tree: ttk.Treeview, parent: str, index: str, *, values, iid=None, tags=()):
        try:
            return tree.insert(parent, index, values=values, iid=iid, tags=tags)
        except TypeError:
            return tree.insert(parent, index, values=values, iid=iid)

    def _tree_column_required_width(
        self,
        tree: ttk.Treeview,
        column_id: str,
        heading_text: str,
        *,
        fallback: int,
    ) -> int:
        """Return the measured width needed by a heading and current row values."""

        try:
            style_name = str(tree.cget("style") or "Treeview")
            body_spec = self.style.lookup(style_name, "font") or "TkDefaultFont"
            heading_spec = (
                self.style.lookup(f"{style_name}.Heading", "font")
                or "TkHeadingFont"
            )
            body_font = tkfont.Font(root=self.root, font=body_spec)
            heading_font = tkfont.Font(root=self.root, font=heading_spec)
            raw_columns = tree.cget("columns")
            if isinstance(raw_columns, (tuple, list)):
                columns = tuple(str(value) for value in raw_columns)
            else:
                columns = tuple(str(value) for value in tree.tk.splitlist(raw_columns))
            column_index = columns.index(column_id)
            widths = [int(heading_font.measure(str(heading_text or "")))]
            for item_id in tree.get_children():
                values = tuple(tree.item(item_id, "values") or ())
                if column_index < len(values):
                    widths.append(int(body_font.measure(str(values[column_index] or ""))))
            cell_gutter = max(18, int(round(12 * self.scale_factor)))
            return max(int(fallback), max(widths, default=0) + cell_gutter)
        except (
            AttributeError,
            RuntimeError,
            tk.TclError,
            TypeError,
            ValueError,
        ):
            return max(1, int(fallback))

    def _adjust_summary_tree_columns(self, event=None):
        if not (hasattr(self, 'summary_tree') and self.summary_tree.winfo_exists()):
            return
        available_width = self._tree_available_width(self.summary_tree)
        if available_width <= 1:
            return
        def apply_display_columns(columns) -> None:
            desired = tuple(columns)
            raw_current = self.summary_tree.cget("displaycolumns")
            if raw_current in ("#all", ("#all",), ["#all"]):
                raw_current = self.summary_tree.cget("columns")
            if isinstance(raw_current, (tuple, list)):
                current = tuple(str(value) for value in raw_current)
            else:
                current = tuple(str(raw_current or "").split())
            if current != desired:
                self.summary_tree["displaycolumns"] = desired

        scale = max(1.0, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        def apply_compact_columns() -> None:
            # The current-work card already carries the item name.  On a
            # narrow/large-text sidebar, keep the actionable historical keys
            # (code + completed count) fully readable instead of squeezing
            # three data columns into the same width.
            apply_display_columns(("item_code", "count"))
            count_fallback = max(52, int(round(32 * scale)), int(available_width * 0.16))
            count_width = self._tree_column_required_width(
                self.summary_tree,
                "count",
                "건",
                fallback=count_fallback,
            )
            item_required = self._tree_column_required_width(
                self.summary_tree,
                "item_code",
                "품목 코드",
                fallback=max(140, int(round(120 * scale))),
            )
            if item_required + count_width > available_width:
                count_width = max(
                    count_fallback,
                    min(count_width, max(1, available_width - item_required)),
                )
            count_width = min(count_width, max(1, available_width - 1))
            self.summary_tree.heading("item_code", text="품목 코드")
            self.summary_tree.heading("count", text="건")
            self.summary_tree.column(
                "item_code",
                width=max(1, available_width - count_width),
                stretch=tk.NO,
            )
            self.summary_tree.column(
                "count",
                width=count_width,
                stretch=tk.NO,
            )
        full_heading_threshold = int(round(540 * scale))
        if (
            bool(getattr(self, "_left_sidebar_compact", False))
            or available_width < full_heading_threshold
        ):
            apply_compact_columns()
            return

        # Full Korean headings need both a wider baseline than the old 420 px
        # cutoff and physical room for the configured Treeview heading font.
        # Prefer the compact wording whenever that room or the current row data
        # is unavailable at the live sidebar font size.
        headings = {"item_name_spec": "품목명", "item_code": "품목코드", "count": "완료 수량"}
        required_widths = {
            "item_name_spec": self._tree_column_required_width(
                self.summary_tree,
                "item_name_spec",
                headings["item_name_spec"],
                fallback=max(150, int(round(120 * scale))),
            ),
            "item_code": self._tree_column_required_width(
                self.summary_tree,
                "item_code",
                headings["item_code"],
                fallback=max(130, int(round(120 * scale))),
            ),
            "count": self._tree_column_required_width(
                self.summary_tree,
                "count",
                headings["count"],
                fallback=max(100, int(round(72 * scale))),
            ),
        }
        if sum(required_widths.values()) > available_width:
            apply_compact_columns()
            return

        apply_display_columns(("item_name_spec", "item_code", "count"))
        count_width = max(
            required_widths["count"],
            max(100, min(150, int(available_width * 0.22))),
        )
        code_width = max(
            required_widths["item_code"],
            max(130, min(210, int(available_width * 0.32))),
        )
        if (
            count_width
            + code_width
            + required_widths["item_name_spec"]
            > available_width
        ):
            count_width = required_widths["count"]
            code_width = required_widths["item_code"]
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
        scale = max(1.0, min(2.5, float(getattr(self, "scale_factor", 1.0) or 1.0)))
        def compact_widths() -> tuple[str, str, int, int]:
            item_heading, count_heading = "품목", "건"
            count_fallback = max(52, int(round(36 * scale)), int(available_width * 0.18))
            count_width = self._tree_column_required_width(
                self.parked_tree,
                "scan_count",
                count_heading,
                fallback=count_fallback,
            )
            item_required = self._tree_column_required_width(
                self.parked_tree,
                "item_name",
                item_heading,
                fallback=max(140, int(round(110 * scale))),
            )
            if item_required + count_width > available_width:
                count_width = max(
                    count_fallback,
                    min(count_width, max(1, available_width - item_required)),
                )
            return item_heading, count_heading, item_required, count_width

        full_heading_threshold = int(round(380 * scale))
        if available_width < full_heading_threshold:
            item_heading, count_heading, _item_required, count_width = compact_widths()
        else:
            item_heading, count_heading = "품목명", "스캔 수량"
            item_required = self._tree_column_required_width(
                self.parked_tree,
                "item_name",
                item_heading,
                fallback=max(160, int(round(120 * scale))),
            )
            count_required = self._tree_column_required_width(
                self.parked_tree,
                "scan_count",
                count_heading,
                fallback=max(128, int(round(84 * scale))),
            )
            if item_required + count_required > available_width:
                item_heading, count_heading, _item_required, count_width = compact_widths()
            else:
                count_width = max(
                    count_required,
                    max(128, min(180, int(available_width * 0.30))),
                )
                if item_required + count_width > available_width:
                    count_width = count_required
        count_width = min(count_width, max(1, available_width - 1))
        self.parked_tree.heading('item_name', text=item_heading)
        self.parked_tree.heading('scan_count', text=count_heading)
        self.parked_tree.column('scan_count', width=count_width, stretch=tk.NO)
        self.parked_tree.column('item_name', width=max(1, available_width - count_width), stretch=tk.NO)

    def _create_left_sidebar_content(self, parent_frame):
        self._left_sidebar_frame = parent_frame
        if getattr(self, "_left_sidebar_view", None) not in {"summary", "parked"}:
            self._left_sidebar_view = "summary"
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        top_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        self._left_top_frame = top_frame
        top_frame.grid(row=0, column=0, sticky='nsew', pady=(0, 10))
        top_frame.grid_columnconfigure(0, weight=1)
        header_frame = ttk.Frame(top_frame, style='Sidebar.TFrame')
        self._left_header_frame = header_frame
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        header_frame.grid_columnconfigure(0, weight=1)
        worker_info_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        self._worker_info_frame = worker_info_frame
        worker_info_frame.grid(row=0, column=0, sticky='ew')
        worker_info_frame.grid_columnconfigure(0, weight=1)
        self.worker_info_label = ttk.Label(
            worker_info_frame,
            text=f"작업자: {display_operator_name(self.worker_name)}",
            style='Sidebar.TLabel',
            justify='left',
        )
        self.worker_info_label.grid(row=0, column=0, sticky='ew')
        self._bind_label_to_container_width(self.worker_info_label, worker_info_frame, padding=8)
        buttons_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        self._worker_buttons_frame = buttons_frame
        buttons_frame.grid(row=1, column=0, sticky='ew', pady=(6, 0))
        self.change_worker_button = ttk.Button(
            buttons_frame,
            text="작업자 변경",
            command=self.change_worker,
            style='Secondary.TButton',
        )
        self.change_worker_button.pack(fill=tk.X)

        current_work_frame = ttk.Frame(top_frame, style='Card.TFrame', padding=12)
        self._current_work_frame = current_work_frame
        current_work_frame.grid(row=1, column=0, sticky='ew', pady=(0, 14))
        current_work_frame.grid_columnconfigure(0, weight=1)
        self.current_work_title_label = ttk.Label(
            current_work_frame,
            text="현재 작업",
            style='Card.Subtle.TLabel',
            anchor='w',
        )
        self.current_work_title_label.grid(row=0, column=0, sticky='ew')
        self.current_work_name_label = ttk.Label(
            current_work_frame,
            text="현품표 대기",
            style='Card.Value.TLabel',
            anchor='w',
            justify='left',
        )
        self.current_work_name_label.grid(row=1, column=0, sticky='ew', pady=(3, 2))
        self.current_work_spec_label = ttk.Label(
            current_work_frame,
            text="",
            style='Card.Subtle.TLabel',
            anchor='w',
            justify='left',
        )
        self.current_work_spec_label.grid(row=2, column=0, sticky='ew', pady=(0, 2))
        self.current_work_spec_label.grid_remove()
        self.current_work_detail_label = ttk.Label(
            current_work_frame,
            text="품목 코드 -\n목표 -",
            style='Card.Subtle.TLabel',
            anchor='w',
            justify='left',
        )
        self.current_work_detail_label.grid(row=3, column=0, sticky='ew')
        self._bind_label_to_container_width(self.current_work_name_label, current_work_frame, padding=24)
        self._bind_label_to_container_width(self.current_work_spec_label, current_work_frame, padding=24)
        self._bind_label_to_container_width(self.current_work_detail_label, current_work_frame, padding=24)
        switch_frame = ttk.Frame(top_frame, style='Sidebar.TFrame')
        self._left_view_switch_frame = switch_frame
        switch_frame.grid_columnconfigure(0, weight=1)
        self.left_context_switch_button = ttk.Button(
            switch_frame,
            text="보류 0건 보기",
            command=self._toggle_left_sidebar_view,
            style='Secondary.TButton',
            width=0,
        )
        self.left_context_switch_button.grid(row=0, column=0, sticky='ew')
        switch_frame.grid_remove()

        self.summary_title_label = ttk.Label(
            top_frame,
            text="누적 작업 현황",
            style='Subtle.TLabel',
            font=(self.DEFAULT_FONT, int(14*self.scale_factor),'bold'),
            justify='left',
        )
        self.summary_title_label.grid(row=2, column=0, sticky='ew', pady=(0,10))
        self._bind_label_to_container_width(self.summary_title_label, top_frame, padding=8)
        tree_frame = ttk.Frame(top_frame)
        self._summary_tree_frame = tree_frame
        tree_frame.grid(row=3, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(3, weight=2)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        cols = ('item_name_spec', 'item_code', 'count')
        self.summary_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', style='Sidebar.Treeview')
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

        # Bind to the Treeview itself.  Its parent receives <Configure> before
        # geometry propagation finishes, so reading the child width there can
        # use the previous frame's size during compact/wide round trips.
        self.summary_tree.bind('<Configure>', self._adjust_summary_tree_columns)
        self.root.after_idle(self._adjust_summary_tree_columns)

        self.parked_title_label = ttk.Label(
            top_frame,
            text="보류 작업 (더블클릭으로 복원)",
            style='Subtle.TLabel',
            font=(self.DEFAULT_FONT, int(12*self.scale_factor),'bold'),
            justify='left',
        )
        self.parked_title_label.grid(row=4, column=0, sticky='ew', pady=(20,10))
        self._bind_label_to_container_width(self.parked_title_label, top_frame, padding=8)
        parked_tree_frame = ttk.Frame(top_frame)
        self._parked_tree_frame = parked_tree_frame
        parked_tree_frame.grid(row=5, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(5, weight=1)
        parked_tree_frame.grid_columnconfigure(0, weight=1)
        parked_tree_frame.grid_rowconfigure(0, weight=1)
        parked_cols = ('item_name', 'scan_count')
        self.parked_tree = ttk.Treeview(parked_tree_frame, columns=parked_cols, show='headings', style='Sidebar.Treeview', height=4)
        self.parked_tree.heading('item_name', text='품목명')
        self.parked_tree.heading('scan_count', text='스캔 수량')
        self.parked_tree.column('item_name', anchor='w', stretch=tk.YES)
        self.parked_tree.column('scan_count', width=100, anchor='center', stretch=tk.NO)
        self._apply_tree_row_styles(self.parked_tree)
        self.parked_tree.grid(row=0, column=0, sticky='nsew')
        sb2 = ttk.Scrollbar(parked_tree_frame, orient='vertical', command=self.parked_tree.yview)
        self.parked_tree['yscrollcommand'] = sb2.set
        sb2.grid(row=0, column=1, sticky='ns')
        self.parked_tree.bind('<Configure>', self._adjust_parked_tree_columns)
        self.root.after_idle(self._adjust_parked_tree_columns)
        self.parked_tree.bind("<Double-1>", self.on_parked_tray_select)
        self._update_parked_recovery_affordance()
        bottom_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        bottom_frame.grid(row=1, column=0, sticky='nsew')
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_rowconfigure(1, weight=1)
        self.tray_image_checkbox = tk.Checkbutton(
            bottom_frame, text="트레이 이미지 보기", variable=self.show_tray_image_var,
            command=self._update_tray_image_display, font=(self.DEFAULT_FONT, self.style_tokens.fonts.body),
            background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT,
            activebackground=self.COLOR_SIDEBAR_BG, activeforeground=self.COLOR_TEXT,
            highlightthickness=0, anchor='w', justify='left',
        )
        self.tray_image_checkbox.grid(row=0, column=0, sticky='w', pady=(10, 5))
        self.tray_image_label = ttk.Label(bottom_frame, background=self.COLOR_SIDEBAR_BG, anchor='center')
        self.tray_image_label.grid(row=1, column=0, sticky='nsew', pady=(0, 10))
        parent_frame.bind('<Configure>', lambda _event: self._apply_left_sidebar_layout())
        self._apply_left_sidebar_layout()

    def _create_center_content(self, parent_frame):
        self._center_content_frame = parent_frame
        previous_job = getattr(self, "_scanned_listbox_layout_job", None)
        if previous_job:
            try:
                self.root.after_cancel(previous_job)
            except (AttributeError, tk.TclError):
                pass
        previous_notice_job = getattr(self, "_notice_message_wrap_job", None)
        if previous_notice_job:
            try:
                self.root.after_cancel(previous_notice_job)
            except (AttributeError, tk.TclError):
                pass
        if hasattr(parent_frame, "unbind"):
            try:
                parent_frame.unbind('<Configure>')
            except (AttributeError, tk.TclError):
                pass
        self._center_widget_generation = getattr(self, "_center_widget_generation", 0) + 1
        center_generation = self._center_widget_generation
        self._center_layout_metrics = None
        parent_frame.grid_columnconfigure(0, weight=1)
        self._scanned_listbox_parent_frame = parent_frame
        self._scanned_listbox_layout_job = None
        self._scanned_listbox_layout_metrics = None
        self._notice_message_wrap_job = None
        self._notice_message_wrap_metrics = None
        initial_center_metrics = self._get_center_layout_metrics(720, 720)
        parent_frame.grid_rowconfigure(
            5,
            weight=2,
            minsize=initial_center_metrics["list_minsize"],
        )
        scanned_metrics = self._get_scanned_listbox_metrics(
            720,
            720,
            initial_center_metrics["list_minsize"],
        )
        hero_frame = ttk.Frame(parent_frame, style='TFrame')
        self._center_hero_frame = hero_frame
        hero_frame.grid(row=0, column=0, sticky='ew', pady=(10, 20))
        hero_frame.grid_columnconfigure(0, weight=1)
        self.stage_label = ttk.Label(hero_frame, text="1 / 2 · 현품표 스캔", style='Stage.TLabel', anchor='center')
        self.stage_label.grid(row=0, column=0, sticky='ew', pady=(0, 4))
        self.current_item_label = ttk.Label(
            hero_frame,
            text="",
            style='ItemInfo.TLabel',
            justify='center',
            anchor='center',
        )
        self.current_item_label.grid(row=1, column=0, sticky='ew')
        self._bind_label_to_container_width(self.current_item_label, hero_frame, padding=60, min_wraplength=240)
        self.main_count_label = ttk.Label(parent_frame, text=f"0 / {self.TRAY_SIZE}", style='MainCounter.TLabel', anchor='center')
        self.main_count_label.grid(row=1, column=0, sticky='ew', pady=(10, 20))
        self.main_progress_bar = ttk.Progressbar(parent_frame, orient='horizontal', mode='determinate', maximum=self.TRAY_SIZE, style='Big.Horizontal.TProgressbar')
        self.main_progress_bar.grid(row=2, column=0, sticky='ew', pady=(0, 20), padx=20)
        vcmd = (self.root.register(self._validate_barcode_input), '%P')
        self.scan_entry = tk.Entry(parent_frame, justify='center', font=(self.DEFAULT_FONT, initial_center_metrics["entry_font"], 'bold'), bd=1, relief=tk.SOLID, bg=self.COLOR_INPUT_BG, fg=self.COLOR_TEXT, insertbackground=self.COLOR_PRIMARY, selectbackground=self.COLOR_PRIMARY, selectforeground='white', highlightbackground=self.COLOR_PRIMARY_SOFT, highlightcolor=self.COLOR_PRIMARY, highlightthickness=2, validate='key', validatecommand=vcmd)
        self.scan_entry.grid(row=3, column=0, sticky='ew', ipady=initial_center_metrics["entry_ipady"], padx=30)
        self.scan_entry.bind('<Return>', self.process_barcode)
        self.notice_frame = tk.Frame(
            parent_frame,
            bg=self.COLOR_SURFACE_ALT,
            bd=0,
            highlightbackground=self.COLOR_BORDER,
            highlightcolor=self.COLOR_BORDER,
            highlightthickness=1,
        )
        self.notice_frame.grid(row=4, column=0, sticky='ew', padx=30, pady=(10, 0))
        self.notice_frame.grid_columnconfigure(1, weight=1)
        self.notice_title_label = tk.Label(
            self.notice_frame,
            text="스캐너 준비",
            bg=self.COLOR_SURFACE_ALT,
            fg=self.COLOR_TEXT,
            font=(self.DEFAULT_FONT, initial_center_metrics["notice_title_font"], 'bold'),
            anchor='w',
        )
        self.notice_title_label.grid(row=0, column=0, sticky='w', padx=(12, 8), pady=8)
        self.notice_message_label = tk.Label(
            self.notice_frame,
            text="현품표 또는 제품 바코드를 스캔하세요.",
            bg=self.COLOR_SURFACE_ALT,
            fg=self.COLOR_TEXT_SUBTLE,
            font=(self.DEFAULT_FONT, initial_center_metrics["notice_message_font"]),
            anchor='w',
            justify='left',
        )
        self.notice_message_label.grid(row=0, column=1, sticky='ew', padx=8, pady=8)
        self.notice_message_label.bind(
            '<Configure>',
            lambda event, generation=center_generation: self._schedule_notice_message_wrap_refresh(
                event,
                generation=generation,
            ),
        )
        self.notice_ack_button = tk.Button(
            self.notice_frame,
            text="확인",
            command=self._acknowledge_active_notice,
            bg=self.COLOR_SIDEBAR_BG,
            fg=self.COLOR_TEXT_SUBTLE,
            disabledforeground=self.COLOR_BORDER_STRONG,
            relief='flat',
            state=tk.DISABLED,
            padx=12,
            pady=4,
        )
        self.notice_ack_button.grid(row=0, column=2, sticky='e', padx=(8, 10), pady=6)
        self.notice_ack_button.bind('<Return>', lambda _event: self._acknowledge_active_notice())
        self.notice_ack_button.bind('<Escape>', lambda _event: self._acknowledge_active_notice())
        self.phs_label_exchange_button = ttk.Button(
            self.notice_frame,
            text="현품표 교체",
            command=self._on_phs_label_exchange_shortcut,
            style="Secondary.TButton",
        )
        self.phs_label_exchange_button.grid(
            row=1,
            column=0,
            sticky="w",
            padx=(12, 8),
            pady=(0, 8),
        )
        self.phs_active_label_info_label = tk.Label(
            self.notice_frame,
            text="F8 → 현재/완료 이적 현품표 스캔 → F8 실행",
            bg=self.COLOR_SURFACE_ALT,
            fg=self.COLOR_TEXT_SUBTLE,
            font=(self.DEFAULT_FONT, max(9, initial_center_metrics["notice_message_font"] - 1)),
            anchor="w",
            justify="left",
        )
        self.phs_active_label_info_label.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky="ew",
            padx=(8, 10),
            pady=(0, 8),
        )
        self.phs_label_exchange_frame = ttk.Frame(
            self.notice_frame,
            style="TFrame",
        )
        self.phs_label_exchange_frame.grid(
            row=2,
            column=0,
            columnspan=3,
            sticky="ew",
            padx=10,
            pady=(0, 10),
        )
        self.phs_label_exchange_frame.grid_columnconfigure(3, weight=1)
        self.phs_label_exchange_close_button = ttk.Button(
            self.phs_label_exchange_frame,
            text="교체 화면 닫기",
            command=self._close_phs_label_exchange_panel,
            style="Secondary.TButton",
        )
        self.phs_label_exchange_close_button.grid(
            row=2, column=0, columnspan=4, sticky="e", pady=(6, 0),
        )
        self.phs_reconciliation_instruction_label = ttk.Label(
            self.phs_label_exchange_frame,
            text="현재 또는 완료된 이적 현품표를 스캔하세요.",
            style="TLabel",
        )
        self.phs_reconciliation_instruction_label.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky="w",
            padx=(0, 6),
        )
        self.phs_label_legacy_fallback_button = ttk.Button(
            self.phs_label_exchange_frame,
            text="보조 교환 (Shift+F8)",
            command=self._show_phs_label_legacy_single_fallback,
            style="Secondary.TButton",
        )
        self.phs_label_legacy_fallback_button.grid(
            row=0,
            column=3,
            sticky="e",
            padx=(0, 6),
        )
        self.phs_label_legacy_single_controls_frame = ttk.Frame(
            self.phs_label_exchange_frame,
            style="TFrame",
        )
        self.phs_label_legacy_single_controls_frame.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky="w",
        )
        ttk.Label(
            self.phs_label_legacy_single_controls_frame,
            text="교환 작업일",
            style="TLabel",
        ).grid(row=0, column=0, sticky="w", padx=(0, 6))
        has_tk_runtime = hasattr(self.root, "tk")
        self.phs_label_target_date_var = (
            tk.StringVar(
                master=self.root,
                value=datetime.date.today().isoformat(),
            )
            if has_tk_runtime
            else _LocalValueVar(datetime.date.today().isoformat())
        )
        self.phs_label_target_date_entry = tk.Entry(
            self.phs_label_legacy_single_controls_frame,
            textvariable=self.phs_label_target_date_var,
            width=12,
        )
        self.phs_label_target_date_entry.grid(
            row=0, column=1, sticky="w", padx=(0, 6)
        )
        self.phs_label_candidate_load_button = ttk.Button(
            self.phs_label_legacy_single_controls_frame,
            text="후보 조회",
            command=self._load_phs_label_exchange_candidates,
            style="Secondary.TButton",
        )
        self.phs_label_candidate_load_button.grid(
            row=0, column=2, sticky="w", padx=(0, 6)
        )
        self.phs_label_candidate_var = (
            tk.StringVar(master=self.root, value="")
            if has_tk_runtime
            else _LocalValueVar("")
        )
        if has_tk_runtime:
            self.phs_label_candidate_combo = ttk.Combobox(
                self.phs_label_exchange_frame,
                textvariable=self.phs_label_candidate_var,
                values=(),
                state="readonly",
                width=38,
            )
        else:
            self.phs_label_candidate_combo = tk.Entry(
                self.phs_label_exchange_frame,
                textvariable=self.phs_label_candidate_var,
                width=38,
            )
        self.phs_label_candidate_combo.grid(
            row=0, column=3, sticky="ew", padx=(0, 6)
        )
        self.phs_label_exchange_execute_button = ttk.Button(
            self.phs_label_exchange_frame,
            text=("서버 지시 교체 실행" if getattr(self, "_phs_reconciliation_context", None)
                  else "선택 교환 실행"),
            command=self._execute_selected_phs_label_exchange,
            style="Success.TButton",
        )
        self.phs_label_exchange_execute_button.grid(
            row=0, column=4, sticky="e"
        )
        self.phs_label_reprint_confirm_var = (
            tk.BooleanVar(master=self.root, value=False)
            if has_tk_runtime
            else _LocalValueVar(False)
        )
        if has_tk_runtime:
            self.phs_label_reprint_confirm_check = ttk.Checkbutton(
                self.phs_label_exchange_frame,
                text="이전 실물 출력 확인 후 재출력 승인",
                variable=self.phs_label_reprint_confirm_var,
                style="TCheckbutton",
            )
        else:
            self.phs_label_reprint_confirm_check = tk.Button(
                self.phs_label_exchange_frame,
                text="이전 실물 출력 확인 후 재출력 승인",
            )
        self.phs_label_reprint_confirm_check.grid(
            row=1,
            column=0,
            columnspan=5,
            sticky="w",
            pady=(6, 0),
        )
        self._set_phs_label_exchange_panel_mode(
            reconciliation_mode=(
                self._phs_reconciliation_exchange_available()
                and not getattr(self, "_phs_legacy_single_fallback_mode", False)
            )
        )
        if not getattr(self, "_phs_label_exchange_panel_open", False):
            if hasattr(self.phs_label_exchange_frame, "grid_remove"):
                self.phs_label_exchange_frame.grid_remove()
            else:
                self.phs_label_exchange_frame.grid_forget()
        scan_list_frame = ttk.Frame(parent_frame, style='TFrame')
        self._scan_list_frame = scan_list_frame
        scan_list_frame.grid(row=5, column=0, sticky='nsew')
        scan_list_frame.grid_columnconfigure(0, weight=1)
        scan_list_frame.grid_rowconfigure(1, weight=1)
        self.scanned_list_header_label = ttk.Label(
            scan_list_frame,
            text="현재 트레이 스캔 목록 · 0건",
            style='Subtle.TLabel',
            anchor='w',
            font=(self.DEFAULT_FONT, scanned_metrics["header_font_size"], 'bold'),
        )
        self.scanned_list_header_label.grid(
            row=0,
            column=0,
            columnspan=2,
            sticky='ew',
            padx=scanned_metrics["horizontal_pad"],
            pady=(scanned_metrics["top_pady"], 6),
        )
        self.scanned_listbox = tk.Listbox(scan_list_frame, font=(self.DEFAULT_FONT, scanned_metrics["font_size"]), relief=tk.SOLID, bd=1, bg=self.COLOR_CARD_BG, fg=self.COLOR_TEXT, highlightbackground=self.COLOR_BORDER, highlightcolor=self.COLOR_PRIMARY, highlightthickness=1, justify='center', selectbackground=self.COLOR_PRIMARY, selectforeground='white', activestyle='none', height=scanned_metrics["visible_rows"])
        self.scanned_listbox.grid(row=1, column=0, sticky='nsew', padx=scanned_metrics["horizontal_pad"])
        self.scanned_list_scrollbar = ttk.Scrollbar(scan_list_frame, orient='vertical', command=self.scanned_listbox.yview)
        self.scanned_listbox.configure(yscrollcommand=self.scanned_list_scrollbar.set)
        self.scanned_list_scrollbar.grid(row=1, column=1, sticky='ns', padx=(0, scanned_metrics["horizontal_pad"]))
        parent_frame.bind(
            '<Configure>',
            lambda event, generation=center_generation: self._schedule_scanned_listbox_layout_refresh(
                event,
                generation=generation,
            ),
        )
        self.scanned_listbox.bind(
            '<Configure>',
            lambda event, generation=center_generation: self._schedule_scanned_listbox_layout_refresh(
                event,
                generation=generation,
            ),
        )
        self.root.after(0, self._apply_scanned_listbox_layout, center_generation)
        button_frame = ttk.Frame(parent_frame)
        self._center_button_frame = button_frame
        button_frame.grid(row=6, column=0, sticky='ew', pady=(30, 0), padx=20)

        self.submit_tray_button = ttk.Button(button_frame, text="트레이 제출", command=self.submit_current_tray, style='Success.TButton', width=0)
        self.undo_button = ttk.Button(button_frame, text="마지막 스캔 취소", command=self.undo_last_scan, state=tk.DISABLED, style='Secondary.TButton', width=0)
        self.park_button = ttk.Button(button_frame, text="트레이 보류", command=self.park_current_tray, style='Warning.TButton', width=0)
        self.operations_button = ttk.Button(button_frame, text="운영 작업 ▾", command=self._show_operations_menu, style='Secondary.TButton', width=0)
        # Secondary actions are created on demand in the operations menu.
        self._center_action_buttons = [
            self.undo_button,
            self.park_button,
            self.submit_tray_button,
            self.operations_button,
        ]
        for button in self._center_action_buttons:
            button.bind(
                '<Configure>',
                lambda event, generation=center_generation: self._schedule_scanned_listbox_layout_refresh(
                    event, generation=generation,
                ),
            )
        self._center_action_groups = []
        self._layout_center_action_buttons(720, initial_center_metrics["button_pad_x"])
        self._update_action_button_states()
        self._render_warning_state()

    def _create_right_sidebar_content(self, parent_frame):
        self._right_sidebar_frame = parent_frame
        self._work_details_expanded = getattr(self, "_work_details_expanded", False)
        if hasattr(parent_frame, "unbind"):
            try:
                parent_frame.unbind('<Configure>')
            except (AttributeError, tk.TclError):
                pass
        self._right_widget_generation = getattr(self, "_right_widget_generation", 0) + 1
        right_generation = self._right_widget_generation
        self._right_sidebar_layout_metrics = None
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        self.date_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(18*self.scale_factor),'bold'))
        self.date_label.grid(row=0, column=0, pady=(0,5))
        self.clock_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(24*self.scale_factor),'bold'))
        self.clock_label.grid(row=1, column=0, pady=(0,20))
        self.info_cards = {
            'status': self._create_info_card(parent_frame, "현재 작업 상태"),
            'direct_sync': self._create_info_card(parent_frame, "저장 전송"),
            'stopwatch': self._create_info_card(parent_frame, "트레이 소요"),
        }
        self.info_cards['status']['frame'].grid(row=2, column=0, sticky='nsew', pady=(0, 10))
        self.info_cards['direct_sync']['frame'].grid(row=3, column=0, sticky='nsew', pady=(0, 10))
        self.info_cards['stopwatch']['frame'].grid(row=4, column=0, sticky='nsew', pady=(0, 10))
        self.info_cards['direct_sync']['value'].configure(
            text="전송 상태 확인 중",
        )
        self.direct_sync_details_button = ttk.Button(
            self.info_cards['direct_sync']['frame'],
            text="상세",
            command=self._show_direct_sync_status_details,
            style='Secondary.TButton',
            width=0,
        )
        self.direct_sync_details_button.pack(
            before=self.info_cards['direct_sync']['label'],
            side='right', anchor='n', padx=(4, 0),
        )
        for widget in self.info_cards['direct_sync'].values():
            try:
                widget.bind('<Button-1>', lambda _event: self._show_direct_sync_status_details())
                widget.configure(cursor='hand2')
            except (AttributeError, tk.TclError):
                pass

        context_frame = ttk.Frame(parent_frame, style='Card.TFrame', padding=16)
        self._right_context_frame = context_frame
        self.work_details_button = ttk.Button(
            parent_frame,
            text="작업 상세 ▸",
            command=self._toggle_work_details,
            style='Secondary.TButton',
        )
        self.work_details_button.grid(row=5, column=0, sticky='ew', pady=(0, 10))
        context_frame.grid(row=6, column=0, sticky='nsew', pady=(0, 10))
        context_frame.grid_columnconfigure(0, weight=1)
        last_scan_caption = ttk.Label(
            context_frame,
            text="마지막 정상 스캔",
            style='Card.Subtle.TLabel',
            anchor='w',
        )
        last_scan_caption.grid(row=0, column=0, sticky='ew')
        self.last_scan_value_label = ttk.Label(
            context_frame,
            text="-",
            style='Card.Value.TLabel',
            anchor='center',
            justify='center',
        )
        self.last_scan_value_label.grid(row=1, column=0, sticky='ew', pady=(4, 12))
        self._bind_label_to_container_width(self.last_scan_value_label, context_frame, padding=32)
        context_separator = ttk.Separator(context_frame, orient='horizontal')
        self._right_context_separator = context_separator
        context_separator.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        follow_up_caption = ttk.Label(
            context_frame,
            text="다음 행동",
            style='Card.Subtle.TLabel',
            anchor='w',
        )
        follow_up_caption.grid(row=3, column=0, sticky='ew')
        self._right_context_captions = (last_scan_caption, follow_up_caption)
        self.follow_up_label = ttk.Label(
            context_frame,
            text="현품표 라벨을 스캔하세요.",
            style='Card.Value.TLabel',
            anchor='center',
            justify='center',
        )
        self.follow_up_label.grid(row=4, column=0, sticky='ew', pady=(4, 0))
        self._bind_label_to_container_width(self.follow_up_label, context_frame, padding=32)

        secondary_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        self._secondary_stats_frame = secondary_frame
        secondary_frame.grid(row=7, column=0, sticky='ew')
        for column in (0, 1):
            secondary_frame.grid_columnconfigure(column, weight=1, uniform="secondary_stats")
        self.info_cards['avg_time'] = self._create_info_card(secondary_frame, "평균")
        self.info_cards['best_time'] = self._create_info_card(secondary_frame, "30일 최고")
        self.info_cards['avg_time']['frame'].configure(style='SecondaryCard.TFrame', padding=10)
        self.info_cards['avg_time']['label'].configure(style='SecondaryCard.Subtle.TLabel')
        self.info_cards['avg_time']['value'].configure(style='SecondaryCard.Value.TLabel')
        self.info_cards['best_time']['frame'].configure(style='SecondaryCard.TFrame', padding=10)
        self.info_cards['best_time']['label'].configure(style='SecondaryCard.Subtle.TLabel')
        self.info_cards['best_time']['value'].configure(style='SecondaryCard.Value.TLabel')
        self.info_cards['avg_time']['frame'].grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        self.info_cards['best_time']['frame'].grid(row=0, column=1, sticky='nsew', padx=(5, 0))
        self._apply_work_details_visibility()
        parent_frame.bind(
            '<Configure>',
            lambda event, generation=right_generation: self._apply_right_sidebar_layout(
                event,
                generation=generation,
            ),
        )
        self.root.after(
            0,
            lambda generation=right_generation: self._apply_right_sidebar_layout(
                generation=generation,
            ),
        )
        self._apply_right_sidebar_layout(generation=right_generation)
        self._render_warning_state()
        if hasattr(self.root, "tk"):
            self._schedule_direct_sync_health_refresh(delay_ms=0)

    def _toggle_work_details(self) -> None:
        self._work_details_expanded = not getattr(self, "_work_details_expanded", False)
        self._apply_work_details_visibility()
        if not self._work_details_expanded:
            self._schedule_focus_return()

    def _apply_work_details_visibility(self) -> None:
        expanded = bool(getattr(self, "_work_details_expanded", False))
        button = getattr(self, "work_details_button", None)
        if button is None:
            return
        button.configure(text="작업 상세 ▾" if expanded else "작업 상세 ▸")
        for name in ("_right_context_frame", "_secondary_stats_frame"):
            frame = getattr(self, name, None)
            if frame is not None:
                frame.grid() if expanded else frame.grid_remove()

    def _create_info_card(self, parent: ttk.Frame, label_text: str) -> Dict[str, ttk.Widget]:
        card = ttk.Frame(parent, style='Card.TFrame', padding=20)
        label = ttk.Label(
            card,
            text=label_text,
            style='Card.Subtle.TLabel',
            anchor='center',
            justify='center',
        )
        label.pack(anchor='center')
        self._bind_label_to_container_width(label, card, padding=40)
        value_label = ttk.Label(
            card,
            text="-",
            style='Card.Value.TLabel',
            anchor='center',
            justify='center',
        )
        value_label.pack(fill='x', expand=True, anchor='center')
        self._bind_label_to_container_width(value_label, value_label, padding=8)
        return {'frame': card, 'label': label, 'value': value_label}

    def _validate_barcode_input(self, p_text: str) -> bool:
        if not p_text:
            return True
        if re.search(r'[ㄱ-ㅎㅏ-ㅣ가-힣]', p_text):
            self.show_fullscreen_warning("입력 모드 오류", "한글이 입력되었습니다. 한/영 키를 눌러주세요.", self.COLOR_DANGER)
            return False
        return True

    def _schedule_focus_return(self, delay_ms: int = 50):
        previous_job = getattr(self, "focus_return_job", None)
        if previous_job:
            try:
                self.root.after_cancel(previous_job)
            except (tk.TclError, AttributeError):
                pass
        self.focus_return_job = self.root.after(max(0, int(delay_ms)), self._return_focus_to_scan_entry)

    def _return_focus_to_scan_entry(self):
        try:
            if self._warning_state_presenter().state.is_blocking:
                self.focus_return_job = None
                return
            if hasattr(self, 'scan_entry') and self.scan_entry.winfo_exists() and self.root.focus_get() != self.scan_entry:
                self.scan_entry.focus_set()
            self.focus_return_job = None
        except Exception as e:
            print(f"포커스 설정 오류: {e}")

    def _update_operator_context(self) -> None:
        name_label = getattr(self, "current_work_name_label", None)
        spec_label = getattr(self, "current_work_spec_label", None)
        detail_label = getattr(self, "current_work_detail_label", None)
        if name_label is None or detail_label is None:
            return
        tray = getattr(self, "current_tray", None)
        active_tray = bool(getattr(tray, "master_label_code", ""))
        try:
            if active_tray:
                item_name = str(getattr(tray, "item_name", "") or "이름 미등록")
                item_spec = str(getattr(tray, "item_spec", "") or "").strip()
                item_code = str(getattr(tray, "item_code", "") or "-")
                target = max(0, int(getattr(tray, "tray_size", 0) or 0))
                name_label.configure(text=item_name)
                if spec_label is not None:
                    spec_label.configure(text=item_spec)
                    if item_spec:
                        spec_label.grid()
                    else:
                        spec_label.grid_remove()
                detail_label.configure(text=f"품목 코드 {item_code}\n목표 {target}개")
            else:
                name_label.configure(text="현품표 대기")
                if spec_label is not None:
                    spec_label.configure(text="")
                    spec_label.grid_remove()
                detail_label.configure(text="품목 코드 -\n목표 -")
        except (tk.TclError, AttributeError, TypeError, ValueError):
            return

    def _active_tray_scan_instruction(self) -> str:
        tray = self.current_tray
        count = len(tray.scanned_barcodes)
        if int(tray.tray_size or 0) > 0 and count >= int(tray.tray_size):
            if getattr(self, "_completion_lane_busy", False):
                return "중앙 이적 확인 중입니다. 현재 트레이를 유지하세요."
            return "제품 스캔이 끝났습니다. '제출'로 이적 완료를 확인하세요."
        return "첫 번째 제품을 스캔하세요." if not count else "다음 제품을 스캔하세요."

    def _update_current_item_label(self, instruction: str = ""):
        self._update_operator_context()
        if not (hasattr(self, 'current_item_label') and self.current_item_label.winfo_exists()): return
        snapshot = getattr(self, "_preflight_hold_snapshot", None)

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
        elif getattr(self, "_master_preflight_pending", False):
            held_count = (
                len(snapshot.items)
                if isinstance(snapshot, PreflightHoldSnapshot)
                else 0
            )
            self.current_item_label['text'] = (
                f"중앙 검사 완료 수량 확인 중 · 보류 {held_count}건"
            )
            self.current_item_label['foreground'] = self.COLOR_PRIMARY
            return
        elif (
            isinstance(snapshot, PreflightHoldSnapshot)
            and snapshot.state == HOLD_LOOKUP_FAILED
        ):
            self.current_item_label['text'] = (
                f"중앙 조회 실패 · 보류 {len(snapshot.items)}건 (삭제되지 않음)"
            )
            self.current_item_label['foreground'] = self.COLOR_DANGER
            return

        # 기본 작업 상태 메시지
        if self.current_tray.master_label_code:
            if not instruction:
                instruction = self._active_tray_scan_instruction()
            self.current_item_label['text'] = instruction.strip()
            self.current_item_label['foreground'] = self.COLOR_TEXT
        else:
            self.current_item_label['text'] = "현품표 라벨을 스캔하세요."
            self.current_item_label['foreground'] = self.COLOR_TEXT_SUBTLE
    
    def _cancel_master_preflight(self) -> None:
        self._master_preflight_epoch = int(getattr(self, "_master_preflight_epoch", 0)) + 1
        poll_job = getattr(self, "_master_preflight_poll_job", None)
        if poll_job:
            try:
                self.root.after_cancel(poll_job)
            except (tk.TclError, AttributeError):
                pass
        self._master_preflight_poll_job = None
        self._master_preflight_pending = False

    def _settle_stale_preflight_result(
        self,
        result: Sequence[Any],
        *,
        reason: str,
    ) -> None:
        """Preserve durable hold ownership when a late lookup may not render."""

        self._master_preflight_pending = False
        store = self._preflight_hold_store()
        if not self._preflight_context_blocks_mutation():
            return
        self._set_preflight_scan_input_locked(True)
        if not getattr(self, "_ui_close_requested", False):
            self._update_action_button_states()

        def settle() -> PreflightHoldSnapshot:
            snapshot = store.load()
            if snapshot.state == HOLD_DRAINING:
                return snapshot
            return store.mark_failed(error_code="PHS2_PREFLIGHT_STALE_RESULT")

        def finish(snapshot: PreflightHoldSnapshot) -> None:
            self._preflight_hold_snapshot = snapshot
            self._preflight_hold_draining = snapshot.state == HOLD_DRAINING
            if not getattr(self, "_ui_close_requested", False):
                self.show_status_message(
                    f"늦은 중앙 조회 결과를 보류 상태로 정리했습니다 · "
                    f"보류 {len(snapshot.items)}건",
                    self.COLOR_DANGER,
                    duration=0,
                )

        def fail(_exc: BaseException) -> None:
            if not getattr(self, "_ui_close_requested", False):
                self.show_status_message(
                    "늦은 중앙 조회 결과를 정리하지 못했습니다. 보류 파일을 유지하고 "
                    "관리자에게 문의하세요.",
                    self.COLOR_DANGER,
                    duration=0,
                )

        admission = self._preflight_hold_writer().submit(
            settle,
            finish,
            fail,
        )
        if not admission.accepted:
            if not getattr(self, "_ui_close_requested", False):
                self.show_status_message(
                    "늦은 중앙 조회 결과의 보류 정리가 대기 중입니다. 입력은 "
                    "접수되지 않았습니다.",
                    self.COLOR_DANGER,
                    duration=0,
                )

    def _activate_master_label_tray(
        self,
        *,
        barcode: str,
        item_code: str,
        tray_quantity: int,
        matched_item: Dict[str, Any],
        event_name: str,
        event_detail: Dict[str, Any],
        canonical_input_tag_qr: str = "",
        active_label_qr_payload: str = "",
        active_label_id: str = "",
        active_label_business_date: str = "",
        active_label_worker_code: str = "",
        operation_lease_id: str = "",
        preflight_hold_owner: bool = False,
        coordinator_ui_snapshot: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        if (
            not preflight_hold_owner
            and self._reject_mutation_during_preflight_hold()
        ):
            return False
        self.current_tray = TraySession(
            master_label_code=barcode,
            canonical_input_tag_qr=canonical_input_tag_qr or barcode,
            active_label_qr_payload=active_label_qr_payload or barcode,
            active_label_id=active_label_id,
            active_label_business_date=active_label_business_date,
            active_label_worker_code=active_label_worker_code,
            operation_lease_id=operation_lease_id,
            item_code=item_code,
            tray_size=tray_quantity,
            item_name=matched_item.get('Item Name', ''),
            item_spec=matched_item.get('Spec', ''),
        )
        self.current_tray.stopwatch_seconds = 0
        self.current_tray.start_time = datetime.datetime.now()
        try:
            self._pending_activation_event_contract = self._activation_event_contract(
                event_type=event_name,
                event_detail=event_detail,
                master_label_code=barcode,
                observed_at=self.current_tray.start_time,
            )
        except (TypeError, ValueError) as exc:
            print(
                "현품표 시작 감사 계약 생성 실패: "
                f"{exc.__class__.__name__}: {exc}"
            )
            self.current_tray = TraySession()
            self._pending_activation_event_contract = None
            self.show_status_message(
                "현품표 시작 기록을 준비하지 못했습니다. 관리자에게 문의하세요.",
                self.COLOR_DANGER,
            )
            return False
        if not self._save_current_tray_state():
            self.current_tray = TraySession()
            self._pending_activation_event_contract = None
            self.show_status_message(
                "현품표 상태 저장에 실패했습니다. 작업을 시작하지 않습니다.",
                self.COLOR_DANGER,
            )
            return False
        if not self._drain_pending_activation_event():
            self.current_tray = TraySession()
            self.worker_name = ""
            messagebox.showerror(
                "현품표 시작 기록 대기",
                "현품표 상태와 감사 outbox는 안전하게 저장했지만 CSV 투영에 "
                "실패했습니다. 다시 작업자를 선택하면 같은 기록으로 재시도합니다.",
            )
            if hasattr(self, "show_worker_input_screen"):
                self.show_worker_input_screen()
            return False
        # The preflight worker read the real exchange store for this label.
        # Publish it only after activation is durable and its finish identity
        # has been checked; an old/no-tray snapshot must not gate the new tray.
        self._apply_transfer_coordinator_ui_snapshot(coordinator_ui_snapshot)
        self._clear_settled_operator_context()
        self.show_tray_image_var.set(True)
        self._update_tray_image_display()
        self._update_current_item_label()
        self._update_center_display()
        self._start_stopwatch()
        return True

    def _begin_compact_phs2_preflight(
        self,
        *,
        barcode: str,
        qr_data: Dict[str, Any],
        matched_item: Dict[str, Any],
    ) -> bool:
        try:
            canonical_fields = validate_compact_phs2_fields(qr_data)
        except TransferSealError:
            self.show_fullscreen_warning(
                "중앙 PHS=2 확인 실패",
                "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 다시 스캔하세요.",
                self.COLOR_DANGER,
            )
            return False

        lane = self._ui_task_lane()
        if lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return False
        self._master_preflight_epoch = int(
            getattr(self, "_master_preflight_epoch", 0)
        ) + 1
        token = self._master_preflight_epoch
        self._master_preflight_pending = True
        self.show_status_message(
            "중앙에서 검사 완료 수량과 제품 구성을 확인하고 있습니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )
        self._update_current_item_label("중앙 검사 완료 정보를 확인 중입니다.")

        hold_store = self._preflight_hold_store()
        hold_worker = persistent_operator_name(self.worker_name)
        marker_log_path = str(getattr(self, "log_file_path", "") or "")
        finish_identity = self._capture_mutation_finish_identity()

        def prepare_hold() -> PreflightHoldSnapshot:
            if hold_store.exists():
                existing = hold_store.load()
                if (
                    existing.worker != hold_worker
                    or existing.master_raw != barcode
                ):
                    raise PreflightHoldConflict(
                        "another preflight hold is already active"
                    )
                if existing.state == HOLD_LOOKUP_FAILED:
                    snapshot = hold_store.resume(
                        master_raw=barcode,
                        worker=hold_worker,
                    )
                elif existing.state == HOLD_LOOKUP:
                    snapshot = existing
                else:
                    raise PreflightHoldConflict(
                        "the existing preflight hold is already draining"
                    )
            else:
                snapshot = hold_store.start(
                    worker=hold_worker,
                    master_raw=barcode,
                    scan_epoch=token,
                )
            return snapshot

        def worker() -> tuple[Any, ...]:
            try:
                hold_snapshot = prepare_hold()
            except BaseException:
                return (
                    False,
                    None,
                    "",
                    TransferSealError(
                        "PHS2_HOLD_DURABILITY_FAILED",
                        "사전조회 보류 상태를 저장하지 못했습니다.",
                        retryable=True,
                    ),
                    None,
                )
            try:
                coordinator = self._transfer_seal_runtime()
                client = coordinator.client
                if client is None:
                    raise TransferSealError(
                        "PHS2_CENTRAL_PREFLIGHT_REQUIRED",
                        "중앙 물류 연결 설정이 없어 PHS=2 현품표를 확인할 수 없습니다.",
                        retryable=True,
                    )
                manager = getattr(coordinator, "operation_lease_manager", None)
                authority_scope_id = str(
                    getattr(client, "authority_scope_id", "") or ""
                ).strip()
                if manager is None or not authority_scope_id:
                    raise TransferSealError(
                        "OPERATION_LEASE_RUNTIME_UNAVAILABLE",
                        "이 PC에서 오프라인 이적 확인 정보를 준비할 수 없습니다.",
                    )
                issue_request = {
                    "authority_scope_id": authority_scope_id,
                    "operation": TRANSFER_OPERATION,
                    "scan_payload": barcode,
                }
                normalized_artifact = None
                preflight = None
                for issue_round in range(2):
                    issue_key = manager.issue_idempotency_key(
                        device_id=client.device_id,
                        source_host_id=client.source_host_id,
                        authority_scope_id=authority_scope_id,
                        scan_payload=barcode,
                        explicit_new=True,
                    )
                    artifact = client.issue_operation_lease(
                        **issue_request,
                        idempotency_key=issue_key,
                    )
                    operation_snapshot = artifact.get("operation_snapshot")
                    if not isinstance(operation_snapshot, Mapping):
                        raise OperationLeaseError(
                            "OPERATION_LEASE_SNAPSHOT_INVALID",
                            "server artifact has no operation snapshot",
                        )
                    preflight = validate_compact_phs2_preflight(
                        canonical_fields,
                        operation_snapshot,
                    )
                    keyring = normalize_keyring(artifact.get("keyring"))
                    binding = transfer_operation_lease_binding(
                        client=client,
                        scan_payload=barcode,
                        preflight=preflight,
                        operation_snapshot=operation_snapshot,
                        site_id=keyring["site_id"],
                    )
                    status = str(artifact.get("status") or "")
                    if status == "ACTIVE":
                        normalized_artifact, _claims = (
                            manager.accept_authenticated(
                                artifact=artifact,
                                expected=binding,
                                issue_request=issue_request,
                                issue_idempotency_key=issue_key,
                            )
                        )
                        break
                    normalized_status, _claims = (
                        manager.accept_authenticated_nonactive(
                            artifact=artifact,
                            expected=binding,
                            issue_request=issue_request,
                            issue_idempotency_key=issue_key,
                        )
                    )
                    if (
                        normalized_status["status"] == "RELEASED"
                        and issue_round == 0
                    ):
                        continue
                    raise OperationLeaseError(
                        "OPERATION_LEASE_NOT_ACTIVE",
                        "server lease remains unresolved and cannot be replaced",
                    )
                if normalized_artifact is None or preflight is None:
                    raise OperationLeaseError(
                        "OPERATION_LEASE_NOT_ACTIVE",
                        "no ACTIVE operation lease was durably prefetched",
                    )
                marker_outcome = None
                if preflight.replaced_scan:
                    replacement_context = {
                        "process_context": "transfer",
                        "scan": {
                            "replacement_required": True,
                            "scanned_label_id": preflight.scanned_label_id,
                            "active_label_id": preflight.active_label_id,
                            "active_qr_payload": (
                                preflight.active_label_qr_payload
                            ),
                        },
                    }
                    apply_ready = self._call_transfer_ui_sync(
                        lambda: self._mutation_finish_can_apply(
                            finish_identity,
                            operation="phs2-master-preflight",
                            expected_preflight_hold=hold_snapshot,
                        )
                    )
                    if apply_ready:
                        marker_outcome = (
                            self._work_phs_replacement_waiting_marker(
                                replacement_context,
                                master_label=(
                                    preflight.canonical_input_tag_qr
                                ),
                                operator=hold_worker,
                                projection_log_file_path=marker_log_path,
                            )
                        )
                self._transfer_member_exchange_runtime()
                ui_snapshot = self._work_transfer_coordinator_ui_snapshot(
                    master_label=preflight.canonical_input_tag_qr,
                )
                result = (
                    True,
                    preflight,
                    normalized_artifact["lease_id"],
                    None,
                    hold_snapshot,
                    marker_outcome,
                    ui_snapshot,
                )
            except TransferSealError as exc:
                result = (False, None, "", exc, hold_snapshot)
            except OperationLeaseError as exc:
                result = (
                    False,
                    None,
                    "",
                    TransferSealError(exc.code, exc.message),
                    hold_snapshot,
                )
            except Exception as exc:
                result = (
                    False,
                    None,
                    "",
                    TransferSealError(
                        "PHS2_PREFLIGHT_UNAVAILABLE",
                        f"중앙 PHS=2 확인 중 통신 오류가 발생했습니다: {exc.__class__.__name__}",
                        retryable=True,
                        committed=None,
                    ),
                    hold_snapshot,
                )
            return result

        def finish(result: tuple[Any, ...]) -> None:
            success = bool(result[0]) if result else False
            expected_hold = (
                result[4]
                if len(result) > 4
                and isinstance(result[4], PreflightHoldSnapshot)
                else None
            )
            if success and expected_hold is not None and not (
                self._mutation_finish_can_apply(
                    finish_identity,
                    operation="phs2-master-preflight",
                    expected_preflight_hold=expected_hold,
                )
            ):
                self._settle_stale_preflight_result(
                    result,
                    reason="finish_context_changed",
                )
                return
            result_queue: queue.Queue = queue.Queue(maxsize=1)
            result_queue.put_nowait(result)
            self._master_preflight_queue = result_queue
            self._poll_compact_phs2_preflight(
                token,
                barcode,
                canonical_fields,
                matched_item,
                result_queue,
            )

        def fail(exc: BaseException) -> None:
            finish(
                (
                    False,
                    None,
                    "",
                    TransferSealError(
                        "PHS2_PREFLIGHT_UNAVAILABLE",
                        "중앙 PHS=2 확인 중 처리 오류가 발생했습니다.",
                        retryable=True,
                        committed=None,
                    ),
                )
            )

        admission = lane.submit(
            LaneTask(
                name="phs2-master-preflight",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=worker,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted or admission.handle is None:
            self._master_preflight_pending = False
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 현품표 입력을 다시 시도하세요.",
                self.COLOR_DANGER,
            )
            return False
        self._set_preflight_scan_input_locked(False)
        self._update_action_button_states()
        self._master_preflight_thread = admission.handle
        return True

    def _poll_compact_phs2_preflight(
        self,
        token: int,
        barcode: str,
        canonical_fields: Dict[str, str],
        matched_item: Dict[str, Any],
        result_queue: queue.Queue,
    ) -> None:
        if token != getattr(self, "_master_preflight_epoch", 0):
            try:
                result = result_queue.get_nowait()
            except queue.Empty:
                result = ()
            self._settle_stale_preflight_result(
                result,
                reason="scan_epoch_changed",
            )
            return
        try:
            result = result_queue.get_nowait()
        except queue.Empty:
            try:
                self._master_preflight_poll_job = self.root.after(
                    25,
                    self._poll_compact_phs2_preflight,
                    token,
                    barcode,
                    canonical_fields,
                    matched_item,
                    result_queue,
                )
            except (tk.TclError, AttributeError):
                self._cancel_master_preflight()
            return

        success, preflight, operation_lease_id, error = result[:4]
        if len(result) > 4 and isinstance(result[4], PreflightHoldSnapshot):
            self._preflight_hold_snapshot = result[4]

        self._master_preflight_poll_job = None
        if getattr(self.current_tray, "master_label_code", ""):
            self._settle_stale_preflight_result(
                result,
                reason="active_tray_changed",
            )
            return
        if not success or preflight is None:
            failure = error if isinstance(error, TransferSealError) else TransferSealError(
                "PHS2_PREFLIGHT_FAILED",
                "중앙 PHS=2 확인에 실패했습니다.",
            )
            self._mark_preflight_hold_failed(failure.code)
            self._update_current_item_label()
            try:
                self._log_event(
                    "MASTER_LABEL_PREFLIGHT_FAILED",
                    detail={
                        "contract_version": "container-audit-phs2-preflight-v1",
                        "input_tag_id": canonical_fields.get("ITG"),
                        "input_tag_label_id": canonical_fields.get("LBL"),
                        "item_code": canonical_fields.get("CLC"),
                        "error_code": failure.code,
                        "retryable": failure.retryable,
                    },
                )
            except Exception:
                pass
            title, message = self._preflight_failure_guidance(
                failure.code,
                held_retry=self._preflight_hold_store().exists(),
            )
            self.show_fullscreen_warning(title, message, self.COLOR_DANGER)
            self._schedule_focus_return()
            return

        self._master_preflight_pending = False
        self._set_preflight_scan_input_locked(True)
        detail = dict(canonical_fields)
        detail["central_source_preflight"] = preflight.audit_detail()
        detail["resolved_tray_quantity"] = preflight.member_count
        detail["scanned_physical_label_qr"] = barcode
        detail["terminal_operation_lease"] = {
            "contract_version": "terminal-operation-lease-artifact-v1",
            "lease_id": operation_lease_id,
            "state": "PREFETCHED",
        }
        replacement_context = {
            "process_context": "transfer",
            "scan": {
                "replacement_required": bool(preflight.replaced_scan),
                "scanned_label_id": preflight.scanned_label_id,
                "active_label_id": preflight.active_label_id,
                "active_qr_payload": preflight.active_label_qr_payload,
            },
        }
        marker_new = False
        if preflight.replaced_scan:
            marker_ready, marker_new = (
                self._finish_phs_replacement_waiting_marker(
                    result[5] if len(result) > 5 else None
                )
            )
            if not marker_ready:
                self._mark_preflight_hold_failed(
                    "PHS2_REPLACEMENT_MARKER_DURABILITY_FAILED"
                )
                self._update_current_item_label()
                self._update_action_button_states()
                self._schedule_focus_return()
                return
        activated = self._activate_master_label_tray(
            barcode=preflight.canonical_input_tag_qr,
            item_code=preflight.item_id,
            tray_quantity=preflight.member_count,
            matched_item=matched_item,
            event_name="MASTER_LABEL_SCANNED_NEW",
            event_detail=detail,
            canonical_input_tag_qr=preflight.canonical_input_tag_qr,
            active_label_qr_payload=preflight.active_label_qr_payload,
            active_label_id=preflight.active_label_id,
            active_label_business_date=preflight.active_label_business_date,
            active_label_worker_code=preflight.active_label_worker_code,
            operation_lease_id=operation_lease_id,
            preflight_hold_owner=True,
            coordinator_ui_snapshot=result[6] if len(result) > 6 else None,
        )
        if activated:
            self._begin_preflight_hold_drain()
            if marker_new:
                self._show_phs_replacement_required_notice()
        else:
            self._mark_preflight_hold_failed("PHS2_ACTIVATION_DURABILITY_FAILED")
        self._update_action_button_states()

    @staticmethod
    def _preflight_failure_guidance(
        error_code: str, *, held_retry: bool,
    ) -> tuple[str, str]:
        retry = (
            "확인을 누르면 보관한 같은 현품표로 자동 재조회합니다. "
            "현품표를 다시 스캔하지 마세요."
            if held_retry
            else "확인 후 같은 현품표를 다시 스캔하세요."
        )
        if error_code == "OPERATION_LEASE_NOT_YET_VALID":
            return (
                "PC·서버 시간 확인 필요",
                "서버가 발급한 작업 확인 정보의 시작 시각이 이 PC보다 앞서 있습니다. "
                "잠시 기다린 뒤 확인을 누르세요. "
                + retry
                + " 반복되면 IT 담당자에게 PC·서버 시간 동기화를 요청하세요.",
            )
        return (
            "중앙 PHS=2 확인 실패",
            "검사 완료 상태와 네트워크를 확인하세요. " + retry,
        )

    def _mark_preflight_hold_failed(self, error_code: str) -> None:
        store = self._preflight_hold_store()
        if not store.exists():
            self._master_preflight_pending = False
            return

        def finish(snapshot: PreflightHoldSnapshot) -> None:
            self._preflight_hold_snapshot = snapshot
            self._master_preflight_pending = False
            self._set_preflight_scan_input_locked(True)
            self._update_action_button_states()
            self._update_current_item_label()
            self.show_status_message(
                f"중앙 조회 실패 · 보류 {len(snapshot.items)}건 (삭제되지 않음)",
                self.COLOR_DANGER,
                duration=0,
            )
            title, message = self._preflight_failure_guidance(
                error_code, held_retry=True,
            )
            self.show_fullscreen_warning(
                title,
                f"보류 스캔 {len(snapshot.items)}건은 삭제되지 않았습니다. " + message,
                self.COLOR_DANGER,
            )

        admission = self._preflight_hold_writer().submit(
            lambda: store.mark_failed(error_code=error_code),
            finish,
            lambda exc: self.show_status_message(
                "중앙 조회는 실패했고 보류 상태 갱신도 지연 중입니다. 현재 파일은 삭제하지 마세요.",
                self.COLOR_DANGER,
                duration=0,
            ),
        )
        if not admission.accepted:
            self._set_preflight_scan_input_locked(True)
            self.show_status_message(
                "중앙 조회 실패 · 보류 상태 저장 대기 중 (삭제되지 않음)",
                self.COLOR_DANGER,
                duration=0,
            )

    def _begin_preflight_hold_drain(self) -> None:
        self._set_preflight_scan_input_locked(True)
        store = self._preflight_hold_store()
        if not store.exists():
            self._preflight_hold_snapshot = None
            self._preflight_hold_draining = False
            self._set_preflight_scan_input_locked(False)
            self._schedule_startup_transfer_recovery()
            return

        def finish(snapshot: Optional[PreflightHoldSnapshot]) -> None:
            self._preflight_hold_snapshot = snapshot
            self._preflight_hold_draining = snapshot is not None
            if snapshot is None:
                self._set_preflight_scan_input_locked(False)
                self.show_status_message(
                    "중앙 확인 완료 · 보류 스캔 없음",
                    self.COLOR_SUCCESS,
                )
                self._schedule_startup_transfer_recovery()
                return
            self.show_status_message(
                f"중앙 확인 완료 · 보류 {len(snapshot.items)}건 순서대로 처리 중",
                self.COLOR_PRIMARY,
                duration=0,
            )
            self.root.after(0, self._drain_preflight_hold_head)

        admission = self._preflight_hold_writer().submit(
            store.mark_draining,
            finish,
            lambda exc: self.show_status_message(
                "보류 스캔 재생 상태를 저장하지 못했습니다. 보류 파일을 유지합니다.",
                self.COLOR_DANGER,
                duration=0,
            ),
        )
        if not admission.accepted:
            self.show_status_message(
                "보류 스캔 재생 준비가 지연 중입니다. 입력은 삭제되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )

    def _drain_preflight_hold_head(self) -> None:
        steps = self._drain_preflight_hold_steps()
        if hasattr(getattr(self, "root", None), "tk"):
            if getattr(self, "_ui_lane", None) is not None and self._ui_lane.is_busy():
                return
            advanced = False
            def finish(result):
                nonlocal advanced
                advanced = bool(result)
            self._submit_scan_steps(
                steps, finish=finish,
                on_idle=lambda: self._resume_preflight_hold_drain() if advanced else None,
            )
        else:
            if self._run_durable_ui_steps(steps):
                self._resume_preflight_hold_drain()

    def _resume_preflight_hold_drain(self) -> None:
        if getattr(self, "_ui_close_requested", False):
            return
        snapshot = getattr(self, "_preflight_hold_snapshot", None)
        if snapshot is None or not snapshot.items:
            self._preflight_hold_draining = False
            self._complete_after_preflight_hold_drain()
        else:
            self.root.after(0, self._drain_preflight_hold_head)

    def _drain_preflight_hold_steps(self):
        snapshot = getattr(self, "_preflight_hold_snapshot", None)
        if not isinstance(snapshot, PreflightHoldSnapshot) or not snapshot.items:
            return True
        if snapshot.state != HOLD_DRAINING:
            return
        if self._warning_state_presenter().state.is_blocking:
            return
        head = snapshot.items[0]
        current_barcodes = list(
            getattr(getattr(self, "current_tray", None), "scanned_barcodes", [])
            or []
        )
        receipts = self._preflight_scan_receipts()
        already_durable = bool(
            head.raw_barcode in current_barcodes
            and receipts.get(head.raw_barcode) == head.scan_id
        )
        audit_durable = False
        if not already_durable:
            decision = self._preflight_held_scan_decision(head.raw_barcode)
            if decision.status != SCAN_ACCEPTED:
                already_durable = yield from self._durably_reject_preflight_hold_head(
                    head,
                    decision,
                )
                audit_durable = already_durable
            else:
                before_count = len(current_barcodes)
                scan_steps = self._process_barcode_logic(
                    head.raw_barcode, _durable_scan_log=True,
                    _durable_scan_id=head.scan_id, _catalog_decision=decision,
                    _defer_persistence=True,
                )
                audit_durable = bool((yield from scan_steps) if scan_steps is not None else False)
                current_barcodes = list(
                    getattr(
                        getattr(self, "current_tray", None),
                        "scanned_barcodes",
                        [],
                    )
                    or []
                )
                receipts = self._preflight_scan_receipts()
                already_durable = (
                    len(current_barcodes) == before_count + 1
                    and current_barcodes[-1] == head.raw_barcode
                    and receipts.get(head.raw_barcode) == head.scan_id
                )
        else:
            audit_durable = yield lambda: self._persist_existing_held_scan_audit(
                head.raw_barcode,
                scan_id=head.scan_id,
                scan_position=current_barcodes.index(head.raw_barcode) + 1,
            )
        if not already_durable or not audit_durable:
            self.show_status_message(
                f"보류 스캔 저장 확인 필요 · 남은 {len(snapshot.items)}건",
                self.COLOR_DANGER,
                duration=0,
            )
            return

        store = self._preflight_hold_store()

        try:
            updated = yield lambda: store.ack_head(head.scan_id)
        except Exception:
            self.show_status_message(
                "제품은 저장됐지만 보류 목록 확인을 마치지 못했습니다. 재시작 시 자동 대조합니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False
        self._preflight_hold_snapshot = updated
        return True

    def _preflight_scan_receipts(self) -> Dict[str, str]:
        tray = getattr(self, "current_tray", None)
        scanned = set(getattr(tray, "scanned_barcodes", []) or [])
        raw_receipts = getattr(tray, "preflight_scan_receipts", {})
        receipts = (
            {
                str(barcode): str(scan_id)
                for barcode, scan_id in raw_receipts.items()
                if isinstance(barcode, str)
                and barcode in scanned
                and isinstance(scan_id, str)
                and scan_id.strip()
            }
            if isinstance(raw_receipts, Mapping)
            else {}
        )
        if tray is not None:
            tray.preflight_scan_receipts = receipts
        return receipts

    def _preflight_held_scan_decision(
        self,
        raw_barcode: str,
    ) -> ProductScanDecision:
        decision = decide_product_scan(
            self.current_tray,
            raw_barcode,
            item_code_length=self.ITEM_CODE_LENGTH,
        )
        if decision.status != SCAN_ACCEPTED:
            return decision
        return decide_catalog_product_match(
            self.current_tray.item_code,
            raw_barcode,
            self._item_catalog().matching_codes_in_barcode(raw_barcode),
        )

    def _durably_reject_preflight_hold_head(
        self,
        head: Any,
        decision: ProductScanDecision,
    ):
        title = "보류 스캔 확인"
        message = "보류 중 접수된 제품 바코드를 반영하지 않았습니다."
        if decision.status == SCAN_FORMAT_ERROR:
            title = "바코드 형식 오류"
            message = decision.format_error_message
        elif decision.status == SCAN_DUPLICATE:
            title = "바코드 중복"
            message = "보류 중 같은 제품 바코드가 중복 접수되어 두 번째 입력을 반영하지 않았습니다."
        elif decision.status == SCAN_TRAY_FULL:
            title = "트레이 수량 초과"
            message = "목표 수량을 넘는 보류 스캔을 반영하지 않았습니다."
        elif decision.event_name == "SCAN_FAIL_AMBIGUOUS_ITEM_CODE":
            title = "품목 코드 모호"
            message = "여러 품목 코드가 포함된 보류 스캔을 반영하지 않았습니다."
        elif decision.status == SCAN_MISMATCH:
            title = "품목 코드 불일치"
            message = "현재 트레이와 품목 코드가 다른 보류 스캔을 반영하지 않았습니다."
        self.show_fullscreen_warning(title, message, self.COLOR_DANGER)
        if not decision.event_name:
            return False
        durable = yield lambda: self._log_event(
            decision.event_name,
            detail=dict(decision.event_detail),
            synchronous=True,
            idempotency_key=f"preflight-held-reject:{head.scan_id}",
            deduplicate=True,
        )
        return bool(durable)

    def _persist_existing_held_scan_audit(
        self,
        raw_barcode: str,
        *,
        scan_id: str,
        scan_position: int,
    ) -> bool:
        scan_times = list(getattr(self.current_tray, "scan_times", []) or [])
        index = max(0, int(scan_position) - 1)
        interval = 0.0
        if index > 0 and index < len(scan_times):
            current_time = scan_times[index]
            previous_time = scan_times[index - 1]
            if isinstance(current_time, datetime.datetime) and isinstance(
                previous_time, datetime.datetime
            ):
                interval = max(0.0, (current_time - previous_time).total_seconds())
        return bool(
            self._log_event(
                "SCAN_OK",
                detail=build_scan_ok_detail(
                    raw_barcode,
                    interval_sec=interval,
                    scan_position=int(scan_position),
                    scan_contract_version=self.SCAN_CONTRACT_VERSION,
                ),
                synchronous=True,
                idempotency_key=f"preflight-held-scan:{scan_id}",
                deduplicate=True,
            )
        )

    def _complete_after_preflight_hold_drain(self) -> None:
        tray = getattr(self, "current_tray", None)
        full = bool(
            getattr(tray, "master_label_code", "")
            and int(getattr(tray, "tray_size", 0) or 0) > 0
            and len(getattr(tray, "scanned_barcodes", []) or [])
            >= int(getattr(tray, "tray_size", 0) or 0)
        )
        completion_due = bool(
            getattr(self, "_preflight_completion_due", False) or full
        )
        self._preflight_completion_due = False
        if not completion_due:
            self._set_preflight_scan_input_locked(False)
            self._update_action_button_states()
            self._schedule_startup_transfer_recovery()
            return

        def complete_after_release() -> None:
            self._set_preflight_scan_input_locked(False)
            if hasattr(getattr(self, "root", None), "tk"):
                admitted = self.request_complete_tray(
                    completion_callback=(
                        lambda _completed: self.root.after(
                            0,
                            self._schedule_startup_transfer_recovery,
                        )
                    )
                )
                if not admitted:
                    self._schedule_startup_transfer_recovery()
                return
            self.complete_tray()
            self._schedule_startup_transfer_recovery()

        self.root.after(0, complete_after_release)

    def _hold_scan_during_preflight(
        self,
        raw_barcode: str,
        *,
        clear_entry_after_ack: bool = False,
    ) -> bool:
        raw = str(raw_barcode or "").strip()
        if not raw:
            return False
        if clear_entry_after_ack and getattr(
            self, "_preflight_hold_append_pending", False
        ):
            self.show_status_message(
                "이전 보류 스캔을 저장하는 중입니다. 입력값을 유지합니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False
        if clear_entry_after_ack:
            self._preflight_hold_append_pending = True
            self._set_scan_callback_pending(True)
        store = self._preflight_hold_store()

        def persist() -> tuple[Any, PreflightHoldSnapshot]:
            item = store.append(raw)
            return item, store.load()

        def finish(result: tuple[Any, PreflightHoldSnapshot]) -> None:
            if clear_entry_after_ack:
                self._preflight_hold_append_pending = False
            _item, snapshot = result
            self._preflight_hold_snapshot = snapshot
            self._update_current_item_label()
            if clear_entry_after_ack:
                self._clear_consumed_scan_entry(raw)
                self._set_scan_callback_pending(False)
            self.show_status_message(
                f"중앙 확인 중 · 보류 스캔 {len(snapshot.items)}건",
                self.COLOR_PRIMARY,
                duration=0,
            )

        def fail(exc: BaseException) -> None:
            if clear_entry_after_ack:
                self._preflight_hold_append_pending = False
            self._set_preflight_scan_input_locked(True)
            if clear_entry_after_ack:
                self._set_scan_callback_pending(False)
            if isinstance(exc, PreflightHoldFull):
                message = "보류 한도 초과 — 이번 스캔은 접수되지 않았습니다."
            else:
                message = "보류 스캔을 저장하지 못해 이번 스캔은 접수되지 않았습니다."
            self.show_status_message(message, self.COLOR_DANGER, duration=0)

        admission = self._preflight_hold_writer().submit(persist, finish, fail)
        if not admission.accepted:
            if clear_entry_after_ack:
                self._preflight_hold_append_pending = False
            self._set_preflight_scan_input_locked(True)
            if clear_entry_after_ack:
                self._set_scan_callback_pending(False)
            self.show_status_message(
                "보류 저장 대기열이 가득 차 이번 스캔은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False
        return True

    def _restore_preflight_scan_hold(self) -> bool:
        store = self._preflight_hold_store()
        if not store.exists():
            self._preflight_hold_snapshot = None
            return True
        try:
            snapshot = store.load()
        except PreflightHoldError:
            messagebox.showerror(
                "보류 스캔 확인 필요",
                "사전조회 보류 파일을 읽지 못했습니다. 파일을 보존하고 관리자에게 문의하세요.",
            )
            return False
        current_worker = persistent_operator_name(self.worker_name)
        if snapshot.worker != current_worker:
            if self._is_preflight_hold_supervisor() and messagebox.askyesno(
                "다른 작업자 보류 묶음",
                "다른 작업자의 중앙 조회 보류 묶음이 남아 있습니다. 복원 가능한 "
                "격리 목록으로 옮겨 새 작업을 허용하시겠습니까?",
                parent=getattr(self, "root", None),
            ):
                return self._quarantine_preflight_hold_for_supervisor(
                    reason="supervisor_worker_boundary",
                    confirm=False,
                )
            messagebox.showwarning(
                "보류 스캔 작업자 확인",
                "다른 작업자의 중앙 조회 보류 묶음이 남아 있어 작업자를 변경할 수 없습니다.",
            )
            return False
        self._preflight_hold_snapshot = snapshot
        self._set_preflight_scan_input_locked(True)
        if snapshot.state == HOLD_DRAINING:
            if self._preflight_hold_matches_current_tray(snapshot):
                self._preflight_hold_draining = True
                self.root.after(0, self._drain_preflight_hold_head)
            else:
                if self._is_preflight_hold_supervisor() and messagebox.askyesno(
                    "보류 묶음 소유권 확인",
                    "제품 반영 중 상태와 현재 트레이가 일치하지 않습니다. 보류 "
                    "묶음을 복원 가능한 격리 목록으로 옮기시겠습니까?",
                    parent=getattr(self, "root", None),
                ):
                    return self._quarantine_preflight_hold_for_supervisor(
                        reason="supervisor_orphaned_draining",
                        confirm=False,
                    )
                messagebox.showerror(
                    "보류 묶음 소유권 확인 필요",
                    "제품 반영 중인 보류 묶음과 현재 트레이가 일치하지 않습니다. "
                    "두 상태를 보존하고 관리자에게 문의하세요.",
                    parent=getattr(self, "root", None),
                )
                return False
        else:
            self.show_status_message(
                f"중앙 조회 재확인 필요 · 보류 {len(snapshot.items)}건 (삭제되지 않음)",
                self.COLOR_DANGER,
                duration=0,
            )
            self.show_fullscreen_warning(
                "중앙 조회 재확인 필요",
                "보류 스캔은 삭제되지 않았습니다. 확인을 누르면 같은 현품표로 다시 조회합니다.",
                self.COLOR_DANGER,
            )
        return True

    def _begin_active_phs_label_refresh(self, raw_barcode: str) -> None:
        """Resolve a PHS2 rescan without disturbing the active tray."""

        if self._reject_mutation_during_preflight_hold():
            return
        if (
            getattr(self, "_phs_label_exchange_pending", False)
            or self._phs_label_exchange_transition_pending()
        ):
            self.show_status_message(
                "현품표 날짜 교환의 중앙 상태가 확정될 때까지 현품표 "
                "재확인은 잠시 보류됩니다. 제품 스캔은 계속할 수 있습니다.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        if getattr(self, "_phs_label_refresh_pending", False):
            self.show_status_message(
                "현재 사용 중인 현품표를 이미 중앙에서 확인하고 있습니다.",
                self.COLOR_PRIMARY,
            )
            self._schedule_focus_return()
            return
        scanned_payload = normalize_master_label_input(raw_barcode)
        scanned_fields = self._parse_new_format_qr(scanned_payload) or {}
        try:
            canonical_fields = validate_compact_phs2_fields(scanned_fields)
        except TransferSealError:
            self.show_status_message(
                "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 다시 스캔하세요.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        tray = self.current_tray
        tray_master = str(getattr(tray, "master_label_code", "") or "")
        tray_fields = self._parse_new_format_qr(tray_master) or {}
        if (
            str(tray_fields.get("PHS") or "").strip() != "2"
            or str(tray_fields.get("ITG") or "").strip()
            != canonical_fields["ITG"]
            or str(tray_fields.get("CLC") or "").strip()
            != canonical_fields["CLC"]
        ):
            self.show_status_message(
                "현재 트레이와 다른 ITG/품목의 PHS2 현품표입니다.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        coordinator = getattr(self, "phs_label_exchange_coordinator", None)
        client = getattr(coordinator, "client", None)
        if client is None:
            self.show_status_message(
                "현재 사용 현품표를 확인하는 중앙 연결 설정이 없습니다.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()
            return
        self._phs_label_refresh_pending = True
        finish_identity = self._capture_mutation_finish_identity()
        canonical_snapshot = copy.deepcopy(canonical_fields)
        source_identity = copy.deepcopy(
            source_identity_from_label(canonical_snapshot)
        )
        marker_operator = str(getattr(self, "worker_name", "") or "")
        marker_log_path = str(getattr(self, "log_file_path", "") or "")
        lane = self._ui_task_lane()
        self._update_action_button_states()
        self.show_status_message(
            "스캔한 현품표의 현재 사용 표를 확인하고 있습니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )

        def work() -> Dict[str, Any]:
            resolved = client.resolve_source(source_identity)
            preflight = validate_compact_phs2_preflight(
                canonical_snapshot,
                resolved,
            )
            marker_outcome = None
            if preflight.replaced_scan:
                replacement_context = {
                    "process_context": "transfer",
                    "scan": {
                        "replacement_required": True,
                        "scanned_label_id": preflight.scanned_label_id,
                        "active_label_id": preflight.active_label_id,
                        "active_qr_payload": preflight.active_label_qr_payload,
                    },
                }
                apply_ready = self._call_transfer_ui_sync(
                    lambda: self._mutation_finish_can_apply(
                        finish_identity,
                        operation="phs-label-active-refresh",
                    )
                )
                if apply_ready:
                    marker_outcome = (
                        self._work_phs_replacement_waiting_marker(
                            replacement_context,
                            master_label=tray_master,
                            operator=marker_operator,
                            projection_log_file_path=marker_log_path,
                        )
                    )
            return {
                "preflight": preflight,
                "marker_outcome": marker_outcome,
            }

        def finish(outcome: Mapping[str, Any]) -> None:
            preflight = outcome.get("preflight")
            apply_ready = self._mutation_finish_can_apply(
                finish_identity,
                operation="phs-label-active-refresh",
            )
            self._phs_label_refresh_pending = False
            self._update_action_button_states()
            if not apply_ready:
                self._schedule_focus_return()
                return
            if self.current_tray is not tray or tray.master_label_code != tray_master:
                self._schedule_focus_return()
                return
            if (
                preflight.canonical_input_tag_qr != tray.master_label_code
                or preflight.item_id != tray.item_code
                or preflight.member_count != tray.tray_size
            ):
                self.show_status_message(
                    "중앙에서 확인한 현품표의 품목 또는 수량이 현재 "
                    "트레이와 다릅니다.",
                    self.COLOR_DANGER,
                    duration=8000,
                )
                self._schedule_focus_return()
                return
            replacement_context = {
                "process_context": "transfer",
                "scan": {
                    "replacement_required": bool(
                        preflight.replaced_scan
                    ),
                    "scanned_label_id": preflight.scanned_label_id,
                    "active_label_id": preflight.active_label_id,
                    "active_qr_payload": (
                        preflight.active_label_qr_payload
                    ),
                },
            }
            marker_new = False
            if preflight.replaced_scan:
                marker_ready, marker_new = (
                    self._finish_phs_replacement_waiting_marker(
                        outcome.get("marker_outcome")
                    )
                )
                if not marker_ready:
                    self._schedule_focus_return()
                    return
            before = {
                "canonical_input_tag_qr": tray.canonical_input_tag_qr,
                "active_label_qr_payload": tray.active_label_qr_payload,
                "active_label_id": tray.active_label_id,
                "active_label_business_date": tray.active_label_business_date,
                "active_label_worker_code": tray.active_label_worker_code,
            }
            tray.canonical_input_tag_qr = preflight.canonical_input_tag_qr
            tray.active_label_qr_payload = preflight.active_label_qr_payload
            tray.active_label_id = preflight.active_label_id
            tray.active_label_business_date = (
                preflight.active_label_business_date
            )
            tray.active_label_worker_code = preflight.active_label_worker_code
            if not self._save_current_tray_state():
                for field_name, value in before.items():
                    setattr(tray, field_name, value)
                self.show_status_message(
                    "현재 사용 현품표 상태를 저장하지 못해 기존 표시를 유지합니다.",
                    self.COLOR_DANGER,
                    duration=8000,
                )
                self._schedule_focus_return()
                return
            try:
                self._log_event(
                    "PHS_LABEL_ACTIVE_REFRESHED",
                    detail={
                        "canonical_input_tag_qr": tray.master_label_code,
                        "scanned_label_id": preflight.scanned_label_id,
                        "active_label_id": preflight.active_label_id,
                        "active_label_business_date": (
                            preflight.active_label_business_date
                        ),
                        "active_label_worker_code": (
                            preflight.active_label_worker_code
                        ),
                        "resolution": preflight.active_label_resolution,
                        "replaced_scan": preflight.replaced_scan,
                    },
                )
            except Exception:
                pass
            if preflight.replaced_scan:
                if marker_new:
                    self._show_phs_replacement_required_notice()
                message = None if marker_new else (
                    "현재 사용 중인 현품표를 다시 확인했습니다."
                )
            else:
                message = (
                    "현재 사용 현품표 "
                    f"{preflight.active_label_business_date or '날짜 미표기'} · "
                    f"{preflight.active_label_worker_code or '작업코드 미배정'}를 "
                    "확인했습니다."
                )
            if message is not None:
                self.show_status_message(
                    message,
                    self.COLOR_PRIMARY,
                    duration=8000,
                )
            self._update_current_item_label()
            self._update_action_button_states()
            self._schedule_focus_return()

        def fail(exc: BaseException) -> None:
            print(f"현품표 active refresh lane 실패: {exc.__class__.__name__}")
            self._phs_label_refresh_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "현재 사용 현품표를 확인하지 못했습니다. 잠시 후 다시 스캔하세요.",
                self.COLOR_DANGER,
                duration=8000,
            )
            self._schedule_focus_return()

        admission = lane.submit(
            LaneTask(
                name="phs-label-active-refresh",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=(
                    (lambda: lane.close_idle())
                    if not hasattr(self.root, "tk")
                    else None
                ),
            )
        )
        if not admission.accepted:
            self._phs_label_refresh_pending = False
            self._update_action_button_states()
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            self._schedule_focus_return()
            return
        self._phs_label_refresh_task_handle = admission.handle

    def _intercept_active_tray_phs2_scan(self, raw_barcode: str) -> bool:
        """Prevent a PHS=2 label from being counted as a product barcode."""
        if not self.current_tray.master_label_code:
            return False

        barcode = normalize_master_label_input(raw_barcode)
        qr_data = self._parse_new_format_qr(barcode)
        if not qr_data or str(qr_data.get("PHS") or "").strip() != "2":
            return False

        try:
            canonical_fields = validate_compact_phs2_fields(qr_data)
        except TransferSealError as exc:
            self._log_event(
                "ACTIVE_TRAY_PHS2_SCAN_REJECTED",
                detail={
                    "contract_version": "container-audit-active-phs2-guard-v1",
                    "error_code": exc.code,
                },
            )
            self.show_status_message(
                "PHS=2 현품표는 제품 바코드로 등록하지 않았습니다. "
                "올바른 현품표를 확인해 주세요.",
                self.COLOR_DANGER,
            )
            self._schedule_focus_return()
            return True

        if self._reject_mutation_during_preflight_hold():
            return True
        current_fields = self._parse_new_format_qr(
            normalize_master_label_input(self.current_tray.master_label_code)
        ) or {}
        self._log_event(
            "ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED",
            detail={
                "contract_version": "container-audit-active-phs2-guard-v1",
                "current_input_tag_id": str(current_fields.get("ITG") or ""),
                "scanned_input_tag_id": canonical_fields["ITG"],
                "scanned_label_id": canonical_fields["LBL"],
            },
        )
        self._begin_active_phs_label_refresh(raw_barcode)
        return True

    def _scan_entry_admission_block_reason(self) -> str:
        if getattr(self, "_ui_close_requested", False):
            return "종료 정리 중입니다. 이번 스캔은 접수되지 않았습니다."
        if getattr(self, "_scan_callback_pending", False):
            return "이전 스캔 입력을 접수하는 중입니다. 입력값을 유지합니다."
        if getattr(self, "_preflight_scan_input_locked", False):
            return "중앙 조회 보류 묶음을 먼저 해결해야 합니다. 입력값을 유지합니다."
        if (
            getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_reconciliation_resolve_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
        ):
            return "이전 중앙 작업 처리 중입니다. 입력값을 유지합니다."
        if self._preflight_context_blocks_mutation():
            return "중앙 조회 보류 묶음을 먼저 해결해야 합니다. 입력값을 유지합니다."
        lane = getattr(self, "_ui_lane", None)
        if lane is not None:
            state = str(getattr(lane, "state", "") or "")
            if lane.is_busy() or state in {
                LANE_BUSY,
                LANE_DRAINING,
                LANE_BROKEN,
                LANE_CLOSED,
            }:
                return "이전 중앙 작업 처리 중입니다. 입력값을 유지합니다."
        try:
            if self._warning_state_presenter().state.is_blocking:
                return "현재 경고를 먼저 확인해야 합니다. 입력값을 유지합니다."
        except (AttributeError, TypeError):
            pass
        return ""

    def _set_scan_callback_pending(self, pending: bool) -> None:
        self._scan_callback_pending = bool(pending)
        entry = getattr(self, "scan_entry", None)
        if entry is None:
            return
        disabled = bool(
            pending
            or getattr(self, "_preflight_scan_input_locked", False)
            or getattr(self, "_completion_lane_busy", False)
            or getattr(self, "_phs_label_candidate_pending", False)
            or getattr(self, "_phs_reconciliation_resolve_pending", False)
            or getattr(self, "_phs_label_refresh_pending", False)
            or getattr(self, "_ui_close_requested", False)
        )
        try:
            entry.configure(state=tk.DISABLED if disabled else tk.NORMAL)
        except (AttributeError, tk.TclError):
            pass
    
    def _clear_consumed_scan_entry(self, raw_barcode: str) -> bool:
        """Consume only the captured value, even while Tk input is locked."""
        entry = getattr(self, "scan_entry", None)
        if entry is None:
            return True
        try:
            if entry.get().strip() != raw_barcode:
                return False
            # Tk ignores delete on a disabled Entry. This synchronous change
            # runs without dispatching events, so no next scan can interleave.
            if hasattr(entry, "configure"):
                entry.configure(state=tk.NORMAL)
            entry.delete(0, tk.END)
            return True
        except (AttributeError, tk.TclError):
            return False
        finally:
            self._set_scan_callback_pending(
                bool(getattr(self, "_scan_callback_pending", False))
            )

    def process_barcode(self, event=None):
        """UI의 스캔 엔트리에서 바코드를 읽어 로직을 실행합니다."""
        raw_barcode = self.scan_entry.get().strip()
        if not raw_barcode:
            return
        if getattr(self, "_master_preflight_pending", False):
            self._hold_scan_during_preflight(
                raw_barcode,
                clear_entry_after_ack=True,
            )
            return
        block_reason = self._scan_entry_admission_block_reason()
        if block_reason:
            self.show_status_message(
                block_reason,
                self.COLOR_DANGER,
                duration=0,
            )
            return
        # Keep the raw scanner value until the scheduled callback owns it.
        scan_epoch = getattr(self, "_scan_callback_epoch", 0)
        self._set_scan_callback_pending(True)
        self.root.after(0, self._process_barcode_if_current, raw_barcode, scan_epoch)

    def _invalidate_pending_scan_callbacks(self) -> None:
        self._scan_callback_epoch = int(getattr(self, "_scan_callback_epoch", 0)) + 1
        self._set_scan_callback_pending(False)
        self._cancel_master_preflight()

    def _process_barcode_if_current(self, raw_barcode: str, scan_epoch: int) -> None:
        self._scan_callback_pending = False
        try:
            if scan_epoch != getattr(self, "_scan_callback_epoch", 0):
                return
            block_reason = self._scan_entry_admission_block_reason()
            if block_reason:
                self.show_status_message(
                    block_reason,
                    self.COLOR_DANGER,
                    duration=0,
                )
                return
            if not self._clear_consumed_scan_entry(raw_barcode):
                self.show_status_message(
                    "스캐너 입력을 확인할 수 없어 이전 입력을 접수하지 않았습니다.",
                    self.COLOR_DANGER,
                    duration=0,
                )
                return
            self._process_barcode_logic(raw_barcode)
        finally:
            self._set_scan_callback_pending(False)

    def _process_barcode_logic(
        self, raw_barcode: str, *, _durable_scan_log: bool = False,
        _durable_scan_id: str = "", _catalog_decision=None,
        _defer_persistence: bool = False,
    ):
        steps = self._process_barcode_steps(
            raw_barcode, _durable_scan_log=_durable_scan_log,
            _durable_scan_id=_durable_scan_id, _catalog_decision=_catalog_decision,
        )
        if _defer_persistence:
            return steps
        scan_tray = getattr(self, "current_tray", None)
        # Master/preflight/replacement routing already owns its own lane task.
        # Only active product input enters the serial persistence sequence here.
        live_product = bool(
            hasattr(getattr(self, "root", None), "tk")
            and getattr(scan_tray, "master_label_code", "")
            and not getattr(self, "master_label_replace_state", None)
            and not getattr(self, "_master_preflight_pending", False)
            and not getattr(self, "internal_test_commands_enabled", False)
            and not self._parse_new_format_qr(raw_barcode)
        )
        if live_product:
            scan_epoch = int(getattr(self, "_scan_callback_epoch", 0))
            before_count = len(scan_tray.scanned_barcodes)
            def on_idle() -> None:
                self._update_action_button_states()
                if (not _durable_scan_log
                        and self.current_tray is scan_tray
                        and int(getattr(self, "_scan_callback_epoch", 0)) == scan_epoch
                        and not getattr(self, "_ui_close_requested", False)
                        and len(scan_tray.scanned_barcodes) > before_count
                        and len(scan_tray.scanned_barcodes) >= scan_tray.tray_size):
                    self.root.after(0, self.request_complete_tray)
            return self._submit_scan_steps(steps, on_idle=on_idle)
        return self._run_durable_ui_steps(steps)

    def _process_barcode_steps(
        self,
        raw_barcode: str,
        *,
        _durable_scan_log: bool = False,
        _durable_scan_id: str = "",
        _catalog_decision: Optional[ProductScanDecision] = None,
    ):
        """바코드 데이터를 받아 실제 처리 로직을 수행합니다."""
        if not raw_barcode: return
        if getattr(self, "_ui_close_requested", False):
            self.show_status_message(
                "종료 정리 중입니다. 이번 스캔은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return
        if getattr(self, "_master_preflight_pending", False):
            self._hold_scan_during_preflight(raw_barcode)
            return
        hold_snapshot = getattr(self, "_preflight_hold_snapshot", None)
        if (
            not getattr(getattr(self, "current_tray", None), "master_label_code", "")
            and isinstance(hold_snapshot, PreflightHoldSnapshot)
            and hold_snapshot.state == HOLD_LOOKUP_FAILED
            and normalize_master_label_input(raw_barcode)
            != normalize_master_label_input(hold_snapshot.master_raw)
        ):
            self.show_status_message(
                f"중앙 조회 실패 · 보류 {len(hold_snapshot.items)}건. 같은 현품표로 재시도하세요. 이번 스캔은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return
        if self._warning_state_presenter().state.is_blocking:
            self._render_warning_state()
            return

        # 현품표 교체 모드 처리
        if self.master_label_replace_state:
            if self.master_label_replace_state in ['awaiting_old_completed', 'awaiting_new_replacement']:
                self._handle_historical_replacement_scan(raw_barcode)
            elif self.master_label_replace_state == 'awaiting_additional_items':
                self._handle_additional_item_scan(raw_barcode)
            elif self.master_label_replace_state == 'awaiting_removed_items':
                self._handle_removed_item_scan(raw_barcode)
            return
        if hasattr(getattr(self, "root", None), "tk"):
            yield from self._activity_steps()
        else:
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

        if self._intercept_phs_reconciliation_scan(raw_barcode):
            return

        if self._intercept_active_tray_phs2_scan(raw_barcode):
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
                    parked_worker = persistent_operator_name(
                        parked_state.get("worker_name")
                    )
                    if (
                        parked_worker
                        and parked_worker != persistent_operator_name(self.worker_name)
                    ):
                        self.show_fullscreen_warning(
                            "보류 작업 중복",
                            f"다른 작업자 '{display_operator_name(parked_worker)}'님의 보류 작업에 같은 현품표가 있습니다.",
                            self.COLOR_DANGER,
                        )
                        return
                    if messagebox.askyesno("보류 작업 발견", "이 현품표는 보류 중인 작업입니다.\n이 작업을 복원하시겠습니까?"):
                        self.restore_parked_tray(str(parked_filepath))
                    return
                try:
                    item_code = inspection_master_item_code(qr_data)
                    if not item_code:
                        self.show_fullscreen_warning("QR코드 오류", "QR코드에 고객사 코드(CLC)가 없습니다.", self.COLOR_DANGER)
                        return
                    matched_item = self._item_catalog().find_by_code(item_code)
                    if not matched_item:
                        self.show_fullscreen_warning("품목 없음", f"코드 '{item_code}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                        return
                    if str(qr_data.get("PHS") or "").strip() == "2":
                        self._begin_compact_phs2_preflight(
                            barcode=barcode,
                            qr_data=qr_data,
                            matched_item=matched_item,
                        )
                        return
                    tray_quantity = parse_positive_quantity(qr_data, default=self.TRAY_SIZE)
                    if tray_quantity is None:
                        self.show_fullscreen_warning("QR코드 오류", "QR코드 수량(QT)은 1 이상의 숫자여야 합니다.", self.COLOR_DANGER)
                        return
                    self._activate_master_label_tray(
                        barcode=barcode,
                        item_code=item_code,
                        tray_quantity=tray_quantity,
                        matched_item=matched_item,
                        event_name='MASTER_LABEL_SCANNED_NEW',
                        event_detail=qr_data,
                    )
                    return
                except Exception as e:
                    print(
                        "현품표 QR 해석 실패: "
                        f"{e.__class__.__name__}: {e}"
                    )
                    self.show_fullscreen_warning(
                        "QR코드 분석 오류",
                        "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 "
                        "다시 스캔하세요.",
                        self.COLOR_DANGER,
                    )
                    return
            else:
                if not is_start_item_code(barcode, item_code_length=self.ITEM_CODE_LENGTH):
                    self.show_fullscreen_warning("작업 시작 오류", f"잘못된 형식의 바코드입니다.\n{self.ITEM_CODE_LENGTH}자리 품목코드 또는 신규 QR을 스캔하세요.", self.COLOR_DANGER)
                    return
                
                matched_item = self._item_catalog().find_by_code(barcode)
                if not matched_item:
                    self.show_fullscreen_warning("품목 없음", f"현품표 코드 '{barcode}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                    return
                
                self._activate_master_label_tray(
                    barcode=barcode,
                    item_code=barcode,
                    tray_quantity=self.TRAY_SIZE,
                    matched_item=matched_item,
                    event_name='MASTER_LABEL_SCANNED_OLD',
                    event_detail={'master_label_code': barcode},
                )
            return
            
        # --- 제품 스캔 로직 ---
        scan_decision = decide_product_scan(self.current_tray, raw_barcode, item_code_length=self.ITEM_CODE_LENGTH)
        if scan_decision.status == SCAN_FORMAT_ERROR:
            if scan_decision.event_name:
                yield lambda: self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            self.show_fullscreen_warning("바코드 형식 오류", scan_decision.format_error_message, self.COLOR_DANGER); return
        if scan_decision.status == SCAN_MISMATCH:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("품목 코드 불일치!", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {self.current_tray.item_code}]", self.COLOR_DANGER)
            yield lambda: self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            (yield self._current_tray_save_operation())
            return
        if scan_decision.status == SCAN_DUPLICATE:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            duplicate_display = compact_scan_value(
                raw_barcode,
                item_code=self.current_tray.item_code,
            )
            self.show_fullscreen_warning(
                "바코드 중복!",
                f"이미 스캔된 제품입니다.\n{duplicate_display}",
                self.COLOR_DANGER,
            )
            yield lambda: self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            (yield self._current_tray_save_operation())
            return
        if scan_decision.status == SCAN_TRAY_FULL:
            self.show_fullscreen_warning("트레이 수량 초과", "현재 트레이는 이미 목표 수량에 도달했습니다. 트레이 완료 처리를 먼저 진행하세요.", self.COLOR_DANGER)
            yield lambda: self._log_event(scan_decision.event_name, detail=scan_decision.event_detail)
            (yield self._current_tray_save_operation())
            return
        # A held head supplies its catalog result in this same synchronous call.
        # Routing and the basic gate above still run; no result survives a callback.
        catalog_decision = _catalog_decision
        if catalog_decision is None:
            catalog_decision = decide_catalog_product_match(
                self.current_tray.item_code,
                raw_barcode,
                self._item_catalog().matching_codes_in_barcode(raw_barcode),
            )
        if not catalog_decision.accepted:
            self.current_tray.mismatch_error_count += 1
            self.current_tray.has_error_or_reset = True
            if catalog_decision.event_name == "SCAN_FAIL_AMBIGUOUS_ITEM_CODE":
                self.show_fullscreen_warning("품목 코드 모호", "제품 바코드에 여러 품목 코드가 포함되어 있습니다.", self.COLOR_DANGER)
            else:
                self.show_fullscreen_warning("품목 코드 불일치!", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {self.current_tray.item_code}]", self.COLOR_DANGER)
            yield lambda: self._log_event(catalog_decision.event_name, detail=catalog_decision.event_detail)
            (yield self._current_tray_save_operation())
            return
        
        tray = self.current_tray
        epoch = int(getattr(self, "_scan_callback_epoch", 0))
        now = datetime.datetime.now()
        interval = max(0.0, (now - tray.scan_times[-1]).total_seconds()) if tray.scan_times else 0.0
        state = self._current_tray_state_snapshot()
        state["scanned_barcodes"].append(raw_barcode)
        state["scan_times"].append(now.isoformat())
        if _durable_scan_id:
            state.setdefault("preflight_scan_receipts", {})[raw_barcode] = _durable_scan_id
        try:
            saved = yield lambda: self._save_tray_state_snapshot(state)
        except Exception:
            saved = False
        if self.current_tray is not tray or int(getattr(self, "_scan_callback_epoch", 0)) != epoch:
            return False
        if not saved:
            self._update_center_display()
            self._update_current_item_label()
            self.show_status_message("스캔 상태 저장에 실패했습니다. 스캔을 반영하지 않습니다.", self.COLOR_DANGER)
            return False
        presenter = self._warning_state_presenter()
        self._last_normal_scan_display_item_code = str(tray.item_code or "")
        presenter.record_normal_scan(raw_barcode)
        presenter.clear()
        self._stop_warning_beep()
        # Install the final notice state before the single count/item render.
        self.add_scanned_barcode(raw_barcode, now, interval)
        if _durable_scan_id:
            self._preflight_scan_receipts()[raw_barcode] = _durable_scan_id
        if self.success_sound:
            self.success_sound.play()
        scan_log_kwargs = {"synchronous": _durable_scan_log}
        if _durable_scan_id:
            scan_log_kwargs.update(idempotency_key=f"preflight-held-scan:{_durable_scan_id}", deduplicate=True)
        detail = build_scan_ok_detail(
            raw_barcode, interval_sec=interval,
            scan_position=len(tray.scanned_barcodes),
            scan_contract_version=self.SCAN_CONTRACT_VERSION,
        )
        audit_durable = yield lambda: self._log_event('SCAN_OK', detail=detail, **scan_log_kwargs)
        if len(tray.scanned_barcodes) >= tray.tray_size:
            if _durable_scan_log:
                self._preflight_completion_due = True
            elif not hasattr(getattr(self, "root", None), "tk"):
                self.complete_tray()
        return bool(audit_durable)

    def _run_durable_ui_steps(self, steps, *, lane=None):
        """Advance UI state on its owner; execute yielded durable work serially.

        The synchronous domain/recovery caller uses the identical sequence.
        Exceptions are returned to the suspended step so its rollback remains
        next to the write. The lane fences every UI checkpoint by generation.
        """
        def advance(value, error):
            try:
                return False, steps.throw(error) if error is not None else steps.send(value)
            except StopIteration as done:
                return True, done.value
        value, error = None, None
        while True:
            done, operation = (lane.call_ui_sync(advance, value, error)
                               if lane is not None else advance(value, error))
            if done:
                return operation
            try:
                value, error = operation(), None
            except Exception as exc:
                value, error = None, exc

    def _submit_scan_steps(self, steps, *, finish=None, on_idle=None):
        lane = self._ui_task_lane()
        def fail(exc):
            print(f"스캔 내구 처리 실패: {exc.__class__.__name__}")
            self.show_status_message(
                "스캔 저장 확인 필요 · 현재 입력과 보류 기록을 확인하세요.",
                self.COLOR_DANGER, duration=0,
            )
        admission = lane.submit(LaneTask(
            name="scan-persistence",
            generation=int(getattr(self, "_scan_callback_epoch", 0)),
            work=lambda: self._run_durable_ui_steps(steps, lane=lane),
            finish=finish or (lambda result: None), fail=fail,
            on_idle=on_idle,
            shutdown_policy=DRAIN_TO_TERMINAL,
        ))
        if not admission.accepted:
            steps.close()
            self.show_status_message("이전 스캔 저장 중입니다. 입력값을 유지합니다.", self.COLOR_DANGER)
            return False
        self._scan_persistence_task_handle = admission.handle
        self._update_action_button_states()
        return True

    def add_scanned_barcode(self, barcode: str, scan_time: datetime.datetime, interval: float):
        self.current_tray.scanned_barcodes.append(barcode)
        self.current_tray.scan_times.append(scan_time)
        count = len(self.current_tray.scanned_barcodes)
        row_text = self._format_scanned_list_row(count, barcode)
        self.scanned_listbox.insert(0, row_text)
        self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SUCCESS, 'fg': 'white'})
        self.root.after(
            400,
            self._reset_scanned_barcode_highlight,
            self.scanned_listbox,
            barcode,
            getattr(self, "_scan_callback_epoch", 0),
        )
        self._update_center_display()
        self._update_current_item_label()
        self.undo_button['state'] = tk.NORMAL

    def _reset_scanned_barcode_highlight(self, listbox, raw_barcode: str, scan_epoch: int):
        if scan_epoch != getattr(self, "_scan_callback_epoch", 0):
            return
        if listbox is not getattr(self, "scanned_listbox", None):
            return
        try:
            if not listbox.winfo_exists():
                return
            raw_rows = getattr(self.current_tray, "scanned_barcodes", [])
            raw_index = raw_rows.index(raw_barcode)
            list_index = len(raw_rows) - raw_index - 1
            expected_row = self._format_scanned_list_row(raw_index + 1, raw_barcode)
            if list_index < listbox.size() and listbox.get(list_index) == expected_row:
                listbox.itemconfig(list_index, {'bg': self.COLOR_SIDEBAR_BG, 'fg': self.COLOR_TEXT})
        except (tk.TclError, AttributeError, ValueError):
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

    def _completion_projection_log_path(
        self,
        projection_log_name: str = "",
    ) -> Path:
        save_root = Path(
            str(
                getattr(self, "save_folder", "")
                or Path(str(getattr(self, "log_file_path", "") or "")).parent
            )
        ).resolve(strict=False)
        if projection_log_name:
            log_name = str(projection_log_name).strip()
            if (
                log_name != Path(log_name).name
                or "/" in log_name
                or "\\" in log_name
                or not log_name.lower().endswith(".csv")
            ):
                raise ValueError("completion projection log name is invalid")
            target = save_root / log_name
        else:
            target = Path(str(getattr(self, "log_file_path", "") or ""))
        if not str(target) or target.resolve(strict=False).parent != save_root:
            raise ValueError("completion projection log must be inside the event folder")
        return target.resolve(strict=False)

    def _freeze_completion_measurements(
        self,
        observed_at: datetime.datetime,
    ) -> None:
        if getattr(self, "is_idle", False):
            last_activity = getattr(self, "last_activity_time", None)
            if isinstance(last_activity, datetime.datetime):
                self.current_tray.total_idle_seconds += max(
                    0.0,
                    (observed_at - last_activity).total_seconds(),
                )
            self.last_activity_time = observed_at
            self.is_idle = False
        self._stop_stopwatch()
        self._stop_idle_checker()

    def _completion_event_contract(
        self,
        *,
        observed_at: datetime.datetime,
        projection_log_path: Path,
        projection_worker_name: str,
        transfer_attempt: SealAttempt,
        was_restored_session: bool,
        transfer_detail: Mapping[str, Any],
        log_may_have_been_attempted: bool,
    ) -> Dict[str, Any]:
        intent_id = str(transfer_attempt.intent_id or "").strip()
        if not intent_id:
            raise ValueError("completion transfer intent is missing")
        projection_worker = persistent_operator_name(projection_worker_name)
        if not projection_worker:
            raise ValueError("completion projection worker is missing")
        return {
            "schema_version": COMPLETION_EVENT_STATE_SCHEMA_VERSION,
            "event_type": "TRAY_COMPLETE",
            "idempotency_key": f"tray-complete:{intent_id}",
            "observed_at": observed_at.isoformat(),
            "projection_log_name": projection_log_path.name,
            "projection_worker_name": projection_worker,
            "transfer_intent_id": intent_id,
            "was_restored_session": bool(was_restored_session),
            "log_may_have_been_attempted": bool(log_may_have_been_attempted),
            "transfer_detail": dict(transfer_detail),
        }

    def _completion_lane_identity(self) -> tuple[Any, ...]:
        tray = self.current_tray
        return (
            id(tray),
            str(getattr(tray, "master_label_code", "") or ""),
            tuple(getattr(tray, "scanned_barcodes", []) or ()),
            str(getattr(tray, "operation_lease_id", "") or ""),
            int(getattr(self, "_scan_callback_epoch", 0) or 0),
        )

    def _set_completion_lane_busy(self, busy: bool) -> None:
        self._completion_lane_busy = bool(busy)
        entry = getattr(self, "scan_entry", None)
        if entry is not None:
            try:
                entry.configure(
                    state=(
                        tk.DISABLED
                        if busy
                        or getattr(self, "_preflight_scan_input_locked", False)
                        or getattr(self, "_ui_close_requested", False)
                        else tk.NORMAL
                    )
                )
            except (AttributeError, tk.TclError):
                pass
        try:
            self._update_action_button_states()
        except (AttributeError, tk.TclError):
            pass
        if busy:
            self.show_status_message(
                "완료 처리 중",
                self.COLOR_PRIMARY,
                duration=0,
            )
        else:
            self._schedule_focus_return()

    def _persist_prepared_completion_contract(self, prepared_attempt, **kwargs):
        return self._run_durable_ui_steps(
            self._prepared_completion_contract_steps(prepared_attempt, **kwargs)
        )

    def _prepared_completion_contract_steps(
        self,
        prepared_attempt: SealAttempt,
        *,
        existing_event_contract: Optional[Mapping[str, Any]],
        completion_observed_at: datetime.datetime,
        projection_log_path: Path,
        completion_projection_worker: str,
        completion_was_restored: bool,
        master_label: str,
        mutation_identity: Optional[Mapping[str, Any]] = None,
    ):
        return (yield from tray_completion.prepared_completion_contract_steps(
            self, prepared_attempt,
            existing_event_contract=existing_event_contract,
            completion_observed_at=completion_observed_at,
            projection_log_path=projection_log_path,
            completion_projection_worker=completion_projection_worker,
            completion_was_restored=completion_was_restored,
            master_label=master_label,
            mutation_identity=mutation_identity,
        ))

    def request_complete_tray(
        self,
        *,
        completion_callback: Optional[Callable[[bool], None]] = None,
    ) -> bool:
        return tray_completion.request_complete_tray(
            self, clock=datetime, completion_callback=completion_callback,
        )

    def complete_tray(self, *, _prepared_transfer_attempt: Optional[SealAttempt] = None):
        return self._run_durable_ui_steps(self._complete_tray_steps(
            _prepared_transfer_attempt=_prepared_transfer_attempt,
        ))

    def _complete_tray_steps(
        self,
        *,
        _prepared_transfer_attempt: Optional[SealAttempt] = None,
        _lane_prechecked: bool = False,
    ):
        return (yield from tray_completion.complete_tray_steps(
            self, clock=datetime, session_factory=TraySession,
            _prepared_transfer_attempt=_prepared_transfer_attempt,
            _lane_prechecked=_lane_prechecked,
        ))

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
        if self._reject_mutation_during_preflight_hold():
            return
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if self._transfer_member_exchange_blocks_local_action("마지막 스캔 취소"):
            return
        self._update_last_activity_time()
        if not self.current_tray.scanned_barcodes: return
        last_barcode = self.current_tray.scanned_barcodes.pop()
        last_scan_time = self.current_tray.scan_times.pop()
        self.scanned_listbox.delete(0)
        if not self._save_current_tray_state():
            self.current_tray.scanned_barcodes.append(last_barcode)
            self.current_tray.scan_times.append(last_scan_time)
            row_text = self._format_scanned_list_row(len(self.current_tray.scanned_barcodes), last_barcode)
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
            row_text = self._format_scanned_list_row(len(self.current_tray.scanned_barcodes), last_barcode)
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
        cancelled_display = compact_scan_value(
            last_barcode,
            item_code=self.current_tray.item_code,
        )
        self.show_status_message(f"{cancelled_display} 스캔이 취소되었습니다.", self.COLOR_DANGER)
        self._sync_last_normal_scan_from_active_tray()
        self._update_current_item_label()
        if not self.current_tray.scanned_barcodes: self.undo_button['state'] = tk.DISABLED
        self._schedule_focus_return()

    def reset_current_work(self):
        if self._reject_mutation_during_preflight_hold():
            return
        if self._phs_label_exchange_blocks_tray_transition("현재 작업 초기화"):
            return
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if self._transfer_member_exchange_blocks_local_action("현재 작업 초기화"):
            return
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
            self._sync_last_normal_scan_from_active_tray(clear_when_inactive=True)
            self._update_all_summaries(); self.undo_button['state'] = tk.DISABLED
            self._reset_ui_to_waiting_state()
            self.show_status_message("현재 작업이 초기화되었습니다.", self.COLOR_DANGER)
            self._schedule_focus_return()

    def submit_current_tray(self):
        if self._reject_mutation_during_preflight_hold():
            return
        blocking_completion = self._active_blocking_completion_snapshot()
        if (
            blocking_completion is not None
            and blocking_completion.operator_retryable
        ):
            self._update_last_activity_time()
            if hasattr(getattr(self, "root", None), "tk"):
                self.request_complete_tray()
            else:
                self.complete_tray()
            return
        if blocking_completion is not None:
            self._render_warning_state()
            return
        if self._transfer_member_exchange_blocks_local_action("현재 트레이 제출"):
            return
        self._update_last_activity_time()
        if not self.current_tray.master_label_code or not self.current_tray.scanned_barcodes:
            self.show_status_message("제출할 스캔 내역이 없습니다.", self.COLOR_TEXT_SUBTLE); return
        master_fields = self._parse_new_format_qr(self.current_tray.master_label_code) or {}
        if (
            str(master_fields.get("PHS") or "").strip() == "2"
            and len(self.current_tray.scanned_barcodes) != int(self.current_tray.tray_size or 0)
        ):
            self.show_status_message(
                "PHS=2 현품표는 일부 제출할 수 없습니다. 등록된 제품을 모두 스캔하세요. "
                "잔량은 검사 공정에서 이름·시간·품목·수량·수기 코드를 적는 새 양식으로 처리하세요. "
                "RSL1은 업그레이드 전에 시작한 예전 작업 복구에만 사용합니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return
        if messagebox.askyesno("트레이 제출 확인", f"현재 {len(self.current_tray.scanned_barcodes)}개 스캔되었습니다.\n이 트레이를 완료로 처리하시겠습니까?"):
            self._complete_current_tray_as_partial()
        self._schedule_focus_return()

    def _complete_current_tray_as_partial(self) -> bool:
        if self._reject_mutation_during_preflight_hold():
            return False
        was_partial = self.current_tray.is_partial_submission
        self.current_tray.is_partial_submission = True
        if hasattr(getattr(self, "root", None), "tk"):
            def settle(completed: bool) -> None:
                if not completed and not self._operator_review_blocks_mutation():
                    self.current_tray.is_partial_submission = was_partial

            admitted = self.request_complete_tray(completion_callback=settle)
            if not admitted:
                self.current_tray.is_partial_submission = was_partial
            return admitted
        if self.complete_tray():
            return True
        if self._operator_review_blocks_mutation():
            return False
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
            count_display = str(data.get('count', 0))
            if data.get('test_count', 0) > 0:
                count_display += f" (T{data['test_count']})"
            item_name_spec = f"{data.get('name', '')}"
            tag = 'even' if row_index % 2 == 0 else 'odd'
            self._insert_tree_row(self.summary_tree, '', 'end', values=(item_name_spec, item_code, count_display), tags=(tag,))
        try:
            self.root.after_idle(self._adjust_summary_tree_columns)
        except (AttributeError, tk.TclError):
            pass

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
        active_tray = bool(self.current_tray.master_label_code)
        target_size = self.current_tray.tray_size if active_tray else 1
        if hasattr(self, 'stage_label'):
            if self.master_label_replace_state:
                self.stage_label['text'] = "부가 작업 · 완료 현품표 교체"
            elif active_tray:
                self.stage_label['text'] = "2 / 2 · 제품 스캔"
            else:
                self.stage_label['text'] = "1 / 2 · 현품표 스캔"
        self.main_count_label['text'] = f"{count} / {target_size}" if active_tray else "목표 대기"
        self.main_progress_bar['maximum'] = max(1, target_size)
        self.main_progress_bar['value'] = count if active_tray else 0
        self.main_progress_bar['style'] = 'Big.Horizontal.TProgressbar' if active_tray else 'Inactive.Horizontal.TProgressbar'
        if hasattr(self, 'scanned_list_header_label'):
            self.scanned_list_header_label['text'] = f"현재 트레이 스캔 목록 · {count}건"
        status_card = self.info_cards.get('status')
        if status_card and status_card['value'].winfo_exists():
            if active_tray and self.current_tray.is_restored_session:
                status_card['value']['text'] = "복구 작업 중"
                status_card['value']['foreground'] = self.COLOR_PRIMARY
            elif active_tray and not getattr(self, "is_idle", False):
                status_card['value']['text'] = "작업 중"
                status_card['value']['foreground'] = self.COLOR_SUCCESS
            else:
                status_card['value']['text'] = "대기 중"
                status_card['value']['foreground'] = self.COLOR_TEXT
        self._update_operator_context()
        self._update_action_button_states()
        self._render_warning_state()

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
        if self._preflight_context_blocks_mutation():
            self.stopwatch_job = self.root.after(1000, self._update_stopwatch)
            return
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
        return self._run_durable_ui_steps(self._activity_steps())

    def _activity_steps(self):
        activity_time = datetime.datetime.now()
        if self.is_idle:
            yield from self._wakeup_steps(activity_time=activity_time)
        self.last_activity_time = activity_time

    def _check_for_idle(self, idle_epoch: Optional[int] = None):
        if idle_epoch is not None and idle_epoch != getattr(self, "_idle_check_epoch", 0):
            return
        if not self.root.winfo_exists() or self.is_idle: return
        if self._preflight_context_blocks_mutation():
            self.idle_check_job = self.root.after(
                1000,
                self._check_for_idle,
                getattr(self, "_idle_check_epoch", 0),
            )
            return
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
        return self._run_durable_ui_steps(self._wakeup_steps(activity_time=activity_time))

    def _wakeup_steps(self, *, activity_time: Optional[datetime.datetime] = None):
        if not self.is_idle: return
        if self._preflight_context_blocks_mutation():
            return
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
            yield lambda: self._log_event('IDLE_END', detail={'duration_sec': f"{idle_duration:.2f}"})
            yield self._current_tray_save_operation()
        self._set_idle_style(is_idle=False)
        self._start_idle_checker()
        self._start_stopwatch(resume=True)
        self.show_status_message(f"작업 재개.", self.COLOR_SUCCESS)

    def _set_idle_style(self, is_idle: bool):
        if not (hasattr(self, 'info_cards') and self.info_cards): return
        card_style = 'Idle.TFrame' if is_idle else 'Card.TFrame'
        label_style = 'Idle.Subtle.TLabel' if is_idle else 'Card.Subtle.TLabel'
        value_style = 'Idle.Value.TLabel' if is_idle else 'Card.Value.TLabel'
        for key in ['status', 'stopwatch']:
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

    def _start_warning_beep(self):
        if getattr(self, "_warning_beep_active", False):
            return
        self._warning_beep_active = True
        if getattr(self, "error_sound", None):
            self.error_sound.play(loops=-1)

    def _stop_warning_beep(self):
        self._warning_beep_active = False
        if getattr(self, "error_sound", None):
            self.error_sound.stop()

    def _warning_state_presenter(self) -> WarningPresenter:
        presenter = getattr(self, "warning_presenter", None)
        if not isinstance(presenter, WarningPresenter):
            presenter = WarningPresenter()
            self.warning_presenter = presenter
        return presenter

    def _operator_review_blocks_mutation(self) -> bool:
        """Return whether a non-ACKed central completion owns the current tray.

        The business-owned snapshot survives view refreshes. The presenter
        fallback keeps older restored/test instances safe while they migrate.
        """

        return self._active_blocking_completion_snapshot() is not None

    def _notice_severity_for_color(self, color: Optional[str]) -> NoticeSeverity:
        normalized = str(color or "").strip().lower()
        if normalized in {
            str(getattr(self, "COLOR_DANGER", "#DC2626")).lower(),
            "danger",
            "red",
        }:
            return NoticeSeverity.ERROR
        if normalized in {
            str(getattr(self, "COLOR_SUCCESS", "#16A34A")).lower(),
            "success",
            "green",
        }:
            return NoticeSeverity.SUCCESS
        if normalized in {
            str(getattr(self, "COLOR_IDLE", "#F59E0B")).lower(),
            "warning",
            "orange",
        }:
            return NoticeSeverity.WARNING
        return NoticeSeverity.INFO

    def _render_warning_state(self) -> None:
        presenter = self._warning_state_presenter()
        state = presenter.state
        notice = state.active_notice
        if notice is None and state.completion is not None and state.completion.blocks_completion:
            notice = notice_for_completion(state.completion)

        if notice is None:
            title = "스캐너 준비"
            if getattr(getattr(self, "current_tray", None), "master_label_code", ""):
                message = self._active_tray_scan_instruction()
                if (
                    int(self.current_tray.tray_size or 0) > 0
                    and len(self.current_tray.scanned_barcodes) >= int(self.current_tray.tray_size)
                ):
                    title = "이적 완료 확인"
            else:
                message = "현품표 라벨을 스캔하여 작업을 시작하세요."
            severity = NoticeSeverity.INFO
        else:
            title = notice.title
            message = notice.message
            severity = notice.severity

        palette = {
            NoticeSeverity.INFO: ("#EFF6FF", "#93C5FD", "#1D4ED8", self.COLOR_TEXT),
            NoticeSeverity.SUCCESS: ("#F0FDF4", "#86EFAC", "#166534", self.COLOR_TEXT),
            NoticeSeverity.WARNING: ("#FFFBEB", "#FCD34D", "#92400E", self.COLOR_TEXT),
            NoticeSeverity.ERROR: ("#FEF2F2", "#FCA5A5", "#991B1B", self.COLOR_TEXT),
        }
        background, border, title_color, message_color = palette[severity]
        frame = getattr(self, "notice_frame", None)
        title_label = getattr(self, "notice_title_label", None)
        message_label = getattr(self, "notice_message_label", None)
        phs_label_info = getattr(self, "phs_active_label_info_label", None)
        acknowledge_button = getattr(self, "notice_ack_button", None)
        try:
            if frame is not None:
                frame.configure(
                    bg=background,
                    highlightbackground=border,
                    highlightcolor=border,
                )
            if title_label is not None:
                title_label.configure(text=title, bg=background, fg=title_color)
            if message_label is not None:
                message_label.configure(text=message, bg=background, fg=message_color)
            if phs_label_info is not None:
                phs_label_info.configure(bg=background, fg=message_color)
            active_notice = state.active_notice
            precommand_retry = (
                self._precommand_operator_review_retry_context() is not None
            )
            if acknowledge_button is not None:
                if precommand_retry:
                    acknowledge_button.grid()
                    acknowledge_button.configure(
                        text="사전검증 재시도",
                        state=tk.NORMAL,
                        bg=title_color,
                        fg="white",
                        activebackground=title_color,
                        activeforeground="white",
                    )
                elif active_notice is not None and active_notice.blocking:
                    acknowledge_button.grid()
                    acknowledge_button.configure(
                        text="확인",
                        state=tk.NORMAL,
                        bg=title_color,
                        fg="white",
                        activebackground=title_color,
                        activeforeground="white",
                    )
                elif state.is_blocking:
                    acknowledge_button.grid()
                    acknowledge_button.configure(
                        text=(
                            "완료 기록 재시도 사용"
                            if state.completion is not None
                            and state.completion.outcome is CompletionOutcome.LOCAL_EVENT_RETRY
                            else "서버 재확인 사용"
                            if state.completion is not None
                            and state.completion.outcome is CompletionOutcome.RETRY_WAIT
                            else "담당자 확인 필요"
                        ),
                        state=tk.DISABLED,
                        bg=background,
                        fg=title_color,
                    )
                else:
                    # A blank disabled button still reserves its horizontal
                    # padding (62 px at DISPLAY2 scaling), clipping ordinary
                    # completion/recovery guidance.  Remove it entirely until
                    # a blocking state needs an explicit acknowledgement.
                    acknowledge_button.grid_remove()
                    acknowledge_button.configure(
                        text="",
                        state=tk.DISABLED,
                        bg=background,
                        fg=message_color,
                    )
            scan_entry = getattr(self, "scan_entry", None)
            if scan_entry is not None:
                scan_entry.configure(state=tk.DISABLED if state.is_blocking else tk.NORMAL)
            current_instruction = getattr(self, "current_item_label", None)
            if current_instruction is not None:
                if state.is_blocking:
                    current_instruction.configure(text="아래 안내를 확인하세요.")
                    self._blocking_instruction_visible = True
                elif getattr(self, "_blocking_instruction_visible", False):
                    self._blocking_instruction_visible = False
                    self._update_current_item_label()
            last_scan_label = getattr(self, "last_scan_value_label", None)
            if last_scan_label is not None:
                last_scan_label.configure(
                    text=self._format_last_normal_scan_value(state.last_normal_scan)
                )
            status_card = getattr(self, "info_cards", {}).get('status')
            status_value = status_card.get('value') if status_card else None
            if status_value is not None:
                if self._active_operator_review_snapshot() is not None:
                    status_value.configure(text="담당자 확인", foreground=self.COLOR_DANGER)
                elif notice is not None and notice.blocking:
                    duplicate_notice = "duplicate" in notice.code.lower() or "중복" in notice.title
                    status_value.configure(
                        text="중복 확인" if duplicate_notice else "오류 확인",
                        foreground=self.COLOR_DANGER,
                    )
                elif state.completion is not None and state.completion.outcome is CompletionOutcome.ACKED:
                    status_value.configure(text="완료", foreground=self.COLOR_SUCCESS)
                elif state.completion is not None and state.completion.outcome is CompletionOutcome.LINKED:
                    status_value.configure(text="이 PC 저장 완료", foreground=self.COLOR_SUCCESS)
                elif state.completion is not None and state.completion.outcome is CompletionOutcome.RETRY_WAIT:
                    status_value.configure(text="서버 확인 대기", foreground=self.COLOR_IDLE)
                elif state.completion is not None and state.completion.outcome is CompletionOutcome.LOCAL_EVENT_RETRY:
                    status_value.configure(text="완료 기록 대기", foreground=self.COLOR_DANGER)
            status_label = getattr(self, "status_label", None)
            if status_label is not None:
                if state.completion is not None and state.completion.blocks_completion:
                    if state.completion.outcome is CompletionOutcome.RETRY_WAIT:
                        status_label.configure(
                            text="스캔 중지 · 서버 승인 대기",
                            fg=self.COLOR_IDLE,
                        )
                    elif state.completion.outcome is CompletionOutcome.LOCAL_EVENT_RETRY:
                        status_label.configure(
                            text="스캔 중지 · 완료 기록 재시도",
                            fg=self.COLOR_DANGER,
                        )
                    else:
                        status_label.configure(
                            text="스캔 중지 · 담당자 확인",
                            fg=self.COLOR_DANGER,
                        )
                elif state.active_notice is not None and state.active_notice.blocking:
                    status_label.configure(
                        text="스캔 중지 · 경고 확인",
                        fg=self.COLOR_DANGER,
                    )
                else:
                    try:
                        current_status = str(status_label.cget("text") or "")
                    except (AttributeError, tk.TclError):
                        current_status = ""
                    if current_status.startswith("스캔 중지 ·"):
                        status_label.configure(text="스캐너 준비", fg=self.COLOR_TEXT)
            follow_up_label = getattr(self, "follow_up_label", None)
            if follow_up_label is not None:
                tray = getattr(self, "current_tray", None)
                active_tray = bool(getattr(tray, "master_label_code", ""))
                scan_count = len(getattr(tray, "scanned_barcodes", []) or [])
                target_count = max(0, int(getattr(tray, "tray_size", 0) or 0))
                if state.completion is not None and state.completion.blocks_completion:
                    follow_up = (
                        "스캔 중지 · 완료 기록 재시도 버튼 사용"
                        if state.completion.outcome is CompletionOutcome.LOCAL_EVENT_RETRY
                        else "스캔 중지 · 서버 재확인 버튼 사용"
                        if state.completion.outcome is CompletionOutcome.RETRY_WAIT
                        else "스캔 중지 · 담당자 확인"
                    )
                elif state.active_notice is not None and state.active_notice.blocking:
                    follow_up = "경고 내용을 확인한 뒤 다음 스캔"
                elif active_tray and target_count and scan_count >= target_count:
                    follow_up = "목표 수량 도달 · 트레이 제출"
                elif active_tray:
                    follow_up = "다음 제품 스캔"
                elif state.completion is not None and state.completion.outcome is CompletionOutcome.RETRY_WAIT:
                    follow_up = "새 현품표 스캔 가능 · 서버 자동 재시도"
                elif (
                    state.completion is not None
                    and state.completion.outcome
                    in {CompletionOutcome.ACKED, CompletionOutcome.LINKED}
                ):
                    follow_up = "새 현품표 스캔"
                else:
                    follow_up = "현품표 라벨 스캔"
                follow_up_label.configure(text=follow_up)
        except (tk.TclError, AttributeError):
            return
        self._apply_notice_visibility()
        self._schedule_notice_message_wrap_refresh(
            generation=getattr(self, "_center_widget_generation", 0)
        )

    def _apply_notice_visibility(self) -> None:
        """Reserve the notice band for feedback and the selected exchange task."""
        state = self._warning_state_presenter().state
        has_notice = state.active_notice is not None or state.is_blocking
        panel = getattr(self, "phs_label_exchange_frame", None)
        try:
            exchange_open = (
                panel is not None and bool(panel.winfo_manager())
            ) or getattr(self, "_phs_label_exchange_recovery_visible", False)
            visible = has_notice or exchange_open
            for name, show in (
                ("notice_frame", visible),
                ("notice_title_label", has_notice),
                ("notice_message_label", has_notice),
                ("phs_label_exchange_button", exchange_open),
                ("phs_active_label_info_label", exchange_open),
            ):
                widget = getattr(self, name, None)
                if widget is not None:
                    widget.grid() if show else widget.grid_remove()
            parent = getattr(self, "_center_content_frame", None)
            if parent is not None:
                # A hidden frame must not leave the old warning minimum behind.
                parent.grid_rowconfigure(4, minsize=0)
        except (tk.TclError, AttributeError):
            return

    def _acknowledge_active_notice(self) -> None:
        if self._precommand_operator_review_retry_context() is not None:
            self._retry_precommand_operator_review_completion()
            return
        presenter = self._warning_state_presenter()
        presenter.acknowledge()
        self._stop_warning_beep()
        # Restore the ordinary working display before rendering the cleared
        # notice. Rendering only the warning band leaves overridden values
        # such as "중복 확인" stale in the right-side status card.
        self._update_center_display()
        if not presenter.state.is_blocking:
            snapshot = getattr(self, "_preflight_hold_snapshot", None)
            if (
                isinstance(snapshot, PreflightHoldSnapshot)
                and snapshot.state == HOLD_DRAINING
                and getattr(self, "_preflight_hold_draining", False)
            ):
                self.root.after(0, self._drain_preflight_hold_head)
                return
            if (
                isinstance(snapshot, PreflightHoldSnapshot)
                and snapshot.state in {HOLD_LOOKUP, HOLD_LOOKUP_FAILED}
                and not getattr(
                    getattr(self, "current_tray", None),
                    "master_label_code",
                    "",
                )
                and not getattr(self, "_master_preflight_pending", False)
            ):
                self._set_preflight_scan_input_locked(False)
                self.root.after(0, self._process_barcode_logic, snapshot.master_raw)
                return
            self._schedule_focus_return()

    def _cancel_status_message_timer(self) -> None:
        self._status_message_generation = int(getattr(self, "_status_message_generation", 0)) + 1
        status_job = getattr(self, "status_message_job", None)
        if status_job:
            try:
                self.root.after_cancel(status_job)
            except (tk.TclError, AttributeError):
                pass
            self.status_message_job = None

    def _publish_completion_snapshot(
        self,
        snapshot: CompletionOutcomeSnapshot,
    ) -> CompletionOutcomeSnapshot:
        self._cancel_status_message_timer()
        self._pending_operator_review_snapshot = (
            snapshot if snapshot.blocks_completion else None
        )
        self._warning_state_presenter().present_completion(snapshot)
        if snapshot.outcome is CompletionOutcome.OPERATOR_REVIEW:
            self._start_warning_beep()
        else:
            self._stop_warning_beep()
        self._render_warning_state()
        self._update_action_button_states()
        return snapshot

    def _present_completion_outcome(self, outcome, **kwargs):
        return self._run_durable_ui_steps(self._completion_outcome_steps(outcome, **kwargs))

    def _completion_outcome_steps(
        self,
        outcome: CompletionOutcome,
        *,
        item_name: str,
        master_label: str,
        scan_count: int,
        target_count: int,
        message: str,
        receipt_id: str = "",
        error_code: str = "",
    ):
        snapshot = CompletionOutcomeSnapshot(
            outcome=outcome,
            item_name=str(item_name or ""),
            master_label=str(master_label or ""),
            scan_count=max(0, int(scan_count or 0)),
            target_count=max(int(scan_count or 0), int(target_count or 0)),
            message=str(message or ""),
            receipt_id=str(receipt_id or ""),
            error_code=str(error_code or ""),
        )
        if snapshot.blocks_completion:
            self._pending_operator_review_snapshot = snapshot
            if not (yield self._current_tray_save_operation()):
                snapshot = CompletionOutcomeSnapshot(
                    outcome=snapshot.outcome,
                    item_name=snapshot.item_name,
                    master_label=snapshot.master_label,
                    scan_count=snapshot.scan_count,
                    target_count=snapshot.target_count,
                    message=(
                        f"{snapshot.message}\n중앙 확인 대기 잠금 상태를 저장하지 못했습니다. "
                        "프로그램을 종료하지 말고 담당자에게 알리세요."
                    ),
                    receipt_id=snapshot.receipt_id,
                    error_code=snapshot.error_code,
                )
        self._publish_completion_snapshot(snapshot)
        if outcome is CompletionOutcome.OPERATOR_REVIEW:
            acknowledge_button = getattr(self, "notice_ack_button", None)
            try:
                if acknowledge_button is not None:
                    acknowledge_button.focus_set()
            except (tk.TclError, AttributeError):
                pass
        return snapshot

    def _clear_settled_operator_context(self) -> None:
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        presenter = self._warning_state_presenter()
        presenter.clear_completion()
        presenter.clear_last_normal_scan()
        presenter.clear()
        self._last_normal_scan_display_item_code = ""
        self._stop_warning_beep()
        self._render_warning_state()

    def _sync_last_normal_scan_from_active_tray(self, *, clear_when_inactive: bool = False) -> None:
        tray = getattr(self, "current_tray", None)
        active_tray = bool(getattr(tray, "master_label_code", ""))
        presenter = self._warning_state_presenter()
        if not active_tray:
            if clear_when_inactive:
                presenter.clear_last_normal_scan()
                self._last_normal_scan_display_item_code = ""
                self._render_warning_state()
            return
        presenter.clear_last_normal_scan()
        scanned_barcodes = list(getattr(tray, "scanned_barcodes", []) or [])
        if scanned_barcodes:
            self._last_normal_scan_display_item_code = str(getattr(tray, "item_code", "") or "")
            presenter.record_normal_scan(str(scanned_barcodes[-1]))
        self._render_warning_state()

    def show_fullscreen_warning(self, title: str, message: str, color: str):
        normalized_title = str(title or "확인 필요").strip() or "확인 필요"
        normalized_message = str(message or "내용을 확인해 주세요.").strip() or "내용을 확인해 주세요."
        code_slug = re.sub(r"[^0-9A-Za-z가-힣]+", "_", normalized_title).strip("_").lower() or "warning"
        notice = Notice(
            code=f"scan.{code_slug}",
            title=normalized_title,
            message=normalized_message,
            severity=self._notice_severity_for_color(color),
            blocking=True,
        )
        changed = self._warning_state_presenter().present(notice)
        if changed:
            self._start_warning_beep()
        if getattr(self, "notice_frame", None) is not None:
            self._render_warning_state()
            acknowledge_button = getattr(self, "notice_ack_button", None)
            try:
                if changed and acknowledge_button is not None:
                    acknowledge_button.focus_set()
            except (tk.TclError, AttributeError):
                pass
            return

        popup = tk.Toplevel(self.root); popup.title(normalized_title); popup.attributes('-fullscreen', True)
        popup.configure(bg=color); popup.grab_set()
        def on_popup_close():
            self._acknowledge_active_notice(); popup.destroy()
        title_font = (self.DEFAULT_FONT, int(60*self.scale_factor), 'bold')
        msg_font = (self.DEFAULT_FONT, int(30*self.scale_factor), 'bold')
        tk.Label(popup, text=normalized_title, font=title_font, fg='white', bg=color).pack(pady=(100, 50), expand=True)
        tk.Label(popup, text=normalized_message, font=msg_font, fg='white', bg=color, wraplength=self.root.winfo_screenwidth() - 100, justify=tk.CENTER).pack(pady=20, expand=True)
        btn = tk.Button(popup, text="확인 (클릭)", font=msg_font, command=on_popup_close, bg='white', fg=color, relief='flat', padx=20, pady=10)
        btn.pack(pady=50, expand=True); btn.focus_set()

    def _cancel_all_jobs(self):
        self._cancel_master_preflight()
        for attribute in ("_direct_sync_health_job", "_direct_sync_health_poll_job"):
            job = getattr(self, attribute, None)
            if job:
                try:
                    self.root.after_cancel(job)
                except (tk.TclError, AttributeError):
                    pass
                setattr(self, attribute, None)
        if self.clock_job: self.root.after_cancel(self.clock_job); self.clock_job = None
        self._cancel_status_message_timer()
        if self.stopwatch_job: self._stop_stopwatch()
        if self.idle_check_job: self._stop_idle_checker()
        if self.focus_return_job: self.root.after_cancel(self.focus_return_job); self.focus_return_job = None
        self._stop_warning_beep()

    def _preflight_hold_matches_current_tray(
        self,
        snapshot: PreflightHoldSnapshot,
    ) -> bool:
        tray = getattr(self, "current_tray", None)
        candidates = (
            str(getattr(tray, "master_label_code", "") or ""),
            str(getattr(tray, "canonical_input_tag_qr", "") or ""),
            str(getattr(tray, "active_label_qr_payload", "") or ""),
        )
        master = normalize_master_label_input(snapshot.master_raw)
        if any(normalize_master_label_input(value) == master for value in candidates if value):
            return True
        master_fields = self._parse_new_format_qr(master) or {}
        if not master_fields:
            return False
        for value in candidates:
            candidate_fields = self._parse_new_format_qr(
                normalize_master_label_input(value)
            ) or {}
            if (
                str(candidate_fields.get("ITG") or "").strip()
                == str(master_fields.get("ITG") or "").strip()
                and str(candidate_fields.get("CLC") or "").strip()
                == str(master_fields.get("CLC") or "").strip()
                and str(master_fields.get("ITG") or "").strip()
            ):
                return True
        return False

    def _preserve_preflight_hold_for_close(self) -> tuple[bool, bool]:
        store = self._preflight_hold_store()
        if not store.exists():
            self._preflight_hold_snapshot = None
            self._preflight_hold_draining = False
            return True, False
        try:
            snapshot = store.load()
        except PreflightHoldError:
            messagebox.showerror(
                "보류 입력 확인 필요",
                "사전조회 보류 파일을 읽지 못해 프로그램을 종료하지 않습니다.",
                parent=getattr(self, "root", None),
            )
            return False, True
        self._preflight_hold_snapshot = snapshot
        current_master = str(
            getattr(getattr(self, "current_tray", None), "master_label_code", "")
            or ""
        )
        if snapshot.state == HOLD_DRAINING:
            if not current_master or not self._preflight_hold_matches_current_tray(
                snapshot
            ):
                messagebox.showerror(
                    "보류 입력 소유권 확인 필요",
                    "제품 반영 중인 보류 묶음과 현재 트레이가 일치하지 않아 "
                    "프로그램을 종료하지 않습니다. 파일을 보존하고 관리자에게 "
                    "문의하세요.",
                    parent=getattr(self, "root", None),
                )
                return False, True
            if not self._save_current_tray_state():
                messagebox.showerror(
                    "보류 입력 저장 실패",
                    "제품 반영 중인 현재 트레이를 저장하지 못해 프로그램을 "
                    "종료하지 않습니다.",
                    parent=getattr(self, "root", None),
                )
                return False, True
            self._preflight_hold_draining = True
        elif current_master:
            messagebox.showerror(
                "보류 입력 소유권 충돌",
                "중앙 조회 보류 묶음과 별도의 현재 트레이가 함께 있어 프로그램을 "
                "종료하지 않습니다. 두 상태를 보존하고 관리자에게 문의하세요.",
                parent=getattr(self, "root", None),
            )
            return False, True
        snapshot_hash = store.snapshot_hash(snapshot)
        detail = self._preflight_hold_ownership_detail(
            snapshot,
            snapshot_hash=snapshot_hash,
            reason="app_close_durable_handoff",
        )
        try:
            audited = bool(
                self._log_event(
                    "PHS2_PREFLIGHT_HOLD_CLOSE_HANDOFF",
                    detail=detail,
                    synchronous=True,
                    idempotency_key=(
                        "preflight-hold-close:"
                        f"{snapshot.preflight_id}:{snapshot_hash}"
                    ),
                    deduplicate=True,
                )
            )
        except Exception:
            audited = False
        if not audited:
            messagebox.showerror(
                "보류 입력 종료 기록 실패",
                "보류 묶음의 종료 인계 기록을 남기지 못해 프로그램을 종료하지 "
                "않습니다.",
                parent=getattr(self, "root", None),
            )
            return False, True
        return True, True

    def _abort_application_close(self) -> None:
        self._ui_close_requested = False
        self._ui_close_lane_drained = False
        self._preflight_close_writer_draining = False
        self._preflight_close_writer_drained = False
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and str(getattr(lane, "state", "") or "") == LANE_CLOSED:
            self._ui_lane = None
        self._set_scan_callback_pending(False)
        self._set_preflight_scan_input_locked(
            self._preflight_context_blocks_mutation()
        )
        snapshot = getattr(self, "_preflight_hold_snapshot", None)
        if (
            isinstance(snapshot, PreflightHoldSnapshot)
            and snapshot.state == HOLD_DRAINING
            and getattr(self, "_preflight_hold_draining", False)
            and self._preflight_hold_matches_current_tray(snapshot)
        ):
            self.root.after(0, self._drain_preflight_hold_head)

    def on_closing(self, *, _confirmed: bool = False):
        if not _confirmed and not messagebox.askokcancel(
            "종료",
            "프로그램을 종료하시겠습니까?",
        ):
            return
        if not _confirmed:
            self._event_log_close_join_attempts = 0
        if (
            getattr(self, "_scan_callback_pending", False)
            and not getattr(self, "_ui_close_requested", False)
        ):
            self.show_status_message(
                "접수 중인 스캔을 먼저 정리한 뒤 종료합니다.",
                self.COLOR_PRIMARY,
                duration=0,
            )
            self.root.after(0, lambda: self.on_closing(_confirmed=True))
            return

        self._ui_close_requested = True
        self._set_scan_callback_pending(False)
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and not getattr(self, "_ui_close_lane_drained", False):
            self.show_status_message(
                "진행 중인 처리를 안전하게 마친 뒤 종료합니다.",
                self.COLOR_PRIMARY,
                duration=0,
            )

            def resume_after_lane() -> None:
                self._ui_close_lane_drained = True
                self.on_closing(_confirmed=True)

            lane.drain_then(resume_after_lane)
            return

        hold_writer = getattr(self, "_preflight_hold_writer_instance", None)
        if (
            hold_writer is not None
            and not getattr(self, "_preflight_close_writer_drained", False)
        ):
            if getattr(self, "_preflight_close_writer_draining", False):
                return
            self._preflight_close_writer_draining = True
            self.show_status_message(
                "보류 입력 저장을 마친 뒤 종료합니다.",
                self.COLOR_PRIMARY,
                duration=0,
            )

            def resume_after_hold_writer() -> None:
                self._preflight_close_writer_draining = False
                self._preflight_close_writer_drained = True
                self.on_closing(_confirmed=True)

            hold_writer.drain_then(resume_after_hold_writer)
            return

        hold_safe, hold_owned = self._preserve_preflight_hold_for_close()
        if not hold_safe:
            self._abort_application_close()
            return

        if getattr(self, "master_label_replace_state", None):
            if not self._log_master_label_replacement_cancel(reason="app_close"):
                messagebox.showerror(
                    "교체 취소 기록 실패",
                    "현품표 교체 취소 기록을 남기지 못해 프로그램을 종료하지 "
                    "않습니다.",
                )
                self._abort_application_close()
                return
            self._reset_master_label_replacement_state()
        exchange_session = getattr(
            self,
            "current_exchange_session",
            ProductExchangeSession(),
        )
        if exchange_session.defective_barcodes or exchange_session.good_barcodes:
            if not self._cancel_exchange(reason="app_close"):
                self._abort_application_close()
                return

        deleted_current_state_for_close = False
        if (
            self.worker_name
            and self.current_tray.master_label_code
            and not hold_owned
        ):
            if self._operator_review_blocks_mutation():
                if not self._save_current_tray_state():
                    messagebox.showerror(
                        "작업 저장 실패",
                        "담당자 확인이 필요한 트레이를 저장하지 못해 프로그램을 "
                        "종료하지 않습니다.",
                    )
                    self._abort_application_close()
                    return
            elif messagebox.askyesno(
                "작업 저장",
                "진행 중인 트레이를 저장하고 종료할까요?",
            ):
                if not self._save_current_tray_state():
                    messagebox.showerror(
                        "작업 저장 실패",
                        "진행 중인 트레이 상태를 저장하지 못해 프로그램을 종료하지 "
                        "않습니다.",
                    )
                    self._abort_application_close()
                    return
            else:
                if not self._log_current_tray_discarded(
                    reason="close_without_saving",
                    synchronous=True,
                ):
                    messagebox.showerror(
                        "작업 기록 실패",
                        "저장하지 않고 종료한 작업 기록을 남기지 못해 프로그램을 "
                        "종료하지 않습니다.",
                    )
                    self._abort_application_close()
                    return
                if not self._delete_current_tray_state():
                    messagebox.showerror(
                        "작업 삭제 실패",
                        "현재 트레이 상태 파일을 삭제하지 못해 프로그램을 종료하지 "
                        "않습니다.",
                    )
                    self._abort_application_close()
                    return
                deleted_current_state_for_close = True
        if self.worker_name and not self._end_work_session(reason="app_close"):
            restore_notice = ""
            if deleted_current_state_for_close and self.current_tray.master_label_code:
                if self._save_current_tray_state():
                    restore_notice = "\n\n삭제했던 현재 트레이 상태 파일을 복구했습니다."
                else:
                    restore_notice = (
                        "\n\n삭제했던 현재 트레이 상태 파일 복구에도 실패했습니다. "
                        "상태 폴더를 확인하세요."
                    )
            messagebox.showerror(
                "작업 종료 기록 실패",
                "작업 종료 기록을 남기지 못해 프로그램을 종료하지 않습니다."
                f"{restore_notice}",
            )
            self._abort_application_close()
            return
        if hasattr(self, "paned_window") and self.paned_window.winfo_exists():
            try:
                num_panes = len(self.paned_window.panes())
                if num_panes > 1:
                    self.paned_window_sash_positions = {
                        str(i): self.paned_window.sashpos(i)
                        for i in range(num_panes - 1)
                    }
            except tk.TclError as exc:
                print(f"종료 시 sash 위치 저장 오류: {exc}")
        self._finalize_application_close()

    def _finalize_application_close(self) -> None:
        lane = getattr(self, "_ui_lane", None)
        if lane is not None:
            lane.close_idle()
        if not getattr(self, "_event_log_close_requested", False):
            self.save_settings()
            self._cancel_all_jobs()
            self.log_queue.put(None)
            self._event_log_close_requested = True
        if self.log_thread.is_alive():
            attempts = int(
                getattr(self, "_event_log_close_join_attempts", 0) or 0
            )
            self.log_thread.join(
                timeout=self.EVENT_LOG_CLOSE_JOIN_TIMEOUT_SECONDS
            )
            attempts += 1
            self._event_log_close_join_attempts = attempts
        if self.log_thread.is_alive():
            if attempts < self.EVENT_LOG_CLOSE_MAX_JOIN_ATTEMPTS:
                try:
                    self.root.after(
                        0,
                        lambda: self.on_closing(_confirmed=True),
                    )
                except (AttributeError, tk.TclError):
                    pass
                return
            if lane is not None:
                try:
                    lane.mark_broken(
                        RuntimeError(
                            "event log writer exceeded the bounded close budget"
                        )
                    )
                except (AttributeError, RuntimeError):
                    pass
            self._ui_close_requested = False
            try:
                self.show_status_message(
                    "종료 정리 지연 · 현재 상태를 유지합니다. 다시 종료해 주세요.",
                    self.COLOR_DANGER,
                    duration=0,
                )
            except (AttributeError, tk.TclError):
                pass
            return
        self._event_log_close_join_attempts = 0
        outbox = getattr(self, "_event_log_outbox_instance", None)
        if outbox is not None and outbox.has_unstaged:
            self._event_log_close_requested = False
            self._ui_close_requested = False
            self.log_thread = threading.Thread(target=self._event_log_writer, daemon=True)
            self.log_thread.start()
            self.show_status_message(
                "로그 저장 실패 · 재시도 중입니다. 저장 공간을 확인하세요. 저장 전에는 종료할 수 없습니다.",
                self.COLOR_DANGER, duration=0,
            )
            self._poll_event_log_notice()
            return
        stop_all_sounds()
        self.root.destroy()

    def _event_log_outbox(self, log_file_path: str) -> EventLogOutbox:
        store = getattr(self, "_event_log_outbox_instance", None)
        if store is None:
            directory = Path(getattr(self, "save_folder", "") or Path(log_file_path).parent)
            store = self._event_log_outbox_instance = EventLogOutbox(directory / "_event_outbox")
        return store

    def _flush_pending_event_logs(self) -> bool:
        store = getattr(self, "_event_log_outbox_instance", None)
        if store is None:
            return True
        try:
            store.drain()
        except Exception as exc:
            message = f"로그 파일 쓰기 오류: {exc.__class__.__name__}"
            if message != getattr(self, "last_log_write_error", None):
                self._record_log_write_error(message)
            self._event_log_notice = "로그 저장 실패 · 원 기록을 유지하고 재시도 중입니다. 저장 공간을 확인하세요."
            return False
        if getattr(self, "_event_log_notice", None):
            self._event_log_notice = "로그 저장 재시도를 완료했습니다."
        return True

    def _poll_event_log_notice(self) -> None:
        notice = getattr(self, "_event_log_notice", None)
        if notice:
            recovered = notice == "로그 저장 재시도를 완료했습니다."
            self.show_status_message(
                notice, self.COLOR_SUCCESS if recovered else self.COLOR_DANGER,
                duration=4000 if recovered else 0,
            )
            if recovered:
                self._event_log_notice = None
        if not getattr(self, "_event_log_close_requested", False):
            self.root.after(200, self._poll_event_log_notice)

    def _event_log_writer(self):
        self._flush_pending_event_logs()
        while True:
            try:
                queued_item = self.log_queue.get(timeout=1.0)
            except queue.Empty:
                self._flush_pending_event_logs()
                continue
            try:
                self._flush_pending_event_logs()
                if queued_item is None:
                    break
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

    def _defer_saved_recovery_state(self, saved_state: Dict[str, Any]) -> bool:
        """Park a declined same-worker recovery before releasing current state."""

        try:
            validate_tray_state(saved_state, default_tray_size=self.TRAY_SIZE)
            deferred = self._parked_store().defer_recovery_state(
                saved_state,
                worker_name=persistent_operator_name(
                    saved_state.get("worker_name") or self.worker_name
                ),
                computer_id=str(getattr(self, "computer_id", "") or ""),
            )
        except Exception as exc:
            print(
                "이전 작업 보류 사본 저장 실패: "
                f"{exc.__class__.__name__}"
            )
            return False

        try:
            parked_logged = bool(
                self._log_event(
                    "TRAY_PARKED",
                    detail={
                        "reason": "restore_declined_same_worker",
                        "defer_id": deferred.defer_id,
                        "state_hash": deferred.state_hash,
                        "master_label_code": saved_state.get("master_label_code"),
                        "item_code": saved_state.get("item_code"),
                        "item_name": saved_state.get("item_name"),
                        "scan_count": len(saved_state.get("scanned_barcodes") or []),
                        "tray_capacity": saved_state.get("tray_size"),
                    },
                    synchronous=True,
                    idempotency_key=f"tray-parked-recovery:{deferred.defer_id}",
                    deduplicate=True,
                )
            )
        except Exception as exc:
            print(
                "이전 작업 보류 감사 기록 실패: "
                f"{exc.__class__.__name__}"
            )
            parked_logged = False
        if not parked_logged:
            return False
        if not self._delete_current_tray_state():
            return False
        self.current_tray = TraySession()
        return True

    def _log_event(
        self,
        event_type: str,
        detail: Optional[Dict] = None,
        synchronous: bool = False,
        canonical_event_name: Optional[str] = None,
        idempotency_key: str = "",
        event_timestamp: str = "",
        log_file_path_override: str = "",
        deduplicate: bool = False,
        worker_name_override: str = "",
    ) -> bool:
        projection_worker_name = persistent_operator_name(
            worker_name_override or self.worker_name
        )
        if not projection_worker_name: return False
        target_log_file_path = str(
            log_file_path_override or self.log_file_path or ""
        ).strip()
        if not target_log_file_path: return False
        normalized_idempotency_key = str(idempotency_key or "").strip()
        raw_detail = dict(detail or {})
        if not synchronous and not normalized_idempotency_key:
            normalized_idempotency_key = str(raw_detail.get("idempotency_key") or uuid.uuid4().hex)
        local_only = (
            str(event_type or "").strip() in LOCAL_ONLY_EVENT_TYPES
            or bool(getattr(getattr(self, "current_tray", None), "is_test_tray", False))
        )

        if local_only:
            target_log_file_path = str(
                local_only_event_log_path(
                    target_log_file_path,
                    local_events_dir=getattr(self, "local_events_folder", ""),
                )
            )
            raw_detail["stream_disposition"] = "LOCAL_ONLY_NOT_FOR_DIRECT_SYNC"
            raw_detail["direct_sync_eligible"] = False
            raw_detail["stream_disposition_reason"] = (
                "EXPLICIT_LOCAL_EVENT_TYPE"
                if str(event_type or "").strip() in LOCAL_ONLY_EVENT_TYPES
                else "TEST_TRAY"
            )
        if normalized_idempotency_key:
            existing_key = str(raw_detail.get("idempotency_key") or "").strip()
            if existing_key and existing_key != normalized_idempotency_key:
                return False
            raw_detail["idempotency_key"] = normalized_idempotency_key
        try:
            enriched_detail = self._plan_b_event_detail(
                event_type,
                raw_detail,
                canonical_event_name=canonical_event_name,
            )
            enriched_detail = sanitize_persistent_value(enriched_detail)
            details_json = (
                redact_protected_admin_identity(
                    json.dumps(enriched_detail, ensure_ascii=False, allow_nan=False)
                )
                if enriched_detail
                else ''
            )
        except (TypeError, ValueError) as e:
            print(f"로그 상세 직렬화 오류: {e}")
            return False
        safe_event_type = redact_protected_admin_identity(event_type)
        log_entry = {
            'timestamp': str(event_timestamp or datetime.datetime.now().isoformat()),
            'worker_name': projection_worker_name,
            'event': safe_event_type,
            'details': details_json,
        }
        if synchronous:
            try:
                if hasattr(self, "log_queue") and hasattr(self.log_queue, "join"):
                    self.log_queue.join()
                if not self._flush_pending_event_logs():
                    return False
                if normalized_idempotency_key and deduplicate:
                    appended = append_event_log_entry_idempotent(
                        target_log_file_path,
                        log_entry,
                        event_type=safe_event_type,
                        idempotency_key=normalized_idempotency_key,
                        durable=True,
                    )
                    self._last_log_event_was_replay = not appended
                else:
                    append_event_log_entry(
                        target_log_file_path,
                        log_entry,
                        durable=True,
                    )
                    self._last_log_event_was_replay = False
                if not local_only and event_type in {
                    "TRAY_COMPLETE",
                    "PRODUCT_EXCHANGE_COMPLETED",
                    "PHS_REPLACEMENT_WAITING_MARKED",
                }:
                    self._trigger_session_direct_sync(event_type)
                return True
            except Exception as e:
                error_message = f"로그 파일 쓰기 오류: {e}"
                self._record_log_write_error(error_message)
                print(error_message)
                return False
        try:
            self._event_log_outbox(target_log_file_path).stage(target_log_file_path, log_entry)
        except Exception as exc:
            self._record_log_write_error(f"로그 재시도 사본 저장 오류: {exc.__class__.__name__}")
            self._event_log_notice = "로그 저장 실패 · 재시도 중입니다. 저장 공간을 확인하고 이 PC를 종료하지 마세요."
            return False
        self.log_queue.put({'log_file_path': target_log_file_path, 'log_entry': log_entry})
        return True

    def _schedule_direct_sync_health_refresh(self, *, delay_ms: int = 5000) -> None:
        if getattr(self, "_direct_sync_health_job", None) is not None:
            return
        try:
            self._direct_sync_health_job = self.root.after(
                max(0, int(delay_ms)),
                self._start_direct_sync_health_refresh,
            )
        except (tk.TclError, AttributeError):
            self._direct_sync_health_job = None

    def _start_direct_sync_health_refresh(self) -> None:
        self._direct_sync_health_job = None
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and lane.is_busy():
            self._schedule_direct_sync_health_refresh(delay_ms=5000)
            return
        if getattr(self, "_direct_sync_health_pending", False):
            self._schedule_direct_sync_health_refresh(delay_ms=5000)
            return

        direct_sync_root = Path(
            str(getattr(self, "direct_sync_program_data_root", "") or "")
        )
        generation = int(getattr(self, "_direct_sync_health_generation", 0)) + 1
        self._direct_sync_health_generation = generation
        self._direct_sync_health_pending = True
        result_queue = getattr(self, "_direct_sync_health_queue", None)
        if result_queue is None:
            result_queue = queue.Queue(maxsize=1)
            self._direct_sync_health_queue = result_queue
        db_path = direct_sync_root / "queue" / "direct_sync_relay.sqlite3"
        runtime_status_path = direct_sync_root / "status" / "direct_sync_relay_status.json"

        def reader() -> None:
            reader_thread_id = threading.get_ident()
            try:
                health = read_relay_health(
                    db_path=db_path,
                    runtime_status_path=runtime_status_path,
                )
            except BaseException:
                health = RelayHealth(
                    state="blocked",
                    pending_count=0,
                    failed_permanent_count=0,
                    operator_review_count=0,
                    last_acked_at="",
                    oldest_pending_at="",
                    observed_at=datetime.datetime.now(datetime.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat(),
                    error_code="relay_health_read_failed",
                )
            result_queue.put((generation, health, reader_thread_id))

        threading.Thread(
            target=reader,
            name="container-audit-direct-sync-health",
            daemon=True,
        ).start()
        self._poll_direct_sync_health_result()

    def _poll_direct_sync_health_result(self) -> None:
        self._direct_sync_health_poll_job = None
        result_queue = getattr(self, "_direct_sync_health_queue", None)
        if result_queue is None:
            self._direct_sync_health_pending = False
            self._schedule_direct_sync_health_refresh(delay_ms=5000)
            return
        try:
            result = result_queue.get_nowait()
        except queue.Empty:
            try:
                self._direct_sync_health_poll_job = self.root.after(
                    25,
                    self._poll_direct_sync_health_result,
                )
            except (tk.TclError, AttributeError):
                self._direct_sync_health_pending = False
            return

        result_queue.task_done()
        generation, health = result[:2]
        if len(result) > 2:
            self._direct_sync_health_reader_thread_id = result[2]
        self._direct_sync_health_pending = False
        if generation == getattr(self, "_direct_sync_health_generation", 0):
            self._apply_direct_sync_health(health)
        self._schedule_direct_sync_health_refresh(delay_ms=5000)

    def _consume_direct_sync_wake_results(self) -> str:
        wake_queue = getattr(self, "_direct_sync_wake_results", None)
        if wake_queue is None:
            return str(getattr(self, "_direct_sync_wake_error_code", "") or "")
        latest = None
        while True:
            try:
                latest = wake_queue.get_nowait()
            except queue.Empty:
                break
            else:
                wake_queue.task_done()
        if isinstance(latest, DirectSyncWakeResult):
            self._direct_sync_wake_error_code = (
                "" if latest.status == "PASS" else latest.error_category or "relay_wake_unknown"
            )
        return str(getattr(self, "_direct_sync_wake_error_code", "") or "")

    def _apply_direct_sync_health(self, health: RelayHealth) -> None:
        if not isinstance(health, RelayHealth):
            return
        self._direct_sync_health_apply_thread_id = threading.get_ident()
        wake_error = self._consume_direct_sync_wake_results()
        if wake_error:
            health = RelayHealth(
                state="blocked",
                pending_count=health.pending_count,
                failed_permanent_count=health.failed_permanent_count,
                operator_review_count=health.operator_review_count,
                last_acked_at=health.last_acked_at,
                oldest_pending_at=health.oldest_pending_at,
                observed_at=health.observed_at,
                error_code=wake_error,
            )
        self._direct_sync_health = health
        card = getattr(self, "info_cards", {}).get("direct_sync")
        if not card:
            return
        model = relay_health_card_model(health)
        attention = model["tone"] == "amber"
        card["frame"].configure(
            style="RelayAttention.TFrame" if attention else "Card.TFrame"
        )
        card["label"].configure(
            style=(
                "RelayAttention.Subtle.TLabel"
                if attention
                else "Card.Subtle.TLabel"
            )
        )
        card["value"].configure(
            text="\n".join(value for value in (model['summary'], model['detail']) if value),
            style=(
                "RelayAttention.Value.TLabel"
                if attention
                else "Card.Value.TLabel"
            ),
        )

    def _show_direct_sync_status_details(self) -> None:
        health = getattr(self, "_direct_sync_health", None)
        if not isinstance(health, RelayHealth):
            health = RelayHealth(
                state="blocked",
                pending_count=0,
                failed_permanent_count=0,
                operator_review_count=0,
                last_acked_at="",
                oldest_pending_at="",
                observed_at="",
                error_code="relay_health_not_loaded",
            )
        detail = relay_health_detail_model(health)
        messagebox.showinfo(
            "전송 상태 상세",
            "\n".join(f"{label}: {value}" for label, value in detail.items()),
            parent=getattr(self, "root", None),
        )
        self._schedule_focus_return()

    def _trigger_session_direct_sync(self, reason: str) -> None:
        app_root = getattr(self, "application_path", "")
        direct_sync_root = getattr(self, "direct_sync_program_data_root", "")
        scan_source_dir = getattr(self, "direct_sync_scan_source_dir", "")
        if not (app_root and direct_sync_root and scan_source_dir):
            return
        try:
            wake_results = getattr(self, "_direct_sync_wake_results", None)
            if wake_results is None:
                wake_results = queue.Queue()
                self._direct_sync_wake_results = wake_results
            start_session_direct_sync(
                app_root=app_root,
                direct_sync_root=direct_sync_root,
                scan_source_dir=scan_source_dir,
                reason=reason,
                result_queue=wake_results,
            )
        except Exception as exc:
            wake_results.put_nowait(
                DirectSyncWakeResult(
                    "UNKNOWN",
                    "relay_wake_start_failed",
                    datetime.datetime.now(datetime.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat(),
                )
            )
            print(f"direct-sync session trigger failed: {exc.__class__.__name__}")

    def _transfer_seal_runtime(self):
        coordinator = getattr(self, "transfer_seal_coordinator", None)
        if coordinator is not None:
            return coordinator
        data_root = str(getattr(self, "data_root", "") or "").strip()
        if not data_root:
            log_path = str(getattr(self, "log_file_path", "") or "").strip()
            data_root = str(Path(log_path).parent if log_path else Path(tempfile.gettempdir()) / "ContainerAudit")
        coordinator = transfer_seal_coordinator_from_env(
            Path(data_root) / "transfer_seal" / "transfer_seal.db",
            owner_thread_id_provider=self._transfer_coordinator_owner_provider(),
            ui_thread_id_provider=self._transfer_coordinator_ui_thread_id,
        )
        self.transfer_seal_coordinator = coordinator
        return coordinator

    def _transfer_member_exchange_runtime(self):
        coordinator = getattr(self, "transfer_member_exchange_coordinator", None)
        if coordinator is not None:
            return coordinator
        seal_coordinator = self._transfer_seal_runtime()
        coordinator = TransferMemberExchangeCoordinator(
            TransferMemberExchangeStore(
                seal_coordinator.store.db_path,
                ui_thread_id_provider=getattr(
                    seal_coordinator,
                    "_ui_thread_id_provider",
                    self._transfer_coordinator_ui_thread_id,
                ),
            ),
            seal_coordinator.client,
            getattr(seal_coordinator, "operation_lease_manager", None),
            owner_thread_id_provider=getattr(
                seal_coordinator,
                "_owner_thread_id_provider",
                self._transfer_coordinator_owner_thread_id,
            ),
        )
        self.transfer_member_exchange_coordinator = coordinator
        return coordinator

    def _work_transfer_coordinator_ui_snapshot(
        self,
        *,
        master_label: str = "",
        precommand_query: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Copy shared-store state on the coordinator owner for Tk consumers."""

        seal_coordinator = getattr(self, "transfer_seal_coordinator", None)
        exact_history = False
        precommand_snapshot: Optional[Dict[str, Any]] = None
        if seal_coordinator is not None:
            exact_history = bool(
                seal_coordinator.client is not None
                or seal_coordinator.store.has_exact_history()
            )
            if isinstance(precommand_query, Mapping):
                row = seal_coordinator.store.precommand_operator_review(
                    master_label=str(
                        precommand_query.get("master_label") or ""
                    ),
                    scanned_barcodes=tuple(
                        precommand_query.get("scanned_barcodes") or ()
                    ),
                    error_code=str(
                        precommand_query.get("error_code") or ""
                    ),
                )
                precommand_snapshot = {
                    "query": {
                        "master_label": str(
                            precommand_query.get("master_label") or ""
                        ),
                        "scanned_barcodes": tuple(
                            precommand_query.get("scanned_barcodes") or ()
                        ),
                        "error_code": str(
                            precommand_query.get("error_code") or ""
                        ),
                    },
                    "row": dict(row) if row is not None else None,
                }

        normalized_master = str(master_label or "").strip()
        member_coordinator = getattr(
            self,
            "transfer_member_exchange_coordinator",
            None,
        )
        member_attempt = None
        member_known = not normalized_master or member_coordinator is not None
        if member_coordinator is not None and normalized_master:
            rows = member_coordinator.store.blocking_rows(
                master_label=normalized_master
            )
            if rows:
                member_attempt = copy.deepcopy(
                    member_coordinator._attempt(rows[-1])
                )

        return {
            "exact_history": exact_history,
            "member": {
                "known": member_known,
                "master_label": normalized_master,
                "attempt": member_attempt,
            },
            "precommand": precommand_snapshot,
        }

    def _apply_transfer_coordinator_ui_snapshot(
        self,
        snapshot: Optional[Mapping[str, Any]],
    ) -> None:
        """Publish only copied values; Tk never follows the snapshot to SQLite."""

        if not isinstance(snapshot, Mapping):
            return
        exact_history = bool(snapshot.get("exact_history"))
        self._exact_transfer_exchange_history_snapshot = exact_history
        if exact_history:
            self._exact_exchange_mode_active = True
        member = snapshot.get("member")
        if isinstance(member, Mapping):
            self._transfer_member_exchange_attempt_snapshot = {
                "known": bool(member.get("known")),
                "master_label": str(member.get("master_label") or ""),
                "attempt": copy.deepcopy(member.get("attempt")),
            }
        if "precommand" in snapshot:
            precommand = snapshot.get("precommand")
            self._precommand_operator_review_store_snapshot = (
                copy.deepcopy(precommand)
                if isinstance(precommand, Mapping)
                else None
            )

    def _current_transfer_member_exchange_attempt(self):
        tray = getattr(self, "current_tray", None)
        master_label = str(getattr(tray, "master_label_code", "") or "").strip()
        if not master_label:
            return None
        snapshot = getattr(
            self,
            "_transfer_member_exchange_attempt_snapshot",
            None,
        )
        if (
            not isinstance(snapshot, Mapping)
            or not bool(snapshot.get("known"))
            or str(snapshot.get("master_label") or "") != master_label
        ):
            return None
        attempt = snapshot.get("attempt")
        return (
            copy.deepcopy(attempt)
            if isinstance(attempt, MemberExchangeAttempt)
            else None
        )

    def _transfer_member_exchange_blocks_local_action(self, action: str) -> bool:
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return True
        attempt = self._current_transfer_member_exchange_attempt()
        if attempt is None:
            if getattr(self, "transfer_member_exchange_coordinator", None) is None:
                return False
            tray = getattr(self, "current_tray", None)
            master_label = str(
                getattr(tray, "master_label_code", "") or ""
            ).strip()
            snapshot = getattr(
                self,
                "_transfer_member_exchange_attempt_snapshot",
                None,
            )
            if master_label and (
                not isinstance(snapshot, Mapping)
                or not bool(snapshot.get("known"))
                or str(snapshot.get("master_label") or "") != master_label
            ):
                self.show_status_message(
                    "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                    self.COLOR_DANGER,
                )
                return True
            return False
        if attempt.status == "ACKED" and attempt.local_apply_status == "PENDING":
            self._reconcile_pending_local_member_exchanges()
        if (
            attempt.status == "OPERATOR_REVIEW"
            or attempt.local_apply_status == "OPERATOR_REVIEW"
        ):
            title = "중앙 제품 교체 확인 필요"
            message = (
                "중앙 제품 교체 결과를 자동으로 확인할 수 없습니다.\n"
                f"{action} 작업을 진행하지 말고 현재 트레이를 유지한 채 관리자에게 알려 주세요."
            )
        elif attempt.status == "ACKED":
            title = "중앙 제품 교체 복구 필요"
            message = (
                "중앙 제품 교체는 완료됐지만 현재 트레이에 반영되지 않았습니다.\n"
                f"로컬 복구가 끝날 때까지 {action} 작업을 진행할 수 없습니다."
            )
        else:
            title = "중앙 제품 교체 응답 대기"
            message = (
                "중앙 제품 교체 결과를 확인 중입니다.\n"
                f"확인이 끝날 때까지 {action} 작업을 진행할 수 없습니다."
            )
        messagebox.showerror(title, message, parent=getattr(self, "root", None))
        return True

    def _dismiss_transfer_exchange_preflight_for_explicit_retry(self) -> bool:
        """Release only preflight failures when the operator explicitly retries."""
        tray = getattr(self, "current_tray", None)
        master_label = str(getattr(tray, "master_label_code", "") or "").strip()
        if not master_label:
            return True

        coordinator = self._transfer_member_exchange_runtime()
        rows = coordinator.store.blocking_rows(master_label=master_label)
        if not rows:
            return True

        dismissible_rows = []
        for row in rows:
            if (
                row["status"] not in DISMISSIBLE_PREFLIGHT_STATUSES
                or row["command_json"] is not None
                or row["command_id"] is not None
                or row["receipt_json"] is not None
            ):
                return True
            dismissible_rows.append(row)

        try:
            for row in dismissible_rows:
                coordinator.store.dismiss_without_durable_command(
                    str(row["intent_id"]),
                    "operator_retry_after_preflight",
                )
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            return False
        return True

    def _precommand_operator_review_query(
        self,
    ) -> Optional[Dict[str, Any]]:
        """Build a Tk-owned identity for a lane-produced review snapshot."""

        snapshot = self._active_operator_review_snapshot()
        if (
            snapshot is None
            or str(snapshot.error_code or "").strip().upper()
            not in SAFE_TRANSFER_PREFLIGHT_RETRY_CODES
        ):
            return None
        tray = getattr(self, "current_tray", None)
        canonical_label = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        active_label = str(
            getattr(tray, "active_label_qr_payload", "") or ""
        ).strip()
        scanned_barcodes = list(
            getattr(tray, "scanned_barcodes", None) or []
        )
        if (
            not canonical_label
            or not active_label
            or active_label == canonical_label
            or str(snapshot.master_label or "").strip() != canonical_label
            or int(snapshot.scan_count or 0) != len(scanned_barcodes)
            or len(scanned_barcodes) != int(getattr(tray, "tray_size", 0) or 0)
        ):
            return None
        try:
            canonical_fields = validate_compact_phs2_fields(
                self._parse_new_format_qr(canonical_label) or {}
            )
            active_fields = validate_compact_phs2_fields(
                self._parse_new_format_qr(active_label) or {}
            )
        except (TransferSealError, TypeError, ValueError):
            return None
        if (
            canonical_fields.get("ITG") != active_fields.get("ITG")
            or not canonical_fields.get("CLC")
            or canonical_fields.get("CLC") != active_fields.get("CLC")
            or canonical_fields.get("LBL") == active_fields.get("LBL")
        ):
            return None
        active_label_id = str(
            getattr(tray, "active_label_id", "") or ""
        ).strip()
        if not active_label_id or active_label_id != active_fields.get("LBL"):
            return None
        return {
            "master_label": canonical_label,
            "scanned_barcodes": tuple(scanned_barcodes),
            "error_code": str(snapshot.error_code or "").strip(),
            "canonical_label_id": str(canonical_fields.get("LBL") or ""),
            "active_label_id": str(active_fields.get("LBL") or ""),
        }

    def _precommand_operator_review_retry_context(
        self,
    ) -> Optional[Dict[str, str]]:
        """Use only a copied lane snapshot for a never-posted preflight."""

        query = self._precommand_operator_review_query()
        snapshot = getattr(
            self,
            "_precommand_operator_review_store_snapshot",
            None,
        )
        if query is None or not isinstance(snapshot, Mapping):
            return None
        snapshot_query = snapshot.get("query")
        if not isinstance(snapshot_query, Mapping) or {
            "master_label": str(snapshot_query.get("master_label") or ""),
            "scanned_barcodes": tuple(
                snapshot_query.get("scanned_barcodes") or ()
            ),
            "error_code": str(snapshot_query.get("error_code") or ""),
        } != {
            "master_label": query["master_label"],
            "scanned_barcodes": tuple(query["scanned_barcodes"]),
            "error_code": query["error_code"],
        }:
            return None
        row = snapshot.get("row")
        if not isinstance(row, Mapping):
            return None
        return {
            "intent_id": str(row["intent_id"]),
            "error_code": str(row["last_error_code"]),
            "canonical_label_id": str(query["canonical_label_id"]),
            "active_label_id": str(query["active_label_id"]),
        }

    def _retry_precommand_operator_review_completion(self) -> bool:
        """Retry only a commandless review against a saved active successor."""

        if self._reject_mutation_during_preflight_hold():
            return False
        retry_context = self._precommand_operator_review_retry_context()
        snapshot = self._active_operator_review_snapshot()
        if retry_context is None or snapshot is None:
            self._render_warning_state()
            return False
        if not self._log_event(
            "TRANSFER_SEAL_PREFLIGHT_RETRY_REQUESTED",
            detail={
                **retry_context,
                "scan_count": len(self.current_tray.scanned_barcodes),
                "retry_policy": "COMMANDLESS_ACTIVE_SUCCESSOR_ONLY",
            },
            synchronous=True,
        ):
            messagebox.showerror(
                "사전검증 재시도 실패",
                "재시도 요청 기록을 저장하지 못해 현재 잠금을 유지합니다.",
                parent=getattr(self, "root", None),
            )
            return False

        presenter = self._warning_state_presenter()
        previous_pending = getattr(
            self,
            "_pending_operator_review_snapshot",
            None,
        )
        if not presenter.resolve_blocking_completion(snapshot):
            self._render_warning_state()
            return False
        self._pending_operator_review_snapshot = None
        presenter.acknowledge()
        self._stop_warning_beep()
        self._render_warning_state()
        self._update_action_button_states()
        self.show_status_message(
            "저장된 활성 현품표로 이적 사전검증을 다시 확인합니다.",
            self.COLOR_PRIMARY,
            duration=0,
        )

        def restore_previous_lock() -> bool:
            if self._active_blocking_completion_snapshot() is not None:
                return False
            self._pending_operator_review_snapshot = previous_pending or snapshot
            presenter.present_completion(snapshot)
            state_restored = self._save_current_tray_state()
            self._start_warning_beep()
            self._render_warning_state()
            self._update_action_button_states()
            message = "이적 사전검증을 완료하지 못해 기존 담당자 확인 잠금을 복원했습니다."
            if not state_restored:
                message += "\n잠금 상태 재저장에도 실패했으므로 프로그램을 종료하지 마세요."
            messagebox.showerror(
                "사전검증 재시도 실패",
                message,
                parent=getattr(self, "root", None),
            )
            return False

        if hasattr(getattr(self, "root", None), "tk"):
            try:
                admitted = self.request_complete_tray(
                    completion_callback=(
                        lambda completed: None
                        if completed
                        else restore_previous_lock()
                    )
                )
            except Exception as exc:
                print(f"이적 사전검증 재시도 실패: {exc.__class__.__name__}")
                admitted = False
            return True if admitted else restore_previous_lock()

        try:
            completed = bool(self.complete_tray())
        except Exception as exc:
            print(f"이적 사전검증 재시도 실패: {exc.__class__.__name__}")
            completed = False
        if completed:
            return True
        return restore_previous_lock()

    def _prepare_and_attempt_transfer_seal_snapshot(
        self,
        *,
        coordinator: Any,
        source_label_payload: str,
        source_label_fields: Mapping[str, Any],
        item_code: str,
        operator: str,
        scanned_barcodes: Sequence[str],
        relay_log_file_path: str,
        operation_lease_id: str,
        on_prepared: Callable[[SealAttempt], None],
    ) -> SealAttempt:
        prepare_arguments = {
            "master_label": source_label_payload,
            "master_label_fields": dict(source_label_fields),
            "item_id": item_code,
            "scanned_barcodes": tuple(scanned_barcodes),
            "operation_lease_id": operation_lease_id,
        }
        previewed = coordinator.preview(**prepare_arguments)
        prepared = coordinator.prepare(
            master_label=source_label_payload,
            master_label_fields=dict(source_label_fields),
            item_id=item_code,
            operator=operator,
            scanned_barcodes=tuple(scanned_barcodes),
            relay_log_file_path=relay_log_file_path,
            operation_lease_id=operation_lease_id,
            require_completion_checkpoint=True,
        )
        if prepared.intent_id != previewed.intent_id:
            raise TransferSealError(
                "TRANSFER_INTENT_PREVIEW_MISMATCH",
                "저장 전 계산한 이적 의도와 로컬 원장의 의도가 다릅니다.",
            )
        on_prepared(prepared)
        coordinator.confirm_completion_checkpoint(prepared.intent_id)
        drain_through = getattr(coordinator, "drain_pending_through", None)
        if callable(drain_through):
            results = drain_through(prepared.intent_id)
            for result in reversed(results):
                if result.intent_id == prepared.intent_id:
                    return result
        return coordinator.attempt(prepared.intent_id)

    def _prepare_and_attempt_transfer_seal(
        self,
        *,
        master_label_fields: Dict[str, Any],
        log_detail: Dict[str, Any],
        on_prepared: Callable[[SealAttempt], None],
    ) -> SealAttempt:
        coordinator = self._transfer_seal_runtime()
        source_label_payload = str(
            getattr(self.current_tray, "active_label_qr_payload", "")
            or self.current_tray.master_label_code
        )
        source_label_fields = self._parse_new_format_qr(source_label_payload)
        if not source_label_fields:
            raise TransferSealError(
                "PHS2_ACTIVE_LABEL_INVALID",
                "현재 사용 현품표를 중앙 이적 원본으로 확인할 수 없습니다.",
            )
        operation_lease_id = str(
            getattr(self.current_tray, "operation_lease_id", "") or ""
        ).strip()
        if (
            str(source_label_fields.get("PHS") or "").strip() == "2"
            and not operation_lease_id
        ):
            raise TransferSealError(
                "OPERATION_LEASE_REQUIRED",
                "이 트레이의 오프라인 이적 확인 정보가 없어 완료할 수 없습니다.",
            )
        return self._prepare_and_attempt_transfer_seal_snapshot(
            coordinator=coordinator,
            source_label_payload=source_label_payload,
            source_label_fields=source_label_fields,
            item_code=str(self.current_tray.item_code or ""),
            operator=persistent_operator_name(self.worker_name),
            scanned_barcodes=tuple(log_detail.get("product_barcodes") or ()),
            relay_log_file_path=str(getattr(self, "log_file_path", "") or ""),
            operation_lease_id=operation_lease_id,
            on_prepared=on_prepared,
        )

    @staticmethod
    def _attach_transfer_seal_detail(log_detail: Dict[str, Any], attempt: SealAttempt) -> None:
        log_detail.update(
            {
                "transfer_seal_schema_version": "container-audit-transfer-seal-v1",
                "transfer_seal_intent_id": attempt.intent_id,
                "transfer_local_completion_id": attempt.local_completion_id or None,
                "transfer_seal_status": attempt.status,
                "transfer_seal_idempotency_key": attempt.command_id or None,
                "transfer_bundle_id": attempt.transfer_bundle_id or None,
                "transfer_source_bundle_id": attempt.source_bundle_id or None,
                "transfer_remainder_bundle_id": attempt.remainder_bundle_id or None,
                "transfer_member_count": attempt.member_count,
                "transfer_membership_hash": attempt.membership_hash or None,
                "transfer_seal_qr_sha256": (
                    hashlib.sha256(attempt.seal_qr_payload.encode("utf-8")).hexdigest()
                    if attempt.seal_qr_payload
                    else None
                ),
                "transfer_seal_receipt_id": attempt.receipt_id or None,
                "transfer_authority_scope_id": attempt.authority_scope_id or None,
                "transfer_authority_epoch": attempt.authority_epoch or None,
                "transfer_ledger_plane": attempt.ledger_plane or None,
                "transfer_plane_epoch": attempt.plane_epoch or None,
                "transfer_inbound_iin": attempt.inbound_iin or None,
                "transfer_item_id": attempt.item_id or None,
                "transfer_uom": attempt.uom or None,
                "transfer_entity_versions": dict(attempt.entity_versions),
                "terminal_operation_lease_id": attempt.operation_lease_id or None,
                "terminal_operation_lease_state": attempt.operation_lease_state or None,
                "transfer_route_provenance": "CONTAINER_AUDIT_EXACT_PRODUCT_SCAN",
                "transfer_seal_retryable": attempt.retryable,
                "transfer_seal_error_code": attempt.error_code or None,
            }
        )

    def _project_transfer_post_review_row(
        self,
        row: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Idempotently project one durable post-local review case to CSV."""

        result = dict(row)
        try:
            event_detail = json.loads(
                str(
                    result.get("outbox_payload_json")
                    or result.get("evidence_json")
                    or ""
                )
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("durable post review evidence is invalid") from exc
        if not isinstance(event_detail, dict):
            raise ValueError("durable post review evidence is invalid")

        event_type = str(event_detail.get("event_type") or "").strip()
        idempotency_key = str(
            event_detail.get("idempotency_key") or ""
        ).strip()
        review_case_id = str(result.get("review_case_id") or "").strip()
        projection_log_file_path = str(
            result.get("projection_log_file_path") or ""
        ).strip()
        if (
            event_type != "POST_REVIEW_REQUIRED"
            or not idempotency_key
            or not review_case_id
            or str(event_detail.get("review_case_id") or "").strip()
            != review_case_id
            or not projection_log_file_path
        ):
            raise ValueError("durable post review projection is incomplete")
        if (
            str(result.get("outbox_payload_hash") or "").strip()
            and str(result.get("outbox_payload_hash") or "").strip()
            != str(result.get("evidence_hash") or "").strip()
        ):
            raise ValueError("durable post review outbox differs from case")

        enriched_detail = self._plan_b_event_detail(event_type, event_detail)
        log_entry = {
            "timestamp": str(
                event_detail.get("created_at")
                or result.get("created_at")
                or datetime.datetime.now().isoformat()
            ),
            "worker_name": persistent_operator_name(
                event_detail.get("operator")
                or getattr(self, "worker_name", "")
                or ""
            ),
            "event": event_type,
            "details": json.dumps(
                sanitize_persistent_value(enriched_detail),
                ensure_ascii=False,
                allow_nan=False,
            ),
        }
        append_event_log_entry_idempotent(
            projection_log_file_path,
            log_entry,
            event_type=event_type,
            idempotency_key=idempotency_key,
            durable=True,
        )
        store = self._transfer_seal_runtime().store
        receipt = store.record_post_review_projection(
            review_case_id,
            projection_log_file_path=projection_log_file_path,
        )
        self._trigger_session_direct_sync(event_type)
        result["projection_id"] = str(receipt["projection_id"])
        return result

    def _project_transfer_post_review_for_intent(
        self,
        intent_id: str,
    ) -> Dict[str, Any]:
        store = self._transfer_seal_runtime().store
        row = store.post_review_case_for_intent(intent_id)
        return self._project_transfer_post_review_row(dict(row))

    def _drain_transfer_post_review_projections(self) -> int:
        store = self._transfer_seal_runtime().store
        pending = store.pending_post_review_projections()
        for row in pending:
            self._project_transfer_post_review_row(dict(row))
        return len(pending)

    def _present_transfer_post_review_required_notice(
        self,
        review_case_id: str = "",
    ) -> bool:
        """Present worker-safe guidance while technical evidence stays local."""

        notice = Notice(
            code="transfer.post_review_required",
            title="완료 후 관리자 확인 필요",
            message=(
                "트레이 완료는 이 PC에 안전하게 저장되었습니다. "
                "중앙 반영 상태는 관리자 확인이 필요합니다. "
                "관리자에게 알린 뒤 확인 버튼을 눌러 주세요."
            ),
            severity=NoticeSeverity.WARNING,
            blocking=True,
        )
        presented = self._warning_state_presenter().present(notice)
        if presented:
            normalized_case_id = str(review_case_id or "").strip()
            if normalized_case_id:
                case_ids = getattr(
                    self,
                    "_presented_post_review_case_ids",
                    None,
                )
                if not isinstance(case_ids, set):
                    case_ids = set()
                    self._presented_post_review_case_ids = case_ids
                case_ids.add(normalized_case_id)
            self._start_warning_beep()
        self._render_warning_state()
        self._update_action_button_states()
        return presented

    def _refresh_transfer_post_review_state(self) -> bool:
        """Queue review projection replay behind the shared coordinator lane."""

        self._transfer_post_review_refresh_pending = True
        return self._schedule_transfer_post_review_refresh()

    def _retry_transfer_post_review(self) -> bool:
        """Offer one reviewed completion through the existing supervisor lane."""
        if not self._is_preflight_hold_supervisor():
            messagebox.showwarning("관리자 인증 필요", "관리자로 로그인해 주세요.", parent=self.root)
            return False
        if (
            getattr(getattr(self, "current_tray", None), "master_label_code", "")
            or self._warning_state_presenter().state.is_blocking
            or getattr(self, "_ui_close_requested", False)
            or getattr(self, "master_label_replace_state", None)
        ):
            return False
        lane = self._ui_task_lane()
        if lane.is_busy():
            return False
        cases = tuple(getattr(self, "_transfer_post_review_cases", ()) or ())
        case = next((row for row in cases if row.get("command_bound")), None)
        if case is None:
            self._refresh_transfer_post_review_state()
            messagebox.showinfo(
                "완료 작업 확인", "재시도할 저장 요청이 없습니다. 전송 상태를 확인해 주세요.",
                parent=self.root,
            )
            return False
        supervisor = persistent_operator_name(str(getattr(self, "worker_name", "") or ""))
        generation = int(getattr(self, "_scan_callback_epoch", 0) or 0)
        if not messagebox.askyesno(
            "완료 작업 중앙 반영 재시도",
            f"품목: {case['item_id']}\n수량: {case['scan_count']}개\n"
            f"완료 작업자: {case['operator']}\n\n"
            "관리자 확인을 마쳤습니까? 저장된 완료 요청을 그대로 다시 보냅니다.",
            parent=self.root,
        ):
            return False

        def authorized() -> bool:
            return bool(
                self._is_preflight_hold_supervisor()
                and persistent_operator_name(str(getattr(self, "worker_name", "") or "")) == supervisor
                and int(getattr(self, "_scan_callback_epoch", 0) or 0) == generation
                and not getattr(getattr(self, "current_tray", None), "master_label_code", "")
            )

        def audit(detail: Mapping[str, Any]) -> bool:
            return bool(self._log_event(
                "TRANSFER_SEAL_REVIEW_RETRY_REQUESTED", detail=dict(detail),
                synchronous=True, worker_name_override=supervisor,
            ))

        def work() -> SealAttempt:
            return self._transfer_seal_runtime().retry_operator_review(
                str(case["intent_id"]), supervisor=supervisor,
                authorize=authorized, record_audit=audit,
            )

        def finish(result: SealAttempt) -> None:
            self._refresh_transfer_post_review_state()
            self._update_action_button_states()
            if result.status == "ACKED":
                messagebox.showinfo(
                    "중앙 반영 확인", "저장된 완료 작업의 중앙 반영을 확인했습니다.", parent=self.root,
                )
            else:
                messagebox.showwarning(
                    "관리자 확인 계속 필요",
                    "완료 기록을 보존했습니다. 중앙 반영이 확인되지 않아 관리자 확인 상태를 유지합니다.",
                    parent=self.root,
                )

        def fail(exc: BaseException) -> None:
            self._refresh_transfer_post_review_state()
            self._update_action_button_states()
            messagebox.showwarning(
                "완료 작업 확인 필요",
                str(exc) if isinstance(exc, TransferSealError) else "요청을 처리하지 못했습니다. 저장 기록을 확인해 주세요.",
                parent=self.root,
            )

        admission = lane.submit(LaneTask(
            name="transfer-post-review-retry", generation=generation,
            work=work, finish=finish, fail=fail,
            on_idle=self._schedule_pending_transfer_coordinator_work,
            shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
        ))
        self._update_action_button_states()
        return bool(admission.accepted)

    def _schedule_transfer_post_review_refresh(self) -> bool:
        if (
            not getattr(self, "_transfer_post_review_refresh_pending", False)
            or getattr(self, "_transfer_post_review_refresh_inflight", False)
            or getattr(self, "_ui_close_requested", False)
        ):
            return False
        refresh_requested = bool(
            getattr(self, "_post_review_refresh_required", False)
        )
        tray = getattr(self, "current_tray", None)
        snapshot_master_label = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        precommand_query = self._precommand_operator_review_query()

        def work() -> Dict[str, Any]:
            replay_failed = False
            ui_snapshot = None
            try:
                self._drain_transfer_post_review_projections()
            except Exception:
                replay_failed = True
            try:
                cases = tuple(
                    dict(row)
                    for row in self._transfer_seal_runtime().store.post_review_cases(active_only=True)
                )
            except Exception:
                cases = ()
                replay_failed = True
            try:
                ui_snapshot = self._work_transfer_coordinator_ui_snapshot(
                    master_label=snapshot_master_label,
                    precommand_query=precommand_query,
                )
            except Exception:
                replay_failed = True
            return {
                "cases": cases,
                "refresh_requested": refresh_requested,
                "replay_failed": replay_failed,
                "ui_snapshot": ui_snapshot,
            }

        def finish(outcome: Mapping[str, Any]) -> None:
            self._transfer_post_review_refresh_inflight = False
            self._apply_transfer_coordinator_ui_snapshot(
                outcome.get("ui_snapshot")
            )
            self._finish_transfer_post_review_refresh(outcome)

        def fail(exc: BaseException) -> None:
            self._transfer_post_review_refresh_inflight = False
            self._post_review_refresh_required = True
            print(
                "이적 사후 확인 replay lane 실패: "
                f"{exc.__class__.__name__}"
            )
            self._present_transfer_post_review_required_notice()

        owner_source = getattr(self, "transfer_seal_coordinator", None)
        owner_provider = getattr(
            owner_source,
            "_owner_thread_id_provider",
            self._transfer_coordinator_owner_provider(),
        )
        if (
            callable(owner_provider)
            and owner_provider() == threading.get_ident()
            and getattr(self, "_ui_lane", None) is None
        ):
            self._transfer_post_review_refresh_pending = False
            self._transfer_post_review_refresh_inflight = True
            try:
                finish(work())
            except Exception as exc:
                fail(exc)
            return True

        lane = self._ui_task_lane()
        if lane.is_busy():
            return False
        self._transfer_post_review_refresh_pending = False
        self._transfer_post_review_refresh_inflight = True

        admission = lane.submit(
            LaneTask(
                name="transfer-post-review-refresh",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=self._schedule_pending_transfer_coordinator_work,
                shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
            )
        )
        if not admission.accepted:
            self._transfer_post_review_refresh_inflight = False
            self._transfer_post_review_refresh_pending = True
            return False
        return True

    def _schedule_pending_transfer_coordinator_work(self) -> None:
        try:
            self.root.after(0, self._admit_pending_transfer_coordinator_work)
        except (AttributeError, tk.TclError):
            pass

    def _admit_pending_transfer_coordinator_work(self) -> None:
        if getattr(self, "_member_exchange_reconcile_pending", False):
            if self._schedule_member_exchange_reconcile():
                return
        self._schedule_transfer_post_review_refresh()
        if not getattr(self, "_ui_close_requested", False):
            self._update_action_button_states()

    def _finish_transfer_post_review_refresh(
        self,
        outcome: Mapping[str, Any],
    ) -> bool:
        refresh_requested = bool(outcome.get("refresh_requested"))
        replay_failed = bool(outcome.get("replay_failed"))
        cases = tuple(outcome.get("cases") or ())
        self._transfer_post_review_cases = cases

        presented_ids = getattr(
            self,
            "_presented_post_review_case_ids",
            None,
        )
        if not isinstance(presented_ids, set):
            presented_ids = set()
            self._presented_post_review_case_ids = presented_ids
        for row in reversed(cases):
            review_case_id = str(row["review_case_id"] or "").strip()
            if review_case_id and review_case_id not in presented_ids:
                presented = self._present_transfer_post_review_required_notice(
                    review_case_id
                )
                self._post_review_refresh_required = bool(
                    replay_failed or not presented
                )
                return presented

        if refresh_requested or replay_failed:
            presented = self._present_transfer_post_review_required_notice()
            self._post_review_refresh_required = bool(
                replay_failed or not presented
            )
            return presented

        self._post_review_refresh_required = False
        return False

    def _schedule_startup_transfer_recovery(self) -> bool:
        if (
            not getattr(self, "_startup_transfer_recovery_pending", False)
            or getattr(self, "_startup_transfer_recovery_inflight", False)
            or getattr(self, "_ui_close_requested", False)
        ):
            return False
        lane = self._ui_task_lane()
        if lane.is_busy():
            return False

        self._startup_transfer_recovery_inflight = True
        tray = getattr(self, "current_tray", None)
        snapshot_master_label = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        precommand_query = self._precommand_operator_review_query()

        def fail(exc: BaseException) -> None:
            self._startup_transfer_recovery_inflight = False
            self._startup_transfer_recovery_pending = True
            self._startup_transfer_recovery_waiting_for_hold = False
            self._startup_transfer_recovery_task_handle = None
            print(f"이적 재시작 복구 lane 실패: {exc.__class__.__name__}")

        admission = lane.submit(
            LaneTask(
                name="startup-transfer-recovery",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=lambda: self._retry_pending_transfer_seals(
                    master_label=snapshot_master_label,
                    precommand_query=precommand_query,
                ),
                finish=self._finish_startup_transfer_recovery,
                fail=fail,
                on_idle=self._schedule_pending_transfer_coordinator_work,
            )
        )
        if not admission.accepted:
            self._startup_transfer_recovery_inflight = False
            return False
        self._startup_transfer_recovery_task_handle = admission.handle
        return True

    def _finish_startup_transfer_recovery(
        self,
        outcome: Mapping[str, Any],
    ) -> None:
        self._startup_transfer_recovery_inflight = False
        self._startup_transfer_recovery_task_handle = None
        self._apply_transfer_coordinator_ui_snapshot(
            outcome.get("ui_snapshot")
        )
        if bool(outcome.get("replacement_projection_failed")):
            self._show_phs_replacement_waiting_storage_block()
        for result in outcome.get("seal_results", ()):
            if result.status == "OPERATOR_REVIEW":
                self._post_review_refresh_required = True
        for result in outcome.get("member_results", ()):
            if result.status == "OPERATOR_REVIEW":
                print(
                    "중앙 제품 교체 복구에 작업자 확인이 필요합니다: "
                    f"{result.intent_id} {result.error_code}"
                )
        blocked_by_hold = bool(outcome.get("blocked_by_hold")) or bool(
            self._preflight_context_blocks_mutation()
        )
        self._startup_transfer_recovery_waiting_for_hold = blocked_by_hold
        self._startup_transfer_recovery_pending = bool(
            blocked_by_hold
            or outcome.get("replacement_projection_failed")
        )

    def _retry_pending_transfer_seals(
        self,
        *,
        master_label: str = "",
        precommand_query: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        lane = getattr(self, "_ui_lane", None)
        if (
            lane is None
            or threading.get_ident() != getattr(lane, "worker_thread_id", None)
        ):
            raise RuntimeError("startup transfer recovery requires the shared lane worker")
        outcome: Dict[str, Any] = {
            "seal_results": (),
            "member_results": (),
            "blocked_by_hold": False,
            "replacement_projection_failed": False,
            "ui_snapshot": None,
        }

        def can_attempt() -> bool:
            blocked = bool(self._preflight_context_blocks_mutation())
            if blocked:
                outcome["blocked_by_hold"] = True
            return not blocked

        try:
            outcome["ui_snapshot"] = (
                self._work_transfer_coordinator_ui_snapshot(
                    master_label=master_label,
                    precommand_query=precommand_query,
                )
            )
        except Exception as exc:
            print(
                "이적 UI snapshot 갱신 실패: "
                f"{exc.__class__.__name__}"
            )
        if not can_attempt():
            return outcome
        try:
            self._drain_phs_replacement_waiting_projections()
        except Exception as exc:
            outcome["replacement_projection_failed"] = True
            print(
                "현품표 교체 대기 replay 실패: "
                f"{exc.__class__.__name__}"
            )
            return outcome
        if not can_attempt():
            return outcome
        try:
            coordinator = self._transfer_seal_runtime()
            outcome["seal_results"] = tuple(
                coordinator.drain_pending(can_attempt=can_attempt)
            )
        except Exception as exc:
            print(f"이적 seal 재시작 복구 실패: {exc.__class__.__name__}")
        if not can_attempt():
            return outcome
        try:
            exchange_coordinator = self._transfer_member_exchange_runtime()
            outcome["member_results"] = tuple(
                exchange_coordinator.drain_pending(can_attempt=can_attempt)
            )
        except Exception as exc:
            print(f"중앙 제품 교체 재시작 복구 실패: {exc.__class__.__name__}")
        try:
            outcome["ui_snapshot"] = (
                self._work_transfer_coordinator_ui_snapshot(
                    master_label=master_label,
                    precommand_query=precommand_query,
                )
            )
        except Exception as exc:
            print(
                "이적 UI snapshot 갱신 실패: "
                f"{exc.__class__.__name__}"
            )
        return outcome

    def _exact_transfer_exchange_blocked(self) -> bool:
        if getattr(self, "_exact_exchange_mode_active", False):
            return True
        coordinator = getattr(self, "transfer_seal_coordinator", None)
        if coordinator is None:
            return False
        if coordinator.client is not None:
            self._exact_exchange_mode_active = True
            return True
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and lane.is_busy():
            # A false snapshot can become true during an in-flight writer, so
            # action admission is conservative until the next lane checkpoint.
            return True
        history_snapshot = getattr(
            self,
            "_exact_transfer_exchange_history_snapshot",
            None,
        )
        if history_snapshot is None:
            return True
        blocked = bool(history_snapshot)
        if blocked:
            self._exact_exchange_mode_active = True
        return blocked

    def _block_unsafe_exact_exchange(self) -> bool:
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return True
        if not self._exact_transfer_exchange_blocked():
            return False
        coordinator = getattr(self, "transfer_seal_coordinator", None)
        if coordinator is not None:
            self._schedule_transfer_exchange_block_receipt(
                coordinator=coordinator,
                reason_code="BLOCKED_REQUIRES_TWO_BUNDLE_CAS",
                details={
                    "operator": persistent_operator_name(
                        getattr(self, "worker_name", "")
                    ),
                    "policy": "pre_seal_phs_exchange_requires_target_and_source_versions",
                    "server_command": "REPLACE_BUNDLE_MEMBERS",
                    "missing_client_contract": "exact_good_barcode_source_bundle_resolver",
                    "post_seal_policy": "POST_SEAL_REPLACEMENT_UNSUPPORTED",
                },
                event_type="PRODUCT_EXCHANGE_BLOCKED_EXACT_MEMBERSHIP",
                event_message="target/source PHS resolution and multi-bundle CAS are required",
            )
        messagebox.showwarning(
            "관리자 교체 절차 필요",
            "현재 작업은 기존 개별 교환 방식으로 처리할 수 없습니다.\n"
            "교체 대상과 새 양품의 소속을 함께 확인하는 관리자 교체 절차를 이용하세요.\n"
            "이미 봉인된 이적·포장 작업은 교체할 수 없습니다.",
        )
        return True

    def _block_unsafe_exact_master_label_replacement(self) -> bool:
        lane = getattr(self, "_ui_lane", None)
        if lane is not None and lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return True
        if not self._exact_transfer_exchange_blocked():
            return False
        coordinator = getattr(self, "transfer_seal_coordinator", None)
        if coordinator is not None:
            self._schedule_transfer_exchange_block_receipt(
                coordinator=coordinator,
                reason_code="BLOCKED_REQUIRES_REPLACE_BUNDLE_MEMBERS_CAS",
                details={
                    "operator": persistent_operator_name(
                        getattr(self, "worker_name", "")
                    ),
                    "operation": "completed_master_label_replacement",
                    "policy": "physical_open_reseal_and_exact_bundle_cas_required",
                },
                event_type="MASTER_LABEL_REPLACEMENT_BLOCKED_EXACT_MEMBERSHIP",
                event_message="physical open/reseal policy and exact bundle CAS are required",
            )
        messagebox.showwarning(
            "관리자 교체 절차 필요",
            "현재 완료 현품표는 기존 교체 방식으로 처리할 수 없습니다.\n"
            "이적 완료 현품표, 교체 제품의 원래 소속, 개봉·재봉인 여부를 함께 "
            "확인하는 관리자 교체 절차를 이용하세요.",
        )
        return True

    def _schedule_transfer_exchange_block_receipt(
        self,
        *,
        coordinator: Any,
        reason_code: str,
        details: Mapping[str, Any],
        event_type: str,
        event_message: str,
    ) -> bool:
        def work() -> str:
            return coordinator.store.record_exchange_block(
                reason_code=reason_code,
                details=dict(details),
            )

        def finish(receipt_id: str) -> None:
            if getattr(self, "worker_name", "") and getattr(
                self,
                "log_file_path",
                "",
            ):
                self._log_event(
                    event_type,
                    detail={
                        "reason_code": reason_code,
                        "restriction_receipt_id": receipt_id,
                        "message": event_message,
                    },
                    synchronous=True,
                )

        owner_provider = getattr(
            coordinator,
            "_owner_thread_id_provider",
            None,
        )
        if (
            callable(owner_provider)
            and owner_provider() == threading.get_ident()
            and getattr(self, "_ui_lane", None) is None
        ):
            finish(work())
            return True

        lane = self._ui_task_lane()
        if lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return False
        admission = lane.submit(
            LaneTask(
                name="transfer-exchange-block-receipt",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=lambda exc: print(
                    "이적 차단 기록 lane 실패: "
                    f"{exc.__class__.__name__}"
                ),
                shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
            )
        )
        if not admission.accepted:
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return False
        return True

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
        self._cancel_status_message_timer()
        generation = self._status_message_generation

        severity = self._notice_severity_for_color(color)
        title_by_severity = {
            NoticeSeverity.INFO: "안내",
            NoticeSeverity.SUCCESS: "처리 완료",
            NoticeSeverity.WARNING: "주의",
            NoticeSeverity.ERROR: "오류",
        }
        notice = Notice(
            code=f"status.{severity.value}",
            title=title_by_severity[severity],
            message=str(message or "상태를 확인해 주세요."),
            severity=severity,
            blocking=False,
        )
        presented = self._warning_state_presenter().present(notice)
        self._render_warning_state()
        status_label = getattr(self, "status_label", None)
        if status_label is not None:
            try:
                if not self._warning_state_presenter().state.is_blocking:
                    status_label['text'] = "스캐너 준비"
                    status_label['fg'] = self.COLOR_TEXT
            except (tk.TclError, KeyError, TypeError):
                pass
        if presented and duration > 0:
            try:
                self.status_message_job = self.root.after(
                    int(duration),
                    self._reset_status_message,
                    generation,
                )
            except (tk.TclError, AttributeError, TypeError, ValueError):
                self.status_message_job = None

    def _reset_status_message(self, generation: Optional[int] = None):
        if generation is not None and generation != getattr(self, "_status_message_generation", 0):
            return
        self.status_message_job = None
        self._warning_state_presenter().clear()
        self._render_warning_state()
        if (
            not self._warning_state_presenter().state.is_blocking
            and hasattr(self, 'status_label')
            and self.status_label.winfo_exists()
        ):
            self.status_label['text'] = "스캐너 준비"; self.status_label['fg'] = self.COLOR_TEXT

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
                        img = RasterImage.from_png(img_path)
                        original_width, original_height = img.width, img.height
                        ratio = min(max_w / original_width, max_h / original_height)
                        new_width = int(original_width * ratio)
                        new_height = int(original_height * ratio)
                        resized_img = img.resized(new_width, new_height, resample="bilinear")
                        photo = resized_img.to_tk_photo_image(master=self.tray_image_label)
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
        hold_store = self._preflight_hold_store()
        if hold_store.exists() or self._preflight_context_blocks_mutation():
            if not getattr(self.current_tray, "master_label_code", ""):
                return self._quarantine_preflight_hold_for_supervisor(
                    reason="supervisor_new_work_required",
                    confirm=confirm,
                )
            self.show_status_message(
                "제품 반영 중인 보류 묶음은 현재 트레이와 함께 완료하거나 다시 "
                "시작해야 합니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False
        if self._phs_label_exchange_blocks_tray_transition("현재 트레이 보류"):
            return False
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return False
        if self._transfer_member_exchange_blocks_local_action("현재 트레이 보류"):
            return False
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
                worker_name=persistent_operator_name(self.worker_name),
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
            self._sync_last_normal_scan_from_active_tray(clear_when_inactive=True)
            self._reset_ui_to_waiting_state()
            self._update_all_summaries()

            self._update_parked_trays_list()
            self._show_left_sidebar_view("parked")
            self.show_status_message("작업을 보류 처리했습니다. 새 현품표를 스캔하세요.", self.COLOR_PRIMARY)
            return True

        except Exception as e:
            print(f"작업 보류 실패: {e.__class__.__name__}: {e}")
            messagebox.showerror(
                "작업 보류 실패",
                "작업을 보류하지 못했습니다. 현재 작업을 유지하고 관리자에게 문의하세요.",
            )
            return False

    def _update_parked_trays_list(self):
        """parked_trays 폴더를 읽어 UI 목록을 갱신합니다."""
        if not hasattr(self, 'parked_tree'): return

        for i in self.parked_tree.get_children():
            self.parked_tree.delete(i)

        try:
            self._quarantine_invalid_parked_tray_files()
            row_index = 0
            for summary in self._parked_store().list_for_worker(self.worker_name):
                tag = 'even' if row_index % 2 == 0 else 'odd'
                self._insert_tree_row(self.parked_tree, '', 'end', values=(summary.item_name, str(summary.scan_count)), iid=str(summary.path), tags=(tag,))
                row_index += 1
            for held in self._quarantined_preflight_holds():
                fields = self._parse_new_format_qr(held.snapshot.master_raw) or {}
                item_code = str(fields.get("CLC") or "현품표")
                tag = "even" if row_index % 2 == 0 else "odd"
                self._insert_tree_row(
                    self.parked_tree,
                    "",
                    "end",
                    values=(f"사전조회 격리 · {item_code}", str(len(held.snapshot.items))),
                    iid=str(held.path),
                    tags=(tag,),
                )
                row_index += 1
        except Exception as e:
            print(f"보류 목록 갱신 중 오류: {e}")
        finally:
            self._update_parked_recovery_affordance()
            try:
                self.root.after_idle(self._adjust_parked_tree_columns)
            except (AttributeError, tk.TclError):
                pass

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
                    print(f"손상된 보류 작업 파일 격리 위치: {quarantined_path}")
                    self.show_status_message(
                        "손상된 보류 작업을 안전하게 분리했습니다. 관리자에게 문의하세요.",
                        getattr(self, "COLOR_DANGER", "red"),
                    )

    def on_parked_tray_select(self, event):
        """보류 목록에서 트레이를 더블 클릭했을 때 실행됩니다."""
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        selected_item_iid = self.parked_tree.focus()
        if not selected_item_iid: return
        filepath = selected_item_iid
        if self._is_preflight_hold_quarantine_path(filepath):
            self.restore_quarantined_preflight_hold(filepath)
            return
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
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if self._reject_mutation_during_preflight_hold():
            return
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
                print(
                    "손상된 보류 작업 분리: "
                    f"{e.__class__.__name__}: {e}; path={quarantined_path}"
                )
                messagebox.showerror(
                    "보류 작업 확인 필요",
                    "보류 작업 정보가 손상되어 안전하게 분리했습니다. "
                    "관리자에게 문의하세요.",
                )
            except Exception as quarantine_error:
                print(
                    "손상된 보류 작업 분리 실패: "
                    f"{quarantine_error.__class__.__name__}: {quarantine_error}"
                )
                messagebox.showerror(
                    "보류 작업 복원 실패",
                    "보류 작업을 복원하거나 안전하게 분리하지 못했습니다. "
                    "프로그램을 종료하지 말고 관리자에게 문의하세요.",
                )
            self._update_parked_trays_list()
            return
        parked_worker = persistent_operator_name(saved_state.get("worker_name"))
        if parked_worker and parked_worker != persistent_operator_name(self.worker_name):
            messagebox.showwarning("복원 실패", "다른 작업자의 보류 작업은 복원할 수 없습니다. 목록을 갱신합니다.")
            self._update_parked_trays_list()
            return
        parked_master_label = str(saved_state.get("master_label_code") or "")
        if parked_master_label and self._is_completed_master_label(parked_master_label):
            try:
                ParkedTrayStore.delete(filepath)
            except Exception:
                quarantined_path = quarantine_tray_state_file(filepath)
                print(f"완료된 보류 작업 격리 위치: {quarantined_path}")
                messagebox.showwarning(
                    "복원 실패",
                    "이미 완료된 보류 작업이라 복원하지 않고 안전하게 분리했습니다.",
                )
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

        try:
            restored_tray = tray_session_from_state(
                saved_state,
                session_factory=TraySession,
                default_tray_size=self.TRAY_SIZE,
            )
            restored_state = tray_session_to_state(restored_tray, worker_name=self.worker_name)
            if OPERATOR_REVIEW_STATE_KEY in saved_state:
                restored_state[OPERATOR_REVIEW_STATE_KEY] = dict(
                    saved_state[OPERATOR_REVIEW_STATE_KEY]
                )
            restore_detail = {
                'master_label_code': restored_tray.master_label_code,
                'item_code': restored_tray.item_code,
                'item_name': restored_tray.item_name,
                'scan_count': len(restored_tray.scanned_barcodes),
                'tray_capacity': restored_tray.tray_size,
            }
            discard_detail = None
            if discard_current_for_restore:
                discard_detail = {
                    'reason': 'restore_parked_overwrite_current',
                    'master_label_code': self.current_tray.master_label_code,
                    'item_code': self.current_tray.item_code,
                    'item_name': self.current_tray.item_name,
                    'scan_count': len(self.current_tray.scanned_barcodes),
                    'is_partial_submission': self.current_tray.is_partial_submission,
                }
            parked_restore = self._build_parked_restore_contract(
                parked_path=Path(filepath),
                restored_state=restored_state,
                restore_detail=restore_detail,
                discard_detail=discard_detail,
            )
            restored_state[PARKED_RESTORE_STATE_KEY] = parked_restore
            validate_tray_state(restored_state, default_tray_size=self.TRAY_SIZE)
            self._pending_parked_restore_contract = parked_restore
            if not self._save_tray_state_snapshot(restored_state):
                self._pending_parked_restore_contract = None
                raise RuntimeError(
                    "복원한 보류 작업과 감사 outbox의 atomic 저장에 실패했습니다."
                )
            if not self._drain_pending_parked_restore():
                self.current_tray = TraySession()
                self.worker_name = ""
                messagebox.showerror(
                    "보류 작업 복구 기록 대기",
                    "복원 상태와 감사 outbox는 안전하게 저장했지만 event 투영 또는 "
                    "source 정리를 끝내지 못했습니다. 다시 로그인해 동일 operation을 "
                    "복구하고 계속되면 관리자에게 문의하세요.",
                )
                self._update_parked_trays_list()
                if hasattr(self, "show_worker_input_screen"):
                    self.show_worker_input_screen()
                return
            self.current_tray = restored_tray
            self._restore_operator_review_from_state(saved_state)
            self._invalidate_pending_scan_callbacks()
            self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)

            self._left_sidebar_view = "summary"
            self.show_validation_screen()

            # 복원 후 이미지 자동 표시
            self.show_tray_image_var.set(True)
            self._update_tray_image_display()

            self.show_status_message(f"'{self.current_tray.item_name}' 작업을 다시 시작합니다.", self.COLOR_SUCCESS)

        except Exception as e:
            print(f"작업 복원 실패: {e.__class__.__name__}: {e}")
            messagebox.showerror(
                "작업 복원 실패",
                "보류 작업을 복원하지 못했습니다. 현재 작업을 유지하고 관리자에게 문의하세요.",
            )
            
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
                'worker_name': persistent_operator_name(self.worker_name),
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
                worker_name=persistent_operator_name(self.worker_name),
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
                worker_name=persistent_operator_name(self.worker_name),
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
            messagebox.showerror(
                "자동 테스트 실패",
                "자동 테스트를 완료하지 못했습니다. 관리자용 진단 기록을 확인하세요.",
            )

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
        if self._reject_mutation_during_preflight_hold():
            return
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if self.current_tray.master_label_code:
            messagebox.showwarning("작업 중 오류", "진행 중인 작업이 있을 때는 현품표를 교체할 수 없습니다.")
            return

        if self.master_label_replace_state:
            self.cancel_master_label_replacement()
        else:
            if self._block_unsafe_exact_master_label_replacement():
                self._update_action_button_states()
                return
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
        if self._reject_mutation_during_preflight_hold():
            return False
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return False
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
        if self._reject_mutation_during_preflight_hold():
            return
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
                operator=persistent_operator_name(self.worker_name),
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
            print(f"현품표 교체 기록 저장 실패: {e.__class__.__name__}: {e}")
            messagebox.showerror(
                "교체 기록 실패",
                "현품표 교체 기록을 저장하지 못했습니다. 현재 상태를 유지하고 "
                "관리자에게 문의하세요.",
            )

    # ==================== 개별 제품 교환 관련 함수들 ====================

    def show_exchange_dialog(self):
        """개별 제품 교환 다이얼로그를 표시합니다."""
        if self._reject_mutation_during_preflight_hold():
            return
        if self._operator_review_blocks_mutation():
            self._render_warning_state()
            return
        if not self._schedule_exchange_dialog_admission():
            return

    def _schedule_exchange_dialog_admission(self) -> bool:
        coordinator = getattr(self, "transfer_member_exchange_coordinator", None)
        tray = getattr(self, "current_tray", None)
        snapshot_master_label = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        owner_source = coordinator or getattr(
            self,
            "transfer_seal_coordinator",
            None,
        )
        owner_provider = getattr(
            owner_source,
            "_owner_thread_id_provider",
            self._transfer_coordinator_owner_provider(),
        )
        if (
            callable(owner_provider)
            and owner_provider() == threading.get_ident()
            and getattr(self, "_ui_lane", None) is None
        ):
            admitted = (
                self._dismiss_transfer_exchange_preflight_for_explicit_retry()
            )
            self._apply_transfer_coordinator_ui_snapshot(
                self._work_transfer_coordinator_ui_snapshot(
                    master_label=snapshot_master_label
                )
            )
            if not admitted:
                messagebox.showerror(
                    "교체 다시 시작 실패",
                    "중앙 명령 전 사전검증 실패를 안전하게 해제하지 못했습니다. 상태를 유지합니다.",
                    parent=getattr(self, "root", None),
                )
                return False
            self._show_exchange_dialog_after_coordinator_admission()
            return True

        lane = self._ui_task_lane()
        if lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False

        def work() -> Dict[str, Any]:
            admitted = (
                self._dismiss_transfer_exchange_preflight_for_explicit_retry()
            )
            return {
                "admitted": admitted,
                "ui_snapshot": self._work_transfer_coordinator_ui_snapshot(
                    master_label=snapshot_master_label
                ),
            }

        def finish(outcome: Mapping[str, Any]) -> None:
            self._apply_transfer_coordinator_ui_snapshot(
                outcome.get("ui_snapshot")
            )
            self._exchange_dialog_admission_result = bool(
                outcome.get("admitted")
            )

        def on_idle() -> None:
            try:
                if bool(getattr(self, "_exchange_dialog_admission_result", False)):
                    self._show_exchange_dialog_after_coordinator_admission()
                    return
                messagebox.showerror(
                    "교체 다시 시작 실패",
                    "중앙 명령 전 사전검증 실패를 안전하게 해제하지 못했습니다. 상태를 유지합니다.",
                    parent=getattr(self, "root", None),
                )
            finally:
                self._schedule_pending_transfer_coordinator_work()

        admission = lane.submit(
            LaneTask(
                name="transfer-exchange-dialog-admission",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=lambda exc: finish({"admitted": False}),
                on_idle=on_idle,
            )
        )
        if not admission.accepted:
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
                duration=0,
            )
            return False
        return True

    def _show_exchange_dialog_after_coordinator_admission(self) -> None:
        member_exchange_view.show_exchange_dialog(self)

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
        if quantity < 1 or quantity > 2:
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
        if self._reject_mutation_during_preflight_hold():
            return
        session = self.current_exchange_session

        # 세션이 시작되지 않았으면 자동으로 시작
        if session.current_step == "not_started":
            if not self._start_exchange():
                messagebox.showwarning("수량 미설정", "교환할 수량을 먼저 설정해주세요.")
                return

        if session.current_step not in ["scan_defective", "scan_good"]:
            return

        if getattr(self, "_active_transfer_exchange_mode", False):
            try:
                current = tuple(self.current_tray.scanned_barcodes)
                normalized_current = {normalize_barcode(value) for value in current}
                normalized_scan = normalize_barcode(barcode)
            except ValueError:
                messagebox.showerror("바코드 형식 오류", "제품 바코드가 올바르지 않습니다.")
                return
            if session.current_step == "scan_defective" and normalized_scan not in normalized_current:
                messagebox.showerror(
                    "교체 대상 아님",
                    "교체 대상은 현재 이적 트레이에 이미 스캔된 제품이어야 합니다.",
                )
                return
            if session.current_step == "scan_good" and normalized_scan in normalized_current:
                messagebox.showerror(
                    "이미 현재 트레이에 포함됨",
                    "새 양품은 현재 이적 트레이에 아직 포함되지 않은 제품이어야 합니다.",
                )
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
        member_exchange_view.update_exchange_display(self)

    def _update_exchange_status(self):
        member_exchange_view.update_exchange_status(self)

    def _member_exchange_apply_plan(
        self, attempt: MemberExchangeAttempt
    ) -> tuple[List[str], List[datetime.datetime], Dict[str, Any]]:
        if attempt.status != "ACKED":
            raise ValueError("central member exchange is not ACKED")
        if (
            attempt.target_label_action != "RETAIN_IDENTITY_LABEL"
            or attempt.target_label_identity_remains_valid is not True
            or attempt.target_label_membership_bound is not False
        ):
            raise ValueError(
                "central receipt does not prove the scanned PHS identity label remains valid"
            )
        if not 1 <= len(attempt.old_barcodes) <= 2:
            raise ValueError("central member exchange pair count is invalid")
        if len(attempt.old_barcodes) != len(attempt.new_barcodes):
            raise ValueError("central member exchange pair counts differ")
        current_master = str(self.current_tray.master_label_code or "")
        expected_master = str(
            getattr(self, "_active_transfer_exchange_master_label", "") or current_master
        )
        if not current_master or current_master != expected_master:
            raise ValueError("active tray master label changed after central exchange")
        before = list(self.current_tray.scanned_barcodes)
        before_normalized = [normalize_barcode(value) for value in before]
        old_values = [normalize_barcode(value) for value in attempt.old_barcodes]
        new_values = [normalize_barcode(value) for value in attempt.new_barcodes]
        if len(before_normalized) != len(set(before_normalized)):
            raise ValueError("active tray contains normalized duplicate barcodes")
        if any(before_normalized.count(value) != 1 for value in old_values):
            raise ValueError("one or more damaged barcodes are no longer in the active tray")
        remaining = set(before_normalized) - set(old_values)
        if remaining & set(new_values) or len(set(new_values)) != len(new_values):
            raise ValueError("one or more replacement barcodes already belong to the active tray")
        after = list(before)
        for old_value, new_value in zip(old_values, new_values, strict=True):
            after[before_normalized.index(old_value)] = new_value
        evidence = {
            "exchange_contract_version": "container-audit-central-member-exchange-v1",
            "exchange_intent_id": attempt.intent_id,
            "idempotency_key": attempt.idempotency_key,
            "central_receipt_id": attempt.receipt_id,
            "target_bundle_id": attempt.target_bundle_id,
            "damage_bundle_id": attempt.damage_bundle_id,
            "entity_versions": dict(attempt.entity_versions),
            "exchange_pairs": [
                {"defective": old, "good": new}
                for old, new in zip(old_values, new_values, strict=True)
            ],
            "defective_barcodes": old_values,
            "good_barcodes": new_values,
            "pair_count": len(old_values),
            "before_selection_hash": stable_hash(
                sorted(normalize_barcode(value) for value in before)
            ),
            "after_selection_hash": stable_hash(
                sorted(normalize_barcode(value) for value in after)
            ),
            "central_atomic": True,
            "central_command_type": "REPLACE_BUNDLE_MEMBERS",
            "post_seal_replacement": False,
            "target_label_action": attempt.target_label_action,
            "target_label_identity_remains_valid": (
                attempt.target_label_identity_remains_valid
            ),
            "target_label_membership_bound": attempt.target_label_membership_bound,
        }
        evidence["evidence_hash"] = stable_hash(evidence)
        return after, list(self.current_tray.scan_times), evidence

    def _redraw_active_tray_scans(self) -> None:
        listbox = getattr(self, "scanned_listbox", None)
        if listbox is not None:
            try:
                listbox.delete(0, tk.END)
                for index, barcode in enumerate(self.current_tray.scanned_barcodes, start=1):
                    listbox.insert(0, self._format_scanned_list_row(index, barcode))
            except (tk.TclError, AttributeError):
                pass
        self._sync_last_normal_scan_from_active_tray()
        self._update_center_display()
        self._update_current_item_label()
        self._update_action_button_states()

    def _apply_acked_member_exchange(
        self, attempt: MemberExchangeAttempt, *, recovery: bool = False
    ) -> bool:
        coordinator = self._transfer_member_exchange_runtime()
        try:
            successor_lease_id = coordinator.ensure_local_rotation(attempt.intent_id)
        except TransferSealError as exc:
            coordinator.store.mark_local_review(
                attempt.intent_id,
                f"{exc.code}: authenticated lease rotation could not be accepted",
            )
            return False
        except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
            # The central receipt remains ACKED/PENDING and blocks every unsafe
            # action. Restart can retry the same immutable receipt and L2.
            print(
                "중앙 제품 교체 lease 회전 저장 실패: "
                f"{exc.__class__.__name__}"
            )
            return False
        if attempt.predecessor_operation_lease_id and not successor_lease_id:
            coordinator.store.mark_local_review(
                attempt.intent_id,
                "central exchange receipt has no durable successor operation lease",
            )
            return False

        outcome = self._call_transfer_ui_sync(
            self._apply_acked_member_exchange_ui,
            attempt,
            successor_lease_id,
            recovery,
        )
        review_reason = str(outcome.get("review_reason") or "")
        if review_reason:
            coordinator.store.mark_local_review(attempt.intent_id, review_reason)
        if not bool(outcome.get("applied")):
            return False
        evidence = dict(outcome.get("evidence") or {})
        try:
            coordinator.store.mark_local_applied(attempt.intent_id, evidence)
        except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
            # The state and append-only event are already durable. Leave the
            # intent PENDING so restart reconciliation can idempotently close it.
            print(f"중앙 제품 교체 local receipt 저장 실패: {exc.__class__.__name__}")
        return True

    def _call_transfer_ui_sync(
        self,
        callback: Callable[..., Any],
        *args: Any,
    ) -> Any:
        lane = getattr(self, "_ui_lane", None)
        if (
            lane is not None
            and threading.get_ident() == getattr(lane, "worker_thread_id", None)
        ):
            return lane.call_ui_sync(callback, *args)
        return callback(*args)

    def _apply_acked_member_exchange_ui(
        self,
        attempt: MemberExchangeAttempt,
        successor_lease_id: str,
        recovery: bool,
    ) -> Dict[str, Any]:
        if self._reject_mutation_during_preflight_hold():
            return {"applied": False, "review_reason": "", "evidence": {}}
        try:
            after, scan_times, evidence = self._member_exchange_apply_plan(attempt)
        except (TypeError, ValueError) as exc:
            return {
                "applied": False,
                "review_reason": str(exc),
                "evidence": {},
            }
        before = list(self.current_tray.scanned_barcodes)
        before_times = list(self.current_tray.scan_times)
        before_error_state = bool(self.current_tray.has_error_or_reset)
        before_operation_lease_id = str(
            getattr(self.current_tray, "operation_lease_id", "") or ""
        )
        if attempt.predecessor_operation_lease_id and before_operation_lease_id not in {
            attempt.predecessor_operation_lease_id,
            successor_lease_id,
        }:
            return {
                "applied": False,
                "review_reason": (
                    "active tray operation lease differs from central rotation predecessor"
                ),
                "evidence": {},
            }
        if successor_lease_id:
            self.current_tray.operation_lease_id = successor_lease_id
        self.current_tray.scanned_barcodes = after
        self.current_tray.scan_times = scan_times
        self.current_tray.has_error_or_reset = True
        evidence.update(
            {
                "predecessor_operation_lease_id": (
                    attempt.predecessor_operation_lease_id or None
                ),
                "successor_operation_lease_id": successor_lease_id or None,
                "operation_lease_rotation_durable": bool(successor_lease_id),
            }
        )
        evidence["evidence_hash"] = stable_hash(
            {key: value for key, value in evidence.items() if key != "evidence_hash"}
        )
        if not self._save_current_tray_state():
            self.current_tray.operation_lease_id = before_operation_lease_id
            self.current_tray.scanned_barcodes = before
            self.current_tray.scan_times = before_times
            self.current_tray.has_error_or_reset = before_error_state
            return {"applied": False, "review_reason": "", "evidence": {}}
        event_type = (
            "PRODUCT_EXCHANGE_LOCAL_RECONCILED"
            if recovery
            else "PRODUCT_EXCHANGE_COMPLETED"
        )
        if not self._log_event(event_type, detail=evidence, synchronous=True):
            self.current_tray.operation_lease_id = before_operation_lease_id
            self.current_tray.scanned_barcodes = before
            self.current_tray.scan_times = before_times
            self.current_tray.has_error_or_reset = before_error_state
            review_reason = ""
            if not self._save_current_tray_state():
                review_reason = (
                    "central exchange committed but local state rollback failed after log error"
                )
            return {
                "applied": False,
                "review_reason": review_reason,
                "evidence": {},
            }
        self._redraw_active_tray_scans()
        return {"applied": True, "review_reason": "", "evidence": evidence}

    def _reconcile_pending_local_member_exchanges(self) -> bool:
        if self._reject_mutation_during_preflight_hold():
            return False
        if not getattr(self.current_tray, "master_label_code", ""):
            return False
        self._member_exchange_reconcile_pending = True
        if (
            getattr(self, "_startup_transfer_recovery_pending", False)
            or getattr(self, "_startup_transfer_recovery_inflight", False)
        ):
            return False
        return self._schedule_member_exchange_reconcile()

    def _schedule_member_exchange_reconcile(self) -> bool:
        if (
            not getattr(self, "_member_exchange_reconcile_pending", False)
            or getattr(self, "_member_exchange_reconcile_inflight", False)
            or getattr(self, "_ui_close_requested", False)
        ):
            return False
        master_label = str(
            getattr(getattr(self, "current_tray", None), "master_label_code", "")
            or ""
        )
        if not master_label:
            self._member_exchange_reconcile_pending = False
            return False
        coordinator = self._transfer_member_exchange_runtime()
        owner_provider = getattr(
            coordinator,
            "_owner_thread_id_provider",
            None,
        )

        def work() -> Dict[str, Any]:
            outcome = dict(
                self._work_member_exchange_reconcile(master_label)
            )
            outcome["ui_snapshot"] = (
                self._work_transfer_coordinator_ui_snapshot(
                    master_label=master_label
                )
            )
            return outcome

        if (
            callable(owner_provider)
            and owner_provider() == threading.get_ident()
            and getattr(self, "_ui_lane", None) is None
        ):
            self._member_exchange_reconcile_pending = False
            self._finish_member_exchange_reconcile(work())
            return True

        lane = self._ui_task_lane()
        if lane.is_busy():
            return False
        self._member_exchange_reconcile_pending = False
        self._member_exchange_reconcile_inflight = True

        def finish(outcome: Mapping[str, Any]) -> None:
            self._member_exchange_reconcile_inflight = False
            self._apply_transfer_coordinator_ui_snapshot(
                outcome.get("ui_snapshot")
            )
            self._finish_member_exchange_reconcile(outcome)

        def fail(exc: BaseException) -> None:
            self._member_exchange_reconcile_inflight = False
            print(
                "중앙 제품 교체 local reconcile lane 실패: "
                f"{exc.__class__.__name__}"
            )
            self._finish_member_exchange_reconcile({"status": "failed"})

        admission = lane.submit(
            LaneTask(
                name="transfer-member-local-reconcile",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                on_idle=self._schedule_pending_transfer_coordinator_work,
                shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
            )
        )
        if not admission.accepted:
            self._member_exchange_reconcile_inflight = False
            self._member_exchange_reconcile_pending = True
            return False
        return True

    def _member_exchange_ui_snapshot(self) -> Dict[str, Any]:
        return {
            "master_label": str(self.current_tray.master_label_code or ""),
            "barcodes": tuple(self.current_tray.scanned_barcodes),
            "operation_lease_id": str(
                getattr(self.current_tray, "operation_lease_id", "") or ""
            ),
        }

    def _work_member_exchange_reconcile(
        self,
        master_label: str,
    ) -> Dict[str, str]:
        coordinator = self._transfer_member_exchange_runtime()
        attempts = coordinator.pending_local_attempts(master_label=master_label)
        for attempt in attempts:
            snapshot = self._call_transfer_ui_sync(
                self._member_exchange_ui_snapshot
            )
            if str(snapshot.get("master_label") or "") != master_label:
                return {"status": "stale"}
            current = {
                normalize_barcode(value)
                for value in tuple(snapshot.get("barcodes") or ())
            }
            old_values = {
                normalize_barcode(value) for value in attempt.old_barcodes
            }
            new_values = {
                normalize_barcode(value) for value in attempt.new_barcodes
            }
            if old_values.issubset(current) and not (new_values & current):
                self._call_transfer_ui_sync(
                    setattr,
                    self,
                    "_active_transfer_exchange_master_label",
                    master_label,
                )
                if not self._apply_acked_member_exchange(attempt, recovery=True):
                    return {"status": "failed"}
                continue
            if not (old_values & current) and new_values.issubset(current):
                try:
                    successor_lease_id = coordinator.ensure_local_rotation(
                        attempt.intent_id
                    )
                except TransferSealError as exc:
                    coordinator.store.mark_local_review(
                        attempt.intent_id,
                        f"{exc.code}: saved tray cannot verify lease rotation",
                    )
                    return {"status": "failed"}
                except (KeyError, TypeError, ValueError, sqlite3.Error):
                    return {"status": "failed"}
                outcome = self._call_transfer_ui_sync(
                    self._reconcile_existing_member_exchange_ui,
                    attempt,
                    successor_lease_id,
                    tuple(sorted(current)),
                )
                review_reason = str(outcome.get("review_reason") or "")
                if review_reason:
                    coordinator.store.mark_local_review(
                        attempt.intent_id,
                        review_reason,
                    )
                    return {"status": "failed"}
                evidence = dict(outcome.get("evidence") or {})
                if not evidence:
                    return {"status": "failed"}
                try:
                    coordinator.store.mark_local_applied(
                        attempt.intent_id,
                        evidence,
                    )
                except ValueError:
                    pass
                continue
            coordinator.store.mark_local_review(
                attempt.intent_id,
                "active tray membership is neither the before nor after exchange set",
            )
            return {"status": "conflict"}
        return {"status": "applied"}

    def _reconcile_existing_member_exchange_ui(
        self,
        attempt: MemberExchangeAttempt,
        successor_lease_id: str,
        current: Sequence[str],
    ) -> Dict[str, Any]:
        current_lease_id = str(
            getattr(self.current_tray, "operation_lease_id", "") or ""
        )
        if successor_lease_id and current_lease_id != successor_lease_id:
            if current_lease_id != attempt.predecessor_operation_lease_id:
                return {
                    "review_reason": (
                        "saved tray lease is neither the rotation predecessor nor successor"
                    ),
                    "evidence": {},
                }
            self.current_tray.operation_lease_id = successor_lease_id
            if not self._save_current_tray_state():
                self.current_tray.operation_lease_id = current_lease_id
                return {"review_reason": "", "evidence": {}}
        return {
            "review_reason": "",
            "evidence": {
                "exchange_intent_id": attempt.intent_id,
                "central_receipt_id": attempt.receipt_id,
                "reconciled_existing_state": True,
                "after_selection_hash": stable_hash(sorted(current)),
                "predecessor_operation_lease_id": (
                    attempt.predecessor_operation_lease_id or None
                ),
                "successor_operation_lease_id": successor_lease_id or None,
            },
        }

    def _finish_member_exchange_reconcile(
        self,
        outcome: Mapping[str, Any],
    ) -> None:
        self._apply_transfer_coordinator_ui_snapshot(
            outcome.get("ui_snapshot")
        )
        status = str(outcome.get("status") or "failed")
        if status == "conflict":
            messagebox.showerror(
                "중앙 교체 상태 충돌",
                "중앙 교체 결과와 현재 트레이 제품 목록이 부분적으로만 일치합니다. "
                "작업을 중단하고 관리자에게 확인하세요.",
            )
        elif status == "failed":
            messagebox.showerror(
                "중앙 교체 복구 실패",
                "서버에서 완료된 제품 교체를 현재 트레이에 복구하지 못했습니다. 담당자 확인이 필요합니다.",
            )

    def _cancel_exchange(self, *, reason: str = "operator_cancel") -> bool:
        """진행 중인 제품 교환을 취소하고 필요한 감사 로그를 남깁니다."""
        if self._reject_mutation_during_preflight_hold():
            return False
        intent_id = str(
            getattr(self, "_active_transfer_exchange_intent_id", "") or ""
        )
        if intent_id:
            return self._schedule_exchange_cancel(intent_id, reason)
        if self._transfer_member_exchange_blocks_local_action("제품 교환 취소"):
            return False
        return self._finish_exchange_cancel_ui(reason)

    def _schedule_exchange_cancel(self, intent_id: str, reason: str) -> bool:
        coordinator = self._transfer_member_exchange_runtime()
        tray = getattr(self, "current_tray", None)
        snapshot_master_label = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()

        def mutate() -> Dict[str, str]:
            if self._call_transfer_ui_sync(
                self._preflight_context_blocks_mutation
            ):
                return {"status": "hold"}
            attempt = coordinator.attempt(intent_id)
            if attempt.status == "ACKED" and attempt.local_apply_status == "PENDING":
                return {
                    "status": (
                        "allowed"
                        if self._apply_acked_member_exchange(
                            attempt,
                            recovery=True,
                        )
                        else "apply_failed"
                    )
                }
            if attempt.status in {
                "PREPARED",
                "COMMAND_READY",
                "RETRY_WAIT",
                "OPERATOR_REVIEW",
            }:
                if not attempt.idempotency_key:
                    coordinator.store.dismiss_without_durable_command(
                        intent_id,
                        reason,
                    )
                    return {"status": "allowed"}
                return {"status": "command_pending"}
            return {"status": "allowed"}

        def work() -> Dict[str, Any]:
            outcome = dict(mutate())
            outcome["ui_snapshot"] = (
                self._work_transfer_coordinator_ui_snapshot(
                    master_label=snapshot_master_label
                )
            )
            return outcome

        def finish(outcome: Mapping[str, Any]) -> None:
            self._apply_transfer_coordinator_ui_snapshot(
                outcome.get("ui_snapshot")
            )
            status = str(outcome.get("status") or "failed")
            if status == "allowed":
                self._finish_exchange_cancel_ui(reason)
            elif status == "apply_failed":
                messagebox.showerror(
                    "교체 취소 불가",
                    "중앙에서 완료된 제품 교체를 현재 트레이에 먼저 복구해야 합니다. 담당자에게 알리세요.",
                )
            elif status == "command_pending":
                messagebox.showerror(
                    "교체 취소 불가",
                    "중앙 제품 교체 완료 여부가 아직 확정되지 않았습니다. "
                    "네트워크를 확인한 뒤 다시 시도하세요.",
                )

        def fail(exc: BaseException) -> None:
            print(f"중앙 제품 교체 취소 lane 실패: {exc.__class__.__name__}")
            messagebox.showerror(
                "교체 취소 기록 실패",
                "중앙 명령 전 사전검증 실패를 안전하게 해제하지 못했습니다. 상태를 유지합니다.",
            )

        owner_provider = getattr(
            coordinator,
            "_owner_thread_id_provider",
            None,
        )
        if (
            callable(owner_provider)
            and owner_provider() == threading.get_ident()
            and getattr(self, "_ui_lane", None) is None
        ):
            try:
                outcome = work()
            except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
                fail(exc)
                return False
            finish(outcome)
            return str(outcome.get("status") or "") == "allowed"

        lane = self._ui_task_lane()
        if lane.is_busy():
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return False
        admission = lane.submit(
            LaneTask(
                name="transfer-member-cancel",
                generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                work=work,
                finish=finish,
                fail=fail,
                shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
            )
        )
        if not admission.accepted:
            self.show_status_message(
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                self.COLOR_DANGER,
            )
            return False
        # App close must re-enter after the admitted cancellation has reached
        # its durable terminal state; an operator cancellation is now owned.
        return reason != "app_close"

    def _finish_exchange_cancel_ui(self, reason: str) -> bool:
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
        self._active_transfer_exchange_mode = False
        self._active_transfer_exchange_master_label = ""
        self._active_transfer_exchange_intent_id = ""
        self._update_action_button_states()
        return True

    def _finish_central_exchange_pending(
        self,
        attempt: MemberExchangeAttempt,
    ) -> None:
        member_exchange_view.finish_central_exchange_pending(self, attempt)

    def _finish_central_exchange_failure(
        self,
        attempt: Optional[MemberExchangeAttempt],
    ) -> None:
        member_exchange_view.finish_central_exchange_failure(self, attempt)

    def _finish_central_exchange_success(self) -> None:
        member_exchange_view.finish_central_exchange_success(self)

    def _complete_exchange(self):
        """제품 교환을 완료합니다."""
        if self._reject_mutation_during_preflight_hold():
            return
        active_transfer_exchange = bool(
            getattr(self, "_active_transfer_exchange_mode", False)
        )
        if not active_transfer_exchange and self._block_unsafe_exact_exchange():
            return
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

        if active_transfer_exchange:
            source_label_payload = str(
                getattr(self.current_tray, "active_label_qr_payload", "")
                or self.current_tray.master_label_code
            )
            master_fields = parse_new_format_qr(source_label_payload)
            if not master_fields:
                self.exchange_complete_button.config(state=tk.NORMAL)
                messagebox.showerror(
                    "중앙 교체 차단",
                    "현재 현품표에서 중앙 등록 정보를 확인할 수 없습니다. "
                    "현품표를 다시 확인하고 관리자에게 문의하세요.",
                )
                return
            coordinator = self._transfer_member_exchange_runtime()
            operation_lease_id = str(
                getattr(self.current_tray, "operation_lease_id", "") or ""
            ).strip()
            if not operation_lease_id:
                self.exchange_complete_button.config(state=tk.NORMAL)
                messagebox.showerror(
                    "중앙 교체 차단",
                    "현재 트레이의 이적 확인 정보가 없어 제품을 교체할 수 없습니다. "
                    "현재 트레이를 유지하고 관리자에게 문의하세요.",
                )
                return
            prepare_arguments = {
                "master_label": str(self.current_tray.master_label_code),
                "master_label_fields": dict(master_fields),
                "item_id": str(self.current_tray.item_code),
                "operator": persistent_operator_name(self.worker_name),
                "old_barcodes": tuple(session.defective_barcodes),
                "new_barcodes": tuple(session.good_barcodes),
                "operation_lease_id": operation_lease_id,
            }

            def mutate() -> Dict[str, Any]:
                if self._call_transfer_ui_sync(
                    self._preflight_context_blocks_mutation
                ):
                    return {"status": "hold"}
                prepared = coordinator.prepare(**prepare_arguments)
                attempt = coordinator.attempt(prepared.intent_id)
                applied = False
                if attempt.status == "ACKED":
                    applied = self._apply_acked_member_exchange(attempt)
                return {
                    "status": "attempted",
                    "intent_id": prepared.intent_id,
                    "attempt": attempt,
                    "applied": applied,
                }

            def work() -> Dict[str, Any]:
                outcome = dict(mutate())
                outcome["ui_snapshot"] = (
                    self._work_transfer_coordinator_ui_snapshot(
                        master_label=str(prepare_arguments["master_label"])
                    )
                )
                return outcome

            def finish(outcome: Mapping[str, Any]) -> None:
                self._apply_transfer_coordinator_ui_snapshot(
                    outcome.get("ui_snapshot")
                )
                if str(outcome.get("status") or "") == "hold":
                    if hasattr(self, "exchange_complete_button"):
                        self.exchange_complete_button.config(state=tk.NORMAL)
                    return
                attempt = outcome.get("attempt")
                self._active_transfer_exchange_intent_id = str(
                    outcome.get("intent_id") or ""
                )
                if not isinstance(attempt, MemberExchangeAttempt):
                    self._finish_central_exchange_failure(None)
                    return
                if attempt.status != "ACKED":
                    self._finish_central_exchange_pending(attempt)
                    return
                if not bool(outcome.get("applied")):
                    self._finish_central_exchange_failure(attempt)
                    return
                self._finish_central_exchange_success()

            def fail(exc: BaseException) -> None:
                print(
                    "중앙 제품 교체 준비 실패: "
                    f"{exc.__class__.__name__}: {exc}"
                )
                self._finish_central_exchange_failure(None)

            owner_provider = getattr(
                coordinator,
                "_owner_thread_id_provider",
                None,
            )
            if (
                callable(owner_provider)
                and owner_provider() == threading.get_ident()
                and getattr(self, "_ui_lane", None) is None
            ):
                try:
                    finish(work())
                except (TransferSealError, TypeError, ValueError) as exc:
                    fail(exc)
                return

            lane = self._ui_task_lane()
            if lane.is_busy():
                if hasattr(self, "exchange_complete_button"):
                    self.exchange_complete_button.config(state=tk.NORMAL)
                self.show_status_message(
                    "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                    self.COLOR_DANGER,
                )
                return
            admission = lane.submit(
                LaneTask(
                    name="transfer-member-central-exchange",
                    generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
                    work=work,
                    finish=finish,
                    fail=fail,
                    shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
                )
            )
            if not admission.accepted and hasattr(
                self,
                "exchange_complete_button",
            ):
                self.exchange_complete_button.config(state=tk.NORMAL)
            if not admission.accepted:
                self.show_status_message(
                    "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                    self.COLOR_DANGER,
                )
            return

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
        self._active_transfer_exchange_mode = False
        self._active_transfer_exchange_master_label = ""
        self._active_transfer_exchange_intent_id = ""
        self._update_action_button_states()

def prepare_startup_item_catalog() -> str:
    bundled_path = Path(resource_path(os.path.join("assets", "Item.csv")))
    active_path = refresh_item_catalog(bundled_path)
    if (
        requires_verified_catalog_snapshot(active_path)
        and get_verified_catalog_snapshot(active_path) is None
    ):
        raise ItemCatalogSyncError(
            "central item catalog snapshot is unavailable after verification",
            cause_code=SNAPSHOT_UNAVAILABLE_AFTER_VERIFY,
        )
    os.environ[ACTIVE_PATH_ENV] = str(active_path)
    return str(active_path)


ITEM_CATALOG_STARTUP_EXIT_CODE = 3
ITEM_CATALOG_STARTUP_ERROR_TITLE = "중앙 품목 목록 확인 실패"
ITEM_CATALOG_STARTUP_ERROR_MESSAGE = (
    "중앙 품목 목록을 확인할 수 없어 프로그램 시작을 중단했습니다.\n\n"
    "네트워크 연결과 이 PC의 중앙 물류 설정을 확인한 뒤 다시 실행하세요. "
    "계속 실패하면 IT 담당자에게 문의하세요."
)
ITEM_CATALOG_CACHE_WARNING_TITLE = "검증된 품목 캐시 사용"
ITEM_CATALOG_CACHE_WARNING_MESSAGE = (
    "중앙 품목 목록을 새로 받지 못해 무결성이 검증된 로컬 캐시로 시작합니다.\n\n"
    "캐시 기준 시각: {cache_time}\n"
    "네트워크가 복구되면 다음 실행에서 중앙 목록을 다시 확인합니다."
)
FIRST_RUN_ONBOARDING_ERROR_TITLE = "초기 설정 실패"
FIRST_RUN_ONBOARDING_ERROR_MESSAGE = (
    "이 사용자 계정의 이적 검사 초기 설정을 완료하지 못했습니다.\n\n"
    "네트워크 연결을 확인한 뒤 다시 실행하세요. 계속 실패하면 오류 보고서 경로를 "
    "IT 담당자에게 전달하세요."
)
BOOTSTRAP_INTEGRITY_WARNING_TITLE = "배포 무결성 기록 없음"
BOOTSTRAP_INTEGRITY_WARNING_MESSAGE = (
    "bootstrap 무결성 기록이 없어 경고 상태로 계속 시작합니다.\n\n"
    "프로그램 파일이 일부만 압축 해제됐을 수 있으므로 공식 ZIP을 다시 받아 확인하세요. "
    "기록이 존재하지만 일치하지 않는 경우에는 시작이 차단됩니다."
)


def _first_run_onboarding_enabled() -> bool:
    if getattr(sys, "frozen", False) and os.name == "nt":
        return True
    value = os.getenv("CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING", "").strip().lower()
    return value in {"1", "true", "yes", "on", "enabled"}


def _show_first_run_onboarding_error(failure: CurrentUserOnboardingError) -> None:
    report_path = str(failure.report_path)
    operator_message = f"{FIRST_RUN_ONBOARDING_ERROR_MESSAGE}\n보고서: {report_path}"
    try:
        messagebox.showerror(
            FIRST_RUN_ONBOARDING_ERROR_TITLE,
            operator_message,
        )
    except Exception:
        pass


def _show_bootstrap_integrity_warning(report_path: object) -> None:
    operator_message = (
        f"{BOOTSTRAP_INTEGRITY_WARNING_MESSAGE}\n보고서: {str(report_path or 'UNKNOWN')}"
    )
    try:
        messagebox.showwarning(
            BOOTSTRAP_INTEGRITY_WARNING_TITLE,
            operator_message,
        )
    except Exception:
        pass


def _show_item_catalog_startup_error(cause_code: str) -> None:
    try:
        messagebox.showerror(
            ITEM_CATALOG_STARTUP_ERROR_TITLE,
            f"{ITEM_CATALOG_STARTUP_ERROR_MESSAGE}\n오류 코드: {cause_code}",
        )
    except Exception:  # The fail-closed exit must survive Tk initialization failures.
        pass


def _item_catalog_cache_time_for_display(value: object) -> str:
    text = str(value or "").strip()
    if not text or text == "UNKNOWN":
        return "UNKNOWN"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return "UNKNOWN"
    if parsed.tzinfo is None:
        return "UNKNOWN"
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _show_item_catalog_cache_warning(context: Mapping[str, object]) -> None:
    cache_time = _item_catalog_cache_time_for_display(
        context.get("cache_last_modified_utc")
    )
    try:
        messagebox.showwarning(
            ITEM_CATALOG_CACHE_WARNING_TITLE,
            ITEM_CATALOG_CACHE_WARNING_MESSAGE.format(cache_time=cache_time),
        )
    except Exception:
        pass


def main(argv: list[str] | None = None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    hosted_result = dispatch_product_mode(arguments)
    if hosted_result is not None:
        return hosted_result

    startup = _prepare_gui_startup()
    if not isinstance(startup, tuple):
        return startup
    app, instance_lease = startup
    try:
        # The resident UI must let the relay and background writers acquire
        # admission between their own guarded mutations.
        app.run()
        return 0
    finally:
        instance_lease.release()


@writer_sink("gui_startup")
def _prepare_gui_startup():
    """Guard initialization without holding admission for a resident mode."""

    verify_factory_contract_startup()
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    storage_paths = build_container_audit_storage_paths(
        application_path=application_path
    )
    try:
        instance_lease = acquire_runtime_instance(storage_paths.data_root)
    except OSError:
        messagebox.showerror(
            "프로그램 실행 잠금 실패",
            "데이터 충돌 방지를 위한 실행 잠금을 확인하지 못했습니다. "
            "프로그램을 시작하지 않고 관리자에게 문의합니다.",
        )
        return
    if instance_lease is None:
        messagebox.showwarning(
            "프로그램이 이미 실행 중입니다",
            "같은 PC에서 이적 검사 프로그램을 두 번 실행할 수 없습니다. "
            "열려 있는 창을 사용해 주세요.",
        )
        return
    startup_complete = False
    try:
        if _first_run_onboarding_enabled():
            try:
                onboarding_report = onboard_current_user(
                    application_path,
                    require_bootstrap_integrity=bool(getattr(sys, "frozen", False)),
                )
            except CurrentUserOnboardingError as exc:
                _show_first_run_onboarding_error(exc)
                return ONBOARDING_EXIT_CODE
            if onboarding_report.get("bootstrap_integrity") == "absent":
                _show_bootstrap_integrity_warning(
                    resolve_current_user_onboarding_paths(
                        application_path
                    ).onboarding_report_path
                )
        try:
            active_catalog_path = prepare_startup_item_catalog()
            if active_catalog_path is not None:
                catalog_context = get_catalog_attempt_context()
                try:
                    write_item_catalog_startup_diagnostic(
                        storage_paths.item_catalog_diagnostic_path
                    )
                except Exception:
                    pass
                if (
                    catalog_context.get("cache_used")
                    and catalog_context.get("catalog_source") == "VERIFIED_CACHE"
                ):
                    _show_item_catalog_cache_warning(catalog_context)
            app = ContainerAudit()
        except ItemCatalogSyncError as exc:
            try:
                write_item_catalog_failure_diagnostic(
                    storage_paths.item_catalog_diagnostic_path,
                    exc,
                )
            except Exception:  # Diagnostic persistence must not bypass fail-closed exit.
                pass
            _show_item_catalog_startup_error(exc.cause_code)
            return ITEM_CATALOG_STARTUP_EXIT_CODE
        app.root.after(500, lambda: schedule_update_check(app.root))
        startup_complete = True
        return app, instance_lease
    finally:
        if not startup_complete:
            instance_lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
