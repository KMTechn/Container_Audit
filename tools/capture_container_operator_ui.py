from __future__ import annotations

import argparse
import ast
import base64
import ctypes
import datetime as dt
import functools
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from PIL import Image, ImageGrab


ROOT = Path(__file__).resolve().parents[1]
REPO_TMP_ROOT = ROOT / "tmp"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scan_display import compact_scan_value, format_scan_list_row
from preflight_scan_hold import HeldScan
from tools.capture_quality import (
    NEAR_BLACK_FAILURE_RATIO,
    analyze_capture_quality,
)


DEFAULT_SIZES = ((1366, 768), (1440, 900), (1920, 1080), (2560, 1080))
M7_REQUIRED_STATE_IDS = (
    "m7_phs2_preflight",
    "m7_central_preflight_queue",
    "m7_completion_busy",
    "m7_recovery_transition",
    "m7_direct_sync_backlog_ack",
    "m7_exact_good_membership",
    "m7_lease_fail_closed",
    "m7_transfer_receipt_status",
    "m7_partial_atomic_exchange",
)
DEFAULT_STATE_IDS = M7_REQUIRED_STATE_IDS
M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA = "M7 external capture bundle v1"
M7_EXTERNAL_CAPTURE_APP = "Container_Audit"
M7_EXTERNAL_CAPTURE_APPROVAL_LOCATION = "E:/requal-evidence/capture-bundle-v1/"
M7_EXTERNAL_CAPTURE_INDEX = (
    "HANDOVER-INDEX.md -> indexes/handover-index__<YYYYMMDDTHHMMSSZ>__<nonce8>.json"
)
M7_CANONICAL_CONTRACT_PATH = (
    "E:/KMTech/production-readiness-20260830/HANDOVER/"
    "CAPTURE-BUNDLE-V1-CONTRACT.md"
)
M7_PHS2_FIELD_ORDER = ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")
CAPTURE_EXACT_SIX_PHS2 = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITG-M7-CONTAINER-0001|"
    "CLC=AAA2270730100|LBL=LBL-M7-CONTAINER-0001|HSH=0123456789abcdef"
)
CAPTURE_ACTIVE_EXACT_SIX_PHS2 = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITG-M7-CONTAINER-0001|"
    "CLC=AAA2270730100|LBL=LBL-M7-CONTAINER-0002|HSH=fedcba9876543210"
)
M7_CAPTURE_MANIFEST_IDENTITY_FIELDS = (
    "app_source.commit",
    "app_source.tree",
    "portable_artifact.file",
    "portable_artifact.sha256",
    "capture_tool.path",
    "capture_tool.commit",
    "capture_tool.blob_sha256",
    "captures[].state_id",
    "captures[].image_file",
    "captures[].image_sha256",
    "captures[].viewport.width_px",
    "captures[].viewport.height_px",
    "captures[].dpi",
    "captures[].generated_at",
    "approval.approver",
    "approval.approval_receipt_file",
    "approval.approval_receipt_sha256",
    "approval.custody_receipt_file",
    "approval.custody_receipt_sha256",
)
M7_APPROVAL_PLACEHOLDER = "미정 — 조직 확정 필요(Q1)"
M7_CAPTURE_TOOL_PATH = "tools/capture_container_operator_ui.py"
M7_PRODUCT_TEXT_BLOBS = (
    "Container_Audit.py",
    "warning_presenter.py",
    "direct_sync_health.py",
    "transfer_seal.py",
    "transfer_member_exchange.py",
    "terminal_operation_lease.py",
)
M7_PRODUCTION_BINDING_PATHS = (
    "Container_Audit.py",
    "label_qr.py",
    "preflight_scan_hold.py",
    *M7_PRODUCT_TEXT_BLOBS[1:],
)
M7_ACTION_NAMES = (
    "reset",
    "undo",
    "park",
    "submit",
    "operations",
    "change_worker",
    "replace",
    "exchange",
    "phs_label_exchange",
)

# Each scene names only the production methods that the capture path must
# actually call.  Text provenance is measured against frozen Git blobs below;
# hand-maintained source ranges are intentionally not evidence.
M7_SCENE_CONTRACT: dict[str, dict[str, Any]] = {
    "m7_phs2_preflight": {
        "label": "exact-six PHS2 · 중앙 preflight 진행/차단",
        "production_call_path": (
            "show_status_message",
            "_set_preflight_scan_input_locked",
            "_update_current_item_label",
            "_update_action_button_states",
        ),
        "input_state": "disabled",
        "disabled_controls": M7_ACTION_NAMES,
    },
    "m7_central_preflight_queue": {
        "label": "중앙 확인 보류 FIFO · 실패/미접수",
        "production_call_path": (
            "show_status_message",
            "_set_preflight_scan_input_locked",
            "_update_action_button_states",
        ),
        "input_state": "disabled",
        "disabled_controls": M7_ACTION_NAMES,
    },
    "m7_completion_busy": {
        "label": "완료 처리 중 · 추가 완료 미접수",
        "production_call_path": (
            "_set_completion_lane_busy",
            "show_status_message",
            "_set_preflight_scan_input_locked",
            "_update_action_button_states",
        ),
        "input_state": "disabled",
        "disabled_controls": M7_ACTION_NAMES,
    },
    "m7_recovery_transition": {
        "label": "이전 작업 복구 · 전환 확인 · 보류 복원",
        "production_call_path": (
            "_update_center_display",
            "_update_parked_trays_list",
            "_update_parked_recovery_affordance",
            "show_status_message",
        ),
        "input_state": "normal",
        "disabled_controls": (),
        "modal_flow_titles": ("이전 작업 복구", "작업 전환 확인"),
    },
    "m7_direct_sync_backlog_ack": {
        "label": "저장 전송 backlog/ACK · 현재 이적 확인",
        "production_call_path": (
            "_apply_direct_sync_health",
            "_render_warning_state",
            "_update_action_button_states",
        ),
        "input_state": "normal",
        "disabled_controls": (),
    },
    "m7_exact_good_membership": {
        "label": "중앙 exact GOOD member_count · ID↔barcode",
        "production_call_path": (
            "_update_center_display",
            "_update_current_item_label",
            "_update_action_button_states",
        ),
        "input_state": "normal",
        "disabled_controls": (),
    },
    "m7_lease_fail_closed": {
        "label": "lease 발급 실패/만료 · 시작 전 오프라인 차단",
        "production_call_path": (
            "show_fullscreen_warning",
            "_set_preflight_scan_input_locked",
            "_update_action_button_states",
        ),
        "input_state": "disabled",
        "disabled_controls": M7_ACTION_NAMES,
    },
    "m7_transfer_receipt_status": {
        "label": "이적 receipt 완료/대기/재시도/확인 필요",
        "production_call_path": (
            "_render_warning_state",
            "_update_action_button_states",
        ),
        "input_state": "disabled",
        "disabled_controls": (
            "reset",
            "undo",
            "park",
            "operations",
            "change_worker",
            "replace",
            "exchange",
            "phs_label_exchange",
        ),
    },
    "m7_partial_atomic_exchange": {
        "label": "표준 부분 완료 차단 · 1~2쌍 원자 교환",
        "production_call_path": (
            "show_status_message",
            "_update_action_button_states",
        ),
        "input_state": "normal",
        "disabled_controls": (),
        "enabled_controls": ("exchange",),
    },
}
MIN_SCALE = 0.7
MAX_SCALE = 2.5
DEFAULT_SCALE = 1.0
CAPTURE_SUMMARY_ITEM_CODE = "AAA2270730200"
CAPTURE_SUMMARY_ROW_COUNT = 1
CAPTURE_PARKED_ROW_COUNT = 1
PRIMARY_MONITOR_FLAG = 1
GA_ROOT = 2
SW_RESTORE = 9
TREE_HEADING_GATE_WIDGETS = (
    ("summary_tree", "summary_tree", "left_context_switch_button"),
    ("parked_tree", "parked_tree", "left_context_switch_button"),
)
TREE_HEADING_SCAN_HEIGHT = 128
TREE_HEADING_IMAGE_GAP_PX = 2
TREE_DATA_CELL_GUTTER_PX = 8
TREE_DATA_VERTICAL_PADDING_PX = 4
# Keep this capture contract aligned with
# Container_Audit.LEFT_SIDEBAR_SWITCH_LOGICAL_HEIGHT.  A dual-tree layout is
# only acceptable when each tree can show a heading and a complete data row.
TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT = 1030.0
ROUNDTRIP_KEY_WIDGET_ATTRS = (
    "paned_window",
    "left_pane",
    "center_pane",
    "right_pane",
    "stage_label",
    "current_item_label",
    "main_count_label",
    "main_progress_bar",
    "scan_entry",
    "notice_frame",
    "_scan_list_frame",
    "scanned_list_header_label",
    "scanned_listbox",
    "scanned_list_scrollbar",
    "_center_button_frame",
    "undo_button",
    "park_button",
    "submit_tray_button",
    "operations_button",
    "_right_context_frame",
    "last_scan_value_label",
    "follow_up_label",
)
MATRIX_ROUNDTRIP_PARITY_TEXT_FIELDS = (
    "stage",
    "current_item",
    "count",
    "notice_title",
    "notice_message",
    "last_normal_scan",
    "last_normal_scan_display",
    "next_action",
    "status",
    "stopwatch",
    "scan_entry_state",
    "status_bar_text",
    "scan_list_row_count",
    "scan_list_rows",
    "scan_list_row_colors",
    "scan_list_rows_neutral",
    "scan_list_header",
    "right_texts",
    "left_sidebar",
)
MATRIX_ROUNDTRIP_SCAN_LAYOUT_FIELDS = (
    "frame_grid",
    "center_row_5",
    "header_grid",
    "list_grid",
    "frame_row_1",
)
MATRIX_ROUNDTRIP_ACTION_NAMES = frozenset(
    ("undo", "park", "submit", "operations")
)


Rect = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class NoticeFixture:
    code: str
    title: str
    message: str
    severity: str
    blocking: bool = False


@dataclass(frozen=True, slots=True)
class CompletionFixture:
    outcome: str
    message: str
    receipt_id: str = ""
    error_code: str = ""


@dataclass(frozen=True, slots=True)
class MemberFixture:
    product_id: str
    barcode: str


@dataclass(frozen=True, slots=True)
class LeaseFixture:
    state: str
    lease_id: str = ""
    expires_at: str = ""
    start_allowed: bool = False
    error_code: str = ""


@dataclass(frozen=True, slots=True)
class DirectSyncFixture:
    state: str
    pending_count: int
    failed_permanent_count: int
    operator_review_count: int
    last_acked_at: str
    oldest_pending_at: str
    observed_at: str
    error_code: str = ""


@dataclass(frozen=True, slots=True)
class TrayFixture:
    master_label: str
    item_code: str
    item_name: str
    item_spec: str
    target_count: int
    scanned_barcodes: tuple[str, ...]
    stopwatch_seconds: float
    restored: bool = False
    operation_lease_id: str = ""
    partial_submission: bool = False


@dataclass(frozen=True, slots=True)
class StateFixture:
    state_id: str
    state_label: str
    scanned_master_label: str = CAPTURE_EXACT_SIX_PHS2
    tray: TrayFixture | None = None
    last_normal_scan: str = ""
    last_normal_item_code: str = ""
    notice: NoticeFixture | None = None
    completion: CompletionFixture | None = None
    completed_tray_count: int = 0
    tray_image_visible: bool = False
    authoritative_members: tuple[MemberFixture, ...] = ()
    lease: LeaseFixture | None = None
    direct_sync: DirectSyncFixture | None = None
    preflight_phase: str = ""
    held_scans: tuple[str, ...] = ()
    status_variants: tuple[str, ...] = ()
    completion_variants: tuple[str, ...] = ()
    receipt_id: str = ""
    exchange_pairs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ExternalCaptureImage:
    """One already-rendered PNG supplied to the external envelope builder."""

    state_id: str
    png_bytes: bytes
    dpi: int


@dataclass(frozen=True, slots=True)
class DisplayMonitor:
    """Stable subset of Win32 monitor metadata used by capture gates."""

    device_name: str
    monitor_rect: Rect
    work_rect: Rect
    primary: bool

    def as_manifest(self) -> dict[str, Any]:
        return {
            "device_name": self.device_name,
            "monitor_rect": list(self.monitor_rect),
            "work_rect": list(self.work_rect),
            "primary": self.primary,
        }


@dataclass(frozen=True, slots=True)
class MonitorTarget:
    """An explicitly selected non-primary monitor for fixture capture."""

    requested_device_name: str
    monitor: DisplayMonitor

    def requested_client_rect(self, size: tuple[int, int]) -> Rect:
        width, height = (int(value) for value in size)
        work_left, work_top, work_right, work_bottom = self.monitor.work_rect
        work_width = work_right - work_left
        work_height = work_bottom - work_top
        if width > work_width or height > work_height:
            raise RuntimeError(
                "capture size does not fit the selected monitor work area: "
                f"device={self.monitor.device_name!r} size={width}x{height} "
                f"work={self.monitor.work_rect}"
            )
        left = work_left + (work_width - width) // 2
        top = work_top + (work_height - height) // 2
        return left, top, left + width, top + height

    def tk_geometry(self, size: tuple[int, int]) -> str:
        left, top, right, bottom = self.requested_client_rect(size)
        return _format_tk_geometry(right - left, bottom - top, left, top)


def _products(count: int) -> tuple[str, ...]:
    return tuple(
        (
            "AAA2270730100|"
            f"SERIAL=M7-CONTAINER-{index:04d}|"
            f"TRACE=M7-TRACE-{index:04d}"
        )
        for index in range(1, count + 1)
    )


def build_state_fixtures() -> tuple[StateFixture, ...]:
    """Return the nine deterministic C-1 scenes for external capture."""

    products = _products(3)
    replacement_products = tuple(
        value.replace("M7-CONTAINER", "M7-REPLACEMENT")
        for value in products[:2]
    )
    members = tuple(
        MemberFixture(product_id=f"UNIT-M7-{index:04d}", barcode=barcode)
        for index, barcode in enumerate(products, start=1)
    )
    active_lease = LeaseFixture(
        state="ACTIVE",
        lease_id="LEASE-M7-CONTAINER-0001",
        expires_at="2026-09-03T09:30:00+09:00",
        start_allowed=True,
    )
    common = {
        "master_label": CAPTURE_EXACT_SIX_PHS2,
        "item_code": "AAA2270730100",
        "item_name": "M7 캡처 기준 품목",
        "item_spec": "중앙 exact GOOD 3개",
        "target_count": len(members),
    }
    return (
        StateFixture(
            state_id="m7_phs2_preflight",
            state_label=M7_SCENE_CONTRACT["m7_phs2_preflight"]["label"],
            authoritative_members=members,
            lease=LeaseFixture(state="ISSUE_PENDING", start_allowed=False),
            preflight_phase="LOOKUP",
            status_variants=(
                "중앙에서 검사 완료 수량과 제품 구성을 확인하고 있습니다.",
                "현품표 정보를 읽지 못했습니다. 현품표를 확인한 뒤 다시 스캔하세요.",
            ),
        ),
        StateFixture(
            state_id="m7_central_preflight_queue",
            state_label=M7_SCENE_CONTRACT["m7_central_preflight_queue"]["label"],
            authoritative_members=members,
            lease=LeaseFixture(
                state="ISSUE_FAILED",
                start_allowed=False,
                error_code="PHS2_PREFLIGHT_UNAVAILABLE",
            ),
            preflight_phase="LOOKUP_FAILED",
            held_scans=products[:2],
            status_variants=(
                "중앙 확인 중 · 보류 스캔 2건",
                "중앙 확인 완료 · 보류 2건 순서대로 처리 중",
                "중앙 조회 실패 · 보류 2건 (삭제되지 않음)",
                "이전 중앙 작업 처리 중입니다. 이번 현품표 입력은 접수되지 않았습니다.",
                "보류 저장 대기열이 가득 차 이번 스캔은 접수되지 않았습니다.",
            ),
        ),
        StateFixture(
            state_id="m7_completion_busy",
            state_label=M7_SCENE_CONTRACT["m7_completion_busy"]["label"],
            tray=TrayFixture(
                **common,
                scanned_barcodes=products,
                stopwatch_seconds=128,
                operation_lease_id=active_lease.lease_id,
            ),
            last_normal_scan=products[-1],
            last_normal_item_code=common["item_code"],
            authoritative_members=members,
            lease=active_lease,
            preflight_phase="DRAINING",
            held_scans=products[-1:],
            status_variants=(
                "완료 처리 중",
                "이전 중앙 작업 처리 중 · 이번 완료 요청은 접수되지 않았습니다.",
                "중앙 조회 보류 묶음 처리 중입니다. 이번 작업은 접수되지 않았습니다.",
            ),
            tray_image_visible=True,
        ),
        StateFixture(
            state_id="m7_recovery_transition",
            state_label=M7_SCENE_CONTRACT["m7_recovery_transition"]["label"],
            tray=TrayFixture(
                **common,
                scanned_barcodes=products[:2],
                stopwatch_seconds=196,
                restored=True,
                operation_lease_id=active_lease.lease_id,
            ),
            last_normal_scan=products[1],
            last_normal_item_code=common["item_code"],
            authoritative_members=members,
            lease=active_lease,
            status_variants=(
                "이전 작업 복구",
                "작업 전환 확인",
                "보류 작업 1건 (더블클릭으로 복원)",
                "이전 트레이 작업을 복구했습니다.",
            ),
            tray_image_visible=True,
        ),
        StateFixture(
            state_id="m7_direct_sync_backlog_ack",
            state_label=M7_SCENE_CONTRACT["m7_direct_sync_backlog_ack"]["label"],
            last_normal_scan=products[-1],
            last_normal_item_code=common["item_code"],
            completion=CompletionFixture(
                outcome="ACKED",
                message="'M7 캡처 기준 품목' 완료 · 서버 이적 확인이 완료되었습니다.",
                receipt_id="RECEIPT-M7-CONTAINER-ACK-0001",
            ),
            completed_tray_count=1,
            authoritative_members=members,
            lease=active_lease,
            direct_sync=DirectSyncFixture(
                state="pending",
                pending_count=2,
                failed_permanent_count=0,
                operator_review_count=0,
                last_acked_at="2026-09-03T08:15:00+09:00",
                oldest_pending_at="2026-09-03T08:20:00+09:00",
                observed_at="2026-09-03T08:25:00+09:00",
            ),
            completion_variants=("ACKED",),
            receipt_id="RECEIPT-M7-CONTAINER-ACK-0001",
        ),
        StateFixture(
            state_id="m7_exact_good_membership",
            state_label=M7_SCENE_CONTRACT["m7_exact_good_membership"]["label"],
            tray=TrayFixture(
                **common,
                scanned_barcodes=products,
                stopwatch_seconds=164,
                operation_lease_id=active_lease.lease_id,
            ),
            last_normal_scan=products[-1],
            last_normal_item_code=common["item_code"],
            authoritative_members=members,
            lease=active_lease,
            tray_image_visible=True,
        ),
        StateFixture(
            state_id="m7_lease_fail_closed",
            state_label=M7_SCENE_CONTRACT["m7_lease_fail_closed"]["label"],
            authoritative_members=members,
            lease=LeaseFixture(
                state="EXPIRED",
                lease_id="LEASE-M7-CONTAINER-EXPIRED-0001",
                expires_at="2026-09-03T07:55:00+09:00",
                start_allowed=False,
                error_code="OPERATION_LEASE_EXPIRED",
            ),
            preflight_phase="LOOKUP_FAILED",
            status_variants=(
                "이 PC에서 오프라인 이적 확인 정보를 준비할 수 없습니다.",
                "server lease remains unresolved and cannot be replaced",
                "검사 완료 상태와 네트워크를 확인한 뒤 다시 스캔하세요.",
            ),
        ),
        StateFixture(
            state_id="m7_transfer_receipt_status",
            state_label=M7_SCENE_CONTRACT["m7_transfer_receipt_status"]["label"],
            tray=TrayFixture(
                **common,
                scanned_barcodes=products,
                stopwatch_seconds=180,
                operation_lease_id=active_lease.lease_id,
            ),
            last_normal_scan=products[-1],
            last_normal_item_code=common["item_code"],
            completion=CompletionFixture(
                outcome="RETRY_WAIT",
                message="동일 이적 요청의 서버 receipt를 다시 확인해야 합니다.",
                receipt_id="RECEIPT-M7-CONTAINER-PENDING-0001",
                error_code="TRANSFER_RECEIPT_PENDING",
            ),
            authoritative_members=members,
            lease=active_lease,
            completion_variants=(
                "LINKED",
                "ACKED",
                "RETRY_WAIT",
                "LOCAL_EVENT_RETRY",
                "OPERATOR_REVIEW",
            ),
            receipt_id="RECEIPT-M7-CONTAINER-PENDING-0001",
            tray_image_visible=True,
        ),
        StateFixture(
            state_id="m7_partial_atomic_exchange",
            state_label=M7_SCENE_CONTRACT["m7_partial_atomic_exchange"]["label"],
            tray=TrayFixture(
                **common,
                scanned_barcodes=products[:2],
                stopwatch_seconds=94,
                operation_lease_id=active_lease.lease_id,
            ),
            last_normal_scan=products[1],
            last_normal_item_code=common["item_code"],
            authoritative_members=members,
            lease=active_lease,
            status_variants=(
                "PHS=2 현품표에 등록된 제품을 모두 스캔해야 이적할 수 있습니다.",
                "현재 이적 제품 교체",
            ),
            exchange_pairs=((products[0], replacement_products[0]),),
            tray_image_visible=True,
        ),
    )


def build_m7_external_capture_bundle_contract() -> dict[str, Any]:
    """Return the canonical headless describe envelope and nothing else."""

    return {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "app": M7_EXTERNAL_CAPTURE_APP,
        "required_state_ids": list(M7_REQUIRED_STATE_IDS),
    }


def _bound_method_identity(method: Any) -> str:
    function = getattr(method, "__func__", method)
    module_name = str(getattr(function, "__module__", "") or "")
    qualname = str(getattr(function, "__qualname__", "") or "")
    return ".".join(part for part in (module_name, qualname) if part)


def _assert_runtime_module_binding(module: Any) -> str:
    module_path = Path(str(getattr(module, "__file__", "") or "")).resolve()
    if module_path != (ROOT / "Container_Audit.py").resolve():
        raise RuntimeError("Container_Audit runtime module is not loaded from this repository")
    commit = _resolve_git_commit(str(ROOT.resolve()), "HEAD")
    _assert_frozen_production_worktree(ROOT, commit)
    return commit


def _git_bytes(repo_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "git evidence query failed: "
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout


@functools.lru_cache(maxsize=16)
def _resolve_git_commit(repo_root_text: str, revision: str) -> str:
    return _git_bytes(
        Path(repo_root_text), "rev-parse", f"{revision}^{{commit}}"
    ).decode("ascii").strip()


def _git_paths_match_commit(
    repo_root: Path,
    commit: str,
    relative_paths: Sequence[str],
) -> bool:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--quiet",
            "--no-ext-diff",
            commit,
            "--",
            *relative_paths,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(
            "git worktree evidence query failed: "
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.returncode == 0


def _production_binding_signature(
    repo_root: Path,
) -> tuple[tuple[str, int, int, bool], ...]:
    signature: list[tuple[str, int, int, bool]] = []
    for relative_path in M7_PRODUCTION_BINDING_PATHS:
        path = repo_root / Path(relative_path)
        try:
            stat = path.stat()
            signature.append(
                (relative_path, stat.st_size, stat.st_mtime_ns, path.is_symlink())
            )
        except OSError:
            signature.append((relative_path, -1, -1, path.is_symlink()))
    return tuple(signature)


@functools.lru_cache(maxsize=32)
def _assert_frozen_production_worktree_cached(
    repo_root_text: str,
    commit: str,
    signature: tuple[tuple[str, int, int, bool], ...],
) -> None:
    repo_root = Path(repo_root_text)
    for relative_path in M7_PRODUCTION_BINDING_PATHS:
        frozen, _digest = _frozen_git_blob(
            str(repo_root.resolve()), commit, relative_path
        )
        path = repo_root / Path(relative_path)
        if not frozen or not path.is_file() or path.is_symlink():
            raise RuntimeError(
                f"production path is not a frozen regular file: {relative_path}"
            )
    if not _git_paths_match_commit(repo_root, commit, M7_PRODUCTION_BINDING_PATHS):
        raise RuntimeError("production worktree does not match the frozen app commit")


def _assert_frozen_production_worktree(repo_root: Path, commit: str) -> None:
    resolved_root = repo_root.resolve()
    _assert_frozen_production_worktree_cached(
        str(resolved_root),
        commit,
        _production_binding_signature(resolved_root),
    )


@functools.lru_cache(maxsize=64)
def _frozen_git_blob(
    repo_root_text: str,
    commit: str,
    relative_path: str,
) -> tuple[bytes, str]:
    repo_root = Path(repo_root_text)
    raw = _git_bytes(repo_root, "show", f"{commit}:{relative_path}")
    return raw, hashlib.sha256(raw).hexdigest()


@functools.lru_cache(maxsize=64)
def _python_non_docstring_literals(raw: bytes) -> frozenset[str]:
    tree = ast.parse(raw.decode("utf-8"))
    docstring_nodes: set[int] = set()
    for parent in ast.walk(tree):
        body = getattr(parent, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstring_nodes.add(id(body[0].value))
    return frozenset(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstring_nodes
    )


def inspect_production_text_provenance(
    text: str,
    *,
    commit: str = "HEAD",
    repo_root: Path = ROOT,
) -> dict[str, Any]:
    """Prove exact visible copy exists in a frozen production Git blob."""

    value = str(text or "")
    resolved_root = repo_root.resolve()
    matches: list[dict[str, str]] = []
    errors: list[str] = []
    try:
        frozen_commit = _resolve_git_commit(str(resolved_root), commit)
        _assert_frozen_production_worktree(resolved_root, frozen_commit)
    except (RuntimeError, UnicodeError) as exc:
        frozen_commit = ""
        errors.append(f"production_binding:{exc.__class__.__name__}")
    if value:
        for relative_path in M7_PRODUCT_TEXT_BLOBS:
            try:
                raw, digest = _frozen_git_blob(
                    str(resolved_root), frozen_commit or commit, relative_path
                )
                literals = _python_non_docstring_literals(raw)
            except (RuntimeError, UnicodeError, SyntaxError) as exc:
                errors.append(f"{relative_path}:{exc.__class__.__name__}")
                continue
            if value in literals:
                matches.append(
                    {
                        "path": relative_path,
                        "blob_sha256": digest,
                        "match_kind": "python_string_literal_exact",
                    }
                )
    return {
        "text": value,
        "exact_product_blob_match": bool(matches),
        "matches": matches,
        "errors": errors,
        "passed": bool(value) and bool(matches) and not errors,
    }


def validate_m7_production_call_trace(
    trace: Mapping[str, Any],
    expected_methods: Sequence[str],
) -> dict[str, Any]:
    """Recompute trace validity from immutable per-call facts."""

    expected = [str(name) for name in expected_methods]
    calls_value = trace.get("calls")
    calls = list(calls_value) if isinstance(calls_value, list) else []
    observed_methods = [
        str(call.get("method") or "") if isinstance(call, Mapping) else ""
        for call in calls
    ]
    unexpected = [name for name in observed_methods if name not in expected]
    checks = {
        "expected_methods_exact": trace.get("expected_methods") == expected,
        "calls_present": bool(calls),
        "ordinals_exact": all(
            isinstance(call, Mapping) and call.get("ordinal") == index
            for index, call in enumerate(calls, start=1)
        ),
        "methods_declared": not unexpected,
        "production_identities_exact": all(
            isinstance(call, Mapping)
            and call.get("production_identity")
            == f"Container_Audit.ContainerAudit.{call.get('method')}"
            for call in calls
        ),
        "originals_invoked": all(
            isinstance(call, Mapping) and call.get("original_invoked") is True
            for call in calls
        ),
        "calls_returned": all(
            isinstance(call, Mapping) and call.get("returned") is True
            for call in calls
        ),
        "every_expected_called": all(name in observed_methods for name in expected),
    }
    return {
        "expected_methods": expected,
        "observed_methods": observed_methods,
        "unexpected_methods": unexpected,
        "checks": checks,
        "passed": all(checks.values()),
    }


@contextmanager
def trace_m7_production_calls(
    app: Any,
    module: Any,
    method_names: Sequence[str],
) -> Iterator[dict[str, Any]]:
    """Wrap bound production methods, invoke the originals, and record calls."""

    expected = tuple(str(name) for name in method_names)
    originals: dict[str, Any] = {}
    prior_instance_values: dict[str, Any] = {}
    had_instance_value: dict[str, bool] = {}
    records: list[dict[str, Any]] = []
    for method_name in expected:
        original = getattr(app, method_name, None)
        identity = _bound_method_identity(original)
        if not callable(original) or identity != (
            f"Container_Audit.ContainerAudit.{method_name}"
        ):
            raise RuntimeError(
                f"M7 call trace cannot bind production method {method_name}: "
                f"{identity or '<missing>'}"
            )
        originals[method_name] = original
        instance_dict = getattr(app, "__dict__", {})
        had_instance_value[method_name] = method_name in instance_dict
        if had_instance_value[method_name]:
            prior_instance_values[method_name] = instance_dict[method_name]

        @functools.wraps(getattr(original, "__func__", original))
        def traced(
            *args: Any,
            __name: str = method_name,
            __identity: str = identity,
            __original: Callable[..., Any] = original,
            **kwargs: Any,
        ) -> Any:
            record: dict[str, Any] = {
                "ordinal": len(records) + 1,
                "method": __name,
                "production_identity": __identity,
                "original_invoked": True,
                "returned": False,
            }
            records.append(record)
            try:
                result = __original(*args, **kwargs)
            except BaseException as exc:
                record["exception"] = exc.__class__.__name__
                raise
            record["returned"] = True
            return result

        setattr(app, method_name, traced)

    trace = {
        "expected_methods": list(expected),
        "calls": records,
        "all_expected_called": False,
        "unexpected_methods": [],
        "passed": False,
    }
    try:
        yield trace
    finally:
        for method_name in reversed(expected):
            if had_instance_value[method_name]:
                setattr(app, method_name, prior_instance_values[method_name])
            else:
                try:
                    delattr(app, method_name)
                except AttributeError:
                    pass
        assessment = validate_m7_production_call_trace(trace, expected)
        trace["all_expected_called"] = assessment["checks"][
            "every_expected_called"
        ]
        trace["unexpected_methods"] = assessment["unexpected_methods"]
        trace["trace_checks"] = assessment["checks"]
        trace["passed"] = assessment["passed"]


def inspect_m7_production_scene_seams(
    module: Any,
    scene_receipts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Report only observed traces as seams; callable presence is declaration-only."""

    _assert_runtime_module_binding(module)
    observed_receipts = dict(scene_receipts or {})
    inspected_scenes: dict[str, Any] = {}
    for state_id in M7_REQUIRED_STATE_IDS:
        spec = M7_SCENE_CONTRACT[state_id]
        identities: dict[str, str] = {}
        for method_name in spec["production_call_path"]:
            method = getattr(module.ContainerAudit, method_name, None)
            identity = _bound_method_identity(method)
            if not callable(method) or identity != (
                f"Container_Audit.ContainerAudit.{method_name}"
            ):
                raise RuntimeError(
                    f"M7 scene {state_id} has no production method {method_name}: "
                    f"{identity or '<missing>'}"
                )
            identities[str(method_name)] = identity
        observed = observed_receipts.get(state_id)
        call_trace = (
            observed.get("production_call_trace")
            if isinstance(observed, Mapping)
            else None
        )
        semantic = (
            observed.get("assertions", {}).get("production_validation", {})
            if isinstance(observed, Mapping)
            and isinstance(observed.get("assertions"), Mapping)
            else {}
        )
        trace_assessment = (
            validate_m7_production_call_trace(
                call_trace,
                spec["production_call_path"],
            )
            if isinstance(call_trace, Mapping)
            else {"passed": False}
        )
        trace_matches = trace_assessment["passed"] is True
        inspected_scenes[state_id] = {
            "state_id": state_id,
            "production_call_path": list(spec["production_call_path"]),
            "production_method_identities": identities,
            "production_call_trace": call_trace,
            "production_call_trace_assessment": trace_assessment,
            "trace_observed": trace_matches,
            "semantic_variants_validated": semantic.get("passed") is True,
            "seam_available": bool(
                trace_matches and semantic.get("passed") is True
            ),
            "reason": (
                "validated"
                if trace_matches and semantic.get("passed") is True
                else "actual_scene_trace_required"
                if call_trace is None
                else "production_semantic_variant_unavailable"
            ),
        }

    support_callables = {
        "phs2_parser": module.parse_new_format_qr,
        "phs2_validator": module.validate_compact_phs2_fields,
        "warning_presenter": module.WarningPresenter.present_completion,
        "completion_notice": module.notice_for_completion,
        "relay_health_presenter": module.relay_health_card_model,
    }
    support_identities = {
        name: _bound_method_identity(callable_value)
        for name, callable_value in support_callables.items()
    }
    expected_support_identities = {
        "phs2_parser": "label_qr.parse_new_format_qr",
        "phs2_validator": "transfer_seal.validate_compact_phs2_fields",
        "warning_presenter": "warning_presenter.WarningPresenter.present_completion",
        "completion_notice": "warning_presenter.notice_for_completion",
        "relay_health_presenter": "direct_sync_health.relay_health_card_model",
    }
    if not all(
        callable(value)
        and support_identities[name] == expected_support_identities[name]
        for name, value in support_callables.items()
    ):
        raise RuntimeError("M7 production support seam is incomplete")
    return {
        "scenes": inspected_scenes,
        "support_method_identities": support_identities,
        "declared_scene_count": len(inspected_scenes),
        "traced_scene_count": sum(
            item["trace_observed"] for item in inspected_scenes.values()
        ),
        "production_validated_scene_count": sum(
            item["seam_available"] for item in inspected_scenes.values()
        ),
        "no_seam_scene_count": sum(
            not item["seam_available"] for item in inspected_scenes.values()
        ),
        "all_seams_available": all(
            item["seam_available"] for item in inspected_scenes.values()
        ),
    }


def _validate_exact_six_phs2(module: Any, payload: str) -> dict[str, Any]:
    segments = str(payload or "").split("|")
    field_order = [segment.split("=", 1)[0] for segment in segments if "=" in segment]
    parsed = module.parse_new_format_qr(payload)
    validated = module.validate_compact_phs2_fields(parsed or {})
    checks = {
        "six_segments": len(segments) == 6,
        "field_order_exact": tuple(field_order) == M7_PHS2_FIELD_ORDER,
        "field_set_exact": set(validated) == set(M7_PHS2_FIELD_ORDER),
        "version_two": validated.get("PHS") == "2",
        "central_input_tag_source": validated.get("SRC") == "KMTECH_INPUT_TAG",
        "hash_prefix_16_hex": bool(
            re.fullmatch(r"[0-9a-f]{16}", str(validated.get("HSH") or ""))
        ),
    }
    return {
        "payload": payload,
        "field_order": field_order,
        "validated_fields": validated,
        "parser_identity": _bound_method_identity(module.parse_new_format_qr),
        "validator_identity": _bound_method_identity(
            module.validate_compact_phs2_fields
        ),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _production_member_set_assertion(
    module: Any,
    fixture: StateFixture,
) -> dict[str, Any]:
    """Run the production PHS2 preflight validator over the exact member map."""

    import transfer_seal

    fields = module.parse_new_format_qr(fixture.scanned_master_label) or {}
    members = [asdict(member) for member in fixture.authoritative_members]
    member_ids = [member["product_id"] for member in members]
    barcodes = [member["barcode"] for member in members]
    validated_fields = module.validate_compact_phs2_fields(fields)
    label_hash = validated_fields["HSH"] + ("0" * 48)
    registry = {
        "input_tag_id": validated_fields["ITG"],
        "label_id": validated_fields["LBL"],
        "item_id": validated_fields["CLC"],
        "tag_core_hash": hashlib.sha256(b"container-m7-input-tag").hexdigest(),
        "label_instance_hash": label_hash,
        "hash_prefix": validated_fields["HSH"],
        "lifecycle": "INSPECTION_COMPLETED",
        "qr_payload": fixture.scanned_master_label,
    }
    resolved = {
        "candidate_count": 1,
        "bundle": {
            "authority_scope_id": "M7-CAPTURE-AUTHORITY",
            "authority_epoch": 1,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 1,
            "bundle_id": "M7-CAPTURE-SOURCE-BUNDLE",
            "bundle_role": "TRANSFER_SOURCE",
            "bundle_type": "PHS",
            "bundle_state": "AVAILABLE",
            "external_label": fixture.scanned_master_label,
            "source_session_id": validated_fields["ITG"],
            "item_id": validated_fields["CLC"],
            "uom": "EA",
            "source_iin": "M7-CAPTURE-IIN",
            "current_location": "PHS_GOOD",
            "current_locations": ["PHS_GOOD"],
            "member_ids": member_ids,
            "member_count": len(member_ids),
            "membership_hash": transfer_seal.membership_hash(member_ids),
            "barcode_member_count": len(barcodes),
            "barcode_membership_hash": transfer_seal.membership_hash(barcodes),
            "entity_version": 1,
            "entity_versions": {"bundle:M7-CAPTURE-SOURCE-BUNDLE": 1},
            "members": [
                {
                    "unit_id": member["product_id"],
                    "normalized_barcode": member["barcode"],
                    "inbound_iin": "M7-CAPTURE-IIN",
                    "current_inbound_iin": "M7-CAPTURE-IIN",
                    "item_id": validated_fields["CLC"],
                    "uom": "EA",
                    "unit_state": "AVAILABLE",
                    "location_code": "PHS_GOOD",
                }
                for member in members
            ],
        },
        "input_tag": registry,
    }
    try:
        preflight = module.validate_compact_phs2_preflight(
            validated_fields,
            resolved,
        )
    except module.TransferSealError as exc:
        return {
            "production_validator_called": True,
            "validator_identity": _bound_method_identity(
                module.validate_compact_phs2_preflight
            ),
            "error_code": exc.code,
            "passed": False,
        }
    expected_pairs = sorted(
        (member["product_id"], member["barcode"]) for member in members
    )
    validated_input_pairs = sorted(
        (member["unit_id"], member["normalized_barcode"])
        for member in resolved["bundle"]["members"]
    )
    checks = {
        "member_count_exact": preflight.member_count == len(members),
        "member_ids_exact": list(preflight.member_ids) == sorted(member_ids),
        "barcodes_exact": list(preflight.normalized_barcodes) == sorted(barcodes),
        "validated_input_pairs_exact": validated_input_pairs == expected_pairs,
        "quantity_basis_central_exact_membership": (
            preflight.audit_detail().get("quantity_basis")
            == "CENTRAL_EXACT_MEMBERSHIP"
        ),
    }
    return {
        "production_validator_called": True,
        "validator_identity": _bound_method_identity(
            module.validate_compact_phs2_preflight
        ),
        "member_count": preflight.member_count,
        "member_ids": list(preflight.member_ids),
        "normalized_barcodes": list(preflight.normalized_barcodes),
        "validated_input_pairs": [list(pair) for pair in validated_input_pairs],
        "membership_hash": preflight.membership_hash,
        "barcode_membership_hash": preflight.barcode_membership_hash,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _status_variant_assertion(
    module: Any,
    *,
    variant_id: str,
    text: str,
    color: str,
) -> dict[str, Any]:
    """Exercise generic copy presentation without claiming business semantics."""

    app = module.ContainerAudit.__new__(module.ContainerAudit)
    app.warning_presenter = module.WarningPresenter()
    app.current_tray = SimpleNamespace(master_label_code="")
    app.status_label = None
    app.notice_frame = None
    app.notice_title_label = None
    app.notice_message_label = None
    app.phs_active_label_info_label = None
    app.notice_ack_button = None
    app.scan_entry = None
    app.last_scan_value_label = None
    app.info_cards = {}
    app.follow_up_label = None
    app._center_widget_generation = 0
    app._schedule_notice_message_wrap_refresh = lambda **_kwargs: None
    trace: dict[str, Any]
    with trace_m7_production_calls(
        app,
        module,
        ("show_status_message",),
    ) as trace:
        app.show_status_message(text, color, duration=0)
    notice = app.warning_presenter.state.active_notice
    provenance = inspect_production_text_provenance(text)
    presenter_checks = {
        "production_presenter_called": trace["passed"] is True,
        "presented_text_exact": notice is not None and notice.message == text,
        "text_exact_in_product_blob": provenance["passed"] is True,
    }
    return {
        "variant_id": variant_id,
        "kind": "status_presenter",
        "expected_text": text,
        "presented_text": notice.message if notice is not None else "",
        "production_call_trace": trace,
        "text_provenance": provenance,
        "presenter_checks": presenter_checks,
        "presenter_checks_passed": all(presenter_checks.values()),
        "business_state_producer_called": False,
        "reason": (
            "generic show_status_message accepts caller-provided copy; no safe "
            "branch-specific producer was called"
        ),
        "seam_available": False,
        "passed": False,
    }


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _expired_lease_validation_assertion(fixture: StateFixture) -> dict[str, Any]:
    """Use the production signed-artifact validator to prove expiry."""

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    import terminal_operation_lease as lease
    import transfer_seal

    lease_fixture = fixture.lease
    if lease_fixture is None or not lease_fixture.lease_id or not lease_fixture.expires_at:
        raise RuntimeError("expired-lease scene requires a bound lease fixture")
    expires = dt.datetime.fromisoformat(lease_fixture.expires_at).astimezone(
        dt.timezone.utc
    )
    issued = expires - dt.timedelta(minutes=5)
    snapshot = {
        "fixture": fixture.state_id,
        "lease_id": lease_fixture.lease_id,
    }
    members = [member.product_id for member in fixture.authoritative_members]
    claims = {
        "contract_version": lease.LEASE_CONTRACT_VERSION,
        "lease_id": lease_fixture.lease_id,
        "site_id": "M7-CAPTURE-SITE",
        "program": "Container_Audit",
        "device_id": "M7-CAPTURE-DEVICE",
        "source_host_id": "M7-CAPTURE-HOST",
        "authority_scope_id": "M7-CAPTURE-AUTHORITY",
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "operation": lease.TRANSFER_OPERATION,
        "resource_id": "phs-work-group:M7-CAPTURE-GROUP",
        "physical_label_id": "LBL-M7-CONTAINER-0001",
        "physical_qr_sha256": lease.physical_qr_sha256(CAPTURE_EXACT_SIX_PHS2),
        "item_id": "AAA2270730100",
        "quantity": len(members),
        "member_count": len(members),
        "membership_hash": transfer_seal.membership_hash(members),
        "expected_versions": {"bundle:M7-CAPTURE-SOURCE": 1},
        "issued_at": lease.utc_text(issued),
        "expires_at": lease.utc_text(expires),
        "fence": 1,
        "snapshot_hash": lease.canonical_hash(snapshot),
    }
    private_key = ec.derive_private_key(7, ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }
    kid = "M7-CAPTURE-LEASE-KEY"
    header = {"alg": "ES256", "kid": kid, "typ": lease.JWS_TYPE}
    encoded_header = _b64url(lease.canonical_json_bytes(header))
    encoded_payload = _b64url(lease.canonical_json_bytes(claims))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der)
    p256_order = int(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    s_value = min(s_value, p256_order - s_value)
    token = (
        f"{encoded_header}.{encoded_payload}."
        + _b64url(r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big"))
    )
    keyring = {
        "contract_version": lease.KEYRING_CONTRACT_VERSION,
        "site_id": claims["site_id"],
        "current_kid": kid,
        "keys": [
            {
                "kid": kid,
                "status": "current",
                "public_jwk": public_jwk,
                "thumbprint": lease.jwk_thumbprint(public_jwk),
            }
        ],
    }
    artifact = {
        "contract_version": lease.ARTIFACT_CONTRACT_VERSION,
        "lease_id": claims["lease_id"],
        "status": "ACTIVE",
        "replayed": False,
        "token": token,
        "kid": kid,
        "expires_at": claims["expires_at"],
        "fence": claims["fence"],
        "snapshot_hash": claims["snapshot_hash"],
        "operation_snapshot": snapshot,
        "keyring": keyring,
    }
    expected = {key: claims[key] for key in lease.LEASE_BINDING_KEYS}
    observed_code = ""
    try:
        lease.validate_artifact(
            artifact,
            expected=expected,
            now=expires + dt.timedelta(seconds=1),
        )
    except lease.OperationLeaseError as exc:
        observed_code = exc.code
    expected_error_code = lease_fixture.error_code
    fixture_binding = {
        "lease_id": artifact["lease_id"] == lease_fixture.lease_id,
        "expires_at": artifact["expires_at"]
        == lease.utc_text(expires),
        "error_code": observed_code == expected_error_code,
    }
    return {
        "variant_id": "lease_expired",
        "production_validator_called": True,
        "validator_identity": _bound_method_identity(lease.validate_artifact),
        "observed_error_code": observed_code,
        "expected_error_code": expected_error_code,
        "fixture_binding": fixture_binding,
        "seam_available": all(fixture_binding.values()),
        "passed": all(fixture_binding.values()),
    }


def _offline_lease_validation_assertion(
    module: Any,
    fixture: StateFixture,
) -> dict[str, Any]:
    coordinator = module.TransferSealCoordinator.__new__(
        module.TransferSealCoordinator
    )
    coordinator.client = None
    coordinator.operation_lease_manager = None
    observed_code = ""
    try:
        coordinator._verified_operation_lease(
            lease_id=(fixture.lease.lease_id if fixture.lease is not None else ""),
            master_label=fixture.scanned_master_label,
            master_label_fields=module.parse_new_format_qr(
                fixture.scanned_master_label
            )
            or {},
            item_id=(fixture.tray.item_code if fixture.tray is not None else "AAA2270730100"),
            scanned_barcodes=(
                list(fixture.tray.scanned_barcodes)
                if fixture.tray is not None
                else []
            ),
        )
    except module.TransferSealError as exc:
        observed_code = exc.code
    passed = observed_code == "OPERATION_LEASE_RUNTIME_UNAVAILABLE"
    return {
        "variant_id": "lease_offline_start_blocked",
        "production_validator_called": True,
        "validator_identity": _bound_method_identity(
            module.TransferSealCoordinator._verified_operation_lease
        ),
        "observed_error_code": observed_code,
        "expected_error_code": "OPERATION_LEASE_RUNTIME_UNAVAILABLE",
        "seam_available": passed,
        "passed": passed,
    }


def _completion_variant_assertions(
    module: Any,
    fixture: StateFixture,
) -> list[dict[str, Any]]:
    assertions: list[dict[str, Any]] = []
    target_count = len(fixture.authoritative_members)
    scan_count = (
        len(fixture.tray.scanned_barcodes)
        if fixture.tray is not None
        else target_count
    )
    for outcome_name in fixture.completion_variants:
        snapshot = module.CompletionOutcomeSnapshot(
            outcome=module.CompletionOutcome(outcome_name),
            item_name=(
                fixture.tray.item_name if fixture.tray is not None else "M7 캡처 기준 품목"
            ),
            master_label=fixture.scanned_master_label,
            scan_count=scan_count,
            target_count=max(scan_count, target_count),
            receipt_id=fixture.receipt_id,
        )
        presenter = module.WarningPresenter()
        changed = presenter.present_completion(snapshot)
        notice = presenter.state.active_notice
        title_provenance = inspect_production_text_provenance(
            notice.title if notice is not None else ""
        )
        checks = {
            "production_presenter_called": changed is True,
            "notice_present": notice is not None,
            "title_exact_in_product_blob": title_provenance["passed"] is True,
        }
        assertions.append(
            {
                "outcome": outcome_name,
                "presented": changed,
                "notice": {
                    "code": notice.code if notice is not None else "",
                    "title": notice.title if notice is not None else "",
                    "message": notice.message if notice is not None else "",
                    "blocking": bool(notice.blocking) if notice is not None else None,
                },
                "receipt_id": snapshot.receipt_id,
                "presenter_identity": _bound_method_identity(
                    presenter.present_completion
                ),
                "title_provenance": title_provenance,
                "checks": checks,
                "seam_available": all(checks.values()),
                "passed": all(checks.values()),
            }
        )
    return assertions


def _m7_variant_assertions(
    fixture: StateFixture,
    module: Any,
    *,
    member_validation: Mapping[str, Any],
    completion_variants: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    state_id = fixture.state_id
    if state_id == "m7_phs2_preflight":
        return [
            _status_variant_assertion(
                module,
                variant_id=f"preflight_{index}",
                text=text,
                color=(module.ContainerAudit.COLOR_PRIMARY if index == 1 else module.ContainerAudit.COLOR_DANGER),
            )
            for index, text in enumerate(fixture.status_variants, start=1)
        ]
    if state_id == "m7_central_preflight_queue":
        return [
            {
                "variant_id": f"central_queue_{index}",
                "kind": "business_state_without_safe_capture_seam",
                "expected_text": text,
                "text_provenance": inspect_production_text_provenance(text),
                "production_state_method_called": False,
                "reason": (
                    "production text is created inside asynchronous hold-store callbacks; "
                    "the capture tool has no read-only state API"
                ),
                "seam_available": False,
                "passed": False,
            }
            for index, text in enumerate(fixture.status_variants, start=1)
        ]
    if state_id == "m7_completion_busy":
        return [
            _status_variant_assertion(
                module,
                variant_id=f"completion_busy_{index}",
                text=text,
                color=(module.ContainerAudit.COLOR_PRIMARY if index == 1 else module.ContainerAudit.COLOR_DANGER),
            )
            for index, text in enumerate(fixture.status_variants, start=1)
        ]
    if state_id == "m7_recovery_transition":
        variants: list[dict[str, Any]] = []
        for index, text in enumerate(fixture.status_variants, start=1):
            if index == len(fixture.status_variants):
                variants.append(
                    _status_variant_assertion(
                        module,
                        variant_id="recovery_restored_status",
                        text=text,
                        color=module.ContainerAudit.COLOR_PRIMARY,
                    )
                )
                continue
            variants.append(
                {
                    "variant_id": f"recovery_flow_{index}",
                    "kind": "modal_or_dynamic_business_state_without_safe_capture_seam",
                    "expected_text": text,
                    "text_provenance": inspect_production_text_provenance(text),
                    "production_state_method_called": False,
                    "reason": (
                        "production exposes this state only through a modal or a dynamic "
                        "parked-row presenter; GUI execution is forbidden in this lane"
                    ),
                    "seam_available": False,
                    "passed": False,
                }
            )
        return variants
    if state_id == "m7_direct_sync_backlog_ack":
        assert fixture.direct_sync is not None
        health = module.RelayHealth(**asdict(fixture.direct_sync))
        card_model = module.relay_health_card_model(health)
        rendered = f"{card_model['summary']}\n{card_model['detail']}"
        ack = list(completion_variants)
        return [
            {
                "variant_id": "direct_sync_backlog_and_last_ack",
                "kind": "production_formatter_dynamic_copy",
                "production_formatter_called": True,
                "formatter_identity": _bound_method_identity(
                    module.relay_health_card_model
                ),
                "presented_text": rendered,
                "text_provenance": inspect_production_text_provenance(rendered),
                "reason": (
                    "the exact rendered backlog/ACK string is dynamic and is not an "
                    "exact product-blob string"
                ),
                "seam_available": False,
                "passed": False,
            },
            *ack,
        ]
    if state_id == "m7_exact_good_membership":
        passed = member_validation.get("passed") is True
        return [
            {
                "variant_id": "exact_good_member_count_and_pairs",
                "kind": "production_exact_membership_validator",
                "production_validation": dict(member_validation),
                "seam_available": passed,
                "passed": passed,
            }
        ]
    if state_id == "m7_lease_fail_closed":
        issue_text = fixture.status_variants[0]
        return [
            {
                "variant_id": "lease_issue_failed",
                "kind": "writer_only_api_without_read_only_validation_seam",
                "expected_text": issue_text,
                "text_provenance": inspect_production_text_provenance(issue_text),
                "production_validator_called": False,
                "reason": (
                    "lease issuance is a writer/network API and no dry-run validator exists"
                ),
                "seam_available": False,
                "passed": False,
            },
            _expired_lease_validation_assertion(fixture),
            _offline_lease_validation_assertion(module, fixture),
        ]
    if state_id == "m7_transfer_receipt_status":
        return [dict(item) for item in completion_variants]
    if state_id == "m7_partial_atomic_exchange":
        partial = _status_variant_assertion(
            module,
            variant_id="partial_completion_blocked",
            text=fixture.status_variants[0],
            color=module.ContainerAudit.COLOR_DANGER,
        )
        return [
            partial,
            {
                "variant_id": "one_or_two_pair_atomic_exchange",
                "kind": "mutation_free_exchange_validation_api_missing",
                "coordinator_identity": (
                    "transfer_member_exchange.TransferMemberExchangeCoordinator"
                ),
                "production_validator_called": False,
                "reason": (
                    "pair validation is coupled to TransferMemberExchangeStore.prepare "
                    "and mutates SQLite; no dry-run/validate API exists"
                ),
                "seam_available": False,
                "passed": False,
            },
        ]
    raise RuntimeError(f"unsupported M7 variant contract: {state_id}")


def build_m7_scene_assertions(
    fixture: StateFixture,
    module: Any,
) -> dict[str, Any]:
    """Build non-pixel assertions from production objects for one scene."""

    _assert_runtime_module_binding(module)
    spec = M7_SCENE_CONTRACT[fixture.state_id]
    phs2 = _validate_exact_six_phs2(module, fixture.scanned_master_label)
    members = [asdict(member) for member in fixture.authoritative_members]
    active_scans = (
        list(fixture.tray.scanned_barcodes) if fixture.tray is not None else []
    )
    member_validation = _production_member_set_assertion(module, fixture)
    direct_sync: dict[str, Any] | None = None
    if fixture.direct_sync is not None:
        health = module.RelayHealth(**asdict(fixture.direct_sync))
        direct_sync = {
            "health": asdict(fixture.direct_sync),
            "card_model": module.relay_health_card_model(health),
            "presenter_identity": _bound_method_identity(
                module.ContainerAudit._apply_direct_sync_health
            ),
        }
    lease = asdict(fixture.lease) if fixture.lease is not None else None
    exchange_pairs = [
        {"old_barcode": old, "new_barcode": new}
        for old, new in fixture.exchange_pairs
    ]
    completion_variants = _completion_variant_assertions(module, fixture)
    variant_assertions = _m7_variant_assertions(
        fixture,
        module,
        member_validation=member_validation,
        completion_variants=completion_variants,
    )
    exchange_applicable = bool(exchange_pairs)
    exchange_validation = {
        "applicable": exchange_applicable,
        "pairs": exchange_pairs,
        "production_validator_called": False,
        "validator_identity": None,
        "reason": (
            "no mutation-free TransferMemberExchangeCoordinator validate API"
            if exchange_applicable
            else "not_applicable"
        ),
        "seam_available": not exchange_applicable,
        "passed": not exchange_applicable,
    }
    production_checks = {
        "exact_six_phs2_validated": phs2["passed"] is True,
        "exact_membership_validated": member_validation.get("passed") is True,
        "every_variant_asserted": bool(variant_assertions),
        "every_variant_has_production_seam": all(
            item.get("passed") is True for item in variant_assertions
        ),
        "exchange_validated_when_applicable": (
            exchange_validation["passed"] is True
        ),
    }
    return {
        "schema": "container-audit-m7-scene-assertions-v1",
        "state_id": fixture.state_id,
        "production_call_path": list(spec["production_call_path"]),
        "expected_input_state": spec["input_state"],
        "expected_disabled_controls": list(spec.get("disabled_controls") or ()),
        "expected_enabled_controls": list(spec.get("enabled_controls") or ()),
        "modal_flow_titles": list(spec.get("modal_flow_titles") or ()),
        "exact_six_phs2": phs2,
        "preflight": {
            "phase": fixture.preflight_phase or None,
            "held_scan_count": len(fixture.held_scans),
            "held_scans": list(fixture.held_scans),
        },
        "member_set": {
            "member_count": len(members),
            "members": members,
            "active_scan_count": len(active_scans),
            "active_scans": active_scans,
            "production_validation": member_validation,
            "passed": member_validation.get("passed") is True,
        },
        "lease": {
            "fixture": lease,
            "production_variants": [
                item
                for item in variant_assertions
                if str(item.get("variant_id") or "").startswith("lease_")
            ],
        },
        "direct_sync": direct_sync,
        "receipt": {
            "active_receipt_id": fixture.receipt_id,
            "completion_variants": completion_variants,
        },
        "exchange": exchange_validation,
        "variant_assertions": variant_assertions,
        "production_validation": {
            "variant_count": len(variant_assertions),
            "validated_variant_count": sum(
                item.get("passed") is True for item in variant_assertions
            ),
            "no_seam_variant_count": sum(
                item.get("passed") is not True for item in variant_assertions
            ),
            "checks": production_checks,
            "passed": all(production_checks.values()),
        },
    }


def _parse_size_sequence(
    value: str,
    *,
    preserve_duplicates: bool,
) -> tuple[tuple[int, int], ...]:
    sizes: list[tuple[int, int]] = []
    for raw_item in str(value or "").split(","):
        item = raw_item.strip().lower().replace("×", "x")
        if not item:
            continue
        parts = item.split("x")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(f"invalid capture size: {raw_item!r}")
        try:
            width, height = (int(part) for part in parts)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid capture size: {raw_item!r}") from exc
        if width < 1024 or height < 720:
            raise argparse.ArgumentTypeError(
                f"capture size must be at least 1024x720: {width}x{height}"
            )
        pair = (width, height)
        if preserve_duplicates or pair not in sizes:
            sizes.append(pair)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one capture size is required")
    return tuple(sizes)


def parse_sizes(value: str) -> tuple[tuple[int, int], ...]:
    return _parse_size_sequence(value, preserve_duplicates=False)


def parse_roundtrip_sizes(value: str) -> tuple[tuple[int, int], ...]:
    """Parse an ordered compact/wide/compact sequence without de-duplication."""

    if not str(value or "").strip():
        return ()
    sizes = _parse_size_sequence(value, preserve_duplicates=True)
    if len(sizes) < 3:
        raise argparse.ArgumentTypeError(
            "roundtrip sizes require compact, wide, compact (at least three sizes)"
        )
    if sizes[0] != sizes[-1]:
        raise argparse.ArgumentTypeError(
            "roundtrip first and last sizes must match exactly"
        )
    if not any(size != sizes[0] for size in sizes[1:-1]):
        raise argparse.ArgumentTypeError(
            "roundtrip must include a different middle size"
        )
    return sizes


def parse_states(value: str) -> tuple[str, ...]:
    states: list[str] = []
    allowed = set(DEFAULT_STATE_IDS)
    for raw_item in str(value or "").split(","):
        state_id = raw_item.strip().lower()
        if not state_id:
            continue
        if state_id not in allowed:
            raise argparse.ArgumentTypeError(
                f"unknown state {raw_item!r}; choose from {', '.join(DEFAULT_STATE_IDS)}"
            )
        if state_id not in states:
            states.append(state_id)
    if not states:
        raise argparse.ArgumentTypeError("at least one state is required")
    return tuple(states)


def parse_scale(value: object) -> float:
    """Parse a supported UI scale without silently clamping capture evidence."""

    if isinstance(value, bool):
        raise argparse.ArgumentTypeError("scale must be a finite number")
    try:
        scale = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("scale must be a finite number") from exc
    if not math.isfinite(scale):
        raise argparse.ArgumentTypeError("scale must be a finite number")
    if not MIN_SCALE <= scale <= MAX_SCALE:
        raise argparse.ArgumentTypeError(
            f"scale must be between {MIN_SCALE} and {MAX_SCALE}: {scale}"
        )
    return scale


def _format_tk_offset(value: int) -> str:
    return f"+{value}" if value >= 0 else str(value)


def _format_tk_geometry(width: int, height: int, left: int, top: int) -> str:
    return (
        f"{int(width)}x{int(height)}"
        f"{_format_tk_offset(int(left))}{_format_tk_offset(int(top))}"
    )


def rect_is_contained(inner: Rect, outer: Rect) -> bool:
    inner_left, inner_top, inner_right, inner_bottom = inner
    outer_left, outer_top, outer_right, outer_bottom = outer
    return bool(
        inner_left < inner_right
        and inner_top < inner_bottom
        and outer_left < outer_right
        and outer_top < outer_bottom
        and inner_left >= outer_left
        and inner_top >= outer_top
        and inner_right <= outer_right
        and inner_bottom <= outer_bottom
    )


def _monitor_from_win32_info(info: dict[str, Any]) -> DisplayMonitor:
    return DisplayMonitor(
        device_name=str(info.get("Device") or ""),
        monitor_rect=tuple(int(value) for value in info["Monitor"]),
        work_rect=tuple(int(value) for value in info["Work"]),
        primary=bool(int(info.get("Flags", 0) or 0) & PRIMARY_MONITOR_FLAG),
    )


def enumerate_display_monitors() -> tuple[DisplayMonitor, ...]:
    """Enumerate physical Windows display targets without guessing by position."""

    if os.name != "nt":
        raise RuntimeError("--monitor-device is supported only on Windows")
    try:
        import win32api
    except ImportError as exc:  # pragma: no cover - Windows dependency guard
        raise RuntimeError("pywin32 is required for --monitor-device") from exc

    monitors = tuple(
        _monitor_from_win32_info(win32api.GetMonitorInfo(handle))
        for handle, _dc, _rect in win32api.EnumDisplayMonitors()
    )
    if not monitors:
        raise RuntimeError("no Windows display monitors were detected")
    return monitors


def resolve_monitor_target(
    device_name: str,
    sizes: Sequence[tuple[int, int]],
    *,
    monitors: Sequence[DisplayMonitor] | None = None,
) -> MonitorTarget:
    """Resolve one exact, non-primary device and preflight every capture size."""

    requested = str(device_name or "").strip()
    if not requested:
        raise RuntimeError("an exact monitor device name is required")
    available = tuple(monitors) if monitors is not None else enumerate_display_monitors()
    matches = [monitor for monitor in available if monitor.device_name == requested]
    if len(matches) != 1:
        available_names = ", ".join(repr(monitor.device_name) for monitor in available)
        raise RuntimeError(
            "selected monitor device must match exactly one connected display: "
            f"requested={requested!r} available=[{available_names}]"
        )
    monitor = matches[0]
    if monitor.primary:
        raise RuntimeError(
            "selected monitor must be non-primary: "
            f"device={monitor.device_name!r} primary={monitor.primary}"
        )
    target = MonitorTarget(requested_device_name=requested, monitor=monitor)
    for size in sizes:
        requested_rect = target.requested_client_rect(size)
        if not rect_is_contained(requested_rect, monitor.work_rect):
            raise RuntimeError(
                "requested capture geometry is outside the selected monitor work area: "
                f"device={monitor.device_name!r} requested={requested_rect} "
                f"work={monitor.work_rect}"
            )
    return target


def monitor_preflight_manifest(
    target: MonitorTarget,
    sizes: Sequence[tuple[int, int]],
) -> dict[str, Any]:
    placements = []
    for size in sizes:
        requested_rect = target.requested_client_rect(size)
        placements.append(
            {
                "requested_size": [int(size[0]), int(size[1])],
                "tk_geometry": target.tk_geometry(size),
                "requested_client_rect": list(requested_rect),
                "requested_geometry_contained_in_work_area": rect_is_contained(
                    requested_rect,
                    target.monitor.work_rect,
                ),
            }
        )
    checks = {
        "requested_device_name_exact_match": (
            target.requested_device_name == target.monitor.device_name
        ),
        "target_is_non_primary": target.monitor.primary is False,
        "all_requested_geometries_contained_in_work_area": all(
            placement["requested_geometry_contained_in_work_area"]
            for placement in placements
        ),
    }
    return {
        "gate_applicable": True,
        "selection_mode": "explicit_device_name",
        "requested_device_name": target.requested_device_name,
        "resolved_monitor": target.monitor.as_manifest(),
        "placements": placements,
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_monitor_capture_gate(
    target: MonitorTarget,
    size: tuple[int, int],
    *,
    actual_client_rect: Rect,
    actual_monitor: DisplayMonitor,
) -> dict[str, Any]:
    """Build the per-capture proof that the client remained on the target."""

    requested_rect = target.requested_client_rect(size)
    actual_width = actual_client_rect[2] - actual_client_rect[0]
    actual_height = actual_client_rect[3] - actual_client_rect[1]
    checks = {
        "requested_device_name_exact_match": (
            target.requested_device_name == target.monitor.device_name
        ),
        "target_is_non_primary": target.monitor.primary is False,
        "requested_geometry_contained_in_target_work_area": rect_is_contained(
            requested_rect,
            target.monitor.work_rect,
        ),
        "actual_monitor_device_matches_target": (
            actual_monitor.device_name == target.monitor.device_name
        ),
        "actual_monitor_is_non_primary": actual_monitor.primary is False,
        "monitor_work_area_unchanged": (
            actual_monitor.work_rect == target.monitor.work_rect
        ),
        "actual_geometry_contained_in_target_work_area": rect_is_contained(
            actual_client_rect,
            target.monitor.work_rect,
        ),
        "actual_client_size_matches_requested": (
            actual_width,
            actual_height,
        )
        == (int(size[0]), int(size[1])),
    }
    return {
        "gate_applicable": True,
        "requested_device_name": target.requested_device_name,
        "target_monitor": target.monitor.as_manifest(),
        "actual_monitor": actual_monitor.as_manifest(),
        "requested_tk_geometry": target.tk_geometry(size),
        "requested_client_rect": list(requested_rect),
        "actual_client_rect": list(actual_client_rect),
        "checks": checks,
        "passed": all(checks.values()),
    }


def collect_monitor_capture_gate(
    root: Any,
    target: MonitorTarget,
    size: tuple[int, int],
) -> dict[str, Any]:
    """Read the live client rectangle and its owning Win32 monitor."""

    import win32api
    import win32con

    left = int(root.winfo_rootx())
    top = int(root.winfo_rooty())
    width = max(1, int(root.winfo_width()))
    height = max(1, int(root.winfo_height()))
    actual_rect = (left, top, left + width, top + height)
    handle = win32api.MonitorFromRect(
        actual_rect,
        win32con.MONITOR_DEFAULTTONEAREST,
    )
    actual_monitor = _monitor_from_win32_info(win32api.GetMonitorInfo(handle))
    return build_monitor_capture_gate(
        target,
        size,
        actual_client_rect=actual_rect,
        actual_monitor=actual_monitor,
    )


def _root_hwnd_with_user32(user32: Any, hwnd: int) -> int:
    return int(user32.GetAncestor(int(hwnd), GA_ROOT) or int(hwnd))


def _root_hwnd(hwnd: int) -> int:
    if os.name != "nt":
        return int(hwnd)
    return _root_hwnd_with_user32(ctypes.windll.user32, hwnd)


def _window_thread_pid_with_user32(user32: Any, hwnd: int) -> tuple[int, int]:
    if not hwnd:
        return 0, 0
    pid = ctypes.c_ulong(0)
    thread_id = user32.GetWindowThreadProcessId(int(hwnd), ctypes.byref(pid))
    return int(thread_id or 0), int(pid.value)


def _window_pid(hwnd: int) -> int:
    if os.name != "nt" or not hwnd:
        return os.getpid() if hwnd else 0
    _thread_id, pid = _window_thread_pid_with_user32(
        ctypes.windll.user32,
        hwnd,
    )
    return pid


def _foreground_observation(
    user32: Any,
    *,
    target_hwnd: int,
    target_pid: int,
) -> dict[str, Any]:
    foreground_hwnd = int(user32.GetForegroundWindow() or 0)
    foreground_root_hwnd = (
        _root_hwnd_with_user32(user32, foreground_hwnd)
        if foreground_hwnd
        else 0
    )
    _thread_id, foreground_pid = _window_thread_pid_with_user32(
        user32,
        foreground_root_hwnd,
    )
    return {
        "foreground_hwnd": foreground_hwnd,
        "foreground_root_hwnd": foreground_root_hwnd,
        "foreground_pid": foreground_pid,
        "hwnd_matches": foreground_root_hwnd == int(target_hwnd),
        "pid_matches": foreground_pid == int(target_pid),
    }


def _attempt_foreground_acquisition(
    user32: Any,
    *,
    target_hwnd: int,
    target_pid: int,
    phase: str,
    ordinal: int,
) -> dict[str, Any]:
    api_results: dict[str, Any] = {}
    api_errors: dict[str, str] = {}
    show_window = {
        "command": "SW_RESTORE",
        "call_completed": False,
        "previously_visible": None,
        "error": "",
    }
    try:
        # ShowWindow reports the window's *previous* visibility, not success.
        show_window["previously_visible"] = bool(
            user32.ShowWindow(int(target_hwnd), SW_RESTORE)
        )
        show_window["call_completed"] = True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        show_window["error"] = error
        api_errors["ShowWindow"] = error
    for name, args in (
        ("BringWindowToTop", (int(target_hwnd),)),
        ("SetForegroundWindow", (int(target_hwnd),)),
    ):
        try:
            api_results[name] = bool(getattr(user32, name)(*args))
        except Exception as exc:
            api_results[name] = False
            api_errors[name] = f"{type(exc).__name__}: {exc}"
    observation = _foreground_observation(
        user32,
        target_hwnd=target_hwnd,
        target_pid=target_pid,
    )
    return {
        "ordinal": int(ordinal),
        "phase": str(phase),
        "api_results": api_results,
        "api_errors": api_errors,
        "show_window": show_window,
        **observation,
        "passed": bool(
            observation["hwnd_matches"] and observation["pid_matches"]
        ),
    }


def acquire_win32_foreground(
    target_hwnd: int,
    target_pid: int,
    *,
    user32: Any | None = None,
) -> dict[str, Any]:
    """Try direct foreground acquisition once and fail closed if it is denied."""

    if user32 is None:
        if os.name != "nt":
            return {
                "gate_applicable": False,
                "target_hwnd": int(target_hwnd),
                "target_pid": int(target_pid),
                "strategy": "direct_only_fail_closed",
                "attempt_count": 0,
                "attempts": [],
                "thread_input": {
                    "policy": "disabled_fail_closed",
                    "attach_attempted": False,
                    "attach_succeeded": False,
                    "detach_attempted": False,
                    "detach_succeeded": False,
                },
                "ownership_acquired": True,
                "thread_input_cleanup_passed": True,
                "failure_reason": "",
                "passed": True,
            }
        user32 = ctypes.windll.user32

    started = time.perf_counter()
    thread_input: dict[str, Any] = {
        "policy": "disabled_fail_closed",
        "attach_attempted": False,
        "attach_succeeded": False,
        "detach_attempted": False,
        "detach_succeeded": False,
    }
    attempts = [
        _attempt_foreground_acquisition(
            user32,
            target_hwnd=target_hwnd,
            target_pid=target_pid,
            phase="direct",
            ordinal=1,
        )
    ]
    ownership_acquired = bool(attempts and attempts[-1]["passed"] is True)
    thread_input_cleanup_passed = True
    passed = ownership_acquired
    duration_ms = int(round((time.perf_counter() - started) * 1000))
    failure_reason = ""
    if not ownership_acquired:
        latest = attempts[-1] if attempts else {}
        failure_reason = (
            "foreground ownership not acquired: "
            f"observed_hwnd={latest.get('foreground_root_hwnd', 0)} "
            f"observed_pid={latest.get('foreground_pid', 0)}"
        )
    return {
        "gate_applicable": True,
        "target_hwnd": int(target_hwnd),
        "target_pid": int(target_pid),
        "strategy": "direct_only_fail_closed",
        "attempt_limit": 1,
        "attempt_count": len(attempts),
        "duration_ms": duration_ms,
        "attempts": attempts,
        "thread_input": thread_input,
        "ownership_acquired": ownership_acquired,
        "thread_input_cleanup_passed": thread_input_cleanup_passed,
        "failure_reason": failure_reason,
        "passed": passed,
    }


def state_requires_scan_lock(state_id: str) -> bool:
    spec = M7_SCENE_CONTRACT.get(str(state_id))
    if spec is not None:
        return str(spec.get("input_state") or "") == "disabled"
    # Compatibility for older manifest evaluators; these IDs are no longer
    # part of the capture matrix.
    return str(state_id) in {"duplicate", "operator_review"}


def build_capture_focus_gate(
    *,
    state_id: str,
    process_pid: int,
    root_hwnd: int,
    root_hwnd_pid: int,
    foreground_root_hwnd: int,
    foreground_pid: int,
    tk_focus_path: str,
    scan_entry_path: str,
    tk_focus_owned_by_root: bool,
    scan_entry_enabled: bool,
    acquisition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blocking = state_requires_scan_lock(state_id)
    checks = {
        "root_hwnd_present": int(root_hwnd) > 0,
        "root_hwnd_pid_matches_process": int(root_hwnd_pid) == int(process_pid),
        "foreground_root_hwnd_matches_capture_root": (
            int(foreground_root_hwnd) == int(root_hwnd)
        ),
        "foreground_pid_matches_process": int(foreground_pid) == int(process_pid),
        "tk_focus_owned_by_capture_root": bool(tk_focus_owned_by_root),
        "state_focus_contract": (
            bool(tk_focus_owned_by_root)
            if blocking
            else (
                scan_entry_enabled
                and bool(tk_focus_owned_by_root)
                and str(tk_focus_path) == str(scan_entry_path)
            )
        ),
    }
    if acquisition is not None:
        checks["foreground_acquisition_passed"] = (
            acquisition.get("passed") is True
        )
    gate = {
        "gate_applicable": True,
        "state": state_id,
        "blocking_state": blocking,
        "process_pid": int(process_pid),
        "root_hwnd": int(root_hwnd),
        "root_hwnd_pid": int(root_hwnd_pid),
        "foreground_root_hwnd": int(foreground_root_hwnd),
        "foreground_pid": int(foreground_pid),
        "tk_focus_path": str(tk_focus_path),
        "scan_entry_path": str(scan_entry_path),
        "scan_entry_enabled": bool(scan_entry_enabled),
        "checks": checks,
        "passed": all(checks.values()),
    }
    if acquisition is not None:
        gate["acquisition"] = acquisition
    return gate


def _widget_is_owned_by_root(widget: Any, root: Any) -> bool:
    current = widget
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if current is root:
            return True
        seen.add(id(current))
        current = getattr(current, "master", None)
    return False


def settle_capture_focus(app: Any, state_id: str) -> dict[str, Any]:
    """Put keyboard focus in the state-authoritative widget before evidence."""

    blocking = state_requires_scan_lock(state_id)
    target = app.root if blocking else app.scan_entry
    app.root.deiconify()
    app.root.lift()
    try:
        target.focus_force()
    except Exception as exc:
        raise RuntimeError(f"capture focus setup failed for {state_id}: {exc}") from exc
    pump_tk(app.root, 120)
    hwnd = _root_hwnd(int(app.root.winfo_id()))
    acquisition = acquire_win32_foreground(
        hwnd,
        os.getpid(),
    )
    pump_tk(app.root, 120)
    return acquisition


def collect_capture_focus_gate(
    app: Any,
    state_id: str,
    *,
    acquisition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = app.root
    root_hwnd = _root_hwnd(int(root.winfo_id()))
    foreground_hwnd = (
        _root_hwnd(int(ctypes.windll.user32.GetForegroundWindow()))
        if os.name == "nt"
        else root_hwnd
    )
    focus_widget = root.focus_get()
    try:
        scan_entry_enabled = str(app.scan_entry.cget("state")) != "disabled"
    except Exception:
        scan_entry_enabled = False
    return build_capture_focus_gate(
        state_id=state_id,
        process_pid=os.getpid(),
        root_hwnd=root_hwnd,
        root_hwnd_pid=_window_pid(root_hwnd),
        foreground_root_hwnd=foreground_hwnd,
        foreground_pid=_window_pid(foreground_hwnd),
        tk_focus_path=str(focus_widget or ""),
        scan_entry_path=str(app.scan_entry),
        tk_focus_owned_by_root=_widget_is_owned_by_root(focus_widget, root),
        scan_entry_enabled=scan_entry_enabled,
        acquisition=acquisition,
    )


def require_capture_focus_gate(
    focus_gate: dict[str, Any],
    *,
    phase: str = "capture",
) -> None:
    """Abort before image evidence when foreground/focus ownership is invalid."""

    if focus_gate.get("passed") is True:
        return
    checks = focus_gate.get("checks") or {}
    failed_checks = sorted(
        str(name) for name, passed in checks.items() if passed is not True
    )
    acquisition = focus_gate.get("acquisition") or {}
    failure_reason = str(acquisition.get("failure_reason") or "")
    attempts = acquisition.get("attempts") or []
    acquisition_summary = {
        "attempt_count": acquisition.get("attempt_count", 0),
        "last_attempt": attempts[-1] if attempts else None,
        "thread_input": acquisition.get("thread_input") or {},
    }
    raise RuntimeError(
        "capture focus gate failed before evidence: "
        f"phase={phase!r} "
        f"state={focus_gate.get('state')!r} "
        f"failed_checks={failed_checks!r} "
        f"acquisition_failure={failure_reason!r} "
        "acquisition_telemetry="
        + json.dumps(
            acquisition_summary,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def combine_capture_focus_gates(
    pre_capture_gate: dict[str, Any],
    post_capture_gate: dict[str, Any],
) -> dict[str, Any]:
    """Keep phase-specific observations while exposing one strict record gate."""

    checks = {
        **{
            f"pre_capture_{name}": passed
            for name, passed in (pre_capture_gate.get("checks") or {}).items()
        },
        **{
            f"post_capture_{name}": passed
            for name, passed in (post_capture_gate.get("checks") or {}).items()
        },
    }
    checks["pre_capture_gate_passed"] = pre_capture_gate.get("passed") is True
    checks["post_capture_gate_passed"] = post_capture_gate.get("passed") is True
    gate = {
        "gate_applicable": bool(
            pre_capture_gate.get("gate_applicable") is True
            and post_capture_gate.get("gate_applicable") is True
        ),
        "state": pre_capture_gate.get("state"),
        "blocking_state": bool(pre_capture_gate.get("blocking_state")),
        "checks": checks,
        "pre_capture": pre_capture_gate,
        "post_capture": post_capture_gate,
        "passed": False,
    }
    gate["passed"] = bool(gate["gate_applicable"] and all(checks.values()))
    return gate


def assert_descendant(path: Path, parent: Path, *, label: str) -> Path:
    resolved = path.resolve()
    resolved_parent = parent.resolve()
    if resolved == resolved_parent or not resolved.is_relative_to(resolved_parent):
        raise RuntimeError(f"{label} must stay below {resolved_parent}: {resolved}")
    return resolved


def create_new_capture_output_root(output_root: Path) -> Path:
    """Create a new evidence root and refuse to mix with any prior run."""

    resolved_output = assert_descendant(
        output_root,
        REPO_TMP_ROOT,
        label="capture output root",
    )
    try:
        resolved_output.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise RuntimeError(
            f"capture output root already exists; use a new path: {resolved_output}"
        ) from exc
    return resolved_output


def prepare_isolated_environment(data_root: Path, geometry: str) -> dict[str, str]:
    """Force every mutable runtime path and integration into repository tmp."""

    resolved_data_root = assert_descendant(
        data_root,
        REPO_TMP_ROOT,
        label="capture data root",
    )
    resolved_data_root.mkdir(parents=True, exist_ok=True)
    temp_root = resolved_data_root / "temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    guards = {
        "CONTAINER_AUDIT_DATA_ROOT": str(resolved_data_root),
        "CONTAINER_AUDIT_DIRECT_SYNC_BOOTSTRAP": "off",
        "CONTAINER_AUDIT_SESSION_SYNC_TRIGGER": "off",
        "CONTAINER_AUDIT_UPDATE_PROVIDER": "off",
        "CONTAINER_AUDIT_AUDIO_ENABLED": "off",
        "CONTAINER_AUDIT_STARTUP_GEOMETRY": geometry,
        "KMTECH_TEST_SILENT_AUDIO": "1",
        "SDL_AUDIODRIVER": "dummy",
        "PYGAME_HIDE_SUPPORT_PROMPT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_CURRENT_TEST": "container_operator_ui_capture_isolated",
        "TEMP": str(temp_root),
        "TMP": str(temp_root),
    }
    os.environ.update(guards)
    for key in list(os.environ):
        if key.startswith("WORKER_ANALYSIS_LOGISTICS_") or key == "WORKER_ANALYSIS_SERVER_URL":
            os.environ.pop(key, None)
    return guards


def enable_per_monitor_dpi_awareness() -> str:
    if os.name != "nt":
        return "not-windows"
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return "per-monitor-aware"
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
            return "system-aware"
        except Exception:
            return "unchanged"


def measure_tk_dpi(root: Any) -> int:
    """Read the live Tk screen DPI used by the already-open capture window."""

    measured = float(root.winfo_fpixels("1i"))
    dpi = int(round(measured))
    if not math.isfinite(measured) or dpi < 1:
        raise RuntimeError("Tk returned an invalid capture-host DPI")
    return dpi


def pump_tk(root: Any, milliseconds: int = 220) -> None:
    deadline = time.monotonic() + max(0, milliseconds) / 1000.0
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.015)
    root.update_idletasks()
    root.update()


def _capture_client_with_print_window(root: Any) -> tuple[Image.Image, str]:
    import win32con
    import win32gui
    import win32ui

    hwnd = int(root.winfo_id())
    try:
        hwnd = int(win32gui.GetAncestor(hwnd, win32con.GA_ROOT))
    except Exception:
        while win32gui.GetParent(hwnd):
            hwnd = int(win32gui.GetParent(hwnd))

    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    window_width = max(1, right - left)
    window_height = max(1, bottom - top)
    client_left, client_top = win32gui.ClientToScreen(hwnd, (0, 0))
    client_rect = win32gui.GetClientRect(hwnd)
    client_width = max(1, int(client_rect[2] - client_rect[0]))
    client_height = max(1, int(client_rect[3] - client_rect[1]))

    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(mfc_dc, window_width, window_height)
    save_dc.SelectObject(bitmap)
    try:
        rendered = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
        if not rendered:
            save_dc.BitBlt(
                (0, 0),
                (window_width, window_height),
                mfc_dc,
                (0, 0),
                win32con.SRCCOPY,
            )
        info = bitmap.GetInfo()
        bits = bitmap.GetBitmapBits(True)
        full_image = Image.frombuffer(
            "RGB",
            (info["bmWidth"], info["bmHeight"]),
            bits,
            "raw",
            "BGRX",
            0,
            1,
        ).copy()
    finally:
        win32gui.DeleteObject(bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)

    crop_left = max(0, int(client_left - left))
    crop_top = max(0, int(client_top - top))
    crop_right = min(full_image.width, crop_left + client_width)
    crop_bottom = min(full_image.height, crop_top + client_height)
    image = full_image.crop((crop_left, crop_top, crop_right, crop_bottom))
    return image, "PrintWindow(PW_RENDERFULLCONTENT)+client-crop"


def capture_tk_client(
    root: Any,
    *,
    pump_events: bool = True,
) -> tuple[Image.Image, str]:
    """Capture the real Tk client area without including OS window chrome."""

    if pump_events:
        root.update_idletasks()
        root.update()
    left = int(root.winfo_rootx())
    top = int(root.winfo_rooty())
    width = max(1, int(root.winfo_width()))
    height = max(1, int(root.winfo_height()))
    try:
        image = ImageGrab.grab(
            bbox=(left, top, left + width, top + height),
            all_screens=True,
        )
        return image, "ImageGrab(visible-client-bbox)"
    except Exception as exc:
        visible_capture_failure = (
            f"ImageGrab failed: {type(exc).__name__}: {exc}"
        )
    if os.name == "nt":
        image, print_window_source = _capture_client_with_print_window(root)
        return image, f"{print_window_source}; {visible_capture_failure}"
    raise RuntimeError(visible_capture_failure)


def _client_geometry_snapshot(root: Any) -> dict[str, Any]:
    left = int(root.winfo_rootx())
    top = int(root.winfo_rooty())
    width = max(1, int(root.winfo_width()))
    height = max(1, int(root.winfo_height()))
    return {
        "client_rect": [left, top, left + width, top + height],
        "client_size": [width, height],
    }


def capture_and_save_focus_verified_tk_client(
    app: Any,
    state_id: str,
    path: Path,
    *,
    expected_row_count: int,
    monitor_target: MonitorTarget | None,
    requested_size: tuple[int, int],
) -> dict[str, Any]:
    """Settle, snapshot metadata, and save one focus-verified frame."""

    if path.exists():
        raise RuntimeError(f"capture target already exists; refusing overwrite: {path}")

    acquisition = settle_capture_focus(app, state_id)
    viewport_gate = collect_scan_list_viewport_gate(
        app,
        expected_row_count=expected_row_count,
    )
    monitor_gate = (
        collect_monitor_capture_gate(app.root, monitor_target, requested_size)
        if monitor_target is not None
        else None
    )
    geometry_record = collect_ui_geometry(app)
    rendered_state = collect_rendered_state(app)
    tree_heading_fit_gate = build_tree_heading_fit_gate(app)

    # All metadata above is collected after the final Tk pump and without
    # dispatching another event. This fresh observation is the last operation
    # before the frame capture itself.
    pre_capture_gate = collect_capture_focus_gate(
        app,
        state_id,
        acquisition=acquisition,
    )
    require_capture_focus_gate(pre_capture_gate, phase="pre_capture")
    pre_capture_geometry = _client_geometry_snapshot(app.root)

    # Metadata collection above performed any final Tk pump needed for the
    # viewport. Do not dispatch more Tk events between this observation and
    # the actual capture.
    image, source = capture_tk_client(app.root, pump_events=False)
    post_capture_geometry = _client_geometry_snapshot(app.root)
    capture_geometry_checks = {
        "client_geometry_stable_during_capture": (
            pre_capture_geometry == post_capture_geometry
        ),
        "captured_pixels_match_client_size": (
            list(image.size) == pre_capture_geometry["client_size"]
        ),
        "visible_screen_capture_used": source == "ImageGrab(visible-client-bbox)",
    }
    capture_geometry_gate = {
        "gate_applicable": True,
        "pre_capture": pre_capture_geometry,
        "post_capture": post_capture_geometry,
        "capture_source": source,
        "captured_pixel_size": list(image.size),
        "checks": capture_geometry_checks,
        "passed": all(capture_geometry_checks.values()),
    }

    post_capture_gate = collect_capture_focus_gate(app, state_id)
    require_capture_focus_gate(post_capture_gate, phase="post_capture")
    focus_gate = combine_capture_focus_gates(
        pre_capture_gate,
        post_capture_gate,
    )
    image.save(path, format="PNG", optimize=True)
    return {
        "image": image,
        "source": source,
        "focus_gate": focus_gate,
        "scan_list_viewport_gate": viewport_gate,
        "monitor_gate": monitor_gate,
        "ui_geometry": geometry_record,
        "rendered_state": rendered_state,
        "tree_heading_fit_gate": tree_heading_fit_gate,
        "capture_geometry_gate": capture_geometry_gate,
    }


def analyze_image(image: Image.Image, expected_size: tuple[int, int]) -> dict[str, Any]:
    rgb = image.convert("RGB")
    quality = analyze_capture_quality(rgb)
    # Preserve the original fixed-capture blank proxy while adding the shared,
    # stricter stripe and low-variance evidence used by manual captures.
    quality["blank_suspected"] = bool(
        quality["blank_suspected"]
        or quality["luma_extrema"][1] - quality["luma_extrema"][0] <= 2
        or quality["luma_stddev"] < 0.75
        or quality["dominant_color_ratio_sampled"] >= 0.997
    )
    quality.update({
        "expected_pixel_size": [int(expected_size[0]), int(expected_size[1])],
        "pixel_size": [rgb.width, rgb.height],
        "pixel_size_matches": (rgb.width, rgb.height) == expected_size,
    })
    return quality


def _descendants(widget: Any) -> Iterable[Any]:
    for child in widget.winfo_children():
        yield child
        yield from _descendants(child)


def _is_mapped(widget: Any) -> bool:
    try:
        return bool(widget.winfo_ismapped())
    except Exception:
        return False


def _widget_record(
    root: Any,
    widget: Any,
    name: str,
    *,
    check_requested_width: bool = False,
    check_requested_height: bool = False,
) -> dict[str, Any]:
    root_x = int(root.winfo_rootx())
    root_y = int(root.winfo_rooty())
    x = int(widget.winfo_rootx()) - root_x
    y = int(widget.winfo_rooty()) - root_y
    width = int(widget.winfo_width())
    height = int(widget.winfo_height())
    try:
        requested_size = [int(widget.winfo_reqwidth()), int(widget.winfo_reqheight())]
    except Exception:
        requested_size = [width, height]
    try:
        widget_class = str(widget.winfo_class())
    except Exception:
        widget_class = type(widget).__name__
    return {
        "name": name,
        "widget_path": str(widget),
        "widget_class": widget_class,
        "master_path": str(getattr(widget, "master", "")),
        "mapped": _is_mapped(widget),
        "bbox": [x, y, x + width, y + height],
        "size": [width, height],
        "requested_size": requested_size,
        "check_requested_width": check_requested_width,
        "check_requested_height": check_requested_height,
    }


def _normalized_grid_info(widget: Any) -> dict[str, Any]:
    try:
        info = dict(widget.grid_info())
    except Exception:
        return {}
    normalized: dict[str, Any] = {}
    for key in ("row", "column", "rowspan", "columnspan"):
        if key in info:
            try:
                normalized[key] = int(info[key])
            except (TypeError, ValueError):
                normalized[key] = str(info[key])
    if "sticky" in info:
        normalized["sticky"] = str(info["sticky"])
    return normalized


def _normalized_grid_row(widget: Any, row: int) -> dict[str, int]:
    try:
        info = dict(widget.grid_rowconfigure(row))
    except Exception:
        return {}
    normalized: dict[str, int] = {}
    for key in ("weight", "minsize", "pad"):
        try:
            normalized[key] = int(info.get(key, 0) or 0)
        except (TypeError, ValueError):
            normalized[key] = 0
    return normalized


def cluster_button_rows(
    records: Sequence[dict[str, Any]],
    *,
    tolerance: int = 10,
) -> list[list[str]]:
    """Return visual button order clustered into top-to-bottom rows."""

    positioned: list[tuple[float, float, str]] = []
    for record in records:
        if not record.get("mapped", False):
            continue
        left, top, right, bottom = (int(value) for value in record["bbox"])
        positioned.append(((top + bottom) / 2.0, (left + right) / 2.0, str(record["name"])))
    positioned.sort()
    rows: list[list[tuple[float, float, str]]] = []
    for item in positioned:
        if not rows:
            rows.append([item])
            continue
        row_center = sum(entry[0] for entry in rows[-1]) / len(rows[-1])
        if abs(item[0] - row_center) <= max(0, int(tolerance)):
            rows[-1].append(item)
        else:
            rows.append([item])
    return [
        [name for _center_y, _center_x, name in sorted(row, key=lambda item: item[1])]
        for row in rows
    ]


def evaluate_clipping_proxy(
    widget_records: Sequence[dict[str, Any]],
    root_size: tuple[int, int],
    *,
    overlap_pairs: Sequence[tuple[str, str]] = (),
    containment_pairs: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    """Evaluate conservative geometry proxies; no OCR assumption is made."""

    root_width, root_height = root_size
    by_name = {str(record["name"]): record for record in widget_records}
    clipped: list[str] = []
    unmapped: list[str] = []
    width_compressed: list[str] = []
    height_compressed: list[str] = []
    for record in widget_records:
        name = str(record["name"])
        if not record.get("mapped", False):
            unmapped.append(name)
            continue
        left, top, right, bottom = (int(value) for value in record["bbox"])
        if (
            right - left <= 1
            or bottom - top <= 1
            or left < -1
            or top < -1
            or right > root_width + 1
            or bottom > root_height + 1
        ):
            clipped.append(name)
        requested = record.get("requested_size") or record.get("size") or [0, 0]
        actual = record.get("size") or [0, 0]
        if record.get("check_requested_width", False) and int(requested[0]) > int(actual[0]) + 2:
            width_compressed.append(name)
        if record.get("check_requested_height", False) and int(requested[1]) > int(actual[1]) + 2:
            height_compressed.append(name)

    overlaps: list[dict[str, Any]] = []
    for first_name, second_name in overlap_pairs:
        first = by_name.get(first_name)
        second = by_name.get(second_name)
        if not first or not second or not first.get("mapped") or not second.get("mapped"):
            continue
        a_left, a_top, a_right, a_bottom = first["bbox"]
        b_left, b_top, b_right, b_bottom = second["bbox"]
        overlap_width = min(a_right, b_right) - max(a_left, b_left)
        overlap_height = min(a_bottom, b_bottom) - max(a_top, b_top)
        if overlap_width > 1 and overlap_height > 1:
            overlaps.append(
                {
                    "widgets": [first_name, second_name],
                    "overlap_size": [int(overlap_width), int(overlap_height)],
                }
            )
    outside_containers: list[dict[str, str]] = []
    for child_name, container_name in containment_pairs:
        child = by_name.get(child_name)
        container = by_name.get(container_name)
        if not child or not container or not child.get("mapped") or not container.get("mapped"):
            continue
        child_left, child_top, child_right, child_bottom = child["bbox"]
        parent_left, parent_top, parent_right, parent_bottom = container["bbox"]
        if (
            child_left < parent_left - 1
            or child_top < parent_top - 1
            or child_right > parent_right + 1
            or child_bottom > parent_bottom + 1
        ):
            outside_containers.append(
                {"widget": child_name, "container": container_name}
            )
    issue_count = (
        len(set(clipped))
        + len(set(unmapped))
        + len(set(width_compressed))
        + len(set(height_compressed))
        + len(overlaps)
        + len(outside_containers)
    )
    return {
        "method": (
            "Tk mapped widget bounds + requested-height + critical-pair overlap + "
            "requested-width + pane/card containment"
        ),
        "root_size": [root_width, root_height],
        "clipped_or_zero_sized_widgets": sorted(set(clipped)),
        "unmapped_critical_widgets": sorted(set(unmapped)),
        "width_compressed_widgets": sorted(set(width_compressed)),
        "height_compressed_widgets": sorted(set(height_compressed)),
        "overlaps": overlaps,
        "outside_containers": outside_containers,
        "issue_count": issue_count,
        "suspected": issue_count > 0,
    }


def _widget_tcl_list(widget: Any, value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, (tuple, list)):
        return list(value)
    try:
        return list(widget.tk.splitlist(value))
    except Exception:
        return [value]


def _widget_pixel_value(widget: Any, value: Any) -> int:
    try:
        return int(round(float(widget.winfo_pixels(value))))
    except Exception:
        return int(round(float(value)))


def _horizontal_style_padding(widget: Any, value: Any) -> tuple[int, int]:
    parts = _widget_tcl_list(widget, value)
    if not parts:
        return 0, 0
    pixels = [_widget_pixel_value(widget, part) for part in parts]
    if len(pixels) == 1:
        return pixels[0], pixels[0]
    if len(pixels) == 2:
        return pixels[0], pixels[0]
    return pixels[0], pixels[2]


def _displayed_tree_columns(tree: Any) -> list[str]:
    columns = [str(value) for value in _widget_tcl_list(tree, tree.cget("columns"))]
    display_columns = [
        str(value) for value in _widget_tcl_list(tree, tree.cget("displaycolumns"))
    ]
    if not display_columns or display_columns == ["#all"]:
        return columns
    return display_columns


def _heading_image_width(tree: Any, image_value: Any) -> int:
    image_names = _widget_tcl_list(tree, image_value)
    if not image_names:
        return 0
    image_name = str(image_names[0]).strip()
    if not image_name:
        return 0
    return max(0, int(tree.tk.call("image", "width", image_name)))


def _tree_heading_pixels(tree: Any) -> dict[str, Any]:
    width = max(0, int(tree.winfo_width()))
    height = max(0, int(tree.winfo_height()))
    if width <= 1 or height <= 1:
        raise RuntimeError("tree has no measurable viewport")

    probe_xs = sorted(
        {
            value
            for value in (
                0,
                1,
                2,
                3,
                width // 4,
                width // 2,
                (width * 3) // 4,
                width - 2,
            )
            if 0 <= value < width
        }
    )
    header_y: int | None = None
    for y in range(min(height, TREE_HEADING_SCAN_HEIGHT)):
        if any(str(tree.identify_region(x, y)) == "heading" for x in probe_xs):
            header_y = y
            break
    if header_y is None:
        raise RuntimeError("tree heading row is not visible")

    visible_heading_widths: dict[str, int] = {}
    first_heading_or_separator_x: int | None = None
    for x in range(width):
        region = str(tree.identify_region(x, header_y))
        if region in {"heading", "separator"} and first_heading_or_separator_x is None:
            first_heading_or_separator_x = x
        if region != "heading":
            continue
        display_position = str(tree.identify_column(x))
        visible_heading_widths[display_position] = (
            visible_heading_widths.get(display_position, 0) + 1
        )
    if first_heading_or_separator_x is None:
        raise RuntimeError("tree heading viewport is not measurable")

    # Clam uses symmetric outer tree borders. Mirroring the observed left inset
    # avoids trusting the configured column widths when the last column extends
    # beneath the border or a sibling scrollbar.
    outer_inset = max(0, int(first_heading_or_separator_x))
    viewport_width = max(0, width - (outer_inset * 2))
    return {
        "header_y": header_y,
        "tree_widget_width_px": width,
        "outer_inset_px": outer_inset,
        "viewport_width_px": viewport_width,
        "visible_heading_widths_px": visible_heading_widths,
    }


def _tree_scrollbar_layout(tree: Any) -> dict[str, Any]:
    parent = tree.master
    parent_width = max(0, int(parent.winfo_width()))
    tree_left = int(tree.winfo_x())
    tree_width = max(0, int(tree.winfo_width()))
    tree_right = tree_left + tree_width
    scrollbars: list[dict[str, Any]] = []
    for child in parent.winfo_children():
        if child is tree:
            continue
        try:
            widget_class = str(child.winfo_class())
            mapped = bool(child.winfo_ismapped())
            orientation = str(child.cget("orient"))
        except Exception:
            continue
        if "Scrollbar" not in widget_class or orientation != "vertical" or not mapped:
            continue
        left = int(child.winfo_x())
        width = max(0, int(child.winfo_width()))
        scrollbars.append(
            {
                "widget_path": str(child),
                "left_px": left,
                "right_px": left + width,
                "width_px": width,
            }
        )

    scrollbar_width = sum(item["width_px"] for item in scrollbars)
    nonoverlapping = all(
        tree_right <= item["left_px"] or item["right_px"] <= tree_left
        for item in scrollbars
    )
    return {
        "parent_width_px": parent_width,
        "tree_left_px": tree_left,
        "tree_right_px": tree_right,
        "mapped_vertical_scrollbars": scrollbars,
        "scrollbar_allowance_px": scrollbar_width,
        "tree_width_within_parent_after_scrollbar": (
            tree_width <= max(0, parent_width - scrollbar_width) + 1
        ),
        "scrollbars_nonoverlapping": nonoverlapping,
    }


def _tree_heading_fit_record(
    app: Any,
    name: str,
    tree: Any,
    *,
    font_factory: Any,
    visibility_required: bool,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": name,
        "widget_path": str(tree),
        "present": True,
        "mapped": False,
        "visibility_required": visibility_required,
        "measurement_applicable": True,
        "columns": [],
        "checks": {},
        "passed": False,
        "error": "",
    }
    try:
        record["mapped"] = bool(tree.winfo_ismapped())
        displayed_columns = _displayed_tree_columns(tree)
        heading_pixels = _tree_heading_pixels(tree)
        scrollbar_layout = _tree_scrollbar_layout(tree)
        tree_style = str(tree.cget("style") or "Treeview")
        heading_style = f"{tree_style}.Heading"
        font_spec = app.style.lookup(heading_style, "font") or "TkHeadingFont"
        padding_value = app.style.lookup(heading_style, "padding")
        padding_left, padding_right = _horizontal_style_padding(tree, padding_value)
        heading_font = font_factory(root=app.root, font=font_spec)
        body_font_spec = app.style.lookup(tree_style, "font") or "TkDefaultFont"
        body_padding_value = app.style.lookup(tree_style, "padding")
        body_padding_left, body_padding_right = _horizontal_style_padding(
            tree, body_padding_value
        )
        body_font = font_factory(root=app.root, font=body_font_spec)
        try:
            font_actual = dict(heading_font.actual())
        except Exception:
            font_actual = {"description": str(font_spec)}
        try:
            font_metrics = dict(heading_font.metrics())
        except Exception:
            font_metrics = {}
        try:
            body_font_actual = dict(body_font.actual())
        except Exception:
            body_font_actual = {"description": str(body_font_spec)}
        try:
            body_font_metrics = dict(body_font.metrics())
        except Exception:
            body_font_metrics = {}
        try:
            configured_row_height = max(
                1,
                int(float(app.style.lookup(tree_style, "rowheight") or 0)),
            )
        except Exception:
            configured_row_height = 1
        tree_widget_height = max(0, int(tree.winfo_height()))
        heading_line_height = max(1, int(font_metrics.get("linespace") or 0))
        body_line_height = max(1, int(body_font_metrics.get("linespace") or 0))
        minimum_data_row_height = body_line_height + TREE_DATA_VERTICAL_PADDING_PX
        minimum_one_row_height = heading_line_height + configured_row_height + 4
        try:
            tree_children = tuple(tree.get_children())
        except Exception:
            tree_children = ()
        first_row_bbox: list[int] | None = None
        first_row_height = 0
        first_existing_row_fully_visible = False
        if tree_children:
            try:
                bbox = tuple(int(value) for value in tree.bbox(tree_children[0]))
            except Exception:
                bbox = ()
            if len(bbox) == 4:
                first_row_bbox = list(bbox)
                row_x, row_y, row_width, row_height = bbox
                first_row_height = max(0, row_height)
                first_existing_row_fully_visible = (
                    row_width > 0
                    and row_height > 0
                    and row_x >= 0
                    and row_y >= 0
                    and row_x + row_width <= int(tree.winfo_width())
                    and row_y + row_height <= tree_widget_height
                )
            else:
                first_existing_row_fully_visible = False

        configured_extent = 0
        all_headings_measured = bool(displayed_columns)
        all_heading_text_fits = bool(displayed_columns)
        all_data_cells_measured = bool(displayed_columns) and bool(tree_children)
        all_data_text_fits = bool(displayed_columns) and bool(tree_children)
        raw_columns = [
            str(value) for value in _widget_tcl_list(tree, tree.cget("columns"))
        ]
        for position, column_id in enumerate(displayed_columns, start=1):
            heading_info = dict(tree.heading(column_id))
            heading_text = str(heading_info.get("text") or "")
            configured_width = max(0, int(tree.column(column_id, "width")))
            configured_extent += configured_width
            text_width = max(0, int(heading_font.measure(heading_text)))
            image_width = _heading_image_width(tree, heading_info.get("image"))
            image_gap = TREE_HEADING_IMAGE_GAP_PX if image_width else 0
            visible_width = int(
                heading_pixels["visible_heading_widths_px"].get(f"#{position}", 0)
            )
            non_text_allowance = (
                padding_left + padding_right + image_width + image_gap
            )
            available_text_width = max(0, visible_width - non_text_allowance)
            fits = visible_width > 0 and text_width <= available_text_width
            all_headings_measured = all_headings_measured and visible_width > 0
            all_heading_text_fits = all_heading_text_fits and fits
            data_cells: list[dict[str, Any]] = []
            try:
                value_index = raw_columns.index(column_id)
            except ValueError:
                value_index = -1
            for item_id in tree_children:
                try:
                    values = _widget_tcl_list(tree, tree.item(item_id, "values"))
                    value = str(values[value_index]) if 0 <= value_index < len(values) else ""
                    cell_bbox = tuple(
                        int(value)
                        for value in tree.bbox(item_id, column_id)
                    )
                    if len(cell_bbox) != 4:
                        raise RuntimeError("data cell bbox is unavailable")
                    cell_x, cell_y, cell_width, cell_height = cell_bbox
                    visible_cell_width = max(
                        0,
                        min(cell_x + cell_width, int(tree.winfo_width()))
                        - max(cell_x, 0),
                    )
                    available_data_width = max(
                        0, visible_cell_width - TREE_DATA_CELL_GUTTER_PX
                    )
                    data_text_width = max(0, int(body_font.measure(value)))
                    data_fits = (
                        visible_cell_width > 0
                        and value_index >= 0
                        and data_text_width <= available_data_width
                    )
                except Exception:
                    value = ""
                    cell_bbox = ()
                    visible_cell_width = 0
                    available_data_width = 0
                    data_text_width = 0
                    data_fits = False
                all_data_cells_measured = all_data_cells_measured and value_index >= 0
                all_data_text_fits = all_data_text_fits and data_fits
                data_cells.append(
                    {
                        "item_id": str(item_id),
                        "text": value,
                        "cell_bbox": list(cell_bbox),
                        "visible_cell_width_px": visible_cell_width,
                        "font_measured_text_width_px": data_text_width,
                        "available_text_width_px": available_data_width,
                        "fit_slack_px": available_data_width - data_text_width,
                        "passed": data_fits,
                    }
                )
            record["columns"].append(
                {
                    "id": column_id,
                    "display_position": position,
                    "text": heading_text,
                    "configured_width_px": configured_width,
                    "visible_heading_width_px": visible_width,
                    "font_measured_text_width_px": text_width,
                    "padding_left_px": padding_left,
                    "padding_right_px": padding_right,
                    "heading_image_width_px": image_width,
                    "heading_image_gap_px": image_gap,
                    "available_text_width_px": available_text_width,
                    "fit_slack_px": available_text_width - text_width,
                    "data_cells": data_cells,
                    "passed": fits,
                }
            )

        column_extent_within_viewport = (
            configured_extent <= int(heading_pixels["viewport_width_px"])
        )
        scrollbar_layout_safe = bool(
            scrollbar_layout["mapped_vertical_scrollbars"]
            and scrollbar_layout["tree_width_within_parent_after_scrollbar"]
            and scrollbar_layout["scrollbars_nonoverlapping"]
        )
        checks = {
            "mapped": record["mapped"],
            "display_columns_present": bool(displayed_columns),
            "all_headings_measured": all_headings_measured,
            "column_extent_within_viewport": column_extent_within_viewport,
            "all_heading_text_fits": all_heading_text_fits,
            "all_data_cells_measured": all_data_cells_measured,
            "all_data_text_fits": all_data_text_fits,
            "configured_row_height_fits_data_font": (
                configured_row_height >= minimum_data_row_height
            ),
            "actual_first_row_height_fits_data_font": (
                first_row_height >= minimum_data_row_height
            ),
            "scrollbar_layout_safe": scrollbar_layout_safe,
            "one_body_row_visible_below_heading": (
                tree_widget_height >= minimum_one_row_height
            ),
            "first_existing_row_fully_visible": first_existing_row_fully_visible,
        }
        record.update(
            {
                "style": tree_style,
                "heading_style": heading_style,
                "heading_font": str(font_spec),
                "heading_font_actual": font_actual,
                "heading_font_metrics": font_metrics,
                "heading_padding": str(padding_value),
                "body_font": str(body_font_spec),
                "body_font_actual": body_font_actual,
                "body_font_metrics": body_font_metrics,
                "body_padding": str(body_padding_value),
                "tree_widget_height_px": tree_widget_height,
                "configured_row_height_px": configured_row_height,
                "minimum_data_row_height_px": minimum_data_row_height,
                "minimum_one_row_height_px": minimum_one_row_height,
                "data_row_count": len(tree_children),
                "first_row_bbox": first_row_bbox,
                "first_row_height_px": first_row_height,
                "configured_column_extent_px": configured_extent,
                "heading_viewport": heading_pixels,
                "scrollbar_layout": scrollbar_layout,
                "checks": checks,
                "passed": all(checks.values()),
            }
        )
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["checks"] = {"measurement_completed": False}
    return record


def _tree_visibility_policy(app: Any) -> dict[str, Any]:
    try:
        scale_factor = float(app.scale_factor)
        if not math.isfinite(scale_factor) or scale_factor <= 0:
            raise ValueError("scale_factor must be finite and positive")
        left_pane_height = max(0, int(app.left_pane.winfo_height()))
        logical_left_pane_height = left_pane_height / scale_factor
    except Exception as exc:
        return {
            "resolved": False,
            "actual_left_pane_height_px": None,
            "scale_factor": None,
            "logical_left_pane_height": None,
            "required_threshold": TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT,
            "visibility_required": True,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "resolved": True,
        "actual_left_pane_height_px": left_pane_height,
        "scale_factor": scale_factor,
        "logical_left_pane_height": logical_left_pane_height,
        "required_threshold": TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT,
        "visibility_required": (
            logical_left_pane_height >= TREE_VISIBILITY_REQUIRED_LOGICAL_HEIGHT
        ),
        "error": "",
    }


def _unmapped_tree_heading_record(
    name: str,
    tree: Any,
    *,
    visibility_required: bool,
    fallback_affordance_name: str,
    fallback_affordance_mapped: bool,
) -> dict[str, Any]:
    compact_reachable = not visibility_required and fallback_affordance_mapped
    checks = {
        "mapped_when_required": not visibility_required,
        "compact_fallback_affordance_mapped": compact_reachable,
    }
    return {
        "name": name,
        "widget_path": str(tree),
        "present": True,
        "mapped": False,
        "visibility_required": visibility_required,
        "fallback_affordance_name": fallback_affordance_name,
        "fallback_affordance_mapped": fallback_affordance_mapped,
        "mapped_or_compact_reachable": compact_reachable,
        "measurement_applicable": False,
        "columns": [],
        "checks": checks,
        "passed": all(checks.values()),
        "error": "",
    }


def build_tree_heading_fit_gate(
    app: Any,
    *,
    font_factory: Any | None = None,
) -> dict[str, Any]:
    """Measure live Tk heading text against its actually visible viewport."""

    if font_factory is None:
        from tkinter import font as tkfont

        font_factory = tkfont.Font

    visibility_policy = _tree_visibility_policy(app)
    visibility_required = bool(visibility_policy["visibility_required"])
    compact_mode = not visibility_required
    active_view = str(getattr(app, "_left_sidebar_view", "summary") or "summary")
    if active_view not in {"summary", "parked"}:
        active_view = "summary"
    switch_button = getattr(app, "left_context_switch_button", None)
    switch_mapped = switch_button is not None and _is_mapped(switch_button)
    trees: list[dict[str, Any]] = []
    for name, attribute, fallback_attribute in TREE_HEADING_GATE_WIDGETS:
        tree = getattr(app, attribute, None)
        fallback_affordance = getattr(app, fallback_attribute, None)
        fallback_affordance_mapped = (
            fallback_affordance is not None and _is_mapped(fallback_affordance)
        )
        if tree is None:
            trees.append(
                {
                    "name": name,
                    "widget_path": "",
                    "present": False,
                    "mapped": False,
                    "visibility_required": visibility_required,
                    "fallback_affordance_name": fallback_attribute,
                    "fallback_affordance_mapped": fallback_affordance_mapped,
                    "mapped_or_compact_reachable": False,
                    "measurement_applicable": False,
                    "columns": [],
                    "checks": {"measurement_completed": False},
                    "passed": False,
                    "error": f"missing app.{attribute}",
                }
            )
            continue
        try:
            mapped = bool(tree.winfo_ismapped())
        except Exception:
            mapped = False
        if not mapped:
            trees.append(
                _unmapped_tree_heading_record(
                    name,
                    tree,
                    visibility_required=visibility_required,
                    fallback_affordance_name=fallback_attribute,
                    fallback_affordance_mapped=fallback_affordance_mapped,
                )
            )
            continue
        tree_record = _tree_heading_fit_record(
            app,
            name,
            tree,
            font_factory=font_factory,
            visibility_required=visibility_required,
        )
        tree_record["fallback_affordance_name"] = fallback_attribute
        tree_record["fallback_affordance_mapped"] = fallback_affordance_mapped
        tree_record["mapped_or_compact_reachable"] = True
        trees.append(tree_record)

    checks = {
        "visibility_policy_resolved": visibility_policy["resolved"] is True,
        "required_trees_present": all(tree.get("present") is True for tree in trees),
        "required_trees_mapped": all(
            tree.get("present") is True
            and tree.get("mapped_or_compact_reachable") is True
            for tree in trees
        ),
        "compact_has_active_tree": (
            visibility_required or any(tree.get("mapped") is True for tree in trees)
        ),
        "compact_switch_mapped": visibility_required or switch_mapped,
        "compact_active_tree_matches_view": (
            visibility_required
            or all(
                bool(tree.get("mapped"))
                == (tree.get("name") == f"{active_view}_tree")
                for tree in trees
            )
        ),
        "all_measurements_completed": all(not tree.get("error") for tree in trees),
        "all_column_extents_within_viewport": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or tree.get("checks", {}).get("column_extent_within_viewport") is True
            )
            for tree in trees
        ),
        "all_heading_text_fits": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or tree.get("checks", {}).get("all_heading_text_fits") is True
            )
            for tree in trees
        ),
        "all_scrollbar_layouts_safe": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or tree.get("checks", {}).get("scrollbar_layout_safe") is True
            )
            for tree in trees
        ),
        "all_data_text_fits": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or (
                    tree.get("checks", {}).get("all_data_cells_measured") is True
                    and tree.get("checks", {}).get("all_data_text_fits") is True
                )
            )
            for tree in trees
        ),
        "all_data_row_heights_fit_fonts": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or (
                    tree.get("checks", {}).get(
                        "configured_row_height_fits_data_font"
                    )
                    is True
                    and tree.get("checks", {}).get(
                        "actual_first_row_height_fits_data_font"
                    )
                    is True
                )
            )
            for tree in trees
        ),
        "all_active_tree_rows_visible": all(
            tree.get("present") is True
            and (
                tree.get("measurement_applicable") is False
                or (
                    tree.get("checks", {}).get("one_body_row_visible_below_heading") is True
                    and tree.get("checks", {}).get("first_existing_row_fully_visible") is True
                )
            )
            for tree in trees
        ),
        "active_tree_has_data_row": any(
            tree.get("name") == f"{active_view}_tree"
            and tree.get("mapped") is True
            and int(tree.get("data_row_count") or 0) >= 1
            for tree in trees
        ),
        "all_mapped_trees_have_data_row": all(
            tree.get("mapped") is not True
            or int(tree.get("data_row_count") or 0) >= 1
            for tree in trees
        ),
        "parked_view_has_recovery_row": (
            active_view != "parked"
            or any(
                tree.get("name") == "parked_tree"
                and int(tree.get("data_row_count") or 0) >= 1
                and tree.get("checks", {}).get("first_existing_row_fully_visible") is True
                for tree in trees
            )
        ),
    }
    try:
        tk_scaling = float(app.root.tk.call("tk", "scaling"))
    except Exception:
        tk_scaling = None
    return {
        "gate_applicable": True,
        "method": (
            "live Tk heading and data font measure vs identify_region-visible column span, "
            "style padding/image allowance, data row-height, configured extent, and sibling scrollbar layout"
        ),
        "tk_scaling": tk_scaling,
        "visibility_policy": visibility_policy,
        "compact_mode": compact_mode,
        "active_view": active_view,
        "switch_mapped": switch_mapped,
        "trees": trees,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _core_action_critical_widget_specs(app: Any) -> dict[str, tuple[Any, bool, bool]]:
    """Require both requested width and height for the four primary actions."""

    return {
        "action_undo": (app.undo_button, True, True),
        "action_park": (app.park_button, True, True),
        "action_submit": (app.submit_tray_button, True, True),
        "action_operations": (app.operations_button, True, True),
    }


def _notice_critical_widget_specs(app: Any) -> dict[str, tuple[Any, bool, bool]]:
    """Inspect notice contents using Tk's wrap-aware requested label size."""

    specs: dict[str, tuple[Any, bool, bool]] = {}
    title = getattr(app, "notice_title_label", None)
    message = getattr(app, "notice_message_label", None)
    if title is not None:
        specs["notice_title"] = (title, True, True)
    if message is not None:
        # Tk Label's requested width already reflects its configured wraplength.
        # Compressing below that post-wrap request clips text instead of causing
        # another automatic reflow, so both axes must remain fail-closed.
        specs["notice_message"] = (message, True, True)
    acknowledge = getattr(app, "notice_ack_button", None)
    if (
        acknowledge is not None
        and getattr(acknowledge, "master", None) is app.notice_frame
        and _is_mapped(acknowledge)
    ):
        specs["notice_ack"] = (acknowledge, True, True)
    return specs


def _left_sidebar_critical_widget_specs(app: Any) -> dict[str, tuple[Any, bool, bool]]:
    specs: dict[str, tuple[Any, bool, bool]] = {}
    checkbox = getattr(app, "tray_image_checkbox", None)
    if checkbox is not None:
        specs["tray_image_checkbox"] = (checkbox, True, True)
    tray_image = getattr(app, "tray_image_label", None)
    if tray_image is not None and _is_mapped(tray_image):
        specs["tray_image_display"] = (tray_image, False, False)
    worker_label = getattr(app, "worker_info_label", None)
    if worker_label is not None and _is_mapped(worker_label):
        specs["left_worker_name"] = (worker_label, False, True)
    change_worker = getattr(app, "change_worker_button", None)
    if change_worker is not None and _is_mapped(change_worker):
        specs["left_change_worker"] = (change_worker, True, True)
    button = getattr(app, "left_context_switch_button", None)
    if button is not None and _is_mapped(button):
        specs["left_context_switch"] = (button, True, True)
    view = str(getattr(app, "_left_sidebar_view", "summary") or "summary")
    active_frame = getattr(
        app,
        "_parked_tree_frame" if view == "parked" else "_summary_tree_frame",
        None,
    )
    active_tree = getattr(
        app,
        "parked_tree" if view == "parked" else "summary_tree",
        None,
    )
    if active_frame is not None and _is_mapped(active_frame):
        specs["left_active_tree_frame"] = (active_frame, False, False)
    if active_tree is not None and _is_mapped(active_tree):
        specs["left_active_tree"] = (active_tree, False, False)
    return specs


def collect_ui_geometry(app: Any) -> dict[str, Any]:
    root = app.root
    root_size = (int(root.winfo_width()), int(root.winfo_height()))
    critical_widgets = {
        "left_pane": (app.left_pane, False),
        "center_pane": (app.center_pane, False),
        "right_pane": (app.right_pane, False),
        "stage": (app.stage_label, True),
        "current_item": (app.current_item_label, True),
        "count": (app.main_count_label, True),
        "progress": (app.main_progress_bar, False),
        "scan_entry": (app.scan_entry, True),
        "notice": (app.notice_frame, False),
        "scan_list_frame": (app._scan_list_frame, False),
        "scan_list_header": (app.scanned_list_header_label, True),
        "scan_list": (app.scanned_listbox, False),
        "scan_list_scrollbar": (app.scanned_list_scrollbar, False),
        "actions": (app._center_button_frame, False),
        "right_status": (app.info_cards["status"]["frame"], False, False),
        "right_status_value": (app.info_cards["status"]["value"], True, True),
        "right_stopwatch": (app.info_cards["stopwatch"]["frame"], False, False),
        "right_stopwatch_value": (app.info_cards["stopwatch"]["value"], True, True),
        "right_context": (app._right_context_frame, False, False),
        "right_last_scan": (app.last_scan_value_label, True, True),
        "right_follow_up": (app.follow_up_label, True, True),
        "right_secondary": (app._secondary_stats_frame, False, False),
        "status_bar_text": (app.status_label, False, True),
    }
    for name in tuple(critical_widgets):
        value = critical_widgets[name]
        if len(value) == 2:
            widget, check_requested_height = value
            critical_widgets[name] = (widget, False, check_requested_height)
    core_action_specs = _core_action_critical_widget_specs(app)
    core_action_widgets = {
        name: specification[0] for name, specification in core_action_specs.items()
    }
    critical_widgets.update(core_action_specs)
    critical_widgets.update(_notice_critical_widget_specs(app))
    critical_widgets.update(_left_sidebar_critical_widget_specs(app))
    records = [
        _widget_record(
            root,
            widget,
            name,
            check_requested_width=check_requested_width,
            check_requested_height=check_requested_height,
        )
        for name, (widget, check_requested_width, check_requested_height) in critical_widgets.items()
    ]
    clipping = evaluate_clipping_proxy(
        records,
        root_size,
        overlap_pairs=(
            ("scan_entry", "notice"),
            ("notice", "scan_list"),
            ("scan_list", "actions"),
            ("left_context_switch", "left_active_tree_frame"),
            ("left_active_tree_frame", "tray_image_checkbox"),
        ),
        containment_pairs=(
            ("stage", "center_pane"),
            ("current_item", "center_pane"),
            ("count", "center_pane"),
            ("progress", "center_pane"),
            ("scan_entry", "center_pane"),
            ("notice", "center_pane"),
            ("notice_title", "notice"),
            ("notice_message", "notice"),
            ("notice_ack", "notice"),
            ("scan_list_frame", "center_pane"),
            ("scan_list_header", "scan_list_frame"),
            ("scan_list", "scan_list_frame"),
            ("scan_list_scrollbar", "scan_list_frame"),
            ("actions", "center_pane"),
            ("action_undo", "actions"),
            ("action_park", "actions"),
            ("action_submit", "actions"),
            ("action_operations", "actions"),
            ("left_context_switch", "left_pane"),
            ("left_worker_name", "left_pane"),
            ("left_change_worker", "left_pane"),
            ("left_active_tree_frame", "left_pane"),
            ("left_active_tree", "left_active_tree_frame"),
            ("tray_image_checkbox", "left_pane"),
            ("right_status", "right_pane"),
            ("right_status_value", "right_status"),
            ("right_stopwatch", "right_pane"),
            ("right_stopwatch_value", "right_stopwatch"),
            ("right_context", "right_pane"),
            ("right_last_scan", "right_context"),
            ("right_follow_up", "right_context"),
            ("right_secondary", "right_pane"),
            ("tray_image_checkbox", "left_pane"),
        ),
    )

    center_history = [
        widget
        for widget in _descendants(app.center_pane)
        if str(widget.winfo_class()) in {"Listbox", "Treeview"}
    ]
    right_history = [
        widget
        for widget in _descendants(app.right_pane)
        if str(widget.winfo_class()) in {"Listbox", "Treeview"}
    ]
    right_progress = [
        widget
        for widget in _descendants(app.right_pane)
        if str(widget.winfo_class()) in {"Progressbar", "TProgressbar"}
    ]
    record_by_name = {record["name"]: record for record in records}
    core_action_records = [record_by_name[name] for name in core_action_widgets]
    core_action_rows = cluster_button_rows(core_action_records)
    center_width = int(app.center_pane.winfo_width())
    expected_core_action_rows = (
        [["action_undo", "action_park", "action_submit", "action_operations"]]
        if center_width >= 620
        else [
            ["action_undo", "action_park"],
            ["action_submit", "action_operations"],
        ]
    )
    hidden_operations = [
        widget
        for widget in (
            getattr(app, "reset_button", None),
            getattr(app, "replace_master_label_button", None),
            getattr(app, "exchange_button", None),
        )
        if widget is not None
    ]
    scan_list_layout_signature = {
        "frame_path": str(app._scan_list_frame),
        "frame_master": str(app._scan_list_frame.master),
        "frame_grid": _normalized_grid_info(app._scan_list_frame),
        "center_row_5": _normalized_grid_row(app.center_pane, 5),
        "header_path": str(app.scanned_list_header_label),
        "header_master": str(app.scanned_list_header_label.master),
        "header_grid": _normalized_grid_info(app.scanned_list_header_label),
        "list_path": str(app.scanned_listbox),
        "list_master": str(app.scanned_listbox.master),
        "list_grid": _normalized_grid_info(app.scanned_listbox),
        "frame_row_1": _normalized_grid_row(app._scan_list_frame, 1),
    }
    scan_list_frame_contract = bool(
        app._scan_list_frame.master is app.center_pane
        and scan_list_layout_signature["frame_grid"].get("row") == 5
        and set(str(scan_list_layout_signature["frame_grid"].get("sticky", "")))
        == set("nsew")
        and app.scanned_list_header_label.master is app._scan_list_frame
        and scan_list_layout_signature["header_grid"].get("row") == 0
        and app.scanned_listbox.master is app._scan_list_frame
        and scan_list_layout_signature["list_grid"].get("row") == 1
        and set(str(scan_list_layout_signature["list_grid"].get("sticky", "")))
        == set("nsew")
        and scan_list_layout_signature["center_row_5"].get("weight", 0) > 0
        and scan_list_layout_signature["frame_row_1"].get("weight", 0) > 0
    )
    structure = {
        "center_history_widget_count": len(center_history),
        "center_history_widgets": [str(widget) for widget in center_history],
        "right_history_widget_count": len(right_history),
        "right_history_widgets": [str(widget) for widget in right_history],
        "right_progress_widget_count": len(right_progress),
        "right_progress_widgets": [str(widget) for widget in right_progress],
        "central_scan_list_is_only_center_history": center_history == [app.scanned_listbox],
        "right_has_no_full_scan_history": not right_history,
        "right_has_no_progress_widget": not right_progress,
        "scan_list_frame_contract": scan_list_frame_contract,
        "scan_list_layout_signature": scan_list_layout_signature,
        "scan_list_below_notice": (
            app.scanned_listbox.winfo_rooty()
            >= app.notice_frame.winfo_rooty() + app.notice_frame.winfo_height()
        ),
        "core_action_button_count": len(core_action_records),
        "core_action_common_parent": len(
            {record["master_path"] for record in core_action_records}
        ) == 1,
        "core_action_rows": core_action_rows,
        "expected_core_action_rows": expected_core_action_rows,
        "core_action_layout_matches": core_action_rows == expected_core_action_rows,
        "hidden_operation_button_count": len(hidden_operations),
        "hidden_operation_buttons_mapped": [
            str(widget) for widget in hidden_operations if _is_mapped(widget)
        ],
    }
    return {
        "root_client_size": [root_size[0], root_size[1]],
        "widgets": records,
        "clipping_proxy": clipping,
        "structure": structure,
    }


def _widget_text(widget: Any) -> str:
    try:
        return str(widget.cget("text"))
    except Exception:
        return ""


def collect_rendered_state(app: Any) -> dict[str, Any]:
    try:
        scan_rows = [str(value) for value in app.scanned_listbox.get(0, "end")]
    except Exception:
        scan_rows = []
    scan_row_colors: list[dict[str, str]] = []
    for row_index in range(len(scan_rows)):
        try:
            background = str(app.scanned_listbox.itemcget(row_index, "background"))
            foreground = str(app.scanned_listbox.itemcget(row_index, "foreground"))
        except Exception:
            background = ""
            foreground = ""
        scan_row_colors.append(
            {"background": background, "foreground": foreground}
        )
    scan_list_rows_neutral = all(
        colors == {
            "background": str(app.COLOR_SIDEBAR_BG),
            "foreground": str(app.COLOR_TEXT),
        }
        for colors in scan_row_colors
    )
    try:
        scan_entry_state = str(app.scan_entry.cget("state"))
    except Exception:
        scan_entry_state = "unknown"
    try:
        presenter_last_normal_scan_raw = str(
            app._warning_state_presenter().state.last_normal_scan or ""
        )
    except Exception:
        presenter_last_normal_scan_raw = ""
    try:
        active_tray_scans_raw = [
            str(value) for value in (app.current_tray.scanned_barcodes or [])
        ]
        active_tray_last_scan_raw = (
            active_tray_scans_raw[-1] if active_tray_scans_raw else ""
        )
    except Exception:
        active_tray_scans_raw = []
        active_tray_last_scan_raw = ""
    right_texts = {
        "status": _widget_text(app.info_cards["status"]["value"]),
        "direct_sync": _widget_text(app.info_cards["direct_sync"]["value"]),
        "stopwatch": _widget_text(app.info_cards["stopwatch"]["value"]),
        "last_normal_scan": _widget_text(app.last_scan_value_label),
        "next_action": _widget_text(app.follow_up_label),
        "average": _widget_text(app.info_cards["avg_time"]["value"]),
        "best": _widget_text(app.info_cards["best_time"]["value"]),
    }
    right_progress_count_texts = {
        key: text
        for key, text in right_texts.items()
        if re.search(r"\b\d+\s*/\s*\d+\b", text)
    }
    action_buttons: dict[str, dict[str, str]] = {}
    for name, button in (
        ("reset", getattr(app, "reset_button", None)),
        ("undo", getattr(app, "undo_button", None)),
        ("park", getattr(app, "park_button", None)),
        ("submit", getattr(app, "submit_tray_button", None)),
        ("operations", getattr(app, "operations_button", None)),
        ("change_worker", getattr(app, "change_worker_button", None)),
        ("replace", getattr(app, "replace_master_label_button", None)),
        ("exchange", getattr(app, "exchange_button", None)),
        ("phs_label_exchange", getattr(app, "phs_label_exchange_button", None)),
    ):
        if button is None:
            action_buttons[name] = {"text": "", "state": "missing"}
            continue
        try:
            state = str(button.cget("state"))
        except Exception:
            state = "unknown"
        action_buttons[name] = {"text": _widget_text(button), "state": state}
    def tree_row_count(tree: Any) -> int:
        try:
            return len(tree.get_children())
        except Exception:
            return -1

    left_sidebar = {
        "view": str(getattr(app, "_left_sidebar_view", "summary") or "summary"),
        "compact": bool(getattr(app, "_left_sidebar_compact", False)),
        "switch_text": _widget_text(
            getattr(app, "left_context_switch_button", None)
        ),
        "switch_mapped": _is_mapped(
            getattr(app, "left_context_switch_button", None)
        ),
        "summary_tree_mapped": _is_mapped(getattr(app, "summary_tree", None)),
        "parked_tree_mapped": _is_mapped(getattr(app, "parked_tree", None)),
        "summary_count": tree_row_count(getattr(app, "summary_tree", None)),
        "parked_count": tree_row_count(getattr(app, "parked_tree", None)),
        "tray_image_requested": bool(
            getattr(app, "show_tray_image_var", None)
            and app.show_tray_image_var.get()
        ),
        "tray_image_has_bitmap": (
            getattr(getattr(app, "tray_image_label", None), "image", None)
            is not None
        ),
    }
    return {
        "stage": _widget_text(app.stage_label),
        "current_item": _widget_text(app.current_item_label),
        "count": _widget_text(app.main_count_label),
        "notice_title": _widget_text(app.notice_title_label),
        "notice_message": _widget_text(app.notice_message_label),
        "last_normal_scan": _widget_text(app.last_scan_value_label),
        "last_normal_scan_display": _widget_text(app.last_scan_value_label),
        "presenter_last_normal_scan_raw": presenter_last_normal_scan_raw,
        "active_tray_scans_raw": active_tray_scans_raw,
        "active_tray_last_scan_raw": active_tray_last_scan_raw,
        "next_action": _widget_text(app.follow_up_label),
        "status": right_texts["status"],
        "stopwatch": right_texts["stopwatch"],
        "scan_entry_state": scan_entry_state,
        "status_bar_text": _widget_text(app.status_label),
        "scan_list_row_count": len(scan_rows),
        "scan_list_rows": scan_rows,
        "scan_list_row_colors": scan_row_colors,
        "scan_list_rows_neutral": scan_list_rows_neutral,
        "scan_list_header": _widget_text(app.scanned_list_header_label),
        "right_texts": right_texts,
        "right_progress_count_texts": right_progress_count_texts,
        "action_buttons": action_buttons,
        "left_sidebar": left_sidebar,
        "m7_scene_receipt": dict(
            getattr(app, "_capture_m7_scene_receipt", None) or {}
        ),
    }


def _severity_from_fixture(value: str, severity_enum: Any) -> Any:
    try:
        return severity_enum(str(value).lower())
    except ValueError as exc:
        raise RuntimeError(f"invalid fixture severity: {value!r}") from exc


def normalize_capture_scan_rows(app: Any) -> int:
    """Put fixture rows into the same neutral style as a settled live scan list."""

    try:
        row_count = int(app.scanned_listbox.size())
    except Exception:
        row_count = 0
    for row_index in range(row_count):
        app.scanned_listbox.itemconfig(
            row_index,
            {"bg": app.COLOR_SIDEBAR_BG, "fg": app.COLOR_TEXT},
        )
    if row_count:
        app.scanned_listbox.see(0)
    return row_count


def build_scan_list_viewport_gate(
    *,
    expected_row_count: int,
    configured_visible_rows: int,
    viewport_size: tuple[int, int],
    row_bboxes: Sequence[Sequence[int] | None],
    see_zero_applied: bool,
) -> dict[str, Any]:
    total_row_count = max(0, int(expected_row_count))
    configured_visible_rows = max(0, int(configured_visible_rows))
    minimum_recent_row_count = min(total_row_count, 3)
    required_visible_row_count = min(
        total_row_count,
        max(minimum_recent_row_count, configured_visible_rows),
    )
    viewport_width, viewport_height = (int(value) for value in viewport_size)
    rows: list[dict[str, Any]] = []
    for index in range(total_row_count):
        bbox = row_bboxes[index] if index < len(row_bboxes) else None
        if bbox is None:
            rows.append(
                {
                    "index": index,
                    "bbox": None,
                    "visible": False,
                    "horizontally_contained": None,
                    "vertically_contained": None,
                    "required_recent": index < required_visible_row_count,
                }
            )
            continue
        x, y, width, height = (int(value) for value in bbox)
        rows.append(
            {
                "index": index,
                "bbox": [x, y, width, height],
                "visible": width > 0 and height > 0,
                "horizontally_contained": (
                    width > 0 and x >= 0 and x + width <= viewport_width
                ),
                "vertically_contained": (
                    height > 0 and y >= 0 and y + height <= viewport_height
                ),
                "required_recent": index < required_visible_row_count,
            }
        )
    required_recent_rows = rows[:required_visible_row_count]
    newest_row = rows[0] if rows else None
    visible_recent_row_count = sum(
        row["visible"] is True for row in required_recent_rows
    )
    fully_contained_recent_row_count = sum(
        row["visible"] is True
        and row["horizontally_contained"] is True
        and row["vertically_contained"] is True
        for row in required_recent_rows
    )
    checks = {
        "see_zero_applied": bool(see_zero_applied),
        "newest_index_zero_visible": (
            newest_row is None or newest_row["visible"] is True
        ),
        "newest_index_zero_horizontally_contained": (
            newest_row is None
            or newest_row["visible"] is not True
            or newest_row["horizontally_contained"] is True
        ),
        "newest_index_zero_vertically_contained": (
            newest_row is None
            or newest_row["visible"] is not True
            or newest_row["vertically_contained"] is True
        ),
        "required_recent_rows_visible": all(
            row["visible"] is True for row in required_recent_rows
        ),
        "required_recent_rows_horizontally_contained": all(
            row["horizontally_contained"] is not False
            for row in required_recent_rows
        ),
        "required_recent_rows_vertically_contained": all(
            row["vertically_contained"] is not False
            for row in required_recent_rows
        ),
    }
    return {
        "gate_applicable": True,
        "expected_row_count": total_row_count,
        "total_row_count": total_row_count,
        "configured_visible_rows": configured_visible_rows,
        "minimum_recent_row_count": minimum_recent_row_count,
        "required_visible_row_count": required_visible_row_count,
        "visible_recent_row_count": visible_recent_row_count,
        "fully_contained_recent_row_count": fully_contained_recent_row_count,
        "viewport_size": [viewport_width, viewport_height],
        "rows": rows,
        "checks": checks,
        "passed": all(checks.values()),
    }


def collect_scan_list_viewport_gate(
    app: Any,
    *,
    expected_row_count: int,
) -> dict[str, Any]:
    listbox = app.scanned_listbox
    see_zero_applied = False
    if expected_row_count:
        listbox.see(0)
        see_zero_applied = True
        pump_tk(app.root, 80)
    else:
        # An empty fixture has no row to reveal; the operation is vacuously applied.
        see_zero_applied = True
    row_bboxes = [listbox.bbox(index) for index in range(expected_row_count)]
    try:
        configured_visible_rows = int(listbox.cget("height"))
    except (TypeError, ValueError, AttributeError):
        configured_visible_rows = 0
    return build_scan_list_viewport_gate(
        expected_row_count=expected_row_count,
        configured_visible_rows=configured_visible_rows,
        viewport_size=(int(listbox.winfo_width()), int(listbox.winfo_height())),
        row_bboxes=row_bboxes,
        see_zero_applied=see_zero_applied,
    )


def _capture_preflight_snapshot(
    fixture: StateFixture,
    module: Any,
) -> Any:
    state_by_phase = {
        "LOOKUP": module.HOLD_LOOKUP,
        "LOOKUP_FAILED": module.HOLD_LOOKUP_FAILED,
        "DRAINING": module.HOLD_DRAINING,
    }
    state = state_by_phase.get(fixture.preflight_phase)
    if state is None:
        return None
    timestamp = "2026-09-03T00:00:00+00:00"
    items = tuple(
        HeldScan(
            scan_id=f"M7-HELD-{index:04d}",
            sequence=index,
            raw_barcode=barcode,
            admitted_at=timestamp,
        )
        for index, barcode in enumerate(fixture.held_scans, start=1)
    )
    return module.PreflightHoldSnapshot(
        preflight_id=f"PREFLIGHT-{fixture.state_id.upper()}",
        scan_epoch=1,
        worker="캡처 작업자",
        master_raw=fixture.scanned_master_label,
        created_at=timestamp,
        updated_at=timestamp,
        state=state,
        items=items,
        error_code=(
            fixture.lease.error_code
            if fixture.lease is not None and state == module.HOLD_LOOKUP_FAILED
            else ""
        ),
    )


def _apply_m7_production_scene(
    app: Any,
    fixture: StateFixture,
    module: Any,
) -> dict[str, Any]:
    """Drive one scene through current ContainerAudit presenter/state methods."""

    static_receipts = inspect_m7_production_scene_seams(module)
    spec = M7_SCENE_CONTRACT[fixture.state_id]
    bound_identities: dict[str, str] = {}
    for method_name in spec["production_call_path"]:
        method = getattr(app, method_name, None)
        identity = _bound_method_identity(method)
        if not callable(method) or identity != (
            static_receipts["scenes"][fixture.state_id][
                "production_method_identities"
            ][method_name]
        ):
            raise RuntimeError(
                f"M7 scene {fixture.state_id} is not bound to production "
                f"{method_name}: {identity or '<missing>'}"
            )
        bound_identities[method_name] = identity

    snapshot = _capture_preflight_snapshot(fixture, module)
    if snapshot is not None:
        app._preflight_hold_snapshot = snapshot
        app._master_preflight_pending = fixture.preflight_phase == "LOOKUP"
        app._preflight_hold_draining = fixture.preflight_phase == "DRAINING"

    state_id = fixture.state_id

    def drive_scene() -> None:
        if state_id == "m7_phs2_preflight":
            app.show_status_message(
                fixture.status_variants[0], app.COLOR_PRIMARY, duration=0
            )
            app._set_preflight_scan_input_locked(True)
            app._update_current_item_label()
            app._update_action_button_states()
        elif state_id == "m7_central_preflight_queue":
            app.show_status_message(
                fixture.status_variants[2], app.COLOR_DANGER, duration=0
            )
            app._set_preflight_scan_input_locked(True)
            app._update_action_button_states()
        elif state_id == "m7_completion_busy":
            app._set_completion_lane_busy(True)
            app.show_status_message(
                fixture.status_variants[1], app.COLOR_DANGER, duration=0
            )
            app._set_preflight_scan_input_locked(True)
            app._update_action_button_states()
        elif state_id == "m7_recovery_transition":
            app._update_center_display()
            app._update_parked_trays_list()
            app._update_parked_recovery_affordance()
            app.show_status_message(
                fixture.status_variants[-1], app.COLOR_PRIMARY, duration=0
            )
        elif state_id == "m7_direct_sync_backlog_ack":
            if fixture.direct_sync is None:
                raise RuntimeError("direct-sync scene requires RelayHealth state")
            app._apply_direct_sync_health(
                module.RelayHealth(**asdict(fixture.direct_sync))
            )
            app._render_warning_state()
            app._update_action_button_states()
        elif state_id == "m7_exact_good_membership":
            app._update_center_display()
            app._update_current_item_label()
            app._update_action_button_states()
        elif state_id == "m7_lease_fail_closed":
            app.show_fullscreen_warning(
                "중앙 PHS=2 확인 실패",
                fixture.status_variants[-1],
                app.COLOR_DANGER,
            )
            app._set_preflight_scan_input_locked(True)
            app._update_action_button_states()
        elif state_id == "m7_transfer_receipt_status":
            app._render_warning_state()
            app._update_action_button_states()
        elif state_id == "m7_partial_atomic_exchange":
            app._exact_exchange_mode_active = True
            app._exact_transfer_exchange_history_snapshot = True
            app.show_status_message(
                fixture.status_variants[0], app.COLOR_DANGER, duration=0
            )
            app._update_action_button_states()
        else:  # pragma: no cover - the constant set is validated by tests
            raise RuntimeError(f"unsupported M7 state: {state_id}")

    call_trace: dict[str, Any]
    with trace_m7_production_calls(
        app,
        module,
        spec["production_call_path"],
    ) as call_trace:
        drive_scene()

    assertions = build_m7_scene_assertions(fixture, module)
    semantic_validation = assertions["production_validation"]
    receipt = {
        "state_id": fixture.state_id,
        "production_call_path": list(spec["production_call_path"]),
        "production_method_identities": bound_identities,
        "production_call_trace": call_trace,
        "seam_available": bool(
            call_trace["passed"] is True
            and semantic_validation["passed"] is True
        ),
        "reason": (
            "validated"
            if call_trace["passed"] is True
            and semantic_validation["passed"] is True
            else "production_semantic_variant_unavailable"
        ),
        "state_values": {
            "preflight_pending": bool(
                getattr(app, "_master_preflight_pending", False)
            ),
            "preflight_draining": bool(
                getattr(app, "_preflight_hold_draining", False)
            ),
            "preflight_input_locked": bool(
                getattr(app, "_preflight_scan_input_locked", False)
            ),
            "completion_lane_busy": bool(
                getattr(app, "_completion_lane_busy", False)
            ),
            "exact_exchange_mode": bool(
                getattr(app, "_exact_exchange_mode_active", False)
            ),
            "parked_count": int(getattr(app, "_parked_tray_count", 0) or 0),
        },
        "assertions": assertions,
    }
    app._capture_m7_scene_receipt = receipt
    return receipt


def apply_state_fixture(app: Any, fixture: StateFixture, module: Any) -> None:
    """Render an M7 fixture through production presenters without business I/O."""

    app._stop_stopwatch()
    app._stop_idle_checker()
    presenter = module.WarningPresenter()
    app.warning_presenter = presenter
    app.master_label_replace_state = None
    app.replacement_context = {}
    app._capture_m7_scene_receipt = None
    app._master_preflight_pending = False
    app._preflight_hold_snapshot = None
    app._preflight_hold_draining = False
    app._preflight_scan_input_locked = False
    app._completion_lane_busy = False
    app._exact_exchange_mode_active = False
    app._exact_transfer_exchange_history_snapshot = False
    app._pending_operator_review_snapshot = None
    app._pending_completion_event_contract = None
    summary_count = max(CAPTURE_SUMMARY_ROW_COUNT, fixture.completed_tray_count)
    app.work_summary = {
        CAPTURE_SUMMARY_ITEM_CODE: {
            "name": "캡처 작업 현황",
            "spec": "DISPLAY2 fixture",
            "count": summary_count,
            "test_count": 0,
        }
    }
    app.total_tray_count = summary_count
    app.completed_tray_times = [142.0, 156.0] if fixture.completed_tray_count else []
    app.best_time_records = {"2026-07-15": 137.0}

    tray_fixture = fixture.tray
    if tray_fixture is None:
        app.current_tray = module.TraySession()
    else:
        start_time = dt.datetime.now() - dt.timedelta(seconds=tray_fixture.stopwatch_seconds)
        scan_times = [
            start_time + dt.timedelta(seconds=(index + 1) * 11)
            for index in range(len(tray_fixture.scanned_barcodes))
        ]
        app.current_tray = module.TraySession(
            master_label_code=tray_fixture.master_label,
            item_code=tray_fixture.item_code,
            item_name=tray_fixture.item_name,
            item_spec=tray_fixture.item_spec,
            scanned_barcodes=list(tray_fixture.scanned_barcodes),
            scan_times=scan_times,
            tray_size=tray_fixture.target_count,
            stopwatch_seconds=tray_fixture.stopwatch_seconds,
            start_time=start_time,
            has_error_or_reset=bool(fixture.exchange_pairs),
            is_restored_session=tray_fixture.restored,
            is_partial_submission=tray_fixture.partial_submission,
            canonical_input_tag_qr=tray_fixture.master_label,
            active_label_qr_payload=CAPTURE_ACTIVE_EXACT_SIX_PHS2,
            active_label_id="LBL-M7-CONTAINER-0002",
            active_label_business_date="2026-09-03",
            active_label_worker_code="capture-worker",
            operation_lease_id=tray_fixture.operation_lease_id,
        )

    app.scanned_listbox.delete(0, "end")
    if tray_fixture is not None:
        for index, barcode in enumerate(tray_fixture.scanned_barcodes, start=1):
            app.scanned_listbox.insert(
                0,
                format_scan_list_row(
                    index,
                    barcode,
                    item_code=tray_fixture.item_code,
                ),
            )
    normalize_capture_scan_rows(app)

    if fixture.last_normal_scan:
        app._last_normal_scan_display_item_code = fixture.last_normal_item_code
        presenter.record_normal_scan(fixture.last_normal_scan)
    if fixture.notice is not None:
        presenter.present(
            module.Notice(
                code=fixture.notice.code,
                title=fixture.notice.title,
                message=fixture.notice.message,
                severity=_severity_from_fixture(
                    fixture.notice.severity,
                    module.NoticeSeverity,
                ),
                blocking=fixture.notice.blocking,
            )
        )
    if fixture.completion is not None:
        tray = fixture.tray
        scan_count = (
            len(tray.scanned_barcodes)
            if tray is not None
            else len(fixture.authoritative_members)
        )
        target_count = tray.target_count if tray is not None else scan_count
        presenter.present_completion(
            module.CompletionOutcomeSnapshot(
                outcome=module.CompletionOutcome(fixture.completion.outcome),
                item_name=tray.item_name if tray is not None else "M7 캡처 기준 품목",
                master_label=(
                    tray.master_label
                    if tray is not None
                    else fixture.scanned_master_label
                ),
                scan_count=scan_count,
                target_count=target_count,
                message=fixture.completion.message,
                receipt_id=fixture.completion.receipt_id,
                error_code=fixture.completion.error_code,
            )
        )

    app.is_idle = fixture.tray is None
    app.show_tray_image_var.set(bool(fixture.tray_image_visible))
    app._update_current_item_label()
    app._update_tray_image_display()
    app._update_all_summaries()
    app._apply_center_layout()
    app._apply_scanned_listbox_layout()
    app._apply_right_sidebar_layout()

    stopwatch_card = app.info_cards.get("stopwatch")
    if stopwatch_card:
        seconds = int(tray_fixture.stopwatch_seconds) if tray_fixture else 0
        stopwatch_card["value"].configure(text=f"{seconds // 60:02d}:{seconds % 60:02d}")
    app.status_label.configure(text="스캐너 준비")
    app._render_warning_state()
    app._update_action_button_states()
    _apply_m7_production_scene(app, fixture, module)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_new_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _write_new_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = _canonical_json_bytes(value)
    _write_new_bytes(path, payload)
    return hashlib.sha256(payload).hexdigest()


def _png_dimensions_from_bytes(payload: bytes) -> tuple[int, int]:
    signature = bytes((137, 80, 78, 71, 13, 10, 26, 10))
    if (
        len(payload) < 24
        or payload[:8] != signature
        or payload[12:16] != b"IHDR"
    ):
        raise ValueError("capture input must be a PNG with an IHDR header")
    width, height = struct.unpack(">II", payload[16:24])
    if width < 1 or height < 1:
        raise ValueError("capture PNG dimensions must be positive")
    return width, height


def _git_source_and_tool_identity(
    *,
    repo_root: Path,
    capture_tool_path: str,
) -> tuple[dict[str, str], dict[str, str]]:
    commit = _git_bytes(repo_root, "rev-parse", "HEAD^{commit}").decode(
        "ascii"
    ).strip()
    tree = _git_bytes(repo_root, "rev-parse", f"{commit}^{{tree}}").decode(
        "ascii"
    ).strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or re.fullmatch(
        r"[0-9a-f]{40}", tree
    ) is None:
        raise RuntimeError("app source commit/tree is not a full Git object ID")
    normalized_tool_path = str(capture_tool_path or "").replace("\\", "/")
    if (
        not normalized_tool_path
        or normalized_tool_path.startswith("/")
        or ".." in Path(normalized_tool_path).parts
        or re.fullmatch(r"[A-Za-z0-9._/-]+", normalized_tool_path) is None
    ):
        raise ValueError("capture tool path must be a safe repository path")
    frozen_tool = _git_bytes(
        repo_root,
        "show",
        f"{commit}:{normalized_tool_path}",
    )
    working_tool_path = repo_root / Path(normalized_tool_path)
    if (
        not working_tool_path.is_file()
        or working_tool_path.is_symlink()
        or not _git_paths_match_commit(
            repo_root,
            commit,
            (normalized_tool_path,),
        )
    ):
        raise RuntimeError(
            "capture tool content must exactly match the frozen app commit"
        )
    _assert_frozen_production_worktree(repo_root, commit)
    return (
        {"commit": commit, "tree": tree},
        {
            "path": normalized_tool_path,
            "commit": commit,
            "blob_sha256": hashlib.sha256(frozen_tool).hexdigest(),
        },
    )


class ExternalEvidencePathError(ValueError):
    """Typed rejection for an external evidence-root path contract violation."""

    def __init__(self, code: str, path: Path, detail: str) -> None:
        self.code = str(code)
        self.reason_code = self.code
        self.path = str(path)
        super().__init__(f"{self.code}: {detail}: {self.path}")


def _is_forbidden_link(path: Path) -> bool:
    """Mirror the canonical validator's symlink/junction/reparse decision."""

    # CAPTURE-BUNDLE-V1-CONTRACT.md section 2.3, lines 87-95. Keep this
    # predicate aligned with HANDOVER/tools/validate_capture_bundle_v1.py.
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction is not None and is_junction():
            return True
        if os.name == "nt":
            attributes = getattr(os.lstat(path), "st_file_attributes", 0)
            return bool(
                attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
            )
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return False


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.fspath(path))


def _resolved_path(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        raise ExternalEvidencePathError(
            "PATH_ESCAPES_ROOT",
            path,
            "evidence path could not be resolved",
        ) from exc


def _paths_have_same_lexical_and_physical_identity(
    first: Path,
    second: Path,
) -> bool:
    first_lexical = _lexical_absolute(first)
    second_lexical = _lexical_absolute(second)
    try:
        first_physical = first_lexical.resolve()
        second_physical = second_lexical.resolve()
    except (OSError, RuntimeError):
        return False
    return (
        _path_key(first_lexical) == _path_key(second_lexical)
        and _path_key(first_physical) == _path_key(second_physical)
    )


def _key_is_within(candidate: str, root: str) -> bool:
    try:
        return os.path.commonpath((root, candidate)) == root
    except (OSError, ValueError):
        return False


def _assert_lexical_and_physical_path_within_root(path: Path, root: Path) -> None:
    path_lexical = _lexical_absolute(path)
    root_lexical = _lexical_absolute(root)
    path_physical = _resolved_path(path_lexical)
    root_physical = _resolved_path(root_lexical)
    path_lexical_key = _path_key(path_lexical)
    root_lexical_key = _path_key(root_lexical)
    path_physical_key = _path_key(path_physical)
    root_physical_key = _path_key(root_physical)
    if not (
        _key_is_within(path_lexical_key, root_lexical_key)
        and _key_is_within(path_physical_key, root_physical_key)
    ):
        raise ExternalEvidencePathError(
            "PATH_ESCAPES_ROOT",
            path_lexical,
            "lexical and resolved physical paths must remain inside the evidence root",
        )
    if (
        path_lexical_key != path_physical_key
        or root_lexical_key != root_physical_key
    ):
        raise ExternalEvidencePathError(
            "SYMLINK_FORBIDDEN",
            path_lexical,
            "lexical and resolved physical paths differ; redirect is forbidden",
        )


def _root_relative(path: Path, root: Path) -> str:
    absolute = _lexical_absolute(path)
    absolute_root = _lexical_absolute(root)
    _assert_no_symlink_path_components(absolute_root)
    _assert_no_symlink_path_components(absolute)
    _assert_lexical_and_physical_path_within_root(absolute, absolute_root)
    try:
        relative = absolute.relative_to(absolute_root).as_posix()
    except ValueError as exc:
        raise ExternalEvidencePathError(
            "PATH_ESCAPES_ROOT",
            absolute,
            "evidence path must remain below the external root",
        ) from exc
    if not relative or re.fullmatch(r"[A-Za-z0-9._/-]+", relative) is None:
        raise ValueError("evidence path is not a canonical root-relative path")
    return relative


def _assert_no_symlink_path_components(path: Path) -> None:
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        components.append(components[-1] / part)
    for current in components:
        if _is_forbidden_link(current):
            raise ExternalEvidencePathError(
                "SYMLINK_FORBIDDEN",
                current,
                "symlink path component is forbidden, including a junction or "
                "reparse-point redirect",
            )


def _assert_clean_evidence_root(root: Path) -> None:
    _assert_no_symlink_path_components(root)
    _assert_lexical_and_physical_path_within_root(root, root)

    def reject_walk_error(exc: OSError) -> None:
        error_path = Path(exc.filename) if exc.filename else root
        raise ExternalEvidencePathError(
            "ROOT_SCAN_ERROR",
            error_path,
            "external evidence root could not be scanned",
        ) from exc

    try:
        for current_text, directories, files in os.walk(
            root,
            followlinks=False,
            onerror=reject_walk_error,
        ):
            current = Path(current_text)
            for name in [*directories, *files]:
                candidate = current / name
                if _is_forbidden_link(candidate):
                    raise ExternalEvidencePathError(
                        "SYMLINK_FORBIDDEN",
                        candidate,
                        "symlinks are forbidden in the external evidence root; "
                        "junctions and reparse-point redirects are also forbidden",
                    )
                if name.lower() == "latest" or Path(name).stem.lower() == "latest":
                    raise ValueError("mutable latest aliases are forbidden")
    except ExternalEvidencePathError:
        raise
    except OSError as exc:
        raise ExternalEvidencePathError(
            "ROOT_SCAN_ERROR",
            root,
            "external evidence root could not be scanned",
        ) from exc


def build_m7_external_capture_bundle(
    *,
    evidence_root: Path,
    portable_artifact: Path,
    captures: Sequence[ExternalCaptureImage],
    repo_root: Path = ROOT,
    capture_tool_path: str = M7_CAPTURE_TOOL_PATH,
    generated_at: dt.datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create one canonical external bundle from already-rendered PNG bytes.

    The function performs no rendering and never opens Tk.  Every document and
    copied byte object is created with exclusive-create semantics.
    """

    root_input = _lexical_absolute(Path(evidence_root))
    _assert_no_symlink_path_components(root_input)
    _assert_lexical_and_physical_path_within_root(root_input, root_input)
    if root_input.exists() and not root_input.is_dir():
        raise ValueError("external evidence root must be a real directory")
    artifact_input = _lexical_absolute(Path(portable_artifact))
    _assert_no_symlink_path_components(artifact_input)
    _assert_lexical_and_physical_path_within_root(artifact_input, artifact_input)
    artifact_source = _resolved_path(artifact_input)
    if (
        not artifact_source.is_file()
        or artifact_source.stat().st_size < 1
    ):
        raise ValueError("portable artifact input must be a non-empty regular file")
    root = root_input
    root.mkdir(parents=True, exist_ok=True)
    _assert_clean_evidence_root(root)
    app_source, capture_tool = _git_source_and_tool_identity(
        repo_root=Path(repo_root).resolve(),
        capture_tool_path=capture_tool_path,
    )
    by_state: dict[str, ExternalCaptureImage] = {}
    for capture in captures:
        if not isinstance(capture, ExternalCaptureImage):
            raise TypeError("captures must contain ExternalCaptureImage values")
        state_id = str(capture.state_id or "")
        if state_id in by_state:
            raise ValueError(f"duplicate capture state ID: {state_id}")
        if state_id not in M7_REQUIRED_STATE_IDS:
            raise ValueError(f"unexpected capture state ID: {state_id}")
        if isinstance(capture.dpi, bool) or int(capture.dpi) < 1:
            raise ValueError("capture DPI must be a positive integer")
        _png_dimensions_from_bytes(capture.png_bytes)
        by_state[state_id] = capture
    if set(by_state) != set(M7_REQUIRED_STATE_IDS) or len(by_state) != len(
        M7_REQUIRED_STATE_IDS
    ):
        missing = [state for state in M7_REQUIRED_STATE_IDS if state not in by_state]
        extra = [state for state in by_state if state not in M7_REQUIRED_STATE_IDS]
        raise ValueError(
            "captures must contain the exact required state set; "
            f"missing={missing!r} extra={extra!r}"
        )

    instant = generated_at or dt.datetime.now(dt.timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    instant = instant.astimezone(dt.timezone.utc).replace(microsecond=0)
    compact_utc = instant.strftime("%Y%m%dT%H%M%SZ")
    rfc3339_utc = instant.strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce8 = str(nonce or secrets.token_hex(4)).lower()
    if re.fullmatch(r"[0-9a-f]{8}", nonce8) is None:
        raise ValueError("bundle nonce must be lowercase 8-hex")
    bundle_id = (
        f"{M7_EXTERNAL_CAPTURE_APP}__{app_source['commit'][:12]}__"
        f"{compact_utc}__{nonce8}"
    )
    bundle_root = root / M7_EXTERNAL_CAPTURE_APP / bundle_id
    bundle_root.mkdir(parents=True, exist_ok=False)
    for directory in ("captures", "states", "approval"):
        (bundle_root / directory).mkdir()

    artifact_digest = _sha256(artifact_source)
    try:
        artifact_relative = _root_relative(artifact_source, root)
    except ExternalEvidencePathError as exc:
        if exc.code != "PATH_ESCAPES_ROOT":
            raise
        suffix = artifact_source.suffix.lower()
        if re.fullmatch(r"\.[a-z0-9]+", suffix) is None:
            suffix = ".bin"
        artifact_destination = (
            root
            / "artifacts"
            / (
                f"{M7_EXTERNAL_CAPTURE_APP}__{app_source['commit'][:12]}__"
                f"{artifact_digest[:12]}{suffix}"
            )
        )
        artifact_destination.parent.mkdir(parents=True, exist_ok=True)
        if artifact_destination.exists():
            if (
                _is_forbidden_link(artifact_destination)
                or not artifact_destination.is_file()
                or _sha256(artifact_destination) != artifact_digest
            ):
                raise RuntimeError("existing portable artifact identity mismatch")
        else:
            with artifact_source.open("rb") as source_handle, artifact_destination.open(
                "xb"
            ) as destination_handle:
                shutil.copyfileobj(source_handle, destination_handle, 1024 * 1024)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
        if _sha256(artifact_destination) != artifact_digest:
            raise RuntimeError("portable artifact copy digest mismatch")
        artifact_relative = _root_relative(artifact_destination, root)
    portable_identity = {
        "file": artifact_relative,
        "sha256": artifact_digest,
    }

    capture_records: list[dict[str, Any]] = []
    for state_id in M7_REQUIRED_STATE_IDS:
        capture = by_state[state_id]
        width, height = _png_dimensions_from_bytes(capture.png_bytes)
        dpi = int(capture.dpi)
        stem = f"{state_id}__{width}x{height}__{dpi}dpi"
        image_path = bundle_root / "captures" / f"{stem}.png"
        _write_new_bytes(image_path, capture.png_bytes)
        image_digest = hashlib.sha256(capture.png_bytes).hexdigest()
        image_relative = _root_relative(image_path, root)
        state_path = bundle_root / "states" / f"{stem}.json"
        state_document = {
            "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
            "app": M7_EXTERNAL_CAPTURE_APP,
            "bundle_id": bundle_id,
            "state_id": state_id,
            "viewport": {"width_px": width, "height_px": height},
            "dpi": dpi,
            "generated_at": rfc3339_utc,
            "image_file": image_relative,
            "image_sha256": image_digest,
        }
        state_digest = _write_new_json(state_path, state_document)
        capture_records.append(
            {
                "state_id": state_id,
                "viewport": {"width_px": width, "height_px": height},
                "dpi": dpi,
                "generated_at": rfc3339_utc,
                "image_file": image_relative,
                "image_sha256": image_digest,
                "state_manifest_file": _root_relative(state_path, root),
                "state_manifest_sha256": state_digest,
            }
        )

    capture_set_relative = _root_relative(bundle_root / "capture-set.json", root)
    capture_set = {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "app": M7_EXTERNAL_CAPTURE_APP,
        "bundle_id": bundle_id,
        "app_source": app_source,
        "portable_artifact": portable_identity,
        "capture_tool": capture_tool,
        "captures": capture_records,
    }
    capture_set_digest = _write_new_json(
        bundle_root / "capture-set.json",
        capture_set,
    )
    approval_relative = _root_relative(
        bundle_root / "approval" / "approval-receipt.json",
        root,
    )
    approval_receipt = {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "app": M7_EXTERNAL_CAPTURE_APP,
        "bundle_id": bundle_id,
        "capture_set_file": capture_set_relative,
        "capture_set_sha256": capture_set_digest,
        "approver": M7_APPROVAL_PLACEHOLDER,
    }
    approval_digest = _write_new_json(
        bundle_root / "approval" / "approval-receipt.json",
        approval_receipt,
    )
    custody_relative = _root_relative(
        bundle_root / "approval" / "custody-receipt.json",
        root,
    )
    custody_receipt = {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "app": M7_EXTERNAL_CAPTURE_APP,
        "bundle_id": bundle_id,
        "capture_set_file": capture_set_relative,
        "capture_set_sha256": capture_set_digest,
        "approval_receipt_file": approval_relative,
        "approval_receipt_sha256": approval_digest,
        "custodian": M7_APPROVAL_PLACEHOLDER,
        "custody_location": M7_APPROVAL_PLACEHOLDER,
        "retention_period": M7_APPROVAL_PLACEHOLDER,
    }
    custody_digest = _write_new_json(
        bundle_root / "approval" / "custody-receipt.json",
        custody_receipt,
    )
    manifest = {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "app": M7_EXTERNAL_CAPTURE_APP,
        "app_source": app_source,
        "portable_artifact": portable_identity,
        "capture_tool": capture_tool,
        "captures": capture_records,
        "approval": {
            "approver": M7_APPROVAL_PLACEHOLDER,
            "approval_receipt_file": approval_relative,
            "approval_receipt_sha256": approval_digest,
            "custody_receipt_file": custody_relative,
            "custody_receipt_sha256": custody_digest,
        },
    }
    manifest_path = bundle_root / "manifest.json"
    manifest_digest = _write_new_json(manifest_path, manifest)
    index_path = root / "indexes" / (
        f"handover-index__{compact_utc}__{nonce8}.json"
    )
    index_document = {
        "schema": M7_EXTERNAL_CAPTURE_BUNDLE_SCHEMA,
        "manifests": [
            {
                "app": M7_EXTERNAL_CAPTURE_APP,
                "manifest_file": _root_relative(manifest_path, root),
                "manifest_sha256": manifest_digest,
            }
        ],
    }
    index_digest = _write_new_json(index_path, index_document)
    return {
        "evidence_root": str(root),
        "bundle_id": bundle_id,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_digest,
        "index_path": str(index_path),
        "index_sha256": index_digest,
        "manifest": manifest,
        "capture_set_sha256": capture_set_digest,
        "approval_pending": True,
    }


def _fixture_manifest(
    fixture: StateFixture,
    module: Any | None = None,
) -> dict[str, Any]:
    record = asdict(fixture)
    tray = fixture.tray
    record["active_tray"] = tray is not None
    record["scan_count"] = len(tray.scanned_barcodes) if tray is not None else 0
    record["target_count"] = tray.target_count if tray is not None else 0
    record["last_normal_scan_preserved"] = bool(fixture.last_normal_scan)
    record["last_normal_scan_display"] = (
        compact_scan_value(
            fixture.last_normal_scan,
            item_code=fixture.last_normal_item_code,
        )
        if fixture.last_normal_scan
        else "-"
    )
    if module is not None:
        record["m7_assertions"] = build_m7_scene_assertions(fixture, module)
    return record


def _expected_scan_list_rows(fixture: dict[str, Any]) -> list[str]:
    """Return the exact rows the active tray should render in current UI order."""

    if not fixture.get("active_tray"):
        return []
    tray = fixture.get("tray")
    if not isinstance(tray, dict):
        return []
    barcodes = tray.get("scanned_barcodes") or ()
    item_code = tray.get("item_code") or ""
    numbered_rows = [
        format_scan_list_row(index, barcode, item_code=item_code)
        for index, barcode in enumerate(barcodes, start=1)
    ]
    return list(reversed(numbered_rows))


def build_compact_display_gate(
    fixture: dict[str, Any],
    rendered: dict[str, Any],
) -> dict[str, Any]:
    expected_rows = _expected_scan_list_rows(fixture)
    actual_rows = [str(value) for value in rendered.get("scan_list_rows") or []]
    expected_last_raw = str(fixture.get("last_normal_scan") or "")
    expected_last_display = str(fixture.get("last_normal_scan_display") or "-")
    tray = fixture.get("tray") if fixture.get("active_tray") else None
    expected_tray_raw = (
        [str(value) for value in tray.get("scanned_barcodes") or []]
        if isinstance(tray, dict)
        else []
    )
    actual_last_display = str(rendered.get("last_normal_scan_display") or "")
    checks = {
        "central_rows_exact_compact": actual_rows == expected_rows,
        "central_rows_have_no_raw_payload_delimiters": all(
            "|" not in row and "=" not in row for row in actual_rows
        ),
        "right_last_normal_exact_compact": actual_last_display == expected_last_display,
        "right_last_normal_has_no_raw_payload_delimiters": (
            "|" not in actual_last_display and "=" not in actual_last_display
        ),
        "presenter_last_normal_raw_exact": (
            str(rendered.get("presenter_last_normal_scan_raw") or "")
            == expected_last_raw
        ),
        "current_tray_raw_list_exact": (
            [str(value) for value in rendered.get("active_tray_scans_raw") or []]
            == expected_tray_raw
        ),
    }
    return {
        "gate_applicable": True,
        "expected_central_rows": expected_rows,
        "actual_central_rows": actual_rows,
        "expected_right_last_normal": expected_last_display,
        "actual_right_last_normal": actual_last_display,
        "expected_presenter_last_normal_raw": expected_last_raw,
        "expected_current_tray_raw_list": expected_tray_raw,
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_left_sidebar_gate(
    rendered: dict[str, Any],
    *,
    requested_view: str,
    compact_expected: bool,
    expected_summary_count: int = CAPTURE_SUMMARY_ROW_COUNT,
    expected_parked_count: int = CAPTURE_PARKED_ROW_COUNT,
    tray_image_expected: bool = False,
) -> dict[str, Any]:
    """Bind the state-switch label and mapped tree to deterministic rows."""

    requested_view = str(requested_view or "summary")
    expected_switch_text = (
        "현재·기록 보기"
        if requested_view == "parked"
        else f"보류 {expected_parked_count}건 보기"
    )
    actual_summary_count = rendered.get("summary_count")
    actual_parked_count = rendered.get("parked_count")
    summary_mapped = rendered.get("summary_tree_mapped") is True
    parked_mapped = rendered.get("parked_tree_mapped") is True
    compact_actual = rendered.get("compact") is True
    if compact_expected:
        expected_summary_mapped = requested_view == "summary"
        expected_parked_mapped = requested_view == "parked"
        tree_mapping_matches_mode = (
            summary_mapped is expected_summary_mapped
            and parked_mapped is expected_parked_mapped
        )
        switch_mapping_matches_mode = rendered.get("switch_mapped") is True
    else:
        expected_summary_mapped = True
        expected_parked_mapped = True
        tree_mapping_matches_mode = summary_mapped and parked_mapped
        switch_mapping_matches_mode = rendered.get("switch_mapped") is False
    checks = {
        "view_matches_request": rendered.get("view") == requested_view,
        "compact_mode_matches_policy": compact_actual is bool(compact_expected),
        "summary_count_exact": (
            isinstance(actual_summary_count, int)
            and not isinstance(actual_summary_count, bool)
            and actual_summary_count == expected_summary_count
        ),
        "parked_count_exact": (
            isinstance(actual_parked_count, int)
            and not isinstance(actual_parked_count, bool)
            and actual_parked_count == expected_parked_count
        ),
        "tray_image_request_exact": (
            rendered.get("tray_image_requested") is bool(tray_image_expected)
        ),
        "tray_image_bitmap_exact": (
            rendered.get("tray_image_has_bitmap") is bool(tray_image_expected)
        ),
        "switch_text_exact": rendered.get("switch_text") == expected_switch_text,
        "switch_mapping_matches_mode": switch_mapping_matches_mode,
        "tree_mapping_matches_mode": tree_mapping_matches_mode,
    }
    return {
        "gate_applicable": True,
        "requested_view": requested_view,
        "compact_expected": bool(compact_expected),
        "expected_switch_text": expected_switch_text,
        "expected_summary_count": expected_summary_count,
        "expected_parked_count": expected_parked_count,
        "tray_image_expected": bool(tray_image_expected),
        "expected_summary_tree_mapped": expected_summary_mapped,
        "expected_parked_tree_mapped": expected_parked_mapped,
        "actual": dict(rendered),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _append_gate_issues(
    issues: list[str],
    record: dict[str, Any],
    gate_name: str,
) -> None:
    gate = record.get(gate_name)
    if not isinstance(gate, dict):
        issues.append(f"{gate_name}_missing")
        return
    if gate.get("gate_applicable") is not True:
        issues.append(f"{gate_name}_not_applicable")
    checks = gate.get("checks")
    if not isinstance(checks, dict) or not checks:
        issues.append(f"{gate_name}_checks_missing")
    else:
        issues.extend(
            f"{gate_name}_{name}"
            for name, passed in checks.items()
            if passed is not True
        )
    if gate.get("passed") is not True and not any(
        issue.startswith(f"{gate_name}_") for issue in issues
    ):
        issues.append(f"{gate_name}_failed")


def build_m7_scene_gate(
    fixture: Mapping[str, Any],
    rendered: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify that one captured scene reflects its production-backed assertions."""

    state_id = str(fixture.get("state_id") or "")
    spec = M7_SCENE_CONTRACT.get(state_id)
    if spec is None:
        return {"gate_applicable": False, "checks": {}, "passed": True}
    assertions = fixture.get("m7_assertions")
    receipt = rendered.get("m7_scene_receipt")
    if not isinstance(assertions, Mapping) or not isinstance(receipt, Mapping):
        checks = {
            "fixture_assertions_present": isinstance(assertions, Mapping),
            "production_scene_receipt_present": isinstance(receipt, Mapping),
        }
        return {
            "gate_applicable": True,
            "state_id": state_id,
            "checks": checks,
            "passed": False,
        }
    actions_value = rendered.get("action_buttons")
    actions = actions_value if isinstance(actions_value, Mapping) else {}
    expected_disabled = list(assertions.get("expected_disabled_controls") or [])
    expected_enabled = list(assertions.get("expected_enabled_controls") or [])
    disabled_actual = {
        name: str((actions.get(name) or {}).get("state") or "")
        for name in expected_disabled
    }
    enabled_actual = {
        name: str((actions.get(name) or {}).get("state") or "")
        for name in expected_enabled
    }
    phs2 = assertions.get("exact_six_phs2") or {}
    member_set = assertions.get("member_set") or {}
    exchange = assertions.get("exchange") or {}
    direct_sync = assertions.get("direct_sync")
    production_validation = assertions.get("production_validation") or {}
    call_trace = receipt.get("production_call_trace") or {}
    call_trace_assessment = (
        validate_m7_production_call_trace(
            call_trace,
            spec["production_call_path"],
        )
        if isinstance(call_trace, Mapping)
        else {"passed": False}
    )
    variant_assertions = assertions.get("variant_assertions") or []
    expected_direct_sync_text = ""
    if isinstance(direct_sync, Mapping):
        model = direct_sync.get("card_model") or {}
        expected_direct_sync_text = (
            f"{model.get('summary', '')}\n{model.get('detail', '')}"
        )
    checks: dict[str, bool] = {
        "state_id_exact": receipt.get("state_id") == state_id,
        "production_seam_available": receipt.get("seam_available") is True,
        "production_call_path_exact": receipt.get("production_call_path")
        == list(spec["production_call_path"]),
        "production_call_trace_complete": (
            call_trace_assessment.get("passed") is True
        ),
        "production_assertions_exact": receipt.get("assertions") == assertions,
        "semantic_variants_production_validated": (
            production_validation.get("passed") is True
            and bool(variant_assertions)
            and all(
                isinstance(item, Mapping) and item.get("passed") is True
                for item in variant_assertions
            )
        ),
        "exact_six_phs2_validated": phs2.get("passed") is True,
        "member_set_validated": member_set.get("passed") is True,
        "exchange_assertion_validated": exchange.get("passed") is True,
        "input_state_exact": str(rendered.get("scan_entry_state") or "")
        == str(assertions.get("expected_input_state") or ""),
        "disabled_controls_exact": all(
            state == "disabled" for state in disabled_actual.values()
        ),
        "enabled_controls_exact": all(
            state == "normal" for state in enabled_actual.values()
        ),
        "direct_sync_card_exact": (
            not expected_direct_sync_text
            or str((rendered.get("right_texts") or {}).get("direct_sync") or "")
            == expected_direct_sync_text
        ),
    }
    notice_title = str(rendered.get("notice_title") or "")
    notice_message = str(rendered.get("notice_message") or "")
    count_text = str(rendered.get("count") or "")
    right_status = str((rendered.get("right_texts") or {}).get("status") or "")
    status_variants = list(fixture.get("status_variants") or [])
    if state_id == "m7_phs2_preflight":
        checks["preflight_progress_visible"] = "중앙 검사 완료 수량 확인 중" in str(
            rendered.get("current_item") or ""
        )
        checks["preflight_status_visible"] = bool(status_variants) and (
            notice_message == status_variants[0]
        )
    elif state_id == "m7_central_preflight_queue":
        checks["central_failure_visible"] = len(status_variants) > 2 and (
            notice_message == status_variants[2]
        )
    elif state_id == "m7_completion_busy":
        checks["completion_busy_control_visible"] = (
            str((actions.get("submit") or {}).get("text") or "") == "완료 처리 중"
        )
        checks["completion_rejection_visible"] = len(status_variants) > 1 and (
            notice_message == status_variants[1]
        )
    elif state_id == "m7_recovery_transition":
        checks["restored_status_visible"] = right_status == "복구 작업 중"
        checks["parked_recovery_row_present"] = int(
            (rendered.get("left_sidebar") or {}).get("parked_count", 0)
        ) >= 1
    elif state_id == "m7_direct_sync_backlog_ack":
        checks["current_transfer_confirmation_visible"] = (
            notice_title == "서버 이적 확인 완료"
        )
    elif state_id == "m7_exact_good_membership":
        checks["exact_member_count_visible"] = count_text == (
            f"{member_set.get('active_scan_count')} / {member_set.get('member_count')}"
        )
    elif state_id == "m7_lease_fail_closed":
        checks["lease_failure_visible"] = notice_title == "중앙 PHS=2 확인 실패"
        lease = (assertions.get("lease") or {}).get("fixture")
        checks["lease_start_blocked"] = (
            isinstance(lease, Mapping) and lease.get("start_allowed") is False
        )
    elif state_id == "m7_transfer_receipt_status":
        checks["receipt_wait_visible"] = notice_title == "서버 이적 확인 대기"
        completion_variants = (assertions.get("receipt") or {}).get(
            "completion_variants"
        ) or []
        checks["all_receipt_variants_production_presented"] = (
            [item.get("outcome") for item in completion_variants]
            == list(fixture.get("completion_variants") or [])
            and all(item.get("passed") is True for item in completion_variants)
        )
    elif state_id == "m7_partial_atomic_exchange":
        checks["partial_count_visible"] = count_text == (
            f"{member_set.get('active_scan_count')} / {member_set.get('member_count')}"
        )
        checks["partial_completion_block_visible"] = bool(status_variants) and (
            notice_message == status_variants[0]
        )
        checks["atomic_exchange_control_visible"] = (
            "현재 이적 제품 교체"
            in str((actions.get("exchange") or {}).get("text") or "")
        )
    return {
        "gate_applicable": True,
        "state_id": state_id,
        "expected_disabled_controls": expected_disabled,
        "observed_disabled_control_states": disabled_actual,
        "expected_enabled_controls": expected_enabled,
        "observed_enabled_control_states": enabled_actual,
        "checks": checks,
        "passed": all(checks.values()),
    }


def evaluate_capture(record: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    monitor_gate = record.get("monitor_gate")
    if monitor_gate is not None:
        if monitor_gate.get("gate_applicable") is not True:
            issues.append("monitor_gate_not_applicable")
        checks = monitor_gate.get("checks")
        if not isinstance(checks, dict) or not checks:
            issues.append("monitor_gate_checks_missing")
        else:
            issues.extend(
                f"monitor_gate_{name}"
                for name, passed in checks.items()
                if passed is not True
            )
        if monitor_gate.get("passed") is not True and not any(
            issue.startswith("monitor_gate_") for issue in issues
        ):
            issues.append("monitor_gate_failed")
    if "requested_scale" in record or "applied_scale_factor" in record:
        try:
            requested_scale = float(record["requested_scale"])
            applied_scale = float(record["applied_scale_factor"])
        except (KeyError, TypeError, ValueError):
            issues.append("scale_factor_not_applied")
        else:
            if not math.isclose(requested_scale, applied_scale, rel_tol=0, abs_tol=1e-9):
                issues.append("scale_factor_not_applied")
    image = record["image_analysis"]
    geometry = record["ui_geometry"]
    structure = geometry["structure"]
    if not image["pixel_size_matches"]:
        issues.append("pixel_size_mismatch")
    if image["blank_suspected"]:
        issues.append("blank_image_suspected")
    if image["near_black_ratio"] > NEAR_BLACK_FAILURE_RATIO:
        issues.append("near_black_ratio_high")
    if image.get("edge_black_stripe_suspected"):
        issues.append("edge_black_stripe_suspected")
    if image.get("contiguous_black_stripe_suspected"):
        issues.append("contiguous_black_stripe_suspected")
    if image.get("uniform_low_variance_suspected"):
        issues.append("uniform_low_variance_suspected")
    if geometry["clipping_proxy"]["suspected"]:
        issues.append("clipping_proxy_suspected")
    if not structure["central_scan_list_is_only_center_history"]:
        issues.append("center_scan_history_structure")
    if not structure["right_has_no_full_scan_history"]:
        issues.append("right_scan_history_duplicate")
    if not structure.get("right_has_no_progress_widget", False):
        issues.append("right_progress_widget_duplicate")
    if not structure.get("scan_list_frame_contract", False):
        issues.append("scan_list_frame_structure")
    if not structure["scan_list_below_notice"]:
        issues.append("scan_list_not_below_notice")
    if int(structure.get("core_action_button_count", 0)) != 4:
        issues.append("core_action_button_count")
    if not structure.get("core_action_common_parent", False):
        issues.append("core_action_parent_structure")
    if not structure.get("core_action_layout_matches", False):
        issues.append("core_action_responsive_layout")
    if structure.get("hidden_operation_buttons_mapped"):
        issues.append("secondary_operations_exposed")
    fixture = record.get("fixture") or {}
    rendered = record.get("rendered_state") or {}
    capture_gate_schema_version = int(record.get("capture_gate_schema_version", 1))
    for gate_name in (
        "focus_gate",
        "scan_list_viewport_gate",
        "compact_display_gate",
    ):
        if capture_gate_schema_version >= 2 or gate_name in record:
            _append_gate_issues(issues, record, gate_name)
    if capture_gate_schema_version >= 3 or "tree_heading_fit_gate" in record:
        _append_gate_issues(issues, record, "tree_heading_fit_gate")
    if capture_gate_schema_version >= 4 or "left_sidebar_gate" in record:
        _append_gate_issues(issues, record, "left_sidebar_gate")
    if capture_gate_schema_version >= 5 or "capture_geometry_gate" in record:
        _append_gate_issues(issues, record, "capture_geometry_gate")
    if capture_gate_schema_version >= 6 or "m7_scene_gate" in record:
        _append_gate_issues(issues, record, "m7_scene_gate")
    if rendered:
        if "requested_left_view" in record or "left_sidebar" in rendered:
            requested_left_view = str(record.get("requested_left_view") or "summary")
            if str((rendered.get("left_sidebar") or {}).get("view") or "") != requested_left_view:
                issues.append("left_sidebar_view_mismatch")
        if int(rendered.get("scan_list_row_count", -1)) != int(fixture.get("scan_count", 0)):
            issues.append("rendered_scan_count_mismatch")
        if "active_tray" in fixture:
            expected_scan_rows = _expected_scan_list_rows(fixture)
            rendered_scan_rows = [
                str(value) for value in (rendered.get("scan_list_rows") or [])
            ]
            if rendered_scan_rows != expected_scan_rows:
                issues.append("rendered_scan_rows_do_not_match_fixture")
        if rendered.get("scan_list_rows_neutral") is False:
            issues.append("scan_list_rows_not_settled")
        expected_last_scan_raw = str(fixture.get("last_normal_scan") or "")
        expected_last_scan_display = fixture.get("last_normal_scan_display")
        if expected_last_scan_display is None:
            expected_last_scan_display = expected_last_scan_raw or "-"
        rendered_last_scan_display = str(
            rendered.get("last_normal_scan_display", rendered.get("last_normal_scan")) or ""
        )
        if rendered_last_scan_display != str(expected_last_scan_display):
            issues.append("last_normal_scan_not_preserved")
        if expected_last_scan_raw:
            if str(rendered.get("presenter_last_normal_scan_raw") or "") != expected_last_scan_raw:
                issues.append("presenter_last_normal_scan_not_preserved")
            if fixture.get("active_tray") and (
                str(rendered.get("active_tray_last_scan_raw") or "") != expected_last_scan_raw
            ):
                issues.append("active_tray_last_scan_not_preserved")
            if (
                expected_last_scan_raw in rendered_last_scan_display
                or "|" in rendered_last_scan_display
                or "=" in rendered_last_scan_display
            ):
                issues.append("last_normal_scan_display_raw_leak")
        if "active_tray" in fixture:
            fixture_tray = fixture.get("tray")
            expected_active_scans_raw = (
                list(fixture_tray.get("scanned_barcodes") or [])
                if fixture.get("active_tray") and isinstance(fixture_tray, dict)
                else []
            )
            if rendered.get("active_tray_scans_raw") != expected_active_scans_raw:
                issues.append("active_tray_scans_not_preserved")
        if state_requires_scan_lock(str(record.get("state") or "")):
            if str(rendered.get("scan_entry_state")) != "disabled":
                issues.append("blocking_state_scan_entry_enabled")
            if "status_bar_text" in rendered and not str(
                rendered.get("status_bar_text") or ""
            ).startswith("스캔 중지"):
                issues.append("blocking_state_status_bar_allows_scan")
        if rendered.get("right_progress_count_texts"):
            issues.append("right_progress_count_duplicate")
    return issues


def apply_cross_capture_contracts(captures: Sequence[dict[str, Any]]) -> None:
    """Attach state-to-state invariants after one resolution matrix is rendered."""

    captures_by_size: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for capture in captures:
        size = tuple(int(value) for value in capture.get("requested_size", (0, 0)))
        captures_by_size.setdefault(size, []).append(capture)

    for size_captures in captures_by_size.values():
        if not size_captures:
            continue
        baseline_signature = size_captures[0]["ui_geometry"]["structure"].get(
            "scan_list_layout_signature"
        )
        for capture in size_captures:
            signature = capture["ui_geometry"]["structure"].get(
                "scan_list_layout_signature"
            )
            if signature != baseline_signature:
                if "scan_list_geometry_changed_across_states" not in capture["issues"]:
                    capture["issues"].append("scan_list_geometry_changed_across_states")

        by_state = {capture.get("state"): capture for capture in size_captures}
        normal = by_state.get("normal")
        duplicate = by_state.get("duplicate")
        if normal is not None and duplicate is not None:
            normal_rows = normal.get("rendered_state", {}).get("scan_list_rows", [])
            duplicate_rows = duplicate.get("rendered_state", {}).get("scan_list_rows", [])
            if duplicate_rows != normal_rows:
                duplicate["issues"].append("duplicate_scan_list_not_preserved")

        for capture in size_captures:
            capture["passed"] = not capture["issues"]


def build_roundtrip_signatures(record: dict[str, Any]) -> dict[str, Any]:
    geometry = record["ui_geometry"]
    widget_geometry: dict[str, dict[str, Any]] = {}
    for widget in geometry.get("widgets") or []:
        mapped = bool(widget.get("mapped"))
        normalized = {"mapped": mapped}
        if mapped:
            normalized.update(
                {
                    "bbox": list(widget.get("bbox") or []),
                    "size": list(widget.get("size") or []),
                }
            )
            requested_size = list(widget.get("requested_size") or [])
            checked_requested_size: dict[str, Any] = {}
            if widget.get("check_requested_width") is True:
                checked_requested_size["width"] = (
                    requested_size[0] if len(requested_size) >= 1 else None
                )
            if widget.get("check_requested_height") is True:
                checked_requested_size["height"] = (
                    requested_size[1] if len(requested_size) >= 2 else None
                )
            if checked_requested_size:
                normalized["checked_requested_size"] = checked_requested_size
        widget_geometry[str(widget["name"])] = normalized
    structure = geometry.get("structure") or {}
    geometry_signature = {
        "root_client_size": list(geometry.get("root_client_size") or []),
        "widgets": widget_geometry,
        "scan_list_layout": structure.get("scan_list_layout_signature"),
    }
    row_signature = list(record.get("rendered_state", {}).get("scan_list_rows") or [])
    action_signature = {
        "rows": structure.get("core_action_rows"),
        "buttons": record.get("rendered_state", {}).get("action_buttons"),
    }
    left_sidebar_signature = dict(
        record.get("rendered_state", {}).get("left_sidebar") or {}
    )
    widget_identity = record.get("roundtrip_widget_identity") or {}
    widget_path_signature = {
        "widget_count": widget_identity.get("widget_count"),
        "tree": widget_identity.get("tree_paths"),
        "key_widgets": widget_identity.get("key_widget_paths"),
    }
    widget_object_signature = {
        "widget_count": widget_identity.get("widget_count"),
        "tree": widget_identity.get("tree_object_ids"),
        "key_widgets": widget_identity.get("key_widget_object_ids"),
    }
    return {
        "geometry": geometry_signature,
        "rows": row_signature,
        "actions": action_signature,
        "left_sidebar": left_sidebar_signature,
        "widget_paths": widget_path_signature,
        "widget_objects": widget_object_signature,
        "widget_identity_complete": roundtrip_widget_identity_is_complete(
            widget_identity
        ),
        "geometry_sha256": hashlib.sha256(
            json.dumps(
                geometry_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "rows_sha256": hashlib.sha256(
            json.dumps(
                row_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "actions_sha256": hashlib.sha256(
            json.dumps(
                action_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "left_sidebar_sha256": hashlib.sha256(
            json.dumps(
                left_sidebar_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "widget_paths_sha256": hashlib.sha256(
            json.dumps(
                widget_path_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "widget_objects_sha256": hashlib.sha256(
            json.dumps(
                widget_object_signature,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def _stable_json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _is_int_sequence(value: object, length: int) -> bool:
    return bool(
        isinstance(value, (list, tuple))
        and len(value) == length
        and all(isinstance(item, int) and not isinstance(item, bool) for item in value)
    )


def _parity_widget_signatures(
    widgets: object,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    actual_geometry: dict[str, Any] = {}
    checked_requested_geometry: dict[str, Any] = {}
    complete = isinstance(widgets, list) and bool(widgets)
    if not isinstance(widgets, list):
        return actual_geometry, checked_requested_geometry, False

    for widget in widgets:
        if not isinstance(widget, dict):
            complete = False
            continue
        name = widget.get("name")
        if not isinstance(name, str) or not name or name in actual_geometry:
            complete = False
            continue
        mapped = widget.get("mapped")
        check_width = widget.get("check_requested_width")
        check_height = widget.get("check_requested_height")
        if not isinstance(mapped, bool):
            complete = False
            mapped = bool(mapped)
        if not isinstance(check_width, bool) or not isinstance(check_height, bool):
            complete = False

        normalized_actual: dict[str, Any] = {"mapped": mapped}
        if mapped:
            widget_class = widget.get("widget_class")
            bbox = widget.get("bbox")
            size = widget.get("size")
            if not isinstance(widget_class, str) or not widget_class:
                complete = False
            if not _is_int_sequence(bbox, 4) or not _is_int_sequence(size, 2):
                complete = False
            normalized_actual.update(
                {
                    "widget_class": widget_class,
                    "bbox": list(bbox or []),
                    "size": list(size or []),
                }
            )
        actual_geometry[name] = normalized_actual

        if mapped and (check_width is True or check_height is True):
            requested_size = widget.get("requested_size")
            if not _is_int_sequence(requested_size, 2):
                complete = False
            normalized_requested: dict[str, Any] = {}
            if check_width is True:
                normalized_requested["width"] = (
                    requested_size[0]
                    if isinstance(requested_size, (list, tuple))
                    and len(requested_size) >= 1
                    else None
                )
            if check_height is True:
                normalized_requested["height"] = (
                    requested_size[1]
                    if isinstance(requested_size, (list, tuple))
                    and len(requested_size) >= 2
                    else None
                )
            checked_requested_geometry[name] = normalized_requested

    return actual_geometry, checked_requested_geometry, complete


def _parity_text_signature(rendered_state: object) -> tuple[dict[str, Any], bool]:
    if not isinstance(rendered_state, dict):
        return {
            field: None for field in MATRIX_ROUNDTRIP_PARITY_TEXT_FIELDS
        }, False
    signature = {
        field: rendered_state.get(field)
        for field in MATRIX_ROUNDTRIP_PARITY_TEXT_FIELDS
    }
    complete = all(
        field in rendered_state for field in MATRIX_ROUNDTRIP_PARITY_TEXT_FIELDS
    )
    string_fields = MATRIX_ROUNDTRIP_PARITY_TEXT_FIELDS[:12] + (
        "scan_list_header",
    )
    complete = complete and all(
        isinstance(signature[field], str) for field in string_fields
    )
    rows = signature["scan_list_rows"]
    row_colors = signature["scan_list_row_colors"]
    row_count = signature["scan_list_row_count"]
    right_texts = signature["right_texts"]
    left_sidebar = signature["left_sidebar"]
    complete = bool(
        complete
        and isinstance(row_count, int)
        and not isinstance(row_count, bool)
        and isinstance(rows, list)
        and all(isinstance(row, str) for row in rows)
        and row_count == len(rows)
        and isinstance(row_colors, list)
        and len(row_colors) == len(rows)
        and all(
            isinstance(colors, dict)
            and isinstance(colors.get("background"), str)
            and isinstance(colors.get("foreground"), str)
            for colors in row_colors
        )
        and isinstance(signature["scan_list_rows_neutral"], bool)
        and isinstance(right_texts, dict)
        and bool(right_texts)
        and all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in right_texts.items()
        )
        and isinstance(left_sidebar, dict)
        and set(left_sidebar)
        == {
            "view",
            "compact",
            "switch_text",
            "switch_mapped",
            "summary_tree_mapped",
            "parked_tree_mapped",
            "summary_count",
            "parked_count",
            "tray_image_requested",
            "tray_image_has_bitmap",
        }
        and isinstance(left_sidebar.get("view"), str)
        and isinstance(left_sidebar.get("switch_text"), str)
        and all(
            isinstance(left_sidebar.get(field), bool)
            for field in (
                "compact",
                "switch_mapped",
                "summary_tree_mapped",
                "parked_tree_mapped",
                "tray_image_requested",
                "tray_image_has_bitmap",
            )
        )
        and all(
            isinstance(left_sidebar.get(field), int)
            and not isinstance(left_sidebar.get(field), bool)
            for field in ("summary_count", "parked_count")
        )
    )
    return signature, complete


def _parity_action_signature(
    structure: object,
    rendered_state: object,
) -> tuple[dict[str, Any], bool]:
    if not isinstance(structure, dict):
        structure = {}
    if not isinstance(rendered_state, dict):
        rendered_state = {}
    buttons = rendered_state.get("action_buttons")
    signature = {
        "button_count": structure.get("core_action_button_count"),
        "rows": structure.get("core_action_rows"),
        "expected_rows": structure.get("expected_core_action_rows"),
        "layout_matches": structure.get("core_action_layout_matches"),
        "buttons": buttons,
    }
    rows = signature["rows"]
    expected_rows = signature["expected_rows"]

    def rows_are_complete(value: object) -> bool:
        return bool(
            isinstance(value, list)
            and value
            and all(
                isinstance(row, list)
                and row
                and all(isinstance(name, str) and name for name in row)
                for row in value
            )
        )

    complete = bool(
        signature["button_count"] == len(MATRIX_ROUNDTRIP_ACTION_NAMES)
        and rows_are_complete(rows)
        and rows_are_complete(expected_rows)
        and isinstance(signature["layout_matches"], bool)
        and isinstance(buttons, dict)
        and set(buttons) == MATRIX_ROUNDTRIP_ACTION_NAMES
        and all(
            isinstance(button, dict)
            and isinstance(button.get("text"), str)
            and isinstance(button.get("state"), str)
            for button in buttons.values()
        )
    )
    return signature, complete


def build_matrix_roundtrip_parity_signatures(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Build path-independent signatures for matrix/roundtrip parity."""

    requested_size = record.get("requested_size")
    geometry = record.get("ui_geometry")
    if not isinstance(geometry, dict):
        geometry = {}
    root_client_size = geometry.get("root_client_size")
    actual_widgets, requested_widgets, widgets_complete = (
        _parity_widget_signatures(geometry.get("widgets"))
    )
    structure = geometry.get("structure")
    if not isinstance(structure, dict):
        structure = {}
    scan_layout = structure.get("scan_list_layout_signature")
    if not isinstance(scan_layout, dict):
        scan_layout = {}
    normalized_scan_layout = {
        field: scan_layout.get(field)
        for field in MATRIX_ROUNDTRIP_SCAN_LAYOUT_FIELDS
    }
    scan_layout_complete = all(
        field in scan_layout
        and isinstance(scan_layout.get(field), dict)
        and bool(scan_layout.get(field))
        for field in MATRIX_ROUNDTRIP_SCAN_LAYOUT_FIELDS
    )
    geometry_signature = {
        "root_client_size": list(root_client_size or []),
        "widgets": actual_widgets,
        "scan_list_layout": normalized_scan_layout,
        "scan_list_frame_contract": structure.get("scan_list_frame_contract"),
    }
    requested_signature = {"widgets": requested_widgets}
    text_signature, text_complete = _parity_text_signature(
        record.get("rendered_state")
    )
    action_signature, actions_complete = _parity_action_signature(
        structure,
        record.get("rendered_state"),
    )
    completeness_checks = {
        "requested_size_valid": _is_int_sequence(requested_size, 2),
        "root_client_size_valid": _is_int_sequence(root_client_size, 2),
        "root_matches_requested_size": (
            _is_int_sequence(requested_size, 2)
            and _is_int_sequence(root_client_size, 2)
            and list(root_client_size) == list(requested_size)
        ),
        "widget_records_complete": widgets_complete,
        "scan_list_layout_complete": scan_layout_complete,
        "scan_list_frame_contract_present": isinstance(
            structure.get("scan_list_frame_contract"), bool
        ),
        "text_fields_complete": text_complete,
        "action_fields_complete": actions_complete,
    }
    return {
        "schema_version": 1,
        "geometry": geometry_signature,
        "requested": requested_signature,
        "text": text_signature,
        "actions": action_signature,
        "completeness_checks": completeness_checks,
        "complete": all(completeness_checks.values()),
        "geometry_sha256": _stable_json_sha256(geometry_signature),
        "requested_sha256": _stable_json_sha256(requested_signature),
        "text_sha256": _stable_json_sha256(text_signature),
        "actions_sha256": _stable_json_sha256(action_signature),
    }


def roundtrip_widget_identity_is_complete(identity: object) -> bool:
    if not isinstance(identity, dict):
        return False
    widget_count = identity.get("widget_count")
    tree_paths = identity.get("tree_paths")
    tree_object_ids = identity.get("tree_object_ids")
    key_widget_paths = identity.get("key_widget_paths")
    key_widget_object_ids = identity.get("key_widget_object_ids")
    if not isinstance(widget_count, int) or isinstance(widget_count, bool):
        return False
    if widget_count <= 0:
        return False
    if not isinstance(tree_paths, list) or len(tree_paths) != widget_count:
        return False
    if not isinstance(tree_object_ids, list) or len(tree_object_ids) != widget_count:
        return False
    if not isinstance(key_widget_paths, dict) or not isinstance(
        key_widget_object_ids, dict
    ):
        return False
    expected_keys = set(ROUNDTRIP_KEY_WIDGET_ATTRS)
    if set(key_widget_paths) != expected_keys:
        return False
    if set(key_widget_object_ids) != expected_keys:
        return False

    path_records: dict[str, dict[str, Any]] = {}
    for record in tree_paths:
        if not isinstance(record, dict):
            return False
        path = record.get("path")
        if not isinstance(path, str) or not path or path in path_records:
            return False
        if not isinstance(record.get("master_path"), str):
            return False
        if not isinstance(record.get("widget_class"), str) or not record.get(
            "widget_class"
        ):
            return False
        path_records[path] = record

    object_ids_by_path: dict[str, int] = {}
    for record in tree_object_ids:
        if not isinstance(record, dict):
            return False
        path = record.get("path")
        object_id = record.get("python_object_id")
        if not isinstance(path, str) or not path or path in object_ids_by_path:
            return False
        if not isinstance(object_id, int) or isinstance(object_id, bool):
            return False
        object_ids_by_path[path] = object_id
    if set(object_ids_by_path) != set(path_records):
        return False

    for attr in ROUNDTRIP_KEY_WIDGET_ATTRS:
        path = key_widget_paths.get(attr)
        object_id = key_widget_object_ids.get(attr)
        if not isinstance(path, str) or path not in path_records:
            return False
        if not isinstance(object_id, int) or isinstance(object_id, bool):
            return False
        if object_ids_by_path[path] != object_id:
            return False
    return True


def collect_roundtrip_widget_identity(app: Any) -> dict[str, Any]:
    """Bind roundtrip evidence to the exact live Tk widget objects and paths."""

    tree_paths: list[dict[str, Any]] = []
    tree_object_ids: list[dict[str, Any]] = []

    def visit(widget: Any) -> None:
        path = str(widget)
        master = getattr(widget, "master", None)
        try:
            widget_class = str(widget.winfo_class())
            children = tuple(widget.winfo_children())
        except Exception as exc:
            raise RuntimeError(
                f"roundtrip widget identity collection failed for {path}: {exc}"
            ) from exc
        tree_paths.append(
            {
                "path": path,
                "master_path": str(master) if master is not None else "",
                "widget_class": widget_class,
            }
        )
        tree_object_ids.append(
            {
                "path": path,
                "python_object_id": id(widget),
            }
        )
        for child in children:
            visit(child)

    visit(app.root)
    tree_paths.sort(key=lambda item: item["path"])
    tree_object_ids.sort(key=lambda item: item["path"])

    key_widget_paths: dict[str, str] = {}
    key_widget_object_ids: dict[str, int] = {}
    for attr in ROUNDTRIP_KEY_WIDGET_ATTRS:
        widget = getattr(app, attr, None)
        if widget is None:
            raise RuntimeError(f"roundtrip key widget missing: {attr}")
        key_widget_paths[attr] = str(widget)
        key_widget_object_ids[attr] = id(widget)

    return {
        "widget_count": len(tree_paths),
        "tree_paths": tree_paths,
        "tree_object_ids": tree_object_ids,
        "key_widget_paths": key_widget_paths,
        "key_widget_object_ids": key_widget_object_ids,
    }


def apply_roundtrip_contracts(captures: Sequence[dict[str, Any]]) -> None:
    roundtrip = [
        capture
        for capture in captures
        if capture.get("capture_sequence") == "roundtrip"
    ]
    if not roundtrip:
        return
    ordinals = sorted({int(capture["sequence_ordinal"]) for capture in roundtrip})
    first_ordinal, last_ordinal = ordinals[0], ordinals[-1]
    first_by_state = {
        str(capture["state"]): capture
        for capture in roundtrip
        if int(capture["sequence_ordinal"]) == first_ordinal
    }
    last_by_state = {
        str(capture["state"]): capture
        for capture in roundtrip
        if int(capture["sequence_ordinal"]) == last_ordinal
    }
    for state, first in first_by_state.items():
        last = last_by_state.get(state)
        if last is None:
            first["issues"].append("roundtrip_final_state_missing")
            first["passed"] = False
            continue
        first_signatures = first["roundtrip_signatures"]
        last_signatures = last["roundtrip_signatures"]
        state_roundtrip = sorted(
            (
                capture
                for capture in roundtrip
                if str(capture.get("state")) == state
            ),
            key=lambda capture: int(capture["sequence_ordinal"]),
        )
        ordinal_signatures = [
            capture.get("roundtrip_signatures") or {}
            for capture in state_roundtrip
        ]
        widget_identity_payload_complete = all(
            signature.get("widget_identity_complete") is True
            for signature in ordinal_signatures
        )
        checks = {
            "first_ordinal_rebuilt": (
                first.get("roundtrip_rebuild_applied") is True
            ),
            "later_ordinals_not_rebuilt": all(
                capture.get("roundtrip_rebuild_applied") is False
                for capture in state_roundtrip[1:]
            ),
            "widget_identity_payload_complete": widget_identity_payload_complete,
            "widget_path_signature_stable": (
                widget_identity_payload_complete
                and all(
                    signature.get("widget_paths")
                    == first_signatures.get("widget_paths")
                    for signature in ordinal_signatures
                )
            ),
            "widget_identity_signature_stable": (
                widget_identity_payload_complete
                and all(
                    signature.get("widget_objects")
                    == first_signatures.get("widget_objects")
                    for signature in ordinal_signatures
                )
            ),
            "compact_size_exact": first.get("requested_size") == last.get("requested_size"),
            "geometry_signature_exact": (
                first_signatures["geometry"] == last_signatures["geometry"]
            ),
            "row_signature_exact": first_signatures["rows"] == last_signatures["rows"],
            "action_signature_exact": (
                first_signatures["actions"] == last_signatures["actions"]
            ),
            "left_sidebar_signature_exact": (
                first_signatures["left_sidebar"]
                == last_signatures["left_sidebar"]
            ),
        }
        last["roundtrip_comparison_gate"] = {
            "gate_applicable": True,
            "first_ordinal": first_ordinal,
            "last_ordinal": last_ordinal,
            "state": state,
            "first_signature_hashes": {
                key: value
                for key, value in first_signatures.items()
                if key.endswith("_sha256")
            },
            "last_signature_hashes": {
                key: value
                for key, value in last_signatures.items()
                if key.endswith("_sha256")
            },
            "ordinal_widget_identity_hashes": [
                {
                    "ordinal": int(capture["sequence_ordinal"]),
                    "widget_paths_sha256": signature.get("widget_paths_sha256"),
                    "widget_objects_sha256": signature.get("widget_objects_sha256"),
                }
                for capture, signature in zip(state_roundtrip, ordinal_signatures)
            ],
            "checks": checks,
            "passed": all(checks.values()),
        }
        last["issues"].extend(
            f"roundtrip_{name}" for name, passed in checks.items() if passed is not True
        )
        last["passed"] = not last["issues"]


def apply_matrix_roundtrip_parity_contracts(
    captures: Sequence[dict[str, Any]],
) -> None:
    """Require every roundtrip frame to equal its matrix size/state baseline."""

    matrix_by_key: dict[tuple[tuple[int, ...], str], list[dict[str, Any]]] = {}
    for capture in captures:
        if capture.get("capture_sequence") != "matrix":
            continue
        size = capture.get("requested_size")
        normalized_size = (
            tuple(size) if isinstance(size, (list, tuple)) else tuple()
        )
        key = (normalized_size, str(capture.get("state")))
        matrix_by_key.setdefault(key, []).append(capture)

    issue_prefix = "matrix_roundtrip_parity_"
    for roundtrip in captures:
        if roundtrip.get("capture_sequence") != "roundtrip":
            continue
        size = roundtrip.get("requested_size")
        normalized_size = (
            tuple(size) if isinstance(size, (list, tuple)) else tuple()
        )
        state = str(roundtrip.get("state"))
        matches = matrix_by_key.get((normalized_size, state), [])
        matrix = matches[0] if len(matches) == 1 else None
        roundtrip_signatures = build_matrix_roundtrip_parity_signatures(roundtrip)
        matrix_signatures = (
            build_matrix_roundtrip_parity_signatures(matrix)
            if matrix is not None
            else None
        )
        matrix_complete = bool(
            matrix_signatures and matrix_signatures.get("complete") is True
        )
        roundtrip_complete = roundtrip_signatures.get("complete") is True
        signatures_complete = matrix_complete and roundtrip_complete
        checks = {
            "matrix_capture_unique": len(matches) == 1,
            "matrix_signature_complete": matrix_complete,
            "roundtrip_signature_complete": roundtrip_complete,
            "geometry_signature_exact": bool(
                signatures_complete
                and matrix_signatures["geometry"] == roundtrip_signatures["geometry"]
            ),
            "requested_signature_exact": bool(
                signatures_complete
                and matrix_signatures["requested"]
                == roundtrip_signatures["requested"]
            ),
            "text_signature_exact": bool(
                signatures_complete
                and matrix_signatures["text"] == roundtrip_signatures["text"]
            ),
            "action_signature_exact": bool(
                signatures_complete
                and matrix_signatures["actions"] == roundtrip_signatures["actions"]
            ),
        }
        roundtrip["matrix_roundtrip_parity_gate"] = {
            "gate_applicable": True,
            "signature_schema_version": 1,
            "state": state,
            "requested_size": list(normalized_size),
            "sequence_ordinal": roundtrip.get("sequence_ordinal"),
            "matching_matrix_capture_count": len(matches),
            "matching_matrix_capture_ids": [
                capture.get("id") for capture in matches
            ],
            "matrix_signature_hashes": (
                {
                    key: value
                    for key, value in matrix_signatures.items()
                    if key.endswith("_sha256")
                }
                if matrix_signatures is not None
                else None
            ),
            "roundtrip_signature_hashes": {
                key: value
                for key, value in roundtrip_signatures.items()
                if key.endswith("_sha256")
            },
            "matrix_completeness_checks": (
                matrix_signatures.get("completeness_checks")
                if matrix_signatures is not None
                else None
            ),
            "roundtrip_completeness_checks": roundtrip_signatures.get(
                "completeness_checks"
            ),
            "checks": checks,
            "passed": all(checks.values()),
        }
        roundtrip["issues"] = [
            issue
            for issue in roundtrip.get("issues", [])
            if not str(issue).startswith(issue_prefix)
        ]
        roundtrip["issues"].extend(
            f"{issue_prefix}{name}"
            for name, passed in checks.items()
            if passed is not True
        )
        roundtrip["passed"] = not roundtrip["issues"]


def build_isolated_app_settings(scale: object = DEFAULT_SCALE) -> dict[str, Any]:
    """Return the only settings allowed for an isolated visual capture."""

    return {
        "scale_factor": parse_scale(scale),
        "enable_internal_test_commands": False,
    }


class CaptureMutationBlocked(RuntimeError):
    pass


MUTATION_GUARD_APP_METHODS: dict[str, tuple[str, ...]] = {
    "barcode": (
        "process_barcode",
        "_process_barcode_logic",
    ),
    "event_write": (
        "_log_event",
        "_event_log_writer",
    ),
    "state_write": (
        "save_settings",
        "_save_best_time_records",
        "_update_best_time_records",
        "_save_current_tray_state",
        "_save_tray_state_snapshot",
        "_delete_current_tray_state",
        "_quarantine_current_tray_state",
    ),
    "completion": (
        "complete_tray",
        "submit_current_tray",
        "_complete_current_tray_as_partial",
    ),
    "transfer_seal": (
        "_prepare_and_attempt_transfer_seal",
        "_retry_pending_transfer_seals",
    ),
    "direct_sync": ("_trigger_session_direct_sync",),
    "worker_write": (
        "_register_worker_name",
        "_ensure_worker_login_name",
        "register_worker_from_login",
        "start_work",
        "change_worker",
    ),
    "parked_write": (
        "park_current_tray",
        "restore_parked_tray",
    ),
}


MUTATION_GUARD_NESTED_METHODS: tuple[
    tuple[str, str, tuple[str, ...]], ...
] = (
    ("worker_write", "worker_registry", ("_write_payload", "register", "mark_recent")),
    ("parked_write", "parked_tray_store", ("save_state", "delete")),
    (
        "transfer_seal",
        "transfer_seal_coordinator",
        ("prepare", "attempt", "drain_pending"),
    ),
    (
        "transfer_seal",
        "transfer_seal_coordinator.store",
        (
            "prepare",
            "bind_command",
            "record_error",
            "record_receipt",
            "record_exchange_block",
        ),
    ),
    ("event_write", "log_queue", ("put",)),
)


MUTATION_GUARD_MODULE_METHODS: dict[str, tuple[str, ...]] = {
    "event_write": ("append_event_log_entry",),
    "state_write": ("atomic_write_json",),
    "parked_write": ("quarantine_tray_state_file",),
    "direct_sync": (
        "start_session_direct_sync",
        "start_direct_sync_auto_bootstrap",
    ),
}


def _resolve_attribute_path(owner: Any, path: str) -> Any:
    current = owner
    for part in path.split("."):
        if not hasattr(current, part):
            raise RuntimeError(f"capture mutation guard target missing: {path}")
        current = getattr(current, part)
    return current


class CaptureMutationGuard:
    """Fail closed if isolated visual fixtures enter any business write path."""

    def __init__(self, app: Any, module: Any):
        self.app = app
        self.module = module
        self.armed = False
        self._originals: list[tuple[Any, str, Any]] = []
        self._protected: list[dict[str, str]] = []
        self._calls: list[dict[str, Any]] = []

    def _specs(self) -> list[tuple[str, str, Any, str]]:
        specs: list[tuple[str, str, Any, str]] = []
        for category, method_names in MUTATION_GUARD_APP_METHODS.items():
            specs.extend(
                (category, f"app.{name}", self.app, name) for name in method_names
            )
        for category, owner_path, method_names in MUTATION_GUARD_NESTED_METHODS:
            owner = _resolve_attribute_path(self.app, owner_path)
            specs.extend(
                (category, f"app.{owner_path}.{name}", owner, name)
                for name in method_names
            )
        for category, method_names in MUTATION_GUARD_MODULE_METHODS.items():
            specs.extend(
                (category, f"module.{name}", self.module, name)
                for name in method_names
            )
        return specs

    def arm(self) -> None:
        if self.armed:
            raise RuntimeError("capture mutation guard is already armed")
        specs = self._specs()
        missing = [
            label
            for _category, label, owner, name in specs
            if not callable(getattr(owner, name, None))
        ]
        if missing:
            raise RuntimeError(
                "capture mutation guard setup failed; missing callable targets: "
                + ", ".join(sorted(missing))
            )
        for category, label, owner, name in specs:
            original = getattr(owner, name)

            @functools.wraps(original)
            def blocked(*args: Any, __category=category, __label=label, **kwargs: Any):
                call = {
                    "category": __category,
                    "target": __label,
                    "positional_argument_count": len(args),
                    "keyword_names": sorted(str(key) for key in kwargs),
                }
                self._calls.append(call)
                raise CaptureMutationBlocked(
                    f"capture mutation blocked: {__category} {__label}"
                )

            self._originals.append((owner, name, original))
            setattr(owner, name, blocked)
            self._protected.append({"category": category, "target": label})
        self.armed = True

    def restore(self) -> None:
        for owner, name, original in reversed(self._originals):
            setattr(owner, name, original)
        self._originals.clear()
        self.armed = False

    def manifest(self) -> dict[str, Any]:
        protected_counts: dict[str, int] = {}
        call_counts: dict[str, int] = {}
        for item in self._protected:
            category = item["category"]
            protected_counts[category] = protected_counts.get(category, 0) + 1
        for item in self._calls:
            category = item["category"]
            call_counts[category] = call_counts.get(category, 0) + 1
        checks = {
            "guard_was_armed": bool(self._protected),
            "all_required_targets_protected": (
                len(self._protected)
                == sum(len(names) for names in MUTATION_GUARD_APP_METHODS.values())
                + sum(len(names) for _category, _owner, names in MUTATION_GUARD_NESTED_METHODS)
                + sum(len(names) for names in MUTATION_GUARD_MODULE_METHODS.values())
            ),
            "no_guarded_mutation_calls": not self._calls,
        }
        return {
            "gate_applicable": True,
            "armed": self.armed,
            "protected_targets": list(self._protected),
            "protected_target_counts_by_category": protected_counts,
            "total_protected_target_count": len(self._protected),
            "blocked_calls": list(self._calls),
            "blocked_call_counts_by_category": call_counts,
            "total_blocked_call_count": len(self._calls),
            "checks": checks,
            "passed": all(checks.values()),
        }


def inventory_isolated_data(data_root: Path) -> dict[str, Any]:
    resolved = data_root.resolve()
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted((item for item in resolved.rglob("*") if item.is_file())):
        size = path.stat().st_size
        relative_path = str(path.relative_to(resolved)).replace("\\", "/")
        file_hash = _sha256(path)
        files.append(
            {
                "path": relative_path,
                "size_bytes": size,
                "sha256": file_hash,
            }
        )
        total_bytes += size
    digest = hashlib.sha256()
    for item in files:
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item["size_bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    return {
        "root": str(resolved),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "inventory_sha256": digest.hexdigest(),
        "files": files,
    }


def build_isolated_data_gate(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "file_count_unchanged": before.get("file_count") == after.get("file_count"),
        "total_bytes_unchanged": before.get("total_bytes") == after.get("total_bytes"),
        "inventory_hash_unchanged": (
            before.get("inventory_sha256") == after.get("inventory_sha256")
        ),
        "file_inventory_exact": before.get("files") == after.get("files"),
    }
    return {
        "gate_applicable": True,
        "before": before,
        "after": after,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _make_capture_app(module: Any, scale: object = DEFAULT_SCALE) -> Any:
    isolated_settings = build_isolated_app_settings(scale)

    class CaptureContainerAudit(module.ContainerAudit):
        def _setup_paths_and_dirs(self) -> None:
            super()._setup_paths_and_dirs()
            isolated_root = Path(self.data_root)
            self.config_folder = str(isolated_root / "config")
            self.parked_trays_dir = str(isolated_root / "parked_trays")
            Path(self.config_folder).mkdir(parents=True, exist_ok=True)
            Path(self.parked_trays_dir).mkdir(parents=True, exist_ok=True)
            settings_path = Path(self.config_folder) / self.SETTINGS_FILE
            settings_path.write_text(
                json.dumps(isolated_settings, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.capture_settings_path = settings_path
            fixture_session = module.TraySession(
                master_label_code=CAPTURE_EXACT_SIX_PHS2,
                item_code="AAA2270730100",
                item_name="캡처 보류 트레이",
                item_spec="M7 recovery state",
                scanned_barcodes=[_products(1)[0]],
                scan_times=[dt.datetime(2026, 7, 19, 9, 0, 0)],
                tray_size=3,
                canonical_input_tag_qr=CAPTURE_EXACT_SIX_PHS2,
                active_label_qr_payload=CAPTURE_ACTIVE_EXACT_SIX_PHS2,
                active_label_id="LBL-M7-CONTAINER-0002",
                active_label_business_date="2026-09-03",
                active_label_worker_code="capture-worker",
                operation_lease_id="LEASE-M7-CONTAINER-PARKED-0001",
            )
            fixture_state = module.tray_session_to_state(
                fixture_session,
                worker_name="캡처 작업자",
            )
            self.capture_parked_fixture_path = (
                Path(self.parked_trays_dir) / "parked_capture_fixture.json"
            )
            module.atomic_write_json(
                self.capture_parked_fixture_path,
                fixture_state,
                indent=4,
                ensure_ascii=False,
            )

    return CaptureContainerAudit()


def _load_app_module() -> Any:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import Container_Audit as module

    return module


def _cancel_runtime_jobs(app: Any) -> None:
    for name in (
        "clock_job",
        "stopwatch_job",
        "idle_check_job",
        "focus_return_job",
        "status_message_job",
        "_scanned_listbox_layout_job",
        "_responsive_style_refresh_job",
        "_notice_message_wrap_job",
    ):
        job = getattr(app, name, None)
        if not job:
            continue
        try:
            app.root.after_cancel(job)
        except Exception:
            pass
        setattr(app, name, None)


def _align_tk_client_to_rect(root: Any, requested_rect: Rect) -> None:
    """Compensate for window chrome so the Tk client uses the requested rect."""

    requested_left, requested_top, requested_right, requested_bottom = requested_rect
    width = requested_right - requested_left
    height = requested_bottom - requested_top
    frame_left = requested_left
    frame_top = requested_top
    for _attempt in range(3):
        root.geometry(_format_tk_geometry(width, height, frame_left, frame_top))
        pump_tk(root, 140)
        actual_left = int(root.winfo_rootx())
        actual_top = int(root.winfo_rooty())
        delta_left = requested_left - actual_left
        delta_top = requested_top - actual_top
        if delta_left == 0 and delta_top == 0:
            break
        frame_left += delta_left
        frame_top += delta_top


def _configure_size(
    app: Any,
    size: tuple[int, int],
    monitor_target: MonitorTarget | None = None,
    *,
    rebuild_validation_screen: bool = True,
) -> dict[str, Any]:
    width, height = size
    app.root.state("normal")
    if monitor_target is None:
        app.root.geometry(f"{width}x{height}+0+0")
    else:
        app.root.geometry(monitor_target.tk_geometry(size))
    app.root.attributes("-topmost", True)
    app.root.deiconify()
    app.root.lift()
    pump_tk(app.root, 260)
    app.apply_scaling()
    if rebuild_validation_screen:
        app.show_validation_screen()
    else:
        _settle_validation_layout_in_place(app)
    pump_tk(app.root, 420)
    if monitor_target is not None:
        _align_tk_client_to_rect(
            app.root,
            monitor_target.requested_client_rect(size),
        )
    _settle_validation_layout_in_place(app)
    _cancel_runtime_jobs(app)
    return {
        "validation_screen_rebuilt": rebuild_validation_screen,
    }


def _settle_validation_layout_in_place(app: Any) -> None:
    """Settle responsive styles and geometry without replacing live widgets."""

    for _attempt in range(2):
        app.root.update_idletasks()
        app._clamp_paned_sashes_to_width()
        app._apply_scanned_listbox_layout()
        pump_tk(app.root, 140)


def _configure_roundtrip_size(
    app: Any,
    size: tuple[int, int],
    sequence_ordinal: int,
    monitor_target: MonitorTarget | None = None,
) -> dict[str, Any]:
    if sequence_ordinal < 1:
        raise ValueError("roundtrip sequence ordinal must be positive")
    return _configure_size(
        app,
        size,
        monitor_target,
        rebuild_validation_screen=sequence_ordinal == 1,
    )


def run_capture_matrix(
    *,
    output_root: Path,
    sizes: Sequence[tuple[int, int]],
    state_ids: Sequence[str],
    scale: object = DEFAULT_SCALE,
    monitor_device: str = "",
    roundtrip_sizes: Sequence[tuple[int, int]] = (),
    left_view: str = "summary",
) -> tuple[Path, dict[str, Any]]:
    requested_scale = parse_scale(scale)
    requested_left_view = str(left_view or "summary").strip().lower()
    if requested_left_view not in {"summary", "parked"}:
        raise ValueError("left_view must be 'summary' or 'parked'")
    isolated_settings = build_isolated_app_settings(requested_scale)
    all_requested_sizes = tuple(sizes) + tuple(roundtrip_sizes)
    monitor_target = (
        resolve_monitor_target(monitor_device, all_requested_sizes)
        if str(monitor_device or "").strip()
        else None
    )
    monitor_preflight = (
        monitor_preflight_manifest(monitor_target, all_requested_sizes)
        if monitor_target is not None
        else {
            "gate_applicable": False,
            "selection_mode": "legacy_default_origin",
            "requested_device_name": None,
            "passed": True,
        }
    )
    if monitor_target is not None and monitor_preflight["passed"] is not True:
        raise RuntimeError("selected monitor failed capture preflight")
    resolved_output = create_new_capture_output_root(output_root)
    screenshot_root = resolved_output / "screenshots"
    screenshot_root.mkdir(parents=True, exist_ok=True)
    data_root = resolved_output / "_isolated_data"
    geometry = (
        monitor_target.tk_geometry(sizes[0])
        if monitor_target is not None
        else f"{sizes[0][0]}x{sizes[0][1]}+0+0"
    )
    guards = prepare_isolated_environment(data_root, geometry)
    dpi_mode = enable_per_monitor_dpi_awareness()
    module = _load_app_module()
    m7_scene_seams = inspect_m7_production_scene_seams(module)
    fixtures_by_id = {fixture.state_id: fixture for fixture in build_state_fixtures()}

    manifest: dict[str, Any] = {
        "schema_version": 6,
        "tool": "tools/capture_container_operator_ui.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
        "repository_root": str(ROOT),
        "output_root": str(resolved_output),
        "data_root": str(data_root.resolve()),
        "isolation_guards": guards,
        "dpi_awareness": dpi_mode,
        "requested_sizes": [[width, height] for width, height in sizes],
        "roundtrip_sizes": [
            [width, height] for width, height in roundtrip_sizes
        ],
        "requested_states": list(state_ids),
        "requested_scale": requested_scale,
        "requested_left_view": requested_left_view,
        "isolated_app_settings": isolated_settings,
        "monitor_preflight": monitor_preflight,
        "near_black_failure_ratio": NEAR_BLACK_FAILURE_RATIO,
        "external_bundle_contract_reference": M7_CANONICAL_CONTRACT_PATH,
        "m7_production_scene_seams": m7_scene_seams,
        "captures": [],
    }

    app = None
    mutation_guard: CaptureMutationGuard | None = None
    isolated_data_before: dict[str, Any] | None = None
    isolated_data_after: dict[str, Any] | None = None
    try:
        app = _make_capture_app(module, requested_scale)
        measured_capture_dpi = measure_tk_dpi(app.root)
        isolated_data_before = inventory_isolated_data(data_root)
        mutation_guard = CaptureMutationGuard(app, module)
        mutation_guard.arm()
        manifest["applied_scale_factor"] = float(app.scale_factor)
        settings_path = Path(app.capture_settings_path).resolve()
        manifest["isolated_settings_path"] = str(
            settings_path.relative_to(resolved_output)
        ).replace("\\", "/")
        app.worker_name = "캡처 작업자"

        def capture_sequence_item(
            size: tuple[int, int],
            *,
            capture_sequence: str,
            sequence_ordinal: int | None = None,
        ) -> None:
            if capture_sequence == "roundtrip":
                if sequence_ordinal is None:
                    raise RuntimeError("roundtrip capture requires an ordinal")
                size_configuration = _configure_roundtrip_size(
                    app,
                    size,
                    sequence_ordinal,
                    monitor_target,
                )
                size_dir = (
                    screenshot_root
                    / "roundtrip"
                    / f"{sequence_ordinal:03d}_{size[0]}x{size[1]}"
                )
            else:
                size_configuration = _configure_size(
                    app,
                    size,
                    monitor_target,
                    rebuild_validation_screen=True,
                )
                size_dir = screenshot_root / f"{size[0]}x{size[1]}"
            size_dir.mkdir(parents=True, exist_ok=True)
            for state_id in state_ids:
                fixture = fixtures_by_id[state_id]
                apply_state_fixture(app, fixture, module)
                app._show_left_sidebar_view(requested_left_view)
                pump_tk(app.root, 260)
                path = size_dir / f"{state_id}.png"
                frame = capture_and_save_focus_verified_tk_client(
                    app,
                    state_id,
                    path,
                    expected_row_count=(
                        len(fixture.tray.scanned_barcodes)
                        if fixture.tray is not None
                        else 0
                    ),
                    monitor_target=monitor_target,
                    requested_size=size,
                )
                image = frame["image"]
                source = frame["source"]
                focus_gate = frame["focus_gate"]
                viewport_gate = frame["scan_list_viewport_gate"]
                monitor_gate = frame["monitor_gate"]
                geometry_record = frame["ui_geometry"]
                rendered_state = frame["rendered_state"]
                tree_heading_fit_gate = frame["tree_heading_fit_gate"]
                capture_geometry_gate = frame["capture_geometry_gate"]
                fixture_manifest = _fixture_manifest(fixture, module)
                record_id = f"{size[0]}x{size[1]}-{state_id}"
                if capture_sequence == "roundtrip":
                    record_id = f"roundtrip-{sequence_ordinal:03d}-{record_id}"
                record = {
                    "id": record_id,
                    "state": state_id,
                    "state_label": fixture.state_label,
                    "capture_sequence": capture_sequence,
                    "sequence_ordinal": sequence_ordinal,
                    "requested_size": [size[0], size[1]],
                    "requested_scale": requested_scale,
                    "requested_left_view": requested_left_view,
                    "measured_capture_dpi": measured_capture_dpi,
                    "applied_scale_factor": float(app.scale_factor),
                    "capture_gate_schema_version": 6,
                    "path": str(path.relative_to(resolved_output)).replace("\\", "/"),
                    "capture_source": source,
                    "sha256": _sha256(path),
                    "file_size_bytes": path.stat().st_size,
                    "fixture": fixture_manifest,
                    "image_analysis": analyze_image(image, size),
                    "ui_geometry": geometry_record,
                    "rendered_state": rendered_state,
                    "focus_gate": focus_gate,
                    "scan_list_viewport_gate": viewport_gate,
                    "tree_heading_fit_gate": tree_heading_fit_gate,
                    "capture_geometry_gate": capture_geometry_gate,
                    "left_sidebar_gate": build_left_sidebar_gate(
                        rendered_state["left_sidebar"],
                        requested_view=requested_left_view,
                        compact_expected=bool(
                            tree_heading_fit_gate.get("compact_mode")
                        ),
                        tray_image_expected=bool(fixture.tray_image_visible),
                    ),
                    "compact_display_gate": build_compact_display_gate(
                        fixture_manifest,
                        rendered_state,
                    ),
                    "m7_scene_gate": build_m7_scene_gate(
                        fixture_manifest,
                        rendered_state,
                    ),
                }
                if monitor_gate is not None:
                    record["monitor_gate"] = monitor_gate
                if capture_sequence == "roundtrip":
                    record["roundtrip_rebuild_applied"] = bool(
                        size_configuration["validation_screen_rebuilt"]
                    )
                    record["roundtrip_widget_identity"] = (
                        collect_roundtrip_widget_identity(app)
                    )
                    record["roundtrip_signatures"] = build_roundtrip_signatures(record)
                record["issues"] = evaluate_capture(record)
                record["passed"] = not record["issues"]
                manifest["captures"].append(record)

        for size in sizes:
            capture_sequence_item(size, capture_sequence="matrix")
        for ordinal, size in enumerate(roundtrip_sizes, start=1):
            capture_sequence_item(
                size,
                capture_sequence="roundtrip",
                sequence_ordinal=ordinal,
            )
    finally:
        if app is not None:
            _cancel_runtime_jobs(app)
            if isolated_data_before is not None:
                isolated_data_after = inventory_isolated_data(data_root)
            if mutation_guard is not None:
                manifest["mutation_guard"] = mutation_guard.manifest()
                mutation_guard.restore()
            try:
                app.root.attributes("-topmost", False)
            except Exception:
                pass
            try:
                app.root.destroy()
            except Exception:
                pass

    if isolated_data_before is None or isolated_data_after is None:
        raise RuntimeError("isolated data inventory was not completed")
    manifest["isolated_data_gate"] = build_isolated_data_gate(
        isolated_data_before,
        isolated_data_after,
    )

    captures = manifest["captures"]
    first_scene_receipts: dict[str, Mapping[str, Any]] = {}
    for capture in captures:
        state_id = str(capture.get("state") or "")
        receipt = (capture.get("rendered_state") or {}).get(
            "m7_scene_receipt"
        )
        if state_id not in first_scene_receipts and isinstance(receipt, Mapping):
            first_scene_receipts[state_id] = receipt
    m7_scene_seams = inspect_m7_production_scene_seams(
        module,
        first_scene_receipts,
    )
    manifest["m7_production_scene_seams"] = m7_scene_seams
    apply_cross_capture_contracts(
        [capture for capture in captures if capture["capture_sequence"] == "matrix"]
    )
    for ordinal in range(1, len(roundtrip_sizes) + 1):
        apply_cross_capture_contracts(
            [
                capture
                for capture in captures
                if capture["capture_sequence"] == "roundtrip"
                and capture["sequence_ordinal"] == ordinal
            ]
        )
    apply_roundtrip_contracts(captures)
    apply_matrix_roundtrip_parity_contracts(captures)
    issue_counts: dict[str, int] = {}
    for capture in captures:
        for issue in capture["issues"]:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    if manifest.get("mutation_guard", {}).get("passed") is not True:
        issue_counts["mutation_guard_failed"] = 1
    if manifest["isolated_data_gate"].get("passed") is not True:
        issue_counts["isolated_data_changed"] = 1
    expected_capture_count = (
        len(sizes) + len(roundtrip_sizes)
    ) * len(state_ids)
    manifest["summary"] = {
        "requested_scale": requested_scale,
        "expected_capture_count": expected_capture_count,
        "capture_count": len(captures),
        "passed_capture_count": sum(1 for capture in captures if capture["passed"]),
        "failed_capture_count": sum(1 for capture in captures if not capture["passed"]),
        "clipping_issue_count": sum(
            int(capture["ui_geometry"]["clipping_proxy"].get("issue_count", 0))
            for capture in captures
        ),
        "issue_counts": issue_counts,
        "monitor_gate_applicable": monitor_target is not None,
        "monitor_gate_passed": (
            all(
                capture.get("monitor_gate", {}).get("passed") is True
                for capture in captures
            )
            if monitor_target is not None
            else True
        ),
        "mutation_guard_total_protected_target_count": manifest.get(
            "mutation_guard", {}
        ).get("total_protected_target_count", 0),
        "mutation_guard_total_blocked_call_count": manifest.get(
            "mutation_guard", {}
        ).get("total_blocked_call_count", 0),
        "isolated_data_file_count_before": isolated_data_before["file_count"],
        "isolated_data_file_count_after": isolated_data_after["file_count"],
        "isolated_data_total_bytes_before": isolated_data_before["total_bytes"],
        "isolated_data_total_bytes_after": isolated_data_after["total_bytes"],
        "roundtrip_capture_count": sum(
            1 for capture in captures if capture["capture_sequence"] == "roundtrip"
        ),
        "m7_required_scene_count": len(M7_REQUIRED_STATE_IDS),
        "m7_requested_scene_ids_exact": tuple(state_ids)
        == tuple(M7_REQUIRED_STATE_IDS),
        "m7_production_seams_available": m7_scene_seams[
            "all_seams_available"
        ],
        "passed": (
            len(captures) == expected_capture_count
            and not issue_counts
            and tuple(state_ids) == tuple(M7_REQUIRED_STATE_IDS)
            and m7_scene_seams["all_seams_available"] is True
        ),
    }
    app_specific_root = resolved_output / "_app_specific"
    app_specific_root.mkdir(parents=True, exist_ok=True)
    manifest_path = app_specific_root / "geometry-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest_path, manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render isolated Container_Audit operator states at fixed client sizes and "
            "write PNG screenshots plus a geometry/pixel manifest."
        )
    )
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_TMP_ROOT / f"container_operator_ui_capture_{timestamp}",
        help=f"new/output directory below {REPO_TMP_ROOT}",
    )
    parser.add_argument(
        "--sizes",
        type=parse_sizes,
        default=DEFAULT_SIZES,
        help="comma-separated client sizes, for example 1366x768,1440x900",
    )
    parser.add_argument(
        "--states",
        type=parse_states,
        default=DEFAULT_STATE_IDS,
        help=f"comma-separated states: {','.join(DEFAULT_STATE_IDS)}",
    )
    parser.add_argument(
        "--scale",
        type=parse_scale,
        default=DEFAULT_SCALE,
        help=f"UI scale factor from {MIN_SCALE} to {MAX_SCALE} (default: {DEFAULT_SCALE})",
    )
    parser.add_argument(
        "--monitor-device",
        default="",
        help=(
            "Exact Win32 non-primary monitor device name, for example "
            r"\\.\DISPLAY2. Omit to preserve legacy +0+0 placement."
        ),
    )
    parser.add_argument(
        "--roundtrip-sizes",
        type=parse_roundtrip_sizes,
        default=(),
        help=(
            "optional ordered same-instance compact,wide,compact sequence; "
            "duplicates are preserved and screenshots use ordinal paths"
        ),
    )
    parser.add_argument(
        "--left-view",
        choices=("summary", "parked"),
        default="summary",
        help=(
            "compact left context to render; run both summary and parked "
            "for recovery-reachability evidence"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="compatibility flag; M7 capture and approval gates always fail closed",
    )
    parser.add_argument(
        "--external-evidence-root",
        type=Path,
        help=(
            "canonical external root (normally "
            f"{M7_EXTERNAL_CAPTURE_APPROVAL_LOCATION})"
        ),
    )
    parser.add_argument(
        "--portable-artifact",
        type=Path,
        help="required sealed portable artifact input for the external manifest",
    )
    parser.add_argument(
        "--describe-m7-contract",
        action="store_true",
        help=(
            "print the canonical {schema, app, required_state_ids} envelope; "
            "do not create a window or output directory"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.describe_m7_contract:
        print(
            json.dumps(
                build_m7_external_capture_bundle_contract(),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.external_evidence_root is None or args.portable_artifact is None:
        print(
            json.dumps(
                {
                    "error": "external_evidence_root_and_portable_artifact_required",
                    "passed": False,
                },
                ensure_ascii=False,
            )
        )
        return 2
    canonical_external_root = Path(M7_EXTERNAL_CAPTURE_APPROVAL_LOCATION)
    if not _paths_have_same_lexical_and_physical_identity(
        args.external_evidence_root,
        canonical_external_root,
    ):
        print(
            json.dumps(
                {
                    "error": "external_evidence_root_must_match_canonical",
                    "expected": M7_EXTERNAL_CAPTURE_APPROVAL_LOCATION,
                    "passed": False,
                },
                ensure_ascii=False,
            )
        )
        return 2
    try:
        external_root = _lexical_absolute(args.external_evidence_root)
        _assert_no_symlink_path_components(external_root)
        _assert_lexical_and_physical_path_within_root(external_root, external_root)
    except ExternalEvidencePathError as exc:
        print(
            json.dumps(
                {
                    "error": "external_evidence_root_path_forbidden",
                    "reason_code": exc.code,
                    "path": exc.path,
                    "passed": False,
                },
                ensure_ascii=False,
            )
        )
        return 2
    manifest_path, manifest = run_capture_matrix(
        output_root=args.output_root,
        sizes=args.sizes,
        state_ids=args.states,
        scale=args.scale,
        monitor_device=args.monitor_device,
        roundtrip_sizes=args.roundtrip_sizes,
        left_view=args.left_view,
    )
    summary = manifest["summary"]
    external_bundle = None
    if summary["passed"]:
        first_size = list(args.sizes[0])
        external_inputs: list[ExternalCaptureImage] = []
        for state_id in M7_REQUIRED_STATE_IDS:
            matching = next(
                capture
                for capture in manifest["captures"]
                if capture["capture_sequence"] == "matrix"
                and capture["requested_size"] == first_size
                and capture["state"] == state_id
            )
            image_path = manifest_path.parent.parent / matching["path"]
            external_inputs.append(
                ExternalCaptureImage(
                    state_id=state_id,
                    png_bytes=image_path.read_bytes(),
                    dpi=int(matching["measured_capture_dpi"]),
                )
            )
        external_bundle = build_m7_external_capture_bundle(
            evidence_root=args.external_evidence_root,
            portable_artifact=args.portable_artifact,
            captures=external_inputs,
        )
    print(
        json.dumps(
            {
                "app_specific_geometry_manifest": str(manifest_path),
                "external_manifest": (
                    external_bundle["manifest_path"]
                    if external_bundle is not None
                    else None
                ),
                "external_index": (
                    external_bundle["index_path"]
                    if external_bundle is not None
                    else None
                ),
                "capture_count": summary["capture_count"],
                "requested_scale": summary["requested_scale"],
                "monitor_device": args.monitor_device or None,
                "monitor_gate_passed": summary["monitor_gate_passed"],
                "roundtrip_sizes": [list(size) for size in args.roundtrip_sizes],
                "left_view": args.left_view,
                "capture_gate_passed": summary["passed"],
                "approval_pending": (
                    external_bundle["approval_pending"]
                    if external_bundle is not None
                    else None
                ),
                "passed": bool(
                    summary["passed"]
                    and external_bundle is not None
                    and not external_bundle["approval_pending"]
                ),
                "issue_counts": summary["issue_counts"],
            },
            ensure_ascii=False,
        )
    )
    if not summary["passed"] or external_bundle is None:
        return 2
    return 3 if external_bundle["approval_pending"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
