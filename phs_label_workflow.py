"""Durable PHS=2 physical-label date exchange for Container Audit.

The central server owns label identity, planning instructions, print attempts,
and activation.  This module keeps only a bounded local recovery journal,
renders the server-issued QR, submits it to the Windows default printer, and
updates the physical-label display fields on the existing ``TraySession``.
It never replaces the tray object or mutates its scanned membership/progress.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import tempfile
import threading
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from label_qr import parse_new_format_qr
from transfer_seal import (
    TransferSealError,
    TransferSourcePreflight,
    source_identity_from_label,
    validate_compact_phs2_fields,
    validate_compact_phs2_preflight,
)


PHS_LABEL_EXCHANGE_JOURNAL_VERSION = "container-audit-phs-label-exchange-v1"
_TERMINAL_JOURNAL_STATES = frozenset({"COMMITTED", "CANCELLED"})
_ACTIVE_TRAY_FIELDS = (
    "canonical_input_tag_qr",
    "active_label_qr_payload",
    "active_label_id",
    "active_label_business_date",
    "active_label_worker_code",
)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _stable_key(prefix: str, *parts: Any) -> str:
    fingerprint = hashlib.sha256(
        "|".join(str(value or "") for value in parts).encode("utf-8")
    ).hexdigest()
    return f"{prefix}:{fingerprint}"


def _positive_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise PHSLabelWorkflowError(
            "PHS_LABEL_EVIDENCE_INVALID", f"{field_name} 값이 올바르지 않습니다."
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PHSLabelWorkflowError(
            "PHS_LABEL_EVIDENCE_INVALID", f"{field_name} 값이 올바르지 않습니다."
        ) from exc
    if parsed < 1:
        raise PHSLabelWorkflowError(
            "PHS_LABEL_EVIDENCE_INVALID", f"{field_name} 값이 올바르지 않습니다."
        )
    return parsed


class PHSLabelWorkflowError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = str(code or "PHS_LABEL_WORKFLOW_ERROR")
        self.retryable = bool(retryable)
        self.details = dict(details or {})


class PHSPhysicalPrintError(PHSLabelWorkflowError):
    def __init__(self, message: str) -> None:
        super().__init__("LOCAL_PRINTER_ERROR", message, retryable=True)


class PHSLabelExchangeJournal:
    """Atomic single-operation recovery journal.

    A corrupt existing journal is fail-closed.  Treating it as an empty
    journal could create a second prepare/activation path after a lost ACK.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.is_file():
                return {}
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                raise PHSLabelWorkflowError(
                    "PHS_LABEL_JOURNAL_CORRUPT",
                    "현품표 교환 복구 journal을 읽을 수 없습니다.",
                ) from exc
        if (
            not isinstance(loaded, dict)
            or loaded.get("schema_version")
            != PHS_LABEL_EXCHANGE_JOURNAL_VERSION
            or not isinstance(loaded.get("state"), dict)
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_JOURNAL_CORRUPT",
                "현품표 교환 복구 journal 형식이 올바르지 않습니다.",
            )
        return dict(loaded["state"])

    def save(self, state: Mapping[str, Any]) -> dict[str, Any]:
        bounded = dict(state or {})
        bounded["updated_at"] = _utc_now()
        payload = {
            "schema_version": PHS_LABEL_EXCHANGE_JOURNAL_VERSION,
            "state": bounded,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f"{self.path.name}.",
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(
                        payload,
                        handle,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
            finally:
                try:
                    if os.path.exists(temporary):
                        os.remove(temporary)
                except OSError:
                    pass
        return dict(bounded)


@dataclass(frozen=True)
class PhysicalPrintEvidence:
    printer_name: str
    spool_job_id: int
    document_name: str
    submitted_at: str

    def to_server_proof(self) -> dict[str, Any]:
        return {
            "attached": True,
            "proof_kind": "WINDOWS_GDI_SPOOL",
            "local_printer_name": self.printer_name,
            "spool_job_id": int(self.spool_job_id),
            "document_name": self.document_name,
            "submitted_at": self.submitted_at,
            "windows_gdi_end_doc": True,
        }


class WindowsGDIPhysicalLabelPrinter:
    """Submit a rendered PNG to the configured Windows default printer."""

    _HORZRES = 8
    _VERTRES = 10

    class _DOCINFOW(ctypes.Structure):
        _fields_ = (
            ("cbSize", ctypes.c_int),
            ("lpszDocName", wintypes.LPCWSTR),
            ("lpszOutput", wintypes.LPCWSTR),
            ("lpszDatatype", wintypes.LPCWSTR),
            ("fwType", wintypes.DWORD),
        )

    @staticmethod
    def _default_printer_name() -> str:
        if os.name != "nt":
            raise PHSPhysicalPrintError(
                "실물 현품표 출력은 Windows 프린터에서만 지원됩니다."
            )
        winspool = ctypes.WinDLL("winspool.drv", use_last_error=True)
        get_default = winspool.GetDefaultPrinterW
        get_default.argtypes = (
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        get_default.restype = wintypes.BOOL
        size = wintypes.DWORD(0)
        get_default(None, ctypes.byref(size))
        if size.value < 2:
            raise PHSPhysicalPrintError(
                "Windows 기본 프린터가 설정되지 않았습니다."
            )
        buffer = ctypes.create_unicode_buffer(size.value)
        if not get_default(buffer, ctypes.byref(size)):
            raise PHSPhysicalPrintError(
                "Windows 기본 프린터를 확인하지 못했습니다"
                f"({ctypes.get_last_error()})."
            )
        printer_name = str(buffer.value or "").strip()
        if not printer_name:
            raise PHSPhysicalPrintError(
                "Windows 기본 프린터 이름이 비어 있습니다."
            )
        return printer_name

    def print_png(
        self,
        filepath: str,
        *,
        document_name: str,
    ) -> PhysicalPrintEvidence:
        path = Path(str(filepath or "")).resolve()
        if not path.is_file():
            raise PHSPhysicalPrintError("출력할 현품표 PNG 파일이 없습니다.")
        printer_name = self._default_printer_name()
        try:
            from PIL import Image, ImageWin
        except Exception as exc:
            raise PHSPhysicalPrintError(
                "실물 현품표 출력에 필요한 Pillow GDI 모듈을 사용할 수 없습니다."
            ) from exc

        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        create_dc = gdi32.CreateDCW
        create_dc.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
        )
        create_dc.restype = wintypes.HDC
        delete_dc = gdi32.DeleteDC
        delete_dc.argtypes = (wintypes.HDC,)
        delete_dc.restype = wintypes.BOOL
        start_doc = gdi32.StartDocW
        start_doc.argtypes = (
            wintypes.HDC,
            ctypes.POINTER(self._DOCINFOW),
        )
        start_doc.restype = ctypes.c_int
        end_doc = gdi32.EndDoc
        end_doc.argtypes = (wintypes.HDC,)
        end_doc.restype = ctypes.c_int
        abort_doc = gdi32.AbortDoc
        abort_doc.argtypes = (wintypes.HDC,)
        abort_doc.restype = ctypes.c_int
        start_page = gdi32.StartPage
        start_page.argtypes = (wintypes.HDC,)
        start_page.restype = ctypes.c_int
        end_page = gdi32.EndPage
        end_page.argtypes = (wintypes.HDC,)
        end_page.restype = ctypes.c_int
        get_caps = gdi32.GetDeviceCaps
        get_caps.argtypes = (wintypes.HDC, ctypes.c_int)
        get_caps.restype = ctypes.c_int

        hdc = create_dc("WINSPOOL", printer_name, None, None)
        if not hdc:
            raise PHSPhysicalPrintError(
                f"프린터 DC를 열지 못했습니다({ctypes.get_last_error()})."
            )
        job_started = False
        try:
            doc_name = str(document_name or path.stem)[:240]
            doc_info = self._DOCINFOW(
                ctypes.sizeof(self._DOCINFOW),
                doc_name,
                None,
                None,
                0,
            )
            job_id = int(start_doc(hdc, ctypes.byref(doc_info)))
            if job_id <= 0:
                raise PHSPhysicalPrintError(
                    "프린터 작업을 시작하지 못했습니다"
                    f"({ctypes.get_last_error()})."
                )
            job_started = True
            if start_page(hdc) <= 0:
                raise PHSPhysicalPrintError(
                    "프린터 페이지를 시작하지 못했습니다"
                    f"({ctypes.get_last_error()})."
                )
            with Image.open(path) as source:
                image = source.convert("RGB")
                page_width = int(get_caps(hdc, self._HORZRES))
                page_height = int(get_caps(hdc, self._VERTRES))
                if page_width <= 0 or page_height <= 0:
                    raise PHSPhysicalPrintError(
                        "프린터의 출력 가능 영역을 확인하지 못했습니다."
                    )
                scale = min(
                    page_width / max(1, image.width),
                    page_height / max(1, image.height),
                )
                output_width = max(1, int(round(image.width * scale)))
                output_height = max(1, int(round(image.height * scale)))
                left = max(0, (page_width - output_width) // 2)
                top = max(0, (page_height - output_height) // 2)
                dib = ImageWin.Dib(image)
                dib.draw(
                    hdc,
                    (
                        left,
                        top,
                        left + output_width,
                        top + output_height,
                    ),
                )
            if end_page(hdc) <= 0:
                raise PHSPhysicalPrintError(
                    "프린터 페이지를 완료하지 못했습니다"
                    f"({ctypes.get_last_error()})."
                )
            if end_doc(hdc) <= 0:
                raise PHSPhysicalPrintError(
                    "프린터 작업을 완료하지 못했습니다"
                    f"({ctypes.get_last_error()})."
                )
            job_started = False
            return PhysicalPrintEvidence(
                printer_name=printer_name,
                spool_job_id=job_id,
                document_name=doc_name,
                submitted_at=_utc_now(),
            )
        finally:
            if job_started:
                try:
                    abort_doc(hdc)
                except Exception:
                    pass
            delete_dc(hdc)


@dataclass(frozen=True)
class RenderedPHSLabel:
    path: str
    sha256: str


class PHSLabelRenderer:
    """Render the server-issued QR with central date and worker code."""

    def __init__(self, output_root: str | os.PathLike[str]):
        self.output_root = Path(output_root)

    @staticmethod
    def _font(size: int, *, bold: bool = False):
        from PIL import ImageFont

        candidates = (
            (
                r"C:\Windows\Fonts\malgunbd.ttf",
                r"C:\Windows\Fonts\malgun.ttf",
            )
            if bold
            else (
                r"C:\Windows\Fonts\malgun.ttf",
                r"C:\Windows\Fonts\malgunbd.ttf",
            )
        )
        for candidate in candidates:
            try:
                return ImageFont.truetype(candidate, size=size)
            except OSError:
                continue
        try:
            return ImageFont.truetype("DejaVuSans.ttf", size=size)
        except OSError:
            return ImageFont.load_default()

    def render(
        self,
        tray: Any,
        target: Mapping[str, Any],
    ) -> RenderedPHSLabel:
        try:
            import qrcode
            from PIL import Image, ImageDraw
        except Exception as exc:
            raise PHSPhysicalPrintError(
                "현품표 PNG 생성에 필요한 qrcode/Pillow 모듈이 없습니다."
            ) from exc

        label_id = str(target.get("label_id") or "").strip()
        qr_payload = str(target.get("qr_payload") or "").strip()
        business_date = str(target.get("business_date") or "").strip()
        worker_code = str(target.get("worker_code") or "").strip()
        if not label_id or not qr_payload or not business_date or not worker_code:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "중앙 target label의 QR/date/worker-code 증거가 불완전합니다.",
            )
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", business_date) is None:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "중앙 target label의 business date 형식이 올바르지 않습니다.",
            )
        try:
            datetime.strptime(business_date, "%Y-%m-%d")
        except ValueError as exc:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "중앙 target label의 business date 값이 올바르지 않습니다.",
            ) from exc
        safe_label = re.sub(r"[^A-Za-z0-9._-]+", "_", label_id)[:120]
        output_root = self.output_root.expanduser().resolve(strict=False)
        folder = output_root / business_date / "phs_label_exchange"
        try:
            folder.resolve(strict=False).relative_to(output_root)
        except (OSError, ValueError) as exc:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "현품표 PNG 상태 경로가 사용자 상태 루트를 벗어났습니다.",
            ) from exc
        folder.mkdir(parents=True, exist_ok=True)
        try:
            folder.resolve(strict=True).relative_to(output_root)
        except (OSError, ValueError) as exc:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "현품표 PNG 상태 경로를 안전하게 확인할 수 없습니다.",
            ) from exc
        output_path = folder / f"{safe_label}.png"

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_payload)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white").convert(
            "RGB"
        )
        qr_image.thumbnail((440, 440))

        canvas = Image.new("RGB", (1100, 600), "white")
        draw = ImageDraw.Draw(canvas)
        draw.rectangle((8, 8, 1091, 591), outline="black", width=5)
        canvas.paste(qr_image, (40, 80))
        draw.text(
            (530, 55),
            "PHS 현품표",
            fill="black",
            font=self._font(48, bold=True),
        )
        draw.text(
            (530, 145),
            f"작업일  {business_date}",
            fill="black",
            font=self._font(38, bold=True),
        )
        draw.text(
            (530, 215),
            f"작업코드  {worker_code}",
            fill="black",
            font=self._font(34, bold=True),
        )
        draw.text(
            (530, 290),
            f"품목  {str(getattr(tray, 'item_code', '') or '')}",
            fill="black",
            font=self._font(29),
        )
        item_name = str(getattr(tray, "item_name", "") or "")
        if item_name:
            draw.text(
                (530, 345),
                item_name[:28],
                fill="black",
                font=self._font(27),
            )
        draw.text(
            (530, 410),
            f"수량  {int(getattr(tray, 'tray_size', 0) or 0)} Pcs",
            fill="black",
            font=self._font(31, bold=True),
        )
        draw.text(
            (530, 490),
            "QR을 스캔해 현품표 상태를 확인하세요",
            fill="black",
            font=self._font(18),
        )

        descriptor, temporary = tempfile.mkstemp(
            prefix=f"{output_path.stem}.",
            suffix=".png",
            dir=str(folder),
        )
        os.close(descriptor)
        try:
            canvas.save(temporary, format="PNG", optimize=True)
            os.replace(temporary, output_path)
        finally:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        return RenderedPHSLabel(str(output_path), digest)


@dataclass(frozen=True)
class PHSLabelExchangeResult:
    status: str
    success: bool
    message: str
    error_code: str = ""
    retryable: bool = False
    exchange_id: str = ""
    journal_state: dict[str, Any] = field(default_factory=dict)


class PHSLabelExchangeCoordinator:
    """Run/replay one central SINGLE label exchange."""

    def __init__(
        self,
        journal: PHSLabelExchangeJournal,
        client: Any,
        *,
        renderer: Any,
        printer: Any = None,
    ) -> None:
        self.journal = journal
        self.client = client
        self.renderer = renderer
        self.printer = (
            printer if printer is not None else WindowsGDIPhysicalLabelPrinter()
        )
        self._execution_lock = threading.Lock()
        from phs_reconciliation_workflow import (
            PHSReconciliationExchangeCoordinator,
        )

        self.reconciliation = PHSReconciliationExchangeCoordinator(
            journal,
            client,
            renderer=renderer,
            printer=self.printer,
            execution_lock=self._execution_lock,
        )

    @property
    def available(self) -> bool:
        required = (
            "resolve_source",
            "list_phs_work_instruction_candidates",
            "adopt_phs_label",
            "prepare_phs_label_exchange",
            "get_phs_label_exchange",
            "request_phs_label_print",
            "complete_phs_label_print",
            "activate_phs_label_exchange",
        )
        return self.client is not None and all(
            callable(getattr(self.client, name, None)) for name in required
        )

    @staticmethod
    def _tray_phs_fields(tray: Any) -> dict[str, str]:
        payload = str(
            getattr(tray, "active_label_qr_payload", "")
            or getattr(tray, "master_label_code", "")
            or ""
        ).strip()
        fields = parse_new_format_qr(payload) or {}
        try:
            return validate_compact_phs2_fields(fields)
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(exc.code, str(exc)) from exc

    def _resolve_tray_source(
        self, tray: Any
    ) -> tuple[TransferSourcePreflight, dict[str, Any]]:
        if not self.available:
            raise PHSLabelWorkflowError(
                "PHS_LABEL_CLIENT_UNAVAILABLE",
                "중앙 현품표 교환 API 설정이 없습니다.",
                retryable=True,
            )
        fields = self._tray_phs_fields(tray)
        resolved = self.client.resolve_source(source_identity_from_label(fields))
        try:
            preflight = validate_compact_phs2_preflight(fields, resolved)
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(
                exc.code,
                str(exc),
                retryable=exc.retryable,
                details=exc.details,
            ) from exc
        canonical_master = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        item_code = str(getattr(tray, "item_code", "") or "").strip()
        tray_size = _positive_integer(
            getattr(tray, "tray_size", 0), "tray_size"
        )
        expected_scope = str(
            getattr(self.client, "authority_scope_id", "") or ""
        ).strip()
        expected_authority_plane = str(
            getattr(self.client, "authority_plane", "") or ""
        ).strip().upper()
        expected_ledger_plane = str(
            getattr(self.client, "ledger_plane", "") or ""
        ).strip().upper()
        try:
            expected_plane_epoch = int(
                getattr(self.client, "plane_epoch", 0) or 0
            )
        except (TypeError, ValueError):
            expected_plane_epoch = -1
        if (
            preflight.ledger_plane
            not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}
            or (
                expected_scope
                and preflight.authority_scope_id != expected_scope
            )
            or (
                expected_authority_plane
                and expected_authority_plane != "AUTHORITATIVE"
            )
            or (
                expected_ledger_plane
                and preflight.ledger_plane != expected_ledger_plane
            )
            or (
                expected_plane_epoch
                and preflight.plane_epoch != expected_plane_epoch
            )
            or canonical_master != preflight.canonical_input_tag_qr
            or item_code != preflight.item_id
            or tray_size != preflight.member_count
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_TRAY_ANCHOR_MISMATCH",
                "현재 트레이의 authoritative canonical "
                "PHS2/item/member-count가 중앙 source와 다릅니다.",
            )
        return preflight, dict(resolved or {})

    @staticmethod
    def _validate_target_date(value: Any) -> str:
        target_date = str(value or "").strip()
        try:
            parsed = datetime.strptime(target_date, "%Y-%m-%d")
        except ValueError as exc:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_DATE_INVALID",
                "교환 작업일은 YYYY-MM-DD 실제 달력 날짜여야 합니다.",
            ) from exc
        if parsed.strftime("%Y-%m-%d") != target_date:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_DATE_INVALID",
                "교환 작업일은 YYYY-MM-DD 형식이어야 합니다.",
            )
        return target_date

    def list_candidates(
        self,
        tray: Any,
        business_date: str,
    ) -> list[dict[str, Any]]:
        target_date = self._validate_target_date(business_date)
        preflight, _resolved = self._resolve_tray_source(tray)
        response = self.client.list_phs_work_instruction_candidates(
            authority_scope_id=preflight.authority_scope_id,
            business_date=target_date,
            item_id=preflight.item_id,
            target_qty_pcs=preflight.member_count,
            limit=50,
        )
        raw_candidates = response.get("candidates")
        raw_response_count = response.get("candidate_count")
        raw_response_quantity = response.get("target_qty_pcs")
        if isinstance(raw_response_count, bool) or isinstance(
            raw_response_quantity,
            bool,
        ):
            raise PHSLabelWorkflowError(
                "PHS_TARGET_CANDIDATES_INVALID",
                "중앙 작업지시 후보 응답의 수량 증거가 올바르지 않습니다.",
            )
        try:
            response_count = int(raw_response_count)
            response_quantity = int(raw_response_quantity)
        except (TypeError, ValueError) as exc:
            raise PHSLabelWorkflowError(
                "PHS_TARGET_CANDIDATES_INVALID",
                "중앙 작업지시 후보 응답의 수량 증거가 올바르지 않습니다.",
            ) from exc
        if (
            str(response.get("authority_scope_id") or "").strip()
            != preflight.authority_scope_id
            or str(response.get("business_date") or "").strip() != target_date
            or str(response.get("item_id") or "").strip() != preflight.item_id
            or str(response.get("uom") or "").strip().upper() != "PCS"
            or response_quantity != preflight.member_count
            or not isinstance(raw_candidates, list)
            or response_count != len(raw_candidates)
            or str(response.get("status") or "").strip().upper()
            != ("MATCH" if raw_candidates else "NO_MATCH")
        ):
            raise PHSLabelWorkflowError(
                "PHS_TARGET_CANDIDATES_INVALID",
                "중앙 후보의 scope/date/item/member-count가 현재 트레이와 다릅니다.",
            )
        candidates: list[dict[str, Any]] = []
        for raw in raw_candidates:
            if not isinstance(raw, Mapping):
                raise PHSLabelWorkflowError(
                    "PHS_TARGET_CANDIDATES_INVALID",
                    "중앙 작업지시 후보 형식이 올바르지 않습니다.",
                )
            candidate = dict(raw)
            if (
                not str(candidate.get("instruction_id") or "").strip()
                or str(candidate.get("business_date") or "").strip()
                != target_date
                or str(candidate.get("item_id") or "").strip()
                != preflight.item_id
                or str(candidate.get("uom") or "").strip().upper() != "PCS"
                or _positive_integer(
                    candidate.get("target_qty_pcs"),
                    "target_qty_pcs",
                )
                != preflight.member_count
                or str(candidate.get("state") or "").strip().upper()
                != "PLANNED"
                or not str(candidate.get("worker_code") or "").strip()
                or _positive_integer(
                    candidate.get("item_daily_ordinal"),
                    "item_daily_ordinal",
                )
                < 1
                or _positive_integer(
                    candidate.get("entity_version"),
                    "entity_version",
                )
                < 1
            ):
                raise PHSLabelWorkflowError(
                    "PHS_TARGET_CANDIDATES_INVALID",
                    "exact PLANNED 작업지시가 아닌 후보가 포함됐습니다.",
                )
            candidates.append(candidate)
        return candidates

    @staticmethod
    def _effective_source_label(
        resolved: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str]:
        resolution = resolved.get("phs_label_resolution")
        if not isinstance(resolution, Mapping):
            return {}, "LEGACY_ACTIVE"
        kind = str(resolution.get("resolution") or "").strip().upper()
        if kind == "OVERLAY_NOT_ACTIVE":
            raise PHSLabelWorkflowError(
                "PHS2_LABEL_NOT_ACTIVE",
                "아직 ACTIVE가 아닌 새 현품표는 교환 source가 될 수 없습니다.",
            )
        effective = resolution.get("effective_labels")
        if (
            kind not in {"OVERLAY_ACTIVE", "OVERLAY_REPLACED"}
            or not isinstance(effective, list)
            or len(effective) != 1
            or not isinstance(effective[0], Mapping)
        ):
            raise PHSLabelWorkflowError(
                "PHS2_ACTIVE_LABEL_AMBIGUOUS",
                "교환 source의 현재 ACTIVE physical label을 하나로 확정하지 못했습니다.",
            )
        active = dict(effective[0])
        if str(active.get("state") or "").strip().upper() != "ACTIVE":
            raise PHSLabelWorkflowError(
                "PHS2_LABEL_NOT_ACTIVE",
                "교환 source physical label이 ACTIVE가 아닙니다.",
            )
        return active, kind

    def _adopt_if_required(
        self,
        *,
        preflight: TransferSourcePreflight,
        resolved: Mapping[str, Any],
    ) -> dict[str, Any]:
        active, kind = self._effective_source_label(resolved)
        if kind != "LEGACY_ACTIVE":
            return active
        input_tag = (
            dict(resolved.get("input_tag"))
            if isinstance(resolved.get("input_tag"), Mapping)
            else {}
        )
        raw_session_version = input_tag.get("session_entity_version")
        expected_session_version = (
            _positive_integer(raw_session_version, "session_entity_version")
            if raw_session_version not in (None, "")
            else None
        )
        adopted = self.client.adopt_phs_label(
            authority_scope_id=preflight.authority_scope_id,
            qr_payload=preflight.canonical_input_tag_qr,
            business_date=preflight.active_label_business_date,
            expected_session_version=expected_session_version,
        )
        active = (
            dict(adopted.get("label"))
            if isinstance(adopted.get("label"), Mapping)
            else {}
        )
        if (
            str(active.get("state") or "").strip().upper() != "ACTIVE"
            or str(active.get("label_id") or "").strip()
            != preflight.active_label_id
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_ADOPTION_INVALID",
                "legacy source adopt 결과가 현재 physical label과 다릅니다.",
            )
        return active

    @staticmethod
    def _validate_active_source_versions(
        active: Mapping[str, Any],
        *,
        preflight: TransferSourcePreflight,
    ) -> tuple[str, int, int]:
        label_id = str(active.get("label_id") or "").strip()
        try:
            qr_fields = validate_compact_phs2_fields(
                parse_new_format_qr(
                    str(active.get("qr_payload") or "").strip()
                )
                or {}
            )
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(exc.code, str(exc)) from exc
        label_version = _positive_integer(
            active.get("label_version"), "label_version"
        )
        membership_version = _positive_integer(
            active.get("membership_version"), "membership_version"
        )
        label_hash = str(
            active.get("label_instance_hash") or ""
        ).strip().lower()
        hash_prefix = str(active.get("hash_prefix") or "").strip().lower()
        if (
            not label_id
            or str(active.get("state") or "").strip().upper() != "ACTIVE"
            or label_id != qr_fields["LBL"]
            or qr_fields["ITG"] != preflight.input_tag_id
            or qr_fields["CLC"] != preflight.item_id
            or hash_prefix != qr_fields["HSH"]
            or len(label_hash) != 64
            or any(value not in "0123456789abcdef" for value in label_hash)
            or label_hash[:16] != hash_prefix
            or str(
                active.get("scan_anchor_input_tag_id") or ""
            ).strip()
            != preflight.input_tag_id
            or str(active.get("item_id") or "").strip()
            != preflight.item_id
            or _positive_integer(
                active.get("member_count"), "member_count"
            )
            != preflight.member_count
            or str(active.get("membership_hash") or "").strip()
            != preflight.membership_hash
        ):
            raise PHSLabelWorkflowError(
                "PHS_SOURCE_LABEL_INVALID",
                "중앙 ACTIVE source label의 QR/anchor/membership 증거가 "
                "현재 exact PHS와 다릅니다.",
            )
        return label_id, label_version, membership_version

    def _save(self, state: Mapping[str, Any], **updates: Any) -> dict[str, Any]:
        return self.journal.save({**dict(state or {}), **updates})

    @staticmethod
    def _exchange_projection(
        response: Mapping[str, Any],
        *,
        recovery: Mapping[str, Any],
        tray: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        exchange = (
            dict(response.get("exchange"))
            if isinstance(response.get("exchange"), Mapping)
            else {}
        )
        target_labels = response.get("target_labels")
        source_labels = response.get("source_labels")
        exchange_id = str(recovery.get("exchange_id") or "").strip()
        if (
            str(exchange.get("exchange_id") or "").strip() != exchange_id
            or str(exchange.get("exchange_kind") or "").strip().upper()
            != "SINGLE"
            or not isinstance(target_labels, list)
            or len(target_labels) != 1
            or not isinstance(target_labels[0], Mapping)
            or not isinstance(source_labels, list)
            or len(source_labels) != 1
            or not isinstance(source_labels[0], Mapping)
            or str(source_labels[0].get("label_id") or "").strip()
            != str(recovery.get("source_label_id") or "").strip()
        ):
            raise PHSLabelWorkflowError(
                "PHS_EXCHANGE_EVIDENCE_INVALID",
                "중앙 SINGLE exchange/source/target cardinality 증거가 다릅니다.",
            )
        target = dict(target_labels[0])
        source = dict(source_labels[0])
        candidate = (
            dict(recovery.get("target_instruction"))
            if isinstance(recovery.get("target_instruction"), Mapping)
            else {}
        )
        try:
            target_qr = validate_compact_phs2_fields(
                parse_new_format_qr(
                    str(target.get("qr_payload") or "")
                )
                or {}
            )
            canonical_qr = validate_compact_phs2_fields(
                parse_new_format_qr(
                    str(recovery.get("canonical_input_tag_qr") or "")
                )
                or {}
            )
        except TransferSealError as exc:
            raise PHSLabelWorkflowError(exc.code, str(exc)) from exc
        exchange_state = str(exchange.get("state") or "").strip().upper()
        target_state = str(target.get("state") or "").strip().upper()
        source_state = str(source.get("state") or "").strip().upper()
        expected_target_state = (
            "ACTIVE" if exchange_state == "COMMITTED" else "PENDING_ACTIVATION"
        )
        expected_source_state = (
            "SUPERSEDED" if exchange_state == "COMMITTED" else "ACTIVE"
        )
        target_hash = str(
            target.get("label_instance_hash") or ""
        ).strip().lower()
        target_prefix = str(target.get("hash_prefix") or "").strip().lower()
        source_membership_hash = str(
            source.get("membership_hash") or ""
        ).strip()
        target_membership_hash = str(
            target.get("membership_hash") or ""
        ).strip()
        if (
            str(target.get("instruction_id") or "").strip()
            != str(candidate.get("instruction_id") or "").strip()
            or str(target.get("business_date") or "").strip()
            != str(candidate.get("business_date") or "").strip()
            or str(target.get("worker_code") or "").strip()
            != str(candidate.get("worker_code") or "").strip()
            or str(target.get("item_id") or "").strip()
            != str(getattr(tray, "item_code", "") or "").strip()
            or str(target.get("scan_anchor_input_tag_id") or "").strip()
            != str(canonical_qr.get("ITG") or "").strip()
            or str(target.get("label_id") or "").strip()
            != str(target_qr.get("LBL") or "").strip()
            or target_prefix != str(target_qr.get("HSH") or "").strip().lower()
            or len(target_hash) != 64
            or any(value not in "0123456789abcdef" for value in target_hash)
            or target_hash[:16] != target_prefix
            or str(target_qr.get("ITG") or "").strip()
            != str(canonical_qr.get("ITG") or "").strip()
            or str(target_qr.get("CLC") or "").strip()
            != str(canonical_qr.get("CLC") or "").strip()
            or _positive_integer(target.get("member_count"), "member_count")
            != _positive_integer(getattr(tray, "tray_size", 0), "tray_size")
            or _positive_integer(source.get("member_count"), "member_count")
            != _positive_integer(getattr(tray, "tray_size", 0), "tray_size")
            or not source_membership_hash
            or source_membership_hash != target_membership_hash
            or target_state != expected_target_state
            or source_state != expected_source_state
            or _positive_integer(
                target.get("label_version"), "label_version"
            )
            < 1
            or _positive_integer(
                target.get("membership_version"), "membership_version"
            )
            < 1
        ):
            raise PHSLabelWorkflowError(
                "PHS_TARGET_LABEL_INVALID",
                "target label/instruction/date/worker/anchor/member-count/state가 "
                "선택 및 source와 다릅니다.",
            )
        return exchange, target

    @staticmethod
    def _print_proof(value: Any) -> dict[str, Any]:
        if callable(getattr(value, "to_server_proof", None)):
            proof = dict(value.to_server_proof())
        elif isinstance(value, Mapping):
            proof = dict(value)
        else:
            proof = {}
        if (
            proof.get("attached") is not True
            or not proof.get("spool_job_id")
            or str(proof.get("proof_kind") or "").strip()
            != "WINDOWS_GDI_SPOOL"
            or proof.get("windows_gdi_end_doc") is not True
        ):
            raise PHSPhysicalPrintError(
                "실제 Windows GDI spool 성공 증거가 불완전합니다."
            )
        return proof

    @staticmethod
    def _apply_target_to_tray(
        tray: Any,
        target: Mapping[str, Any],
        *,
        canonical_input_tag_qr: str,
        persist_tray: Callable[[], bool] | None,
    ) -> None:
        before = {
            field_name: getattr(tray, field_name, "")
            for field_name in _ACTIVE_TRAY_FIELDS
        }
        master_before = str(getattr(tray, "master_label_code", "") or "")
        scanned_object = getattr(tray, "scanned_barcodes", None)
        scans_before = (
            tuple(scanned_object) if isinstance(scanned_object, list) else None
        )
        setattr(tray, "canonical_input_tag_qr", canonical_input_tag_qr)
        setattr(
            tray,
            "active_label_qr_payload",
            str(target.get("qr_payload") or "").strip(),
        )
        setattr(
            tray,
            "active_label_id",
            str(target.get("label_id") or "").strip(),
        )
        setattr(
            tray,
            "active_label_business_date",
            str(target.get("business_date") or "").strip(),
        )
        setattr(
            tray,
            "active_label_worker_code",
            str(target.get("worker_code") or "").strip(),
        )
        invariant_ok = (
            str(getattr(tray, "master_label_code", "") or "") == master_before
            and getattr(tray, "scanned_barcodes", None) is scanned_object
            and (
                scans_before is None
                or tuple(getattr(tray, "scanned_barcodes", [])) == scans_before
            )
        )
        persisted = True if persist_tray is None else bool(persist_tray())
        if not invariant_ok or not persisted:
            for field_name, value in before.items():
                setattr(tray, field_name, value)
            raise PHSLabelWorkflowError(
                "PHS_LOCAL_TRAY_STATE_SAVE_FAILED",
                "중앙 교환은 완료됐지만 current tray label 상태를 안전하게 저장하지 못했습니다.",
                retryable=True,
            )

    def _result(
        self,
        state: Mapping[str, Any],
        *,
        success: bool,
        message: str,
        error_code: str = "",
        retryable: bool = False,
    ) -> PHSLabelExchangeResult:
        return PHSLabelExchangeResult(
            status=str(state.get("status") or "FAILED"),
            success=success,
            message=message,
            error_code=error_code,
            retryable=retryable,
            exchange_id=str(state.get("exchange_id") or ""),
            journal_state=dict(state),
        )

    def execute_single(
        self,
        tray: Any,
        target_instruction: Mapping[str, Any] | None,
        *,
        persist_tray: Callable[[], bool] | None = None,
        confirm_ambiguous_reprint: bool = False,
        status_callback: Callable[[str], None] | None = None,
    ) -> PHSLabelExchangeResult:
        if not self._execution_lock.acquire(blocking=False):
            return PHSLabelExchangeResult(
                status="BUSY",
                success=False,
                message="현품표 날짜 교환이 이미 진행 중입니다.",
                error_code="PHS_LABEL_EXCHANGE_BUSY",
                retryable=True,
            )
        try:
            return self._execute_single(
                tray,
                target_instruction,
                persist_tray=persist_tray,
                confirm_ambiguous_reprint=confirm_ambiguous_reprint,
                status_callback=status_callback,
            )
        except PHSLabelWorkflowError as exc:
            try:
                state = self.journal.load()
            except PHSLabelWorkflowError:
                state = {}
            return self._result(
                state,
                success=False,
                message=str(exc),
                error_code=exc.code,
                retryable=exc.retryable,
            )
        except TransferSealError as exc:
            try:
                state = self.journal.load()
            except PHSLabelWorkflowError:
                state = {}
            return self._result(
                state,
                success=False,
                message=str(exc),
                error_code=exc.code,
                retryable=exc.retryable,
            )
        except Exception as exc:
            try:
                state = self.journal.load()
            except PHSLabelWorkflowError:
                state = {}
            return self._result(
                state,
                success=False,
                message=(
                    "현품표 날짜 교환 중 중앙 응답을 확인하지 못했습니다: "
                    f"{exc.__class__.__name__}"
                ),
                error_code="PHS_LABEL_EXCHANGE_UNAVAILABLE",
                retryable=True,
            )
        finally:
            self._execution_lock.release()

    def _execute_single(
        self,
        tray: Any,
        target_instruction: Mapping[str, Any] | None,
        *,
        persist_tray: Callable[[], bool] | None,
        confirm_ambiguous_reprint: bool,
        status_callback: Callable[[str], None] | None,
    ) -> PHSLabelExchangeResult:
        notify = status_callback if callable(status_callback) else lambda _value: None
        canonical_master = str(
            getattr(tray, "master_label_code", "") or ""
        ).strip()
        target_request = dict(target_instruction or {})
        requested_instruction_id = str(
            target_request.get("instruction_id") or ""
        ).strip()
        state = self.journal.load()
        journal_status = str(state.get("status") or "").strip().upper()
        if (
            state
            and journal_status not in _TERMINAL_JOURNAL_STATES
            and str(state.get("canonical_input_tag_qr") or "").strip()
            != canonical_master
        ):
            raise PHSLabelWorkflowError(
                "PHS_LABEL_RECOVERY_CONFLICT",
                "다른 트레이의 미완료 현품표 교환 journal이 있습니다. "
                "해당 트레이를 복원해 먼저 복구해야 합니다.",
            )
        recoverable = bool(
            state
            and journal_status not in _TERMINAL_JOURNAL_STATES
            and str(state.get("canonical_input_tag_qr") or "").strip()
            == canonical_master
        )
        if recoverable:
            saved_instruction_id = str(
                state.get("target_instruction_id") or ""
            ).strip()
            if (
                requested_instruction_id
                and requested_instruction_id != saved_instruction_id
            ):
                raise PHSLabelWorkflowError(
                    "PHS_LABEL_RECOVERY_CONFLICT",
                    "다른 작업지시의 미완료 현품표 교환을 먼저 복구해야 합니다.",
                )
            target = (
                dict(state.get("target_instruction"))
                if isinstance(state.get("target_instruction"), Mapping)
                else {}
            )
        else:
            if not requested_instruction_id:
                raise PHSLabelWorkflowError(
                    "PHS_TARGET_INSTRUCTION_REQUIRED",
                    "교환할 중앙 작업지시를 선택해야 합니다.",
                )
            business_date = self._validate_target_date(
                target_request.get("business_date")
            )
            candidates = self.list_candidates(tray, business_date)
            target = next(
                (
                    candidate
                    for candidate in candidates
                    if str(candidate.get("instruction_id") or "").strip()
                    == requested_instruction_id
                    and _positive_integer(
                        candidate.get("entity_version"), "entity_version"
                    )
                    == _positive_integer(
                        target_request.get("entity_version"),
                        "entity_version",
                    )
                ),
                None,
            )
            if target is None:
                raise PHSLabelWorkflowError(
                    "PHS_TARGET_INSTRUCTION_STALE",
                    "선택한 작업지시가 더 이상 exact PLANNED 후보가 아닙니다.",
                )
            preflight, resolved = self._resolve_tray_source(tray)
            active_source = self._adopt_if_required(
                preflight=preflight,
                resolved=resolved,
            )
            source_label_id, label_version, membership_version = (
                self._validate_active_source_versions(
                    active_source,
                    preflight=preflight,
                )
            )
            current_physical = {
                "qr_payload": str(
                    active_source.get("qr_payload")
                    or preflight.active_label_qr_payload
                    or ""
                ).strip(),
                "label_id": source_label_id,
                "business_date": str(
                    active_source.get("business_date")
                    or preflight.active_label_business_date
                    or ""
                ).strip(),
                "worker_code": str(
                    active_source.get("worker_code")
                    or preflight.active_label_worker_code
                    or ""
                ).strip(),
            }
            if any(
                (
                    str(getattr(tray, "canonical_input_tag_qr", "") or "")
                    != preflight.canonical_input_tag_qr,
                    str(getattr(tray, "active_label_qr_payload", "") or "")
                    != current_physical["qr_payload"],
                    str(getattr(tray, "active_label_id", "") or "")
                    != current_physical["label_id"],
                    str(
                        getattr(tray, "active_label_business_date", "") or ""
                    )
                    != current_physical["business_date"],
                    str(getattr(tray, "active_label_worker_code", "") or "")
                    != current_physical["worker_code"],
                )
            ):
                self._apply_target_to_tray(
                    tray,
                    current_physical,
                    canonical_input_tag_qr=preflight.canonical_input_tag_qr,
                    persist_tray=persist_tray,
                )
            prepare_key = _stable_key(
                "container-phs-label-single-prepare",
                preflight.authority_scope_id,
                preflight.input_tag_id,
                source_label_id,
                label_version,
                membership_version,
                requested_instruction_id,
                target.get("entity_version"),
            )
            state = self._save(
                {},
                status="PREPARE_PENDING",
                authority_scope_id=preflight.authority_scope_id,
                input_tag_id=preflight.input_tag_id,
                canonical_input_tag_qr=preflight.canonical_input_tag_qr,
                canonical_label_id=preflight.input_tag_label_id,
                source_label_id=source_label_id,
                source_label_version=label_version,
                source_membership_version=membership_version,
                target_instruction_id=requested_instruction_id,
                target_instruction=dict(target),
                prepare_idempotency_key=prepare_key,
                print_attempt_no=0,
            )
            journal_status = "PREPARE_PENDING"

        scope = str(state.get("authority_scope_id") or "").strip()
        exchange_id = str(state.get("exchange_id") or "").strip()
        if not scope:
            raise PHSLabelWorkflowError(
                "PHS_LABEL_JOURNAL_CORRUPT",
                "복구 journal에 authority scope가 없습니다.",
            )
        notify("중앙 현품표 교환 prepare/복구 상태를 확인하고 있습니다.")
        if not exchange_id:
            try:
                prepared = self.client.prepare_phs_label_exchange(
                    authority_scope_id=scope,
                    exchange_kind="SINGLE",
                    sources=[
                        {
                            "source_label_id": str(
                                state.get("source_label_id") or ""
                            ).strip(),
                            "expected_label_version": _positive_integer(
                                state.get("source_label_version"),
                                "source_label_version",
                            ),
                            "expected_membership_version": _positive_integer(
                                state.get("source_membership_version"),
                                "source_membership_version",
                            ),
                        }
                    ],
                    targets=[
                        {
                            "target_instruction_id": str(
                                state.get("target_instruction_id") or ""
                            ).strip()
                        }
                    ],
                    idempotency_key=str(
                        state.get("prepare_idempotency_key") or ""
                    ).strip(),
                )
            except TransferSealError as exc:
                if exc.committed is False:
                    self._save(
                        state,
                        status="CANCELLED",
                        prepare_error={
                            "code": exc.code,
                            "message": str(exc),
                        },
                    )
                raise
            exchange_value = (
                dict(prepared.get("exchange"))
                if isinstance(prepared.get("exchange"), Mapping)
                else {}
            )
            exchange_id = str(
                exchange_value.get("exchange_id") or ""
            ).strip()
            if not exchange_id:
                raise PHSLabelWorkflowError(
                    "PHS_PREPARE_ACK_INVALID",
                    "중앙 prepare ACK에 exchange id가 없습니다.",
                    retryable=True,
                )
            state = self._save(
                state,
                status="PREPARED",
                exchange_id=exchange_id,
                prepare_ack=dict(prepared),
            )
            central = prepared
        else:
            central = self.client.get_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
            )
        exchange, target_label = self._exchange_projection(
            central,
            recovery=state,
            tray=tray,
        )
        state = self._save(
            state,
            target_label=dict(target_label),
            exchange_entity_version=_positive_integer(
                exchange.get("entity_version"), "exchange_entity_version"
            ),
        )
        exchange_state = str(exchange.get("state") or "").strip().upper()
        if exchange_state == "COMMITTED":
            try:
                self._apply_target_to_tray(
                    tray,
                    target_label,
                    canonical_input_tag_qr=str(
                        state.get("canonical_input_tag_qr") or ""
                    ),
                    persist_tray=persist_tray,
                )
            except PHSLabelWorkflowError:
                self._save(
                    state,
                    status="COMMITTED_LOCAL_REFRESH_PENDING",
                    committed_ack=dict(central),
                )
                raise
            committed = self._save(
                state,
                status="COMMITTED",
                committed_ack=dict(central),
            )
            return self._result(
                committed,
                success=True,
                message=(
                    "현품표 날짜 교환을 복구했습니다: "
                    f"{target_label.get('business_date')} · "
                    f"{target_label.get('worker_code')}"
                ),
            )

        journal_status = str(state.get("status") or "").strip().upper()
        if journal_status == "PRINT_FAILURE_ACK_PENDING":
            failed_ack = self.client.complete_phs_label_print(
                str(state.get("print_attempt_id") or ""),
                authority_scope_id=scope,
                succeeded=False,
                error_code=str(
                    state.get("print_error_code") or "LOCAL_PRINTER_ERROR"
                ),
                error_message=str(
                    state.get("print_error_message")
                    or "Local physical printer failed."
                )[:1024],
            )
            failed = self._save(
                state,
                status="PRINT_FAILED",
                print_failure_ack=dict(failed_ack),
            )
            return self._result(
                failed,
                success=False,
                message=(
                    "기존 현품표는 ACTIVE입니다. 프린터를 확인한 뒤 "
                    "같은 교환을 재시도하세요."
                ),
                error_code="LOCAL_PRINTER_ERROR",
                retryable=True,
            )

        if exchange_state != "READY":
            print_attempt_id = str(
                state.get("print_attempt_id") or ""
            ).strip()
            journal_status = str(state.get("status") or "").strip().upper()
            if journal_status == "PRINT_FAILED":
                print_attempt_id = ""
            if not print_attempt_id:
                if (
                    journal_status == "PRINT_REQUEST_PENDING"
                    and str(state.get("print_idempotency_key") or "").strip()
                ):
                    attempt_no = _positive_integer(
                        state.get("print_attempt_no"), "print_attempt_no"
                    )
                    print_key = str(
                        state.get("print_idempotency_key") or ""
                    ).strip()
                else:
                    attempt_no = int(state.get("print_attempt_no") or 0) + 1
                    print_key = _stable_key(
                        "container-phs-label-single-print",
                        exchange_id,
                        target_label.get("label_id"),
                        attempt_no,
                    )
                    state = self._save(
                        state,
                        status="PRINT_REQUEST_PENDING",
                        print_attempt_no=attempt_no,
                        print_idempotency_key=print_key,
                        print_attempt_id="",
                    )
                notify("중앙 print-attempt를 요청하고 있습니다.")
                requested = self.client.request_phs_label_print(
                    exchange_id,
                    authority_scope_id=scope,
                    label_id=str(target_label.get("label_id") or ""),
                    idempotency_key=print_key,
                )
                attempt = (
                    dict(requested.get("print_attempt"))
                    if isinstance(requested.get("print_attempt"), Mapping)
                    else {}
                )
                print_attempt_id = str(
                    attempt.get("print_attempt_id") or ""
                ).strip()
                if (
                    not print_attempt_id
                    or str(attempt.get("label_id") or "").strip()
                    != str(target_label.get("label_id") or "").strip()
                    or str(attempt.get("state") or "").strip().upper()
                    != "REQUESTED"
                ):
                    raise PHSLabelWorkflowError(
                        "PHS_PRINT_REQUEST_ACK_INVALID",
                        "중앙 REQUESTED print-attempt 증거가 일치하지 않습니다.",
                    )
                state = self._save(
                    state,
                    status="PRINT_REQUESTED",
                    print_attempt_id=print_attempt_id,
                    print_request_ack=dict(requested),
                )
                journal_status = "PRINT_REQUESTED"

            if (
                journal_status == "LOCAL_PRINT_STARTING"
                and not confirm_ambiguous_reprint
            ):
                raise PHSLabelWorkflowError(
                    "PHS_PRINT_REPRINT_CONFIRMATION_REQUIRED",
                    "이전 실행이 실제 프린터 제출 중 종료됐습니다. 실물 출력 "
                    "여부를 확인한 뒤 재출력을 명시적으로 승인하세요.",
                    retryable=True,
                )
            if journal_status not in {
                "LOCAL_PRINT_SUCCEEDED",
                "PRINT_COMPLETE_PENDING",
            }:
                notify("새 현품표 PNG를 생성하고 Windows 기본 프린터로 출력합니다.")
                try:
                    rendered = self.renderer.render(tray, target_label)
                except Exception as exc:
                    error_message = str(exc) or exc.__class__.__name__
                    state = self._save(
                        state,
                        status="PRINT_FAILURE_ACK_PENDING",
                        print_error_code="LOCAL_PRINTER_ERROR",
                        print_error_message=error_message[:1024],
                    )
                    try:
                        failed_ack = self.client.complete_phs_label_print(
                            str(state.get("print_attempt_id") or ""),
                            authority_scope_id=scope,
                            succeeded=False,
                            error_code="LOCAL_PRINTER_ERROR",
                            error_message=error_message[:1024],
                        )
                    except Exception:
                        raise PHSPhysicalPrintError(
                            "현품표 생성 실패와 중앙 실패 ACK가 모두 복구 대기 중입니다."
                        )
                    failed = self._save(
                        state,
                        status="PRINT_FAILED",
                        print_failure_ack=dict(failed_ack),
                    )
                    return self._result(
                        failed,
                        success=False,
                        message=(
                            "현품표 생성에 실패했습니다. 기존 현품표는 ACTIVE로 "
                            "유지됩니다."
                        ),
                        error_code="LOCAL_PRINTER_ERROR",
                        retryable=True,
                    )
                state = self._save(
                    state,
                    status="LOCAL_PRINT_STARTING",
                    rendered_path=rendered.path,
                    rendered_artifact_hash=rendered.sha256,
                )
                try:
                    evidence = self.printer.print_png(
                        rendered.path,
                        document_name=(
                            "PHS "
                            + str(target_label.get("worker_code") or "")
                        ),
                    )
                    proof = self._print_proof(evidence)
                except Exception as exc:
                    error_message = str(exc) or exc.__class__.__name__
                    state = self._save(
                        state,
                        status="PRINT_FAILURE_ACK_PENDING",
                        print_error_code="LOCAL_PRINTER_ERROR",
                        print_error_message=error_message[:1024],
                    )
                    try:
                        failed_ack = self.client.complete_phs_label_print(
                            str(state.get("print_attempt_id") or ""),
                            authority_scope_id=scope,
                            succeeded=False,
                            error_code="LOCAL_PRINTER_ERROR",
                            error_message=error_message[:1024],
                        )
                    except Exception:
                        raise PHSPhysicalPrintError(
                            "실제 출력과 중앙 실패 ACK가 모두 복구 대기 중입니다."
                        )
                    failed = self._save(
                        state,
                        status="PRINT_FAILED",
                        print_failure_ack=dict(failed_ack),
                    )
                    return self._result(
                        failed,
                        success=False,
                        message=(
                            "실제 출력에 실패했습니다. 기존 현품표는 ACTIVE로 "
                            "유지됩니다."
                        ),
                        error_code="LOCAL_PRINTER_ERROR",
                        retryable=True,
                    )
                try:
                    state = self._save(
                        state,
                        status="LOCAL_PRINT_SUCCEEDED",
                        local_print_proof=proof,
                    )
                except Exception as exc:
                    raise PHSLabelWorkflowError(
                        "PHS_LOCAL_PRINT_JOURNAL_UNCERTAIN",
                        "실물 출력은 제출됐지만 복구 journal에 spool 증거를 "
                        "저장하지 못했습니다. 출력물을 확인한 뒤 명시적으로 "
                        "재출력을 승인해야 합니다.",
                        retryable=True,
                    ) from exc

            state = self._save(state, status="PRINT_COMPLETE_PENDING")
            notify("실제 spool 증거를 중앙 print-attempt에 완료 기록합니다.")
            completed = self.client.complete_phs_label_print(
                str(state.get("print_attempt_id") or ""),
                authority_scope_id=scope,
                succeeded=True,
                rendered_artifact_hash=str(
                    state.get("rendered_artifact_hash") or ""
                ),
                proof=dict(state.get("local_print_proof") or {}),
            )
            completed_attempt = (
                dict(completed.get("print_attempt"))
                if isinstance(completed.get("print_attempt"), Mapping)
                else {}
            )
            completed_exchange = (
                dict(completed.get("exchange"))
                if isinstance(completed.get("exchange"), Mapping)
                else {}
            )
            if (
                str(completed_attempt.get("state") or "").strip().upper()
                != "SUCCEEDED"
                or str(completed_exchange.get("state") or "").strip().upper()
                != "READY"
            ):
                raise PHSLabelWorkflowError(
                    "PHS_PRINT_COMPLETE_ACK_INVALID",
                    "중앙 SUCCEEDED print/READY exchange 증거가 없습니다.",
                )
            exchange = completed_exchange
            exchange_state = "READY"
            state = self._save(
                state,
                status="PRINT_COMPLETED",
                print_complete_ack=dict(completed),
                exchange_entity_version=_positive_integer(
                    exchange.get("entity_version"),
                    "exchange_entity_version",
                ),
            )

        if exchange_state != "READY":
            raise PHSLabelWorkflowError(
                "PHS_LABEL_EXCHANGE_NOT_READY",
                "모든 target의 실제 출력 성공 전에는 활성화할 수 없습니다.",
            )
        expected_exchange_version = _positive_integer(
            exchange.get("entity_version")
            or state.get("exchange_entity_version"),
            "exchange_entity_version",
        )
        state = self._save(
            state,
            status="ACTIVATE_PENDING",
            exchange_entity_version=expected_exchange_version,
        )
        notify("출력 성공 증거를 확인하고 새 현품표를 중앙 ACTIVE로 전환합니다.")
        try:
            activated = self.client.activate_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
                expected_exchange_version=expected_exchange_version,
            )
        except Exception:
            activated = self.client.get_phs_label_exchange(
                exchange_id,
                authority_scope_id=scope,
            )
        activated_exchange = (
            dict(activated.get("exchange"))
            if isinstance(activated.get("exchange"), Mapping)
            else {}
        )
        if (
            str(
                activated.get("status")
                or activated_exchange.get("state")
                or ""
            )
            .strip()
            .upper()
            != "COMMITTED"
            or str(activated_exchange.get("exchange_id") or "").strip()
            != exchange_id
        ):
            raise PHSLabelWorkflowError(
                "PHS_ACTIVATE_ACK_INVALID",
                "중앙 COMMITTED exchange 증거가 없습니다.",
                retryable=True,
            )
        try:
            self._apply_target_to_tray(
                tray,
                target_label,
                canonical_input_tag_qr=str(
                    state.get("canonical_input_tag_qr") or ""
                ),
                persist_tray=persist_tray,
            )
        except PHSLabelWorkflowError:
            self._save(
                state,
                status="COMMITTED_LOCAL_REFRESH_PENDING",
                committed_ack=dict(activated),
            )
            raise
        committed = self._save(
            state,
            status="COMMITTED",
            committed_ack=dict(activated),
        )
        return self._result(
            committed,
            success=True,
            message=(
                "현품표 날짜 교환 완료: "
                f"{target_label.get('business_date')} · "
                f"{target_label.get('worker_code')} · "
                "현재 트레이/스캔 진행은 그대로 유지됩니다."
            ),
        )

    def recover_for_tray(
        self,
        tray: Any,
        *,
        persist_tray: Callable[[], bool] | None = None,
        status_callback: Callable[[str], None] | None = None,
    ) -> PHSLabelExchangeResult | None:
        state = self.journal.load()
        status = str(state.get("status") or "").strip().upper()
        if (
            not state
            or status in _TERMINAL_JOURNAL_STATES
            or str(state.get("canonical_input_tag_qr") or "").strip()
            != str(getattr(tray, "master_label_code", "") or "").strip()
        ):
            return None
        target = (
            dict(state.get("target_instruction"))
            if isinstance(state.get("target_instruction"), Mapping)
            else None
        )
        return self.execute_single(
            tray,
            target,
            persist_tray=persist_tray,
            status_callback=status_callback,
        )


__all__ = [
    "PHSLabelExchangeCoordinator",
    "PHSLabelExchangeJournal",
    "PHSLabelExchangeResult",
    "PHSLabelRenderer",
    "PHSLabelWorkflowError",
    "PHSPhysicalPrintError",
    "PhysicalPrintEvidence",
    "RenderedPHSLabel",
    "WindowsGDIPhysicalLabelPrinter",
]
