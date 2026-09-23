"""Read recovery evidence once, retaining bytes even when its shape is invalid."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from preflight_scan_hold import PreflightHoldSnapshot
from tray_state import OPERATOR_REVIEW_STATE_KEY, TrayStateValidationError, validate_tray_state


@dataclass(frozen=True)
class RecoveryRead:
    path: Path
    raw: bytes | None
    sha256: str | None
    value: Any | None
    reason: str | None

    @property
    def verified(self) -> bool:
        return self.reason is None


def _validated_payload(raw: bytes, kind: str, tray_size: int) -> Any:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    if kind == "json":
        pass
    elif kind == "parked_summary":
        if (not isinstance(value.get("worker_name"), str)
                or not isinstance(value.get("scanned_barcodes"), list)
                or any(not isinstance(item, str) for item in value["scanned_barcodes"])):
            raise ValueError("parked summary fields invalid")
    elif kind == "hold":
        text_fields = ("schema_version", "preflight_id", "worker", "master_raw",
                       "created_at", "updated_at", "state")
        if any(not isinstance(value.get(field), str) or not value[field]
               for field in text_fields):
            raise ValueError("preflight hold field type invalid")
        if (type(value.get("scan_epoch")) is not int
                or not isinstance(value.get("items"), list)
                or "error_code" in value and not isinstance(value["error_code"], str)):
            raise ValueError("preflight hold field type invalid")
        for item in value["items"]:
            if (not isinstance(item, dict)
                    or any(not isinstance(item.get(field), str) or not item[field]
                           for field in ("scan_id", "raw_barcode", "admitted_at"))
                    or type(item.get("sequence")) is not int):
                raise ValueError("preflight hold item field type invalid")
        PreflightHoldSnapshot.from_payload(value)
    elif kind in {"current", "parked", "stale"}:
        validate_tray_state(value, default_tray_size=tray_size)
    elif kind == "released":
        if (not isinstance(value.get("id"), str) or len(value["id"]) != 64
                or any(character not in "0123456789abcdef" for character in value["id"])):
            raise ValueError("release id missing")
    elif kind == "manager_hold":
        if (value.get("schema") != "container-audit-paired-manager-hold-v1"
                or not isinstance(value.get("labels"), list)
                or len(value["labels"]) != 2
                or any(not isinstance(label, str) or not label for label in value["labels"])):
            raise ValueError("manager hold invalid")
        if "source_sha256" in value and (
            not isinstance(value["source_sha256"], str)
            or len(value["source_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in value["source_sha256"])
        ):
            raise ValueError("manager hold source SHA256 invalid")
        if "evidence_sha256" in value:
            hashes = value["evidence_sha256"]
            if (not isinstance(hashes, dict)
                    or set(hashes) != {"record.json", "hold.original", "current.original", "released.json"}
                    or any(digest is not None and (
                        not isinstance(digest, str) or len(digest) != 64
                        or any(character not in "0123456789abcdef" for character in digest)
                    ) for digest in hashes.values())):
                raise ValueError("manager hold evidence SHA256 invalid")
    elif kind == "parked_manager_hold":
        if (value.get("schema") != "container-audit-parked-manager-hold-v1"
                or not isinstance(value.get("label"), str) or not value["label"]
                or not isinstance(value.get("source_sha256"), str)
                or len(value["source_sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in value["source_sha256"])):
            raise ValueError("parked manager hold invalid")
    elif kind == "stale_hold":
        if (value.get("schema") != "container-audit-stale-current-hold-v1"
                or not isinstance(value.get("labels"), list)
                or any(not isinstance(label, str) or not label for label in value["labels"])
                or not isinstance(value.get("original_sha256"), str)
                or not isinstance(value.get("changed_sha256"), str)):
            raise ValueError("stale current hold invalid")
    elif kind == "record":
        if (value.get("schema") != "container-audit-paired-preflight-v1"
                or not isinstance(value.get("id"), str)
                or len(value["id"]) != 64
                or not isinstance(value.get("created_at"), str)):
            raise ValueError("paired record header invalid")
        parts = []
        for name in ("hold", "current"):
            part = value.get(name)
            if not isinstance(part, dict):
                raise ValueError(f"{name} part invalid")
            source = part.get("path")
            digest = part.get("sha256")
            encoded = part.get("bytes_b64")
            components = Path(source).parts[1:] if isinstance(source, str) else ()
            if (not isinstance(source, str) or not Path(source).is_absolute()
                    or "\x00" in source or ".." in Path(source).parts
                    or len(source) > 240 or Path(source).is_reserved()
                    or any(Path(piece).is_reserved() or len(piece) > 255
                           or piece.rstrip(" .") != piece
                           or any(character in '<>:"|?*' or ord(character) < 32
                                  for character in piece)
                           for piece in components)
                    or not isinstance(digest, str) or len(digest) != 64
                    or not isinstance(encoded, str)):
                raise ValueError(f"{name} part fields invalid")
            original = base64.b64decode(encoded, validate=True)
            if hashlib.sha256(original).hexdigest() != digest:
                raise ValueError(f"{name} SHA256 differs")
            _validated_payload(original, name, tray_size)
            parts.append((source, digest))
        identity = hashlib.sha256(
            "".join(source + digest for source, digest in parts).encode("utf-8")
        ).hexdigest()
        if value["id"] != identity:
            raise ValueError("paired identity differs")
    else:
        raise ValueError(f"unknown recovery kind: {kind}")
    return value


def read_recovery_file(path: Path, kind: str, *, tray_size: int = 60) -> RecoveryRead:
    """One read per file; invalid content remains available as exact evidence."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except Exception as exc:
        return RecoveryRead(path, None, None, None, f"파일을 읽을 수 없음 ({exc.__class__.__name__})")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        value = _validated_payload(raw, kind, tray_size)
    except Exception as exc:
        # Keep only a reviewed field name in diagnostics; a validator message
        # may otherwise contain untrusted content from the saved document.
        field = (f": {OPERATOR_REVIEW_STATE_KEY}"
                 if isinstance(exc, TrayStateValidationError)
                 and str(exc).startswith(OPERATOR_REVIEW_STATE_KEY) else "")
        return RecoveryRead(path, raw, digest, None,
                            f"내용 또는 SHA256 확인 실패 ({exc.__class__.__name__}{field})")
    return RecoveryRead(path, raw, digest, value, None)
