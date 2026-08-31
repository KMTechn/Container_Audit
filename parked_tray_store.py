from __future__ import annotations

import json
import os
import re
import uuid
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping

from label_qr import canonical_master_label_key, parse_new_format_qr
from protected_admin import persistent_operator_name
from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


def sanitize_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "_", str(filename))


def _safe_worker_filename(worker_name: str) -> str:
    return sanitize_filename(persistent_operator_name(worker_name)) or "worker"


@dataclass(frozen=True)
class ParkedTraySummary:
    path: Path
    item_name: str
    scan_count: int


@dataclass(frozen=True)
class ParkedRecoveryDeferResult:
    path: Path
    defer_id: str
    state_hash: str
    replayed: bool


class ParkedTrayStore:
    def __init__(self, directory: str | os.PathLike[str]):
        self.directory = Path(directory)

    def deterministic_label_path(self, *, worker_name: str, master_label: str) -> Path | None:
        if not parse_new_format_qr(master_label):
            return None
        safe_worker = _safe_worker_filename(worker_name)
        safe_prefix = sanitize_filename(master_label)[:16].rstrip("_") or "label"
        digest = hashlib.sha256(canonical_master_label_key(master_label).encode("utf-8")).hexdigest()[:16]
        return self.directory / f"parked_qr_{safe_worker}_{safe_prefix}_{digest}.json"

    def legacy_deterministic_label_path(self, *, worker_name: str, master_label: str) -> Path | None:
        if not parse_new_format_qr(master_label):
            return None
        safe_worker = _safe_worker_filename(worker_name)
        return self.directory / f"parked_qr_{safe_worker}_{sanitize_filename(master_label)}.json"

    def existing_label_path(self, *, worker_name: str, master_label: str) -> Path | None:
        for path in (
            self.deterministic_label_path(worker_name=worker_name, master_label=master_label),
            self.legacy_deterministic_label_path(worker_name=worker_name, master_label=master_label),
        ):
            if path is not None and path.exists():
                return path
        return None

    def existing_label_path_any_worker(self, *, master_label: str) -> Path | None:
        if not self.directory.exists():
            return None
        target_key = canonical_master_label_key(master_label)
        for path in sorted(self.directory.glob("parked_*.json")):
            try:
                data = self.load(path)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            parked_label = str(data.get("master_label_code") or "")
            if parked_label and canonical_master_label_key(parked_label) == target_key:
                return path
        return None

    @staticmethod
    def _canonical_state_hash(state: Mapping[str, Any]) -> str:
        encoded = json.dumps(
            dict(state),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @writer_sink("parked_recovery_defer")
    def defer_recovery_state(
        self,
        state: Mapping[str, Any],
        *,
        worker_name: str,
        computer_id: str,
    ) -> ParkedRecoveryDeferResult:
        """Promote a recovery snapshot to an idempotent parked owner.

        This method never deletes the current recovery slot.  The caller must
        durably audit the ownership change before releasing that slot.
        """

        payload = dict(state)
        payload["worker_name"] = persistent_operator_name(
            payload.get("worker_name") or worker_name
        )
        safe_worker = _safe_worker_filename(payload["worker_name"] or worker_name)
        host = str(computer_id or "").strip()
        if not host:
            raise ValueError("computer_id is required for recovery defer")
        state_hash = self._canonical_state_hash(payload)
        defer_id = "tray-recovery-defer-" + hashlib.sha256(
            f"{host}:{payload['worker_name']}:{state_hash}".encode("utf-8")
        ).hexdigest()[:32]
        path = self.directory / f"parked_recovery_{safe_worker}_{state_hash[:16]}.json"
        self.directory.mkdir(parents=True, exist_ok=True)

        replayed = False
        if path.exists():
            existing = self.load(path)
            if self._canonical_state_hash(existing) != state_hash:
                raise FileExistsError("parked recovery identity collision")
            replayed = True
        else:
            atomic_write_json(path, payload, indent=4, ensure_ascii=False)

        readback = self.load(path)
        if self._canonical_state_hash(readback) != state_hash or readback != payload:
            raise OSError("parked recovery readback verification failed")
        return ParkedRecoveryDeferResult(
            path=path,
            defer_id=defer_id,
            state_hash=state_hash,
            replayed=replayed,
        )

    @writer_sink("parked_tray_save")
    def save_state(
        self,
        state: Mapping[str, Any],
        *,
        worker_name: str,
        master_label: str,
    ) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        existing_path = self.existing_label_path(worker_name=worker_name, master_label=master_label)
        if existing_path is not None:
            raise FileExistsError(f"parked tray already exists for master label: {existing_path}")
        label_path = self.deterministic_label_path(worker_name=worker_name, master_label=master_label)
        if label_path is not None:
            path = label_path
        else:
            safe_worker = _safe_worker_filename(worker_name)
            path = self.directory / f"parked_legacy_{safe_worker}_{sanitize_filename(master_label)}_{uuid.uuid4().hex[:8]}.json"
        payload = dict(state)
        payload["worker_name"] = persistent_operator_name(
            payload.get("worker_name") or worker_name
        )
        atomic_write_json(path, payload, indent=4, ensure_ascii=False)
        return path

    def list_for_worker(self, worker_name: str) -> List[ParkedTraySummary]:
        if not self.directory.exists():
            return []
        summaries: List[ParkedTraySummary] = []
        for path in sorted(self.directory.glob("parked_*.json")):
            try:
                data = self.load(path)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            stored_worker = persistent_operator_name(data.get("worker_name"))
            requested_worker = persistent_operator_name(worker_name)
            if stored_worker:
                if stored_worker != requested_worker:
                    continue
            elif f"_{_safe_worker_filename(requested_worker)}_" not in path.name:
                continue
            summaries.append(
                ParkedTraySummary(
                    path=path,
                    item_name=str(data.get("item_name") or "알 수 없음"),
                    scan_count=len(data.get("scanned_barcodes") or []),
                )
            )
        return summaries

    @staticmethod
    @writer_sink("parked_tray_load_normalize")
    def load(path: str | os.PathLike[str]) -> Dict[str, Any]:
        source = Path(path)
        with source.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise json.JSONDecodeError("parked tray payload must be an object", "", 0)
        saved_worker = str(payload.get("worker_name") or "").strip()
        safe_worker = persistent_operator_name(saved_worker)
        if safe_worker != saved_worker:
            payload["worker_name"] = safe_worker
            atomic_write_json(source, payload, indent=4, ensure_ascii=False)
        return payload

    @staticmethod
    @writer_sink("parked_tray_delete")
    def delete(path: str | os.PathLike[str]) -> None:
        Path(path).unlink()
