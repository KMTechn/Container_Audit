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
from storage_utils import atomic_write_json


def sanitize_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "_", str(filename))


def _safe_worker_filename(worker_name: str) -> str:
    return sanitize_filename(str(worker_name).strip()) or "worker"


@dataclass(frozen=True)
class ParkedTraySummary:
    path: Path
    item_name: str
    scan_count: int


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
        atomic_write_json(path, dict(state), indent=4, ensure_ascii=False)
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
            stored_worker = str(data.get("worker_name") or "")
            if stored_worker:
                if stored_worker != worker_name:
                    continue
            elif f"_{_safe_worker_filename(worker_name)}_" not in path.name:
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
    def load(path: str | os.PathLike[str]) -> Dict[str, Any]:
        with Path(path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise json.JSONDecodeError("parked tray payload must be an object", "", 0)
        return payload

    @staticmethod
    def delete(path: str | os.PathLike[str]) -> None:
        Path(path).unlink()
