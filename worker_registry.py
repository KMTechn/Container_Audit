import datetime
import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

from protected_admin import (
    PROTECTED_ADMIN_DISPLAY_NAME,
    PROTECTED_ADMIN_OPERATOR_ID,
    is_protected_admin_candidate,
)
from storage_utils import atomic_write_json
from writer_session_fence import writer_sink

FORMULA_PREFIX_CHARS = ("=", "+", "-", "@")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


class WorkerRegistry:
    def __init__(self, registry_path: str):
        self.registry_path = registry_path

    @staticmethod
    def normalize_name(name: str) -> str:
        return str(name or "").strip()

    @staticmethod
    def _validate_name(name: str, *, roster_identity: bool = False, legacy_local: bool = False) -> None:
        if not name:
            raise ValueError("작업자 이름은 비워둘 수 없습니다.")
        # Existing local names retain the registration rules of the baseline.
        if (CONTROL_CHAR_RE.search(name) if legacy_local else
                any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in name)):
            raise ValueError("작업자 이름에는 제어 문자를 사용할 수 없습니다.")
        if not legacy_local and len(name.strip()) > 64:
            raise ValueError("작업자 이름은 64자까지 사용할 수 있습니다.")
        if name.strip().startswith(FORMULA_PREFIX_CHARS):
            raise ValueError("작업자 이름은 = + - @ 문자로 시작할 수 없습니다.")
        if re.search(r'[\\/:*?"<>|]', name):
            raise ValueError("작업자 이름에는 \\ / : * ? \" < > | 문자를 사용할 수 없습니다.")
        if name in {PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME}:
            raise ValueError("보호된 관리자 식별자는 일반 작업자로 등록할 수 없습니다.")
        if not roster_identity and is_protected_admin_candidate(name):
            raise ValueError("6자리 숫자 입력은 관리자 인증에만 사용할 수 있습니다.")

    @staticmethod
    def _timestamp_sort_value(value: Any) -> Optional[float]:
        text = str(value or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.datetime.fromisoformat(text).timestamp()
        except ValueError:
            return None

    @classmethod
    def _worker_sort_key(cls, entry: Dict[str, Any]) -> tuple[int, float, str]:
        for key in ("last_used_at", "last_login_at"):
            value = cls._timestamp_sort_value(entry.get(key))
            if value is not None:
                return (0, -value, cls.normalize_name(entry.get("name", "")))
        for key in ("updated_at", "created_at"):
            value = cls._timestamp_sort_value(entry.get(key))
            if value is not None:
                return (1, -value, cls.normalize_name(entry.get("name", "")))
        return (2, 0.0, cls.normalize_name(entry.get("name", "")))

    def _read_payload(self) -> Dict[str, Any]:
        if not os.path.exists(self.registry_path):
            return {"workers": []}
        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except json.JSONDecodeError:
            self._quarantine_registry_file()
            return {"workers": []}
        except OSError:
            return {"workers": []}
        if not isinstance(payload, dict) or not isinstance(payload.get("workers"), list):
            self._quarantine_registry_file()
            return {"workers": []}
        raw_workers = payload.get("workers", [])
        sanitized_workers = self._sanitize_worker_entries(raw_workers)
        if sanitized_workers != raw_workers:
            sanitized_payload = dict(payload)
            sanitized_payload["workers"] = sanitized_workers
            self._write_payload(sanitized_payload)
        result = dict(payload, workers=sanitized_workers)
        if "automatic_start_enabled" in payload:
            result["automatic_start_enabled"] = payload["automatic_start_enabled"]
        return result

    @writer_sink("worker_registry_quarantine")
    def _quarantine_registry_file(self) -> str:
        source = Path(self.registry_path)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        target = source.with_name(f"{source.name}.bad-{timestamp}")
        suffix = 1
        while target.exists():
            target = source.with_name(f"{source.name}.bad-{timestamp}-{suffix}")
            suffix += 1
        source.replace(target)
        return str(target)

    def _sanitize_worker_entries(self, entries: List[Any]) -> List[Dict[str, Any]]:
        by_name: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = self.normalize_name(entry.get("name", ""))
            if (
                (is_protected_admin_candidate(name) and not entry.get("worker_id"))
                or name in {PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME}
            ):
                continue
            try:
                self._validate_name(str(entry.get("name") or ""), roster_identity=bool(entry.get("worker_id")),
                                    legacy_local=not entry.get("worker_id"))
                self._validate_name(name, roster_identity=bool(entry.get("worker_id")),
                                    legacy_local=not entry.get("worker_id"))
            except ValueError:
                continue
            active_value = entry.get("active", True)
            if not isinstance(active_value, bool):
                continue
            if name not in by_name:
                sanitized = dict(entry)
                sanitized["name"] = name
                sanitized["active"] = active_value
                by_name[name] = sanitized
                order.append(name)
            else:
                by_name[name]["active"] = bool(by_name[name]["active"] or active_value)
                for key in ("last_used_at", "last_login_at", "updated_at", "created_at"):
                    incoming_value = entry.get(key)
                    if self._timestamp_sort_value(incoming_value) is None:
                        continue
                    current_value = by_name[name].get(key)
                    current_sort = self._timestamp_sort_value(current_value)
                    incoming_sort = self._timestamp_sort_value(incoming_value)
                    if current_sort is None or (incoming_sort is not None and incoming_sort > current_sort):
                        by_name[name][key] = incoming_value
        return [by_name[name] for name in order]

    @writer_sink("worker_registry_write")
    def _write_payload(self, payload: Dict[str, Any]) -> None:
        atomic_write_json(self.registry_path, payload, indent=2, ensure_ascii=False, trailing_newline=True)

    def list_workers(self) -> List[str]:
        workers: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for entry in self._read_payload().get("workers", []):
            if not isinstance(entry, dict) or not entry.get("active", True):
                continue
            name = self.normalize_name(entry.get("name", ""))
            if name and name not in seen:
                workers.append(entry)
                seen.add(name)
        workers.sort(key=self._worker_sort_key)
        return [self.normalize_name(entry.get("name", "")) for entry in workers]

    def has_worker(self, name: str) -> bool:
        normalized = self.normalize_name(name)
        if (
            is_protected_admin_candidate(normalized)
            or normalized in {PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME}
        ):
            return False
        return normalized in set(self.list_workers())

    def recent_worker(self) -> Optional[str]:
        """Read the last used identity without substituting another active name."""
        try:
            with open(self.registry_path, "r", encoding="utf-8") as stream:
                payload = json.load(stream)
            entries = payload["workers"]
            if not isinstance(entries, list):
                return None
            recent = []
            for entry in entries:
                if not isinstance(entry, dict):
                    return None
                used = entry.get("last_used_at") or entry.get("last_login_at")
                if not used:
                    continue
                timestamp = self._timestamp_sort_value(used)
                if timestamp is None:
                    return None
                recent.append((timestamp, entry))
            if not recent:
                return None
            latest = max(timestamp for timestamp, _entry in recent)
            candidates = [entry for timestamp, entry in recent if timestamp == latest]
            names = {self.normalize_name(entry.get("name", "")) for entry in candidates}
            if len(names) != 1 or any(entry.get("active", True) is not True for entry in candidates):
                return None
            name = names.pop()
            self._validate_name(name, roster_identity=bool(candidates[0].get("worker_id")),
                                legacy_local=not candidates[0].get("worker_id"))
            return name
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            return None

    def automatic_start_enabled(self) -> bool:
        try:
            with open(self.registry_path, "r", encoding="utf-8") as stream:
                payload = json.load(stream)
            return isinstance(payload, dict) and payload.get("automatic_start_enabled", True) is True
        except (OSError, UnicodeError, ValueError):
            return False

    def disable_automatic_start(self) -> None:
        # Keep names and usage timestamps: selection order is independent of startup eligibility.
        try:
            with open(self.registry_path, "r", encoding="utf-8") as stream:
                payload = json.load(stream)
        except FileNotFoundError:
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("workers"), list):
            raise ValueError("Invalid worker registry")
        if payload.get("automatic_start_enabled") is False:
            return
        payload["automatic_start_enabled"] = False
        self._write_payload(payload)

    def register(self, name: str) -> str:
        self._validate_name(str(name or ""))
        name = self.normalize_name(name)
        self._validate_name(name)
        payload = self._read_payload()
        workers = payload.setdefault("workers", [])
        for entry in workers:
            if isinstance(entry, dict) and self.normalize_name(entry.get("name", "")) == name:
                entry["active"] = True
                self._write_payload(payload)
                return name
        workers.append(
            {
                "name": name,
                "active": True,
                "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
            }
        )
        self._write_payload(payload)
        return name

    def mark_recent(self, name: str, *, worker_id: str = "") -> str:
        legacy_local = not worker_id and self.has_worker(name)
        self._validate_name(str(name or ""), roster_identity=bool(worker_id), legacy_local=legacy_local)
        name = self.normalize_name(name)
        self._validate_name(name, roster_identity=bool(worker_id), legacy_local=legacy_local)
        payload = self._read_payload()
        workers = payload.setdefault("workers", [])
        # Keep the existing ISO timestamp field, including distinct starts in
        # the same second (for example an immediate worker change).
        payload["automatic_start_enabled"] = True
        now = datetime.datetime.now().isoformat(timespec="microseconds")
        for entry in workers:
            if isinstance(entry, dict) and (entry.get("worker_id") == worker_id if worker_id and entry.get("worker_id")
                                           else self.normalize_name(entry.get("name", "")) == name):
                entry["name"] = name
                if worker_id:
                    entry["worker_id"] = worker_id
                entry["active"] = True
                entry["last_used_at"] = now
                self._write_payload(payload)
                return name
        workers.append(
            {
                "name": name,
                "active": True,
                "created_at": now,
                "last_used_at": now,
                **({"worker_id": worker_id} if worker_id else {}),
            }
        )
        self._write_payload(payload)
        return name

    def recent_worker_id(self) -> str:
        name = self.recent_worker()
        for entry in self._read_payload()["workers"]:
            if entry["name"] == name:
                return str(entry.get("worker_id") or "")
        return ""

    def bind_worker_id(self, name: str, worker_id: str) -> None:
        """Upgrade an old remembered name without changing its start eligibility."""
        payload = self._read_payload()
        for entry in payload["workers"]:
            if entry["name"] == name and not entry.get("worker_id"):
                entry["worker_id"] = worker_id
                self._write_payload(payload)
                return

    def worker_id_for_name(self, name: str) -> str:
        normalized = self.normalize_name(name)
        for entry in self._read_payload().get("workers", []):
            if self.normalize_name(entry.get("name", "")) == normalized:
                return str(entry.get("worker_id") or "")
        return ""

    def order_roster(self, rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
        entries = self._read_payload()["workers"]
        def recent(row):
            matches = [entry for entry in entries if
                       (entry.get("worker_id") == row["worker_id"] if entry.get("worker_id")
                        else entry["name"] == row["display_name"])]
            return min((self._worker_sort_key(entry) for entry in matches),
                       default=(2, 0.0, row["display_name"]))[:2] + (row["display_name"],)
        return sorted(rows, key=recent)
