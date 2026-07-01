import datetime
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from storage_utils import atomic_write_json

FORMULA_PREFIX_CHARS = ("=", "+", "-", "@")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


class WorkerRegistry:
    def __init__(self, registry_path: str):
        self.registry_path = registry_path

    @staticmethod
    def normalize_name(name: str) -> str:
        return str(name or "").strip()

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name:
            raise ValueError("작업자 이름은 비워둘 수 없습니다.")
        if CONTROL_CHAR_RE.search(name):
            raise ValueError("작업자 이름에는 제어 문자를 사용할 수 없습니다.")
        if name.startswith(FORMULA_PREFIX_CHARS):
            raise ValueError("작업자 이름은 = + - @ 문자로 시작할 수 없습니다.")
        if re.search(r'[\\/:*?"<>|]', name):
            raise ValueError("작업자 이름에는 \\ / : * ? \" < > | 문자를 사용할 수 없습니다.")

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
        return {"workers": self._sanitize_worker_entries(payload.get("workers", []))}

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
            try:
                self._validate_name(name)
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
        return self.normalize_name(name) in set(self.list_workers())

    def register(self, name: str) -> str:
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

    def mark_recent(self, name: str) -> str:
        name = self.normalize_name(name)
        self._validate_name(name)
        payload = self._read_payload()
        workers = payload.setdefault("workers", [])
        now = datetime.datetime.now().isoformat(timespec="seconds")
        for entry in workers:
            if isinstance(entry, dict) and self.normalize_name(entry.get("name", "")) == name:
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
            }
        )
        self._write_payload(payload)
        return name
