"""Shared worker roster and optional identity on new business records."""

from __future__ import annotations

import datetime
import hashlib
import json
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Mapping

from storage_utils import atomic_write_json
from writer_session_fence import writer_sink

CONTRACT_VERSION = "worker-roster.v1"
MAX_RESPONSE_BYTES = 262144
# Local indentation adds bytes to a valid wire response; bound disk reads separately.
MAX_CACHE_BYTES = 2 * MAX_RESPONSE_BYTES + 1024


def record_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep old records absent; never invent a number for a local name."""
    if "worker_name_snapshot" not in value and "worker_id" not in value:
        return {}
    name = value.get("worker_name_snapshot")
    worker_id = value.get("worker_id")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("invalid worker name snapshot")
    if worker_id is not None and (
        not isinstance(worker_id, str) or str(uuid.UUID(worker_id)) != worker_id
    ):
        raise ValueError("invalid record worker id")
    return {"worker_id": worker_id, "worker_name_snapshot": name}


def record_owner_matches(value: Mapping[str, Any], *, worker_name: str,
                         worker_id: str = "") -> bool:
    identity = record_identity(value)
    if identity.get("worker_id"):
        return identity["worker_id"] == worker_id
    return str(value.get("worker_name") or value.get("worker") or "").strip() == worker_name


def record_identity_enabled(answer: Any) -> bool:
    if not isinstance(answer, Mapping):
        return False
    capabilities = answer.get("capabilities")
    capability = capabilities.get("worker_record_identity_v1") if isinstance(capabilities, Mapping) else None
    return isinstance(capability, Mapping) and capability.get("enabled") is True


def _digest(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate roster field")
        result[name] = value
    return result


class WorkerRoster:
    def __init__(self, path: str | Path, authority_scope_id: str):
        self.path = Path(path)
        self.good_path = self.path.with_name(self.path.stem + ".last-good.json")
        self.authority_scope_id = authority_scope_id
        self.snapshot: dict[str, Any] | None = None
        self.load()

    def _validate(self, value: Any, *, cache: bool = False) -> dict[str, Any]:
        if (not isinstance(value, dict) or value.get("contract_version") != CONTRACT_VERSION
                or not self.authority_scope_id
                or value.get("authority_scope_id") != self.authority_scope_id
                or type(value.get("version")) is not int or value["version"] < 0):
            raise ValueError("invalid roster identity or version")
        if cache:
            fields = {"contract_version", "authority_scope_id", "version", "workers", "fetched_at", "sha256"}
            if set(value) not in (fields, fields | {"source_row_count"}):
                raise ValueError("invalid roster cache fields")
            unsigned = {name: item for name, item in value.items() if name != "sha256"}
            if value["sha256"] != _digest(unsigned):
                raise ValueError("roster digest mismatch")
            fetched = datetime.datetime.fromisoformat(value["fetched_at"])
            if fetched.tzinfo is None:
                raise ValueError("invalid roster fetch time")
        rows = value.get("workers")
        if not isinstance(rows, list):
            raise ValueError("invalid roster workers")
        source_row_count = value.get("source_row_count", len(rows)) if cache else len(rows)
        if type(source_row_count) is not int or source_row_count < len(rows):
            raise ValueError("invalid roster source row count")
        workers, seen = [], set()
        for row in rows:
            if (not isinstance(row, dict) or type(row.get("worker_id")) is not str
                    or str(uuid.UUID(row["worker_id"])) != row["worker_id"]
                    or row["worker_id"] in seen or row.get("status") not in {"ACTIVE", "DISABLED"}
                    or type(row.get("display_name")) is not str):
                raise ValueError("invalid or duplicate roster worker")
            seen.add(row["worker_id"])
            name = row["display_name"].strip()
            if (name and len(name) <= 64 and not name.startswith(("=", "+", "-", "@"))
                    and not any(character in '\\/:*?"<>|' for character in name)
                    and not any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
                                for character in row["display_name"])):
                workers.append({"worker_id": row["worker_id"], "display_name": name, "status": row["status"]})
        return {"contract_version": CONTRACT_VERSION, "authority_scope_id": self.authority_scope_id,
                 "version": value["version"], "workers": workers, "source_row_count": source_row_count}

    @writer_sink("worker_roster_quarantine")
    def _preserve_bad(self, path: Path) -> None:
        # A rename preserves the exact bytes, including malformed UTF-8/JSON.
        path.replace(path.with_name(path.name + ".bad-" + uuid.uuid4().hex))

    def load(self) -> None:
        for path in (self.path, self.good_path):
            try:
                with path.open("rb") as stream:
                    raw = stream.read(MAX_CACHE_BYTES + 1)
                if len(raw) > MAX_CACHE_BYTES:
                    raise ValueError("oversized roster cache")
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
                normalized = self._validate(value, cache=True)
                self.snapshot = normalized | {"fetched_at": value["fetched_at"]}
                return
            except FileNotFoundError:
                continue
            except (ValueError, TypeError, UnicodeError, AttributeError):
                self._preserve_bad(path)
            except OSError:
                continue

    @property
    def known_version(self) -> int | None:
        return self.snapshot["version"] if self.snapshot is not None else None

    @property
    def has_rows(self) -> bool:
        return self.snapshot is not None and self.snapshot["source_row_count"] > 0

    @writer_sink("worker_roster_cache")
    def apply(self, answer: Any, *, requested_version: int | None) -> None:
        if (not isinstance(answer, dict) or answer.get("ok") is not True
                or type(answer.get("unchanged")) is not bool):
            raise ValueError("unsuccessful roster response")
        if answer["unchanged"]:
            if (self.snapshot is None or requested_version != self.known_version
                    or answer.get("version") != requested_version
                    or answer.get("contract_version") != CONTRACT_VERSION
                    or answer.get("authority_scope_id") != self.authority_scope_id
                    or type(answer.get("version")) is not int):
                raise ValueError("unchanged roster has no matching cache")
            value = self._validate(self.snapshot)
            value["source_row_count"] = self.snapshot["source_row_count"]
        else:
            value = self._validate(answer)
            if self.known_version is not None and value["version"] < self.known_version:
                raise ValueError("obsolete roster version")
        value["fetched_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        value["sha256"] = _digest(value)
        atomic_write_json(self.good_path, value, indent=2, ensure_ascii=False, trailing_newline=True)
        atomic_write_json(self.path, value, indent=2, ensure_ascii=False, trailing_newline=True)
        self.snapshot = value

    def active_workers(self) -> list[dict[str, str]]:
        return [row for row in (self.snapshot or {}).get("workers", []) if row["status"] == "ACTIVE"]

    def active_worker(self, *, worker_id: str = "", name: str = "") -> dict[str, str] | None:
        for row in self.active_workers():
            matches = row["worker_id"] == worker_id if worker_id else row["display_name"] == name
            if matches:
                return row
        return None
