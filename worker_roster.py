"""Shared worker roster and optional identity on new business records."""

from __future__ import annotations

import datetime
import copy
import hashlib
import json
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Mapping

from storage_utils import atomic_write_json
from worker_registry import WorkerRegistry
from writer_session_fence import writer_admission, writer_sink

CONTRACT_VERSION = "worker-roster.v1"
CONTRACT_VERSION_V2 = "worker-roster.v2"
STAGE_A = False  # Stage B never hides workers or calculates inactivity.
MAX_RESPONSE_BYTES = 262144
# Local indentation adds bytes to a valid wire response; bound disk reads separately.
MAX_CACHE_BYTES = 2 * MAX_RESPONSE_BYTES + 1024
MAX_LOCAL_BYTES = 4 * 1024 * 1024


def normalize_registration_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("이름을 적어 주세요.")
    # Reject unsafe characters before whitespace normalization can erase them.
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value):
        raise ValueError("이름에 보이지 않는 문자가 있습니다. 다시 적어 주세요.")
    value = unicodedata.normalize("NFC", value)
    value = " ".join(value.split())
    WorkerRegistry._validate_name(value)
    return value


def registration_enabled(answer: Any) -> bool:
    if not isinstance(answer, Mapping):
        return False
    data = answer.get("data", answer)
    if not isinstance(data, Mapping):
        return False
    ids = data.get("capability_ids")
    capabilities = data.get("capabilities")
    signal = capabilities.get("worker_roster_v2") if isinstance(capabilities, Mapping) else None
    return (isinstance(ids, list) and "worker_roster_v2_stage_b" in ids) or (
        isinstance(signal, Mapping) and signal.get("stage_b") is True
        and signal.get("temporary_identity_ingest") is True)


def worker_choice_label(row: Mapping[str, Any]) -> str:
    number = row.get("worker_number")
    if number is None and row.get("local_sequence"):
        number = "임시" + str(row["local_sequence"])
    return row["display_name"] + (" #" + str(number) if number is not None else "")


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
        self.local_path = self.path.with_name(self.path.stem + ".registrations.json")
        self.local = {"schema": "worker-roster-b.local.v1", "authority_scope_id": authority_scope_id,
                      "sequence": 0, "workers": [], "requests": [], "temp_links": {}, "snapshot": None}
        self.local_blocked = False
        self.load()
        self._load_local()

    def _validate(self, value: Any, *, cache: bool = False) -> dict[str, Any]:
        if (not isinstance(value, dict) or value.get("contract_version") not in {CONTRACT_VERSION, CONTRACT_VERSION_V2}
                or not self.authority_scope_id
                or value.get("authority_scope_id") != self.authority_scope_id
                or type(value.get("version")) is not int or value["version"] < 0):
            raise ValueError("invalid roster identity or version")
        if cache:
            fields = {"contract_version", "authority_scope_id", "version", "workers", "fetched_at", "sha256"}
            if set(value) - fields - {"source_row_count", "unselectable_worker_ids"} or fields - set(value):
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
        source_row_count = value.get("source_row_count", len(rows))
        if type(source_row_count) is not int or source_row_count < len(rows):
            raise ValueError("invalid roster source row count")
        workers, seen, unselectable = [], set(), set(value.get("unselectable_worker_ids", []))
        if any(str(uuid.UUID(identity)) != identity for identity in unselectable):
            raise ValueError("invalid unselectable worker identity")
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
                normalized = {"worker_id": row["worker_id"], "display_name": name, "status": row["status"]}
                if value["contract_version"] == CONTRACT_VERSION_V2:
                    if type(row.get("worker_number")) is not int or row["worker_number"] < 1:
                        raise ValueError("invalid worker number")
                    normalized["worker_number"] = row["worker_number"]
                workers.append(normalized)
            else:
                unselectable.add(row["worker_id"])
        result = {"contract_version": value["contract_version"], "authority_scope_id": self.authority_scope_id,
                  "version": value["version"], "workers": workers, "source_row_count": source_row_count}
        if unselectable:
            result["unselectable_worker_ids"] = sorted(unselectable)
        return result

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

    def _validate_local(self, value):
        if (not isinstance(value, dict) or value.get("schema") != self.local["schema"]
                or value.get("authority_scope_id") != self.authority_scope_id
                or type(value.get("sequence")) is not int or value["sequence"] < 0
                or not isinstance(value.get("workers"), list)
                or not isinstance(value.get("requests"), list)
                or not isinstance(value.get("temp_links"), dict)):
            raise ValueError("invalid local registration envelope")
        unsigned = {key: item for key, item in value.items() if key != "sha256"}
        if value.get("sha256") != _digest(unsigned):
            raise ValueError("registration envelope digest mismatch")
        seen, sequences, creates = set(), set(), {}
        for row in value["workers"]:
            identity = row["worker_id"]
            if (str(uuid.UUID(identity)) != identity or identity in seen
                    or type(row["local_sequence"]) is not int or row["local_sequence"] < 1
                    or row["local_sequence"] > value["sequence"] or row["local_sequence"] in sequences
                    or normalize_registration_name(row["display_name"]) != row["display_name"]):
                raise ValueError("invalid local worker")
            seen.add(identity)
            sequences.add(row["local_sequence"])
        request_ids = set()
        for item in value["requests"]:
            request_id = item["request_id"]
            if (str(uuid.UUID(request_id)) != request_id or request_id in request_ids
                    or item["state"] not in {"PENDING", "ACKED", "REVIEW", "TERMINAL"}
                    or type(item["error"]) is not str):
                raise ValueError("invalid local request")
            request_ids.add(request_id)
            if item["body"] is not None:
                body = item["body"]
                self._validate_request(body)
                if body["request_id"] != request_id:
                    raise ValueError("request identity changed")
                if body["mode"] == "create":
                    if body["temp_uuid"] not in seen or body["temp_uuid"] in creates:
                        raise ValueError("missing or reused temporary worker")
                    creates[body["temp_uuid"]] = request_id
            elif not item.get("depends_on"):
                raise ValueError("request has no body or dependency")
        if seen != set(creates):
            raise ValueError("local worker lacks durable create request")
        for item in value["requests"]:
            if item.get("depends_on"):
                intent = item["intent"]
                if creates.get(intent["temp_uuid"]) != item["depends_on"]:
                    raise ValueError("invalid return dependency")
                self._action_time(intent["action_at"])
                normalize_registration_name(intent["display_name"])
        for temp_uuid, link in value["temp_links"].items():
            self._validate_link({"temp_uuid": temp_uuid, **link})
        if value.get("snapshot") is not None:
            self._validate(value["snapshot"])
        return unsigned

    @staticmethod
    def _action_time(value):
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
            raise ValueError("invalid registration action time")
        return parsed

    def _validate_request(self, body):
        mode = body.get("mode")
        fields = {"mode", "authority_scope_id", "request_id", "display_name", "action_at"}
        fields.add("temp_uuid" if mode == "create" else "existing_worker_id")
        if (mode not in {"create", "return"} or set(body) != fields
                or body["authority_scope_id"] != self.authority_scope_id
                or str(uuid.UUID(body["request_id"])) != body["request_id"]
                or normalize_registration_name(body["display_name"]) != body["display_name"]):
            raise ValueError("invalid registration request")
        identity = body["temp_uuid" if mode == "create" else "existing_worker_id"]
        if str(uuid.UUID(identity)) != identity:
            raise ValueError("invalid registration worker identity")
        self._action_time(body["action_at"])

    @staticmethod
    def _validate_link(link):
        if (not isinstance(link, dict) or type(link.get("worker_number")) is not int
                or link["worker_number"] < 1):
            raise ValueError("invalid temporary identity mapping")
        for key in ("temp_uuid", "worker_id"):
            if str(uuid.UUID(link[key])) != link[key]:
                raise ValueError("invalid mapping UUID")
        return {key: link[key] for key in ("worker_id", "worker_number")}

    def _load_local(self):
        try:
            with self.local_path.open("rb") as stream:
                raw = stream.read(MAX_LOCAL_BYTES + 1)
            if len(raw) > MAX_LOCAL_BYTES:
                raise ValueError("oversized registration envelope")
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            self.local = self._validate_local(value)
            self.local_blocked = False
            snapshot = self.local["snapshot"]
            if snapshot is not None and (self.known_version is None or snapshot["version"] >= self.known_version):
                self.snapshot = snapshot
        except FileNotFoundError:
            # Preserved damage must never be mistaken for a fresh empty queue.
            self.local_blocked = any(self.local_path.parent.glob(self.local_path.name + ".bad-*"))
        except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            self._preserve_bad(self.local_path)
            self.local_blocked = True
        except OSError:
            self.local_blocked = True

    @writer_sink("worker_roster_registration")
    def _save_local(self, value):
        if self.local_blocked:
            raise ValueError("이 PC의 이름 등록 기록을 확인해야 합니다. 기존 이름으로 작업을 계속하세요.")
        encoded = {**value, "sha256": _digest(value)}
        if len(json.dumps(encoded, ensure_ascii=False).encode("utf-8")) > MAX_LOCAL_BYTES // 2:
            raise ValueError("회사 서버로 보낼 이름이 많습니다. 기존 이름으로 작업을 계속하세요.")
        self._validate_local(encoded)
        atomic_write_json(self.local_path, encoded, indent=2, ensure_ascii=False, trailing_newline=True)
        self.local = value

    def duplicate_workers(self, name):
        name = normalize_registration_name(name)
        candidates = list((self.snapshot or {}).get("workers", [])) + self.local["workers"]
        result, seen = [], set()
        for row in candidates:
            if row.get("status", "ACTIVE") != "ACTIVE":
                continue
            try:
                matches = normalize_registration_name(row["display_name"]) == name
            except ValueError:
                matches = False
            identity = self.resolved_id(row["worker_id"])
            active = self.active_worker(worker_id=row["worker_id"])
            if matches and active is not None and identity not in seen:
                result.append(active)
                seen.add(identity)
        return result

    @writer_sink("worker_roster_registration")
    def register_local(self, name, *, existing_worker_id=""):
        name = normalize_registration_name(name)
        # Admission serializes processes; refresh the durable envelope while
        # holding it so another GUI's rows, requests and sequence are retained.
        self._load_local()
        value = copy.deepcopy(self.local)
        request_id = str(uuid.uuid4())
        action_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        body = {"mode": "create", "authority_scope_id": self.authority_scope_id,
                "request_id": request_id, "display_name": name, "action_at": action_at}
        item = {"request_id": request_id, "body": body, "state": "PENDING", "error": ""}
        if existing_worker_id:
            row = self.active_worker(worker_id=existing_worker_id)
            if row is None:
                raise ValueError("이 이름은 지금 사용할 수 없습니다. 다른 이름을 골라 주세요.")
            source = next((entry for entry in value["requests"]
                           if entry["body"] and entry["body"].get("temp_uuid") == existing_worker_id), None)
            if source is not None and existing_worker_id not in value["temp_links"]:
                item.update(body=None, depends_on=source["request_id"],
                            intent={"temp_uuid": existing_worker_id, "display_name": name, "action_at": action_at})
            else:
                body.update(mode="return", existing_worker_id=self.resolved_id(existing_worker_id))
            selected = existing_worker_id
        else:
            if self.duplicate_workers(name):
                raise ValueError("같은 이름이 있습니다. 같은 분인지 확인하거나 구분할 이름을 적어 주세요.")
            selected = str(uuid.uuid4())
            value["sequence"] += 1
            body["temp_uuid"] = selected
            value["workers"].append({"worker_id": selected, "display_name": name,
                                     "local_sequence": value["sequence"]})
        value["requests"].append(item)
        self._save_local(value)
        return self.active_worker(worker_id=selected)

    def pending_requests(self):
        return [copy.deepcopy(item["body"]) for item in self.local["requests"]
                if item["state"] == "PENDING" and item["body"] is not None]

    def resolved_id(self, worker_id):
        return self.local["temp_links"].get(worker_id, {}).get("worker_id", worker_id)

    def same_person(self, first, second):
        return bool(first and second and self.resolved_id(first) == self.resolved_id(second))

    def identity_aliases(self, worker_id):
        resolved = self.resolved_id(worker_id)
        return tuple(dict.fromkeys([worker_id, resolved] + [temp for temp, link in self.local["temp_links"].items()
                                                           if link["worker_id"] == resolved]))

    def _merge_links(self, value, links):
        if not isinstance(links, list):
            raise ValueError("invalid roster mappings")
        for link in links:
            normalized = self._validate_link(link)
            worker = next((row for row in (value["snapshot"] or {}).get("workers", [])
                           if row["worker_id"] == link["worker_id"]), None)
            if worker is not None and worker.get("worker_number", link["worker_number"]) != link["worker_number"]:
                raise ValueError("mapping worker number does not match roster")
            previous = value["temp_links"].get(link["temp_uuid"])
            if previous is not None and previous != normalized:
                raise ValueError("temporary mapping changed")
            value["temp_links"][link["temp_uuid"]] = normalized

    def _resolve_requests(self, value):
        workers = {row["worker_id"]: row for row in (value["snapshot"] or {}).get("workers", [])}
        for item in value["requests"]:
            body = item["body"]
            if body and body["mode"] == "create":
                link = value["temp_links"].get(body["temp_uuid"])
                if link:
                    row = workers.get(link["worker_id"])
                    if item["state"] == "PENDING" or (item["state"] == "REVIEW" and row
                                                          and row["display_name"] == body["display_name"]):
                        item.update(state="ACKED", error=item["error"] if item["state"] == "REVIEW" else "")
            if body is None:
                intent = item["intent"]
                link = value["temp_links"].get(intent["temp_uuid"])
                if link:
                    item["body"] = {"mode": "return", "authority_scope_id": self.authority_scope_id,
                                    "request_id": item["request_id"], "display_name": intent["display_name"],
                                    "action_at": intent["action_at"], "existing_worker_id": link["worker_id"]}
                    body = item["body"]
            if body and body["mode"] == "return" and item["state"] == "PENDING":
                row = workers.get(body["existing_worker_id"])
                if row and row["status"] == "DISABLED":
                    item.update(state="TERMINAL", error="WORKER_DISABLED", error_version=value["snapshot"]["version"])

    @writer_sink("worker_roster_registration")
    def apply_registration(self, request, answer=None, error=None):
        self._load_local()
        value = copy.deepcopy(self.local)
        item = next((row for row in value["requests"] if row["request_id"] == request["request_id"]), None)
        if item is None or item["body"] != request or item["state"] != "PENDING":
            return
        if error is not None:
            code, status = getattr(error, "code", "VERIFY_UNAVAILABLE"), getattr(error, "status", None)
            item["error"] = code
            if status == 409 or code in {"REQUEST_CONFLICT", "TEMP_ID_CONFLICT"}:
                item["state"] = "REVIEW"
            elif request["mode"] == "return" and code in {"WORKER_DISABLED", "WORKER_NOT_FOUND"}:
                item.update(state="TERMINAL", error_version=self.known_version)
            elif status == 400:
                future = self._action_time(request["action_at"]) > (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
                if code != "INVALID_REQUEST" or not future:
                    item["state"] = "REVIEW"
        else:
            if (not isinstance(answer, dict) or answer.get("ok") is not True
                    or answer.get("contract_version") != CONTRACT_VERSION_V2
                    or answer.get("authority_scope_id") != self.authority_scope_id
                    or answer.get("request_id") != request["request_id"]):
                raise ValueError("invalid registration acknowledgement")
            snapshot = self._validate({**answer, "workers": [answer.get("worker")]})
            row = snapshot["workers"][0] if snapshot["workers"] else None
            if row is None or row["status"] != "ACTIVE":
                raise ValueError("invalid registration worker")
            if request["mode"] == "create":
                link = answer.get("temp_link")
                if (not isinstance(link, dict) or link.get("temp_uuid") != request["temp_uuid"]
                        or link.get("worker_id") != row["worker_id"]
                        or link.get("worker_number") != row["worker_number"]):
                    raise ValueError("acknowledgement does not match temporary worker")
                self._merge_links(value, [link])
            elif row["worker_id"] != request["existing_worker_id"] or answer.get("temp_link") is not None:
                raise ValueError("return acknowledgement changed worker identity")
            # A replay can contain an older name/status. It never wins over a newer query.
            current = value["snapshot"]
            if self.snapshot is not None and (current is None or self.snapshot["version"] > current["version"]):
                current = self.snapshot
            if current is None or snapshot["version"] >= current["version"]:
                others = [entry for entry in (current or {}).get("workers", []) if entry["worker_id"] != row["worker_id"]]
                snapshot.update(workers=others + [row], source_row_count=len(others) + 1,
                                fetched_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                value["snapshot"] = snapshot
            item.update(state="ACKED", error="")
        self._resolve_requests(value)
        self._save_local(value)
        if value["snapshot"] is not None:
            self.snapshot = value["snapshot"]

    @writer_sink("worker_roster_cache")
    def apply(self, answer: Any, *, requested_version: int | None) -> None:
        self._load_local()
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
                if value["contract_version"] == CONTRACT_VERSION_V2 and not self.local_blocked:
                    # Mapping is immutable and useful after ACK loss even when
                    # the accompanying roster state is obsolete.
                    local = copy.deepcopy(self.local)
                    self._merge_links(local, answer.get("temp_links"))
                    self._resolve_requests(local)
                    self._save_local(local)
                    return
                raise ValueError("obsolete roster version")
        if value["contract_version"] == CONTRACT_VERSION_V2 and not self.local_blocked:
            local = copy.deepcopy(self.local)
            value["fetched_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            local["snapshot"] = value
            self._merge_links(local, answer.get("temp_links"))
            self._resolve_requests(local)
            self._save_local(local)
            self.snapshot = value
            return
        value["fetched_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        value["sha256"] = _digest(value)
        if not self.local_blocked and (self.local["workers"] or self.local["requests"]):
            local = copy.deepcopy(self.local)
            local["snapshot"] = value
            self._resolve_requests(local)
            self._save_local(local)
        atomic_write_json(self.good_path, value, indent=2, ensure_ascii=False, trailing_newline=True)
        atomic_write_json(self.path, value, indent=2, ensure_ascii=False, trailing_newline=True)
        self.snapshot = value

    def active_workers(self) -> list[dict[str, Any]]:
        snapshot = self.snapshot or {}
        known = {row["worker_id"]: row for row in snapshot.get("workers", [])}
        stopped = {item["body"]["existing_worker_id"] for item in self.local["requests"]
                   if item["body"] and item["body"]["mode"] == "return" and item["state"] == "TERMINAL"
                   and item["error"] in {"WORKER_DISABLED", "WORKER_NOT_FOUND"}
                   and not (item.get("error_version") is not None
                            and snapshot.get("version", -1) > item["error_version"]
                            and known.get(item["body"]["existing_worker_id"], {}).get("status") == "ACTIVE")}
        rows = [dict(row) for row in (self.snapshot or {}).get("workers", [])
                if row["status"] == "ACTIVE" and row["worker_id"] not in stopped]
        for row in self.local["workers"]:
            resolved = self.resolved_id(row["worker_id"])
            if resolved in known or resolved in stopped or resolved in (self.snapshot or {}).get("unselectable_worker_ids", []):
                continue  # Including DISABLED: never resurrect through the local alias.
            link = self.local["temp_links"].get(row["worker_id"], {})
            rows.append({**row, **link, "worker_id": resolved, "status": "ACTIVE"})
        return rows

    def active_worker(self, *, worker_id: str = "", name: str = "") -> dict[str, str] | None:
        for row in self.active_workers():
            matches = row["worker_id"] == self.resolved_id(worker_id) if worker_id else row["display_name"] == name
            if matches:
                return row
        return None
