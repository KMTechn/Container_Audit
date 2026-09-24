from __future__ import annotations

import json
import csv
import os
import re
import uuid
import hashlib
import base64
import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping

from label_qr import canonical_master_label_key, parse_new_format_qr
from protected_admin import persistent_operator_name
from storage_utils import atomic_write_json
from writer_session_fence import writer_sink
from recovery_file_read import read_recovery_file
from paired_preflight_handoff import PairedPreflightHandoffStore


def sanitize_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', "_", str(filename))


def _safe_worker_filename(worker_name: str) -> str:
    return sanitize_filename(persistent_operator_name(worker_name)) or "worker"


_ATOMIC_TEMP_SUFFIX = re.compile(r"\.([0-9]+)\.([0-9a-f]{32})\.tmp$")


def atomic_temp_target(path: Path) -> Path | None:
    """Return the destination of a known interrupted recovery write."""
    match = _ATOMIC_TEMP_SUFFIX.search(path.name)
    if match:
        return path.with_name(path.name[:match.start()])
    if re.fullmatch(r"phs_label_exchange_recovery\.json\.[A-Za-z0-9_-]{6,}\.tmp", path.name):
        return path.with_name("phs_label_exchange_recovery.json")
    return None


def _phs2_labels_in_payload(value: Any) -> list[str]:
    labels: list[str] = []
    pending = [(value, 0)]
    while pending:
        part, depth = pending.pop()
        if depth > 8:
            continue
        if isinstance(part, str):
            if str((parse_new_format_qr(part) or {}).get("PHS") or "") == "2":
                labels.append(part)
        elif isinstance(part, dict):
            pending.extend((child, depth + 1) for child in part.values())
        elif isinstance(part, list):
            pending.extend((child, depth + 1) for child in part)
    return labels


@dataclass(frozen=True)
class ParkedTraySummary:
    path: Path
    item_name: str
    scan_count: int
    problem: str = ""


@dataclass(frozen=True)
class ParkedRecoveryDeferResult:
    path: Path
    defer_id: str
    state_hash: str
    replayed: bool


@dataclass(frozen=True)
class KeyEvidence:
    path: Path
    kind: str
    labels: tuple[str, ...] = ()
    digest: str = ""
    unidentified: bool = False
    problem: str = ""
    evidence_id: str = ""
    content_sha256: str = ""

    def binds(self, label: str) -> bool:
        key = canonical_master_label_key(label)
        return (self.unidentified
                or any(canonical_master_label_key(value) == key for value in self.labels)
                or bool(self.digest and self.digest == hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]))


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
            if path is not None and (path.exists() or self.manager_hold_path(path).exists()):
                return path
        return None

    def enumerate_key_evidence(
        self, *, pair_store: PairedPreflightHandoffStore | None = None,
    ) -> tuple[KeyEvidence, ...]:
        """Read the remaining durable files on every call; never infer absence from an index."""
        rows: list[KeyEvidence] = []
        pin_dir = self.directory / "admin_pin_intents"
        for path in sorted(pin_dir.glob("admin-pin-*.json")) if pin_dir.exists() else ():
            match = re.fullmatch(
                r"admin-pin-([0-9a-f]{16})-([0-9a-f]{32})\.json", path.name,
            )
            target_digest = match.group(1) if match else ""
            labels: tuple[str, ...] = ()
            problem = ""
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("admin PIN intent is not an object")
                if value.get("state") in {"APPLIED", "REJECTED", "SUPERSEDED"}:
                    continue
                labels = tuple(label for label in value.get("labels", ())
                               if isinstance(label, str) and label)
            except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
                problem = "관리자 PIN intent 원본 확인 필요"
            rows.append(KeyEvidence(path, "pin_intent", labels, target_digest,
                                    problem=problem))
        if self.directory.exists():
            for path in sorted(self.directory.glob("parked_*.json*")):
                name = path.name
                identified = re.search(r"\.manager-hold\.json\.identified-(?:source-)?[0-9a-f]{64}\.json$", name) is not None
                marker = name.endswith(".manager-hold.json")
                bad = re.search(r"\.json\.bad-.+$", name) is not None
                temporary_target = atomic_temp_target(path)
                if temporary_target is not None and not temporary_target.name.endswith(".json"):
                    temporary_target = None
                if not (identified or marker or bad or name.endswith(".json") or temporary_target):
                    continue
                source_name = (temporary_target.name if temporary_target else
                               re.sub(r"\.manager-hold\.json\.identified-(?:source-)?[0-9a-f]{64}\.json$", "", name) if identified
                               else name.removesuffix(".manager-hold.json") if marker
                               else re.sub(r"\.bad-.+$", "", name))
                source = path.with_name(source_name)
                digest_match = (re.search(r"_([0-9a-f]{16})\.json(?:\.manager-hold\.json(?:\.identified-(?:source-)?[0-9a-f]{64}\.json)?)?$", source_name)
                                if source_name.startswith("parked_qr_") else None)
                digest = digest_match.group(1) if digest_match else ""
                labels: list[str] = []
                legacy = source_name.find("PHS=")
                if legacy >= 0:
                    candidate = source_name[legacy:].removesuffix(".json")
                    if parse_new_format_qr(candidate):
                        labels.append(candidate)
                kind = ("parked_temp" if temporary_target else
                        "parked_identified" if identified else "parked_marker" if marker
                        else "parked_bad" if bad else "parked")
                source_is_marker = (temporary_target.name if temporary_target else name).find(".manager-hold.json") >= 0
                result = read_recovery_file(path, "parked_manager_hold" if marker or identified or source_is_marker else "parked")
                if result.verified:
                    candidate = result.value.get("label" if marker or identified or source_is_marker else "master_label_code")
                    if isinstance(candidate, str) and candidate:
                        labels.append(candidate)
                    if marker and source.exists():
                        source_read = read_recovery_file(source, "parked")
                        if source_read.sha256 != result.value["source_sha256"]:
                            result = result.__class__(result.path, result.raw, result.sha256,
                                                      result.value, "관리자 보류 표시의 원본 SHA256 불일치")
                elif result.raw is not None:
                    try:
                        raw_value = json.loads(result.raw.decode("utf-8"))
                        candidate = raw_value.get("label" if marker or identified or source_is_marker else "master_label_code") if isinstance(raw_value, dict) else None
                        if isinstance(candidate, str) and candidate:
                            labels.append(candidate)
                    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
                        pass
                if not labels and not marker and not identified and result.sha256:
                    binding = read_recovery_file(self.manager_hold_path(path), "parked_manager_hold")
                    if binding.verified and binding.value["source_sha256"] == result.sha256:
                        labels.append(binding.value["label"])
                if marker and not result.verified:
                    identified_read = read_recovery_file(
                        path.with_name(name + f".identified-{result.sha256}.json"), "parked_manager_hold",
                    )
                    if (identified_read.verified
                            and identified_read.value["source_sha256"] == result.sha256):
                        labels.append(identified_read.value["label"])
                if temporary_target and result.sha256:
                    bound = read_recovery_file(self.manager_hold_path(path), "parked_manager_hold")
                    if bound.verified and bound.value["source_sha256"] == result.sha256:
                        labels.append(bound.value["label"])
                problem = ("원자 저장 중단 임시파일 · 최종 파일 있음, 원본 격리 보존" if temporary_target and temporary_target.exists()
                           else "원자 저장 중단 임시파일 · 관리자 확인 필요" if temporary_target else result.reason or "")
                if temporary_target and result.reason:
                    problem += f" · {result.reason}"
                rows.append(KeyEvidence(path, kind, tuple(dict.fromkeys(labels)), digest,
                                        not labels and not digest and (not temporary_target or result.raw is None), problem,
                                        content_sha256=result.sha256 or ""))
        pair_store = pair_store or PairedPreflightHandoffStore(self.directory / "paired_preflight_handoff")
        for path in pair_store.paths():
            inspection = pair_store.inspect(path)
            rows.append(KeyEvidence(path, "pair", inspection.labels,
                                    unidentified=inspection.unidentified,
                                    problem=" · ".join(inspection.problems)))
        # A crash between fsync and replace leaves the only durable copy under
        # its atomic temporary name. Include temporary-only pair directories.
        temporary_paths = []
        if pair_store.directory.exists():
            temporary_paths.extend(pair_store.directory.rglob("*.tmp"))
        outbox_dir = (pair_store.current_path.parent / "_event_outbox"
                      if pair_store.current_path is not None else None)
        if outbox_dir is not None and outbox_dir.exists():
            temporary_paths.extend(outbox_dir.glob("*.tmp"))
        journal_dir = self.directory.parent / "phs_label_exchange"
        if journal_dir.exists():
            temporary_paths.extend(journal_dir.glob("phs_label_exchange_recovery.json.*.tmp"))
        for active_path in (pair_store.current_path, pair_store.hold_path):
            if active_path is not None and active_path.parent.exists():
                temporary_paths.extend(active_path.parent.glob(active_path.name + ".*.tmp"))
        for path in sorted(set(temporary_paths)):
            target = atomic_temp_target(path)
            if target is None or not target.name.endswith(".json"):
                continue
            name = target.name
            kind = ("record" if name == "record.json" else
                    "released" if name == "released.json" else
                    "manager_hold" if name.endswith("manager-hold.json") else
                    "stale_hold" if name.startswith("stale-current-") else
                    "outbox" if outbox_dir == target.parent and re.fullmatch(r"[0-9]{20}-[0-9a-f]{32}\.json", name) else
                    "label_journal" if journal_dir == target.parent and name == "phs_label_exchange_recovery.json" else
                    "hold" if pair_store.hold_path == target else
                    "current" if pair_store.current_path == target else "")
            if not kind:
                continue
            result = read_recovery_file(path, "json" if kind in {"outbox", "label_journal"} else kind)
            value = result.value if result.verified else None
            if value is None and result.raw is not None:
                try:
                    parsed = json.loads(result.raw.decode("utf-8"))
                    value = parsed if isinstance(parsed, dict) else None
                except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
                    pass
            labels = []
            if isinstance(value, dict):
                if kind == "record":
                    for part, field in (("hold", "master_raw"), ("current", "master_label_code")):
                        try:
                            embedded = json.loads(base64.b64decode(value[part]["bytes_b64"], validate=True).decode("utf-8"))
                            labels.append(embedded[field])
                        except (KeyError, UnicodeError, ValueError, TypeError, binascii.Error):
                            pass
                elif kind in {"manager_hold", "stale_hold"}:
                    labels.extend(value.get("labels") if isinstance(value.get("labels"), list) else ())
                elif kind == "outbox":
                    entry = value.get("log_entry")
                    if isinstance(entry, dict):
                        detail = entry.get("details")
                        if isinstance(detail, str):
                            try:
                                detail = json.loads(detail)
                            except (ValueError, TypeError, RecursionError):
                                detail = None
                        labels.extend(_phs2_labels_in_payload(detail))
                elif kind == "label_journal":
                    labels.extend(_phs2_labels_in_payload(value.get("state")))
                else:
                    label = value.get("master_raw" if kind == "hold" else "master_label_code")
                    if isinstance(label, str):
                        labels.append(label)
            if kind in {"released", "manager_hold"}:
                labels.extend(label for row in rows if row.kind == "pair" and row.path.parent == path.parent
                              for label in row.labels)
            labels = list(dict.fromkeys(label for label in labels if isinstance(label, str) and label))
            evidence_id = hashlib.sha256(
                (str(path.resolve()) + ":" + (result.sha256 or "")).encode("utf-8")
            ).hexdigest() if result.sha256 else ""
            problem = ("원자 저장 중단 임시파일 · 최종 파일 있음, 원본 격리 보존" if target.exists()
                       else "원자 저장 중단 임시파일 · 관리자 확인 필요")
            rows.append(KeyEvidence(path, "atomic_temp", tuple(labels),
                                    unidentified=not labels and result.raw is None,
                                    problem=problem + (f" · {result.reason}" if result.reason else ""),
                                    evidence_id=evidence_id, content_sha256=result.sha256 or ""))
        for path in sorted(pair_store.directory.glob("stale-current-*.json*")) if pair_store.directory.exists() else ():
            if atomic_temp_target(path) is not None:
                continue
            marker = path.name.endswith(".manager-hold.json")
            result = read_recovery_file(path, "manager_hold" if marker else "stale_hold")
            labels = tuple(result.value["labels"]) if result.verified else ()
            if not labels and not marker:
                binding = read_recovery_file(pair_store.stale_manager_path(path), "manager_hold")
                if binding.verified:
                    labels = tuple(binding.value["labels"])
            rows.append(KeyEvidence(path, "stale_marker" if marker else "stale", labels,
                                    unidentified=not labels, problem=result.reason or "",
                                    content_sha256=result.sha256 or ""))
        if pair_store.current_path is not None:
            current_path = pair_store.current_path
            for path in sorted(current_path.parent.glob(current_path.name + ".bad-*")) if current_path.parent.exists() else ():
                result = read_recovery_file(path, "stale")
                labels = []
                if result.verified:
                    labels.append(result.value["master_label_code"])
                elif result.raw is not None:
                    try:
                        value = json.loads(result.raw.decode("utf-8"))
                        if isinstance(value, dict) and isinstance(value.get("master_label_code"), str):
                            labels.append(value["master_label_code"])
                    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
                        pass
                evidence_id = hashlib.sha256(
                    (str(path.resolve()) + ":" + result.sha256).encode("utf-8")
                ).hexdigest() if result.sha256 else ""
                rows.append(KeyEvidence(path, "stale_current", tuple(labels),
                                        unidentified=not labels, problem=result.reason or "",
                                        evidence_id=evidence_id, content_sha256=result.sha256 or ""))
        audit_dir = self.directory.parent / "local_events"
        if audit_dir.exists():
            audit_events = {
                "PHS2_DAMAGED_PARKED_DEFERRED", "PHS2_PAIRED_MANUAL_HOLD",
                "PHS2_PAIRED_PREFLIGHT_DEFERRED", "PHS2_PAIRED_RECOVERY_DEFERRED",
                "PHS2_PAIRED_STALE_CURRENT_DEFERRED",
                "PHS2_PAIRED_STALE_CURRENT_PRESERVATION_REQUESTED",
                "PHS2_STALE_HOLD_RECHECKED", "PHS2_PAIRED_RECEIPT_RECHECK_REQUESTED",
                "PHS2_ATOMIC_TEMP_QUARANTINED",
            }
            audit_events.update({"PHS2_AUDIT_EVIDENCE_BOUND",
                                 "PHS2_AUDIT_EVIDENCE_UNVERIFIED_HOLD"})
            audit_rows: list[tuple[Path, str, dict[str, Any], str]] = []
            damaged_audits: list[tuple[Path, str]] = []
            for path in sorted(audit_dir.glob("*.csv")):
                try:
                    with path.open("r", encoding="utf-8-sig", newline="") as stream:
                        for ordinal, row in enumerate(csv.DictReader(stream), 1):
                            event = row.get("event")
                            if event not in audit_events:
                                continue
                            detail = json.loads(row.get("details") or "{}")
                            if not isinstance(detail, dict):
                                raise ValueError("audit detail is not an object")
                            evidence_id = hashlib.sha256(
                                f"{path.resolve()}:{ordinal}:{event}:{row.get('details')}".encode("utf-8")
                            ).hexdigest()
                            audit_rows.append((path, event, detail, evidence_id))
                except (OSError, UnicodeError, ValueError, RecursionError, csv.Error):
                    try:
                        digest = hashlib.sha256()
                        with path.open("rb") as raw_stream:
                            for block in iter(lambda: raw_stream.read(1024 * 1024), b""):
                                digest.update(block)
                        evidence_id = hashlib.sha256(
                            (str(path.resolve()) + ":" + digest.hexdigest()).encode("utf-8")
                        ).hexdigest()
                    except OSError:
                        evidence_id = ""
                    damaged_audits.append((path, evidence_id))
            known_by_handoff: dict[str, list[str]] = {}
            known_by_audit: dict[str, list[str]] = {}
            for _path, event, detail, _evidence_id in audit_rows:
                handoff = detail.get("handoff_id")
                labels = [detail.get(key) for key in (
                    "master_label_code", "master_raw", "hold_master", "current_master",
                )]
                if isinstance(detail.get("labels"), list):
                    labels.extend(detail["labels"])
                known = [label for label in labels if isinstance(label, str) and label]
                if isinstance(handoff, str) and handoff:
                    known_by_handoff.setdefault(handoff, []).extend(known)
                source_audit_id = detail.get("source_audit_id")
                if (event in {"PHS2_AUDIT_EVIDENCE_BOUND",
                              "PHS2_AUDIT_EVIDENCE_UNVERIFIED_HOLD"}
                        and isinstance(source_audit_id, str) and source_audit_id):
                    known_by_audit.setdefault(source_audit_id, []).extend(known)
            for index, row in enumerate(rows):
                if row.kind in {"stale_current", "atomic_temp"} and row.evidence_id in known_by_audit:
                    labels = tuple(dict.fromkeys((*row.labels, *known_by_audit[row.evidence_id])))
                    rows[index] = KeyEvidence(row.path, row.kind, labels, row.digest,
                                              not labels, row.problem, row.evidence_id,
                                              row.content_sha256)
            for path, event, detail, evidence_id in audit_rows:
                labels = [detail.get(key) for key in (
                    "master_label_code", "master_raw", "hold_master", "current_master",
                )]
                if isinstance(detail.get("labels"), list):
                    labels.extend(detail["labels"])
                handoff = detail.get("handoff_id")
                if isinstance(handoff, str):
                    labels.extend(known_by_handoff.get(handoff, ()))
                    labels.extend(label for row in rows if row.kind == "pair"
                                  and row.path.parent.name == handoff for label in row.labels)
                for reference in ("preserved_file", "changed_file", "source_file", "marker_file"):
                    name = detail.get(reference)
                    if isinstance(name, str) and name and name == Path(name).name:
                        hashes = {detail.get(key) for key in (
                            "original_sha256", "changed_sha256", "current_sha256", "source_sha256",
                        ) if isinstance(detail.get(key), str)}
                        labels.extend(label for row in rows
                                      if row.kind in {"stale", "stale_current", "stale_marker",
                                                      "parked_temp", "atomic_temp"}
                                      and (row.path.name == name or row.path.name.startswith(name + ".bad-"))
                                      and row.content_sha256 in hashes
                                      for label in row.labels)
                labels.extend(known_by_audit.get(evidence_id, ()))
                labels = list(dict.fromkeys(label for label in labels
                                            if isinstance(label, str) and label))
                rows.append(KeyEvidence(path, "audit", tuple(labels),
                                        unidentified=not labels and event != "PHS2_ATOMIC_TEMP_QUARANTINED",
                                        problem="원 현품표 신원 미확인 감사 사건" if not labels and event != "PHS2_ATOMIC_TEMP_QUARANTINED" else event,
                                        evidence_id=evidence_id))
            for path, evidence_id in damaged_audits:
                labels = tuple(dict.fromkeys(known_by_audit.get(evidence_id, ())))
                rows.append(KeyEvidence(path, "audit", labels, unidentified=not labels,
                                        problem="관리자 감사 파일 판독 실패", evidence_id=evidence_id))
        return tuple(rows)

    def existing_label_path_any_worker(self, *, master_label: str) -> Path | None:
        phs2 = str((parse_new_format_qr(master_label) or {}).get("PHS") or "") == "2"
        for row in self.enumerate_key_evidence():
            if row.kind.startswith("parked") and row.binds(master_label) and (phs2 or not row.unidentified):
                return row.path
        return None

    @staticmethod
    def manager_hold_path(path: Path) -> Path:
        return path.with_name(path.name + ".manager-hold.json")

    @writer_sink("parked_tray_manager_hold")
    def bind_invalid_label(self, path: Path, label: str) -> None:
        path = Path(path)
        source = read_recovery_file(path, "parked")
        marker = self.manager_hold_path(path)
        previous = read_recovery_file(marker, "parked_manager_hold")
        if not path.exists() and previous.verified:
            if canonical_master_label_key(previous.value["label"]) != canonical_master_label_key(label):
                raise FileExistsError("parked manager binding differs")
            return
        damaged_marker = marker.exists() and not previous.verified
        archived_original = ".json.bad-" in path.name
        marker_drift = previous.verified and source.sha256 is not None and previous.value["source_sha256"] != source.sha256
        if (source.verified and not archived_original and atomic_temp_target(path) is None
                and not damaged_marker and not marker_drift) or (source.sha256 is None and not damaged_marker):
            raise ValueError("parked source is not an intact invalid file")
        payload = {
            "schema": "container-audit-parked-manager-hold-v1",
            "label": label,
            "source_sha256": previous.sha256 if damaged_marker else source.sha256,
        }
        target = (marker.with_name(marker.name + f".identified-{previous.sha256}.json")
                  if damaged_marker else marker.with_name(marker.name + f".identified-source-{source.sha256}.json")
                  if marker_drift else marker)
        if target.exists():
            prior = read_recovery_file(target, "parked_manager_hold")
            if not prior.verified or prior.value != payload:
                raise FileExistsError("parked manager binding differs")
        else:
            atomic_write_json(target, payload, ensure_ascii=False)
        check = read_recovery_file(target, "parked_manager_hold")
        if not check.verified or check.value != payload:
            raise OSError("parked manager binding readback differs")

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
        return [row for row in self.scan_for_worker(worker_name) if not row.problem]

    def scan_for_worker(self, worker_name: str, *, tray_size: int = 60,
                        strict: bool = False) -> List[ParkedTraySummary]:
        if not self.directory.exists():
            return []
        summaries: List[ParkedTraySummary] = []
        evidence_rows = self.enumerate_key_evidence()
        for evidence in evidence_rows:
            if evidence.kind not in {"parked", "parked_bad", "parked_temp"}:
                continue
            path = evidence.path
            try:
                result = read_recovery_file(path, "parked" if strict else "parked_summary",
                                            tray_size=tray_size)
                if not result.verified or evidence.kind in {"parked_bad", "parked_temp"}:
                    # An unreadable payload has no trustworthy owner. Expose
                    # it without hiding healthy rows.
                    summaries.append(ParkedTraySummary(path, f"확인 필요 · {path.name}",
                                                        0, evidence.problem or result.reason or "격리된 원본 보존"))
                    continue
                data = result.value
                stored_worker = persistent_operator_name(data.get("worker_name"))
                requested_worker = persistent_operator_name(worker_name)
                if stored_worker:
                    if stored_worker != requested_worker:
                        continue
                elif f"_{_safe_worker_filename(requested_worker)}_" not in path.name:
                    continue
                summaries.append(ParkedTraySummary(
                    path=path, item_name=str(data.get("item_name") or "알 수 없음"),
                    scan_count=len(data.get("scanned_barcodes") or []),
                ))
            except Exception as exc:
                summaries.append(ParkedTraySummary(
                    path, f"확인 필요 · {path.name}", 0,
                    f"보류 작업 판독 실패 ({exc.__class__.__name__})",
                ))
        for evidence in evidence_rows:
            if evidence.kind != "parked_marker":
                continue
            marker = evidence.path
            try:
                source = marker.with_name(marker.name.removesuffix(".manager-hold.json"))
                if not source.exists():
                    summaries.append(ParkedTraySummary(marker, f"확인 필요 · {source.name}", 0,
                                                       "원본 없음, 보류 표시만 남음"))
                elif evidence.problem:
                    summaries.append(ParkedTraySummary(marker, f"확인 필요 · {marker.name}", 0,
                                                       "관리자 보류 표시 손상 · 원본은 보존됨"))
            except Exception as exc:
                summaries.append(ParkedTraySummary(marker, f"확인 필요 · {marker.name}", 0,
                                                   f"관리자 보류 판독 실패 ({exc.__class__.__name__})"))
        return summaries

    @staticmethod
    @writer_sink("parked_tray_load_normalize")
    def load(
        path: str | os.PathLike[str], *, normalize_worker: bool = False,
    ) -> Dict[str, Any]:
        source = Path(path)
        result = read_recovery_file(source, "json")
        if not result.verified:
            raise json.JSONDecodeError("parked tray payload cannot be verified", "", 0)
        payload = result.value
        saved_worker = str(payload.get("worker_name") or "").strip()
        safe_worker = persistent_operator_name(saved_worker)
        if safe_worker != saved_worker:
            payload["worker_name"] = safe_worker
            if normalize_worker:
                atomic_write_json(source, payload, indent=4, ensure_ascii=False)
        return payload

    @staticmethod
    @writer_sink("parked_tray_delete")
    def delete(path: str | os.PathLike[str]) -> None:
        Path(path).unlink()
