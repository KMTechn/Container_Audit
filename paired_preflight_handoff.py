"""Durable ownership of a DRAINING hold and its separate current tray."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from recovery_file_read import RecoveryRead, read_recovery_file
from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


class PairedHandoffError(RuntimeError):
    pass


@writer_sink("paired_stale_evidence")
def preserve_stale_bytes(source: Path, data: bytes) -> Path:
    """Keep a byte-exact copy without replacing an active current slot."""
    source = Path(source)
    digest = hashlib.sha256(data).hexdigest()
    target = source.with_name(f"{source.name}.bad-{digest}")
    if not target.exists():
        with target.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    if read_recovery_file(target, "stale").raw != data:
        raise PairedHandoffError("stale evidence readback differs")
    return target


def _validated_part(part: dict[str, str], _name: str) -> bytes:
    return base64.b64decode(part["bytes_b64"], validate=True)


@dataclass(frozen=True)
class PairInspection:
    path: Path
    record: dict[str, Any] | None
    labels: tuple[str, ...]
    problems: tuple[str, ...]
    released: bool
    unidentified: bool
    hold_read: RecoveryRead
    current_read: RecoveryRead


class PairedPreflightHandoffStore:
    def __init__(self, directory: Path, *, hold_path: Path | None = None,
                 current_path: Path | None = None) -> None:
        self.directory = Path(directory)
        self.hold_path = Path(hold_path) if hold_path is not None else None
        self.current_path = Path(current_path) if current_path is not None else None

    def paths(self) -> tuple[Path, ...]:
        if not self.directory.exists():
            return ()
        return tuple(sorted(child / "record.json" for child in self.directory.iterdir()
                            if child.is_dir() and any((child / name).exists() for name in (
                                "record.json", "hold.original", "current.original",
                                "released.json", "manager-hold.json"))))

    def inspect(self, path: Path) -> PairInspection:
        path = Path(path)
        try:
            return self._inspect_verified(path)
        except Exception as exc:
            # The directory entry remains visible to a supervisor even if an
            # unexpected error prevents identifying either original label.
            reason = f"인계 묶음 판독 실패 ({exc.__class__.__name__})"
            unread = RecoveryRead(path, None, None, None, reason)
            return PairInspection(path, None, (), (reason,), False, True,
                                  unread, unread)

    def _inspect_verified(self, path: Path) -> PairInspection:
        record_read = read_recovery_file(path, "record")
        record = record_read.value if record_read.verified else None
        problems = []
        if (path.parent / "superseded.json").exists():
            problems.append("PIN 원본 변경으로 이전 인계 기록 보존"
                            if self._superseded(path) else "이전 인계 기록 표지 손상")
        if record is not None and record["id"] != path.parent.name:
            problems.append("인계 기록 식별자가 폴더와 다름")
            record = None
        if record is not None and any(
            expected is not None and Path(record[name]["path"]) != expected.resolve()
            for name, expected in (("hold", self.hold_path), ("current", self.current_path))
        ):
            problems.append("인계 원본 경로가 현재 슬롯과 다름")
            record = None
        if record is None:
            problems.append("인계 기록이 없거나 손상됨")
        labels = []
        identified_parts = 0
        archived_reads = {}
        for name, field in (("hold", "master_raw"), ("current", "master_label_code")):
            original_path = path.parent / f"{name}.original"
            original = read_recovery_file(original_path, name)
            archived_reads[name] = original
            embedded = None
            if record is not None:
                embedded = _validated_part(record[name], name)
            if original.verified:
                identified_parts += 1
                labels.append(original.value[field])
                if embedded is not None and original.raw != embedded:
                    problems.append(f"{name} 원본 SHA256 변경")
                    labels.append(json.loads(embedded.decode("utf-8"))[field])
            elif embedded is not None:
                identified_parts += 1
                labels.append(json.loads(embedded.decode("utf-8"))[field])
                if original_path.exists():
                    problems.append(f"{name} 원본 손상")
                elif not Path(record[name]["path"]).exists():
                    problems.append(f"{name} 원본 없음")
            else:
                problems.append(f"{name} 원본을 확인할 수 없음")
        if record is None and all(archived_reads[name].verified for name in ("hold", "current")):
            if self.hold_path is None or self.current_path is None:
                identified_parts = 0
            else:
                identity = hashlib.sha256((
                    str(self.hold_path.resolve()) + archived_reads["hold"].sha256
                    + str(self.current_path.resolve()) + archived_reads["current"].sha256
                ).encode("utf-8")).hexdigest()
                if identity != path.parent.name:
                    identified_parts = 0
                    problems.append("남은 원본의 SHA256이 인계 쌍 식별자와 다름")
        marker = read_recovery_file(path.parent / "released.json", "released")
        released = bool(record is not None and marker.verified
                        and marker.value == {"id": record["id"]})
        if (path.parent / "released.json").exists() and not released:
            problems.append("해제 표지를 확인할 수 없음")
        binding = read_recovery_file(path.parent / "manager-hold.json", "manager_hold")
        if binding.verified:
            labels.extend(binding.value["labels"])
            identified_parts = 2
        elif (path.parent / "manager-hold.json").exists():
            problems.append("관리자 보류 기록 손상")
        return PairInspection(path, record, tuple(dict.fromkeys(labels)),
                              tuple(problems), released, identified_parts < 2,
                              archived_reads["hold"], archived_reads["current"])

    def unidentified_pending(self) -> bool:
        return any(self.inspect(path).unidentified for path in self.paths())

    def stale_labels(self) -> tuple[str, ...]:
        labels = []
        for path, result in self.stale_entries():
            if not result.verified:
                binding = read_recovery_file(self.stale_manager_path(path), "manager_hold")
                if not binding.verified:
                    raise PairedHandoffError("stale current hold cannot be verified")
                labels.extend(binding.value["labels"])
            else:
                labels.extend(result.value["labels"])
        return tuple(labels)

    def stale_entries(self):
        return tuple((path, read_recovery_file(path, "stale_hold"))
                     for path in sorted(self.directory.glob("stale-current-*.json"))
                     if not path.name.endswith(".manager-hold.json"))

    @staticmethod
    def stale_manager_path(path: Path) -> Path:
        return path.with_name(path.name + ".manager-hold.json")

    def unidentified_stale(self) -> bool:
        return any(not result.verified and not read_recovery_file(
            self.stale_manager_path(path), "manager_hold").verified
            for path, result in self.stale_entries())

    @writer_sink("paired_stale_manager_hold")
    def bind_unidentified_stale(self, path: Path, labels: tuple[str, str]) -> None:
        path = Path(path)
        if path not in [entry[0] for entry in self.stale_entries()]:
            raise PairedHandoffError("stale hold does not exist")
        source = read_recovery_file(path, "stale_hold")
        if source.verified or source.sha256 is None:
            raise PairedHandoffError("stale hold is already verified")
        payload = {
            "schema": "container-audit-paired-manager-hold-v1",
            "labels": list(labels),
            "source_sha256": source.sha256,
        }
        marker = self.stale_manager_path(path)
        if marker.exists():
            prior = read_recovery_file(marker, "manager_hold")
            if not prior.verified or prior.value != payload:
                raise PairedHandoffError("stale manager hold differs")
        else:
            atomic_write_json(marker, payload, ensure_ascii=False)
        verified = read_recovery_file(marker, "manager_hold")
        if not verified.verified or verified.value != payload:
            raise PairedHandoffError("stale manager hold readback differs")

    @writer_sink("paired_stale_hold")
    def hold_stale_current(self, original: Path, changed: Path) -> None:
        first = read_recovery_file(original, "stale")
        second = read_recovery_file(changed, "stale")
        if first.raw is None or second.raw is None:
            raise PairedHandoffError("stale current evidence cannot be read")
        labels = []
        for result in (first, second):
            try:
                candidate = result.value if result.verified else json.loads(result.raw.decode("utf-8"))
                label = candidate.get("master_label_code") if isinstance(candidate, dict) else None
            except (UnicodeDecodeError, ValueError, TypeError):
                label = None
            # An unverified candidate may add a guard, never release one.
            if isinstance(label, str) and label and label not in labels:
                labels.append(label)
        payload = {
            "schema": "container-audit-stale-current-hold-v1",
            "labels": labels,
            "original_sha256": first.sha256,
            "changed_sha256": second.sha256,
        }
        path = self.directory / f"stale-current-{first.sha256}.json"
        if path.exists():
            prior = read_recovery_file(path, "stale_hold")
            if not prior.verified or prior.value != payload:
                raise PairedHandoffError("stale current hold differs")
        else:
            atomic_write_json(path, payload, ensure_ascii=False)
        verified = read_recovery_file(path, "stale_hold")
        if not verified.verified or verified.value != payload:
            raise PairedHandoffError("stale current hold readback differs")

    @writer_sink("paired_preflight_manager_hold")
    def bind_unidentified(self, path: Path, labels: tuple[str, str]) -> None:
        path = Path(path)
        if path not in self.paths() or not self.inspect(path).unidentified:
            raise PairedHandoffError("pair does not need manual identification")
        if len(labels) != 2 or not all(isinstance(value, str) and value for value in labels):
            raise PairedHandoffError("two original labels are required")
        payload = {
            "schema": "container-audit-paired-manager-hold-v1",
            "labels": list(labels),
            "evidence_sha256": {
                name: read_recovery_file(path.parent / name, kind).sha256
                for name, kind in (("record.json", "record"),
                                   ("hold.original", "hold"),
                                   ("current.original", "current"),
                                   ("released.json", "released"))
            },
        }
        marker = path.parent / "manager-hold.json"
        if marker.exists():
            prior = read_recovery_file(marker, "manager_hold")
            if not prior.verified or prior.value != payload:
                raise PairedHandoffError("manager hold already differs")
        else:
            atomic_write_json(marker, payload, ensure_ascii=False)
        verified = read_recovery_file(marker, "manager_hold")
        if not verified.verified or verified.value != payload:
            raise PairedHandoffError("manager hold readback differs")

    def pending(self) -> bool:
        return any(not self.inspect(path).released and not self._superseded(path)
                   for path in self.paths())

    def pending_path(self) -> Path | None:
        for path in self.paths():
            if not self.inspect(path).released and not self._superseded(path):
                return path
        return None

    def _superseded(self, path: Path) -> bool:
        marker = path.parent / "superseded.json"
        if not marker.is_file() or not path.is_file():
            return False
        result = read_recovery_file(marker, "json")
        return bool(result.verified and result.value == {
            "id": path.parent.name, "record_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "reason": "TARGET_CHANGED",
        })

    @writer_sink("paired_preflight_changed_record")
    def supersede_changed_record(self, path: Path) -> None:
        record = self.read(path)
        marker = path.parent / "superseded.json"
        payload = {"id": record["id"],
                   "record_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "reason": "TARGET_CHANGED"}
        if marker.exists():
            if not self._superseded(path):
                raise PairedHandoffError("changed record marker differs")
            return
        atomic_write_json(marker, payload)
        if not self._superseded(path):
            raise PairedHandoffError("changed record marker readback differs")

    @staticmethod
    def _part(path: Path, kind: str) -> dict[str, str]:
        data = read_recovery_file(path, kind)
        if not data.verified:
            raise PairedHandoffError("paired original cannot be verified")
        return {
            "path": str(path.resolve()),
            "sha256": data.sha256,
            "bytes_b64": base64.b64encode(data.raw).decode("ascii"),
        }

    @staticmethod
    def _bytes(part: dict[str, str]) -> bytes:
        data = base64.b64decode(part["bytes_b64"], validate=True)
        if hashlib.sha256(data).hexdigest() != part["sha256"]:
            raise PairedHandoffError("paired original hash differs")
        return data

    def read(self, path: Path) -> dict[str, Any]:
        result = read_recovery_file(path, "record")
        if not result.verified or result.value["id"] != Path(path).parent.name:
            raise PairedHandoffError("paired record cannot be verified")
        for name, expected in (("hold", self.hold_path), ("current", self.current_path)):
            if expected is not None and Path(result.value[name]["path"]) != expected.resolve():
                raise PairedHandoffError("paired original path differs from active slot")
        return result.value

    @writer_sink("paired_preflight_record")
    def prepare(self, hold_path: Path, current_path: Path) -> Path:
        if self.pending():
            raise PairedHandoffError("another paired handoff is pending")
        hold = self._part(hold_path, "hold")
        current = self._part(current_path, "current")
        identity = hashlib.sha256(
            (hold["path"] + hold["sha256"] + current["path"] + current["sha256"])
            .encode("utf-8")
        ).hexdigest()
        path = self.directory / identity / "record.json"
        record = {
            "schema": "container-audit-paired-preflight-v1",
            "id": identity,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hold": hold,
            "current": current,
        }
        if path.exists():
            prior = self.read(path)
            if any(prior[name] != record[name] for name in ("hold", "current")):
                raise PairedHandoffError("paired handoff identity collision")
        else:
            atomic_write_json(path, record, ensure_ascii=False)
        verified = self.read(path)
        if any(verified[name] != record[name] for name in ("hold", "current")):
            raise PairedHandoffError("paired handoff readback differs")
        return path

    @writer_sink("paired_preflight_original_move")
    def move_original(self, path: Path, name: str, *, expected_sha256: str | None = None,
                      move=None) -> None:
        record = self.read(path)
        part = record[name]
        source = Path(part["path"])
        target = path.parent / f"{name}.original"
        expected = self._bytes(part)
        if expected_sha256 is not None:
            if hashlib.sha256(expected).hexdigest() != expected_sha256 or move is None:
                raise PairedHandoffError("paired PIN source differs from record")
            move(source, target, expected_sha256)
        elif target.exists():
            if read_recovery_file(target, name).raw != expected or source.exists():
                raise PairedHandoffError("paired original ownership conflicts")
        else:
            if read_recovery_file(source, name).raw != expected:
                raise PairedHandoffError("active original differs from paired record")
            os.replace(source, target)
        if read_recovery_file(target, name).raw != expected:
            raise PairedHandoffError("moved original readback differs")

    @writer_sink("paired_preflight_release")
    def release(self, path: Path) -> None:
        record = self.read(path)
        for name in ("hold", "current"):
            part = record[name]
            if Path(part["path"]).exists():
                raise PairedHandoffError("active original remains")
            if read_recovery_file(path.parent / f"{name}.original", name).raw != self._bytes(part):
                raise PairedHandoffError("archived original differs")
        marker = path.parent / "released.json"
        atomic_write_json(marker, {"id": record["id"]})
        if read_recovery_file(marker, "released").value != {"id": record["id"]}:
            raise PairedHandoffError("paired release readback differs")

    def is_released(self, path: Path) -> bool:
        return self.inspect(path).released

    def originals_match(self, path: Path) -> bool:
        record = self.read(path)
        try:
            for name in ("hold", "current"):
                if read_recovery_file(path.parent / f"{name}.original", name).raw != self._bytes(record[name]):
                    return False
            return True
        except (OSError, ValueError, TypeError):
            return False
