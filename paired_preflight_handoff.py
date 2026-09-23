"""Durable ownership of a DRAINING hold and its separate current tray."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


class PairedHandoffError(RuntimeError):
    pass


class PairedPreflightHandoffStore:
    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def paths(self) -> tuple[Path, ...]:
        return tuple(sorted(self.directory.glob("*/record.json")))

    def pending(self) -> bool:
        # An incomplete or unreadable record must keep the workbench locked.
        for path in self.paths():
            try:
                if not self.is_released(path):
                    return True
            except PairedHandoffError:
                return True
        return False

    def pending_path(self) -> Path | None:
        for path in self.paths():
            if not self.is_released(path):
                return path
        return None

    @staticmethod
    def _part(path: Path) -> dict[str, str]:
        data = path.read_bytes()
        return {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes_b64": base64.b64encode(data).decode("ascii"),
        }

    @staticmethod
    def _bytes(part: dict[str, str]) -> bytes:
        data = base64.b64decode(part["bytes_b64"], validate=True)
        if hashlib.sha256(data).hexdigest() != part["sha256"]:
            raise PairedHandoffError("paired original hash differs")
        return data

    def read(self, path: Path) -> dict[str, Any]:
        try:
            record = json.loads(Path(path).read_text(encoding="utf-8"))
            if record["schema"] != "container-audit-paired-preflight-v1":
                raise PairedHandoffError("paired record schema differs")
            for name in ("hold", "current"):
                self._bytes(record[name])
            return record
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise PairedHandoffError("paired record cannot be verified") from exc

    @writer_sink("paired_preflight_record")
    def prepare(self, hold_path: Path, current_path: Path) -> Path:
        if self.pending():
            raise PairedHandoffError("another paired handoff is pending")
        hold = self._part(hold_path)
        current = self._part(current_path)
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
    def move_original(self, path: Path, name: str) -> None:
        record = self.read(path)
        part = record[name]
        source = Path(part["path"])
        target = path.parent / f"{name}.original"
        expected = self._bytes(part)
        if target.exists():
            if target.read_bytes() != expected or source.exists():
                raise PairedHandoffError("paired original ownership conflicts")
        else:
            if source.read_bytes() != expected:
                raise PairedHandoffError("active original differs from paired record")
            os.replace(source, target)
        if target.read_bytes() != expected:
            raise PairedHandoffError("moved original readback differs")

    @writer_sink("paired_preflight_release")
    def release(self, path: Path) -> None:
        record = self.read(path)
        for name in ("hold", "current"):
            part = record[name]
            if Path(part["path"]).exists():
                raise PairedHandoffError("active original remains")
            if (path.parent / f"{name}.original").read_bytes() != self._bytes(part):
                raise PairedHandoffError("archived original differs")
        marker = path.parent / "released.json"
        atomic_write_json(marker, {"id": record["id"]})
        if json.loads(marker.read_text(encoding="utf-8")) != {"id": record["id"]}:
            raise PairedHandoffError("paired release readback differs")

    def is_released(self, path: Path) -> bool:
        record = self.read(path)
        marker = path.parent / "released.json"
        if not marker.is_file():
            return False
        try:
            return json.loads(marker.read_text(encoding="utf-8")) == {"id": record["id"]}
        except (OSError, ValueError, TypeError):
            return False

    def originals_match(self, path: Path) -> bool:
        record = self.read(path)
        try:
            for name in ("hold", "current"):
                if (path.parent / f"{name}.original").read_bytes() != self._bytes(record[name]):
                    return False
            return True
        except (OSError, ValueError, TypeError):
            return False
