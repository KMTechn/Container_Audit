from __future__ import annotations

import datetime
import json
import math
import os
import uuid
from pathlib import Path
from typing import Any, Mapping

from storage_utils import atomic_write_json
from writer_session_fence import writer_sink


class BestTimeRecordStore:
    def __init__(self, path: str | Path, *, retention_days: int = 30):
        self.path = Path(path)
        self.retention_days = max(0, int(retention_days))
        self.load_warning = ""
        self._preserve_source = False

    def load(self, *, today: datetime.date | None = None) -> dict[str, float]:
        self.load_warning = ""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, UnicodeError, OSError):
            self._preserve_source = True
            self.load_warning = "최고 기록을 읽지 못했습니다. 원본을 보존하고 기록 표시를 비웠습니다."
            return {}
        if not isinstance(raw, dict):
            self._preserve_source = True
            self.load_warning = "최고 기록 형식이 손상되었습니다. 원본을 보존하고 기록 표시를 비웠습니다."
            return {}

        if any(self._parse_record_date(key) is None or self._parse_record_time(value) is None
               for key, value in raw.items()):
            self._preserve_source = True
            self.load_warning = "유효하지 않은 최고 기록을 제외했습니다. 손상 원본은 설정 폴더에 보존합니다."
        records = self.cleanup(raw, today=today, persist=False)
        if records != raw:
            try:
                self.save(records)
            except OSError:
                self.load_warning = "최고 기록 정리 저장에 실패했습니다. 원본을 유지하고 유효한 기록만 표시합니다."
        return records

    @writer_sink("best_time_records")
    def save(self, records: Mapping[str, float]) -> None:
        if self._preserve_source and self.path.exists():
            backup = self.path.with_name(f"{self.path.name}.bad-{uuid.uuid4().hex}")
            with self.path.open("rb") as source, backup.open("xb") as target:
                target.write(source.read())
                target.flush()
                os.fsync(target.fileno())
            self._preserve_source = False
        atomic_write_json(self.path, dict(records), indent=4)

    def cleanup(
        self,
        records: Mapping[str, Any],
        *,
        today: datetime.date | None = None,
        persist: bool = True,
    ) -> dict[str, float]:
        today = today or datetime.date.today()
        cutoff = today - datetime.timedelta(days=self.retention_days)
        cleaned: dict[str, float] = {}
        for date_text, value in records.items():
            parsed_date = self._parse_record_date(date_text)
            parsed_time = self._parse_record_time(value)
            if parsed_date is None or parsed_time is None:
                continue
            if parsed_date < cutoff:
                continue
            cleaned[parsed_date.isoformat()] = parsed_time
        if persist and cleaned != records:
            self.save(cleaned)
        return cleaned

    def update_best_time(
        self,
        records: Mapping[str, Any],
        new_time: float,
        *,
        today: datetime.date | None = None,
    ) -> dict[str, float]:
        parsed_time = self._parse_record_time(new_time)
        if parsed_time is None:
            return self.cleanup(records, today=today)

        today = today or datetime.date.today()
        cleaned = self.cleanup(records, today=today, persist=False)
        today_key = today.isoformat()
        current_best = cleaned.get(today_key)
        if current_best is None or parsed_time < current_best:
            cleaned[today_key] = parsed_time
            self.save(cleaned)
        return cleaned

    @staticmethod
    def _parse_record_date(value: Any) -> datetime.date | None:
        try:
            return datetime.datetime.strptime(str(value), "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_record_time(value: Any) -> float | None:
        if isinstance(value, bool):
            return None
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(parsed) or parsed <= 0:
            return None
        return parsed
