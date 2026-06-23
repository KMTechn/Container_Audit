from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Mapping

from storage_utils import atomic_write_json


class BestTimeRecordStore:
    def __init__(self, path: str | Path, *, retention_days: int = 30):
        self.path = Path(path)
        self.retention_days = max(0, int(retention_days))

    def load(self, *, today: datetime.date | None = None) -> dict[str, float]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        if not isinstance(raw, dict):
            return {}

        records = self.cleanup(raw, today=today, persist=False)
        if records != raw:
            self.save(records)
        return records

    def save(self, records: Mapping[str, float]) -> None:
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
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        if parsed <= 0:
            return None
        return parsed
