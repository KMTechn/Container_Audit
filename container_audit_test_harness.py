from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class InternalTestCommand:
    action: str
    count: int = 0
    item_code: str = ""
    error_message: str = ""


def parse_internal_test_command(raw_barcode: str) -> InternalTestCommand | None:
    value = str(raw_barcode or "").strip()
    upper = value.upper()
    if upper == "_RUN_AUTO_TEST_":
        return InternalTestCommand(action="run_auto_test")

    if upper.startswith("TEST_LOG_"):
        try:
            count = int(upper.split("_")[2])
        except (IndexError, ValueError):
            return None
        if count > 0:
            return InternalTestCommand(action="generate_test_logs", count=count)
        return None

    if upper.startswith("_CREATE_PARKED_TRAYS_"):
        match = re.fullmatch(r"_CREATE_PARKED_TRAYS_([^_]+)_(\d+)_?", value, flags=re.IGNORECASE)
        if not match:
            return InternalTestCommand(
                action="error",
                error_message="형식: _CREATE_PARKED_TRAYS_[품목코드]_[수량]_",
            )
        count = int(match.group(2))
        if count <= 0:
            return InternalTestCommand(
                action="error",
                error_message="수량은 1 이상이어야 합니다.",
            )
        return InternalTestCommand(
            action="create_parked_trays",
            item_code=match.group(1),
            count=count,
        )

    return None
