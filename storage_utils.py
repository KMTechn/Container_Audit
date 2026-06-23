from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any


def atomic_write_json(
    path: str | os.PathLike[str],
    payload: Any,
    *,
    indent: int = 4,
    ensure_ascii: bool = True,
    trailing_newline: bool = False,
) -> None:
    serialized = json.dumps(payload, indent=indent, ensure_ascii=ensure_ascii)
    if trailing_newline:
        serialized += "\n"

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_name(f"{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as f:
            f.write(serialized)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
