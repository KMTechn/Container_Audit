#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate a Container_Audit update archive with the production extractor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from update_service import safe_extract_update_zip  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and extract a Container_Audit update archive")
    parser.add_argument("--zip-path", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args(argv)

    destination = Path(args.destination).resolve()
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            print(f"destination must be an empty directory or absent: {destination}", file=sys.stderr)
            return 2
    try:
        safe_extract_update_zip(args.zip_path, destination)
    except ValueError as exc:
        message = str(exc)
        if "runtime-local" in message and "현장 런타임/민감 상태 파일" not in message:
            message = "업데이트 ZIP에 현장 런타임/민감 상태 파일이 포함되어 있습니다: " + message
        print(message, file=sys.stderr)
        return 1
    print(f"update_archive_smoke_dir={destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
