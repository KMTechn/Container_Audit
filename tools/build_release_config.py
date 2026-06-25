#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a clean release config directory from a local runtime config."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.check_release_config import SETTINGS_FILE, validate_release_config


def build_release_config(source_config_dir: str | Path, output_config_dir: str | Path) -> Path:
    source_root = Path(source_config_dir)
    output_root = Path(output_config_dir)
    if not source_root.is_dir():
        raise ValueError("source config directory does not exist")

    source_settings = source_root / SETTINGS_FILE
    if not source_settings.is_file():
        raise ValueError(f"source config is missing {SETTINGS_FILE}")

    output_root.mkdir(parents=True, exist_ok=True)
    output_settings = output_root / SETTINGS_FILE
    shutil.copyfile(source_settings, output_settings)

    validate_release_config(output_root)
    return output_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a clean Container_Audit release config")
    parser.add_argument("--source-config-dir", default="config")
    parser.add_argument("--output-config-dir", required=True)
    args = parser.parse_args(argv)
    try:
        output_root = build_release_config(args.source_config_dir, args.output_config_dir)
    except ValueError as exc:
        print(f"release_config_build=FAIL reason={exc}", file=sys.stderr)
        return 2
    print(f"release_config_build=PASS output={output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
