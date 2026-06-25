#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate config files that are allowed into a release artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SETTINGS_FILE = "container_audit_settings.json"
ALLOWED_SETTINGS_KEYS = {
    "scale_factor",
    "column_widths_validator",
    "paned_window_sash_positions",
    "enable_internal_test_commands",
}
FORBIDDEN_RUNTIME_NAMES = {"worker_registry.json", "best_time_records.json"}
FORBIDDEN_RUNTIME_DIRS = {"parked_trays"}
ALLOWED_RELEASE_CONFIG_NAMES = {SETTINGS_FILE}
FORBIDDEN_TEXT_MARKERS = (
    "secret",
    "token",
    "api_key",
    "apikey",
    "hmac",
    "producer",
    "credential",
    "endpoint",
    "http://",
    "https://",
    "localhost",
    "127.0.0.1",
    "175.45.200.171",
    "fault",
    "debug",
)


def _reject_forbidden_text_marker(value: str, *, path: str) -> None:
    lowered = value.lower()
    matched = [marker for marker in FORBIDDEN_TEXT_MARKERS if marker in lowered]
    if matched:
        raise ValueError(f"{path} contains forbidden release marker: {matched[0]}")


def _reject_forbidden_markers(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                _reject_forbidden_text_marker(key, path=f"{path}.{key}")
            _reject_forbidden_markers(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden_markers(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _reject_forbidden_text_marker(value, path=path)


def _require_int_mapping(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ValueError(f"{name} values must be non-negative integers")


def validate_settings_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{SETTINGS_FILE} must be a JSON object")
    _reject_forbidden_markers(payload, path=SETTINGS_FILE)
    unknown_keys = sorted(set(payload) - ALLOWED_SETTINGS_KEYS)
    if unknown_keys:
        raise ValueError(f"{SETTINGS_FILE} contains unknown keys: {', '.join(unknown_keys)}")
    scale_factor = payload.get("scale_factor")
    if scale_factor is not None:
        if not isinstance(scale_factor, (int, float)) or isinstance(scale_factor, bool):
            raise ValueError("scale_factor must be numeric")
        if not 0.7 <= float(scale_factor) <= 2.5:
            raise ValueError("scale_factor must be between 0.7 and 2.5")
    internal_commands = payload.get("enable_internal_test_commands")
    if internal_commands is True:
        raise ValueError("enable_internal_test_commands must be false or absent in release config")
    if internal_commands is not None and not isinstance(internal_commands, bool):
        raise ValueError("enable_internal_test_commands must be boolean when present")
    _require_int_mapping(payload.get("column_widths_validator"), name="column_widths_validator")
    _require_int_mapping(payload.get("paned_window_sash_positions"), name="paned_window_sash_positions")


def validate_release_config(config_dir: str | Path) -> None:
    root = Path(config_dir)
    if not root.is_dir():
        raise ValueError("release config directory does not exist")
    forbidden: list[str] = []
    for name in FORBIDDEN_RUNTIME_NAMES:
        if (root / name).exists():
            forbidden.append(name)
    for name in FORBIDDEN_RUNTIME_DIRS:
        if (root / name).exists():
            forbidden.append(name)
    if forbidden:
        raise ValueError("release config contains runtime-local artifacts: " + ", ".join(sorted(forbidden)))
    unknown_entries = sorted(child.name for child in root.iterdir() if child.name not in ALLOWED_RELEASE_CONFIG_NAMES)
    if unknown_entries:
        raise ValueError("release config contains unknown files: " + ", ".join(unknown_entries))
    settings_path = root / SETTINGS_FILE
    if not settings_path.is_file():
        raise ValueError(f"release config is missing {SETTINGS_FILE}")
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{SETTINGS_FILE} is not valid JSON: {exc.__class__.__name__}") from exc
    validate_settings_payload(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Container_Audit release config")
    parser.add_argument("--config-dir", default="config")
    args = parser.parse_args(argv)
    try:
        validate_release_config(args.config_dir)
    except ValueError as exc:
        print(f"release_config_check=FAIL reason={exc}", file=sys.stderr)
        return 2
    print("release_config_check=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
