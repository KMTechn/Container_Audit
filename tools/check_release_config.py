#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate config files that are allowed into a release artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse


SETTINGS_FILE = "container_audit_settings.json"
ALLOWED_SETTINGS_KEYS = {
    "scale_factor",
    "column_widths_validator",
    "paned_window_sash_positions",
    "enable_internal_test_commands",
    "update_settings",
}
ALLOWED_UPDATE_SETTINGS_KEYS = {
    "provider",
    "manifest_url",
    "manifest_signature_url",
    "manifest_public_key",
    "channel",
}
UPDATE_SECRET_QUERY_KEYS = {
    "access_token",
    "api_key",
    "client_secret",
    "github_token",
    "pat",
    "private_key",
    "sig",
    "signature",
    "token",
}
UPDATE_SECRET_QUERY_PREFIXES = ("x_amz_", "x_goog_")
GITHUB_UPDATE_HOSTS = {"api.github.com", "github.com", "www.github.com"}
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


def _require_https_update_url(value: Any, *, name: str, required: bool = False) -> None:
    if value in (None, "") and not required:
        return
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"update_settings.{name} must be a non-empty HTTPS URL")
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(f"update_settings.{name} must be HTTPS")
    if parsed.username or parsed.password:
        raise ValueError(f"update_settings.{name} must not include userinfo")
    if parsed.fragment:
        raise ValueError(f"update_settings.{name} must not include fragments")
    host = (parsed.hostname or "").lower()
    if host in GITHUB_UPDATE_HOSTS or host.endswith(".githubusercontent.com"):
        raise ValueError(f"update_settings.{name} must not point to GitHub-hosted update storage")
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = key.lower().replace("-", "_")
        if normalized_key in UPDATE_SECRET_QUERY_KEYS or normalized_key.startswith(UPDATE_SECRET_QUERY_PREFIXES):
            raise ValueError(f"update_settings.{name} must not contain raw token query parameters")


def validate_update_settings_payload(payload: Any) -> None:
    if payload is None:
        return
    if not isinstance(payload, dict):
        raise ValueError("update_settings must be an object")
    unknown_keys = sorted(set(payload) - ALLOWED_UPDATE_SETTINGS_KEYS)
    if unknown_keys:
        raise ValueError("update_settings contains unknown keys: " + ", ".join(unknown_keys))
    provider = payload.get("provider")
    if provider == "github":
        channel = payload.get("channel")
        if channel is not None and (
            not isinstance(channel, str)
            or not channel.strip()
            or not all(ch.isalnum() or ch in "._-" for ch in channel.strip())
            or len(channel.strip()) > 32
        ):
            raise ValueError("update_settings.channel contains invalid characters")
        forbidden = sorted(set(payload) - {"provider", "channel"})
        if forbidden:
            raise ValueError("update_settings github provider contains private-manifest keys: " + ", ".join(forbidden))
        return
    if provider != "private_manifest":
        raise ValueError("update_settings.provider must be private_manifest or github")
    public_key = payload.get("manifest_public_key")
    if not isinstance(public_key, str) or not public_key.strip():
        raise ValueError("update_settings.manifest_public_key is required")
    if not all(ch in "0123456789abcdefABCDEF" for ch in public_key.strip()) or len(public_key.strip()) != 64:
        raise ValueError("update_settings.manifest_public_key must be 64 hex characters")
    channel = payload.get("channel")
    if not isinstance(channel, str) or not channel.strip():
        raise ValueError("update_settings.channel is required")
    if not all(ch.isalnum() or ch in "._-" for ch in channel.strip()) or len(channel.strip()) > 32:
        raise ValueError("update_settings.channel contains invalid characters")
    _require_https_update_url(payload.get("manifest_url"), name="manifest_url", required=True)
    _require_https_update_url(payload.get("manifest_signature_url"), name="manifest_signature_url")


def validate_settings_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{SETTINGS_FILE} must be a JSON object")
    validate_update_settings_payload(payload.get("update_settings"))
    payload_for_marker_check = {key: value for key, value in payload.items() if key != "update_settings"}
    _reject_forbidden_markers(payload_for_marker_check, path=SETTINGS_FILE)
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
