#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate Phase 0 read-only preflight execution inputs before any commands run."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_APP = "/root/WorkerAnalysisGUI-web"
EXPECTED_DB = "/mnt/rebuild/worker-analysis/data/worker_analysis.db"
EXPECTED_FQDN = "https://worker.kmtecherp.com"
EXPECTED_ROUTE_METHOD = "OPTIONS"
EXPECTED_ROUTE_PATH = "/api/producer-ingest/v1/source-file"
DEFAULT_EVIDENCE_SUBDIR = "00_freeze_manifest/phase0-preflight"
RUN_ID_RE = re.compile(r"^phase0-readonly-\d{8}T\d{6}Z$")

REQUIRED_OWNER_KEYS = {
    "db",
    "app",
    "field",
    "security",
    "downstream",
    "rollback",
    "change_coordinator",
}

FORBIDDEN_KEY_MARKERS = (
    "password",
    "passwd",
    "authorization",
    "secret",
    "signature",
    "token",
    "bearer",
    "hmac",
    "hmac_key",
    "api_key",
    "apikey",
    "x-producer-signature",
    "producer_signature",
    "producer_secret",
    "receipt_json",
    "raw_receipt",
    "raw_payload",
    "payload_bytes",
)

FORBIDDEN_VALUE_MARKERS = (
    "POST /api/producer-ingest/v1/source-file",
    "raw receipt json",
    "raw hmac secret",
    "producer secret",
    "producer-hmac-sha256-v1",
    "authorization:",
    "x-producer-signature",
    "signature=",
    "hmac=",
    "api_key=",
    "password=",
    "bearer token",
    "full raw payload",
)


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"inputs JSON is not readable JSON: {exc.__class__.__name__}") from exc
    if not isinstance(payload, dict):
        raise ValueError("inputs JSON must be an object")
    return payload


def _require_string(payload: dict[str, Any], key: str, *, non_placeholder: bool = True) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    value = value.strip()
    if non_placeholder and value.upper() in {"TBD", "TODO", "PLACEHOLDER", "CHANGEME"}:
        raise ValueError(f"{key} must be filled, not {value}")
    return value


def _require_exact(payload: dict[str, Any], key: str, expected: str) -> None:
    value = _require_string(payload, key)
    if value != expected:
        raise ValueError(f"{key} must be {expected!r}")


def _iter_items(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, item in value.items():
            yield f"{path}.{key}", key
            yield from _iter_items(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_items(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _reject_secret_material(payload: dict[str, Any]) -> None:
    for path, value in _iter_items(payload):
        lowered = str(value).lower()
        if path.endswith(tuple(f".{marker}" for marker in FORBIDDEN_KEY_MARKERS)):
            raise ValueError(f"{path} is forbidden in Phase 0 inputs")
        for marker in FORBIDDEN_KEY_MARKERS:
            if marker in lowered and path.rsplit(".", 1)[-1].lower() != "redaction_policy":
                raise ValueError(f"{path} contains forbidden secret marker: {marker}")
        for marker in FORBIDDEN_VALUE_MARKERS:
            if marker.lower() in lowered:
                raise ValueError(f"{path} contains forbidden Phase 0 value: {marker}")


def _validate_owners(payload: dict[str, Any]) -> None:
    owners = payload.get("owners")
    if not isinstance(owners, dict):
        raise ValueError("owners must be an object")
    missing = sorted(REQUIRED_OWNER_KEYS - set(owners))
    if missing:
        raise ValueError("owners missing required signoff keys: " + ", ".join(missing))
    not_signed = sorted(key for key in REQUIRED_OWNER_KEYS if owners.get(key) is not True)
    if not_signed:
        raise ValueError("owners not signed: " + ", ".join(not_signed))


def _validate_evidence_dir(payload: dict[str, Any]) -> None:
    root = Path(_require_string(payload, "evidence_root"))
    subdir = _require_string(payload, "evidence_subdir")
    if subdir.replace("\\", "/") != DEFAULT_EVIDENCE_SUBDIR:
        raise ValueError(f"evidence_subdir must be {DEFAULT_EVIDENCE_SUBDIR!r}")
    evidence_dir = root / Path(subdir)
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise ValueError(f"evidence subdir must be empty before Phase 0: {evidence_dir}")
    if evidence_dir.exists() and not evidence_dir.is_dir():
        raise ValueError(f"evidence subdir path exists but is not a directory: {evidence_dir}")


def validate_phase0_execution_inputs(inputs_json: str | Path) -> None:
    payload = _load_json(inputs_json)
    _reject_secret_material(payload)

    _require_string(payload, "change_id")
    run_id = _require_string(payload, "run_id")
    if not RUN_ID_RE.match(run_id):
        raise ValueError("run_id must match phase0-readonly-YYYYMMDDThhmmssZ")

    _require_string(payload, "server_host")
    _require_exact(payload, "app_path", EXPECTED_APP)
    _require_exact(payload, "db_path", EXPECTED_DB)
    _require_exact(payload, "fqdn", EXPECTED_FQDN)
    _require_exact(payload, "producer_route_method", EXPECTED_ROUTE_METHOD)
    _require_exact(payload, "producer_route_path", EXPECTED_ROUTE_PATH)
    _require_string(payload, "operator")
    _require_string(payload, "reviewer")
    if payload.get("redaction_policy_accepted") is not True:
        raise ValueError("redaction_policy_accepted must be true")

    _validate_owners(payload)
    _validate_evidence_dir(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 0 execution inputs")
    parser.add_argument("--inputs-json", required=True)
    args = parser.parse_args(argv)

    try:
        validate_phase0_execution_inputs(args.inputs_json)
    except ValueError as exc:
        print(f"phase0_execution_inputs_check=FAIL reason={exc}", file=sys.stderr)
        return 2

    print("phase0_execution_inputs_check=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
