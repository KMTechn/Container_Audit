#!/usr/bin/env python3
"""Validate that final TEST1 transport pins match manifest build evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


EVIDENCE_SCHEMA = "kmtech-test1-manifest-build-evidence-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def validate_manifest_transport_binding(
    pins_path: Path,
    evidence_path: Path,
) -> dict[str, str]:
    pins_path = pins_path.resolve(strict=True)
    evidence_path = evidence_path.resolve(strict=True)
    evidence = read_json(evidence_path)
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise ValueError("manifest build evidence schema mismatch")
    if evidence.get("status") != "COMPLETE":
        raise ValueError("manifest build evidence is not complete")
    if evidence.get("scope") != "TEST1_ONLY":
        raise ValueError("manifest build evidence is not TEST1-only")

    recorded_pins_sha256 = evidence.get("pins_file_sha256")
    actual_pins_sha256 = sha256_file(pins_path)
    if recorded_pins_sha256 != actual_pins_sha256:
        raise ValueError(
            "final transport pins changed after manifest evidence was built: "
            f"recorded={recorded_pins_sha256}, actual={actual_pins_sha256}"
        )
    return {
        "pins_file_sha256": actual_pins_sha256,
        "manifest_build_evidence_sha256": sha256_file(evidence_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--manifest-build-evidence", type=Path, required=True)
    args = parser.parse_args()
    result = validate_manifest_transport_binding(
        args.pins,
        args.manifest_build_evidence,
    )
    print(json.dumps({"status": "PASS", **result}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
