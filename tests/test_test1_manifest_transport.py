from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.validate_test1_manifest_transport import (
    validate_manifest_transport_binding,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_evidence(path: Path, pins_path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "kmtech-test1-manifest-build-evidence-v1",
                "status": "COMPLETE",
                "scope": "TEST1_ONLY",
                "pins_file_sha256": _sha256(pins_path),
            }
        ),
        encoding="utf-8",
    )


def test_accepts_final_pins_matching_build_evidence(tmp_path: Path) -> None:
    pins_path = tmp_path / "pins.json"
    evidence_path = tmp_path / "manifest-build-evidence.json"
    pins_path.write_text('{"authority":{"computer":"TEST1"}}', encoding="utf-8")
    _write_evidence(evidence_path, pins_path)

    result = validate_manifest_transport_binding(pins_path, evidence_path)

    assert result["pins_file_sha256"] == _sha256(pins_path)
    assert result["manifest_build_evidence_sha256"] == _sha256(evidence_path)


def test_rejects_pins_mutated_after_evidence_build(tmp_path: Path) -> None:
    pins_path = tmp_path / "pins.json"
    evidence_path = tmp_path / "manifest-build-evidence.json"
    pins_path.write_text('{"staging_root":"original"}', encoding="utf-8")
    _write_evidence(evidence_path, pins_path)

    pins_path.write_text('{"staging_root":"changed-after-build"}', encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="final transport pins changed after manifest evidence was built",
    ):
        validate_manifest_transport_binding(pins_path, evidence_path)
