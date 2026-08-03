#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate a Container_Audit update archive with the production extractor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from update_service import safe_extract_update_zip  # noqa: E402


def _is_link(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(int(getattr(metadata, "st_mode", 0))):
        return True
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_entries(root: Path, *, label: str) -> dict[str, tuple[str, Path]]:
    if _is_link(root) or not root.is_dir():
        raise ValueError(f"{label} root is unavailable or linked: {root}")
    entries: dict[str, tuple[str, Path]] = {}
    pending = [root]
    file_count = 0
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            if _is_link(path):
                raise ValueError(f"{label} contains a link or reparse point: {path}")
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                kind = "directory"
                pending.append(path)
            elif path.is_file():
                kind = "file"
                file_count += 1
            else:
                raise ValueError(f"{label} contains an unsupported entry: {path}")
            entries[relative] = (kind, path)
    if not file_count:
        raise ValueError(f"{label} contains no files")
    if len({name.casefold() for name in entries}) != len(entries):
        raise ValueError(f"{label} contains case-insensitive path collisions")
    return entries


def compare_staged_and_extracted(package_root: Path, extracted_root: Path) -> dict[str, object]:
    staged = _tree_entries(package_root, label="staged package")
    extracted = _tree_entries(extracted_root, label="extracted archive")
    if set(staged) != set(extracted):
        missing = sorted(set(staged) - set(extracted))
        extra = sorted(set(extracted) - set(staged))
        raise ValueError(
            f"archive membership differs from staged package: missing={missing} extra={extra}"
        )
    total_bytes = 0
    file_count = 0
    directory_count = 0
    for relative, (source_kind, source) in staged.items():
        candidate_kind, candidate = extracted[relative]
        if candidate_kind != source_kind:
            raise ValueError(f"archive entry type differs from staged package: {relative}")
        if source_kind == "directory":
            directory_count += 1
            continue
        file_count += 1
        source_size = source.stat().st_size
        if candidate.stat().st_size != source_size:
            raise ValueError(f"archive size differs from staged package: {relative}")
        if _sha256_file(candidate) != _sha256_file(source):
            raise ValueError(f"archive byte parity failed: {relative}")
        total_bytes += source_size
    return {
        "schema_version": "kmtech-container-release-archive-v1",
        "status": "PASS",
        "file_count": file_count,
        "directory_count": directory_count,
        "uncompressed_size_bytes": total_bytes,
        "crc_and_safe_extraction": True,
        "exact_membership": True,
        "byte_parity": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and extract a Container_Audit update archive")
    parser.add_argument("--zip-path", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--package-root", required=True)
    args = parser.parse_args(argv)

    destination = Path(args.destination).resolve()
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            print(f"destination must be an empty directory or absent: {destination}", file=sys.stderr)
            return 2
    try:
        safe_extract_update_zip(args.zip_path, destination)
        package_root = Path(args.package_root)
        extracted_root = destination / package_root.name
        report = compare_staged_and_extracted(package_root, extracted_root)
    except ValueError as exc:
        message = str(exc)
        if "runtime-local" in message and "현장 런타임/민감 상태 파일" not in message:
            message = "업데이트 ZIP에 현장 런타임/민감 상태 파일이 포함되어 있습니다: " + message
        print(message, file=sys.stderr)
        return 1
    report["update_archive_smoke_dir"] = str(destination)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
