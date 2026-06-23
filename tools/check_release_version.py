#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate that a release tag matches Container_Audit.CURRENT_VERSION."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from update_service import parse_version_tag  # noqa: E402

VERSION_RE = re.compile(r'^\s*CURRENT_VERSION\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)


def read_current_version(source_path: str | os.PathLike[str] = ROOT / "Container_Audit.py") -> str:
    text = Path(source_path).read_text(encoding="utf-8")
    match = VERSION_RE.search(text)
    if not match:
        raise ValueError(f"CURRENT_VERSION not found in {source_path}")
    return match.group(1).strip()


def normalize_tag(tag: str) -> str:
    value = str(tag or "").strip()
    if not value:
        raise ValueError("release tag is required")
    if parse_version_tag(value) is None:
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check release tag against Container_Audit CURRENT_VERSION")
    parser.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--source-path", default=str(ROOT / "Container_Audit.py"))
    args = parser.parse_args(argv)

    try:
        tag = normalize_tag(args.tag)
        current_version = read_current_version(args.source_path)
        if parse_version_tag(current_version) is None:
            raise ValueError("CURRENT_VERSION must be vMAJOR.MINOR.PATCH")
    except Exception as exc:
        print(f"release_version_check=FAIL reason={exc}", file=sys.stderr)
        return 2

    if tag != current_version:
        print(
            f"release_version_check=FAIL tag={tag} current_version={current_version}",
            file=sys.stderr,
        )
        return 1
    print(f"release_version_check=PASS tag={tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
