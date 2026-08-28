"""Stage only charset-normalizer Python sources for release analysis."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import shutil


REQUIRED_FILES = ("__init__.py", "api.py", "md.py")
NATIVE_SUFFIXES = frozenset({".dll", ".exe", ".pyd"})


def stage(output_root: Path) -> dict[str, object]:
    target_root = output_root.resolve() / "charset_normalizer"
    if output_root.exists():
        raise RuntimeError(f"source-only override root must be absent: {output_root}")

    spec = importlib.util.find_spec("charset_normalizer")
    locations = tuple(spec.submodule_search_locations or ()) if spec else ()
    if len(locations) != 1:
        raise RuntimeError("installed charset-normalizer package root is ambiguous")
    source_root = Path(locations[0]).resolve()
    if not source_root.is_dir():
        raise RuntimeError(f"installed charset-normalizer package root is missing: {source_root}")

    target_root.mkdir(parents=True)
    copied: list[str] = []
    for source_path in sorted(source_root.rglob("*")):
        if not source_path.is_file():
            continue
        if source_path.suffix.lower() != ".py" and source_path.name != "py.typed":
            continue
        relative = source_path.relative_to(source_root)
        target_path = target_root / relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)
        copied.append(relative.as_posix())

    missing = [name for name in REQUIRED_FILES if not (target_root / name).is_file()]
    native = [
        path.relative_to(output_root).as_posix()
        for path in output_root.rglob("*")
        if path.is_file() and path.suffix.lower() in NATIVE_SUFFIXES
    ]
    if missing or native:
        raise RuntimeError(
            f"source-only charset-normalizer staging failed: missing={missing}, native={native}"
        )
    return {
        "source_root": str(source_root),
        "output_root": str(output_root.resolve()),
        "version": importlib.metadata.version("charset-normalizer"),
        "files": copied,
        "native_files": native,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.output_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
