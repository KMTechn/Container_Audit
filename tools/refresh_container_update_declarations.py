"""Refresh current-byte bindings while preserving released preimages."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

if __package__:
    from . import derive_container_writer_sinks as inventory
else:
    import derive_container_writer_sinks as inventory

ROOT = inventory.ROOT
PINS = {
    "writer_session_fence.py": rb'(WRITER_INVENTORY_SHA256 = ")[0-9a-f]{64}(")',
    "tools/container_writer_fence.ps1": rb"(\$Script:ContainerWriterFenceInventorySha256 = ')[0-9a-f]{64}(')",
    "tools/container_writer_session_contract.json": rb'("writer_inventory_sha256": ")[0-9a-f]{64}(")',
}


def current_bindings(root: Path) -> dict[Path, bytes]:
    snapshot = root / "tools/container_writer_sink_inventory.json"
    digest = json.loads(snapshot.read_bytes())["inventory_sha256"].encode("ascii")
    bindings = {}
    for relative, pattern in PINS.items():
        path = root / relative
        contents, count = re.subn(pattern, lambda m: m[1] + digest + (m[2] or b""), path.read_bytes())
        if count != 1:
            raise ValueError("writer inventory pin is missing or ambiguous: " + relative)
        bindings[path] = contents

    declaration = root / "tools/container_data_generation_transition.json"
    transition = json.loads(declaration.read_bytes())
    if transition["schema_version"] != "container-audit-g-forward-transition-v1" or transition["direction"] != "forward":
        raise ValueError("unsupported transition declaration")
    transition["after_inventory_sha256"] = digest.decode("ascii")

    def current_sha(path: Path) -> str:
        contents = bindings[path] if path in bindings else path.read_bytes()
        return hashlib.sha256(contents).hexdigest()

    for row in transition["source_replacements"]:
        row["after"] = current_sha(root / row["path"])
    for row in transition["files"]:
        relative = row["path"]
        source = "portable/main.py" if relative == "app/main.py" else relative.removeprefix("app/")
        path = root / source
        if path.is_file():
            row["after"] = current_sha(path)
    bindings[declaration] = (json.dumps(transition, indent=2) + "\n").encode("utf-8")
    return bindings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    inventory.main(["--write" if args.write else "--check"])
    for path, contents in current_bindings(ROOT).items():
        if args.write:
            path.write_bytes(contents)
        elif path.read_bytes() != contents:
            raise SystemExit("current-byte declaration is stale: " + path.relative_to(ROOT).as_posix())
    # Pin substitution must not change the code-derived writer inventory.
    if args.write:
        inventory.main(["--check"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
