"""Refresh current-byte bindings while preserving released preimages."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

if __package__:
    from . import derive_container_writer_sinks as inventory
else:
    import derive_container_writer_sinks as inventory

ROOT = inventory.ROOT
INSTALLED_RELEASE_SOURCES = (
    "e0c46f4104c3034f061580f11718aca2bc209bcc",
    "d3a1ad7b2364aae808c36a2359b18b04f92025e2",
)
PINS = {
    "writer_session_fence.py": rb'(WRITER_INVENTORY_SHA256 = ")[0-9a-f]{64}(")',
    "tools/container_writer_fence.ps1": rb"(\$Script:ContainerWriterFenceInventorySha256 = ')[0-9a-f]{64}(')",
    "tools/container_writer_session_contract.json": rb'("writer_inventory_sha256": ")[0-9a-f]{64}(")',
}


def released_preimages(root: Path, transition: dict) -> list[dict]:
    """Derive complete deployed preimages from immutable, approved releases."""
    source_paths = {row["path"] for row in transition["source_replacements"]}
    deployed = {}
    for row in transition["files"]:
        relative = row["path"]
        source = "portable/main.py" if relative == "app/main.py" else relative.removeprefix("app/")
        if source in source_paths:
            deployed[relative] = source

    def git(*arguments: str) -> bytes:
        result = subprocess.run(["git", *arguments], cwd=root, capture_output=True,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise ValueError("approved installed release object is unavailable")
        return result.stdout

    releases = []
    for commit in INSTALLED_RELEASE_SOURCES:
        if git("rev-parse", "--verify", commit + "^{commit}").decode("ascii").strip() != commit:
            raise ValueError("installed release must use its exact commit")
        tracked = set(git("ls-tree", "-r", "--name-only", commit).decode("utf-8").splitlines())
        old_inventory = json.loads(git("show", commit + ":tools/container_writer_sink_inventory.json"))
        files = []
        for relative, source in deployed.items():
            if source in tracked:
                files.append({"path": relative, "sha256": hashlib.sha256(git("show", commit + ":" + source)).hexdigest()})
            else:
                files.append({"path": relative, "absent": True})
        releases.append({"source_commit": commit,
                         "writer_inventory_sha256": old_inventory["inventory_sha256"], "files": files})
    return releases


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
    derived = released_preimages(root, transition)
    replacing = {row["source_commit"] for row in derived}
    transition["installed_release_preimages"] = [
        row for row in transition["installed_release_preimages"] if row["source_commit"] not in replacing
    ] + derived

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
