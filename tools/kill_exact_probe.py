from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Mapping

import psutil


def durable_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    run_root = args.run_root.resolve()
    checkpoint_path = args.checkpoint.resolve()
    identity_path = args.identity.resolve() if args.identity else checkpoint_path
    output_path = args.output.resolve()
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    if int(identity.get("pid") or -1) != args.pid:
        raise SystemExit("identity PID mismatch")
    process = psutil.Process(args.pid)
    command_line = process.cmdline()
    if str(run_root).casefold() not in " ".join(command_line).casefold():
        raise SystemExit("run-root is absent from exact process command line")
    state_path = Path(str(checkpoint["state_path"]))
    marker_stat = checkpoint_path.stat()
    state_stat = state_path.stat()
    before = {
        "pid": args.pid,
        "process_name": process.name(),
        "executable": process.exe(),
        "command_line": command_line,
        "process_create_time_ns": int(process.create_time() * 1_000_000_000),
        "kill_requested_wall_time_ns": time.time_ns(),
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_sha256": sha256_file(checkpoint_path),
        "checkpoint_mtime_ns": marker_stat.st_mtime_ns,
        "checkpoint_last_execution_point": checkpoint.get("last_execution_point"),
        "process_identity_path": str(identity_path),
        "process_identity_sha256": sha256_file(identity_path),
        "state_path": str(state_path),
        "state_sha256": sha256_file(state_path),
        "state_mtime_ns": state_stat.st_mtime_ns,
        "state_precedes_checkpoint": state_stat.st_mtime_ns <= marker_stat.st_mtime_ns,
        "exact_event_count_at_cut": checkpoint.get("exact_event_count"),
        "run_root_verified_in_command_line": True,
    }
    process.kill()
    return_code = process.wait(timeout=15.0)
    before.update(
        {
            "kill_completed_wall_time_ns": time.time_ns(),
            "return_code": return_code,
            "process_absent_after_kill": not psutil.pid_exists(args.pid),
            "power_cut_equivalence": "PROCESS_KILL_APPROXIMATION_ONLY",
        }
    )
    durable_json(output_path, before)
    return 0 if before["process_absent_after_kill"] else 6


if __name__ == "__main__":
    raise SystemExit(main())
