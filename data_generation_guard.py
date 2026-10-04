"""CA admission before the first user-data read; no launch-time generation claim."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from kmtech_shared import data_generation as generation
from writer_session_fence import canonical_control_root, writer_sink


class DataGenerationBlocked(RuntimeError):
    def __init__(self, decision):
        self.decision = decision
        self.user_message = (generation.REFUSAL_MESSAGE if decision.get("status") == "REFUSE"
                             else generation.UNKNOWN_MESSAGE)
        super().__init__(self.user_message)


def _runtime_release():
    """Bind to the running clean source commit or the verified installed packet."""
    from tools.check_release_version import read_current_version

    if getattr(sys, "frozen", False):
        from kmtech_factory_contracts.package import verify_staged_package
        detail = verify_staged_package(Path(sys.executable).resolve().parent, release_mode=True)
        if detail.get("app_id") != "container_audit":
            raise ValueError("release application identity differs")
        version, build = detail["app_version"], detail["source_commit"]
        generation.version_key(version)
        return {"version": version, "build_id": build,
                "data_compatible_min_version": version, "compatibility_verified": False}
    app_root = Path(__file__).resolve().parent
    version = read_current_version(app_root / "Container_Audit.py")
    packet_root = app_root.parent if (app_root.parent / "portable-manifest.json").is_file() else app_root
    manifest_path = packet_root / "portable-manifest.json"
    if manifest_path.exists():
        from current_user_onboarding import verify_bootstrap_integrity
        from types import SimpleNamespace

        detail = verify_bootstrap_integrity(SimpleNamespace(
            app_root=packet_root, bootstrap_integrity_path=packet_root / "bootstrap-integrity.json"), required=True,
            expected_entrypoint=(app_root / "Container_Audit.py").relative_to(packet_root).as_posix())
        if detail.get("status") != "PASS":
            raise ValueError("release code integrity is not proven")
        if manifest_path.stat().st_size > 65536:
            raise ValueError("release manifest is oversized")
        manifest = json.loads(manifest_path.read_bytes())
        if manifest.get("version") != version:
            raise ValueError("release version binding differs")
        build = manifest.get("source_commit")
    else:
        build = subprocess.check_output(
            ["git", "--no-optional-locks", "-C", str(app_root), "rev-parse", "HEAD^{commit}"], stderr=subprocess.DEVNULL, text=True).strip()
        changed = subprocess.check_output(["git", "--no-optional-locks", "-C", str(app_root), "status", "--porcelain"],
                                          stderr=subprocess.DEVNULL, text=True)
        if changed.strip():
            raise ValueError("running source is not the release commit")
    if not isinstance(build, str) or not re.fullmatch(r"[0-9a-f]{40}", build):
        raise ValueError("release build identity is not proven")
    # This support-portable path has no verified private release declaration.
    return {"version": version, "build_id": build,
            "data_compatible_min_version": version, "compatibility_verified": False}


def marker_paths(data_root, subject_sid, *, environ=None):
    return (Path(os.path.abspath(os.fspath(data_root))) / "data-generation.json",
            canonical_control_root(environ) / "data-generation" / (subject_sid + ".json"))


@writer_sink("data_generation_marker")
def record_before_data_open(data_root):
    """Probe/record/readback under existing admission, before any DB or sidecar."""
    try:
        from tools.register_container_audit_worker_pc import _current_user_sid

        sid = _current_user_sid()
        release = _runtime_release()
        # Bind to the same ambient current-user control root as writer_sink's
        # admission. An onboarding data-root override does not relocate admission.
        paths = marker_paths(data_root, sid)
        decision = generation.probe_downgrade(paths, release["version"], app_id="container_audit",
                                              subject_sid=sid, target_build_id=release["build_id"])
        if not decision["allowed"]:
            raise DataGenerationBlocked(decision)
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            generation.record_generation(path, app_id="container_audit", subject_sid=sid, **release)
        return decision
    except DataGenerationBlocked:
        raise
    except Exception as exc:
        raise DataGenerationBlocked({"status": "UNKNOWN", "allowed": False,
            "message_key": "data_generation_unknown", "message": generation.UNKNOWN_MESSAGE}) from exc
