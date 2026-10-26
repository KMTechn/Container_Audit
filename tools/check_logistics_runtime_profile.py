"""Read-only readiness check for the Container_Audit current-user profile."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from logistics_runtime_profile import default_profile_path, load_logistics_runtime_profile, resolve_logistics_profile_path  # noqa: E402
from auto_update import SupportArgumentParser, emit_support_record


def main(argv: list[str] | None = None) -> int:
    parser = SupportArgumentParser(description="Validate the installed logistics profile.")
    parser.add_argument("--profile-path", default=str(default_profile_path()))
    parser.add_argument("--optional", action="store_true")
    args = parser.parse_args(argv)
    original_profile_path = args.profile_path
    try:
        from data_generation_guard import record_before_owner_paths
        from storage_policy import build_container_audit_storage_paths
        from writer_session_fence import writer_admission
        # The optional absent-profile branch opens no user file and writes no state.
        effective_profile_path = resolve_logistics_profile_path(args.profile_path)
        args.profile_path = str(effective_profile_path)
        if args.optional and not str(original_profile_path).strip() and not effective_profile_path.exists():
            from logistics_runtime_profile import app_profile_env_value
            if not app_profile_env_value():
                print(json.dumps({'status':'optional-not-configured'}, sort_keys=True))
                return 0
        if not (args.optional and not effective_profile_path.is_file()):
            with writer_admission("logistics_profile_install"):
                storage = build_container_audit_storage_paths(application_path=str(REPO_ROOT))
                record_before_owner_paths(storage.data_root, file_paths=(args.profile_path,))
        profile = load_logistics_runtime_profile(read_retry=None,
            required=not args.optional,
            profile_path=args.profile_path,
        )
    except Exception as exc:
        emit_support_record(stage='runtime_profile_check', error=exc, file=sys.stderr)
        return 2
    if profile is None:
        print(json.dumps({"status": "optional-not-configured"}, sort_keys=True))
        return 0
    report = profile.redacted_summary()
    report["status"] = "ready"
    emit_support_record(report, stage='runtime_profile_check')
    return 0


if __name__ == "__main__":
    from auto_update import run_support_main
    raise SystemExit(run_support_main(main, stage='runtime_profile_check'))
