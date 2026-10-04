"""PyInstaller entry point for the canonical active-work probe."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kmtech_factory_contracts.active_work_probe.cli import main as common_main


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Independent frozen common probes have their own tool identity/contract.
    if not getattr(sys, 'frozen', False) and '-Mode' in arguments and arguments[arguments.index('-Mode') + 1:][:1] == ['active-work-evidence']:
        from data_generation_guard import DataGenerationBlocked, record_before_data_open
        from storage_policy import build_container_audit_storage_paths
        from writer_session_fence import writer_admission
        try:
            with writer_admission('current_user_onboarding'):
                storage = build_container_audit_storage_paths(application_path=str(ROOT))
                record_before_data_open(storage.data_root)
        except DataGenerationBlocked as exc:
            print(exc.user_message)
            return 3
    return common_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
