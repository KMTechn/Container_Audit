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
    if (not getattr(sys, 'frozen', False) and '-Mode' in arguments
        and arguments[arguments.index('-Mode') + 1:][:1] == ['active-work-evidence']
        and '-App' in arguments and arguments[arguments.index('-App') + 1:][:1] == ['Container_Audit']):
        from data_generation_guard import DataGenerationBlocked, probe_before_data_open
        from storage_policy import build_container_audit_storage_paths
        from writer_session_fence import writer_admission
        prepared = None
        try:
            with writer_admission('current_user_onboarding'):
                storage = build_container_audit_storage_paths(application_path=str(ROOT))
                probe_before_data_open(storage.data_root)
            # Resolve the same trusted adapter that common_main will observe.
            from kmtech_factory_contracts.active_work_probe import cli
            from kmtech_factory_contracts.active_work_probe.adapters import create_adapter
            from data_generation_guard import record_before_owner_paths
            namespace = cli._parser().parse_args(arguments)
            request = cli._request(namespace)
            adapter = create_adapter(request.app, request.target_pc)
            if request.app == 'Container_Audit':
                with writer_admission('current_user_onboarding'):
                    record_before_owner_paths(adapter.data_root,
                        directory_paths=(adapter.direct_sync_root,),
                        file_paths=(adapter.profile_path, *adapter.legacy_profile_paths))
                prepared = adapter
        except DataGenerationBlocked as exc:
            print(exc.user_message)
            return 3
        except Exception:
            # Resolver/config errors are handled by the original common CLI;
            # its resolver cannot reach observation until it succeeds.
            pass
        if prepared is not None:
            return common_main(arguments, adapter_factory=lambda app, target: prepared)
    return common_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
