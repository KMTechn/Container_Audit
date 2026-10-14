"""Portable Container_Audit entry point for the signed CPython runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

_APP_PROCESS_STARTED_AT = datetime.now(timezone.utc)

APP_ROOT = Path(__file__).resolve().parent
SITE_PACKAGES = APP_ROOT / "site-packages"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
if str(SITE_PACKAGES) not in sys.path:
    sys.path.insert(1, str(SITE_PACKAGES))

from writer_session_fence import WriterFenceError, writer_sink  # noqa: E402


@writer_sink("portable_smoke_marker")
def _portable_smoke() -> int:
    if str(os.environ.get("CONTAINER_AUDIT_AUTOMATED_TEST") or "").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }:
        raise RuntimeError("portable smoke requires CONTAINER_AUDIT_AUTOMATED_TEST")
    marker_text = str(os.environ.get("CONTAINER_AUDIT_PORTABLE_SMOKE_MARKER") or "").strip()
    if not marker_text:
        raise RuntimeError("portable smoke marker path is required")

    import Container_Audit  # noqa: F401

    roots = (
        "PIL",
        "pygame",
        "charset_normalizer",
        "cryptography",
        "cffi",
        "_cffi_backend",
    )
    loaded = sorted(
        name
        for name in sys.modules
        if any(name == root or name.startswith(root + ".") for root in roots)
    )
    payload = {
        "schema": "container-audit-portable-smoke-v1",
        "python_executable": sys.executable,
        "python_version": list(sys.version_info[:3]),
        "app_root": str(APP_ROOT),
        "forbidden_modules_loaded": loaded,
    }
    marker = Path(marker_text).expanduser().resolve()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


def main() -> int:
    if "--zero-pe-portable-smoke" in sys.argv[1:]:
        return _portable_smoke()
    arguments = list(sys.argv[1:])
    application_main_started = False
    try:
        if arguments[:1] == ["--container-audit-user-relay"] and "--request-app-stop" in arguments:
            from user_relay import main as relay_main

            return relay_main(arguments[1:])
        if arguments[:1] == ["--container-audit-direct-sync-relay"]:
            # The product host owns the relay startup gate and guarded runner.
            from container_audit_product_host import dispatch_product_mode

            return dispatch_product_mode(arguments)
        if not arguments or arguments[0] not in {
            "--onboard-current-user", "--remove-current-user-setup",
            "--restore-current-user-lifecycle-after-replacement",
            "--container-audit-user-relay", "--container-audit-direct-sync-relay",
        }:
            from current_user_onboarding import (
                CurrentUserOnboardingError, consume_pending_machine_onboarding,
            )
            try:
                consume_pending_machine_onboarding(APP_ROOT, check_target_only=True)
            except CurrentUserOnboardingError as failure:
                from Container_Audit import _show_first_run_onboarding_error
                _show_first_run_onboarding_error(failure)
                return 1
        from auto_update import startup_gate

        gate_result = startup_gate(APP_ROOT, arguments)
        if gate_result is not None:
            return gate_result
        import Container_Audit as application

        # Requests during entrypoint imports/onboarding belong to this launch.
        application._APP_PROCESS_STARTED_AT = _APP_PROCESS_STARTED_AT
        application_main_started = True
        result = application.main()
        return 0 if result is None else int(result)
    except Exception as error:
        if arguments[:1] not in (["--onboard-current-user"], ["--remove-current-user-setup"],
                                  ["--restore-current-user-lifecycle-after-replacement"]):
            from auto_update import emit_support_record
            emit_support_record(stage='portable_entrypoint', error=error, file=sys.stderr)
            if not application_main_started and isinstance(error, WriterFenceError) and error.code == "WRITER_GATE_ABANDONED":
                from container_audit_product_host import PRODUCT_MODES
                if not any(argument in PRODUCT_MODES or argument in {"--help", "-h"} for argument in arguments):
                    try:
                        from Container_Audit import _show_startup_unavailable
                        _show_startup_unavailable("이적 다시 열기 — 한 번 더 여세요")
                    except Exception:
                        pass  # The optional notice cannot change support evidence or exit.
            return 1
        from current_user_onboarding import emit_installer_failure
        return emit_installer_failure(error, "installer_entrypoint")


if __name__ == "__main__":
    raise SystemExit(main())
