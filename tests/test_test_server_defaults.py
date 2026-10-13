"""Address selection stays unreachable, including modules imported after setup."""
import argparse
import ast
import importlib
import inspect
from pathlib import Path
import sys
from urllib.parse import urlsplit

import pytest


def _source_address(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
    return ast.literal_eval(assignment.value)


def test_default_registration_and_onboarding_addresses_stay_off_production(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    defaults = {
        "current_user_onboarding": ("current_user_onboarding.py", "DEFAULT_SERVER_BASE_URL"),
        "tools.register_container_audit_worker_pc": ("tools/register_container_audit_worker_pc.py", "DEFAULT_ENDPOINT_URL"),
        "Container_Audit": ("Container_Audit.py", "UPDATE_BOOTSTRAP_MANIFEST_URL"),
    }
    production_hosts = {urlsplit(_source_address(root / file, attribute)).hostname
                        for file, attribute in defaults.values()}
    chosen = []

    class StopBeforeRunning(Exception):
        pass

    def capture_default(parser, *args, **kwargs):
        chosen.append(parser.get_default("endpoint_url") or parser.get_default("server_base_url"))
        raise StopBeforeRunning

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", capture_default)
    import tools
    # Both import paths run after the autouse fixture. Restoring these entries
    # also preserves references held by other tests to the original modules.
    with monkeypatch.context() as late_imports:
        late_imports.delattr(tools, "register_container_audit_worker_pc", raising=False)
        for name in ("current_user_onboarding", "tools.register_container_audit_worker_pc"):
            late_imports.delitem(sys.modules, name, raising=False)
        registration = importlib.import_module("tools.register_container_audit_worker_pc")
        onboarding = __import__("current_user_onboarding")
        application = importlib.import_module("Container_Audit")
        with pytest.raises(StopBeforeRunning):
            registration.main([])
        with pytest.raises(StopBeforeRunning):
            onboarding.onboarding_main([])
        chosen.append(inspect.signature(onboarding.onboard_current_user).parameters["server_base_url"].default)
        chosen.extend(getattr(module, attribute) for module, attribute in (
            (registration, "DEFAULT_ENDPOINT_URL"), (onboarding, "DEFAULT_SERVER_BASE_URL"),
            (application, "UPDATE_BOOTSTRAP_MANIFEST_URL"),
        ))
        for address in chosen:
            host = urlsplit(address).hostname
            assert host not in production_hosts, "production default remained"
            assert host == "unreachable.invalid", "test default differs"
