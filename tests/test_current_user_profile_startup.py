"""Launcher start: the onboarded current-user logistics profile drives the catalog."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import Container_Audit as app_module
import item_catalog_sync as sync
import logistics_runtime_profile as runtime_module
from current_user_onboarding import resolve_current_user_onboarding_paths
from tests.test_item_catalog_sync import CATALOG, FakeResponse
from tools.install_logistics_runtime_profile import install_runtime_profile


pytestmark = pytest.mark.skipif(os.name != "nt", reason="current-user DPAPI is Windows-only")

APP_ROOT = Path(app_module.__file__).resolve().parent
ONBOARDED_ORIGIN = "https://lab-onboarded.example.invalid"
EXPLICIT_ORIGIN = "https://explicit.example.invalid"
PROCESS_ORIGIN = "https://process-env.example.invalid"
MACHINE_ORIGIN = "https://machine-profile.example.invalid"
TOKEN = "synthetic-w9caprofile-token"
SETUP_TITLE = "중앙 연결 설정 필요"


def _install_profile(path: Path, origin: str) -> Path:
    install_runtime_profile(
        profile_path=path,
        base_url=origin,
        authority_scope="scope-w9caprofile",
        authority_epoch=1,
        authority_plane="AUTHORITATIVE",
        plane_epoch=1,
        device_id="ca-device-w9caprofile",
        source_host_id="ca-host-w9caprofile",
        bearer_token=TOKEN,
        credential_scope="current_user",
    )
    return path


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    """Environment of launch-container-audit.cmd: no profile variables, no machine profile."""

    for name in (
        app_module.LOGISTICS_PROFILE_PATH_ENV,
        runtime_module.PROFILE_PATH_ENV,
        runtime_module.REQUIRED_ENV,
        runtime_module.TEST1_ISOLATED_LEGACY_OVERRIDE_ENV,
        app_module.DATA_ROOT_ENV,
        sync.URL_ENV,
        sync.ACTIVE_PATH_ENV,
        *sync.BASE_URL_ENV_NAMES,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setattr(
        runtime_module,
        "_canonical_machine_profile_path",
        lambda: tmp_path / "ProgramData" / runtime_module.DEFAULT_PROFILE_RELATIVE_PATH,
    )
    monkeypatch.setattr(runtime_module, "_machine_environment_value", lambda _name: "")
    requests = []

    def transport(kind):
        def get(url, **kwargs):
            requests.append((kind, url, dict(kwargs.get("headers") or {})))
            return FakeResponse(CATALOG)
        return get

    monkeypatch.setattr(sync, "_hardened_get", transport("authenticated"))
    monkeypatch.setattr(sync.requests, "get", transport("anonymous"))
    return requests


def _start_like_launcher(monkeypatch):
    # pytest re-sets this per phase; the product skips profile discovery under it.
    monkeypatch.delenv("PYTEST_CURRENT_TEST")


def test_launcher_start_uses_onboarded_current_user_profile(launcher, monkeypatch):
    onboarded = resolve_current_user_onboarding_paths(APP_ROOT).logistics_profile_path
    assert onboarded == (
        Path(os.environ["LOCALAPPDATA"])
        / "KMTech" / "Logistics" / "profiles" / "Container_Audit" / "runtime-profile.json"
    )
    _install_profile(onboarded, ONBOARDED_ORIGIN)
    _start_like_launcher(monkeypatch)

    app_module.prepare_startup_item_catalog()

    context = sync.get_catalog_attempt_context()
    assert [(kind, url) for kind, url, _headers in launcher] == [
        ("authenticated", ONBOARDED_ORIGIN + sync.CATALOG_PATH)
    ]
    assert launcher[0][2]["Authorization"] == f"Bearer {TOKEN}"
    assert context["profile_present"] is True
    assert context["catalog_source"] == "CENTRAL_REFRESH"
    # The transfer client and the catalog authenticate with the same profile.
    assert app_module.container_startup_logistics_client().base_url == ONBOARDED_ORIGIN


@pytest.mark.parametrize(
    "selector",
    ["container_audit_explicit", "process_km_logistics", "onboarded_over_machine"],
)
def test_environment_selected_profiles_are_kept(launcher, monkeypatch, tmp_path, selector):
    if selector == "onboarded_over_machine":
        _install_profile(runtime_module._canonical_machine_profile_path(), MACHINE_ORIGIN)
        onboarded = resolve_current_user_onboarding_paths(APP_ROOT).logistics_profile_path
        _install_profile(onboarded, ONBOARDED_ORIGIN)
        expected_origin = ONBOARDED_ORIGIN
    elif selector == "container_audit_explicit":
        onboarded = resolve_current_user_onboarding_paths(APP_ROOT).logistics_profile_path
        _install_profile(onboarded, ONBOARDED_ORIGIN)
        explicit = _install_profile(tmp_path / "explicit" / "runtime-profile.json", EXPLICIT_ORIGIN)
        monkeypatch.setenv(app_module.LOGISTICS_PROFILE_PATH_ENV, str(explicit))
        expected_origin = EXPLICIT_ORIGIN
    else:
        process = _install_profile(tmp_path / "process" / "runtime-profile.json", PROCESS_ORIGIN)
        monkeypatch.setenv(runtime_module.PROFILE_PATH_ENV, str(process))
        monkeypatch.setenv(runtime_module.REQUIRED_ENV, "1")
        expected_origin = PROCESS_ORIGIN
    _start_like_launcher(monkeypatch)

    app_module.prepare_startup_item_catalog()

    assert [(kind, url) for kind, url, _headers in launcher] == [
        ("authenticated", expected_origin + sync.CATALOG_PATH)
    ]
    assert app_module.container_startup_logistics_client().base_url == expected_origin


def test_no_profile_sends_no_request_and_startup_shows_setup_action(
    launcher, monkeypatch,
):
    calls, dialogs = [], []

    class Lease:
        def release(self):
            calls.append("release")

    class FakeRoot:
        def after(self, _delay_ms, _callback):
            calls.append("after")

    class FakeApp:
        def __init__(self):
            calls.append("app-created")
            self.root = FakeRoot()

        def run(self):
            calls.append("run")

    monkeypatch.setattr(app_module, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(app_module, "acquire_runtime_instance", lambda _root: Lease())
    monkeypatch.setattr(app_module, "ContainerAudit", FakeApp)
    monkeypatch.setattr(
        app_module.messagebox,
        "showwarning",
        lambda title, message, **_kwargs: dialogs.append((title, message)),
    )
    _start_like_launcher(monkeypatch)

    assert app_module.main([]) == 0

    assert launcher == []
    assert calls == ["app-created", "after", "run", "release"]
    assert len(dialogs) == 1
    title, message = dialogs[0]
    assert title == SETUP_TITLE
    assert "Windows 사용자" in message and "할 일" in message and "다시 시작" in message
    assert "작업은 계속" in message
    assert os.environ[sync.ACTIVE_PATH_ENV] == app_module.resource_path(
        os.path.join("assets", "Item.csv")
    )
    diagnostic = json.loads(
        next(
            Path(os.environ["LOCALAPPDATA"]).rglob("item_catalog_startup_diagnostic.json")
        ).read_text(encoding="utf-8")
    )
    assert diagnostic["request_sent"] is False
    assert diagnostic["profile_present"] is False
    assert diagnostic["pre_send_rejection_code"] == "PROFILE_ABSENT"
    assert diagnostic["catalog_source"] == "BUNDLED"
