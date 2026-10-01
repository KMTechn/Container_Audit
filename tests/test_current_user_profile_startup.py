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
from tests.test_container_p0_contracts import _health_card
from tools.install_logistics_runtime_profile import install_runtime_profile
from tools import install_logistics_runtime_profile as installer_module


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
    """Launcher state with synthetic credentials and an old Machine configuration."""

    for name in (
        app_module.LOGISTICS_PROFILE_PATH_ENV,
        runtime_module.PROFILE_PATH_ENV,
        "KM_LOGISTICS_PROFILE_PATH",
        runtime_module.REQUIRED_ENV,
        runtime_module.TEST1_ISOLATED_LEGACY_OVERRIDE_ENV,
        app_module.DATA_ROOT_ENV,
        sync.URL_ENV,
        sync.ACTIVE_PATH_ENV,
        *sync.BASE_URL_ENV_NAMES,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    program_data = tmp_path / "ProgramData"
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    # Redirect the baseline's fixed PC-wide path as well as its process default.
    monkeypatch.setattr(
        runtime_module,
        "Path",
        lambda value: program_data if os.fspath(value).casefold() == r"c:\programdata"
        else Path(value),
    )
    machine_reads = []

    def machine_value(name):
        machine_reads.append(name)
        return {
            runtime_module.PROFILE_PATH_ENV: str(
                program_data / runtime_module.DEFAULT_PROFILE_RELATIVE_PATH
            ),
            runtime_module.REQUIRED_ENV: "1",
        }.get(name, "")

    monkeypatch.setattr(runtime_module, "_machine_environment_value", machine_value)
    encrypted_token = b"synthetic-current-user-protected-token"

    def decrypt(value):
        assert value == encrypted_token
        return TOKEN

    def protect(token):
        assert token == TOKEN
        return encrypted_token

    monkeypatch.setattr(installer_module, "protect_current_user_secret", protect)
    monkeypatch.setattr(installer_module, "unprotect_current_user_secret", decrypt)
    monkeypatch.setattr(runtime_module, "unprotect_machine_secret", decrypt)
    monkeypatch.setattr(runtime_module, "unprotect_current_user_secret", decrypt)
    monkeypatch.setattr(app_module, "unprotect_current_user_secret", decrypt)
    requests = []

    def transport(kind):
        def get(url, **kwargs):
            requests.append((kind, url, dict(kwargs.get("headers") or {})))
            return FakeResponse(CATALOG)
        return get

    monkeypatch.setattr(sync, "_hardened_get", transport("authenticated"))
    monkeypatch.setattr(sync.requests, "get", transport("anonymous"))
    yield requests
    assert machine_reads == [], "current-user startup must not read Machine logistics values"


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
    ["container_audit_explicit", "process_container_audit", "onboarded_over_machine"],
)
def test_environment_selected_profiles_are_kept(launcher, monkeypatch, tmp_path, selector):
    if selector == "onboarded_over_machine":
        _install_profile(
            Path(os.environ["PROGRAMDATA"]) / runtime_module.DEFAULT_PROFILE_RELATIVE_PATH,
            MACHINE_ORIGIN,
        )
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
        _apply_direct_sync_health = app_module.ContainerAudit._apply_direct_sync_health
        _consume_direct_sync_wake_results = lambda self: ""

        def __init__(self):
            calls.append("app-created")
            self.root = FakeRoot()
            self.info_cards = {"direct_sync": _health_card()}
            cards.append(self.info_cards["direct_sync"])

        def run(self):
            calls.append("run")

    cards = []
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
    assert dialogs == []  # DESIGN §0/§1: guidance stays in the work screen.
    message = cards[0]["value"].options["text"]
    assert SETUP_TITLE in message
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


@pytest.mark.parametrize("factory", ["loader", "startup", "catalog", "transfer"])
@pytest.mark.parametrize(
    "case", ["inherited_own", "own_override", "pc_default", "own_absent", "own_invalid"]
)
def test_clients_never_borrow_old_shared_identity(launcher, monkeypatch, tmp_path, factory, case):
    """Exercise real consumers with first-run disabled and valid old credentials."""
    shared = Path(os.environ["PROGRAMDATA"]) / "KMTech" / "Logistics"
    old_paths = [
        _install_profile(shared / "runtime-profile.json", MACHINE_ORIGIN),
        _install_profile(shared / "profiles" / "Container_Audit" / "runtime-profile.json", MACHINE_ORIGIN),
    ]
    for path in old_paths:
        values = json.loads(path.read_text(encoding="utf-8"))
        values["source_host_id"] = "foreign-old-program"
        path.write_text(json.dumps(values), encoding="utf-8")
    old_bytes = {path: path.read_bytes() for path in shared.rglob("*") if path.is_file()}
    own = resolve_current_user_onboarding_paths(APP_ROOT).logistics_profile_path
    if case in {"inherited_own", "own_override"}:
        if case == "own_override":
            own = tmp_path / "app-override" / "runtime-profile.json"
            monkeypatch.setenv("CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH", str(own))
        _install_profile(own, ONBOARDED_ORIGIN)
    elif case == "own_invalid":
        own.parent.mkdir(parents=True, exist_ok=True)
        own.write_text("{broken", encoding="utf-8")
    if case != "pc_default":
        monkeypatch.setenv("KM_LOGISTICS_PROFILE_PATH", str(old_paths[0]))
        monkeypatch.setenv("KM_LOGISTICS_REQUIRED", "1")
    else:
        assert "KM_LOGISTICS_PROFILE_PATH" not in os.environ
        assert "KM_LOGISTICS_REQUIRED" not in os.environ
    _start_like_launcher(monkeypatch)
    monkeypatch.setattr(app_module, "_first_run_onboarding_enabled", lambda: False)
    from transfer_client import logistics_transfer_client_from_env

    factories = {
        "loader": runtime_module.load_logistics_runtime_profile,
        "startup": app_module.container_startup_logistics_client,
        "catalog": sync._load_item_catalog_logistics_profile,
        "transfer": lambda: logistics_transfer_client_from_env(probe_required=False),
    }
    try:
        if case in {"own_absent", "own_invalid"}:
            with pytest.raises(runtime_module.LogisticsRuntimeConfigurationError):
                factories[factory]()
        else:
            selected = factories[factory]()
            if case == "pc_default":
                assert selected is None
            else:
                assert selected.base_url == ONBOARDED_ORIGIN
                assert selected.source_host_id == "ca-host-w9caprofile"
                if factory in {"loader", "catalog"}:
                    assert selected.profile_path == str(own.resolve())
    finally:
        assert {path: path.read_bytes() for path in old_bytes} == old_bytes
        assert launcher == [], "client creation must not contact the network"
