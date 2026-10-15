#!/usr/bin/env python
"""Build the Container_Audit signed-CPython portable tree without freezing."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vendor.kmtech_zero_pe.release_signature import (  # noqa: E402
    validate_public_key_config,
)
from tools.derive_container_writer_sinks import (  # noqa: E402
    SHELL_KIT_READY_SHA256,
    SHELL_KIT_READY_VERSION,
    _canonical_json_bytes as _writer_inventory_json_bytes,
    derive_inventory as _derive_writer_inventory,
)
from update_service import (  # noqa: E402
    DEFAULT_MAX_RUNTIME_FILE_INVENTORY_BYTES,
    RUNTIME_FILE_INVENTORY_FILENAME,
    RUNTIME_FILE_INVENTORY_SCHEMA,
)


EXPECTED_PYTHON = (3, 12, 10)
PORTABLE_SCHEMA = "container-audit-portable-tree-v1"
RUNTIME_ROOT_FILES = (
    "LICENSE.txt",
    "python.exe",
    "pythonw.exe",
    "python3.dll",
    "python312.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
)
# Preserve the existing portable root modules, including compatibility/recovery
# consumers. Add new runtime modules here explicitly; unrelated root scripts
# must not enter the packet or seed its tools import closure.
APP_ROOT_FILES = (
    "atomic_replace.py",
    "worker_roster.py",
    "auto_update.py",
    "startup_check.py",
    "startup_check_report.py",
    "best_time_records.py",
    "Container_Audit.py",
    "ca_screen_bridge.py",
    "screen_startup_fallback.py",
    "container_admin_pin.py",
    "container_audit_product_host.py",
    "container_audit_test_harness.py",
    "current_user_onboarding.py",
    "data_generation_guard.py",
    "direct_sync_auto_bootstrap.py",
    "direct_sync_health.py",
    "direct_sync_operator.py",
    "direct_sync_push.py",
    "direct_sync_runtime.py",
    "event_contracts.py",
    "event_log_store.py",
    "event_payloads.py",
    "event_stream_policy.py",
    "isolated_qualification.py",
    "item_catalog.py",
    "item_catalog_sync.py",
    "label_qr.py",
    "legacy_state_migration.py",
    "logistics_runtime_profile.py",
    "native_audio.py",
    "paired_preflight_handoff.py",
    "parked_tray_store.py",
    "pin_file_move.py",
    "phs_label_workflow.py",
    "phs_reconciliation_workflow.py",
    "preflight_scan_hold.py",
    "producer_runtime_client.py",
    "product_exchange.py",
    "tray_completion.py",
    "product_identity_port.py",
    "product_scan.py",
    "protected_admin.py",
    "recovery_file_read.py",
    "recovery_two_phase.py",
    "replacement_log_lookup.py",
    "replacement_workflow.py",
    "responsive_layout.py",
    "runtime_dependency_guard.py",
    "runtime_instance.py",
    "runtime_entry.py",
    "runtime_instance_win32.py",
    "tk_callback_result.py",
    "scan_display.py",
    "session_history.py",
    "storage_policy.py",
    "storage_utils.py",
    "style_tokens.py",
    "terminal_operation_lease.py",
    "tk_serial_ui_lane.py",
    "transfer_client.py",
    "transfer_common.py",
    "transfer_member_exchange.py",
    "transfer_seal.py",
    "transfer_store.py",
    "tray_state.py",
    "update_service.py",
    "user_relay.py",
    "warning_presenter.py",
    "work_session_state.py",
    "worker_registry.py",
    "writer_session_fence.py",
)
APP_PACKAGE_DIRS = (
    "kmtech_factory_contracts",
    "kmtech_shared",
    "vendor",
    "shell",
)
APP_DATA_DIRS = ("assets", "ui")
APP_DATA_FILES = (
    "contract.lock.json",
    "kmtech_shared.manifest.json",
    "kmtech_shared.lock.json",
    "config/container_audit_settings.json",
)
EXTERNAL_TOOL_MODULES: tuple[str, ...] = ("tools.direct_sync_relay_operator",)
PORTABLE_INSTALL_ASSETS = (
    ("tools/apply_prepared_update.ps1", "tools/apply_prepared_update.ps1"),
    ("INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_CANONICAL_PORTABLE.ps1"),
    ("INSTALL_THIS_PC.ps1", "INSTALL_THIS_PC.ps1"),
    ("tools/bootstrap_integrity.ps1", "tools/bootstrap_integrity.ps1"),
    ("kmtech_shared/powershell/portable.ps1", "app/kmtech_shared/powershell/portable.ps1"),
    ("kmtech_shared/powershell/ps51_module_prologue.ps1", "app/kmtech_shared/powershell/ps51_module_prologue.ps1"),
    ("tools/container_writer_fence.ps1", "tools/container_writer_fence.ps1"),
    ("tools/container_writer_session.ps1", "tools/container_writer_session.ps1"),
    ("tools/container_data_generation_transition.json", "tools/container_data_generation_transition.json"),
    (
        "tools/container_writer_session_contract.json",
        "tools/container_writer_session_contract.json",
    ),
    (
        "tools/container_writer_sink_inventory.json",
        "tools/container_writer_sink_inventory.json",
    ),
)
UPDATE_KEY_CONFIG_FILENAME = "update-manifest-key-config.json"
UPDATE_KEY_CONFIG_SCHEMA = "container-audit-update-key-config-v1"
THIRD_PARTY = {
    "certifi": ("2026.6.17", ("certifi",)),
    "chardet": ("5.2.0", ("chardet",)),
    "idna": ("3.18", ("idna",)),
    "qrcode": ("8.2", ("qrcode",)),
    "requests": ("2.34.2", ("requests",)),
    "typing-extensions": ("4.15.0", ("typing_extensions.py",)),
    "urllib3": ("2.7.0", ("urllib3",)),
    # Same shell runtime closure as Inspection_worker dceb851d.
    "keyboard": ("0.13.5", ("keyboard",)),
    "bottle": ("0.13.4", ("bottle.py",)),
    "cffi": ("2.1.1", ("cffi", "_cffi_backend.cp312-win_amd64.pyd")),
    "clr_loader": ("0.3.1", ("clr_loader",)),
    "proxy_tools": ("0.1.0", ("proxy_tools",)),
    "pycparser": ("3.11", ("pycparser",)),
    "pythonnet": ("3.2.1", ("pythonnet", "clr.py")),
    "pywebview": ("6.2.1", ("webview",)),
}
BUILD_ENVIRONMENT_LOCK = "requirements-portable-build-win-py312.lock"
NATIVE_ALLOWLIST_SOURCE_SHA256 = "b58c9873926e26056672f8aa7f2fae9ba0a1dc11a9f5b4ca12dc727959c07c42"
# Exact approved NATIVE-ALLOWLIST.json bytes; only its unsigned subset is
# exempt from signature validation. Core, WinForms and all three Loaders remain signed.
APP_NATIVE_ALLOWLIST: dict[str, tuple[int, str]] = {
    "site-packages/_cffi_backend.cp312-win_amd64.pyd": (181248, "9af5e4f68a41f26b726f2e9424f9d58a4f5666189f6a48be95f406b257102aec"),
    "site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll": (10752, "07f62bcb1b70320f221ffb2cfc5ce6133815195f3e7cdb8d833222506188c2ac"),
    "site-packages/pythonnet/runtime/Python.Runtime.dll": (451584, "2ebd4492e28442ef1f1af587afe5b3a090c2ebfa220758ded4f1450f2a27f13a"),
    "site-packages/webview/lib/Microsoft.Web.WebView2.Core.dll": (649800, "8219a3135436c147f8eb02fb831e99596103eebc18b6d7b794ca93f4c67018a2"),
    "site-packages/webview/lib/Microsoft.Web.WebView2.WinForms.dll": (39016, "c48f8d729dc531288d2c53a6241effe7922ed1b947850b2442008a945c098c48"),
    "site-packages/webview/lib/runtimes/win-arm64/native/WebView2Loader.dll": (147016, "0937030efc718f3da77c5e0978fb5046e381d0bb7b01acaad31a535a1b588a33"),
    "site-packages/webview/lib/runtimes/win-x64/native/WebView2Loader.dll": (161864, "eb5335edeaa6f2122c044e82aab2351dc8c9b4e0fe5e578c71922fb61be285e7"),
    "site-packages/webview/lib/runtimes/win-x86/native/WebView2Loader.dll": (121928, "04814b2c59314c6452d61b821a4a3a5c5f8e8577b55b985f6a7a4b59f8907ec5"),
}
APP_NATIVE_UNSIGNED = frozenset({
    "site-packages/_cffi_backend.cp312-win_amd64.pyd",
    "site-packages/clr_loader/ffi/dlls/amd64/ClrLoader.dll",
    "site-packages/pythonnet/runtime/Python.Runtime.dll",
})
THIRD_PARTY_EXCLUDED_PATHS = frozenset({
    "qrcode/tests",
    "clr_loader/ffi/dlls/x86/ClrLoader.dll",
    "webview/lib/WebBrowserInterop.x64.dll",
    "webview/lib/WebBrowserInterop.x86.dll",
})
SHELL_BRIDGE_SOURCE_COMMIT = "65003a342d7c79f38ee078edd381a254af38cd07"
FORBIDDEN_PACKAGE_NAMES = frozenset(
    {"PIL", "charset_normalizer", "cryptography", "pygame"}
)


class PortableBuildError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ignore(_directory: str, names: list[str]) -> set[str]:
    ignored = {name for name in names if name == "__pycache__" or name.endswith((".pyc", ".pyo"))}
    return ignored


def _copy_tree(source: Path, target: Path, excluded: frozenset[str] = frozenset()) -> None:
    if not source.is_dir():
        raise PortableBuildError(f"required source directory is missing: {source}")
    def ignore(directory: str, names: list[str]) -> set[str]:
        relative = Path(directory).relative_to(source.parent)
        return _ignore(directory, names) | {
            name for name in names if (relative / name).as_posix() in excluded
        }

    shutil.copytree(source, target, ignore=ignore)


def _tool_module_source(repo_root: Path, module_name: str) -> Path:
    if not module_name.startswith("tools."):
        raise PortableBuildError(f"not a tools module: {module_name}")
    relative = Path(*module_name.split(".")[1:]).with_suffix(".py")
    source = repo_root / "tools" / relative
    if not source.is_file():
        raise PortableBuildError(
            f"required portable tool module is missing: {module_name}"
        )
    return source


def _imported_tool_modules(source: Path) -> set[str]:
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise PortableBuildError(
            f"portable dependency scan failed for {source}"
        ) from exc

    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.name
                for alias in node.names
                if alias.name.startswith("tools.")
            )
            continue
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "tools":
                modules.update(
                    f"tools.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
            elif node.module.startswith("tools."):
                modules.add(node.module)
            continue
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function = node.func
        is_dynamic_import = (
            isinstance(function, ast.Name) and function.id == "__import__"
        ) or (
            isinstance(function, ast.Attribute)
            and function.attr == "import_module"
            and isinstance(function.value, ast.Name)
            and function.value.id == "importlib"
        )
        first = node.args[0]
        if (
            is_dynamic_import
            and isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and first.value.startswith("tools.")
        ):
            modules.add(first.value)
    return modules


def _portable_application_sources(repo_root: Path) -> list[Path]:
    sources = [repo_root / name for name in APP_ROOT_FILES]
    for source in sources:
        if not source.is_file():
            raise PortableBuildError(f"required application module is missing: {source}")
    for name in APP_PACKAGE_DIRS:
        sources.extend((repo_root / name).rglob("*.py"))
    portable_main = repo_root / "portable" / "main.py"
    if not portable_main.is_file():
        raise PortableBuildError(f"portable entrypoint is missing: {portable_main}")
    sources.append(portable_main)
    return sorted(set(sources), key=lambda item: item.as_posix().casefold())


def _discover_portable_tool_sources(
    repo_root: Path,
    initial_sources: Iterable[Path] | None = None,
    external_modules: Iterable[str] = EXTERNAL_TOOL_MODULES,
) -> list[Path]:
    pending = set(external_modules)
    for source in initial_sources or _portable_application_sources(repo_root):
        pending.update(_imported_tool_modules(source))

    discovered: dict[str, Path] = {}
    while pending:
        module_name = min(pending, key=str.casefold)
        pending.remove(module_name)
        if module_name in discovered:
            continue
        source = _tool_module_source(repo_root, module_name)
        discovered[module_name] = source
        pending.update(_imported_tool_modules(source) - discovered.keys())
    return [discovered[name] for name in sorted(discovered, key=str.casefold)]


def _runtime_source(python_home: Path, runtime: Path) -> None:
    if tuple(sys.version_info[:3]) != EXPECTED_PYTHON:
        raise PortableBuildError(
            f"builder Python must be exact {EXPECTED_PYTHON}, got {tuple(sys.version_info[:3])}"
        )
    if platform.architecture()[0] != "64bit":
        raise PortableBuildError("portable runtime requires 64-bit CPython")
    runtime.mkdir(parents=True)
    for name in RUNTIME_ROOT_FILES:
        source = python_home / name
        if not source.is_file():
            raise PortableBuildError(f"curated CPython runtime file is missing: {source}")
        shutil.copy2(source, runtime / name)

    dll_source = python_home / "DLLs"
    dll_target = runtime / "DLLs"
    dll_target.mkdir()
    for source in sorted(dll_source.iterdir(), key=lambda item: item.name.casefold()):
        if source.is_file() and source.suffix.casefold() in {".dll", ".pyd"}:
            if source.name.casefold().startswith("_cffi_backend"):
                raise PortableBuildError(
                    f"curated CPython runtime contains forbidden cffi backend: {source}"
                )
            shutil.copy2(source, dll_target / source.name)

    lib_source = python_home / "Lib"
    lib_target = runtime / "Lib"

    def lib_ignore(directory: str, names: list[str]) -> set[str]:
        ignored = _ignore(directory, names)
        if Path(directory).resolve() == lib_source.resolve():
            ignored.update({"site-packages", "ensurepip", "idlelib", "test", "turtledemo", "venv"})
        return ignored

    shutil.copytree(lib_source, lib_target, ignore=lib_ignore)
    def tcl_ignore(directory: str, names: list[str]) -> set[str]:
        ignored = _ignore(directory, names)
        ignored.update(
            name
            for name in names
            if Path(name).suffix.casefold() in {".dll", ".exe", ".pyd"}
        )
        return ignored

    shutil.copytree(python_home / "tcl", runtime / "tcl", ignore=tcl_ignore)


def _distribution_root(name: str, expected_version: str) -> tuple[Path, Path]:
    distribution = importlib.metadata.distribution(name)
    actual = distribution.version
    if actual != expected_version:
        raise PortableBuildError(
            f"distribution {name} must be exact {expected_version}, got {actual}"
        )
    metadata_path = Path(distribution._path).resolve()  # type: ignore[attr-defined]
    return metadata_path.parent, metadata_path


def _copy_third_party(site_packages: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    locations: set[Path] = set()
    for distribution_name, (version, package_names) in THIRD_PARTY.items():
        source_root, metadata_path = _distribution_root(distribution_name, version)
        locations.add(source_root)
        versions[distribution_name] = version
        for package_name in package_names:
            source = source_root / package_name
            target = site_packages / package_name
            if source.is_dir():
                _copy_tree(source, target, THIRD_PARTY_EXCLUDED_PATHS)
            elif source.is_file():
                shutil.copy2(source, target)
            else:
                raise PortableBuildError(
                    f"distribution {distribution_name} payload is missing: {source}"
                )
        shutil.copytree(metadata_path, site_packages / metadata_path.name, ignore=_ignore)
    if len(locations) != 1:
        raise PortableBuildError("third-party packages must come from one exact environment")
    return versions


def _copy_application(repo_root: Path, app_root: Path) -> list[Path]:
    application_sources = _portable_application_sources(repo_root)
    app_root.mkdir(parents=True)
    for name in APP_ROOT_FILES:
        shutil.copy2(repo_root / name, app_root / name)
    for name in APP_PACKAGE_DIRS:
        _copy_tree(repo_root / name, app_root / name)
    for name in APP_DATA_DIRS:
        _copy_tree(repo_root / name, app_root / name)
    for name in APP_DATA_FILES:
        source = repo_root / name
        if not source.is_file():
            raise PortableBuildError(f"application data file is missing: {source}")
        target = app_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    tools_target = app_root / "tools"
    tools_target.mkdir()
    tool_sources = _discover_portable_tool_sources(repo_root, initial_sources=application_sources)
    for source in tool_sources:
        relative = source.relative_to(repo_root / "tools")
        target = tools_target / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copy2(repo_root / "portable" / "main.py", app_root / "main.py")
    return tool_sources


def _assert_portable_import_closure(
    output: Path,
    repo_root: Path,
    tool_sources: Iterable[Path],
    python_executable: Path | None = None,
) -> None:
    modules = [
        "atomic_replace",
        "runtime_entry",
        "runtime_instance_win32",
        "tk_callback_result",
        "Container_Audit",
        "container_audit_product_host",
        "current_user_onboarding",
        "ca_screen_bridge",
        "webview",
        "clr_loader",
        "pythonnet",
    ]
    modules.extend(
        "tools."
        + ".".join(source.relative_to(repo_root / "tools").with_suffix("").parts)
        for source in tool_sources
    )
    code = (
        "import importlib,json,os,sys;"
        "app=sys.argv[1];"
        "sys.path[:0]=[app,os.path.join(app,'site-packages')];"
        "[importlib.import_module(name) for name in json.loads(sys.argv[2])]"
    )
    environment = os.environ.copy()
    environment["KMTECH_TEST_SILENT_AUDIO"] = "1"
    completed = subprocess.run(
        [
            str(python_executable or output / "runtime" / "python.exe"),
            "-I",
            "-B",
            "-c",
            code,
            str(output / "app"),
            json.dumps(sorted(set(modules), key=str.casefold)),
        ],
        cwd=output,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no diagnostic").strip()
        raise PortableBuildError(
            "portable runtime import closure failed: " + detail[-1000:]
        )


def _is_pe(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size < 2:
        return False
    with path.open("rb") as handle:
        return handle.read(2) == b"MZ"


def _app_native_inventory(app_root: Path) -> list[str]:
    native = sorted(
        path.relative_to(app_root).as_posix()
        for path in app_root.rglob("*")
        if _is_pe(path)
    )
    mismatched = [
        path for path in native
        if path not in APP_NATIVE_ALLOWLIST
        or (app_root / path).stat().st_size != APP_NATIVE_ALLOWLIST[path][0]
        or _sha256(app_root / path) != APP_NATIVE_ALLOWLIST[path][1]
    ]
    if mismatched or set(native) != set(APP_NATIVE_ALLOWLIST):
        raise PortableBuildError(
            "portable app native closure must be exactly the pinned allowlist: "
            + ", ".join(sorted(set(mismatched) | (set(native) ^ set(APP_NATIVE_ALLOWLIST))))
        )
    return native


INSTALLER_UNSIGNED_PIN = re.compile(r"'(site-packages/[^']+)' = '([0-9a-f]{64})'")


def _assert_installer_unsigned_pins(output: Path, app_root: Path) -> None:
    expected = {path: APP_NATIVE_ALLOWLIST[path][1] for path in APP_NATIVE_UNSIGNED}
    actual = {path: _sha256(app_root / path) for path in APP_NATIVE_UNSIGNED if (app_root / path).is_file()}
    if actual != expected:
        raise PortableBuildError("packet unsigned natives differ from the builder pins")
    for name in ("INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1", "tools/apply_prepared_update.ps1"):
        rows = INSTALLER_UNSIGNED_PIN.findall((output / name).read_text(encoding="utf-8-sig"))
        if dict(rows) != expected or any(expected.get(path) != sha for path, sha in rows):
            raise PortableBuildError(f"{name} unsigned native pins differ from the builder pins")


def _build_environment(repo_root: Path) -> dict[str, object]:
    lock = repo_root / BUILD_ENVIRONMENT_LOCK
    pins = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        requirement = line.split("--hash", 1)[0].strip()
        if requirement and not requirement.startswith("#"):
            name, _, version = requirement.partition("==")
            pins[name] = version
    installed = {
        str(distribution.metadata["Name"]).replace("_", "-").lower(): distribution.version
        for distribution in importlib.metadata.distributions()
    }
    if installed != pins:
        extra = sorted(set(installed) - set(pins))
        missing = sorted(set(pins) - set(installed))
        changed = sorted(name for name in set(pins) & set(installed) if pins[name] != installed[name])
        raise PortableBuildError(
            f"builder environment must be exactly {BUILD_ENVIRONMENT_LOCK}: "
            f"extra={extra} missing={missing} changed={changed}"
        )
    for name, (version, _packages) in THIRD_PARTY.items():
        if pins.get(name.replace("_", "-").lower()) != version:
            raise PortableBuildError(f"THIRD_PARTY {name} is not in {BUILD_ENVIRONMENT_LOCK}")
    return {
        "build_python_sha256": _sha256(Path(getattr(sys, "_base_executable", sys.executable))),
        "build_venv_python_sha256": _sha256(Path(sys.executable)),
        "build_requirements_lock": BUILD_ENVIRONMENT_LOCK,
        "build_requirements_lock_sha256": _sha256(lock),
        "build_distribution_count": len(installed),
        "native_allowlist_source_sha256": NATIVE_ALLOWLIST_SOURCE_SHA256,
    }


def _git_bytes(repo_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-c", "core.autocrlf=false", *arguments], cwd=repo_root,
        capture_output=True, timeout=30, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode:
        raise PortableBuildError("committed shell source is unavailable")
    return completed.stdout


def _assert_screen_bundle(repo_root: Path, app_root: Path) -> dict[str, object]:
    ready_path = "shell/SHELL-READY-v3.16.json"
    ready_bytes = (app_root / ready_path).read_bytes()
    if hashlib.sha256(ready_bytes).hexdigest() != SHELL_KIT_READY_SHA256:
        raise PortableBuildError("packet shell READY differs from the v3.16.3 pin")
    ready = json.loads(ready_bytes)
    if ready.get("version") != SHELL_KIT_READY_VERSION:
        raise PortableBuildError("packet shell version differs from the v3.16.3 pin")
    committed = _git_bytes(repo_root, "ls-tree", "-r", "--name-only", SHELL_BRIDGE_SOURCE_COMMIT, "--", "shell").decode().splitlines()
    installed_rows = []
    for row in ready["files"]:
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "shell-v3.16.3":
            raise PortableBuildError("packet shell READY path is outside its accepted source")
        installed_rows.append(("shell/" + Path(*relative.parts[1:]).as_posix(), row))
    expected = {name for name, _ in installed_rows} | {ready_path}
    actual = {path.relative_to(app_root).as_posix() for path in (app_root / "shell").rglob("*") if path.is_file()}
    if set(committed) != expected or actual != expected:
        raise PortableBuildError("packet shell file set differs from the accepted bridge")
    for name, row in installed_rows:
        path = app_root / name
        if path.stat().st_size != row["bytes"] or _sha256(path) != row["sha256"]:
            raise PortableBuildError("packet shell file differs from READY: " + row["path"])
    for name in committed:
        if (app_root / name).read_bytes() != _git_bytes(repo_root, "show", SHELL_BRIDGE_SOURCE_COMMIT + ":" + name):
            raise PortableBuildError("packet shell differs from the accepted bridge: " + name)
    ui_manifest_path = app_root / "ui/MANIFEST.json"
    if ui_manifest_path.read_bytes() != (repo_root / "ui/MANIFEST.json").read_bytes():
        raise PortableBuildError("packet UI manifest differs from source")
    ui_manifest = json.loads(ui_manifest_path.read_bytes())
    if ui_manifest.get("app") != "ca" or ui_manifest.get("commit") != "97efc8e733ba8d73c3d4c8d8a486cad5c3d8d531":
        raise PortableBuildError("packet UI differs from the accepted export")
    for row in ui_manifest["files"]:
        name = Path(row["path"])
        if name.is_absolute() or ".." in name.parts:
            raise PortableBuildError("UI manifest path is outside its bundle")
        path = app_root / "ui" / name
        if path.stat().st_size != row["bytes"] or _sha256(path) != row["sha256"]:
            raise PortableBuildError("packet UI file differs from manifest: " + name.as_posix())
    return {
        "shell_kit_ready_version": SHELL_KIT_READY_VERSION,
        "shell_kit_ready_sha256": SHELL_KIT_READY_SHA256,
        "shell_bridge_source_commit": SHELL_BRIDGE_SOURCE_COMMIT,
        "shell_file_count": len(committed),
        "shell_ready_match": "PASS",
        "ui_source_commit": ui_manifest["commit"],
        "ui_manifest_sha256": _sha256(ui_manifest_path),
        "ui_manifest_file_count": len(ui_manifest["files"]),
    }


def _forbidden_dependency_paths(root: Path) -> list[str]:
    forbidden: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        components = {part.casefold() for part in relative.parts}
        if components & {item.casefold() for item in FORBIDDEN_PACKAGE_NAMES}:
            forbidden.append(relative.as_posix())
    return sorted(forbidden)


def _update_public_key_config(value: str) -> str | dict[str, object]:
    text = str(value or "").strip()
    if not text:
        raise PortableBuildError("portable build requires an update public key config")
    try:
        validate_public_key_config(text)
    except ValueError as exc:
        raise PortableBuildError("portable update public key config is invalid") from exc
    if len(text) == 64 and all(character in "0123456789abcdefABCDEF" for character in text):
        return text.lower()
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PortableBuildError("portable update public key config is malformed") from exc
    if not isinstance(document, dict):
        raise PortableBuildError("portable update public key config must be an object")
    return document


def _write_update_key_config(app_root: Path, value: str) -> str:
    configured = _update_public_key_config(value)
    payload = {
        "schema": UPDATE_KEY_CONFIG_SCHEMA,
        "manifest_public_key": configured,
    }
    raw = (
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    path = app_root / UPDATE_KEY_CONFIG_FILENAME
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _tree_metrics(root: Path) -> tuple[int, int]:
    files = [path for path in root.rglob("*") if path.is_file()]
    return len(files), sum(path.stat().st_size for path in files)


def _write_runtime_file_inventory(output: Path) -> dict:
    inventory = {
        "schema": RUNTIME_FILE_INVENTORY_SCHEMA,
        "files": [
            {"path": path.relative_to(output).as_posix(), "sha256": _sha256(path)}
            for path in sorted((output / "runtime").rglob("*")) if path.is_file()
        ],
    }
    raw = (json.dumps(inventory, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > DEFAULT_MAX_RUNTIME_FILE_INVENTORY_BYTES:
        raise PortableBuildError("runtime file inventory exceeds its reader bound")
    (output / RUNTIME_FILE_INVENTORY_FILENAME).write_bytes(raw)
    return {"runtime_file_inventory_sha256": hashlib.sha256(raw).hexdigest(),
            "runtime_file_inventory_bytes": len(raw)}


def _git_value(repo_root: Path, expression: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "rev-parse", "--verify", expression],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise PortableBuildError(f"git identity is unavailable: {expression}")
    return completed.stdout.strip().lower()


def _assert_clean_source(repo_root: Path) -> None:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise PortableBuildError("git source cleanliness could not be verified")
    if completed.stdout.strip():
        raise PortableBuildError("portable source tree must be clean and committed")


def _assert_writer_sink_inventory(repo_root: Path) -> dict[str, object]:
    snapshot_path = repo_root / "tools" / "container_writer_sink_inventory.json"
    if not snapshot_path.is_file():
        raise PortableBuildError("writer sink inventory snapshot is missing")
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PortableBuildError("writer sink inventory snapshot is invalid") from exc
    derived = _derive_writer_inventory(repo_root)
    if snapshot != derived or snapshot_path.read_bytes() != _writer_inventory_json_bytes(derived):
        raise PortableBuildError("writer sink inventory is stale")
    if (
        derived.get("schema_version") != "container-audit-writer-sink-inventory-v8"
        or derived.get("uncovered_direct_mutation_functions") != []
        or derived.get("caller_fence_reference_failures") != []
        or derived.get("powershell_guard_failures") != []
        or not isinstance(derived.get("inventory_sha256"), str)
    ):
        raise PortableBuildError("writer sink inventory is not release-admissible")
    route_rows = derived.get("known_route_coverage")
    if (
        not isinstance(route_rows, list)
        or not route_rows
        or any(not isinstance(row, dict) or row.get("pass") is not True for row in route_rows)
    ):
        raise PortableBuildError("known writer route coverage is not release-admissible")
    return derived


def _release_data_metadata(repo_root: Path, compatible_min_version: str | None) -> dict[str, str]:
    from kmtech_shared.data_generation import DataGenerationError, version_key
    from tools.check_release_version import read_current_version

    try:
        version = version_key(read_current_version(repo_root / "Container_Audit.py"))
        floor = version_key(compatible_min_version) if compatible_min_version is not None else version
        if floor > version:
            raise DataGenerationError("compatibility floor exceeds release")
    except (ValueError, DataGenerationError) as exc:
        raise PortableBuildError("release data compatibility version is invalid") from exc
    return {"version": "v" + ".".join(map(str, version)),
            "data_compatible_min_version": "v" + ".".join(map(str, floor))}


RELEASE_AUTO_UPDATE_SETTINGS_SHA256 = "1b9372bd13d7b7ffc1d5e155cc1a984f12bea47453e1be0c9252e30ed3de5359"


def _release_auto_update_settings(path: Path | None) -> bytes:
    """Admit the approved field feed before creating any release output."""
    from auto_update import policy_from_settings

    if not isinstance(path, (str, os.PathLike)):
        raise PortableBuildError("RELEASE_AUTO_UPDATE_SETTINGS_REQUIRED")
    try:
        path = Path(path)
        if not path.is_file() or not 0 < path.stat().st_size <= 65536:
            raise ValueError
        raw = path.read_bytes()
        settings = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(settings, dict) or not settings:
            raise ValueError
        policy = policy_from_settings(settings)
        if (not isinstance(settings.get("feed_url"), str) or not settings["feed_url"].strip()
                or not settings["feed_url"].startswith("https://")
                or settings.get("channel") != "stable" or settings.get("profile_auth") is not True
                or not policy.get("feed_url") or policy.get("profile_auth") is not True):
            raise ValueError
        if hashlib.sha256(raw).hexdigest() != RELEASE_AUTO_UPDATE_SETTINGS_SHA256:
            raise ValueError
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise PortableBuildError("RELEASE_AUTO_UPDATE_SETTINGS_INVALID") from exc
    return raw


def _write_release_auto_update_settings(app_root: Path, raw: bytes) -> None:
    target = app_root / "auto-update-settings.json"
    target.write_bytes(raw)
    if target.read_bytes() != raw:
        raise PortableBuildError("RELEASE_AUTO_UPDATE_SETTINGS_READBACK_FAILED")


def build(
    repo_root: Path,
    python_home: Path,
    output: Path,
    *,
    update_manifest_public_key_config: str | None = None,
    data_compatible_min_version: str | None = None,
    data_generation_update_manifest: Path | None = None,
    data_generation_update_signature: Path | None = None,
    auto_update_settings: Path | None = None,
) -> dict[str, object]:
    startup_settings_bytes = _release_auto_update_settings(auto_update_settings)
    repo_root = repo_root.resolve()
    if update_manifest_public_key_config is None:
        public_configuration = json.loads((repo_root / UPDATE_KEY_CONFIG_FILENAME).read_text(encoding="utf-8"))
        if public_configuration.get("schema") != UPDATE_KEY_CONFIG_SCHEMA:
            raise PortableBuildError("committed update public key schema differs")
        update_manifest_public_key_config = json.dumps(public_configuration["manifest_public_key"], sort_keys=True)
    python_home = python_home.resolve()
    output = output.resolve()
    _assert_clean_source(repo_root)
    shared_check = subprocess.run(
        [sys.executable, "-I", "-B", str(repo_root / "qualification/check_kmtech_shared.py"),
         "--check", "--root", str(repo_root)],
        capture_output=True, text=True, check=False, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if shared_check.returncode:
        raise PortableBuildError("shared source pin check failed: " + shared_check.stderr.strip())
    data_metadata = _release_data_metadata(repo_root, data_compatible_min_version)
    private_generation_manifest = None
    private_generation_signature = None
    if bool(data_generation_update_manifest) != bool(data_generation_update_signature):
        raise PortableBuildError("private compatibility manifest and signature are required together")
    if data_generation_update_manifest is not None:
        from data_generation_guard import verified_private_compatibility
        from kmtech_shared.data_generation import DataGenerationError

        try:
            if (data_generation_update_manifest.stat().st_size > 1024 * 1024
                    or data_generation_update_signature.stat().st_size != 64):
                raise ValueError("private compatibility proof size is invalid")
            private_generation_manifest = json.loads(data_generation_update_manifest.read_bytes())
            private_generation_signature = data_generation_update_signature.read_bytes()
            proof = verified_private_compatibility(
                private_generation_manifest, private_generation_signature,
                _update_public_key_config(update_manifest_public_key_config),
                version=data_metadata["version"], build_id=_git_value(repo_root, "HEAD^{commit}"),
            )
        except (OSError, ValueError, TypeError, DataGenerationError) as exc:
            raise PortableBuildError("private compatibility proof is invalid") from exc
        data_metadata["data_compatible_min_version"] = proof["data_compatible_min_version"]
    writer_inventory = _assert_writer_sink_inventory(repo_root)
    from auto_update import source_version_literal
    version = source_version_literal((repo_root / 'Container_Audit.py').read_bytes())
    build_environment = _build_environment(repo_root)
    if output.exists():
        raise PortableBuildError(f"portable output already exists: {output}")
    output.mkdir(parents=True)
    _runtime_source(python_home, output / "runtime")
    app_root = output / "app"
    tool_sources = _copy_application(repo_root, app_root)
    screen_bundle = _assert_screen_bundle(repo_root, app_root)
    if source_version_literal((app_root / 'Container_Audit.py').read_bytes()) != version:
        raise PortableBuildError('copied application version differs from source literal')
    update_key_config_sha256 = _write_update_key_config(
        app_root,
        update_manifest_public_key_config,
    )
    _write_release_auto_update_settings(app_root, startup_settings_bytes)
    site_packages = app_root / "site-packages"
    site_packages.mkdir()
    versions = _copy_third_party(site_packages)
    _assert_portable_import_closure(output, repo_root, tool_sources)
    shutil.copy2(
        repo_root / "portable" / "launch-container-audit.cmd",
        output / "launch-container-audit.cmd",
    )
    for source_relative, target_relative in PORTABLE_INSTALL_ASSETS:
        source = repo_root / source_relative
        target = output / target_relative
        if not source.is_file():
            raise PortableBuildError(
                f"portable install asset is missing: {source_relative}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    native = _app_native_inventory(app_root)
    _assert_installer_unsigned_pins(output, app_root)
    forbidden_paths = _forbidden_dependency_paths(output)
    if forbidden_paths:
        raise PortableBuildError(
            "forbidden dependencies entered the portable tree: " + ", ".join(forbidden_paths)
        )
    runtime_inventory_pin = _write_runtime_file_inventory(output)
    file_count, byte_count = _tree_metrics(output)
    manifest = {
        "schema": PORTABLE_SCHEMA,
        **data_metadata,
        "startup_update_protocol": 1,
        "relay_identity_protocol": 1,
        "startup_update_helper_sha256": _sha256(output / "tools/apply_prepared_update.ps1"),
        "source_commit": _git_value(repo_root, "HEAD^{commit}"),
        "source_tree": _git_value(repo_root, "HEAD^{tree}"),
        "python_version": ".".join(str(value) for value in EXPECTED_PYTHON),
        "python_home": str(python_home),
        "runtime_pythonw_sha256": _sha256(output / "runtime" / "pythonw.exe"),
        **runtime_inventory_pin,
        "entrypoint": "runtime/pythonw.exe app/main.py",
        "launcher": "launch-container-audit.cmd",
        "launcher_sha256": _sha256(output / "launch-container-audit.cmd"),
        "installer_sha256": _sha256(output / "INSTALL_CANONICAL_PORTABLE.ps1"),
        "helper_sha256": _sha256(output / "INSTALL_THIS_PC.ps1"),
        "integrity_helper_sha256": _sha256(
            output / "tools" / "bootstrap_integrity.ps1"
        ),
        "writer_fence_helper_path": "tools/container_writer_fence.ps1",
        "writer_fence_helper_sha256": _sha256(
            output / "tools" / "container_writer_fence.ps1"
        ),
        "writer_session_adapter_path": "tools/container_writer_session.ps1",
        "writer_session_adapter_sha256": _sha256(
            output / "tools" / "container_writer_session.ps1"
        ),
        "writer_session_contract_path": (
            "tools/container_writer_session_contract.json"
        ),
        "writer_session_contract_schema": (
            "container-audit-writer-session-cli-contract-v1"
        ),
        "writer_session_contract_sha256": _sha256(
            output / "tools" / "container_writer_session_contract.json"
        ),
        "writer_sink_inventory_path": "tools/container_writer_sink_inventory.json",
        "writer_sink_inventory_sha256": _sha256(
            output / "tools" / "container_writer_sink_inventory.json"
        ),
        "writer_sink_inventory_contract_sha256": writer_inventory[
            "inventory_sha256"
        ],
        "third_party_versions": versions,
        "build_environment": build_environment,
        **screen_bundle,
        "allowed_unsigned_app_pe": [path for path in native if path in APP_NATIVE_UNSIGNED],
        "update_key_config_sha256": update_key_config_sha256,
        "forbidden_dependency_paths": forbidden_paths,
        "file_count_before_manifest": file_count,
        "byte_count_before_manifest": byte_count,
    }
    if private_generation_manifest is not None:
        manifest["data_generation_signed_manifest"] = private_generation_manifest
        manifest["data_generation_signature_hex"] = private_generation_signature.hex()
    serialized_manifest = json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if len(serialized_manifest.encode("utf-8")) > 65536:
        raise PortableBuildError("portable generation metadata exceeds the runtime bound")
    (output / "portable-manifest.json").write_text(
        serialized_manifest,
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python-home", type=Path, default=Path(sys.base_prefix))
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--update-manifest-public-key-config")
    parser.add_argument("--data-compatible-min-version", help="Release data floor; portable installers still require a verified signed binding before trusting a lower floor")
    parser.add_argument("--data-generation-update-manifest", type=Path)
    parser.add_argument("--data-generation-update-signature", type=Path)
    parser.add_argument("--auto-update-settings", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    result = build(
        args.repo_root,
        args.python_home,
        args.output,
        update_manifest_public_key_config=args.update_manifest_public_key_config,
        data_compatible_min_version=args.data_compatible_min_version,
        data_generation_update_manifest=args.data_generation_update_manifest,
        data_generation_update_signature=args.data_generation_update_signature,
        auto_update_settings=args.auto_update_settings,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
