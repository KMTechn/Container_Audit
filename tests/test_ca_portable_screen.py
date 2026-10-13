"""Headless packet checks: accepted shell/UI bytes and the new-screen route."""
import ast
import hashlib
from pathlib import Path

import pytest

from tools import build_portable_release_candidate as builder

ROOT = Path(__file__).resolve().parents[1]


def _function(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)


def assert_packet_screen_entry(app):
    for source, target in (("portable/main.py", "main.py"), ("Container_Audit.py", "Container_Audit.py"),
                           ("ca_screen_bridge.py", "ca_screen_bridge.py")):
        assert (app / target).read_bytes() == (ROOT / source).read_bytes()
    entry = ast.parse((app / "main.py").read_text(encoding="utf-8"))
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Name) and node.func.value.id == "application"
               and node.func.attr == "main" for node in ast.walk(_function(entry, "main")))
    product = ast.parse((app / "Container_Audit.py").read_text(encoding="utf-8"))
    assert any(isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "CA_NEW_SCREEN_ARGUMENT"
               for target in node.targets) and isinstance(node.value, ast.Constant) and node.value.value == "--new-screen"
               for node in product.body)
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_run_application_main"
               for node in ast.walk(_function(product, "main")))
    product_main = _function(product, "_run_application_main")
    route = next(node for node in ast.walk(product_main) if isinstance(node, ast.If)
                 and any(isinstance(item, ast.Name) and item.id == "CA_NEW_SCREEN_ARGUMENT" for item in ast.walk(node.test)))
    assert any(isinstance(node, ast.ImportFrom) and node.module == "ca_screen_bridge" for node in ast.walk(route))
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "screen_runner"
               for node in ast.walk(route))
    bridge = ast.parse((app / "ca_screen_bridge.py").read_text(encoding="utf-8"))
    call = next(node for node in ast.walk(_function(bridge, "screen_runner"))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run_app")
    keywords = {item.arg: item.value for item in call.keywords}
    assert isinstance(keywords["write_guard"], ast.Name) and keywords["write_guard"].id == "admission_write_guard"
    assert "on_force_exit" not in keywords or (
        isinstance(keywords["on_force_exit"], ast.Constant) and keywords["on_force_exit"].value is None)
    host_bytes = (app / "shell/host.py").read_bytes()
    host = ast.parse(host_bytes)
    run_app = _function(host, "run_app")
    defaults = dict(zip((arg.arg for arg in run_app.args.kwonlyargs), run_app.args.kw_defaults))
    assert isinstance(defaults["on_force_exit"], ast.Constant) and defaults["on_force_exit"].value is None
    assert "그래도 닫기".encode() in host_bytes
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"
               and node.func.attr == "_exit" for node in ast.walk(run_app))
    forced = next(node for node in ast.walk(run_app) if isinstance(node, ast.If)
                  and isinstance(node.test, ast.Attribute) and node.test.attr == "forced")
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "on_force_exit"
               for node in ast.walk(forced))
    choose = _function(host, "choose")
    assert any(isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is True
               and any(isinstance(target, ast.Attribute) and target.attr == "forced" for target in node.targets)
               for node in ast.walk(choose))


def test_packet_new_screen_and_forced_close_keep_the_accepted_shell(tmp_path):
    app = tmp_path / "app"
    builder._copy_application(ROOT, app)
    receipt = builder._assert_screen_bundle(ROOT, app)
    assert receipt["shell_ready_match"] == "PASS"
    assert receipt["shell_file_count"] == 20
    assert receipt["ui_manifest_file_count"] == 72
    assert_packet_screen_entry(app)
    (app / "shell/host.py").write_bytes(b"changed")
    with pytest.raises(builder.PortableBuildError):
        builder._assert_screen_bundle(ROOT, app)


def test_packet_ui_tamper_stops_the_build(tmp_path):
    app = tmp_path / "app"
    builder._copy_application(ROOT, app)
    (app / "ui/app/ca/ca.js").write_bytes(b"changed")
    with pytest.raises(builder.PortableBuildError):
        builder._assert_screen_bundle(ROOT, app)


@pytest.mark.parametrize("mutation", ["missing", "changed", "extra"])
def test_native_closure_refuses_any_change(tmp_path, monkeypatch, mutation):
    pins = {}
    for index, name in enumerate(builder.APP_NATIVE_ALLOWLIST):
        data = f"MZ synthetic native {index}".encode()
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        pins[name] = (len(data), hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(builder, "APP_NATIVE_ALLOWLIST", pins)
    assert set(builder._app_native_inventory(tmp_path)) == set(pins)
    path = tmp_path / next(iter(pins))
    if mutation == "missing":
        path.unlink()
    elif mutation == "changed":
        path.write_bytes(b"MZ changed")
    else:
        (tmp_path / "extra.dll").write_bytes(b"MZ extra")
    with pytest.raises(builder.PortableBuildError):
        builder._app_native_inventory(tmp_path)


@pytest.mark.parametrize("stale_asset", ["INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1", "tools/apply_prepared_update.ps1"])
def test_installer_builder_and_packet_unsigned_pins_must_agree(tmp_path, monkeypatch, stale_asset):
    app = tmp_path / "app"
    pins = {}
    for index, name in enumerate(sorted(builder.APP_NATIVE_UNSIGNED)):
        data = f"MZ synthetic native {index}".encode()
        path = app / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        pins[name] = (len(data), hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(builder, "APP_NATIVE_ALLOWLIST", {**builder.APP_NATIVE_ALLOWLIST, **pins})
    block = "".join(f"'{name}' = '{sha}'\n" for name, (_size, sha) in pins.items())
    for name in ("INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1", "tools/apply_prepared_update.ps1"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(block, encoding="utf-8-sig")
    builder._assert_installer_unsigned_pins(tmp_path, app)
    first = next(iter(pins))
    (tmp_path / stale_asset).write_text(block.replace(pins[first][1], "0" * 64), encoding="utf-8-sig")
    with pytest.raises(builder.PortableBuildError):
        builder._assert_installer_unsigned_pins(tmp_path, app)
    (tmp_path / stale_asset).write_text(block, encoding="utf-8-sig")
    (app / first).write_bytes(b"MZ changed")
    with pytest.raises(builder.PortableBuildError):
        builder._assert_installer_unsigned_pins(tmp_path, app)
