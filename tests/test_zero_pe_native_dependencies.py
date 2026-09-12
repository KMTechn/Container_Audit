import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace
import zlib

import native_audio
import pytest
from tools import build_portable_release_candidate as portable_builder
from tools.stage_pure_python_charset_normalizer import stage
from tools import stage_pure_python_charset_normalizer as staging
from tests.native_process_fixtures import native_argument_recorder
from tests.powershell_contracts import run_functions
from tests.spec_contracts import evaluate_spec
from vendor.kmtech_zero_pe.raster import RasterError, RasterImage


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "kmtech_zero_pe"
FORBIDDEN_ROOTS = {
    "PIL",
    "_cffi_backend",
    "cffi",
    "charset_normalizer",
    "cryptography",
    "pygame",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _portable_production_imports(roots: set[str]) -> list[tuple[str, str]]:
    paths = list(ROOT.glob("*.py"))
    for package in portable_builder.APP_PACKAGE_DIRS:
        paths.extend((ROOT / package).rglob("*.py"))
    paths.extend(portable_builder._discover_portable_tool_sources(ROOT))
    matches: list[tuple[str, str]] = []
    for path in sorted(paths):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                if name.split(".", 1)[0] in roots:
                    matches.append((path.relative_to(ROOT).as_posix(), name))
    return matches


def test_rendering_vendor_records_exact_local_patch_and_upstream_provenance():
    manifest = json.loads((VENDOR / "RENDER_VENDOR.json").read_text(encoding="utf-8"))
    assert manifest["source_artifact"] == "E:/KMTech/autoloop-20260824/seq259-zero-pe-contract"
    assert manifest["local_modifications"]["raster.py"]["upstream_sha256"] == (
        "1296fc461e349cc02c1379b09096559203d2ec22cdc27c780958a05006d97c48"
    )
    assert _sha256(VENDOR / "raster.py") == (
        "83abc51557547c2d23e136ec91b281ce66c8ef71a19f52fb3d1d8aa6723c74c0"
    )
    assert _sha256(VENDOR / "gdi_print.py") == (
        "48453e70a4bdd2008c2e4565bf647a852f319322458f9dc5a094a064274faece"
    )
    assert manifest["files"] == {
        "gdi_print.py": _sha256(VENDOR / "gdi_print.py"),
        "raster.py": _sha256(VENDOR / "raster.py"),
    }


def _png_from_scanlines(color_type, scanlines):
    def chunk(kind, payload):
        return (
            struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 3, 2, 8, color_type, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanlines))
        + chunk(b"IEND", b"")
    )


def _filtered_scanline(raw, previous, channels, filter_kind):
    encoded = bytearray([filter_kind])
    for index, value in enumerate(raw):
        left = raw[index - channels] if index >= channels else 0
        above = previous[index]
        corner = previous[index - channels] if index >= channels else 0
        if filter_kind == 1:
            predictor = left
        elif filter_kind == 2:
            predictor = above
        elif filter_kind == 3:
            predictor = (left + above) // 2
        elif filter_kind == 4:
            estimate = left + above - corner
            predictor = min(
                enumerate((left, above, corner)),
                key=lambda candidate: (abs(estimate - candidate[1]), candidate[0]),
            )[1]
        else:
            predictor = 0
        encoded.append((value - predictor) & 255)
    return bytes(encoded)


@pytest.mark.parametrize("color_type,channels", [(2, 3), (6, 4)])
@pytest.mark.parametrize("filter_kind", range(5))
def test_raster_png_decodes_exact_colors_alpha_and_previous_row(color_type, channels, filter_kind):
    pixels = [
        (10, 20, 30, 0), (80, 90, 100, 1), (255, 0, 77, 128),
        (11, 22, 33, 254), (99, 10, 110, 255), (0, 255, 17, 64),
    ]
    first = bytes(channel for pixel in pixels[:3] for channel in pixel[:channels])
    second = bytes(channel for pixel in pixels[3:] for channel in pixel[:channels])
    # The first raw row exercises the tray-asset path; the next row exercises
    # each supported filter against that reconstructed previous row.
    scanlines = b"\0" + first + _filtered_scanline(second, first, channels, filter_kind)
    image = RasterImage.from_png_bytes(_png_from_scanlines(color_type, scanlines))
    expected = bytes(
        channel for red, green, blue, alpha in pixels
        for channel in (blue, green, red, alpha if channels == 4 else 255)
    )
    assert (image.width, image.height, image.bgra) == (3, 2, expected)


@pytest.mark.parametrize("name,width,height,expected", [
    ("HMC_LHD_RHD.png", 174, 64, "15318da1832bee28c679a08d257c5f622737b04f65afd84dc1312b8636807be5"),
    ("KMC_LHD.png", 792, 291, "ba43d304b8b5960f01aabe10f4a183a8a17ecfbafd05c8228d8ce2e1f7e43e95"),
    ("KMC_RHD.png", 174, 64, "975a1fc9b96ec4335c132cb8fc5a6e1d4894dd48c9070068d64d9bc8faedd525"),
    ("logo.png", 1024, 720, "ff90839d31c021d0180720fea2793af42f1eff4b54685b6d1903f20534f5ed23"),
])
def test_raster_png_preserves_original_asset_pixels(name, width, height, expected):
    # Goldens independently decoded with the already-installed host Pillow;
    # this test and the shipped renderer do not depend on Pillow.
    image = RasterImage.from_png(ROOT / "assets" / name)
    assert (image.width, image.height) == (width, height)
    assert hashlib.sha256(image.bgra).hexdigest() == expected


@pytest.mark.parametrize("failure", ["crc", "filter", "scanline_length", "trailing", "color_type"])
def test_raster_png_keeps_validation_before_returning_pixels(failure):
    rows = b"\0" + bytes(range(12)) + b"\0" + bytes(range(12, 24))
    if failure == "filter":
        rows = rows[:13] + b"\5" + rows[14:]
    elif failure == "scanline_length":
        rows = rows[:-1]
    png = _png_from_scanlines(0 if failure == "color_type" else 6, rows)
    if failure == "crc":
        png = png[:29] + bytes([png[29] ^ 1]) + png[30:]
    elif failure == "trailing":
        png += b"extra"
    with pytest.raises(RasterError):
        RasterImage.from_png_bytes(png)


def test_tray_image_display_tracks_asset_item_size_visibility_and_errors(tmp_path, monkeypatch):
    import Container_Audit as application

    first = tmp_path / "first.png"
    second = tmp_path / "second.png"
    first.write_bytes(RasterImage.solid(4, 2, (255, 0, 0)).to_png_bytes())
    second.write_bytes(RasterImage.solid(2, 4, (0, 0, 255)).to_png_bytes())
    catalog = {"first": {"Tray Image": str(first)}, "second": {"Tray Image": str(second)}}
    bounds = {"width": 60, "height": 200}
    visible = {"value": True}
    options = {}
    label = SimpleNamespace(
        master=SimpleNamespace(winfo_width=lambda: bounds["width"]),
        winfo_exists=lambda: True, config=lambda **values: options.update(values), image=None,
    )
    app = SimpleNamespace(
        tray_image_label=label,
        left_pane=SimpleNamespace(winfo_height=lambda: bounds["height"]),
        show_tray_image_var=SimpleNamespace(get=lambda: visible["value"]),
        current_tray=SimpleNamespace(item_code="first"),
        _item_catalog=lambda: SimpleNamespace(find_by_code=lambda code: catalog.get(code)),
        _apply_left_sidebar_layout=lambda: None, _schedule_focus_return=lambda: None,
        COLOR_DANGER="danger", COLOR_TEXT_SUBTLE="subtle",
    )
    app._clear_tray_image_label = lambda text="", foreground=None: application.ContainerAudit._clear_tray_image_label(app, text, foreground)
    monkeypatch.setattr(
        RasterImage, "to_tk_photo_image",
        lambda image, *, master: SimpleNamespace(width=image.width, height=image.height, bgra=image.bgra),
    )
    update = lambda: application.ContainerAudit._update_tray_image_display(app)

    update()
    assert (label.image.width, label.image.height) == (40, 20)
    assert label.image.bgra == bytes((0, 0, 255, 255)) * (40 * 20)
    update()  # Repeated use must keep the same correct pixels.
    assert label.image.bgra == bytes((0, 0, 255, 255)) * (40 * 20)
    bounds["width"] = 80
    update()
    assert (label.image.width, label.image.height) == (60, 30)

    first.write_bytes(RasterImage.solid(4, 2, (0, 255, 0)).to_png_bytes())
    update()  # Replacement at the same item and asset path must be observed.
    assert label.image.bgra == bytes((0, 255, 0, 255)) * (60 * 30)
    app.current_tray.item_code = "second"
    update()
    assert (label.image.width, label.image.height) == (30, 60)
    assert label.image.bgra == bytes((255, 0, 0, 255)) * (30 * 60)

    visible["value"] = False
    update()
    assert label.image is None and options["image"] == "" and options["text"] == ""
    visible["value"] = True
    update()
    assert label.image.bgra == bytes((255, 0, 0, 255)) * (30 * 60)
    catalog["second"]["Tray Image"] = str(tmp_path / "missing.png")
    update()
    assert label.image is None and options["image"] == ""
    assert options["text"].startswith("이미지 오류:") and options["foreground"] == "danger"
    app.current_tray.item_code = "unregistered"
    update()
    assert label.image is None and "등록되지 않았습니다" in options["text"]
    app.current_tray.item_code = ""
    update()
    assert label.image is None and "현품표를 먼저" in options["text"]


def test_runtime_dependencies_remove_pillow_and_pygame():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").casefold()
    application = (ROOT / "Container_Audit.py").read_text(encoding="utf-8")
    label = (ROOT / "phs_label_workflow.py").read_text(encoding="utf-8")

    assert "pillow" not in requirements
    assert "pygame" not in requirements
    assert "chardet" in requirements
    assert "from PIL" not in application
    assert "import PIL" not in application
    assert "pygame" not in application
    assert "from PIL" not in label
    assert "import PIL" not in label


def test_portable_production_imports_have_no_native_crypto_or_removed_ui_packages():
    assert _portable_production_imports(FORBIDDEN_ROOTS) == []
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").casefold()
    for forbidden in ("cffi", "cryptography", "pillow", "pygame"):
        assert forbidden not in requirements


def test_source_only_charset_normalizer_stage_has_no_pe(tmp_path, monkeypatch):
    source = tmp_path / 'owned installed package'
    source.mkdir()
    expected = ['__init__.py', 'api.py', 'md.py', 'nested/helper.py', 'py.typed']
    for name in expected + ['native.pyd', 'nested/accelerator.dll', 'tool.exe', '__pycache__/api.pyc']:
        file = source / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(('fixture:' + name).encode())
    monkeypatch.setattr(staging, 'importlib', SimpleNamespace(
        util=SimpleNamespace(find_spec=lambda name: SimpleNamespace(submodule_search_locations=[str(source)])),
        metadata=SimpleNamespace(version=lambda name: 'owned-fixture-version'),
    ))
    output_root = tmp_path / "pure-python-overrides"
    report = stage(output_root)

    package = output_root / "charset_normalizer"
    assert (package / "__init__.py").is_file()
    assert (package / "api.py").is_file()
    assert (package / "md.py").is_file()
    assert report["native_files"] == []
    assert report['version'] == 'owned-fixture-version'
    assert report['files'] == sorted(expected)
    assert all((package / name).read_bytes() == (source / name).read_bytes() for name in expected)
    assert not [
        path
        for path in output_root.rglob("*")
        if path.is_file() and path.suffix.casefold() in {".dll", ".exe", ".pyd"}
    ]


def test_container_import_loads_chardet_without_forbidden_modules(tmp_path):
    script = r'''
import json
import sys
import Container_Audit
import requests.compat

forbidden = sorted(
    name for name in sys.modules
    if name == "PIL" or name.startswith("PIL.")
    or name == "pygame" or name.startswith("pygame.")
    or name == "charset_normalizer" or name.startswith("charset_normalizer.")
)
print(json.dumps({"forbidden": forbidden, "detector": requests.compat.chardet.__name__}))
'''
    environment = os.environ.copy()
    environment["KMTECH_TEST_SILENT_AUDIO"] = "1"
    module_report = tmp_path / "module-report.json"
    environment["KMTECH_ZERO_PE_MODULE_REPORT"] = str(module_report)
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {"forbidden": [], "detector": "chardet"}
    loaded = json.loads(module_report.read_text(encoding="utf-8"))["loaded"]
    assert loaded["PIL"] == []
    assert loaded["pygame"] == []
    assert loaded["charset_normalizer"] == []
    assert loaded["cryptography"] == []
    assert loaded["cffi"] == []
    assert loaded["_cffi_backend"] == []


def test_wav_sound_uses_async_winsound_flags(monkeypatch, tmp_path):
    calls = []

    class FakeWinsound:
        SND_FILENAME = 1
        SND_ASYNC = 2
        SND_NODEFAULT = 4
        SND_LOOP = 8

        @staticmethod
        def PlaySound(path, flags):
            calls.append((path, flags))

    wav = tmp_path / "signal.wav"
    wav.write_bytes(b"RIFF")
    monkeypatch.setattr(native_audio, "_winsound", FakeWinsound)
    sound = native_audio.WavSound(wav)

    sound.play()
    sound.play(loops=-1)
    sound.stop()

    assert calls == [
        (str(wav.resolve()), 1 | 2 | 4),
        (str(wav.resolve()), 1 | 2 | 4 | 8),
        (None, 0),
    ]


def test_frozen_analysis_configuration_excludes_native_packages(tmp_path, monkeypatch):
    override = tmp_path / 'pure-python-source-override'
    monkeypatch.setenv('KMTECH_PURE_PYTHON_OVERRIDE', str(override))
    configured = evaluate_spec(ROOT / 'Container_Audit.spec')['analysis']
    assert configured['pathex'] == [str(override)]
    assert {'PIL', 'pygame', '_brotli', 'bcrypt', 'numpy', 'psutil', 'rpds', 'win32',
            'yaml', '_cffi_backend', 'cffi', 'cryptography', 'charset_normalizer.md__mypyc'} <= set(configured['excludes'])
    hook = runpy.run_path(str(ROOT / 'tools/pyinstaller_hooks/hook-charset_normalizer.py'))
    assert hook['hiddenimports'] == []


@pytest.mark.parametrize('forbidden', ['pygame/base.py', 'PIL/core.py', 'charset_normalizer/md.pyd',
                                       'numpy/core.pyd', 'nested/_brotli.pyd'])
def test_frozen_package_guard_rejects_actual_forbidden_files(tmp_path, forbidden):
    package = tmp_path / 'package'
    package.mkdir()
    (package / 'stdlib.py').write_text('# ordinary pure Python')
    result = run_functions(tmp_path, ROOT / 'tools/build_frozen_release_candidate.ps1', ['Assert-LowRiskNativeFreePackage'],
                           'Assert-LowRiskNativeFreePackage -Root $env:CA_PACKAGE_ROOT | ConvertTo-Json -Compress',
                           values={'CA_PACKAGE_ROOT': str(package)}, engine='pwsh')
    assert result.returncode == 0, result.stderr[-1600:]
    assert json.loads(result.stdout)['unused_optional_native_paths'] == []
    path = package / forbidden
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'owned forbidden artifact')
    result = run_functions(tmp_path, ROOT / 'tools/build_frozen_release_candidate.ps1', ['Assert-LowRiskNativeFreePackage'],
                           'Assert-LowRiskNativeFreePackage -Root $env:CA_PACKAGE_ROOT',
                           values={'CA_PACKAGE_ROOT': str(package)}, engine='pwsh')
    assert result.returncode != 0
    assert 'native dependency removal failed' in result.stderr
    assert forbidden in result.stderr


def test_portable_builder_requires_empty_native_closure_and_curated_tools():
    assert portable_builder.EXPECTED_PYTHON == (3, 12, 10)
    assert portable_builder.ALLOWED_APP_NATIVE_NAMES == set()
    assert "config" not in portable_builder.APP_DATA_DIRS
    assert "config/container_audit_settings.json" in portable_builder.APP_DATA_FILES
    assert portable_builder.EXTERNAL_TOOL_MODULES == ()
    tool_sources = portable_builder._discover_portable_tool_sources(ROOT)
    assert {path.relative_to(ROOT).as_posix() for path in tool_sources} == {
        "tools/direct_sync_relay_runner.py",
        "tools/install_logistics_runtime_profile.py",
        "tools/register_container_audit_worker_pc.py",
    }
    assert set(portable_builder.PORTABLE_INSTALL_ASSETS) == {
        ("INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_CANONICAL_PORTABLE.ps1"),
        ("INSTALL_THIS_PC.ps1", "INSTALL_THIS_PC.ps1"),
        ("tools/bootstrap_integrity.ps1", "tools/bootstrap_integrity.ps1"),
        ("tools/container_writer_fence.ps1", "tools/container_writer_fence.ps1"),
        ("tools/container_writer_session.ps1", "tools/container_writer_session.ps1"),
        (
            "tools/container_writer_session_contract.json",
            "tools/container_writer_session_contract.json",
        ),
        (
            "tools/container_writer_sink_inventory.json",
            "tools/container_writer_sink_inventory.json",
        ),
    }
    for forbidden in ("cffi", "cryptography", "pillow", "pygame", "pycparser"):
        assert forbidden not in portable_builder.THIRD_PARTY


def test_portable_manifest_preserves_existing_application_file_set(tmp_path):
    # The old builder shipped every root Python file. Keep that migration
    # baseline independent of APP_ROOT_FILES so an omission cannot self-validate.
    expected = {path.name: path for path in ROOT.glob("*.py")}
    for directory in ("kmtech_factory_contracts", "kmtech_shared", "vendor", "assets"):
        for source in (ROOT / directory).rglob("*"):
            if (source.is_file() and "__pycache__" not in source.parts
                    and source.suffix not in {".pyc", ".pyo"}):
                expected[source.relative_to(ROOT).as_posix()] = source
    for name in (
        "contract.lock.json", "kmtech_shared.manifest.json", "kmtech_shared.lock.json",
        "config/container_audit_settings.json",
        "config/validator_settings.json", "tools/direct_sync_relay_runner.py",
        "tools/install_logistics_runtime_profile.py",
        "tools/register_container_audit_worker_pc.py",
    ):
        expected[name] = ROOT / name
    expected["main.py"] = ROOT / "portable" / "main.py"

    app_root = tmp_path / "app"
    portable_builder._copy_application(ROOT, app_root)
    actual = {path.relative_to(app_root).as_posix(): path
              for path in app_root.rglob("*") if path.is_file()}
    assert actual.keys() == expected.keys()
    assert all(actual[name].read_bytes() == source.read_bytes()
               for name, source in expected.items())


def test_portable_tool_dependency_closure_is_recursive_and_fail_closed(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    entrypoint = tmp_path / "entrypoint.py"
    first = tools / "first.py"
    second = tools / "second.py"
    entrypoint.write_text("from tools import first\n", encoding="utf-8")
    first.write_text("from tools import second\n", encoding="utf-8")
    second.write_text("VALUE = 1\n", encoding="utf-8")

    discovered = portable_builder._discover_portable_tool_sources(
        tmp_path,
        initial_sources=[entrypoint],
        external_modules=(),
    )
    assert [path.name for path in discovered] == ["first.py", "second.py"]

    second.unlink()
    with pytest.raises(
        portable_builder.PortableBuildError,
        match="required portable tool module is missing: tools.second",
    ):
        portable_builder._discover_portable_tool_sources(
            tmp_path,
            initial_sources=[entrypoint],
            external_modules=(),
        )


def test_portable_packet_copies_and_imports_derived_tool_closure(
    monkeypatch,
    tmp_path,
):
    repo_root = tmp_path / "source"
    tools_root = repo_root / "tools"
    portable_root = repo_root / "portable"
    tools_root.mkdir(parents=True)
    portable_root.mkdir()
    for module_name in (
        "Container_Audit",
        "container_audit_product_host",
        "current_user_onboarding",
    ):
        (repo_root / f"{module_name}.py").write_text(
            "VALUE = 1\n",
            encoding="utf-8",
        )
    (repo_root / "entrypoint.py").write_text(
        "from tools import first\n",
        encoding="utf-8",
    )
    (portable_root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
    first = tools_root / "first.py"
    second = tools_root / "second.py"
    first.write_text("from tools import second\n", encoding="utf-8")
    second.write_text("VALUE = 1\n", encoding="utf-8")
    # An unrelated root script must neither ship nor add its tools dependency.
    (repo_root / "developer_only.py").write_text(
        "from tools import unshipped\n", encoding="utf-8",
    )
    monkeypatch.setattr(portable_builder, "APP_ROOT_FILES", (
        "Container_Audit.py", "container_audit_product_host.py",
        "current_user_onboarding.py", "entrypoint.py",
    ))
    monkeypatch.setattr(portable_builder, "APP_PACKAGE_DIRS", ())
    monkeypatch.setattr(portable_builder, "APP_DATA_DIRS", ())
    monkeypatch.setattr(portable_builder, "APP_DATA_FILES", ())

    output = tmp_path / "packet"
    app_root = output / "app"
    tool_sources = portable_builder._copy_application(repo_root, app_root)

    assert [path.name for path in tool_sources] == ["first.py", "second.py"]
    assert (app_root / "tools" / "first.py").is_file()
    assert (app_root / "tools" / "second.py").is_file()
    assert not (app_root / "developer_only.py").exists()
    portable_builder._assert_portable_import_closure(
        output,
        repo_root,
        tool_sources,
        python_executable=Path(sys.executable),
    )

    (app_root / "tools" / "second.py").unlink()
    with pytest.raises(
        portable_builder.PortableBuildError,
        match="portable runtime import closure failed",
    ):
        portable_builder._assert_portable_import_closure(
            output,
            repo_root,
            tool_sources,
            python_executable=Path(sys.executable),
        )
    assert list(output.rglob("__pycache__")) == []

    (repo_root / "entrypoint.py").unlink()
    with pytest.raises(
        portable_builder.PortableBuildError,
        match="required application module is missing: .*entrypoint.py",
    ):
        portable_builder._copy_application(repo_root, tmp_path / "incomplete")
    assert not (tmp_path / "incomplete").exists()


@pytest.mark.parametrize('exit_code', [0, 23])
def test_portable_launcher_uses_pythonw_source_entrypoint_without_focus(tmp_path, native_argument_recorder, exit_code):
    packet = tmp_path / 'portable with spaces 한글'
    (packet / 'runtime').mkdir(parents=True)
    (packet / 'app').mkdir()
    shutil.copy2(native_argument_recorder, packet / 'runtime/pythonw.exe')
    launcher = packet / 'launch-container-audit.cmd'
    shutil.copy2(ROOT / 'portable/launch-container-audit.cmd', launcher)
    receipt = tmp_path / 'launch-arguments.json'
    environment = dict(os.environ, CA_ARGUMENT_RECEIPT=str(receipt), CA_ARGUMENT_EXIT_CODE=str(exit_code))
    # Pass cmd its actual command text; list2cmdline would add backslash-escaped
    # quotes intended for a CRT executable, which cmd interprets differently.
    command = '"' + os.environ['COMSPEC'] + '" /d /s /c ""' + str(launcher) + '" --help "argument with spaces""'
    result = subprocess.run(command,
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert receipt.exists(), result.stderr[-1600:]
    assert json.loads(receipt.read_text()) == ['-I', '-B', str(packet / 'app/main.py'), '--help', 'argument with spaces']
    assert result.returncode == exit_code


def test_release_signature_vendor_is_byte_pinned():
    assert _sha256(VENDOR / "release_signature.py") == (
        "ac21e2bca45899cd1161d89d4d2b6261ccb624bef745f88f5357c402e151cf1e"
    )
