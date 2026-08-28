import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import native_audio
from tools import build_portable_release_candidate as portable_builder
from tools.stage_pure_python_charset_normalizer import stage


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
    paths.extend(ROOT / "tools" / name for name in portable_builder.APP_TOOL_FILES)
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


def test_seq259_rendering_vendor_is_byte_identical():
    manifest = json.loads((VENDOR / "RENDER_VENDOR.json").read_text(encoding="utf-8"))
    assert _sha256(VENDOR / "raster.py") == (
        "1296fc461e349cc02c1379b09096559203d2ec22cdc27c780958a05006d97c48"
    )
    assert _sha256(VENDOR / "gdi_print.py") == (
        "48453e70a4bdd2008c2e4565bf647a852f319322458f9dc5a094a064274faece"
    )
    assert manifest["files"] == {
        "gdi_print.py": _sha256(VENDOR / "gdi_print.py"),
        "raster.py": _sha256(VENDOR / "raster.py"),
    }


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


def test_source_only_charset_normalizer_stage_has_no_pe(tmp_path):
    output_root = tmp_path / "pure-python-overrides"
    report = stage(output_root)

    package = output_root / "charset_normalizer"
    assert (package / "__init__.py").is_file()
    assert (package / "api.py").is_file()
    assert (package / "md.py").is_file()
    assert report["native_files"] == []
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


def test_frozen_builder_enforces_native_free_analysis_and_package_guard():
    builder = (ROOT / "tools" / "build_frozen_release_candidate.ps1").read_text(
        encoding="utf-8"
    )
    spec = (ROOT / "Container_Audit.spec").read_text(encoding="utf-8")
    hook = (
        ROOT / "tools" / "pyinstaller_hooks" / "hook-charset_normalizer.py"
    ).read_text(encoding="utf-8")

    assert "stage_pure_python_charset_normalizer.py" in builder
    assert "Assert-LowRiskNativeFreePackage" in builder
    assert "pure-python-source-override" in builder
    assert '"--exclude-module", "PIL"' in builder
    assert '"--exclude-module", "pygame"' in builder
    for module_name in ("_brotli", "bcrypt", "numpy", "psutil", "rpds", "win32", "yaml"):
        assert f"'{module_name}'" in builder
        assert f"'{module_name}'" in spec
    assert "unused_optional_native_paths" in builder
    assert "KMTECH_PURE_PYTHON_OVERRIDE" in spec
    assert "charset_normalizer.md__mypyc" in spec
    for module_name in ("_cffi_backend", "cffi", "cryptography"):
        assert f"'{module_name}'" in spec
    assert "hiddenimports: list[str] = []" in hook


def test_portable_builder_requires_empty_native_closure_and_curated_tools():
    assert portable_builder.EXPECTED_PYTHON == (3, 12, 10)
    assert portable_builder.ALLOWED_APP_NATIVE_NAMES == set()
    assert "config" not in portable_builder.APP_DATA_DIRS
    assert "config/container_audit_settings.json" in portable_builder.APP_DATA_FILES
    assert set(portable_builder.APP_TOOL_FILES) == {
        "direct_sync_relay_runner.py",
        "install_logistics_runtime_profile.py",
        "register_container_audit_worker_pc.py",
    }
    for forbidden in ("cffi", "cryptography", "pillow", "pygame", "pycparser"):
        assert forbidden not in portable_builder.THIRD_PARTY


def test_portable_launcher_uses_pythonw_source_entrypoint_without_focus():
    launcher = (ROOT / "portable" / "launch-container-audit.cmd").read_text(
        encoding="utf-8"
    )
    assert "runtime\\pythonw.exe" in launcher
    assert " -I -B " in launcher
    assert "app\\main.py" in launcher
    assert "Container_Audit.exe" not in launcher
    assert "--focus" not in launcher


def test_release_signature_vendor_is_byte_pinned():
    assert _sha256(VENDOR / "release_signature.py") == (
        "ac21e2bca45899cd1161d89d4d2b6261ccb624bef745f88f5357c402e151cf1e"
    )
