import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import native_audio
from tools.stage_pure_python_charset_normalizer import stage


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "kmtech_zero_pe"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    assert loaded["cryptography"]
    assert loaded["cffi"] == []


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
    assert "hiddenimports: list[str] = []" in hook
