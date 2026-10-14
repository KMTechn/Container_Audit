"""Exercise the portable builder's copy paths without creating a release ZIP."""

import json
from pathlib import Path
import subprocess
import sys

from tools import build_portable_release_candidate as builder


def test_third_party_copy_omits_qrcode_tests_and_preserves_runtime(tmp_path, monkeypatch):
    version, packages = builder.THIRD_PARTY["qrcode"]
    source_root, metadata = builder._distribution_root("qrcode", version)
    source = source_root / "qrcode"
    assert (source / "tests").is_dir()
    monkeypatch.setattr(builder, "THIRD_PARTY", {"qrcode": (version, packages)})
    target = tmp_path / "packet" / "app" / "site-packages"
    target.mkdir(parents=True)

    assert builder._copy_third_party(target) == {"qrcode": version}

    files = {
        path.relative_to(target / "qrcode").as_posix(): path
        for path in (target / "qrcode").rglob("*") if path.is_file()
    }
    assert not (target / "qrcode" / "tests").exists()
    expected = {
        path.relative_to(source).as_posix(): path
        for path in source.rglob("*")
        if path.is_file()
        and "tests" not in path.relative_to(source).parts
        and "__pycache__" not in path.relative_to(source).parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    assert files.keys() == expected.keys()
    assert all(files[name].read_bytes() == original.read_bytes()
               for name, original in expected.items())
    assert (target / metadata.name / "METADATA").read_bytes() == (
        metadata / "METADATA"
    ).read_bytes()

    # Use the copied encoder in a child process, so a cached host import cannot
    # hide a missing runtime module. Matrix construction does not open a window.
    script = """
import json
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
import qrcode
qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, mask_pattern=0)
qr.add_data('portable-pruning-regression')
qr.make(fit=True)
print(json.dumps({'source': str(Path(qrcode.__file__).resolve()), 'matrix': qr.get_matrix()}))
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script, str(target)],
        capture_output=True, text=True, check=False, timeout=30,
        **({"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}),
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert Path(result["source"]) == (target / "qrcode" / "__init__.py").resolve()
    import qrcode
    original = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, mask_pattern=0)
    original.add_data("portable-pruning-regression")
    original.make(fit=True)
    assert result["matrix"] == original.get_matrix()


def test_runtime_copy_omits_venv_and_keeps_standard_library(tmp_path, monkeypatch):
    python_home = tmp_path / "python"
    fixtures = {
        **{name: b"owned-runtime-root" for name in builder.RUNTIME_ROOT_FILES},
        "DLLs/_socket.pyd": b"owned-runtime-extension",
        "Lib/asyncio/events.py": b"# required standard library\n",
        "Lib/unittest/__init__.py": b"# public standard library\n",
        "Lib/venv/__init__.py": b"# development-only virtual environment\n",
        "Lib/venv/scripts/nt/deactivate.bat": b"owned-venv-script",
        "Lib/test/test_fixture.py": b"# standard library test\n",
        "Lib/asyncio/__pycache__/events.pyc": b"owned-bytecode",
        "tcl/tcl8.6/init.tcl": b"# required Tcl data\n",
        "tcl/tcl8.6/unused.dll": b"owned-unused-native-library",
    }
    for relative, content in fixtures.items():
        path = python_home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    # Keep this test about copying; the pinned-version/architecture admission
    # checks have their own contract tests.
    monkeypatch.setattr(builder, "EXPECTED_PYTHON", tuple(sys.version_info[:3]))
    monkeypatch.setattr(builder.platform, "architecture", lambda: ("64bit", ""))
    runtime = tmp_path / "packet" / "runtime"

    builder._runtime_source(python_home, runtime)

    assert not (runtime / "Lib" / "venv").exists()
    assert not (runtime / "Lib" / "test").exists()
    assert list(runtime.rglob("__pycache__")) == []
    expected = {
        *builder.RUNTIME_ROOT_FILES, "DLLs/_socket.pyd", "Lib/asyncio/events.py",
        "Lib/unittest/__init__.py", "tcl/tcl8.6/init.tcl",
    }
    actual = {path.relative_to(runtime).as_posix()
              for path in runtime.rglob("*") if path.is_file()}
    assert actual == expected
    assert all((runtime / name).read_bytes() == fixtures[name] for name in expected)
