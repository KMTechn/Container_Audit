"""Pinned source and CA facade contracts; no runtime sibling imports."""
import hashlib
import inspect
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from kmtech_shared import raster as core
from tools import build_portable_release_candidate as builder
from vendor.kmtech_zero_pe import raster as facade


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "qualification/check_kmtech_shared.py"


def _check(root):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(CHECKER), "--check", "--root", str(root)],
        capture_output=True, text=True, check=False,
    )


def test_pinned_shared_source_passes_local_checker():
    from tests.spec_contracts import evaluate_spec

    result = _check(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    configured = evaluate_spec(ROOT / "Container_Audit.spec")["analysis"]
    assert {"kmtech_shared.catalog", "kmtech_shared.raster"} <= set(configured["hiddenimports"])
    assert {("kmtech_shared.manifest.json", "."), ("kmtech_shared.lock.json", ".")} <= set(configured["datas"])


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed", "manifest"])
def test_local_checker_rejects_shared_source_drift(tmp_path, mutation):
    shutil.copytree(ROOT / "kmtech_shared", tmp_path / "kmtech_shared")
    for name in ("kmtech_shared.manifest.json", "kmtech_shared.lock.json"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    if mutation == "missing":
        (tmp_path / "kmtech_shared/catalog.py").unlink()
    elif mutation == "extra":
        (tmp_path / "kmtech_shared/extra.py").write_text("", encoding="utf-8")
    elif mutation == "changed":
        with (tmp_path / "kmtech_shared/catalog.py").open("ab") as stream:
            stream.write(b"\n# unexpected drift\n")
    else:
        manifest_path = tmp_path / "kmtech_shared.manifest.json"
        manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
    result = _check(tmp_path)
    assert result.returncode == 1
    assert "FAIL:" in result.stderr


@pytest.mark.parametrize("mutation", ["version", "hash", "fields", "malformed"])
def test_local_checker_rejects_invalid_lock(tmp_path, mutation):
    shutil.copytree(ROOT / "kmtech_shared", tmp_path / "kmtech_shared")
    shutil.copyfile(ROOT / "kmtech_shared.manifest.json", tmp_path / "kmtech_shared.manifest.json")
    lock = json.loads((ROOT / "kmtech_shared.lock.json").read_bytes())
    if mutation == "version":
        lock["version"] = "0.0.0"
    elif mutation == "hash":
        lock["manifest_sha256"] = "0" * 64
    elif mutation == "fields":
        lock.pop("manifest_sha256")
    path = tmp_path / "kmtech_shared.lock.json"
    path.write_text("{" if mutation == "malformed" else json.dumps(lock), encoding="utf-8")
    result = _check(tmp_path)
    assert result.returncode == 1
    assert "FAIL:" in result.stderr


def test_local_checker_tests_pass_without_sibling_checkout(tmp_path):
    app = tmp_path / "app"
    builder._copy_application(ROOT, app)
    for name in ("pytest.ini", "Container_Audit.spec", "tests/__init__.py", "tests/conftest.py",
                 "tests/native_widgets.py", "tests/spec_contracts.py", "tests/test_kmtech_shared.py",
                 "tests/integration/check_kmtech_shared_canonical.py", "qualification/check_kmtech_shared.py",
                 "tools/build_portable_release_candidate.py", "tools/derive_container_writer_sinks.py"):
        target = app / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    assert not (app.parent / "kmtech_shared").exists()
    code = """
import pathlib, sys
app = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(app))
def guard(event, args):
    if event in {'socket.connect', 'socket.bind'}:
        raise RuntimeError('Standalone pin test forbids network')
sys.addaudithook(guard)
import tkinter
def deny(*args, **kwargs):
    raise RuntimeError('Standalone pin test forbids GUI')
tkinter.Tk.__init__ = deny
tkinter.Toplevel.__init__ = deny
import pytest
result = pytest.main(sys.argv[2:])
for name in ('kmtech_shared', 'vendor.kmtech_zero_pe.raster',
             'tools.build_portable_release_candidate', 'tools.derive_container_writer_sinks'):
    assert pathlib.Path(sys.modules[name].__file__).resolve().is_relative_to(app), name
raise SystemExit(result)
"""
    command = [sys.executable, "-I", "-B", "-c", code, str(app),
               "-q", "-p", "no:cacheprovider", "--tb=short", "-c", str(app / "pytest.ini"),
               "--basetemp", str(tmp_path / "child-pytest")]
    test = str(app / "tests/test_kmtech_shared.py")
    result = subprocess.run(
        [*command, test + "::test_pinned_shared_source_passes_local_checker",
         test + "::test_local_checker_rejects_shared_source_drift"],
        cwd=app, capture_output=True, text=True, check=False, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "5 passed" in result.stdout
    collected = subprocess.run(
        [*command, "--collect-only", "tests"], cwd=app,
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert collected.returncode == 0, collected.stdout + collected.stderr
    assert "test_pinned_shared_source_passes_local_checker" in collected.stdout
    assert "test_canonical_shared_source_matches_app_checker" not in collected.stdout


def test_every_image_factory_retains_ca_class_and_png_bytes(tmp_path, monkeypatch):
    from phs_label_workflow import _save_raster_png
    import writer_session_fence as fence
    from contextlib import contextmanager

    path = tmp_path / "source.png"
    image = facade.RasterImage.solid(6, 4, (10, 20, 30))
    path.write_bytes(image.to_png_bytes())
    images = [image, facade.RasterImage.from_png(path),
              facade.RasterImage.from_png_bytes(path.read_bytes()),
              image.resized(6, 4), image.resized(3, 2),
              image.resized(3, 2, resample="nearest"),
              image.contain((30, 20)), image.contain((3, 2))]
    with facade.RasterCanvas(6, 4, background=(10, 20, 30)) as canvas:
        images.extend([canvas.snapshot(), canvas.snapshot().resized(3, 2)])
    assert str(inspect.signature(facade.RasterImage.save_png)) == (
        "(self, path: 'str | os.PathLike[str]', *, dpi: 'tuple[int, int] | None' = None, "
        "atomic: 'bool' = True) -> 'dict[str, object]'"
    )
    for index, result in enumerate(images):
        assert type(result) is facade.RasterImage
        expected = core.RasterImage(result.width, result.height, result.bgra)
        assert result.to_png_bytes(dpi=(300, 300)) == expected.to_png_bytes(dpi=(300, 300))
        target = tmp_path / f"saved-{index}.png"
        receipt = _save_raster_png(result, target)
        assert target.read_bytes() == expected.to_png_bytes(dpi=(300, 300))
        assert receipt["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()

    @contextmanager
    def denied(source):
        assert source == "phs_raster_png"
        raise fence.WriterFencedError("TEST_DENIED", "synthetic admission denied")
        yield

    monkeypatch.setattr(fence, "writer_admission", denied)
    for result in images:
        with pytest.raises(fence.WriterFencedError, match="synthetic admission denied"):
            _save_raster_png(result, tmp_path / "denied.png")
    assert not (tmp_path / "denied.png").exists()


def test_portable_copy_imports_one_shared_module_identity(tmp_path):
    app = tmp_path / "app"
    sources = builder._copy_application(ROOT, app)
    builder._assert_portable_import_closure(tmp_path, ROOT, sources, Path(sys.executable))
    checked = _check(app)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    code = """
import importlib, pathlib, sys
sys.path.insert(0, sys.argv[1])
from kmtech_shared import raster, catalog
from vendor.kmtech_zero_pe import raster as facade, gdi_print
import Container_Audit, phs_label_workflow, item_catalog_sync
assert item_catalog_sync._catalog_core is catalog
assert facade.RasterImage.__bases__ == (raster.RasterImage,)
assert facade.RasterCanvas.__bases__ == (raster.RasterCanvas,)
assert Container_Audit.RasterImage is phs_label_workflow.RasterImage is gdi_print.RasterImage is facade.RasterImage
for module in (catalog, raster):
    origin = pathlib.Path(module.__file__).resolve()
    assert origin.is_relative_to(pathlib.Path(sys.argv[1]).resolve())
    identities = [name for name, loaded in list(sys.modules.items())
                  if getattr(loaded, '__file__', None)
                  and pathlib.Path(loaded.__file__).resolve() == origin]
    assert identities == [module.__name__], identities
print('PASS: isolated portable imports and one shared identity')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(app)], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_pre_adoption_v2_sidecars_read_write_and_recover_unchanged(tmp_path, monkeypatch):
    import item_catalog_sync as sync

    # Frozen before leaf delegation, using the bb8351e CA algorithm and synthetic identity.
    fixture = json.loads((ROOT / "tests/fixtures/item_catalog_v2_ca.json").read_bytes())
    payload = fixture["catalog_utf8"].encode("utf-8")
    binding = fixture["binding"]
    monkeypatch.setattr(sync, "_load_item_catalog_logistics_profile", lambda: None)
    cache = tmp_path / "Item.csv"
    cache.write_bytes(payload)
    authority_path = tmp_path / "Item.csv.authority.json"
    recovery_path = tmp_path / "Item.csv.recovery.json"
    authority_path.write_bytes(fixture["authority_json"].encode("utf-8"))
    recovery_path.write_bytes(fixture["recovery_json"].encode("utf-8"))
    assert sync._read_authenticated_cache_payload(cache, **binding) == payload
    rotated = dict(binding, bearer_token="rotated-synthetic-token")
    assert sync._read_authenticated_cache_payload(cache, **rotated) is None
    assert sync._read_authenticated_recovery_payload(cache, **rotated) is None

    sync._write_authenticated_cache(cache, payload, **binding)
    assert cache.read_bytes() == payload
    assert authority_path.read_bytes() == fixture["authority_json"].encode("utf-8")
    assert recovery_path.read_bytes() == fixture["recovery_json"].encode("utf-8")
    cache.write_bytes(b"interrupted primary write")
    assert sync._read_authenticated_cache_payload(cache, **binding) is None
    recovered = sync._recover_authenticated_cache(cache, **binding)
    assert recovered == tmp_path / "Item.csv.last-good"
    assert recovered.read_bytes() == payload
    assert sync.get_verified_catalog_snapshot(recovered) == payload
    assert cache.read_bytes() == b"interrupted primary write"
