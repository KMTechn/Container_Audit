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
CHECKER = ROOT.parent / "kmtech_shared" / "manifest" / "sync_shared.py"


def _check(root):
    lock = json.loads((root / "kmtech_shared.lock.json").read_bytes())
    manifest = json.loads((root / "kmtech_shared.manifest.json").read_bytes())
    assert lock["version"] == manifest["version"]
    return subprocess.run(
        [sys.executable, "-B", str(CHECKER), "--check", "--root", str(root),
         "--manifest", str(root / "kmtech_shared.manifest.json"),
         "--expected-sha256", lock["manifest_sha256"]],
        capture_output=True, text=True, check=False,
    )


def test_pinned_shared_source_passes_canonical_checker():
    result = _check(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed", "manifest"])
def test_canonical_checker_rejects_shared_source_drift(tmp_path, mutation):
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
