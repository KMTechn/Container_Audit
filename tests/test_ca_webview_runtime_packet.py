"""The archive must retain every Loader that pywebview imports on Windows."""
import hashlib
import zipfile

import pytest

from tools import build_portable_release_candidate as builder


LOADERS = {
    "win-arm64": (147016, "0937030efc718f3da77c5e0978fb5046e381d0bb7b01acaad31a535a1b588a33"),
    "win-x64": (161864, "eb5335edeaa6f2122c044e82aab2351dc8c9b4e0fe5e578c71922fb61be285e7"),
    "win-x86": (121928, "04814b2c59314c6452d61b821a4a3a5c5f8e8577b55b985f6a7a4b59f8907ec5"),
}


def _relative(arch):
    return f"site-packages/webview/lib/runtimes/{arch}/native/WebView2Loader.dll"


def test_all_three_loaders_are_pinned_to_the_approved_native_inventory():
    assert builder.NATIVE_ALLOWLIST_SOURCE_SHA256 == "b58c9873926e26056672f8aa7f2fae9ba0a1dc11a9f5b4ca12dc727959c07c42"
    for arch, pin in LOADERS.items():
        name = _relative(arch)
        assert builder.APP_NATIVE_ALLOWLIST[name] == pin
        assert name not in builder.APP_NATIVE_UNSIGNED
        assert name.removeprefix("site-packages/") not in builder.THIRD_PARTY_EXCLUDED_PATHS


def test_third_party_archive_contains_all_loader_files_not_only_empty_directories(tmp_path, monkeypatch):
    source = tmp_path / "source"
    metadata = source / "pywebview-6.2.1.dist-info"
    metadata.mkdir(parents=True)
    (metadata / "METADATA").write_text("Name: pywebview\nVersion: 6.2.1\n", encoding="utf-8")
    originals = {}
    for arch in LOADERS:
        relative = _relative(arch).removeprefix("site-packages/")
        path = source / relative
        path.parent.mkdir(parents=True)
        originals[relative] = b"MZ" + arch.encode("ascii")
        path.write_bytes(originals[relative])
    for arch in ("x64", "x86"):
        (source / "webview/lib" / f"WebBrowserInterop.{arch}.dll").write_bytes(b"MZexcluded")
    monkeypatch.setattr(builder, "THIRD_PARTY", {"pywebview": ("6.2.1", ("webview",))})
    monkeypatch.setattr(builder, "_distribution_root", lambda *_: (source, metadata))
    site = tmp_path / "stage/app/site-packages"
    site.mkdir(parents=True)
    builder._copy_third_party(site)
    archive = tmp_path / "packet.zip"
    with zipfile.ZipFile(archive, "w") as packet:
        for path in site.rglob("*"):
            if path.is_file():
                packet.write(path, path.relative_to(site).as_posix())
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(archive) as packet:
        assert set(originals) <= set(packet.namelist())
        assert not any("WebBrowserInterop" in name for name in packet.namelist())
        packet.extractall(extracted)
    assert all((extracted / name).read_bytes() == value for name, value in originals.items())


@pytest.mark.parametrize("missing_arch", tuple(LOADERS))
def test_release_inventory_rejects_each_missing_loader_file(tmp_path, monkeypatch, missing_arch):
    # Tiny native fixtures exercise exact set/size/hash checks without a native loader.
    original_names = set(builder.APP_NATIVE_ALLOWLIST)
    assert {_relative(arch) for arch in LOADERS} <= original_names
    pins = {}
    for name in original_names:
        data = b"MZ" + name.encode("ascii")
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        pins[name] = (len(data), hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(builder, "APP_NATIVE_ALLOWLIST", pins)
    assert set(builder._app_native_inventory(tmp_path)) == original_names
    (tmp_path / _relative(missing_arch)).unlink()
    with pytest.raises(builder.PortableBuildError, match="exactly the pinned allowlist"):
        builder._app_native_inventory(tmp_path)
