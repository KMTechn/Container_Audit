"""Explicit integration node; the filename excludes it from default discovery."""
import importlib.util
import inspect
import json
import subprocess
import sys

from qualification import check_kmtech_shared as local


def test_canonical_shared_source_matches_app_checker(tmp_path, capsys):
    assert local.main(["--check"]) == 0
    lock = json.loads((local.ROOT / "kmtech_shared.lock.json").read_bytes())
    manifest = json.loads((local.ROOT / "kmtech_shared.manifest.json").read_bytes())
    pinned_commit = manifest["source_commit"]
    canonical_root = local.ROOT.parent / "kmtech_shared"
    assert (canonical_root / ".git").exists(), "Explicit integration check requires the canonical kmtech_shared checkout"

    def pinned_bytes(path):
        return subprocess.run(
            ["git", "-C", str(canonical_root), "show", f"{pinned_commit}:{path}"],
            capture_output=True, check=True,
        ).stdout

    # The code pin precedes the release manifest commit. Compare its package
    # bytes and checker, while the app lock authenticates the release manifest.
    for path in manifest["files"]:
        assert (local.ROOT / path).read_bytes() == pinned_bytes(path), path
    checker = tmp_path / "manifest/sync_shared.py"
    checker.parent.mkdir()
    checker.write_bytes(pinned_bytes("manifest/sync_shared.py"))
    spec = importlib.util.spec_from_file_location("canonical_shared_checker", checker)
    canonical = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(canonical)
    assert local.FILES == canonical.FILES
    assert local.SCHEMA == canonical.SCHEMA
    for name in ("digest", "inventory", "package_version", "check_manifest"):
        assert inspect.getsource(getattr(local, name)) == inspect.getsource(getattr(canonical, name)), name
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(checker), "--check", "--root", str(local.ROOT),
         "--manifest", str(local.ROOT / "kmtech_shared.manifest.json"),
         "--expected-sha256", lock["manifest_sha256"]],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    # A newer/dirty canonical checkout is informational; it cannot change this
    # app's pinned release or weaken any of the comparisons above.
    checkout_version = "unavailable"
    try:
        checkout_version = local.package_version(canonical_root)
        drift = (local.inventory(canonical_root) != manifest["files"]
                 or checkout_version != manifest["version"])
    except (OSError, ValueError):
        drift = True
    if drift:
        head = subprocess.run(
            ["git", "-C", str(canonical_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        ).stdout.strip()[:12] or "unavailable"
        with capsys.disabled():
            print(f"canonical drift: pin {manifest['version']} at {pinned_commit[:12]}; "
                  f"HEAD {head}, checkout {checkout_version}; pinned comparison PASS")
