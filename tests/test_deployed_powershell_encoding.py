"""Windows PowerShell 5.1 must decode shipped text independently of the ACP."""
import ast
import codecs
from pathlib import Path
import re

from tools import build_portable_release_candidate as builder


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL_SUFFIXES = {".ps1", ".psm1", ".psd1"}


def test_deployed_nonascii_powershell_requires_utf8_bom():
    sources = {
        ROOT / source for source, _target in builder.PORTABLE_INSTALL_ASSETS
        if Path(source).suffix.lower() in POWERSHELL_SUFFIXES
    }
    for package in builder.APP_PACKAGE_DIRS:
        sources.update(path for path in (ROOT / package).rglob("*")
                       if path.suffix.lower() in POWERSHELL_SUFFIXES)
    # Include resource paths referenced by the real portable Python closure
    # and the frozen payload, without executing a PyInstaller specification.
    python_sources = builder._portable_application_sources(ROOT)
    python_sources += builder._discover_portable_tool_sources(ROOT, python_sources)
    for source in [*python_sources, *ROOT.glob("*.spec")]:
        tree = ast.parse(source.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if Path(node.value).suffix.lower() not in POWERSHELL_SUFFIXES:
                continue
            for candidate in (ROOT / node.value, ROOT / "tools" / node.value):
                if candidate.is_file():
                    sources.add(candidate)
    # Current field/IT instructions can name support tools outside the packet.
    for document in (ROOT / "README.md", ROOT / "docs/spec/operations.md"):
        for target in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            candidate = (document.parent / target).resolve()
            if (candidate.is_relative_to(ROOT) and candidate.is_file()
                    and candidate.suffix.lower() in POWERSHELL_SUFFIXES):
                sources.add(candidate)
    missing = []
    for source in sorted(sources):
        data = source.read_bytes()
        if any(byte > 127 for byte in data.removeprefix(codecs.BOM_UTF8)):
            assert data.decode("utf-8-sig"), source.relative_to(ROOT).as_posix()
            if not data.startswith(codecs.BOM_UTF8):
                missing.append(source.relative_to(ROOT).as_posix())
    assert not missing, f"Deployed non-ASCII PowerShell requires UTF-8 BOM: {missing}"
