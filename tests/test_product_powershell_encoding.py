"""Keep tracked product scripts readable by Windows PowerShell 5.1."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
UTF8_BOM = b"\xef\xbb\xbf"
# Baseline exceptions must say: 바탕부터 — 1차 판정 대기.
BASELINE_WITHOUT_BOM: dict[str, str] = {}


def test_product_powershell_preserves_one_utf8_bom_for_windows_powershell():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT,
    ).decode("utf-8").split("\0")
    violations = []
    checked = 0
    for name in tracked:
        path = Path(name)
        if path.suffix.lower() not in {".ps1", ".psm1"}:
            continue
        if any("test" in part.lower() for part in path.parts):
            continue
        raw = (ROOT / path).read_bytes()
        if not any(byte >= 0x80 for byte in raw):
            continue
        checked += 1
        if name in BASELINE_WITHOUT_BOM:
            continue
        if not raw.startswith(UTF8_BOM) or raw[len(UTF8_BOM):].startswith(UTF8_BOM):
            violations.append(name)
    assert checked, "No tracked non-ASCII product PowerShell scripts were checked"
    assert not violations, "Product PowerShell must have exactly one UTF-8 BOM: " + ", ".join(violations)
