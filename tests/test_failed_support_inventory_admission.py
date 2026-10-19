"""FAILED support must load the pinned library through an admitted symbol."""
from pathlib import Path

import pytest

from tools import derive_container_writer_sinks as inventory


@pytest.mark.parametrize(
    ("relative", "function_name"),
    [
        ("INSTALL_CANONICAL_PORTABLE.ps1", None),
        ("tools/bootstrap_integrity.ps1", "Assert-BootstrapFailedSupportState"),
    ],
    ids=["installer", "failed_support"],
)
def test_failed_support_library_load_is_release_admitted(relative, function_name):
    root = Path(__file__).resolve().parents[1]
    lines = (root / relative).read_text(encoding="utf-8-sig").splitlines()
    ranges = inventory._powershell_function_ranges(lines)
    scope = next((row for row in ranges if row["name"] == function_name), None)
    candidates = [
        number
        for number, line in enumerate(lines, 1)
        if "Get-BootstrapSharedPortableLeaf" in line
        and "'data_generation.ps1'" in line
        and (
            not any(row["start"] <= number <= row["end"] for row in ranges)
            if function_name is None
            else scope is not None and scope["start"] <= number <= scope["end"]
        )
    ]
    assert len(candidates) == 1
    call_line = candidates[0]
    sites = [
        {**site, "line": number}
        for number in range(call_line, min(call_line + 2, len(lines)) + 1)
        for site in inventory._powershell_line_sites(lines, number)
        if site["kind"] == "dot_source"
    ]
    assert len(sites) == 1
    guarded, guard_name, guard_line = inventory._powershell_site_guard(
        Path(relative), sites[0], scope, {"valid": False}, {}
    )
    assert guarded is True
    assert guard_name == "byte_pinned_function_library"
    assert guard_line == sites[0]["line"]
