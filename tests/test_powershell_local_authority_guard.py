"""A function-local lease protects only its unconditional try/finally lifetime."""
from pathlib import Path

import pytest

from tests.test_container_writer_sink_inventory import _load_module


ACQUIRE = "$lease = Enter-ContainerWriterSessionAuthority -SessionId $session"
RELEASE = "Exit-ContainerWriterSessionAuthority $lease"
HELD = ACQUIRE + "\ntry {\nCALL\n} finally {\n" + RELEASE + "\n}"
BOTH = ACQUIRE + "\ntry {\n$slot = Enter-ContainerWriterAdmission\ntry {\nCALL\n} finally {\nExit-ContainerWriterAdmission $slot\n}\n} finally {\n" + RELEASE + "\n}"

POSITIVE = (
    HELD,
    BOTH,
    "try {\n$checked = Read-OnlyProof\n" + BOTH + "\n} catch { throw } finally { $saved = $previous }",
)
NEGATIVE = (
    ("no_finally", ACQUIRE + "\nCALL\n" + RELEASE),
    ("after_exit", HELD + "\nCALL"),
    ("before_enter", "CALL\n" + HELD),
    ("early_return", "if ($skip) { return }\n" + HELD),
    ("conditional_enter", "if ($ok) { " + ACQUIRE + " }\ntry {\nCALL\n} finally {\n" + RELEASE + "\n}"),
    ("different_lease", HELD.replace(RELEASE, "Exit-ContainerWriterSessionAuthority $otherLease")),
    ("conditional_exit", HELD.replace(RELEASE, "if ($ok) { " + RELEASE + " }")),
    ("rebound_lease", HELD.replace("CALL", "$lease = $otherLease\nCALL")),
    ("exit_in_body", HELD.replace("CALL", RELEASE + "\nCALL")),
    ("intervening_call", HELD.replace("\ntry {", "\nCALL\ntry {", 1)),
    ("throw_before_exit", HELD.replace(RELEASE, "throw 'fixture'\n" + RELEASE)),
    ("admission_no_finally", BOTH.replace("} finally {\nExit-ContainerWriterAdmission $slot\n}", "}\ncatch { throw }")),
    ("admission_wrong_lease", BOTH.replace("Exit-ContainerWriterAdmission $slot", "Exit-ContainerWriterAdmission $otherSlot")),
)


def inspect(body, direct):
    module = _load_module()
    call = "Set-Content -LiteralPath $path -Value 'fixture'" if direct else "Invoke-ProtectedLeaf"
    source = (
        "function ArbitraryOwner {\n" + body.replace("CALL", call) + "\n}\n"
        "function Invoke-ProtectedLeaf {\nSet-Content -LiteralPath $path -Value 'fixture'\n}\n"
        "ArbitraryOwner\n$globalLease = Enter-ContainerWriterSessionAuthority\ntry {\n}\n"
        "finally { Exit-ContainerWriterSessionAuthority $globalLease }\n"
    )
    lines = source.splitlines()
    ranges = module._powershell_function_ranges(lines)
    path = Path("INSTALL_CANONICAL_PORTABLE.ps1")
    entry = module._powershell_entry_guard(path, lines, ranges)
    proofs = module._powershell_function_guard_proofs(path, lines, ranges, entry)
    assert entry["valid"]
    if not direct:
        return proofs["Invoke-ProtectedLeaf"]["guarded"]
    owner = next(row for row in ranges if row["name"] == "ArbitraryOwner")
    results = []
    for number, line in enumerate(lines, 1):
        if owner["start"] < number < owner["end"] and "Set-Content" in line:
            result = module._powershell_site_guard(path, {"kind": "filesystem_mutation", "command": "Set-Content", "line": number}, owner, entry, proofs)
            results.append(result[0])
    assert results
    return all(results)


@pytest.mark.parametrize("direct", (False, True), ids=("callee", "direct"))
@pytest.mark.parametrize("body", POSITIVE, ids=("authority", "authority-admission", "outer-try"))
def test_local_authority_protects_only_its_held_calls(body, direct):
    assert inspect(body, direct)


@pytest.mark.parametrize("direct", (False, True), ids=("callee", "direct"))
@pytest.mark.parametrize("case,body", NEGATIVE, ids=[row[0] for row in NEGATIVE])
def test_unproven_local_authority_stays_unsafe(case, body, direct):
    assert not inspect(body, direct), case


@pytest.mark.parametrize("position", ("inside", "before", "after"))
def test_shared_library_requires_each_call_inside_the_local_lifetime(tmp_path, position):
    module = _load_module()
    body = BOTH.replace("CALL", "Initialize-SharedNative")
    if position == "before":
        body = "Initialize-SharedNative\n" + body
    elif position == "after":
        body += "\nInitialize-SharedNative"
    source = (
        "function ArbitraryOwner {\n" + body + "\n}\nArbitraryOwner\n"
        "$globalLease = Enter-ContainerWriterSessionAuthority\ntry {\n}\n"
        "finally { Exit-ContainerWriterSessionAuthority $globalLease }\n"
    )
    installer = tmp_path / "INSTALL_CANONICAL_PORTABLE.ps1"
    library = tmp_path / "tools/bootstrap_integrity.ps1"
    library.parent.mkdir()
    installer.write_text(source, encoding="utf-8")
    library.write_text("function Initialize-SharedNative {\nAdd-Type -TypeDefinition 'fixture'\n}\n", encoding="utf-8")
    proofs = module._powershell_bootstrap_caller_proofs(tmp_path, (Path(installer.name), Path("tools/bootstrap_integrity.ps1")))
    assert ("Initialize-SharedNative" in proofs) == (position == "inside")
