"""Raw-bound receipts share the product comparator; legacy hashes remain strict."""
import hashlib
import json
from pathlib import Path

import pytest

import current_user_onboarding as onboarding
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
BEFORE = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
ORDER = "O:BAG:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)"


def identity(raw, *, legacy=False):
    value = dict(file_count=1, aggregate_sha256="a" * 64,
                 integrity_sha256="b" * 64, manifest_sha256="c" * 64,
                 source_commit="d" * 40, source_tree="e" * 40,
                 owner_sid="S-1-5-32-544", access_rules_protected=True,
                 acl_sddl_sha256=hashlib.sha256(raw.encode()).hexdigest(), reparse_count=0)
    if not legacy:
        value["acl_sddl"] = raw
    return value


def pair(case):
    expected = identity(BEFORE, legacy=case.startswith("legacy"))
    actual = identity(BEFORE.replace("D:P", "D:PAI"))
    accepted = case in ("ai", "order", "legacy_ai", "legacy_exact")
    if case in ("order", "legacy_order"):
        actual = identity(ORDER)
    elif case == "legacy_exact":
        actual = identity(BEFORE)
    elif case == "tampered_raw":
        actual["acl_sddl"] += "(A;;FW;;;WD)"
    elif case == "owner":
        actual = identity(BEFORE.replace("O:BA", "O:SY"))
        actual["owner_sid"] = "S-1-5-18"
    elif case == "group":
        actual = identity(BEFORE.replace("G:BA", "G:SY"))
    elif case in ("ace", "legacy_ace"):
        actual = identity(BEFORE + "(A;;FW;;;WD)")
    elif case in ("control", "legacy_control"):
        actual = identity(BEFORE.replace("D:P", "D:PAR"))
    elif case == "protection":
        actual = identity(BEFORE.replace("D:P", "D:"))
        actual["access_rules_protected"] = False
    elif case == "inherited":
        actual = identity(BEFORE.replace("(A;;FA;;;SY)", "(A;ID;FA;;;SY)"))
    elif case == "owner_binding":
        actual = identity(BEFORE.replace("O:BA", "O:SY"))
    elif case == "deny_order":
        expected = identity(BEFORE + "(A;;FR;;;WD)(D;;FR;;;WD)")
        actual = identity(BEFORE + "(D;;FR;;;WD)(A;;FR;;;WD)")
    return expected, actual, accepted


CASES = ("ai", "order", "legacy_ai", "legacy_exact", "legacy_order",
         "tampered_raw", "owner", "group", "ace", "legacy_ace", "control",
         "legacy_control", "protection", "inherited", "owner_binding", "deny_order")


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", CASES)
def test_replacement_receipt_permission_identity(tmp_path, engine, case):
    expected, actual, accepted = pair(case)
    path = tmp_path / "pair.json"
    path.write_text(json.dumps(dict(expected=expected, actual=actual)), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", ["Test-BootstrapReplacementTreeIdentity"], r'''
. $env:CA_ACL_LIBRARY
$pair=Get-Content -LiteralPath $env:CA_ACL_PAIR -Raw|ConvertFrom-Json
Test-BootstrapReplacementTreeIdentity $pair.expected $pair.actual
''', engine=engine, values={"CA_ACL_LIBRARY": str(ROOT / "tools/bootstrap_integrity.ps1"),
                           "CA_ACL_PAIR": str(path)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == str(accepted)


@pytest.mark.parametrize("case", CASES)
def test_python_zero_touch_readback_uses_executing_library(case):
    expected, actual, accepted = pair(case)
    if case == "tampered_raw":
        with pytest.raises(ValueError, match="raw descriptor binding"):
            onboarding._normalized_replacement_identity(actual, "test")
    else:
        expected = onboarding._normalized_replacement_identity(expected, "expected")
        actual = onboarding._normalized_replacement_identity(actual, "actual")
        assert onboarding._replacement_identities_match(expected, actual) is accepted
