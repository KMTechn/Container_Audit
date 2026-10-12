import json
import os
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "tools/bootstrap_integrity.ps1"
WORKER = "S-1-5-21-1000-2000-3000-1001"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

# Windows default descriptors read on a field PC (inspection 3, 2026-10-13).
PROGRAMDATA_DEFAULT = "O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)"
SYSTEM_DRIVE_DEFAULT = ("O:" + TRUSTED_INSTALLER + "D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)"
                        "(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1-2-3-4-5-6-7-8)")
# KMTech created under ProgramData by an older app: the inherited default.
KMTECH_INHERITED = "O:BAD:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"

CASES = [
    # name, path under machine data ("" = the root itself, None = drive root), leaf, sddl, expected
    ("programdata default", "", False, PROGRAMDATA_DEFAULT, "ADMIT"),
    ("programdata default as checked parent", "", True, PROGRAMDATA_DEFAULT, "ADMIT"),
    ("kmtech inherited default", "KMTech", False, KMTECH_INHERITED, "ADMIT"),
    ("system drive default", None, False, SYSTEM_DRIVE_DEFAULT, "ADMIT"),
    # Label_Match creates KMTech with New-Item -Force (INSTALL_CANONICAL_PORTABLE.ps1 FreezePlacementHelper):
    # inherited default, owner Administrators (elevated) or SYSTEM.
    ("kmtech made by label match elevated", "KMTech", False, KMTECH_INHERITED, "ADMIT"),
    ("kmtech made by label match as system", "KMTech", False, "O:SYG:SY" + KMTECH_INHERITED[4:], "ADMIT"),
    ("programdata users delete child", "", False, PROGRAMDATA_DEFAULT + "(A;CI;0x40;;;BU)", "MUTABLE"),
    ("programdata users write dac", "", False, PROGRAMDATA_DEFAULT + "(A;;0x40000;;;BU)", "MUTABLE"),
    ("programdata users generic write", "", False, PROGRAMDATA_DEFAULT + "(A;;GW;;;BU)", "MUTABLE"),
    ("kmtech owned by a user", "KMTech", False, "O:" + WORKER + KMTECH_INHERITED[4:], "OWNER"),
    ("app state under kmtech keeps the strict mask", "KMTech\\ContainerAudit", False, KMTECH_INHERITED, "MUTABLE"),
    ("sibling name is not the machine data root", "..\\ProgramDataX", False, PROGRAMDATA_DEFAULT, "MUTABLE"),
    ("worker write on protected leaf", "KMTech\\ContainerAudit\\machine-install", True,
     "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + WORKER + ")", "MUTABLE"),
    ("protected leaf", "KMTech\\ContainerAudit\\machine-install", True,
     "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", "ADMIT"),
]

SCRIPT = r"""
$machineData=[IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\')
foreach($case in (Get-Content -LiteralPath $env:CA_CASES -Raw | ConvertFrom-Json)) {
    $path=if($null -eq $case.relative){[IO.Path]::GetPathRoot($machineData)}
        elseif($case.relative -eq ''){$machineData}
        else{[IO.Path]::GetFullPath((Join-Path $machineData $case.relative))}
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($case.sddl)
    $verdict=if(-not(Test-BootstrapPrivilegedOwnerSid $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)){'OWNER'}
        elseif(Test-BootstrapRelayAclUserMutable $acl (Get-BootstrapRelayPathRightsMask $path ([bool]$case.leaf))){'MUTABLE'}
        else{'ADMIT'}
    [Console]::Out.WriteLine((ConvertTo-Json -Compress @{name=$case.name;verdict=$verdict}))
}
"""


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_shared_machine_data_ancestors_admit_windows_defaults_only(tmp_path, engine):
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([{"name": n, "relative": r, "leaf": leaf, "sddl": s} for n, r, leaf, s, _ in CASES]),
                     encoding="utf-8")
    result = run_functions(tmp_path, LIBRARY, ["Test-BootstrapPrivilegedOwnerSid", "Get-BootstrapRelayPathRightsMask",
                                               "Test-BootstrapRelayAclUserMutable"], SCRIPT,
                           values={"CA_CASES": str(cases)}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = {row["name"]: row["verdict"] for row in map(json.loads, result.stdout.splitlines()) if row}
    assert verdicts == {name: expected for name, _, _, _, expected in CASES}


@pytest.mark.skipif(os.name != "nt", reason="Windows machine data root")
def test_this_host_machine_data_root_is_admitted_as_an_installation_parent(tmp_path):
    # The 10/11 machine installation checks this parent before creating its
    # state directory; a default Windows ProgramData must pass that check.
    result = run_functions(tmp_path, LIBRARY, ["Assert-BootstrapProtectedRelayPath", "Get-StrictFullPath",
                                               "Test-BootstrapPrivilegedOwnerSid", "Get-BootstrapRelayPathRightsMask",
                                               "Test-BootstrapRelayAclUserMutable"],
                           "Assert-BootstrapProtectedRelayPath ([Environment]::GetFolderPath('CommonApplicationData'))\n"
                           "[Console]::Out.WriteLine('ADMITTED')\n")
    assert result.returncode == 0 and result.stdout.strip().endswith("ADMITTED"), result.stdout + result.stderr
