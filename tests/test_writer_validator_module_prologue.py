"""Exact OS imports are read-only exceptions; other module loads stay refused."""
import hashlib
from pathlib import Path

import pytest

from tests.test_container_writer_sink_inventory import _load_module, _write_minimal_inventory_fixture


def _inventory(tmp_path, source):
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    (tmp_path / "tools/bootstrap_integrity.ps1").write_bytes(source)
    return module._collect_powershell_inventory(tmp_path)


@pytest.mark.parametrize("prefix", [b"", b"\xef\xbb\xbf", b"# library\n", b"[CmdletBinding()]\nparam(\n [string]$Path = ''\n)\n"])
def test_validator_accepts_only_exact_os_module_block_at_script_head(tmp_path, prefix):
    module = _load_module()
    assert hashlib.sha256(module.PS_MODULE_PROLOGUE).hexdigest() == "9c5e083b8e332573f3368be3e9592a2e2409aa89891e15942026361be17d0b71"
    inventory = _inventory(tmp_path, prefix + module.PS_MODULE_PROLOGUE +
                           b"function Read-Hash {\n Get-FileHash -LiteralPath $Path\n}\n")
    imports = [row for row in inventory["execution_sites"] if row["command"] == "Import-Module"]
    assert len(imports) == 2
    assert all(row["guarded"] and row["guard_name"] == "byte_exact_os_module_prologue" for row in imports)
    assert inventory["guard_failures"] == []


@pytest.mark.parametrize("mutation", [
    "character", "module", "root", "action", "third", "leading_space",
    "trailing_space", "case", "crlf", "before_param", "late", "function", "parameter_command",
    "parameter_select", "parameter_dynamic",
])
def test_validator_refuses_changed_or_misplaced_os_module_block(tmp_path, mutation):
    source = _load_module().PS_MODULE_PROLOGUE
    if mutation == "character":
        source = source.replace(b"Utility.psd1", b"Utilitx.psd1", 1)
    elif mutation == "module":
        source = source.replace(b"Microsoft.PowerShell.Utility", b"Microsoft.PowerShell.Management")
    elif mutation == "root":
        source = source.replace(b"$PSHOME", b"$env:TEMP")
    elif mutation == "action":
        source = source.replace(b"-ErrorAction Stop", b"-ErrorAction Continue")
    elif mutation == "third":
        source += b"Import-Module -Name $UntrustedModule\n"
    elif mutation == "leading_space":
        source = b" " + source
    elif mutation == "trailing_space":
        source = source.replace(b"Stop\n", b"Stop \n")
    elif mutation == "case":
        source = source.replace(b"Import-Module", b"import-module")
    elif mutation == "crlf":
        source = source.replace(b"\n", b"\r\n")
    elif mutation == "before_param":
        source += b"param([string]$Path)\n"
    elif mutation == "late":
        source = b"Get-Content -LiteralPath 'fixture'\n" + source
    elif mutation == "function":
        source = b"function Read-Hash {\n" + source + b"}\n"
    elif mutation == "parameter_select":
        source = b"param($Path = ('fixture' | Select-Object -First 1))\n" + source
    elif mutation == "parameter_dynamic":
        source = b"param($Path = (& $Command))\n" + source
    else:
        source = b"param($Path = (Get-FileHash 'fixture'))\n" + source
    rejected = _inventory(tmp_path, source)["guard_failures"]
    assert any(row["kind"] == "dot_source" and row["command"].casefold() == "import-module" for row in rejected)


@pytest.mark.parametrize("source", [b". $UntrustedLibrary\n", b"Import-PSSession $Session\n", b"using module Untrusted\n"])
def test_validator_keeps_other_module_execution_refused(tmp_path, source):
    assert _inventory(tmp_path, source)["guard_failures"]


@pytest.mark.parametrize("consumer", [
    "", "import kmtech_shared.diagnostic_log", "from kmtech_shared import diagnostic_log",
    "from kmtech_shared import *", "import kmtech_shared",
    "import importlib\nimportlib.import_module('kmtech_shared.diagnostic_log')",
    "import importlib\nimportlib.import_module(name='kmtech_shared.diagnostic_log')",
    "import kmtech_shared as shared\ngetattr(shared, 'diagnostic_log')",
])
def test_validator_exempts_diagnostic_leaf_only_when_pinned_and_unconsumed(tmp_path, monkeypatch, consumer):
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, consumer + "\ndef main():\n    pass\n")
    leaf = tmp_path / "kmtech_shared/diagnostic_log.py"
    leaf.parent.mkdir(exist_ok=True)
    source = b"from pathlib import Path\ndef persist(path: Path):\n    path.write_text('fixture')\n"
    leaf.write_bytes(source)
    monkeypatch.setattr(module, "SHARED_UNUSED_DIAGNOSTIC_SHA256", hashlib.sha256(source).hexdigest())
    if consumer:
        with pytest.raises(module.InventoryError, match="byte-pinned and unconsumed"):
            module.derive_inventory(tmp_path)
    else:
        result = module.derive_inventory(tmp_path)
        assert result["uncovered_direct_mutation_functions"] == []
        assert "kmtech_shared/diagnostic_log.py" in result["closure_modules"]
        assert result["pinned_unused_sources"] == [{"path": "kmtech_shared/diagnostic_log.py", "sha256": hashlib.sha256(source).hexdigest()}]
        leaf.write_bytes(source + b"# drift\n")
        with pytest.raises(module.InventoryError, match="byte-pinned and unconsumed"):
            module.derive_inventory(tmp_path)
