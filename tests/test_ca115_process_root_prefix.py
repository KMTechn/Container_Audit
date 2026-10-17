from pathlib import Path

import pytest

from ca115_process_root_vectors import PREFIX_CASES, prefix_vector
from test_removal_chain_admission import _run
from test_startup_update_bootstrap_readiness import observe  # noqa: F401


def _ps(value):
    return "'" + value.replace("'", "''") + "'"


@pytest.mark.parametrize("case", PREFIX_CASES)
def test_removal_census_uses_shared_prefix_vectors(tmp_path, case):
    image = tmp_path / "managed" / "versions" / "candidate" / "runtime" / "pythonw.exe"
    root, value, expected = prefix_vector(image, case)
    script = r"""
$script:prefixCalls=0
if(Get-Command Test-BootstrapProcessRootPrefix -ErrorAction SilentlyContinue){
 $script:originalPrefix=(Get-Command Test-BootstrapProcessRootPrefix).ScriptBlock
 function Test-BootstrapProcessRootPrefix([string]$Value,[string]$Root,[switch]$CommandLine){
  $script:prefixCalls++
  & $script:originalPrefix $Value $Root -CommandLine:$CommandLine
 }
}
function Get-CimInstance { return [pscustomobject]@{ProcessId=($PID+1);ExecutablePath=__IMAGE__;CommandLine=''} }
$blocked=$false
try { Assert-ContainerRemovalQuiescent __ROOT__ } catch {
 if($_.Exception.Message -cne 'REMOVAL_REQUIRES_PRODUCT_PROCESS_STOP'){throw}
 $blocked=$true
}
if($blocked -ne __EXPECTED__){throw 'PREFIX_VECTOR_RESULT_DIFFERS'}
if($script:prefixCalls -lt 1){throw 'PREFIX_HELPER_NOT_CALLED'}
"""
    script = script.replace("__IMAGE__", _ps(value)).replace("__ROOT__", _ps(root))
    script = script.replace("__EXPECTED__", "$true" if expected else "$false")
    _run(tmp_path, script)


@pytest.mark.parametrize("case", PREFIX_CASES)
def test_relay_observe_uses_shared_prefix_vectors(observe, case):
    row = observe.row(3010, "relay")
    root, value, expected = prefix_vector(Path(row["ExecutablePath"]), case)
    row["ExecutablePath"] = value
    actual = observe.run([row], root_override=root + "\\current")
    assert observe.prefix_counts[-1] > 0
    assert bool(actual["rows"]) is expected
    if expected:
        assert actual["rows"][0]["role"] == "relay"
        assert actual["rows"][0]["sid"] == observe.owner
