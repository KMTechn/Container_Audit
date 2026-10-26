"""Content ownership and restart convergence on disposable real NTFS trees.

Process census, Task Scheduler and protected JSON ACLs are injected; file
hashes, locks, reparse boundaries and individual moves use Windows itself.
"""
import hashlib
import json
import os
from pathlib import Path
import uuid

import pytest
from tests.powershell_contracts import run_functions
from tests.test_official_legacy_relay_identity import XML_SETUP

REPO = Path(__file__).resolve().parents[1]
NAMES = ['Test-SamePath', 'Get-ContainerRemovalIoPath',
         'Assert-ContainerRemovalBoundary', 'Assert-ContainerRemovalQuiescent',
         'Resolve-ContainerRemovalTaskSid', 'Get-ContainerRemovalTaskNames', 'Remove-ContainerScheduledTasks',
         'Test-ContainerRemovalFile', 'Get-ContainerArtifactFilePlan',
         'Get-ContainerRemovalArtifacts', 'Remove-ContainerEmptiedParents',
         'Invoke-ContainerConvergentRemoval']

DRIVER = r'''
. $env:CA_REMOVAL_LIBRARY
$root=$env:CA_REMOVAL_ROOT;$testOverride=$true;$script:cut=$env:CA_REMOVAL_CUT
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public class RemovalTask {
 public string Name; public string RawXml; public bool Enabled=true;
 public string Xml {get{return RawXml.Replace("<Enabled>true</Enabled>",Enabled?"<Enabled>true</Enabled>":"<Enabled>false</Enabled>");}}
 public RemovalTask(string name,string xml){Name=name;RawXml=xml;}
 public string GetSecurityDescriptor(int flags){return "fixture-sddl";} public void Stop(int flags){}
}
public class RemovalFolder {
 public string LegacyXml="";
 public HashSet<string> Tasks=new HashSet<string>{"direct-sync-relay-container-audit","container-audit-isolated-qualification-authority"};
 public Dictionary<string,RemovalTask> Definitions=new Dictionary<string,RemovalTask>();
 public object[] GetTasks(int flags){return new object[0];}
 public RemovalTask GetTask(string name){
   if(!Tasks.Contains(name))throw new COMException("absent",unchecked((int)0x80070002));
   if(!Definitions.ContainsKey(name))Definitions[name]=new RemovalTask(name,name=="direct-sync-relay-container-audit"?LegacyXml:"<Task><Fixture/></Task>");
   return Definitions[name];
 }
 public void DeleteTask(string name,int flags){Tasks.Remove(name);Definitions.Remove(name);}
 public RemovalTask RegisterTask(string name,string xml,int flags,string user,object password,int logon,string sddl){
   Tasks.Add(name);Definitions[name]=new RemovalTask(name,xml);return Definitions[name];
 }
}
'@
$folder=[RemovalFolder]::new()
function Get-CimInstance {
 if($env:CA_REMOVAL_CUT -ceq 'process-unknown'){return @()}
 if($env:CA_REMOVAL_CUT -ceq 'process-live'){return [pscustomobject]@{ProcessId=2147483646;ExecutablePath=(Join-Path $root 'versions\x\runtime\python.exe');CommandLine='fixture'}}
 return [pscustomobject]@{ProcessId=$PID;ExecutablePath='fixture';CommandLine='fixture'}
}
function Write-ContainerStartupUpdateRecord {
 param([string]$Path,$Payload)
 [IO.File]::WriteAllText($Path,($Payload|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}
function Move-Item {
 [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
 if($script:cut -ceq 'metadata-before' -and (Split-Path -Leaf $LiteralPath) -ceq 'bootstrap-integrity.json'){throw 'injected before metadata'}
 Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
 if((Split-Path -Leaf $LiteralPath) -ceq $script:cut){throw 'injected after rename'}
}
$locked=$null
if($script:cut -cin @('lock-none','lock-read')){
 $share=if($script:cut -ceq 'lock-none'){[IO.FileShare]::None}else{[IO.FileShare]::Read}
 $locked=[IO.File]::Open((Join-Path $root 'current\owned.bin'),[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
}
$errorCode=''
try { [void](Invoke-ContainerConvergentRemoval (Join-Path $root 'current') $folder) }
catch { $errorCode=$_.Exception.Message; if(-not $script:cut){throw} }
if($null -ne $locked){$locked.Dispose()}
[IO.File]::WriteAllText((Join-Path $root 'first-result.json'),($errorCode|ConvertTo-Json))
$script:cut='';$env:CA_REMOVAL_CUT=''
[void](Invoke-ContainerConvergentRemoval (Join-Path $root 'current') $folder)
[void](Invoke-ContainerConvergentRemoval (Join-Path $root 'current') $folder)
if($folder.Tasks.Count -ne 1 -or -not $folder.Tasks.Contains('direct-sync-relay-container-audit') -or $folder.GetTask('direct-sync-relay-container-audit').Enabled){throw 'owned startup absence and credential-preserving legacy disable not proven'}
'PASS'
'''


# Use the real source-owned legacy XML; the native folder retains its credentials.
DRIVER = DRIVER.replace('$folder=[RemovalFolder]::new()', XML_SETUP + '\n$folder=[RemovalFolder]::new();$folder.LegacyXml=$xml')


def setup_tree():
    root = Path(os.environ['CA_NTFS_TEST_ROOT']) / uuid.uuid4().hex[:8]
    current = root / 'current'; current.mkdir(parents=True)
    originals = {}
    for name, data in [('owned.bin', b'product code'), ('nested/second.bin', b'other code'), ('portable-manifest.json', b'{"source_commit":"fixture"}')]:
        path = current / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        originals[path] = data
    rows = [dict(path=p.relative_to(current).as_posix(), size=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for p, raw in originals.items()]
    record = current / 'bootstrap-integrity.json'
    record.write_text(json.dumps(dict(schema_version='container-audit-bootstrap-integrity-v1', status='PASS', files=rows)), encoding='utf-8')
    originals[record] = record.read_bytes()
    return root, originals


def remove(root, tmp_path, engine, cut=''):
    source = Path(os.environ.get('CA_CONVERGENT_SOURCE', str(REPO / 'INSTALL_THIS_PC.ps1')))
    result = run_functions(tmp_path, source, NAMES, DRIVER, engine=engine,
                           values=dict(CA_REMOVAL_ROOT=str(root), CA_REMOVAL_CUT=cut,
                                       CA_REMOVAL_LIBRARY=str(REPO / 'tools/bootstrap_integrity.ps1')))
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((root / 'removed.json').read_text()), json.loads((root / 'first-result.json').read_text())


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('cut', ['', 'owned.bin', 'second.bin', 'metadata-before', 'bootstrap-integrity.json', 'lock-none', 'lock-read', 'process-live', 'process-unknown'])
def test_owned_code_individual_moves_restart_and_real_lock_convergence(tmp_path, engine, cut):
    root, originals = setup_tree()
    sentinel = root / 'business/ledger.bin'; sentinel.parent.mkdir(); sentinel.write_bytes(b'quantity=7;membership=3;ACK=UNKNOWN')
    marker, first_error = remove(root, tmp_path, engine, cut)
    assert marker['lifecycle_state'] == 'REMOVED'
    assert not (root / 'current').exists()
    assert sentinel.read_bytes() == b'quantity=7;membership=3;ACK=UNKNOWN'
    for path, raw in originals.items():
        archives = list((root / 'removal-evidence').glob('*/' + path.relative_to(root).as_posix()))
        assert len(archives) == 1 and archives[0].read_bytes() == raw
    if cut in ('lock-none', 'lock-read', 'process-live', 'process-unknown'):
        assert first_error, 'unknown/live/locked input must fail before REMOVED'


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
@pytest.mark.parametrize('variant', ['different-content', 'unlisted', 'inventory-absent', 'inventory-malformed', 'inventory-directory'])
def test_foreign_material_and_unreadable_inventory_stay_at_original_paths(tmp_path, engine, variant):
    root, originals = setup_tree()
    current = root / 'current'
    if variant == 'different-content':
        preserved = current / 'owned.bin'; preserved.write_bytes(b'not product code')
    elif variant == 'unlisted':
        preserved = current / 'user-data.bin'; preserved.write_bytes(b'original user material')
    else:
        record = current / 'bootstrap-integrity.json'; record.unlink()
        if variant == 'inventory-malformed': record.write_bytes(b'{truncated')
        elif variant == 'inventory-directory': record.mkdir()
        preserved = current / 'owned.bin'
    raw = preserved.read_bytes()
    marker, _ = remove(root, tmp_path, engine)
    assert preserved.read_bytes() == raw
    assert str(current) in marker['retained_paths']
    if variant.startswith('inventory-'):
        assert all(p.read_bytes() == data for p, data in originals.items() if p.name != 'bootstrap-integrity.json')


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_external_junction_is_retained_without_touching_target(tmp_path, engine):
    root, _ = setup_tree()
    outside = root / 'outside'; outside.mkdir(); original = outside / 'original.bin'; original.write_bytes(b'untouched')
    link = root / 'current/redirect'
    from tests.powershell_contracts import run_powershell
    result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                            f"New-Item -ItemType Junction -Path '{str(link).replace(chr(39), chr(39)*2)}' -Target '{str(outside).replace(chr(39), chr(39)*2)}' | Out-Null"])
    assert result.returncode == 0
    marker, _ = remove(root, tmp_path, engine)
    assert link.is_junction() and original.read_bytes() == b'untouched'
    assert str(root / 'current') in marker['retained_paths']
