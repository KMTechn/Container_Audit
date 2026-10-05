"""The app-specific G exception admits one forward route pair and exact bytes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mutation', ('none', 'writer', 'source', 'guard', 'unguarded',
    'writer-kind', 'after-byte', 'unlisted-file', 'unlisted-case-file', 'unlisted-hidden-file', 'unlisted-change', 'outside-route',
    'reverse', 'extra-declared-route', 'extra-declared-edge', 'missing-entry'))
def test_forward_generation_exception_is_exact_and_closed(tmp_path, mutation):
    before = tmp_path/'before'
    after = tmp_path/'after'
    for tree in (before, after):
        (tree/'tools').mkdir(parents=True)
        (tree/'helper.py').write_bytes(b'# unchanged helper\n')
    (before/'main.py').write_bytes(b'# baseline entry\n')
    (after/'main.py').write_bytes(b'# guarded entry\n')
    (before/'portable-manifest.json').write_text(json.dumps({'source_commit':'ea566d131f37db3ee74468e1645c6b57ac45b6fa'}))
    old = json.loads(subprocess.check_output(['git','show','ea566d1:tools/container_writer_sink_inventory.json'],cwd=ROOT))
    # This predicate authorizes only the two original route changes.  The whole
    # assembly is admitted separately through exact approved release pairs.
    new = copy.deepcopy(old)
    new['inventory_sha256'] = hashlib.sha256(b'isolated two-route fixture').hexdigest()
    relay = next(route for route in new['known_route_coverage'] if route['route_id']=='persistent_relay')
    relay['reachable_sources'] = sorted(set(relay['reachable_sources']) | {'data_generation_marker'})
    relay['reachable_direct_mutation_functions'] = sorted(set(relay['reachable_direct_mutation_functions']) | {
        'data_generation_guard._runtime_release', 'kmtech_shared.data_generation.record_generation'})
    runner = next(route for route in new['known_route_coverage'] if route['route_id']=='raw_runner')
    runner['reachable_sources'] = [value for value in runner['reachable_sources']
        if value not in ('hosted_relay_failure', 'hosted_relay_json', 'hosted_relay_jsonl')]
    runner['reachable_direct_mutation_functions'] = [value for value in runner['reachable_direct_mutation_functions']
        if value not in ('container_audit_product_host._append_jsonl', 'container_audit_product_host._write_json_atomic')]
    replacements = []
    for route_id in ('persistent_relay','raw_runner'):
        old_route = next(route for route in old['known_route_coverage'] if route['route_id']==route_id)
        new_route = next(route for route in new['known_route_coverage'] if route['route_id']==route_id)
        fields = ('reachable_sources','reachable_direct_mutation_functions')
        replacements.append({'route_id':route_id,'before':{f:old_route[f] for f in fields},'after':{f:new_route[f] for f in fields}})
    declaration = {'schema_version':'container-audit-g-forward-transition-v1','direction':'forward',
        'before_source_commit':'ea566d131f37db3ee74468e1645c6b57ac45b6fa',
        'before_inventory_sha256':old['inventory_sha256'],'after_inventory_sha256':new['inventory_sha256'],
        'route_replacements':replacements, 'files':[
            {'path':name,'before':hashlib.sha256((before/name).read_bytes()).hexdigest(),
             'after':hashlib.sha256((after/name).read_bytes()).hexdigest()}
            for name in ('helper.py','main.py')]}
    if mutation=='writer': new['writer_sinks'][0]['function']='forged-writer'
    elif mutation=='source': new['writer_sink_sources'].append('forged-source')
    elif mutation=='guard': new['powershell_writer_sinks'][0]['guard_name']='forged-guard'
    elif mutation=='unguarded': new['powershell_writer_sinks'][0]['guarded']=False
    elif mutation=='writer-kind': new['powershell_writer_sinks'][0]['writer_site_kinds'].append('foreign-kind')
    elif mutation=='after-byte': (after/'main.py').write_bytes(b'# guarded entry!\n')
    elif mutation=='unlisted-file': (after/'extra.py').write_bytes(b'# undeclared addition\n')
    elif mutation=='unlisted-case-file': (after/'extra.PY').write_bytes(b'# undeclared case variant\n')
    elif mutation=='unlisted-hidden-file':
        import ctypes
        extra=after/'hidden.py'; extra.write_bytes(b'# undeclared hidden addition\n')
        assert ctypes.windll.kernel32.SetFileAttributesW(str(extra), 2)
    elif mutation=='unlisted-change': (after/'helper.py').write_bytes(b'# changed helper\n')
    elif mutation=='outside-route': new['known_route_coverage'][0]['reachable_sources'].append('foreign-route-edge')
    elif mutation=='reverse': before,after=after,before; old,new=new,old
    elif mutation=='extra-declared-route': declaration['route_replacements'].append(copy.deepcopy(replacements[0]))
    elif mutation=='extra-declared-edge':
        next(route for route in new['known_route_coverage'] if route['route_id']=='persistent_relay')['reachable_sources'].append('foreign-source')
        declaration['route_replacements'][0]['after']['reachable_sources'].append('foreign-source')
    elif mutation=='missing-entry': declaration['files'].pop()
    (after/'tools/container_data_generation_transition.json').write_text(json.dumps(declaration))
    old_path=tmp_path/'old.json'; old_path.write_text(json.dumps(old))
    new_path=tmp_path/'new.json'; new_path.write_text(json.dumps(new))
    script=tmp_path/'test.ps1'
    script.write_text(r'''
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parse errors' }
foreach ($name in @('Get-WriterInventorySemantics','Get-ContainerTransitionCodeFiles','Test-ContainerDataGenerationForwardTransition')) {
    $function=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    if ($function.Count -ne 1) { throw 'predicate mismatch' }
    Invoke-Expression $function[0].Extent.Text
}
$old=Get-Content -LiteralPath $args[3] -Raw | ConvertFrom-Json
$new=Get-Content -LiteralPath $args[4] -Raw | ConvertFrom-Json
Test-ContainerDataGenerationForwardTransition -BeforeRoot $args[1] -AfterRoot $args[2] -BeforeInventory $old -AfterInventory $new
''',encoding='utf-8')
    executable=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    completed=subprocess.run([str(executable),'-NoProfile','-NonInteractive','-File',str(script),
        str(ROOT/'INSTALL_CANONICAL_PORTABLE.ps1'),
        str(before),str(after),str(old_path),str(new_path)],capture_output=True,text=True,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    assert completed.returncode==0, completed.stderr[-1200:]
    assert completed.stdout.strip()==('True' if mutation=='none' else 'False')
