"""One installed release binds all deployed G preimages, never mixed files."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest
from tests.powershell_contracts import run_functions

ROOT=Path(__file__).resolve().parents[1]
NON_DEPLOYED=(
    'tools/active_work_probe.py', 'tools/build_operator_review_case_report.py',
    'tools/build_portable_release_candidate.py', 'tools/check_logistics_runtime_profile.py',
    'tools/direct_sync_relay_install_pack.py', 'tools/install_protected_admin.py',
)
EA='ea566d131f37db3ee74468e1645c6b57ac45b6fa'
INSTALLED='8928228c0c85109bd5d184f9507d6d9b670c93fd'


def assert_undeployed_tools_absent(table, stock_names):
    paths={row['path'] for row in table['files']}
    assert len(paths)==871
    for source in NON_DEPLOYED:
        assert source not in paths and 'app/'+source not in paths, source
        assert source not in stock_names and 'app/'+source not in stock_names, source


@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
@pytest.mark.parametrize('mutation', ('ea','892','byte','mixed','ea-absent','892-present',
    'inventory','commit','reverse','after-byte','same-build'))
def test_installed_release_exact_pair_binds_complete_preimages(tmp_path, engine, mutation):
    declaration=json.loads((ROOT/'tools/container_data_generation_transition.json').read_bytes())
    releases={row['source_commit']:row for row in declaration['installed_release_preimages']}
    assert set(releases)=={EA,INSTALLED}
    assert all(len(row['files'])==21 for row in releases.values())
    before=tmp_path/'before';after=tmp_path/'after'
    before.mkdir();after.mkdir()
    selected=EA if mutation in ('ea','ea-absent') else INSTALLED
    source_map={f['path']:e['path'] for e in declaration['source_replacements'] for f in declaration['files']
                if f['path'] in (e['path'],'app/'+e['path'])}
    assert len(source_map)==21
    for entry in releases[selected]['files']:
        relative=entry['path']; target=before/relative
        if 'absent' not in entry:
            contents=subprocess.check_output(['git','show',selected+':'+source_map[relative]],cwd=ROOT,
                creationflags=subprocess.CREATE_NO_WINDOW)
            assert b'\r\n' not in contents
            if hashlib.sha256(contents).hexdigest()!=entry['sha256']:
                # EA's real stock was CRLF. Reconstruct only the one declared
                # exact preimage; admission accepts no line-ending alternative.
                assert selected==EA
                contents=contents.replace(b'\n',b'\r\n')
            assert hashlib.sha256(contents).hexdigest()==entry['sha256']
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(contents)
        target=after/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/source_map[relative]).read_bytes())
    (after/'tools').mkdir(exist_ok=True)
    (after/'tools/container_data_generation_transition.json').write_bytes(
        (ROOT/'tools/container_data_generation_transition.json').read_bytes())
    changed=next(e['path'] for e in releases[INSTALLED]['files'] if 'sha256' in e and
        e['sha256']!=next(f['sha256'] for f in releases[EA]['files'] if f['path']==e['path']))
    guard='app/data_generation_guard.py'
    if mutation=='byte': (before/changed).write_bytes((before/changed).read_bytes()+b'!')
    elif mutation=='mixed':
        contents=subprocess.check_output(['git','show',EA+':'+source_map[changed]],cwd=ROOT,
            creationflags=subprocess.CREATE_NO_WINDOW)
        expected=next(e['sha256'] for e in releases[EA]['files'] if e['path']==changed)
        if hashlib.sha256(contents).hexdigest()!=expected:contents=contents.replace(b'\n',b'\r\n')
        assert hashlib.sha256(contents).hexdigest()==expected
        (before/changed).write_bytes(contents)
    elif mutation=='ea-absent': (before/guard).unlink()
    elif mutation=='892-present': (before/guard).write_bytes((after/guard).read_bytes())
    elif mutation=='after-byte': (after/changed).write_bytes((after/changed).read_bytes()+b'!')
    final_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,
        creationflags=subprocess.CREATE_NO_WINDOW).decode().strip()
    old={'source_commit':selected,'writer_sink_inventory_contract_sha256':releases[selected]['writer_inventory_sha256']}
    new={'source_commit':final_commit,'writer_sink_inventory_contract_sha256':declaration['after_inventory_sha256']}
    pin={'from_commit':old['source_commit'],'to_commit':new['source_commit'],
         'from_contract_sha256':old['writer_sink_inventory_contract_sha256'],
         'to_contract_sha256':new['writer_sink_inventory_contract_sha256']}
    (after/'app/auto-update-settings.json').write_text(json.dumps({'approved_transitions':[pin]}),encoding='utf-8')
    if mutation=='inventory': old['writer_sink_inventory_contract_sha256']='1'*64
    elif mutation=='commit': old['source_commit']='1'*40
    elif mutation=='reverse': before,after=after,before;old,new=new,old
    elif mutation=='same-build': new['source_commit']='9'*40
    for name,value in (('old',old),('new',new)):
        (tmp_path/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',[
        'Test-ExactPropertySet','Test-ExactApprovedWriterTransition','Test-InstalledReleasePreimages',
        'Test-ExactApprovedInstalledWriterTransition','Sha'],r'''
$old=Get-Content -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'old.json') -Raw|ConvertFrom-Json
$new=Get-Content -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'new.json') -Raw|ConvertFrom-Json
Test-ExactApprovedInstalledWriterTransition $old $new $env:CA_G_AFTER $env:CA_G_BEFORE
''',engine=engine,values={'CA_G_AFTER':str(after),'CA_G_BEFORE':str(before)})
    assert result.returncode==0,'actual forward pair probe failed; private diagnostics retained'
    assert result.stdout.strip()==('True' if mutation in ('ea','892') else 'False')


def test_non_deployed_g_tools_fail_if_added_to_stock(tmp_path):
    from tools import build_portable_release_candidate as builder
    stock=tmp_path/'stock'
    builder._copy_application(ROOT,stock/'app')
    for source,relative in builder.PORTABLE_INSTALL_ASSETS:
        target=stock/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/source,target)
    archive=tmp_path/'application-scope.zip'
    with zipfile.ZipFile(archive,'w') as output:
        for path in stock.rglob('*'):
            if path.is_file():output.write(path,path.relative_to(stock).as_posix())
    with zipfile.ZipFile(archive) as package:
        assert_undeployed_tools_absent(json.loads((ROOT/'tools/container_data_generation_transition.json').read_bytes()),set(package.namelist()))
