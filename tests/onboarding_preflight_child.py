"""Separate-process preflight regression with real G and isolated host adapters."""
from pathlib import Path
import hashlib
import json
import os
import sys

repo, root, case = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(repo))
for name, folder in [('LOCALAPPDATA','local'),('APPDATA','roaming'),('PROGRAMDATA','program')]:
    selected = root/folder
    selected.mkdir(parents=True,exist_ok=True)
    os.environ[name] = str(selected)
os.environ['CONTAINER_AUDIT_DATA_ROOT'] = str(root/'data')
os.environ['CONTAINER_AUDIT_WRITER_TEST_MODE'] = '1'
os.environ['CONTAINER_AUDIT_WRITER_CONTROL_ROOT'] = str(root/'control')

import storage_policy
storage_policy._persisted_data_root = lambda: None
from tools import register_container_audit_worker_pc as registration
registration._current_user_sid = lambda: 'S-1-5-21-272'
import current_user_onboarding as onboarding
import direct_sync_runtime as runtime
from kmtech_shared import data_generation as generation
from data_generation_guard import _runtime_release

paths = onboarding.resolve_current_user_onboarding_paths(repo)
paths.credential_path.parent.mkdir(parents=True,exist_ok=True)
secret_root = root/'nested'
secret_root.mkdir()
payload={'secret_ref':'dpapi:preflight','secret_data_dir':str(secret_root)}
if case == 'malformed':
    paths.credential_path.write_text('{',encoding='utf-8')
elif case == 'duplicate':
    paths.credential_path.write_text('{"secret_ref":"a","secret_ref":"b"}',encoding='utf-8')
else:
    paths.credential_path.write_text(json.dumps(payload),encoding='utf-8')
if case in {'nested-newer','nested-unknown','locator-newer','same'}:
    owner = paths.data_root if case == 'locator-newer' else secret_root
    marker=owner/'data-generation.json'
    if case == 'nested-unknown':
        marker.write_text('{}',encoding='utf-8')
    else:
        release=_runtime_release()
        if case != 'same':
            release.update(version='99.0.0',data_compatible_min_version='99.0.0')
        generation.record_generation(marker,app_id='container_audit',subject_sid=registration._current_user_sid(),**release)

reads={'protected':0,'registry':0,'network':0,'child':0,'writes':0}
def forbidden(*args,**kwargs):
    raise AssertionError('Host operation prohibited')
runtime._dpapi_unprotect_current_user = forbidden
runtime._read_wincred_secret = forbidden
import winreg
winreg.OpenKey = forbidden
import subprocess
native_popen = subprocess.Popen
def isolated_popen(argv,*args,**kwargs):
    if isinstance(argv,(list,tuple)) and argv and str(argv[0]).lower() in {'git','powershell.exe','pwsh.exe'}:
        return native_popen(argv,*args,**kwargs)
    return forbidden()
subprocess.Popen = isolated_popen

engine=sys.argv[4] if len(sys.argv)>4 else ''
if engine:
    packet=root/'packet'
    (packet/'app').mkdir(parents=True)
    # Only executable placement is adapted. The real product preparation/G runs
    # in a new interpreter; no generation or admission function is replaced.
    wrapper="""import sys
sys.path.insert(0, REPO)
import storage_policy
storage_policy._persisted_data_root=lambda: None
from tools import register_container_audit_worker_pc as registration
registration._current_user_sid=lambda: 'S-1-5-21-272'
import direct_sync_runtime as runtime
def forbidden(*args,**kwargs): raise AssertionError('Host API prohibited')
runtime._dpapi_unprotect_current_user=forbidden
runtime._read_wincred_secret=forbidden
import winreg
winreg.OpenKey=forbidden
from current_user_onboarding import onboarding_main
raise SystemExit(onboarding_main(sys.argv[2:]))
""".replace('REPO',repr(str(repo)))
    (packet/'app/main.py').write_text(wrapper,encoding='utf-8')
    def quote(value): return "'"+str(value).replace("'","''")+"'"
    script=f"""$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({quote(repo/'INSTALL_CANONICAL_PORTABLE.ps1')},[ref]$tokens,[ref]$errors)
if($errors.Count){{throw 'parse errors'}}
foreach($name in @('Arg','Get-CanonicalOnboardingInputBinding')){{
 $found=$ast.FindAll({{param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name}},$true)
 if($found.Count -ne 1){{throw 'preflight function unavailable'}}
 Invoke-Expression $found[0].Extent.Text
}}
$Script:PythonExe={quote(sys.executable)}
function Join-Path {{param($Path,$ChildPath)
 if($ChildPath -ceq 'runtime\\pythonw.exe'){{return $Script:PythonExe}}
 return Microsoft.PowerShell.Management\\Join-Path $Path $ChildPath
}}
try{{[void](Get-CanonicalOnboardingInputBinding {quote(packet)});'preflight_status=PASS'}}
catch{{'preflight_status=REFUSED'}}
"""
    ps_script=root/'preflight.ps1'
    ps_script.write_text(script,encoding='utf-8-sig')

def snapshot():
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}
before=snapshot()
status='FAILED'
code=None
binding=None
try:
    if engine:
        result=subprocess.run([engine,'-NoProfile','-NonInteractive','-File',str(ps_script)],
            capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        status='PASS' if result.returncode==0 and 'preflight_status=PASS' in result.stdout else 'REFUSED'
        code=(0 if status=='PASS' else 4) if result.returncode==0 else None
    elif case == 'binding-changed':
        binding=onboarding.preflight_current_user_onboarding(repo)
        payload['secret_data_dir']=str(root/'different')
        paths.credential_path.write_text(json.dumps(payload),encoding='utf-8')
        before=snapshot()
        try:
            onboarding.onboard_current_user(repo,expected_input_binding=binding,require_bootstrap_integrity=False)
        except onboarding.CurrentUserOnboardingError as exc:
            status=exc.status
            code=onboarding.ONBOARDING_EXIT_CODE
    else:
        code=onboarding.onboarding_main(['--app-root',str(repo),'--preflight-only'])
        status='PASS' if code==0 else 'REFUSED'
except (SystemExit,Exception) as exc:
    code=exc.code if isinstance(exc,SystemExit) else None
    status=type(exc).__name__
after=snapshot()
print(json.dumps({'status':status,'exit':code,'unchanged':before==after,
    'report_exists':paths.onboarding_report_path.exists(),'g_stubbed':False}))
