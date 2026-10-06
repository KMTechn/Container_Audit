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
target_root=None
if case.startswith('restore-'):
    target_root=root/'old-target'
    (target_root/'app').mkdir(parents=True)
    (target_root/'runtime').mkdir()
    (target_root/'app/Container_Audit.py').write_text('CURRENT_VERSION = "v2.0.98"\n',encoding='utf-8')
    (target_root/'app/main.py').write_text('# isolated metadata-only target\n',encoding='utf-8')
    (target_root/'runtime/pythonw.exe').write_bytes(b'isolated target is never executed')
    manifest={'schema':onboarding.PORTABLE_MANIFEST_VERSION,'entrypoint':'runtime/pythonw.exe app/main.py',
        'source_commit':'1'*40,'source_tree':'2'*40,'version':'v2.0.98'}
    (target_root/'portable-manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
    files=[]
    for name in ('app/Container_Audit.py','app/main.py','runtime/pythonw.exe','portable-manifest.json'):
        raw=(target_root/name).read_bytes()
        files.append({'path':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    aggregate=hashlib.sha256(''.join(f"{f['sha256']} {f['size']} {f['path']}\n" for f in files).encode()).hexdigest()
    record={'schema_version':onboarding.BOOTSTRAP_INTEGRITY_VERSION,'status':'PASS','code_root':'.',
        'file_count':len(files),'files':files,'aggregate_sha256':aggregate}
    (target_root/'bootstrap-integrity.json').write_text(json.dumps(record),encoding='utf-8')
    for name in ('current-app.txt','old-run.txt','old-task.txt','old-relay.txt','existing-fence.txt'):
        (root/name).write_text('preserved synthetic current state',encoding='utf-8')
    if case=='restore-bootstrap-tampered':
        record['file_count']+=1
        (target_root/'bootstrap-integrity.json').write_text(json.dumps(record),encoding='utf-8')
    elif case=='restore-manifest-tampered':
        (target_root/'portable-manifest.json').write_text('{}',encoding='utf-8')
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
if case in {'restore-newer','restore-locator-newer','restore-same','restore-unknown'}:
    marker=(paths.data_root if case=='restore-locator-newer' else secret_root)/'data-generation.json'
    if case=='restore-unknown':
        marker.write_text('{}',encoding='utf-8')
    else:
        release=_runtime_release()
        if case=='restore-same':
            release.update(version='v2.0.98',data_compatible_min_version='v2.0.98',build_id='1'*40)
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
sys.path.extend(DEPENDENCIES)
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
""".replace('REPO',repr(str(repo))).replace('DEPENDENCIES',repr([p for p in sys.path if 'site-packages' in Path(p).parts and Path(p).is_dir()])).replace('{{','{').replace('}}','}')
    (packet/'app/main.py').write_text(wrapper,encoding='utf-8')
    def quote(value): return "'"+str(value).replace("'","''")+"'"
    script=f"""$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({quote(repo/'INSTALL_CANONICAL_PORTABLE.ps1')},[ref]$tokens,[ref]$errors)
if($errors.Count){{throw 'parse errors'}}
foreach($name in @('Write-CanonicalInstallationPublicRecord','Full','Arg','ConvertTo-CanonicalSafeDiagnostic','Get-CanonicalOnboardingInputBinding','Write-CanonicalPreparationAdmissionFailure','Invoke-ContainerSourceDataAdmission','Get-CanonicalFailureDetails','Assert-CanonicalRestoreCodeBinding','Exit-RetirementResumeClaim')){{
 $found=$ast.FindAll({{param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name}},$true)
 if($found.Count -ne 1){{throw 'preflight function unavailable'}}
 Invoke-Expression $found[0].Extent.Text
}}
$Script:PythonExe={quote(sys.executable)}
function Join-Path {{param($Path,$ChildPath)
 if($ChildPath -ceq 'runtime\\python.exe'){{return $Script:PythonExe}}
 return Microsoft.PowerShell.Management\\Join-Path $Path $ChildPath
}}
. {quote(repo/'tools/bootstrap_integrity.ps1')}
. {quote(repo/'tools/container_writer_fence.ps1')}
. (Get-BootstrapSharedPortableLeaf {quote(repo)})
function Read-ContainerWriterFence {{param([switch]$AllowAbsent) return $null}}
function Abort-ContainerWriterFence {{throw 'unexpected fence mutation'}}
function Remove-Item {{throw 'unexpected cleanup'}}
function StartRaw {{throw 'unexpected relay change'}}
$mainCandidates=@($ast.FindAll({{param($n)
 $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and
 $n.Finally.Extent.Text -match 'Exit-ContainerWriterSessionAuthority' -and
 @($n.Body.Statements|Where-Object {{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and
   $_.Left.Extent.Text -ceq '$canonicalWriterFencePreparedReceipt' -and
   $_.Extent.Text -match 'New-CanonicalWriterFencePreparedReceipt'}}).Count -eq 1
}},$true))
if($mainCandidates.Count -ne 1){{throw 'TEST_MAIN_PLACEMENT_BLOCK_NOT_UNIQUE'}}
$mainTry=$mainCandidates[0]
$receipts=@($mainTry.Body.Statements|Where-Object {{$_ -is [Management.Automation.Language.AssignmentStatementAst] -and
 $_.Left.Extent.Text -ceq '$canonicalWriterFencePreparedReceipt' -and $_.Extent.Text -match 'New-CanonicalWriterFencePreparedReceipt'}})
if($receipts.Count -ne 1){{throw 'TEST_PREPARED_RECEIPT_STATEMENT_NOT_UNIQUE'}}
$receipt=$receipts[0]
$prefix=(@($mainTry.Body.Statements|Where-Object {{$_.Extent.StartOffset -lt $receipt.Extent.StartOffset}})|ForEach-Object {{$_.Extent.Text}})-join "`n"
# Match the no-recovery state initialized before the product's placement try.
$enteredPlacementTry=$false;$canonicalWriterFenceActive=$false;$audit=$null;$retirementResume=$null;$retirementResumeClaim=$null
$legacyRelayPreimage=$null;$legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$false
$continuationOldClaim=$null;$original=$null
$rollbackContinuation=$null;$abandonedPending=$null
$canonicalWriterFenceAuthority=$null;$canonicalWriterFenceEnvironmentNames=@()
$rollbackContinuation=$null;$continuationOldClaim=$null;$abandonedPending=$null;$original=$null
$legacyRelayRestoreNeeded=$false;$legacyRelayRestoreAttempted=$false;$legacyRelayPreimage=$null
$canonicalWriterFencePreparedPath={quote(root/'no-receipt.json')}
$Script:CanonicalPreparationAdmissionFailed=$false;$Script:CanonicalInstallerSourceInventorySha256=''
$auditPath={quote(root.parent/'preflight-admission-audit.json')};$evidenceFull={quote(root.parent/'preflight-admission-evidence.json')}
$source={quote(packet)};$install={quote(root/'existing-code')};$old=@()
$Uninstall=$false;$CompleteRetiredRemoval=$false;$RestoreVerifiedReplacement={'$true' if target_root is not None else '$false'}
$publicRestore=@{{state='PENDING';receipt=@{{rollback_root={quote(target_root or root/'unused')};old=@{{source_commit='1'*40;aggregate_sha256={quote(('0'*64 if case=='restore-code-binding-wrong' else aggregate) if target_root is not None else '')};manifest_sha256={quote(hashlib.sha256(json.dumps(manifest).encode()).hexdigest() if target_root is not None else '')}}}}}}}
$Script:CanonicalWriterFenceSessionId='a'*32;$Script:CanonicalWriterFenceAttemptId='b'*32
$canonicalWriterFenceOrchestratorSha256='c'*64;$Script:CanonicalWriterFenceTransactionId='d'*32
$canonicalWriterFenceContractSha256='e'*64
$earlyCatch=@($mainTry.CatchClauses[0].Body.Statements|Where-Object {{$_.Extent.Text -match '^if \(-not \$enteredPlacementTry\)'}})[0].Extent.Text
try{{
 $ErrorActionPreference='Continue'
 try{{Invoke-Expression $prefix;'preflight_status=PASS'}}
 catch{{
  $original=$_
  $nativeErrors=@(@($Error)|ForEach-Object {{@{{type=$_.Exception.GetType().Name;message=(ConvertTo-CanonicalSafeDiagnostic ([string]$_.Exception.Message))}}}})
  [System.IO.File]::WriteAllText({quote(root.parent/'powershell.native-errors.json')},(ConvertTo-Json -InputObject $nativeErrors))
  $failure=@{{type=$original.Exception.GetType().Name;message=(ConvertTo-CanonicalSafeDiagnostic ([string]$original.Exception.Message));script_stack=[string]$original.ScriptStackTrace}}
  [System.IO.File]::WriteAllText({quote(root.parent/'powershell.preflight.exception.json')},($failure|ConvertTo-Json))
  Invoke-Expression $earlyCatch}}
 finally{{Invoke-Expression (($mainTry.Finally.Statements|ForEach-Object {{$_.Extent.Text}})-join "`n")}}
}}
catch{{
 $failure=@{{type=$_.Exception.GetType().Name;message=(ConvertTo-CanonicalSafeDiagnostic ([string]$_.Exception.Message));script_stack=[string]$_.ScriptStackTrace}}
 [System.IO.File]::WriteAllText({quote(root.parent/'powershell.exception.json')},($failure|ConvertTo-Json))
 'preflight_status=REFUSED'
}}
$released=$false
try{{
 $again=Enter-ContainerWriterSessionAuthority -SessionId $Script:CanonicalWriterFenceSessionId -AttemptId $Script:CanonicalWriterFenceAttemptId -OrchestratorSha256 $canonicalWriterFenceOrchestratorSha256 -ReplacementTransactionId $Script:CanonicalWriterFenceTransactionId -WriterContractSha256 $canonicalWriterFenceContractSha256
 Exit-ContainerWriterSessionAuthority $again
 $admission=Enter-ContainerWriterAdmission
 Exit-ContainerWriterAdmission $admission
 $released=$true
}}catch{{}}
if($released){{'preflight_authority_released=true'}}else{{'preflight_authority_released=false'}}
"""
    ps_script=root/'preflight.ps1'
    ps_script.write_text(script,encoding='utf-8-sig')

def snapshot():
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}
if case in {"bootstrap-same", "bootstrap-changed"}:
    paths.bootstrap_tls_ca_bundle_path.parent.mkdir(parents=True, exist_ok=True)
    paths.bootstrap_tls_ca_bundle_path.write_bytes(b"isolated public CA bytes")
    installed_app = root / "installed-app"
    installed_app.mkdir()
    original_binding = onboarding.preflight_current_user_onboarding(repo)
    installed_binding = onboarding.preflight_current_user_onboarding(installed_app)
    if case == "bootstrap-changed":
        paths.bootstrap_tls_ca_bundle_path.write_bytes(b"isolated public CA bytez")
    before = snapshot()
    reached = []
    class BindingAcceptedBeforeWriter(BaseException):
        pass
    def writer_cutoff(*args, **kwargs):
        reached.append(True)
        raise BindingAcceptedBeforeWriter
    onboarding.writer_admission = writer_cutoff
    try:
        onboarding.onboard_current_user(installed_app, expected_input_binding=original_binding)
        raise AssertionError("writer cutoff missing")
    except BindingAcceptedBeforeWriter:
        code, status = 0, "ALLOWED_BEFORE_WRITER"
    except onboarding.CurrentUserOnboardingError as exc:
        code, status = 4, exc.status
    after = snapshot()
    print(json.dumps({"code": code, "status": status,
        "same_input_binding": original_binding == installed_binding,
        "changed_file_count": len([p for p in before.keys() | after.keys() if before.get(p) != after.get(p)]),
        "admission_cutoff_reached": bool(reached)}))
    raise SystemExit(0)

before=snapshot()
status='FAILED'
code=None
binding=None
authority_released=None
try:
    if engine:
        result=subprocess.run([engine,'-NoProfile','-NonInteractive','-File',str(ps_script)],
            capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        from tools.direct_sync_relay_install_pack import _redact_install_diagnostic
        (root.parent/'powershell.stdout.txt').write_text(
            _redact_install_diagnostic(result.stdout),encoding='utf-8')
        (root.parent/'powershell.stderr.txt').write_text(
            _redact_install_diagnostic(result.stderr),encoding='utf-8')
        status='PASS' if result.returncode==0 and 'preflight_status=PASS' in result.stdout else 'REFUSED'
        code=(0 if status=='PASS' else 4) if result.returncode==0 else None
        authority_released='preflight_authority_released=true' in result.stdout
    elif case=='restore-api-none-denied':
        try:
            onboarding._read_replacement_tree_identity(target_root,target_root,acl_identity_reader=None)
            status='UNEXPECTED_ALLOWED'
            code=0
        except ValueError:
            status='DENIED'
            code=4
    elif target_root is not None:
        code=onboarding.onboarding_main(['--app-root',str(repo),'--preflight-only','--target-release-root',str(target_root)])
        status='PASS' if code==0 else 'REFUSED'
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
    'report_exists':paths.onboarding_report_path.exists(),'g_stubbed':False,
    'authority_released':authority_released}))
