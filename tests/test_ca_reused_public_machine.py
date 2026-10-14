import pytest
import os
import json
import shutil
from pathlib import Path
from tests.test_administrator_installation_pending import test_machine_placement_existing_restore_and_removal_preserve_profiles as _machine


def prepare_managed_reused_task(source, installed, sid, library, helper):
    import auto_update
    configuration=Path(auto_update.__file__).resolve().parent/'update-manifest-key-config.json'
    shutil.copyfile(configuration,source/'app'/'update-manifest-key-config.json')
    task = auto_update.install_task_spec(installed, sid)
    task_xml = task['xml'].replace("'", "''")
    task_name = task['name'].replace("'", "''")
    scope = str(Path(os.environ['IWRUN_CONFIG']).resolve().parent).replace("'", "''")
    native = """
function Export-ScheduledTask {
    param([string]$TaskName,[string]$TaskPath)
    if($TaskName -cne 'TASK_NAME' -or $TaskPath -cne '\\'){throw 'Fixture task identity differs.'}
    return 'TASK_XML'
}
function Get-Acl {
    param([string]$LiteralPath,[string]$Path)
    $full=[IO.Path]::GetFullPath($(if($LiteralPath){$LiteralPath}else{$Path})).TrimEnd('\\')
    $scope='FIXTURE_SCOPE'
    if(-not $full.StartsWith($scope+'\\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture ACL read escaped its generated root.'}
    Assert-BootstrapNoReparsePoint $full -PathOnly
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    return $acl
}
function Get-BootstrapAclIdentity([string]$Path){
    $acl=Get-Acl -LiteralPath $Path
    $sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
    $sddl=$acl.GetSecurityDescriptorSddlForm($sections)
    return [pscustomobject]@{owner_sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;access_rules_protected=$acl.AreAccessRulesProtected;sddl=$sddl;sddl_sha256=Get-BootstrapStringSha256 $sddl}
}
""".replace('TASK_NAME',task_name).replace('TASK_XML',task_xml).replace('FIXTURE_SCOPE',scope)
    library.write_text(library.read_text(encoding='utf-8-sig')+native,encoding='utf-8',newline='\n')
    text=helper.read_text(encoding='utf-8-sig')
    condition='if(-not $testOverride -and -not $RestoreUninstallRecordPath -and -not $SupportedActiveVersionPlacement) {'
    assert text.count(condition)==1
    text=text.replace(condition,'if(-not $RestoreUninstallRecordPath -and -not $SupportedActiveVersionPlacement) {')
    # Only the native OS query boundary is substituted; the actual classifier runs.
    admission='if(-not $RestoreUninstallRecordPath -and -not $SupportedActiveVersionPlacement) {'
    text=text.replace(admission,native+'\n'+admission)
    target="$context=Get-ContainerSupportedInstallContext $sourceRootFull $installRootFull '자료와 등록 및 전송 대기를 보존하고 지원 제거를 먼저 실행한 뒤 다시 설치하세요.'"
    assert text.count(target)==1
    # The fixture runtime is a layout placeholder. Use the actual in-process
    # pinned classifier instead of launching that non-executable placeholder.
    text=text.replace(target,"$context=Get-BootstrapSupportedLifecycleContext (Split-Path -Parent $installRootFull) 'install'")
    helper.write_text(text,encoding='utf-8',newline='\n')
    commit=json.loads((source/'portable-manifest.json').read_text())['source_commit']
    control=installed.parent/'update-control';control.mkdir(exist_ok=True)
    for name,value in [('policy.json',{'schema':'container-audit-startup-update-policy-v1','operator_sid':sid}),
                       ('active.json',{'schema':auto_update.SCHEMA,'sha':commit}),
                       ('transition.json',{'schema':auto_update.SCHEMA,'phase':'CONFIRMED','candidate_sha':commit,'previous_sha':commit})]:
        (control/name).write_text(json.dumps(value),encoding='utf-8')


def materialize_active_version(installed):
    commit=json.loads((installed/'portable-manifest.json').read_text())['source_commit']
    active=installed.parent/'versions'/commit
    shutil.copytree(installed,active)
    # A relocated integrity record keeps the declared code root of the copy.
    record=active/'bootstrap-integrity.json';value=json.loads(record.read_text(encoding='utf-8-sig'))
    value['code_root']=str(active)
    record.write_text(json.dumps(value),encoding='utf-8')


def inject_evidence_fault(canonical,fault):
    target='$reused=Read-CanonicalReusedPlacementEvidence $binding $Source $Root $Manifest $run'
    text=canonical.read_text(encoding='utf-8-sig');assert text.count(target)==1
    mutation={
        'missing':"[IO.File]::Delete($proofPath)",
        'run':"$proof.run_id=('f'*32);[IO.File]::WriteAllText($proofPath,($proof|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))",
        'manifest':"$proof.installed_manifest_sha256=('f'*64);[IO.File]::WriteAllText($proofPath,($proof|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))",
    }[fault]
    injection="$proofPath=Read-CanonicalHelperArtifact $binding 'reused-evidence.json' 'REUSED_EVIDENCE_READY';$proof=Get-Content -LiteralPath $proofPath -Raw|ConvertFrom-Json;"+mutation+"\n                    "
    canonical.write_text(text.replace(target,injection+target),encoding='utf-8',newline='\n')


@pytest.mark.parametrize('engine', ('powershell', 'pwsh'))
def test_actual_public_machine_reused_completion(tmp_path, engine):
    tmp_path = Path(os.environ['IWRUN_CONFIG']).resolve().parent / 'n' / ('5' if engine == 'powershell' else '7')
    tmp_path.mkdir(parents=True)
    _machine(tmp_path, engine, 'reused')


@pytest.mark.parametrize('proof_fault',('missing','run','manifest'))
def test_actual_public_machine_rejects_unbound_reused_evidence(tmp_path,proof_fault):
    tmp_path=Path(os.environ['IWRUN_CONFIG']).resolve().parent/'n'/proof_fault
    tmp_path.mkdir(parents=True)
    _machine(tmp_path,'pwsh','reused',proof_fault=proof_fault)
