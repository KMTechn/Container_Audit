"""Execute checked-in workflow run blocks against owned Git/GitHub boundaries."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[1]
TAG = 'v1.0.0'
COMMIT = '1'*40
TREE = '2'*40
TAG_OBJECT = '3'*40
# Independent release-contract oracle; never derive it from the workflow or builder.
CONTRACT_SHA = 'c4f5d00b0fcfa22be2b8f284d9fd57c4b4979085f6030548111c835dd3ad7b7c'
WAIT = 'Wait boundedly for finalized immutable frozen prerelease'
FINAL = 'Finally revalidate remote tag main and frozen prerelease'


def workflow_step(name):
    # Parse this repository's named steps, literal run blocks and plain env
    # scalars. Resolve only the two GitHub context inputs supplied by this fixture;
    # checked-in configuration values must reach the child unchanged.
    lines=(ROOT/'.github/workflows/release.yml').read_text(encoding='utf-8').splitlines()
    marker='      - name: '+name
    assert lines.count(marker)==1
    start=lines.index(marker)+1
    end=next((i for i in range(start,len(lines)) if lines[i].startswith('      - name: ')),len(lines))
    run=next(i for i in range(start,end) if lines[i].startswith('        run:'))
    assert lines[run]=='        run: |', 'workflow contract requires an executable literal run block'
    environment={}
    header=lines[start:run]
    if '        env:' in header:
        for line in header[header.index('        env:')+1:]:
            if not line.startswith('          '):break
            key,value=line.strip().split(':',1)
            value=value.strip()
            value={'${{ github.token }}':'contract-only','${{ github.ref_name }}':TAG}.get(value,value)
            assert re.fullmatch(r'[A-Z][A-Z0-9_]*',key) and key not in environment
            assert re.fullmatch(r'[A-Za-z0-9_.-]+',value), 'unsupported workflow env scalar: '+key
            environment[key]=value
    block=lines[run+1:end]
    assert all(not line.strip() or line.startswith('          ') for line in block)
    return textwrap.dedent('\n'.join(block)).replace('${{ github.ref_name }}',TAG)+'\n',environment


def release_fixture():
    zip_name=f'Container_Audit-{TAG}.zip'
    payloads={zip_name:b'owned frozen artifact bytes',zip_name+'.sha256':b'owned checksum bytes'}
    assets=[{'id':10+i,'name':name,'state':'uploaded','size':len(data),
             'digest':'sha256:'+hashlib.sha256(data).hexdigest()} for i,(name,data) in enumerate(payloads.items())]
    body='\n'.join(['Internal prerelease; not production-ready.',f'Tag: {TAG}',f'Commit: {COMMIT}',f'Tree: {TREE}',
        f'Artifact: {zip_name}',f'Artifact-SHA256: {assets[0]["digest"][7:]}',f'Artifact-Size: {assets[0]["size"]}',
        'Main-EXE-SHA256: '+'4'*64,f'Factory-Contract-SHA256: {CONTRACT_SHA}',
        'Hosted-CI-Release-Gate: WAIVED_NOT_TESTED','Status: QUARANTINED_PENDING_FACTORY_QUALIFICATION'])
    return {'id':7,'tag_name':TAG,'name':f'Release {TAG}','body':body,'target_commitish':COMMIT,
            'draft':False,'prerelease':True,'immutable':True,'assets':assets},payloads


class WorkflowHarness:
    def __init__(self, root):
        self.root=root
        self.release,self.payloads=release_fixture()
        self.env=dict(os.environ,RELEASE_TAG=TAG,GITHUB_REF_NAME=TAG,RELEASE_TAG_COMMIT_SHA=COMMIT,
            RELEASE_TAG_OBJECT_SHA=TAG_OBJECT,GITHUB_REPOSITORY='contract/owned',RUNNER_TEMP=str(root),
            GITHUB_ENV=str(root/'github.env'),GITHUB_STEP_SUMMARY=str(root/'summary.md'),
            GH_TOKEN='contract-only',GITHUB_TOKEN='contract-only')
        self.env.pop('FACTORY_CONTRACT_SHA256',None)
        self.step=0

    def run(self, name, *, release=None, missing_before=0, main_commit=COMMIT, ref_sha=TAG_OBJECT, peel=COMMIT,
            corrupt_download=False, workflow_runs=None, head_commit=COMMIT, tag_type='tag', fetch_failure=False,
            parser_identity=None, parser_failure=False):
        executable=shutil.which('pwsh')
        if not executable:pytest.skip('PowerShell 7 is required for native workflow execution')
        self.step+=1
        prefix=self.root/f'step-{self.step}'
        run_source,step_environment=workflow_step(name)
        source=prefix.with_suffix('.source.ps1');source.write_text(run_source,encoding='utf-8')
        data={'release':self.release if release is None else release,'missing_before':missing_before,
              'main_commit':main_commit,'tree':TREE,'ref_sha':ref_sha,'peel':peel,
              'workflow_runs':[] if workflow_runs is None else workflow_runs,
              'head_commit':head_commit, 'tag_type':tag_type, 'fetch_failure':fetch_failure,
              'parser_identity':parser_identity or {'tag_object_sha':TAG_OBJECT, 'peeled_commit_sha':COMMIT, 'message':'Release '+TAG},
              'parser_failure':parser_failure}
        metadata=prefix.with_suffix('.input.json');metadata.write_text(json.dumps(data),encoding='utf-8')
        downloads=self.root/'download-source';downloads.mkdir(exist_ok=True)
        for filename,payload in self.payloads.items():
            (downloads/filename).write_bytes(payload+(b'changed' if corrupt_download else b''))
        report=prefix.with_suffix('.report.json')
        driver=prefix.with_suffix('.driver.ps1')
        driver.write_text(r'''
$ErrorActionPreference='Stop'
$fixture=Get-Content -Raw -LiteralPath $env:CA_WORKFLOW_INPUT | ConvertFrom-Json
$script:caWorkflowObservation=[ordered]@{gh_calls=0;gh_arguments=@();sleeps=@();git_calls=@();python_arguments=@();error=''}
function gh {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
    $script:caWorkflowObservation.gh_calls++
    $script:caWorkflowObservation.gh_arguments+=($Arguments -join ' ')
    if ($script:caWorkflowObservation.gh_calls -gt 200) { throw 'workflow exceeded owned API-call ceiling' }
    $global:LASTEXITCODE=0
    if ($Arguments[0] -eq 'release' -and $Arguments[1] -eq 'download') {
        $directory=[string]$Arguments[[array]::IndexOf($Arguments,'--dir')+1]
        Copy-Item -LiteralPath (Join-Path $env:CA_WORKFLOW_DOWNLOAD $env:FROZEN_ZIP_NAME) -Destination $directory
        Copy-Item -LiteralPath (Join-Path $env:CA_WORKFLOW_DOWNLOAD $env:FROZEN_CHECKSUM_NAME) -Destination $directory
        return
    }
    if ($Arguments[0] -cne 'api') { throw 'unexpected GitHub command' }
    $endpoint=($Arguments | Where-Object { $_ -like 'repos/*' } | Select-Object -First 1)
    if ($endpoint -like '*/git/ref/tags/*') {
        return (@{ref="refs/tags/$env:RELEASE_TAG";object=@{type='tag';sha=$fixture.ref_sha}} | ConvertTo-Json -Depth 4 -Compress)
    }
    if ($endpoint -like '*/git/tags/*') {
        return (@{sha=$fixture.ref_sha;tag=$env:RELEASE_TAG;object=@{type='commit';sha=$fixture.peel}} | ConvertTo-Json -Depth 4 -Compress)
    }
    if ($endpoint -like '*/actions/workflows/*/runs*') {
        if ($fixture.missing_before -gt 0) {$global:LASTEXITCODE=1;return ''}
        return (@{workflow_runs=@($fixture.workflow_runs)} | ConvertTo-Json -Depth 8 -Compress)
    }
    if ($endpoint -notlike '*/releases/tags/*') { throw "unexpected GitHub endpoint: $endpoint" }
    if ($script:caWorkflowObservation.gh_calls -le $fixture.missing_before) {$global:LASTEXITCODE=1;return ''}
    return ($fixture.release | ConvertTo-Json -Depth 8 -Compress)
}
function git {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
    $script:caWorkflowObservation.git_calls+=($Arguments -join ' ')
    $global:LASTEXITCODE=0
    if ($Arguments[0] -ceq 'fetch') {
        if ($fixture.fetch_failure) {$global:LASTEXITCODE=1}
        return
    }
    if ($Arguments[0] -ceq 'cat-file' -and $Arguments[1] -ceq '-t') {return $fixture.tag_type}
    if ($Arguments[0] -cne 'rev-parse') {throw 'unexpected Git command'}
    if ($Arguments[-1] -like '*^{tree}') {return $fixture.tree}
    if ($Arguments[-1] -ceq 'HEAD^{commit}') {return $fixture.head_commit}
    if ($Arguments[-1] -like 'refs/tags/*^{commit}') {return $fixture.peel}
    if ($Arguments[-1] -like 'refs/tags/*') {return $fixture.ref_sha}
    return $fixture.main_commit
}
function Start-Sleep {param([int]$Seconds) $script:caWorkflowObservation.sleeps+=@($Seconds)}
function python {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
    $script:caWorkflowObservation.python_arguments=@($Arguments)
    $global:LASTEXITCODE=0
    if ($Arguments[0] -ceq 'tools/read_release_qualification_tag.py') {
        if ($fixture.parser_failure) {$global:LASTEXITCODE=2;return ''}
        return ($fixture.parser_identity | ConvertTo-Json -Compress)
    }
    $target=[string]$Arguments[[array]::IndexOf($Arguments,'--report-path')+1]
    [IO.File]::WriteAllText($target,'{"fixture_boundary":"verifier subprocess"}')
}
try { . $env:CA_WORKFLOW_SOURCE }
catch { $script:caWorkflowObservation.error=$_.Exception.Message }
finally { $script:caWorkflowObservation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $env:CA_WORKFLOW_REPORT -Encoding utf8NoBOM }
if ($script:caWorkflowObservation.error) { [Console]::Error.WriteLine($script:caWorkflowObservation.error); exit 1 }
''',encoding='utf-8')
        env=dict(self.env,CA_WORKFLOW_INPUT=str(metadata),CA_WORKFLOW_SOURCE=str(source),
                 CA_WORKFLOW_REPORT=str(report),CA_WORKFLOW_DOWNLOAD=str(downloads))
        env.update(step_environment)
        result=subprocess.run([executable,'-NoLogo','-NoProfile','-NonInteractive','-File',str(driver)],
            cwd=self.root,env=env,capture_output=True,text=True,timeout=30)
        observed=json.loads(report.read_text(encoding='utf-8'))
        github_env=self.root/'github.env'
        if github_env.exists():
            for line in github_env.read_text(encoding='utf-8-sig').splitlines():
                key,value=line.split('=',1);self.env[key]=value
        return result,observed
