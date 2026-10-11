"""Execute the product read nodes against real Windows Hidden folders."""
import json
import os
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_hidden_programdata_appdata_reads_and_unforced_negative(tmp_path, engine):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required")
    driver = tmp_path / "hidden-read.ps1"
    driver.write_text(r'''
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=$env:CA_HIDDEN_ROOT;$repo=$env:CA_HIDDEN_REPO
$specs=@(
 @('tools/bootstrap_integrity.ps1','Protect-KmtechCodeAncestors',3),
 @('tools/bootstrap_integrity.ps1','Assert-BootstrapProtectedRelayPath',1),
 @('INSTALL_THIS_PC.ps1','Assert-ProtectedCodeAncestors',1),
 @('tools/apply_prepared_update.ps1','Assert-Protected',1))
$reads=0;$negatives=0
foreach($folder in @('ProgramData','profile\AppData')){
 $hidden=Join-Path $root $folder
 [void][IO.Directory]::CreateDirectory($hidden)
 $info=Get-Item -LiteralPath $hidden -Force
 $info.Attributes=$info.Attributes -bor [IO.FileAttributes]::Hidden
 if(-not ((Get-Item -LiteralPath $hidden -Force).Attributes -band [IO.FileAttributes]::Hidden)){throw 'HIDDEN_FIXTURE_ATTRIBUTE_ABSENT'}
 foreach($spec in $specs){
  $errors=$null;$tokens=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $spec[0]),[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'PRODUCT_PARSE_FAILED'}
  $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -ceq $spec[1]})
  if($functions.Count -ne 1){throw 'HIDDEN_READ_FUNCTION_NOT_UNIQUE'}
  $nodes=@($functions[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Get-Item'},$true))
  if($nodes.Count -ne $spec[2]){throw 'HIDDEN_READ_NODE_COUNT_DIFFERS'}
  foreach($node in $nodes){
   $ancestor=$hidden;$path=$hidden;$full=$hidden
   $actual=Invoke-Expression $node.Extent.Text
   if(-not $actual.PSIsContainer -or ($actual.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'HIDDEN_READ_CONTAINER_OR_REPARSE_DIFFERS'}
   $reads++
   $unforced=$node.Extent.Text -replace '\s-Force\b',''
   $rejected=$false
   try{[void](Invoke-Expression $unforced)}catch{$rejected=$true}
   if(-not $rejected){throw 'UNFORCED_HIDDEN_READ_DID_NOT_FAIL'}
   $negatives++
  }
 }
}
$store=Join-Path $root 'continuations'
[void][IO.Directory]::CreateDirectory((Join-Path $store 'visible'))
$hiddenChild=Join-Path $store 'hidden'
[void][IO.Directory]::CreateDirectory($hiddenChild)
(Get-Item -LiteralPath $hiddenChild -Force).Attributes=[IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$null,[ref]$null)
$function=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-CanonicalRollbackContinuation'},$true))
if($function.Count -ne 1){throw 'CONTINUATION_FUNCTION_NOT_UNIQUE'}
$node=@($function[0].Body.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Get-ChildItem'},$true))
if($node.Count -ne 1){throw 'CONTINUATION_ENUMERATION_NOT_UNIQUE'}
$children=@(Invoke-Expression $node[0].Extent.Text)
if($children.Count -ne 2){throw 'HIDDEN_CONTINUATION_OMITTED'}
$unforced=$node[0].Extent.Text -replace '\s-Force\b',''
if(@(Invoke-Expression $unforced).Count -ne 1){throw 'UNFORCED_CONTINUATION_NEGATIVE_DIFFERS'}

$Root=Join-Path $root 'native-tree';$resolvedRoot=$Root
[void][IO.Directory]::CreateDirectory($Root)
[IO.File]::WriteAllText((Join-Path $Root 'visible.bin'),'visible')
$hiddenFile=Join-Path $Root 'hidden.bin';[IO.File]::WriteAllText($hiddenFile,'hidden')
(Get-Item -LiteralPath $hiddenFile -Force).Attributes=[IO.FileAttributes]::Hidden
$inventories=0
foreach($spec in @(@('tools/build_frozen_release_candidate.ps1','Assert-LowRiskNativeFreePackage'),@('tools/sandbox_container_sac/guest.ps1','Get-PeInventory'),@('tools/scan_portable_pe.ps1',''))){
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $spec[0]),[ref]$null,[ref]$null)
 $scope=$ast
 if($spec[1]){
  $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $spec[1]},$true))
  if($functions.Count -ne 1){throw 'PE_ENUMERATION_FUNCTION_NOT_UNIQUE'}
  $scope=$functions[0].Body
 }
 $nodes=@($scope.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Get-ChildItem'},$true))
 if($nodes.Count -ne 1){throw 'PE_ENUMERATION_NODE_NOT_UNIQUE'}
 if(@(Invoke-Expression $nodes[0].Extent.Text).Count -ne 2){throw 'HIDDEN_NATIVE_INVENTORY_OMITTED'}
 $unforced=$nodes[0].Extent.Text -replace '\s-Force\b',''
 if(@(Invoke-Expression $unforced).Count -ne 1){throw 'UNFORCED_NATIVE_INVENTORY_NEGATIVE_DIFFERS'}
 $inventories++
}
[ordered]@{reads=$reads;unforced_rejections=$negatives;continuations=$children.Count;inventories=$inventories}|ConvertTo-Json -Compress
''', encoding="utf-8-sig")
    result = run_powershell([executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
        env=dict(os.environ, CA_HIDDEN_ROOT=str(tmp_path), CA_HIDDEN_REPO=str(REPO)))
    (tmp_path / "native-stdout.log").write_text(result.stdout, encoding="utf-8")
    (tmp_path / "native-stderr.log").write_text(result.stderr, encoding="utf-8")
    assert result.returncode == 0, "Product Hidden read node rejected the owned fixture"
    assert json.loads(result.stdout) == {"reads": 12, "unforced_rejections": 12, "continuations": 2, "inventories": 3}
