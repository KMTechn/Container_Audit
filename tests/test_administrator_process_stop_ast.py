"""Installer process stop sites stay noninteractive and PID scoped."""
from pathlib import Path
import pytest
from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_installer_stop_process_ast_has_force_and_exact_id(tmp_path, engine):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Full"], r'''
$files=@('INSTALL_CANONICAL_PORTABLE.ps1','INSTALL_THIS_PC.ps1','tools/bootstrap_integrity.ps1',
 'tools/container_writer_session.ps1','tools/container_writer_fence.ps1','tools/apply_prepared_update.ps1')
$count=0
foreach($relative in $files){
 $path=Join-Path $env:CA_PRODUCT_ROOT $relative
 $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$null,[ref]$null)
 $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ieq 'Stop-Process'},$true))
 foreach($command in $commands){
  $count++
  $parameters=@($command.CommandElements|Where-Object {$_ -is [Management.Automation.Language.CommandParameterAst]}|ForEach-Object {$_.ParameterName})
  if($parameters -inotcontains 'Id' -or $parameters -inotcontains 'Force' -or
   $parameters -icontains 'Name' -or $parameters -icontains 'InputObject'){throw 'Unscoped or interactive stop site'}
  $index=@($command.CommandElements|ForEach-Object {$_.Extent.Text}).IndexOf('-Id')
  if($command.CommandElements[$index+1].Extent.Text -cne '$holder.Id'){throw 'Unexpected process identity binding'}
  $function=$command.Parent
  while($null -ne $function -and $function -isnot [Management.Automation.Language.FunctionDefinitionAst]){$function=$function.Parent}
  if($null -eq $function -or $function.Name -cne 'Invoke-ContainerWriterSessionSelfTest'){throw 'Product worker stop needs an identity contract'}
 }
}
if($count -ne 1){throw 'Process stop inventory changed'}
'PROCESS_STOP_AST_PASS'
''', engine=engine, values={"CA_PRODUCT_ROOT": str(ROOT)})
    (tmp_path / "ps-stop-diagnostic.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    assert result.returncode == 0, "Process stop AST contract failed; captured streams remain private"
    assert result.stdout.strip() == "PROCESS_STOP_AST_PASS"
