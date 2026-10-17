param([string]$Root,[string]$Entry,[string]$AuditPath,[string]$ConfigurationPath)
$ErrorActionPreference='Stop'
$config=Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
$definitions=@{};$commands=[Collections.Generic.List[object]]::new();$trees=@{}
function Read-Tree([string]$Path) {
    if($trees.ContainsKey($Path)){return $trees[$Path]}
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $Path),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'ENTRY_PARSE_FAILED'}
    $trees[$Path]=$tree
    return $tree
}
function Collect($Tree,[string]$Path) {
    foreach($function in $Tree.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
        $definitions[$function.Name]=$true
    }
    foreach($call in $Tree.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
        $name=$call.GetCommandName()
        if($name -match '^[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9-]*$'){
            $owner=$call.Parent
            while($null -ne $owner -and $owner -isnot [Management.Automation.Language.FunctionDefinitionAst]){$owner=$owner.Parent}
            $commands.Add(@{name=$name;path=$Path;line=$call.Extent.StartLineNumber;owner=$(if($owner){$owner.Name}else{''})})
        }
    }
}
foreach($path in $config.files){Collect (Read-Tree $path) $path}
# Canonical authenticates ITP and dot-sources ONLY the named functions. Loading
# all ITP definitions here would conceal exactly the F2 sibling-scope defect.
if($Entry -eq 'INSTALL_CANONICAL_PORTABLE.ps1'){
    $canonical=Read-Tree $Entry
    $admission=$canonical.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-CanonicalMachineRemovalWorkerPart'},$false)
    $assignment=$admission.Find({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$names'},$true)
    if($null -eq $assignment){throw 'HELPER_SELECTION_UNCLASSIFIED'}
    $names=@($assignment.Right.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst]},$true)|ForEach-Object {$_.Value})
    $helper=Read-Tree 'INSTALL_THIS_PC.ps1'
    $selected=@($helper.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names},$false))
    if($selected.Count -ne $names.Count){throw 'HELPER_SELECTION_DIFFERS'}
    foreach($function in $selected){$definitions[$function.Name]=$true;Collect $function 'INSTALL_THIS_PC.ps1'}
}
# Windows PowerShell 5.1 ships these modules; product modules are never loaded.
$builtins=@{}
foreach($module in $config.modules){
    foreach($command in Get-Command -Module $module -CommandType Cmdlet,Function -ErrorAction SilentlyContinue){$builtins[$command.Name]=$true}
}
$allowed=@{}
foreach($exception in $config.allowed){
    $provider=Read-Tree $exception.provider
    if(-not $provider.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $exception.name},$true)){
        throw 'CALLBACK_PROVIDER_DEFINITION_MISSING'
    }
    foreach($owner in $exception.owners){$allowed[('tools/bootstrap_integrity.ps1|'+$owner+'|'+$exception.name)]=$true}
}
$missing=@($commands | Where-Object {
    -not $definitions.ContainsKey($_.name) -and -not $builtins.ContainsKey($_.name) -and
    -not $allowed.ContainsKey(($_.path+'|'+$_.owner+'|'+$_.name))
})
@{entry=$Entry;missing=$missing;definitions=$definitions.Count;commands=$commands.Count} |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $AuditPath -Encoding UTF8
if($missing.Count){exit 1}
