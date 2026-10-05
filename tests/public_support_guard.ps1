param([Parameter(Mandatory)][string]$Root,[string]$ExtraSource='')
$ErrorActionPreference='Stop'
$files=@('INSTALL_THIS_PC.ps1','INSTALL_CANONICAL_PORTABLE.ps1',
 'tools/bootstrap_integrity.ps1','tools/apply_prepared_update.ps1',
 'tools/container_writer_session.ps1','tools/container_writer_fence.ps1',
 'tools/provision_protected_admin_acl.ps1','tools/resolve_windows_powershell.ps1',
 'kmtech_shared/powershell/data_generation.ps1','kmtech_shared/powershell/portable.ps1')
$result=[Collections.Generic.List[object]]::new()
$sourceAsts=@{}
$closedCommands=@{}
$safeReturnFields=@{}
function Get-GuardValueExpression($Node){
 if($Node -is [Management.Automation.Language.StatementBlockAst] -and $Node.Statements.Count -eq 1){return Get-GuardValueExpression $Node.Statements[0]}
 if($Node -is [Management.Automation.Language.PipelineAst] -and $Node.PipelineElements.Count -eq 1){return Get-GuardValueExpression $Node.PipelineElements[0]}
 if($Node -is [Management.Automation.Language.CommandExpressionAst]){return Get-GuardValueExpression $Node.Expression}
 return $Node
}
foreach($relative in $files){
 $parsed=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $relative),[ref]$null,[ref]$null)
 $sourceAsts[$relative]=$parsed
 foreach($definition in $parsed.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
  $returns=@($definition.Body.FindAll({param($n) $n -is [Management.Automation.Language.ReturnStatementAst]},$false))
  $allLiteral=$returns.Count -gt 0
  $commonFields=$null
  foreach($return in $returns){
   $currentFields=@{}
   $expression=Get-GuardValueExpression $return.Pipeline
   if($expression -isnot [Management.Automation.Language.StringConstantExpressionAst] -and $expression -isnot [Management.Automation.Language.ConstantExpressionAst]){$allLiteral=$false}
   if($expression -is [Management.Automation.Language.ConvertExpressionAst]){$expression=Get-GuardValueExpression $expression.Child}
   if($expression -is [Management.Automation.Language.HashtableAst]){
    foreach($pair in $expression.KeyValuePairs){
     $value=Get-GuardValueExpression $pair.Item2
     $literal=$value -is [Management.Automation.Language.StringConstantExpressionAst] -or $value -is [Management.Automation.Language.ConstantExpressionAst]
     $calculatedHash=$value -is [Management.Automation.Language.CommandAst] -and $value.GetCommandName() -ceq 'Get-FileSha256'
     if($literal -or $calculatedHash){
      $currentFields[[string]$pair.Item1.Value]=$true
     }
    }
   }
   if($null -eq $commonFields){$commonFields=$currentFields}
   else{foreach($key in @($commonFields.Keys)){if(-not $currentFields.ContainsKey($key)){$commonFields.Remove($key)}}}
  }
  if($allLiteral){$closedCommands[$definition.Name]=$true}
  if($null -ne $commonFields -and $commonFields.Count){$safeReturnFields[$definition.Name]=$commonFields}
 }
}
foreach($relative in $files){
 $source=Join-Path $Root $relative
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Shipped PowerShell source does not parse.'}
 if($ExtraSource -and $relative -ceq 'INSTALL_THIS_PC.ps1'){
  $ast=[Management.Automation.Language.Parser]::ParseInput(($ast.Extent.Text+"`n"+$ExtraSource),[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'Negative probe does not parse.'}
 }
 $bindings=@{}
 function Get-Owner($Node){
  $ancestor=$Node
  while($ancestor){if($ancestor -is [Management.Automation.Language.FunctionDefinitionAst]){return $ancestor.Name};$ancestor=$ancestor.Parent}
  return '<module>'
 }
 function Get-DirectProvenance($Node){
  $text=$Node.Extent.Text
  if($text -match '\bConvertTo-KmtechPublicRecord\b|\bGet-InstallationHelperPublicFailure\b'){return 0}
  $mask=0
  if($text -match '(?i)\.Exception\.Message|\bGet-InstallationFailureDetails\b|\bGet-InstallationFallbackDiagnostic\b|\bGet-InstallationFailureUserLine\b'){$mask=$mask -bor 1}
  if($text -match '(?i)\.(Stdout|Stderr)\b|\$(standardOutput|standardError|Output|childOutput)\b'){$mask=$mask -bor 2}
  if($text -match '(?i)\.CommandLine\b|\$(args|arguments|command)\b'){$mask=$mask -bor 4}
  if($text -match '(?i)\$env:|\bGet-ItemProperty\b|\bInvoke-RestMethod\b|\bInvoke-WebRequest\b|\bRead-Host\b'){$mask=$mask -bor 8}
  return $mask
 }
 foreach($assignment in $ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst]},$true)){
  $variables=@($assignment.Left.FindAll({param($n) $n -is [Management.Automation.Language.VariableExpressionAst]},$true))
  if($variables.Count -eq 1){
    $symbol=if($assignment.Left -is [Management.Automation.Language.VariableExpressionAst]){$variables[0].VariablePath.UserPath}else{$assignment.Left.Extent.Text.ToLowerInvariant()}
    $name=(Get-Owner $assignment)+'|'+$symbol
   if(-not $bindings.ContainsKey($name)){$bindings[$name]=[Collections.Generic.List[object]]::new()}
   $bindings[$name].Add($assignment.Right)
  }
 }
 $masks=@{}
  function Get-PublicProvenance($Node){
   $valueExpression=Get-GuardValueExpression $Node
   if($valueExpression -is [Management.Automation.Language.CommandAst] -and $valueExpression.GetCommandName() -and $closedCommands.ContainsKey($valueExpression.GetCommandName())){return 0}
   if($Node -is [Management.Automation.Language.IfStatementAst]){
    $mask=0
    foreach($clause in $Node.Clauses){$mask=$mask -bor (Get-PublicProvenance $clause.Item2)}
    if($Node.ElseClause){$mask=$mask -bor (Get-PublicProvenance $Node.ElseClause)}
    return $mask
   }
  if($Node.Extent.Text -match '\bConvertTo-KmtechPublicRecord\b|\bGet-InstallationHelperPublicFailure\b'){return 0}
  $mask=Get-DirectProvenance $Node
  $owner=Get-Owner $Node
   foreach($variable in $Node.FindAll({param($n) $n -is [Management.Automation.Language.VariableExpressionAst]},$true)){
    $member=$variable
    while($member.Parent -is [Management.Automation.Language.MemberExpressionAst] -and $member.Parent.Expression -eq $member){$member=$member.Parent}
    if($member -ne $variable){
     $symbol=$member.Extent.Text.ToLowerInvariant()
     $specific=@(($owner+'|'+$symbol),('<module>|'+$symbol))
     $resolved=$false
     foreach($key in $specific){if($masks.ContainsKey($key)){$mask=$mask -bor $masks[$key];$resolved=$true}}
     if($resolved){continue}
     $rootKeys=@(($owner+'|'+$variable.VariablePath.UserPath),('<module>|'+$variable.VariablePath.UserPath))
     foreach($key in $rootKeys){
      if($bindings.ContainsKey($key)){
       foreach($value in $bindings[$key]){
        $provider=Get-GuardValueExpression $value
        if($provider -is [Management.Automation.Language.CommandAst] -and $provider.GetCommandName() -and $safeReturnFields.ContainsKey($provider.GetCommandName()) -and $safeReturnFields[$provider.GetCommandName()].ContainsKey([string]$member.Member.Value)){$resolved=$true}
       }
      }
     }
     if($resolved){continue}
    }
    foreach($key in @(($owner+'|'+$variable.VariablePath.UserPath),('<module>|'+$variable.VariablePath.UserPath))){
    if($masks.ContainsKey($key)){$mask=$mask -bor $masks[$key]}
   }
  }
  return $mask
 }
 # Finite monotone propagation avoids recursive/exponential AST walks.
 do{
  $changed=$false
  foreach($key in @($bindings.Keys)){
   $mask=0
   foreach($value in $bindings[$key]){$mask=$mask -bor (Get-PublicProvenance $value)}
   if(-not $masks.ContainsKey($key) -or $masks[$key] -ne $mask){$masks[$key]=$mask;$changed=$true}
  }
 }while($changed)
 $nodes=$ast.FindAll({param($n)
  ($n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Write-Host','Write-Output','Write-Warning','Write-Error')) -or
  ($n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -in @('WriteLine','Write') -and $n.Expression.Extent.Text -match '^\[Console\]')
 },$true)
 foreach($node in $nodes){
  $owner=Get-Owner $node
  # Authenticated receipts are a parser protocol (contract 1a), not diagnostics.
  # Their canonical caller is guarded independently before any human forwarding.
   if($relative -ceq 'tools/container_writer_session.ps1' -and
      $node.Extent.Text -match '"(writer_session_|writer_restore_|replacement_receipt_validation_|container_recovery_)') {continue}
   if($relative -ceq 'INSTALL_THIS_PC.ps1' -and $owner -ceq 'Invoke-SelfElevated' -and
      $node.Extent.Text -match "'installation_(stage_evidence_root|elevation_result_path)='") {continue}
  $causes=Get-PublicProvenance $node
  if($causes){$result.Add([ordered]@{file=$relative;function=$owner;line=$node.Extent.StartLineNumber;sources=$causes})}
 }
}
ConvertTo-Json -InputObject @($result.ToArray()) -Depth 4 -Compress
