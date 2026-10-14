param([string]$Root)
$ErrorActionPreference='Stop'
$rows=[Collections.Generic.List[object]]::new()
$skip=@('.git','__pycache__','.pytest_cache','build','dist','.venv','venv','node_modules')
$files=Get-ChildItem -LiteralPath $Root -File -Recurse -Filter '*.ps1' |
    Where-Object { $parts=$_.FullName.Substring($Root.Length).Split([char[]]'\/'); @($parts|Where-Object {$_ -in $skip}).Count -eq 0 }
foreach($file in $files){
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if(@($errors).Count -ne 0){throw 'PowerShell source parse failed.'}
    foreach($node in $tree.FindAll({param($n)
        if($n -is [Management.Automation.Language.CommandAst]){
            $command=$n.GetCommandName()
            return $null -ne $command -and ($command.Split('\')[-1] -in @('Move-Item','Rename-Item','mi','mv','move','ren','rni'))
        }
        if($n -is [Management.Automation.Language.InvokeMemberExpressionAst]){
            $method=[string]$n.Member.Value
            if($method -in @('MoveFileExW','ReplaceFileW')){return $true}
            return $n.Static -and $n.Expression -is [Management.Automation.Language.TypeExpressionAst] -and
                $n.Expression.TypeName.FullName -in @('IO.File','System.IO.File') -and $method -in @('Replace','Move')
        }
        return $false
    },$true)){
        $owner=$node.Parent
        while($null -ne $owner -and $owner -isnot [Management.Automation.Language.FunctionDefinitionAst]){$owner=$owner.Parent}
        $bytes=[Text.Encoding]::UTF8.GetBytes($node.Extent.Text.Replace("`r`n","`n"))
        $hash=[Security.Cryptography.SHA256]::Create()
        try{$digest=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
        $relative=$file.FullName.Substring($Root.TrimEnd('\','/').Length+1).Replace('\','/')
        $rows.Add([ordered]@{path=$relative;function=if($null -eq $owner){'<module>'}else{$owner.Name};
            line=$node.Extent.StartLineNumber;sha256=$digest})
    }
}
ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 5 -Compress
