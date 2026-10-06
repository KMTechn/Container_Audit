$BootstrapIntegrityFileName = "bootstrap-integrity.json"
$BootstrapIntegritySchema = "container-audit-bootstrap-integrity-v1"

function ConvertTo-KmtechPublicRecord {
    param([Parameter(Mandatory)][Collections.IDictionary]$Fields,
          [AllowEmptyCollection()][string[]]$AllowedCodes=@(),
          [AllowEmptyCollection()][string[]]$SafeMessages=@())
    # Contract section 0. No environment, exception text, or child output input.
    $patterns=@{
        key='^[a-z][a-z0-9_]{0,63}\z'
        identifier='^[A-Za-z_][A-Za-z0-9_.]{0,127}\z'
        sha256='^[0-9a-f]{64}\z'
        commit='^(?:[0-9a-f]{40}|[0-9a-f]{64})\z'
        version='^v?[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}\z'
        id='^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\z'
        utc='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\z'
        path='^(?:[A-Za-z]:\\[^\x00-\x1f"<>|?*]{0,256}|/[^\x00-\x1f]{0,255})\z'
    }
    function Test-PublicValue([string]$Name,$Value) {
        if($null -eq $Value -or $Value -is [bool]){return $true}
        $integer=$Value -is [sbyte] -or $Value -is [byte] -or $Value -is [int16] -or
            $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
            $Value -is [int64] -or $Value -is [uint64] -or $Value -is [bigint]
        if($Name -cin @('status','stage','code')){return $Value -is [string] -and $Value -cin $AllowedCodes}
        if($Name -ceq 'guidance'){return $Value -is [string] -and $Value -cin $SafeMessages}
        if($Name -cin @('exception_type','location_module','location_function')){$kind='identifier'}
        elseif($Name -cin @('exit_code','location_line')){return $integer}
        elseif($Name -cin @('version','utc')){$kind=$Name}
        elseif($Name -cmatch '_(status|stage|code)\z'){return $Value -is [string] -and $Value -cin $AllowedCodes}
        elseif($Name -cmatch '_message\z'){return $Value -is [string] -and $Value -cin $SafeMessages}
        elseif($Name -cmatch '_(count|bytes|ms|line)\z'){return $integer}
        elseif($Name.EndsWith('_sha256')){$kind='sha256'}
        elseif($Name.EndsWith('_commit')){$kind='commit'}
        elseif($Name.EndsWith('_version')){$kind='version'}
        elseif($Name.EndsWith('_id')){$kind='id'}
        elseif($Name.EndsWith('_utc')){$kind='utc'}
        elseif($Name -cmatch '_(path|dir|root|file)\z'){$kind='path'}
        else{return $false}
        return $Value -is [string] -and $Value -cmatch $patterns[$kind]
    }
    $result=[ordered]@{};$rejected=[Collections.Generic.List[string]]::new();$invalid=0
    foreach($key in $Fields.Keys){
        if($key -isnot [string] -or $key -cnotmatch $patterns.key){$invalid++;continue}
        if(Test-PublicValue $key $Fields[$key]){$result[$key]=$Fields[$key]}
        else{$rejected.Add($key)}
    }
    if($rejected.Count){$result.nonconforming_fields=@($rejected.ToArray())}
    if($invalid){$result.nonconforming_invalid_key_count=$invalid}
    if($rejected.Count -or $invalid){$result.public_record_code='PUBLIC_FIELD_NONCONFORMING'}
    return $result
}

function ConvertTo-BootstrapPrincipalSid([string]$Identity) {
    try {
        if ([string]::IsNullOrWhiteSpace($Identity)) { throw 'Empty task identity.' }
        if ($Identity.StartsWith('S-', [StringComparison]::Ordinal)) {
            return [Security.Principal.SecurityIdentifier]::new($Identity).Value
        }
        return [Security.Principal.NTAccount]::new($Identity).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { throw [InvalidOperationException]::new('Task user SID cannot be resolved.', $_.Exception) }
}

function Test-BootstrapPrivilegedOwnerSid([string]$Sid) {
    return $Sid -cin @(
        'S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
}

function Protect-InstallationText([string]$Text, [int]$Limit=4096, [switch]$Configuration, [switch]$LiteralOnly, [Collections.IDictionary]$Environment, [switch]$CommonOnly, [switch]$NoTruncate, [switch]$KnownOnly) {
    $policy=@{environment_names=@('DEFECT_FINAL_DEFECT_CLAIM_TOKEN','DEFECT_FINAL_DEFECT_INTAKE_CLAIM_TOKEN','DEFECT_LINKED_MANIFEST_LOCK_API_TOKEN','DEFECT_LOGISTICS_API_TOKEN','DEFECT_RETURN_MANIFEST_API_TOKEN','DEFECT_SERVER_ACTIVE_LOCK_TOKEN','DEFECT_TRANSFER_MANIFEST_API_TOKEN','INSPECTION_WORKER_WAREHOUSE_RESPONSE_EXPORT_TOKEN','KMTECH_DEFECT_WRITER_DELEGATION_TOKEN','KMTECH_REWORK_TEMP_NG_CANDIDATE_TOKEN','KMTECH_REWORK_TEMP_NG_CLAIM_TOKEN','REWORK_ENROLLMENT_RESTORE_TOKEN','REWORK_LOGISTICS_API_TOKEN','CONTAINER_AUDIT_ENROLLMENT_TOKEN','CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','CONTAINER_RUNTIME_SECRET','KM_LOGISTICS_INSTALL_BEARER_TOKEN','WORKER_ANALYSIS_LOGISTICS_API_TOKEN','KMTECH_LABEL_WRITER_DELEGATION_TOKEN','PRODUCER_SELF_ENROLL_TOKEN','DIRECT_SYNC_AUTH_TOKEN','PRODUCER_API_TOKEN','LOGISTICS_API_TOKEN');sensitive_pattern='(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|API_?KEY|COOKIE|SESSION_?KEY|DELEGATION|BEARER|ENROLLMENT_CODE|RESTORE_CODE|ADMIN_PIN)';path_pattern='(?i)_(FILE|PATH|DIR|ROOT)$';digest_pattern='(?i)_(sha256s?|fingerprint|hash)$';short_digest_pattern='(?i)(pin|otp|password)';identifier_name_pattern='(?i)_(TRANSACTION|SESSION|ATTEMPT)_ID\z';identifier_value_pattern='^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\z';env_marker='[REDACTED:{0}]';field_marker='[REDACTED:field]';short_marker='[REDACTION_NOTE:short_value_skipped:{0}]';full_byte_cap=65536;head_byte_cap=8192;truncation_marker="`n[TRUNCATED: {0} bytes omitted]`n"}
    $policy.process_identifier_patterns=@{
        '(?i)_PID\z'='^[1-9][0-9]{0,9}\z'
        '(?i)_START\z'='^(windows-filetime|linux-startticks):[1-9][0-9]{0,24}\z'
        '(?i)_MUTEX\z'='^(Local|Global)\\[A-Za-z0-9._-]{1,200}\z'
    }
    if($Configuration){return $policy}
    if($null -eq $Environment){$Environment=[Environment]::GetEnvironmentVariables('Process')}
    $values=@();$notes=@()
    foreach($name in @($Environment.Keys|Sort-Object)){
        if($name -cin $policy.environment_names -or ($name -match $policy.sensitive_pattern -and $name -notmatch $policy.path_pattern)){
            $value=[string]$Environment[$name]
            if(-not $value){continue}
            $identifier=$name -match $policy.identifier_name_pattern -and $value -cmatch $policy.identifier_value_pattern
            foreach($pattern in $policy.process_identifier_patterns.Keys){
                if($name -match $pattern -and $value -cmatch $policy.process_identifier_patterns[$pattern]){$identifier=$true;break}
            }
            if($name -cnotin $policy.environment_names -and $identifier){continue}
            if($value.Length -lt 4){$notes+=($policy.short_marker -f $name);continue}
            $values+=,@{name=[string]$name;value=$value}
        }
    }
    # Explicit secret arguments can be supplied before their process env exists.
    $known=Get-Variable -Name InstallationEvidenceSensitiveValues -Scope Script -ErrorAction SilentlyContinue
    if($null -ne $known){foreach($value in $known.Value){if($value -is [string] -and $value.Length -ge 4){$values+=,@{name='field';value=$value}}}}
    foreach($name in @('CanonicalWriterFenceDelegationToken','WriterFenceDelegationToken')){
        $value=Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue
        if($value -is [string] -and $value.Length -ge 4){$values+=,@{name='CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN';value=$value}}
    }
    foreach($entry in @($values|Sort-Object @{Expression={$_.value.Length};Descending=$true},@{Expression={$_.name}})){
        $marker=$policy.env_marker -f $entry.name
        $escaped=ConvertTo-Json -InputObject $entry.value -Compress
        $jsonVariant=$escaped.Substring(1,$escaped.Length-2)
        $asciiVariant=[regex]::Replace($jsonVariant,'[^\x00-\x7F]',[Text.RegularExpressions.MatchEvaluator]{param($m) '\u'+([int][char]$m.Value).ToString('x4')})
        $variants=@($entry.value,$jsonVariant,$asciiVariant,$entry.value.Replace("'","''"),$entry.value.Replace('"','""'))|Sort-Object Length -Descending -Unique
        foreach($variant in $variants){$Text=$Text.Replace($variant,$marker)}
    }
    if(-not $LiteralOnly -and -not $KnownOnly){
        function Test-RedactedField([string]$Name,$Value){
            if($null -eq $Value -or $Value -is [bool]){return $false}
            if($Name -match $policy.path_pattern){return $false}
            if($Name -match $policy.digest_pattern -and $Name -notmatch $policy.short_digest_pattern){return $false}
            return ($Name -match $policy.sensitive_pattern -or $Name -imatch '^(pin|otp|password)$' -or (-not $CommonOnly -and $Name -imatch '^(authorization|registration[_-]?(?:value|code))$'))
        }
        function Convert-RedactedValue($Value){
            if($null -eq $Value){return $null}
            if($Value -is [Collections.IDictionary]){
                $result=[ordered]@{}
                foreach($key in $Value.Keys){$result[$key]=if(Test-RedactedField $key $Value[$key]){$redactionState.changed=$true;$policy.field_marker}else{Convert-RedactedValue $Value[$key]}}
                return $result
            }
            if($Value -is [pscustomobject]){
                $result=[ordered]@{}
                foreach($property in $Value.PSObject.Properties){$key=$property.Name;$result[$key]=if(Test-RedactedField $key $property.Value){$redactionState.changed=$true;$policy.field_marker}else{Convert-RedactedValue $property.Value}}
                return $result
            }
            if($Value -is [Collections.IEnumerable] -and $Value -isnot [string]){
                $items=@(foreach($item in $Value){Convert-RedactedValue $item});return ,$items
            }
            if($Value -is [string]){
                $safe=Protect-InstallationText $Value -1 -Environment @{} -CommonOnly:$CommonOnly -NoTruncate
                if($safe -cne $Value){$redactionState.changed=$true}
                return $safe
            }
            return $Value
        }
        try{
            $jsonProcessed=$false
            $candidate=$Text.Trim()
            if($candidate.StartsWith('{') -or $candidate.StartsWith('[')){
                $value=ConvertFrom-Json -InputObject $candidate -ErrorAction Stop
                $redactionState=@{changed=$false}
                $converted=Convert-RedactedValue $value
                if($redactionState.changed){$Text=$converted|ConvertTo-Json -Depth 100 -Compress};$jsonProcessed=$true
            }
        }catch{}
        # Bracketed sensitive values must be removed before scalar compatibility
        # redaction can discard their opener. An incomplete record fails closed.
        function Get-StructuredRedactionEnd([string]$Value,[int]$Offset){
            $closing=[Collections.Generic.List[char]]::new();$quote='';$escaped=$false
            for($index=$Offset;$index -lt $Value.Length;$index++){
                $ch=$Value[$index]
                if($quote){
                    if($escaped){$escaped=$false}
                    elseif($ch -ceq '\'){$escaped=$true}
                    elseif($ch -ceq $quote){
                        if($quote -ceq "'" -and $index+1 -lt $Value.Length -and $Value[$index+1] -ceq $quote){$index++}
                        else{$quote=''}
                    }
                }elseif($ch -cin @([char]34,[char]39)){$quote=$ch}
                elseif($ch -ceq '{'){$closing.Add([char]125)}
                elseif($ch -ceq '['){$closing.Add([char]93)}
                elseif($ch -cin @([char]125,[char]93)){
                    if(-not $closing.Count -or $ch -cne $closing[$closing.Count-1]){return $Value.Length}
                    $closing.RemoveAt($closing.Count-1)
                    if(-not $closing.Count){return $index+1}
                }
            }
            return $Value.Length
        }
        $structuredPattern=@'
(?=(?<![\w"'])(?<quote>["']?)(?<key>[A-Za-z_][A-Za-z0-9_.-]*)\k<quote>\s*[:=]\s*(?<opening>[{\[]))
'@
        $spans=@();$covered=0
        foreach($match in [regex]::Matches($Text,$structuredPattern)){
            $offset=$match.Groups['opening'].Index
            if($offset -lt $covered -or $Text.Substring($offset).StartsWith('[REDACTED:')){continue}
            if(-not(Test-RedactedField $match.Groups['key'].Value 'structured-value')){continue}
            $end=Get-StructuredRedactionEnd $Text $offset
            $replacement=if($match.Groups['quote'].Value){'"'+$policy.field_marker+'"'}else{$policy.field_marker}
            $spans+=,@{start=$offset;end=$end;replacement=$replacement};$covered=$end
        }
        foreach($span in @($spans|Sort-Object start -Descending)){
            $Text=$Text.Substring(0,$span.start)+$span.replacement+$Text.Substring($span.end)
        }
        if(-not $CommonOnly -and -not $jsonProcessed){
            $jsonKey='"(?<key>(?:\\.|[^"\\])*)"\s*:\s*'
            $matches=@([regex]::Matches($Text,$jsonKey));$spans=@();$covered=0
            foreach($match in $matches){
                if($match.Index -lt $covered){continue}
                try{$key=ConvertFrom-Json -InputObject ('"'+$match.Groups['key'].Value+'"') -ErrorAction Stop}catch{continue}
                if(-not(Test-RedactedField $key 'untyped-json-value')){continue}
                $begin=$match.Index+$match.Length;$end=$begin;$depth=0;$quoted=$false;$escaped=$false
                for(;$end -lt $Text.Length;$end++){
                    $ch=$Text[$end]
                    if($quoted){if($escaped){$escaped=$false}elseif($ch -ceq '\'){$escaped=$true}elseif($ch -ceq '"'){$quoted=$false;if($depth -eq 0){$end++;break}};continue}
                    if($ch -ceq '"'){$quoted=$true;continue}
                    if($ch -cin @('{','[')){$depth++;continue}
                    if($ch -cin @('}',']')){if($depth -eq 0){break};$depth--;if($depth -eq 0){$end++;break};continue}
                    if($depth -eq 0 -and $ch -cin @(',',"`r","`n")){break}
                }
                try{$fieldValue=ConvertFrom-Json -InputObject $Text.Substring($begin,$end-$begin) -ErrorAction Stop;if(-not(Test-RedactedField $key $fieldValue)){continue}}catch{}
                $spans+=,@{start=$begin;end=$end};$covered=$end
            }
            foreach($span in @($spans|Sort-Object start -Descending)){$Text=$Text.Substring(0,$span.start)+'"'+$policy.field_marker+'"'+$Text.Substring($span.end)}

            # Retain existing non-JSON credential assignments/header protection.
            $Text=[regex]::Replace($Text,'(?i)(\b[A-Za-z0-9_-]*(?:secret|token|signature|password|credential|registration[_-]?(?:value|code)|api[_-]?key)[A-Za-z0-9_-]*\s*[=:]\s*)([^\r\n,;]+)',[Text.RegularExpressions.MatchEvaluator]{param($m) if($m.Groups[2].Value.StartsWith('[REDACTED:')){return $m.Value};return $m.Groups[1].Value+$policy.field_marker})
            $Text=[regex]::Replace($Text,'(?i)authorization\s*:\s*[^\r\n]+',$policy.field_marker)
            $Text=[regex]::Replace($Text,'(https?://)[^\s/@]+:[^\s/@]+@',('$1'+$policy.field_marker+'@'))
            $Text=[regex]::Replace($Text,'(https?://[^\s?]+)\?[^\s]+',('$1?'+$policy.field_marker))
        }
        # Discover overlapping assignments so a non-sensitive exception prefix
        # cannot consume a later sensitive key/value. Redact before byte bounding.
        $assignmentPattern=@'
(?=(?<![\w"'])(?<quote>["']?)(?<key>[A-Za-z_][A-Za-z0-9_.-]*)\k<quote>\s*[:=]\s*(?<value>"(?:\\.|[^"\\])*(?:"|$)|'(?:''|\\.|[^'\\])*(?:'|$)|[^\s,;}\]"']+))
'@
        $spans=@()
        foreach($match in [regex]::Matches($Text,$assignmentPattern)){
            $value=$match.Groups['value'].Value
            if($value.StartsWith('[REDACTED:') -or $value -cin @('true','false','null')){continue}
            if(Test-RedactedField $match.Groups['key'].Value $value){
                $start=$match.Groups['value'].Index;$end=$start+$match.Groups['value'].Length
                if($match.Groups['quote'].Value -and $value.Length -ge 2 -and
                    $value[0] -cin @([char]34,[char]39) -and $value[$value.Length-1] -ceq $value[0]){
                    $start++;$end--
                }
                if($spans.Count -and $start -lt $spans[-1].end){$spans[-1].end=[Math]::Max($spans[-1].end,$end)}
                else{$spans+=,@{start=$start;end=$end}}
            }
        }
        foreach($span in @($spans|Sort-Object start -Descending)){
            $Text=$Text.Substring(0,$span.start)+$policy.field_marker+$Text.Substring($span.end)
        }
    }

    # Match each UTF16 unit literally or as mixed/nested JSON unicode escapes.
    $knownPattern={param([string]$Value)
        $parts=[Collections.Generic.List[string]]::new()
        foreach($character in $Value.ToCharArray()){
            $forms=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            [void]$forms.Add([string]$character)
            [void]$forms.Add('\u'+([int]$character).ToString('x4'))
            $encoded=ConvertTo-Json -InputObject ([string]$character) -Compress
            [void]$forms.Add($encoded.Substring(1,$encoded.Length-2))
            for($depth=0;$depth -lt 3;$depth++){
                foreach($form in @($forms)){
                    $encoded=ConvertTo-Json -InputObject $form -Compress
                    [void]$forms.Add($encoded.Substring(1,$encoded.Length-2))
                }
            }
            $choices=@(foreach($form in $forms){
                $chunks=[Text.StringBuilder]::new();$start=0
                foreach($match in [regex]::Matches($form,'\\+u([0-9a-f]{4})')){
                    [void]$chunks.Append([regex]::Escape($form.Substring($start,$match.Index+$match.Length-4-$start)))
                    foreach($digit in $match.Groups[1].Value.ToCharArray()){
                        [void]$chunks.Append($(if($digit -cmatch '[a-f]'){'['+[string]$digit+([string]$digit).ToUpperInvariant()+']'}else{[string]$digit}))
                    }
                    $start=$match.Index+$match.Length
                }
                [void]$chunks.Append([regex]::Escape($form.Substring($start)));$chunks.ToString()
            })
            $parts.Add('(?:'+(($choices|Sort-Object Length -Descending) -join '|')+')')
        }
        return $parts -join ''
    }

    # Parsing and serialization above can decode an initially escaped value.
    $remaining=[Collections.Generic.List[string]]::new()
    foreach($entry in @($values|Sort-Object @{Expression={$_.value.Length};Descending=$true},@{Expression={$_.name}})){
        $pattern=& $knownPattern $entry.value
        $marker=$policy.env_marker -f $entry.name
        $Text=[regex]::Replace($Text,$pattern,[Text.RegularExpressions.MatchEvaluator]{param($match)$marker})
        $remaining.Add($pattern)
    }
    foreach($pattern in $remaining){if([regex]::IsMatch($Text,$pattern)){throw 'REPORT_UNAVAILABLE'}}
    $assertFinalKnown={param([string]$Value)
        foreach($pattern in $remaining){if([regex]::IsMatch($Value,$pattern)){throw 'REPORT_UNAVAILABLE'}}
        return $Value
    }
    if(-not $KnownOnly -and $notes.Count){$Text+="`n"+($notes -join "`n")}
    if($NoTruncate){return (& $assertFinalKnown $Text)} # Internal in-memory envelope budgeting only.
    $bound=if($Limit -lt 0){$policy.full_byte_cap}else{[Math]::Min($Limit,$policy.full_byte_cap)}
    $utf8=[Text.UTF8Encoding]::new($false)
    $bytes=$utf8.GetBytes($Text)
    if($bytes.Length -le $bound){return (& $assertFinalKnown $Text)}
    $headCount=[Math]::Min($policy.head_byte_cap,[int]($bound/8))
    while($headCount -gt 0 -and ($bytes[$headCount] -band 192) -eq 128){$headCount--}
    $tailCount=[Math]::Max(0,$bound-$headCount-80)
    for($i=0;$i -lt 8;$i++){
        $tailStart=$bytes.Length-$tailCount
        while($tailStart -lt $bytes.Length -and ($bytes[$tailStart] -band 192) -eq 128){$tailStart++}
        $tailCount=$bytes.Length-$tailStart
        $marker=$policy.truncation_marker -f ($bytes.Length-$headCount-$tailCount)
        $budget=[Math]::Max(0,$bound-$headCount-$utf8.GetByteCount($marker))
        if($tailCount -eq $budget){break};$tailCount=$budget
    }
    $tailStart=$bytes.Length-$tailCount
    while($tailStart -lt $bytes.Length -and ($bytes[$tailStart] -band 192) -eq 128){$tailStart++}
    $tailCount=$bytes.Length-$tailStart
    $marker=$policy.truncation_marker -f ($bytes.Length-$headCount-$tailCount)
    return (& $assertFinalKnown ($utf8.GetString($bytes,0,$headCount)+$marker+$utf8.GetString($bytes,$tailStart,$tailCount)))
}

function ConvertTo-KmtechRedactedSinkText {
    param([string]$Text,[Collections.IDictionary]$Environment,[switch]$UserLine)
    $safe=Protect-InstallationText $Text -1 -Environment $Environment
    if($UserLine){
        $lines=@($safe -split '\r?\n'|Where-Object {$_ -and $_ -notmatch '^\[REDACTION_NOTE:|^\[TRUNCATED:'})
        $line=if($lines.Count){[string]$lines[-1]}else{''}
        if($line.Length -gt 300){$line=$line.Substring(0,300)}
        return $line
    }
    return $safe
}

function Get-InstallationFailureDetails($Failure) {
    $line = 0; $file = ''
    if ($Failure -is [Exception]) { $exception = $Failure }
    else {
        $exception = $Failure.Exception
        if ($null -ne $Failure.InvocationInfo) {
            $line = [int]$Failure.InvocationInfo.ScriptLineNumber
            $file = [IO.Path]::GetFileName([string]$Failure.InvocationInfo.ScriptName)
        }
    }
    $chain = @()
    for ($depth=0; $null -ne $exception -and $depth -lt 8; $depth++) {
        $native = $null; if ($exception -is [ComponentModel.Win32Exception]) { $native = $exception.NativeErrorCode }
        $chain += [ordered]@{type=$exception.GetType().FullName; message=(Protect-InstallationText $exception.Message); hresult=$exception.HResult; win32_error=$native}
        $exception = $exception.InnerException
    }
    return [ordered]@{script_file=$file;script_line=$line;exception_chain=$chain}
}

function Set-InstallationEvidenceAcl([string]$Path, [string]$Sid, [switch]$Directory, [switch]$PrepareOnly) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $privileged=Test-InstallationEvidencePrivileged
    $owner=if($privileged){'S-1-5-32-544'}else{$Sid}
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
    foreach ($identity in @($Sid,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $principal = [Security.Principal.SecurityIdentifier]::new($identity)
        $rights=if($privileged -and $identity -cnotin @('S-1-5-18','S-1-5-32-544')){'ReadAndExecute'}else{'FullControl'}
        if ($Directory) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,$rights,'ContainerInherit,ObjectInherit','None','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,$rights,'Allow') }
        $acl.AddAccessRule($rule)
    }
    if($PrepareOnly){return $acl}
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Test-InstallationEvidencePrivileged {
    $forced=Get-Variable -Name InstallationEvidencePrivileged -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($forced){return $true}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InstallationEvidenceControlRoot {
    return 'C:\KMTech\Apps\Container_Audit\update-control'
}

function Assert-InstallationEvidenceProtectedPath([string]$Path,[switch]$AllowSupportedPreparation) {
    try {
        if($AllowSupportedPreparation){Assert-BootstrapProtectedRelayPath $Path -AllowSupportedPreparation}
        else{Assert-BootstrapProtectedRelayPath $Path}
    }
    catch {
        Write-InstallationCaughtFailure $_
        throw [InvalidOperationException]::new(('설치 증거 폴더를 사용할 수 없습니다: '+$Path+' (상위 폴더 소유자·쓰기 권한·재분석 지점을 확인하세요)'),$_.Exception)
    }
}

function Get-InstallationPreparationExitCode($Failure) {
    $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    for($depth=0;$null -ne $exception -and $depth -lt 8;$depth++){
        if($exception.Data.Contains('installation_preparation_exit_code')){return [int]$exception.Data['installation_preparation_exit_code']}
        $exception=$exception.InnerException
    }
    return 66
}

function Get-InstallationPreparationDiagnostic([int]$ExitCode) {
    $diagnostics=@{
        61=@('UNSUPPORTED_ACL','상위 폴더 권한이 지원하는 기본값 또는 보호된 값과 다릅니다.')
        62=@('REPARSE_POINT','설치 경로에 재분석 지점이 있어 바탕을 준비할 수 없습니다.')
        63=@('UNTRUSTED_OWNER','설치 폴더 소유자를 신뢰할 수 없어 바탕을 준비할 수 없습니다.')
        64=@('APP_PARENT_CREATE','보호된 앱 폴더를 만들지 못했습니다.')
        65=@('CONTROL_CREATE','보호된 설치 제어·증거 폴더를 만들지 못했습니다.')
        66=@('OTHER','설치 바탕 준비 중 오류가 발생했습니다.')
    }
    $entry=$diagnostics[$ExitCode]
    if($null -eq $entry){return $null}
    return [pscustomobject]@{code=('INSTALLATION_PREPARATION_'+$entry[0]);message=($entry[1]+' 지원 담당자에게 문의하세요.');exit_code=$ExitCode}
}

function New-InstallationProtectedDirectory([string]$Path,[string]$Sid,[switch]$RecoverAbandoned) {
    $parent=Split-Path -Parent $Path
    if($RecoverAbandoned){
        # This narrow admission is used only after claiming a dead install's
        # recorded authority, or at the start of its already-owned rollback.
        if($Path -ine (Split-Path -Parent (Get-InstallationEvidenceControlRoot)) -or
            -not(Test-InstallationEvidencePrivileged)){throw 'Abandoned app protection requires the privileged canonical parent.'}
        Assert-InstallationEvidenceProtectedPath $parent
        Assert-BootstrapNoReparsePoint $Path 'abandoned app parent' -PathOnly
        $existing=Get-Acl -LiteralPath $Path -ErrorAction Stop
        if(-not $existing.AreAccessRulesProtected){
            $rules=@($existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            $key=(@($rules|ForEach-Object {[string]$_.IdentityReference.Value+'|'+[int64]$_.FileSystemRights+'|'+[string]$_.AccessControlType+'|'+[int]$_.InheritanceFlags+'|'+[int]$_.PropagationFlags+'|'+[int]$_.IsInherited}|Sort-Object)-join ';')
            $expected=(@('S-1-5-32-544|2032127|Allow|3|0|1','S-1-5-18|2032127|Allow|3|0|1','S-1-5-32-545|1179817|Allow|3|0|1','S-1-5-11|-536805376|Allow|3|2|1','S-1-5-11|1245631|Allow|0|0|1')|Sort-Object)-join ';'
            if($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or $key -cne $expected){throw 'Abandoned app parent ACL is not the recorded reset shape.'}
            # Set the protected DACL directly. There is no reset/unprotected gap
            # and no recursive owner or permission change beneath this parent.
            Set-InstallationEvidenceAcl $Path $Sid -Directory
        }
    }
    if($parent -ieq 'C:\KMTech\Apps'){Assert-InstallationEvidenceProtectedPath $Path -AllowSupportedPreparation}
    else{Assert-InstallationEvidenceProtectedPath $parent}
    if(-not(Test-Path -LiteralPath $Path)){
        # Apply the protected DACL at creation, before inheritable child-write
        # rights from the shared Apps directory can reach this application.
        $acl=Set-InstallationEvidenceAcl $Path $Sid -Directory -PrepareOnly
        if($PSVersionTable.PSEdition -ceq 'Core'){[IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path),$acl)}
        else{[void][IO.Directory]::CreateDirectory($Path,$acl)}
    }
    Assert-InstallationEvidenceProtectedPath $Path
}

function Read-InstallationAbandonedRollback([string]$InstallRoot,[string]$LocalAppDataRoot,[string]$Sid) {
    $root=Join-Path $LocalAppDataRoot 'KMTech\DirectSync\container_audit\control\writer-session'
    $activePath=Join-Path $root 'active.json'
    if(-not(Test-Path -LiteralPath $activePath)){return $null}
    if(-not(Test-BootstrapSamePath $LocalAppDataRoot (Get-ContainerWriterFenceProfileLocalAppDataRoot $Sid))){throw 'Abandoned operator profile differs.'}
    Assert-BootstrapNoReparsePoint $activePath 'abandoned fence'
    if((Get-Item -LiteralPath $activePath).Length -gt 262144){throw 'Abandoned fence is oversized.'}
    $activeSha=Get-FileSha256 $activePath
    $active=Get-Content -LiteralPath $activePath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    if([string]$active.status -cne 'INSTALLING' -or [string]$active.owner_kind -cne 'canonical_installer'){throw 'Abandoned fence state differs.'}
    $auditRoot=Join-Path $LocalAppDataRoot 'KMTech\ContainerAudit\install-audit'
    $preparedPath=Get-StrictFullPath ([string]$active.prepared_receipt_path) 'abandoned prepared receipt'
    if(-not(Test-BootstrapSamePath (Split-Path -Parent $preparedPath) $auditRoot) -or
        [IO.Path]::GetFileName($preparedPath) -cnotmatch '^canonical-portable-(\d{8}T\d{9}Z-[0-9a-f]{32})-writer-prepared\.json$'){throw 'Abandoned prepared path differs.'}
    $runId=$Matches[1]
    $auditPath=Join-Path $auditRoot ('canonical-portable-'+$runId+'.json')
    Assert-BootstrapNoReparsePoint $auditPath 'abandoned audit'
    if((Get-Item -LiteralPath $auditPath).Length -gt 1048576){throw 'Abandoned audit is oversized.'}
    $audit=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8 | ConvertFrom-ContainerWriterFenceJson
    $stage=Get-StrictFullPath ([string]$audit.stage_evidence_root) 'abandoned stage root'
    $store=Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence'
    $run=Split-Path -Parent $stage
    $protectedRun=Test-BootstrapSamePath (Split-Path -Parent $run) $store
    $ordinaryRun=Test-BootstrapSamePath (Split-Path -Parent $stage) $auditRoot
    if(($protectedRun -and [IO.Path]::GetFileName($run) -cnotmatch '^run-[0-9a-f]{32}$') -or
        (-not $protectedRun -and -not $ordinaryRun) -or
        [IO.Path]::GetFileName($stage) -cnotmatch ('^canonical-portable-'+[regex]::Escape($runId)+'\.json\.evidence\.([1-9][0-9]{0,9})$')){throw 'Abandoned evidence run differs.'}
    # Only the corrected installer's durable record qualifies. Ordinary caller
    # evidence is owned by that same operator; elevated evidence stays machine
    # protected. Unknown owners, writable trustees and reparse points refuse.
    $recordPath=Join-Path $stage 'reentry-record.json'
    Assert-BootstrapNoReparsePoint $recordPath 'abandoned reentry record' -PathOnly
    if($protectedRun){Assert-InstallationEvidenceProtectedPath $recordPath}
    else{
        $acl=Get-Acl -LiteralPath $stage
        if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $Sid){throw 'Abandoned ordinary evidence owner differs.'}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin @($Sid,'S-1-5-18','S-1-5-32-544')){throw 'Abandoned ordinary evidence trustee differs.'}
        }
    }
    if((Get-Item -LiteralPath $recordPath).Length -gt 65536){throw 'Abandoned reentry record is oversized.'}
    $record=Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$record.schema -cne 'container-audit-install-reentry-v1' -or [string]$record.phase -cnotin @('RUNTIME_QUIESCED_UNPLACED','PLACEMENT_ATTEMPTED') -or
        [string]$record.run_id -cne $runId -or [string]$record.operator_sid -cne $Sid -or
        -not(Test-BootstrapSamePath ([string]$record.install_root) $InstallRoot) -or
        -not(Test-BootstrapSamePath ([string]$record.operator_local_appdata_root) $LocalAppDataRoot) -or
        $record.removal_completed -isnot [bool] -or -not $record.removal_completed -or
        $record.secret_values_recorded -isnot [bool] -or $record.secret_values_recorded -or
        -not(Test-BootstrapJsonInteger $record.owner_process_id) -or [int64]$record.owner_process_id -le 0 -or
        [string]$record.delegation_sha256 -cne [string]$active.delegation_sha256 -or
        -not(Test-ContainerWriterFenceHex ([string]$record.delegation_sha256) 64) -or
        [string]$record.prepared_receipt_sha256 -cne [string]$active.prepared_receipt_sha256){throw 'Abandoned durable admission is incomplete.'}
    [void](ConvertTo-ContainerWriterFenceUtc ([string]$record.owner_started_at_utc))
    foreach($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','writer_contract_sha256','writer_inventory_sha256')){
        if([string]$record.$name -cne [string]$active.$name){throw 'Abandoned record/fence tuple differs.'}
    }
    $accepted=$Script:ContainerWriterFenceAcceptedInstalledInventorySha256
    try{
        $Script:ContainerWriterFenceAcceptedInstalledInventorySha256=[string]$record.writer_inventory_sha256
        [void](Read-ContainerWriterFence $root)
        if((Get-FileSha256 $activePath) -cne $activeSha){throw 'Abandoned fence changed during admission.'}
    }finally{$Script:ContainerWriterFenceAcceptedInstalledInventorySha256=$accepted}
    $prepared=Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$prepared.schema -cne 'container-audit-canonical-writer-prepared-v1' -or [string]$prepared.status -cne 'PREPARED' -or
        [string]$prepared.operator_sid -cne $Sid -or [string]$prepared.source_manifest_sha256 -cne [string]$record.source_manifest_sha256 -or [string]$prepared.writer_inventory_sha256 -cne [string]$record.prepared_writer_inventory_sha256){throw 'Abandoned prepared identity differs.'}
    foreach($name in @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','writer_contract_sha256')){
        if([string]$prepared.$name -cne [string]$active.$name){throw 'Abandoned prepared/fence tuple differs.'}
    }
    # PID reuse is never interpreted as a dead owner. The start time is kept for
    # support diagnostics; a surviving PID or mutex always refuses recovery.
    $ownerPid=[int]$record.owner_process_id
    if(@(Get-Process -ErrorAction Stop | Where-Object {$_.Id -eq $ownerPid}).Count){throw 'Abandoned installer PID is alive or reused.'}
    if((Get-FileSha256 (Join-Path $InstallRoot 'portable-manifest.json')) -cne [string]$record.old_manifest_sha256 -or
        (Get-FileSha256 (Join-Path $InstallRoot 'bootstrap-integrity.json')) -cne [string]$record.old_integrity_sha256){throw 'Abandoned old code metadata changed.'}
    [void](Assert-BootstrapIntegrityRecord $InstallRoot)
    $expected=(ConvertTo-BootstrapRelayArgument (Join-Path $InstallRoot 'runtime\pythonw.exe'))+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $InstallRoot 'app\main.py'))+' --container-audit-user-relay'
    $entryExpected=(ConvertTo-BootstrapRelayArgument (Join-Path $InstallRoot 'runtime\pythonw.exe'))+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $InstallRoot 'app\user_relay_entry.py'))
    if($record.preimage.exists -isnot [bool] -or -not $record.preimage.exists -or [string]$record.preimage.kind -cne 'String' -or
        [string]$record.preimage.data -cnotin @($expected,$entryExpected) -or
        [string]$audit.schema -cne 'container-audit-canonical-portable-install-v2' -or [string]$audit.operation -cne 'INSTALL' -or
        [string]$audit.run_id -cne $runId -or [string]$audit.source_manifest_sha256 -cne [string]$record.source_manifest_sha256 -or
        [string]$audit.preimage.data -cne [string]$record.preimage.data -or
        [string]$audit.code_replacement.receipt_path -or [string]$audit.code_replacement.receipt_sha256 -or
        [bool]$audit.scheduled_writer.preimage.present){throw 'Abandoned rollback state is ambiguous.'}
    $stop=Join-Path $LocalAppDataRoot 'KMTech\DirectSync\container_audit\control\container_audit_user_relay.stop.json'
    Assert-BootstrapNoReparsePoint $stop 'abandoned stop marker'
    if((Get-FileSha256 $stop) -cne [string]$record.stop_marker_sha256){throw 'Abandoned stop marker changed.'}
    return [pscustomobject]@{active=$active;active_path=$activePath;active_sha256=$activeSha;audit=$audit;audit_path=$auditPath;
        audit_sha256=Get-FileSha256 $auditPath;record=$record;record_path=$recordPath;record_sha256=Get-FileSha256 $recordPath;
        stop=$stop;stop_sha256=Get-FileSha256 $stop;owner_pid=$ownerPid;removal_sha256=[string]$record.removal_receipt_sha256}
}

function Read-InstallationOwnedParentRepair([string]$InstallRoot,[string]$LocalAppDataRoot,[string]$Sid,[int]$ParentProcessId,$Manifest) {
    if($InstallRoot -ine 'C:\KMTech\Apps\Container_Audit\current' -or
        -not(Test-BootstrapSamePath $LocalAppDataRoot (Get-ContainerWriterFenceProfileLocalAppDataRoot $Sid))){throw 'Owned repair path differs.'}
    $security=Get-BootstrapRelaySecurity $ParentProcessId
    if($security.sid -cne $Sid -or $security.elevated -or $security.integrity_level -ne 8192 -or $security.session_id -le 0){throw 'Owned repair parent is not the ordinary operator.'}
    $root=Join-Path $LocalAppDataRoot 'KMTech\DirectSync\container_audit\control\writer-session'
    $path=Join-Path $root 'active.json'
    Assert-BootstrapNoReparsePoint $path 'owned repair fence'
    $raw=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    # A fresh placement can fail before current exists. In that state only the
    # authenticated source inventory may bind the owned repair; an existing
    # current still requires its manifest and exact installed inventory.
    $oldInventorySha256=''
    if(Test-Path -LiteralPath $InstallRoot -ErrorAction Stop){
        $old=Get-Content -LiteralPath (Join-Path $InstallRoot 'portable-manifest.json') -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
        $oldInventorySha256=[string]$old.writer_sink_inventory_contract_sha256
    }
    if([string]$raw.orchestrator_sha256 -cne [string]$Manifest.installer_sha256 -or
        [string]$raw.writer_contract_sha256 -cne [string]$Manifest.writer_session_contract_sha256 -or
        [string]$raw.writer_inventory_sha256 -cnotin @([string]$Manifest.writer_sink_inventory_contract_sha256,$oldInventorySha256) -or
        [string]$raw.writer_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Owned repair source/fence differs.'}
    $saved=$Script:ContainerWriterFenceAcceptedInstalledInventorySha256
    try{$Script:ContainerWriterFenceAcceptedInstalledInventorySha256=$oldInventorySha256;$active=Read-ContainerWriterFence $root}
    finally{$Script:ContainerWriterFenceAcceptedInstalledInventorySha256=$saved}
    if([string]$active.status -cne 'INSTALLING' -or [string]$active.owner_kind -cne 'canonical_installer'){throw 'Owned repair state differs.'}
    $prepared=Get-Content -LiteralPath $active.prepared_receipt_path -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
    if([string]$prepared.operator_sid -cne $Sid -or [string]$prepared.source_manifest_sha256 -cne $script:OwnedRepairManifestSha256){throw 'Owned repair prepared source differs.'}
    return [pscustomobject]@{active=$active}
}

function Initialize-InstallationProtectedBase([string]$Sid) {
    $control=Get-InstallationEvidenceControlRoot
    $appParent=Split-Path -Parent $control
    # Admit all existing paths before changing either shared ancestor. Missing
    # reviewed paths/default ancestor ACLs are supported only for preparation.
    Assert-InstallationEvidenceProtectedPath $(if(Test-Path -LiteralPath $control){$control}else{$appParent}) -AllowSupportedPreparation
    $Script:InstallationPreparationEvents=[Collections.Generic.List[object]]::new()
    Write-InstallationEvidenceEvent ([ordered]@{event='PREPARATION_START';stage='shared_ancestors';captured_at=[DateTime]::UtcNow.ToString('o')})
    [void](Protect-KmtechCodeAncestors $appParent -BeforeAppCreation)
    Write-InstallationEvidenceEvent ([ordered]@{event='PREPARATION_STAGE';stage='app_parent';captured_at=[DateTime]::UtcNow.ToString('o')})
    try{New-InstallationProtectedDirectory $appParent $Sid}
    catch{
        if((Get-InstallationPreparationExitCode $_) -eq 66){$_.Exception.Data['installation_preparation_exit_code']=64}
        throw
    }
    Assert-InstallationEvidenceProtectedPath $appParent
    Write-InstallationEvidenceEvent ([ordered]@{event='PREPARATION_STAGE';stage='control';captured_at=[DateTime]::UtcNow.ToString('o')})
}

function New-InstallationProtectedEvidenceRun([string]$Sid,[string]$RunRoot='') {
    try{[void][Security.Principal.SecurityIdentifier]::new($Sid)}catch{throw 'Installation evidence operator SID is invalid.'}
    Initialize-InstallationProtectedBase $Sid
    $control=Get-InstallationEvidenceControlRoot
    $store=Join-Path $control 'installation-evidence'
    try{
        New-InstallationProtectedDirectory $control $Sid
        New-InstallationProtectedDirectory $store $Sid
    }catch{
        if((Get-InstallationPreparationExitCode $_) -eq 66){$_.Exception.Data['installation_preparation_exit_code']=65}
        throw
    }
    if(-not $RunRoot){$RunRoot=Join-Path $store ('run-'+[Guid]::NewGuid().ToString('N'))}
    $RunRoot=Get-StrictFullPath $RunRoot 'protected installation run'
    if(-not(Test-BootstrapSamePath (Split-Path -Parent $RunRoot) $store) -or
        [IO.Path]::GetFileName($RunRoot) -cnotmatch '^run-[0-9a-f]{32}$'){throw 'Protected installation run binding differs.'}
    if(Test-Path -LiteralPath $RunRoot){
        Assert-InstallationEvidenceProtectedPath $RunRoot
        # The wrapper already persisted this run's initial preparation proof.
        $Script:InstallationPreparationEvents=$null
        return $RunRoot
    }
    # Creation supplies the protected DACL atomically; existing directories are
    # checked as-is and never repaired when user-owned or user-writable.
    $prior=@(Get-ChildItem -LiteralPath $store -Directory -Force | Where-Object {$_.Name -cmatch '^run-[0-9a-f]{32}$'} | Sort-Object CreationTimeUtc -Descending)
    foreach($old in @($prior | Select-Object -Skip 4)) {
        Assert-InstallationEvidenceProtectedPath $old.FullName
        Assert-BootstrapNoReparsePoint $old.FullName 'expired installation evidence'
        Remove-Item -LiteralPath $old.FullName -Recurse -ErrorAction Stop
    }
    try{New-InstallationProtectedDirectory $RunRoot $Sid}
    catch{
        if((Get-InstallationPreparationExitCode $_) -eq 66){$_.Exception.Data['installation_preparation_exit_code']=65}
        throw
    }
    $pending=Get-Variable -Name InstallationPreparationEvents -Scope Script -ErrorAction SilentlyContinue
    if($null -ne $pending -and $null -ne $pending.Value){
        Write-InstallationEvidenceEvent ([ordered]@{event='PREPARATION_END';stage='protected_run';captured_at=[DateTime]::UtcNow.ToString('o')})
        $path=Join-Path $RunRoot 'preparation.json'
        Assert-InstallationEvidenceProtectedPath $RunRoot
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((Protect-InstallationText ($pending.Value.ToArray() | ConvertTo-Json -Depth 12) -Limit 1048576))
        if($bytes.Length -gt 1048576 -or (Test-Path -LiteralPath $path)){throw 'Installation preparation evidence is invalid.'}
        $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        Set-InstallationEvidenceAcl $path $Sid
        $Script:InstallationPreparationEvents=$null
    }
    return $RunRoot
}

function Assert-InstallationEvidenceWriteRoot([string]$Root) {
    Assert-BootstrapNoReparsePoint $Root 'installation evidence write root' -PathOnly
    if(Test-InstallationEvidencePrivileged){
        $run=Get-Variable -Name InstallationProtectedRunRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if(-not $run -or (-not(Test-BootstrapSamePath $Root $run) -and
            -not $Root.StartsWith($run+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'Privileged evidence write is outside the protected run.'}
        Assert-InstallationEvidenceProtectedPath $Root
    }
}

function Initialize-InstallationEvidence([string]$BasePath,[string]$OperatorSid,[string[]]$SensitiveValues=@()) {
    if(Test-InstallationEvidencePrivileged){
        $run=Get-Variable -Name InstallationProtectedRunRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $Script:InstallationProtectedRunRoot=New-InstallationProtectedEvidenceRun $OperatorSid $run
        $BasePath=Join-Path $Script:InstallationProtectedRunRoot ([IO.Path]::GetFileName($BasePath))
    }
    $root = Get-StrictFullPath ($BasePath + '.evidence.' + $PID) 'installation evidence root'
    $parent=Split-Path -Parent $root
    $existing=$parent
    while (-not (Test-Path -LiteralPath $existing)) { $existing=Split-Path -Parent $existing }
    Assert-BootstrapNoReparsePoint $existing 'installation evidence ancestor' -PathOnly
    if (Test-Path -LiteralPath $root) { throw 'Installation evidence directory already exists.' }
    [void][IO.Directory]::CreateDirectory($root)
    Set-InstallationEvidenceAcl $root $OperatorSid -Directory
    Assert-InstallationEvidenceWriteRoot $root
    $Script:InstallationEvidenceRoot = $root
    $Script:InstallationEvidenceSid = $OperatorSid
    $Script:InstallationEvidenceSensitiveValues = @($SensitiveValues)
    $Script:InstallationEvidenceLanes = @{}
    $Script:InstallationEvidenceSequence = 0
    $Script:InstallationLastChildCapture=$null
    $Script:InstallationLastChildEvidenceFailure=$null
    $Script:InstallationFirstFailedChildCapture=$null
    $Script:InstallationFirstFailedChildEvidenceFailure=$null
    $Script:InstallationFirstFailedChildStreams=$null
    $Script:InstallationOriginalFailure=$null
    $Script:InstallationMostRecentOriginalFailureReference=$null
    $Script:InstallationEvidenceFailed = $false
    $Script:InstallationEvidenceFailureCodes = [Collections.Generic.List[string]]::new()
    Write-InstallationEvidenceEvent ([ordered]@{event='INITIALIZED';process_id=$PID;byte_cap_per_stream=(Protect-InstallationText -Configuration).full_byte_cap;journal_cap_bytes=1048576;raw_command_recorded=$false})
    return $root
}

function Write-InstallationEvidenceEvent($Payload) {
    $pending=Get-Variable -Name InstallationPreparationEvents -Scope Script -ErrorAction SilentlyContinue
    if($null -ne $pending -and $null -ne $pending.Value){
        $Payload['captured_at']=[DateTime]::UtcNow.ToString('o')
        $pending.Value.Add($Payload);return
    }
    $root = Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $root) { return }
    try {
        Assert-InstallationEvidenceWriteRoot $root
        $path=Join-Path $root 'stages.jsonl'
        $Payload['captured_at']=[DateTime]::UtcNow.ToString('o')
        $text=Protect-InstallationText ($Payload|ConvertTo-Json -Depth 12 -Compress) -1 -NoTruncate
        if([Text.Encoding]::UTF8.GetByteCount($text)+1 -gt 65536){
            $preview=Protect-InstallationText $text 57344
            do{$text=Protect-InstallationText (@{event=$Payload.event;captured_at=$Payload.captured_at;detail_text=$preview;complete=$false}|ConvertTo-Json -Depth 6 -Compress) -1 -NoTruncate -KnownOnly;if([Text.Encoding]::UTF8.GetByteCount($text)+1 -gt 65536){$preview=Protect-InstallationText $preview ([Math]::Max(256,[int]([Text.Encoding]::UTF8.GetByteCount($preview)/2)))}}while([Text.Encoding]::UTF8.GetByteCount($text)+1 -gt 65536)
        }
        try{$null=ConvertFrom-Json -InputObject $text -ErrorAction Stop}catch{throw 'REPORT_UNAVAILABLE'}
        $bytes=[Text.Encoding]::UTF8.GetBytes($text+"`n")
        # Each journal part is a sink capped at 64 KiB; retain the existing
        # aggregate 1 MiB budget as at most sixteen independently pinned parts.
        $index=0
        while(Test-Path -LiteralPath $path){
            $length=(Get-Item -LiteralPath $path).Length
            if($length -gt 65536 -or ($index -ge 15 -and $length+$bytes.Length -gt 65536)){
                $Script:InstallationEvidenceFailed=$true
                if(-not $Script:InstallationEvidenceFailureCodes.Contains('JOURNAL_LIMIT')){$Script:InstallationEvidenceFailureCodes.Add('JOURNAL_LIMIT')}
                return
            }
            if($length+$bytes.Length -le 65536){break}
            $index++;$path=Join-Path $root ('stages-'+$index.ToString('00')+'.jsonl')
        }
        $newFile=-not (Test-Path -LiteralPath $path)
        $stream=[IO.FileStream]::new($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ($newFile) { Set-InstallationEvidenceAcl $path $Script:InstallationEvidenceSid }
    } catch {
        $Script:InstallationEvidenceFailed=$true
        $failureCode=if($_.Exception.Message -ceq 'REPORT_UNAVAILABLE'){'REPORT_UNAVAILABLE'}else{'JOURNAL_IO_OR_ACL_FAILURE'}
        if(-not $Script:InstallationEvidenceFailureCodes.Contains($failureCode)){$Script:InstallationEvidenceFailureCodes.Add($failureCode)}
    }
}

function Complete-InstallationEvidence {
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $failed=Get-Variable -Name InstallationEvidenceFailed -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $codes=Get-Variable -Name InstallationEvidenceFailureCodes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $summary=[ordered]@{status=if(-not $root){'NOT_CONFIGURED'}elseif($failed){'INCOMPLETE'}else{'COMPLETE'};
        recording_failed=[bool]$failed;root=[string]$root;journal_cap_bytes=1048576;failure_codes=@($codes);
        summary_path='';summary_written=$false;business_result_is_separate=$true;journal_part_cap_bytes=65536;journal_parts=@()}
    if(-not $root){return $summary}
    $summary.summary_path=Join-Path $root 'evidence-status.json'
    foreach($index in 0..15){$leaf=if($index){'stages-'+$index.ToString('00')+'.jsonl'}else{'stages.jsonl'};$part=Join-Path $root $leaf;if(Test-Path -LiteralPath $part -PathType Leaf){$summary.journal_parts+=,@{path=$part;sha256=(Get-FileSha256 $part)}}}
    try {
        Assert-InstallationEvidenceWriteRoot $root
        $summary.summary_written=$true
        [IO.File]::WriteAllText($summary.summary_path,(Protect-InstallationText ($summary|ConvertTo-Json -Depth 5) -1),[Text.UTF8Encoding]::new($false))
        Set-InstallationEvidenceAcl $summary.summary_path $Script:InstallationEvidenceSid
    }catch {
        $Script:InstallationEvidenceFailed=$true
        $summary.status='INCOMPLETE';$summary.recording_failed=$true;$summary.summary_written=$false
        # If writing succeeded before an ACL/readback failure, replace the
        # success-looking body where possible; stdout still carries INCOMPLETE.
        try{Assert-InstallationEvidenceWriteRoot $root;[IO.File]::WriteAllText($summary.summary_path,(Protect-InstallationText ($summary|ConvertTo-Json -Depth 5) -1),[Text.UTF8Encoding]::new($false))}catch{}
        $summary.failure_codes+=@('FINAL_SUMMARY_IO_OR_ACL_FAILURE')
    }
    return $summary
}

function Register-InstallationChildEvidenceSummary($Summary) {
    if($null -eq $Summary -or [string]$Summary.status -cne 'COMPLETE'){
        $Script:InstallationEvidenceFailed=$true
        $codes=Get-Variable -Name InstallationEvidenceFailureCodes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $codes -and -not $codes.Contains('CHILD_EVIDENCE_INCOMPLETE')){$codes.Add('CHILD_EVIDENCE_INCOMPLETE')}
    }
}

function Read-InstallationEvidenceChildSummary([string]$Root) {
    $path=Join-Path $Root 'evidence-status.json'
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){return [ordered]@{status='INCOMPLETE';recording_failed=$true;summary_path=$path;reason='CHILD_SUMMARY_NOT_RECORDED'}}
    Assert-BootstrapNoReparsePoint $path 'child evidence summary' -PathOnly
    if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Child evidence summary is oversized.'}
    $record=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    if(-not(Test-BootstrapSamePath ([string]$record.root) $Root) -or [string]$record.status -cnotin @('COMPLETE','INCOMPLETE') -or
        $record.recording_failed -isnot [bool] -or ($record.status -ceq 'COMPLETE' -and $record.recording_failed)){throw 'Child evidence summary binding differs.'}
    return [ordered]@{status=[string]$record.status;recording_failed=[bool]$record.recording_failed;summary_path=$path;summary_sha256=Get-FileSha256 $path}
}

function Read-InstallationHelperEvidenceBinding([string[]]$Output,[string]$AuditLogPath,[int]$DirectProcessId,[string]$ExpectedHelperSha256='') {
    $roots=@($Output | Where-Object {$_ -cmatch '^installation_stage_evidence_root=.+$'} | ForEach-Object {$_.Substring('installation_stage_evidence_root='.Length)})
    $results=@($Output | Where-Object {$_ -cmatch '^installation_elevation_result_path=.+$'} | ForEach-Object {$_.Substring('installation_elevation_result_path='.Length)})
    $parentRoot=Get-StrictFullPath ($AuditLogPath+'.evidence.'+$DirectProcessId) 'helper evidence root'
    if($results.Count) {
        $path=Get-StrictFullPath ([string]$results[-1]) 'elevation result'
        if(-not(Test-BootstrapSamePath $path (Join-Path $parentRoot 'elevation-result.json'))){throw 'Elevation result path binding differs.'}
        Assert-BootstrapNoReparsePoint $path 'elevation result' -PathOnly
        if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Elevation result is oversized.'}
        $result=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if([string]$result.schema -cne 'container-audit-installation-elevation-capture-v1' -or
            -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $DirectProcessId -or
            -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -le 0 -or
            -not(Test-BootstrapJsonInteger $result.helper_process_id) -or [int64]$result.helper_process_id -lt 0 -or
            ($ExpectedHelperSha256 -and [string]$result.helper_sha256 -cne $ExpectedHelperSha256)){throw 'Elevation result identity binding differs.'}
        $protectedRun=Get-StrictFullPath ([string]$result.protected_run_root) 'protected child evidence run'
        if(-not(Test-BootstrapSamePath (Split-Path -Parent $protectedRun) (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence')) -or
            [IO.Path]::GetFileName($protectedRun) -cnotmatch '^run-[0-9a-f]{32}$'){throw 'Protected child evidence run binding differs.'}
        Assert-InstallationEvidenceProtectedPath $protectedRun
        $expectedCapture=Join-Path $protectedRun ('elevation-capture.evidence.'+[int]$result.wrapper_process_id)
        if(-not(Test-BootstrapSamePath ([string]$result.capture_root) $expectedCapture)){throw 'Elevation capture root binding differs.'}
        Assert-BootstrapNoReparsePoint $expectedCapture 'elevation capture root' -PathOnly
        if([int64]$result.helper_process_id -eq 0) {
            if([int]$result.helper_exit_code -eq 0 -or $null -eq $result.failure -or $null -ne $result.streams -or [string]$result.helper_stage_evidence_root){throw 'Unstarted helper failure binding differs.'}
            return [ordered]@{status='CHILD_NOT_STARTED';helper_process_id=0;stage_evidence_root='';outer_stage_evidence_root=$parentRoot;
                capture_root=$expectedCapture;streams=$null;child_exit_code=[int]$result.helper_exit_code;failure=$result.failure;
                result_path=$path;result_sha256=Get-FileSha256 $path;evidence_summary=$result.evidence_summary}
        }
        foreach($name in @('stdout','stderr')) {
            $stream=$result.streams.$name
            $expected=Join-Path $expectedCapture ('elevated-helper-'+[int]$result.helper_process_id+'-'+$name+'.bin')
            if(-not(Test-BootstrapSamePath ([string]$stream.path) $expected)){throw 'Elevation stream path binding differs.'}
            Assert-BootstrapNoReparsePoint $expected 'elevation stream' -PathOnly
            if((Get-Item -LiteralPath $expected).Length -gt 1048576 -or (Get-FileSha256 $expected) -cne [string]$stream.sha256){throw 'Elevation stream hash/size binding differs.'}
        }
        $actualRoot=[string]$result.helper_stage_evidence_root
        if($actualRoot -and -not(Test-BootstrapSamePath $actualRoot ((Join-Path $protectedRun 'helper-audit')+'.evidence.'+[int]$result.helper_process_id))){throw 'Elevated helper journal identity binding differs.'}
        if($actualRoot){Assert-BootstrapNoReparsePoint $actualRoot 'elevated helper evidence' -PathOnly}
        $childSummary=if($actualRoot){Read-InstallationEvidenceChildSummary $actualRoot}else{$null}
        Register-InstallationChildEvidenceSummary $result.evidence_summary
        Register-InstallationChildEvidenceSummary $childSummary
        return [ordered]@{status=if($actualRoot){'BOUND_ELEVATED_CHILD'}else{'CHILD_JOURNAL_NOT_RECORDED'};helper_process_id=[int]$result.helper_process_id;
            stage_evidence_root=$actualRoot;outer_stage_evidence_root=$parentRoot;capture_root=$expectedCapture;streams=$result.streams;
            child_exit_code=[int]$result.helper_exit_code;failure=$result.failure;result_path=$path;result_sha256=Get-FileSha256 $path;evidence_summary=$result.evidence_summary;child_stage_evidence_summary=$childSummary}
    }
    if(-not $roots.Count){return [ordered]@{status='NOT_RECORDED';helper_process_id=$DirectProcessId;stage_evidence_root='';streams=$null}}
    $root=Get-StrictFullPath ([string]$roots[-1]) 'helper emitted evidence root'
    if(-not(Test-BootstrapSamePath $root $parentRoot)){
        # A directly privileged helper also relocates evidence to its protected
        # run. Preserve the same basename/PID and protected-control boundaries
        # used for the elevated-wrapper path; never accept an arbitrary root.
        $protectedRun=Split-Path -Parent $root
        if(-not(Test-BootstrapSamePath (Split-Path -Parent $protectedRun) (Join-Path (Get-InstallationEvidenceControlRoot) 'installation-evidence')) -or
            [IO.Path]::GetFileName($protectedRun) -cnotmatch '^run-[0-9a-f]{32}$' -or
            [IO.Path]::GetFileName($root) -cne [IO.Path]::GetFileName($parentRoot)){throw 'Direct helper evidence root binding differs.'}
        Assert-InstallationEvidenceProtectedPath $protectedRun
        Assert-InstallationEvidenceProtectedPath $root
    }
    Assert-BootstrapNoReparsePoint $root 'helper emitted evidence root' -PathOnly
    $childSummary=Read-InstallationEvidenceChildSummary $root
    Register-InstallationChildEvidenceSummary $childSummary
    return [ordered]@{status='BOUND_DIRECT_CHILD';helper_process_id=$DirectProcessId;stage_evidence_root=$root;streams=$null;child_stage_evidence_summary=$childSummary}
}

function Get-InstallationVerifiedScript {
    param([string]$Path,[string]$ExpectedSha256,[string]$PinFailure='Pinned installation source bytes differ.')
    # A bounded shared read, closed before hashing/parsing. Antivirus/indexer
    # handles and source replacement remain compatible; only captured bytes run.
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try{
        if($stream.Length -le 0 -or $stream.Length -gt 4194304){throw 'Pinned installation source size is invalid.'}
        $bytes=[byte[]]::new([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$read=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($read -eq 0){throw 'Pinned installation source read is incomplete.'};$offset+=$read}
        if($stream.ReadByte() -ne -1){throw 'Pinned installation source size changed.'}
    }finally{$stream.Dispose()}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    if($actual -cne $ExpectedSha256){throw $PinFailure}
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($text,$Path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Pinned installation source parse failed.'}
    return $ast.GetScriptBlock()
}

function ConvertTo-InstallationMemoryCommand([string]$Source,[string[]]$Arguments) {
    $literals=@($Arguments|ForEach-Object {"'"+([string]$_).Replace("'","''")+"'"})
    $command='& {'+$Source+"`n} "+($literals -join ' ')
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    if($encoded.Length -gt 30000){throw 'Installation memory command exceeds the supported argument budget.'}
    return $encoded
}

function Assert-InstallationMemoryCommandBound([string]$Encoded) {
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $line=(ConvertTo-BootstrapRelayArgument $winps)+' -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$Encoded
    if($line.Length -gt 16000){throw 'Installation launcher command exceeds the supported caller budget.'}
}

function Remove-InstallationMemoryTransport($Transport) {
    if($null -eq $Transport){return}
    foreach($path in $Transport.Paths){
        try{if([IO.File]::Exists($path)){Remove-Item -LiteralPath $path -ErrorAction Stop}}
        catch{
            # Cleanup must not replace the original child/cancellation/rollback
            # error. Retain incomplete evidence and the private file on failure.
            $Script:InstallationEvidenceFailed=$true
            Write-InstallationEvidenceEvent ([ordered]@{event='TRANSPORT_CLEANUP_FAILED';raw_arguments_recorded=$false})
        }
    }
}

function New-InstallationMemoryTransport([string]$Source,[string[]]$Arguments,[string]$Root,[string]$ReaderSid='') {
    Assert-InstallationEvidenceWriteRoot $Root
    $stem=Join-Path $Root ([Guid]::NewGuid().ToString('N').Substring(0,16))
    $paths=@(($stem+'.ps1'),($stem+'.dat'))
    $buffers=@([Text.UTF8Encoding]::new($false).GetBytes($Source),
        [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject ([string[]]@($Arguments)) -Compress)))
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $readers=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    if($ReaderSid){$readers+=$ReaderSid}
    foreach($sid in $readers | Select-Object -Unique){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Delete),'Allow'))
    }
    $created=@();$hashes=@()
    try{
        for($i=0;$i -lt 2;$i++){
            [byte[]]$bytes=$buffers[$i]
            if($bytes.Length -le 0 -or $bytes.Length -gt 16777216){throw 'Installation transport size is invalid.'}
            $sha=[Security.Cryptography.SHA256]::Create()
            try{$hashes+=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
            $stream=[IO.File]::Open($paths[$i],'CreateNew','Write','None');$created+=$paths[$i]
            try{
                # Only the DACL of this new file is set, before private content
                # is written. Do not require WRITE_OWNER/TakeOwnership.
                # Native setters clear the descriptor's modified flags. Give
                # each file a fresh DACL, so the second file is also protected.
                $fileAcl=[Security.AccessControl.FileSecurity]::new()
                $fileAcl.SetSecurityDescriptorSddlForm($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access),[Security.AccessControl.AccessControlSections]::Access)
                if($PSVersionTable.PSEdition -ceq 'Desktop'){[IO.File]::SetAccessControl($paths[$i],$fileAcl)}
                else{[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($paths[$i]),$fileAcl)}
                $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
            }finally{$stream.Dispose()}
        }
        $bootstrap=@'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$streams=[Collections.Generic.List[IO.Stream]]::new()
function ReadPinned([string]$path,[string]$expected){
 for($p=[IO.Path]::GetFullPath($path);$p;$p=[IO.Path]::GetDirectoryName($p)){
  if([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint){throw 'Installation transport reparse point.'}
 }
 $s=[IO.File]::Open($path,'Open','Read','Read');$streams.Add($s)
 if($s.Length -le 0 -or $s.Length -gt 16777216){throw 'Installation transport size is invalid.'}
 [byte[]]$b=([IO.BinaryReader]::new($s)).ReadBytes([int]$s.Length)
 if($b.Length -ne $s.Length -or $s.ReadByte() -ne -1){throw 'Installation transport read is incomplete.'}
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$actual=([BitConverter]::ToString($sha.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 if($actual -cne $expected){throw 'Installation transport byte pin differs.'}
 return ,$b
}
try{
 [byte[]]$code=ReadPinned '@@code-path@@' '@@code-sha@@'
 [byte[]]$data=ReadPinned '@@data-path@@' '@@data-sha@@'
 $utf8=[Text.UTF8Encoding]::new($false,$true)
 $json=$utf8.GetString($data).TrimStart([char]0xfeff)
 if(-not $json.StartsWith('[') -or -not $json.EndsWith(']')){throw 'Installation transport arguments are not an array.'}
 $parsed=ConvertFrom-Json -InputObject $json
 $values=@()
 if($json -cnotmatch '^\[\s*\]$'){$values=@($parsed)}
 if(@($values|Where-Object {$_ -isnot [string]}).Count){throw 'Installation transport arguments are not strings.'}
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseInput($utf8.GetString($code).TrimStart([char]0xfeff),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Installation transport parse failed.'}
 $block=$ast.GetScriptBlock()
 & $block @values
}catch{[Console]::Error.WriteLine('Installation launcher transport rejected.');exit 1}
finally{foreach($s in $streams){$s.Dispose()}}
'@
        $bootstrap=$bootstrap.Replace('@@code-path@@',$paths[0].Replace("'","''")).Replace('@@code-sha@@',$hashes[0]).Replace(
            '@@data-path@@',$paths[1].Replace("'","''")).Replace('@@data-sha@@',$hashes[1])
        $encoded=ConvertTo-InstallationMemoryCommand $bootstrap @()
        Assert-InstallationMemoryCommandBound $encoded
        return [pscustomobject]@{Encoded=$encoded;Paths=$paths;PayloadSha256=$hashes[1]}
    }catch{Remove-InstallationMemoryTransport ([pscustomobject]@{Paths=$created});throw}
}

function Get-InstallationHelperMemorySource {
    return @'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$target=$args[0];$targetSha=$args[1];$library=$args[2];$librarySha=$args[3]
$Script:InstallationEvidencePrivileged=$true;$Script:InstallationProtectedRunRoot=$args[4]
$libraryBlock=Get-InstallationVerifiedScript $library $librarySha
$helperBlock=Get-InstallationVerifiedScript $target $targetSha
. $libraryBlock
$Script:InstallationPinnedBootstrapLibrary=$libraryBlock
$bound=@{};$values=@($args|Select-Object -Skip 5)
for($i=0;$i -lt $values.Count;$i++){
 $name=([string]$values[$i]).TrimStart('-')
 $definition=@($helperBlock.Ast.ParamBlock.Parameters|Where-Object {$_.Name.VariablePath.UserPath -ieq $name})
 if($definition.Count -ne 1 -or -not([string]$values[$i]).StartsWith('-')){throw 'Elevated helper parameter is unsupported.'}
 if($definition[0].StaticType -eq [Management.Automation.SwitchParameter]){$bound[$name]=$true}
 else{if(++$i -ge $values.Count){throw 'Elevated helper parameter value is missing.'};$bound[$name]=[string]$values[$i]}
}
if($bound.ContainsKey('ElevationLogPath')){$bound['ElevationLogPath']=Join-Path $Script:InstallationProtectedRunRoot 'helper-audit'}
if($bound.ContainsKey('RepairAbandonedInstallationParent') -or $bound.ContainsKey('RepairOwnedInstallationParent')){$Script:InstallationAbandonedRepairAdmitted=$true}
& $helperBlock @bound
'@
}

function Get-InstallationElevationWrapperSource {
    # Transport pins protect the wrapper; the independent original source pins
    # and verified AST filename metadata remain mandatory inside it.
    return ('function Get-InstallationVerifiedScript {'+${function:Get-InstallationVerifiedScript}.ToString()+"}`n"+@'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($args.Count -lt 8){exit 1}
$target=[string]$args[0];$resultPath=[string]$args[1];$auditBase=[string]$args[2];$sid=[string]$args[3]
$parentPid=[int]$args[4];$targetSha=[string]$args[5];$librarySha=[string]$args[6]
$childArgs=[string[]]@($args | Select-Object -Skip 7)
$library=Join-Path (Split-Path -Parent $target) 'tools\bootstrap_integrity.ps1'
$index=[Array]::IndexOf($childArgs,'-WriterFenceDelegationToken')
$sensitive=@();if($index -ge 0 -and $index+1 -lt $childArgs.Length){$sensitive=@($childArgs[$index+1])}
try{
 $libraryBlock=Get-InstallationVerifiedScript $library $librarySha
 . $libraryBlock
 $Script:InstallationEvidencePrivileged=$true
 $Script:InstallationProtectedRunRoot=Split-Path -Parent $resultPath
 if(($childArgs -ccontains '-RepairAbandonedInstallationParent') -or ($childArgs -ccontains '-RepairOwnedInstallationParent')){
  $repairValues=@{}
  foreach($name in @('InstallRoot','OperatorLocalAppDataRoot','OperatorSid','AbandonedRecoverySourceManifestSha256','AbandonedRecoveryParentProcessId')){
   $index=[Array]::IndexOf($childArgs,'-'+$name)
   if($index -lt 0 -or $index+1 -ge $childArgs.Length){throw 'Abandoned repair argument missing.'}
   $repairValues[$name]=[string]$childArgs[$index+1]
  }
  $manifestPath=Join-Path (Split-Path -Parent $target) 'portable-manifest.json'
  if((Get-FileSha256 $manifestPath) -cne $repairValues.AbandonedRecoverySourceManifestSha256 -or $repairValues.OperatorSid -cne $sid -or [int]$repairValues.AbandonedRecoveryParentProcessId -ne $parentPid){throw 'Abandoned repair caller/source differs.'}
  $repairManifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json
  $writerFenceHelperPath=Join-Path (Split-Path -Parent $target) 'tools\container_writer_fence.ps1'
  . (Get-InstallationVerifiedScript $writerFenceHelperPath ([string]$repairManifest.writer_fence_helper_sha256))
  if($childArgs -ccontains '-RepairOwnedInstallationParent'){$Script:OwnedRepairManifestSha256=$repairValues.AbandonedRecoverySourceManifestSha256;$prior=Read-InstallationOwnedParentRepair $repairValues.InstallRoot $repairValues.OperatorLocalAppDataRoot $sid $parentPid $repairManifest}
  else{$prior=Read-InstallationAbandonedRollback $repairValues.InstallRoot $repairValues.OperatorLocalAppDataRoot $sid}
  if($null -eq $prior -or -not(Test-ContainerWriterSessionAuthorityHeldByOther ([string]$prior.active.session_authority_mutex_name))){throw 'Abandoned repair authority differs.'}
  New-InstallationProtectedDirectory (Split-Path -Parent $repairValues.InstallRoot) $sid -RecoverAbandoned
  $Script:InstallationAbandonedRepairAdmitted=$true
 }
 $captureRoot=Initialize-InstallationEvidence (Join-Path $Script:InstallationProtectedRunRoot 'elevation-capture') $sid $sensitive
}catch{
 # No privileged fallback to an operator-writable path before the run exists.
 if(Get-Command Get-InstallationPreparationExitCode -ErrorAction SilentlyContinue){exit (Get-InstallationPreparationExitCode $_)}
 exit 66
}
$child=$null;$failure=$null;$helperRoot='';$exitCode=1
try {
 Set-InstallationEvidenceStage 'elevation.helper_capture'
 $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
 $fileIndex=[Array]::IndexOf($childArgs,'-File')
 if($fileIndex -lt 0 -or $fileIndex+1 -ge $childArgs.Length -or -not(Test-BootstrapSamePath $childArgs[$fileIndex+1] $target)){throw 'Elevated helper invocation differs.'}
 $parameters=[string[]]@($childArgs|Select-Object -Skip ($fileIndex+2))
 $helperSource='function Get-InstallationVerifiedScript {'+${function:Get-InstallationVerifiedScript}.ToString()+"}`n"+(Get-InstallationHelperMemorySource)
 $helperTransport=New-InstallationMemoryTransport $helperSource (@($target,$targetSha,$library,$librarySha,$Script:InstallationProtectedRunRoot)+$parameters) $Script:InstallationEvidenceRoot
 $child=Invoke-InstallationEvidenceChild 'elevated-helper' $winps @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$helperTransport.Encoded)
 $exitCode=[int]$child.ExitCode
 $roots=@($child.Stdout -split "`r?`n" | Where-Object {$_ -cmatch '^installation_stage_evidence_root=.+$'} | ForEach-Object {$_.Substring('installation_stage_evidence_root='.Length)})
 if($roots.Count){
  $helperRoot=Get-StrictFullPath ([string]$roots[-1]) 'elevated helper emitted root'
  if(-not(Test-BootstrapSamePath $helperRoot ((Join-Path $Script:InstallationProtectedRunRoot 'helper-audit')+'.evidence.'+$child.ProcessId))){throw 'Elevated helper emitted journal binding differs.'}
  Assert-BootstrapNoReparsePoint $helperRoot 'elevated helper journal' -PathOnly
 }
 Complete-InstallationEvidenceStage 'forward'
}catch{$failure=Get-InstallationFailureDetails $_;Fail-InstallationEvidenceStages $_;$exitCode=1}
finally{Remove-InstallationMemoryTransport (Get-Variable -Name helperTransport -ValueOnly -ErrorAction SilentlyContinue)}
$summary=Complete-InstallationEvidence
$record=[ordered]@{schema='container-audit-installation-elevation-capture-v1';parent_process_id=$parentPid;wrapper_process_id=$PID;
 helper_process_id=if($null -ne $child){[int]$child.ProcessId}else{0};helper_exit_code=$exitCode;helper_sha256=$targetSha;
 helper_stage_evidence_root=$helperRoot;capture_root=$captureRoot;streams=if($null -ne $child){$child.Streams}else{$null};
 protected_run_root=$Script:InstallationProtectedRunRoot;
 evidence_summary=$summary;failure=$failure;raw_arguments_recorded=$false;secret_values_recorded=$false}
Assert-InstallationEvidenceWriteRoot (Split-Path -Parent $resultPath)
if(Test-Path -LiteralPath $resultPath){throw 'Elevation result already exists.'}
[IO.File]::WriteAllText($resultPath,(Protect-InstallationText ($record|ConvertTo-Json -Depth 10) -1),[Text.UTF8Encoding]::new($false))
Set-InstallationEvidenceAcl $resultPath $sid
exit $exitCode
'@)
}

function Invoke-InstallationElevationCapture([string]$Target,[string[]]$Arguments,[string]$AuditBase,[string]$OperatorSid,$AuthorityLease=$null) {
    if(Test-InstallationEvidencePrivileged){throw 'Elevation capture requires the ordinary operator caller.'}
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if(-not $root){throw 'Elevation capture requires initialized private evidence.'}
    Assert-BootstrapNoReparsePoint $root 'elevation capture parent' -PathOnly
    $resultPath=Join-Path $root 'elevation-result.json'
    if(Test-Path -LiteralPath $resultPath){throw 'Elevation capture target already exists.'}
    $control=Get-InstallationEvidenceControlRoot
    $ancestor=if(Test-Path -LiteralPath $control){$control}else{Split-Path -Parent $control}
    # Missing app/shared folders and the reviewed default ancestor shape are
    # prepared by the supported elevated creator; all other paths still refuse.
    if(($Arguments -ccontains '-RepairAbandonedInstallationParent') -or ($Arguments -ccontains '-RepairOwnedInstallationParent')){
        $rootIndex=[Array]::IndexOf($Arguments,'-InstallRoot');$ladIndex=[Array]::IndexOf($Arguments,'-OperatorLocalAppDataRoot')
        if($rootIndex -lt 0 -or $ladIndex -lt 0){throw 'Abandoned repair arguments differ.'}
        if($Arguments -ccontains '-RepairOwnedInstallationParent'){
            $manifest=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $Target) 'portable-manifest.json') -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
            $Script:OwnedRepairManifestSha256=Get-FileSha256 (Join-Path (Split-Path -Parent $Target) 'portable-manifest.json')
            $prior=Read-InstallationOwnedParentRepair $Arguments[$rootIndex+1] $Arguments[$ladIndex+1] $OperatorSid $PID $manifest
        }else{$prior=Read-InstallationAbandonedRollback $Arguments[$rootIndex+1] $Arguments[$ladIndex+1] $OperatorSid}
        if($null -eq $prior -or $null -eq $AuthorityLease){throw 'Abandoned repair authority is absent.'}
        # This caller owns the mutex on this thread: verify its actual lease.
        # HeldByOther is reserved for the separate elevated wrapper process.
        Assert-ContainerWriterSessionAuthority $prior.active $AuthorityLease
    }else{Assert-InstallationEvidenceProtectedPath $ancestor -AllowSupportedPreparation}
    $protectedRun=Join-Path (Join-Path $control 'installation-evidence') ('run-'+[Guid]::NewGuid().ToString('N'))
    $protectedResult=Join-Path $protectedRun 'elevation-result.json'
    $library=Join-Path (Split-Path -Parent $Target) 'tools\bootstrap_integrity.ps1'
    $targetSha=Get-FileSha256 $Target
    $transport=New-InstallationMemoryTransport (Get-InstallationElevationWrapperSource) (@($Target,$protectedResult,$AuditBase,$OperatorSid,[string]$PID,$targetSha,(Get-FileSha256 $library))+$Arguments) $root
    try{
    $argv=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$transport.Encoded)
    $line=($argv|ForEach-Object {ConvertTo-BootstrapRelayArgument ([string]$_)}) -join ' '
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    # Verb RunAs cannot share RedirectStandardOutput/Error parameter sets.
    # The supported elevated wrapper captures its finite helper internally.
    $process=Start-Process -FilePath $winps -Verb RunAs -ArgumentList $line -WindowStyle Hidden -Wait -PassThru
    $preparationFailure=Get-InstallationPreparationDiagnostic ([int]$process.ExitCode)
    if($null -ne $preparationFailure -and -not(Test-Path -LiteralPath $protectedResult)){
        Write-InstallationEvidenceEvent ([ordered]@{event='PREPARATION_FAILED';wrapper_pid=[int]$process.Id;exit_code=[int]$process.ExitCode;
            diagnostic_code=$preparationFailure.code;message=$preparationFailure.message;protected_run_root=$protectedRun;original_failure_available=$false})
        $failure=[InvalidOperationException]::new($preparationFailure.message+' ['+$preparationFailure.code+']')
        $failure.Data['installation_preparation_exit_code']=[int]$process.ExitCode
        throw $failure
    }
    Assert-InstallationEvidenceProtectedPath $protectedResult
    if((Get-Item -LiteralPath $protectedResult).Length -gt 65536){throw 'Elevation result is oversized.'}
    $resultText=Get-Content -LiteralPath $protectedResult -Raw -Encoding UTF8
    $result=$resultText | ConvertFrom-Json
    if([string]$result.schema -cne 'container-audit-installation-elevation-capture-v1' -or
        -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $PID -or
        -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -ne [int64]$process.Id -or
        [int]$result.helper_exit_code -ne [int]$process.ExitCode -or [string]$result.helper_sha256 -cne $targetSha -or
        -not(Test-BootstrapSamePath ([string]$result.protected_run_root) $protectedRun)){throw 'Elevated wrapper process/result binding differs.'}
    # Only this ordinary caller writes the operator-owned result/summary. The
    # privileged original and all streams remain in the protected run.
    Assert-InstallationEvidenceWriteRoot $root
    [IO.File]::WriteAllText($resultPath,(ConvertTo-KmtechRedactedSinkText $resultText),[Text.UTF8Encoding]::new($false))
    Set-InstallationEvidenceAcl $resultPath $OperatorSid
    if($result.helper_stage_evidence_root){
        $log=Join-Path ([string]$result.helper_stage_evidence_root) 'placement-result.jsonl'
        if(Test-Path -LiteralPath $log){Assert-InstallationEvidenceProtectedPath $log;[IO.File]::WriteAllText($AuditBase,(ConvertTo-KmtechRedactedSinkText ([IO.File]::ReadAllText($log))),[Text.UTF8Encoding]::new($false))}
        $exports=@{'RestoreEvidencePath'='restore-evidence.json'}
        if($Arguments -ccontains '-ReplaceExistingVerifiedPortable'){$exports['ReplacementReceiptPath']='replacement-receipt.json'}
        foreach($name in $exports.Keys){
            $index=[Array]::IndexOf($Arguments,'-'+$name)
            if($index -lt 0 -or $index+1 -ge $Arguments.Count){continue}
            $source=Join-Path ([string]$result.helper_stage_evidence_root) $exports[$name]
            if(-not(Test-Path -LiteralPath $source)){continue}
            Assert-InstallationEvidenceProtectedPath $source
            if((Get-Item -LiteralPath $source).Length -gt 1048576){throw 'Protected installation export is oversized.'}
            $destination=Get-StrictFullPath $Arguments[$index+1] 'ordinary installation result'
            Assert-BootstrapNoReparsePoint (Split-Path -Parent $destination) 'ordinary installation result parent' -PathOnly
            if(Test-Path -LiteralPath $destination){throw 'Ordinary installation result already exists.'}
            [IO.File]::WriteAllText($destination,(ConvertTo-KmtechRedactedSinkText ([IO.File]::ReadAllText($source))),[Text.UTF8Encoding]::new($false))
            Set-InstallationEvidenceAcl $destination $OperatorSid
        }
    }
    Write-InstallationEvidenceEvent ([ordered]@{event='ELEVATED_FINITE_CHILD';wrapper_pid=[int]$process.Id;helper_pid=[int]$result.helper_process_id;exit_code=[int]$process.ExitCode;result_path=$resultPath;result_sha256=Get-FileSha256 $resultPath})
    return [pscustomobject]@{ExitCode=[int]$process.ExitCode;Id=[int]$result.helper_process_id;WrapperProcessId=[int]$process.Id;ResultPath=$resultPath;
        HelperStageEvidenceRoot=[string]$result.helper_stage_evidence_root;Streams=$result.streams;EvidenceSummary=$result.evidence_summary}
    }finally{Remove-InstallationMemoryTransport $transport}
}

function Import-BootstrapCanonicalUserProcessApi([string]$VerifiedProducerRoot) {
    $path=Join-Path $VerifiedProducerRoot 'INSTALL_CANONICAL_PORTABLE.ps1'
    Assert-BootstrapNoReparsePoint $path 'verified normal-user process API' -PathOnly
    $manifest=Read-KmtechPortableManifest $VerifiedProducerRoot
    if([string]$manifest.installer_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Normal-user process API byte pin differs.'}
    $tree=(Get-InstallationVerifiedScript $path ([string]$manifest.installer_sha256) 'Normal-user process API byte pin differs.').Ast
    $functions=@($tree.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Initialize-CanonicalUserProcessApi'})
    if($functions.Count -ne 1){throw 'Normal-user process API definition is ambiguous.'}
    Invoke-Expression $functions[0].Extent.Text
    Initialize-CanonicalUserProcessApi
    if($null -eq [ContainerAuditCanonicalUserProcess].GetMethod('StartLimitedWithOverrides')){throw 'Normal-user finite producer API is unsupported.'}
}

function Get-InstallationNormalProducerWrapperSource {
    return ('function Get-InstallationVerifiedScript {'+${function:Get-InstallationVerifiedScript}.ToString()+"}`n"+@'
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($args.Count -lt 7){exit 1}
$library=[string]$args[0];$librarySha=[string]$args[1];$resultPath=[string]$args[2]
$parentPid=[int]$args[3];$sid=[string]$args[4];$executable=[string]$args[5]
$childArgs=[string[]]@($args|Select-Object -Skip 6)
$libraryBlock=Get-InstallationVerifiedScript $library $librarySha
. $libraryBlock
$security=Get-BootstrapRelaySecurity $PID
if($security.elevated -or $security.integrity_level -ne 8192 -or $security.sid -cne $sid -or $security.session_id -le 0){throw 'Finite lifecycle producer wrapper is not the ordinary operator.'}
$sensitive=@([Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','Process'))
$root=Initialize-InstallationEvidence (Join-Path (Split-Path -Parent $resultPath) 'normal-producer-capture') $sid $sensitive
$child=$null;$failure=$null;$exitCode=1
try {
 Set-InstallationEvidenceStage 'lifecycle.normal_producer_capture'
 $child=Invoke-InstallationEvidenceChild 'normal-producer' $executable $childArgs
 $exitCode=[int]$child.ExitCode
 Complete-InstallationEvidenceStage 'forward'
}catch{$failure=Get-InstallationFailureDetails $_;Fail-InstallationEvidenceStages $_}
$summary=Complete-InstallationEvidence
$record=[ordered]@{schema='container-audit-normal-producer-capture-v1';parent_process_id=$parentPid;wrapper_process_id=$PID;
 producer_process_id=if($null -ne $child){[int]$child.ProcessId}else{0};exit_code=$exitCode;security=$security;
 capture_root=$root;streams=if($null -ne $child){$child.Streams}else{$null};failure=$failure;evidence_summary=$summary;
 raw_arguments_recorded=$false;secret_values_recorded=$false}
Assert-BootstrapNoReparsePoint (Split-Path -Parent $resultPath) 'normal producer result parent' -PathOnly
if(Test-Path -LiteralPath $resultPath){throw 'Normal producer result already exists.'}
[IO.File]::WriteAllText($resultPath,(Protect-InstallationText ($record|ConvertTo-Json -Depth 10) -1),[Text.UTF8Encoding]::new($false))
Set-InstallationEvidenceAcl $resultPath $sid
exit $exitCode
'@)
}

function Start-BootstrapNormalProducerWrapper([string]$Line,$Caller,[string[]]$EnvironmentNames,[string[]]$EnvironmentValues) {
    return [ContainerAuditCanonicalUserProcess]::StartLimitedWithOverrides($Line,[string]$Caller.sid,[int]$Caller.session_id,$EnvironmentNames,$EnvironmentValues)
}

function Invoke-BootstrapNormalFiniteProducer([string]$VerifiedProducerRoot,[string]$Executable,[string[]]$Arguments,[string]$EvidenceBase) {
    $caller=Get-BootstrapRelaySecurity $PID
    if([int]$caller.session_id -le 0){throw 'Lifecycle producer requires the operator interactive session.'}
    $root=Initialize-InstallationEvidence ($EvidenceBase+'.normal') ([string]$caller.sid) @([Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','Process'))
    Set-InstallationEvidenceStage 'lifecycle.normal_producer_prepare'
    $transport=$null
    try {
    if(-not $caller.elevated){
        Set-InstallationEvidenceStage 'lifecycle.normal_producer_capture'
        $child=Invoke-InstallationEvidenceChild 'lifecycle-producer' $Executable $Arguments
        Complete-InstallationEvidenceStage 'forward';$summary=Complete-InstallationEvidence
        return [pscustomobject]@{ExitCode=$child.ExitCode;ProcessId=$child.ProcessId;Stdout=$child.Stdout;Stderr=$child.Stderr;
            Streams=$child.Streams;EvidenceSummary=$summary;Failure=$null;NormalProducerResultPath=''}
    }
    Import-BootstrapCanonicalUserProcessApi $VerifiedProducerRoot
    # The low token owns this result. Its directory is created by that token;
    # the elevated manager only reads it and records its own protected evidence.
    $resultPath=$EvidenceBase+'.normal-producer-result.'+[Guid]::NewGuid().ToString('N')+'.json'
    if(Test-Path -LiteralPath $resultPath){throw 'Normal producer capture target already exists.'}
    $library=Join-Path $VerifiedProducerRoot 'tools\bootstrap_integrity.ps1'
    $winps=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $transport=New-InstallationMemoryTransport (Get-InstallationNormalProducerWrapperSource) (@($library,(Get-FileSha256 $library),$resultPath,[string]$PID,[string]$caller.sid,$Executable)+$Arguments) $root ([string]$caller.sid)
    $argv=@((ConvertTo-BootstrapRelayArgument $winps),'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$transport.Encoded)
    $names=@('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID','CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID','CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID','CONTAINER_AUDIT_DATA_ROOT')
    $values=[string[]]@($names|ForEach-Object {[string][Environment]::GetEnvironmentVariable($_,'Process')})
    $wrapperPid=Start-BootstrapNormalProducerWrapper ($argv -join ' ') $caller $names $values
    $wrapperExit=$null
    try{$process=[Diagnostics.Process]::GetProcessById($wrapperPid);try{$process.WaitForExit();$wrapperExit=$process.ExitCode}finally{$process.Dispose()}}catch [ArgumentException]{if(-not(Test-Path -LiteralPath $resultPath -PathType Leaf)){throw}}
    Assert-BootstrapNoReparsePoint $resultPath 'normal producer result' -PathOnly
    if((Get-Item -LiteralPath $resultPath).Length -gt 65536){throw 'Normal producer result is oversized.'}
    $result=Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$result.schema -cne 'container-audit-normal-producer-capture-v1' -or
        -not(Test-BootstrapJsonInteger $result.parent_process_id) -or [int64]$result.parent_process_id -ne $PID -or
        -not(Test-BootstrapJsonInteger $result.wrapper_process_id) -or [int64]$result.wrapper_process_id -ne $wrapperPid -or
        -not(Test-BootstrapJsonInteger $result.producer_process_id) -or [int64]$result.producer_process_id -lt 0 -or
        -not(Test-BootstrapJsonInteger $result.exit_code) -or ($null -ne $wrapperExit -and [int]$result.exit_code -ne $wrapperExit) -or
        $result.security.elevated -isnot [bool] -or $result.security.elevated -or
        [int]$result.security.integrity_level -ne 8192 -or [string]$result.security.sid -cne [string]$caller.sid -or
        [int]$result.security.session_id -ne [int]$caller.session_id){throw 'Normal producer result/security binding differs.'}
    $expectedRoot=Join-Path (Split-Path -Parent $resultPath) ('normal-producer-capture.evidence.'+$wrapperPid)
    if(-not(Test-BootstrapSamePath ([string]$result.capture_root) $expectedRoot)){throw 'Normal producer capture root binding differs.'}
    Assert-BootstrapNoReparsePoint $expectedRoot 'normal producer capture root' -PathOnly
    if([int64]$result.producer_process_id -eq 0 -and ([int]$result.exit_code -eq 0 -or $null -eq $result.failure -or $null -ne $result.streams)){throw 'Unstarted normal producer failure binding differs.'}
    $texts=@{stdout='';stderr=''}
    if([int]$result.producer_process_id -gt 0){foreach($name in @('stdout','stderr')){
        $stream=$result.streams.$name;$path=Join-Path $expectedRoot ('normal-producer-'+[int]$result.producer_process_id+'-'+$name+'.bin')
        if(-not(Test-BootstrapSamePath ([string]$stream.path) $path)){throw 'Normal producer stream path binding differs.'}
        Assert-BootstrapNoReparsePoint $path 'normal producer stream' -PathOnly
        if((Get-Item -LiteralPath $path).Length -gt 1048576 -or (Get-FileSha256 $path) -cne [string]$stream.sha256){throw 'Normal producer stream hash/size binding differs.'}
        $texts[$name]=[Text.Encoding]::GetEncoding([string]$stream.encoding).GetString([IO.File]::ReadAllBytes($path))
    }}
    Write-InstallationEvidenceEvent ([ordered]@{event='NORMAL_FINITE_PRODUCER';wrapper_pid=$wrapperPid;producer_pid=[int]$result.producer_process_id;exit_code=[int]$result.exit_code;result_path=$resultPath;result_sha256=Get-FileSha256 $resultPath})
    Register-InstallationChildEvidenceSummary $result.evidence_summary
    Complete-InstallationEvidenceStage 'forward';$summary=Complete-InstallationEvidence
    return [pscustomobject]@{ExitCode=[int]$result.exit_code;ProcessId=[int]$result.producer_process_id;Stdout=$texts.stdout;Stderr=$texts.stderr;
        Streams=$result.streams;EvidenceSummary=$summary;Failure=$result.failure;NormalProducerResultPath=$resultPath}
    }catch{Fail-InstallationEvidenceStages $_;throw}
    finally{Remove-InstallationMemoryTransport $transport;[void](Complete-InstallationEvidence)}
}

function Complete-InstallationEvidenceStage([string]$Lane, $Failure=$null) {
    if (-not (Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }
    if (-not $Script:InstallationEvidenceLanes.ContainsKey($Lane)) { return }
    $stage=$Script:InstallationEvidenceLanes[$Lane]
    $stage.watch.Stop()
    $detail=$null; if ($null -ne $Failure) { $detail=Get-InstallationFailureDetails $Failure }
    Write-InstallationEvidenceEvent ([ordered]@{event='END';sequence=$stage.sequence;lane=$Lane;stage=$stage.name;result=if($null -eq $Failure){'PROVEN'}else{'FAILED'};elapsed_ms=$stage.watch.ElapsedMilliseconds;failure=$detail})
    $Script:InstallationEvidenceLanes.Remove($Lane)
}

function Set-InstallationEvidenceStage([string]$Name,[string]$Lane='forward') {
    if (-not (Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { return }
    Complete-InstallationEvidenceStage $Lane
    $Script:InstallationEvidenceSequence++
    $Script:InstallationEvidenceLanes[$Lane]=@{name=$Name;sequence=$Script:InstallationEvidenceSequence;watch=[Diagnostics.Stopwatch]::StartNew()}
    Write-InstallationEvidenceEvent ([ordered]@{event='START';sequence=$Script:InstallationEvidenceSequence;lane=$Lane;stage=$Name})
}

function Write-InstallationCaughtFailure($Failure) {
function Write-InstallationOriginalFailure($Failure) {
    $cap=(Protect-InstallationText -Configuration).full_byte_cap
    $record=[ordered]@{status='NOT_CONFIGURED';path='';sha256='';saved_bytes=0;complete=$false;byte_cap=$cap;depth_cap=64}
    $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if(-not $root){return $record}
    $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    $cacheKey='installation_original_failure_reference'
    if($exception.Data.Contains($cacheKey)){
        $cached=$exception.Data[$cacheKey]
        $published=Get-Variable -Name InstallationMostRecentOriginalFailureReference -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if([object]::ReferenceEquals($cached,$published) -and $cached.Contains('atomic_published') -and $cached.atomic_published -eq $true){return $cached}
    }
    $detail=Get-InstallationFailureDetails $Failure
    $detail.exception_chain=@();$observed=0;$complete=$true
    $exception=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    for($depth=0;$null -ne $exception -and $depth -lt 64;$depth++){
        $message=Protect-InstallationText ([string]$exception.Message) -1 -NoTruncate
        $message=[regex]::Replace($message,'S-\d+(?:-\d+)+','[SID redacted]')
        $native=if($exception -is [ComponentModel.Win32Exception]){$exception.NativeErrorCode}else{$null}
        $entry=[ordered]@{type=$exception.GetType().FullName;message=$message;hresult=$exception.HResult;win32_error=$native}
        $observed+=[Text.Encoding]::UTF8.GetByteCount(($entry|ConvertTo-Json -Depth 5 -Compress))
        # Reserve envelope space inside the common 64 KiB failure boundary.
        # Never present an omitted message as complete.
        if($observed -gt ($cap-4096)){$complete=$false;$entry.message=Protect-InstallationText $message ([Math]::Max(256,$cap-8192));$detail.exception_chain+=,$entry;break}
        $detail.exception_chain+=,$entry
        $exception=$exception.InnerException
    }
    if($null -ne $exception){$complete=$false}
    $payload=[ordered]@{schema='container-audit-original-installation-failure-v1';complete=$complete;
        byte_cap=$cap;depth_cap=64;observed_detail_bytes=$observed;truncated=(-not $complete);truncation_marker=if($complete){''}else{'[TRUNCATED: bounded original failure]'};failure=$detail}
    $temporary=$null
    try{
        Assert-InstallationEvidenceWriteRoot $root
        $path=Join-Path $root ('original-failure-'+[guid]::NewGuid().ToString('N')+'.json')
        $temporary=$path+'.tmp'
        $text=Protect-InstallationText ($payload|ConvertTo-Json -Depth 12 -Compress) -1 -NoTruncate
        while([Text.Encoding]::UTF8.GetByteCount($text) -gt $cap){
            $largest=@($payload.failure.exception_chain|Sort-Object @{Expression={[Text.Encoding]::UTF8.GetByteCount($_.message)};Descending=$true})[0]
            $length=[Text.Encoding]::UTF8.GetByteCount($largest.message)
            if($length -le 256){throw 'Original failure envelope exceeds its metadata budget.'}
            $largest.message=Protect-InstallationText $largest.message ([Math]::Max(256,[int]($length/2)))
            $complete=$false;$payload.complete=$false;$payload.truncated=$true;$payload.truncation_marker='[TRUNCATED: bounded original failure]'
            $text=Protect-InstallationText ($payload|ConvertTo-Json -Depth 12 -Compress) -1 -NoTruncate
        }
        $bytes=[Text.Encoding]::UTF8.GetBytes($text)
        if($bytes.Length -gt $cap){throw 'Original failure envelope exceeded its byte bound.'}
        $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        Set-InstallationEvidenceAcl $temporary $Script:InstallationEvidenceSid
        if(Test-InstallationEvidencePrivileged){Assert-InstallationEvidenceProtectedPath $temporary}
        [IO.File]::Move($temporary,$path)
        if(Test-InstallationEvidencePrivileged){Assert-InstallationEvidenceProtectedPath $path}
        $hasher=[Security.Cryptography.SHA256]::Create()
        try{$expectedDigest=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
        $digest=Get-FileSha256 $path
        if($digest -cne $expectedDigest -or (Get-Item -LiteralPath $path).Length -ne $bytes.Length){throw 'Original failure readback differs.'}
        $record.status=if($complete){'PRESERVED'}else{'INCOMPLETE_SIZE_OR_DEPTH_BOUND'}
        $record.path=$path;$record.sha256=$digest;$record.saved_bytes=$bytes.Length;$record.complete=$complete
        $record.atomic_published=$true
        $Script:InstallationMostRecentOriginalFailureReference=$record
    }catch{
        $record.status='IO_OR_ACL_FAILED';$Script:InstallationEvidenceFailed=$true
        $codes=Get-Variable -Name InstallationEvidenceFailureCodes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($null -ne $codes -and -not $codes.Contains('ORIGINAL_FAILURE_IO_OR_ACL_FAILURE')){$codes.Add('ORIGINAL_FAILURE_IO_OR_ACL_FAILURE')}
    }finally{if($temporary -and (Test-Path -LiteralPath $temporary)){Remove-Item -LiteralPath $temporary}}
    $outerException=if($Failure -is [Exception]){$Failure}else{$Failure.Exception}
    $outerException.Data[$cacheKey]=$record
    if(-not(Get-Variable -Name InstallationOriginalFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){$Script:InstallationOriginalFailure=$record}
    return $record
}

    $active=@()
    $lanes=Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $lanes){foreach($lane in $lanes.Keys){$active+=@{lane=$lane;stage=$lanes[$lane].name;sequence=$lanes[$lane].sequence}}}
    $original=Write-InstallationOriginalFailure $Failure
    Write-InstallationEvidenceEvent ([ordered]@{event='CAUGHT_FAILURE';active_stages=$active;failure=(Get-InstallationFailureDetails $Failure);original_failure=$original})
}

function Fail-InstallationEvidenceStages($Failure) {
    Write-InstallationCaughtFailure $Failure
    $lanes=Get-Variable -Name InstallationEvidenceLanes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $lanes) { foreach ($lane in @($lanes.Keys)) { Complete-InstallationEvidenceStage $lane $Failure } }
}

function Initialize-InstallationChildCapture {
    if ('KMTechInstallationChildCapture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Threading; using System.Diagnostics;
public static class KMTechInstallationChildCapture {
 public sealed class Output { public byte[] bytes; public long observed; public bool complete; }
 public sealed class Result { public int pid, exit_code; public Output stdout, stderr; }
 sealed class Reader {
  public MemoryStream saved=new MemoryStream(); public long observed; public bool complete; public object gate=new object();
  public void Read(Stream stream) { try { byte[] b=new byte[8192]; int n; while((n=stream.Read(b,0,b.Length))>0) { lock(gate) { observed+=n; int keep=(int)Math.Min(n,33554432-saved.Length); if(keep>0) saved.Write(b,0,keep); } } complete=true; } catch(ObjectDisposedException) {} catch(IOException) {} }
  public Output Snapshot() { lock(gate) { return new Output {bytes=saved.ToArray(),observed=observed,complete=complete}; } }
 }
 static string Quote(string value) {
  StringBuilder b=new StringBuilder("\""); int slashes=0;
  foreach(char c in value) { if(c=='\\') { slashes++; continue; } if(c=='\"') { b.Append('\\',slashes*2+1); b.Append(c); } else { b.Append('\\',slashes); b.Append(c); } slashes=0; }
  b.Append('\\',slashes*2); b.Append('"'); return b.ToString();
 }
 public static Result Run(string executable,string[] arguments,string directory) {
  ProcessStartInfo info=new ProcessStartInfo(executable); info.Arguments=String.Join(" ",Array.ConvertAll(arguments,Quote)); info.WorkingDirectory=directory;
  info.UseShellExecute=false; info.CreateNoWindow=true; info.RedirectStandardOutput=true; info.RedirectStandardError=true;
  using(Process p=new Process()) { p.StartInfo=info; if(!p.Start()) throw new IOException("Installer child did not start.");
   Reader output=new Reader(),error=new Reader(); Thread a=new Thread(()=>output.Read(p.StandardOutput.BaseStream)),b=new Thread(()=>error.Read(p.StandardError.BaseStream)); a.IsBackground=b.IsBackground=true; a.Start(); b.Start(); p.WaitForExit();
   // Wait only for this process. A persistent descendant may retain pipe handles.
   bool outDone=a.Join(750),errDone=b.Join(750); if(!outDone) p.StandardOutput.Dispose(); if(!errDone) p.StandardError.Dispose();
   return new Result {pid=p.Id,exit_code=p.ExitCode,stdout=output.Snapshot(),stderr=error.Snapshot()};
  }
 }
}
'@
}

function ConvertTo-SafeInstallationOutput($Output) {
    $bytes=[byte[]]$Output.bytes
    # A finite 32 MiB RAM admission boundary prevents unbounded child output.
    # Above it no partial input is persisted: a token/JSON value may straddle
    # the admission boundary. Ordinary output is redacted before its 64 KiB cap.
    if($Output.observed -gt $bytes.Length){return @{bytes=[Text.Encoding]::UTF8.GetBytes('[TRUNCATED: child input exceeded 33554432 byte RAM admission; detail unavailable]');redacted=$true;truncated=$true;encoding='utf-8'}}
    $truncated=($Output.observed -gt $bytes.Length -or -not $Output.complete)
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { $encoding=[Text.UnicodeEncoding]::new($false,$true,$true) }
    try { $text=$encoding.GetString($bytes) }
    catch {
        try { $encoding=[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage,[Text.EncoderFallback]::ExceptionFallback,[Text.DecoderFallback]::ExceptionFallback); $text=$encoding.GetString($bytes) }
        catch { return @{bytes=[Text.Encoding]::UTF8.GetBytes('[redacted: undecodable child output]');redacted=$true;truncated=$truncated;encoding='utf-8'} }
    }
    if ($truncated) {
        # Do not retain a partial credential/assignment at the capture boundary.
        $lastNewline=$text.LastIndexOf("`n")
        $text=if($lastNewline -ge 0){$text.Substring(0,$lastNewline+1)}else{''}
        $known=Get-Variable -Name InstallationEvidenceSensitiveValues -Scope Script -ErrorAction SilentlyContinue
        $values=$known.Value
        foreach($value in $values) {
            if ($value -is [string] -and $value.Length) {
                for($n=[Math]::Min($value.Length-1,$text.Length);$n -gt 0;$n--) {
                    if($text.EndsWith($value.Substring(0,$n),[StringComparison]::Ordinal)){$text=$text.Substring(0,$text.Length-$n);break}
                }
            }
        }
    }
    $safe=Protect-InstallationText $text -1
    $redacted=($safe -cne $text)
    $safe=ConvertTo-KmtechRedactedSinkText -Text $text
    $saved=[Text.Encoding]::UTF8.GetBytes($safe)
    $truncated=($truncated -or $safe.Contains('[TRUNCATED: '))
    if($truncated -and -not $safe.Contains('[TRUNCATED: ')){$safe+='[TRUNCATED: capture incomplete]';$saved=[Text.Encoding]::UTF8.GetBytes((Protect-InstallationText $safe -1))}
    return @{bytes=[byte[]]$saved;redacted=$redacted;truncated=$truncated;encoding='utf-8'}
}

function Invoke-InstallationEvidenceChild([string]$Name,[string]$Executable,[string[]]$Arguments,[string]$WorkingDirectory='') {
    Initialize-InstallationChildCapture
    if (-not $WorkingDirectory) { $WorkingDirectory=[IO.Path]::GetDirectoryName($Executable) }
    Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_START';stage=$Name;executable_leaf=[IO.Path]::GetFileName($Executable);byte_cap_per_stream=(Protect-InstallationText -Configuration).full_byte_cap;arguments_recorded=$false})
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $result=[KMTechInstallationChildCapture]::Run($Executable,$Arguments,$WorkingDirectory)
    $watch.Stop(); $streams=@{}; $texts=@{}; $evidenceFailure=$null
    # Decode/redact both native streams before attempting any evidence writes.
    # The child exit and original output must survive a failed protected writer.
    $safeOutputs=@{}
    foreach($streamName in @('stdout','stderr')){
        $safeOutputs[$streamName]=ConvertTo-SafeInstallationOutput $result.$streamName
        $texts[$streamName]=[Text.Encoding]::GetEncoding($safeOutputs[$streamName].encoding).GetString($safeOutputs[$streamName].bytes)
    }
    $Script:InstallationLastChildCapture=[ordered]@{stage=$Name;pid=$result.pid;exit_code=$result.exit_code;stdout=(Protect-InstallationText $texts.stdout 512);stderr=(Protect-InstallationText $texts.stderr 512)}
    foreach ($streamName in @('stdout','stderr')) {
        $output=$result.$streamName; $safe=$safeOutputs[$streamName]
        $path='';$storedSha=''
        $root=Get-Variable -Name InstallationEvidenceRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if($root) {
            try{
                Assert-InstallationEvidenceWriteRoot $root
                $path=Join-Path $root ($Name+'-'+$result.pid+'-'+$streamName+'.bin')
                if(Test-Path -LiteralPath $path){throw 'Installer child evidence target already exists.'}
                [IO.File]::WriteAllBytes($path,$safe.bytes)
                Set-InstallationEvidenceAcl $path $Script:InstallationEvidenceSid
                $storedSha=Get-FileSha256 $path
            }catch{
                if($null -eq $evidenceFailure){$evidenceFailure=Get-InstallationFailureDetails $_}
                $path='';$Script:InstallationEvidenceFailed=$true
                if(-not $Script:InstallationEvidenceFailureCodes.Contains('CHILD_STREAM_IO_OR_ACL_FAILURE')){$Script:InstallationEvidenceFailureCodes.Add('CHILD_STREAM_IO_OR_ACL_FAILURE')}
            }
        }
        $streams[$streamName]=@{path=$path;observed_bytes=$output.observed;saved_bytes=$safe.bytes.Length;complete=$output.complete;truncated=$safe.truncated;redacted=$safe.redacted;sha256=$storedSha;encoding=$safe.encoding}
    }
    $Script:InstallationLastChildEvidenceFailure=$evidenceFailure
    if(($result.exit_code -ne 0 -or $null -ne $evidenceFailure) -and
        -not(Get-Variable -Name InstallationFirstFailedChildCapture -Scope Script -ValueOnly -ErrorAction SilentlyContinue)){
        $Script:InstallationFirstFailedChildCapture=$Script:InstallationLastChildCapture
        $Script:InstallationFirstFailedChildEvidenceFailure=$evidenceFailure
        $Script:InstallationFirstFailedChildStreams=$streams
    }
    Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_EXIT';stage=$Name;pid=$result.pid;exit_code=$result.exit_code;elapsed_ms=$watch.ElapsedMilliseconds;streams=$streams;evidence_failure=$evidenceFailure})
    # A pinned helper's bounded one-line fallback belongs in its parent's own
    # journal. Retain it even when the helper could not persist a summary file.
    $failureDiagnostic=$null
    foreach($line in @($texts.stdout -split '\r?\n')){
        if($line.StartsWith('installation_failure_summary=',[StringComparison]::Ordinal)){
            try{
                if([Text.Encoding]::UTF8.GetByteCount($line) -gt 65536){throw 'Helper failure JSON exceeded the 64 KiB bound; full stream evidence remains authoritative.'}
                $diagnostic=$line.Substring('installation_failure_summary='.Length) | ConvertFrom-Json
                if([string]$diagnostic.schema -ceq 'container-audit-installation-fallback-v1' -and [int]$diagnostic.exit_code -in @(71,72,73)){
                    Write-InstallationEvidenceEvent ([ordered]@{event='CHILD_FAILURE_FALLBACK';stage=$Name;pid=$result.pid;child_exit_code=$result.exit_code;diagnostic=$diagnostic})
                    if($null -eq $failureDiagnostic -and [int]$diagnostic.exit_code -eq [int]$result.exit_code){$failureDiagnostic=$diagnostic}
                }
            }catch{Write-InstallationCaughtFailure $_}
        }
    }
    return [pscustomobject]@{ExitCode=$result.exit_code;ProcessId=$result.pid;Stdout=$texts.stdout;Stderr=$texts.stderr;Streams=$streams;EvidenceFailure=$evidenceFailure;FailureDiagnostic=$failureDiagnostic}
}

function Get-InstallationFallbackDiagnostic($Failure) {
    $detail=Get-InstallationFailureDetails $Failure
    $detail.script_file=Protect-InstallationText $detail.script_file 96
    if($detail.exception_chain.Count -gt 4){$detail.exception_chain=@($detail.exception_chain | Select-Object -First 3)+@($detail.exception_chain[-1])}
    foreach($item in $detail.exception_chain){$item.message=Protect-InstallationText $item.message 96;$item.type=Protect-InstallationText $item.type 96}
    $child=Get-Variable -Name InstallationLastChildCapture -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $evidence=Get-Variable -Name InstallationLastChildEvidenceFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $first=Get-Variable -Name InstallationFirstFailedChildCapture -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $first){$child=$first;$evidence=Get-Variable -Name InstallationFirstFailedChildEvidenceFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue}
    if($null -ne $child){
        $child=($child|ConvertTo-Json -Depth 12)|ConvertFrom-Json
        $child.stdout=Protect-InstallationText $child.stdout 256
        $child.stderr=Protect-InstallationText $child.stderr 256
        $child.stage=Protect-InstallationText $child.stage 96
    }
    if($null -ne $evidence){
        $evidence=($evidence|ConvertTo-Json -Depth 12)|ConvertFrom-Json
        $evidence.script_file=Protect-InstallationText $evidence.script_file 96
        if($evidence.exception_chain.Count -gt 4){$evidence.exception_chain=@($evidence.exception_chain | Select-Object -First 3)+@($evidence.exception_chain[-1])}
        foreach($item in $evidence.exception_chain){$item.message=Protect-InstallationText $item.message 96;$item.type=Protect-InstallationText $item.type 96}
    }
    # Fixed table: protected evidence write / native child / other helper failure.
    $code=if($null -ne $evidence){71}elseif($null -ne $child -and [int]$child.exit_code -ne 0){72}else{73}
    $diagnostic=[ordered]@{schema='container-audit-installation-fallback-v1';exit_code=$code;failure=$detail;child=$child;evidence_failure=$evidence}
    $original=Get-Variable -Name InstallationOriginalFailure -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $original){$diagnostic.original_failure=$original}
    $streams=Get-Variable -Name InstallationFirstFailedChildStreams -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if($null -ne $streams){$diagnostic.child_streams=$streams}
    return $diagnostic
}

function Get-StrictFullPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose must be an absolute path."
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "$Purpose must not use a device namespace."
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($full) -or $full -eq [IO.Path]::GetPathRoot($full)) {
        throw "$Purpose must not be a filesystem root."
    }
    return $full
}

function Protect-KmtechCodeAncestors([string]$CodeParent,[switch]$AdmissionOnly,[switch]$BeforeAppCreation,[string]$ProtectedAncestor) {
    # Deliberately persistent, non-recursive protection of these two shared paths.
    # Never restore their old permissions as part of an app rollback/uninstall.
    if (-not ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($CodeParent))).Equals('C:\KMTech\Apps',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Code parent must be a direct application directory under C:\KMTech\Apps.'
    }
    if($ProtectedAncestor -and (-not $AdmissionOnly -or $ProtectedAncestor -notin @('C:\KMTech','C:\KMTech\Apps'))){
        throw 'Protected ancestor admission requires one literal shared ancestor and read-only admission.'
    }
    $records=@(); $plans=@()
    function Get-KmtechAncestorAclShapeKey($Acl) {
        (@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
            [string]$_.IdentityReference.Value+'|'+[int64]$_.FileSystemRights+'|'+[string]$_.AccessControlType+'|'+[int]$_.InheritanceFlags+'|'+[int]$_.PropagationFlags+'|'+[int]$_.IsInherited
        } | Sort-Object) -join ';')
    }
    $ancestorPaths=if($ProtectedAncestor){@($ProtectedAncestor)}else{@('C:\KMTech','C:\KMTech\Apps')}
    foreach ($path in $ancestorPaths) {
        $reason=''
        if (-not (Test-Path -LiteralPath $path)) {
            if($AdmissionOnly -and -not $ProtectedAncestor){continue}
            if($AdmissionOnly){
                $reason='폴더가 없습니다'
                Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_REJECTED';path=$path;reason=$reason;before_sddl=$null;changed=$false})
                $failure=[InvalidOperationException]::new("설치 폴더 권한을 확인하세요: $path ($reason). 지원 담당자에게 문의하세요.")
                $failure.Data['canonical_code']='CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED'
                $failure.Data['ancestor_trust_failure']=$failure.Message
                $failure.Data['installation_preparation_exit_code']=61
                throw $failure
            }
            $ancestor=Split-Path -Parent $path
            $entry=Get-Item -LiteralPath $ancestor -ErrorAction Stop
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $reason='상위 폴더가 재분석 지점입니다' }
            else { [void][IO.Directory]::CreateDirectory($path) }
        }
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $reason='폴더가 재분석 지점입니다' }
        $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
        $before=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $shape=@(
            'S-1-5-32-544|2032127|Allow|3|0', 'S-1-5-18|2032127|Allow|3|0',
            'S-1-5-32-545|1179817|Allow|3|0', 'S-1-5-11|-536805376|Allow|3|2'
        )
        foreach($rule in $rules) {
            if ([string]$rule.AccessControlType -cne 'Allow') { $reason='거부 권한 항목이 있습니다' }
        }
        $actualKey=Get-KmtechAncestorAclShapeKey $acl
        $defaultKey=(@(($shape+@('S-1-5-11|1245631|Allow|0|0')) | ForEach-Object {$_+'|1'} | Sort-Object) -join ';')
        $targetKey=(@(($shape+@('S-1-5-11|1179823|Allow|0|0')) | ForEach-Object {$_+'|0'} | Sort-Object) -join ';')
        $defaultShape=($rules.Count -eq 5 -and -not $acl.AreAccessRulesProtected -and $actualKey -ceq $defaultKey)
        $targetShape=($rules.Count -eq 5 -and $acl.AreAccessRulesProtected -and $actualKey -ceq $targetKey)
        if($owner -cne 'S-1-5-32-544'){$reason='폴더 소유자가 예상과 다릅니다'}
        if(-not $reason -and -not $defaultShape -and -not $targetShape){$reason='권한 모양이 지원하는 기본값 또는 보호된 값과 다릅니다'}
        if(-not $reason -and $ProtectedAncestor -and -not $targetShape){$reason='권한 모양이 지원하는 보호된 값과 다릅니다'}
        if($reason) {
            Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_REJECTED';path=$path;reason=$reason;before_sddl=$before;changed=$false})
            $failure=[InvalidOperationException]::new("설치 폴더 권한을 확인하세요: $path ($reason). 지원 담당자에게 문의하세요.")
            $failure.Data['canonical_code']='CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED'
            $failure.Data['ancestor_trust_failure']=$failure.Message
            $failure.Data['installation_preparation_exit_code']=if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){62}elseif($owner -cne 'S-1-5-32-544'){63}else{61}
            throw $failure
        }
        $plans+=@{path=$path;shape_key=$actualKey;comparison_key=(Get-BootstrapAclComparisonKey $before);owner=$owner;group=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value;
            protected=$acl.AreAccessRulesProtected;
            default_shape=$defaultShape;target_shape=$targetShape}
    }
    if($AdmissionOnly){return}
    # Both existing shapes are admitted before the first ACL write.
    foreach($plan in $plans) {
        $path=$plan.path
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Ancestor became a reparse point before protection.'}
        $fresh=Get-Acl -LiteralPath $path -ErrorAction Stop
        $freshSddl=$fresh.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        # Our preceding parent write can reorder this child's inherited ACEs.
        # Reject changed permissions/identity/flags, then transform the fresh ACL.
        if((Get-BootstrapAclComparisonKey $freshSddl) -cne $plan.comparison_key -or
            $fresh.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $plan.owner -or
            $fresh.GetGroup([Security.Principal.SecurityIdentifier]).Value -cne $plan.group -or
            $fresh.AreAccessRulesProtected -ne $plan.protected){throw 'Ancestor ACL changed during protection admission.'}
        $acl=$fresh; $before=$freshSddl
        Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_BEFORE';path=$path;before_sddl=$before;already_target=$plan.target_shape;intentional_persistent_change=$true})
        if($plan.default_shape) {
            $acl.SetAccessRuleProtection($true,$true)
            # .NET can retain the inherited flag until persistence. Convert each
            # copied ACE explicitly without remapping its generic/inherit-only mask.
            $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
            foreach($ace in $raw.DiscretionaryAcl){$ace.AceFlags=[Security.AccessControl.AceFlags]([int]$ace.AceFlags -band (-bnot [int][Security.AccessControl.AceFlags]::Inherited))}
            $binary=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($binary,0)
            $acl.SetSecurityDescriptorBinaryForm($binary,[Security.AccessControl.AccessControlSections]::Access)
            $self=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.IdentityReference.Value -ceq 'S-1-5-11' -and [int64]$_.FileSystemRights -eq 1245631 -and [int]$_.InheritanceFlags -eq 0 -and [int]$_.PropagationFlags -eq 0
            })
            if($self.Count -ne 1){throw 'Ancestor ACL copied self-entry readback failed.'}
            $acl.RemoveAccessRuleSpecific($self[0])
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new('S-1-5-11'),
                [Security.AccessControl.FileSystemRights]1179823,'None','None','Allow'))
            Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
        }
        $afterAcl=Get-Acl -LiteralPath $path -ErrorAction Stop
        $after=$afterAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        $afterRules=@($afterAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $afterKey=Get-KmtechAncestorAclShapeKey $afterAcl
        if($afterAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or -not $afterAcl.AreAccessRulesProtected -or $afterRules.Count -ne 5 -or $afterKey -cne $targetKey){throw 'Ancestor ACL protected readback failed.'}
        $record=[ordered]@{path=$path;before_sddl=$before;after_sddl=$after;changed=$plan.default_shape;intentional_persistent_change=$true}
        $records+=$record
        Write-InstallationEvidenceEvent ([ordered]@{event='ANCESTOR_ACL_AFTER';record=$record})
    }
    # The app directory is the guarded leaf; Apps/KMTech are higher ancestors,
    # where direct creation remains allowed. This also rejects user-owned squatters.
    try { if(-not $BeforeAppCreation){Assert-ProtectedCodeAncestors $CodeParent} }
    catch {
        Write-InstallationCaughtFailure $_
        $failure=[InvalidOperationException]::new("설치 폴더 권한을 확인하세요: $CodeParent (코드 경로의 신뢰 재검사가 실패했습니다). 지원 담당자에게 문의하세요.",$_.Exception)
        $failure.Data['canonical_code']='CONTAINER_PLACEMENT_ANCESTOR_TRUST_FAILED'
        $failure.Data['ancestor_trust_failure']=$failure.Message
        throw $failure
    }
    return [pscustomobject]@{status='VERIFIED';records=$records;rollback_restores_ancestor_permissions=$false}
}

function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-RelativeCodePath([string]$Root, [string]$Path) {
    $rootFull = (Get-StrictFullPath $Root "inventory root") + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Inventory path escaped its root."
    }
    return $pathFull.Substring($rootFull.Length).Replace('\', '/')
}

function Get-BootstrapSharedPortableLeaf([string]$Root, [string]$Leaf = 'portable.ps1') {
    # This bootstrap is trusted with the installer. Never use shared code to
    # authenticate itself, or derive the expected release pin from input bytes.
    $rootFull = Get-StrictFullPath $Root 'shared installer root'
    Assert-BootstrapNoReparsePoint $rootFull 'shared installer root' -PathOnly
    $appRoot = $rootFull
    if (Test-Path -LiteralPath (Join-Path $rootFull 'app') -PathType Container) {
        $appRoot = Join-Path $rootFull 'app'
    }
    $lockPath = Join-Path $appRoot 'kmtech_shared.lock.json'
    $manifestPath = Join-Path $appRoot 'kmtech_shared.manifest.json'
    if ($Leaf -cnotin @('portable.ps1','data_generation.ps1')) { throw 'Shared PowerShell leaf is not approved.' }
    $sharedLeaf = Join-Path $appRoot ('kmtech_shared\powershell\' + $Leaf)
    foreach ($path in @($lockPath, $manifestPath, $sharedLeaf)) {
        Assert-BootstrapNoReparsePoint $path 'shared installer input' -PathOnly
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Shared installer input must be a file.'
        }
    }
    $expectedManifestSha = 'de1aa3a5a2b072ec15ec2b3d60733881dcf4d5c87f14b15ed06691ba643ac918'
    if ((Get-Item -LiteralPath $lockPath).Length -gt 65536) { throw 'Shared consumer lock is oversized.' }
    $lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (@($lock.PSObject.Properties.Name).Count -ne 2 -or
        $lock.version -cne '0.3.3' -or $lock.manifest_sha256 -cne $expectedManifestSha) {
        throw 'Shared consumer lock pin mismatch.'
    }
    if ((Get-FileSha256 $manifestPath) -cne $expectedManifestSha) {
        throw 'Shared manifest pin mismatch.'
    }
    $pinnedSharedManifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $expectedLeafSha = $pinnedSharedManifest.files.('kmtech_shared/powershell/' + $Leaf)
    if ((Get-FileHash -LiteralPath $sharedLeaf -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedLeafSha) {
        throw 'Shared PowerShell leaf pin mismatch.'
    }
    return $sharedLeaf
}

function Get-CodeInventory([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "code root"
    $result = [Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -File -Force -Recurse)) {
        $relative = Get-RelativeCodePath $rootFull $file.FullName
        if ($relative.Equals($BootstrapIntegrityFileName, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $result.Add($relative, [pscustomobject][ordered]@{
            path = $relative
            size = [int64]$file.Length
            sha256 = Get-FileSha256 $file.FullName
        })
    }
    return @($result.Values)
}

function Assert-ContainerDataGenerationTarget(
    [string]$CandidateRoot, [string]$TargetSid, [string]$LocalAppDataRoot,
    [string]$DataRoot, [string]$HelperRoot
) {
    # Caller already owns the existing deployment/writer admission and authenticates
    # the candidate tree. Unsigned portable floors never grant downgrade permission.
    $dataGenerationLeaf = Get-BootstrapSharedPortableLeaf $HelperRoot 'data_generation.ps1'
    . $dataGenerationLeaf
    try {
        Assert-KmtechDataIdentity 'container_audit' $TargetSid
        $local = Get-StrictFullPath $LocalAppDataRoot 'operator LOCALAPPDATA'
        if (-not $DataRoot) { $DataRoot = Join-Path $local 'KMTech\ContainerAudit' }
        $data = Get-StrictFullPath $DataRoot 'operator data root'
        $markers = @((Join-Path $data 'data-generation.json'),
            (Join-Path $local ('KMTech\DirectSync\container_audit\control\writer-session\data-generation\' + $TargetSid + '.json')))
        $present = $false
        foreach ($marker in $markers) {
            if ($null -ne (Read-KmtechDataGeneration $marker 'container_audit' $TargetSid)) { $present = $true }
        }
        # A pre-G candidate can lack version metadata. No generation means the
        # existing before-data-open restoration still proceeds; no claim is written.
        if (-not $present) { return }
        $candidate = Get-StrictFullPath $CandidateRoot 'candidate code root'
        $manifestPath = Join-Path $candidate 'portable-manifest.json'
        $frozen = -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)
        if ($frozen) { $manifestPath = Join-Path $candidate 'build-identity.json' }
        Assert-BootstrapNoReparsePoint $manifestPath 'candidate release metadata' -PathOnly
        if ((Get-Item -LiteralPath $manifestPath).Length -gt 65536) { throw 'Release metadata is oversized.' }
        $metadata = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $version = [string]$metadata.version
        if ($frozen) { $version = [string]$metadata.app_version }
        if (-not $version) {
            $sourceFile = Join-Path $candidate 'app\Container_Audit.py'
            if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) { $sourceFile = Join-Path $candidate 'Container_Audit.py' }
            Assert-BootstrapNoReparsePoint $sourceFile 'candidate version source' -PathOnly
            if ((Get-Item -LiteralPath $sourceFile).Length -gt 2097152) { throw 'Version source is oversized.' }
            $sourceText = Get-Content -LiteralPath $sourceFile -Raw -Encoding UTF8
            if ($sourceText -cmatch '(?m)^CURRENT_VERSION\s*=\s*"(v[0-9]+\.[0-9]+\.[0-9]+)"\s*$') { $version = $Matches[1] }
        }
        $decision = Get-KmtechDataDowngradeDecision -MarkerPaths $markers -TargetVersion $version `
            -AppId 'container_audit' -SubjectSid $TargetSid -TargetBuildId ([string]$metadata.source_commit)
    }
    catch {
        throw '이 PC의 자료 판을 확인할 수 없어 옛 판으로 되돌릴 수 없습니다. 자료와 확인 기록을 보존하고 관리자 지원 복구를 요청하세요.'
    }
    if (-not $decision.allowed) { throw $decision.message }
}

function Get-InventoryAggregate([object[]]$Inventory) {
    $lines = @($Inventory | ForEach-Object { "$($_.sha256) $($_.size) $($_.path)" })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-InstallationMachineMetadataNoSecrets([string]$Json) {
    # Authentication documents preserve their exact bytes. Reject secret
    # content before opening even a temporary file; diagnostics use the sink
    # redactor instead. The selection policy remains one common constant.
    $policy=Protect-InstallationText -Configuration
    $environment=[Environment]::GetEnvironmentVariables('Process')
    $selected=[Collections.Generic.List[string]]::new()
    foreach($name in $environment.Keys){
        $explicit=$name -cin $policy.environment_names
        if(-not $explicit -and ($name -notmatch $policy.sensitive_pattern -or $name -match $policy.path_pattern)){continue}
        $value=[string]$environment[$name]
        if(-not $value){continue}
        $identifier=$name -match $policy.identifier_name_pattern -and $value -cmatch $policy.identifier_value_pattern
        foreach($pattern in $policy.process_identifier_patterns.Keys){
            if($name -match $pattern -and $value -cmatch $policy.process_identifier_patterns[$pattern]){$identifier=$true;break}
        }
        if(-not $explicit -and $identifier){continue}
        $selected.Add($value)
    }
    $known=Get-Variable -Name InstallationEvidenceSensitiveValues -Scope Script -ErrorAction SilentlyContinue
    if($null -ne $known){foreach($value in $known.Value){if($value -is [string] -and $value){$selected.Add($value)}}}
    foreach($name in @('CanonicalWriterFenceDelegationToken','WriterFenceDelegationToken')){
        $value=Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue
        if($value -is [string] -and $value){$selected.Add($value)}
    }
    foreach($value in $selected){
        $quoted=ConvertTo-Json -InputObject $value -Compress
        $variants=@($value,$quoted.Substring(1,$quoted.Length-2),$value.Replace("'","''"),$value.Replace('"','""'))
        foreach($variant in $variants){
            if($Json.Contains($variant)){throw 'BOOTSTRAP_MACHINE_METADATA_SECRET_DETECTED'}
        }
    }
}
function Write-Utf8Json([string]$Path, $Payload) {
    $temporary = "$Path.tmp.$PID"
    $json = (($Payload | ConvertTo-Json -Depth 40).Replace("`r`n","`n")) + "`n"
    Assert-InstallationMachineMetadataNoSecrets $json
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-BootstrapIntegrityRecord(
    [string]$Root,
    [string]$CodeRootIdentity,
    [string]$RecordedAt = ""
) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $inventory = @(Get-CodeInventory $rootFull)
    if ($inventory.Count -eq 0) {
        throw "Bootstrap integrity inventory is empty."
    }
    if ([string]::IsNullOrWhiteSpace($RecordedAt)) {
        $RecordedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    $record = [ordered]@{
        schema_version = $BootstrapIntegritySchema
        status = 'PASS'
        code_root = $CodeRootIdentity
        installed_at = $RecordedAt
        file_count = $inventory.Count
        aggregate_sha256 = Get-InventoryAggregate $inventory
        files = $inventory
        identity_profile_created = $false
        state_scope = 'current_user_first_run'
    }
    Write-Utf8Json (Join-Path $rootFull $BootstrapIntegrityFileName) $record
    return [pscustomobject]$record
}

function Assert-BootstrapIntegrityRecord([string]$Root) {
    $rootFull = Get-StrictFullPath $Root "bootstrap integrity root"
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw "Bootstrap integrity record is absent."
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$record.schema_version -cne $BootstrapIntegritySchema -or [string]$record.status -cne 'PASS') {
        throw "Bootstrap integrity record schema or status is invalid."
    }
    if ([string]$record.code_root -ceq '.') {
        $declaredCodeRoot = $rootFull
    }
    else {
        $declaredCodeRoot = Get-StrictFullPath ([string]$record.code_root) "bootstrap integrity code root"
    }
    if (-not $declaredCodeRoot.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bootstrap integrity record code root is invalid."
    }
    $inventory = @(Get-CodeInventoryInRecordOrder $rootFull @($record.files))
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count
    ) {
        throw "Bootstrap integrity record file count is invalid."
    }
    for ($index = 0; $index -lt $inventory.Count; $index += 1) {
        $actual = $inventory[$index]
        $expected = @($record.files)[$index]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [string]$expected.path -cne [string]$actual.path -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw "Bootstrap integrity inventory differs at index $index."
        }
    }
    $aggregate = Get-InventoryAggregate $inventory
    if ([string]$record.aggregate_sha256 -cne $aggregate) {
        throw "Bootstrap integrity aggregate is invalid."
    }
    $frozenMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'Container_Audit.exe' }
    ).Count
    $portablePythonCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'runtime/pythonw.exe' }
    ).Count
    $portableMainCount = @(
        $inventory | Where-Object { [string]$_.path -ieq 'app/main.py' }
    ).Count
    $frozenLayout = $frozenMainCount -eq 1
    $portableLayout = $portablePythonCount -eq 1 -and $portableMainCount -eq 1
    if ($frozenLayout -eq $portableLayout) {
        throw "Bootstrap integrity record does not identify exactly one supported release layout."
    }
    return [pscustomobject]@{
        status = 'PASS'
        record_path = $recordPath
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
    }
}

function Test-BootstrapJsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}

function Assert-BootstrapProtectedRelayPath([string]$Path,[switch]$AllowSupportedPreparation) {
    if($AllowSupportedPreparation){Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit' -AdmissionOnly}
    $full=Get-StrictFullPath $Path 'protected relay path';$leaf=$true
    while($full) {
        $shared=$full -in @('C:\KMTech','C:\KMTech\Apps')
        if($AllowSupportedPreparation -and -not(Test-Path -LiteralPath $full) -and
            ($shared -or $full -ieq 'C:\KMTech\Apps\Container_Audit')){
            $full=[IO.Path]::GetDirectoryName($full);$leaf=$false;continue
        }
        $entry=Get-Item -LiteralPath $full -ErrorAction Stop
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){
            $failure=[InvalidOperationException]::new('Relay path contains a reparse point.')
            $failure.Data['installation_preparation_exit_code']=62;throw $failure
        }
        $acl=Get-Acl -LiteralPath $full -ErrorAction Stop
        if(-not(Test-BootstrapPrivilegedOwnerSid $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)){
            $failure=[InvalidOperationException]::new('Relay path owner is not privileged.')
            $failure.Data['installation_preparation_exit_code']=63;throw $failure
        }
        if($shared -and -not $AllowSupportedPreparation){
            try{Protect-KmtechCodeAncestors 'C:\KMTech\Apps\Container_Audit' -AdmissionOnly -ProtectedAncestor $full}
            catch{
                $code=[int]$_.Exception.Data['installation_preparation_exit_code']
                if($code -notin @(61,62,63)){throw}
                $message=switch($code){62{'Relay path contains a reparse point.'}63{'Relay path owner is not privileged.'}61{'Relay path is user mutable.'}}
                $failure=[InvalidOperationException]::new($message,$_.Exception)
                $failure.Data['installation_preparation_exit_code']=$code;throw $failure
            }
            $full=[IO.Path]::GetDirectoryName($full);$leaf=$false;continue
        }
        $mask=if($leaf){0x500D0156}else{0x500D0150}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and
                -not($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544') -and
                ([int64]$rule.FileSystemRights -band $mask) -and -not($AllowSupportedPreparation -and $shared)){
                $failure=[InvalidOperationException]::new('Relay path is user mutable.')
                $failure.Data['installation_preparation_exit_code']=61;throw $failure
            }
        }
        if($full -eq [IO.Path]::GetPathRoot($full)){break}
        $full=[IO.Path]::GetDirectoryName($full);$leaf=$false
    }
}

function ConvertTo-BootstrapRelayArgument([string]$Value) {
    if($Value.Contains('"')){throw 'Relay path contains a quote.'}
    if($Value -match '\s'){return '"'+$Value+'"'}
    return $Value
}

function Get-BootstrapRelayCommandIdentity([string]$CommandLine,[string]$ExecutablePath) {
    $quoted='"'+$ExecutablePath+'"'
    if($CommandLine.StartsWith($quoted+' ',[StringComparison]::Ordinal)){return $ExecutablePath+$CommandLine.Substring($quoted.Length)}
    return $CommandLine
}

function Initialize-BootstrapRelaySecurity {
    if('KMTechBootstrapRelaySecurity' -as [type]){return}
    Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Runtime.InteropServices; using System.Security.Principal;
public static class KMTechBootstrapRelaySecurity {
 public sealed class Security { public string sid; public int session_id,integrity_level; public bool elevated; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int needed);
 static void Check(bool ok,string api) { if(!ok) { Win32Exception error=new Win32Exception(Marshal.GetLastWin32Error(),api);error.Data["canonical_api"]=api;throw error; } }
 static int Integer(IntPtr token,int kind) { IntPtr data=Marshal.AllocHGlobal(4);try{int needed;Check(GetTokenInformation(token,kind,data,4,out needed),"GetTokenInformation:"+kind);return Marshal.ReadInt32(data);}finally{Marshal.FreeHGlobal(data);} }
 static int Integrity(IntPtr token) { int needed;GetTokenInformation(token,25,IntPtr.Zero,0,out needed);if(needed<=0||needed>65536)throw new InvalidOperationException("Relay integrity record size is invalid.");
  IntPtr data=Marshal.AllocHGlobal(needed);try{Check(GetTokenInformation(token,25,data,needed,out needed),"GetTokenInformation:integrity");string[] parts=new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value.Split('-');return Int32.Parse(parts[parts.Length-1]);}finally{Marshal.FreeHGlobal(data);} }
 public static Security Read(int pid) { IntPtr process=OpenProcess(0x1000,false,pid);Check(process!=IntPtr.Zero,"OpenProcess:relay-query");
  try{IntPtr token;Check(OpenProcessToken(process,8,out token),"OpenProcessToken:relay-query");try{using(WindowsIdentity identity=new WindowsIdentity(token)){return new Security{sid=identity.User.Value,session_id=Integer(token,12),elevated=Integer(token,20)!=0,integrity_level=Integrity(token)};}}finally{CloseHandle(token);}}finally{CloseHandle(process);} }
}
'@
}

function Get-BootstrapRelaySecurity([int]$ProcessId) {
    Initialize-BootstrapRelaySecurity
    return [KMTechBootstrapRelaySecurity]::Read($ProcessId)
}

function Get-BootstrapRelayExpectedIdentity([string]$Root,[string]$RunCommand) {
    $rootFull=Get-StrictFullPath $Root 'relay install root'
    $runtime=Join-Path $rootFull 'runtime\pythonw.exe'
    $prefix=(ConvertTo-BootstrapRelayArgument $runtime)+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $rootFull 'app\auto_update.py'))+' --bootstrap --role relay --'
    $managed=$RunCommand.StartsWith($prefix+' --container-audit-user-relay',[StringComparison]::Ordinal)
    $sha='';$manifestSha='';$aggregate='';$bundle=$rootFull;$command=$RunCommand;$requiresStatusIdentity=$false
    if($managed) {
        if([IO.Path]::GetFileName($rootFull) -cne 'current'){throw 'Relay bootstrap is outside the installed current root.'}
        $control=Join-Path (Split-Path -Parent $rootFull) 'update-control'
        foreach($path in @((Join-Path $control 'active.json'),(Join-Path $control 'policy.json'))){
            Assert-BootstrapProtectedRelayPath $path
            if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Relay control record is oversized.'}
        }
        $policy=Get-Content -LiteralPath (Join-Path $control 'policy.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if($policy.operator_sid -isnot [string] -or $policy.operator_sid -cnotmatch '^S-1-'){throw 'Relay operator SID is invalid.'}
        $active=Get-Content -LiteralPath (Join-Path $control 'active.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if([string]$active.schema -cne 'container-audit-startup-update-v1' -or $active.sha -isnot [string] -or $active.sha -cnotmatch '^[0-9a-f]{40}$'){throw 'Relay active version identity is invalid.'}
        $sha=[string]$active.sha;$bundle=Join-Path (Split-Path -Parent $rootFull) ('versions\'+$sha)
        foreach($path in @($bundle,(Join-Path $bundle 'portable-manifest.json'),(Join-Path $bundle 'runtime\pythonw.exe'),(Join-Path $bundle 'app\main.py'),(Join-Path $bundle 'bootstrap-integrity.json'))){Assert-BootstrapProtectedRelayPath $path}
        $manifest=Read-KmtechPortableManifest $bundle
        if($manifest.source_commit -isnot [string] -or $manifest.source_commit -cne $sha -or
            -not(Test-BootstrapJsonInteger $manifest.startup_update_protocol) -or [int64]$manifest.startup_update_protocol -ne 1){throw 'Relay active manifest binding differs.'}
        if(@($manifest.PSObject.Properties.Name) -ccontains 'relay_identity_protocol') {
            if(-not(Test-BootstrapJsonInteger $manifest.relay_identity_protocol) -or [int64]$manifest.relay_identity_protocol -ne 1){throw 'Relay identity protocol is unsupported.'}
            $requiresStatusIdentity=$true
        }
        $record=Get-Content -LiteralPath (Join-Path $bundle 'bootstrap-integrity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $integrity=if([string]$record.code_root -ceq '.' -or (Test-BootstrapSamePath ([string]$record.code_root) $bundle)){
            Assert-BootstrapIntegrityRecord $bundle
        }else{Assert-BootstrapRelocatedIntegrityRecord $bundle $rootFull}
        $aggregate=[string]$integrity.aggregate_sha256
        $manifestSha=Get-FileSha256 (Join-Path $bundle 'portable-manifest.json')
        $runtime=Join-Path $bundle 'runtime\pythonw.exe'
        $command=(ConvertTo-BootstrapRelayArgument $runtime)+' -I -B '+(ConvertTo-BootstrapRelayArgument (Join-Path $bundle 'app\main.py'))+$RunCommand.Substring($prefix.Length)
    }
    return [pscustomobject]@{root=$bundle;install_root=$rootFull;managed=$managed;source_commit=$sha;manifest_sha256=$manifestSha;aggregate_sha256=$aggregate;executable=$runtime;command=$command;run_command=$RunCommand;requires_status_identity=$requiresStatusIdentity;operator_sid=if($managed){[string]$policy.operator_sid}else{''}}
}

function Get-BootstrapRelayReadinessSnapshot($Identity) {
    if(-not $Identity.managed){return [pscustomobject]@{identity=$Identity;settled=$true;phase='UNMANAGED'}}
    $control=Join-Path (Split-Path -Parent ([string]$Identity.install_root)) 'update-control'
    $path=Join-Path $control 'active.json'
    Assert-BootstrapProtectedRelayPath $path
    if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'Relay active record is oversized.'}
    $active=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    if([string]$active.schema -cne 'container-audit-startup-update-v1' -or $active.sha -isnot [string] -or $active.sha -cnotmatch '^[0-9a-f]{40}$'){throw 'Relay active version identity is invalid.'}
    if([string]$active.sha -cne [string]$Identity.source_commit){$Identity=Get-BootstrapRelayExpectedIdentity ([string]$Identity.install_root) ([string]$Identity.run_command)}
    $transitionPath=Join-Path $control 'transition.json';$phase='ABSENT'
    if(Test-Path -LiteralPath $transitionPath -PathType Leaf){
        Assert-BootstrapProtectedRelayPath $transitionPath
        if((Get-Item -LiteralPath $transitionPath).Length -gt 65536){throw 'Relay transition is oversized.'}
        $transition=Get-Content -LiteralPath $transitionPath -Raw -Encoding UTF8|ConvertFrom-Json
        $phase=[string]$transition.phase
    }
    return [pscustomobject]@{identity=$Identity;settled=($phase -cin @('ABSENT','CONFIRMED','ROLLED_BACK','DEFERRED'));phase=$phase}
}

function Test-BootstrapRelayReadback($Identity,$Process,$Security,$Caller,$Status=$null,[Nullable[DateTime]]$StartedAt=$null,[string]$PreviousStatusSha256='',[string]$StatusSha256='') {
    try {
        if($null -eq $Process -or $null -eq $Security -or $null -eq $Caller -or
            $Process.ProcessId -isnot [int] -and $Process.ProcessId -isnot [long] -and $Process.ProcessId -isnot [uint32]){return $false}
        if([int64]$Process.ProcessId -le 0 -or -not(Test-BootstrapSamePath ([string]$Process.ExecutablePath) ([string]$Identity.executable)) -or
            (Get-BootstrapRelayCommandIdentity ([string]$Process.CommandLine) ([string]$Identity.executable)) -cne
            (Get-BootstrapRelayCommandIdentity ([string]$Identity.command) ([string]$Identity.executable)) -or
            $Security.elevated -isnot [bool] -or $Security.elevated -or
            (@($Security.PSObject.Properties.Name) -ccontains 'integrity_level' -and [int]$Security.integrity_level -ne 8192) -or
            [string]$Security.sid -cne [string]$Caller.sid -or [int]$Security.session_id -ne [int]$Caller.session_id -or
            ([string]$Identity.operator_sid -and [string]$Security.sid -cne [string]$Identity.operator_sid) -or
            [int]$Security.session_id -le 0){return $false}
        if($null -eq $StartedAt){return $true}
        if($null -eq $Status -or [string]$Status.report_version -cne 'container-audit-user-relay-v1' -or
            [string]$Status.status -cne 'RUNNING' -or [string]$Status.principal -cne 'current_user' -or
            $Status.persistent_retry -isnot [bool] -or -not $Status.persistent_retry -or
            ($PreviousStatusSha256 -and $PreviousStatusSha256 -ceq $StatusSha256)){return $false}
        $properties=@($Status.PSObject.Properties.Name)
        if($Identity.requires_status_identity -and @(@('process_id','source_commit','ordinary_user')|Where-Object {$properties -cnotcontains $_}).Count){return $false}
        if($properties -ccontains 'process_id' -and (-not(Test-BootstrapJsonInteger $Status.process_id) -or [int64]$Status.process_id -ne [int64]$Process.ProcessId)){return $false}
        if($properties -ccontains 'source_commit' -and [string]$Status.source_commit -cne [string]$Identity.source_commit){return $false}
        if($properties -ccontains 'ordinary_user' -and ($Status.ordinary_user -isnot [bool] -or -not $Status.ordinary_user)){return $false}
        $updated=[DateTimeOffset]::MinValue
        if($Status.updated_at -is [DateTime]) {
            # PowerShell 7.5+ converts ISO JSON dates; PS5 retains strings.
            if($Status.updated_at.Kind -eq [DateTimeKind]::Unspecified){return $false}
            $updated=[DateTimeOffset]::new($Status.updated_at.ToUniversalTime())
        }elseif([string]$Status.updated_at -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$' -or
            -not[DateTimeOffset]::TryParse([string]$Status.updated_at,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$updated)){return $false}
        if($Process.CreationDate -isnot [DateTime]){return $false}
        $start=([DateTime]$StartedAt).ToUniversalTime();$created=([DateTime]$Process.CreationDate).ToUniversalTime()
        return $updated.UtcDateTime -ge $start.AddSeconds(-1) -and $updated.UtcDateTime -le [DateTime]::UtcNow.AddSeconds(1) -and
            $created -ge $start.AddSeconds(-1) -and $created -le $updated.UtcDateTime.AddSeconds(1)
    }catch{return $false}
}

function Get-BootstrapStringSha256([string]$Value) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-BootstrapSamePath([string]$Left, [string]$Right) {
    return (Get-StrictFullPath $Left 'left path').Equals(
        (Get-StrictFullPath $Right 'right path'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-BootstrapNoReparsePoint([string]$Path, [string]$Purpose, [switch]$PathOnly) {
    $root = Get-StrictFullPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $root)) { throw "$Purpose is unavailable." }
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop))
    $ancestor = Split-Path -Parent $root
    while ($ancestor) {
        $items += Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        $next = Split-Path -Parent $ancestor
        if ($next -eq $ancestor) { break }
        $ancestor = $next
    }
    if (-not $PathOnly -and $items[0].PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    }
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose contains a reparse point: $($item.FullName)"
        }
    }
}

function Get-BootstrapAclComparisonKey([string]$Sddl) {
    # Descriptor identity, except Windows' DACL auto-inherited bookkeeping bit.
    # Every ACE byte remains bound, including inherited/explicit and deny flags.
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 65536) {
        throw 'ACL comparison descriptor is invalid.'
    }
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $flags=[int]$raw.ControlFlags -band (-bnot [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
    $parts=@([string]$flags,[string]$raw.Owner.Value,[string]$raw.Group.Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        foreach($name in @('DiscretionaryAcl','SystemAcl')) {
            $acl=$raw.$name
            if($null -eq $acl){$parts+='NULL';continue}
            $aces=@(foreach($ace in $acl){
                $bytes=[byte[]]::new($ace.BinaryLength)
                $ace.GetBinaryForm($bytes,0)
                ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
            })
            # Allow/deny precedence can change permissions. The supported
            # all-Allow shapes are sets; mixed access ACEs retain their order.
            $allow=@($acl | Where-Object {$_.AceType -in @(0,5,9,11)})
            $deny=@($acl | Where-Object {$_.AceType -in @(1,6,10,12)})
            if($name -cne 'DiscretionaryAcl' -or -not($allow.Count -and $deny.Count)){
                [Array]::Sort($aces,[StringComparer]::Ordinal)
            }
            $parts+=([string]$acl.Revision+':'+(@($aces) -join ','))
        }
    } finally {$sha.Dispose()}
    return ($parts -join '|')
}

function Test-BootstrapAclRawBinding($Identity, [string]$HashField = 'sddl_sha256', [string]$RawField = 'sddl') {
    try {
        if ([string]$Identity.$HashField -cnotmatch '^[0-9a-f]{64}$') { return $false }
        if ($null -eq $Identity.PSObject.Properties[$RawField]) { return $true }
        $sddl = $Identity.$RawField
        if ($sddl -isnot [string] -or [string]::IsNullOrWhiteSpace($sddl) -or $sddl.Length -gt 65536 -or
            (Get-BootstrapStringSha256 $sddl) -cne [string]$Identity.$HashField) { return $false }
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        return ([string]$raw.Owner.Value -ceq [string]$Identity.owner_sid -and
            $Identity.access_rules_protected -is [bool] -and
            [bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq $Identity.access_rules_protected)
    } catch { return $false }
}

function Test-BootstrapAclPropertySet($Identity, [string[]]$Fields, [string]$RawField = 'sddl', [string]$HashField = 'sddl_sha256') {
    if ($null -eq $Identity) { return $false }
    $names = @($Identity.PSObject.Properties.Name)
    $expected = @($Fields)
    if ($names -ccontains $RawField) { $expected += $RawField }
    if ($names.Count -ne $expected.Count) { return $false }
    foreach ($name in $names) { if ($expected -cnotcontains $name) { return $false } }
    return (Test-BootstrapAclRawBinding $Identity $HashField $RawField)
}

function Test-BootstrapAclIdentity($Expected, $Actual, [string]$HashField = 'sddl_sha256', [string]$RawField = 'sddl') {
    try {
        if ($null -eq $Expected -or $null -eq $Actual -or
            $Expected.access_rules_protected -isnot [bool] -or $Actual.access_rules_protected -isnot [bool] -or
            $Expected.access_rules_protected -ne $Actual.access_rules_protected -or
            [string]$Expected.owner_sid -cne [string]$Actual.owner_sid -or
            -not (Test-BootstrapAclRawBinding $Expected $HashField $RawField) -or
            -not (Test-BootstrapAclRawBinding $Actual $HashField $RawField)) { return $false }
        $expectedRaw = $Expected.PSObject.Properties[$RawField]
        $actualRaw = $Actual.PSObject.Properties[$RawField]
        if ($null -ne $expectedRaw -and $null -ne $actualRaw) {
            return ((Get-BootstrapAclComparisonKey $expectedRaw.Value) -ceq (Get-BootstrapAclComparisonKey $actualRaw.Value))
        }
        if ([string]$Expected.$HashField -ceq [string]$Actual.$HashField) { return $true }
        # A legacy digest proves only exact bytes or the same bytes with DACL AI toggled.
        $rawProperty = if ($null -ne $actualRaw) { $actualRaw } else { $expectedRaw }
        if ($null -eq $rawProperty) { return $false }
        $legacyHash = if ($null -eq $expectedRaw) { [string]$Expected.$HashField } else { [string]$Actual.$HashField }
        $text = [string]$rawProperty.Value
        $match = [regex]::Match($text, '(?<=D:)(?:P|AI|AR)*')
        if (-not $match.Success) { return $false }
        $control = $match.Value.Replace('AI','')
        $withAI = if ($control.Contains('AR')) { $control.Replace('AR','AIAR') } else { $control + 'AI' }
        foreach ($value in @($control,$withAI)) {
            $candidate = $text.Substring(0,$match.Index) + $value + $text.Substring($match.Index+$match.Length)
            if ((Get-BootstrapStringSha256 $candidate) -ceq $legacyHash) { return $true }
        }
        return $false
    } catch { return $false }
}

function Get-BootstrapAclIdentity([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $acl = if ($PSVersionTable.PSEdition -ceq 'Core') {
        [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    }
    else {
        $item.GetAccessControl($sections)
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    if ($acl.AreAccessRulesProtected -isnot [bool]) {
        throw 'Bootstrap ACL protection readback type is invalid.'
    }
    return [pscustomobject][ordered]@{
        owner_sid = [string]$owner
        access_rules_protected = $acl.AreAccessRulesProtected
        sddl_sha256 = Get-BootstrapStringSha256 $sddl
        sddl = $sddl
    }
}

function Assert-BootstrapRelocatedIntegrityRecord(
    [string]$Root,
    [string]$ExpectedCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'relocated bootstrap root'
    $expectedRoot = Get-StrictFullPath $ExpectedCodeRoot 'declared bootstrap root'
    $recordPath = Join-Path $rootFull $BootstrapIntegrityFileName
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        throw 'Relocated bootstrap integrity record is absent.'
    }
    if ((Get-Item -LiteralPath $recordPath -Force).Length -gt 1048576) {
        throw 'Relocated bootstrap integrity record is oversized.'
    }
    $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$record.schema_version -cne $BootstrapIntegritySchema -or
        [string]$record.status -cne 'PASS' -or
        -not (Test-BootstrapSamePath ([string]$record.code_root) $expectedRoot)
    ) {
        throw 'Relocated bootstrap integrity identity is invalid.'
    }
    $inventory = @(Get-CodeInventoryInRecordOrder $rootFull @($record.files))
    $aggregate = Get-InventoryAggregate $inventory
    if (
        -not (Test-BootstrapJsonInteger $record.file_count) -or
        [int64]$record.file_count -ne $inventory.Count -or
        @($record.files).Count -ne $inventory.Count -or
        [string]$record.aggregate_sha256 -cne $aggregate
    ) {
        throw 'Relocated bootstrap integrity aggregate differs.'
    }
    $actualByPath = @{}
    foreach ($item in $inventory) { $actualByPath[[string]$item.path] = $item }
    foreach ($expected in @($record.files)) {
        $path = [string]$expected.path
        if (-not $actualByPath.ContainsKey($path)) {
            throw 'Relocated bootstrap integrity inventory is incomplete.'
        }
        $actual = $actualByPath[$path]
        if (
            -not (Test-BootstrapJsonInteger $expected.size) -or
            -not (Test-BootstrapJsonInteger $actual.size) -or
            [int64]$expected.size -ne [int64]$actual.size -or
            [string]$expected.sha256 -cne [string]$actual.sha256
        ) {
            throw 'Relocated bootstrap integrity inventory differs.'
        }
        $actualByPath.Remove($path)
    }
    if ($actualByPath.Count -ne 0) {
        throw 'Relocated bootstrap integrity contains unrecorded files.'
    }
    return [pscustomobject][ordered]@{
        file_count = $inventory.Count
        aggregate_sha256 = $aggregate
        integrity_sha256 = Get-FileSha256 $recordPath
    }
}

function Get-BootstrapReplacementTreeIdentity(
    [string]$Root,
    [string]$DeclaredCodeRoot
) {
    $rootFull = Get-StrictFullPath $Root 'replacement tree'
    Assert-BootstrapNoReparsePoint $rootFull 'replacement tree'
    $integrity = Assert-BootstrapRelocatedIntegrityRecord `
        -Root $rootFull `
        -ExpectedCodeRoot $DeclaredCodeRoot
    $manifestPath = Join-Path $rootFull 'portable-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Replacement tree portable manifest is absent.'
    }
    if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 65536) {
        throw 'Replacement tree portable manifest is oversized.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$manifest.schema -cne 'container-audit-portable-tree-v1' -or
        [string]$manifest.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.source_tree -cnotmatch '^[0-9a-f]{40}$'
    ) {
        throw 'Replacement tree portable identity is invalid.'
    }
    $acl = Get-BootstrapAclIdentity $rootFull
    return [pscustomobject][ordered]@{
        file_count = $integrity.file_count
        aggregate_sha256 = [string]$integrity.aggregate_sha256
        integrity_sha256 = [string]$integrity.integrity_sha256
        manifest_sha256 = Get-FileSha256 $manifestPath
        source_commit = [string]$manifest.source_commit
        source_tree = [string]$manifest.source_tree
        owner_sid = [string]$acl.owner_sid
        access_rules_protected = $acl.access_rules_protected
        acl_sddl_sha256 = [string]$acl.sddl_sha256
        acl_sddl = [string]$acl.sddl
        reparse_count = 0
    }
}

function Test-BootstrapReplacementTreeIdentity($Expected, $Actual) {
    if ($null -eq $Expected -or $null -eq $Actual) { return $false }
    foreach ($name in @('file_count', 'reparse_count')) {
        if (
            -not (Test-BootstrapJsonInteger $Expected.$name) -or
            -not (Test-BootstrapJsonInteger $Actual.$name) -or
            [int64]$Expected.$name -ne [int64]$Actual.$name
        ) { return $false }
    }
    if (
        $Expected.access_rules_protected -isnot [bool] -or
        $Actual.access_rules_protected -isnot [bool] -or
        $Expected.access_rules_protected -ne $Actual.access_rules_protected
    ) { return $false }
    foreach ($name in @(
        'aggregate_sha256', 'integrity_sha256', 'manifest_sha256', 'source_commit',
        'source_tree', 'owner_sid'
    )) {
        if ([string]$Expected.$name -cne [string]$Actual.$name) { return $false }
    }
    return (Test-BootstrapAclIdentity $Expected $Actual 'acl_sddl_sha256' 'acl_sddl')
}

function Write-BootstrapReplacementReceipt(
    [string]$Path,
    $Payload,
    [switch]$AllowReplace
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    $parent = Split-Path -Parent $full
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-BootstrapNoReparsePoint $parent 'replacement receipt parent' -PathOnly
    if ((Test-Path -LiteralPath $full) -and -not $AllowReplace.IsPresent) {
        throw 'Replacement receipt path already exists.'
    }
    Write-Utf8Json -Path $full -Payload $Payload
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt write readback failed.'
    }
    return [pscustomobject][ordered]@{
        path = $full
        sha256 = Get-FileSha256 $full
    }
}

function Read-BootstrapReplacementReceipt(
    [string]$Path,
    [string]$ExpectedSha256
) {
    $full = Get-StrictFullPath $Path 'replacement receipt path'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Replacement receipt is absent.'
    }
    Assert-BootstrapNoReparsePoint $full 'replacement receipt'
    $length = (Get-Item -LiteralPath $full -Force).Length
    if ($length -le 0 -or $length -gt 131072) { throw 'Replacement receipt size is invalid.' }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Replacement receipt SHA-256 is invalid.'
    }
    if ((Get-FileSha256 $full) -cne $ExpectedSha256) {
        throw 'Replacement receipt SHA-256 differs.'
    }
    try { return Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'Replacement receipt JSON is invalid.' }
}



function Read-BootstrapRollbackContinuationAuthority($Record,[string]$JournalPath,[string]$JournalSha256,$Fence,[int]$Depth=0,[switch]$AllowLiveOwner) {
    if($Depth -gt 128){throw 'Rollback authority lineage exceeds its bound.'}
    $names=@('session_id','attempt_id','orchestrator_sha256','writer_contract_sha256','replacement_transaction_id')
    $original=[pscustomobject]@{session_id=[string]$Record.session_id;attempt_id=[string]$Record.attempt_id;
        orchestrator_sha256=[string]$Record.orchestrator_sha256;writer_contract_sha256=[string]$Record.writer_contract_sha256;replacement_transaction_id=[string]$Record.transaction_id}
    $matches=$true;foreach($name in $names){if([string]$Fence.$name -cne [string]$original.$name){$matches=$false}}
    if($matches){return [pscustomobject]@{tuple=$original;link_sha256='';owner_process_id=[int]$Record.owner_process_id;owner_started_at_utc=[string]$Record.owner_started_at_utc}}
    if([string]$Fence.attempt_id -cnotmatch '^[0-9a-f]{32}$'){throw 'Rollback authority attempt differs.'}
    $path=Join-Path (Split-Path -Parent $JournalPath) ('authority-'+[string]$Fence.attempt_id+'.json')
    Assert-InstallationEvidenceProtectedPath $path
    Assert-BootstrapNoReparsePoint $path 'rollback authority link' -PathOnly
    if((Get-Item -LiteralPath $path).Length -gt 131072){throw 'Rollback authority link is oversized.'}
    $sha=Get-FileSha256 $path
    $link=Read-BootstrapReplacementReceipt $path $sha
    if(-not(Test-WriterSessionContractExactPropertySet $link @('schema','transaction_id','journal_sha256','receipt_sha256','previous','authority','owner_process_id','owner_started_at_utc','prepared_receipt_path','prepared_receipt_sha256','previous_link_sha256','secret_values_recorded')) -or
        [string]$link.schema -cne 'container-audit-rollback-authority-link-v1' -or
        [string]$link.transaction_id -cne [string]$Record.transaction_id -or [string]$link.journal_sha256 -cne $JournalSha256 -or
        (Get-FileSha256 $JournalPath) -cne $JournalSha256 -or [string]$link.receipt_sha256 -cne [string]$Record.receipt_sha256 -or
        $link.secret_values_recorded -isnot [bool] -or $link.secret_values_recorded -or
        -not(Test-WriterSessionContractExactPropertySet $link.previous $names) -or -not(Test-WriterSessionContractExactPropertySet $link.authority $names) -or
        [string]$link.authority.attempt_id -cne [string]$Fence.attempt_id -or
        [string]$link.authority.orchestrator_sha256 -cne [string]$Record.orchestrator_sha256 -or
        [string]$link.authority.writer_contract_sha256 -cne [string]$Record.writer_contract_sha256 -or
        [int]$link.owner_process_id -le 0){throw 'Rollback authority link binding differs.'}
    foreach($name in $names){if([string]$link.authority.$name -cne [string]$Fence.$name){throw 'Rollback linked fence tuple differs.'}}
    if($Depth -eq 0) {
        if(Test-BootstrapSamePath ([string]$Fence.prepared_receipt_path) $path) {
            if([string]$Fence.prepared_receipt_sha256 -cne $sha){throw 'Rollback fence-to-link hash differs.'}
        }else{
            # A release authorization can replace the fence's preparation only
            # when its audited bytes bind this exact protected link as well.
            $release=Read-BootstrapReplacementReceipt ([string]$Fence.prepared_receipt_path) ([string]$Fence.prepared_receipt_sha256)
            if([string]$release.schema -cne 'container-audit-writer-release-authorization-v1' -or
                [string]$release.session_id -cne [string]$Fence.session_id -or [string]$release.attempt_id -cne [string]$Fence.attempt_id -or
                [string]$release.replacement_transaction_id -cne [string]$Fence.replacement_transaction_id){throw 'Rollback link publication differs.'}
            $auditPath=Get-StrictFullPath ([string]$release.install_audit_path) 'rollback release audit'
            Assert-BootstrapNoReparsePoint $auditPath 'rollback release audit' -PathOnly
            if((Get-Item -LiteralPath $auditPath).Length -gt 1048576 -or (Get-FileSha256 $auditPath) -cne [string]$release.install_audit_sha256){throw 'Rollback release audit bytes differ.'}
            $audit=Get-Content -LiteralPath $auditPath -Raw -Encoding UTF8|ConvertFrom-ContainerWriterFenceJson
            if((Get-FileSha256 $auditPath) -cne [string]$release.install_audit_sha256){throw 'Rollback release audit changed.'}
            if(-not(Test-BootstrapSamePath ([string]$audit.code_replacement.continuation_authority_link.path) $path) -or
                [string]$audit.code_replacement.continuation_authority_link.sha256 -cne $sha){throw 'Rollback release audit link differs.'}
        }
    }
    $previous=Read-BootstrapRollbackContinuationAuthority $Record $JournalPath $JournalSha256 $link.previous ($Depth+1)
    if([string]$link.previous_link_sha256 -cne [string]$previous.link_sha256){throw 'Rollback authority predecessor hash differs.'}
    [void][DateTime]::Parse([string]$link.owner_started_at_utc)
    $owners=@(Get-Process -Id ([int]$link.owner_process_id) -ErrorAction SilentlyContinue)
    if($owners.Count -and (-not $AllowLiveOwner -or $Depth -ne 0 -or
        $owners[0].StartTime.ToUniversalTime().ToString('o') -cne ([DateTime]$link.owner_started_at_utc).ToUniversalTime().ToString('o'))){throw 'Rollback linked owner is alive or PID reused.'}
    if([string]$link.prepared_receipt_sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Rollback linked preparation hash differs.'}
    # The immutable protected link is the durable preparation binding. Rotating
    # caller evidence is not required to remain available on a later retry.
    return [pscustomobject]@{tuple=$link.authority;link_sha256=$sha;owner_process_id=[int]$link.owner_process_id;owner_started_at_utc=[string]$link.owner_started_at_utc}
}

function ConvertFrom-BootstrapLifecycleJsonNode([Xml.XmlElement]$Node) {
    switch -CaseSensitive ($Node.GetAttribute('type')) {
        'object' {
            $value=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
            foreach($child in $Node.ChildNodes){
                if($child -isnot [Xml.XmlElement]){throw 'lifecycle_json_invalid'}
                $key=if($child.NamespaceURI -ceq 'item'){$child.GetAttribute('item')}else{$child.LocalName}
                if($value.ContainsKey($key)){throw 'lifecycle_json_duplicate_key'}
                $value.Add($key,(ConvertFrom-BootstrapLifecycleJsonNode $child))
            }
            return ,$value
        }
        'array' {
            $value=[Collections.Generic.List[object]]::new()
            foreach($child in $Node.ChildNodes){$value.Add((ConvertFrom-BootstrapLifecycleJsonNode $child))}
            return ,$value.ToArray()
        }
        'string' { return [string]$Node.InnerText }
        'boolean' { return $Node.InnerText -ceq 'true' }
        'number' {
            if($Node.InnerText -cmatch '^-?[0-9]+$'){return [Numerics.BigInteger]::Parse($Node.InnerText,[Globalization.CultureInfo]::InvariantCulture)}
            return [double]::Parse($Node.InnerText,[Globalization.CultureInfo]::InvariantCulture)
        }
        'null' { return $null }
        default { throw 'lifecycle_json_invalid' }
    }
}

function Read-BootstrapLifecycleJson([string]$Path) {
    Assert-BootstrapNoReparsePoint $Path 'lifecycle record' -PathOnly
    if((Get-Item -LiteralPath $Path).Length -gt 1048576){throw 'lifecycle_json_oversized'}
    $raw=[IO.File]::ReadAllBytes($Path)
    if($raw.Length -gt 1048576){throw 'lifecycle_json_oversized'}
    $reader=[System.Runtime.Serialization.Json.JsonReaderWriterFactory, System.Runtime.Serialization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]::CreateJsonReader($raw,[Xml.XmlDictionaryReaderQuotas]::Max)
    try{
        $document=[Xml.XmlDocument]::new();$document.Load($reader)
        $value=ConvertFrom-BootstrapLifecycleJsonNode $document.DocumentElement
        if($value -isnot [Collections.Generic.Dictionary[string,object]]){throw 'lifecycle_json_object_required'}
        return ,$value
    }finally{$reader.Dispose()}
}

function Test-BootstrapLifecycleJsonEqual($Left,$Right) {
    if($null -eq $Left -or $null -eq $Right){return $null -eq $Left -and $null -eq $Right}
    if($Left -is [Collections.Generic.Dictionary[string,object]]){
        if($Right -isnot [Collections.Generic.Dictionary[string,object]] -or $Left.Count -ne $Right.Count){return $false}
        foreach($key in $Left.Keys){if(-not $Right.ContainsKey($key) -or -not(Test-BootstrapLifecycleJsonEqual $Left[$key] $Right[$key])){return $false}}
        return $true
    }
    if($Left -is [array]){
        if($Right -isnot [array] -or $Left.Count -ne $Right.Count){return $false}
        for($index=0;$index -lt $Left.Count;$index++){if(-not(Test-BootstrapLifecycleJsonEqual $Left[$index] $Right[$index])){return $false}}
        return $true
    }
    if($Left -is [string]){return $Right -is [string] -and $Left -ceq $Right}
    if($Right -is [string] -or $Right -is [array] -or $Right -is [Collections.Generic.Dictionary[string,object]]){return $false}
    if($Left -is [Numerics.BigInteger] -and $Right -is [double]){
        return -not [double]::IsInfinity($Right) -and -not [double]::IsNaN($Right) -and [Math]::Truncate($Right) -eq $Right -and $Left.Equals([Numerics.BigInteger]$Right)
    }
    if($Right -is [Numerics.BigInteger] -and $Left -is [double]){return Test-BootstrapLifecycleJsonEqual $Right $Left}
    return $Left -eq $Right
}

function Get-BootstrapOfficialLegacyRelayExpectedIdentitySet {
    # Candidate authorization: lab1/2 passed; guest must prove install3/4.
    # Coordinator closes this single switch if guest recovery or exclusion fails.
    $allowCredentialPrincipalTransition=$true
    $entries=@((@'
[{"branch":"interactive_current_user","field_templates":{"task.path":"\\","task.name":"direct-sync-relay-container-audit","action.count":"1","action.type":"Exec","action.command":"{system_directory}\\wscript.exe","action.arguments":"//B //NoLogo {program_data}\\KMTech\\DirectSync\\container_audit\\bin\\direct-sync-relay-container-audit.vbs","action.workdir":"","principal.user":"{current_user}","principal.logon_type":"InteractiveToken","principal.run_level":"LeastPrivilege","trigger.count":"1","trigger.type":"TimeTrigger","trigger.repetition_interval":"PT1M"},"tags":["v2.0.10","v2.0.11","v2.0.12","v2.0.13","v2.0.14","v2.0.15","v2.0.16","v2.0.17"],"allowed":false},{"branch":"stored_password_current_user","field_templates":{"task.path":"\\","task.name":"direct-sync-relay-container-audit","action.count":"1","action.type":"Exec","action.command":"{system_directory}\\wscript.exe","action.arguments":"//B //NoLogo {program_data}\\KMTech\\DirectSync\\container_audit\\bin\\direct-sync-relay-container-audit.vbs","action.workdir":"","principal.user":"{current_user}","principal.logon_type":"Password","principal.run_level":"LeastPrivilege","trigger.count":"1","trigger.type":"TimeTrigger","trigger.repetition_interval":"PT1M"},"tags":["v2.0.12","v2.0.13","v2.0.14","v2.0.15","v2.0.16","v2.0.17","v2.0.18","v2.0.19","v2.0.20","v2.0.21","v2.0.22","v2.0.23","v2.0.24","v2.0.25","v2.0.26","v2.0.27","v2.0.28","v2.0.29","v2.0.30","v2.0.31","v2.0.32","v2.0.33","v2.0.34","v2.0.36","v2.0.37","v2.0.52","v2.0.53","v2.0.54","v2.0.55","v2.0.56","v2.0.57","v2.0.58","v2.0.59","v2.0.61"],"allowed":false},{"branch":"system_vbs","field_templates":{"task.path":"\\","task.name":"direct-sync-relay-container-audit","action.count":"1","action.type":"Exec","action.command":"{system_directory}\\wscript.exe","action.arguments":"//B //NoLogo {program_data}\\KMTech\\DirectSync\\container_audit\\bin\\direct-sync-relay-container-audit.vbs","action.workdir":"","principal.user":"SYSTEM","principal.logon_type":"ServiceAccount","principal.run_level":"LeastPrivilege","trigger.count":"1","trigger.type":"TimeTrigger","trigger.repetition_interval":"PT1M"},"tags":["v2.0.18","v2.0.19","v2.0.20","v2.0.21","v2.0.22","v2.0.23","v2.0.24","v2.0.25","v2.0.26","v2.0.27","v2.0.28","v2.0.29","v2.0.30","v2.0.31","v2.0.32","v2.0.33","v2.0.34","v2.0.36","v2.0.37","v2.0.52","v2.0.53","v2.0.54","v2.0.55","v2.0.56","v2.0.57","v2.0.58","v2.0.59","v2.0.61"],"allowed":true}]
'@ | ConvertFrom-Json))
    foreach($entry in $entries){if($entry.branch -cin @('stored_password_current_user','interactive_current_user')){$entry.allowed=$allowCredentialPrincipalTransition}}
    return ,$entries
}

function Get-BootstrapOfficialLegacyRelayIdentity($Task,[string]$Xml='',[object[]]$ExpectedIdentitySet=@()) {
    # v2.0.33 tools/direct_sync_relay_install_pack.py:40,133-153,978-988.
    # Identity contract 298c9729; guest-proven XML default normalization.
    $name='direct-sync-relay-container-audit'
    $empty=[pscustomobject]@{matched=$false;sha256='';fields=@();records=@();entry_tag='';reason_code='IDENTITY_DIFFERS'}
    if(-not $ExpectedIdentitySet.Count){$ExpectedIdentitySet=Get-BootstrapOfficialLegacyRelayExpectedIdentitySet}
    if([string]$Task.TaskName -ine $name){return $empty}
    if($null -eq $Task.PSObject.Properties['TaskPath'] -or -not [string]$Task.TaskPath){return $empty}
    if(-not $Xml){$Xml=Export-ScheduledTask -TaskName ([string]$Task.TaskName) -TaskPath ([string]$Task.TaskPath) -ErrorAction Stop}
    if([Text.Encoding]::UTF8.GetByteCount($Xml) -gt 65536){throw 'NONCANONICAL_WRITER_ENABLED'}
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
    try{$document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.Load($reader)}finally{$reader.Dispose()}
    function Task-Nodes([string]$XPath){return ,@($document.SelectNodes($XPath))}
    function Task-Text($Node,[string]$Name){$value=$Node.SelectSingleNode('*[local-name()="'+$Name+'"]');if($null -eq $value){return ''};return [string]$value.InnerText}
    function Task-Path([string]$Path,[switch]$Executable){
        if(-not $Path){return ''}
        $pathValue=[Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')).Replace('/','\')
        if($Executable -and -not[IO.Path]::IsPathRooted($pathValue)){$pathValue=Join-Path ([Environment]::SystemDirectory) $pathValue}
        if(-not[IO.Path]::IsPathRooted($pathValue)){return '!relative'}
        return [IO.Path]::GetFullPath($pathValue).TrimEnd('\').ToLowerInvariant()
    }
    function Task-Sha([string]$Value){$algorithm=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').ToLowerInvariant())}finally{$algorithm.Dispose()}}
    $actions=Task-Nodes '/*[local-name()="Task"]/*[local-name()="Actions"]/*'
    $principals=Task-Nodes '/*[local-name()="Task"]/*[local-name()="Principals"]/*'
    $triggers=Task-Nodes '/*[local-name()="Task"]/*[local-name()="Triggers"]/*'
    if($actions.Count -ne 1 -or $principals.Count -ne 1 -or $triggers.Count -ne 1){return $empty}
    $principal=Task-Text $principals[0] 'UserId'
    try{$sid=ConvertTo-BootstrapPrincipalSid $principal}catch{return $empty}
    $principalLabel=if($sid -ceq (@('S','1','5','18') -join '-')){'SYSTEM'}elseif($sid -ceq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){'CURRENT_USER'}else{'OTHER'}
    $logonNode=$principals[0].SelectSingleNode('*[local-name()="LogonType"]')
    $logonType=if($null -eq $logonNode){if($principalLabel -ceq 'SYSTEM'){'ServiceAccount'}else{'ABSENT'}}else{[string]$logonNode.InnerText}
    if($null -ne $logonNode -and $logonType -cnotin @('Password','S4U','InteractiveToken','Group','ServiceAccount','InteractiveTokenOrPassword')){
        $empty.reason_code='LOGON_TYPE_UNKNOWN';return $empty
    }
    $runLevelNode=$principals[0].SelectSingleNode('*[local-name()="RunLevel"]')
    $runLevel=if($null -eq $runLevelNode){'LeastPrivilege'}else{[string]$runLevelNode.InnerText}
    if($runLevel -cnotin @('LeastPrivilege','HighestAvailable')){$empty.reason_code='RUN_LEVEL_UNKNOWN';return $empty}
    $arguments=Task-Text $actions[0] 'Arguments'
    function Task-Arguments([string]$Value){
        $tokens=@([regex]::Matches($Value.Trim(),'"[^"]*"|[^\s]+')|ForEach-Object {
            $token=$_.Value;$quoted=$token.StartsWith('"');$bare=$token.Trim('"')
            $pathValue=[Environment]::ExpandEnvironmentVariables($bare).Replace('/','\')
            if($pathValue -match '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)'){$bare=Task-Path $bare;$token=if($quoted){'"'+$bare+'"'}else{$bare}}
            $token
        });return ($tokens -join ' ')
    }
    $argumentIdentity=Task-Arguments $arguments
    $repetition=$triggers[0].SelectSingleNode('*[local-name()="Repetition"]')
    $interval=if($null -eq $repetition){''}else{Task-Text $repetition 'Interval'}
    if($interval){try{$interval=[Xml.XmlConvert]::ToString([Xml.XmlConvert]::ToTimeSpan($interval))}catch{return $empty}}
    $actual=[ordered]@{
        'task.path'=(([string]$Task.TaskPath).TrimEnd('\')+'\').ToLowerInvariant();'task.name'=([string]$Task.TaskName).ToLowerInvariant()
        'action.count'=[string]$actions.Count;'action.type'=[string]$actions[0].LocalName
        'action.command'=Task-Path (Task-Text $actions[0] 'Command') -Executable
        'action.arguments'=$argumentIdentity;'action.workdir'=Task-Path (Task-Text $actions[0] 'WorkingDirectory')
        'principal.user'=$principalLabel;'principal.logon_type'=$logonType;'principal.run_level'=$runLevel
        'trigger.count'=[string]$triggers.Count;'trigger.type'=[string]$triggers[0].LocalName;'trigger.repetition_interval'=$interval
    }
    $equal=$false;$entryTag='';$expected=$null
    foreach($entry in $ExpectedIdentitySet){
        if(-not $entry.allowed){continue}
        $candidate=[ordered]@{}
        foreach($property in $entry.field_templates.PSObject.Properties){
            $value=[string]$property.Value
            $value=$value.Replace('{system_directory}',[Environment]::SystemDirectory).Replace('{program_data}',[Environment]::GetFolderPath('CommonApplicationData')).Replace('{user_local_app_data}',[Environment]::GetFolderPath('LocalApplicationData')).Replace('{current_user}','CURRENT_USER')
            if($property.Name -cin @('action.command','action.workdir')){$value=Task-Path $value -Executable:($property.Name -ceq 'action.command')}
            if($property.Name -ceq 'action.arguments'){
                # Source subprocess.list2cmdline quotes paths only when required.
                $prefix=if($entry.branch -ceq 'system_cmd'){'/d /q /c '}else{'//B //NoLogo '}
                $path=$value.Substring($prefix.Length);if($path -match '\s'){$path='"'+$path+'"'}
                $value=Task-Arguments ($prefix+$path)
            }
            $candidate[$property.Name]=$value
        }
        $same=$true
        foreach($key in $actual.Keys){if([string]$actual[$key] -cne [string]$candidate[$key]){$same=$false;break}}
        if($same){$equal=$true;$entryTag=[string]$entry.tags[0];$expected=$candidate;break}
    }
    if($null -eq $expected){$expected=@{}}
    $fields=@();$lines=''
    foreach($key in @($actual.Keys|Sort-Object)){
        $line=$key+'='+$actual[$key]+"`n";$lines+=$line
        $same=([string]$actual[$key] -ceq [string]$expected[$key])
        $fields+=,@{name=$key;sha256=(Task-Sha $line);matched=$same}
    }
    $records=@()
    foreach($node in @($document.SelectNodes('/*[local-name()="Task"]/*[local-name()="RegistrationInfo"]/* | /*[local-name()="Task"]/*[local-name()="Settings"] | /*[local-name()="Task"]/*[local-name()="Triggers"]/*/*[local-name()="StartBoundary" or local-name()="EndBoundary"]'))){$records+=,@{name=[string]$node.LocalName;sha256=(Task-Sha $node.OuterXml)}}
    return [pscustomobject]@{matched=$equal;sha256=(Task-Sha $lines);fields=$fields;records=$records;entry_tag=$entryTag;reason_code=if($equal){'EXACT_OFFICIAL_SOURCE_IDENTITY'}elseif($logonType -ceq 'ABSENT'){'LOGON_TYPE_ABSENT_UNMATCHED'}else{'IDENTITY_DIFFERS'}}
}

function Get-BootstrapSupportedLifecycleContext([string]$Root,[string]$Operation='inspect',[string]$ExpectedFromCommit='') {
    # Read-only counterpart of auto_update.resolve_lifecycle_context, called
    # through the existing byte-pinned bootstrap library before PlanOnly.
    if($Operation -cnotin @('inspect','install','register','uninstall','user_remove')){throw 'lifecycle_operation_invalid'}
    $rootFull=[IO.Path]::GetFullPath($Root)
    $fixed=Join-Path $rootFull 'current';$control=Join-Path $rootFull 'update-control'
    if($Operation -cin @('uninstall','user_remove')){
        return [pscustomobject]@{status='PASS';lifecycle_state='REMOVAL_READY';fixed_root=$fixed;owner_app_root=(Join-Path $fixed 'app');active_code_root=$null;active_app_root=$null;from_commit=$null}
    }
    try {
        foreach($path in @($rootFull,$fixed,$control,(Join-Path $rootFull 'versions'))){
            $existing=$path
            while(-not(Test-Path -LiteralPath $existing)){
                $parent=Split-Path -Parent $existing
                if(-not $parent -or $parent -ceq $existing){throw 'lifecycle_namespace_parent_unavailable'}
                $existing=$parent
            }
            Assert-BootstrapNoReparsePoint $existing 'lifecycle namespace' -PathOnly
            if((Test-Path -LiteralPath $path) -and -not(Test-Path -LiteralPath $path -PathType Container)){throw 'lifecycle_owned_namespace_collision'}
        }
        if($env:CONTAINER_AUDIT_DATA_ROOT){
            $data=[IO.Path]::GetFullPath($env:CONTAINER_AUDIT_DATA_ROOT).TrimEnd('\')
            foreach($reserved in @($fixed,$control,(Join-Path $rootFull 'versions'),(Join-Path $rootFull 'removal-evidence'))){
                if($data.Equals($reserved,[StringComparison]::OrdinalIgnoreCase) -or
                    $data.StartsWith($reserved+'\',[StringComparison]::OrdinalIgnoreCase) -or
                    $reserved.StartsWith($data+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'lifecycle_data_namespace_collision'}
            }
        }
        $records=@('policy.json','active.json','transition.json'|ForEach-Object {Join-Path $control $_})
        $present=@($records|ForEach-Object {Test-Path -LiteralPath $_})
        $managed=$present -contains $true
        if(-not(Test-Path -LiteralPath $fixed)){
            if($managed){throw 'lifecycle_removed_control_remains'}
            if($Operation -ceq 'register'){throw 'lifecycle_register_requires_installed_code'}
            foreach($task in @(Get-ScheduledTask -ErrorAction Stop)){
                if([string]$task.TaskName -ieq 'direct-sync-relay-container-audit'){
                    if($Operation -cne 'install' -or -not(Get-BootstrapOfficialLegacyRelayIdentity $task).matched){throw 'lifecycle_removed_tasks_remain_or_unknown'}
                }elseif([string]$task.TaskName -ieq 'container-audit-isolated-qualification-authority'){throw 'lifecycle_removed_tasks_remain_or_unknown'}
                if([string]$task.TaskName -cmatch '^KMTech\.ContainerAudit\.StartupUpdate\.[0-9a-f]{24}$'){
                    [xml]$taskXml=Export-ScheduledTask -TaskName ([string]$task.TaskName) -TaskPath ([string]$task.TaskPath) -ErrorAction Stop
                    foreach($action in @($taskXml.Task.Actions.Exec)){
                        if(([string]$action.Arguments).IndexOf($fixed,[StringComparison]::OrdinalIgnoreCase) -ge 0){throw 'lifecycle_removed_tasks_remain_or_unknown'}
                    }
                }
            }
            return [pscustomobject]@{status='PASS';lifecycle_state='REMOVED';fixed_root=$fixed;owner_app_root=(Join-Path $fixed 'app');active_code_root=$null;active_app_root=$null;from_commit=$null}
        }
        $identity=Get-BootstrapReplacementTreeIdentity $fixed $fixed
        if([string]$identity.owner_sid -cne 'S-1-5-32-544' -or $identity.access_rules_protected -isnot [bool] -or -not $identity.access_rules_protected){throw 'lifecycle_stock_protection_invalid'}
        if(-not(Test-Path -LiteralPath (Join-Path $fixed 'runtime\pythonw.exe') -PathType Leaf) -or
            -not(Test-Path -LiteralPath (Join-Path $fixed 'app\main.py') -PathType Leaf) -or
            (Test-Path -LiteralPath (Join-Path $fixed 'Container_Audit.exe') -PathType Leaf)){throw 'lifecycle_stock_layout_invalid'}
        $owner=Read-BootstrapLifecycleJson (Join-Path $fixed 'portable-manifest.json')
        if($owner['schema'] -cne 'container-audit-portable-tree-v1' -or
            $owner['entrypoint'] -cne 'runtime/pythonw.exe app/main.py' -or
            $owner['source_commit'] -isnot [string] -or $owner['source_commit'] -cnotmatch '^[0-9a-f]{40}$'){throw 'lifecycle_stock_manifest_invalid'}
        $ownerSha=$owner['source_commit'];$activeSha=$ownerSha;$activeRoot=$fixed
        if($managed){
            if($present -contains $false){throw 'lifecycle_control_incomplete'}
            $policy,$pointer,$state=@($records|ForEach-Object {Read-BootstrapLifecycleJson $_})
            if($policy['schema'] -cne 'container-audit-startup-update-policy-v1' -or
                $pointer['schema'] -cne 'container-audit-startup-update-v1' -or
                $state['schema'] -cne 'container-audit-startup-update-v1' -or
                $state['phase'] -cnotin @('CONFIRMED','DEFERRED','ROLLED_BACK')){throw 'lifecycle_transition_requires_recovery'}
            $activeSha=$pointer['sha']
            if($activeSha -isnot [string] -or $activeSha -cnotmatch '^[0-9a-f]{40}$'){throw 'lifecycle_active_manifest_mismatch'}
            if(($state['phase'] -ceq 'CONFIRMED' -and $state['candidate_sha'] -cne $activeSha) -or
                ($state['phase'] -ceq 'ROLLED_BACK' -and $state['previous_sha'] -cne $activeSha)){throw 'lifecycle_pointer_mismatch'}
            $activeRoot=Join-Path (Join-Path $rootFull 'versions') $activeSha
            $activeIdentity=Get-BootstrapReplacementTreeIdentity $activeRoot $activeRoot
            if([string]$activeIdentity.owner_sid -cne 'S-1-5-32-544' -or $activeIdentity.access_rules_protected -isnot [bool] -or -not $activeIdentity.access_rules_protected){throw 'lifecycle_stock_protection_invalid'}
            if(-not(Test-Path -LiteralPath (Join-Path $activeRoot 'runtime\pythonw.exe') -PathType Leaf) -or
                -not(Test-Path -LiteralPath (Join-Path $activeRoot 'app\main.py') -PathType Leaf) -or
                (Test-Path -LiteralPath (Join-Path $activeRoot 'Container_Audit.exe') -PathType Leaf)){throw 'lifecycle_stock_layout_invalid'}
            $actual=Read-BootstrapLifecycleJson (Join-Path $activeRoot 'portable-manifest.json')
            if($actual['schema'] -cne $owner['schema'] -or $actual['entrypoint'] -cne 'runtime/pythonw.exe app/main.py' -or
                $actual['source_commit'] -cne $activeSha){throw 'lifecycle_active_manifest_mismatch'}
            $fixedKey=Join-Path $fixed 'app\update-manifest-key-config.json';$activeKey=Join-Path $activeRoot 'app\update-manifest-key-config.json'
            Assert-BootstrapNoReparsePoint $fixedKey 'lifecycle trust configuration';Assert-BootstrapNoReparsePoint $activeKey 'lifecycle trust configuration'
            if((Get-FileSha256 $fixedKey) -cne (Get-FileSha256 $activeKey)){throw 'lifecycle_active_trust_key_mismatch'}
            $sid=$policy['operator_sid']
            if($sid -cnotmatch '^S-1-(?:[0-9]+-)+[0-9]+$' -or $fixed.IndexOfAny([char[]]@('"',"`r","`n")) -ge 0){throw 'lifecycle_task_absence_or_unknown'}
            $taskName='KMTech.ContainerAudit.StartupUpdate.'+(Get-BootstrapStringSha256 ($fixed.ToLowerInvariant()+"`n"+$sid)).Substring(0,24)
            [xml]$taskXml=Export-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
            $names=[Xml.XmlNamespaceManager]::new($taskXml.NameTable);$names.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
            if($taskXml.SelectNodes('/t:Task/t:Actions/t:Exec',$names).Count -ne 1 -or
                $taskXml.SelectNodes('/t:Task/t:Triggers/t:LogonTrigger',$names).Count -ne 1 -or
                $taskXml.SelectNodes('/t:Task/t:Principals/t:Principal',$names).Count -ne 1){throw 'lifecycle_task_absence_or_unknown'}
            $arguments='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File "'+$fixed+'\tools\apply_prepared_update.ps1" -InstallRoot "'+$fixed+'"'
            $wanted=@{
                '/t:Task/t:Triggers/t:LogonTrigger/t:UserId'=$sid
                '/t:Task/t:Principals/t:Principal/t:UserId'='S-1-5-18'
                '/t:Task/t:Principals/t:Principal/t:RunLevel'='HighestAvailable'
                '/t:Task/t:Actions/t:Exec/t:Command'=(Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
                '/t:Task/t:Actions/t:Exec/t:Arguments'=$arguments
                '/t:Task/t:Settings/t:AllowHardTerminate'='false'
                '/t:Task/t:Settings/t:Hidden'='true'
            }
            foreach($field in $wanted.Keys){$node=$taskXml.SelectSingleNode($field,$names);if($null -eq $node -or $node.InnerText -cne $wanted[$field]){throw 'lifecycle_task_absence_or_unknown'}}
            $after=@($records|ForEach-Object {Read-BootstrapLifecycleJson $_})
            for($index=0;$index -lt 3;$index++){
                if(-not(Test-BootstrapLifecycleJsonEqual $after[$index] @($policy,$pointer,$state)[$index])){throw 'lifecycle_state_changed_during_verification'}
            }
        }
        if($PSBoundParameters.ContainsKey('ExpectedFromCommit') -and ($ExpectedFromCommit -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedFromCommit -cne $activeSha)){throw 'lifecycle_from_commit_mismatch'}
        return [pscustomobject]@{status='PASS';lifecycle_state='HEALTHY';fixed_root=$fixed;owner_app_root=(Join-Path $fixed 'app');active_code_root=$activeRoot;active_app_root=(Join-Path $activeRoot 'app');from_commit=$activeSha;bootstrap_commit=$ownerSha;managed=$managed}
    }catch{
        throw [InvalidOperationException]::new('자료와 등록 및 전송 대기를 보존하고 지원 제거를 먼저 실행한 뒤 다시 설치하세요.',$_.Exception)
    }
}

function Get-BootstrapSupportedVersionRestoreState($Receipt,[string]$ReceiptPath,[string]$InstallRoot,[string]$ExpectedAppId,[string]$ExpectedTransactionId,[string]$ExpectedHelperSha256) {
    $fixed=Get-StrictFullPath $InstallRoot 'supported fixed owner'
    $parent=Split-Path -Parent $fixed
    $selection=$Receipt.active_version
    if ([string]$Receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$Receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or [string]$Receipt.app_id -cne $ExpectedAppId -or
        $ExpectedTransactionId -cnotmatch '^[0-9a-f]{32}$' -or [string]$Receipt.transaction_id -cne $ExpectedTransactionId -or
        [string]$Receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        -not(Test-BootstrapSamePath ([string]$Receipt.receipt_path) $ReceiptPath) -or
        -not(Test-BootstrapSamePath ([string]$Receipt.install_root) $fixed) -or
        -not(Test-BootstrapSamePath ([string]$Receipt.install_parent) $parent) -or
        [string]$selection.kind -cne 'SUPPORTED_ACTIVE_VERSION' -or
        [string]$selection.from_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$selection.to_sha -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$selection.from_sha -ceq [string]$selection.to_sha -or
        [string]$Receipt.old.source_commit -ceq [string]$selection.from_sha -or
        [string]$Receipt.new.source_commit -cne [string]$selection.to_sha -or
        -not(Test-BootstrapSamePath ([string]$selection.from_root) (Join-Path $parent ('versions\'+[string]$selection.from_sha))) -or
        -not(Test-BootstrapSamePath ([string]$selection.to_root) (Join-Path $parent ('versions\'+[string]$selection.to_sha))) -or
        -not(Test-BootstrapSamePath ([string]$Receipt.rollback_root) ([string]$selection.from_root)) -or
        -not(Test-BootstrapSamePath ([string]$Receipt.failed_root) (Join-Path $parent ('.version.failed.'+$ExpectedTransactionId))) -or
        -not $Receipt.PSObject.Properties['startup_update_preimage']) {throw 'Supported placement receipt binding differs.'}
    Assert-BootstrapNoReparsePoint $parent 'supported restore parent' -PathOnly
    if (-not(Test-BootstrapAclIdentity $Receipt.parent_acl (Get-BootstrapAclIdentity $parent))) {throw 'Supported restore parent protection differs.'}
    if (-not(Test-BootstrapReplacementTreeIdentity $Receipt.old (Get-BootstrapReplacementTreeIdentity $fixed $fixed)) -or
        -not(Test-BootstrapReplacementTreeIdentity $selection.from (Get-BootstrapReplacementTreeIdentity ([string]$selection.from_root) ([string]$selection.from_root)))) {throw 'Supported restore original owner or active code differs.'}
    $directory=[string]$Receipt.startup_update_preimage
    Assert-BootstrapNoReparsePoint $directory 'supported startup preimage'
    Assert-InstallationEvidenceProtectedPath $directory
    if((Get-FileSha256 (Join-Path $directory 'preimage.json')) -cne [string]$Receipt.startup_update_preimage_sha256){throw 'Supported restore preimage differs.'}
    $saved=Get-Content -LiteralPath (Join-Path $directory 'preimage.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if([string]$saved.schema -cne 'container-audit-startup-update-install-preimage-v1' -or
        -not(Test-BootstrapSamePath ([string]$saved.root) $fixed) -or
        (@($saved.files|ForEach-Object {[string]$_.name}) -join ',') -cne 'policy.json,active.json,transition.json' -or
        (@($selection.control_after|ForEach-Object {[string]$_.name}) -join ',') -cne 'policy.json,active.json,transition.json'){throw 'Supported restore control binding differs.'}
    foreach($item in @($saved.files)) {
        $planned=@($selection.control_after|Where-Object {$_.name -ceq $item.name})[0]
        if($item.exists -isnot [bool] -or -not $item.exists -or [string]$item.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            (Get-FileSha256 (Join-Path $directory ([string]$item.name))) -cne [string]$item.sha256 -or
            [string]$planned.sha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Supported restore control bytes differ.'}
        $target=Join-Path $parent ('update-control\'+[string]$item.name)
        Assert-BootstrapNoReparsePoint $target 'supported control cut' -PathOnly
        if((Get-FileSha256 $target) -cnotin @([string]$item.sha256,[string]$planned.sha256)){throw 'Supported control state is not an authenticated transaction cut.'}
    }
    $new=[string]$selection.to_root; $failed=[string]$Receipt.failed_root
    $newExists=Test-Path -LiteralPath $new; $failedExists=Test-Path -LiteralPath $failed
    if($newExists -eq $failedExists){throw 'Supported candidate preservation state is ambiguous.'}
    $selected=if($newExists){$new}else{$failed}
    if(-not(Test-BootstrapReplacementTreeIdentity $Receipt.new (Get-BootstrapReplacementTreeIdentity $selected $new))){throw 'Supported candidate tree or protection differs.'}
    return [pscustomobject]@{status=$(if($newExists){'PENDING'}else{'RESTORED'});install_root=$fixed;rollback_root=[string]$selection.from_root;failed_new_root=$failed}
}

function Get-BootstrapVerifiedReplacementRestoreState(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256
) {
    if($Receipt.PSObject.Properties['active_version']) {return Get-BootstrapSupportedVersionRestoreState $Receipt $ReceiptPath $InstallRoot $ExpectedAppId $ExpectedTransactionId $ExpectedHelperSha256}
    $current = Get-StrictFullPath $InstallRoot 'restore current root'
    $parent = Get-StrictFullPath (Split-Path -Parent $current) 'restore parent'
    $rollback = Get-StrictFullPath ([string]$Receipt.rollback_root) 'restore rollback root'
    $failed = Get-StrictFullPath ([string]$Receipt.failed_root) 'restore failed root'
    $receiptFull = Get-StrictFullPath $ReceiptPath 'replacement receipt path'
    if (
        [string]$Receipt.schema_version -cne 'container-audit-verified-replacement-v1' -or
        [string]$Receipt.status -cne 'OLD_PRESERVED_NEW_VERIFIED' -or
        [string]$Receipt.app_id -cne $ExpectedAppId -or
        [string]$Receipt.transaction_id -cne $ExpectedTransactionId -or
        [string]$Receipt.helper_sha256 -cne $ExpectedHelperSha256 -or
        -not (Test-BootstrapSamePath ([string]$Receipt.receipt_path) $receiptFull) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_root) $current) -or
        -not (Test-BootstrapSamePath ([string]$Receipt.install_parent) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $rollback) $parent) -or
        -not (Test-BootstrapSamePath (Split-Path -Parent $failed) $parent) -or
        $ExpectedTransactionId -cnotmatch '^[0-9a-f]{32}$' -or
        [IO.Path]::GetFileName($rollback) -cne ".current.rollback.$ExpectedTransactionId" -or
        [IO.Path]::GetFileName($failed) -cne ".current.failed.$ExpectedTransactionId"
    ) {
        throw 'Replacement receipt identity or path binding is invalid.'
    }
    Assert-BootstrapNoReparsePoint $parent 'replacement restore parent' -PathOnly
    $parentAcl = Get-BootstrapAclIdentity $parent
    if (-not (Test-BootstrapAclIdentity $Receipt.parent_acl $parentAcl)) { throw 'Replacement restore parent ACL identity differs.' }
    # Only the receipt-selected trees participate in this transaction. Retained
    # history is neither read nor moved; each selected tree is checked recursively.
    foreach ($selected in @($current, $rollback, $failed)) {
        if ((Test-Path -LiteralPath $selected) -and
            -not (Test-Path -LiteralPath $selected -PathType Container)) {
            throw 'Replacement restore selected path is not a directory.'
        }
    }

    $currentExists = Test-Path -LiteralPath $current -PathType Container
    $rollbackExists = Test-Path -LiteralPath $rollback -PathType Container
    $failedExists = Test-Path -LiteralPath $failed -PathType Container
    $currentIdentity = if ($currentExists) { Get-BootstrapReplacementTreeIdentity $current $current } else { $null }
    $rollbackIdentity = if ($rollbackExists) { Get-BootstrapReplacementTreeIdentity $rollback $current } else { $null }
    $failedIdentity = if ($failedExists) { Get-BootstrapReplacementTreeIdentity $failed $current } else { $null }
    $pending = $currentExists -and $rollbackExists -and -not $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity)
    $displaced = -not $currentExists -and $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $rollbackIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    $restored = $currentExists -and -not $rollbackExists -and $failedExists -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.old $currentIdentity) -and
        (Test-BootstrapReplacementTreeIdentity $Receipt.new $failedIdentity)
    if (-not $pending -and -not $displaced -and -not $restored) {
        throw 'Replacement restore state is ambiguous or drifted.'
    }
    return [pscustomobject][ordered]@{
        status = if ($restored) { 'RESTORED' } elseif ($pending) { 'PENDING' } else { 'DISPLACED' }
        install_root = $current
        rollback_root = $rollback
        failed_new_root = $failed
    }
}

function Invoke-BootstrapVerifiedReplacementRestore(
    $Receipt,
    [string]$ReceiptPath,
    [string]$InstallRoot,
    [string]$ExpectedAppId,
    [string]$ExpectedTransactionId,
    [string]$ExpectedHelperSha256,
    [switch]$InjectFailureAfterDisplace
) {
    $state = Get-BootstrapVerifiedReplacementRestoreState `
        -Receipt $Receipt -ReceiptPath $ReceiptPath -InstallRoot $InstallRoot `
        -ExpectedAppId $ExpectedAppId -ExpectedTransactionId $ExpectedTransactionId `
        -ExpectedHelperSha256 $ExpectedHelperSha256
    if($Receipt.PSObject.Properties['active_version']) {
        if([string]$state.status -ceq 'PENDING') {
            Move-Item -LiteralPath ([string]$Receipt.active_version.to_root) -Destination ([string]$Receipt.failed_root) -ErrorAction Stop
            if($InjectFailureAfterDisplace){throw 'Injected supported restore interruption after candidate preservation.'}
        }
        $verified=Get-BootstrapSupportedVersionRestoreState $Receipt $ReceiptPath $InstallRoot $ExpectedAppId $ExpectedTransactionId $ExpectedHelperSha256
        if([string]$verified.status -cne 'RESTORED'){throw 'Supported restore exact readback failed.'}
        return [pscustomobject]@{status='RESTORED';install_root=$InstallRoot;failed_new_root=[string]$Receipt.failed_root;prior_code_exact=$true;failed_new_preserved=$true}
    }
    $current = [string]$state.install_root
    $rollback = [string]$state.rollback_root
    $failed = [string]$state.failed_new_root
    if ([string]$state.status -ceq 'RESTORED') {
        return [pscustomobject][ordered]@{
            status = 'ALREADY_RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    try {
        if ([string]$state.status -ceq 'PENDING') { Move-Item -LiteralPath $current -Destination $failed -ErrorAction Stop }
        if ($InjectFailureAfterDisplace.IsPresent) { throw 'Injected restore failure after current displacement.' }
        Move-Item -LiteralPath $rollback -Destination $current -ErrorAction Stop
        $restoredOld = Get-BootstrapReplacementTreeIdentity $current $current
        $preservedNew = Get-BootstrapReplacementTreeIdentity $failed $current
        if (
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.old $restoredOld) -or
            -not (Test-BootstrapReplacementTreeIdentity $Receipt.new $preservedNew)
        ) { throw 'Replacement restore exact readback failed.' }
        return [pscustomobject][ordered]@{
            status = 'RESTORED'
            install_root = $current
            failed_new_root = $failed
            prior_code_exact = $true
            failed_new_preserved = $true
        }
    }
    catch {
        $original = $_.Exception.Message
        $contained = $false
        try {
            if (
                (Test-Path -LiteralPath $current -PathType Container) -and
                -not (Test-Path -LiteralPath $rollback) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $current -Destination $rollback -ErrorAction Stop
            }
            if (
                -not (Test-Path -LiteralPath $current) -and
                (Test-Path -LiteralPath $failed -PathType Container)
            ) {
                Move-Item -LiteralPath $failed -Destination $current -ErrorAction Stop
            }
            $containedCurrent = Get-BootstrapReplacementTreeIdentity $current $current
            $containedRollback = Get-BootstrapReplacementTreeIdentity $rollback $current
            $contained = (
                -not (Test-Path -LiteralPath $failed) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.new $containedCurrent) -and
                (Test-BootstrapReplacementTreeIdentity $Receipt.old $containedRollback)
            )
        }
        catch { $contained = $false }
        if (-not $contained) { throw "Replacement restore failed and containment also failed: $original" }
        throw "Replacement restore failed; the pre-restore state was contained: $original"
    }
}

function Test-WriterSessionContractExactPropertySet($Value, [string[]]$Expected) {
    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($name -cnotin $actual) { return $false }
    }
    return $true
}

function Test-WriterSessionContractExactStringProperties($Value, [string[]]$Names) {
    if ($null -eq $Value) { return $false }
    foreach ($name in $Names) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [string])) { return $false }
    }
    return $true
}

function Get-WriterSessionContractMutexName($Fence, $Vector) {
    $values = @(
        [string]$Fence.session_tuple_version,
        [string]$Vector.session_id,
        [string]$Vector.attempt_id,
        [string]$Vector.orchestrator_sha256,
        [string]$Vector.replacement_transaction_id,
        [string]$Vector.writer_contract_sha256
    )
    $normalized = @($values | ForEach-Object {
        $_.Normalize([Text.NormalizationForm]::FormC)
    })
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($normalized -join "`n"))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
    return [string]$Fence.session_mutex_prefix + $digest
}

function Assert-WriterSessionPublicContract([string]$Path, [string]$ExpectedSha256) {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 65536) {
        throw "Writer session public contract is oversized."
    }
    if ((Get-FileSha256 $Path) -cne $ExpectedSha256) {
        throw "Writer session public contract hash differs."
    }
    try { $contract = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "Writer session public contract JSON is invalid." }
    $bindings = @('session_id','attempt_id','replacement_transaction_id','session_started_at_utc','orchestrator_sha256','session_authority_mutex_name','adapter_sha256','contract_sha256','evidence_path','historical_capability.receipt_sha256','historical_capability.capability_binding_sha256')
    $fenceFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','session_tuple_fields','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule','verification_vectors','active_statuses','writer_admission_fail_closed','unknown_or_unobservable_is_denied','denial_mutates_state')
    $fenceStringFields = @('active_schema','release_schema','control_root','active_filename','release_filename_pattern','admission_mutex_name','noncanonical_mutex_derivation','session_mutex_prefix','session_tuple_version','tuple_separator','tuple_encoding','tuple_normalization','writer_inventory_path','writer_inventory_sha256','canonical_installer_delegation_source','scheduled_task_mutation_rule','natural_trigger_phase_rule')
    $vectorFields = @('session_id','attempt_id','orchestrator_sha256','replacement_transaction_id','writer_contract_sha256','expected_mutex_name')
    $vectors = @($contract.all_writer_fence.verification_vectors)
    $vectorsValid = $vectors.Count -eq 2
    foreach ($vector in $vectors) {
        if (
            -not (Test-WriterSessionContractExactPropertySet $vector $vectorFields) -or
            -not (Test-WriterSessionContractExactStringProperties $vector $vectorFields) -or
            [string]$vector.session_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.attempt_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.orchestrator_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.replacement_transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$vector.writer_contract_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$vector.expected_mutex_name -cne (Get-WriterSessionContractMutexName $contract.all_writer_fence $vector)
        ) { $vectorsValid = $false }
    }
    if ($vectors.Count -eq 2) {
        $vectorsValid = $vectorsValid -and
            [string]$vectors[0].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.1121406d92315036b04c14edfea1a09a03938923fa052324623e225d006a7b0c' -and
            [string]$vectors[1].expected_mutex_name -ceq 'Local\KMTech.ContainerAudit.DeploymentSession.7487aff53f2ea39a278e3648037625e8c1484636d80a5177dee05ba06556f071'
    }
    $requiredTrue = @(
        $contract.lifecycle_restore.require_same_session_receipt,
        $contract.lifecycle_restore.require_code_restore_before_writer_restore,
        $contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore,
        $contract.lifecycle_restore.require_live_current_user_lifecycle_before_writer_restore,
        $contract.lifecycle_restore.require_non_elevated_medium_integrity_lifecycle_producer,
        $contract.lifecycle_restore.producer_code_tree_read_locked_through_execution,
        $contract.lifecycle_restore.failure_is_explicit,
        $contract.security.active_session_authority_mutex_required,
        $contract.security.all_writer_fence_required,
        $contract.security.all_writer_sinks_require_admission,
        $contract.security.evidence_paths_outside_install_parent_required,
        $contract.security.evidence_paths_local_fixed_drive_required,
        $contract.security.evidence_path_reparse_ancestors_forbidden,
        $contract.security.evidence_path_aliases_canonicalized
    )
    $requiredFalse = @($contract.security.secret_values_recorded, $contract.security.manual_writer_start_allowed, $contract.security.contract_mode_system_mutation, $contract.all_writer_fence.denial_mutates_state)
    if (
        [string]$contract.schema -cne 'container-audit-writer-session-cli-contract-v1' -or
        [string]$contract.app_id -cne 'container_audit' -or
        [string]$contract.cli.relative_path -cne 'tools/container_writer_session.ps1' -or
        (@($contract.cli.public_writer_modes) -join ',') -cne 'Contract,Prepare,ValidatePrepared,RestoreWriter' -or
        -not (Test-BootstrapJsonInteger $contract.cli.success_exit_code) -or [int64]$contract.cli.success_exit_code -ne 0 -or
        @($contract.cli.failure_exit_codes | Where-Object { -not (Test-BootstrapJsonInteger $_) }).Count -ne 0 -or
        (@($contract.cli.failure_exit_codes) -join ',') -cne '1,20' -or
        -not (Test-BootstrapJsonInteger $contract.identifiers.session_max_age_hours) -or [int64]$contract.identifiers.session_max_age_hours -ne 24 -or
        [string]$contract.identifiers.session_authority_mutex_derivation -cne 'Local\KMTech.ContainerAudit.DeploymentSession.<sha256(v1 canonical session tuple)>' -or
        -not (Test-WriterSessionContractExactPropertySet $contract.all_writer_fence $fenceFields) -or
        -not (Test-WriterSessionContractExactStringProperties $contract.all_writer_fence $fenceStringFields) -or
        [string]$contract.all_writer_fence.active_schema -cne 'container-audit-all-writer-fence-active-v1' -or
        [string]$contract.all_writer_fence.release_schema -cne 'container-audit-all-writer-fence-release-v1' -or
        [string]$contract.all_writer_fence.control_root -cne '%LOCALAPPDATA%\KMTech\DirectSync\container_audit\control\writer-session' -or
        [string]$contract.all_writer_fence.active_filename -cne 'active.json' -or
        [string]$contract.all_writer_fence.release_filename_pattern -cne 'release-{replacement_transaction_id}-{release_authorization_sha256}.json' -or
        [string]$contract.all_writer_fence.admission_mutex_name -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1' -or
        [string]$contract.all_writer_fence.noncanonical_mutex_derivation -cne 'Local\KMTech.ContainerAudit.WriterAdmission.v1.<first 16 lowercase hex characters of SHA-256 over the absolute control root after slash-to-backslash conversion, trailing-backslash removal, Unicode NFC, and ASCII A-Z to a-z mapping with every other code point unchanged, encoded as UTF-8 without BOM>' -or
        [string]$contract.all_writer_fence.session_mutex_prefix -cne 'Local\KMTech.ContainerAudit.DeploymentSession.' -or
        [string]$contract.all_writer_fence.session_tuple_version -cne 'container-audit-deployment-session-authority-v1' -or
        $contract.all_writer_fence.session_tuple_fields -isnot [Object[]] -or
        @($contract.all_writer_fence.session_tuple_fields | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.session_tuple_fields) -join ',') -cne 'session_tuple_version,session_id,attempt_id,orchestrator_sha256,replacement_transaction_id,writer_contract_sha256' -or
        [string]$contract.all_writer_fence.tuple_separator -cne 'LF (U+000A) between ordered fields; no trailing LF' -or
        [string]$contract.all_writer_fence.tuple_encoding -cne 'UTF-8 without BOM' -or
        [string]$contract.all_writer_fence.tuple_normalization -cne 'Unicode NFC applied to each field before joining' -or
        [string]$contract.all_writer_fence.writer_inventory_path -cne 'tools/container_writer_sink_inventory.json' -or
        [string]$contract.all_writer_fence.canonical_installer_delegation_source -cne 'writer_sink_sources from the exact pinned code-derived inventory' -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.scheduled_task_mutation_rule) -or
        [string]::IsNullOrWhiteSpace([string]$contract.all_writer_fence.natural_trigger_phase_rule) -or
        [string]$contract.all_writer_fence.writer_inventory_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $contract.all_writer_fence.verification_vectors -isnot [Object[]] -or
        $contract.all_writer_fence.active_statuses -isnot [Object[]] -or
        @($contract.all_writer_fence.active_statuses | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        (@($contract.all_writer_fence.active_statuses) -join ',') -cne 'PREPARING,PREPARED,RESTORING,RESTORE_FAILED,INSTALLING' -or
        $contract.all_writer_fence.writer_admission_fail_closed -isnot [bool] -or -not $contract.all_writer_fence.writer_admission_fail_closed -or
        $contract.all_writer_fence.unknown_or_unobservable_is_denied -isnot [bool] -or -not $contract.all_writer_fence.unknown_or_unobservable_is_denied -or
        -not $vectorsValid -or
        [string]$contract.receipts.prepared_schema -cne 'container-audit-writer-session-prepared-v3' -or
        [string]$contract.receipts.restored_schema -cne 'container-audit-writer-session-restored-v2' -or
        [string]$contract.receipts.lifecycle_restore_schema -cne 'container-audit-replacement-lifecycle-restore-v1' -or
        (@($contract.receipts.prepared_required_bindings) -join ',') -cne ($bindings -join ',') -or
        [string]$contract.lifecycle_restore.product_mode -cne '--restore-current-user-lifecycle-after-replacement' -or
        @($requiredTrue | Where-Object { $_ -isnot [bool] -or -not $_ }).Count -ne 0 -or
        @($requiredFalse | Where-Object { $_ -isnot [bool] -or $_ }).Count -ne 0
    ) { throw "Writer session public contract semantics differ." }
}

function Get-CodeInventoryInRecordOrder([string]$Root, [object[]]$RecordedFiles) {
    # V1 records predate ordinal issuance. Preserve their exact order and digest;
    # only a bijection onto the actual, case-sensitive relative paths is valid.
    # Both consumers still check every size/hash and the original aggregate.
    $inventory = @(Get-CodeInventory $Root)
    if ($RecordedFiles.Count -ne $inventory.Count) {
        throw 'Bootstrap integrity inventory differs: recorded file count.'
    }
    $actualByPath = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($item in $inventory) { $actualByPath.Add([string]$item.path, $item) }
    $ordered = @()
    foreach ($expected in $RecordedFiles) {
        if ($expected.path -isnot [string] -or -not $actualByPath.ContainsKey($expected.path)) {
            throw 'Bootstrap integrity inventory differs: missing, duplicate or changed path.'
        }
        $ordered += $actualByPath[$expected.path]
        [void]$actualByPath.Remove($expected.path)
    }
    return $ordered
}
