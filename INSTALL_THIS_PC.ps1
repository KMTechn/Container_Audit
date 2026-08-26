[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$PurgeContainerAuditState,
    [switch]$ConfirmPermanentContainerAuditDataRemoval,
    [string]$RollbackReportPath = "",
    [switch]$AllowNoncanonicalLayoutForTest,
    [switch]$EnableWindowsSandboxQualification,
    [string]$ServerBaseUrl = "https://worker.kmtecherp.com",
    [string]$DataRoot = "",
    [string]$DirectSyncRoot = "C:\ProgramData\KMTech\DirectSync\container_audit",
    [string]$TaskName = "direct-sync-relay-container-audit",
    [string]$EnrollmentTokenEnv = "CONTAINER_AUDIT_ENROLLMENT_TOKEN",
    [string]$ExistingProducerManifestPath = "",
    [string]$ExistingCredentialPath = "",
    [string]$ExistingRegistrationReportPath = "",
    [string]$ProducerIdentityPath = "",
    [string]$ProducerInstallId = "",
    [string]$ProducerId = "",
    [string]$SourceHostId = "",
    [string]$OperatorUserSid = "",
    [string]$OperatorLocalAppDataRoot = ""
)

$ErrorActionPreference = "Stop"

function ConvertTo-ElevationArgument([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashCount += 1
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append((('\' * (($slashCount * 2) + 1)) -join ''))
            [void]$builder.Append('"')
            $slashCount = 0
            continue
        }
        if ($slashCount -gt 0) {
            [void]$builder.Append((('\' * $slashCount) -join ''))
            $slashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashCount -gt 0) {
        [void]$builder.Append((('\' * ($slashCount * 2)) -join ''))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-SelfElevated(
    [string]$ScriptPath,
    [hashtable]$BoundParameters,
    [object[]]$RemainingArguments
) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }
    $powershellExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $launchArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($name in $BoundParameters.Keys) {
        $value = $BoundParameters[$name]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $launchArguments += "-$name" }
            continue
        }
        $launchArguments += @("-$name", [string]$value)
    }
    $launchArguments += @($RemainingArguments | ForEach-Object { [string]$_ })
    $argumentLine = ($launchArguments | ForEach-Object { ConvertTo-ElevationArgument $_ }) -join ' '
    $process = Start-Process -FilePath $powershellExe -Verb RunAs -ArgumentList $argumentLine -Wait -PassThru -ErrorAction Stop
    exit $process.ExitCode
}

function Get-CurrentOperatorContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User -or [string]::IsNullOrWhiteSpace($identity.User.Value)) {
        throw "The invoking operator SID is unavailable."
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "The invoking operator LOCALAPPDATA is unavailable."
    }
    return [ordered]@{
        sid = $identity.User.Value
        local_app_data_root = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA)
    }
}

$currentOperator = Get-CurrentOperatorContext
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$currentIsAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $currentIsAdministrator) {
    if (
        (-not [string]::IsNullOrWhiteSpace($OperatorUserSid) -and $OperatorUserSid -cne $currentOperator.sid) -or
        (-not [string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot) -and
            -not ([System.IO.Path]::GetFullPath($OperatorLocalAppDataRoot)).Equals(
                $currentOperator.local_app_data_root,
                [System.StringComparison]::OrdinalIgnoreCase
            ))
    ) {
        throw "Operator identity parameters cannot replace the invoking non-elevated operator."
    }
    $OperatorUserSid = $currentOperator.sid
    $OperatorLocalAppDataRoot = $currentOperator.local_app_data_root
    $PSBoundParameters["OperatorUserSid"] = $OperatorUserSid
    $PSBoundParameters["OperatorLocalAppDataRoot"] = $OperatorLocalAppDataRoot
}
else {
    if ([string]::IsNullOrWhiteSpace($OperatorUserSid)) {
        $OperatorUserSid = $currentOperator.sid
    }
    if ([string]::IsNullOrWhiteSpace($OperatorLocalAppDataRoot)) {
        $OperatorLocalAppDataRoot = $currentOperator.local_app_data_root
    }
}

if (-not $DryRun.IsPresent) {
    Invoke-SelfElevated $MyInvocation.MyCommand.Path $PSBoundParameters $args
}


function Assert-HttpsServerBaseUrl([string]$Value, [switch]$AllowExplicitHttp) {
    $uri = $null
    if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "ServerBaseUrl must be an absolute HTTP or HTTPS origin."
    }
    $schemeAllowed = (
        $uri.Scheme -ceq "https" -or
        ($AllowExplicitHttp.IsPresent -and $uri.Scheme -ceq "http")
    )
    if (
        -not $schemeAllowed -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment)
    ) {
        throw "ServerBaseUrl must be an HTTPS origin, or an HTTP origin authorized by Windows Sandbox qualification, without userinfo, query, or fragment."
    }
}
function Resolve-ProducerSubmissionBaseUrl(
    [string]$RequestedServerBaseUrl,
    [bool]$RequestedServerBaseUrlIsExplicit,
    [string]$QualificationAuthorityServerBaseUrl
) {
    # The qualification authority keeps its loopback origin for its own bounded
    # duties. An explicitly supplied origin stays the product's receipt/projection
    # submission target instead of being replaced by it, production default included.
    if ($RequestedServerBaseUrlIsExplicit) {
        return $RequestedServerBaseUrl.Trim().TrimEnd('/')
    }
    return $QualificationAuthorityServerBaseUrl.Trim().TrimEnd('/')
}
function Remove-NewMachineProfilesFromRegistrationReport([string]$RegistrationReportPath) {
    if (-not (Test-Path -LiteralPath $RegistrationReportPath -PathType Leaf)) {
        return
    }
    $payload = Get-Content -LiteralPath $RegistrationReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $payload.machine_profiles) {
        return
    }
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $profileRoot = Join-Path $programData "KMTech\Logistics\profiles\Container_Audit"
    $allowed = @(
        [System.IO.Path]::GetFullPath((Join-Path $profileRoot "runtime-profile.json")),
        [System.IO.Path]::GetFullPath((Join-Path $profileRoot "secrets\bearer-token.dpapi"))
    )
    foreach ($property in $payload.machine_profiles.PSObject.Properties) {
        $profile = $property.Value
        if ([string]$profile.status -cne "installed") {
            continue
        }
        foreach ($createdPath in @($profile.created_paths)) {
            $fullPath = [System.IO.Path]::GetFullPath([string]$createdPath)
            if ($allowed -notcontains $fullPath) {
                throw "Refusing to roll back an unexpected machine profile path."
            }
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
            }
        }
    }
}

function Read-BoundedJson([string]$Path, [string]$Purpose) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Purpose is absent." }
    $length = (Get-Item -LiteralPath $Path -Force).Length
    if ($length -le 0 -or $length -gt 1048576) { throw "$Purpose size is invalid." }
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    Assert-JsonHasNoDuplicateObjectKeys $text $Purpose
    return ($text | ConvertFrom-Json)
}

function Write-Utf8JsonFile([string]$Path, $Payload) {
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $json = $Payload | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [System.Environment]::NewLine, $utf8NoBom)
}

function ConvertTo-CanonicalJsonValue($Value) {
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string]) {
        return $Value.Normalize([System.Text.NormalizationForm]::FormC)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        [string[]]$keys = @($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $ordered[$key] = ConvertTo-CanonicalJsonValue $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        [string[]]$keys = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $ordered[$key] = ConvertTo-CanonicalJsonValue $Value.$key
        }
        return $ordered
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) {
            [void]$items.Add((ConvertTo-CanonicalJsonValue $item))
        }
        return ,$items.ToArray()
    }
    return $Value
}

function ConvertTo-PythonJsonString([string]$Value) {
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    :jsonCharacters foreach ($character in $Value.Normalize([System.Text.NormalizationForm]::FormC).ToCharArray()) {
        switch ([int]$character) {
            8 { [void]$builder.Append('\b'); continue jsonCharacters }
            9 { [void]$builder.Append('\t'); continue jsonCharacters }
            10 { [void]$builder.Append('\n'); continue jsonCharacters }
            12 { [void]$builder.Append('\f'); continue jsonCharacters }
            13 { [void]$builder.Append('\r'); continue jsonCharacters }
            34 { [void]$builder.Append('\"'); continue jsonCharacters }
            92 { [void]$builder.Append('\\'); continue jsonCharacters }
        }
        if ([int]$character -lt 32) {
            [void]$builder.Append(('\u{0:x4}' -f [int]$character))
        }
        else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-PythonCanonicalJson($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ConvertTo-PythonJsonString $Value }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if (
        $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [decimal]
    ) {
        return ([System.IFormattable]$Value).ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [single] -or $Value -is [double]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
            throw 'Canonical JSON does not allow a non-finite number.'
        }
        $text = $number.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture).Replace('E', 'e')
        if ($text -match 'e([+-]?)([0-9]+)$') {
            $sign = $Matches[1]
            $digits = $Matches[2].TrimStart('0')
            if ($digits.Length -eq 0) { $digits = '0' }
            $text = $text.Substring(0, $text.LastIndexOf('e')) + 'e' + $sign + $digits
        }
        if ($text -notmatch '[\.e]') { $text += '.0' }
        return $text
    }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Value -is [System.Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            [void]$parts.Add((ConvertTo-PythonJsonString $key) + ':' + (ConvertTo-PythonCanonicalJson $Value[$key]))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        [string[]]$keys = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            [void]$parts.Add((ConvertTo-PythonJsonString $key) + ':' + (ConvertTo-PythonCanonicalJson $Value.$key))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            [void]$parts.Add((ConvertTo-PythonCanonicalJson $item))
        }
        return '[' + ($parts -join ',') + ']'
    }
    throw "Canonical JSON does not support value type $($Value.GetType().FullName)."
}

function Assert-JsonHasNoDuplicateObjectKeys([string]$Json, [string]$Purpose) {
    $state = [pscustomobject]@{ position = 0 }
    $length = $Json.Length
    $skipWhitespace = {
        while ($state.position -lt $length -and [char]::IsWhiteSpace($Json[$state.position])) {
            $state.position += 1
        }
    }
    $readString = {
        if ($state.position -ge $length -or $Json[$state.position] -ne '"') {
            throw "$Purpose contains invalid JSON string syntax."
        }
        $state.position += 1
        $builder = New-Object System.Text.StringBuilder
        while ($state.position -lt $length) {
            $character = $Json[$state.position]
            $state.position += 1
            if ($character -eq '"') {
                return $builder.ToString()
            }
            if ([int]$character -lt 32) {
                throw "$Purpose contains an invalid JSON control character."
            }
            if ($character -ne '\') {
                [void]$builder.Append($character)
                continue
            }
            if ($state.position -ge $length) {
                throw "$Purpose contains a truncated JSON escape."
            }
            $escape = $Json[$state.position]
            $state.position += 1
            switch ($escape) {
                '"' { [void]$builder.Append('"') }
                '\' { [void]$builder.Append('\') }
                '/' { [void]$builder.Append('/') }
                'b' { [void]$builder.Append([char]8) }
                'f' { [void]$builder.Append([char]12) }
                'n' { [void]$builder.Append([char]10) }
                'r' { [void]$builder.Append([char]13) }
                't' { [void]$builder.Append([char]9) }
                'u' {
                    if ($state.position + 4 -gt $length) {
                        throw "$Purpose contains a truncated JSON unicode escape."
                    }
                    $hex = $Json.Substring($state.position, 4)
                    if ($hex -notmatch '^[0-9A-Fa-f]{4}$') {
                        throw "$Purpose contains an invalid JSON unicode escape."
                    }
                    [void]$builder.Append([char][Convert]::ToInt32($hex, 16))
                    $state.position += 4
                }
                default { throw "$Purpose contains an invalid JSON escape." }
            }
        }
        throw "$Purpose contains an unterminated JSON string."
    }
    $readValue = $null
    $readValue = {
        & $skipWhitespace
        if ($state.position -ge $length) {
            throw "$Purpose contains truncated JSON."
        }
        $character = $Json[$state.position]
        if ($character -eq '"') {
            [void](& $readString)
            return
        }
        if ($character -eq '{') {
            $state.position += 1
            $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            & $skipWhitespace
            if ($state.position -lt $length -and $Json[$state.position] -eq '}') {
                $state.position += 1
                return
            }
            while ($true) {
                & $skipWhitespace
                $key = & $readString
                if (-not $keys.Add($key)) {
                    throw "$Purpose contains duplicate JSON key: $key"
                }
                & $skipWhitespace
                if ($state.position -ge $length -or $Json[$state.position] -ne ':') {
                    throw "$Purpose contains an invalid JSON object separator."
                }
                $state.position += 1
                & $readValue
                & $skipWhitespace
                if ($state.position -ge $length) {
                    throw "$Purpose contains an unterminated JSON object."
                }
                if ($Json[$state.position] -eq '}') {
                    $state.position += 1
                    return
                }
                if ($Json[$state.position] -ne ',') {
                    throw "$Purpose contains an invalid JSON object delimiter."
                }
                $state.position += 1
            }
        }
        if ($character -eq '[') {
            $state.position += 1
            & $skipWhitespace
            if ($state.position -lt $length -and $Json[$state.position] -eq ']') {
                $state.position += 1
                return
            }
            while ($true) {
                & $readValue
                & $skipWhitespace
                if ($state.position -ge $length) {
                    throw "$Purpose contains an unterminated JSON array."
                }
                if ($Json[$state.position] -eq ']') {
                    $state.position += 1
                    return
                }
                if ($Json[$state.position] -ne ',') {
                    throw "$Purpose contains an invalid JSON array delimiter."
                }
                $state.position += 1
            }
        }
        $remaining = $Json.Substring($state.position)
        if ($remaining -match '^(true|false|null)') {
            $state.position += $Matches[1].Length
            return
        }
        if ($remaining -match '^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?') {
            $state.position += $Matches[0].Length
            return
        }
        throw "$Purpose contains an invalid JSON value."
    }
    & $readValue
    & $skipWhitespace
    if ($state.position -ne $length) {
        throw "$Purpose contains trailing JSON content."
    }
}

function Get-CanonicalJsonSha256($Payload) {
    $json = ConvertTo-PythonCanonicalJson $Payload
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-AtomicFileBytes([string]$Path, [byte[]]$Bytes) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }
    $temporary = Join-Path $parent ('.{0}.{1}.{2}.tmp' -f ([System.IO.Path]::GetFileName($fullPath)), $PID, [Guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllBytes($temporary, $Bytes)
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            # Windows PowerShell 5.1 converts a bare $null string argument to String.Empty.
            [System.IO.File]::Replace(
                $temporary,
                $fullPath,
                [System.Management.Automation.Language.NullString]::Value,
                $true
            )
        }
        else {
            [System.IO.File]::Move($temporary, $fullPath)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-AtomicUtf8JsonFile([string]$Path, $Payload) {
    $canonical = ConvertTo-CanonicalJsonValue $Payload
    $json = ConvertTo-PythonCanonicalJson $canonical
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json + [System.Environment]::NewLine)
    Write-AtomicFileBytes $Path $bytes
}

function Get-JsonPropertyNames($Value) {
    if ($Value -is [System.Collections.IDictionary]) {
        return @($Value.Keys | ForEach-Object { [string]$_ })
    }
    if ($null -eq $Value) {
        return @()
    }
    return @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Assert-ExactJsonFields($Value, [string[]]$Expected, [string]$Purpose) {
    $actual = @(Get-JsonPropertyNames $Value | Sort-Object)
    $required = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($required -join "`n")) {
        throw "$Purpose fields are invalid."
    }
}

function Get-SafeSecretReferenceName([string]$Value) {
    $name = [string]$Value
    if (
        [string]::IsNullOrWhiteSpace($name) -or
        $name.Length -gt 200 -or
        $name -notmatch '^[A-Za-z0-9_.-]+$'
    ) {
        throw "secret_ref target is invalid."
    }
    return $name
}

function Protect-MachineSecret([string]$Value, [byte[]]$Entropy = $null) {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Machine secret is empty."
    }
    $clear = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Value)
    return [System.Security.Cryptography.ProtectedData]::Protect(
        $clear,
        $Entropy,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
}

function Test-MachineSecret([byte[]]$Protected, [string]$Expected, [byte[]]$Entropy = $null) {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    $clear = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $Protected,
        $Entropy,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $actual = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($clear)
    return $actual -ceq $Expected
}

function Set-ContainerAuditMachineProfileAcl([string]$DirectoryPath) {
    if (-not (Test-Path -LiteralPath $DirectoryPath -PathType Container)) {
        New-Item -ItemType Directory -Path $DirectoryPath -Force -ErrorAction Stop | Out-Null
    }
    $directory = New-Object System.IO.DirectoryInfo -ArgumentList $DirectoryPath
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($entry in @(
        @('S-1-5-18', [System.Security.AccessControl.FileSystemRights]::FullControl),
        @('S-1-5-32-544', [System.Security.AccessControl.FileSystemRights]::FullControl),
        @('S-1-5-32-545', [System.Security.AccessControl.FileSystemRights]::Read)
    )) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList ([string]$entry[0])
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $sid,
            [System.Security.AccessControl.FileSystemRights]$entry[1],
            $inheritance,
            $propagation,
            $allow
        )
        [void]$security.AddAccessRule($rule)
    }
    $directory.SetAccessControl($security)
    $readback = $directory.GetAccessControl()
    if (-not $readback.AreAccessRulesProtected) {
        throw "Machine profile ACL inheritance removal was not proven."
    }
    $rules = @($readback.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    $expectedRights = @{
        'S-1-5-18' = [System.Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = [System.Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-545' = (
            [System.Security.AccessControl.FileSystemRights]::Read -bor
            [System.Security.AccessControl.FileSystemRights]::Synchronize
        )
    }
    if ($rules.Count -ne $expectedRights.Count) {
        throw "Machine profile ACL readback contains unexpected rules."
    }
    foreach ($expectedSid in $expectedRights.Keys) {
        $matches = @($rules | Where-Object {
            $_.IdentityReference.Value -ceq $expectedSid -and
            $_.AccessControlType -eq $allow -and
            $_.FileSystemRights -eq $expectedRights[$expectedSid] -and
            $_.InheritanceFlags -eq $inheritance -and
            $_.PropagationFlags -eq $propagation
        })
        if ($matches.Count -ne 1) {
            throw "Machine profile ACL readback differs for $expectedSid."
        }
    }
}

function Get-ContainerAuditHostSlug([string]$HostName) {
    $slug = ([string]$HostName).Trim().ToLowerInvariant() -replace '[^a-z0-9]+', '-'
    $slug = $slug.Trim('-')
    if ([string]::IsNullOrWhiteSpace($slug)) {
        return 'unknown'
    }
    return $slug
}

function Get-ContainerAuditNodeIdHex {
    $addresses = New-Object System.Collections.Generic.List[string]
    foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        $candidate = ([string]$adapter.GetPhysicalAddress()).Replace('-', '').ToLowerInvariant()
        if ($candidate -match '^[0-9a-f]{12}$' -and $candidate -ne '000000000000') {
            [void]$addresses.Add($candidate)
        }
    }
    if ($addresses.Count -gt 0) {
        return @($addresses | Sort-Object)[0]
    }
    $fallback = Get-CanonicalJsonSha256 ([ordered]@{ machine = [Environment]::MachineName })
    return $fallback.Substring(0, 12)
}

function Read-ContainerAuditIdentity([string]$Path) {
    $payload = Read-BoundedJson $Path "Container_Audit producer identity"
    if ([string]$payload.schema_version -cne 'container-audit-producer-identity-v1') {
        throw "Producer identity schema is invalid."
    }
    foreach ($field in @('producer_id', 'source_host_id', 'producer_install_id')) {
        $trimmed = ([string]$payload.$field).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            throw "Producer identity omitted $field."
        }
        $payload.$field = $trimmed
    }
    return $payload
}

function Test-ContainerAuditUnsafeEndpointAddress([System.Net.IPAddress]$Address) {
    if ([System.Net.IPAddress]::IsLoopback($Address)) { return $true }
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        [byte[]]$bytes = $Address.GetAddressBytes()
        if (
            $bytes[0] -eq 0 -or
            $bytes[0] -eq 10 -or
            $bytes[0] -eq 127 -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 0) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 198 -and ($bytes[1] -eq 18 -or $bytes[1] -eq 19)) -or
            ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
            ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113) -or
            $bytes[0] -ge 224
        ) {
            return $true
        }
        return $false
    }
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($Address.IsIPv4MappedToIPv6) {
            return Test-ContainerAuditUnsafeEndpointAddress $Address.MapToIPv4()
        }
        if ($Address.IsIPv6LinkLocal -or $Address.IsIPv6SiteLocal -or $Address.IsIPv6Multicast) {
            return $true
        }
        [byte[]]$bytes = $Address.GetAddressBytes()
        if (
            ($bytes[0] -band 0xfe) -eq 0xfc -or
            ($bytes[0] -band 0xe0) -ne 0x20 -or
            (
                $bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
                $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8
            )
        ) {
            return $true
        }
        return $false
    }
    return $true
}

function Assert-ContainerAuditPublicEndpoint([string]$EndpointUrl) {
    $endpoint = New-Object System.Uri -ArgumentList $EndpointUrl
    if (
        $endpoint.Scheme -cne 'https' -or
        [string]::IsNullOrWhiteSpace($endpoint.Host) -or
        -not [string]::IsNullOrWhiteSpace($endpoint.UserInfo) -or
        $endpoint.AbsolutePath -cne '/api/producer-ingest/v1/source-file' -or
        -not [string]::IsNullOrWhiteSpace($endpoint.Query) -or
        -not [string]::IsNullOrWhiteSpace($endpoint.Fragment)
    ) {
        throw "endpoint_url is invalid or does not use HTTPS."
    }
    $hostName = $endpoint.DnsSafeHost.TrimEnd('.').ToLowerInvariant()
    if ($hostName -ceq 'localhost' -or $hostName.EndsWith('.localhost')) {
        throw "endpoint_url must not target localhost"
    }
    $literalAddress = $null
    $addresses = @()
    if ([System.Net.IPAddress]::TryParse($hostName, [ref]$literalAddress)) {
        $addresses = @($literalAddress)
    }
    else {
        try {
            $addresses = @([System.Net.Dns]::GetHostAddresses($hostName))
        }
        catch [System.Net.Sockets.SocketException] {
            return
        }
    }
    foreach ($address in $addresses) {
        if (Test-ContainerAuditUnsafeEndpointAddress $address) {
            throw "endpoint_url must not target loopback, unspecified, private, link-local, multicast, or reserved addresses"
        }
    }
}

function Read-ContainerAuditQualificationContext([string]$Path, [string]$ExpectedEndpointUrl) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    $context = Read-BoundedJson $Path "Container_Audit isolated qualification context"
    Assert-ExactJsonFields $context @(
        'contract_version', 'activation_mode', 'authority_instance_id', 'created_at',
        'machine_name', 'operator_user_sid', 'operator_local_app_data_root', 'state_root',
        'server_base_url', 'endpoint_url', 'ca_bundle_path'
    ) "Isolated qualification context"
    if (
        [string]$context.contract_version -cne 'container-audit-isolated-qualification-client-v1' -or
        [string]$context.activation_mode -cne 'windows_sandbox_qualification' -or
        [string]$context.authority_instance_id -notmatch '^qualification-[0-9a-f]{32}$' -or
        [string]::IsNullOrWhiteSpace([string]$context.machine_name) -or
        -not ([string]$context.machine_name).Equals([Environment]::MachineName, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Isolated qualification context identity is invalid."
    }
    $stateRoot = [System.IO.Path]::GetFullPath([string]$context.state_root)
    $contextFull = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-SamePath $contextFull (Join-Path $stateRoot 'client-context.json'))) {
        throw "Isolated qualification context path is not canonical."
    }
    $caPath = [System.IO.Path]::GetFullPath([string]$context.ca_bundle_path)
    if (-not (Test-PathWithin $caPath $stateRoot) -or -not (Test-Path -LiteralPath $caPath -PathType Leaf)) {
        throw "Isolated qualification CA bundle is unavailable."
    }
    $caLength = (Get-Item -LiteralPath $caPath -Force).Length
    if ($caLength -le 0 -or $caLength -gt 131072) {
        throw "Isolated qualification CA bundle is invalid."
    }
    Assert-NoReparsePoint $contextFull "Container_Audit isolated qualification context"
    Assert-NoReparsePoint $caPath "Container_Audit isolated qualification CA bundle"
    $serverBase = New-Object System.Uri -ArgumentList ([string]$context.server_base_url)
    $endpoint = New-Object System.Uri -ArgumentList ([string]$context.endpoint_url)
    if (
        $serverBase.Scheme -cne 'https' -or
        $serverBase.Host -cne '127.0.0.1' -or
        $serverBase.Port -lt 1024 -or $serverBase.Port -gt 65535 -or
        $serverBase.AbsolutePath -cne '/' -or
        -not [string]::IsNullOrWhiteSpace($serverBase.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($serverBase.Query) -or
        -not [string]::IsNullOrWhiteSpace($serverBase.Fragment) -or
        $endpoint.Scheme -cne 'https' -or
        $endpoint.Host -cne '127.0.0.1' -or
        $endpoint.Port -ne $serverBase.Port -or
        $endpoint.AbsolutePath -cne '/api/producer-ingest/v1/source-file' -or
        [string]$context.endpoint_url -cne (([string]$context.server_base_url).TrimEnd('/') + '/api/producer-ingest/v1/source-file')
    ) {
        throw "Isolated qualification producer endpoint is invalid."
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedEndpointUrl)) {
        throw "Qualification enrollment requires a bound producer endpoint."
    }
    if ([string]$context.endpoint_url -cne $ExpectedEndpointUrl) {
        $boundEndpoint = New-Object System.Uri -ArgumentList $ExpectedEndpointUrl
        $boundHost = $boundEndpoint.Host.TrimEnd('.').ToLowerInvariant()
        if (
            @('http', 'https') -cnotcontains $boundEndpoint.Scheme -or
            $boundEndpoint.IsLoopback -or
            $boundHost -ceq 'localhost' -or
            $boundHost.EndsWith('.localhost') -or
            [string]::IsNullOrWhiteSpace($boundEndpoint.Host) -or
            -not [string]::IsNullOrWhiteSpace($boundEndpoint.UserInfo) -or
            $boundEndpoint.AbsolutePath -cne '/api/producer-ingest/v1/source-file' -or
            -not [string]::IsNullOrWhiteSpace($boundEndpoint.Query) -or
            -not [string]::IsNullOrWhiteSpace($boundEndpoint.Fragment)
        ) {
            throw "Qualification context does not authorize the requested submission endpoint."
        }
    }
    return $context
}

function Get-ContainerAuditRawEventNames([string]$AppRoot) {
    $catalogPath = Join-Path $AppRoot 'kmtech_factory_contracts\bundle\v1\catalogs\canonical-stream-catalog.json'
    $catalog = Read-BoundedJson $catalogPath "Container_Audit canonical stream catalog"
    $matches = @($catalog.streams | Where-Object {
        [string]$_.app_id -ceq 'container_audit' -and
        [string]$_.stream_id -ceq 'container_audit_events'
    })
    if ($matches.Count -ne 1) {
        throw "Canonical stream catalog omitted the Container_Audit event stream."
    }
    $names = @($matches[0].raw_event_names)
    if ($names.Count -eq 0 -or @($names | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        throw "Container_Audit canonical event names are invalid."
    }
    if (@($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw "Container_Audit canonical event names are not unique."
    }
    return ,$names
}

function New-ContainerAuditProducerManifest(
    [string]$HostName,
    [string]$SourceHostId,
    [string]$ProducerInstallId,
    [string]$EndpointUrl,
    [string]$SecretReference,
    [string]$DataRoot,
    [string]$DirectSyncRoot,
    [string[]]$RawEventNames
) {
    $pathText = {
        param([string]$Value)
        return ([System.IO.Path]::GetFullPath($Value)).Replace('\', '/')
    }
    $stream = [ordered]@{
        stream_name = 'container_audit_events'
        source_system = 'container_audit'
        source_transport = 'legacy_transfer_csv'
        raw_event_names = @($RawEventNames)
        quantity_basis = 'PRODUCT_BARCODE'
        barcode_policy = 'legacy_low_confidence_without_barcode'
        hmac_required = $false
        hash_chain_required = $false
        producer_role = 'container_audit'
        source_transport_or_dataset = 'legacy_transfer_csv'
        dispatch_key_fields = @('source_system', 'source_transport_or_dataset', 'raw_event_name')
        source_lineage_fields = @(
            'source_host_id', 'source_file_id', 'source_file_hash', 'source_row_number',
            'source_byte_offset', 'legacy_row_locator', 'row_hash'
        )
        source_file_id_policy = [ordered]@{
            format = '<source_host_id>/<producer_role>/<stream_name>/<relative_path_under_stream_root>'
            example = "$SourceHostId/container_audit/container_audit_events/sample.csv"
            legacy_sync_wrapper_format = '<source_host_id>:<parent_hash>:<filename>'
            legacy_sync_wrapper_status = 'not_canonical_for_batch1_onboarding'
        }
        temp_file_exclusion_policy = [ordered]@{
            excluded_suffixes = @('.tmp', '.partial', '.crdownload')
            excluded_prefixes = @('~', '.')
        }
        conflict_file_exclusion_policy = [ordered]@{
            excluded_name_contains = @('sync-conflict')
            excluded_dirs = @('.stfolder')
        }
        stability_window_policy = [ordered]@{
            minimum_stable_seconds = 30
            requires_size_and_mtime_unchanged = $true
        }
        replay_policy = [ordered]@{
            idempotency_key = @('source_system', 'event_identity')
            same_payload_hash = 'replay'
            same_legacy_row_locator_different_row_hash = 'append_only_correction_required'
            conflict_without_correction = 'quarantine'
        }
    }
    $endpoint = New-Object System.Uri -ArgumentList $EndpointUrl
    $origin = '{0}://{1}' -f $endpoint.Scheme, $endpoint.Authority
    return [ordered]@{
        schema_version = 'producer-onboarding-manifest-v1'
        pc_identity = [ordered]@{
            pc_id = $HostName
            source_host_id = $SourceHostId
            producer_install_id = $ProducerInstallId
        }
        apps = @('ContainerAudit')
        streams = @($stream)
        sync = [ordered]@{
            sync_transport = 'http_push'
            sync_dir = (& $pathText (Join-Path $DataRoot 'events'))
            server_ingest_target = $EndpointUrl
            auth = [ordered]@{
                method = 'producer_hmac_v1'
                secret_ref = $SecretReference
                secret_material_persisted = $false
            }
            queue = [ordered]@{
                queue_dir = (& $pathText (Join-Path $DirectSyncRoot 'relay_queue'))
                client_state_db = (& $pathText (Join-Path $DirectSyncRoot 'relay_state.sqlite3'))
                allowed_streams = @('container_audit_events')
                status = 'operator_supplied_uncontacted'
            }
            fallback = [ordered]@{
                sync_dir_preserved = $true
                syncthing_folder_id_required = $false
            }
            status = 'operator_supplied_uncontacted'
        }
        paths = [ordered]@{
            data_dir = (& $pathText $DirectSyncRoot)
            evidence_dir = (& $pathText (Join-Path $DirectSyncRoot 'evidence'))
            rollback_dir = (& $pathText (Join-Path $DirectSyncRoot 'rollback'))
        }
        server = [ordered]@{
            health_target = "$origin/health/ingest"
            contacted = $false
        }
        identity_registry = [ordered]@{
            required_for_pass = $true
            status = 'checked'
            source_host_id_unique = $true
        }
        hmac_gate = [ordered]@{
            required = $false
            registry_status = 'not_required'
            key_fingerprint = $null
            fixture_verifier_status = 'not_required'
            hash_chain_status = 'not_required'
            row_verifier_status = 'not_required'
            row_verifier_id = $null
            row_verifier_code_hash = $null
            row_verifier_receipt_hash = $null
            row_verifier_evidence_hash = $null
            decision = 'not_required'
        }
        plan_b_invariants = [ordered]@{
            product_barcode_priority = $true
            source_csv_immutable = $true
            append_only_correction_required = $true
            quarantine_projection_business_separated = $true
            no_erp_write = $true
            shipping_waiting_is_no_shipping_evidence = $true
        }
        rollback = [ordered]@{ sync_dir_preserve = $true }
    }
}

function Invoke-ContainerAuditEnrollmentRequest(
    [string]$EnrollmentUrl,
    $Payload,
    [string]$EnrollmentToken,
    [int]$TimeoutSeconds,
    [string]$ServerCertificatePath = '',
    [string]$CaBundlePath = '',
    [switch]$DisableProxy
) {
    $json = $Payload | ConvertTo-Json -Depth 100 -Compress
    $body = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $request = [System.Net.HttpWebRequest]::Create($EnrollmentUrl)
    $request.Method = 'POST'
    $request.ContentType = 'application/json; charset=utf-8'
    $request.Accept = 'application/json'
    $request.AllowAutoRedirect = $false
    $request.Timeout = [Math]::Max(1, $TimeoutSeconds) * 1000
    $request.ReadWriteTimeout = $request.Timeout
    $request.ContentLength = $body.Length
    if ($DisableProxy.IsPresent) {
        $request.Proxy = $null
    }
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        $request.Headers['X-Producer-Enrollment-Token'] = $EnrollmentToken
    }
    $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    if (-not [string]::IsNullOrWhiteSpace($ServerCertificatePath)) {
        if ([string]::IsNullOrWhiteSpace($CaBundlePath)) {
            throw "Qualification enrollment requires its bound CA certificate."
        }
        $expectedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $ServerCertificatePath
        $expectedAuthority = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CaBundlePath
        $expectedCertificateBytes = [Convert]::ToBase64String($expectedCertificate.RawData)
        $expectedAuthorityBytes = [Convert]::ToBase64String($expectedAuthority.RawData)
        $callback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            if ($null -eq $certificate) { return $false }
            if (
                ($sslPolicyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0 -or
                ($sslPolicyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) -ne 0
            ) {
                return $false
            }
            $presented = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate
            if ([Convert]::ToBase64String($presented.RawData) -cne $expectedCertificateBytes) {
                return $false
            }
            $now = [DateTime]::UtcNow
            if (
                $now -lt $presented.NotBefore.ToUniversalTime() -or
                $now -gt $presented.NotAfter.ToUniversalTime() -or
                $now -lt $expectedAuthority.NotBefore.ToUniversalTime() -or
                $now -gt $expectedAuthority.NotAfter.ToUniversalTime()
            ) {
                return $false
            }
            $qualificationChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            try {
                $qualificationChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $qualificationChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
                [void]$qualificationChain.ChainPolicy.ExtraStore.Add($expectedAuthority)
                if (-not $qualificationChain.Build($presented)) {
                    $unexpectedStatus = @($qualificationChain.ChainStatus | Where-Object {
                        $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot -and
                        $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
                    })
                    if ($unexpectedStatus.Count -gt 0) { return $false }
                }
                $elements = @($qualificationChain.ChainElements)
                if ($elements.Count -lt 2) { return $false }
                $rootBytes = [Convert]::ToBase64String($elements[$elements.Count - 1].Certificate.RawData)
                return $rootBytes -ceq $expectedAuthorityBytes
            }
            finally {
                $qualificationChain.Dispose()
            }
        }.GetNewClosure()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $callback
    }
    $response = $null
    try {
        $requestStream = $request.GetRequestStream()
        try {
            $requestStream.Write($body, 0, $body.Length)
        }
        finally {
            $requestStream.Dispose()
        }
        try {
            $response = [System.Net.HttpWebResponse]$request.GetResponse()
        }
        catch [System.Net.WebException] {
            if ($null -eq $_.Exception.Response) { throw }
            $response = [System.Net.HttpWebResponse]$_.Exception.Response
        }
        $reader = New-Object System.IO.StreamReader -ArgumentList @(
            $response.GetResponseStream(),
            (New-Object System.Text.UTF8Encoding($false, $true))
        )
        try {
            $responseText = $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
        if ($responseText.Length -le 0 -or (New-Object System.Text.UTF8Encoding($false)).GetByteCount($responseText) -gt 1048576) {
            throw "Self-enrollment response size is invalid."
        }
        Assert-JsonHasNoDuplicateObjectKeys $responseText "Self-enrollment response"
        return [ordered]@{
            status_code = [int]$response.StatusCode
            payload = ($responseText | ConvertFrom-Json)
        }
    }
    finally {
        if ($null -ne $response) { $response.Dispose() }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
    }
}

function Get-ContainerAuditSafeProfileText($Value, [string]$FieldName) {
    $text = ([string]$Value).Trim()
    if (
        [string]::IsNullOrWhiteSpace($text) -or
        $text.Length -gt 200 -or
        @($text.ToCharArray() | Where-Object { [int]$_ -lt 32 }).Count -gt 0
    ) {
        throw "Machine logistics $FieldName is required."
    }
    return $text
}

function Install-ContainerAuditMachineProfile(
    $ResponsePayload,
    [string]$ExpectedProducerSecret,
    [string]$ExpectedSourceHostId,
    [string]$ExpectedDeviceId,
    [string]$ProfilePath,
    $QualificationContext = $null
) {
    $bundle = $ResponsePayload.machine_credential_bundle
    if ($null -eq $bundle) { return $null }
    Assert-ExactJsonFields $bundle @('contract_version', 'bindings', 'credentials', 'profiles') "Machine credential bundle"
    if ([string]$bundle.contract_version -cne 'producer-self-enrollment-machine-credentials-v1') {
        throw "Machine credential bundle contract is invalid."
    }
    Assert-ExactJsonFields $bundle.bindings @('app', 'program', 'source_host_id', 'device_id', 'authority_scope_id') "Machine credential bindings"
    Assert-ExactJsonFields $bundle.credentials @('producer_ingest', 'logistics') "Machine credential sections"
    Assert-ExactJsonFields $bundle.profiles @('logistics') "Machine profile sections"
    Assert-ExactJsonFields $bundle.credentials.producer_ingest @('audience', 'auth_scheme', 'key_id', 'secret') "Producer ingest credential"
    Assert-ExactJsonFields $bundle.credentials.logistics @('audience', 'auth_scheme', 'token_header', 'token') "Logistics credential"
    Assert-ExactJsonFields $bundle.profiles.logistics @(
        'contract_version', 'base_url', 'authority_scope', 'authority_epoch',
        'authority_plane', 'ledger_plane', 'plane_epoch', 'device_id',
        'source_host_id', 'timeout_seconds'
    ) "Machine logistics profile"
    $bindings = $bundle.bindings
    if (
        [string]$bindings.app -cne 'ContainerAudit' -or
        [string]$bindings.program -cne 'Container_Audit' -or
        [string]$bindings.source_host_id -cne $ExpectedSourceHostId -or
        [string]$bindings.device_id -cne $ExpectedDeviceId -or
        [string]::IsNullOrWhiteSpace([string]$bindings.authority_scope_id)
    ) {
        throw "Machine credential bundle binding mismatch."
    }
    $producerCredential = $bundle.credentials.producer_ingest
    $logisticsCredential = $bundle.credentials.logistics
    $producerSecret = $ExpectedProducerSecret
    if (
        [string]$producerCredential.audience -cne 'producer-ingest-hmac-v1' -or
        [string]$producerCredential.auth_scheme -cne 'hmac-sha256' -or
        [string]$producerCredential.key_id -cne [string]$ResponsePayload.key_id -or
        [string]$producerCredential.secret -cne $producerSecret -or
        [string]::IsNullOrWhiteSpace($producerSecret)
    ) {
        throw "Machine producer ingest credential contract is invalid."
    }
    $bearerToken = [string]$logisticsCredential.token
    if (
        [string]$logisticsCredential.audience -cne 'worker-analysis-logistics-v1' -or
        [string]$logisticsCredential.auth_scheme -cne 'bearer' -or
        [string]$logisticsCredential.token_header -cne 'X-Logistics-API-Token' -or
        [string]::IsNullOrWhiteSpace($bearerToken) -or
        $bearerToken -ceq $producerSecret -or
        $bearerToken.Length -gt 16384 -or
        @($bearerToken.ToCharArray() | Where-Object { [char]::IsWhiteSpace($_) }).Count -gt 0
    ) {
        throw "Machine logistics credential contract is invalid."
    }
    $profile = $bundle.profiles.logistics
    $authorityScope = Get-ContainerAuditSafeProfileText $profile.authority_scope 'authority_scope'
    $profileDeviceId = Get-ContainerAuditSafeProfileText $profile.device_id 'device_id'
    $profileSourceHostId = Get-ContainerAuditSafeProfileText $profile.source_host_id 'source_host_id'
    if (
        [string]$profile.contract_version -cne 'km-logistics-runtime-profile-v1' -or
        $profileSourceHostId -cne $ExpectedSourceHostId -or
        $profileDeviceId -cne $ExpectedDeviceId -or
        [string]$profile.authority_scope -cne [string]$bindings.authority_scope_id -or
        [string]$profile.authority_plane -cne 'AUTHORITATIVE' -or
        @('AUTHORITATIVE', 'SHADOW_CANDIDATE') -cnotcontains ([string]$profile.ledger_plane).ToUpperInvariant() -or
        $profile.authority_epoch -is [bool] -or [int64]$profile.authority_epoch -lt 1 -or
        $profile.plane_epoch -is [bool] -or [int64]$profile.plane_epoch -lt 1
    ) {
        throw "Machine logistics profile identity or plane is invalid."
    }
    $timeout = [double]$profile.timeout_seconds
    if ([double]::IsNaN($timeout) -or [double]::IsInfinity($timeout) -or $timeout -lt 0.1 -or $timeout -gt 60.0) {
        throw "Machine logistics profile timeout is invalid."
    }
    $baseUrl = (Get-ContainerAuditSafeProfileText $profile.base_url 'base_url').TrimEnd('/')
    if ($baseUrl.Contains('\') -or @($baseUrl.ToCharArray() | Where-Object { [char]::IsWhiteSpace($_) }).Count -gt 0) {
        throw "Machine logistics base_url contains unsafe characters."
    }
    $baseUri = New-Object System.Uri -ArgumentList $baseUrl
    if (
        $baseUri.Scheme -cne 'https' -or
        [string]::IsNullOrWhiteSpace($baseUri.Host) -or
        -not [string]::IsNullOrWhiteSpace($baseUri.UserInfo) -or
        $baseUri.AbsolutePath -cne '/' -or
        -not [string]::IsNullOrWhiteSpace($baseUri.Query) -or
        -not [string]::IsNullOrWhiteSpace($baseUri.Fragment)
    ) {
        throw "Machine logistics base_url is invalid."
    }
    $isolated = $baseUri.IsLoopback
    if ($isolated -and ($null -eq $QualificationContext -or [string]$QualificationContext.server_base_url -cne $baseUrl)) {
        throw "Machine logistics loopback origin lacks the bound qualification context."
    }
    $values = [ordered]@{
        contract_version = 'km-logistics-runtime-profile-v1'
        base_url = $baseUrl
        authority_scope = $authorityScope
        authority_epoch = [int64]$profile.authority_epoch
        authority_plane = 'AUTHORITATIVE'
        ledger_plane = ([string]$profile.ledger_plane).ToUpperInvariant()
        plane_epoch = [int64]$profile.plane_epoch
        device_id = $profileDeviceId
        source_host_id = $profileSourceHostId
        bearer_token_ref = 'dpapi:secrets/bearer-token.dpapi'
        timeout_seconds = $timeout
    }
    $target = [System.IO.Path]::GetFullPath($ProfilePath)
    Assert-NoReparsePoint $target "Container_Audit machine logistics profile"
    $parent = Split-Path -Parent $target
    $secretPath = Join-Path $parent 'secrets\bearer-token.dpapi'
    Assert-NoReparsePoint $secretPath "Container_Audit machine logistics credential"
    $summary = [ordered]@{
        contract_version = 'km-logistics-runtime-profile-v1'
        base_url = $baseUrl
        authority_scope = $authorityScope
        authority_epoch = [int64]$profile.authority_epoch
        authority_plane = 'AUTHORITATIVE'
        ledger_plane = ([string]$profile.ledger_plane).ToUpperInvariant()
        plane_epoch = [int64]$profile.plane_epoch
        device_id = $profileDeviceId
        source_host_id = $profileSourceHostId
        timeout_seconds = $timeout
        profile_path = $target
        bearer_token_present = $true
        required = $true
        isolated_qualification = $isolated
        isolated_qualification_authority_id = $(if ($isolated) { [string]$QualificationContext.authority_instance_id } else { '' })
        tls_private_ca_configured = $isolated
    }
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        $existing = Read-BoundedJson $target "Existing Container_Audit machine logistics profile"
        Assert-ExactJsonFields $existing @(
            'contract_version', 'base_url', 'authority_scope', 'authority_epoch',
            'authority_plane', 'ledger_plane', 'plane_epoch', 'device_id',
            'source_host_id', 'bearer_token_ref', 'timeout_seconds'
        ) "Existing machine logistics profile"
        if ((Get-CanonicalJsonSha256 $existing) -cne (Get-CanonicalJsonSha256 $values)) {
            throw "Existing machine logistics profile conflicts with enrollment."
        }
        if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
            throw "Existing machine logistics credential is unavailable."
        }
        $secretLength = (Get-Item -LiteralPath $secretPath -Force).Length
        if ($secretLength -le 0 -or $secretLength -gt 65536) {
            throw "Existing machine logistics credential size is invalid."
        }
        $entropy = (New-Object System.Text.UTF8Encoding($false)).GetBytes('KMTech Logistics Runtime Profile v1')
        if (-not (Test-MachineSecret ([System.IO.File]::ReadAllBytes($secretPath)) $bearerToken $entropy)) {
            throw "Existing machine logistics credential conflicts with enrollment."
        }
        Set-ContainerAuditMachineProfileAcl $parent
        $summary.status = 'reused'
        $summary.created_paths = @()
        return $summary
    }
    if (Test-Path -LiteralPath $secretPath) {
        throw "Orphan machine logistics credential already exists."
    }
    Set-ContainerAuditMachineProfileAcl $parent
    Assert-NoReparsePoint $secretPath "Container_Audit machine logistics credential"
    $entropy = (New-Object System.Text.UTF8Encoding($false)).GetBytes('KMTech Logistics Runtime Profile v1')
    $protected = Protect-MachineSecret $bearerToken $entropy
    $created = New-Object System.Collections.Generic.List[string]
    try {
        Write-AtomicFileBytes $secretPath $protected
        [void]$created.Add($secretPath)
        Write-AtomicUtf8JsonFile $target $values
        [void]$created.Add($target)
        $readback = Read-BoundedJson $target "Installed Container_Audit machine logistics profile"
        if ((Get-CanonicalJsonSha256 $readback) -cne (Get-CanonicalJsonSha256 $values)) {
            throw "Machine logistics profile exact readback failed."
        }
        if (-not (Test-MachineSecret ([System.IO.File]::ReadAllBytes($secretPath)) $bearerToken $entropy)) {
            throw "Machine logistics credential readback failed."
        }
    }
    catch {
        foreach ($createdPath in @($created.ToArray() | Sort-Object -Descending)) {
            Remove-Item -LiteralPath $createdPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    $summary.status = 'installed'
    $summary.created_paths = @($target, $secretPath)
    return $summary
}

function Invoke-ContainerAuditWorkerPcRegistration(
    [string]$AppRoot,
    [string]$DataRoot,
    [string]$DirectSyncRoot,
    [string]$EndpointUrl,
    [string]$EnrollmentTokenEnv,
    [string]$ManifestPath,
    [string]$CredentialPath,
    [string]$ReportPath,
    [string]$MachineProfilePath,
    [string]$QualificationContextPath = '',
    [string]$ProducerIdentityPath = '',
    [string]$ProducerInstallId = '',
    [string]$ProducerId = '',
    [string]$SourceHostId = ''
) {
    $blockedReport = [ordered]@{
        report_version = 'container-audit-worker-pc-registration-v1'
        status = 'BLOCKED'
        blocked_reason = ''
        raw_secret_written = $false
        installer_process_id = $PID
        execution_mode = 'in_process_native_powershell'
    }
    $report = $null
    try {
        $explicitIdentityPath = ([string]$ProducerIdentityPath).Trim()
        $registrationPaths = @($DataRoot, $DirectSyncRoot, $ManifestPath, $CredentialPath, $ReportPath, $MachineProfilePath)
        if (-not [string]::IsNullOrWhiteSpace($explicitIdentityPath)) {
            $registrationPaths += $explicitIdentityPath
        }
        foreach ($pathItem in $registrationPaths) {
            $full = [System.IO.Path]::GetFullPath($pathItem)
            if ((Test-SamePath $full 'C:\Sync') -or (Test-PathWithin $full 'C:\Sync')) {
                throw "Registration paths must not point at the legacy Syncthing folder."
            }
        }
        foreach ($directory in @(
            $DataRoot,
            (Join-Path $DataRoot 'events'),
            $DirectSyncRoot,
            (Join-Path $DirectSyncRoot 'queue'),
            (Join-Path $DirectSyncRoot 'spool'),
            (Join-Path $DirectSyncRoot 'status'),
            (Join-Path $DirectSyncRoot 'logs')
        )) {
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
                New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
            }
        }
        $endpoint = New-Object System.Uri -ArgumentList $EndpointUrl
        if (
            @('http', 'https') -cnotcontains $endpoint.Scheme -or
            [string]::IsNullOrWhiteSpace($endpoint.Host) -or
            -not [string]::IsNullOrWhiteSpace($endpoint.UserInfo) -or
            $endpoint.AbsolutePath -cne '/api/producer-ingest/v1/source-file' -or
            -not [string]::IsNullOrWhiteSpace($endpoint.Query) -or
            -not [string]::IsNullOrWhiteSpace($endpoint.Fragment)
        ) {
            throw "Registration endpoint is invalid."
        }
        $qualificationContext = Read-ContainerAuditQualificationContext $QualificationContextPath $EndpointUrl
        if ($endpoint.Scheme -cne 'https' -and $null -eq $qualificationContext) {
            throw "Registration endpoint must use HTTPS outside isolated qualification."
        }
        if ($null -eq $qualificationContext) {
            Assert-ContainerAuditPublicEndpoint $EndpointUrl
        }

        $hostName = [Environment]::MachineName
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            throw "Container_Audit host identity is unavailable."
        }
        $hostSlug = Get-ContainerAuditHostSlug $hostName
        $cliSourceHostId = ([string]$SourceHostId).Trim()
        $cliProducerInstallId = ([string]$ProducerInstallId).Trim()
        $cliProducerId = ([string]$ProducerId).Trim()
        $defaultIdentityPath = Join-Path (Split-Path -Parent ([System.IO.Path]::GetFullPath($ManifestPath))) 'producer_identity.json'
        $loadedIdentity = $null
        $loadedFrom = ''
        if (-not [string]::IsNullOrWhiteSpace($explicitIdentityPath)) {
            $loadedIdentity = Read-ContainerAuditIdentity $explicitIdentityPath
            $loadedFrom = [System.IO.Path]::GetFullPath($explicitIdentityPath)
        }
        elseif (Test-Path -LiteralPath $defaultIdentityPath -PathType Leaf) {
            $loadedIdentity = Read-ContainerAuditIdentity $defaultIdentityPath
            $loadedFrom = [System.IO.Path]::GetFullPath($defaultIdentityPath)
        }
        $resolvedSourceHostId = if (-not [string]::IsNullOrWhiteSpace($cliSourceHostId)) {
            $cliSourceHostId
        }
        elseif ($null -ne $loadedIdentity) {
            [string]$loadedIdentity.source_host_id
        }
        else {
            "container-audit-$hostSlug"
        }
        $resolvedInstallId = if (-not [string]::IsNullOrWhiteSpace($cliProducerInstallId)) {
            $cliProducerInstallId
        }
        elseif ($null -ne $loadedIdentity) {
            [string]$loadedIdentity.producer_install_id
        }
        else {
            'container-audit-{0}-{1}' -f $hostSlug, (Get-ContainerAuditNodeIdHex)
        }
        $resolvedProducerId = if (-not [string]::IsNullOrWhiteSpace($cliProducerId)) {
            $cliProducerId
        }
        elseif ($null -ne $loadedIdentity) {
            [string]$loadedIdentity.producer_id
        }
        else {
            $resolvedSourceHostId
        }
        $identitySource = if (
            -not [string]::IsNullOrWhiteSpace($cliSourceHostId) -or
            -not [string]::IsNullOrWhiteSpace($cliProducerInstallId) -or
            -not [string]::IsNullOrWhiteSpace($cliProducerId)
        ) { 'cli' } elseif ($null -ne $loadedIdentity) { 'identity_file' } else { 'generated' }
        $secretTarget = Get-SafeSecretReferenceName "KMTech.DirectSync.ContainerAudit.$hostSlug"
        $secretReference = "dpapi:$secretTarget"
        $rawEventNames = Get-ContainerAuditRawEventNames $AppRoot
        $manifest = New-ContainerAuditProducerManifest `
            $hostName `
            $resolvedSourceHostId `
            $resolvedInstallId `
            $EndpointUrl `
            $secretReference `
            $DataRoot `
            $DirectSyncRoot `
            $rawEventNames
        $expectedManifestHash = Get-CanonicalJsonSha256 $manifest
        $capturedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture)
        $credential = [ordered]@{
            credential_schema_version = 'producer-ingest-credential-reference-v1'
            created_at = $capturedAt
            producer_id = $resolvedProducerId
            key_id = "pending-server-key-$hostSlug"
            secret_ref = $secretReference
            endpoint_url = $EndpointUrl
            secret_data_dir = [System.IO.Path]::GetFullPath($DirectSyncRoot)
        }
        if ($null -ne $qualificationContext) {
            $credential.isolated_qualification_context_path = [System.IO.Path]::GetFullPath($QualificationContextPath)
        }
        $report = [ordered]@{
            report_version = 'container-audit-worker-pc-registration-v1'
            status = 'LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET'
            captured_at = $capturedAt
            hostname = $hostName
            source_host_id = $resolvedSourceHostId
            producer_install_id = $resolvedInstallId
            producer_id = $resolvedProducerId
            key_id = $credential.key_id
            endpoint_url = $EndpointUrl
            secret_ref_scheme = 'dpapi'
            secret_ref_target = $secretTarget
            raw_secret_written = $false
            server_registration_verified = $false
            secret_bootstrap_verified = $false
            self_enrollment_requested = $true
            isolated_qualification_mode = ($null -ne $qualificationContext)
            isolated_qualification_authority_id = $(if ($null -ne $qualificationContext) { [string]$qualificationContext.authority_instance_id } else { '' })
            producer_identity_source = $identitySource
            producer_identity_loaded_from = $loadedFrom
            producer_identity_path = [System.IO.Path]::GetFullPath($defaultIdentityPath)
            local_storage = [ordered]@{
                data_root = [System.IO.Path]::GetFullPath($DataRoot)
                events_dir = [System.IO.Path]::GetFullPath((Join-Path $DataRoot 'events'))
                direct_sync_root = [System.IO.Path]::GetFullPath($DirectSyncRoot)
                syncthing_dependency = $false
            }
            next_required_external_step = 'Run self-enrollment during install, or issue/register the producer key on the server and provision the matching secret into the referenced Windows credential target.'
            installer_process_id = $PID
            execution_mode = 'in_process_native_powershell'
        }

        $origin = '{0}://{1}' -f $endpoint.Scheme, $endpoint.Authority
        $enrollmentUrl = "$origin/api/producer-ingest/v1/enroll"
        $token = [Environment]::GetEnvironmentVariable($EnrollmentTokenEnv, 'Process')
        $requestPayload = [ordered]@{
            contract_version = 'producer-self-enrollment-v1'
            producer_id = $credential.producer_id
            key_id = $credential.key_id
            endpoint_url = $credential.endpoint_url
            manifest = $manifest
        }
        $serverCertificatePath = ''
        $caBundlePath = ''
        if ($null -ne $qualificationContext -and [string]$qualificationContext.endpoint_url -ceq $EndpointUrl) {
            $serverCertificatePath = Join-Path ([string]$qualificationContext.state_root) 'qualification-server.pem'
            $caBundlePath = [string]$qualificationContext.ca_bundle_path
            if (-not (Test-Path -LiteralPath $serverCertificatePath -PathType Leaf)) {
                throw "Qualification server certificate is unavailable."
            }
        }
        $enrollment = Invoke-ContainerAuditEnrollmentRequest `
            $enrollmentUrl `
            $requestPayload `
            $token `
            30 `
            $serverCertificatePath `
            $caBundlePath `
            -DisableProxy:($null -ne $qualificationContext)
        $response = $enrollment.payload
        if ([int]$enrollment.status_code -ge 400) {
            $errorCode = [string]$response.error.code
            if ([string]::IsNullOrWhiteSpace($errorCode)) { $errorCode = [string]$enrollment.status_code }
            throw "Self-enrollment failed: $errorCode"
        }
        $authorizedHashes = @($response.active_manifest_hashes | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
        if ($authorizedHashes -cnotcontains $expectedManifestHash) {
            throw "Self-enrollment response does not authorize the requested manifest hash."
        }
        $secret = [string]$response.secret
        if ([string]::IsNullOrWhiteSpace($secret)) {
            $secretHex = ([string]$response.secret_hex).Trim()
            if ($secretHex -notmatch '^(?:[0-9A-Fa-f]{2})+$') {
                throw "Self-enrollment response missing valid secret."
            }
            $secretBytes = New-Object byte[] ($secretHex.Length / 2)
            for ($index = 0; $index -lt $secretBytes.Length; $index += 1) {
                $secretBytes[$index] = [Convert]::ToByte($secretHex.Substring($index * 2, 2), 16)
            }
            $secret = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($secretBytes)
        }
        if ([string]::IsNullOrWhiteSpace($secret)) {
            throw "Self-enrollment response missing valid secret."
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$response.producer_id)) {
            $credential.producer_id = [string]$response.producer_id
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$response.key_id)) {
            $credential.key_id = [string]$response.key_id
        }
        $machineProfile = Install-ContainerAuditMachineProfile `
            $response `
            $secret `
            $resolvedSourceHostId `
            $hostName `
            $MachineProfilePath `
            $qualificationContext
        if ($null -eq $machineProfile) {
            throw "Self-enrollment response missing machine credential bundle."
        }
        $report.machine_profiles = [ordered]@{ logistics = $machineProfile }
        $report.machine_profile_mode = 'enrollment_bundle'
        $secretPath = Join-Path $DirectSyncRoot ("secrets\{0}.dpapi" -f $secretTarget)
        try {
            $protectedSecret = Protect-MachineSecret $secret
            Write-AtomicFileBytes $secretPath $protectedSecret
            if (-not (Test-MachineSecret ([System.IO.File]::ReadAllBytes($secretPath)) $secret)) {
                throw "Producer credential DPAPI readback failed."
            }
        }
        catch {
            foreach ($createdPath in @($machineProfile.created_paths)) {
                Remove-Item -LiteralPath ([string]$createdPath) -Force -ErrorAction SilentlyContinue
            }
            throw
        }
        $identityPayload = [ordered]@{
            schema_version = 'container-audit-producer-identity-v1'
            producer_id = [string]$credential.producer_id
            source_host_id = $resolvedSourceHostId
            producer_install_id = $resolvedInstallId
        }
        Write-AtomicUtf8JsonFile $defaultIdentityPath $identityPayload
        $report.producer_identity_path = [System.IO.Path]::GetFullPath($defaultIdentityPath)
        $report.producer_identity_persisted = $true
        $report.producer_id = [string]$credential.producer_id
        $report.key_id = [string]$credential.key_id
        $report.server_registration_verified = $true
        $report.manifest_hash_verified = $true
        $report.manifest_hash = $expectedManifestHash
        $report.secret_bootstrap_verified = $true
        $report.enrollment_url = $enrollmentUrl
        $report.enrollment_status = $response.status
        $report.enrollment_authorization_mode = $(if ([string]::IsNullOrEmpty($token)) { 'server_ip_allowlist' } else { 'token' })
        $report.secret_fingerprint_sha256 = $response.secret_fingerprint_sha256
        $report.server_binding = $(if ($null -eq $response.server_binding) { [ordered]@{} } else { $response.server_binding })
        $report.secret_bootstrap = [ordered]@{
            secret_ref_scheme = 'dpapi'
            secret_data_dir = [System.IO.Path]::GetFullPath($DirectSyncRoot)
            secret_artifact_path = [System.IO.Path]::GetFullPath($secretPath)
        }
        $report.status = 'SELF_ENROLLMENT_REGISTERED'
        $report.next_required_external_step = 'Run direct-sync relay and verify upload receipt.'
        $report.producer_manifest_path = [System.IO.Path]::GetFullPath($ManifestPath)
        $report.credential_path = [System.IO.Path]::GetFullPath($CredentialPath)
        $report.report_path = [System.IO.Path]::GetFullPath($ReportPath)

        Write-AtomicUtf8JsonFile $ManifestPath $manifest
        Write-AtomicUtf8JsonFile $CredentialPath $credential
        $persistedManifest = Read-BoundedJson $ManifestPath "Persisted Container_Audit producer manifest"
        $persistedHash = Get-CanonicalJsonSha256 $persistedManifest
        if ($persistedHash -cne $expectedManifestHash) {
            $report.status = 'BLOCKED'
            $report.blocked_reason = 'persisted manifest hash differs from the server-authorized manifest hash'
            $report.persisted_manifest_hash_verified = $false
            Write-AtomicUtf8JsonFile $ReportPath $report
            throw "Persisted producer manifest hash verification failed."
        }
        $report.persisted_manifest_hash_verified = $true
        Write-AtomicUtf8JsonFile $ReportPath $report
        return $report
    }
    catch {
        $failureMessage = $_.Exception.Message
        $failureReport = $blockedReport
        if ($null -ne $report) {
            $report.status = 'BLOCKED'
            if ($null -eq $report.PSObject.Properties['blocked_reason']) {
                $report.blocked_reason = $failureMessage
            }
            elseif ([string]::IsNullOrWhiteSpace([string]$report.blocked_reason)) {
                $report.blocked_reason = $failureMessage
            }
            $failureReport = $report
        }
        elseif ($blockedReport.blocked_reason.Length -eq 0) {
            $blockedReport.blocked_reason = $failureMessage
        }
        try {
            Write-AtomicUtf8JsonFile $ReportPath $failureReport
        }
        catch {
        }
        throw
    }
}

function Assert-ContainerAuditManifestHash([string]$ManifestPath, [string]$ExpectedHash) {
    $manifest = Read-BoundedJson $ManifestPath "Existing Container_Audit producer manifest"
    $actualHash = Get-CanonicalJsonSha256 $manifest
    if ($actualHash -cne ([string]$ExpectedHash).Trim().ToLowerInvariant()) {
        throw "Existing producer manifest differs from its verified registration report."
    }
    return $actualHash
}

function ConvertTo-ContainerAuditCommandLine([string[]]$Arguments) {
    return (@($Arguments | ForEach-Object { ConvertTo-ElevationArgument ([string]$_) }) -join ' ')
}

function Get-ContainerAuditTaskTransportEnvironment {
    $names = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($environmentName in @('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE')) {
        $value = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
        if ([string]::IsNullOrEmpty($value)) {
            continue
        }
        if (
            $value.IndexOf([char]0) -ge 0 -or
            $value.Contains("`r") -or
            $value.Contains("`n") -or
            $value.Contains('"') -or
            $value.Contains('%')
        ) {
            throw "$environmentName contains characters unsafe for the scheduled-task wrapper."
        }
        $fullPath = Get-StrictFullPath $value "$environmentName certificate bundle"
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "$environmentName certificate bundle does not exist."
        }
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        if ($item.Length -le 0 -or $item.Length -gt 1048576) {
            throw "$environmentName certificate bundle size is invalid."
        }
        Assert-NoReparsePoint $fullPath "$environmentName certificate bundle"
        [void]$names.Add($environmentName)
        [void]$lines.Add(('set "{0}={1}"' -f $environmentName, $fullPath))
    }
    return [ordered]@{
        names = $names.ToArray()
        lines = $lines.ToArray()
    }
}

function Install-ContainerAuditDirectSyncTask(
    [string]$AppRoot,
    [string]$ProgramDataRoot,
    [string]$ProducerManifestPath,
    [string]$CredentialPath,
    [string]$ScanSourceDir,
    [string]$SourceGlob,
    [string]$TaskName,
    [string]$ReportPath,
    $FieldLayoutContract
) {
    $report = [ordered]@{
        report_version = 'container-audit-direct-sync-install-pack-v1'
        status = 'BLOCKED'
        apply = $true
        uninstall = $false
        task_name = $TaskName
        field_layout_contract = $FieldLayoutContract
        task_name_validation = [ordered]@{
            status = 'NOT_TESTED'
            task_name_valid = $false
            max_length = 128
            allowed_pattern = '^[A-Za-z0-9_.-]+$'
        }
        explicit_path_boundary = [ordered]@{ status = 'NOT_TESTED'; blocked_reason = ''; unsafe_paths = @() }
        container_audit_storage = [ordered]@{}
        program_data_root = ''
        runtime_paths = [ordered]@{}
        runtime_path_boundary = [ordered]@{ status = 'NOT_TESTED'; all_runtime_paths_under_program_data_root = $false }
        task_runtime_acl = [ordered]@{
            status = 'PASS'; blocked_reason = ''; enabled = $false; principal = ''; rights = 'M'; inheritance = '(OI)(CI)'; paths = @()
            apply_result = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'task_run_user_not_configured'; created_paths = @(); command_results = @() }
        }
        bundled_relay_executable = [ordered]@{ status = 'NOT_TESTED'; blocked_reason = ''; path = ''; exists = $false }
        use_bundled_relay_executable = $true
        python_exe_explicit = $false
        app_root_dependencies = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'bundled relay executable supplies scheduled-task runtime' }
        python_executable = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'bundled relay executable selected' }
        python_runtime_imports = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'bundled relay executable selected' }
        producer_manifest = [ordered]@{ status = 'NOT_TESTED'; path = '' }
        credential = [ordered]@{ status = 'NOT_TESTED'; path = ''; isolated_qualification = $false }
        source_scan = [ordered]@{}
        source_scan_validation = [ordered]@{ status = 'NOT_TESTED'; enabled = $true }
        backpressure = [ordered]@{ max_active_queue_count = 1000; max_active_queue_age_seconds = 86400 }
        backpressure_validation = [ordered]@{ status = 'PASS'; limits_valid = $true }
        runner_script = ''
        runner_command = @()
        scheduled_task_wrapper_path = ''
        scheduled_task_wrapper_command = ''
        scheduled_task_launcher_path = ''
        scheduled_task_launcher_command = ''
        scheduled_task_uses_hidden_launcher = $true
        scheduled_task_launcher_uses_absolute_system32_cmd = $true
        scheduled_task_launcher_status_path = ''
        local_test_task_environment_names = @()
        local_test_task_environment_persisted = $false
        task_principal = [ordered]@{
            status = 'PASS'
            mode = 'system_service_account'
            run_user = 'SYSTEM'
            password_source = ''
            password_supplied = $false
            password_in_report = $false
            blocked_reason = ''
        }
        scheduled_task_create_command = @()
        scheduled_task_delete_command = @('Unregister-ScheduledTask', '-TaskName', $TaskName, '-Confirm:$false')
        secret_redaction = [ordered]@{
            credential_path_only = $true
            raw_secret_in_report = $false
        }
        production_apply_guard = [ordered]@{
            requires_apply = $true
            requires_confirm_production_install = $true
            confirm_production_install = $true
            requires_canonical_field_layout = $true
            canonical_field_layout = $(if ($null -eq $FieldLayoutContract) { $false } else { [bool]$FieldLayoutContract.production_layout_matches })
            allow_noncanonical_layout_for_test = $(if ($null -eq $FieldLayoutContract) { $false } else { [bool]$FieldLayoutContract.local_test_override_enabled })
        }
        installer_process_id = $PID
        execution_mode = 'in_process_native_powershell'
        blocked_reason = ''
    }
    try {
        if ([string]::IsNullOrWhiteSpace($TaskName) -or $TaskName.Length -gt 128 -or $TaskName -notmatch '^[A-Za-z0-9_.-]+$') {
            throw "task_name must be 1-128 characters and contain only letters, digits, underscore, dash, or dot"
        }
        $report.task_name_validation.status = 'PASS'
        $report.task_name_validation.task_name_valid = $true
        if (
            $null -eq $FieldLayoutContract -or
            (
                -not [bool]$FieldLayoutContract.production_layout_matches -and
                -not [bool]$FieldLayoutContract.local_test_override_enabled
            )
        ) {
            throw "production apply requires the canonical Container_Audit field layout"
        }
        $appRootFull = [System.IO.Path]::GetFullPath($AppRoot)
        $programDataRootFull = [System.IO.Path]::GetFullPath($ProgramDataRoot)
        $manifestFull = [System.IO.Path]::GetFullPath($ProducerManifestPath)
        $credentialFull = [System.IO.Path]::GetFullPath($CredentialPath)
        $scanSourceFull = [System.IO.Path]::GetFullPath($ScanSourceDir)
        $report.program_data_root = $programDataRootFull
        foreach ($pathItem in @($programDataRootFull, $manifestFull, $credentialFull, $scanSourceFull, $ReportPath)) {
            if ((Test-SamePath $pathItem 'C:\Sync') -or (Test-PathWithin $pathItem 'C:\Sync')) {
                throw "DirectSync paths must not point at the legacy Syncthing folder."
            }
        }
        $report.explicit_path_boundary.status = 'PASS'
        $report.container_audit_storage = [ordered]@{
            data_root = [System.IO.Path]::GetFullPath((Split-Path -Parent $scanSourceFull))
            events_dir = $scanSourceFull
            direct_sync_root = $programDataRootFull
            defaulted_program_data_root = $false
            defaulted_scan_source_dir = $false
            defaulted_source_glob = $false
        }
        if (-not (Test-Path -LiteralPath $scanSourceFull -PathType Container)) {
            throw "scan_source_dir does not exist or is not a directory"
        }
        if ([string]::IsNullOrWhiteSpace($SourceGlob) -or $SourceGlob.Contains('**') -or $SourceGlob.Contains('/') -or $SourceGlob.Contains('\')) {
            throw "source glob must be a direct-child file pattern"
        }
        $relayExecutable = Join-Path $appRootFull 'Container_Audit_DirectSync_Relay.exe'
        if (-not (Test-Path -LiteralPath $relayExecutable -PathType Leaf)) {
            throw "bundled relay executable is not present"
        }
        Assert-NoReparsePoint $relayExecutable "Container_Audit bundled DirectSync relay"
        $report.bundled_relay_executable = [ordered]@{
            status = 'PASS'; blocked_reason = ''; path = $relayExecutable; exists = $true
        }

        $manifest = Read-BoundedJson $manifestFull "Container_Audit producer manifest"
        if (
            $null -eq $manifest.pc_identity -or
            [string]::IsNullOrWhiteSpace([string]$manifest.pc_identity.producer_install_id) -or
            [string]::IsNullOrWhiteSpace([string]$manifest.pc_identity.source_host_id)
        ) {
            throw "producer manifest identity is incomplete"
        }
        $containerStreams = @($manifest.streams | Where-Object {
            [string]$_.stream_name -ceq 'container_audit_events'
        })
        if (
            $containerStreams.Count -ne 1 -or
            [string]$containerStreams[0].producer_role -cne 'container_audit' -or
            [string]$containerStreams[0].source_system -cne 'container_audit' -or
            [string]$containerStreams[0].source_transport -cne 'legacy_transfer_csv'
        ) {
            throw "producer manifest stream does not match Container_Audit legacy CSV"
        }
        $report.producer_manifest = [ordered]@{
            status = 'PASS'
            blocked_reason = ''
            path = $manifestFull
            missing_identity_fields = @()
            container_audit_stream_present = $true
            container_audit_stream_valid = $true
        }

        $credential = Read-BoundedJson $credentialFull "Container_Audit producer credential"
        foreach ($field in @('producer_id', 'key_id', 'endpoint_url', 'secret_ref')) {
            if ([string]::IsNullOrWhiteSpace([string]$credential.$field)) {
                throw "credential file is missing required identity, endpoint, or secret_ref fields"
            }
        }
        if (
            $null -ne $credential.PSObject.Properties['secret'] -and
            -not [string]::IsNullOrWhiteSpace([string]$credential.secret)
        ) {
            throw "raw credential secret is disabled for production apply; use secret_ref"
        }
        $secretRef = [string]$credential.secret_ref
        if ($secretRef -notmatch '^(env|dpapi|wincred):(.+)$') {
            throw "secret_ref must start with env:, dpapi:, or wincred:"
        }
        $secretRefScheme = $Matches[1].ToLowerInvariant()
        [void](Get-SafeSecretReferenceName $Matches[2])
        $credentialEndpoint = New-Object System.Uri -ArgumentList ([string]$credential.endpoint_url)
        if (
            @('http', 'https') -cnotcontains $credentialEndpoint.Scheme -or
            [string]::IsNullOrWhiteSpace($credentialEndpoint.Host) -or
            -not [string]::IsNullOrWhiteSpace($credentialEndpoint.UserInfo) -or
            $credentialEndpoint.AbsolutePath -cne '/api/producer-ingest/v1/source-file' -or
            -not [string]::IsNullOrWhiteSpace($credentialEndpoint.Query) -or
            -not [string]::IsNullOrWhiteSpace($credentialEndpoint.Fragment)
        ) {
            throw "credential endpoint_url is invalid"
        }
        $isolatedContextPath = [string]$credential.isolated_qualification_context_path
        $isolatedQualification = $false
        if (-not [string]::IsNullOrWhiteSpace($isolatedContextPath)) {
            [void](Read-ContainerAuditQualificationContext $isolatedContextPath ([string]$credential.endpoint_url))
            $isolatedQualification = $true
        }
        elseif ($credentialEndpoint.Scheme -cne 'https') {
            throw "credential endpoint_url must use HTTPS outside isolated qualification"
        }
        else {
            Assert-ContainerAuditPublicEndpoint ([string]$credential.endpoint_url)
        }
        $report.credential = [ordered]@{
            status = 'PASS'
            blocked_reason = ''
            path = $credentialFull
            missing_fields = @()
            secret_material_configured = $true
            secret_ref_configured = $true
            raw_secret_configured = $false
            secret_ref_scheme = $secretRefScheme
            raw_secret_forbidden = $true
            endpoint_url_valid = $true
            isolated_qualification = $isolatedQualification
            isolated_qualification_context_configured = $isolatedQualification
        }
        $taskTransportEnvironment = Get-ContainerAuditTaskTransportEnvironment
        $report.local_test_task_environment_names = @($taskTransportEnvironment.names)
        $report.local_test_task_environment_persisted = ($taskTransportEnvironment.names.Count -gt 0)

        $paths = [ordered]@{
            db_path = Join-Path $programDataRootFull 'queue\direct_sync_relay.sqlite3'
            spool_dir = Join-Path $programDataRootFull 'spool'
            upload_status_dir = Join-Path $programDataRootFull 'upload_status'
            runtime_status_path = Join-Path $programDataRootFull 'status\direct_sync_relay_status.json'
            launcher_status_path = Join-Path $programDataRootFull 'status\direct_sync_relay_launcher.log'
            log_path = Join-Path $programDataRootFull 'logs\direct_sync_relay.jsonl'
            operator_pause_path = Join-Path $programDataRootFull 'control\pause.json'
            runtime_temp_dir = Join-Path $programDataRootFull 'temp'
        }
        foreach ($runtimePath in $paths.Values) {
            if (-not (Test-SamePath $runtimePath $programDataRootFull) -and -not (Test-PathWithin $runtimePath $programDataRootFull)) {
                throw "runtime path escaped program_data_root"
            }
        }
        foreach ($directory in @(
            $programDataRootFull,
            (Split-Path -Parent $paths.db_path),
            $paths.spool_dir,
            $paths.upload_status_dir,
            (Split-Path -Parent $paths.runtime_status_path),
            (Split-Path -Parent $paths.log_path),
            (Split-Path -Parent $paths.operator_pause_path),
            $paths.runtime_temp_dir,
            (Join-Path $programDataRootFull 'bin')
        )) {
            New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
            Assert-NoReparsePoint $directory "Container_Audit DirectSync runtime directory"
        }
        $report.runtime_paths = $paths
        $report.runtime_path_boundary = [ordered]@{
            status = 'PASS'
            blocked_reason = ''
            program_data_root = $programDataRootFull
            all_runtime_paths_under_program_data_root = $true
            escaped_paths = @()
            resolved_runtime_paths = $paths
        }
        $report.source_scan = [ordered]@{
            enabled = $true
            scan_source_dir = $scanSourceFull
            source_globs = @($SourceGlob)
            max_enqueue_files = 100
            min_source_file_age_seconds = 30
            drain_after_scan = $true
        }
        $report.source_scan_validation = [ordered]@{
            status = 'PASS'
            enabled = $true
            scan_source_dir_exists = $true
            source_globs_valid = $true
            source_scan_limits_valid = $true
            syncthing_path_rejected = $false
        }

        [string[]]$runnerCommand = @(
            $relayExecutable,
            '--db-path', $paths.db_path,
            '--spool-dir', $paths.spool_dir,
            '--producer-manifest-path', $manifestFull,
            '--credential-path', $credentialFull,
            '--upload-status-dir', $paths.upload_status_dir,
            '--runtime-status-path', $paths.runtime_status_path,
            '--log-path', $paths.log_path,
            '--operator-pause-path', $paths.operator_pause_path,
            '--worker-id', $TaskName,
            '--min-free-bytes', '536870912',
            '--max-active-queue-count', '1000',
            '--max-active-queue-age-seconds', '86400'
        )
        if ($isolatedQualification) {
            $runnerCommand += '--require-runtime-lease-before-scan'
        }
        $runnerCommand += @(
            '--scan-source-dir', $scanSourceFull,
            '--source-glob', $SourceGlob,
            '--max-enqueue-files', '100',
            '--min-source-file-age-seconds', '30',
            '--drain-after-scan'
        )
        $launcherPath = Join-Path $programDataRootFull ("bin\{0}.cmd" -f $TaskName)
        $launcherArguments = '/d /q /c "{0}"' -f $launcherPath
        $report.runner_command = @($runnerCommand)
        $report.scheduled_task_wrapper_path = $launcherPath
        $report.scheduled_task_wrapper_command = ConvertTo-ElevationArgument $launcherPath
        $report.scheduled_task_launcher_path = $launcherPath
        $report.scheduled_task_launcher_command = ConvertTo-ContainerAuditCommandLine @(
            (Join-Path ([Environment]::SystemDirectory) 'cmd.exe'), '/d', '/q', '/c', $launcherPath
        )
        $report.scheduled_task_launcher_status_path = $paths.launcher_status_path
        $report.scheduled_task_create_command = @(
            'Register-ScheduledTask', '-TaskName', $TaskName,
            '-Principal', 'SYSTEM/ServiceAccount/Highest',
            '-MultipleInstances', 'IgnoreNew',
            '-RepetitionInterval', 'PT1M',
            '-RepetitionDuration', 'P3650D'
        )

        [void](Get-OwnedScheduledTaskState $TaskName $launcherPath)
        $report.status = 'APPLYING'
        Write-AtomicUtf8JsonFile $ReportPath $report

        $runnerLine = ConvertTo-ContainerAuditCommandLine $runnerCommand
        $quotedWorking = ConvertTo-ElevationArgument (Split-Path -Parent $launcherPath)
        $quotedStatus = ConvertTo-ElevationArgument $paths.launcher_status_path
        $wrapperLines = @(
            '@echo off',
            'setlocal',
            ('set "TEMP={0}"' -f $paths.runtime_temp_dir),
            ('set "TMP={0}"' -f $paths.runtime_temp_dir)
        ) + @($taskTransportEnvironment.lines) + @(
            ('>{0} echo launcher_status=WRAPPER_STARTED' -f $quotedStatus),
            ('cd /d {0}' -f $quotedWorking),
            'if errorlevel 1 (',
            ('  >>{0} echo launcher_status=WORKING_DIRECTORY_FAILED' -f $quotedStatus),
            '  exit /b 125',
            ')',
            ($runnerLine + ' >nul 2>&1'),
            'set "relayExit=%ERRORLEVEL%"',
            ('>>{0} echo launcher_status=RUNNER_EXITED' -f $quotedStatus),
            ('>>{0} echo launcher_exit_code=%relayExit%' -f $quotedStatus),
            'exit /b %relayExit%',
            ''
        )
        $wrapperBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($wrapperLines -join "`r`n"))
        Write-AtomicFileBytes $launcherPath $wrapperBytes

        $action = New-ScheduledTaskAction `
            -Execute (Join-Path ([Environment]::SystemDirectory) 'cmd.exe') `
            -Argument $launcherArguments `
            -WorkingDirectory (Split-Path -Parent $launcherPath)
        $trigger = New-ScheduledTaskTrigger `
            -Once `
            -At (Get-Date).Date `
            -RepetitionInterval (New-TimeSpan -Minutes 1) `
            -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal = New-ScheduledTaskPrincipal `
            -UserId 'SYSTEM' `
            -LogonType ServiceAccount `
            -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet `
            -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -Hidden `
            -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Force | Out-Null
        $taskReadback = Assert-ContainerAuditScheduledTaskContract $TaskName $launcherPath
        if ([string]$taskReadback.status -cne 'OWNED_EXACT') {
            throw "Container_Audit scheduled-task readback did not prove ownership."
        }
        $report.command_result = [ordered]@{
            returncode = 0
            operation = 'Register-ScheduledTask'
            task_state = $taskReadback
            process_id = $PID
        }
        $report.status = 'PASS'
        Write-AtomicUtf8JsonFile $ReportPath $report
        return $report
    }
    catch {
        $report.status = 'FAIL'
        $report.blocked_reason = $_.Exception.Message
        try { Write-AtomicUtf8JsonFile $ReportPath $report } catch { }
        throw
    }
}

function Test-SamePath([string]$Left, [string]$Right) {
    if (
        [string]::IsNullOrWhiteSpace($Left) -or
        [string]::IsNullOrWhiteSpace($Right) -or
        -not [System.IO.Path]::IsPathRooted($Left) -or
        -not [System.IO.Path]::IsPathRooted($Right)
    ) {
        return $false
    }
    $leftFull = [System.IO.Path]::GetFullPath($Left).TrimEnd('\')
    $rightFull = [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
    return $leftFull.Equals($rightFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-StrictFullPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Purpose path is required."
    }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose path must be absolute."
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "$Purpose path must not use a device namespace."
    }
    if ($Path -match '(^|[\\/])\.\.?(?:[\\/]|$)') {
        throw "$Purpose path must not contain traversal segments."
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($fullPath) -or $fullPath.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose path must not be a filesystem root."
    }
    $rootLength = [System.IO.Path]::GetPathRoot($fullPath).Length
    if ($fullPath.Substring($rootLength).Contains(':')) {
        throw "$Purpose path must not contain an alternate data stream."
    }
    return $fullPath
}

function Assert-ExactCanonicalPath([string]$Actual, [string]$Expected, [string]$Purpose) {
    $actualFull = Get-StrictFullPath $Actual $Purpose
    $expectedFull = Get-StrictFullPath $Expected "$Purpose expected"
    if (-not $actualFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose path is outside the exact owned location."
    }
    return $actualFull
}

function Test-PathWithin([string]$Candidate, [string]$Container) {
    $candidateFull = (Get-StrictFullPath $Candidate "Candidate").TrimEnd('\')
    $containerFull = (Get-StrictFullPath $Container "Container").TrimEnd('\')
    if ($candidateFull.Equals($containerFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidateFull.StartsWith(
        $containerFull + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Set-ProcessWorkingDirectoryOutsideOwnedTree([string]$OwnedRoot) {
    $ownedFull = Get-StrictFullPath $OwnedRoot "Owned application root"
    $safePath = Get-StrictFullPath ([Environment]::SystemDirectory) "Rollback working directory"
    if (Test-PathWithin $safePath $ownedFull) {
        throw "Rollback working directory must be outside the owned application root."
    }
    Set-Location -LiteralPath $safePath -ErrorAction Stop
    [Environment]::CurrentDirectory = $safePath
    $providerPath = [string](Get-Location).Path
    $processPath = [string][Environment]::CurrentDirectory
    if (-not (Test-SamePath $providerPath $safePath) -or -not (Test-SamePath $processPath $safePath)) {
        throw "Rollback could not relocate both PowerShell and process working directories."
    }
    return [ordered]@{
        status = "PASS"
        provider_location = $providerPath
        process_working_directory = $processPath
        outside_application_root = $true
    }
}

function Assert-NoReparsePoint([string]$Path, [string]$Purpose, [switch]$IncludeDescendants) {
    $fullPath = Get-StrictFullPath $Path $Purpose
    $cursor = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    if ($IncludeDescendants.IsPresent -and (Test-Path -LiteralPath $fullPath -PathType Container)) {
        $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
        $pendingDirectories.Push($fullPath)
        while ($pendingDirectories.Count -gt 0) {
            $directory = $pendingDirectories.Pop()
            foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "$Purpose contains a descendant reparse point: $($child.FullName)"
                }
                if ($child.PSIsContainer) {
                    $pendingDirectories.Push($child.FullName)
                }
            }
        }
    }
}

function Assert-OperatorContext([string]$Sid, [string]$LocalAppDataRoot) {
    try {
        $securityIdentifier = New-Object Security.Principal.SecurityIdentifier -ArgumentList $Sid
    }
    catch {
        throw "OperatorUserSid is not a valid Windows SID."
    }
    if ($securityIdentifier.Value -cne $Sid) {
        throw "OperatorUserSid is not canonical."
    }
    $localRoot = Get-StrictFullPath $LocalAppDataRoot "OperatorLocalAppDataRoot"
    $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    if (-not (Test-Path -LiteralPath $profileKey)) {
        throw "OperatorUserSid has no local Windows profile."
    }
    $profilePathValue = [string](Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
    $profileRoot = Get-StrictFullPath ([Environment]::ExpandEnvironmentVariables($profilePathValue)) "Operator profile"
    $expectedLocalRoot = Join-Path $profileRoot "AppData\Local"
    [void](Assert-ExactCanonicalPath $localRoot $expectedLocalRoot "OperatorLocalAppDataRoot")
    Assert-NoReparsePoint $localRoot "OperatorLocalAppDataRoot"
    return $localRoot
}

function Get-ContainerAuditShortcutName {
    return -join @(
        [char]0xC774,
        [char]0xC801,
        [char]0x20,
        [char]0xAC80,
        [char]0xC0AC,
        [char]0x20,
        [char]0xC2DC,
        [char]0xC2A4,
        [char]0xD15C
    )
}

function Get-OwnedShortcutState(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    Assert-NoReparsePoint $ShortcutPath "Container_Audit Start Menu shortcut"
    if (-not (Test-Path -LiteralPath $ShortcutPath)) {
        return [ordered]@{ status = "ABSENT"; path = $ShortcutPath }
    }
    if (-not (Test-Path -LiteralPath $ShortcutPath -PathType Leaf)) {
        throw "The Container_Audit Start Menu shortcut path is not a file."
    }
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $targetPath = [string]$shortcut.TargetPath
        $workingDirectory = [string]$shortcut.WorkingDirectory
        $arguments = [string]$shortcut.Arguments
        $iconLocation = [string]$shortcut.IconLocation
    }
    finally {
        if ($null -ne $shortcut) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    $iconPath = $iconLocation
    $iconIndex = ""
    if ($iconLocation -match '^(.*),\s*(-?\d+)$') {
        $iconPath = $Matches[1].Trim().Trim('"')
        $iconIndex = $Matches[2]
    }
    if (
        -not (Test-SamePath $targetPath $ExpectedTarget) -or
        -not (Test-SamePath $workingDirectory $ExpectedWorkingDirectory) -or
        $arguments -cne "" -or
        -not (Test-SamePath $iconPath $ExpectedTarget) -or
        ($iconIndex -ne "" -and $iconIndex -cne "0")
    ) {
        throw "A conflicting Start Menu shortcut exists; refusing to overwrite or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        path = $ShortcutPath
        target = $targetPath
        working_directory = $workingDirectory
        arguments = $arguments
        icon = $iconLocation
    }
}

function Install-OwnedShortcut(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    $existing = Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
    if ($existing.status -ceq "OWNED") {
        return $existing
    }
    $shortcutDirectory = Split-Path -Parent $ShortcutPath
    Assert-NoReparsePoint $shortcutDirectory "KMTech Start Menu group"
    New-Item -ItemType Directory -Path $shortcutDirectory -Force -ErrorAction Stop | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $shortcut.TargetPath = $ExpectedTarget
        $shortcut.WorkingDirectory = $ExpectedWorkingDirectory
        $shortcut.Arguments = ""
        $shortcut.IconLocation = "$ExpectedTarget,0"
        $shortcut.Save()
    }
    finally {
        if ($null -ne $shortcut) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
        }
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    return Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
}

function Remove-OwnedShortcut(
    [string]$ShortcutPath,
    [string]$ExpectedTarget,
    [string]$ExpectedWorkingDirectory
) {
    $existing = Get-OwnedShortcutState $ShortcutPath $ExpectedTarget $ExpectedWorkingDirectory
    if ($existing.status -ceq "OWNED") {
        Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $ShortcutPath) {
        throw "Container_Audit Start Menu shortcut removal postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $ShortcutPath }
}

function Get-OwnedScheduledTaskState([string]$Name, [string]$ExpectedLauncherPath) {
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) {
        return [ordered]@{ status = "ABSENT"; task_name = $Name }
    }
    if ($tasks.Count -ne 1) {
        throw "Multiple scheduled tasks use the Container_Audit task name."
    }
    $task = $tasks[0]
    if ([string]$task.TaskPath -cne "\") {
        throw "The Container_Audit scheduled task exists outside the owned root task path."
    }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw "The Container_Audit scheduled task action is not owned."
    }
    $expectedCmd = Join-Path ([Environment]::SystemDirectory) "cmd.exe"
    $actualExecute = [string]$actions[0].Execute
    $actualArguments = ([string]$actions[0].Arguments).Trim()
    $expectedArguments = @(
        "/d /q /c $ExpectedLauncherPath",
        "/d /q /c `"$ExpectedLauncherPath`""
    )
    $argumentMatches = $false
    foreach ($candidate in $expectedArguments) {
        if ($actualArguments.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            $argumentMatches = $true
            break
        }
    }
    $principal = [string]$task.Principal.UserId
    $principalMatches = @("SYSTEM", "NT AUTHORITY\SYSTEM", "S-1-5-18") -contains $principal
    if (
        -not (Test-SamePath $actualExecute $expectedCmd) -or
        -not $argumentMatches -or
        -not $principalMatches
    ) {
        throw "A conflicting scheduled task exists; refusing to stop or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        task_name = $Name
        task_path = [string]$task.TaskPath
        execute = $actualExecute
        arguments = $actualArguments
        principal = $principal
    }
}

function Assert-ContainerAuditScheduledTaskContract([string]$Name, [string]$ExpectedLauncherPath) {
    [void](Get-OwnedScheduledTaskState $Name $ExpectedLauncherPath)
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction Stop)
    if ($tasks.Count -ne 1) {
        throw "Container_Audit scheduled-task exact readback is unavailable."
    }
    $task = $tasks[0]
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    if ($actions.Count -ne 1 -or $triggers.Count -ne 1) {
        throw "Container_Audit scheduled-task action or trigger count differs from the install contract."
    }
    $expectedWorkingDirectory = Split-Path -Parent $ExpectedLauncherPath
    if (-not (Test-SamePath ([string]$actions[0].WorkingDirectory) $expectedWorkingDirectory)) {
        throw "Container_Audit scheduled-task working directory differs from the install contract."
    }
    $interval = [System.Xml.XmlConvert]::ToTimeSpan([string]$triggers[0].Repetition.Interval)
    $duration = [System.Xml.XmlConvert]::ToTimeSpan([string]$triggers[0].Repetition.Duration)
    if ($interval -ne (New-TimeSpan -Minutes 1) -or $duration -ne (New-TimeSpan -Days 3650)) {
        throw "Container_Audit scheduled-task repetition differs from the install contract."
    }
    $logonType = [string]$task.Principal.LogonType
    $runLevel = [string]$task.Principal.RunLevel
    if (@('ServiceAccount', '5') -notcontains $logonType -or @('Highest', '1') -notcontains $runLevel) {
        throw "Container_Audit scheduled-task principal differs from the SYSTEM service-account contract."
    }
    $settings = $task.Settings
    $mismatches = New-Object System.Collections.Generic.List[string]
    $formatSettingValue = {
        param($Value)
        if ($null -eq $Value) { return '<absent>' }
        if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
        $text = [regex]::Replace([string]$Value, '[^A-Za-z0-9_.:+-]', '?')
        if ($text.Length -gt 80) { return $text.Substring(0, 77) + '...' }
        return $text
    }

    $multipleInstancesProperty = $settings.PSObject.Properties['MultipleInstances']
    $multipleInstances = if ($null -eq $multipleInstancesProperty) {
        $null
    }
    else {
        [string]$multipleInstancesProperty.Value
    }
    if (
        $null -eq $multipleInstancesProperty -or
        @('IgnoreNew', '2') -notcontains $multipleInstances
    ) {
        [void]$mismatches.Add(
            'MultipleInstances expected=IgnoreNew actual=' + (& $formatSettingValue $multipleInstances)
        )
    }

    # New-ScheduledTaskSettingsSet exposes -AllowStartIfOnBatteries, but the
    # registered task's CIM settings model stores the inverse property.
    $disallowBatteryStartProperty = $settings.PSObject.Properties['DisallowStartIfOnBatteries']
    $disallowBatteryStart = if ($null -eq $disallowBatteryStartProperty) {
        $null
    }
    else {
        [bool]$disallowBatteryStartProperty.Value
    }
    if ($null -eq $disallowBatteryStartProperty -or [bool]$disallowBatteryStart) {
        [void]$mismatches.Add(
            'DisallowStartIfOnBatteries expected=false actual=' +
            (& $formatSettingValue $disallowBatteryStart)
        )
    }

    $stopOnBatteryProperty = $settings.PSObject.Properties['StopIfGoingOnBatteries']
    $stopOnBattery = if ($null -eq $stopOnBatteryProperty) {
        $null
    }
    else {
        [bool]$stopOnBatteryProperty.Value
    }
    if ($null -eq $stopOnBatteryProperty -or [bool]$stopOnBattery) {
        [void]$mismatches.Add(
            'StopIfGoingOnBatteries expected=false actual=' + (& $formatSettingValue $stopOnBattery)
        )
    }

    $startWhenAvailableProperty = $settings.PSObject.Properties['StartWhenAvailable']
    $startWhenAvailable = if ($null -eq $startWhenAvailableProperty) {
        $null
    }
    else {
        [bool]$startWhenAvailableProperty.Value
    }
    if ($null -eq $startWhenAvailableProperty -or -not [bool]$startWhenAvailable) {
        [void]$mismatches.Add(
            'StartWhenAvailable expected=true actual=' + (& $formatSettingValue $startWhenAvailable)
        )
    }

    $hiddenProperty = $settings.PSObject.Properties['Hidden']
    $hidden = if ($null -eq $hiddenProperty) { $null } else { [bool]$hiddenProperty.Value }
    if ($null -eq $hiddenProperty -or -not [bool]$hidden) {
        [void]$mismatches.Add(
            'Hidden expected=true actual=' + (& $formatSettingValue $hidden)
        )
    }

    $executionLimitProperty = $settings.PSObject.Properties['ExecutionTimeLimit']
    $executionLimitText = if ($null -eq $executionLimitProperty) {
        $null
    }
    else {
        [string]$executionLimitProperty.Value
    }
    $executionLimitMatches = $false
    if ($null -ne $executionLimitProperty) {
        try {
            $executionLimit = [System.Xml.XmlConvert]::ToTimeSpan($executionLimitText)
            $executionLimitMatches = $executionLimit -eq [TimeSpan]::Zero
        }
        catch {
            $executionLimitMatches = $false
        }
    }
    if (-not $executionLimitMatches) {
        [void]$mismatches.Add(
            'ExecutionTimeLimit expected=PT0S actual=' + (& $formatSettingValue $executionLimitText)
        )
    }

    if ($mismatches.Count -gt 0) {
        throw (
            'Container_Audit scheduled-task settings differ from the install contract: ' +
            ($mismatches -join '; ') + '.'
        )
    }
    return [ordered]@{
        status = 'OWNED_EXACT'
        task_name = $Name
        working_directory = [string]$actions[0].WorkingDirectory
        repetition_interval = [string]$triggers[0].Repetition.Interval
        repetition_duration = [string]$triggers[0].Repetition.Duration
        logon_type = $logonType
        run_level = $runLevel
        multiple_instances = $multipleInstances
        disallow_start_if_on_batteries = [bool]$disallowBatteryStart
        stop_if_going_on_batteries = [bool]$stopOnBattery
        start_when_available = [bool]$startWhenAvailable
        hidden = [bool]$hidden
        execution_time_limit = $executionLimitText
    }
}

function Remove-OwnedScheduledTask(
    [string]$Name,
    [string]$ExpectedLauncherPath,
    [string]$ApplicationRoot,
    [string]$ProgramDataRoot,
    [string]$ReportPath
) {
    $report = [ordered]@{
        report_version = 'container-audit-direct-sync-install-pack-v1'
        status = 'APPLYING'
        apply = $true
        uninstall = $true
        task_name = $Name
        app_root = [System.IO.Path]::GetFullPath($ApplicationRoot)
        program_data_root = [System.IO.Path]::GetFullPath($ProgramDataRoot)
        producer_manifest = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'uninstall does not read the producer manifest' }
        credential = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'uninstall does not read producer credentials' }
        runtime_path_boundary = [ordered]@{ status = 'SKIPPED'; blocked_reason = ''; reason = 'uninstall does not use runtime data paths' }
        task_principal = [ordered]@{
            status = 'SKIPPED'; mode = 'uninstall'; run_user = ''; password_source = ''
            password_supplied = $false; password_in_report = $false; blocked_reason = ''
        }
        scheduled_task_create_command = @()
        scheduled_task_delete_command = @('Unregister-ScheduledTask', '-TaskName', $Name, '-Confirm:$false')
        scheduled_task_delete = [ordered]@{
            operation = 'Unregister-ScheduledTask'
            already_absent = $false
            postcondition = 'NOT_TESTED'
        }
        secret_redaction = [ordered]@{
            credential_path_only = $true
            raw_secret_in_report = $false
        }
        installer_process_id = $PID
        execution_mode = 'in_process_native_powershell'
        blocked_reason = ''
    }
    try {
        $state = Get-OwnedScheduledTaskState $Name $ExpectedLauncherPath
        $report.scheduled_task_delete.already_absent = ([string]$state.status -ceq 'ABSENT')
        Write-AtomicUtf8JsonFile $ReportPath $report
        if ($state.status -ceq "OWNED") {
            Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop
        }
        if (@(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "Container_Audit scheduled-task removal postcondition failed."
        }
        $report.scheduled_task_delete.postcondition = 'ABSENT'
        $report.status = 'PASS'
        Write-AtomicUtf8JsonFile $ReportPath $report
        return [ordered]@{ status = "ABSENT"; task_name = $Name }
    }
    catch {
        $report.status = 'FAIL'
        $report.blocked_reason = $_.Exception.Message
        try { Write-AtomicUtf8JsonFile $ReportPath $report } catch { }
        throw
    }
}

function Get-OwnedQualificationAuthorityTaskState(
    [string]$Name,
    [string]$ExpectedExecutable,
    [string]$ExpectedStateRoot
) {
    $tasks = @(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) {
        return [ordered]@{ status = "ABSENT"; task_name = $Name }
    }
    if ($tasks.Count -ne 1) {
        throw "Multiple scheduled tasks use the Container_Audit qualification authority task name."
    }
    $task = $tasks[0]
    if ([string]$task.TaskPath -cne "\") {
        throw "The Container_Audit qualification authority task exists outside the owned root task path."
    }
    $actions = @($task.Actions)
    if ($actions.Count -ne 1) {
        throw "The Container_Audit qualification authority task action is not owned."
    }
    $expectedArguments = "serve --state-root `"$ExpectedStateRoot`""
    $actualExecute = [string]$actions[0].Execute
    $actualArguments = ([string]$actions[0].Arguments).Trim()
    $principal = [string]$task.Principal.UserId
    $principalMatches = @("SYSTEM", "NT AUTHORITY\SYSTEM", "S-1-5-18") -contains $principal
    if (
        -not (Test-SamePath $actualExecute $ExpectedExecutable) -or
        -not $actualArguments.Equals($expectedArguments, [System.StringComparison]::Ordinal) -or
        -not $principalMatches
    ) {
        throw "A conflicting qualification authority task exists; refusing to start, stop, or remove it."
    }
    return [ordered]@{
        status = "OWNED"
        task_name = $Name
        task_path = [string]$task.TaskPath
        execute = $actualExecute
        arguments = $actualArguments
        principal = $principal
    }
}

function Install-OwnedQualificationAuthorityTask(
    [string]$Name,
    [string]$Executable,
    [string]$StateRoot
) {
    $state = Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot
    if ($state.status -ceq "ABSENT") {
        $action = New-ScheduledTaskAction `
            -Execute $Executable `
            -Argument "serve --state-root `"$StateRoot`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask `
            -TaskName $Name `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Force | Out-Null
    }
    return (Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot)
}

function Get-OwnedQualificationAuthorityProcesses([string]$Executable) {
    $processes = @(
        Get-CimInstance Win32_Process -Filter "Name='Container_Audit_Qualification_Authority.exe'" -ErrorAction Stop
    )
    foreach ($process in $processes) {
        if ([string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            throw "Container_Audit qualification authority process identity could not be proven."
        }
    }
    return @($processes | Where-Object {
        Test-SamePath ([string]$_.ExecutablePath) $Executable
    })
}

function Stop-OwnedQualificationAuthorityProcesses([string]$Executable) {
    $graceDeadline = (Get-Date).AddSeconds(3)
    do {
        $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
        if ($owned.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $graceDeadline)

    $deadline = (Get-Date).AddSeconds(12)
    do {
        $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
        if ($owned.Count -eq 0) { return }
        foreach ($process in $owned) {
            $processId = [uint32]$process.ProcessId
            $current = @(
                Get-CimInstance Win32_Process `
                    -Filter "ProcessId=$processId AND Name='Container_Audit_Qualification_Authority.exe'" `
                    -ErrorAction Stop
            )
            if ($current.Count -gt 1) {
                throw "Container_Audit qualification authority PID identity is ambiguous."
            }
            if ($current.Count -eq 1) {
                if (
                    [string]::IsNullOrWhiteSpace([string]$current[0].ExecutablePath) -or
                    -not (Test-SamePath ([string]$current[0].ExecutablePath) $Executable)
                ) {
                    throw "Container_Audit qualification authority PID identity could not be proven."
                }
                Stop-Process -Id $processId -Force -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    $owned = @(Get-OwnedQualificationAuthorityProcesses $Executable)
    if ($owned.Count -eq 0) { return }
    throw "Container_Audit qualification authority process removal postcondition failed."
}

function Get-OwnedApplicationProcesses([string]$InstallRoot) {
    $ownedRoot = Get-StrictFullPath $InstallRoot "Container_Audit application root"
    $owned = @()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $executablePath = [string]$process.ExecutablePath
        if (
            [string]::IsNullOrWhiteSpace($executablePath) -or
            -not [System.IO.Path]::IsPathRooted($executablePath)
        ) {
            continue
        }
        try {
            $canonicalExecutablePath = [System.IO.Path]::GetFullPath($executablePath)
            $insideOwnedRoot = Test-PathWithin $canonicalExecutablePath $ownedRoot
        }
        catch {
            continue
        }
        if ($insideOwnedRoot) {
            $owned += $process
        }
    }
    return @($owned)
}

function Stop-OwnedApplicationProcesses([string]$InstallRoot) {
    $ownedRoot = Get-StrictFullPath $InstallRoot "Container_Audit application root"
    foreach ($process in @(Get-OwnedApplicationProcesses $ownedRoot)) {
        $processId = [uint32]$process.ProcessId
        $current = @(
            Get-CimInstance Win32_Process `
                -Filter "ProcessId=$processId" `
                -ErrorAction Stop
        )
        if ($current.Count -gt 1) {
            throw "Container_Audit application PID identity is ambiguous."
        }
        if ($current.Count -eq 0) {
            continue
        }
        $currentExecutablePath = [string]$current[0].ExecutablePath
        if (
            [string]::IsNullOrWhiteSpace($currentExecutablePath) -or
            -not [System.IO.Path]::IsPathRooted($currentExecutablePath) -or
            -not (Test-PathWithin $currentExecutablePath $ownedRoot)
        ) {
            continue
        }
        Stop-Process -Id $processId -Force -ErrorAction Stop
    }
    if (@(Get-OwnedApplicationProcesses $ownedRoot).Count -ne 0) {
        throw "Container_Audit application process removal postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; application_root = $ownedRoot }
}

function Remove-OwnedQualificationAuthorityTask(
    [string]$Name,
    [string]$Executable,
    [string]$StateRoot
) {
    $state = Get-OwnedQualificationAuthorityTaskState $Name $Executable $StateRoot
    if ($state.status -ceq "OWNED") {
        Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction Stop
    }
    if (@(Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "Container_Audit qualification authority task removal postcondition failed."
    }
    Stop-OwnedQualificationAuthorityProcesses $Executable
    return [ordered]@{ status = "ABSENT"; task_name = $Name }
}

function Assert-OwnedTree([string]$Path, [string]$ExpectedPath, [string]$Purpose) {
    $fullPath = Assert-ExactCanonicalPath $Path $ExpectedPath $Purpose
    Assert-NoReparsePoint $fullPath $Purpose -IncludeDescendants
    if ((Test-Path -LiteralPath $fullPath) -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "$Purpose exists but is not a directory."
    }
    return $fullPath
}

function Assert-ApplicationParentInventory([string]$ApplicationParent) {
    Assert-NoReparsePoint $ApplicationParent "Container_Audit application parent" -IncludeDescendants
    if (-not (Test-Path -LiteralPath $ApplicationParent)) {
        return
    }
    if (-not (Test-Path -LiteralPath $ApplicationParent -PathType Container)) {
        throw "Container_Audit application parent is not a directory."
    }
    $allowedNames = @("current", ".current.update-backups", ".current.update-evidence")
    foreach ($child in @(Get-ChildItem -LiteralPath $ApplicationParent -Force -ErrorAction Stop)) {
        if ($allowedNames -notcontains $child.Name) {
            throw "Container_Audit application parent contains a foreign child: $($child.Name)"
        }
    }
}

function Assert-DirectSyncOwnership([string]$Root, [string]$InstallReport, [string]$ExpectedName) {
    if (-not (Test-Path -LiteralPath $Root)) {
        return
    }
    $report = Read-BoundedJson $InstallReport "Container_Audit DirectSync install report"
    if (
        [string]$report.task_name -cne $ExpectedName -or
        -not (Test-SamePath ([string]$report.program_data_root) $Root)
    ) {
        throw "Container_Audit DirectSync ownership metadata does not match the exact app scope."
    }
}

function Assert-NoOwnedProcess([string[]]$ProcessNames) {
    foreach ($processName in $ProcessNames) {
        if (@(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "Destructive rollback is blocked while the owned process is running: $processName"
        }
    }
}

function Assert-ExternalRollbackReportPath([string]$Path, [object[]]$DeletionTargets) {
    $fullPath = Get-StrictFullPath $Path "RollbackReportPath"
    if (Test-Path -LiteralPath $fullPath) {
        throw "RollbackReportPath must be a fresh absent external file."
    }
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "RollbackReportPath parent must already exist."
    }
    Assert-NoReparsePoint $parent "RollbackReportPath parent"
    foreach ($target in $DeletionTargets) {
        if ($target.kind -ceq "scheduled_task") {
            continue
        }
        if (Test-PathWithin $fullPath ([string]$target.path)) {
            throw "RollbackReportPath must be outside every deletion target."
        }
    }
    return $fullPath
}

function Remove-ExactOwnedTree([string]$Path, [string]$Purpose) {
    Assert-NoReparsePoint $Path $Purpose -IncludeDescendants
    if (Test-Path -LiteralPath $Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            throw "$Purpose is not a directory."
        }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $Path) {
        throw "$Purpose deletion postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $Path }
}

function Remove-OwnedCurrentApplicationFootprint(
    [string]$InstallRoot,
    [string]$ExpectedInstallRoot
) {
    $ownedInstallRoot = Assert-OwnedTree `
        $InstallRoot `
        $ExpectedInstallRoot `
        "Container_Audit application root"
    [void](Stop-OwnedApplicationProcesses $ownedInstallRoot)
    [void](Set-ProcessWorkingDirectoryOutsideOwnedTree $ownedInstallRoot)
    return Remove-ExactOwnedTree $ownedInstallRoot "Container_Audit application root"
}

function Initialize-CanonicalApplicationRoot(
    [string]$SourceRoot,
    [string]$InstallRoot,
    [string]$ApplicationParent
) {
    $sourceFull = Get-StrictFullPath $SourceRoot "Container_Audit release source"
    $parentFull = Get-StrictFullPath $ApplicationParent "Container_Audit application parent"
    $targetFull = Assert-ExactCanonicalPath `
        $InstallRoot `
        (Join-Path $parentFull "current") `
        "Container_Audit application root"
    if (Test-SamePath $sourceFull $targetFull) {
        return $targetFull
    }
    if (-not (Test-Path -LiteralPath $sourceFull -PathType Container)) {
        throw "Container_Audit release source is not a directory."
    }
    if ((Test-PathWithin $targetFull $sourceFull) -or (Test-PathWithin $sourceFull $targetFull)) {
        throw "Container_Audit release source and canonical target must be separate trees."
    }
    Assert-NoReparsePoint $sourceFull "Container_Audit release source" -IncludeDescendants
    Assert-NoReparsePoint $parentFull "Container_Audit application parent" -IncludeDescendants
    Assert-ApplicationParentInventory $parentFull
    if (Test-Path -LiteralPath $targetFull) {
        [void](Assert-OwnedTree $targetFull $targetFull "Container_Audit application root")
        throw "The canonical Container_Audit application root already exists; use the installed application's owned update flow."
    }

    if (-not (Test-Path -LiteralPath $parentFull)) {
        New-Item -ItemType Directory -Path $parentFull -Force -ErrorAction Stop | Out-Null
    }
    Assert-NoReparsePoint $parentFull "Container_Audit application parent" -IncludeDescendants
    New-Item -ItemType Directory -Path $targetFull -ErrorAction Stop | Out-Null
    try {
        foreach ($child in @(Get-ChildItem -LiteralPath $sourceFull -Force -ErrorAction Stop)) {
            Copy-Item `
                -LiteralPath $child.FullName `
                -Destination $targetFull `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
        Assert-NoReparsePoint $targetFull "Container_Audit application root" -IncludeDescendants
        return $targetFull
    }
    catch {
        $copyFailure = $_
        [void](Remove-ExactOwnedTree $targetFull "Container_Audit incomplete application root")
        throw $copyFailure
    }
}

function Remove-EmptyOwnedParent([string]$Path, [string]$Purpose, [switch]$RequireEmpty) {
    Assert-NoReparsePoint $Path $Purpose
    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ status = "ABSENT"; path = $Path }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose is not a directory."
    }
    $firstChild = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $firstChild) {
        if ($RequireEmpty.IsPresent) {
            throw "$Purpose contains unexpected state after owned-child deletion."
        }
        return [ordered]@{ status = "PRESERVED_NONEMPTY"; path = $Path }
    }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Path) {
        throw "$Purpose empty-parent cleanup postcondition failed."
    }
    return [ordered]@{ status = "ABSENT"; path = $Path }
}

function Test-RollbackPostconditions([object[]]$Inventory) {
    $remaining = New-Object System.Collections.Generic.List[string]
    foreach ($target in $Inventory) {
        if ($target.kind -ceq "scheduled_task") {
            if (@(Get-ScheduledTask -TaskName ([string]$target.name) -ErrorAction SilentlyContinue).Count -gt 0) {
                [void]$remaining.Add("scheduled_task:$([string]$target.name)")
            }
            continue
        }
        if (Test-Path -LiteralPath ([string]$target.path)) {
            [void]$remaining.Add([string]$target.path)
        }
    }
    return [ordered]@{
        status = if ($remaining.Count -eq 0) { "PASS" } else { "FAIL" }
        remaining = @($remaining)
    }
}

function Wait-CurrentRuntimeLease([datetime]$Started, [string]$ProgramDataRoot, [string]$AuthorizedManifestHash) {
    $runtimePath = Join-Path $ProgramDataRoot "status\direct_sync_relay_status.json"
    $deadline = (Get-Date).AddSeconds(120)
    do {
        if (Test-Path -LiteralPath $runtimePath -PathType Leaf) {
            $runtimeItem = Get-Item -LiteralPath $runtimePath -Force
            if ($runtimeItem.LastWriteTimeUtc -ge $Started) {
                $runtime = Read-BoundedJson $runtimePath "Relay runtime status"
                if ([string]$runtime.manifest_hash -cne $AuthorizedManifestHash) {
                    throw "Relay runtime manifest hash differs from the server-authorized manifest hash."
                }
                $lease = $runtime.runtime_lease
                $leaseExpiry = [datetime]::MinValue
                if (
                    $null -ne $lease -and
                    [string]$lease.status -ceq "ACTIVE" -and
                    $lease.server_grant_accepted -is [bool] -and [bool]$lease.server_grant_accepted -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.producer_install_id) -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.runtime_instance_id) -and
                    -not [string]::IsNullOrWhiteSpace([string]$lease.lease_id) -and
                    [datetime]::TryParse([string]$lease.expires_at, [ref]$leaseExpiry) -and
                    $leaseExpiry.ToUniversalTime() -gt (Get-Date).ToUniversalTime()
                ) {
                    return
                }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Relay did not prove a current server runtime lease within 120 seconds."
}

$OperatorLocalAppDataRoot = Assert-OperatorContext $OperatorUserSid $OperatorLocalAppDataRoot
$explicitServerBaseUrl = $PSBoundParameters.ContainsKey("ServerBaseUrl")
if (-not $Uninstall.IsPresent) {
    $allowExplicitHttpServerBaseUrl = $EnableWindowsSandboxQualification.IsPresent
    Assert-HttpsServerBaseUrl $ServerBaseUrl -AllowExplicitHttp:$allowExplicitHttpServerBaseUrl
}
if ($Uninstall.IsPresent -and $EnableWindowsSandboxQualification.IsPresent) {
    throw "EnableWindowsSandboxQualification is an installation-only switch."
}
if (-not $Uninstall.IsPresent -and (
    $PurgeContainerAuditState.IsPresent -or
    $ConfirmPermanentContainerAuditDataRemoval.IsPresent -or
    -not [string]::IsNullOrWhiteSpace($RollbackReportPath)
)) {
    throw "Rollback-only parameters require -Uninstall."
}
if ($Uninstall.IsPresent) {
    if ($PurgeContainerAuditState.IsPresent) {
        if (-not $ConfirmPermanentContainerAuditDataRemoval.IsPresent) {
            throw "Destructive rollback requires -ConfirmPermanentContainerAuditDataRemoval."
        }
        if ([string]::IsNullOrWhiteSpace($RollbackReportPath)) {
            throw "Destructive rollback requires an external -RollbackReportPath."
        }
    }
    elseif (
        $ConfirmPermanentContainerAuditDataRemoval.IsPresent -or
        -not [string]::IsNullOrWhiteSpace($RollbackReportPath)
    ) {
        throw "Permanent-removal confirmation and RollbackReportPath require -PurgeContainerAuditState."
    }
    if ($AllowNoncanonicalLayoutForTest.IsPresent -and -not $DryRun.IsPresent) {
        throw "AllowNoncanonicalLayoutForTest cannot authorize uninstall or destructive deletion."
    }
}

$releaseSourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($DataRoot)) {
    $DataRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ContainerAudit"
}
$eventDir = Join-Path $DataRoot "events"
$statusDir = Join-Path $DirectSyncRoot "status"
$requiredReleaseNames = @(
    "Container_Audit.exe",
    "Container_Audit_DirectSync_Install.exe",
    "Container_Audit_DirectSync_Relay.exe",
    "Container_Audit_Qualification_Authority.exe"
)
if (-not $Uninstall.IsPresent) {
    foreach ($requiredName in $requiredReleaseNames) {
        $required = Join-Path $releaseSourceRoot $requiredName
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Release package is incomplete. Missing: $required"
        }
    }
}

$expectedInstallRoot = "C:\KMTech\Apps\Container_Audit\current"
$expectedApplicationParent = "C:\KMTech\Apps\Container_Audit"
$expectedUpdateBackupRoot = "C:\KMTech\Apps\Container_Audit\.current.update-backups"
$expectedUpdateEvidenceRoot = "C:\KMTech\Apps\Container_Audit\.current.update-evidence"
$expectedDirectSyncRoot = "C:\ProgramData\KMTech\DirectSync\container_audit"
$expectedLogisticsProfileRoot = "C:\ProgramData\KMTech\Logistics\profiles\Container_Audit"
$expectedTaskName = "direct-sync-relay-container-audit"
$qualificationAuthorityTaskName = "container-audit-isolated-qualification-authority"
$qualificationStateRoot = Join-Path $expectedDirectSyncRoot "qualification-authority"
$qualificationContextPath = Join-Path $qualificationStateRoot "client-context.json"
$qualificationFixturePath = Join-Path $qualificationStateRoot "operator-fixture.json"
$qualificationInitializeReportPath = Join-Path $statusDir "isolated_qualification_initialize.json"
$qualificationProbeReportPath = Join-Path $statusDir "isolated_qualification_probe.json"
$expectedTaskLauncherPath = Join-Path $expectedDirectSyncRoot "bin\direct-sync-relay-container-audit.cmd"
$expectedStateDbPath = Join-Path $expectedDirectSyncRoot "queue\direct_sync_relay.sqlite3"
$expectedOperatorDataRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ContainerAudit"
$expectedOperatorCatalogRoot = Join-Path $OperatorLocalAppDataRoot "KMTech\ItemCatalog\Container_Audit"
$operatorCatalogCachePath = Join-Path $expectedOperatorCatalogRoot "Item.csv"
$localTestOverrideEnabled = (
    $AllowNoncanonicalLayoutForTest.IsPresent -and
    [string]$env:KMTECH_FACTORY_INSTALL_TEST_MODE -ceq "1"
)
$packageRoot = $releaseSourceRoot
if ($Uninstall.IsPresent) {
    $packageRoot = $expectedInstallRoot
}
elseif (
    -not $DryRun.IsPresent -and
    -not $localTestOverrideEnabled -and
    -not (Test-SamePath $releaseSourceRoot $expectedInstallRoot)
) {
    $packageRoot = Initialize-CanonicalApplicationRoot `
        $releaseSourceRoot `
        $expectedInstallRoot `
        $expectedApplicationParent
}
$appExe = Join-Path $packageRoot "Container_Audit.exe"
$installExe = Join-Path $packageRoot "Container_Audit_DirectSync_Install.exe"
$runnerExe = Join-Path $packageRoot "Container_Audit_DirectSync_Relay.exe"
$qualificationAuthorityExe = Join-Path $packageRoot "Container_Audit_Qualification_Authority.exe"
if (-not $Uninstall.IsPresent) {
    foreach ($required in @($appExe, $installExe, $runnerExe, $qualificationAuthorityExe)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Release package is incomplete. Missing: $required"
        }
    }
}

$reuseExistingIdentity = (
    -not [string]::IsNullOrWhiteSpace($ExistingProducerManifestPath) -or
    -not [string]::IsNullOrWhiteSpace($ExistingCredentialPath) -or
    -not [string]::IsNullOrWhiteSpace($ExistingRegistrationReportPath)
)
if ($reuseExistingIdentity) {
    if (
        [string]::IsNullOrWhiteSpace($ExistingProducerManifestPath) -or
        [string]::IsNullOrWhiteSpace($ExistingCredentialPath) -or
        [string]::IsNullOrWhiteSpace($ExistingRegistrationReportPath)
    ) {
        throw "Existing producer manifest, credential, and registration report paths must be provided together."
    }
    foreach ($existingPath in @(
        $ExistingProducerManifestPath,
        $ExistingCredentialPath,
        $ExistingRegistrationReportPath
    )) {
        if (-not (Test-Path -LiteralPath $existingPath -PathType Leaf)) {
            throw "Existing registered identity evidence does not exist."
        }
    }
}
$manifestPath = if ($reuseExistingIdentity) { $ExistingProducerManifestPath } else { Join-Path $DirectSyncRoot "producer_manifest.json" }
$credentialPath = if ($reuseExistingIdentity) { $ExistingCredentialPath } else { Join-Path $DirectSyncRoot "credential.json" }
$registrationReportPath = if ($reuseExistingIdentity) { $ExistingRegistrationReportPath } else { Join-Path $statusDir "worker_pc_registration.json" }
$installReportPath = Join-Path $statusDir "container_audit_direct_sync_install.json"
$commonProgramsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
$shortcutGroupPath = Join-Path $commonProgramsRoot "KMTech"
$shortcutName = Get-ContainerAuditShortcutName
$expectedShortcutPath = Join-Path $shortcutGroupPath ($shortcutName + ".lnk")
$actualInstallRoot = [System.IO.Path]::GetFullPath($packageRoot)
$actualDirectSyncRoot = [System.IO.Path]::GetFullPath($DirectSyncRoot)
$actualTaskLauncherPath = Join-Path $actualDirectSyncRoot ("bin\{0}.cmd" -f $TaskName)
$actualStateDbPath = Join-Path $actualDirectSyncRoot "queue\direct_sync_relay.sqlite3"
$installRootMatches = Test-SamePath $actualInstallRoot $expectedInstallRoot
$directSyncRootMatches = Test-SamePath $actualDirectSyncRoot $expectedDirectSyncRoot
$taskNameMatches = $TaskName -ceq $expectedTaskName
$taskLauncherPathMatches = Test-SamePath $actualTaskLauncherPath $expectedTaskLauncherPath
$stateDbPathMatches = Test-SamePath $actualStateDbPath $expectedStateDbPath
$productionLayoutMatches = (
    $installRootMatches -and
    $directSyncRootMatches -and
    $taskNameMatches -and
    $taskLauncherPathMatches -and
    $stateDbPathMatches
)
$fieldLayoutContract = [ordered]@{
    status = if ($productionLayoutMatches) { "PASS" } else { "MISMATCH" }
    expected_install_root = $expectedInstallRoot
    actual_install_root = $actualInstallRoot
    expected_direct_sync_root = $expectedDirectSyncRoot
    actual_direct_sync_root = $actualDirectSyncRoot
    expected_task_name = $expectedTaskName
    actual_task_name = $TaskName
    expected_task_launcher_path = $expectedTaskLauncherPath
    actual_task_launcher_path = $actualTaskLauncherPath
    expected_state_db_path = $expectedStateDbPath
    actual_state_db_path = $actualStateDbPath
    install_root_matches = $installRootMatches
    direct_sync_root_matches = $directSyncRootMatches
    task_name_matches = $taskNameMatches
    task_launcher_path_matches = $taskLauncherPathMatches
    state_db_path_matches = $stateDbPathMatches
    production_layout_matches = $productionLayoutMatches
    local_test_override_requested = $AllowNoncanonicalLayoutForTest.IsPresent
    local_test_override_enabled = $localTestOverrideEnabled
    production_apply_allowed = $productionLayoutMatches
}

$rollbackInventory = @(
    [ordered]@{ order = 1; kind = "scheduled_task"; name = $qualificationAuthorityTaskName },
    [ordered]@{ order = 2; kind = "scheduled_task"; name = $expectedTaskName },
    [ordered]@{ order = 3; kind = "shortcut"; path = $expectedShortcutPath },
    [ordered]@{ order = 4; kind = "directory"; path = $expectedLogisticsProfileRoot; purpose = "Container_Audit logistics profile" },
    [ordered]@{ order = 5; kind = "directory"; path = $expectedDirectSyncRoot; purpose = "Container_Audit DirectSync root" },
    [ordered]@{ order = 6; kind = "directory"; path = $expectedOperatorDataRoot; purpose = "Container_Audit operator data" },
    [ordered]@{ order = 7; kind = "directory"; path = $expectedOperatorCatalogRoot; purpose = "Container_Audit operator catalog" },
    [ordered]@{ order = 8; kind = "directory"; path = $expectedUpdateBackupRoot; purpose = "Container_Audit update backups" },
    [ordered]@{ order = 9; kind = "directory"; path = $expectedUpdateEvidenceRoot; purpose = "Container_Audit update evidence" },
    [ordered]@{ order = 10; kind = "directory"; path = $expectedInstallRoot; purpose = "Container_Audit application root" }
)

if ($DryRun.IsPresent) {
    if ($Uninstall.IsPresent) {
        if (-not $productionLayoutMatches) {
            throw "Rollback planning requires the canonical Container_Audit production layout."
        }
        if (-not (Test-SamePath $DataRoot $expectedOperatorDataRoot)) {
            throw "Rollback planning requires the captured operator's canonical Container_Audit data root."
        }
        if ($PurgeContainerAuditState.IsPresent) {
            $externalReportPath = Assert-ExternalRollbackReportPath $RollbackReportPath $rollbackInventory
            $dryRunReport = [ordered]@{
                report_version = "container-audit-pristine-rollback-v1"
                status = "DRY_RUN"
                apply = $false
                destructive = $true
                operator_user_sid = $OperatorUserSid
                operator_local_app_data_root = $OperatorLocalAppDataRoot
                deletion_inventory = $rollbackInventory
                application_root_is_last = ($rollbackInventory[-1].path -ceq $expectedInstallRoot)
                report_path = $externalReportPath
                contains_credential_content = $false
            }
            Write-Utf8JsonFile $externalReportPath $dryRunReport
            Write-Output "rollback_status=DRY_RUN"
            Write-Output "rollback_report=$externalReportPath"
        }
        else {
            Write-Output "uninstall_status=DRY_RUN_DATA_PRESERVED"
            Write-Output "data_preserved=true"
        }
        exit 0
    }
    Write-Utf8JsonFile $installReportPath ([ordered]@{
        report_version = "container-audit-one-step-field-layout-plan-v1"
        status = "DRY_RUN"
        apply = $false
        uninstall = $false
        field_layout_contract = $fieldLayoutContract
    })
    Write-Output "install_status=DRY_RUN"
    Write-Output "package_root=$packageRoot"
    Write-Output "data_root=$DataRoot"
    Write-Output "direct_sync_root=$DirectSyncRoot"
    Write-Output "install_report=$installReportPath"
    exit 0
}

if (-not $Uninstall.IsPresent -and -not $productionLayoutMatches -and -not $localTestOverrideEnabled) {
    Write-Utf8JsonFile $installReportPath ([ordered]@{
        report_version = "container-audit-one-step-field-layout-plan-v1"
        status = "BLOCKED"
        blocked_reason = if ($AllowNoncanonicalLayoutForTest.IsPresent) { "noncanonical layout override requires KMTECH_FACTORY_INSTALL_TEST_MODE=1" } else { "production install requires the canonical Container_Audit field layout" }
        apply = $true
        uninstall = $false
        field_layout_contract = $fieldLayoutContract
    })
    throw "Production install requires C:\KMTech\Apps\Container_Audit\current and the fixed Container_Audit DirectSync layout. Report: $installReportPath"
}

if ($Uninstall.IsPresent) {
    if (-not $productionLayoutMatches) {
        throw "Uninstall requires the exact canonical Container_Audit production layout."
    }
    if (-not (Test-SamePath $DataRoot $expectedOperatorDataRoot)) {
        throw "Uninstall requires the captured operator's canonical Container_Audit data root."
    }
    [void](Assert-ExactCanonicalPath $actualInstallRoot $expectedInstallRoot "Container_Audit application root")
    [void](Assert-ExactCanonicalPath $actualDirectSyncRoot $expectedDirectSyncRoot "Container_Audit DirectSync root")
    Assert-NoReparsePoint $installExe "Container_Audit DirectSync installer"
    Assert-NoReparsePoint $installReportPath "Container_Audit DirectSync install report"
    [void](Get-OwnedScheduledTaskState $TaskName $expectedTaskLauncherPath)
    [void](Get-OwnedQualificationAuthorityTaskState `
        $qualificationAuthorityTaskName `
        $qualificationAuthorityExe `
        $qualificationStateRoot)
    [void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

    if (-not $PurgeContainerAuditState.IsPresent) {
        $preservedDataPaths = @(
            $expectedDirectSyncRoot,
            $expectedLogisticsProfileRoot,
            $expectedOperatorDataRoot,
            $expectedOperatorCatalogRoot,
            $expectedUpdateBackupRoot,
            $expectedUpdateEvidenceRoot
        )
        $preservedDataPathsPresentBeforeUninstall = @(
            $preservedDataPaths | Where-Object { Test-Path -LiteralPath $_ }
        )
        [void](Remove-OwnedQualificationAuthorityTask `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot)
        [void](Remove-OwnedScheduledTask `
            $TaskName `
            $expectedTaskLauncherPath `
            $packageRoot `
            $DirectSyncRoot `
            $installReportPath)
        [void](Remove-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot)
        [void](Remove-OwnedCurrentApplicationFootprint $actualInstallRoot $expectedInstallRoot)
        foreach ($preservedDataPath in $preservedDataPathsPresentBeforeUninstall) {
            if (-not (Test-Path -LiteralPath $preservedDataPath)) {
                throw "Container_Audit uninstall data-preservation postcondition failed: $preservedDataPath"
            }
        }
        Write-Output "application_root_status=ABSENT"
        Write-Output "application_process_status=ABSENT"
        Write-Output "scheduled_task_status=ABSENT"
        Write-Output "qualification_authority_task_status=ABSENT"
        Write-Output "qualification_authority_process_status=ABSENT"
        Write-Output "start_menu_shortcut_status=ABSENT"
        Write-Output "data_preserved=true"
        if (Test-Path -LiteralPath $installReportPath -PathType Leaf) {
            Write-Output "install_report=$installReportPath"
        }
        Write-Output "uninstall_status=PASS_DATA_PRESERVED"
        exit 0
    }

    $externalReportPath = Assert-ExternalRollbackReportPath $RollbackReportPath $rollbackInventory
    $rollbackResults = New-Object System.Collections.Generic.List[object]
    $rollbackReport = [ordered]@{
        report_version = "container-audit-pristine-rollback-v1"
        status = "PREFLIGHT"
        apply = $true
        destructive = $true
        purge_container_audit_state = $PurgeContainerAuditState.IsPresent
        permanent_removal_confirmed = $ConfirmPermanentContainerAuditDataRemoval.IsPresent
        operator_user_sid = $OperatorUserSid
        operator_local_app_data_root = $OperatorLocalAppDataRoot
        report_path = $externalReportPath
        deletion_inventory = $rollbackInventory
        application_root_is_last = ($rollbackInventory[-1].path -ceq $expectedInstallRoot)
        working_directory_relocation = [ordered]@{ status = "NOT_TESTED"; outside_application_root = $false }
        results = $rollbackResults
        parent_cleanup = @()
        postconditions = [ordered]@{ status = "NOT_TESTED"; remaining = @() }
        contains_credential_content = $false
        failure = ""
    }
    Write-Utf8JsonFile $externalReportPath $rollbackReport
    try {
        Assert-NoOwnedProcess @("Container_Audit", "Container_Audit_DirectSync_Relay")
        [void](Assert-OwnedTree $expectedApplicationParent $expectedApplicationParent "Container_Audit application parent")
        Assert-ApplicationParentInventory $expectedApplicationParent
        [void](Assert-OwnedTree $expectedLogisticsProfileRoot $expectedLogisticsProfileRoot "Container_Audit logistics profile")
        [void](Assert-OwnedTree $expectedDirectSyncRoot $expectedDirectSyncRoot "Container_Audit DirectSync root")
        [void](Assert-OwnedTree $expectedOperatorDataRoot $expectedOperatorDataRoot "Container_Audit operator data")
        [void](Assert-OwnedTree $expectedOperatorCatalogRoot $expectedOperatorCatalogRoot "Container_Audit operator catalog")
        [void](Assert-OwnedTree $expectedUpdateBackupRoot $expectedUpdateBackupRoot "Container_Audit update backups")
        [void](Assert-OwnedTree $expectedUpdateEvidenceRoot $expectedUpdateEvidenceRoot "Container_Audit update evidence")
        Assert-DirectSyncOwnership $expectedDirectSyncRoot $installReportPath $expectedTaskName
        [void](Get-OwnedScheduledTaskState $TaskName $expectedTaskLauncherPath)
        [void](Get-OwnedQualificationAuthorityTaskState `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot)
        [void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

        $rollbackReport.status = "APPLYING"
        Write-Utf8JsonFile $externalReportPath $rollbackReport

        [void]$rollbackResults.Add((Remove-OwnedQualificationAuthorityTask `
            $qualificationAuthorityTaskName `
            $qualificationAuthorityExe `
            $qualificationStateRoot))
        Assert-NoOwnedProcess @("Container_Audit_Qualification_Authority")
        [void]$rollbackResults.Add((Remove-OwnedScheduledTask `
            $TaskName `
            $expectedTaskLauncherPath `
            $packageRoot `
            $DirectSyncRoot `
            $installReportPath))
        [void]$rollbackResults.Add((Remove-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedLogisticsProfileRoot "Container_Audit logistics profile"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedDirectSyncRoot "Container_Audit DirectSync root"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedOperatorDataRoot "Container_Audit operator data"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedOperatorCatalogRoot "Container_Audit operator catalog"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedUpdateBackupRoot "Container_Audit update backups"))
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedUpdateEvidenceRoot "Container_Audit update evidence"))
        $rollbackReport.working_directory_relocation = Set-ProcessWorkingDirectoryOutsideOwnedTree $expectedInstallRoot
        [void]$rollbackResults.Add((Remove-ExactOwnedTree $expectedInstallRoot "Container_Audit application root"))

        $rollbackReport.parent_cleanup = @(
            (Remove-EmptyOwnedParent $expectedApplicationParent "Container_Audit application parent" -RequireEmpty),
            (Remove-EmptyOwnedParent $shortcutGroupPath "KMTech Start Menu group")
        )
        $rollbackReport.postconditions = Test-RollbackPostconditions $rollbackInventory
        if ($rollbackReport.postconditions.status -cne "PASS") {
            throw "Destructive rollback postconditions did not prove every exact owned resource absent."
        }
        $rollbackReport.status = "PASS"
        Write-Utf8JsonFile $externalReportPath $rollbackReport
        Write-Output "rollback_status=PASS"
        Write-Output "rollback_report=$externalReportPath"
        exit 0
    }
    catch {
        $rollbackReport.status = "FAIL"
        $rollbackReport.failure = $_.Exception.Message
        $rollbackReport.postconditions = Test-RollbackPostconditions $rollbackInventory
        Write-Utf8JsonFile $externalReportPath $rollbackReport
        throw "Container_Audit destructive rollback failed. Report: $externalReportPath. $($_.Exception.Message)"
    }
}

[void](Get-OwnedShortcutState $expectedShortcutPath $appExe $expectedInstallRoot)

New-Item -ItemType Directory -Path $eventDir -Force | Out-Null
New-Item -ItemType Directory -Path $statusDir -Force | Out-Null

$qualificationAuthorityEnabled = $false
if ($EnableWindowsSandboxQualification.IsPresent) {
    $qualificationServerBaseUri = [System.Uri]$ServerBaseUrl
    if (
        $ServerBaseUrl.Trim().TrimEnd('/') -cne "https://worker.kmtecherp.com" -and
        $qualificationServerBaseUri.Scheme -cne "http"
    ) {
        throw "Windows Sandbox qualification ServerBaseUrl override must be an HTTP origin."
    }
    [void](Assert-ExactCanonicalPath $qualificationStateRoot (Join-Path $DirectSyncRoot "qualification-authority") "Qualification authority state")
    if (-not (Test-Path -LiteralPath $qualificationStateRoot)) {
        New-Item -ItemType Directory -Path $qualificationStateRoot -Force | Out-Null
    }
    Assert-NoReparsePoint $qualificationStateRoot "Qualification authority state" -IncludeDescendants
    & icacls.exe $qualificationStateRoot `
        "/inheritance:r" `
        "/grant:r" `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-32-545:RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Qualification authority state ACL installation failed."
    }
    & $qualificationAuthorityExe `
        initialize `
        --state-root $qualificationStateRoot `
        --operator-user-sid $OperatorUserSid `
        --operator-local-app-data-root $OperatorLocalAppDataRoot `
        --report-path $qualificationInitializeReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Sandbox qualification authority initialization failed."
    }
    foreach ($publicName in @(
        "client-context.json",
        "qualification-ca.pem",
        "operator-fixture.json"
    )) {
        $publicPath = Join-Path $qualificationStateRoot $publicName
        & icacls.exe $publicPath `
            "/inheritance:r" `
            "/grant:r" `
            "*S-1-5-18:F" `
            "*S-1-5-32-544:F" `
            "*S-1-5-32-545:R" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Qualification authority public-state ACL installation failed."
        }
    }
    foreach ($privateName in @(
        "private-state.json",
        "qualification-server-key.pem",
        "qualification-operation-lease-key.pem"
    )) {
        $privatePath = Join-Path $qualificationStateRoot $privateName
        & icacls.exe $privatePath `
            "/inheritance:r" `
            "/grant:r" `
            "*S-1-5-18:F" `
            "*S-1-5-32-544:F" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Qualification authority private-state ACL installation failed."
        }
    }
    $qualificationInitialize = Read-BoundedJson `
        $qualificationInitializeReportPath `
        "Qualification authority initialization report"
    if (
        @("INITIALIZED", "REUSED") -notcontains [string]$qualificationInitialize.status -or
        [string]$qualificationInitialize.activation_mode -cne "windows_sandbox_qualification" -or
        $qualificationInitialize.loopback_only -isnot [bool] -or -not [bool]$qualificationInitialize.loopback_only -or
        $qualificationInitialize.production_write_enabled -isnot [bool] -or [bool]$qualificationInitialize.production_write_enabled -or
        -not (Test-SamePath ([string]$qualificationInitialize.context_path) $qualificationContextPath) -or
        -not (Test-SamePath ([string]$qualificationInitialize.fixture_path) $qualificationFixturePath)
    ) {
        throw "Qualification authority initialization report did not prove the isolated route."
    }
    $qualificationAuthorityServerBaseUrl = [string]$qualificationInitialize.server_base_url
    Assert-HttpsServerBaseUrl $qualificationAuthorityServerBaseUrl
    $ServerBaseUrl = Resolve-ProducerSubmissionBaseUrl `
        $ServerBaseUrl `
        $explicitServerBaseUrl `
        $qualificationAuthorityServerBaseUrl
    Assert-HttpsServerBaseUrl `
        $ServerBaseUrl `
        -AllowExplicitHttp:$explicitServerBaseUrl
    [void](Install-OwnedQualificationAuthorityTask `
        $qualificationAuthorityTaskName `
        $qualificationAuthorityExe `
        $qualificationStateRoot)
    Start-ScheduledTask -TaskName $qualificationAuthorityTaskName -ErrorAction Stop
    $qualificationProbePassed = $false
    $qualificationDeadline = (Get-Date).AddSeconds(30)
    do {
        & $qualificationAuthorityExe `
            probe `
            --state-root $qualificationStateRoot `
            --report-path $qualificationProbeReportPath | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $qualificationProbePassed = $true
            break
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $qualificationDeadline)
    if (-not $qualificationProbePassed) {
        throw "APPLIED_UNPROVEN: the owned qualification authority task did not prove HTTPS readiness."
    }
    $qualificationProbe = Read-BoundedJson `
        $qualificationProbeReportPath `
        "Qualification authority probe report"
    if (
        [string]$qualificationProbe.status -cne "PASS" -or
        $qualificationProbe.loopback_only -isnot [bool] -or -not [bool]$qualificationProbe.loopback_only -or
        $qualificationProbe.production_write_enabled -isnot [bool] -or [bool]$qualificationProbe.production_write_enabled
    ) {
        throw "Qualification authority probe did not prove the isolated HTTPS route."
    }
    $qualificationAuthorityEnabled = $true
}

# Preserve the app's established per-user data root. SYSTEM can read that
# source, while the machine-scope DPAPI credential and relay state stay under
# the ProgramData root.

$endpointUrl = "$($ServerBaseUrl.Trim().TrimEnd('/'))/api/producer-ingest/v1/source-file"
if (-not $reuseExistingIdentity) {
    $ProducerIdentityPath = ([string]$ProducerIdentityPath).Trim()
    if (
        -not [string]::IsNullOrWhiteSpace($ProducerIdentityPath) -and
        -not (Test-Path -LiteralPath $ProducerIdentityPath -PathType Leaf)
    ) {
        throw "Producer identity seed file does not exist."
    }
    [void](Invoke-ContainerAuditWorkerPcRegistration `
        $packageRoot `
        $DataRoot `
        $DirectSyncRoot `
        $endpointUrl `
        $EnrollmentTokenEnv `
        $manifestPath `
        $credentialPath `
        $registrationReportPath `
        (Join-Path $expectedLogisticsProfileRoot 'runtime-profile.json') `
        $(if ($qualificationAuthorityEnabled) { $qualificationContextPath } else { '' }) `
        $ProducerIdentityPath `
        $ProducerInstallId `
        $ProducerId `
        $SourceHostId)
}
$registrationReport = Read-BoundedJson $registrationReportPath "Container_Audit registration report"
if (
    [string]$registrationReport.status -cne "SELF_ENROLLMENT_REGISTERED" -or
    $registrationReport.server_registration_verified -isnot [bool] -or -not [bool]$registrationReport.server_registration_verified -or
    $registrationReport.manifest_hash_verified -isnot [bool] -or -not [bool]$registrationReport.manifest_hash_verified -or
    $registrationReport.persisted_manifest_hash_verified -isnot [bool] -or -not [bool]$registrationReport.persisted_manifest_hash_verified
) {
    throw "Container_Audit registration report did not prove the persisted server-authorized manifest."
}
if (
    $qualificationAuthorityEnabled -and
    (
        $registrationReport.isolated_qualification_mode -isnot [bool] -or
        -not [bool]$registrationReport.isolated_qualification_mode -or
        [string]$registrationReport.isolated_qualification_authority_id -cne [string]$qualificationInitialize.authority_instance_id
    )
) {
    throw "Container_Audit registration report did not prove the isolated qualification authority binding."
}
$authorizedManifestHash = ([string]$registrationReport.manifest_hash).ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($authorizedManifestHash)) {
    throw "Container_Audit registration report omitted the authorized manifest hash."
}
if ($reuseExistingIdentity) {
    [void](Assert-ContainerAuditManifestHash $manifestPath $authorizedManifestHash)
}
[void](Install-ContainerAuditDirectSyncTask `
    $packageRoot `
    $DirectSyncRoot `
    $manifestPath `
    $credentialPath `
    $eventDir `
    '*.csv' `
    $TaskName `
    $installReportPath `
    $fieldLayoutContract)

$report = Read-BoundedJson $installReportPath "Container_Audit DirectSync install report"
if (
    [string]$report.status -cne "PASS" -or
    [string]$report.task_principal.mode -cne "system_service_account" -or
    [string]$report.task_principal.run_user -cne "SYSTEM" -or
    (
        -not $localTestOverrideEnabled -and
        (
            $report.field_layout_contract.production_layout_matches -isnot [bool] -or
            -not [bool]$report.field_layout_contract.production_layout_matches
        )
    )
) {
    throw "Container_Audit install report did not prove the SYSTEM task and canonical field-layout contract."
}
if (
    $qualificationAuthorityEnabled -and
    (
        $report.credential.isolated_qualification -isnot [bool] -or
        -not [bool]$report.credential.isolated_qualification
    )
) {
    throw "Container_Audit install report did not prove the isolated qualification credential boundary."
}
try {
    $relayStarted = (Get-Date).ToUniversalTime()
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
catch {
    $startFailure = $_
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (-not $reuseExistingIdentity) {
        Remove-NewMachineProfilesFromRegistrationReport $registrationReportPath
    }
    throw $startFailure
}
try {
    Wait-CurrentRuntimeLease $relayStarted $DirectSyncRoot $authorizedManifestHash
}
catch {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    throw "APPLIED_UNPROVEN: relay task was installed but current runtime liveness was not proven: $($_.Exception.Message)"
}

$installedShortcut = Install-OwnedShortcut $expectedShortcutPath $appExe $expectedInstallRoot
if ($installedShortcut.status -cne "OWNED") {
    throw "Container_Audit Start Menu shortcut readback did not prove the owned shortcut contract."
}

Write-Output "install_status=PASS"
Write-Output "operator_readiness_status=PENDING_FIRST_LAUNCH"
Write-Output "first_launch_catalog_status=NOT_TESTED"
Write-Output "start_menu_shortcut=$expectedShortcutPath"
Write-Output "operator_catalog_cache_path=$operatorCatalogCachePath"
Write-Output "registration_report=$registrationReportPath"
Write-Output "install_report=$installReportPath"
if ($qualificationAuthorityEnabled) {
    Write-Output "qualification_authority_status=PASS"
    Write-Output "qualification_authority_context=$qualificationContextPath"
    Write-Output "qualification_operator_fixture=$qualificationFixturePath"
}
