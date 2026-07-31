<#
    Step 4 - Computes an ADMX policy's current state (Not Configured /
    Enabled / Disabled) from registry.pol entries (Step 2), and formats
    security setting state (Step 3).
#>

Set-StrictMode -Version Latest

function New-PolLookup {
    # Builds a "registry key|value name" (lowercase) -> .pol entry dict for O(1) lookup.
        [CmdletBinding(SupportsShouldProcess)]
    param([System.Collections.IEnumerable]$Entries)
    if ($PSCmdlet.ShouldProcess('New-PolLookup', 'Invoke')) {

    $lookup = @{}
    if ($null -eq $Entries) { return $lookup }
    foreach ($e in $Entries) {
        $k = ('{0}|{1}' -f $e.KeyName, $e.ValueName).ToLowerInvariant()
        $lookup[$k] = $e
    }
    return $lookup

    }
}

function Get-PolFileEntriesSafe {
    # Reads registry.pol if it exists, else returns an empty list
    # (local GPO not yet materialized: state = everything not configured).
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        try { return Read-PolFile -Path $Path } catch {
            Write-Warning "Unable to read $Path`: $($_.Exception.Message)"
            return New-Object System.Collections.Generic.List[object]
        }
    }
    return New-Object System.Collections.Generic.List[object]
}

function Get-AdmxPolicyState {
    # Determines an ADMX policy's state from the .pol lookup of the matching scope (Machine/User).
    param($Policy, [hashtable]$PolLookup)

    if ($Policy.registryKey) {
        if ($Policy.valueName) {
            $mainKey = ('{0}|{1}' -f $Policy.registryKey, $Policy.valueName).ToLowerInvariant()
            if ($PolLookup.ContainsKey($mainKey)) {
                $entry = $PolLookup[$mainKey]
                if ($null -ne $Policy.enabledValue -and "$($entry.Value)" -eq "$($Policy.enabledValue)") { return 'Enabled' }
                if ($null -ne $Policy.disabledValue -and "$($entry.Value)" -eq "$($Policy.disabledValue)") { return 'Disabled' }
                return 'Enabled'
            }
            $delKey = ('{0}|**del.{1}' -f $Policy.registryKey, $Policy.valueName).ToLowerInvariant()
            if ($PolLookup.ContainsKey($delKey)) { return 'NotConfigured' }
        }

        foreach ($el in @($Policy.elements)) {
            $elKey = $el.key
            if (-not $elKey) { $elKey = $Policy.registryKey }
            if ($el.valueName) {
                $k = ('{0}|{1}' -f $elKey, $el.valueName).ToLowerInvariant()
                if ($PolLookup.ContainsKey($k)) { return 'Enabled' }
            }
        }
    }

    return 'NotConfigured'
}

function Get-PolicyElementValue {
    # For each element of a policy, gets its current value from the scope's
    # registry.pol (to pre-fill the edit dialog). Key = element.id.
    param($Policy, [hashtable]$PolLookup)

    $values = @{}
    foreach ($el in @($Policy.elements)) {
        $elKey = $el.key
        if (-not $elKey) { $elKey = $Policy.registryKey }
        if (-not $el.valueName) { continue }
        $k = ('{0}|{1}' -f $elKey, $el.valueName).ToLowerInvariant()
        if ($PolLookup.ContainsKey($k)) {
            $values[$el.id] = $PolLookup[$k].Value
        }
    }
    return $values
}

function Get-AdmxPolicyStateLabel {
    param([string]$State, [hashtable]$Ui)
    switch ($State) {
        'Enabled'  { return $Ui.StateEnabled }
        'Disabled' { return $Ui.StateDisabled }
        default    { return $Ui.StateNotConfigured }
    }
}

function ConvertTo-RegistryValuesEncoding {
    # Encodes a value for GptTmpl.inf's [Registry Values] section, as
    # "<REG_* type>,<data>" (e.g. "4,1" = REG_DWORD 1). REG_SZ (type 1) is
    # the only type quoted in the real file (e.g. 1,"10"), unlike
    # REG_DWORD/REG_BINARY which stay bare (4,1 / 3,0) - confirmed on real
    # secedit.inf (CachedLogonsCount, AllocateFloppies).
    param([int]$RegType, [string]$Data)
    if ($RegType -eq 1) { $Data = '"' + $Data + '"' }
    return "$RegType,$Data"
}

function ConvertFrom-RegistryValuesEncoding {
    # Inverse of ConvertTo-RegistryValuesEncoding: "4,1" -> RegType=4,
    # Data='1'. Data can itself contain commas (e.g. REG_MULTI_SZ list
    # "7,a,b,c"), so only the first comma splits type from the rest, never
    # a plain Split(','). Strips quotes from REG_SZ (type 1) data here once,
    # so all callers get clean data without knowing this quirk - real bug:
    # AllocateFloppies/AllocateCDRoms (reg-boolean, RegType=1) showed
    # '"0"'/'"1"' instead of Disabled/Enabled for lack of this stripping
    # before comparing to '0'/'1'.
    param([string]$RawValue)
    if ([string]::IsNullOrEmpty($RawValue)) { return $null }
    $idx = $RawValue.IndexOf(',')
    if ($idx -lt 0) { return $null }
    $regType = 0
    [void][int]::TryParse($RawValue.Substring(0, $idx), [ref]$regType)
    $data = $RawValue.Substring($idx + 1)
    if ($regType -eq 1 -and $data.Length -ge 2 -and $data.StartsWith('"') -and $data.EndsWith('"')) {
        $data = $data.Substring(1, $data.Length - 2)
    }
    return [pscustomobject]@{ RegType = $regType; Data = $data }
}

function Resolve-PrincipalDisplayName {
    # Resolves a raw [Privilege Rights] token ("*S-1-5-32-544" or an
    # already-plain account name) to a friendly name, like the real console
    # does. BUILTIN/NT AUTHORITY/local machine name prefixes are stripped
    # (as the real console does for built-in groups); a domain account
    # keeps its "DOMAIN\" prefix. Falls back silently to the raw SID if
    # resolution fails (unreachable domain, orphaned SID...).
    param([string]$RawToken)

    if ([string]::IsNullOrWhiteSpace($RawToken)) { return $RawToken }
    if (-not $RawToken.StartsWith('*')) { return $RawToken }

    $sidText = $RawToken.Substring(1)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
        if ($name -match '^(BUILTIN|NT AUTHORITY|NT SERVICE)\\(.+)$') { return $Matches[2] }
        if ($name -match "^$([regex]::Escape($env:COMPUTERNAME))\\(.+)$") { return $Matches[1] }
        return $name
    }
    catch {
        return $sidText
    }
}

function Format-SecuritySettingValue {
    # Formats a security setting's raw value for display in the list
    # (State/Value column), using the current UI language ($Ui from Get-UiString).
    param($Setting, [hashtable]$Ui)

    if (-not $Setting.isConfigured) { return $Ui.StateNotDefined }

    switch ($Setting.valueType) {
        'boolean' {
            if ($Setting.rawValue -eq '1') { return $Ui.StateEnabled }
            if ($Setting.rawValue -eq '0') { return $Ui.StateDisabled }
            return $Setting.rawValue
        }
        'audit' {
            switch ($Setting.rawValue) {
                '0' { return $Ui.AuditNone }
                '1' { return $Ui.AuditSuccess }
                '2' { return $Ui.AuditFailure }
                '3' { return $Ui.AuditSuccessFailure }
                default { return $Setting.rawValue }
            }
        }
        'minutes-or-forever' {
            if ($Setting.rawValue -eq '-1') { return $Ui.UntilManualUnlock }
            return ($Ui.MinutesUnit -f $Setting.rawValue)
        }
        'minutes'  { return ($Ui.MinutesUnit -f $Setting.rawValue) }
        'days'     { return ($Ui.DaysUnit -f $Setting.rawValue) }
        'attempts' { return ($Ui.AttemptsUnit -f $Setting.rawValue) }
        'count'    { return "$($Setting.rawValue)" }
        'principal-list' {
            $members = ConvertTo-PrivilegeMemberList -Value $Setting.rawValue
            if ($members.Count -eq 0) { return $Ui.EmptyPrincipalList }
            return (($members | ForEach-Object { Resolve-PrincipalDisplayName -RawToken $_ }) -join ', ')
        }
        'reg-boolean' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            if ($parsed.Data -eq '1') { return $Ui.StateEnabled }
            if ($parsed.Data -eq '0') { return $Ui.StateDisabled }
            return $parsed.Data
        }
        'reg-number' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            return $parsed.Data
        }
        'reg-string' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            return $parsed.Data
        }
        'reg-multistring' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            $items = @($parsed.Data -split ',' | Where-Object { $_ -ne '' })
            return ($Ui.ElementCountFormat -f $items.Count)
        }
        'reg-enum' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            $choice = @($Setting.choices) | Where-Object { "$($_.value)" -eq $parsed.Data } | Select-Object -First 1
            if ($choice) { return $choice.displayName }
            return $parsed.Data
        }
        'reg-flags' {
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($null -eq $parsed) { return $Setting.rawValue }
            $current = 0
            [void][int]::TryParse($parsed.Data, [ref]$current)
            $setFlags = @(@($Setting.flags) | Where-Object { ($current -band $_.value) -ne 0 } | ForEach-Object { $_.displayName })
            if ($setFlags.Count -eq 0) { return $Ui.NoFlagsSet }
            return ($setFlags -join ', ')
        }
        default { return $Setting.rawValue }
    }
}

function Get-AdmxTechnicalDetailText {
    # "Technical details" panel text for a selected ADMX policy: source
    # ADMX file, full registry key (hive per Machine/User scope) and value
    # name, plus per-element detail (id AND the real value name it writes)
    # and its min/max or max-length bounds when known.
    param($Policy, [string]$Scope, [hashtable]$Ui)

    $hive = if ($Scope -eq 'Machine') { 'HKEY_LOCAL_MACHINE' } else { 'HKEY_CURRENT_USER' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Ui.DetailAdmxFileLabel) : $($Policy.admxFile)")
    $lines.Add("$($Ui.DetailRegistryKeyLabel) : $hive\$($Policy.registryKey)")
    if ($Policy.valueName) {
        $lines.Add("$($Ui.DetailValueNameLabel) : $($Policy.valueName)")
        # Get-InferredRegType (PolicyWriter.ps1, same logic used to actually
        # write the .pol): REG_* type isn't kept as-is in the JSON index, so
        # it's inferred here too from the value's .NET type.
        if ($null -ne $Policy.enabledValue) {
            $enType = Get-RegTypeName (Get-InferredRegType $Policy.enabledValue)
            $lines.Add("$($Ui.DetailEnabledValueLabel) : $($Policy.enabledValue) ($enType)")
        }
        if ($null -ne $Policy.disabledValue) {
            $disType = Get-RegTypeName (Get-InferredRegType $Policy.disabledValue)
            $lines.Add("$($Ui.DetailDisabledValueLabel) : $($Policy.disabledValue) ($disType)")
        }
    }

    foreach ($el in @($Policy.elements)) {
        if (-not $el.valueName) { continue }
        $elKey = if ($el.key) { $el.key } else { $Policy.registryKey }

        $suffix = ''
        if ($el.type -eq 'decimal' -and ($el.minValue -or $el.maxValue)) {
            $suffix = $Ui.DetailMinMaxFormat -f $el.minValue, $el.maxValue
        }
        elseif ($el.type -in @('text', 'multiText') -and $el.maxLength) {
            $suffix = $Ui.DetailMaxLengthFormat -f $el.maxLength
        }

        $elLine = "$($Ui.DetailElementFormat -f $el.id) → $($Ui.DetailValueNameLabel) : $($el.valueName)$suffix"
        if ($elKey -ne $Policy.registryKey) {
            $elLine += " ($($Ui.DetailRegistryKeyLabel) : $hive\$elKey)"
        }
        $lines.Add($elLine)
    }

    return ($lines -join "`r`n")
}

function Get-SecurityTechnicalDetailText {
    # Equivalent for a security setting (backing store secedit.inf):
    # file, INI section and key name, for the same transparency reason.
    param($Setting, [hashtable]$Ui)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Ui.DetailFileLabel) : secedit.inf")
    $lines.Add("$($Ui.DetailSectionLabel) : [$($Setting.section)]")
    $lines.Add("$($Ui.DetailKeyNameLabel) : $($Setting.name)")
    return ($lines -join "`r`n")
}

function Get-AdvancedAuditTechnicalDetailText {
    # Equivalent for an Advanced Audit Policy subcategory: audit.csv file,
    # canonical name (as written in the file, UI-language-independent) and
    # the stable GUID used for matching.
    param($Setting, [hashtable]$Ui)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$($Ui.DetailFileLabel) : audit.csv")
    $lines.Add("$($Ui.DetailKeyNameLabel) : $($Setting.name)")
    $lines.Add("$($Ui.DetailGuidLabel) : $($Setting.guid)")
    return ($lines -join "`r`n")
}
