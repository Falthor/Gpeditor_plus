<#
    Step 6 - Applying changes: merges pending changes (Step 5,
    $script:PendingAdmxChanges / $script:PendingSecurityChanges) into .pol
    entries / the GptTmpl.inf structure, and provides the automatic
    timestamped backup before any real write.

    Key rule for .pol: when a policy goes back to Disabled (no
    disabledValue defined) or Not Configured, simply omitting the entry
    isn't enough - an explicit "**del.<value>" marker is required for
    Windows to delete the existing registry value on next gpupdate (this
    is real gpedit.msc behavior with this format). The marker is only set
    if a value was actually present before the change (no point
    "deleting" what didn't exist).
#>

Set-StrictMode -Off

function Get-InferredRegType {
    # Exact REG_* type of an enabledValue/disabledValue/element value isn't
    # kept in the JSON index (only the resolved value is), so it's inferred
    # from the JSON's .NET type (number -> REG_DWORD, text -> REG_SZ),
    # covering the vast majority of real ADMX (REG_SZ for these fields is rare).
    param($Value)
    if ($null -eq $Value) { return 1 }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [bool]) {
        return 4
    }
    return 1
}

function Merge-PolEntriesForPolicy {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Entries,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$NewState,
        [hashtable]$ElementValues = @{}
    )

    # 1. (Key,ValueName) slots managed by this policy.
    $slots = New-Object System.Collections.Generic.List[object]
    if ($Policy.valueName) {
        $slots.Add([pscustomobject]@{ Key = $Policy.registryKey; ValueName = $Policy.valueName })
    }
    foreach ($el in @($Policy.elements)) {
        if ($el.valueName) {
            $k = if ($el.key) { $el.key } else { $Policy.registryKey }
            $slots.Add([pscustomobject]@{ Key = $k; ValueName = $el.valueName })
        }
    }

    $slotKeySet = @{}
    foreach ($slot in $slots) { $slotKeySet[("$($slot.Key)|$($slot.ValueName)").ToLowerInvariant()] = $true }

    # 2. A slot "had" a real value if a non-marker entry exists for it in
    #    the CURRENT file (before this change).
    $hadValue = @{}
    foreach ($k in $slotKeySet.Keys) { $hadValue[$k] = $false }
    foreach ($e in $Entries) {
        if (Test-PolValueIsDeleteMarker -ValueName $e.ValueName) { continue }
        $ek = ("$($e.KeyName)|$($e.ValueName)").ToLowerInvariant()
        if ($hadValue.ContainsKey($ek)) { $hadValue[$ek] = $true }
    }

    # 3. Removes from the result any entry (real value or delete marker)
    #    already tied to a managed slot - replaced by the new intent below.
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Entries) {
        $directKey = ("$($e.KeyName)|$($e.ValueName)").ToLowerInvariant()
        $isManaged = $slotKeySet.ContainsKey($directKey)
        if (-not $isManaged -and (Test-PolValueIsDeleteMarker -ValueName $e.ValueName)) {
            $targetName = $e.ValueName.Substring(6)
            $isManaged = $slotKeySet.ContainsKey(("$($e.KeyName)|$targetName").ToLowerInvariant())
        }
        if (-not $isManaged) { $kept.Add($e) }
    }

    function Add-ValueOrDelete {
        param($Key, $ValueName, $HadValueKey)
        if ($hadValue[$HadValueKey]) {
            $kept.Add((New-PolDeleteValueEntry -KeyName $Key -ValueName $ValueName))
        }
    }

    switch ($NewState) {
        'Enabled' {
            if ($Policy.valueName) {
                $type = Get-InferredRegType $Policy.enabledValue
                $kept.Add((New-PolEntry -KeyName $Policy.registryKey -ValueName $Policy.valueName -Type $type -Value $Policy.enabledValue))
            }
            foreach ($el in @($Policy.elements)) {
                if (-not $el.valueName) { continue }
                $k = if ($el.key) { $el.key } else { $Policy.registryKey }
                $hk = ("$k|$($el.valueName)").ToLowerInvariant()
                $val = $null
                if ($ElementValues.ContainsKey($el.id)) { $val = $ElementValues[$el.id] }

                switch ($el.type) {
                    'boolean' {
                        $isChecked = [bool]$val
                        if ($isChecked) {
                            if ($null -ne $el.trueValue) {
                                $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type (Get-InferredRegType $el.trueValue) -Value $el.trueValue))
                            }
                            else {
                                $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type 4 -Value 1))
                            }
                        }
                        else {
                            if ($null -ne $el.falseValue) {
                                $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type (Get-InferredRegType $el.falseValue) -Value $el.falseValue))
                            }
                            else {
                                Add-ValueOrDelete -Key $k -ValueName $el.valueName -HadValueKey $hk
                            }
                        }
                    }
                    'enum' {
                        if ($null -ne $val) {
                            $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type (Get-InferredRegType $val) -Value $val))
                        }
                    }
                    'decimal' {
                        if ($null -ne $val) {
                            $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type 4 -Value ([int]$val)))
                        }
                    }
                    'text' {
                        $t = if ($el.expandable) { 2 } else { 1 }
                        $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type $t -Value "$val"))
                    }
                    'multiText' {
                        $kept.Add((New-PolEntry -KeyName $k -ValueName $el.valueName -Type 7 -Value @($val)))
                    }
                    'list' {
                        $i = 0
                        foreach ($line in @($val)) {
                            if ([string]::IsNullOrEmpty($line)) { continue }
                            $i++
                            if ($el.explicitValue -and $line -match '^(?<n>[^=]+)=(?<v>.*)$') {
                                $kept.Add((New-PolEntry -KeyName $k -ValueName $Matches['n'].Trim() -Type 1 -Value $Matches['v']))
                            }
                            else {
                                $kept.Add((New-PolEntry -KeyName $k -ValueName "$i" -Type 1 -Value $line))
                            }
                        }
                    }
                }
            }
        }
        'Disabled' {
            if ($Policy.valueName) {
                if ($null -ne $Policy.disabledValue) {
                    $type = Get-InferredRegType $Policy.disabledValue
                    $kept.Add((New-PolEntry -KeyName $Policy.registryKey -ValueName $Policy.valueName -Type $type -Value $Policy.disabledValue))
                }
                else {
                    Add-ValueOrDelete -Key $Policy.registryKey -ValueName $Policy.valueName -HadValueKey ("$($Policy.registryKey)|$($Policy.valueName)").ToLowerInvariant()
                }
            }
            foreach ($el in @($Policy.elements)) {
                if (-not $el.valueName) { continue }
                $k = if ($el.key) { $el.key } else { $Policy.registryKey }
                Add-ValueOrDelete -Key $k -ValueName $el.valueName -HadValueKey ("$k|$($el.valueName)").ToLowerInvariant()
            }
        }
        'NotConfigured' {
            if ($Policy.valueName) {
                Add-ValueOrDelete -Key $Policy.registryKey -ValueName $Policy.valueName -HadValueKey ("$($Policy.registryKey)|$($Policy.valueName)").ToLowerInvariant()
            }
            foreach ($el in @($Policy.elements)) {
                if (-not $el.valueName) { continue }
                $k = if ($el.key) { $el.key } else { $Policy.registryKey }
                Add-ValueOrDelete -Key $k -ValueName $el.valueName -HadValueKey ("$k|$($el.valueName)").ToLowerInvariant()
            }
        }
    }

    return , $kept
}

function Invoke-AdmxChangeToEntry {
    # Applies all pending changes for a given scope (Machine or User) to a list of .pol entries, one by one.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Entries,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$PendingChanges,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)]$PoliciesById
    )

    # NB: local var must differ from -Scope by more than case - PowerShell
    # var names are case-insensitive, so "$scope = ..." would silently
    # shadow the -Scope parameter.
    $result = $Entries
    foreach ($pendingKey in $PendingChanges.Keys) {
        $parts = $pendingKey -split '\|', 2
        $policyId = $parts[0]
        $entryScope = $parts[1]
        if ($entryScope -ne $Scope) { continue }
        if (-not $PoliciesById.ContainsKey($policyId)) { continue }

        $policy = $PoliciesById[$policyId]
        $change = $PendingChanges[$pendingKey]
        $result = Merge-PolEntriesForPolicy -Entries $result -Policy $policy -NewState $change.State -ElementValues $change.ElementValues
    }
    return , $result
}

function Invoke-SecurityChangeToGpt {
    # Applies pending security changes to the GptTmpl.inf structure
    # (see GptTmplFile.ps1 for Set-GptTmplValue/Remove-GptTmplValue).
    param(
        [Parameter(Mandatory)]$GptTmpl,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$PendingChanges,
        [Parameter(Mandatory)]$SettingsById
    )

    foreach ($settingId in $PendingChanges.Keys) {
        if (-not $SettingsById.ContainsKey($settingId)) { continue }
        $setting = $SettingsById[$settingId]
        $pending = $PendingChanges[$settingId]
        if ($pending.IsConfigured) {
            Set-GptTmplValue -GptTmpl $GptTmpl -Section $setting.section -Key $setting.name -Value $pending.Value
        }
        else {
            Remove-GptTmplValue -GptTmpl $GptTmpl -Section $setting.section -Key $setting.name
        }
    }
    return $GptTmpl
}

function New-TimestampedBackup {
    # Timestamped backup of affected files before the real write (plan
    # Step 3.5/6). $FilesToBackup: hashtable Tag -> source path (Tag is
    # used as the backup filename, to avoid collisions between Machine and
    # User registry.pol which share the same filename).
        [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$FilesToBackup,
        [Parameter(Mandatory)][string]$BackupRoot
    )
    if ($PSCmdlet.ShouldProcess('New-TimestampedBackup', 'Invoke')) {

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dest = Join-Path $BackupRoot $stamp
    New-Item -ItemType Directory -Path $dest -Force | Out-Null

    $copied = New-Object System.Collections.Generic.List[string]
    foreach ($tag in $FilesToBackup.Keys) {
        $src = $FilesToBackup[$tag]
        if (Test-Path -LiteralPath $src) {
            $destFile = Join-Path $dest $tag
            Copy-Item -LiteralPath $src -Destination $destFile -Force
            $copied.Add($destFile)
        }
    }
    # No unary comma needed here: a plain assignment inside a hashtable
    # literal doesn't enumerate the collection (unlike a return/pipeline
    # output) - adding one would wrap the array in a single-element array,
    # breaking .Count.
    return [pscustomobject]@{ BackupDir = $dest; Files = @($copied) }

    }
}
