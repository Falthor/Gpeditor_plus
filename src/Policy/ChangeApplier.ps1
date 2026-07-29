<#
    Step 6 - Real writes, live (like real gpedit.msc: every OK click writes
    immediately to registry.pol / GptTmpl.inf, no separate "Save" step).
    This live model only applies in real-machine mode: in project mode
    (New/Open Group Policy), GpEdit.ps1 redirects these same writes to temp
    files and only writes to the project folder on an explicit "Save now"
    (see Save-GpoProjectChanges in GpEdit.ps1).

    Backup: one timestamped backup per session (on the very first write),
    capturing file state before any change - enough for a full manual
    rollback by copying the backed-up files back.

    Requires admin rights to write under
    C:\Windows\System32\GroupPolicy\... (folder ACL restricts write to
    Administrators/SYSTEM). Auto-elevation is Step 8's job; here, a
    rights failure is detected and reported clearly instead of crashing.
#>

Set-StrictMode -Off

function Test-IsRunningAsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsUacEnabled {
    # Missing key = UAC active (Windows default since Vista); only an
    # explicit EnableLUA=0 disables UAC.
    $prop = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
    if ($null -eq $prop) { return $true }
    return ($prop.EnableLUA -ne 0)
}

function Save-AdmxChangeToFile {
    # Merges ONE ADMX policy change into the scope's registry.pol and writes
    # it immediately, then bumps GPT.ini - unless $GptIniPath is empty/omitted:
    # a "New/Open Group Policy" project doesn't persist a GPT.ini (explicit
    # choice) and nothing reads its version, so only the real System32
    # GPT.ini (real-machine mode) needs the bump, for gpupdate/gpsvc to
    # detect the change. Returns the new entries to refresh the in-memory
    # lookup without re-reading the file.
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$NewState,
        [hashtable]$ElementValues = @{},
        [Parameter(Mandatory)][string]$PolPath,
        [string]$GptIniPath
    )

    $entries = Get-PolFileEntriesSafe -Path $PolPath
    $newEntries = Merge-PolEntriesForPolicy -Entries $entries -Policy $Policy -NewState $NewState -ElementValues $ElementValues
    Write-PolFile -Path $PolPath -Entries $newEntries

    if ($GptIniPath) {
        $gptIni = Read-GptIni -Path $GptIniPath
        Step-GptIniVersion -GptIni $gptIni -IncrementMachine:($Scope -eq 'Machine') -IncrementUser:($Scope -eq 'User') | Out-Null
        Write-GptIni -Path $GptIniPath -GptIni $gptIni
    }

    return , $newEntries
}

function Save-SecurityChangeToFile {
    # Applies ONE security setting change to secedit.inf and writes it
    # immediately. Unlike other categories, this write does NOT touch
    # GPT.ini: these settings no longer go through the local GPO mechanism
    # (System32 GptTmpl.inf) - the real system apply happens later, once,
    # via `secedit /import` + `/configure` on app close (see
    # Invoke-SecEditInfApply below).
    param(
        [Parameter(Mandatory)][string]$SettingSection,
        [Parameter(Mandatory)][string]$SettingName,
        [Parameter(Mandatory)][bool]$IsConfigured,
        $Value,
        [Parameter(Mandatory)][string]$SecEditInfPath
    )

    $gpt = Read-GptTmplInf -Path $SecEditInfPath
    if ($IsConfigured) {
        Set-GptTmplValue -GptTmpl $gpt -Section $SettingSection -Key $SettingName -Value $Value
    }
    else {
        Remove-GptTmplValue -GptTmpl $gpt -Section $SettingSection -Key $SettingName
    }
    Write-GptTmplInf -Path $SecEditInfPath -GptTmpl $gpt
}

function Save-AdvancedAuditChangeToFile {
    # Applies ONE Advanced Audit Policy subcategory change to audit.csv and
    # writes it immediately (always Machine scope). Empty/omitted
    # $GptIniPath skips the GPT.ini bump - see Save-AdmxChangeToFile above
    # (not needed in project mode).
    param(
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$IsConfigured,
        $Value,
        [Parameter(Mandatory)][string]$AuditCsvPath,
        [string]$GptIniPath
    )

    $rows = Read-AuditCsv -Path $AuditCsvPath
    if ($IsConfigured) {
        Set-AuditCsvValue -Rows $rows -Guid $Guid -SubcategoryName $Name -SettingValue ([int]$Value)
    }
    else {
        Remove-AuditCsvValue -Rows $rows -Guid $Guid
    }
    Write-AuditCsv -Path $AuditCsvPath -Rows $rows

    if ($GptIniPath) {
        $gptIni = Read-GptIni -Path $GptIniPath
        Step-GptIniVersion -GptIni $gptIni -IncrementMachine | Out-Null
        Write-GptIni -Path $GptIniPath -GptIni $gptIni
    }
}

function Invoke-SecEditInfExport {
    # Captures the EFFECTIVE system security state into secedit.inf via the
    # secedit engine itself, rather than hand-managing a GptTmpl.inf. Called
    # on EVERY app launch, before building the security index, so state is
    # never stale. No admin rights needed (read-only).
    param([Parameter(Mandatory)][string]$SecEditInfPath)

    $dir = Split-Path -Parent $SecEditInfPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $output = & secedit.exe /export /cfg $SecEditInfPath /quiet 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Remove-TattooedRegistryValues {
    # secedit /configure NEVER clears a registry value just because it's
    # absent from the imported .cfg - known SCE/Windows "tattooing" behavior
    # (same in real gpedit.msc/secpol.msc for raw-registry-key settings),
    # not a limitation of this app. Without this explicit cleanup,
    # unchecking "Define this policy setting" for a [Registry Values]
    # setting removes the line from secedit.inf but leaves the old value in
    # the real registry forever. Compares [Registry Values] keys present at
    # the session's first export ($BaselineKeys) against those remaining in
    # the current secedit.inf: any key that disappeared was unchecked by the
    # user this session and must be removed directly.
    #
    # [Privilege Rights]/[System Access]/[Event Audit] don't have this
    # problem - secedit manages those entirely via SAM/LSA, no isolated
    # registry key to clean up - so out of scope here.
    param(
        [Parameter(Mandatory)][string]$SecEditInfPath,
        [Parameter(Mandatory)][hashtable]$BaselineKeys
    )

    if ($BaselineKeys.Count -eq 0) { return , @() }

    $currentGpt = Read-GptTmplInf -Path $SecEditInfPath
    $currentKeys = if ($currentGpt.Sections.Contains('Registry Values')) { $currentGpt.Sections['Registry Values'] } else { $null }

    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($key in $BaselineKeys.Keys) {
        if ($currentKeys -and $currentKeys.Contains($key)) { continue }

        # Expected format: "MACHINE\<registry path>\<value name>"
        # (see Get-SecurityCatalogEntries, SecurityCatalog.ps1).
        if ($key -notmatch '^(MACHINE|USER)\\(.+)\\([^\\]+)$') { continue }
        $hive = if ($Matches[1] -eq 'USER') { 'HKCU:' } else { 'HKLM:' }
        $regPath = $Matches[2]
        $valueName = $Matches[3]
        $fullPath = Join-Path $hive $regPath

        if (Test-Path -LiteralPath $fullPath) {
            Remove-ItemProperty -LiteralPath $fullPath -Name $valueName -Force -ErrorAction SilentlyContinue
        }
        $removed.Add($key)
    }

    return , $removed
}

function Invoke-SecEditInfApply {
    # Actually applies secedit.inf's current content to the system
    # (registry/LSA/SAM), once, on app close: /import loads the file into a
    # temp secedit working db ($env:TEMP), /configure applies it. /overwrite
    # is needed because the temp db may already exist from a previous
    # session - without it /import would merge instead of starting fresh
    # from secedit.inf. Requires admin rights: caller must check
    # (Test-IsRunningAsAdministrator) BEFORE calling. Optional
    # $RegistryValuesBaselineKeys triggers Remove-TattooedRegistryValues
    # before import - see its comment for why.
    param(
        [Parameter(Mandatory)][string]$SecEditInfPath,
        [hashtable]$RegistryValuesBaselineKeys = @{}
    )

    if ($RegistryValuesBaselineKeys.Count -gt 0) {
        Remove-TattooedRegistryValues -SecEditInfPath $SecEditInfPath -BaselineKeys $RegistryValuesBaselineKeys | Out-Null
    }

    $sdbPath = Join-Path $env:TEMP 'gpedit-security.sdb'

    $importOutput = & secedit.exe /import /db $sdbPath /cfg $SecEditInfPath /overwrite /quiet 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $importOutput }
    }

    $configureOutput = & secedit.exe /configure /db $sdbPath /quiet 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($importOutput + $configureOutput) }
}
