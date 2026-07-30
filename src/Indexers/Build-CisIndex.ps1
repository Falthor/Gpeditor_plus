<#
    Indexes CIS (Center for Internet Security) recommendations for Windows
    Server from .audit files (Tenable Nessus format) in the "Audit file"
    folder. Produces a single JSON index (cis-index.json) grouping, per
    covered setting, the shared description/info and the list of
    recommendations per profile (benchmark, version, L1/L2 level, MS/DC role).

    Like Build-AdmxIndex.ps1, GpEdit.ps1 now invokes this script
    automatically at startup if the Audit files folder fingerprint
    (AuditFilesFingerprint.ps1) no longer matches meta.sourceFingerprint -
    covering both Options-window changes and direct folder manipulation.
#>
param(
    [string]$AuditFilesPath = (Join-Path $PSScriptRoot '..\..\Audit file'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\Data\cis-index.json'),
    # Audit files folder fingerprint (see AuditFilesFingerprint.ps1), stored
    # in meta.sourceFingerprint so GpEdit.ps1 can skip regeneration when
    # nothing changed since the last index.
    [string]$SourceFingerprint = ''
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
# Dot-sourced only to reuse Get-CisOverrides (reads data/cis-overrides.json,
# see below) - CisCatalog.ps1 enables Set-StrictMode -Version Latest, so
# disable it again right after to avoid changing the rest of this script's behavior.
. (Join-Path $PSScriptRoot '..\Catalogs\CisCatalog.ps1')
Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Extracts "key : value" fields inside a <custom_item> block
# ---------------------------------------------------------------------------
function Get-CisField {
    param([string]$BlockText, [string]$FieldName)

    # Lookahead for the "next field key" requires at least one indentation
    # space (all real field keys in the block have one, e.g.
    # "      info        :"). Without this guard, a free-text pseudo-label
    # at the start of a line (e.g. "Note:", "Caution:", "Impact:", common in
    # info/solution, always at column 0 in these files) gets mistaken for
    # the end of the current field, silently truncating real text (real bug
    # found while checking extraction of "The recommended state for this
    # setting is:" - missing from "info" for ~20 entries due to this truncation).
    $pattern = "(?ms)^\s*$FieldName\s*:\s*(.+?)(?=\r?\n[ \t]+[a-zA-Z_]+\s*:|\z)"
    $m = [regex]::Match($BlockText, $pattern)
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.Trim().Trim('"').Trim()
}

# ---------------------------------------------------------------------------
# File header: <spec> (benchmark/version/profile) and <variables>
# ---------------------------------------------------------------------------
function Get-CisSpec {
    param([string]$Text)

    $m = [regex]::Match($Text, '(?s)<spec>.*?<name>(?<name>.*?)</name>.*?<profile>(?<profile>.*?)</profile>.*?<version>(?<version>.*?)</version>.*?</spec>')
    if (-not $m.Success) { return $null }

    $profileParts = $m.Groups['profile'].Value.Trim() -split '\s+'
    return [ordered]@{
        benchmark = $m.Groups['name'].Value.Trim()
        version   = $m.Groups['version'].Value.Trim()
        level     = $profileParts[0]
        role      = if ($profileParts.Count -gt 1) { $profileParts[1] } else { $null }
    }
}

function Get-CisVariables {
    param([string]$Text)

    $vars = @{}
    foreach ($vm in [regex]::Matches($Text, '(?s)<variable>(.*?)</variable>')) {
        $body = $vm.Groups[1].Value
        $nameM = [regex]::Match($body, '(?s)<name>(.*?)</name>')
        $defM = [regex]::Match($body, '(?s)<default>(.*?)</default>')
        if ($nameM.Success -and $defM.Success) {
            $vars[$nameM.Groups[1].Value.Trim()] = $defM.Groups[1].Value.Trim()
        }
    }
    return $vars
}

function Resolve-CisValueData {
    param([string]$Raw, [hashtable]$Variables)

    if ([string]::IsNullOrEmpty($Raw)) { return $Raw }
    $resolved = [regex]::Replace($Raw, '@([A-Za-z0-9_]+)@', {
        param($m)
        $name = $m.Groups[1].Value
        if ($Variables.ContainsKey($name)) { return $Variables[$name] }
        return $m.Value
    })
    # Normalizes each "A" || "B" alternative by stripping quotes around each
    # segment while keeping the "||" separator: final display ("A or B") is
    # done by the UI, not here, to avoid baking a language into the index.
    $segments = $resolved -split '\s*\|\|\s*' | ForEach-Object { $_.Trim().Trim('"').Trim() }
    return ($segments -join ' || ')
}

function Get-CisRecommendedStateText {
    # In the "info" field (multi-paragraph text separated by a blank line),
    # extracts the portion following "The recommended state for this
    # setting is:" - same sentence bolded in the CIS recommendation tab
    # (EditDialogs.ps1, Add-CisInfoParagraph). Verbatim (no trailing
    # punctuation stripped): feeds the "CIS States" column of the main grid.
    param([string]$Info)

    # The ":" isn't always present ("is: Enabled" vs "is Enabled"), and the
    # sentence isn't always at line start (sometimes chained after the
    # previous sentence) - but each "info" paragraph is a single source line
    # not manually wrapped, so capturing to end of line (multiline mode, $ =
    # end of line) catches the full recommended-state text either way; the
    # optional trailing period is excluded from the capture group (never
    # part of the value). Variant seen in User Rights Assignment: "...for
    # this setting on Domain Controllers is: ..." / "...on Member Servers is: ...".
    # Stops at the first sentence end (". " or trailing ".") rather than end
    # of line: some items (e.g. "Configure NetBIOS settings", "Password
    # Settings: Password Complexity") chain a second sentence ("...
    # Configuring this setting to X also conforms to the benchmark.") on the
    # same source line without a paragraph break - stopping at end of line
    # would capture that extra sentence too.
    if ([string]::IsNullOrEmpty($Info)) { return $null }
    $m = [regex]::Match($Info, 'The recommended state for this (?:policy )?setting(?: on [A-Za-z ]+?)? is\s*:?\s*(?<state>.+?)(?:\.(?=\s|$)|\r?\n|$)')
    if (-not $m.Success) { return $null }
    $state = $m.Groups['state'].Value.Trim()

    # Some "X or higher" items chain a fixed equivalence clause
    # ("Configuring this setting to Y also conforms to the benchmark") right
    # after the recommended value, on the same source line - in at least one
    # file (2016) without a separating period, which breaks the rule above.
    # Fixed CIS benchmark wording: safe to strip even without punctuation.
    $state = $state -replace '\s+Configuring this setting to .+? also conforms to the benchmark\.?\s*$', ''
    return $state.Trim()
}

function ConvertTo-CisNumberAndTitle {
    param([string]$Description)

    if ([string]::IsNullOrEmpty($Description)) { return $null }
    $m = [regex]::Match($Description, '^(?<num>\d+(\.\d+)*)\s+(?<title>.+)$')
    if (-not $m.Success) { return $null }

    # Some files (e.g. 2016) prefix the title with "(L1) "/"(L2) " -
    # redundant with the "level" field already carried by the profile,
    # stripped so the title stays identical across benchmark versions.
    $title = $m.Groups['title'].Value -replace '^\(L\d\)\s*', ''
    return [ordered]@{ cisNumber = $m.Groups['num'].Value; title = $title.Trim() }
}

# ---------------------------------------------------------------------------
# Match key per control type (see plan-gpedit-cis.md §4)
# ---------------------------------------------------------------------------
function Get-CisMatchKey {
    param([string]$Type, [string]$RegKey, [string]$RegItem, [string]$PasswordPolicy, [string]$LockoutPolicy, [string]$RightType, [string]$AuditSubcategory)

    switch ($Type) {
        'REGISTRY_SETTING' {
            if (-not $RegKey -or -not $RegItem) { return $null }
            $normKey = ($RegKey -replace '^HKLM\\', '').ToLowerInvariant()
            return [ordered]@{ bucket = 'byRegistry'; key = "$normKey|$($RegItem.ToLowerInvariant())" }
        }
        'REG_CHECK' {
            # Same byRegistry match as REGISTRY_SETTING, but REG_CHECK names
            # its fields the other way round: "value_data" carries the
            # registry PATH and "key_item" the value NAME (caller passes
            # them in as -RegKey/-RegItem already swapped accordingly - see
            # Read-CisAuditFile). Confirmed against real .audit entries
            # (e.g. 18.9.19.5/.7 "Turn off background refresh of Group
            # Policy": value_data = "HKLM\...\Policies\System", key_item =
            # "DisableBkGndGroupPolicy").
            if (-not $RegKey -or -not $RegItem) { return $null }
            $normKey = ($RegKey -replace '^HKLM\\', '').ToLowerInvariant()
            return [ordered]@{ bucket = 'byRegistry'; key = "$normKey|$($RegItem.ToLowerInvariant())" }
        }
        'PASSWORD_POLICY' {
            if (-not $PasswordPolicy) { return $null }
            return [ordered]@{ bucket = 'byPasswordPolicy'; key = $PasswordPolicy }
        }
        'LOCKOUT_POLICY' {
            if (-not $LockoutPolicy) { return $null }
            return [ordered]@{ bucket = 'byLockoutPolicy'; key = $LockoutPolicy }
        }
        'USER_RIGHTS_POLICY' {
            if (-not $RightType) { return $null }
            return [ordered]@{ bucket = 'byUserRight'; key = $RightType }
        }
        'AUDIT_POLICY_SUBCATEGORY' {
            if (-not $AuditSubcategory) { return $null }
            return [ordered]@{ bucket = 'byAuditSubcategory'; key = $AuditSubcategory }
        }
        default { return $null }
    }
}

# ---------------------------------------------------------------------------
# Processing of a single .audit file
# ---------------------------------------------------------------------------
function Add-CisTitleFallbackCandidate {
    # Records a numbered CIS entry that couldn't get a primary match key
    # (REG_CHECK missing value_data/key_item, or ANONYMOUS_SID_SETTING -
    # which never carries a location field, see Get-CisMatchKey) so it can
    # be resolved after all files are read, via cis-fallback-map.json - see
    # Resolve-CisTitleFallbackCandidates below.
    param(
        [System.Collections.Generic.List[object]]$Candidates,
        [string]$Title,
        [string]$Info,
        [string]$ValueType,
        $Spec,
        [string]$CisNumber
    )
    # Keyed by the extracted setting name (Get-CisSettingNameFromTitle), not
    # the whole CIS sentence: at runtime the app only has a bare
    # SecurityCatalog/ADMX DisplayName to look up with (see
    # Get-CisRecommendationForSecuritySetting's byTitle fallback), never the
    # full "Ensure '...' is set to '...'" phrasing.
    $normalizedTitle = ConvertTo-CisNormalizedTitle -Title (Get-CisSettingNameFromTitle -Title $Title)
    if (-not $normalizedTitle) { return }
    # [pscustomobject], not a plain hashtable: Group-Object -Property below
    # (Resolve-CisTitleFallbackCandidates) only resolves real object
    # properties, not hashtable keys - a hashtable here would silently
    # group everything under one empty-name bucket.
    $Candidates.Add([pscustomobject]@{
        NormalizedTitle = $normalizedTitle
        Title     = $Title
        Info      = $Info
        ValueType = $ValueType
        Spec      = $Spec
        CisNumber = $CisNumber
    })
}

function Read-CisAuditFile {
    param([string]$Path, [System.Collections.IDictionary]$Index, [hashtable]$Counters, [System.Collections.Generic.List[object]]$TitleFallbackCandidates)

    $text = Get-Content -Raw -LiteralPath $Path
    $spec = Get-CisSpec -Text $text
    if ($null -eq $spec) {
        Write-Warning "<spec> block not found, file skipped: $Path"
        return
    }
    $variables = Get-CisVariables -Text $text

    foreach ($blockMatch in [regex]::Matches($text, '(?s)<custom_item>(.*?)</custom_item>')) {
        $body = $blockMatch.Groups[1].Value
        $type = Get-CisField -BlockText $body -FieldName 'type'
        $description = Get-CisField -BlockText $body -FieldName 'description'
        $numberAndTitle = ConvertTo-CisNumberAndTitle -Description $description
        if ($null -eq $numberAndTitle) { continue }

        # REG_CHECK names its location fields the other way round from
        # REGISTRY_SETTING: "value_data" is the registry path and
        # "key_item" the value name (see Get-CisMatchKey's 'REG_CHECK'
        # case) - read the right pair depending on type.
        if ($type -eq 'REG_CHECK') {
            $regKey = Get-CisField -BlockText $body -FieldName 'value_data'
            $regItem = Get-CisField -BlockText $body -FieldName 'key_item'
        }
        else {
            $regKey = Get-CisField -BlockText $body -FieldName 'reg_key'
            $regItem = Get-CisField -BlockText $body -FieldName 'reg_item'
        }
        $passwordPolicy = Get-CisField -BlockText $body -FieldName 'password_policy'
        $lockoutPolicy = Get-CisField -BlockText $body -FieldName 'lockout_policy'
        $rightType = Get-CisField -BlockText $body -FieldName 'right_type'
        $auditSubcategory = Get-CisField -BlockText $body -FieldName 'audit_policy_subcategory'

        $matchKey = Get-CisMatchKey -Type $type -RegKey $regKey -RegItem $regItem -PasswordPolicy $passwordPolicy -LockoutPolicy $lockoutPolicy -RightType $rightType -AuditSubcategory $auditSubcategory
        if ($null -eq $matchKey) {
            if ($type -eq 'REG_CHECK' -or $type -eq 'ANONYMOUS_SID_SETTING') {
                # Deferred, not counted as Skipped yet - the title-fallback
                # pass (after all files are read) may still resolve it via
                # cis-fallback-map.json into the byTitle bucket; only what's
                # still unresolved after that pass is counted as Skipped.
                Add-CisTitleFallbackCandidate -Candidates $TitleFallbackCandidates -Title $numberAndTitle.title -Info (Get-CisField -BlockText $body -FieldName 'info') -ValueType (Get-CisField -BlockText $body -FieldName 'value_type') -Spec $spec -CisNumber $numberAndTitle.cisNumber
                continue
            }
            $Counters.Skipped++
            continue
        }

        # Fetched unconditionally (not just on first occurrence): needed
        # below for every REG_CHECK profile's valueData, not only to seed a
        # newly-created bucket entry.
        $info = Get-CisField -BlockText $body -FieldName 'info'

        $bucket = $Index[$matchKey.bucket]
        if (-not $bucket.Contains($matchKey.key)) {
            $bucket[$matchKey.key] = [ordered]@{
                bucket   = $matchKey.bucket
                key      = $matchKey.key
                title    = $numberAndTitle.title
                info     = $info
                recommendedStateText = Get-CisRecommendedStateText -Info $info
                valueType = Get-CisField -BlockText $body -FieldName 'value_type'
                regKey   = $regKey
                regItem  = $regItem
                profiles = New-Object System.Collections.Generic.List[object]
            }
            $Counters.Entries++
        }

        # For REG_CHECK, "value_data" was already consumed above as the
        # registry PATH (regKey), not the recommended value - there is no
        # per-profile recommended value to resolve for this type from the
        # .audit file itself the way REGISTRY_SETTING has one. Falling back
        # to $null here would silently break the CIS Yes/No column, the CIS
        # R. Value column and profile filtering (Get-CisRecommendationValueForProfile/
        # Test-CisProfileFilterMatch in GpEdit.ps1 all treat an empty
        # valueData as "no recommendation for this profile") - use this
        # profile's own recommendedStateText ("Disabled"/"Enabled", from its
        # own "info" above) as the value instead.
        $rawValueData = if ($type -eq 'REG_CHECK') { $null } else { Get-CisField -BlockText $body -FieldName 'value_data' }
        $valueData = Resolve-CisValueData -Raw $rawValueData -Variables $variables
        if ($type -eq 'REG_CHECK' -and [string]::IsNullOrEmpty($valueData)) {
            $valueData = Get-CisRecommendedStateText -Info $info
        }

        $bucket[$matchKey.key].profiles.Add([ordered]@{
            benchmark = $spec.benchmark
            version   = $spec.version
            level     = $spec.level
            role      = $spec.role
            cisNumber = $numberAndTitle.cisNumber
            valueData = $valueData
        })
        $Counters.Profiles++
    }
}

# ---------------------------------------------------------------------------
# Title-fallback resolution (cis-fallback-map.json): second-chance matching
# for entries collected above with no usable location field. Populates the
# byTitle bucket and non-destructively completes cis-fallback-map.json with
# what it can auto-resolve, leaving the rest flagged needsManualReview.
# ---------------------------------------------------------------------------

function Resolve-CisTitleAutomatically {
    <#
        Best-effort auto-resolution of a CIS title with no usable location
        field in the .audit file: matched against Data_SecurityCatalog.json
        (SecurityOptionsRegistryCatalog - the only section with a real
        RegistryPath/ValueName) then the ADMX index, both by simple
        substring containment - CIS titles literally wrap the catalog's
        DisplayName in quotes (e.g. "Ensure '<DisplayName>' is set to ...").
        Only an UNAMBIGUOUS single match (across both sources combined) is
        accepted; 0 or 2+ candidates leave the entry unresolved
        (needsManualReview) rather than risk pairing the wrong setting.
    #>
    param([string]$NormalizedTitle, [string]$SecurityCatalogPath, [string]$AdmxIndexPath, [string]$ValueType)

    $candidates = New-Object System.Collections.Generic.List[object]

    if (Test-Path -LiteralPath $SecurityCatalogPath) {
        try {
            $catalog = Get-Content -Raw -Encoding UTF8 -LiteralPath $SecurityCatalogPath | ConvertFrom-Json
            foreach ($entry in @($catalog.SecurityOptionsRegistryCatalog)) {
                if (-not $entry.DisplayName -or -not $entry.RegistryPath -or -not $entry.ValueName) { continue }
                if ($NormalizedTitle.Contains($entry.DisplayName.ToLowerInvariant())) {
                    $candidates.Add([ordered]@{ source = 'securitycatalog'; regKey = $entry.RegistryPath; regItem = $entry.ValueName })
                }
            }
        }
        catch { Write-Warning "Security catalog unreadable during CIS fallback resolution ($SecurityCatalogPath): $($_.Exception.Message)" }
    }

    if (Test-Path -LiteralPath $AdmxIndexPath) {
        try {
            $admx = Get-Content -Raw -Encoding UTF8 -LiteralPath $AdmxIndexPath | ConvertFrom-Json
            foreach ($pol in @($admx.policies)) {
                if (-not $pol.displayName -or -not $pol.registryKey -or -not $pol.valueName) { continue }
                if ($NormalizedTitle.Contains($pol.displayName.ToLowerInvariant())) {
                    $candidates.Add([ordered]@{ source = 'admx'; regKey = $pol.registryKey; regItem = $pol.valueName })
                }
            }
        }
        catch { Write-Warning "ADMX index unreadable during CIS fallback resolution ($AdmxIndexPath): $($_.Exception.Message)" }
    }

    if ($candidates.Count -eq 1) {
        $c = $candidates[0]
        return [ordered]@{ source = $c.source; regKey = $c.regKey; regItem = $c.regItem; valueType = $ValueType; valueMap = $null; needsManualReview = $false }
    }
    return $null
}

function Resolve-CisTitleFallbackCandidates {
    param(
        [System.Collections.Generic.List[object]]$Candidates,
        [System.Collections.IDictionary]$Index,
        [hashtable]$Counters,
        [hashtable]$FallbackMap,
        [string]$SecurityCatalogPath,
        [string]$AdmxIndexPath
    )

    $Counters.NeedsManualReview = 0
    $fallbackMapDirty = $false

    foreach ($group in ($Candidates | Group-Object -Property NormalizedTitle)) {
        $normTitle = $group.Name
        $first = $group.Group[0]

        $fbEntry = $null
        if ($FallbackMap.ContainsKey($normTitle)) {
            if (-not $FallbackMap[$normTitle].needsManualReview) { $fbEntry = $FallbackMap[$normTitle] }
        }
        else {
            $resolved = Resolve-CisTitleAutomatically -NormalizedTitle $normTitle -SecurityCatalogPath $SecurityCatalogPath -AdmxIndexPath $AdmxIndexPath -ValueType $first.ValueType
            if ($resolved) {
                $FallbackMap[$normTitle] = $resolved
                $fbEntry = $resolved
            }
            else {
                $FallbackMap[$normTitle] = [ordered]@{ source = 'manual'; regKey = $null; regItem = $null; valueType = $first.ValueType; valueMap = $null; needsManualReview = $true }
            }
            $fallbackMapDirty = $true
        }

        if ($null -eq $fbEntry) {
            $Counters.NeedsManualReview++
            $Counters.Skipped += $group.Group.Count
            continue
        }

        $Index.byTitle[$normTitle] = [ordered]@{
            bucket   = 'byTitle'
            key      = $normTitle
            title    = $first.Title
            info     = $first.Info
            recommendedStateText = Get-CisRecommendedStateText -Info $first.Info
            valueType = $fbEntry.valueType
            regKey   = $fbEntry.regKey
            regItem  = $fbEntry.regItem
            profiles = New-Object System.Collections.Generic.List[object]
        }
        $Counters.Entries++

        foreach ($cand in $group.Group) {
            $stateText = Get-CisRecommendedStateText -Info $cand.Info
            $valueData = $null
            if ($fbEntry.valueMap -and $stateText -and $fbEntry.valueMap.PSObject.Properties[$stateText]) {
                $valueData = $fbEntry.valueMap.$stateText
            }
            $Index.byTitle[$normTitle].profiles.Add([ordered]@{
                benchmark = $cand.Spec.benchmark
                version   = $cand.Spec.version
                level     = $cand.Spec.level
                role      = $cand.Spec.role
                cisNumber = $cand.CisNumber
                valueData = $valueData
            })
            $Counters.Profiles++
        }
    }

    return $fallbackMapDirty
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $AuditFilesPath)) {
    throw "Audit files folder not found: $AuditFilesPath"
}

$files = Get-ChildItem -LiteralPath $AuditFilesPath -Filter 'CIS_Microsoft_Windows_*.audit' | Sort-Object Name
if ($files.Count -eq 0) {
    throw "No CIS_Microsoft_Windows_*.audit file found in $AuditFilesPath"
}

$index = [ordered]@{
    byRegistry         = [ordered]@{}
    byPasswordPolicy   = [ordered]@{}
    byLockoutPolicy    = [ordered]@{}
    byUserRight        = [ordered]@{}
    byAuditSubcategory = [ordered]@{}
    byTitle            = [ordered]@{}
}
$counters = @{ Entries = 0; Profiles = 0; Skipped = 0 }
$titleFallbackCandidates = New-Object System.Collections.Generic.List[object]

foreach ($f in $files) {
    Read-CisAuditFile -Path $f.FullName -Index $index -Counters $counters -TitleFallbackCandidates $titleFallbackCandidates
}

$dataPath = Split-Path -Parent $OutputPath

# Title-fallback resolution (cis-fallback-map.json, see CisCatalog.ps1):
# second-chance matching for REG_CHECK/ANONYMOUS_SID_SETTING entries with no
# usable location field (Read-CisAuditFile above). Auto-resolves what it can
# against Data_SecurityCatalog.json/the ADMX index, flags the rest
# needsManualReview, and writes back only newly-added keys - existing
# entries (especially manual ones) are never touched.
if ($titleFallbackCandidates.Count -gt 0) {
    $fallbackMap = Get-CisFallbackMap -DataPath $dataPath
    $securityCatalogPath = Join-Path $PSScriptRoot '..\DefaultData\Data_SecurityCatalog.json'
    $admxIndexPath = Join-Path $dataPath 'admx-index.json'
    $fallbackMapDirty = Resolve-CisTitleFallbackCandidates -Candidates $titleFallbackCandidates -Index $index -Counters $counters -FallbackMap $fallbackMap -SecurityCatalogPath $securityCatalogPath -AdmxIndexPath $admxIndexPath

    if ($fallbackMapDirty) {
        $orderedFallbackMap = [ordered]@{}
        foreach ($k in ($fallbackMap.Keys | Sort-Object)) { $orderedFallbackMap[$k] = $fallbackMap[$k] }
        $fallbackMapOutPath = Get-CisFallbackMapPath -DataPath $dataPath
        $fallbackMapOutDir = Split-Path -Parent $fallbackMapOutPath
        if (-not (Test-Path -LiteralPath $fallbackMapOutDir)) { New-Item -ItemType Directory -Path $fallbackMapOutDir -Force | Out-Null }
        $fallbackJson = $orderedFallbackMap | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($fallbackMapOutPath, $fallbackJson, (New-Object System.Text.UTF8Encoding($true)))
    }
}
if (-not $counters.ContainsKey('NeedsManualReview')) { $counters.NeedsManualReview = 0 }

# "info" overrides (see plan-gpedit-security-catalog-editor.md §4.3):
# applied here too (in addition to Import-CisIndex, app-side) so UI edits
# survive a full regeneration of this index. Pre-serialization hashtable
# here (not yet a PSCustomObject from ConvertFrom-Json) - direct key
# indexing, no .PSObject.Properties walk like in Merge-CisOverrides.
$overrides = Get-CisOverrides -DataPath $dataPath
foreach ($overrideKey in $overrides.Keys) {
    $parts = $overrideKey -split '::', 2
    if ($parts.Count -ne 2) { continue }
    $bucket = $index[$parts[0]]
    if ($bucket -and $bucket.Contains($parts[1])) {
        $bucket[$parts[1]].info = $overrides[$overrideKey].info
    }
}

$output = [ordered]@{
    meta = [ordered]@{
        generatedAt = (Get-Date).ToString('o')
        sourceFiles = @($files | ForEach-Object { $_.Name })
        entryCount  = $counters.Entries
        profileCount = $counters.Profiles
        skippedItemCount = $counters.Skipped
        needsManualReviewCount = $counters.NeedsManualReview
        sourceFingerprint = $SourceFingerprint
    }
    byRegistry         = $index.byRegistry
    byPasswordPolicy   = $index.byPasswordPolicy
    byLockoutPolicy    = $index.byLockoutPolicy
    byUserRight        = $index.byUserRight
    byAuditSubcategory = $index.byAuditSubcategory
    byTitle            = $index.byTitle
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding utf8

Write-Host "CIS index generated: $OutputPath"
Write-Host "  .audit files processed: $($files.Count)"
Write-Host "  Entries (unique controls): $($counters.Entries)"
Write-Host "  Recommendations per profile: $($counters.Profiles)"
Write-Host "  Items skipped (out-of-scope type or missing fields): $($counters.Skipped)"
Write-Host "  Fallback-map entries needing manual review: $($counters.NeedsManualReview)"
