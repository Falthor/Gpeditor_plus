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
function Read-CisAuditFile {
    param([string]$Path, [System.Collections.IDictionary]$Index, [hashtable]$Counters)

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

        $regKey = Get-CisField -BlockText $body -FieldName 'reg_key'
        $regItem = Get-CisField -BlockText $body -FieldName 'reg_item'
        $passwordPolicy = Get-CisField -BlockText $body -FieldName 'password_policy'
        $lockoutPolicy = Get-CisField -BlockText $body -FieldName 'lockout_policy'
        $rightType = Get-CisField -BlockText $body -FieldName 'right_type'
        $auditSubcategory = Get-CisField -BlockText $body -FieldName 'audit_policy_subcategory'

        $matchKey = Get-CisMatchKey -Type $type -RegKey $regKey -RegItem $regItem -PasswordPolicy $passwordPolicy -LockoutPolicy $lockoutPolicy -RightType $rightType -AuditSubcategory $auditSubcategory
        if ($null -eq $matchKey) {
            $Counters.Skipped++
            continue
        }

        $bucket = $Index[$matchKey.bucket]
        if (-not $bucket.Contains($matchKey.key)) {
            $info = Get-CisField -BlockText $body -FieldName 'info'
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

        $valueData = Resolve-CisValueData -Raw (Get-CisField -BlockText $body -FieldName 'value_data') -Variables $variables

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
}
$counters = @{ Entries = 0; Profiles = 0; Skipped = 0 }

foreach ($f in $files) {
    Read-CisAuditFile -Path $f.FullName -Index $index -Counters $counters
}

# "info" overrides (see plan-gpedit-security-catalog-editor.md §4.3):
# applied here too (in addition to Import-CisIndex, app-side) so UI edits
# survive a full regeneration of this index. Pre-serialization hashtable
# here (not yet a PSCustomObject from ConvertFrom-Json) - direct key
# indexing, no .PSObject.Properties walk like in Merge-CisOverrides.
$dataPath = Split-Path -Parent $OutputPath
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
        sourceFingerprint = $SourceFingerprint
    }
    byRegistry         = $index.byRegistry
    byPasswordPolicy   = $index.byPasswordPolicy
    byLockoutPolicy    = $index.byLockoutPolicy
    byUserRight        = $index.byUserRight
    byAuditSubcategory = $index.byAuditSubcategory
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding utf8

Write-Host "CIS index generated: $OutputPath"
Write-Host "  .audit files processed: $($files.Count)"
Write-Host "  Entries (unique controls): $($counters.Entries)"
Write-Host "  Recommendations per profile: $($counters.Profiles)"
Write-Host "  Items skipped (out-of-scope type or missing fields): $($counters.Skipped)"
