<#
    Verification (read-only): for every CIS profile (benchmark/version/level/
    role, one per .audit file), compares:
      - "raw in-scope count"  = number of numbered <custom_item> blocks in the
        .audit file that are of a type the app can actually resolve to a
        setting (REGISTRY_SETTING/REG_CHECK/PASSWORD_POLICY/LOCKOUT_POLICY/
        USER_RIGHTS_POLICY/AUDIT_POLICY_SUBCATEGORY/ANONYMOUS_SID_SETTING),
        replicating Build-CisIndex.ps1's own matching rules;
      - "app filter count"    = number of entries in the REAL cis-index.json
        (the one GpEdit.ps1 actually loads) whose profiles[] contains that
        exact profile - i.e. exactly what Test-CisProfileFilterMatch
        (GpEdit.ps1) would show when filtering the main grid to this profile.

    Does NOT regenerate or write anything - reads the live index/fallback map
    from %LOCALAPPDATA%\Gpeditor_plus\Index and the bundled .audit files from
    the repo. Any per-profile mismatch beyond the expected out-of-scope types
    (WMI_POLICY, AUDIT_POWERSHELL, CHECK_ACCOUNT, BANNER_CHECK) or an
    unresolved fallback candidate (needsManualReview) points at a real bug.

    Usage: run from anywhere, e.g.
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Verify-CisProfileCounts.ps1
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$IndexDir = (Join-Path $env:LOCALAPPDATA 'Gpeditor_plus\Index')
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# Reuse the exact same title-normalization helpers the app/indexer use, so a
# fallback-candidate title here collides with cis-fallback-map.json/byTitle
# the same way it does at index-build time. Dot-sourcing only this file is
# safe: no WPF/Add-Type calls at its top level (checked).
. (Join-Path $RepoRoot 'src\Catalogs\CisCatalog.ps1')
Set-StrictMode -Off

$auditDir = Join-Path $RepoRoot 'src\DefaultData\Audit'
$cisIndexPath = Join-Path $IndexDir 'cis-index.json'
$fallbackMapPath = Join-Path $IndexDir 'cis-fallback-map.json'

if (-not (Test-Path -LiteralPath $cisIndexPath)) { throw "cis-index.json not found: $cisIndexPath (run GpEdit.ps1 at least once first)" }
if (-not (Test-Path -LiteralPath $auditDir)) { throw "Audit folder not found: $auditDir" }

$cisIndex = Get-Content -Raw -Encoding UTF8 -LiteralPath $cisIndexPath | ConvertFrom-Json
$fallbackMap = @{}
if (Test-Path -LiteralPath $fallbackMapPath) {
    $rawFb = Get-Content -Raw -Encoding UTF8 -LiteralPath $fallbackMapPath | ConvertFrom-Json
    foreach ($p in $rawFb.PSObject.Properties) { $fallbackMap[$p.Name] = $p.Value }
}

$buckets = @('byRegistry', 'byPasswordPolicy', 'byLockoutPolicy', 'byUserRight', 'byAuditSubcategory', 'byTitle')

# ---------------------------------------------------------------------------
# Helpers duplicated (read-only parsing) from Build-CisIndex.ps1 - kept
# minimal and behaviourally identical, since the whole point is to check
# that script's output, not to re-run it.
# ---------------------------------------------------------------------------
function Get-CisFieldLocal {
    param([string]$BlockText, [string]$FieldName)
    $pattern = "(?ms)^\s*$FieldName\s*:\s*(.+?)(?=\r?\n[ \t]+[a-zA-Z_]+\s*:|\z)"
    $m = [regex]::Match($BlockText, $pattern)
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.Trim().Trim('"').Trim()
}

function Get-CisSpecLocal {
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

function ConvertTo-CisNumberAndTitleLocal {
    param([string]$Description)
    if ([string]::IsNullOrEmpty($Description)) { return $null }
    $m = [regex]::Match($Description, '^(?<num>\d+(\.\d+)*)\s+(?<title>.+)$')
    if (-not $m.Success) { return $null }
    $title = $m.Groups['title'].Value -replace '^\(L\d\)\s*', ''
    return [ordered]@{ cisNumber = $m.Groups['num'].Value; title = $title.Trim() }
}

# Types Build-CisIndex.ps1's Get-CisMatchKey resolves directly (given the
# right fields present).
$directTypes = @('REGISTRY_SETTING', 'REG_CHECK', 'PASSWORD_POLICY', 'LOCKOUT_POLICY', 'USER_RIGHTS_POLICY', 'AUDIT_POLICY_SUBCATEGORY')
# Types that never get a primary match key and always go through the
# byTitle fallback candidate path.
$titleFallbackTypes = @('ANONYMOUS_SID_SETTING')

function Get-DirectMatchKey {
    # Returns the same (bucket, key) pair Build-CisIndex.ps1's
    # Get-CisMatchKey would compute, as a single string - $null if the
    # required field(s) are missing (no direct match key). Used both to
    # decide whether an item is a "direct match" and to detect two
    # <custom_item> blocks in the SAME file that collapse onto the SAME
    # underlying setting (duplicate CIS control - see 2.3.10.9 in the
    # Server L1 benchmarks: one control split into several AND-condition
    # sub-blocks that each repeat the same description/reg_key).
    param([string]$Type, [string]$Body)
    switch ($Type) {
        'REGISTRY_SETTING' {
            $rk = Get-CisFieldLocal -BlockText $Body -FieldName 'reg_key'
            $ri = Get-CisFieldLocal -BlockText $Body -FieldName 'reg_item'
            if ([string]::IsNullOrEmpty($rk) -or [string]::IsNullOrEmpty($ri)) { return $null }
            return "byRegistry::$(($rk -replace '^HKLM\\','').ToLowerInvariant())|$($ri.ToLowerInvariant())"
        }
        'REG_CHECK' {
            $rk = Get-CisFieldLocal -BlockText $Body -FieldName 'value_data'
            $ri = Get-CisFieldLocal -BlockText $Body -FieldName 'key_item'
            if ([string]::IsNullOrEmpty($rk) -or [string]::IsNullOrEmpty($ri)) { return $null }
            return "byRegistry::$(($rk -replace '^HKLM\\','').ToLowerInvariant())|$($ri.ToLowerInvariant())"
        }
        'PASSWORD_POLICY' {
            $v = Get-CisFieldLocal -BlockText $Body -FieldName 'password_policy'
            if ([string]::IsNullOrEmpty($v)) { return $null }
            return "byPasswordPolicy::$v"
        }
        'LOCKOUT_POLICY' {
            $v = Get-CisFieldLocal -BlockText $Body -FieldName 'lockout_policy'
            if ([string]::IsNullOrEmpty($v)) { return $null }
            return "byLockoutPolicy::$v"
        }
        'USER_RIGHTS_POLICY' {
            $v = Get-CisFieldLocal -BlockText $Body -FieldName 'right_type'
            if ([string]::IsNullOrEmpty($v)) { return $null }
            return "byUserRight::$v"
        }
        'AUDIT_POLICY_SUBCATEGORY' {
            $v = Get-CisFieldLocal -BlockText $Body -FieldName 'audit_policy_subcategory'
            if ([string]::IsNullOrEmpty($v)) { return $null }
            return "byAuditSubcategory::$v"
        }
        default { return $null }
    }
}

function Test-FallbackResolved {
    param([string]$Title)
    $normalized = ConvertTo-CisNormalizedTitle -Title (Get-CisSettingNameFromTitle -Title $Title)
    if (-not $normalized) { return $false }
    if (-not $fallbackMap.ContainsKey($normalized)) { return $false }
    return -not $fallbackMap[$normalized].needsManualReview
}

# ---------------------------------------------------------------------------
# App-side count: for a given profile spec, count cis-index.json entries
# (across all buckets) whose profiles[] contains a matching entry - this is
# exactly the population Test-CisProfileFilterMatch/GpEdit.ps1 filters the
# main grid down to.
# ---------------------------------------------------------------------------
function Get-AppFilterCount {
    # Untyped params on purpose: Role is genuinely $null for Desktop
    # profiles (no MS/DC split) - a [string] param would silently coerce
    # that $null to "" and break the -eq comparison below, exactly like
    # Get-CisRecommendationValueForProfile (GpEdit.ps1) must NOT do.
    param($CisIndex, $Benchmark, $Version, $Level, $Role)
    $count = 0
    foreach ($bucketName in $buckets) {
        $bucketProp = $CisIndex.PSObject.Properties[$bucketName]
        if ($null -eq $bucketProp) { continue }
        foreach ($entryProp in $bucketProp.Value.PSObject.Properties) {
            $entry = $entryProp.Value
            foreach ($p in @($entry.profiles)) {
                if ($p.benchmark -eq $Benchmark -and $p.version -eq $Version -and $p.level -eq $Level -and $p.role -eq $Role) {
                    $count++
                    break
                }
            }
        }
    }
    return $count
}

# ---------------------------------------------------------------------------
# Main: one row per .audit file (= one CIS profile)
# ---------------------------------------------------------------------------
$files = Get-ChildItem -LiteralPath $auditDir -Filter 'CIS_Microsoft_Windows_*.audit' | Sort-Object Name
$results = New-Object System.Collections.Generic.List[object]

foreach ($f in $files) {
    $text = Get-Content -Raw -LiteralPath $f.FullName
    $spec = Get-CisSpecLocal -Text $text
    if ($null -eq $spec) { Write-Warning "No <spec> in $($f.Name), skipped"; continue }

    $directCount = 0
    $fallbackResolvedCount = 0
    $fallbackUnresolvedCount = 0
    $outOfScopeCount = 0
    $totalNumbered = 0
    $duplicateCount = 0
    $duplicateDetails = New-Object System.Collections.Generic.List[object]
    # Tracks match keys already seen IN THIS FILE: a second <custom_item>
    # with the same key doesn't add a new grid row (Build-CisIndex.ps1
    # collapses it into the same bucket entry) - counted separately as a
    # "duplicate", not folded silently into ExpectedAppCount.
    $seenKeys = @{}

    foreach ($blockMatch in [regex]::Matches($text, '(?s)<custom_item>(.*?)</custom_item>')) {
        $body = $blockMatch.Groups[1].Value
        $type = Get-CisFieldLocal -BlockText $body -FieldName 'type'
        $description = Get-CisFieldLocal -BlockText $body -FieldName 'description'
        $numberAndTitle = ConvertTo-CisNumberAndTitleLocal -Description $description
        if ($null -eq $numberAndTitle) { continue }
        $totalNumbered++

        $directKey = if ($directTypes -contains $type) { Get-DirectMatchKey -Type $type -Body $body } else { $null }
        if ($null -ne $directKey) {
            if ($seenKeys.ContainsKey($directKey)) {
                $duplicateCount++
                $duplicateDetails.Add([pscustomobject]@{ CisNumber = $numberAndTitle.cisNumber; Title = $numberAndTitle.title; Key = $directKey })
            }
            else {
                $seenKeys[$directKey] = $true
                $directCount++
            }
            continue
        }
        if ($directTypes -contains $type -or $titleFallbackTypes -contains $type) {
            # REG_CHECK/ANONYMOUS_SID_SETTING missing fields -> title-fallback candidate
            $normalizedTitle = ConvertTo-CisNormalizedTitle -Title (Get-CisSettingNameFromTitle -Title $numberAndTitle.title)
            $fallbackKey = "byTitle::$normalizedTitle"
            if ($normalizedTitle -and $seenKeys.ContainsKey($fallbackKey)) {
                $duplicateCount++
                $duplicateDetails.Add([pscustomobject]@{ CisNumber = $numberAndTitle.cisNumber; Title = $numberAndTitle.title; Key = $fallbackKey })
                continue
            }
            if ($normalizedTitle) { $seenKeys[$fallbackKey] = $true }
            if (Test-FallbackResolved -Title $numberAndTitle.title) { $fallbackResolvedCount++ }
            else { $fallbackUnresolvedCount++ }
            continue
        }
        $outOfScopeCount++
    }

    $expectedAppCount = $directCount + $fallbackResolvedCount
    $actualAppCount = Get-AppFilterCount -CisIndex $cisIndex -Benchmark $spec.benchmark -Version $spec.version -Level $spec.level -Role $spec.role

    $results.Add([pscustomobject]@{
        File               = $f.Name
        Benchmark          = $spec.benchmark
        Version            = $spec.version
        Level              = $spec.level
        Role               = $spec.role
        TotalNumbered      = $totalNumbered
        OutOfScope         = $outOfScopeCount
        FallbackUnresolved = $fallbackUnresolvedCount
        Duplicates         = $duplicateCount
        DuplicateDetails   = $duplicateDetails
        ExpectedAppCount   = $expectedAppCount
        ActualAppCount     = $actualAppCount
        Match              = ($expectedAppCount -eq $actualAppCount)
    })
}

$results | Format-Table File, TotalNumbered, OutOfScope, FallbackUnresolved, Duplicates, ExpectedAppCount, ActualAppCount, Match -AutoSize

$withDuplicates = $results | Where-Object { $_.Duplicates -gt 0 }
if ($withDuplicates.Count -gt 0) {
    Write-Host "Duplicate CIS items found (same underlying setting listed more than once in the same .audit file - collapses to a single grid row, not a bug):" -ForegroundColor Yellow
    foreach ($r in $withDuplicates) {
        Write-Host "  $($r.File): $($r.Duplicates) duplicate item(s)"
        $r.DuplicateDetails | Group-Object CisNumber, Title | ForEach-Object {
            Write-Host "    - $($_.Group[0].CisNumber) `"$($_.Group[0].Title)`" x$($_.Count + 1) occurrences in file"
        }
    }
    Write-Host ''
}

$mismatches = $results | Where-Object { -not $_.Match }
Write-Host ''
if ($mismatches.Count -eq 0) {
    Write-Host "OK: all $($results.Count) profiles match (ExpectedAppCount == ActualAppCount, duplicates accounted for)." -ForegroundColor Green
}
else {
    Write-Host "MISMATCH on $($mismatches.Count) profile(s):" -ForegroundColor Red
    $mismatches | Format-Table File, ExpectedAppCount, ActualAppCount -AutoSize
}

Write-Host ''
Write-Host "Totals: $($results.Count) profiles, $(($results | Measure-Object TotalNumbered -Sum).Sum) numbered items, $(($results | Measure-Object OutOfScope -Sum).Sum) out-of-scope, $(($results | Measure-Object Duplicates -Sum).Sum) duplicate items, $(($results | Measure-Object FallbackUnresolved -Sum).Sum) unresolved fallback candidates."
