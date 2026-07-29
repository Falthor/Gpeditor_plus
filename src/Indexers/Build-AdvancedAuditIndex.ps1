<#
    Indexes Advanced Audit Policy Configuration: merges the static catalog
    (AdvancedAuditCatalog.ps1) with the current state from audit.csv (if
    present), same spirit as Build-SecurityIndex.ps1. Always regenerated
    (small, cheap to reparse), never cached, to avoid ever showing stale state.
#>
param(
    [string]$AuditCsvPath = (Join-Path $env:WinDir 'System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\data\advanced-audit-index.json')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\AuditCsvFile.ps1')
. (Join-Path $PSScriptRoot '..\Catalogs\AdvancedAuditCatalog.ps1')

$rows = Read-AuditCsv -Path $AuditCsvPath
$fileExists = Test-Path -LiteralPath $AuditCsvPath

$settings = New-Object System.Collections.Generic.List[object]
foreach ($entry in (Get-AdvancedAuditCatalogEntries)) {
    $row = Get-AuditCsvValue -Rows $rows -Guid $entry.guid
    $isConfigured = $null -ne $row
    $rawValue = if ($isConfigured) { $row['Setting Value'] } else { $null }

    $settings.Add([ordered]@{
        id           = "AdvAudit::$($entry.guid)"
        category     = $entry.category
        guid         = $entry.guid
        name         = $entry.name
        displayName  = $entry.displayName
        description  = ''
        explain      = ''
        valueType    = $entry.valueType
        isConfigured = $isConfigured
        rawValue     = $rawValue
    })
}

$index = [ordered]@{
    meta = [ordered]@{
        generatedAt  = (Get-Date).ToString('o')
        auditCsvPath = $AuditCsvPath
        auditCsvFound = $fileExists
        settingCount = $settings.Count
    }
    settings = $settings
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$index | ConvertTo-Json -Depth 10 -Compress | Out-File -LiteralPath $OutputPath -Encoding utf8

Write-Host "Advanced audit index generated: $OutputPath"
Write-Host "  audit.csv found: $fileExists ($AuditCsvPath)"
Write-Host "  Subcategories cataloged: $($settings.Count)"
