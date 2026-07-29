<#
    Indexes local security settings: merges the static catalog
    (SecurityCatalog.ps1) with the current state from secedit.inf into a
    JSON structure for search/UI (like admx-index.json for ADMX templates).

    secedit.inf uses the same INI format as GptTmpl.inf (GptTmplFile.ps1
    parser reused as-is) but is NOT the real GPO file under System32: it's a
    snapshot produced by `secedit /export /cfg` at app startup, reflecting
    the EFFECTIVE system state rather than a hand-managed GptTmpl.inf - see
    plan-gpedit-security-secedit-cycle.md.
#>
param(
    [string]$SecEditInfPath = (Join-Path $PSScriptRoot '..\..\data\secedit.inf'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\data\security-index.json')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\GptTmplFile.ps1')
. (Join-Path $PSScriptRoot '..\Catalogs\SecurityCatalog.ps1')

$gpt = Read-GptTmplInf -Path $SecEditInfPath
$fileExists = Test-Path -LiteralPath $SecEditInfPath

$settings = New-Object System.Collections.Generic.List[object]

foreach ($entry in (Get-SecurityCatalogEntries)) {
    $raw = Get-GptTmplValue -GptTmpl $gpt -Section $entry.section -Key $entry.name
    $isConfigured = $null -ne $raw

    # LegalNoticeCaption/LegalNoticeText (Security Options) : alwaysConfigured
    # = $true dans le catalogue - par choix explicite de l'utilisateur, ces
    # deux parametres doivent toujours apparaitre comme definis, "Define this
    # policy setting" verrouille coche (voir Show-SecurityEditDialog dans
    # EditDialogs.ps1 pour le verrou cote UI).
    if ($entry.alwaysConfigured) { $isConfigured = $true }

    $item = [ordered]@{
        id           = "$($entry.section)::$($entry.name)"
        category     = $entry.category
        section      = $entry.section
        name         = $entry.name
        catalogKey   = $entry.catalogKey
        displayName  = $entry.displayName
        description  = $entry.description
        explain      = $entry.explain
        valueType    = $entry.valueType
        isConfigured = $isConfigured
        rawValue     = $raw
        members      = $null
        choices      = $null
        flags        = $null
        regType      = $entry.regType
        alwaysConfigured = $entry.alwaysConfigured
    }

    if ($entry.valueType -eq 'principal-list') {
        $item.members = if ($isConfigured) { ConvertTo-PrivilegeMemberList -Value $raw } else { , @() }
    }
    if ($entry.valueType -eq 'reg-enum') {
        $item.choices = $entry.choices
    }
    if ($entry.valueType -eq 'reg-flags') {
        $item.flags = $entry.flags
    }

    $settings.Add($item)
}

# Conserve egalement les cles presentes dans le fichier mais absentes du
# catalogue (parametres hors perimetre ou inconnus), pour ne perdre aucune
# information lors d'une reecriture ulterieure (Etape 6).
$catalogKeys = @{}
foreach ($entry in (Get-SecurityCatalogEntries)) { $catalogKeys["$($entry.section)::$($entry.name)"] = $true }

$otherSections = New-Object System.Collections.Generic.List[object]
foreach ($secName in $gpt.Sections.Keys) {
    foreach ($key in $gpt.Sections[$secName].Keys) {
        if (-not $catalogKeys.ContainsKey("$secName`::$key")) {
            $otherSections.Add([ordered]@{ section = $secName; name = $key; rawValue = $gpt.Sections[$secName][$key] })
        }
    }
}

$index = [ordered]@{
    meta = [ordered]@{
        generatedAt      = (Get-Date).ToString('o')
        secEditInfPath   = $SecEditInfPath
        secEditInfFound  = $fileExists
        settingCount     = $settings.Count
    }
    settings      = $settings
    otherSettings = $otherSections
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$index | ConvertTo-Json -Depth 10 -Compress | Out-File -LiteralPath $OutputPath -Encoding utf8

Write-Host "Security index generated: $OutputPath"
Write-Host "  secedit.inf found: $fileExists ($SecEditInfPath)"
Write-Host "  Cataloged settings: $($settings.Count)"
Write-Host "  Out-of-catalog settings kept: $($otherSections.Count)"
