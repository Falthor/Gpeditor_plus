<#
    Regression tests for the audit.csv parser (Advanced Audit Policy
    Configuration). Temp files only.
#>
param(
    [string]$TestFile = (Join-Path $env:TEMP 'gpedit-audit-test.csv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\AuditCsvFile.ps1')
. (Join-Path $PSScriptRoot '..\Catalogs\AdvancedAuditCatalog.ps1')

$script:TestCount = 0
$script:FailCount = 0

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    $script:TestCount++
    if ($Expected -eq $Actual) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    }
    else {
        $script:FailCount++
        Write-Host "  [FAIL] $Message (attendu='$Expected' obtenu='$Actual')" -ForegroundColor Red
    }
}

Write-Host "=== Test 1: missing file -> no rows ===" -ForegroundColor Cyan
$rows = Read-AuditCsv -Path (Join-Path $env:TEMP 'inexistant-audit-test.csv')
Assert-Equal -Expected 0 -Actual $rows.Count -Message 'Aucune ligne si fichier absent'

Write-Host "`n=== Test 2: write, reread, match by GUID ===" -ForegroundColor Cyan
$rows2 = @{}
Set-AuditCsvValue -Rows $rows2 -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' -SubcategoryName 'Logon' -SettingValue 3
Set-AuditCsvValue -Rows $rows2 -Guid '{0cce9216-69ae-11d9-bed3-505054503030}' -SubcategoryName 'Logoff' -SettingValue 1
Write-AuditCsv -Path $TestFile -Rows $rows2

$reread = Read-AuditCsv -Path $TestFile
Assert-Equal -Expected 2 -Actual $reread.Count -Message 'Deux lignes relues'
$logon = Get-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}'
Assert-Equal -Expected '3' -Actual $logon['Setting Value'] -Message 'Setting Value Logon = 3'
Assert-Equal -Expected 'Success and Failure' -Actual $logon['Inclusion Setting'] -Message 'Inclusion Setting texte coherent (3)'
$logoff = Get-AuditCsvValue -Rows $reread -Guid '{0CCE9216-69AE-11D9-BED3-505054503030}'
Assert-Equal -Expected '1' -Actual $logoff['Setting Value'] -Message 'Setting Value Logoff = 1'
Assert-Equal -Expected 'Success' -Actual $logoff['Inclusion Setting'] -Message 'Inclusion Setting texte coherent (1)'

Write-Host "`n=== Test 3: GUID matching is case-insensitive ===" -ForegroundColor Cyan
$viaLower = Get-AuditCsvValue -Rows $reread -Guid '{0cce9215-69ae-11d9-bed3-505054503030}'
Assert-Equal -Expected $true -Actual ($null -ne $viaLower) -Message 'GUID retrouve independamment de la casse'

Write-Host "`n=== Test 4: removing a value ===" -ForegroundColor Cyan
Remove-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}'
Assert-Equal -Expected 1 -Actual $reread.Count -Message 'Une ligne restante apres suppression'
Assert-Equal -Expected $null -Actual (Get-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}') -Message 'Valeur supprimee introuvable'

Write-Host "`n=== Test 5: full round-trip (write -> reread -> rewrite -> compare) ===" -ForegroundColor Cyan
$testFile2 = $TestFile + '.2'
Write-AuditCsv -Path $testFile2 -Rows $reread
$reread2 = Read-AuditCsv -Path $testFile2
Assert-Equal -Expected $reread.Count -Actual $reread2.Count -Message 'Nombre de lignes identique apres 2e ecriture'
Remove-Item -LiteralPath $testFile2 -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 6: subcategory catalog ===" -ForegroundColor Cyan
$catalog = Get-AdvancedAuditCatalogEntries
Assert-Equal -Expected 59 -Actual $catalog.Count -Message 'Le catalogue contient 59 sous-categories'
$guids = $catalog | ForEach-Object { $_.guid }
$uniqueGuids = $guids | Select-Object -Unique
Assert-Equal -Expected 59 -Actual $uniqueGuids.Count -Message 'Tous les GUID sont uniques (pas de doublon/collision)'
$logonEntry = $catalog | Where-Object { $_.name -eq 'Logon' }
Assert-Equal -Expected 'Logon' -Actual $logonEntry.displayName -Message "displayName de 'Logon'"

Remove-Item -LiteralPath $TestFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Result: $($script:TestCount - $script:FailCount)/$($script:TestCount) tests passed ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
