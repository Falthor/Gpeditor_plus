<#
    Regression tests for the GptTmpl.inf parser.
#>
param(
    [string]$TestFile = (Join-Path $env:TEMP 'gpedit-inf-test.inf')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\GptTmplFile.ps1')
. (Join-Path $PSScriptRoot '..\Catalogs\SecurityCatalog.ps1')

$script:TestCount = 0
$script:FailCount = 0

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    $script:TestCount++
    $eq = $false
    if ($Expected -is [array] -or $Actual -is [array]) {
        $eq = @(Compare-Object @($Expected) @($Actual) -SyncWindow 0).Count -eq 0
    }
    else {
        $eq = ($Expected -eq $Actual)
    }
    if ($eq) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    }
    else {
        $script:FailCount++
        Write-Host "  [FAIL] $Message (expected='$Expected' actual='$Actual')" -ForegroundColor Red
    }
}

Write-Host "=== Test 1: parsing a realistic GptTmpl.inf (synthetic sample) ===" -ForegroundColor Cyan

$sample = @'
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = -1
ClearTextPassword = 0
NewAdministratorName = "Admin Local"
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 1
AuditAccountLogon = 0
[Registry Values]
MACHINE\Software\Policies\Microsoft\Windows\Test\Value1=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-11
SeDenyNetworkLogonRight = *S-1-5-32-546
SeBackupPrivilege =
[Version]
signature="$CHICAGO$"
Revision=1
'@ -replace "`n", "`r`n"

[System.IO.File]::WriteAllText($TestFile, $sample, (New-Object System.Text.UnicodeEncoding($false, $true)))

$gpt = Read-GptTmplInf -Path $TestFile

Assert-Equal -Expected 'Unicode' -Actual $gpt.Encoding -Message 'Encodage detecte = Unicode (UTF-16LE avec BOM)'
Assert-Equal -Expected '1' -Actual (Get-GptTmplValue $gpt 'System Access' 'MinimumPasswordAge') -Message 'MinimumPasswordAge = 1'
Assert-Equal -Expected '42' -Actual (Get-GptTmplValue $gpt 'System Access' 'MaximumPasswordAge') -Message 'MaximumPasswordAge = 42'
Assert-Equal -Expected '-1' -Actual (Get-GptTmplValue $gpt 'System Access' 'LockoutDuration') -Message 'LockoutDuration = -1 (verrouillage manuel)'
Assert-Equal -Expected '"Admin Local"' -Actual (Get-GptTmplValue $gpt 'System Access' 'NewAdministratorName') -Message 'NewAdministratorName (chaine entre guillemets preservee)'
Assert-Equal -Expected '3' -Actual (Get-GptTmplValue $gpt 'Event Audit' 'AuditSystemEvents') -Message 'AuditSystemEvents = 3 (reussite+echec)'
Assert-Equal -Expected '4,1' -Actual (Get-GptTmplValue $gpt 'Registry Values' 'MACHINE\Software\Policies\Microsoft\Windows\Test\Value1') -Message 'Registry Values passthrough (hors perimetre) preserve'
Assert-Equal -Expected '*S-1-5-32-544,*S-1-5-32-545,*S-1-5-11' -Actual (Get-GptTmplValue $gpt 'Privilege Rights' 'SeNetworkLogonRight') -Message 'SeNetworkLogonRight (liste de SID)'
Assert-Equal -Expected '' -Actual (Get-GptTmplValue $gpt 'Privilege Rights' 'SeBackupPrivilege') -Message 'SeBackupPrivilege configure vide (liste explicitement vide, different de non-configure)'
Assert-Equal -Expected $null -Actual (Get-GptTmplValue $gpt 'Privilege Rights' 'SeShutdownPrivilege') -Message 'SeShutdownPrivilege absent = non configure (null, pas vide)'

$members = ConvertTo-PrivilegeMemberList -Value (Get-GptTmplValue $gpt 'Privilege Rights' 'SeNetworkLogonRight')
Assert-Equal -Expected @('*S-1-5-32-544', '*S-1-5-32-545', '*S-1-5-11') -Actual $members -Message 'Decomposition de la liste de SID en tableau'

Write-Host "`n=== Test 2: semantic round-trip (write -> read) ===" -ForegroundColor Cyan
$roundtripFile = $TestFile + '.roundtrip'
Write-GptTmplInf -Path $roundtripFile -GptTmpl $gpt
$gpt2 = Read-GptTmplInf -Path $roundtripFile

foreach ($secName in $gpt.Sections.Keys) {
    foreach ($key in $gpt.Sections[$secName].Keys) {
        Assert-Equal -Expected $gpt.Sections[$secName][$key] -Actual $gpt2.Sections[$secName][$key] -Message "Round-trip [$secName] $key"
    }
}
Remove-Item -LiteralPath $roundtripFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 3: modification then rewrite ===" -ForegroundColor Cyan
Set-GptTmplValue -GptTmpl $gpt -Section 'System Access' -Key 'MinimumPasswordLength' -Value '12'
Set-GptTmplValue -GptTmpl $gpt -Section 'Privilege Rights' -Key 'SeShutdownPrivilege' -Value '*S-1-5-32-544'
$modifiedFile = $TestFile + '.modified'
Write-GptTmplInf -Path $modifiedFile -GptTmpl $gpt
$gpt3 = Read-GptTmplInf -Path $modifiedFile
Assert-Equal -Expected '12' -Actual (Get-GptTmplValue $gpt3 'System Access' 'MinimumPasswordLength') -Message 'Valeur modifiee persistee (MinimumPasswordLength=12)'
Assert-Equal -Expected '*S-1-5-32-544' -Actual (Get-GptTmplValue $gpt3 'Privilege Rights' 'SeShutdownPrivilege') -Message 'Nouvelle cle ajoutee persistee (SeShutdownPrivilege)'
Remove-Item -LiteralPath $modifiedFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 4: missing file -> empty default structure ===" -ForegroundColor Cyan
$missing = Read-GptTmplInf -Path (Join-Path $env:TEMP 'fichier-inexistant-gpedit-test.inf')
Assert-Equal -Expected 'yes' -Actual (Get-GptTmplValue $missing 'Unicode' 'Unicode') -Message 'Structure par defaut valide pour fichier absent'
Assert-Equal -Expected $null -Actual (Get-GptTmplValue $missing 'System Access' 'MinimumPasswordAge') -Message 'Aucun parametre configure par defaut'

Remove-Item -LiteralPath $TestFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 5: security catalog ===" -ForegroundColor Cyan
$entries = Get-SecurityCatalogEntries
Assert-Equal -Expected $true -Actual ($entries.Count -gt 40) -Message "Le catalogue contient un nombre plausible d'entrees ($($entries.Count))"
$rightEntry = $entries | Where-Object { $_.name -eq 'SeNetworkLogonRight' }
Assert-Equal -Expected 'User Rights Assignment' -Actual $rightEntry.category -Message 'SeNetworkLogonRight categorise User Rights Assignment'
$pwdEntry = $entries | Where-Object { $_.name -eq 'MinimumPasswordLength' }
Assert-Equal -Expected 'Password Policy' -Actual $pwdEntry.category -Message 'MinimumPasswordLength categorise Password Policy'

Write-Host "`n=== Result: $($script:TestCount - $script:FailCount)/$($script:TestCount) tests passed ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
