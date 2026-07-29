<#
    Regression tests for Step 6 (merging changes into .pol / GptTmpl.inf,
    GPT.ini increment, timestamped backup). Uses only temp files: no
    writes to real system paths.
#>
param(
    [string]$TempDir = (Join-Path $env:TEMP 'gpedit-writer-test')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\PolFile.ps1')
. (Join-Path $PSScriptRoot '..\Parsers\GptIniFile.ps1')
. (Join-Path $PSScriptRoot '..\Parsers\GptTmplFile.ps1')
. (Join-Path $PSScriptRoot '..\Policy\PolicyWriter.ps1')

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
        Write-Host "  [FAIL] $Message (attendu='$Expected' obtenu='$Actual')" -ForegroundColor Red
    }
}

if (Test-Path -LiteralPath $TempDir) { Remove-Item -LiteralPath $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

function New-TestPolicy {
    param(
        [string]$Id = 'Test::Policy1',
        [string]$RegistryKey = 'Software\Policies\Test',
        [string]$ValueName = 'MyValue',
        $EnabledValue = 1,
        $DisabledValue = 0,
        [array]$Elements = @()
    )
    return [pscustomobject]@{
        id            = $Id
        registryKey   = $RegistryKey
        valueName     = $ValueName
        enabledValue  = $EnabledValue
        disabledValue = $DisabledValue
        elements      = $Elements
    }
}

Write-Host "=== Test 1: NotConfigure -> Active (simple, no elements) ===" -ForegroundColor Cyan
$pol1 = New-TestPolicy
$entries = New-Object System.Collections.Generic.List[object]
$result = Merge-PolEntriesForPolicy -Entries $entries -Policy $pol1 -NewState 'Enabled'
Assert-Equal -Expected 1 -Actual $result.Count -Message 'Une entree ajoutee'
Assert-Equal -Expected 'MyValue' -Actual $result[0].ValueName -Message 'ValueName correct'
Assert-Equal -Expected 1 -Actual $result[0].Value -Message 'enabledValue ecrit'
Assert-Equal -Expected 4 -Actual $result[0].Type -Message 'Type infere REG_DWORD pour valeur numerique'

Write-Host "`n=== Test 2: Active -> NonConfigure (existing value -> delete marker) ===" -ForegroundColor Cyan
$result2 = Merge-PolEntriesForPolicy -Entries $result -Policy $pol1 -NewState 'NotConfigured'
Assert-Equal -Expected 1 -Actual $result2.Count -Message 'Une entree (marqueur) presente'
Assert-Equal -Expected '**del.MyValue' -Actual $result2[0].ValueName -Message 'Marqueur de suppression correct'

Write-Host "`n=== Test 3: NonConfigure -> Disabled (never had a value -> nothing to remove) ===" -ForegroundColor Cyan
$emptyEntries = New-Object System.Collections.Generic.List[object]
$result3 = Merge-PolEntriesForPolicy -Entries $emptyEntries -Policy $pol1 -NewState 'Disabled'
Assert-Equal -Expected 1 -Actual $result3.Count -Message 'disabledValue defini => une entree ecrite (0)'
Assert-Equal -Expected 0 -Actual $result3[0].Value -Message 'disabledValue = 0 ecrit'

Write-Host "`n=== Test 4: Disabled with no disabledValue set, existing value -> removal ===" -ForegroundColor Cyan
$polNoDisabled = New-TestPolicy -DisabledValue $null
$entriesWithValue = New-Object System.Collections.Generic.List[object]
$entriesWithValue.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'MyValue' -Type 4 -Value 1))
$result4 = Merge-PolEntriesForPolicy -Entries $entriesWithValue -Policy $polNoDisabled -NewState 'Disabled'
Assert-Equal -Expected 1 -Actual $result4.Count -Message 'Une entree (marqueur) presente'
Assert-Equal -Expected '**del.MyValue' -Actual $result4[0].ValueName -Message 'Marqueur pose (pas de disabledValue)'

Write-Host "`n=== Test 5: Disabled with no disabledValue, never configured -> nothing written ===" -ForegroundColor Cyan
$result5 = Merge-PolEntriesForPolicy -Entries (New-Object System.Collections.Generic.List[object]) -Policy $polNoDisabled -NewState 'Disabled'
Assert-Equal -Expected 0 -Actual $result5.Count -Message 'Aucune entree (rien a supprimer)'

Write-Host "`n=== Test 6: Elements (enum, decimal, text, multiText, boolean) ===" -ForegroundColor Cyan
$elements = @(
    [pscustomobject]@{ id = 'ElEnum'; type = 'enum'; valueName = 'EnumVal'; key = $null; items = @([pscustomobject]@{displayName='A';value=0},[pscustomobject]@{displayName='B';value=1}) }
    [pscustomobject]@{ id = 'ElDecimal'; type = 'decimal'; valueName = 'DecVal'; key = $null; minValue=0; maxValue=100 }
    [pscustomobject]@{ id = 'ElText'; type = 'text'; valueName = 'TxtVal'; key = $null; expandable = $false }
    [pscustomobject]@{ id = 'ElMulti'; type = 'multiText'; valueName = 'MultiVal'; key = $null }
    [pscustomobject]@{ id = 'ElBoolChecked'; type = 'boolean'; valueName = 'BoolChecked'; key = $null; trueValue = $null; falseValue = $null }
    [pscustomobject]@{ id = 'ElBoolUnchecked'; type = 'boolean'; valueName = 'BoolUnchecked'; key = $null; trueValue = $null; falseValue = $null }
)
$polWithElements = New-TestPolicy -ValueName $null -Elements $elements
$existingForBool = New-Object System.Collections.Generic.List[object]
$existingForBool.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'BoolUnchecked' -Type 4 -Value 1))
$elementValues = @{ ElEnum = 1; ElDecimal = 42; ElText = 'hello'; ElMulti = @('a','b','c'); ElBoolChecked = $true; ElBoolUnchecked = $false }
$result6 = Merge-PolEntriesForPolicy -Entries $existingForBool -Policy $polWithElements -NewState 'Enabled' -ElementValues $elementValues

$byName = @{}
foreach ($e in $result6) { $byName[$e.ValueName] = $e }
Assert-Equal -Expected 1 -Actual $byName['EnumVal'].Value -Message 'Element enum : valeur correcte'
Assert-Equal -Expected 42 -Actual $byName['DecVal'].Value -Message 'Element decimal : valeur correcte'
Assert-Equal -Expected 'hello' -Actual $byName['TxtVal'].Value -Message 'Element texte : valeur correcte'
Assert-Equal -Expected @('a','b','c') -Actual $byName['MultiVal'].Value -Message 'Element multiText : valeurs correctes'
Assert-Equal -Expected 1 -Actual $byName['BoolChecked'].Value -Message 'Element boolean coche (sans trueValue) : DWORD 1'
Assert-Equal -Expected $true -Actual ($byName.ContainsKey('**del.BoolUnchecked')) -Message 'Element boolean decoche (avait une valeur) : marqueur de suppression'

Write-Host "`n=== Test 7: round-trip via Write-PolFile/Read-PolFile ===" -ForegroundColor Cyan
$polFilePath = Join-Path $TempDir 'test.pol'
Write-PolFile -Path $polFilePath -Entries $result6
$reread = Read-PolFile -Path $polFilePath
Assert-Equal -Expected $result6.Count -Actual $reread.Count -Message 'Nombre d''entrees identique apres ecriture/relecture'
$rereadByName = @{}
foreach ($e in $reread) { $rereadByName[$e.ValueName] = $e }
Assert-Equal -Expected 42 -Actual $rereadByName['DecVal'].Value -Message 'Valeur decimal preservee apres round-trip fichier'
Assert-Equal -Expected @('a','b','c') -Actual $rereadByName['MultiVal'].Value -Message 'Valeurs multiText preservees apres round-trip fichier'

Write-Host "`n=== Test 8: GPT.ini - version increment (independent Machine/User) ===" -ForegroundColor Cyan
$gptIniPath = Join-Path $TempDir 'GPT.ini'
[System.IO.File]::WriteAllText($gptIniPath, "[General]`r`ngPCMachineExtensionNames=`r`nVersion=65537`r`n", [System.Text.Encoding]::Default)
$gptIni = Read-GptIni -Path $gptIniPath
Assert-Equal -Expected '65537' -Actual $gptIni.Sections['General']['Version'] -Message 'Version initiale lue (65537 = machine=1,user=1)'
Step-GptIniVersion -GptIni $gptIni -IncrementMachine | Out-Null
Assert-Equal -Expected "$((2 -shl 16) -bor 1)" -Actual $gptIni.Sections['General']['Version'] -Message 'Increment Machine seul (machine=2,user=1)'
Step-GptIniVersion -GptIni $gptIni -IncrementUser | Out-Null
Assert-Equal -Expected "$((2 -shl 16) -bor 2)" -Actual $gptIni.Sections['General']['Version'] -Message 'Increment User seul (machine=2,user=2)'
Write-GptIni -Path $gptIniPath -GptIni $gptIni
$gptIniReread = Read-GptIni -Path $gptIniPath
Assert-Equal -Expected $gptIni.Sections['General']['Version'] -Actual $gptIniReread.Sections['General']['Version'] -Message 'Version persistee apres ecriture/relecture'
Assert-Equal -Expected '' -Actual $gptIniReread.Sections['General']['gPCMachineExtensionNames'] -Message 'Cle inconnue (gPCMachineExtensionNames) preservee'

Write-Host "`n=== Test 9: GPT.ini missing -> default values ===" -ForegroundColor Cyan
$missingIni = Read-GptIni -Path (Join-Path $TempDir 'inexistant.ini')
Assert-Equal -Expected '0' -Actual $missingIni.Sections['General']['Version'] -Message 'Version par defaut = 0 si fichier absent'

Write-Host "`n=== Test 10: timestamped backup ===" -ForegroundColor Cyan
$srcMachine = Join-Path $TempDir 'machine-registry.pol'
$srcUser = Join-Path $TempDir 'user-registry.pol'
[System.IO.File]::WriteAllText($srcMachine, 'MACHINE-CONTENT')
[System.IO.File]::WriteAllText($srcUser, 'USER-CONTENT')
$backupRoot = Join-Path $TempDir 'Backups'
$backupResult = New-TimestampedBackup -FilesToBackup @{ 'Machine_registry.pol' = $srcMachine; 'User_registry.pol' = $srcUser } -BackupRoot $backupRoot
Assert-Equal -Expected $true -Actual (Test-Path -LiteralPath $backupResult.BackupDir) -Message 'Dossier de sauvegarde horodate cree'
Assert-Equal -Expected 2 -Actual $backupResult.Files.Count -Message 'Deux fichiers sauvegardes'
$backedUpMachine = Join-Path $backupResult.BackupDir 'Machine_registry.pol'
Assert-Equal -Expected 'MACHINE-CONTENT' -Actual (Get-Content -Raw $backedUpMachine) -Message 'Contenu Machine preserve (pas de collision de nom avec User)'
$backedUpUser = Join-Path $backupResult.BackupDir 'User_registry.pol'
Assert-Equal -Expected 'USER-CONTENT' -Actual (Get-Content -Raw $backedUpUser) -Message 'Contenu User preserve'

Write-Host "`n=== Test 11: applying security changes to GptTmpl.inf ===" -ForegroundColor Cyan
$gpt = New-EmptyGptTmpl
Set-GptTmplValue -GptTmpl $gpt -Section 'System Access' -Key 'MinimumPasswordLength' -Value '7'
$settingsById = @{
    'System Access::MinimumPasswordLength' = [pscustomobject]@{ section = 'System Access'; name = 'MinimumPasswordLength' }
    'System Access::PasswordComplexity'    = [pscustomobject]@{ section = 'System Access'; name = 'PasswordComplexity' }
}
$pendingSecChanges = @{
    'System Access::MinimumPasswordLength' = @{ IsConfigured = $false; Value = $null }
    'System Access::PasswordComplexity'    = @{ IsConfigured = $true; Value = '1' }
}
Apply-SecurityChangesToGpt -GptTmpl $gpt -PendingChanges $pendingSecChanges -SettingsById $settingsById | Out-Null
Assert-Equal -Expected $null -Actual (Get-GptTmplValue $gpt 'System Access' 'MinimumPasswordLength') -Message 'Parametre retire (IsConfigured=false) => valeur absente'
Assert-Equal -Expected '1' -Actual (Get-GptTmplValue $gpt 'System Access' 'PasswordComplexity') -Message 'Parametre defini (IsConfigured=true) => valeur ecrite'

Write-Host "`n=== Test 12: Apply-AdmxChangesToEntries (multi-policy orchestration) ===" -ForegroundColor Cyan
$polA = New-TestPolicy -Id 'Test::PolA' -ValueName 'ValA'
$polB = New-TestPolicy -Id 'Test::PolB' -ValueName 'ValB'
$policiesById = @{ 'Test::PolA' = $polA; 'Test::PolB' = $polB }
$pendingAdmx = @{
    'Test::PolA|Machine' = @{ State = 'Enabled'; ElementValues = @{} }
    'Test::PolB|Machine' = @{ State = 'Enabled'; ElementValues = @{} }
    'Test::PolA|User'    = @{ State = 'Enabled'; ElementValues = @{} }
}
$initial = New-Object System.Collections.Generic.List[object]
$machineResult = Apply-AdmxChangesToEntries -Entries $initial -PendingChanges $pendingAdmx -Scope 'Machine' -PoliciesById $policiesById
Assert-Equal -Expected 2 -Actual $machineResult.Count -Message 'Scope Machine : 2 strategies appliquees (PolA + PolB), pas PolA|User'
$userResult = Apply-AdmxChangesToEntries -Entries (New-Object System.Collections.Generic.List[object]) -PendingChanges $pendingAdmx -Scope 'User' -PoliciesById $policiesById
Assert-Equal -Expected 1 -Actual $userResult.Count -Message 'Scope User : 1 strategie appliquee (PolA seulement)'

Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Result: $($script:TestCount - $script:FailCount)/$($script:TestCount) tests passed ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
