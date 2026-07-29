<#
    Regression tests for AppSettings.ps1 (File > Options - configurable
    default locations + Editor Mode toggle). Uses only a %LOCALAPPDATA%
    redirected to a temp folder: never writes to the machine's real
    settings.json.
#>
param(
    [string]$TempDir = (Join-Path $env:TEMP 'gpedit-appsettings-test')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:TestCount++
    if ($Condition) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    }
    else {
        $script:FailCount++
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
    }
}

if (Test-Path -LiteralPath $TempDir) { Remove-Item -LiteralPath $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Redirect LOCALAPPDATA to the test folder BEFORE loading the module, so
# Get-AppSettingsPath/Get-DefaultAppPaths never touch the machine's real
# %LocalAppData%\Gpeditor_plus.
$env:LOCALAPPDATA = Join-Path $TempDir 'AppData'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

. (Join-Path $PSScriptRoot '..\AppSettings.ps1')

# Fake ScriptRoot with a fake DefaultData\*.audit, to test first-run logic
# without depending on the repo's real CIS files.
$fakeScriptRoot = Join-Path $TempDir 'src'
$fakeDefaultData = Join-Path $fakeScriptRoot 'DefaultData'
New-Item -ItemType Directory -Path $fakeDefaultData -Force | Out-Null
1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $fakeDefaultData "Fake_$_.audit") -Value "fake $_" }

Write-Host "`n=== Test 1: Get-DefaultAppPaths ===" -ForegroundColor Cyan
$defaults = Get-DefaultAppPaths
foreach ($key in @('logDir', 'tempDir', 'backupRoot', 'importExportDir', 'auditFilesDir', 'indexDir')) {
    Assert-True -Condition ($defaults.ContainsKey($key) -and $defaults[$key]) -Message "Get-DefaultAppPaths contient '$key'"
}
Assert-Equal -Expected 'C:\Windows\Logs\Gpeditor_plus\' -Actual $defaults.logDir -Message 'Defaut logDir'
Assert-Equal -Expected 'C:\ProgramData\Gpeditor_plus\Backup\' -Actual $defaults.backupRoot -Message 'Defaut backupRoot'

Write-Host "`n=== Test 2: Get-AppSettings sans fichier existant => defauts ===" -ForegroundColor Cyan
$settings = Get-AppSettings
Assert-Equal -Expected $defaults.logDir -Actual $settings.paths.logDir -Message 'Get-AppSettings (absent) reprend le defaut logDir'
Assert-Equal -Expected $true -Actual $settings.editorMode -Message 'Get-AppSettings (absent) editorMode par defaut true'

Write-Host "`n=== Test 3: Save-AppSettings / Get-AppSettings round-trip ===" -ForegroundColor Cyan
$settings.paths.logDir = (Join-Path $TempDir 'CustomLogs\')
$settings.editorMode = $false
Save-AppSettings -Settings $settings
$reloaded = Get-AppSettings
Assert-Equal -Expected $settings.paths.logDir -Actual $reloaded.paths.logDir -Message 'Round-trip logDir'
Assert-Equal -Expected $false -Actual $reloaded.editorMode -Message 'Round-trip editorMode'
Assert-Equal -Expected $defaults.backupRoot -Actual $reloaded.paths.backupRoot -Message 'Round-trip preserve les cles non modifiees'

Write-Host "`n=== Test 4: fusion tolerante d'un settings.json partiel ===" -ForegroundColor Cyan
'{ "paths": { "logDir": "D:\\PartialOnly\\" } }' | Set-Content -LiteralPath (Get-AppSettingsPath) -Encoding UTF8
$partial = Get-AppSettings
Assert-Equal -Expected 'D:\PartialOnly\' -Actual $partial.paths.logDir -Message 'Cle presente reprise du fichier partiel'
Assert-Equal -Expected $defaults.backupRoot -Actual $partial.paths.backupRoot -Message 'Cle absente repliee sur le defaut'
Assert-Equal -Expected $true -Actual $partial.editorMode -Message 'editorMode absent replie sur le defaut (true)'

Write-Host "`n=== Test 5: Set-AppSettingPath ===" -ForegroundColor Cyan
$settings = Get-AppSettings
Set-AppSettingPath -Settings $settings -Key 'auditFilesDir' -Value (Join-Path $TempDir 'CustomAudit\')
$afterSet = Get-AppSettings
Assert-Equal -Expected (Join-Path $TempDir 'CustomAudit\') -Actual $afterSet.paths.auditFilesDir -Message 'Set-AppSettingPath persiste immediatement'

Write-Host "`n=== Test 6: Initialize-AppSettingsFirstRun (premier lancement) ===" -ForegroundColor Cyan
Remove-Item -LiteralPath (Get-AppSettingsPath) -Force
$firstRunSettings = Get-AppSettings
# Real defaults (C:\Windows\Logs, C:\ProgramData) require admin rights (app
# always runs elevated, see Test-IsRunningAsAdministorator) - out of scope
# for this unit test: redirect the 6 paths to the test folder before
# calling Initialize-AppSettingsFirstRun, to verify only the create/seed
# logic, not the real locations.
foreach ($key in @($firstRunSettings.paths.PSObject.Properties.Name)) {
    $firstRunSettings.paths.$key = Join-Path $TempDir "FirstRun\$key\"
}
Initialize-AppSettingsFirstRun -Settings $firstRunSettings -ScriptRoot $fakeScriptRoot
Assert-True -Condition (Test-Path -LiteralPath (Get-AppSettingsPath)) -Message 'settings.json cree au premier lancement'
foreach ($prop in $firstRunSettings.paths.PSObject.Properties) {
    Assert-True -Condition (Test-Path -LiteralPath $prop.Value) -Message "Dossier cree : $($prop.Value)"
}
$copiedAuditFiles = @(Get-ChildItem -LiteralPath $firstRunSettings.paths.auditFilesDir -Filter '*.audit')
Assert-Equal -Expected 3 -Actual $copiedAuditFiles.Count -Message 'Les 3 fichiers .audit de DefaultData sont copies'

Write-Host "`n=== Test 7: Initialize-AppSettingsFirstRun ne re-seed jamais ===" -ForegroundColor Cyan
Remove-Item -LiteralPath (Join-Path $firstRunSettings.paths.auditFilesDir 'Fake_1.audit') -Force
$secondRunSettings = Get-AppSettings
Initialize-AppSettingsFirstRun -Settings $secondRunSettings -ScriptRoot $fakeScriptRoot
$remainingAuditFiles = @(Get-ChildItem -LiteralPath $secondRunSettings.paths.auditFilesDir -Filter '*.audit')
Assert-Equal -Expected 2 -Actual $remainingAuditFiles.Count -Message 'Le fichier supprime par l''utilisateur n''est pas restaure (settings.json deja present)'

Write-Host "`n=== Resultat : $($script:TestCount - $script:FailCount)/$($script:TestCount) tests reussis ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
