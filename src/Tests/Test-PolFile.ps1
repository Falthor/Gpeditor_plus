<#
    Regression tests for the custom .pol parser (PolFile.ps1). A single
    misplaced byte makes the file unreadable by gpedit.msc: these tests
    verify binary exactness (round-trip) and format compliance.
#>
param(
    [string]$TestFile = (Join-Path $env:TEMP 'gpedit-pol-test.pol')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Parsers\PolFile.ps1')

$script:TestCount = 0
$script:FailCount = 0

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    $script:TestCount++
    $eq = $false
    if ($Expected -is [array] -or $Actual -is [array]) {
        $eq = @(Compare-Object @($Expected) @($Actual) -SyncWindow 0).Count -eq 0
    }
    elseif ($Expected -is [byte[]] -or $Actual -is [byte[]]) {
        $eq = [System.Linq.Enumerable]::SequenceEqual([byte[]]$Expected, [byte[]]$Actual)
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

Write-Host "=== Test 1: round-trip of value types ===" -ForegroundColor Cyan

$original = New-Object System.Collections.Generic.List[object]
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'StringVal' -Type (Get-RegTypeValue 'REG_SZ') -Value 'Bonjour, ceci est un test avec des accents : éàçùê€'))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'ExpandVal' -Type (Get-RegTypeValue 'REG_EXPAND_SZ') -Value '%SystemRoot%\System32'))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'DwordVal' -Type (Get-RegTypeValue 'REG_DWORD') -Value 42))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'DwordMax' -Type (Get-RegTypeValue 'REG_DWORD') -Value 4294967295))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'QwordVal' -Type (Get-RegTypeValue 'REG_QWORD') -Value 9999999999))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'MultiVal' -Type (Get-RegTypeValue 'REG_MULTI_SZ') -Value @('ligne1', 'ligne2', 'ligne3 avec é')))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'BinVal' -Type (Get-RegTypeValue 'REG_BINARY') -Value ([byte[]](1, 2, 3, 255, 0, 128))))
$original.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'EmptyString' -Type (Get-RegTypeValue 'REG_SZ') -Value ''))
$original.Add((New-PolDeleteValueEntry -KeyName 'Software\Policies\Test' -ValueName 'ObsoleteVal'))
$original.Add((New-PolDeleteAllValuesEntry -KeyName 'Software\Policies\OldKey'))

Write-PolFile -Path $TestFile -Entries $original
$readBack = Read-PolFile -Path $TestFile

Assert-Equal -Expected $original.Count -Actual $readBack.Count -Message "Nombre d'entrees relu identique ($($readBack.Count))"

Assert-Equal -Expected 'Bonjour, ceci est un test avec des accents : éàçùê€' -Actual $readBack[0].Value -Message 'REG_SZ avec accents/unicode'
Assert-Equal -Expected '%SystemRoot%\System32' -Actual $readBack[1].Value -Message 'REG_EXPAND_SZ'
Assert-Equal -Expected 42 -Actual $readBack[2].Value -Message 'REG_DWORD valeur simple'
Assert-Equal -Expected 4294967295 -Actual $readBack[3].Value -Message 'REG_DWORD valeur maximale (uint32)'
Assert-Equal -Expected 9999999999 -Actual $readBack[4].Value -Message 'REG_QWORD'
Assert-Equal -Expected @('ligne1', 'ligne2', 'ligne3 avec é') -Actual $readBack[5].Value -Message 'REG_MULTI_SZ'
Assert-Equal -Expected ([byte[]](1, 2, 3, 255, 0, 128)) -Actual $readBack[6].Value -Message 'REG_BINARY'
Assert-Equal -Expected '' -Actual $readBack[7].Value -Message 'REG_SZ vide'
Assert-Equal -Expected '**del.ObsoleteVal' -Actual $readBack[8].ValueName -Message 'Marqueur de suppression de valeur'
Assert-Equal -Expected $true -Actual (Test-PolValueIsDeleteMarker $readBack[8].ValueName) -Message 'Detection marqueur **del.'
Assert-Equal -Expected $true -Actual (Test-PolValueIsDeleteMarker $readBack[9].ValueName) -Message 'Detection marqueur **delvals.'

foreach ($i in 0..($original.Count - 1)) {
    Assert-Equal -Expected $original[$i].KeyName -Actual $readBack[$i].KeyName -Message "KeyName identique (entree $i)"
    Assert-Equal -Expected $original[$i].ValueName -Actual $readBack[$i].ValueName -Message "ValueName identique (entree $i)"
    Assert-Equal -Expected $original[$i].Type -Actual $readBack[$i].Type -Message "Type identique (entree $i)"
}

Write-Host "`n=== Test 2: binary stability (write -> read -> write) ===" -ForegroundColor Cyan
$bytes1 = [System.IO.File]::ReadAllBytes($TestFile)
$testFile2 = $TestFile + '.roundtrip2'
Write-PolFile -Path $testFile2 -Entries $readBack
$bytes2 = [System.IO.File]::ReadAllBytes($testFile2)
Assert-Equal -Expected $bytes1.Length -Actual $bytes2.Length -Message "Taille de fichier identique apres 2e ecriture ($($bytes1.Length) octets)"
$identical = [System.Linq.Enumerable]::SequenceEqual([byte[]]$bytes1, [byte[]]$bytes2)
Assert-Equal -Expected $true -Actual $identical -Message 'Octets strictement identiques apres double round-trip'
Remove-Item -LiteralPath $testFile2 -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 3: PReg header ===" -ForegroundColor Cyan
$rawBytes = [System.IO.File]::ReadAllBytes($TestFile)
$sig = [BitConverter]::ToUInt32($rawBytes, 0)
$ver = [BitConverter]::ToUInt32($rawBytes, 4)
Assert-Equal -Expected 0x67655250 -Actual $sig -Message 'Signature PReg (0x67655250)'
Assert-Equal -Expected 1 -Actual $ver -Message 'Version = 1'

Write-Host "`n=== Test 4: empty file (0 entries) ===" -ForegroundColor Cyan
$emptyFile = $TestFile + '.empty'
Write-PolFile -Path $emptyFile -Entries @()
$emptyBytes = [System.IO.File]::ReadAllBytes($emptyFile)
Assert-Equal -Expected 8 -Actual $emptyBytes.Length -Message 'Fichier vide = 8 octets (en-tete seul)'
$emptyRead = Read-PolFile -Path $emptyFile
Assert-Equal -Expected 0 -Actual $emptyRead.Count -Message 'Relecture fichier vide = 0 entree'
Remove-Item -LiteralPath $emptyFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Test 5: invalid signature detected ===" -ForegroundColor Cyan
$badFile = $TestFile + '.bad'
[System.IO.File]::WriteAllBytes($badFile, [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
$threw = $false
try { Read-PolFile -Path $badFile | Out-Null } catch { $threw = $true }
Assert-Equal -Expected $true -Actual $threw -Message 'Exception levee sur signature invalide'
Remove-Item -LiteralPath $badFile -Force -ErrorAction SilentlyContinue

Remove-Item -LiteralPath $TestFile -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Result: $($script:TestCount - $script:FailCount)/$($script:TestCount) tests passed ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
