<#
    Pester regression suite for Gpeditor_plus.

    Covers the binary/text parsers (PolFile, GptTmplFile, GptIniFile,
    AuditCsvFile), the policy merge/write engine (PolicyWriter), app
    settings persistence (AppSettings) and the CIS benchmark catalog
    (CisCatalog). All file I/O happens under Pester's $TestDrive, so
    nothing here touches real system paths.

    Run with:  Invoke-Pester (Join-Path $PSScriptRoot 'Gpeditor_plus.Tests.ps1')
    Filter by kind: Invoke-Pester ... -TagFilter Regression

    Tag legend (kind of test, set on each Describe/Context):
      Unit        - pure function logic, no dependency on other modules
      RoundTrip   - write -> read (or write -> read -> write) fidelity check
      Regression  - pinned to a specific historical bug, named in the test
      Catalog     - static reference data integrity (counts, uniqueness, lookups)
      Integration - exercises several modules together and/or real repo data
                    (real CIS .audit files, real first-run bootstrap flow)
#>

BeforeDiscovery {
    $script:SrcRoot = Split-Path -Parent $PSScriptRoot
}

Describe 'PolFile' -Tag 'Unit' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Parsers\PolFile.ps1')
    }

    Context 'round-trip of value types' -Tag 'RoundTrip' {

        BeforeAll {
            $script:PolTestFile = Join-Path $TestDrive 'gpedit-pol-test.pol'

            $script:original = New-Object System.Collections.Generic.List[object]
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

            Write-PolFile -Path $PolTestFile -Entries $original
            $script:readBack = Read-PolFile -Path $PolTestFile
        }

        It 'reads back the same number of entries' {
            $readBack.Count | Should -Be $original.Count
        }

        It 'preserves REG_SZ with accents/unicode' {
            $readBack[0].Value | Should -Be 'Bonjour, ceci est un test avec des accents : éàçùê€'
        }

        It 'preserves REG_EXPAND_SZ' {
            $readBack[1].Value | Should -Be '%SystemRoot%\System32'
        }

        It 'preserves a simple REG_DWORD value' {
            $readBack[2].Value | Should -Be 42
        }

        It 'preserves the maximum REG_DWORD value (uint32)' {
            $readBack[3].Value | Should -Be 4294967295
        }

        It 'preserves REG_QWORD' {
            $readBack[4].Value | Should -Be 9999999999
        }

        It 'preserves REG_MULTI_SZ' {
            @($readBack[5].Value) | Should -Be @('ligne1', 'ligne2', 'ligne3 avec é')
        }

        It 'preserves REG_BINARY' {
            [byte[]]$readBack[6].Value | Should -Be ([byte[]](1, 2, 3, 255, 0, 128))
        }

        It 'preserves an empty REG_SZ' {
            $readBack[7].Value | Should -Be ''
        }

        It 'writes a value-deletion marker' {
            $readBack[8].ValueName | Should -Be '**del.ObsoleteVal'
        }

        It 'detects the **del. marker' {
            Test-PolValueIsDeleteMarker $readBack[8].ValueName | Should -BeTrue
        }

        It 'detects the **delvals. marker' {
            Test-PolValueIsDeleteMarker $readBack[9].ValueName | Should -BeTrue
        }

        It 'preserves KeyName/ValueName/Type for entry <_>' -ForEach (0..9) {
            $readBack[$_].KeyName | Should -Be $original[$_].KeyName
            $readBack[$_].ValueName | Should -Be $original[$_].ValueName
            $readBack[$_].Type | Should -Be $original[$_].Type
        }
    }

    Context 'binary stability (write -> read -> write)' -Tag 'RoundTrip' {

        It 'produces byte-identical output after a second write' {
            $testFile = Join-Path $TestDrive 'stability.pol'
            $entries = New-Object System.Collections.Generic.List[object]
            $entries.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'V' -Type (Get-RegTypeValue 'REG_SZ') -Value 'x'))
            Write-PolFile -Path $testFile -Entries $entries
            $readBack = Read-PolFile -Path $testFile
            $bytes1 = [System.IO.File]::ReadAllBytes($testFile)

            $testFile2 = Join-Path $TestDrive 'stability2.pol'
            Write-PolFile -Path $testFile2 -Entries $readBack
            $bytes2 = [System.IO.File]::ReadAllBytes($testFile2)

            $bytes2.Length | Should -Be $bytes1.Length
            [System.Linq.Enumerable]::SequenceEqual([byte[]]$bytes1, [byte[]]$bytes2) | Should -BeTrue
        }
    }

    Context 'PReg header' {

        It 'writes the correct signature and version' {
            $testFile = Join-Path $TestDrive 'header.pol'
            Write-PolFile -Path $testFile -Entries @()
            $rawBytes = [System.IO.File]::ReadAllBytes($testFile)
            [BitConverter]::ToUInt32($rawBytes, 0) | Should -Be 0x67655250
            [BitConverter]::ToUInt32($rawBytes, 4) | Should -Be 1
        }
    }

    Context 'empty file (0 entries)' {

        It 'writes an 8-byte file containing only the header' {
            $emptyFile = Join-Path $TestDrive 'empty.pol'
            Write-PolFile -Path $emptyFile -Entries @()
            (Get-Item -LiteralPath $emptyFile).Length | Should -Be 8
        }

        It 'reads back zero entries' {
            $emptyFile = Join-Path $TestDrive 'empty2.pol'
            Write-PolFile -Path $emptyFile -Entries @()
            (Read-PolFile -Path $emptyFile).Count | Should -Be 0
        }
    }

    Context 'invalid signature' {

        It 'throws when the signature is not recognized' {
            $badFile = Join-Path $TestDrive 'bad.pol'
            [System.IO.File]::WriteAllBytes($badFile, [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
            { Read-PolFile -Path $badFile } | Should -Throw
        }
    }
}

Describe 'GptTmplFile & SecurityCatalog' -Tag 'Unit' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Parsers\GptTmplFile.ps1')
        . (Join-Path $SrcRoot 'Catalogs\SecurityCatalog.ps1')

        $script:GptTestFile = Join-Path $TestDrive 'gpedit-inf-test.inf'
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

        [System.IO.File]::WriteAllText($GptTestFile, $sample, (New-Object System.Text.UnicodeEncoding($false, $true)))
        $script:gpt = Read-GptTmplInf -Path $GptTestFile
    }

    Context 'parsing a realistic GptTmpl.inf' {

        It 'detects Unicode (UTF-16LE with BOM) encoding' {
            $gpt.Encoding | Should -Be 'Unicode'
        }

        It 'reads MinimumPasswordAge' {
            Get-GptTmplValue $gpt 'System Access' 'MinimumPasswordAge' | Should -Be '1'
        }

        It 'reads MaximumPasswordAge' {
            Get-GptTmplValue $gpt 'System Access' 'MaximumPasswordAge' | Should -Be '42'
        }

        It 'reads LockoutDuration = -1 (manual unlock)' {
            Get-GptTmplValue $gpt 'System Access' 'LockoutDuration' | Should -Be '-1'
        }

        It 'preserves quoted strings (NewAdministratorName)' {
            Get-GptTmplValue $gpt 'System Access' 'NewAdministratorName' | Should -Be '"Admin Local"'
        }

        It 'reads AuditSystemEvents = 3 (success+failure)' {
            Get-GptTmplValue $gpt 'Event Audit' 'AuditSystemEvents' | Should -Be '3'
        }

        It 'passes through Registry Values verbatim' {
            Get-GptTmplValue $gpt 'Registry Values' 'MACHINE\Software\Policies\Microsoft\Windows\Test\Value1' | Should -Be '4,1'
        }

        It 'reads a SID list (SeNetworkLogonRight)' {
            Get-GptTmplValue $gpt 'Privilege Rights' 'SeNetworkLogonRight' | Should -Be '*S-1-5-32-544,*S-1-5-32-545,*S-1-5-11'
        }

        It 'distinguishes an explicitly empty list from not-configured' {
            Get-GptTmplValue $gpt 'Privilege Rights' 'SeBackupPrivilege' | Should -Be ''
        }

        It 'returns $null for an unconfigured privilege' {
            Get-GptTmplValue $gpt 'Privilege Rights' 'SeShutdownPrivilege' | Should -BeNullOrEmpty
        }

        It 'splits a SID list into an array' {
            $members = ConvertTo-PrivilegeMemberList -Value (Get-GptTmplValue $gpt 'Privilege Rights' 'SeNetworkLogonRight')
            @($members) | Should -Be @('*S-1-5-32-544', '*S-1-5-32-545', '*S-1-5-11')
        }
    }

    Context 'semantic round-trip (write -> read)' -Tag 'RoundTrip' {

        It 'preserves every section/key value after a round-trip' {
            $roundtripFile = Join-Path $TestDrive 'roundtrip.inf'
            Write-GptTmplInf -Path $roundtripFile -GptTmpl $gpt
            $gpt2 = Read-GptTmplInf -Path $roundtripFile

            foreach ($secName in $gpt.Sections.Keys) {
                foreach ($key in $gpt.Sections[$secName].Keys) {
                    $gpt2.Sections[$secName][$key] | Should -Be $gpt.Sections[$secName][$key]
                }
            }
        }
    }

    Context 'modification then rewrite' {

        BeforeAll {
            Set-GptTmplValue -GptTmpl $gpt -Section 'System Access' -Key 'MinimumPasswordLength' -Value '12'
            Set-GptTmplValue -GptTmpl $gpt -Section 'Privilege Rights' -Key 'SeShutdownPrivilege' -Value '*S-1-5-32-544'
            $modifiedFile = Join-Path $TestDrive 'modified.inf'
            Write-GptTmplInf -Path $modifiedFile -GptTmpl $gpt
            $script:gpt3 = Read-GptTmplInf -Path $modifiedFile
        }

        It 'persists a modified value' {
            Get-GptTmplValue $gpt3 'System Access' 'MinimumPasswordLength' | Should -Be '12'
        }

        It 'persists a newly added key' {
            Get-GptTmplValue $gpt3 'Privilege Rights' 'SeShutdownPrivilege' | Should -Be '*S-1-5-32-544'
        }
    }

    Context 'missing file' {

        It 'returns a valid default structure' {
            $missing = Read-GptTmplInf -Path (Join-Path $TestDrive 'fichier-inexistant.inf')
            Get-GptTmplValue $missing 'Unicode' 'Unicode' | Should -Be 'yes'
            Get-GptTmplValue $missing 'System Access' 'MinimumPasswordAge' | Should -BeNullOrEmpty
        }
    }

    Context 'security catalog' -Tag 'Catalog' {

        BeforeAll {
            $script:entries = Get-SecurityCatalogEntries
        }

        It 'contains a plausible number of entries' {
            $entries.Count | Should -BeGreaterThan 40
        }

        It 'categorizes SeNetworkLogonRight as User Rights Assignment' {
            ($entries | Where-Object { $_.name -eq 'SeNetworkLogonRight' }).category | Should -Be 'User Rights Assignment'
        }

        It 'categorizes MinimumPasswordLength as Password Policy' {
            ($entries | Where-Object { $_.name -eq 'MinimumPasswordLength' }).category | Should -Be 'Password Policy'
        }
    }
}

Describe 'AuditCsvFile & AdvancedAuditCatalog' -Tag 'Unit' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Parsers\AuditCsvFile.ps1')
        . (Join-Path $SrcRoot 'Catalogs\AdvancedAuditCatalog.ps1')
    }

    Context 'missing file' {

        It 'returns no rows' {
            $rows = Read-AuditCsv -Path (Join-Path $TestDrive 'inexistant-audit-test.csv')
            $rows.Count | Should -Be 0
        }
    }

    Context 'write, reread, match by GUID' -Tag 'RoundTrip' {

        BeforeAll {
            $script:AuditTestFile = Join-Path $TestDrive 'gpedit-audit-test.csv'
            $rows2 = @{}
            Set-AuditCsvValue -Rows $rows2 -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' -SubcategoryName 'Logon' -SettingValue 3
            Set-AuditCsvValue -Rows $rows2 -Guid '{0cce9216-69ae-11d9-bed3-505054503030}' -SubcategoryName 'Logoff' -SettingValue 1
            Write-AuditCsv -Path $AuditTestFile -Rows $rows2
            $script:reread = Read-AuditCsv -Path $AuditTestFile
        }

        It 'rereads two rows' {
            $reread.Count | Should -Be 2
        }

        It 'reads back Setting Value and Inclusion Setting for Logon (3)' {
            $logon = Get-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}'
            $logon['Setting Value'] | Should -Be '3'
            $logon['Inclusion Setting'] | Should -Be 'Success and Failure'
        }

        It 'reads back Setting Value and Inclusion Setting for Logoff (1)' {
            $logoff = Get-AuditCsvValue -Rows $reread -Guid '{0CCE9216-69AE-11D9-BED3-505054503030}'
            $logoff['Setting Value'] | Should -Be '1'
            $logoff['Inclusion Setting'] | Should -Be 'Success'
        }

        It 'matches GUIDs case-insensitively' {
            Get-AuditCsvValue -Rows $reread -Guid '{0cce9215-69ae-11d9-bed3-505054503030}' | Should -Not -BeNullOrEmpty
        }

        It 'removes a value' {
            Remove-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}'
            $reread.Count | Should -Be 1
            Get-AuditCsvValue -Rows $reread -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' | Should -BeNullOrEmpty
        }

        It 'preserves row count through a full round-trip (write -> reread -> rewrite)' {
            $testFile2 = Join-Path $TestDrive 'gpedit-audit-test-2.csv'
            Write-AuditCsv -Path $testFile2 -Rows $reread
            $reread2 = Read-AuditCsv -Path $testFile2
            $reread2.Count | Should -Be $reread.Count
        }
    }

    Context 'subcategory catalog' -Tag 'Catalog' {

        BeforeAll {
            $script:catalog = Get-AdvancedAuditCatalogEntries
        }

        It 'contains 59 subcategories' {
            $catalog.Count | Should -Be 59
        }

        It 'has no duplicate GUIDs' {
            $guids = $catalog | ForEach-Object { $_.guid }
            @($guids | Select-Object -Unique).Count | Should -Be 59
        }

        It "has the correct displayName for 'Logon'" {
            ($catalog | Where-Object { $_.name -eq 'Logon' }).displayName | Should -Be 'Logon'
        }
    }
}

Describe 'PolicyWriter' -Tag 'Unit' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Parsers\PolFile.ps1')
        . (Join-Path $SrcRoot 'Parsers\GptIniFile.ps1')
        . (Join-Path $SrcRoot 'Parsers\GptTmplFile.ps1')
        . (Join-Path $SrcRoot 'Policy\PolicyWriter.ps1')

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
    }

    Context 'NotConfigured -> Enabled (simple, no elements)' {

        It 'adds a single entry with the enabledValue and inferred REG_DWORD type' {
            $pol1 = New-TestPolicy
            $entries = New-Object System.Collections.Generic.List[object]
            $result = Merge-PolEntriesForPolicy -Entries $entries -Policy $pol1 -NewState 'Enabled'
            $result.Count | Should -Be 1
            $result[0].ValueName | Should -Be 'MyValue'
            $result[0].Value | Should -Be 1
            $result[0].Type | Should -Be 4
        }
    }

    Context 'Enabled -> NotConfigured (existing value -> delete marker)' {

        It 'replaces the value with a deletion marker' {
            $pol1 = New-TestPolicy
            $entries = New-Object System.Collections.Generic.List[object]
            $result = Merge-PolEntriesForPolicy -Entries $entries -Policy $pol1 -NewState 'Enabled'
            $result2 = Merge-PolEntriesForPolicy -Entries $result -Policy $pol1 -NewState 'NotConfigured'
            $result2.Count | Should -Be 1
            $result2[0].ValueName | Should -Be '**del.MyValue'
        }
    }

    Context 'NotConfigured -> Disabled (never had a value)' {

        It 'writes the disabledValue' {
            $pol1 = New-TestPolicy
            $emptyEntries = New-Object System.Collections.Generic.List[object]
            $result3 = Merge-PolEntriesForPolicy -Entries $emptyEntries -Policy $pol1 -NewState 'Disabled'
            $result3.Count | Should -Be 1
            $result3[0].Value | Should -Be 0
        }
    }

    Context 'Disabled with no disabledValue set' {

        It 'removes an existing value via a deletion marker' {
            $polNoDisabled = New-TestPolicy -DisabledValue $null
            $entriesWithValue = New-Object System.Collections.Generic.List[object]
            $entriesWithValue.Add((New-PolEntry -KeyName 'Software\Policies\Test' -ValueName 'MyValue' -Type 4 -Value 1))
            $result4 = Merge-PolEntriesForPolicy -Entries $entriesWithValue -Policy $polNoDisabled -NewState 'Disabled'
            $result4.Count | Should -Be 1
            $result4[0].ValueName | Should -Be '**del.MyValue'
        }

        It 'writes nothing when never configured' {
            $polNoDisabled = New-TestPolicy -DisabledValue $null
            $result5 = Merge-PolEntriesForPolicy -Entries (New-Object System.Collections.Generic.List[object]) -Policy $polNoDisabled -NewState 'Disabled'
            $result5.Count | Should -Be 0
        }
    }

    Context 'Elements (enum, decimal, text, multiText, boolean)' {

        BeforeAll {
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
            $script:result6 = Merge-PolEntriesForPolicy -Entries $existingForBool -Policy $polWithElements -NewState 'Enabled' -ElementValues $elementValues

            $script:byName = @{}
            foreach ($e in $result6) { $byName[$e.ValueName] = $e }
        }

        It 'writes the correct enum value' { $byName['EnumVal'].Value | Should -Be 1 }
        It 'writes the correct decimal value' { $byName['DecVal'].Value | Should -Be 42 }
        It 'writes the correct text value' { $byName['TxtVal'].Value | Should -Be 'hello' }
        It 'writes the correct multiText values' { @($byName['MultiVal'].Value) | Should -Be @('a','b','c') }
        It 'writes DWORD 1 for a checked boolean without trueValue' { $byName['BoolChecked'].Value | Should -Be 1 }
        It 'writes a deletion marker for an unchecked boolean that had a value' {
            $byName.ContainsKey('**del.BoolUnchecked') | Should -BeTrue
        }

        It 'survives a round-trip via Write-PolFile/Read-PolFile' -Tag 'RoundTrip' {
            $polFilePath = Join-Path $TestDrive 'elements.pol'
            Write-PolFile -Path $polFilePath -Entries $result6
            $rereadEl = Read-PolFile -Path $polFilePath
            $rereadEl.Count | Should -Be $result6.Count

            $rereadByName = @{}
            foreach ($e in $rereadEl) { $rereadByName[$e.ValueName] = $e }
            $rereadByName['DecVal'].Value | Should -Be 42
            @($rereadByName['MultiVal'].Value) | Should -Be @('a','b','c')
        }
    }

    Context 'GPT.ini version increment (independent Machine/User)' -Tag 'RoundTrip' {

        BeforeEach {
            # Fresh file + freshly-read $gptIni per It: Step-GptIniVersion mutates
            # $gptIni in place, so sharing it across It blocks would make each
            # test's outcome depend on execution order of its siblings.
            $script:GptIniPath = Join-Path $TestDrive "GPT-$([guid]::NewGuid().ToString('N')).ini"
            [System.IO.File]::WriteAllText($GptIniPath, "[General]`r`ngPCMachineExtensionNames=`r`nVersion=65537`r`n", [System.Text.Encoding]::Default)
            $script:gptIni = Read-GptIni -Path $GptIniPath
        }

        It 'reads the initial version (65537 = machine=1,user=1)' {
            $gptIni.Sections['General']['Version'] | Should -Be '65537'
        }

        It 'increments Machine and User independently, then persists across write/reread' {
            Step-GptIniVersion -GptIni $gptIni -IncrementMachine | Out-Null
            $gptIni.Sections['General']['Version'] | Should -Be "$((2 -shl 16) -bor 1)"

            Step-GptIniVersion -GptIni $gptIni -IncrementUser | Out-Null
            $gptIni.Sections['General']['Version'] | Should -Be "$((2 -shl 16) -bor 2)"

            Write-GptIni -Path $GptIniPath -GptIni $gptIni
            $gptIniReread = Read-GptIni -Path $GptIniPath
            $gptIniReread.Sections['General']['Version'] | Should -Be $gptIni.Sections['General']['Version']
            $gptIniReread.Sections['General']['gPCMachineExtensionNames'] | Should -Be ''
        }
    }

    Context 'GPT.ini missing' {

        It 'defaults Version to 0' {
            $missingIni = Read-GptIni -Path (Join-Path $TestDrive 'inexistant.ini')
            $missingIni.Sections['General']['Version'] | Should -Be '0'
        }
    }

    Context 'timestamped backup' {

        It 'backs up files into a fresh timestamped folder without name collisions' {
            $srcMachine = Join-Path $TestDrive 'machine-registry.pol'
            $srcUser = Join-Path $TestDrive 'user-registry.pol'
            [System.IO.File]::WriteAllText($srcMachine, 'MACHINE-CONTENT')
            [System.IO.File]::WriteAllText($srcUser, 'USER-CONTENT')
            $backupRoot = Join-Path $TestDrive 'Backups'
            $backupResult = New-TimestampedBackup -FilesToBackup @{ 'Machine_registry.pol' = $srcMachine; 'User_registry.pol' = $srcUser } -BackupRoot $backupRoot

            Test-Path -LiteralPath $backupResult.BackupDir | Should -BeTrue
            $backupResult.Files.Count | Should -Be 2

            $backedUpMachine = Join-Path $backupResult.BackupDir 'Machine_registry.pol'
            $backedUpUser = Join-Path $backupResult.BackupDir 'User_registry.pol'
            Get-Content -Raw $backedUpMachine | Should -Be 'MACHINE-CONTENT'
            Get-Content -Raw $backedUpUser | Should -Be 'USER-CONTENT'
        }
    }

    Context 'applying security changes to GptTmpl.inf' {

        It 'removes an unconfigured setting and writes a configured one' {
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

            Get-GptTmplValue $gpt 'System Access' 'MinimumPasswordLength' | Should -BeNullOrEmpty
            Get-GptTmplValue $gpt 'System Access' 'PasswordComplexity' | Should -Be '1'
        }
    }

    Context 'Apply-AdmxChangesToEntries (multi-policy orchestration)' {

        BeforeAll {
            $polA = New-TestPolicy -Id 'Test::PolA' -ValueName 'ValA'
            $polB = New-TestPolicy -Id 'Test::PolB' -ValueName 'ValB'
            $script:policiesById = @{ 'Test::PolA' = $polA; 'Test::PolB' = $polB }
            $script:pendingAdmx = @{
                'Test::PolA|Machine' = @{ State = 'Enabled'; ElementValues = @{} }
                'Test::PolB|Machine' = @{ State = 'Enabled'; ElementValues = @{} }
                'Test::PolA|User'    = @{ State = 'Enabled'; ElementValues = @{} }
            }
        }

        It 'applies only Machine-scoped policies for scope Machine' {
            $initial = New-Object System.Collections.Generic.List[object]
            $machineResult = Apply-AdmxChangesToEntries -Entries $initial -PendingChanges $pendingAdmx -Scope 'Machine' -PoliciesById $policiesById
            $machineResult.Count | Should -Be 2
        }

        It 'applies only User-scoped policies for scope User' {
            $userResult = Apply-AdmxChangesToEntries -Entries (New-Object System.Collections.Generic.List[object]) -PendingChanges $pendingAdmx -Scope 'User' -PoliciesById $policiesById
            $userResult.Count | Should -Be 1
        }
    }
}

Describe 'AppSettings' -Tag 'Unit' {

    BeforeAll {
        $script:SavedLocalAppData = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path $TestDrive 'AppData'
        New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

        . (Join-Path $SrcRoot 'Core\AppSettings.ps1')

        $script:FakeScriptRoot = Join-Path $TestDrive 'src'
        $script:FakeDefaultData = Join-Path $FakeScriptRoot 'DefaultData'
        New-Item -ItemType Directory -Path $FakeDefaultData -Force | Out-Null
        1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $FakeDefaultData "Fake_$_.audit") -Value "fake $_" }

        $script:defaults = Get-DefaultAppPaths
    }

    AfterAll {
        $env:LOCALAPPDATA = $SavedLocalAppData
    }

    Context 'Get-DefaultAppPaths' {

        It 'contains all 6 configurable paths' {
            foreach ($key in @('logDir', 'tempDir', 'backupRoot', 'importExportDir', 'auditFilesDir', 'indexDir')) {
                $defaults.ContainsKey($key) | Should -BeTrue
                $defaults[$key] | Should -Not -BeNullOrEmpty
            }
        }

        It 'defaults logDir to C:\Windows\Logs\Gpeditor_plus\' {
            $defaults.logDir | Should -Be 'C:\Windows\Logs\Gpeditor_plus\'
        }

        It 'defaults backupRoot to C:\ProgramData\Gpeditor_plus\Backup\' {
            $defaults.backupRoot | Should -Be 'C:\ProgramData\Gpeditor_plus\Backup\'
        }
    }

    Context 'Get-AppSettings without an existing file' {

        It 'falls back to defaults' {
            $settings = Get-AppSettings
            $settings.paths.logDir | Should -Be $defaults.logDir
            $settings.editorMode | Should -BeTrue
        }
    }

    Context 'Save-AppSettings / Get-AppSettings round-trip' -Tag 'RoundTrip' {

        It 'persists modified values and preserves untouched keys' {
            $settings = Get-AppSettings
            $settings.paths.logDir = Join-Path $TestDrive 'CustomLogs\'
            $settings.editorMode = $false
            Save-AppSettings -Settings $settings

            $reloaded = Get-AppSettings
            $reloaded.paths.logDir | Should -Be $settings.paths.logDir
            $reloaded.editorMode | Should -BeFalse
            $reloaded.paths.backupRoot | Should -Be $defaults.backupRoot
        }
    }

    Context 'tolerant merge of a partial settings.json' {

        It 'keeps the present key and falls back on the absent ones' {
            $settingsPath = Get-AppSettingsPath
            New-Item -ItemType Directory -Path (Split-Path -Parent $settingsPath) -Force | Out-Null
            '{ "paths": { "logDir": "D:\\PartialOnly\\" } }' | Set-Content -LiteralPath $settingsPath -Encoding UTF8
            $partial = Get-AppSettings
            $partial.paths.logDir | Should -Be 'D:\PartialOnly\'
            $partial.paths.backupRoot | Should -Be $defaults.backupRoot
            $partial.editorMode | Should -BeTrue
        }
    }

    Context 'Set-AppSettingPath' {

        It 'persists a single path immediately' {
            $settings = Get-AppSettings
            Set-AppSettingPath -Settings $settings -Key 'auditFilesDir' -Value (Join-Path $TestDrive 'CustomAudit\')
            $afterSet = Get-AppSettings
            $afterSet.paths.auditFilesDir | Should -Be (Join-Path $TestDrive 'CustomAudit\')
        }
    }

    Context 'Initialize-AppSettingsFirstRun' -Tag 'Integration' {

        BeforeAll {
            if (Test-Path -LiteralPath (Get-AppSettingsPath)) { Remove-Item -LiteralPath (Get-AppSettingsPath) -Force }
            $script:firstRunSettings = Get-AppSettings
            foreach ($key in @($firstRunSettings.paths.PSObject.Properties.Name)) {
                $firstRunSettings.paths.$key = Join-Path $TestDrive "FirstRun\$key\"
            }
            Initialize-AppSettingsFirstRun -Settings $firstRunSettings -ScriptRoot $FakeScriptRoot
        }

        It 'creates settings.json on first run' {
            Test-Path -LiteralPath (Get-AppSettingsPath) | Should -BeTrue
        }

        It 'creates every configured path folder' {
            foreach ($prop in $firstRunSettings.paths.PSObject.Properties) {
                Test-Path -LiteralPath $prop.Value | Should -BeTrue
            }
        }

        It 'seeds auditFilesDir with the 3 bundled .audit files' {
            @(Get-ChildItem -LiteralPath $firstRunSettings.paths.auditFilesDir -Filter '*.audit').Count | Should -Be 3
        }

        It 'never re-seeds once settings.json already exists' {
            Remove-Item -LiteralPath (Join-Path $firstRunSettings.paths.auditFilesDir 'Fake_1.audit') -Force
            $secondRunSettings = Get-AppSettings
            Initialize-AppSettingsFirstRun -Settings $secondRunSettings -ScriptRoot $FakeScriptRoot
            @(Get-ChildItem -LiteralPath $secondRunSettings.paths.auditFilesDir -Filter '*.audit').Count | Should -Be 2
        }
    }
}

Describe 'CisCatalog' -Tag 'Integration' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Catalogs\CisCatalog.ps1')

        $auditFilesPath = Join-Path $SrcRoot 'DefaultData\Audit'
        $outputPath = Join-Path $TestDrive 'cis-index.json'
        & (Join-Path $SrcRoot 'Indexers\Build-CisIndex.ps1') -AuditFilesPath $auditFilesPath -OutputPath $outputPath | Out-Null

        $script:cisIndex = Import-CisIndex -Path $outputPath
    }

    It 'loads the generated CIS index' {
        $cisIndex | Should -Not -BeNullOrEmpty
    }

    Context 'REGISTRY_SETTING match (NTP Client)' {

        BeforeAll {
            $script:ntp = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ValueName 'Enabled'
        }

        It 'finds an entry for NtpClient\Enabled' {
            $ntp | Should -Not -BeNullOrEmpty
        }

        It 'has the correct title' {
            $ntp.title | Should -Be "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
        }

        It 'renumbers the CIS number between the 2016 and 2019 benchmarks' {
            $profile2016 = @($ntp.profiles) | Where-Object { $_.benchmark -eq 'Microsoft Windows Server 2016' -and $_.level -eq 'L1' -and $_.role -eq 'MS' } | Select-Object -First 1
            $profile2019 = @($ntp.profiles) | Where-Object { $_.benchmark -eq 'Microsoft Windows Server 2019' -and $_.level -eq 'L1' -and $_.role -eq 'MS' } | Select-Object -First 1
            $profile2016.cisNumber | Should -Be '18.9.51.1.1'
            $profile2019.cisNumber | Should -Be '18.9.53.1.1'
            $profile2019.valueData | Should -Be '1'
        }

        It "extracts 'Enabled' via Get-CisRecommendationStateText" {
            Get-CisRecommendationStateText -CisEntry $ntp | Should -Be 'Enabled'
        }
    }

    Context 'case and HKLM prefix ignored (admx-style registryKey)' {

        It 'matches case-insensitively' {
            Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ValueName 'ENABLED' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'PASSWORD_POLICY match (via manual table)' {

        It 'resolves the @PASSWORD_HISTORY@ variable to [24..MAX]' {
            $pwdHistory = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'System Access' -Name 'PasswordHistorySize'
            $pwdHistory | Should -Not -BeNullOrEmpty
            (@($pwdHistory.profiles)[0]).valueData | Should -Be '[24..MAX]'
        }
    }

    Context 'USER_RIGHTS_POLICY match (direct name)' {

        It 'finds SeTrustedCredManAccessPrivilege' {
            Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'AUDIT_POLICY_SUBCATEGORY match' {

        It "finds 'Security Group Management' and normalizes the A||B alternative" {
            $auditSub = Get-CisRecommendationForAuditSubcategory -CisIndex $cisIndex -SubcategoryNameEn 'Security Group Management'
            $auditSub | Should -Not -BeNullOrEmpty
            (@($auditSub.profiles)[0]).valueData | Should -Be 'Success || Success, Failure'
        }
    }

    Context 'settings with no CIS match' {

        It 'returns $null instead of throwing' {
            Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\NotInAnyBenchmark' -ValueName 'DoesNotExist' | Should -BeNullOrEmpty
            Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'System Access' -Name 'SomeUncatalogedSetting' | Should -BeNullOrEmpty
            Get-CisRecommendationForAuditSubcategory -CisIndex $cisIndex -SubcategoryNameEn 'Not A Real Subcategory' | Should -BeNullOrEmpty
            Get-CisRecommendationForRegistry -CisIndex $null -RegistryKey 'Software\X' -ValueName 'Y' | Should -BeNullOrEmpty
        }
    }

    Context "Get-CisRecommendationStateText ('CIS States' column)" {

        It 'strips the equivalence clause even without punctuation (NetBIOS)' {
            $netbios = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableNetbios'
            $netbios | Should -Not -BeNullOrEmpty
            $netbios.recommendedStateText | Should -Be 'Enabled: Disable NetBIOS name resolution on public networks'
        }

        It 'works outside Administrative Templates (byUserRight)' {
            $userRight = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege'
            Get-CisRecommendationStateText -CisEntry $userRight | Should -Be 'No One'
        }

        It 'does not throw on $null and returns $null' {
            Get-CisRecommendationStateText -CisEntry $null | Should -BeNullOrEmpty
        }
    }

    Context 'Get-CisRecommendationValueForProfile - no fallback across OS families' -Tag 'Regression' {

        It 'never borrows a Server profile recommendation for a Windows 11 profile that NoLMHash does not cover' {
            # Regression: NoLMHash exists in Windows 10/Server benchmarks but in
            # no Windows 11 benchmark. The "CIS R. Value" column must never
            # borrow a Server profile's recommendation for a Windows 11
            # Stand-alone machine (real bug: NoLMHash showed "Enabled" via
            # Server 2022 on a Windows 11 Stand-alone machine).
            $ui = @{ CisOrWord = 'or' }
            $noLmHash = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'System\CurrentControlSet\Control\Lsa' -ValueName 'NoLMHash'
            $noLmHash | Should -Not -BeNullOrEmpty

            # $allProfiles must be assigned to a variable before piping:
            # Get-CisDistinctProfiles uses "return , $list" to guard against
            # empty-list-becomes-$null, which means piping directly off the
            # function call would pass the whole list as one pipeline object.
            $allProfiles = Get-CisDistinctProfiles -CisIndex $cisIndex
            $win11StandAlone = $allProfiles | Where-Object { $_.Benchmark -match 'Windows\s*11' -and $_.Benchmark -match 'Stand-alone' -and $_.Level -eq 'L1' } | Select-Object -First 1
            $win11StandAlone | Should -Not -BeNullOrEmpty
            Get-CisRecommendationValueForProfile -CisEntry $noLmHash -ActiveProfile $win11StandAlone -Ui $ui | Should -BeNullOrEmpty
        }
    }

    Context 'byTitle fallback (ANONYMOUS_SID_SETTING via cis-fallback-map.json)' {

        BeforeAll {
            # Separate index build, isolated from the top-level $cisIndex
            # fixture: this one seeds cis-fallback-map.json first (as
            # GpEdit.ps1 does from DefaultData on first run) so the
            # "Network access: Allow anonymous SID/Name translation"
            # (2.3.10.1) entry - which carries no reg_key/reg_item at all
            # in the .audit file - resolves into byTitle instead of being
            # left needsManualReview.
            $fallbackTestDir = Join-Path $TestDrive 'fallback-map-test'
            New-Item -ItemType Directory -Path $fallbackTestDir -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $SrcRoot 'DefaultData\Data_CisFallbackMap.json') -Destination (Join-Path $fallbackTestDir 'cis-fallback-map.json') -Force

            $fallbackOutputPath = Join-Path $fallbackTestDir 'cis-index.json'
            & (Join-Path $SrcRoot 'Indexers\Build-CisIndex.ps1') -AuditFilesPath $auditFilesPath -OutputPath $fallbackOutputPath | Out-Null
            $script:cisIndexWithFallback = Import-CisIndex -Path $fallbackOutputPath
        }

        It 'resolves a System Access setting with no registry backing via DisplayName' {
            $rec = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndexWithFallback -Section 'System Access' -Name 'LSAAnonymousNameLookup' -DisplayName "Network access: Allow anonymous SID/Name translation"
            $rec | Should -Not -BeNullOrEmpty
            $rec.recommendedStateText | Should -Be 'Disabled'
            (@($rec.profiles) | Where-Object { $_.cisNumber -eq '2.3.10.1' } | Select-Object -First 1).valueData | Should -Be 0
        }

        It 'still returns $null for a System Access setting with no match anywhere' {
            Get-CisRecommendationForSecuritySetting -CisIndex $cisIndexWithFallback -Section 'System Access' -Name 'SomeUncatalogedSetting' -DisplayName 'Not a real setting' | Should -BeNullOrEmpty
        }

        It 'primary matches (Registry Values / Privilege Rights) still win over the byTitle fallback' {
            # Get-CisRecommendationForSecuritySetting -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege' - already covered above without
            # -DisplayName; passing a bogus DisplayName here must not change
            # that a primary byUserRight match still wins.
            $rec = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndexWithFallback -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege' -DisplayName 'Unrelated title that would never match anything'
            $rec | Should -Not -BeNullOrEmpty
            Get-CisRecommendationStateText -CisEntry $rec | Should -Be 'No One'
        }
    }
}
