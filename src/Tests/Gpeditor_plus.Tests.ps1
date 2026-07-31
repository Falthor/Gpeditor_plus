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
            $script:entries = Get-SecurityCatalogEntry
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

        # plan-gpedit-cis-admx-check.md §3.2/§3.4 - two settings that were
        # missing from the catalog entirely, hence unreachable anywhere.
        It 'ships the two settings added for the CIS catalog gaps, with the right shape' -Tag 'Regression' {
            $relax = $entries | Where-Object catalogKey -eq 'RelaxMinimumPasswordLengthLimits'
            $relax | Should -Not -BeNullOrEmpty
            $relax.valueType | Should -Be 'reg-boolean'
            $relax.section | Should -Be 'Registry Values'
            # Registry-backed, but the real console shows it under Password
            # Policy - per-entry Category override.
            $relax.category | Should -Be 'Password Policy'

            $sealing = $entries | Where-Object catalogKey -eq 'LDAPClientConfidentiality'
            $sealing | Should -Not -BeNullOrEmpty
            $sealing.valueType | Should -Be 'reg-enum'
            $sealing.category | Should -Be 'Security Options'
            @($sealing.choices).Count | Should -Be 3
        }

        It 'keeps the live catalog editor able to resolve an overridden category' -Tag 'Regression' {
            # Without a matching row in SecurityCatalogVariableByCategorySection,
            # the pencil button could not find the source catalog to patch.
            Get-SecurityCatalogVariableName -Category 'Password Policy' -Section 'Registry Values' | Should -Be 'SecurityOptionsRegistryCatalog'
        }
    }

    Context 'Merge-SecurityCatalogBundledEntry' -Tag 'Regression' {

        # GpEdit.ps1 only copies the bundled catalog into indexDir when the
        # file is absent (it must never clobber catalog-editor edits), so a
        # setting added by a later app version would otherwise stay invisible
        # on any machine that already ran the app once.

        BeforeEach {
            $script:bundledPath = Join-Path $SrcRoot 'DefaultData\Data_SecurityCatalog.json'
            $script:userPath = Join-Path $TestDrive 'user-catalog.json'

            # A stale copy: two known settings removed, one entry edited by
            # "the user", and a whole catalog missing (older file layout).
            $stale = Get-Content -Raw -Encoding UTF8 -LiteralPath $bundledPath | ConvertFrom-Json
            $stale.SecurityOptionsRegistryCatalog = @($stale.SecurityOptionsRegistryCatalog | Where-Object { $_.Key -notin @('LDAPClientConfidentiality', 'RelaxMinimumPasswordLengthLimits') })
            ($stale.SecurityOptionsRegistryCatalog | Where-Object Key -eq 'LDAPClientIntegrity').DisplayName = 'EDITED BY USER'
            $stale.PSObject.Properties.Remove('AuditPolicyCatalog')
            [System.IO.File]::WriteAllText($userPath, ($stale | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($true)))
        }

        It 'adds missing settings and missing catalogs without touching existing entries' {
            $added = Merge-SecurityCatalogBundledEntry -BundledPath $bundledPath -UserPath $userPath
            $added | Should -Be 11   # 2 new settings + the 9 restored audit-policy entries

            $merged = Get-Content -Raw -Encoding UTF8 -LiteralPath $userPath | ConvertFrom-Json
            @($merged.SecurityOptionsRegistryCatalog | Where-Object { $_.Key -in @('LDAPClientConfidentiality', 'RelaxMinimumPasswordLengthLimits') }).Count | Should -Be 2
            @($merged.AuditPolicyCatalog).Count | Should -Be 9
            # Append-only: a user edit always wins over the bundled text.
            ($merged.SecurityOptionsRegistryCatalog | Where-Object Key -eq 'LDAPClientIntegrity').DisplayName | Should -Be 'EDITED BY USER'
        }

        It 'is idempotent and leaves an up-to-date file untouched' {
            Merge-SecurityCatalogBundledEntry -BundledPath $bundledPath -UserPath $userPath | Out-Null
            $before = [System.IO.File]::ReadAllBytes($userPath)
            Merge-SecurityCatalogBundledEntry -BundledPath $bundledPath -UserPath $userPath | Should -Be 0
            [System.IO.File]::ReadAllBytes($userPath) | Should -Be $before
        }

        It 'writes UTF-8 with BOM' {
            Merge-SecurityCatalogBundledEntry -BundledPath $bundledPath -UserPath $userPath | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($userPath)
            @($bytes[0], $bytes[1], $bytes[2]) | Should -Be @(239, 187, 191)
        }

        It 'does nothing when either file is missing, instead of throwing' {
            Merge-SecurityCatalogBundledEntry -BundledPath $bundledPath -UserPath (Join-Path $TestDrive 'does-not-exist.json') | Should -Be 0
            Merge-SecurityCatalogBundledEntry -BundledPath (Join-Path $TestDrive 'no-bundle.json') -UserPath $userPath | Should -Be 0
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
            $script:catalog = Get-AdvancedAuditCatalogEntry
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
                [CmdletBinding(SupportsShouldProcess)]
    param(
                [string]$Id = 'Test::Policy1',
                [string]$RegistryKey = 'Software\Policies\Test',
                [string]$ValueName = 'MyValue',
                $EnabledValue = 1,
                $DisabledValue = 0,
                [array]$Elements = @()
            )
    if ($PSCmdlet.ShouldProcess('New-TestPolicy', 'Invoke')) {
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
            Invoke-SecurityChangeToGpt -GptTmpl $gpt -PendingChanges $pendingSecChanges -SettingsById $settingsById | Out-Null

            Get-GptTmplValue $gpt 'System Access' 'MinimumPasswordLength' | Should -BeNullOrEmpty
            Get-GptTmplValue $gpt 'System Access' 'PasswordComplexity' | Should -Be '1'
        }
    }

    Context 'Invoke-AdmxChangeToEntry (multi-policy orchestration)' {

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
            $machineResult = Invoke-AdmxChangeToEntry -Entries $initial -PendingChanges $pendingAdmx -Scope 'Machine' -PoliciesById $policiesById
            $machineResult.Count | Should -Be 2
        }

        It 'applies only User-scoped policies for scope User' {
            $userResult = Invoke-AdmxChangeToEntry -Entries (New-Object System.Collections.Generic.List[object]) -PendingChanges $pendingAdmx -Scope 'User' -PoliciesById $policiesById
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
        $script:FakeDefaultData = Join-Path $FakeScriptRoot 'DefaultData\Audit'
        New-Item -ItemType Directory -Path $FakeDefaultData -Force | Out-Null
        1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $FakeDefaultData "Fake_$_.audit") -Value "fake $_" }

        $script:defaults = Get-DefaultAppPath
    }

    AfterAll {
        $env:LOCALAPPDATA = $SavedLocalAppData
    }

    Context 'Get-DefaultAppPath' {

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

    Context 'Get-AppSetting without an existing file' {

        It 'falls back to defaults' {
            $settings = Get-AppSetting
            $settings.paths.logDir | Should -Be $defaults.logDir
            $settings.editorMode | Should -BeTrue
        }
    }

    Context 'Save-AppSetting / Get-AppSetting round-trip' -Tag 'RoundTrip' {

        It 'persists modified values and preserves untouched keys' {
            $settings = Get-AppSetting
            $settings.paths.logDir = Join-Path $TestDrive 'CustomLogs\'
            $settings.editorMode = $false
            Save-AppSetting -Settings $settings

            $reloaded = Get-AppSetting
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
            $partial = Get-AppSetting
            $partial.paths.logDir | Should -Be 'D:\PartialOnly\'
            $partial.paths.backupRoot | Should -Be $defaults.backupRoot
            $partial.editorMode | Should -BeTrue
        }
    }

    Context 'Set-AppSettingPath' {

        It 'persists a single path immediately' {
            $settings = Get-AppSetting
            Set-AppSettingPath -Settings $settings -Key 'auditFilesDir' -Value (Join-Path $TestDrive 'CustomAudit\')
            $afterSet = Get-AppSetting
            $afterSet.paths.auditFilesDir | Should -Be (Join-Path $TestDrive 'CustomAudit\')
        }
    }

    Context 'Initialize-AppSettingsFirstRun' -Tag 'Integration' {

        BeforeAll {
            if (Test-Path -LiteralPath (Get-AppSettingsPath)) { Remove-Item -LiteralPath (Get-AppSettingsPath) -Force }
            $script:firstRunSettings = Get-AppSetting
            foreach ($key in @($firstRunSettings.paths.PSObject.Properties.Name)) {
                $firstRunSettings.paths.$key = Join-Path $TestDrive "FirstRun\$key\"
            }
            Initialize-AppSettingsFirstRun -Settings $firstRunSettings
        }

        It 'creates settings.json on first run' {
            Test-Path -LiteralPath (Get-AppSettingsPath) | Should -BeTrue
        }

        It 'creates every configured path folder' {
            foreach ($prop in $firstRunSettings.paths.PSObject.Properties) {
                Test-Path -LiteralPath $prop.Value | Should -BeTrue
            }
        }
    }

    Context 'Initialize-AuditFilesFolder' -Tag 'Integration' {

        BeforeAll {
            $script:auditSettings = Get-AppSetting
            $auditSettings.paths.auditFilesDir = Join-Path $TestDrive 'AuditSeed\'
            Initialize-AuditFilesFolder -Settings $auditSettings -ScriptRoot $FakeScriptRoot
        }

        It 'seeds auditFilesDir with the 3 bundled .audit files' {
            @(Get-ChildItem -LiteralPath $auditSettings.paths.auditFilesDir -Filter '*.audit').Count | Should -Be 3
        }

        It 'never re-seeds once the folder already exists' {
            Remove-Item -LiteralPath (Join-Path $auditSettings.paths.auditFilesDir 'Fake_1.audit') -Force
            Initialize-AuditFilesFolder -Settings $auditSettings -ScriptRoot $FakeScriptRoot
            @(Get-ChildItem -LiteralPath $auditSettings.paths.auditFilesDir -Filter '*.audit').Count | Should -Be 2
        }
    }
}

Describe 'CisCatalog' -Tag 'Integration' {

    BeforeAll {
        . (Join-Path $SrcRoot 'Catalogs\CisCatalog.ps1')
        # Resolve-CisSecurityWrite encodes [Registry Values] through
        # ConvertTo-RegistryValuesEncoding, which lives in PolicyState.ps1
        # (dot-sourced before CisCatalog.ps1 by GpEdit.ps1 at runtime).
        . (Join-Path $SrcRoot 'Policy\PolicyState.ps1')

        $auditFilesPath = Join-Path $SrcRoot 'DefaultData\Audit'
        $outputPath = Join-Path $TestDrive 'cis-index.json'
        & (Join-Path $SrcRoot 'Indexers\Build-Index.ps1') -Kind Cis -AuditFilesPath $auditFilesPath -OutputPath $outputPath | Out-Null

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

    Context 'catalog gaps closed (plan-gpedit-cis-admx-check.md §3)' -Tag 'Regression' {

        # The 3 settings that were covered by a CIS profile but reachable
        # from nowhere in the app. Each failed for its own reason: a missing
        # row in CisPasswordLockoutKeyMap, and two settings absent from
        # Data_SecurityCatalog.json entirely.

        It 'resolves "Allow Administrator account lockout" (LOCKOUT_ADMINS)' {
            # Routed to byPasswordPolicy by the .audit type (PASSWORD_POLICY),
            # even though the app files it under Account Lockout Policy.
            $rec = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'System Access' -Name 'AllowAdministratorLockout' -DisplayName 'Allow Administrator account lockout'
            $rec | Should -Not -BeNullOrEmpty
            $rec.title | Should -BeLike "*Allow Administrator account lockout*"
        }

        It 'resolves "Relax minimum password length limits"' {
            $rec = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Registry Values' -Name 'MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits' -DisplayName 'Relax minimum password length limits'
            $rec | Should -Not -BeNullOrEmpty
            $rec.title | Should -BeLike "*Relax minimum password length limits*"
        }

        It 'resolves LDAP client ENCRYPTION separately from LDAP client SIGNING' {
            # Two real, distinct Windows settings under the same registry key
            # with near-identical names - the whole point of this entry.
            $sealing = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Registry Values' -Name 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientConfidentiality' -DisplayName 'Network security: LDAP client encryption requirements'
            $signing = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Registry Values' -Name 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity' -DisplayName 'Network security: LDAP client signing requirements'
            $sealing | Should -Not -BeNullOrEmpty
            $signing | Should -Not -BeNullOrEmpty
            $sealing.title | Should -BeLike "*encryption requirements*"
            $signing.title | Should -BeLike "*signing requirements*"
            $sealing.key | Should -Not -Be $signing.key
        }

    }

    Context 'Resolve-CisSecurityWrite REG_* type' -Tag 'Regression' {

        # Found while adding the two catalog entries above: a catalog entry
        # with no explicit RegType (77 of 97) bound $null to the [int]
        # parameter as 0, so CIS Gap-fill/Full compliance wrote "0,<data>"
        # (REG_NONE) where the interactive path writes "4,<data>".

        It 'defaults a RegType-less reg-boolean to REG_DWORD' {
            $setting = [pscustomobject]@{ valueType = 'reg-boolean'; regType = $null; choices = $null }
            (Resolve-CisSecurityWrite -Setting $setting -RecommendedValue 'Enabled').Value | Should -Be '4,1'
        }

        It 'defaults a RegType-less reg-number to REG_DWORD' {
            $setting = [pscustomobject]@{ valueType = 'reg-number'; regType = $null; choices = $null }
            (Resolve-CisSecurityWrite -Setting $setting -RecommendedValue '900').Value | Should -Be '4,900'
        }

        It 'honours an explicit RegType (REG_SZ settings such as AllocateFloppies)' {
            $setting = [pscustomobject]@{ valueType = 'reg-boolean'; regType = 1; choices = $null }
            (Resolve-CisSecurityWrite -Setting $setting -RecommendedValue 'Enabled').Value | Should -Be '1,"1"'
        }

        It 'encodes a reg-enum choice as REG_DWORD' {
            $setting = [pscustomobject]@{ valueType = 'reg-enum'; regType = $null; choices = @([pscustomobject]@{ value = 2; displayName = 'Require sealing' }) }
            (Resolve-CisSecurityWrite -Setting $setting -RecommendedValue 'Require sealing').Value | Should -Be '4,2'
        }

        It 'encodes an explicitly empty reg-multistring as REG_MULTI_SZ' {
            $setting = [pscustomobject]@{ valueType = 'reg-multistring'; regType = $null; choices = $null }
            (Resolve-CisSecurityWrite -Setting $setting -RecommendedValue '').Value | Should -Be '7,'
        }
    }

    Context 'ADMX requirement note numbered "Note #N:" (plan-gpedit-cis-admx-check.md §3.3)' -Tag 'Regression' {

        It 'detects the SecGuide.admx dependency of NetBT NodeType configuration' {
            # This control is NOT a catalog gap: it is an Administrative
            # Templates setting needing a template Windows does not ship.
            # Its "solution" numbers the note ("Note #2:"), which the four
            # phrasing patterns used to miss - so it was misreported as an
            # unexplained gap instead of a missing template.
            $netbt = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'System\CurrentControlSet\Services\NetBT\Parameters' -ValueName 'NodeType'
            $netbt | Should -Not -BeNullOrEmpty
            $netbt.requiredAdmx | Should -Not -BeNullOrEmpty
            $netbt.requiredAdmx.file | Should -Be 'SecGuide.admx'
            $netbt.requiredAdmx.category | Should -Be 'ManualDownload'
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
            # Get-CisDistinctProfile uses "return , $list" to guard against
            # empty-list-becomes-$null, which means piping directly off the
            # function call would pass the whole list as one pipeline object.
            $allProfiles = Get-CisDistinctProfile -CisIndex $cisIndex
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
            & (Join-Path $SrcRoot 'Indexers\Build-Index.ps1') -Kind Cis -AuditFilesPath $auditFilesPath -OutputPath $fallbackOutputPath | Out-Null
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

    Context 'Get-CisMissingAdmxReport / Get-CisCatalogGapsReport (plan-gpedit-cis-admx-check.md)' {
        <#
            Fixture-driven: src\Tests\Fixtures\CIS_Microsoft_Windows_FAKE-TEST_v9.9.9_L1.audit
            has one fabricated custom_item per shape the real parser handles
            (REGISTRY_SETTING, REG_CHECK, PASSWORD_POLICY, LOCKOUT_POLICY,
            USER_RIGHTS_POLICY, AUDIT_POLICY_SUBCATEGORY, CHECK_ACCOUNT,
            BANNER_CHECK, ANONYMOUS_SID_SETTING, and an unrecognized type
            modeling Windows Services/Firewall) - built ALONE in its own
            $TestDrive folder, never mixed with the real 23 benchmark files.

            The ADMX index is a small hand-built fixture (NOT
            Build-Index.ps1 -Kind Admx against this machine's real
            C:\Windows\PolicyDefinitions) so this test stays deterministic
            and machine-independent, unlike the manual verification pass
            this test formalizes. Security Options / Password / Lockout /
            User Rights / Advanced Audit "reached" cases instead reuse real,
            stable keys from the repo-bundled Data_SecurityCatalog.json /
            AdvancedAuditCatalog.ps1 (already a dependency of every other
            test in this file, not machine state).
        #>

        BeforeAll {
            . (Join-Path $SrcRoot 'Catalogs\SecurityCatalog.ps1')
            . (Join-Path $SrcRoot 'Catalogs\AdvancedAuditCatalog.ps1')

            $fixtureAuditDir = Join-Path $TestDrive 'catalog-gaps-fixture'
            New-Item -ItemType Directory -Path $fixtureAuditDir -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $SrcRoot 'Tests\Fixtures\CIS_Microsoft_Windows_FAKE-TEST_v9.9.9_L1.audit') -Destination $fixtureAuditDir -Force

            $fixtureOutputPath = Join-Path $TestDrive 'catalog-gaps-fixture-index.json'
            & (Join-Path $SrcRoot 'Indexers\Build-Index.ps1') -Kind Cis -AuditFilesPath $fixtureAuditDir -OutputPath $fixtureOutputPath | Out-Null
            $script:fixtureCisIndex = Import-CisIndex -Path $fixtureOutputPath
            $script:fixtureProfile = (Get-CisDistinctProfile -CisIndex $fixtureCisIndex) | Select-Object -First 1

            # Only what fixture item #1 (real ADMX passthrough) needs to resolve as "reached".
            $script:fixtureAdmxIndex = [pscustomobject]@{
                policies = @(
                    [pscustomobject]@{
                        registryKey  = 'Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
                        valueName    = 'Enabled'
                        enabledValue = 1
                        disabledValue = 0
                        elements     = @()
                        admxFile     = 'W32Time.admx'
                    }
                )
            }

            $script:missingAdmxRows = Get-CisMissingAdmxReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $fixtureProfile
            $script:catalogGapsRows = Get-CisCatalogGapsReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $fixtureProfile
        }

        It 'builds the fixture index with the expected Skipped/needsManualReview counts' {
            # 2 Skipped: the unrecognized "SERVICE_POLICY" item (models
            # Windows Services/Firewall, out of scope - plan §2/§4) PLUS the
            # ANONYMOUS_SID_SETTING item below, which also counts towards
            # Skipped once its title-fallback resolution fails (see
            # Resolve-CisTitleFallbackCandidate: NeedsManualReview items are
            # folded into Skipped too, not a separate disjoint count).
            $fixtureCisIndex.meta.skippedItemCount | Should -Be 2
            $fixtureCisIndex.meta.needsManualReviewCount | Should -Be 1
        }

        It 'never flags a setting reachable via a real ADMX policy (byRegistry)' {
            (@($missingAdmxRows.Title) -match 'NTP passthrough').Count | Should -Be 0
            (@($catalogGapsRows.Title) -match 'NTP passthrough').Count | Should -Be 0
        }

        It 'never flags a setting reachable via a real Security Options "Registry Values" entry (REG_CHECK)' {
            (@($missingAdmxRows.Title) -match 'Blank password use passthrough').Count | Should -Be 0
            (@($catalogGapsRows.Title) -match 'Blank password use passthrough').Count | Should -Be 0
        }

        It 'never flags a setting reachable via CisPasswordLockoutKeyMap (Password/Lockout Policy)' {
            $allTitles = @($missingAdmxRows.Title) + @($catalogGapsRows.Title)
            ($allTitles -match 'Minimum password length passthrough').Count | Should -Be 0
            ($allTitles -match 'Account lockout threshold passthrough').Count | Should -Be 0
        }

        It 'never flags a setting reachable via a real User Right / Advanced Audit subcategory' {
            $allTitles = @($missingAdmxRows.Title) + @($catalogGapsRows.Title)
            ($allTitles -match 'Backup privilege passthrough').Count | Should -Be 0
            ($allTitles -match 'Credential Validation passthrough').Count | Should -Be 0
        }

        It 'reports an unreached REGISTRY_SETTING/REG_CHECK with no requiredAdmx note as a Catalog gap, not Missing ADMX' {
            (@($catalogGapsRows.Title) -match 'Fictitious registry feature').Count | Should -Be 1
            (@($catalogGapsRows.Title) -match 'Fictitious REG_CHECK feature').Count | Should -Be 1
            (@($missingAdmxRows.Title) -match 'Fictitious registry feature').Count | Should -Be 0
            (@($missingAdmxRows.Title) -match 'Fictitious REG_CHECK feature').Count | Should -Be 0
        }

        It 'reports an unreached REGISTRY_SETTING WITH a requiredAdmx note as Missing ADMX, not a Catalog gap' {
            (@($missingAdmxRows.Title) -match 'Fictitious feature needing a template').Count | Should -Be 1
            (@($catalogGapsRows.Title) -match 'Fictitious feature needing a template').Count | Should -Be 0
        }

        It 'reports an unreached Password/Lockout/User Right/Audit Subcategory entry as a Catalog gap (the real 1.2.3-style bug this report exists for)' {
            (@($catalogGapsRows.Title) -match 'Fictitious password rule').Count | Should -Be 1
            (@($catalogGapsRows.Title) -match 'Fictitious lockout rule').Count | Should -Be 1
            (@($catalogGapsRows.Title) -match 'Fictitious privilege').Count | Should -Be 1
            (@($catalogGapsRows.Title) -match 'Fictitious audit subcategory').Count | Should -Be 1
        }

        It 'never reports a Catalog gap row with the wrong bucket label' {
            ($catalogGapsRows | Where-Object { $_.Title -match 'Fictitious registry feature' }).Bucket | Should -Be 'byRegistry'
            ($catalogGapsRows | Where-Object { $_.Title -match 'Fictitious password rule' }).Bucket | Should -Be 'byPasswordPolicy'
            ($catalogGapsRows | Where-Object { $_.Title -match 'Fictitious lockout rule' }).Bucket | Should -Be 'byLockoutPolicy'
            ($catalogGapsRows | Where-Object { $_.Title -match 'Fictitious privilege' }).Bucket | Should -Be 'byUserRight'
            ($catalogGapsRows | Where-Object { $_.Title -match 'Fictitious audit subcategory' }).Bucket | Should -Be 'byAuditSubcategory'
        }

        It 'never surfaces organization-specific (byOrgValue) entries in either report' {
            $allTitles = @($missingAdmxRows.Title) + @($catalogGapsRows.Title)
            ($allTitles -match 'Fictitious Administrator account name').Count | Should -Be 0
            ($allTitles -match 'Fictitious logon banner text').Count | Should -Be 0
        }

        It 'never surfaces an unresolved title-fallback (needsManualReview) entry in either report' {
            $allTitles = @($missingAdmxRows.Title) + @($catalogGapsRows.Title)
            ($allTitles -match 'Totally fictitious unmatched setting').Count | Should -Be 0
        }

        It 'never surfaces an unrecognized (Skipped) custom_item type in either report' {
            $allTitles = @($missingAdmxRows.Title) + @($catalogGapsRows.Title)
            ($allTitles -match 'Fictitious Test Service').Count | Should -Be 0
        }

        It 'returns empty lists (not $null, does not throw) when no CIS profile is active' {
            # NOT wrapped in @() at the call site: Get-CisMissingAdmxReport/
            # Get-CisCatalogGapsReport already "return , $list" (see
            # Get-CisAllEntry's comment on this idiom) precisely so the
            # caller gets the List[object] itself - wrapping the call in an
            # extra @() would instead produce a 1-element array containing
            # that (empty) list, making .Count report 1 instead of 0.
            { Get-CisMissingAdmxReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $null } | Should -Not -Throw
            { Get-CisCatalogGapsReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $null } | Should -Not -Throw
            (Get-CisMissingAdmxReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $null).Count | Should -Be 0
            (Get-CisCatalogGapsReport -CisIndex $fixtureCisIndex -AdmxIndex $fixtureAdmxIndex -ActiveProfile $null).Count | Should -Be 0
        }
    }
}
