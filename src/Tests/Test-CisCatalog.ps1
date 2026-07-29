<#
    Regression tests for CIS parsing (Build-CisIndex.ps1) and matching
    against the app's settings (CisCatalog.ps1).
#>
param(
    [string]$AuditFilesPath = (Join-Path $PSScriptRoot '..\..\Audit file'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\data\cis-index.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Catalogs\CisCatalog.ps1')

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
        Write-Host "  [FAIL] $Message (expected='$Expected' actual='$Actual')" -ForegroundColor Red
    }
}

function Assert-NotNull {
    param($Actual, [string]$Message)
    $script:TestCount++
    if ($null -ne $Actual) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    }
    else {
        $script:FailCount++
        Write-Host "  [FAIL] $Message (actual=`$null)" -ForegroundColor Red
    }
}

function Assert-Null {
    param($Actual, [string]$Message)
    $script:TestCount++
    if ($null -eq $Actual) {
        Write-Host "  [OK] $Message" -ForegroundColor Green
    }
    else {
        $script:FailCount++
        Write-Host "  [FAIL] $Message (expected=`$null, actual='$Actual')" -ForegroundColor Red
    }
}

Write-Host "=== Regenerating the test CIS index ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot '..\Indexers\Build-CisIndex.ps1') -AuditFilesPath $AuditFilesPath -OutputPath $OutputPath | Out-Null

$cisIndex = Import-CisIndex -Path $OutputPath
Assert-NotNull -Actual $cisIndex -Message "CIS index loaded from $OutputPath"

Write-Host "=== Test 1: REGISTRY_SETTING match (NTP Client) ===" -ForegroundColor Cyan
$ntp = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ValueName 'Enabled'
Assert-NotNull -Actual $ntp -Message "Entree trouvee pour NtpClient\Enabled"
if ($ntp) {
    Assert-Equal -Expected "Ensure 'Enable Windows NTP Client' is set to 'Enabled'" -Actual $ntp.title -Message 'Titre NTP Client'
    $profile2016 = @($ntp.profiles) | Where-Object { $_.benchmark -eq 'Microsoft Windows Server 2016' -and $_.level -eq 'L1' -and $_.role -eq 'MS' } | Select-Object -First 1
    $profile2019 = @($ntp.profiles) | Where-Object { $_.benchmark -eq 'Microsoft Windows Server 2019' -and $_.level -eq 'L1' -and $_.role -eq 'MS' } | Select-Object -First 1
    Assert-Equal -Expected '18.9.51.1.1' -Actual $profile2016.cisNumber -Message 'Numero CIS 2016 (avant renumerotation)'
    Assert-Equal -Expected '18.9.53.1.1' -Actual $profile2019.cisNumber -Message 'Numero CIS 2019 (apres renumerotation)'
    Assert-Equal -Expected '1' -Actual $profile2019.valueData -Message 'Valeur recommandee stable entre versions'
    Assert-Equal -Expected 'Enabled' -Actual (Get-CisRecommendationStateText -CisEntry $ntp) -Message "Get-CisRecommendationStateText extrait 'Enabled' depuis info"
}

Write-Host "=== Test 2: case and HKLM prefix ignored (admx-style registryKey) ===" -ForegroundColor Cyan
$ntpCaseInsensitive = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ValueName 'ENABLED'
Assert-NotNull -Actual $ntpCaseInsensitive -Message 'Correspondance insensible a la casse'

Write-Host "=== Test 3: PASSWORD_POLICY match (via manual table) ===" -ForegroundColor Cyan
$pwdHistory = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'System Access' -Name 'PasswordHistorySize'
Assert-NotNull -Actual $pwdHistory -Message 'Entree trouvee pour PasswordHistorySize'
if ($pwdHistory) {
    $anyProfile = @($pwdHistory.profiles)[0]
    Assert-Equal -Expected '[24..MAX]' -Actual $anyProfile.valueData -Message 'Variable @PASSWORD_HISTORY@ resolue en [24..MAX]'
}

Write-Host "=== Test 4: USER_RIGHTS_POLICY match (direct name) ===" -ForegroundColor Cyan
$userRight = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege'
Assert-NotNull -Actual $userRight -Message 'Entree trouvee pour SeTrustedCredManAccessPrivilege'

Write-Host "=== Test 5: AUDIT_POLICY_SUBCATEGORY match ===" -ForegroundColor Cyan
$auditSub = Get-CisRecommendationForAuditSubcategory -CisIndex $cisIndex -SubcategoryNameEn 'Security Group Management'
Assert-NotNull -Actual $auditSub -Message "Entree trouvee pour la sous-categorie 'Security Group Management'"
if ($auditSub) {
    $anyProfile = @($auditSub.profiles)[0]
    Assert-Equal -Expected 'Success || Success, Failure' -Actual $anyProfile.valueData -Message 'Alternative "A" || "B" normalisee (guillemets retires)'
}

Write-Host "=== Test 6: settings with no CIS match -> `$null (hidden tab) ===" -ForegroundColor Cyan
Assert-Null -Actual (Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\NotInAnyBenchmark' -ValueName 'DoesNotExist') -Message 'Cle de registre inconnue'
Assert-Null -Actual (Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'System Access' -Name 'SomeUncatalogedSetting') -Message 'Nom de parametre securite inconnu'
Assert-Null -Actual (Get-CisRecommendationForAuditSubcategory -CisIndex $cisIndex -SubcategoryNameEn 'Not A Real Subcategory') -Message 'Sous-categorie audit inconnue'
Assert-Null -Actual (Get-CisRecommendationForRegistry -CisIndex $null -RegistryKey 'Software\X' -ValueName 'Y') -Message 'Index `$null (fichier absent) -> pas de crash, retourne `$null'

Write-Host "=== Test 7: Get-CisRecommendationStateText ('CIS States' column) ===" -ForegroundColor Cyan
$netbios = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableNetbios'
Assert-NotNull -Actual $netbios -Message "Entree trouvee pour 'Configure NetBIOS settings'"
if ($netbios) {
    # The 2016 .audit file (processed first, so its entry wins) runs
    # "... on public networks Configuring this setting to ..." with no
    # separating period - Get-CisRecommendedStateText (Build-CisIndex.ps1)
    # must still strip this fixed equivalence clause from the captured text.
    Assert-Equal -Expected 'Enabled: Disable NetBIOS name resolution on public networks' -Actual $netbios.recommendedStateText -Message "Clause d'equivalence 'Configuring this setting...' retiree meme sans ponctuation"
}
$userRight = Get-CisRecommendationForSecuritySetting -CisIndex $cisIndex -Section 'Privilege Rights' -Name 'SeTrustedCredManAccessPrivilege'
if ($userRight) {
    Assert-Equal -Expected 'No One' -Actual (Get-CisRecommendationStateText -CisEntry $userRight) -Message 'CIS States fonctionne aussi hors Administrative Templates (byUserRight)'
}
Assert-Null -Actual (Get-CisRecommendationStateText -CisEntry $null) -Message 'Get-CisRecommendationStateText($null) -> pas de crash, retourne `$null'

Write-Host "=== Test 8: Get-CisRecommendationValueForProfile - no fallback across OS families ===" -ForegroundColor Cyan
$ui = @{ CisOrWord = 'or' }
# NoLMHash exists in the Windows 10 and Server (2016/2019/2022) benchmarks
# but in NO Windows 11 benchmark - the "CIS R. Value" column must therefore
# never borrow a Server profile's recommendation when the active profile is
# a Windows 11 workstation (real bug reported by the user: NoLMHash showed
# "Enabled" via Server 2022 on a Windows 11 Stand-alone machine, even though
# that benchmark doesn't cover this setting).
$noLmHash = Get-CisRecommendationForRegistry -CisIndex $cisIndex -RegistryKey 'System\CurrentControlSet\Control\Lsa' -ValueName 'NoLMHash'
Assert-NotNull -Actual $noLmHash -Message "Entree trouvee pour 'NoLMHash'"
if ($noLmHash) {
    # $allProfiles must be assigned to a variable BEFORE piping: Get-CisDistinctProfiles
    # uses "return , $list" (see its own comment) to guard against empty-list-becomes-
    # $null, but that means piping directly off the function CALL passes the whole list
    # as ONE pipeline object (not element-by-element) - Where-Object then filters
    # nothing. Piping off the VARIABLE after assignment avoids this (normal array
    # enumeration via | works fine on a variable; only the function's own output is affected).
    $allProfiles = Get-CisDistinctProfiles -CisIndex $cisIndex
    $win11StandAlone = $allProfiles | Where-Object { $_.Benchmark -match 'Windows\s*11' -and $_.Benchmark -match 'Stand-alone' -and $_.Level -eq 'L1' } | Select-Object -First 1
    if ($win11StandAlone) {
        Assert-Null -Actual (Get-CisRecommendationValueForProfile -CisEntry $noLmHash -ActiveProfile $win11StandAlone -Ui $ui) -Message "Pas de recommandation empruntee a un benchmark Server : vide pour un profil Windows 11 que NoLMHash ne couvre pas"
    }
}

Write-Host "`n=== Result: $($script:TestCount - $script:FailCount)/$($script:TestCount) tests passed ===" -ForegroundColor $(if ($script:FailCount -eq 0) { 'Green' } else { 'Red' })
if ($script:FailCount -gt 0) { exit 1 }
exit 0
