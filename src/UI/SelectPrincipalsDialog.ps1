<#
    "Select Users or Groups" window - visual clone of the real Windows
    dialog, but name resolution uses NTAccount.Translate/Win32_Account
    (.NET/CIM) instead of the IDsObjectPicker COM interop, which was
    abandoned (CDsObjectPicker CLSID unavailable via dsuiext.dll on this
    machine).
#>

Set-StrictMode -Version Latest

function Get-PrincipalSidType {
    # Returns the SidType (Win32_Account) of a SID as a simplified string
    # (User/Group/Alias/WellKnownGroup/...), or $null if not found (orphan
    # SID, deleted account, etc.).
    param([Parameter(Mandatory)][string]$Sid)

    try {
        $escapedSid = $Sid -replace "'", "''"
        $acct = Get-CimInstance -Query "SELECT SidType FROM Win32_Account WHERE SID='$escapedSid'" -ErrorAction Stop
        if ($acct) {
            switch ([int]$acct.SidType) {
                1 { return 'User' }
                2 { return 'Group' }
                3 { return 'Domain' }
                4 { return 'Alias' }
                5 { return 'WellKnownGroup' }
                9 { return 'Computer' }
                default { return $null }
            }
        }
    }
    catch { }
    return $null
}

function Get-PrincipalLocationChoices {
    # Local machine always, plus the domain if joined. No full AD browsing -
    # this project only handles local security policy.
    $choices = New-Object System.Collections.Generic.List[object]
    $choices.Add([pscustomobject]@{ Label = $env:COMPUTERNAME; Prefix = $null })
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain -and $cs.Domain) {
            $choices.Add([pscustomobject]@{ Label = $cs.Domain; Prefix = $cs.Domain })
        }
    }
    catch { }
    # .ToArray(), not @($choices): @() directly on a List[object] triggers
    # a PowerShell 5.1 dynamic-binder ArgumentException on this machine
    # (confirmed environment bug specific to List[object] - List[string]
    # and pipeline @(... | Where-Object) expressions are unaffected).
    return $choices.ToArray()
}

function Resolve-PrincipalNamesText {
    <#
        Resolves a "name1; name2; ..." string entered by the user.
        $LocationPrefix, if given, is prefixed to names without a "\"
        already (mimics "From this location" in the real dialog).
        $AllowedTypes restricts to the listed SidTypes; $null/empty = no
        restriction. Returns @{ Resolved = [...]; NotFound = [...] }.
    #>
    param(
        [string]$NamesText,
        [string]$LocationPrefix,
        [string[]]$AllowedTypes
    )

    $names = @($NamesText -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $resolved = New-Object System.Collections.Generic.List[object]
    $notFound = New-Object System.Collections.Generic.List[string]

    foreach ($name in $names) {
        $lookup = if ($LocationPrefix -and ($name -notmatch '\\')) { "$LocationPrefix\$name" } else { $name }
        try {
            $account = New-Object System.Security.Principal.NTAccount($lookup)
            $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
            $sidType = Get-PrincipalSidType -Sid $sid.Value
            if ($AllowedTypes -and $AllowedTypes.Count -gt 0 -and $sidType -and ($AllowedTypes -notcontains $sidType)) {
                $notFound.Add($name)
                continue
            }
            $rawToken = "*$($sid.Value)"
            $resolved.Add([pscustomobject]@{ Raw = $rawToken; Display = (Resolve-PrincipalDisplayName -RawToken $rawToken) })
        }
        catch {
            $notFound.Add($name)
        }
    }

    # .ToArray(), not @(): see note in Get-PrincipalLocationChoices.
    return [pscustomobject]@{ Resolved = $resolved.ToArray(); NotFound = $notFound.ToArray() }
}

function Show-ObjectTypesDialog {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [string[]]$SelectedTypes)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ObjectTypesWindow' -Owner $Owner
    $window.Title = $Ui.ObjectTypesWindowTitle
    $window.FindName('ObjectTypesIntroLabel').Text = $Ui.ObjectTypesIntro

    $userCheck = $window.FindName('UserTypeCheck')
    $groupCheck = $window.FindName('GroupTypeCheck')
    $wellKnownCheck = $window.FindName('WellKnownTypeCheck')
    $userCheck.Content = $Ui.ObjectTypeUsers
    $groupCheck.Content = $Ui.ObjectTypeGroups
    $wellKnownCheck.Content = $Ui.ObjectTypeWellKnown

    $userCheck.IsChecked = ($SelectedTypes -contains 'User')
    $groupCheck.IsChecked = ($SelectedTypes -contains 'Group')
    $wellKnownCheck.IsChecked = ($SelectedTypes -contains 'WellKnownGroup')

    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    $script:__objectTypesResult = $null
    $okButton.Add_Click({
        $types = New-Object System.Collections.Generic.List[string]
        if ($userCheck.IsChecked) { $types.Add('User') }
        if ($groupCheck.IsChecked) { $types.Add('Group'); $types.Add('Alias') }
        if ($wellKnownCheck.IsChecked) { $types.Add('WellKnownGroup') }
        $script:__objectTypesResult = @($types)
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({ $window.DialogResult = $false })

    $null = $window.ShowDialog()
    return $script:__objectTypesResult
}

function Show-LocationsDialog {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [string]$CurrentLabel)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'LocationsWindow' -Owner $Owner
    $window.Title = $Ui.LocationsWindowTitle
    $window.FindName('LocationsIntroLabel').Text = $Ui.LocationsIntro

    $listBox = $window.FindName('LocationsListBox')
    $choices = Get-PrincipalLocationChoices
    foreach ($c in $choices) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = $c.Label
        $item.Tag = $c
        [void]$listBox.Items.Add($item)
        if ($c.Label -eq $CurrentLabel) { $listBox.SelectedItem = $item }
    }
    if (-not $listBox.SelectedItem -and $listBox.Items.Count -gt 0) { $listBox.SelectedIndex = 0 }

    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    $script:__locationResult = $null
    $okButton.Add_Click({
        if ($listBox.SelectedItem) { $script:__locationResult = $listBox.SelectedItem.Tag }
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({ $window.DialogResult = $false })

    $null = $window.ShowDialog()
    return $script:__locationResult
}

function Show-SelectPrincipalsDialog {
    <#
        Main window, visual clone of "Select Users or Groups". Returns an
        array of {Raw, Display} objects (verified accounts/groups) on OK,
        $null on Cancel.
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'SelectPrincipalsWindow' -Owner $Owner
    $window.Title = $Ui.SelectPrincipalsWindowTitle
    $window.FindName('ObjectTypeIntroLabel').Text = $Ui.ObjectTypeIntro
    $window.FindName('LocationIntroLabel').Text = $Ui.LocationIntro
    $window.FindName('NamesIntroLabel').Text = $Ui.NamesIntro

    $objectTypeTextBox = $window.FindName('ObjectTypeTextBox')
    $objectTypesButton = $window.FindName('ObjectTypesButton')
    $locationTextBox = $window.FindName('LocationTextBox')
    $locationsButton = $window.FindName('LocationsButton')
    $namesTextBox = $window.FindName('NamesTextBox')
    $checkNamesButton = $window.FindName('CheckNamesButton')
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')

    $objectTypesButton.Content = $Ui.ObjectTypesEllipsisButton
    $locationsButton.Content = $Ui.LocationsEllipsisButton
    $checkNamesButton.Content = $Ui.CheckNamesButton
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    # Mutable state shared between event handlers: reassigning a variable
    # ($x = ...) inside an Add_Click scriptblock only affects a local
    # (child-scope) copy, so we use hashtable keys instead, whose mutation
    # crosses closures fine (like $listBox.Items.Add(...) elsewhere).
    $state = @{
        SelectedTypes   = @('User', 'Group', 'Alias', 'WellKnownGroup')
        CurrentLocation = (Get-PrincipalLocationChoices)[0]
        LastCheckedText = ''
    }
    $resolvedPrincipals = New-Object System.Collections.Generic.List[object]

    $objectTypeTextBox.Text = "$($Ui.ObjectTypeUsers), $($Ui.ObjectTypeGroups), $($Ui.ObjectTypeWellKnown)"
    $locationTextBox.Text = $state.CurrentLocation.Label

    $objectTypesButton.Add_Click({
        $result = Show-ObjectTypesDialog -Owner $window -ScriptRoot $ScriptRoot -Ui $Ui -SelectedTypes $state.SelectedTypes
        if ($null -ne $result) {
            $state.SelectedTypes = $result
            $labels = New-Object System.Collections.Generic.List[string]
            if ($result -contains 'User') { $labels.Add($Ui.ObjectTypeUsers) }
            if ($result -contains 'Group') { $labels.Add($Ui.ObjectTypeGroups) }
            if ($result -contains 'WellKnownGroup') { $labels.Add($Ui.ObjectTypeWellKnown) }
            $objectTypeTextBox.Text = if ($labels.Count -gt 0) { $labels -join ', ' } else { $Ui.ObjectTypeNoneText }
        }
    })

    $locationsButton.Add_Click({
        $result = Show-LocationsDialog -Owner $window -ScriptRoot $ScriptRoot -Ui $Ui -CurrentLabel $state.CurrentLocation.Label
        if ($null -ne $result) {
            $state.CurrentLocation = $result
            $locationTextBox.Text = $result.Label
        }
    })

    $runCheckNames = {
        if ($namesTextBox.Text -eq $state.LastCheckedText) { return $true }
        if ([string]::IsNullOrWhiteSpace($namesTextBox.Text)) { $state.LastCheckedText = ''; return $true }

        $result = Resolve-PrincipalNamesText -NamesText $namesTextBox.Text -LocationPrefix $state.CurrentLocation.Prefix -AllowedTypes $state.SelectedTypes
        foreach ($r in $result.Resolved) {
            $already = @($resolvedPrincipals | Where-Object { $_.Raw -eq $r.Raw })
            if ($already.Count -eq 0) { $resolvedPrincipals.Add($r) }
        }
        $namesTextBox.Text = if ($resolvedPrincipals.Count -gt 0) { (($resolvedPrincipals | ForEach-Object { $_.Display }) -join '; ') } else { '' }
        $state.LastCheckedText = $namesTextBox.Text

        if ($result.NotFound.Count -gt 0) {
            [System.Windows.MessageBox]::Show(($Ui.PrincipalNotFoundMessage -f ($result.NotFound -join '; ')), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
            return $false
        }
        return $true
    }

    $checkNamesButton.Add_Click($runCheckNames)

    $script:__selectPrincipalsResult = $null
    $okButton.Add_Click({
        $ok = & $runCheckNames
        if (-not $ok) { return }
        # .ToArray(), not @(): see note in Get-PrincipalLocationChoices.
        $script:__selectPrincipalsResult = $resolvedPrincipals.ToArray()
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({ $window.DialogResult = $false })

    $null = $window.ShowDialog()
    return $script:__selectPrincipalsResult
}
