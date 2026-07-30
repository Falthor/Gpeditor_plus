<#
    Top-menu windows: optional-column picker (View > Add/remove columns),
    the Filter dialog, and the "?" menu info windows (About / Patch note).
    Reuses Import-XamlWindow (EditDialogs.ps1).
#>

Set-StrictMode -Version Latest

function Get-ColumnCatalog {
    # Catalog of ALL columns managed by View > Add/remove columns: the 3
    # default columns (Name/State/CIS, Locked=$true - always shown, not
    # removable but reorderable) and the 3 optional ones (Scope/Recommended
    # state/Location, Locked=$false - Reg Key/Reg Value/Value type were
    # considered then dropped). Each entry carries the stable key used
    # elsewhere in the code (never the localized label). The Location
    # column (internal key "Category", same column as search mode) also
    # gets auto-toggled by search even if the user didn't add it here -
    # see Set-ColumnsDisplay/Invoke-Search in GpEdit.ps1.
    param([hashtable]$Ui)
    return @(
        [pscustomobject]@{ Key = 'Name';             Label = $Ui.ColumnName;             Locked = $true }
        [pscustomobject]@{ Key = 'State';             Label = $Ui.ColumnState;            Locked = $true }
        [pscustomobject]@{ Key = 'Cis';               Label = $Ui.ColumnCis;               Locked = $true }
        [pscustomobject]@{ Key = 'Scope';             Label = $Ui.ColumnScope;             Locked = $false }
        [pscustomobject]@{ Key = 'RecommendedState';  Label = $Ui.ColumnRecommendedState;  Locked = $false }
        [pscustomobject]@{ Key = 'Category';          Label = $Ui.ColumnCategory;          Locked = $false }
    )
}

function Show-ColumnPickerDialog {
    <#
        $DisplayedKeys: ordered list of ALL currently displayed columns
        (Locked default columns included). Returns the new ordered list on
        OK, $null on Cancel. No persistence across sessions by design - the
        caller just reapplies this to PolicyList's columns for the run.
    #>
    param(
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        [string[]]$DisplayedKeys = @()
    )

    $catalog = Get-ColumnCatalog -Ui $Ui
    $byKey = @{}
    foreach ($c in $catalog) { $byKey[$c.Key] = $c }

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ColumnPickerWindow' -Owner $Owner
    $window.Title = $Ui.ColumnPickerTitle
    $availableLabel = $window.FindName('AvailableLabel')
    $displayedLabel = $window.FindName('DisplayedLabel')
    $availableListBox = $window.FindName('AvailableListBox')
    $displayedListBox = $window.FindName('DisplayedListBox')
    $addButton = $window.FindName('AddButton')
    $removeButton = $window.FindName('RemoveButton')
    $moveUpButton = $window.FindName('MoveUpButton')
    $moveDownButton = $window.FindName('MoveDownButton')
    $resetButton = $window.FindName('ResetButton')
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')

    $availableLabel.Text = $Ui.ColumnPickerAvailable
    $displayedLabel.Text = $Ui.ColumnPickerDisplayed
    $addButton.Content = $Ui.ColumnPickerAdd
    $removeButton.Content = $Ui.ColumnPickerRemove
    $moveUpButton.Content = $Ui.ColumnPickerMoveUp
    $moveDownButton.Content = $Ui.ColumnPickerMoveDown
    $resetButton.Content = $Ui.ColumnPickerReset
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    function Set-ListBoxItems {
        param($ListBox, [string[]]$Keys)
        $ListBox.Items.Clear()
        foreach ($key in $Keys) {
            $item = New-Object System.Windows.Controls.ListBoxItem
            $col = $byKey[$key]
            $item.Content = $col.Label
            $item.Tag = $key
            [void]$ListBox.Items.Add($item)
        }
    }

    $displayedKeysList = New-Object System.Collections.Generic.List[string]
    foreach ($k in $DisplayedKeys) { if ($byKey.ContainsKey($k)) { $displayedKeysList.Add($k) } }
    # Locked columns are always shown, even if missing from $DisplayedKeys
    # (defends against an incomplete call) - never removable, so never
    # candidates for the "Available" list.
    foreach ($c in $catalog) { if ($c.Locked -and -not $displayedKeysList.Contains($c.Key)) { $displayedKeysList.Add($c.Key) } }
    $availableKeysList = New-Object System.Collections.Generic.List[string]
    foreach ($c in $catalog) { if (-not $c.Locked -and -not $displayedKeysList.Contains($c.Key)) { $availableKeysList.Add($c.Key) } }

    Set-ListBoxItems -ListBox $availableListBox -Keys $availableKeysList
    Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList

    $addButton.Add_Click({
        param($EventSender, $e)
        $selected = @($availableListBox.SelectedItems) | ForEach-Object { $_.Tag }
        foreach ($key in $selected) {
            [void]$availableKeysList.Remove($key)
            $displayedKeysList.Add($key)
        }
        Set-ListBoxItems -ListBox $availableListBox -Keys $availableKeysList
        Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList
    })

    $removeButton.Add_Click({
        param($EventSender, $e)
        # Selected Locked columns (Name/State/CIS) are silently ignored -
        # not removable, only reorderable.
        $selected = @($displayedListBox.SelectedItems) | ForEach-Object { $_.Tag } | Where-Object { -not $byKey[$_].Locked }
        foreach ($key in $selected) {
            [void]$displayedKeysList.Remove($key)
            $availableKeysList.Add($key)
        }
        Set-ListBoxItems -ListBox $availableListBox -Keys $availableKeysList
        Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList
    })

    $moveUpButton.Add_Click({
        param($EventSender, $e)
        $idx = $displayedListBox.SelectedIndex
        if ($idx -gt 0) {
            $key = $displayedKeysList[$idx]
            $displayedKeysList.RemoveAt($idx)
            $displayedKeysList.Insert($idx - 1, $key)
            Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList
            $displayedListBox.SelectedIndex = $idx - 1
        }
    })

    $moveDownButton.Add_Click({
        param($EventSender, $e)
        $idx = $displayedListBox.SelectedIndex
        if ($idx -ge 0 -and $idx -lt ($displayedKeysList.Count - 1)) {
            $key = $displayedKeysList[$idx]
            $displayedKeysList.RemoveAt($idx)
            $displayedKeysList.Insert($idx + 1, $key)
            Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList
            $displayedListBox.SelectedIndex = $idx + 1
        }
    })

    $resetButton.Add_Click({
        param($EventSender, $e)
        $displayedKeysList.Clear()
        $availableKeysList.Clear()
        foreach ($c in $catalog) {
            if ($c.Locked) { $displayedKeysList.Add($c.Key) } else { $availableKeysList.Add($c.Key) }
        }
        Set-ListBoxItems -ListBox $availableListBox -Keys $availableKeysList
        Set-ListBoxItems -ListBox $displayedListBox -Keys $displayedKeysList
    })

    $script:__columnPickerResult = $null
    $okButton.Add_Click({
        param($EventSender, $e)
        $script:__columnPickerResult = @($displayedKeysList)
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({
        param($EventSender, $e)
        $window.DialogResult = $false
    })

    $null = $window.ShowDialog()
    return $script:__columnPickerResult
}

function Get-CisProfileGroups {
    # Groups Get-CisDistinctProfiles by (Benchmark, Version, Role) - Level
    # (L1/L2) is NOT part of the grouping: in Show-ProfileSelectionDialog a
    # group is one selectable row in a tab, level is chosen separately via
    # the L1/L2 radio buttons (not every benchmark+role combo has both
    # levels available).
    param($CisIndex)

    $all = Get-CisDistinctProfiles -CisIndex $CisIndex
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($g in ($all | Group-Object -Property { "$($_.Benchmark)|$($_.Version)|$($_.Role)" })) {
        $first = $g.Group[0]
        $groups.Add([pscustomobject]@{
            Benchmark = $first.Benchmark
            Version   = $first.Version
            Role      = $first.Role
            Profiles  = @($g.Group)
        })
    }
    # ", $groups" (not just "$groups"): an unprotected "return" enumerates
    # the collection - an EMPTY list (no CIS profiles in the index) would
    # become $null for the caller instead of an empty list. Same real bug
    # as Select-FilteredItems (GpEdit.ps1), fixed here as a precaution.
    return , $groups
}

function Show-ProfileSelectionDialog {
    <#
        Replaces the old flat View > Profile submenu with a tabbed
        Desktop/Servers/Domain Controller window - one row per
        benchmark+version+role (L1/L2 level chosen separately via 2 radio
        buttons, enabled/disabled based on what's actually available for
        the selected row). $CurrentProfile (active filter, or $null) is
        pre-selected on open. Returns the chosen profile (same shape as
        Get-CisDistinctProfiles) on OK, $null on Cancel - never a $null
        meaning "clear the filter", that stays the job of the separate
        "Remove profile filter" button.

        -AllowLevelUnion (only used by the "New Group Policy > CIS
        Gap-fill/Full compliance" flow, plan-gpedit-new-gpo-cis-generation.md
        §3.3/§4.2): reveals a 3rd "L1 + L2" radio and changes the OK return
        shape to [pscustomobject]@{ Group = <group>; Levels = @('L1') or
        @('L1','L2') } instead of a single profile row, since "L1 + L2" has
        no single matching row. The plain View > Profile picker never sets
        this switch, so its return shape is completely unchanged.
    #>
    param(
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        $CisIndex,
        $CurrentProfile,
        [switch]$AllowLevelUnion,
        [string]$TitleOverride
    )

    $groups = Get-CisProfileGroups -CisIndex $CisIndex

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ProfileSelectionWindow' -Owner $Owner
    $window.Title = if ($TitleOverride) { $TitleOverride } else { $Ui.ProfileSelectionWindowTitle }
    $window.FindName('ProfileDesktopTabItem').Header = $Ui.ProfileTabDesktop
    $window.FindName('ProfileServersTabItem').Header = $Ui.ProfileTabServers
    $window.FindName('ProfileDomainControllerTabItem').Header = $Ui.ProfileTabDomainController
    $window.FindName('ProfileLevelLabel').Text = $Ui.ProfileLevelLabel
    $desktopListBox = $window.FindName('ProfileDesktopListBox')
    $serversListBox = $window.FindName('ProfileServersListBox')
    $dcListBox = $window.FindName('ProfileDomainControllerListBox')
    $level1Radio = $window.FindName('ProfileLevel1RadioButton')
    $level2Radio = $window.FindName('ProfileLevel2RadioButton')
    $bothRadio = $window.FindName('ProfileLevelBothRadioButton')
    $bothRadio.Content = $Ui.ProfileLevelBothLabel
    if ($AllowLevelUnion) {
        # CIS generation only offers "L1 only" / "L1 + L2" (plan
        # §3.3 - a plain L2 file is a pure delta on top of L1, never a
        # standalone profile) - the plain "L2" radio is hidden entirely
        # rather than just disabled, so it can never end up the checked
        # option. The ordinary View > Profile picker (AllowLevelUnion not
        # set) is completely unaffected.
        $level2Radio.Visibility = 'Collapsed'
        $bothRadio.Visibility = 'Visible'
    }
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton
    $okButton.IsEnabled = $false

    function Add-ProfileGroupItem {
        param($ListBox, $Group)
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = "$($Group.Benchmark) v$($Group.Version)".Trim()
        $item.Tag = $Group
        [void]$ListBox.Items.Add($item)
    }

    foreach ($g in ($groups | Where-Object { -not $_.Role })) { Add-ProfileGroupItem -ListBox $desktopListBox -Group $g }
    foreach ($g in ($groups | Where-Object { $_.Role -eq 'MS' })) { Add-ProfileGroupItem -ListBox $serversListBox -Group $g }
    foreach ($g in ($groups | Where-Object { $_.Role -eq 'DC' })) { Add-ProfileGroupItem -ListBox $dcListBox -Group $g }

    $script:__profileSelectedGroup = $null

    # Scriptblock kept PLAIN (no .GetNewClosure()): a $script:x = ...
    # executed directly inside a .GetNewClosure() block never reaches the
    # real script variable (confirmed by isolated test) - the closure gets
    # its own isolated "$script:" pseudo-scope for both read and write. A
    # scriptblock that is NOT itself passed through GetNewClosure() resolves
    # "$script:" normally even when invoked from inside a closure - hence
    # this indirection.
    $setSelectedGroup = {
        param($Group)
        $script:__profileSelectedGroup = $Group
    }

    # Scriptblock (not a nested function): called from inside the
    # .GetNewClosure() closures below, which only capture variables in
    # scope, not nested functions defined there - a function here would be
    # "not recognized" once SelectionChanged actually fires from WPF.
    $updateProfileLevelAvailability = {
        param($Group, [string]$PreferredLevel)
        if ($null -eq $Group) {
            $level1Radio.IsEnabled = $false
            $level2Radio.IsEnabled = $false
            $bothRadio.IsEnabled = $false
            return
        }
        $hasL1 = [bool]($Group.Profiles | Where-Object { $_.Level -eq 'L1' })
        $hasL2 = [bool]($Group.Profiles | Where-Object { $_.Level -eq 'L2' })
        $level1Radio.IsEnabled = $hasL1
        # Plain "L2 only" is never a selectable outcome during CIS
        # generation (see the AllowLevelUnion branch above) - disabled here
        # too so IsEnabled stays consistent with the hidden Visibility.
        $level2Radio.IsEnabled = (-not $AllowLevelUnion) -and $hasL2
        # "L1 + L2" only makes sense (and is only enabled) when BOTH levels
        # actually exist for this group - otherwise it would be identical
        # to whichever single level is available.
        $bothRadio.IsEnabled = ($hasL1 -and $hasL2)
        if ($AllowLevelUnion) {
            if ($PreferredLevel -eq 'Both' -and $hasL1 -and $hasL2) { $bothRadio.IsChecked = $true }
            elseif ($hasL1) { $level1Radio.IsChecked = $true }
            elseif ($hasL2) {
                # No L1 recommendations at all for this group - "L1 only"/
                # "L1 + L2" are both meaningless. No radio can be validly
                # checked; block OK rather than silently falling back to a
                # bare L2 (never offered here, see plan §3.3).
                $level1Radio.IsChecked = $false
                $bothRadio.IsChecked = $false
                $okButton.IsEnabled = $false
            }
        }
        elseif ($PreferredLevel -eq 'L2' -and $hasL2) { $level2Radio.IsChecked = $true }
        elseif ($PreferredLevel -eq 'L1' -and $hasL1) { $level1Radio.IsChecked = $true }
        elseif ($hasL1) { $level1Radio.IsChecked = $true }
        else { $level2Radio.IsChecked = $true }
    }.GetNewClosure()

    $allListBoxes = @($desktopListBox, $serversListBox, $dcListBox)
    foreach ($lb in $allListBoxes) {
        $lb.Add_SelectionChanged({
            param($EventSender, $e)
            if ($null -eq $EventSender.SelectedItem) { return }
            foreach ($other in $allListBoxes) { if ($other -ne $EventSender) { $other.SelectedIndex = -1 } }
            # Never read/write $script:__profileSelectedGroup directly here
            # (isolated, see $setSelectedGroup comment) - go through the
            # local $group variable and the plain scriptblock.
            $group = $EventSender.SelectedItem.Tag
            & $setSelectedGroup $group
            & $updateProfileLevelAvailability -Group $group
            $okButton.IsEnabled = $true
        }.GetNewClosure())
    }

    if ($CurrentProfile) {
        $matchGroup = $groups | Where-Object { $_.Benchmark -eq $CurrentProfile.Benchmark -and $_.Version -eq $CurrentProfile.Version -and $_.Role -eq $CurrentProfile.Role } | Select-Object -First 1
        if ($matchGroup) {
            $targetListBox = if (-not $matchGroup.Role) { $desktopListBox } elseif ($matchGroup.Role -eq 'MS') { $serversListBox } else { $dcListBox }
            $targetTabItem = if (-not $matchGroup.Role) { $window.FindName('ProfileDesktopTabItem') } elseif ($matchGroup.Role -eq 'MS') { $window.FindName('ProfileServersTabItem') } else { $window.FindName('ProfileDomainControllerTabItem') }
            $targetTabItem.IsSelected = $true
            foreach ($item in $targetListBox.Items) {
                if ($item.Tag -eq $matchGroup) { $targetListBox.SelectedItem = $item; break }
            }
            $script:__profileSelectedGroup = $matchGroup
            & $updateProfileLevelAvailability -Group $matchGroup -PreferredLevel $CurrentProfile.Level
            $okButton.IsEnabled = $true
        }
    }

    $script:__profileSelectionResult = $null
    $okButton.Add_Click({
        param($EventSender, $e)
        if ($bothRadio.IsChecked) {
            $script:__profileSelectionResult = [pscustomobject]@{ Group = $script:__profileSelectedGroup; Levels = @('L1', 'L2') }
        }
        elseif ($AllowLevelUnion) {
            $level = if ($level2Radio.IsChecked) { 'L2' } else { 'L1' }
            $script:__profileSelectionResult = [pscustomobject]@{ Group = $script:__profileSelectedGroup; Levels = @($level) }
        }
        else {
            $level = if ($level2Radio.IsChecked) { 'L2' } else { 'L1' }
            $script:__profileSelectionResult = $script:__profileSelectedGroup.Profiles | Where-Object { $_.Level -eq $level } | Select-Object -First 1
        }
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({
        param($EventSender, $e)
        $window.DialogResult = $false
    })

    $null = $window.ShowDialog()
    return $script:__profileSelectionResult
}

# Field metadata for Show-OrgSpecificValuesDialog, in the plan §4.3 mockup
# order - Panel/Label/Box are the XAML x:Name suffixes shared by
# OrgSpecificValuesWindow, UiKey is the UiStrings.ps1 label for that field.
$script:CisOrgValueFieldDefs = @(
    @{ Key = 'RenameAdministratorAccount'; Panel = 'RenameAdministratorAccountPanel'; Label = 'RenameAdministratorAccountLabel'; Box = 'RenameAdministratorAccountTextBox'; UiKey = 'OrgSpecificFieldRenameAdministratorAccount' }
    @{ Key = 'RenameGuestAccount'; Panel = 'RenameGuestAccountPanel'; Label = 'RenameGuestAccountLabel'; Box = 'RenameGuestAccountTextBox'; UiKey = 'OrgSpecificFieldRenameGuestAccount' }
    @{ Key = 'LogonMessageTitle'; Panel = 'LogonMessageTitlePanel'; Label = 'LogonMessageTitleLabel'; Box = 'LogonMessageTitleTextBox'; UiKey = 'OrgSpecificFieldLogonMessageTitle' }
    @{ Key = 'LogonMessageText'; Panel = 'LogonMessageTextPanel'; Label = 'LogonMessageTextLabel'; Box = 'LogonMessageTextTextBox'; UiKey = 'OrgSpecificFieldLogonMessageText' }
)

function Show-OrgSpecificValuesDialog {
    <#
        "New Group Policy > CIS Gap-fill/Full compliance", screen 3 (plan
        §4.3): one text field per organization-specific CIS item actually
        present in the chosen profile(s) - $OrgValueEntries is
        Get-CisOrgValueEntries's result (already filtered to what's
        recommended; the caller is expected to skip this whole dialog when
        it's empty, per plan §4.4). Fields for anything absent from
        $OrgValueEntries are hidden entirely, never just disabled.

        Cancel aborts the WHOLE "New Group Policy" flow (plan §4.3 - "Annuler
        ici annule tout le flux, aucun dossier créé"): returns $null. Generate
        returns a hashtable Key -> entered text (untrimmed; a field left
        blank is simply not written later - see Invoke-CisProfileOverlay).
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][System.Collections.Generic.List[object]]$OrgValueEntries)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'OrgSpecificValuesWindow' -Owner $Owner
    $window.Title = $Ui.OrgSpecificValuesWindowTitle
    $window.FindName('OrgSpecificValuesIntroText').Text = $Ui.OrgSpecificValuesIntro

    $presentKeys = @($OrgValueEntries | ForEach-Object { $_.Key })
    $boxes = @{}
    foreach ($def in $script:CisOrgValueFieldDefs) {
        $window.FindName($def.Label).Text = $Ui[$def.UiKey]
        $box = $window.FindName($def.Box)
        $boxes[$def.Key] = $box
        $window.FindName($def.Panel).Visibility = if ($def.Key -in $presentKeys) { 'Visible' } else { 'Collapsed' }
    }

    $generateButton = $window.FindName('GenerateButton')
    $cancelButton = $window.FindName('CancelButton')
    $generateButton.Content = $Ui.GenerateButton
    $cancelButton.Content = $Ui.CancelButton

    $generateButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $cancelButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $false })

    if (-not $window.ShowDialog()) { return $null }

    $result = @{}
    foreach ($key in $boxes.Keys) { $result[$key] = $boxes[$key].Text }
    return $result
}

function Show-FilterDialog {
    <#
        "Filter" top menu dialog. Combines, in AND logic: configuration
        state (Any/Configured only/Enabled/Disabled/Not Configured),
        Computer/User scope, setting type (Admx/Security/AdvancedAudit),
        CIS profile (delegates to Show-ProfileSelectionDialog) and "has a
        CIS recommendation" only.

        $CurrentState: pscustomobject with StateMode (string), Scopes
        (string[], subset of 'Machine'/'User'), Kinds (string[], subset of
        'Admx'/'Security'/'AdvancedAudit'), Profile (CIS profile spec or
        $null), HasCisRecOnly (bool) - same shape as the return value.
        Returns the new state on Apply, $null on Cancel.
    #>
    param(
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        $CisIndex,
        [Parameter(Mandatory)]$CurrentState
    )

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'FilterWindow' -Owner $Owner
    $window.Title = $Ui.FilterWindowTitle
    $window.FindName('FilterStateGroupBox').Header = $Ui.FilterStateGroupHeader
    $stateAnyRadio = $window.FindName('FilterStateAnyRadio')
    $stateConfiguredRadio = $window.FindName('FilterStateConfiguredRadio')
    $stateEnabledRadio = $window.FindName('FilterStateEnabledRadio')
    $stateDisabledRadio = $window.FindName('FilterStateDisabledRadio')
    $stateNotConfiguredRadio = $window.FindName('FilterStateNotConfiguredRadio')
    $stateAnyRadio.Content = $Ui.FilterStateAny
    $stateConfiguredRadio.Content = $Ui.FilterStateConfiguredOnly
    $stateEnabledRadio.Content = $Ui.FilterStateEnabled
    $stateDisabledRadio.Content = $Ui.FilterStateDisabled
    $stateNotConfiguredRadio.Content = $Ui.FilterStateNotConfigured

    $window.FindName('FilterScopeGroupBox').Header = $Ui.FilterScopeGroupHeader
    $scopeComputerCheck = $window.FindName('FilterScopeComputerCheck')
    $scopeUserCheck = $window.FindName('FilterScopeUserCheck')
    $scopeComputerCheck.Content = $Ui.ScopeComputer
    $scopeUserCheck.Content = $Ui.ScopeUser

    $window.FindName('FilterKindGroupBox').Header = $Ui.FilterKindGroupHeader
    $kindAdmxCheck = $window.FindName('FilterKindAdmxCheck')
    $kindSecurityCheck = $window.FindName('FilterKindSecurityCheck')
    $kindAdvancedAuditCheck = $window.FindName('FilterKindAdvancedAuditCheck')
    $kindAdmxCheck.Content = $Ui.FilterKindAdmx
    $kindSecurityCheck.Content = $Ui.FilterKindSecurity
    $kindAdvancedAuditCheck.Content = $Ui.FilterKindAdvancedAudit

    $window.FindName('FilterCisGroupBox').Header = $Ui.FilterCisGroupHeader
    $cisProfileLabel = $window.FindName('FilterCisProfileLabel')
    $chooseProfileButton = $window.FindName('FilterChooseProfileButton')
    $clearProfileButton = $window.FindName('FilterClearProfileButton')
    $hasCisRecCheck = $window.FindName('FilterHasCisRecCheck')
    $chooseProfileButton.Content = $Ui.FilterChooseProfileButton
    $clearProfileButton.Content = $Ui.FilterClearProfileButton
    $hasCisRecCheck.Content = $Ui.FilterHasCisRecOnly

    $resetButton = $window.FindName('FilterResetButton')
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $resetButton.Content = $Ui.FilterResetButton
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    # CIS group is only meaningful when a CIS index is actually loaded -
    # same guard as the old Update-ProfileMenuVisibility.
    $hasCisIndex = ($null -ne $CisIndex)
    $window.FindName('FilterCisGroupBox').Visibility = if ($hasCisIndex) { 'Visible' } else { 'Collapsed' }

    $script:__filterSelectedProfile = $CurrentState.Profile

    function Update-FilterCisProfileLabel {
        if ($null -eq $script:__filterSelectedProfile) {
            $cisProfileLabel.Text = $Ui.FilterNoProfileSelected
        } else {
            $cisProfileLabel.Text = ($Ui.FilterCurrentProfileFormat -f (Get-CisProfileDisplayText -ProfileSpec $script:__filterSelectedProfile))
        }
    }
    Update-FilterCisProfileLabel

    function Set-FilterFormFromState {
        param($State)
        switch ($State.StateMode) {
            'ConfiguredOnly' { $stateConfiguredRadio.IsChecked = $true }
            'Enabled'        { $stateEnabledRadio.IsChecked = $true }
            'Disabled'       { $stateDisabledRadio.IsChecked = $true }
            'NotConfigured'  { $stateNotConfiguredRadio.IsChecked = $true }
            default          { $stateAnyRadio.IsChecked = $true }
        }
        $scopeComputerCheck.IsChecked = ($State.Scopes -contains 'Machine')
        $scopeUserCheck.IsChecked = ($State.Scopes -contains 'User')
        $kindAdmxCheck.IsChecked = ($State.Kinds -contains 'Admx')
        $kindSecurityCheck.IsChecked = ($State.Kinds -contains 'Security')
        $kindAdvancedAuditCheck.IsChecked = ($State.Kinds -contains 'AdvancedAudit')
        $hasCisRecCheck.IsChecked = [bool]$State.HasCisRecOnly
    }
    Set-FilterFormFromState -State $CurrentState

    $chooseProfileButton.Add_Click({
        param($EventSender, $e)
        $selected = Show-ProfileSelectionDialog -Owner $window -ScriptRoot $ScriptRoot -Ui $Ui -CisIndex $CisIndex -CurrentProfile $script:__filterSelectedProfile
        if ($selected) {
            $script:__filterSelectedProfile = $selected
            Update-FilterCisProfileLabel
        }
    })

    $clearProfileButton.Add_Click({
        param($EventSender, $e)
        $script:__filterSelectedProfile = $null
        Update-FilterCisProfileLabel
    })

    $resetButton.Add_Click({
        param($EventSender, $e)
        $script:__filterSelectedProfile = $null
        Update-FilterCisProfileLabel
        Set-FilterFormFromState -State ([pscustomobject]@{
            StateMode = 'Any'
            Scopes = @('Machine', 'User')
            Kinds = @('Admx', 'Security', 'AdvancedAudit')
            HasCisRecOnly = $false
        })
    })

    $script:__filterDialogResult = $null
    $okButton.Add_Click({
        param($EventSender, $e)
        $stateMode = if ($stateConfiguredRadio.IsChecked) { 'ConfiguredOnly' }
            elseif ($stateEnabledRadio.IsChecked) { 'Enabled' }
            elseif ($stateDisabledRadio.IsChecked) { 'Disabled' }
            elseif ($stateNotConfiguredRadio.IsChecked) { 'NotConfigured' }
            else { 'Any' }
        $scopes = New-Object System.Collections.Generic.List[string]
        if ($scopeComputerCheck.IsChecked) { $scopes.Add('Machine') }
        if ($scopeUserCheck.IsChecked) { $scopes.Add('User') }
        $kinds = New-Object System.Collections.Generic.List[string]
        if ($kindAdmxCheck.IsChecked) { $kinds.Add('Admx') }
        if ($kindSecurityCheck.IsChecked) { $kinds.Add('Security') }
        if ($kindAdvancedAuditCheck.IsChecked) { $kinds.Add('AdvancedAudit') }
        $script:__filterDialogResult = [pscustomobject]@{
            StateMode = $stateMode
            Scopes = @($scopes)
            Kinds = @($kinds)
            Profile = $script:__filterSelectedProfile
            HasCisRecOnly = [bool]$hasCisRecCheck.IsChecked
        }
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({
        param($EventSender, $e)
        $window.DialogResult = $false
    })

    $null = $window.ShowDialog()
    return $script:__filterDialogResult
}

function Show-CisMissingAdmxDialog {
    <#
        View > CIS - Missing ADMX templates. $Rows comes from
        Get-CisMissingAdmxReport (GpEdit.ps1) - already filtered to the
        active profile and to entries with a non-null requiredAdmx. This
        function only maps Category -> translated label and
        IsPresent -> Yes/No label, and renders the intro text/grid.
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [object[]]$Rows, [string]$ActiveProfileText)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'CisMissingAdmxWindow' -Owner $Owner
    $window.Title = $Ui.CisMissingAdmxWindowTitle

    $introText = $window.FindName('CisMissingAdmxIntroText')
    $introText.Text = if ($ActiveProfileText) { $Ui.CisMissingAdmxIntroFormat -f $ActiveProfileText } else { $Ui.CisMissingAdmxNoActiveProfile }

    $categoryLabels = @{
        BundledConditional = $Ui.CisAdmxCategoryBundledConditional
        ManualDownload      = $Ui.CisAdmxCategoryManualDownload
        ThirdParty          = $Ui.CisAdmxCategoryThirdParty
    }

    $grid = $window.FindName('CisMissingAdmxGrid')
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($Rows)) {
        $items.Add([pscustomobject]@{
            CisNumber     = $row.CisNumber
            Title         = $row.Title
            AdmxFile      = $row.AdmxFile
            CategoryLabel = if ($categoryLabels.ContainsKey($row.Category)) { $categoryLabels[$row.Category] } else { $row.Category }
            VersionText   = $row.VersionText
            PresentLabel  = if ($row.IsPresent) { $Ui.CisYes } else { $Ui.CisNo }
        })
    }
    $grid.ItemsSource = $items

    $okButton = $window.FindName('OkButton')
    $okButton.Content = $Ui.OkButton
    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $null = $window.ShowDialog()
}

function Show-AboutWindow {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [System.Collections.Generic.List[object]]$ChangelogEntries)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'AboutWindow' -Owner $Owner
    $window.Title = $Ui.AboutWindowTitle
    $window.FindName('AppNameLabel').Text = $Ui.AboutAppNameLabel
    $window.FindName('SeeChangelogLabel').Text = $Ui.AboutSeeChangelog

    $versionLabel = $window.FindName('VersionLabel')
    if ($ChangelogEntries -and $ChangelogEntries.Count -gt 0) {
        $latest = $ChangelogEntries[0]
        $versionLabel.Text = ($Ui.AboutVersionFormat -f $latest.Date, $latest.Title)
    } else {
        $versionLabel.Text = ($Ui.AboutVersionFormat -f '-', '-')
    }

    $okButton = $window.FindName('OkButton')
    $okButton.Content = $Ui.OkButton
    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $null = $window.ShowDialog()
}

function Show-PatchNoteWindow {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [System.Collections.Generic.List[object]]$ChangelogEntries)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'PatchNoteWindow' -Owner $Owner
    $window.Title = $Ui.PatchNoteWindowTitle
    $textBlock = $window.FindName('PatchNoteTextBlock')
    Set-ChangelogTextBlockContent -TextBlock $textBlock -Entries $ChangelogEntries -MaxEntries 0

    $okButton = $window.FindName('OkButton')
    $okButton.Content = $Ui.OkButton
    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $null = $window.ShowDialog()
}

function Show-NewGpoDialog {
    <#
        "Advanced > New Group Policy" first step: Default, CIS - Gap-fill,
        or CIS - Full compliance. Returns 'Default'/'GapFill'/
        'FullCompliance' on OK, $null on Cancel.
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'NewGpoWindow' -Owner $Owner
    $window.Title = $Ui.NewGpoWindowTitle
    $defaultRadio = $window.FindName('NewGpoDefaultRadioButton')
    $gapFillRadio = $window.FindName('NewGpoCisGapFillRadioButton')
    $fullComplianceRadio = $window.FindName('NewGpoCisFullComplianceRadioButton')
    $defaultRadio.Content = $Ui.NewGpoOptionDefault
    $gapFillRadio.Content = $Ui.NewGpoOptionCisGapFill
    $fullComplianceRadio.Content = $Ui.NewGpoOptionCisFullCompliance
    $window.FindName('NewGpoDefaultDescriptionText').Text = $Ui.NewGpoOptionDefaultDescription
    $window.FindName('NewGpoCisGapFillDescriptionText').Text = $Ui.NewGpoOptionCisGapFillDescription
    $window.FindName('NewGpoCisFullComplianceDescriptionText').Text = $Ui.NewGpoOptionCisFullComplianceDescription
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $cancelButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $false })

    if ($window.ShowDialog()) {
        if ($gapFillRadio.IsChecked) { return 'GapFill' }
        if ($fullComplianceRadio.IsChecked) { return 'FullCompliance' }
        return 'Default'
    }
    return $null
}

function Show-UnsavedProjectCloseDialog {
    <#
        Closing the main window (X/Alt+F4) while a "New Group Policy"
        session isn't saved yet - 3 distinct choices, not a plain Yes/No:
        'Save' (save before closing), 'Continue' (close without saving,
        temp files lost), 'Cancel' (abort closing). Dedicated buttons
        instead of [System.Windows.MessageBox] since Yes/No/Cancel can't be
        relabeled. Returns one of the 3 strings, or 'Cancel' if the window
        is closed via X itself (same effect as an explicit Cancel click).
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [switch]$AlreadySaved)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'UnsavedProjectCloseWindow' -Owner $Owner
    $window.Title = $Ui.UnsavedProjectCloseTitle
    # $AlreadySaved: the project was already saved/opened at least once and
    # only has pending changes since the last "Save now" - distinct wording
    # from the never-saved-at-all "New Group Policy" session case, same 3
    # choices either way (see Add_Closing).
    $window.FindName('UnsavedProjectCloseMessageLabel').Text = if ($AlreadySaved) { $Ui.UnsavedProjectChangesCloseMessage } else { $Ui.UnsavedProjectCloseMessage }
    $saveButton = $window.FindName('SaveButton')
    $continueButton = $window.FindName('ContinueButton')
    $cancelButton = $window.FindName('CancelButton')
    $saveButton.Content = $Ui.SaveButton
    $continueButton.Content = $Ui.ContinueButton
    $cancelButton.Content = $Ui.CancelButton

    $script:__unsavedProjectCloseResult = 'Cancel'
    $saveButton.Add_Click({ param($EventSender, $e) $script:__unsavedProjectCloseResult = 'Save'; $window.Close() })
    $continueButton.Add_Click({ param($EventSender, $e) $script:__unsavedProjectCloseResult = 'Continue'; $window.Close() })
    $cancelButton.Add_Click({ param($EventSender, $e) $script:__unsavedProjectCloseResult = 'Cancel'; $window.Close() })

    $null = $window.ShowDialog()
    return $script:__unsavedProjectCloseResult
}

