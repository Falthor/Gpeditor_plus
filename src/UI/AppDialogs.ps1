<#
    Top-menu windows: optional-column picker (View > Add/remove columns),
    and the three "?" menu info windows (About / Patch note / Benchmark).
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
    # as Select-OnlyConfiguredItems (GpEdit.ps1), fixed here as a precaution.
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
    #>
    param(
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        $CisIndex,
        $CurrentProfile
    )

    $groups = Get-CisProfileGroups -CisIndex $CisIndex

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ProfileSelectionWindow' -Owner $Owner
    $window.Title = $Ui.ProfileSelectionWindowTitle
    $window.FindName('ProfileDesktopTabItem').Header = $Ui.ProfileTabDesktop
    $window.FindName('ProfileServersTabItem').Header = $Ui.ProfileTabServers
    $window.FindName('ProfileDomainControllerTabItem').Header = $Ui.ProfileTabDomainController
    $window.FindName('ProfileLevelLabel').Text = $Ui.ProfileLevelLabel
    $desktopListBox = $window.FindName('ProfileDesktopListBox')
    $serversListBox = $window.FindName('ProfileServersListBox')
    $dcListBox = $window.FindName('ProfileDomainControllerListBox')
    $level1Radio = $window.FindName('ProfileLevel1RadioButton')
    $level2Radio = $window.FindName('ProfileLevel2RadioButton')
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
            return
        }
        $hasL1 = [bool]($Group.Profiles | Where-Object { $_.Level -eq 'L1' })
        $hasL2 = [bool]($Group.Profiles | Where-Object { $_.Level -eq 'L2' })
        $level1Radio.IsEnabled = $hasL1
        $level2Radio.IsEnabled = $hasL2
        if ($PreferredLevel -eq 'L2' -and $hasL2) { $level2Radio.IsChecked = $true }
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
        $level = if ($level2Radio.IsChecked) { 'L2' } else { 'L1' }
        $script:__profileSelectionResult = $script:__profileSelectedGroup.Profiles | Where-Object { $_.Level -eq $level } | Select-Object -First 1
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({
        param($EventSender, $e)
        $window.DialogResult = $false
    })

    $null = $window.ShowDialog()
    return $script:__profileSelectionResult
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
        "Advanced > New Group Policy" first step: Default (only enabled
        option) vs CIS prefill (grayed out, future work). Returns 'Default'
        on OK, $null on Cancel - since CIS prefill isn't selectable, OK
        always means Default.
    #>
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'NewGpoWindow' -Owner $Owner
    $window.Title = $Ui.NewGpoWindowTitle
    $window.FindName('NewGpoDefaultRadioButton').Content = $Ui.NewGpoOptionDefault
    $window.FindName('NewGpoCisPrefillRadioButton').Content = $Ui.NewGpoOptionCisPrefill
    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton

    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $cancelButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $false })

    if ($window.ShowDialog()) { return 'Default' }
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

function Show-BenchmarkWindow {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, $CisIndex)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'BenchmarkWindow' -Owner $Owner
    $window.Title = $Ui.BenchmarkWindowTitle
    $window.FindName('BenchmarkIntroLabel').Text = $Ui.BenchmarkIntro

    $listBox = $window.FindName('BenchmarkListBox')
    if ($CisIndex -and $CisIndex.meta -and $CisIndex.meta.sourceFiles) {
        foreach ($f in @($CisIndex.meta.sourceFiles)) { [void]$listBox.Items.Add($f) }
    }

    $okButton = $window.FindName('OkButton')
    $okButton.Content = $Ui.OkButton
    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $null = $window.ShowDialog()
}
