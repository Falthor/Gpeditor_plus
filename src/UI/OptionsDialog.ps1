<#
    File > Options: sidebar (Path / File / Others / Close) on the left,
    right panel toggles between the 3 tabs (Close just closes the window).
#>

Set-StrictMode -Version Latest

function Show-OptionsDialog {
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'OptionsWindow' -Owner $Owner
    $window.Title = $Ui.OptionsWindowTitle

    $pathNavButton   = $window.FindName('PathNavButton')
    $fileNavButton   = $window.FindName('FileNavButton')
    $editorNavButton = $window.FindName('EditorNavButton')
    $closeNavButton  = $window.FindName('CloseNavButton')
    $pathPanel       = $window.FindName('PathPanel')
    $filePanel       = $window.FindName('FilePanel')
    $editorPanel     = $window.FindName('EditorPanel')

    $window.FindName('OptionsNavPathLabel').Text = $Ui.OptionsNavPath
    $window.FindName('OptionsNavFileLabel').Text = $Ui.OptionsNavFile
    $window.FindName('OptionsNavEditorLabel').Text = $Ui.OptionsNavEditor
    $closeNavButton.Content = $Ui.OptionsNavClose

    $window.FindName('PathTabLogLabel').Text = $Ui.PathTabLogLabel
    $window.FindName('PathTabBackupLabel').Text = $Ui.PathTabBackupLabel
    $window.FindName('PathTabImportExportLabel').Text = $Ui.PathTabImportExportLabel
    $window.FindName('PathTabAuditLabel').Text = $Ui.PathTabAuditLabel
    $window.FindName('PathTabProjectsLabel').Text = $Ui.PathTabProjectsLabel
    $window.FindName('AppPreferenceGroupBox').Header = $Ui.PathGroupAppPreferenceHeader
    $window.FindName('FileTabAuditListHeader').Text = $Ui.FileTabAuditListHeader
    $window.FindName('AddAuditFileButton').Content = $Ui.AddAuditFileButton
    $window.FindName('DeleteAuditFileButton').Content = $Ui.DeleteAuditFileButton
    $window.FindName('EditionGroupBox').Header = $Ui.OthersGroupEditionHeader
    $window.FindName('EditorModeExplanationLabel').Text = $Ui.EditorModeWarning
    $window.FindName('EditorModeCheckBox').Content = $Ui.EditorModeCheckboxLabel
    $window.FindName('ImportGroupBox').Header = $Ui.OthersGroupImportHeader
    $window.FindName('OthersImportExplanationLabel').Text = $Ui.OthersImportExplanation
    $window.FindName('DefaultImportModeLabel').Text = $Ui.DefaultImportModeLabel
    $window.FindName('DefaultImportModeClassicItem').Content = $Ui.ImportModeClassic
    $window.FindName('DefaultImportModeStandardItem').Content = $Ui.ImportModeStandard
    $window.FindName('DefaultImportModeAdvancedItem').Content = $Ui.ImportModeAdvanced
    $window.FindName('BusyOverlayLabel').Text = $Ui.OptionsBusyOverlayLabel

    foreach ($name in @('LogPathResetButton', 'BackupPathResetButton',
                         'ImportExportPathResetButton', 'AuditPathResetButton',
                         'ProjectsPathResetButton')) {
        $window.FindName($name).Content = $Ui.ResetToDefaultButton
    }
    foreach ($name in @('LogPathBrowseButton', 'BackupPathBrowseButton',
                         'ImportExportPathBrowseButton', 'AuditPathBrowseButton',
                         'ProjectsPathBrowseButton')) {
        $window.FindName($name).Content = $Ui.BrowseEllipsisButton
    }
    foreach ($name in @('LogPathOpenButton', 'BackupPathOpenButton',
                         'ImportExportPathOpenButton', 'AuditPathOpenButton',
                         'ProjectsPathOpenButton')) {
        $window.FindName($name).ToolTip = $Ui.OpenFolderButtonTooltip
    }
    $window.FindName('SavePathsButton').Content = $Ui.SaveButton

    # --- Sidebar: exclusivity via RadioButton.GroupName (see XAML), just
    # toggle Visibility of the 3 panels -----------------------------------
    $pathNavButton.Add_Checked({ $pathPanel.Visibility = 'Visible'; $filePanel.Visibility = 'Collapsed'; $editorPanel.Visibility = 'Collapsed' })
    $fileNavButton.Add_Checked({
        $pathPanel.Visibility = 'Collapsed'; $filePanel.Visibility = 'Visible'; $editorPanel.Visibility = 'Collapsed'
        Update-OptionsAuditFilesList -ListBox $auditFilesListBox -AuditFilesDir $script:AppSettings.paths.auditFilesDir
    })
    $editorNavButton.Add_Checked({ $pathPanel.Visibility = 'Collapsed'; $filePanel.Visibility = 'Collapsed'; $editorPanel.Visibility = 'Visible' })
    $closeNavButton.Add_Click({ $window.Close() })

    # --- Path tab: 6 rows, each Key/TextBox/BrowseButton/OpenButton/ResetButton ---
    # Shared state via hashtable (variable reassignment inside Add_Click
    # closures wouldn't stick) - same pattern as Show-SelectPrincipalsDialog.
    # "..."/Default only update the TextBox + $pendingPaths; nothing is
    # written to disk until Save is clicked, so closing the window doesn't
    # silently confirm unwanted path changes.
    $pathRows = @(
        @{ Key = 'logDir';          TextBox = $window.FindName('LogPathTextBox');          Browse = $window.FindName('LogPathBrowseButton');          Open = $window.FindName('LogPathOpenButton');          Reset = $window.FindName('LogPathResetButton') }
        @{ Key = 'backupRoot';      TextBox = $window.FindName('BackupPathTextBox');       Browse = $window.FindName('BackupPathBrowseButton');       Open = $window.FindName('BackupPathOpenButton');       Reset = $window.FindName('BackupPathResetButton') }
        @{ Key = 'importExportDir'; TextBox = $window.FindName('ImportExportPathTextBox'); Browse = $window.FindName('ImportExportPathBrowseButton'); Open = $window.FindName('ImportExportPathOpenButton'); Reset = $window.FindName('ImportExportPathResetButton') }
        @{ Key = 'auditFilesDir';   TextBox = $window.FindName('AuditPathTextBox');        Browse = $window.FindName('AuditPathBrowseButton');        Open = $window.FindName('AuditPathOpenButton');        Reset = $window.FindName('AuditPathResetButton') }
        @{ Key = 'projectsDir';     TextBox = $window.FindName('ProjectsPathTextBox');     Browse = $window.FindName('ProjectsPathBrowseButton');     Open = $window.FindName('ProjectsPathOpenButton');     Reset = $window.FindName('ProjectsPathResetButton') }
    )
    $defaultPaths = Get-DefaultAppPaths
    $pendingPaths = @{}

    foreach ($row in $pathRows) {
        $pendingPaths[$row.Key] = $script:AppSettings.paths.($row.Key)
        $row.TextBox.Text = $pendingPaths[$row.Key]

        $row.Browse.Add_Click({
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.SelectedPath = $row.TextBox.Text
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
            $newPath = Join-Path $dialog.SelectedPath ''
            $pendingPaths[$row.Key] = $newPath
            $row.TextBox.Text = $newPath
        }.GetNewClosure())

        $row.Open.Add_Click({
            if (Test-Path -LiteralPath $row.TextBox.Text) {
                Start-Process -FilePath 'explorer.exe' -ArgumentList $row.TextBox.Text
            }
        }.GetNewClosure())

        $row.Reset.Add_Click({
            $newPath = $defaultPaths[$row.Key]
            $pendingPaths[$row.Key] = $newPath
            $row.TextBox.Text = $newPath
        }.GetNewClosure())
    }

    $window.FindName('SavePathsButton').Add_Click({
        foreach ($key in $pendingPaths.Keys) { $script:AppSettings.paths.$key = $pendingPaths[$key] }
        Save-AppSettings -Settings $script:AppSettings
        [System.Windows.MessageBox]::Show($Ui.SettingsSavedMessage, $Ui.InfoTitle, 'OK', 'Information') | Out-Null

        # Restart ourselves (same exe + script, re-elevated via -Verb RunAs,
        # since the app requires elevation - see GpEdit.ps1 startup check)
        # instead of asking the user to relaunch manually. Only close the
        # windows after the new process actually launched, so a failed
        # relaunch (UAC denied) or a cancelled main-window close (unsaved
        # project) doesn't leave the user without an app.
        try {
            $hostExePath = (Get-Process -Id $PID).Path
            $mainScriptPath = Join-Path $ScriptRoot 'GpEdit.ps1'
            Start-Process -FilePath $hostExePath -ArgumentList @('-File', "`"$mainScriptPath`"") -Verb RunAs -ErrorAction Stop | Out-Null
        }
        catch {
            [System.Windows.MessageBox]::Show(($Ui.RestartFailedFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
            return
        }

        $window.Close()
        if (-not $window.IsVisible) { $Owner.Close() }
    })

    # --- File tab: multi-select list of .audit files, Add/Delete + rebuild ---
    $auditFilesListBox = $window.FindName('AuditFilesListBox')
    $addAuditFileButton = $window.FindName('AddAuditFileButton')
    $deleteAuditFileButton = $window.FindName('DeleteAuditFileButton')

    $addAuditFileButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = 'Audit files (*.audit)|*.audit'
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            Copy-Item -LiteralPath $dialog.FileName -Destination $script:AppSettings.paths.auditFilesDir -Force
            Invoke-CisIndexRebuild -Window $window -ScriptRoot $ScriptRoot -Ui $Ui `
                -AuditFilesPath $script:AppSettings.paths.auditFilesDir -IndexDir $script:AppSettings.paths.indexDir
            Update-OptionsAuditFilesList -ListBox $auditFilesListBox -AuditFilesDir $script:AppSettings.paths.auditFilesDir
        }
        catch {
            [System.Windows.MessageBox]::Show(($Ui.AuditFileAddErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        }
    })

    $deleteAuditFileButton.Add_Click({
        $selected = @($auditFilesListBox.SelectedItems)
        if ($selected.Count -eq 0) { return }
        $confirm = [System.Windows.MessageBox]::Show($Ui.DeleteAuditFileConfirmMessage, $Ui.DeleteAuditFileConfirmTitle, 'YesNo', 'Question')
        if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }
        try {
            foreach ($item in $selected) {
                Remove-Item -LiteralPath (Join-Path $script:AppSettings.paths.auditFilesDir $item) -Force
            }
            Invoke-CisIndexRebuild -Window $window -ScriptRoot $ScriptRoot -Ui $Ui `
                -AuditFilesPath $script:AppSettings.paths.auditFilesDir -IndexDir $script:AppSettings.paths.indexDir
            Update-OptionsAuditFilesList -ListBox $auditFilesListBox -AuditFilesDir $script:AppSettings.paths.auditFilesDir
        }
        catch {
            [System.Windows.MessageBox]::Show(($Ui.AuditFileDeleteErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        }
    })

    # --- Others tab: Editor Mode + default import mode, both apply immediately + persisted ---
    $editorModeCheckBox = $window.FindName('EditorModeCheckBox')
    $editorModeCheckBox.IsChecked = $script:AppSettings.editorMode
    $editorModeCheckBox.Add_Click({
        $script:CatalogEditingEnabled = [bool]$editorModeCheckBox.IsChecked
        $script:AppSettings.editorMode = [bool]$editorModeCheckBox.IsChecked
        Save-AppSettings -Settings $script:AppSettings
    })

    $defaultImportModeComboBox = $window.FindName('DefaultImportModeComboBox')
    $defaultImportModeComboBox.Items | Where-Object { $_.Tag -eq $script:AppSettings.defaultImportMode } | ForEach-Object { $defaultImportModeComboBox.SelectedItem = $_ }
    if (-not $defaultImportModeComboBox.SelectedItem) { $defaultImportModeComboBox.SelectedItem = $window.FindName('DefaultImportModeClassicItem') }
    $defaultImportModeComboBox.Add_SelectionChanged({
        $selected = $defaultImportModeComboBox.SelectedItem
        if (-not $selected) { return }
        $script:AppSettings.defaultImportMode = $selected.Tag
        Save-AppSettings -Settings $script:AppSettings
    })

    $null = $window.ShowDialog()
}

function Update-OptionsAuditFilesList {
    param([Parameter(Mandatory)]$ListBox, [Parameter(Mandatory)][string]$AuditFilesDir)
    $ListBox.Items.Clear()
    if (-not (Test-Path -LiteralPath $AuditFilesDir)) { return }
    Get-ChildItem -LiteralPath $AuditFilesDir -Filter '*.audit' | Sort-Object Name | ForEach-Object {
        [void]$ListBox.Items.Add($_.Name)
    }
}

function Invoke-CisIndexRebuild {
    <#
        Rebuilds cis-index.json from the current Audit files folder
        (synchronous), then reloads $script:CisIndex so the running session
        reflects the change without a restart. The Dispatcher.Invoke forces
        WPF to render the BusyOverlay before the blocking Build-Index.ps1 -Kind Cis
        call - just setting Visibility isn't enough, WPF only paints it
        after this handler returns otherwise. The folder fingerprint is
        stored in meta.sourceFingerprint so GpEdit.ps1 can skip rebuilding
        the index on next launch if nothing changed.
    #>
    param(
        [Parameter(Mandatory)]$Window,
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        [Parameter(Mandatory)][string]$AuditFilesPath,
        [Parameter(Mandatory)][string]$IndexDir
    )
    $busyOverlay = $Window.FindName('BusyOverlay')
    $prevCursor = $Window.Cursor
    $Window.Cursor = [System.Windows.Input.Cursors]::Wait
    $busyOverlay.Visibility = 'Visible'
    $Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render) | Out-Null
    try {
        $outputPath = Join-Path $IndexDir 'cis-index.json'
        $fingerprint = Get-AuditFilesFingerprint -AuditFilesPath $AuditFilesPath
        & (Join-Path $ScriptRoot 'Indexers\Build-Index.ps1') -Kind Cis -AuditFilesPath $AuditFilesPath -OutputPath $outputPath -SourceFingerprint $fingerprint
        $script:CisIndex = Import-CisIndex -Path $outputPath
    }
    catch {
        [System.Windows.MessageBox]::Show(($Ui.CisIndexRebuildErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
    }
    finally {
        $busyOverlay.Visibility = 'Collapsed'
        $Window.Cursor = $prevCursor
    }
}
