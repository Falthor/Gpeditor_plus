# Overview — Gpeditor_plus

> Single reference document on how the project actually works, up to date
> as of 2026-07-29. 

## 1. What is Gpeditor_plus?

A PowerShell + WPF reimplementation of the `gpedit.msc` console (Windows
Local Group Policy Editor), plus:
- a CIS Benchmark cross-reference (comparing current state against
  hardening recommendations),
- an off-machine "GPO project" workflow (deferred editing, outside the
  system `registry.pol`, with explicit save/export),
- a "catalog editor mode" allowing live editing of security-setting
  metadata (name, explanation, CIS link).

English-only (en-US) application, no language selector. Must be launched
as administrator (blocking check at startup): there is no read-only
mode.

## 2. Entry point and startup

Everything starts from `Gpeditor_plus\src\GpEdit.ps1` (~2600 lines).
Startup sequence:

1. Load WPF assemblies, then dot-source modules in a fixed order:
   `AppLog.ps1`, `AppSettings.ps1` → `Parsers\*.ps1` →
   `Catalogs\SecurityCatalog.ps1` → `Policy\PolicyState.ps1` →
   `UI\EditDialogs.ps1`, `SelectPrincipalsDialog.ps1`, `OptionsDialog.ps1`,
   `UiStrings.ps1` → `Indexers\*Fingerprint.ps1` →
   `Policy\PolicyWriter.ps1`, `ChangeApplier.ps1` →
   `Parsers\AuditCsvFile.ps1` → `Catalogs\AdvancedAuditCatalog.ps1`,
   `CisCatalog.ps1` → `Parsers\ChangelogFile.ps1` → `UI\AppDialogs.ps1` →
   `ImportGpoProjectFiles.ps1`.
2. Admin elevation check (`Test-IsRunningAsAdministrator`,
   `Policy\ChangeApplier.ps1`) — otherwise a blocking message and exit.
3. Load `AppSettings` (JSON persisted at
   `%LocalAppData%\Gpeditor_plus\settings.json`); on first run,
   `Initialize-AppSettingsFirstRun` creates default folders and copies
   the bundled CIS `.audit` files.
4. Set up `$script:` state (dirty flags for project/security, search
   state, Filter-menu state, GPO-project temp-file tracking).
5. Load/rebuild the cached JSON indexes (see §4).
6. `secedit /export` runs on every launch to snapshot the effective
   security policy (`secedit.inf`), plus a snapshot of
   `[Registry Values]` keys so tattooed values can be cleaned up later
   (`Remove-TattooedRegistryValues` — `secedit /configure` never deletes
   a value just because it's absent from the imported `.inf`).
7. Read the current `registry.pol` state (Machine + User).
8. Build category lookups, load the merged XAML
   (`UI\AllWindows.Reference.xaml` — every window plus the shared style
   merged into a single file, each `<Window>` tagged with a stable
   `x:Name`; `Get-MergedXamlWindowNode` extracts the needed fragment and
   loads it via `XamlReader.Load`), wire up named controls, build the
   tree (`Build-MainTreeRoots`), then enter the WPF loop
   (`$window.ShowDialog()`).

The rest of the file (~lines 1000-2600) implements: GPO project
lifecycle (New/Open/Save/Export), the Filter menu, column management,
policy-list rendering, and search (`Invoke-Search` plus tree
navigation/restoration).

## 3. Code layout (`src/`)

| Folder | Role |
|---|---|
| `Parsers\` | Pure read/write of file formats, no UI dependency |
| `Policy\` | Translation between parsed data ↔ displayable/editable state |
| `Catalogs\` | Static metadata describing settings not self-described by ADMX |
| `Indexers\` | Standalone scripts that build the cached JSON indexes |
| `UI\` | XAML windows + PowerShell code-behind |
| `Tests\` | Custom in-house regression scripts (no Pester) |
| `DefaultData\` | Bundled data: security catalog, CIS `.audit` files |

### Parsers\
- `PolFile.ps1` — hand-rolled binary parser/writer for `registry.pol`
  (PReg format). `Read-PolFile`, `Write-PolFile`,
  `ConvertFrom/ToPolData`, delete-marker handling (`**del.<value>`).
- `GptIniFile.ps1` — reads/writes `GPT.ini` (packed `Version=` DWORD,
  Machine/User). `Step-GptIniVersion` bumps it on every write to force
  `gpupdate` to reprocess.
- `GptTmplFile.ps1` — INI reader/writer for `GptTmpl.inf` (passwords,
  lockout, user rights, audit policy), also used to parse `secedit.inf`
  (same format).
- `AuditCsvFile.ps1` — reads/writes `audit.csv` (Advanced Audit Policy),
  matched by subcategory GUID.
- `ChangelogFile.ps1` — parses `CHANGELOG.md` for the Release Notes
  panel / Patch Note window.

### Policy\
- `PolicyState.ps1` — computes the effective state of an ADMX policy
  (Not Configured/Enabled/Disabled) from `.pol`
  (`Get-AdmxPolicyState`), formats security setting values for display,
  resolves SIDs to display names.
- `PolicyWriter.ps1` — merges a pending change into `.pol` entries or
  the `GptTmpl.inf` structure, plus `New-TimestampedBackup` (one backup
  per session before the first write).
- `ChangeApplier.ps1` — actual disk writes (`Save-AdmxChangeToFile`,
  `Save-SecurityChangeToFile`, `Save-AdvancedAuditChangeToFile`), the
  `secedit /export` / `secedit /configure` cycle, tattooed-registry
  cleanup, admin/UAC detection. **Write model**: like `gpedit.msc`,
  every OK click writes immediately — except inside a GPO project,
  where writes redirect to temp files until "Save now".

### Catalogs\ + Indexers\ (Security / CIS / Advanced Audit system)
- `SecurityCatalog.ps1` — hardcoded catalog of local security settings
  (Password Policy, Account Lockout, Audit Policy, User Rights
  Assignment, Security Options — 71 settings total). Backed by
  `DefaultData\Data_SecurityCatalog.json`, live-editable via catalog
  editor mode (`CatalogEditingEnabled`, pencil buttons in
  `EditDialogs.ps1`).
- `AdvancedAuditCatalog.ps1` — catalog of the 9 categories / 59
  subcategories of Advanced Audit Policy, keyed by Microsoft's stable
  GUIDs.
- `CisCatalog.ps1` — maps app-managed settings (registry key, security
  section/name, or audit subcategory name) to CIS Benchmark
  recommendations loaded from `cis-index.json`. Supports per-entry user
  overrides, OS-based default profile detection via WMI, and
  profile-specific recommended-value lookup.
- `Build-AdmxIndex.ps1` — parses all `.admx`/`.adml` (en-US) under
  `PolicyDefinitions` → `admx-index.json`.
- `Build-SecurityIndex.ps1` — merges `SecurityCatalog.ps1` with live
  `secedit.inf` state → `security-index.json`.
- `Build-AdvancedAuditIndex.ps1` — merges `AdvancedAuditCatalog.ps1`
  with `audit.csv` state → `advanced-audit-index.json`.
- `Build-CisIndex.ps1` — parses the `.audit` files (Tenable/Nessus-format
  CIS Benchmark exports, 24 files under `DefaultData\Audit\`, covering
  Windows 10/11 and Server 2016/2019/2022/2025, various levels/roles)
  into `cis-index.json`, grouped by profile
  (benchmark/version/level/role).
- `PolicyDefinitionsFingerprint.ps1` / `AuditFilesFingerprint.ps1` —
  SHA256 fingerprints (relative path + size + mtime) used purely for
  cache invalidation.

**Cache policy**: the ADMX/Security/CIS indexes are only rebuilt if the
source fingerprint changed (compared against `meta.sourceFingerprint`
stored in the cached JSON). The Security and Advanced Audit indexes are
in practice **always** rebuilt on launch (cheap, small files) so the UI
never shows stale state.

### UI\
- `AllWindows.Reference.xaml` — every window/dialog plus the shared
  style (derived from `Styles\ModernStyle.xaml`) merged into one file,
  loaded by fragment via `XamlReader.Load` (a deliberate consolidation
  that replaced nine separate XAML files).
- `EditDialogs.ps1` — per-setting edit windows (`Show-AdmxEditDialog`,
  `Show-SecurityEditDialog`), shared XAML-loading helpers
  (`Import-XamlWindow`), CIS-tab rendering.
- `OptionsDialog.ps1` — the File > Options window (Path/File/Editor/
  Close tabs).
- `SelectPrincipalsDialog.ps1` — a clone of the Windows "Select Users or
  Groups" picker via `NTAccount.Translate`/`Win32_Account` (the
  `CDsObjectPicker` COM object picker was abandoned — unavailable).
- `AppDialogs.ps1` — column picker, CIS profile picker, Filter dialog,
  About/Patch-note windows, New/unsaved-project dialogs.
- `UiStrings.ps1` — a flat hashtable of all UI label strings
  (English only).

### AppSettings.ps1 / AppLog.ps1
- `AppSettings.ps1` — persists 6 configurable paths plus the
  `editorMode` boolean to
  `%LocalAppData%\Gpeditor_plus\settings.json`.
  `Initialize-AppSettingsFirstRun` creates default folders and seeds
  `auditFilesDir` from the bundled `.audit` files on first run.
- `AppLog.ps1` — a single continuously-appended log file
  (`gpedit.log`) recording every setting change (parameter name,
  key/path, old/new value) and every project create/import/export.

### Tests\
Six hand-rolled scripts, no Pester (`Assert-Equal`/`Assert-True`/
`Assert-NotNull` helpers, `$script:TestCount`/`$script:FailCount`
counters), covering: exact binary round-trip of `PolFile`,
`GptTmplFile`, `AuditCsvFile`, `PolicyWriter` (merge + backup + GPT.ini
bump), `CisCatalog`/CIS parsing, `AppSettings`. All operate on temp
files, never on the real machine.

## 4. Repo state

Git repo rooted at `Gpeditor_plus\Gpeditor_plus`, branch `main`, clean
tree. Very short history (4 commits: `Initial commit`, `Init`,
`FilterMenu_and_BugFix`, `fix_filter_menu`) — the richer development
history lives in `CHANGELOG.md` (dated entries, e.g. 2026-07-23: added
66 missing Security Options settings, fixed the Windows Settings /
Security Settings tree split) and in code comments, not in the git log.

No TODO/FIXME/stub markers found anywhere in the code (repo-wide grep
across all `.ps1`/`.xaml` files) — the codebase appears to be in a
deliberately "finished" state, with no known pending feature.
