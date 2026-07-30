# GPeditor Plus

Alternative local Group Policy editor for Windows, written in PowerShell +
WPF. It reproduces the functions of `gpedit.msc` / `secpol.msc`
(Administrative Templates, Security Settings, Advanced Audit Policy) in a
single interface, plus a few features missing from the standard console:
cross-category search, inline CIS Benchmark recommendations, off-machine GPO
projects, built-in release notes.

> Requires administrator rights (read/write access to registry.pol,
> `GptTmpl.inf`, `secedit`). The app refuses to start if the process is not
> elevated.

> Built with the help of [Claude Code](https://claude.com/claude-code).

## Features

- **Administrative Templates (ADMX/ADML)**: Computer/User tree built from
  `%WinDir%\PolicyDefinitions`, resolved in the requested language with a
  clean fallback if the ADML file is missing. Current state is read directly
  from `registry.pol`.
- **Security Settings**: Account Policies (password, lockout), Local
  Policies (classic audit, user rights assignment, security options — 71
  settings covered), via `GptTmpl.inf` + `secedit /import` +
  `/configure` cycle.
- **Advanced Audit Policy**: dedicated catalog, `audit.csv` backing store.
- **Cross-category search**: a search queries all three catalogs (ADMX,
  Security, Advanced Audit) at once and shows multi-category results in the
  same grid as the tree view.
- **CIS Benchmark recommendations**: a "CIS recommendation" tab in a
  setting's properties window shows the matching recommendation(s) (Windows
  10/11, Server 2016/2019/2022/2025, L1/L2 × Member Server/Domain Controller
  profiles), plus a "CIS" column and an active-profile filter in the main
  grid.
- **"Explain" tab**: official Microsoft documentation shown in the Security
  Settings properties windows, like the real console.
- **Live catalog editor**: lets you fix a security setting's name /
  explanation text / CIS info directly from the UI (`Editor Mode`,
  toggleable in Options).
- **Off-machine GPO projects** (Advanced menu): create/open a set of
  `.pol`/`.csv`/`.cfg` files outside the real system, edited in memory then
  exported (`Save` / `Save now`) — lets you prepare a policy without
  touching the local machine until it's pushed.
- **Horizontal menu**: File (Import/Export/Options/Exit), View (customizable
  columns, active CIS profile, language), `?` (About / Patch notes /
  Benchmark).
- **Built-in release notes**: the right pane shows the latest
  `CHANGELOG.md` entries while no category or search is active.
- **Persistent logging** under `%LocalAppData%\Gpeditor_plus` /
  `C:\Windows\Logs\Gpeditor_plus`: `gpedit.log` records every setting change
  and GPO project action, `Gpeditor_Error.log` records every unhandled
  script error (message, category, source line, call stack).

## Requirements

- Windows 10/11 or Windows Server (2016+), with `gpedit.msc` available
  (Pro/Enterprise/Server editions — not present on Home editions).
- PowerShell 5.1 or PowerShell 7+ (Windows PowerShell / `pwsh`), WPF
  assemblies (`PresentationFramework`, `PresentationCore`, `WindowsBase`,
  `System.Xaml`, `System.Windows.Forms` — bundled with Windows).
- An administrator session.

## Running the app

From an **elevated** PowerShell prompt:

```powershell
cd gpeditor_plus\src
.\GpEdit.ps1
```

On first launch, the app automatically creates its working folders
(`%LocalAppData%\Gpeditor_plus`, `C:\ProgramData\Gpeditor_plus\...`) and
populates the CIS audit files folder from `src\DefaultData\Audit\*.audit`.

## Architecture

```
src/
├── GpEdit.ps1              # Entry point: WPF window, orchestration
├── Core/                    # App infrastructure (settings, logging, import)
│   ├── AppSettings.ps1         # Configurable paths + Editor Mode (settings.json)
│   ├── AppLog.ps1              # Activity log (gpedit.log) + error log (Gpeditor_Error.log)
│   └── ImportGpoProjectFiles.ps1
├── Catalogs/                # Per-domain setting definitions
│   ├── SecurityCatalog.ps1     # Account/Local Policies, Security Options
│   ├── AdvancedAuditCatalog.ps1
│   └── CisCatalog.ps1          # CIS recommendations by (benchmark, profile)
├── Parsers/                  # Raw format read/write
│   ├── PolFile.ps1             # registry.pol (PReg format)
│   ├── GptIniFile.ps1
│   ├── GptTmplFile.ps1         # GptTmpl.inf (secedit)
│   ├── AuditCsvFile.ps1
│   └── ChangelogFile.ps1
├── Indexers/                 # Builds JSON indexes (data/*.json)
│   ├── Build-Index.ps1                   # -Kind Admx|Security|AdvancedAudit|Cis
│   ├── PolicyDefinitionsFingerprint.ps1  # ADMX freshness detection
│   └── AuditFilesFingerprint.ps1         # CIS audit freshness detection
├── Policy/                   # Current-state read / change write
│   ├── PolicyState.ps1
│   ├── PolicyWriter.ps1
│   └── ChangeApplier.ps1
├── UI/                        # WPF windows and styles
│   ├── AppDialogs.ps1
│   ├── EditDialogs.ps1
│   ├── OptionsDialog.ps1
│   ├── SelectPrincipalsDialog.ps1
│   ├── UiStrings.ps1           # EN strings
│   └── Styles/ModernStyle.xaml
├── DefaultData/               # Bundled templates and CIS audit files
└── Tests/                     # Pester regression suite (Gpeditor_plus.Tests.ps1)

data/                          # Generated JSON indexes (cache, rebuilt as needed)
```

**General flow**: catalogs (`Catalogs/`) describe the available settings;
indexers build/refresh a JSON cache in `data/` from source data (system
ADMX/ADML, CIS `.audit` files) based on a freshness fingerprint computed on
every launch; current state is read via `Policy/PolicyState.ps1` from the
raw files (`registry.pol`, `GptTmpl.inf`, `audit.csv`) parsed by `Parsers/`;
changes go through `Policy/PolicyWriter.ps1` then `ChangeApplier.ps1`, which
triggers the real reconciliation (`secedit /import` + `/configure`, or
waiting for a `gpupdate`) depending on the domain touched.

## Tests

`src/Tests/Gpeditor_plus.Tests.ps1` is a [Pester](https://pester.dev) suite
covering the parsers, the policy merge/write engine, app settings
persistence and the CIS catalog. All file I/O runs under Pester's
`$TestDrive`, so nothing touches real system paths.

```powershell
Install-Module Pester -MinimumVersion 6.0 -Scope CurrentUser  # if not already installed
cd gpedit_custom\src\Tests
Invoke-Pester .\Gpeditor_plus.Tests.ps1
```

Tests are tagged by kind (`Unit`, `RoundTrip`, `Regression`, `Catalog`,
`Integration` - see the legend at the top of the file); filter with:

```powershell
Invoke-Pester .\Gpeditor_plus.Tests.ps1 -TagFilter Regression
```

## Design documents

Every notable feature has its own plan/decision log at the repo root
(`plan-gpedit-overview.md`), kept up to date as it's implemented: cross-category
search, CIS recommendations, GPO projects, security options, Explain tab,
catalog editor, secedit cycle, UI enhancements, script consolidation.

`CHANGELOG.md` is the single source for the app's "release notes" panel and
for the `? > Patch note` window — every notable change must be logged there.

## User configuration

| Item | Location |
|---|---|
| `settings.json` (paths, Editor Mode) | `%LocalAppData%\Gpeditor_plus\settings.json` |
| Activity log | `C:\Windows\Logs\Gpeditor_plus\gpedit.log` |
| Error log | `C:\Windows\Logs\Gpeditor_plus\Gpeditor_Error.log` |
| Backups | `C:\ProgramData\Gpeditor_plus\Backup\` |
| Import/Export | `C:\ProgramData\Gpeditor_plus\export\` |
| CIS audit files | `C:\ProgramData\Gpeditor_plus\audit\` |
| JSON indexes | `%LocalAppData%\Gpeditor_plus\Index\` |

## Warning

This tool reads and writes directly to the local Group Policy backing
stores (`registry.pol`, `GptTmpl.inf`, `secedit.sdb` via `secedit`). Use it
knowingly, ideally on a test machine first — an off-machine GPO project
(Advanced menu) lets you prepare and verify changes before pushing them to
the real system.
