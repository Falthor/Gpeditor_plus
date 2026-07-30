# Changelog

Format inspired by [Keep a Changelog](https://keepachangelog.com/): one
section per release date, most recent first. This file is the single
source for the "Release Notes" panel in the right-hand pane and for
? > Patch note

## 2026-07-30 — Integrity check on Export/Import and pre-import backups

- Added View > "CIS - Missing ADMX templates": for the active CIS profile,
  lists controls this app cannot resolve to any real Administrative
  Templates policy/Security setting/Advanced Audit subcategory, but for
  which the source CIS benchmark names a required `.admx`/`.adml`
  template — distinguishing a template bundled with Windows from a
  certain version onward, one requiring a manual download from Microsoft
  (e.g. `SecGuide.admx`, `MSS-legacy.admx`), or a third-party template —
  and whether that file is already present on this machine. Settings with
  no ADMX mechanism at all (Windows Services, firewall profiles...) are
  not listed, since adding a template can never help them.
- Fix: a CIS control whose recommended value is an explicitly empty list
  (a User Right set to "No One", e.g. "Act as part of the operating
  system"; a registry multi-string list set to "None", e.g. "Network
  access: Named Pipes/Shares that can be accessed anonymously") no longer
  shows CIS = No and no longer disappears when filtering by CIS profile.
  These settings' recommended value legitimately IS "empty" - Windows'
  own default is not necessarily empty either, so the setting still needs
  enforcing. "New Group Policy > CIS Gap-fill/Full compliance" now writes
  the empty list for these instead of silently skipping them.
- Export and the automatic pre-import backup now record a SHA-256 hash of
  each file (`Machine\registry.pol`, `User\registry.pol`, `secedit.inf`,
  `Machine\Microsoft\Windows NT\Audit\audit.csv`) in their `*_Info.xml`
  manifest. File > Import re-checks these hashes before applying anything
  real, and blocks with a clear error if a file was modified, deleted, or
  added outside GPedit since it was generated - manifests created before
  this change are unaffected and still import normally. The automatic
  rollback that follows a failed import now goes through this same check
  before replaying the backup.

## 2026-07-29 — Readable logs, project Close, Options fixes, Import bug fix

- The app log (`gpedit.log`) is now one field per line (Name/Registry/Old
  value/New value) instead of one long pipe-separated line, and setting
  changes are labeled ADDED/CHANGED/REMOVED. Project save/export/import
  now also log their on-disk location, and "Save now" is logged too.
- Added File > Close: leaves the active GPO project (prompting to save
  first if there are unsaved changes) and switches editing back to the
  real machine, re-enabling New/Open so another project can be started
  without relaunching the app.
- Fix: the "Projects" path row in File > Options had no effect - the
  field stayed empty and "..." did nothing, since the row was missing
  from the code wiring the Path tab. File > Save/Open now also default
  to that configured Projects folder.
- Fix: exporting a saved GPO project whose folder was missing a file for
  a never-configured category (e.g. no User-scope policy ever set) made
  the export unreadable by File > Import ("This is not a valid GPedit
  project."), even though the export itself was legitimate. Import now
  treats a missing registry.pol/secedit.inf/audit.csv the same way the
  rest of the app already does elsewhere: as "nothing configured", not
  an error.

## 2026-07-23 — Security options completed, tree structure fixed

- Added 66 missing settings under Local Policies > Security Options
  (Accounts, Audit, Devices, Domain Controller/Domain Member,
  Interactive Logon, Microsoft Network Client/Server, Network Access,
  Network Security, System Shutdown, System Objects, User Account
  Control): 71 settings in total, up from 5 previously.
- Fix: "Windows Settings" and "Security Settings" are now two separate
  folders in the tree, as in the standard gpedit.msc console, instead
  of a single node with a combined label.
