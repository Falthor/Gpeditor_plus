# Changelog

Format inspired by [Keep a Changelog](https://keepachangelog.com/): one
section per release date, most recent first. This file is the single
source for the "Release Notes" panel in the right-hand pane and for
? > Patch note

## 2026-07-23 — Security options completed, tree structure fixed

- Added 66 missing settings under Local Policies > Security Options
  (Accounts, Audit, Devices, Domain Controller/Domain Member,
  Interactive Logon, Microsoft Network Client/Server, Network Access,
  Network Security, System Shutdown, System Objects, User Account
  Control): 71 settings in total, up from 5 previously.
- Fix: "Windows Settings" and "Security Settings" are now two separate
  folders in the tree, as in the standard gpedit.msc console, instead
  of a single node with a combined label.
