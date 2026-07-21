# Event Log Archive Hardening Plan

Status: Approved for implementation on 2026-07-21. Fix all six scoped review findings.

## Goal

Harden the PowerShell event-log archive workflows against unsafe cleanup targets, archive collisions, hidden access failures, incomplete event-log discovery, lost run reports, and unreported domain-controller check failures.

## Compatibility and constraints

- Preserve Windows PowerShell 5.1 compatibility because `EventLogArchiving.cmd` invokes that runtime.
- Preserve configuration and command-line precedence.
- Preserve existing retention boundaries and remote/local mode behavior except where this plan explicitly changes failure reporting or artifact retention.
- Keep each review finding in its own commit.
- Do not push as part of implementation.
- Add Pester coverage for each behavior. Prove each new test red before its production fix and green afterward.

## Slice 1: cleanup target safety

Files: `NewEventLogArchiving.ps1`, `tests/NewEventLogArchiving.Tests.ps1`

- Reject relative, drive-relative, provider-qualified non-filesystem, drive-root, share-root, and Windows-root cleanup targets.
- Resolve accepted filesystem paths to canonical absolute paths before destructive enumeration.
- Add script-level `SupportsShouldProcess` behavior and ensure archive moves, compression, and cleanup can be previewed without changing archive data.
- Cover `.` and `..`, rooted safe paths, roots, and `WhatIf` behavior.

## Slice 2: collision-safe archive writes

Files: `NewEventLogArchiving.ps1`, `tests/NewEventLogArchiving.Tests.ps1`

- Never overwrite an existing EVTX or ZIP archive.
- Generate a deterministic available sibling path when a destination name already exists.
- Compress to a temporary file, verify the expected entry can be opened, publish to an unused final path, and only then remove the source EVTX.
- Keep the source and record a failure whenever a safe final archive cannot be established.

## Slice 3: accurate access and enumeration failures

Files: `NewEventLogArchiving.ps1`, `tests/NewEventLogArchiving.Tests.ps1`

- Distinguish a missing path from an inaccessible path.
- Capture enumeration errors from archive discovery, cleanup, and compression.
- Convert access/enumeration errors into operation failure metrics so HTML/text summaries cannot report a false clean run.

## Slice 4: complete archived-event-log discovery

Files: `NewEventLogArchiving.ps1`, `tests/NewEventLogArchiving.Tests.ps1`

- Discover unique event-log storage directories from installed event-log configurations, always retaining the default directory as a fallback.
- Search every discovered directory for other `Archive-*.evtx` files.
- Exclude only exact primary-log archive names and their timestamped `Name-*` variants.
- Deduplicate files before relocation or expiration handling.

## Slice 5: durable remote run reports

Files: `NewEventLogArchiving.ps1`, `tests/NewEventLogArchiving.Tests.ps1`

- Use timestamped remote transcript, result, and attachment names so same-day reruns do not overwrite prior reports.
- Package available text reports independently of mail configuration.
- Remove text reports only after a durable ZIP was created successfully; retain them when packaging fails.
- Keep the ZIP when mail is disabled or sending fails.

## Slice 6: complete standalone security checks

Files: `CheckLastSecLog.ps1`, `tests/CheckLastSecLog.Tests.ps1`

- Inspect every child job after the timeout and identify unfinished or failed targets.
- Capture remote error records and include incomplete targets in a controller-side alert.
- Stop unfinished jobs, remove all jobs in `finally`, and exit unsuccessfully after reporting incomplete coverage.
- Preserve normal per-target stale-log and event-521 alerts.

## Verification

- Run Pester 5.7.1 under Windows PowerShell 5.1 for the test suite.
- Parse both production scripts with the Windows PowerShell 5.1 parser.
- Run PSScriptAnalyzer at Warning and Error severity; classify any remaining warnings.
- Run the non-mutating `NewEventLogArchiving.ps1 -Local $false -SkipConfig` smoke path.
- Confirm the final worktree contains only committed planned changes and remains unpushed.
