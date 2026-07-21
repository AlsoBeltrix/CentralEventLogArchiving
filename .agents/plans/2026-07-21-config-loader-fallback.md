# Configuration Loader Fallback Plan

Status: Completed on 2026-07-21 in code commit `232480b`. The owner approved the recommended safe PSD1 fallback after the elevated launcher could not resolve `Import-PowerShellDataFile`.

## Goal

Allow `EventLogArchiving.cmd` to load its PowerShell data-file configuration when the elevated Windows PowerShell environment cannot discover `Import-PowerShellDataFile`, without evaluating the configuration as executable code.

## Implementation

- Keep `Import-PowerShellDataFile` as the preferred loader when it is available.
- Add a fallback that parses the PSD1 with the Windows PowerShell language parser and obtains only a safe constant value from one top-level expression.
- Reject parse errors, multiple statements, commands, and other executable expressions.
- Route existing configuration loading through the compatible loader without changing configuration precedence or schema validation.
- Add regression coverage for loading the repository's nested hashtable shape with the native cmdlet unavailable and for rejecting an executable expression.

## Verification

- Prove the new regression tests fail before the production change and pass afterward.
- Run Pester 5.7.1 under Windows PowerShell 5.1 for the full test suite.
- Parse both production scripts with the Windows PowerShell 5.1 parser.
- Run PSScriptAnalyzer at Warning and Error severity and classify remaining warnings.
- Run the non-mutating `NewEventLogArchiving.ps1 -Local:$false -SkipConfig` smoke path.
- Commit the plan and the code/test fix separately. Do not push.

Completed verification:

- The two regression tests failed before the production change and passed afterward.
- Pester 5.7.1 under Windows PowerShell 5.1: 22 passed, 0 failed.
- Windows PowerShell 5.1 parser: both production scripts passed.
- PSScriptAnalyzer: 0 errors. The same seven naming/heuristic warnings classified by the archive-hardening plan remain.
- Native configuration loading and the non-mutating startup smoke path passed.
- The elevated launcher was not invoked because it requires an interactive elevation prompt; its missing-cmdlet condition is covered by the fallback regression test.
