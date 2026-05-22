@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "%~dp0NewEventLogArchiving.ps1" -Remote -SkipRemoteIntegrityCheck
