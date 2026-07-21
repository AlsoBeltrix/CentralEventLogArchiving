BeforeAll {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $scriptPath = Join-Path $repoRoot 'NewEventLogArchiving.ps1'
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )

    if ($parseErrors.Count -gt 0) {
        throw "Unable to load functions from '$scriptPath': $($parseErrors -join '; ')"
    }

    foreach ($statement in $scriptAst.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            Invoke-Expression $statement.Extent.Text
        }
    }
}

Describe 'configuration data-file compatibility' {
    BeforeEach {
        Mock Get-Command { $null } -ParameterFilter {
            $Name -eq 'Import-PowerShellDataFile'
        }
    }

    It 'loads safe nested configuration when Import-PowerShellDataFile is unavailable' {
        $configPath = Join-Path $TestDrive 'fallback.psd1'
        @'
@{
    RetentionDays = 14
    Paths = @{
        EventLogArchiveRoot = 'D:\Archive'
    }
    Cleanup = @{
        SkipSecurityLogCheck = $true
    }
    OptionalValue = $null
}
'@ | Set-Content -LiteralPath $configPath

        $configuration = Import-EventLogArchiveDataFile -LiteralPath $configPath

        $configuration | Should -BeOfType ([hashtable])
        $configuration.RetentionDays | Should -Be 14
        $configuration.Paths.EventLogArchiveRoot | Should -Be 'D:\Archive'
        $configuration.Cleanup.SkipSecurityLogCheck | Should -BeTrue
        $configuration.OptionalValue | Should -BeNullOrEmpty
    }

    It 'rejects executable expressions in the parser fallback' {
        $configPath = Join-Path $TestDrive 'executable.psd1'
        @'
@{
    RetentionDays = $(Get-Date)
}
'@ | Set-Content -LiteralPath $configPath

        {
            Import-EventLogArchiveDataFile -LiteralPath $configPath
        } | Should -Throw '*safe constant data*'
    }
}

Describe 'cleanup target safety' {
    It 'rejects relative and drive-relative paths' {
        foreach ($path in @('.', '..', 'D:relative')) {
            Test-CleanupPathSafety -Path $path -ItemType 'test cleanup' | Should -BeFalse
        }
    }

    It 'returns a canonical absolute filesystem path for an accepted target' {
        $resolvedPath = $null

        Test-CleanupPathSafety -Path $TestDrive -ItemType 'test cleanup' -ResolvedPath ([ref]$resolvedPath) |
            Should -BeTrue
        $resolvedPath | Should -Be ([System.IO.Path]::GetFullPath($TestDrive))
    }

    It 'does not remove eligible files when WhatIf is requested' {
        $cleanupRoot = Join-Path $TestDrive 'cleanup'
        $oldFile = Join-Path $cleanupRoot 'old.txt'
        New-Item -Path $cleanupRoot -ItemType Directory | Out-Null
        Set-Content -LiteralPath $oldFile -Value 'retain me'

        $results = @(Remove-OldFiles `
            -Path $cleanupRoot `
            -OlderThan (Get-Date).AddDays(1) `
            -RetentionDays 1 `
            -ItemType 'test cleanup' `
            -Patterns @('*') `
            -WhatIf)

        Test-Path -LiteralPath $oldFile -PathType Leaf | Should -BeTrue
        $metric = $results | Where-Object { $_.PSObject.Properties['ItemType'] } | Select-Object -Last 1
        $metric.Succeeded | Should -Be 0
        $metric.Failed | Should -Be 0
    }
}

Describe 'collision-safe archive writes' {
    It 'selects the first unused sibling path without changing existing files' {
        $desiredPath = Join-Path $TestDrive 'Archive-Security.evtx'
        $firstSibling = Join-Path $TestDrive 'Archive-Security.1.evtx'
        Set-Content -LiteralPath $desiredPath -Value 'original'
        Set-Content -LiteralPath $firstSibling -Value 'first sibling'

        $availablePath = Get-AvailableArchivePath -DesiredPath $desiredPath

        $availablePath | Should -Be (Join-Path $TestDrive 'Archive-Security.2.evtx')
        (Get-Content -LiteralPath $desiredPath -Raw).Trim() | Should -Be 'original'
        (Get-Content -LiteralPath $firstSibling -Raw).Trim() | Should -Be 'first sibling'
    }

    It 'preserves both files when an archived event-log destination already exists' {
        $sourceDirectory = Join-Path $TestDrive 'source'
        $destinationDirectory = Join-Path $TestDrive 'destination'
        New-Item -Path $sourceDirectory -ItemType Directory | Out-Null
        New-Item -Path $destinationDirectory -ItemType Directory | Out-Null
        $fileName = 'Archive-Security-20260721.evtx'
        $sourcePath = Join-Path $sourceDirectory $fileName
        $existingDestination = Join-Path $destinationDirectory $fileName
        Set-Content -LiteralPath $sourcePath -Value 'new archive'
        Set-Content -LiteralPath $existingDestination -Value 'existing archive'
        Mock Resolve-EventLogDirectory { $sourceDirectory }

        Move-ArchivedEventLogs `
            -LogName 'Security' `
            -DestinationPath $destinationDirectory `
            -OlderThan (Get-Date).AddDays(-1) |
            Out-Null

        Test-Path -LiteralPath $sourcePath -PathType Leaf | Should -BeFalse
        (Get-Content -LiteralPath $existingDestination -Raw).Trim() | Should -Be 'existing archive'
        (Get-Content -LiteralPath (Join-Path $destinationDirectory 'Archive-Security-20260721.1.evtx') -Raw).Trim() |
            Should -Be 'new archive'
    }

    It 'publishes a verified sibling ZIP before removing an EVTX source' {
        $sourcePath = Join-Path $TestDrive 'Archive-System-20260721.evtx'
        $existingZipPath = Join-Path $TestDrive 'Archive-System-20260721.zip'
        Set-Content -LiteralPath $sourcePath -Value 'event log payload'
        Set-Content -LiteralPath $existingZipPath -Value 'existing archive must remain unchanged'

        $result = Compress-ArchivedEventLog -File (Get-Item -LiteralPath $sourcePath)

        $result.Succeeded | Should -Be 1
        $result.Failed | Should -Be 0
        Test-Path -LiteralPath $sourcePath -PathType Leaf | Should -BeFalse
        (Get-Content -LiteralPath $existingZipPath -Raw).Trim() | Should -Be 'existing archive must remain unchanged'
        $publishedZipPath = Join-Path $TestDrive 'Archive-System-20260721.1.zip'
        Test-Path -LiteralPath $publishedZipPath -PathType Leaf | Should -BeTrue

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($publishedZipPath)
        try {
            $entry = $archive.Entries | Where-Object { $_.FullName -eq 'Archive-System-20260721.evtx' }
            $entry | Should -Not -BeNullOrEmpty
        }
        finally {
            $archive.Dispose()
        }
    }

    It 'keeps the source when ZIP verification fails' {
        $failureRoot = Join-Path $TestDrive 'verification-failure'
        New-Item -Path $failureRoot -ItemType Directory | Out-Null
        $sourcePath = Join-Path $failureRoot 'Archive-Application-20260721.evtx'
        Set-Content -LiteralPath $sourcePath -Value 'event log payload'
        Mock Test-ArchiveZipEntry { throw 'simulated verification failure' }

        $result = Compress-ArchivedEventLog -File (Get-Item -LiteralPath $sourcePath)

        $result.Succeeded | Should -Be 0
        $result.Failed | Should -Be 1
        Test-Path -LiteralPath $sourcePath -PathType Leaf | Should -BeTrue
        @(Get-ChildItem -LiteralPath $failureRoot -Filter '*.zip').Count | Should -Be 0
    }
}

Describe 'access and enumeration failure reporting' {
    It 'reports an inaccessible cleanup path as a failure instead of missing' {
        Mock Test-Path { throw 'simulated access denied' }

        $results = @(Remove-OldFiles `
            -Path (Join-Path $TestDrive 'restricted') `
            -OlderThan (Get-Date) `
            -RetentionDays 1 `
            -ItemType 'test cleanup')

        $metric = $results | Where-Object { $_.PSObject.Properties['ItemType'] } | Select-Object -Last 1
        $metric.Failed | Should -Be 1
        @($metric.FailureDetails)[0] | Should -Match 'access denied'
    }

    It 'reports cleanup enumeration errors in the operation metric' {
        $cleanupRoot = Join-Path $TestDrive 'enumeration-error'
        New-Item -Path $cleanupRoot -ItemType Directory | Out-Null
        Mock Get-ChildItem { Write-Error 'simulated enumeration failure' }

        $results = @(Remove-OldFiles `
            -Path $cleanupRoot `
            -OlderThan (Get-Date) `
            -RetentionDays 1 `
            -ItemType 'test cleanup')

        $metric = $results | Where-Object { $_.PSObject.Properties['ItemType'] } | Select-Object -Last 1
        $metric.Failed | Should -Be 1
        @($metric.FailureDetails)[0] | Should -Match 'enumeration failure'
    }

    It 'returns an archive-discovery failure metric when source enumeration fails' {
        $sourceDirectory = Join-Path $TestDrive 'archive-enumeration-error'
        New-Item -Path $sourceDirectory -ItemType Directory | Out-Null
        Mock Resolve-EventLogDirectory { $sourceDirectory }
        Mock Get-ChildItem { Write-Error 'simulated archive enumeration failure' }

        $results = @(Move-ArchivedEventLogs `
            -LogName 'Security' `
            -DestinationPath $TestDrive `
            -OlderThan (Get-Date))

        $metric = $results |
            Where-Object { $_.PSObject.Properties['ItemType'] -and $_.ItemType -eq 'Security archive discovery' } |
            Select-Object -Last 1
        $metric.Failed | Should -Be 1
        @($metric.FailureDetails)[0] | Should -Match 'archive enumeration failure'
    }
}

Describe 'complete archived event-log discovery' {
    It 'discovers and deduplicates configured event-log directories' {
        $firstDirectory = Join-Path $TestDrive 'configured-log-one'
        $secondDirectory = Join-Path $TestDrive 'configured-log-two'
        New-Item -Path $firstDirectory -ItemType Directory | Out-Null
        New-Item -Path $secondDirectory -ItemType Directory | Out-Null
        Mock Get-WinEvent {
            @(
                [pscustomobject]@{ LogFilePath = (Join-Path $firstDirectory 'one.evtx') }
                [pscustomobject]@{ LogFilePath = (Join-Path $firstDirectory 'duplicate.evtx') }
                [pscustomobject]@{ LogFilePath = (Join-Path $secondDirectory 'two.evtx') }
            )
        }

        $result = Get-EventLogArchiveDirectories

        @($result.Directories | Where-Object { $_ -eq $firstDirectory }).Count | Should -Be 1
        @($result.Directories | Where-Object { $_ -eq $secondDirectory }).Count | Should -Be 1
        @($result.Errors).Count | Should -Be 0
    }

    It 'moves other archived logs from every discovered directory' {
        $firstDirectory = Join-Path $TestDrive 'other-log-one'
        $secondDirectory = Join-Path $TestDrive 'other-log-two'
        $destinationDirectory = Join-Path $TestDrive 'other-log-destination'
        New-Item -Path $firstDirectory -ItemType Directory | Out-Null
        New-Item -Path $secondDirectory -ItemType Directory | Out-Null
        New-Item -Path $destinationDirectory -ItemType Directory | Out-Null
        $firstSource = Join-Path $firstDirectory 'Archive-CustomOne-20260721.evtx'
        $secondSource = Join-Path $secondDirectory 'Archive-CustomTwo-20260721.evtx'
        Set-Content -LiteralPath $firstSource -Value 'one'
        Set-Content -LiteralPath $secondSource -Value 'two'
        Mock Get-EventLogArchiveDirectories {
            [pscustomobject]@{
                Directories = @($firstDirectory, $secondDirectory, $firstDirectory)
                Errors = @()
            }
        }

        Move-OtherArchivedEventLogs `
            -DestinationPath $destinationDirectory `
            -OlderThan (Get-Date).AddDays(-1) |
            Out-Null

        Test-Path -LiteralPath $firstSource -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath $secondSource -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $destinationDirectory 'Archive-CustomOne-20260721.evtx') -PathType Leaf |
            Should -BeTrue
        Test-Path -LiteralPath (Join-Path $destinationDirectory 'Archive-CustomTwo-20260721.evtx') -PathType Leaf |
            Should -BeTrue
    }

    It 'does not classify a similarly prefixed log as a primary log' {
        $sourceDirectory = Join-Path $TestDrive 'prefix-source'
        $destinationDirectory = Join-Path $TestDrive 'prefix-destination'
        New-Item -Path $sourceDirectory -ItemType Directory | Out-Null
        New-Item -Path $destinationDirectory -ItemType Directory | Out-Null
        $systemSource = Join-Path $sourceDirectory 'Archive-System-20260721.evtx'
        $similarSource = Join-Path $sourceDirectory 'Archive-SystemRestore-20260721.evtx'
        Set-Content -LiteralPath $systemSource -Value 'system'
        Set-Content -LiteralPath $similarSource -Value 'system restore'
        Mock Resolve-EventLogDirectory { $sourceDirectory }

        Move-ArchivedEventLogs `
            -LogName 'System' `
            -DestinationPath $destinationDirectory `
            -OlderThan (Get-Date).AddDays(-1) |
            Out-Null

        Test-Path -LiteralPath $systemSource -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath $similarSource -PathType Leaf | Should -BeTrue
    }
}

Describe 'durable remote run reports' {
    It 'uses a timestamped collision-free path set for each run' {
        $runTime = [datetime]'2026-07-21T14:15:16.123'
        $baseToken = '20260721_141516_123'
        Set-Content -LiteralPath (Join-Path $TestDrive "EvtLogArchRemoteTranscript_$baseToken.txt") -Value 'existing'

        $paths = Get-RemoteArchiveRunPathSet -LogDirectory $TestDrive -RunTime $runTime

        [System.IO.Path]::GetFileName($paths.TranscriptPath) |
            Should -Be "EvtLogArchRemoteTranscript_$baseToken.1.txt"
        [System.IO.Path]::GetFileName($paths.ResultPath) |
            Should -Be "EvtLogArchRemote_$baseToken.1.txt"
        [System.IO.Path]::GetFileName($paths.AttachmentPath) |
            Should -Be "EvtLogArchRemote_$baseToken.1.zip"
    }

    It 'creates and verifies a durable report package without removing text logs' {
        $transcriptPath = Join-Path $TestDrive 'transcript.txt'
        $resultPath = Join-Path $TestDrive 'result.txt'
        $attachmentPath = Join-Path $TestDrive 'report.zip'
        Set-Content -LiteralPath $transcriptPath -Value 'transcript'
        Set-Content -LiteralPath $resultPath -Value 'result'

        $package = New-RemoteArchiveReportPackage `
            -TextLogPaths @($transcriptPath, $resultPath) `
            -AttachmentPath $attachmentPath

        $package.Succeeded | Should -BeTrue
        Test-Path -LiteralPath $package.AttachmentPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $transcriptPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $resultPath -PathType Leaf | Should -BeTrue
    }

    It 'packages a successful report even when summary mail is disabled' {
        $reportRoot = Join-Path $TestDrive 'mail-disabled'
        New-Item -Path $reportRoot -ItemType Directory | Out-Null
        $transcriptPath = Join-Path $reportRoot 'transcript.txt'
        $resultPath = Join-Path $reportRoot 'result.txt'
        $attachmentPath = Join-Path $reportRoot 'report.zip'
        Set-Content -LiteralPath $transcriptPath -Value 'transcript'
        Set-Content -LiteralPath $resultPath -Value 'result'

        $publishResult = Publish-RemoteArchiveReport `
            -RunDate '20260721' `
            -Controller 'controller' `
            -TranscriptPath $transcriptPath `
            -ResultPath $resultPath `
            -AttachmentPath $attachmentPath

        $publishResult.PackageSucceeded | Should -BeTrue
        Test-Path -LiteralPath $publishResult.AttachmentPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $transcriptPath -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath $resultPath -PathType Leaf | Should -BeFalse
    }

    It 'retains text logs when report packaging fails' {
        $reportRoot = Join-Path $TestDrive 'package-failure'
        New-Item -Path $reportRoot -ItemType Directory | Out-Null
        $transcriptPath = Join-Path $reportRoot 'transcript.txt'
        $resultPath = Join-Path $reportRoot 'result.txt'
        Set-Content -LiteralPath $transcriptPath -Value 'transcript'
        Set-Content -LiteralPath $resultPath -Value 'result'
        Mock New-RemoteArchiveReportPackage {
            [pscustomobject]@{
                Succeeded = $false
                AttachmentPath = $null
                FailureMessage = 'simulated packaging failure'
            }
        }

        $publishResult = Publish-RemoteArchiveReport `
            -RunDate '20260721' `
            -Controller 'controller' `
            -TranscriptPath $transcriptPath `
            -ResultPath $resultPath `
            -AttachmentPath (Join-Path $reportRoot 'report.zip')

        $publishResult.PackageSucceeded | Should -BeFalse
        Test-Path -LiteralPath $transcriptPath -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $resultPath -PathType Leaf | Should -BeTrue
    }
}
