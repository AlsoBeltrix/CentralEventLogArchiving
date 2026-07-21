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
