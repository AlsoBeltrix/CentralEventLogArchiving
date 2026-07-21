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
