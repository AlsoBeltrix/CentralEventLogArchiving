BeforeAll {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $scriptPath = Join-Path $repoRoot 'CheckLastSecLog.ps1'
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

Describe 'standalone domain-controller security checks' {
    BeforeEach {
        $script:childJob = [pscustomobject]@{
            Location = 'dc1.example.test'
            State = 'Completed'
            JobStateInfo = [pscustomobject]@{ Reason = $null }
        }
        $script:parentJob = [pscustomobject]@{
            ChildJobs = @($script:childJob)
        }

        Mock Invoke-Command { $script:parentJob }
        Mock Wait-Job { $script:parentJob } -RemoveParameterType Job
        Mock Receive-Job { 'remote result' } -RemoveParameterType Job
        Mock Stop-Job {} -RemoveParameterType Job
        Mock Remove-Job {} -RemoveParameterType Job
        Mock Send-MailMessage {}
    }

    It 'alerts, fails, and cleans up when a target does not finish before timeout' {
        $script:childJob.State = 'Running'

        {
            Invoke-DomainControllerSecurityLogCheck `
                -ComputerName @('dc1.example.test') `
                -TimeoutSeconds 60 `
                -AlertTo @('alerts@example.test') `
                -MailFrom 'sender@example.test' `
                -SmtpServer 'smtp.example.test'
        } | Should -Throw '*did not complete*'

        Should -Invoke Send-MailMessage -Times 1 -Exactly
        Should -Invoke Stop-Job -ParameterFilter { $Job -eq $script:parentJob }
        Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter { $Job -eq $script:parentJob }
    }

    It 'alerts and fails when a completed remote job returns an error record' {
        Mock Receive-Job { Write-Error 'simulated remote check failure' } -RemoveParameterType Job

        {
            Invoke-DomainControllerSecurityLogCheck `
                -ComputerName @('dc1.example.test') `
                -TimeoutSeconds 60 `
                -AlertTo @('alerts@example.test') `
                -MailFrom 'sender@example.test' `
                -SmtpServer 'smtp.example.test'
        } | Should -Throw '*remote check failure*'

        Should -Invoke Send-MailMessage -Times 1 -Exactly
        Should -Invoke Remove-Job -Times 1 -Exactly
    }

    It 'returns results without alerting when every target completes cleanly' {
        $results = @(Invoke-DomainControllerSecurityLogCheck `
            -ComputerName @('dc1.example.test') `
            -TimeoutSeconds 60 `
            -AlertTo @('alerts@example.test') `
            -MailFrom 'sender@example.test' `
            -SmtpServer 'smtp.example.test')

        $results | Should -Contain 'remote result'
        Should -Invoke Send-MailMessage -Times 0 -Exactly
        Should -Invoke Remove-Job -Times 1 -Exactly
    }
}
