function Get-SecurityLogCheckScriptBlock {
    [CmdletBinding()]
    param()

    {
        $mailParams = $null

        "Checking $($env:COMPUTERNAME)"
        $lastSecLog = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        $lastSecLog2 = Get-EventLog -LogName Security -Newest 1 -ErrorAction Stop

        if (($lastSecLog.TimeCreated -lt ((Get-Date).AddMinutes(-30))) -and
            ($lastSecLog2.TimeWritten -lt ((Get-Date).AddMinutes(-30)))) {
            $mailParams = @{
                To = @('iam@analog.com', 'tcs.winadmins@analog.com', 'Infosys-Tech@analog.com')
                Subject = "Check Security Logs on $($env:COMPUTERNAME)"
                Body = "Latest Security Log written more than 30 minutes ago`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)"
                From = 'svc_scriptadm@analog.com'
                SmtpServer = 'mailhost.analog.com'
            }
        }

        if (($lastSecLog.Id -eq 521) -or ($lastSecLog2.InstanceID -eq 521)) {
            $mailParams = @{
                To = @('iam@analog.com', 'tcs.winadmins@analog.com', 'Infosys-Tech@analog.com')
                Subject = "Unable to log events to security log on $($env:COMPUTERNAME)"
                Body = "Unable to log events to security log on $($env:COMPUTERNAME)`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)"
                From = 'svc_scriptadm@analog.com'
                SmtpServer = 'mailhost.analog.com'
            }
        }

        if ($mailParams) {
            Send-MailMessage @mailParams -ErrorAction Stop
        }
    }
}

function Invoke-DomainControllerSecurityLogCheck {
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,

        [string[]]$DiscoveryServer = @('ashbfdc1.winroot.analog.com'),

        [ValidateRange(1, [int]::MaxValue)]
        [int]$ThrottleLimit = 10,

        [ValidateRange(1, [int]::MaxValue)]
        [int]$TimeoutSeconds = 900,

        [Parameter(Mandatory)]
        [string[]]$AlertTo,

        [Parameter(Mandatory)]
        [string]$MailFrom,

        [Parameter(Mandatory)]
        [string]$SmtpServer,

        [scriptblock]$CheckScript
    )

    $jobs = $null

    try {
        if (-not $ComputerName) {
            Import-Module ActiveDirectory -ErrorAction Stop

            $discoveredComputerNames = @(
                Get-ADDomainController -Filter * -ErrorAction Stop |
                    Select-Object -ExpandProperty HostName

                foreach ($server in $DiscoveryServer) {
                    Get-ADDomainController -Filter * -Server $server -ErrorAction Stop |
                        Select-Object -ExpandProperty HostName
                }
            )

            $ComputerName = @(
                $discoveredComputerNames |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
            )
        }

        if (-not $ComputerName) {
            throw 'No domain controllers were discovered for the security log check.'
        }

        if (-not $CheckScript) {
            $CheckScript = Get-SecurityLogCheckScriptBlock
        }

        $jobs = Invoke-Command `
            -AsJob `
            -ScriptBlock $CheckScript `
            -ComputerName $ComputerName `
            -ThrottleLimit $ThrottleLimit `
            -ErrorAction Stop

        Wait-Job -Job $jobs -Timeout $TimeoutSeconds -ErrorAction Stop | Out-Null

        $issues = New-Object 'System.Collections.Generic.List[string]'
        $childJobs = @($jobs.ChildJobs)

        if ($childJobs.Count -eq 0) {
            $issues.Add('The remoting job did not create any target jobs.')
        }

        foreach ($childJob in $childJobs) {
            if ([string]$childJob.State -ne 'Completed') {
                $location = [string]$childJob.Location
                if ([string]::IsNullOrWhiteSpace($location)) {
                    $location = '<unknown target>'
                }

                $issue = "$location [$($childJob.State)] did not complete within $TimeoutSeconds seconds."
                if ($childJob.JobStateInfo.Reason) {
                    $issue += " $($childJob.JobStateInfo.Reason.Message)"
                }

                $issues.Add($issue)
            }
        }

        $receiveErrors = @()
        $results = @(
            Receive-Job `
                -Job $jobs `
                -ErrorAction SilentlyContinue `
                -ErrorVariable +receiveErrors
        )

        foreach ($receiveError in $receiveErrors) {
            $issues.Add([string]$receiveError)
        }

        if ($issues.Count -gt 0) {
            throw "Security log check did not complete successfully: $($issues -join ' | ')"
        }

        $results
    }
    catch {
        $failureMessage = $_.Exception.Message

        try {
            $mailParams = @{
                To = $AlertTo
                Subject = "Security log check incomplete on $($env:COMPUTERNAME)"
                Body = "The domain-controller security log check did not complete successfully.`n`n$failureMessage"
                From = $MailFrom
                SmtpServer = $SmtpServer
            }
            Send-MailMessage @mailParams -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to send the security log check failure alert: $($_.Exception.Message)"
        }

        throw $failureMessage
    }
    finally {
        if ($null -ne $jobs) {
            Stop-Job -Job $jobs -ErrorAction SilentlyContinue
            Remove-Job -Job $jobs -Force -ErrorAction SilentlyContinue
        }
    }
}

$invokeParams = @{
    AlertTo = @('iam@analog.com', 'tcs.winadmins@analog.com', 'Infosys-Tech@analog.com')
    MailFrom = 'svc_scriptadm@analog.com'
    SmtpServer = 'mailhost.analog.com'
}

Invoke-DomainControllerSecurityLogCheck @invokeParams | Select-Object *
