[CmdletBinding()]
param(
    [switch]$Remote,

    [string[]]$ComputerName,

    [ValidateRange(1,365)]
    [int]$RetentionDays = 30,

    [string]$EventLogArchiveRoot,

    [string]$WWWOutputPath = 'E:\WWWOutput',

    [string[]]$WWWOutputFilePatterns = @('*'),

    [string[]]$IisLogFilePatterns = @('*.log'),

    [switch]$SkipSecurityLogCheck,

    [string[]]$SecurityAlertTo = @('iam@analog.com','tcs.winadmins@analog.com'),

    [Alias('MailFrom')]
    [string]$SecurityMailFrom = 'svc_scriptadm@analog.com',

    [string]$SmtpServer = 'mailhost.analog.com',

    [string]$TranscriptDirectory,

    [string]$LogDirectory,

    [ValidateRange(1,100)]
    [int]$ThrottleLimit = 10,

    [ValidateRange(60,86400)]
    [int]$TimeoutSeconds = 39600,

    [string]$ExpectedScriptHash,

    [switch]$SkipRemoteIntegrityCheck,

    [string[]]$AdditionalExchangeServers = @(
        'ashbmbx9.ad.analog.com',
        'ashbmbx8.ad.analog.com',
        'scsqmbx10.ad.analog.com',
        'scsqmbx11.ad.analog.com',
        'ashbmbxtest1.ad.analog.com',
        'ASHBCASHYB4.ad.analog.com',
        'ASHBCASHYB5.ad.analog.com',
        'scsqcashyb7.ad.analog.com',
        'scsqcashyb6.ad.analog.com'
    ),

    [string[]]$SummaryMailTo = @('iam@analog.com','tcs.winadmins@analog.com'),

    [string]$SummaryMailFrom = 'michael.coelho@analog.com'
)

function Test-PathSafely {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet('Any','Container','Leaf')]
        [string]$PathType = 'Any'
    )

    try {
        return Test-Path -LiteralPath $Path -PathType $PathType -ErrorAction Stop
    }
    catch {
        Write-Warning "Skipping inaccessible path '$Path'. Error: $($_.Exception.Message)"
        return $false
    }
}

function New-DirectoryIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-PathSafely -Path $Path -PathType Container)) {
        try {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Failed to create directory '$Path'. Error: $($_.Exception.Message)"
        }
    }
}

function Resolve-EventLogDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $defaultEventLogDirectory = Join-Path $env:SystemRoot 'system32\Winevt\Logs'

    try {
        $eventLogConfiguration = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $LogName
        $logFilePath = [Environment]::ExpandEnvironmentVariables($eventLogConfiguration.LogFilePath)

        if (![string]::IsNullOrWhiteSpace($logFilePath)) {
            $eventLogDirectory = Split-Path -Path $logFilePath -Parent

            if (Test-PathSafely -Path $eventLogDirectory -PathType Container) {
                return $eventLogDirectory
            }

            Write-Warning "$LogName event log directory '$eventLogDirectory' was configured but does not exist. Falling back to '$defaultEventLogDirectory'."
        }
    }
    catch {
        Write-Warning "Unable to read the configured $LogName event log path. Falling back to '$defaultEventLogDirectory'. Error: $($_.Exception.Message)"
    }

    return $defaultEventLogDirectory
}

function Resolve-EventLogArchiveRoot {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan
    )

    $systemDriveArchiveRoot = "$($env:SystemDrive)\Evt_Logs"
    $candidatePaths = @(
        $systemDriveArchiveRoot,
        'E:\Evt_logs'
    ) | Sort-Object -Unique

    $candidateScores = foreach ($candidatePath in $candidatePaths) {
        $exists = Test-PathSafely -Path $candidatePath -PathType Container
        $archiveFiles = @()

        if ($exists) {
            $archiveFiles = Get-ChildItem -LiteralPath $candidatePath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*.zip' -or $_.Name -like '*.evtx' }
        }

        [pscustomobject]@{
            Path = $candidatePath
            Exists = $exists
            InRetentionCount = @($archiveFiles | Where-Object { $_.LastWriteTime -gt $OlderThan }).Count
            TotalCount = @($archiveFiles).Count
            IsDefault = [string]::Equals($candidatePath, $systemDriveArchiveRoot, [System.StringComparison]::OrdinalIgnoreCase)
        }
    }

    $existingCandidates = @($candidateScores | Where-Object { $_.Exists })

    if ($existingCandidates.Count -eq 0) {
        Write-Output "No existing event log archive root found. Using '$systemDriveArchiveRoot'."
        return $systemDriveArchiveRoot
    }

    $selected = $existingCandidates |
        Sort-Object `
            @{ Expression = 'InRetentionCount'; Descending = $true },
            @{ Expression = 'TotalCount'; Descending = $true },
            @{ Expression = 'IsDefault'; Descending = $true } |
        Select-Object -First 1

    Write-Output "Selected event log archive root '$($selected.Path)' (in-retention artifacts: $($selected.InRetentionCount), total artifacts: $($selected.TotalCount))."
    return $selected.Path
}

function Move-ArchivedEventLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan
    )

    $eventLogDirectory = Resolve-EventLogDirectory -LogName $LogName
    Write-Output "Checking $LogName archived event logs in '$eventLogDirectory'."

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -le $OlderThan } |
        ForEach-Object {
            try {
                Write-Output "Removing expired archived $LogName event log '$($_.FullName)'."
                Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to remove expired log '$($_.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $OlderThan } |
        ForEach-Object {
            $destination = Join-Path $DestinationPath $_.Name
            try {
                Move-Item -LiteralPath $_.FullName -Destination $destination -Verbose -ErrorAction Stop
            }
            catch {
                Write-Warning "Move failed for '$($_.FullName)', attempting copy. Error: $($_.Exception.Message)"
                try {
                    Copy-Item -LiteralPath $_.FullName -Destination $destination -Force -ErrorAction Stop
                    Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -ErrorAction Stop
                    Write-Output "Copied and removed '$($_.FullName)' to '$destination'."
                }
                catch {
                    Write-Warning "Copy fallback also failed for '$($_.FullName)'. Error: $($_.Exception.Message)"
                }
            }
        }
}

function Get-IisLogDirectories {
    $directories = @()
    $applicationHostConfigPaths = @(
        (Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'),
        (Join-Path $env:SystemRoot 'Sysnative\inetsrv\config\applicationHost.config')
    )
    $defaultIisLogDirectory = "$($env:SystemDrive)\inetpub\logs\LogFiles"

    foreach ($applicationHostConfig in $applicationHostConfigPaths) {
        if (Test-PathSafely -Path $applicationHostConfig -PathType Leaf) {
            try {
                [xml]$iisConfig = Get-Content -LiteralPath $applicationHostConfig -Raw -ErrorAction Stop
                $directories += $iisConfig.SelectNodes('//logFile[@directory]') | ForEach-Object { $_.GetAttribute('directory') }
            }
            catch {
                Write-Warning "Unable to read IIS log directories from '$applicationHostConfig'. Error: $($_.Exception.Message)"
            }
        }
    }

    $directories += $defaultIisLogDirectory

    $directories |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
        Sort-Object -Unique |
        Where-Object { Test-PathSafely -Path $_ -PathType Container }
}

function Remove-OldFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan,

        [Parameter(Mandatory = $true)]
        [int]$RetentionDays,

        [string[]]$Patterns = @('*')
    )

    if (!(Test-PathSafely -Path $Path -PathType Container)) {
        Write-Output "Skipping missing cleanup path '$Path'."
        return
    }

    Write-Output "Removing files older than $RetentionDays days from '$Path'."

    Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $file = $_
            ($file.LastWriteTime -le $OlderThan) -and
                ($Patterns | Where-Object { $file.Name -like $_ })
        } |
        ForEach-Object {
            try {
                Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to remove old file '$($_.FullName)'. Error: $($_.Exception.Message)"
            }
        }
}

function Test-SecurityLogFreshness {
    param(
        [switch]$SkipCheck,

        [string[]]$AlertTo,

        [string]$MailFrom,

        [string]$MailServer
    )

    if ($SkipCheck) {
        return
    }

    try {
        $lastSecLog = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop

        if ($lastSecLog.Id -eq 521) {
            Send-MailMessage -To $AlertTo -Subject "Unable to log events to security log on $($env:COMPUTERNAME)" -Body "Unable to log events to security log on $($env:COMPUTERNAME)`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($PSCommandPath)" -From $MailFrom -SmtpServer $MailServer
        }

        if ($lastSecLog.TimeCreated -lt ((Get-Date).AddMinutes(-15))) {
            Send-MailMessage -To $AlertTo -Subject "Check Security Logs on $($env:COMPUTERNAME)" -Body "Latest Security Log written more than 15 minutes ago`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($PSCommandPath)" -From $MailFrom -SmtpServer $MailServer
        }
    }
    catch {
        Write-Warning "Unable to check the latest Security event log entry. Error: $($_.Exception.Message)"
    }
}

function Invoke-LocalArchive {
    param(
        [int]$RetentionDays,

        [string]$EventLogArchiveRoot,

        [string]$WWWOutputPath,

        [string[]]$WWWOutputFilePatterns,

        [string[]]$IisLogFilePatterns,

        [switch]$SkipSecurityLogCheck,

        [string[]]$SecurityAlertTo,

        [string]$SecurityMailFrom,

        [string]$SmtpServer,

        [string]$TranscriptDirectory
    )

    $datechk = (Get-Date).AddDays(-$RetentionDays)

    if ([string]::IsNullOrWhiteSpace($EventLogArchiveRoot)) {
        $EventLogArchiveRoot = Resolve-EventLogArchiveRoot -OlderThan $datechk
    }

    if ([string]::IsNullOrWhiteSpace($TranscriptDirectory) -and ![string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $TranscriptDirectory = Join-Path $PSScriptRoot 'logs'
    }

    $securityArchivePath = Join-Path $EventLogArchiveRoot 'Sec_Logs'
    $applicationArchivePath = Join-Path $EventLogArchiveRoot 'App_Logs'
    $systemArchivePath = Join-Path $EventLogArchiveRoot 'Sys_Logs'
    $transcriptStarted = $false

    try {
        if (![string]::IsNullOrWhiteSpace($TranscriptDirectory)) {
            New-DirectoryIfMissing -Path $TranscriptDirectory
            $transcriptPath = Join-Path $TranscriptDirectory "EvtLogArchTranscript_$(Get-Date -Format yyyyMMdd).txt"
            Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
            $transcriptStarted = $true
        }

        Write-Output "Starting local event log archive and cleanup on $($env:COMPUTERNAME)."

        New-DirectoryIfMissing -Path $EventLogArchiveRoot
        New-DirectoryIfMissing -Path $securityArchivePath
        New-DirectoryIfMissing -Path $applicationArchivePath
        New-DirectoryIfMissing -Path $systemArchivePath

        Test-SecurityLogFreshness -SkipCheck:$SkipSecurityLogCheck -AlertTo $SecurityAlertTo -MailFrom $SecurityMailFrom -MailServer $SmtpServer

        Move-ArchivedEventLogs -LogName 'Security' -DestinationPath $securityArchivePath -OlderThan $datechk
        Move-ArchivedEventLogs -LogName 'Application' -DestinationPath $applicationArchivePath -OlderThan $datechk
        Move-ArchivedEventLogs -LogName 'System' -DestinationPath $systemArchivePath -OlderThan $datechk

        Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -Patterns @('*.zip')
        Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -Patterns @('*.evtx')

        $evtxFiles = Get-ChildItem -LiteralPath $EventLogArchiveRoot -Filter *.evtx -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $evtxFiles) {
            if (!(Test-Path -LiteralPath $file.FullName -PathType Leaf)) {
                continue
            }

            $destinationPath = Join-Path $file.DirectoryName "$($file.BaseName).zip"

            try {
                Compress-Archive -LiteralPath $file.FullName -DestinationPath $destinationPath -Force -ErrorAction Stop
                Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -ErrorAction Stop
                Write-Output "Compressed '$($file.FullName)' to '$destinationPath'."
            }
            catch {
                Write-Warning "Unable to compress or clean up '$($file.FullName)'. Error: $($_.Exception.Message)"
            }
        }

        foreach ($iisLogDirectory in (Get-IisLogDirectories)) {
            Remove-OldFiles -Path $iisLogDirectory -OlderThan $datechk -RetentionDays $RetentionDays -Patterns $IisLogFilePatterns
        }

        Remove-OldFiles -Path $WWWOutputPath -OlderThan $datechk -RetentionDays $RetentionDays -Patterns $WWWOutputFilePatterns

        Write-Output "Completed local event log archive and cleanup on $($env:COMPUTERNAME)."
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript
        }
    }
}

function Get-ArchiveComputerName {
    param(
        [string[]]$ExchangeServers
    )

    $targets = @()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to import ActiveDirectory module. Continuing with configured static targets only. Error: $($_.Exception.Message)"
        return $ExchangeServers | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique -Descending
    }

    try {
        $targets += Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Warning "Unable to discover AD domain controllers in the current domain. Error: $($_.Exception.Message)"
    }

    try {
        $targets += Get-ADDomainController -Filter * -Server ashbfdc1.winroot.analog.com -ErrorAction Stop | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Warning "Unable to discover domain controllers from ashbfdc1.winroot.analog.com. Error: $($_.Exception.Message)"
    }

    $targets += $ExchangeServers

    $targets |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique -Descending
}

function Get-StringSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)

    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
}

function Assert-RemoteScriptIntegrity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [string]$ExpectedScriptHash,

        [switch]$SkipCheck
    )

    $actualHash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash

    if (![string]::IsNullOrWhiteSpace($ExpectedScriptHash)) {
        if (![string]::Equals($actualHash, $ExpectedScriptHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Remote script integrity check failed for '$ScriptPath'. Expected SHA256 '$ExpectedScriptHash' but found '$actualHash'."
        }

        Write-Verbose "Remote script file hash verified: $actualHash"
        return $actualHash
    }

    if ($SkipCheck) {
        Write-Warning "Skipping remote script integrity verification for '$ScriptPath'. Current SHA256: $actualHash"
        return $actualHash
    }

    $signature = Get-AuthenticodeSignature -FilePath $ScriptPath
    if ($signature.Status -eq 'Valid') {
        Write-Verbose "Remote script Authenticode signature is valid. SHA256: $actualHash"
        return $actualHash
    }

    Write-Warning "Remote script '$ScriptPath' is not signed and no -ExpectedScriptHash was provided. Continuing without enforced script integrity. Current SHA256: $actualHash"
    return $actualHash
}

function Invoke-RemoteArchive {
    param(
        [string[]]$ComputerName,

        [int]$RetentionDays,

        [string]$EventLogArchiveRoot,

        [string]$WWWOutputPath,

        [string[]]$WWWOutputFilePatterns,

        [string[]]$IisLogFilePatterns,

        [switch]$SkipSecurityLogCheck,

        [string[]]$SecurityAlertTo,

        [string]$SecurityMailFrom,

        [int]$ThrottleLimit,

        [int]$TimeoutSeconds,

        [string[]]$AdditionalExchangeServers,

        [string]$LogDirectory,

        [string]$ExpectedScriptHash,

        [switch]$SkipRemoteIntegrityCheck,

        [string[]]$SummaryMailTo,

        [string]$SummaryMailFrom,

        [string]$SmtpServer
    )

    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            $LogDirectory = Join-Path (Get-Location) 'logs'
        }
        else {
            $LogDirectory = Join-Path $PSScriptRoot 'logs'
        }
    }

    New-DirectoryIfMissing -Path $LogDirectory

    $runDate = Get-Date -Format yyyyMMdd
    $localDateChk = (Get-Date).AddDays(-$RetentionDays)
    $transcriptPath = Join-Path $LogDirectory "EvtLogArchRemoteTranscript_$runDate.txt"
    $resultPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.txt"
    $attachmentPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.zip"
    $transcriptStarted = $false
    $jobs = $null
    $remoteRunFailed = $false
    $remoteErrors = New-Object System.Collections.Generic.List[string]

    $remoteWorker = {
        param(
            [string]$ScriptText,
            [string]$ScriptTextHash,
            [int]$RetentionDays,
            [string]$EventLogArchiveRoot,
            [string]$WWWOutputPath,
            [string[]]$WWWOutputFilePatterns,
            [string[]]$IisLogFilePatterns,
            [bool]$SkipSecurityLogCheck,
            [string[]]$SecurityAlertTo,
            [string]$SecurityMailFrom,
            [string]$SmtpServer
        )

        $scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($ScriptText)
        $actualTextHash = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($scriptBytes))).Replace('-', '')

        if (![string]::Equals($actualTextHash, $ScriptTextHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Remote script text hash verification failed on $($env:COMPUTERNAME). Expected '$ScriptTextHash' but found '$actualTextHash'."
        }

        $worker = [scriptblock]::Create($ScriptText)
        $parameters = @{
            RetentionDays = $RetentionDays
            WWWOutputPath = $WWWOutputPath
            WWWOutputFilePatterns = $WWWOutputFilePatterns
            IisLogFilePatterns = $IisLogFilePatterns
            SecurityAlertTo = $SecurityAlertTo
            SecurityMailFrom = $SecurityMailFrom
            SmtpServer = $SmtpServer
        }

        if (![string]::IsNullOrWhiteSpace($EventLogArchiveRoot)) {
            $parameters.EventLogArchiveRoot = $EventLogArchiveRoot
        }

        if ($SkipSecurityLogCheck) {
            $parameters.SkipSecurityLogCheck = $true
        }

        & $worker @parameters
    }

    try {
        Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
        $transcriptStarted = $true

        if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
            throw 'Remote mode must be run from a script file so the current code can be sent to remote targets.'
        }

        $scriptFileHash = Assert-RemoteScriptIntegrity -ScriptPath $PSCommandPath -ExpectedScriptHash $ExpectedScriptHash -SkipCheck:$SkipRemoteIntegrityCheck
        $scriptText = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop
        $scriptTextHash = Get-StringSha256 -Value $scriptText

        if (!$ComputerName -or $ComputerName.Count -eq 0) {
            $ComputerName = Get-ArchiveComputerName -ExchangeServers $AdditionalExchangeServers
        }
        else {
            $ComputerName = $ComputerName | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
        }

        if (!$ComputerName -or $ComputerName.Count -eq 0) {
            throw 'No remote archive targets were discovered or provided.'
        }

        Write-Output "Running event log archive worker on $($ComputerName.Count) remote targets."

        $argumentList = @(
            $scriptText
            $scriptTextHash
            $RetentionDays
            $EventLogArchiveRoot
            $WWWOutputPath
            (,$WWWOutputFilePatterns)
            (,$IisLogFilePatterns)
            ([bool]$SkipSecurityLogCheck)
            (,$SecurityAlertTo)
            $SecurityMailFrom
            $SmtpServer
        )

        $jobs = Invoke-Command -AsJob -ScriptBlock $remoteWorker -ComputerName $ComputerName -ArgumentList $argumentList -ThrottleLimit $ThrottleLimit -Verbose

        Wait-Job $jobs -Timeout $TimeoutSeconds | Out-Null

        $childJobs = @($jobs.ChildJobs)
        $unfinishedJobs = $childJobs | Where-Object { $_.State -eq 'Running' }
        if ($unfinishedJobs) {
            $remoteRunFailed = $true
            Write-Warning "$($unfinishedJobs.Count) remote archive jobs did not finish within $TimeoutSeconds seconds."
        }

        $receiveErrors = @()
        $results = Receive-Job -Job $jobs -ErrorAction SilentlyContinue -ErrorVariable receiveErrors
        $failedJobs = $childJobs | Where-Object { $_.State -notin @('Completed','Running') }

        if ($receiveErrors -or $failedJobs) {
            $remoteRunFailed = $true
        }

        $jobSummary = $childJobs |
            Sort-Object Location |
            ForEach-Object {
                $reason = if ($_.JobStateInfo.Reason) { $_.JobStateInfo.Reason.Message } else { '' }
                '{0} [{1}] {2}' -f $_.Location, $_.State, $reason
            }

        $resultLines = @(
            "Remote event log archive run: $runDate"
            "Controller: $($env:COMPUTERNAME)"
            "Script file SHA256: $scriptFileHash"
            "Script text SHA256: $scriptTextHash"
            "Targets: $($ComputerName.Count)"
            ''
            'Remote job summary:'
        )
        $resultLines += $jobSummary

        if ($receiveErrors) {
            $resultLines += ''
            $resultLines += 'Receive-Job errors:'
            $resultLines += ($receiveErrors | ForEach-Object { $_.ToString() })
        }

        $resultLines += ''
        $resultLines += 'Remote output:'
        $resultLines += ($results | Out-String)
        $resultLines | Set-Content -Path $resultPath
    }
    catch {
        $remoteRunFailed = $true
        $remoteErrors.Add($_.Exception.Message)
        Write-Warning "Remote archive run failed before completion. Error: $($_.Exception.Message)"

        try {
            @(
                "Remote event log archive run failed: $runDate"
                "Controller: $($env:COMPUTERNAME)"
                "Error: $($_.Exception.Message)"
            ) | Set-Content -Path $resultPath
        }
        catch {
            Write-Warning "Unable to write remote run failure summary to '$resultPath'. Error: $($_.Exception.Message)"
        }
    }
    finally {
        if ($jobs) {
            Stop-Job $jobs -ErrorAction SilentlyContinue
            Remove-Job $jobs -Force -ErrorAction SilentlyContinue
        }

        if ($transcriptStarted) {
            Stop-Transcript
        }
    }

    try {
        $mailParams = @{
            To = $SummaryMailTo
            From = $SummaryMailFrom
            Subject = 'Event Log Archiving Remote Output'
            Body = "See attached `n`nServer: $($env:COMPUTERNAME)`nScript: $($PSCommandPath)"
            SmtpServer = $SmtpServer
        }

        $textLogs = Get-ChildItem -LiteralPath $LogDirectory -Filter *.txt -File -ErrorAction SilentlyContinue
        if ($textLogs) {
            Compress-Archive -LiteralPath $textLogs.FullName -DestinationPath $attachmentPath -CompressionLevel Optimal -Force -ErrorAction Stop
            $mailParams.Attachments = $attachmentPath
        }

        if ($remoteRunFailed) {
            $mailParams.Subject = 'Event Log Archiving Remote Output - Failed'
            if ($remoteErrors.Count -gt 0) {
                $mailParams.Body += "`n`nErrors:`n$($remoteErrors -join "`n")"
            }
        }

        Send-MailMessage @mailParams
    }
    catch {
        Write-Warning "Unable to package or send remote archive summary email. Error: $($_.Exception.Message)"
    }

    Get-ChildItem -LiteralPath $LogDirectory -Filter *.txt -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $LogDirectory -Filter *.zip -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -le $localDateChk } | Remove-Item -Force -Confirm:$false -Verbose

    if ($remoteRunFailed) {
        throw "Remote archive run failed. See '$resultPath' for details."
    }
}

if ($Remote) {
    Invoke-RemoteArchive `
        -ComputerName $ComputerName `
        -RetentionDays $RetentionDays `
        -EventLogArchiveRoot $EventLogArchiveRoot `
        -WWWOutputPath $WWWOutputPath `
        -WWWOutputFilePatterns $WWWOutputFilePatterns `
        -IisLogFilePatterns $IisLogFilePatterns `
        -SkipSecurityLogCheck:$SkipSecurityLogCheck `
        -SecurityAlertTo $SecurityAlertTo `
        -SecurityMailFrom $SecurityMailFrom `
        -ThrottleLimit $ThrottleLimit `
        -TimeoutSeconds $TimeoutSeconds `
        -AdditionalExchangeServers $AdditionalExchangeServers `
        -LogDirectory $LogDirectory `
        -ExpectedScriptHash $ExpectedScriptHash `
        -SkipRemoteIntegrityCheck:$SkipRemoteIntegrityCheck `
        -SummaryMailTo $SummaryMailTo `
        -SummaryMailFrom $SummaryMailFrom `
        -SmtpServer $SmtpServer
}
else {
    Invoke-LocalArchive `
        -RetentionDays $RetentionDays `
        -EventLogArchiveRoot $EventLogArchiveRoot `
        -WWWOutputPath $WWWOutputPath `
        -WWWOutputFilePatterns $WWWOutputFilePatterns `
        -IisLogFilePatterns $IisLogFilePatterns `
        -SkipSecurityLogCheck:$SkipSecurityLogCheck `
        -SecurityAlertTo $SecurityAlertTo `
        -SecurityMailFrom $SecurityMailFrom `
        -SmtpServer $SmtpServer `
        -TranscriptDirectory $TranscriptDirectory
}
