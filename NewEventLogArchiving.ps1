[CmdletBinding()]
param(
    [switch]$Remote,

    [string[]]$ComputerName,

    [int]$RetentionDays = 30,

    [string]$EventLogArchiveRoot,

    [string]$WWWOutputPath = 'E:\WWWOutput',

    [string[]]$WWWOutputFilePatterns = @('*'),

    [string[]]$IisLogFilePatterns = @('*.log'),

    [switch]$SkipSecurityLogCheck,

    [string[]]$SecurityAlertTo = @('Michael.Coelho@analog.com','Jose.Hernandez@analog.com'),

    [Alias('MailFrom')]
    [string]$SecurityMailFrom = 'svc_scriptadm@analog.com',

    [string]$SmtpServer = 'mailhost.analog.com',

    [string]$TranscriptDirectory,

    [string]$LogDirectory,

    [int]$ThrottleLimit = 10,

    [int]$TimeoutSeconds = 39600,

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

    [string[]]$SummaryMailTo = @('Michael.Coelho@analog.com','Jose.Hernandez@analog.com'),

    [string]$SummaryMailFrom = 'michael.coelho@analog.com'
)

function Test-PathSafely {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Microsoft.PowerShell.Commands.TestPathType]$PathType = 'Any'
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
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
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

    $archivedEventLogs = Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue

    $archivedEventLogs |
        Where-Object { $_.LastWriteTime -le $OlderThan } |
        ForEach-Object {
            Write-Output "Removing expired archived $LogName event log '$($_.FullName)' before archive move."
            Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose
        }

    $archivedEventLogs |
        Where-Object { $_.LastWriteTime -gt $OlderThan } |
        Move-Item -Destination $DestinationPath -Verbose
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
            Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose
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
        $lastSecLog = Get-EventLog -LogName security -Newest 1 -ErrorAction Stop

        if ($lastSecLog.TimeWritten -lt ((Get-Date).AddMinutes(-15))) {
            Send-MailMessage -To $AlertTo -Subject "Check Security Logs on $($env:COMPUTERNAME)" -Body "Latest Security Log written more than 15 minutes ago`n$($lastSecLog | Out-String)" -From $MailFrom -SmtpServer $MailServer
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
        $EventLogArchiveRoot = "$($env:SystemDrive)\Evt_Logs"
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

        foreach ($file in (Get-ChildItem -LiteralPath $EventLogArchiveRoot -Filter *.evtx -Recurse -File -ErrorAction SilentlyContinue)) {
            $destinationPath = Join-Path $file.DirectoryName "$($file.BaseName).zip"

            try {
                Compress-Archive -LiteralPath $file.FullName -DestinationPath $destinationPath -Force -ErrorAction Stop
                Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false
            }
            catch {
                Write-Warning "Unable to compress '$($file.FullName)' to '$destinationPath'. Error: $($_.Exception.Message)"
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

    Import-Module ActiveDirectory -ErrorAction Stop

    $targets = @()

    $targets += Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $targets += Get-ADDomainController -Filter * -Server ashbfdc1.winroot.analog.com | Select-Object -ExpandProperty HostName
    $targets += $ExchangeServers

    $targets |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique -Descending
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

        [int]$ThrottleLimit,

        [int]$TimeoutSeconds,

        [string[]]$AdditionalExchangeServers,

        [string]$LogDirectory,

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

    if (!$ComputerName -or $ComputerName.Count -eq 0) {
        $ComputerName = Get-ArchiveComputerName -ExchangeServers $AdditionalExchangeServers
    }
    else {
        $ComputerName = $ComputerName | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
    }

    if (!$ComputerName -or $ComputerName.Count -eq 0) {
        throw 'No remote archive targets were discovered or provided.'
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Remote mode must be run from a script file so the current code can be sent to remote targets.'
    }

    $runDate = Get-Date -Format yyyyMMdd
    $localDateChk = (Get-Date).AddDays(-$RetentionDays)
    $transcriptPath = Join-Path $LogDirectory "EvtLogArchRemoteTranscript_$runDate.txt"
    $resultPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.txt"
    $attachmentPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.zip"
    $scriptText = Get-Content -LiteralPath $PSCommandPath -Raw
    $transcriptStarted = $false
    $jobs = $null

    $remoteWorker = {
        param(
            [string]$ScriptText,
            [int]$RetentionDays,
            [string]$EventLogArchiveRoot,
            [string]$WWWOutputPath,
            [string[]]$WWWOutputFilePatterns,
            [string[]]$IisLogFilePatterns,
            [bool]$SkipSecurityLogCheck
        )

        $worker = [scriptblock]::Create($ScriptText)
        $parameters = @{
            RetentionDays = $RetentionDays
            WWWOutputPath = $WWWOutputPath
            WWWOutputFilePatterns = $WWWOutputFilePatterns
            IisLogFilePatterns = $IisLogFilePatterns
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

        Write-Output "Running event log archive worker on $($ComputerName.Count) remote targets."

        $argumentList = @(
            $scriptText
            $RetentionDays
            $EventLogArchiveRoot
            $WWWOutputPath
            (,$WWWOutputFilePatterns)
            (,$IisLogFilePatterns)
            ([bool]$SkipSecurityLogCheck)
        )

        $jobs = Invoke-Command -AsJob -ScriptBlock $remoteWorker -ComputerName $ComputerName -ArgumentList $argumentList -ThrottleLimit $ThrottleLimit -Verbose

        Wait-Job $jobs -Timeout $TimeoutSeconds | Out-Null

        $unfinishedJobs = $jobs | Where-Object { $_.State -eq 'Running' }
        if ($unfinishedJobs) {
            Write-Warning "$($unfinishedJobs.Count) remote archive jobs did not finish within $TimeoutSeconds seconds."
        }

        $results = Receive-Job -Job $jobs
        $results | Set-Content -Path $resultPath
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

    Compress-Archive -Path (Join-Path $LogDirectory '*.txt') -DestinationPath $attachmentPath -CompressionLevel Optimal -Force

    Send-MailMessage -To $SummaryMailTo -From $SummaryMailFrom -Subject 'Event Log Archiving Remote Output' -Attachments $attachmentPath -Body "See attached `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)" -SmtpServer $SmtpServer

    Get-ChildItem -LiteralPath $LogDirectory -Filter *.txt -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -LiteralPath $LogDirectory -Filter *.zip -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -le $localDateChk } | Remove-Item -Force -Confirm:$false -Verbose
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
        -ThrottleLimit $ThrottleLimit `
        -TimeoutSeconds $TimeoutSeconds `
        -AdditionalExchangeServers $AdditionalExchangeServers `
        -LogDirectory $LogDirectory `
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
