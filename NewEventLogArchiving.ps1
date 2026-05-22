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

    [string]$ConfigPath,

    [switch]$SkipConfig,

    [switch]$SkipSecurityLogCheck,

    [string[]]$SecurityAlertTo = @('michael.coelho@analog.com'),

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

    [bool]$ScanDomainControllers = $true,

    [string[]]$DomainControllerDiscoveryServers = @('ashbfdc1.winroot.analog.com'),

    [Alias('AdditionalArchiveTargets')]
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

    [string[]]$SummaryMailTo = @('michael.coelho@analog.com'),

    [string]$SummaryMailFrom = 'michael.coelho@analog.com',

    [switch]$EmitOperationSummary
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

function Resolve-DefaultConfigPath {
    if (![string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return Join-Path $PSScriptRoot 'EventLogArchiving.config.psd1'
    }

    return Join-Path (Get-Location) 'EventLogArchiving.config.psd1'
}

function Get-ConfigurationValue {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,

        [Parameter(Mandatory = $true)]
        [string[]]$Path,

        [Parameter(Mandatory = $true)]
        [ref]$Value
    )

    $current = $Configuration
    foreach ($segment in $Path) {
        if (($current -isnot [System.Collections.IDictionary]) -or !$current.Contains($segment)) {
            return $false
        }

        $current = $current[$segment]
    }

    $Value.Value = $current
    return $true
}

function ConvertTo-ConfiguredValue {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName,

        [ValidateSet('Object','Bool','Int','String','StringArray')]
        [string]$ValueType = 'Object',

        [object]$Minimum,

        [object]$Maximum
    )

    if ($null -eq $Value) {
        return $null
    }

    switch ($ValueType) {
        'Bool' {
            if ($Value -is [bool]) {
                return [bool]$Value
            }

            if ($Value -is [string]) {
                $boolValue = $false
                if ([bool]::TryParse($Value, [ref]$boolValue)) {
                    return $boolValue
                }
            }

            throw "Configuration value '$ParameterName' must be a Boolean."
        }

        'Int' {
            if ($Value -is [array]) {
                throw "Configuration value '$ParameterName' must be an integer, not an array."
            }

            try {
                $convertedValue = [int]$Value
            }
            catch {
                throw "Configuration value '$ParameterName' must be an integer. Found '$Value'."
            }

            if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
                if ($convertedValue -ne $Value) {
                    throw "Configuration value '$ParameterName' must be a whole integer. Found '$Value'."
                }
            }

            if ($Value -is [string] -and $Value -notmatch '^([+-]?\d+|0x[0-9A-Fa-f]+)$') {
                throw "Configuration value '$ParameterName' must be a whole integer. Found '$Value'."
            }

            if ($null -ne $Minimum -and $convertedValue -lt [int]$Minimum) {
                throw "Configuration value '$ParameterName' must be at least $Minimum. Found $convertedValue."
            }

            if ($null -ne $Maximum -and $convertedValue -gt [int]$Maximum) {
                throw "Configuration value '$ParameterName' must be no more than $Maximum. Found $convertedValue."
            }

            return $convertedValue
        }

        'String' {
            if ($Value -is [array]) {
                throw "Configuration value '$ParameterName' must be a string, not an array."
            }

            return [string]$Value
        }

        'StringArray' {
            if ($Value -is [string]) {
                return [string[]]@($Value)
            }

            if ($Value -is [System.Collections.IDictionary]) {
                throw "Configuration value '$ParameterName' must be a string array, not a hashtable."
            }

            if ($Value -isnot [System.Collections.IEnumerable]) {
                throw "Configuration value '$ParameterName' must be a string array."
            }

            $convertedValues = @()
            foreach ($item in $Value) {
                if ($null -eq $item) {
                    throw "Configuration value '$ParameterName' contains a null array item."
                }

                if ($item -isnot [string]) {
                    throw "Configuration value '$ParameterName' must contain only strings. Found '$item'."
                }

                $convertedValues += [string]$item
            }

            return [string[]]$convertedValues
        }
    }

    return $Value
}

function Resolve-ConfiguredParameter {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,

        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName,

        [Parameter(Mandatory = $true)]
        [string[]]$ConfigPath,

        [ValidateSet('Object','Bool','Int','String','StringArray')]
        [string]$ValueType = 'Object',

        [object]$Minimum,

        [object]$Maximum,

        [switch]$AsSwitch
    )

    if ($BoundParameters.ContainsKey($ParameterName)) {
        return
    }

    $configuredValue = $null
    if (!(Get-ConfigurationValue -Configuration $Configuration -Path $ConfigPath -Value ([ref]$configuredValue))) {
        return
    }

    if ($null -eq $configuredValue) {
        return
    }

    if ($ValueType -eq 'StringArray') {
        $configuredValue = @(ConvertTo-ConfiguredValue -Value $configuredValue -ParameterName $ParameterName -ValueType $ValueType -Minimum $Minimum -Maximum $Maximum)
    }
    else {
        $configuredValue = ConvertTo-ConfiguredValue -Value $configuredValue -ParameterName $ParameterName -ValueType $ValueType -Minimum $Minimum -Maximum $Maximum
    }

    if ($AsSwitch) {
        Set-Variable -Name $ParameterName -Scope Script -Value ([System.Management.Automation.SwitchParameter][bool]$configuredValue)
        return
    }

    Set-Variable -Name $ParameterName -Scope Script -Value $configuredValue
}

function Get-ConfigurationKeyPath {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Configuration,

        [string[]]$Prefix = @()
    )

    foreach ($key in $Configuration.Keys) {
        $path = @($Prefix + [string]$key)
        $path -join '.'

        $value = $Configuration[$key]
        if ($value -is [System.Collections.IDictionary]) {
            Get-ConfigurationKeyPath -Configuration $value -Prefix $path
        }
    }
}

function Write-UnrecognizedConfigurationKeyWarning {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,

        [Parameter(Mandatory = $true)]
        [hashtable[]]$Mappings
    )

    $allowedLeafPaths = @{}
    $allowedPrefixPaths = @{}

    foreach ($mapping in $Mappings) {
        $path = @($mapping.ConfigPath)
        for ($index = 0; $index -lt $path.Count; $index++) {
            $pathText = ($path[0..$index] -join '.')
            if ($index -eq ($path.Count - 1)) {
                $allowedLeafPaths[$pathText] = $true
            }
            else {
                $allowedPrefixPaths[$pathText] = $true
            }
        }
    }

    $unknownPrefixes = @()
    $configurationKeyPaths = Get-ConfigurationKeyPath -Configuration $Configuration |
        Sort-Object { @($_ -split '\.').Count }, { $_ }

    foreach ($pathText in $configurationKeyPaths) {
        if (!$allowedLeafPaths.ContainsKey($pathText) -and !$allowedPrefixPaths.ContainsKey($pathText)) {
            $knownUnknownParent = $false
            foreach ($unknownPrefix in $unknownPrefixes) {
                if ($pathText.StartsWith("$unknownPrefix.", [System.StringComparison]::OrdinalIgnoreCase)) {
                    $knownUnknownParent = $true
                    break
                }
            }

            if ($knownUnknownParent) {
                continue
            }

            Write-Warning "Configuration key '$pathText' is not recognized and will be ignored."
            $unknownPrefixes += $pathText
        }
    }
}

function Import-EventLogArchiveConfiguration {
    param(
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Resolve-DefaultConfigPath
    }

    if (!(Test-PathSafely -Path $Path -PathType Leaf)) {
        if ($BoundParameters.ContainsKey('ConfigPath')) {
            throw "Configuration file '$Path' was not found. Copy 'EventLogArchiving.config.sample.psd1' to 'EventLogArchiving.config.psd1' or pass a valid -ConfigPath."
        }

        Write-Verbose "Configuration file '$Path' was not found. Using script defaults and command-line parameters."
        return $false
    }

    try {
        $configuration = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        throw "Unable to load configuration file '$Path'. Error: $($_.Exception.Message)"
    }

    if ($configuration -isnot [hashtable]) {
        throw "Configuration file '$Path' must contain a hashtable."
    }

    $mappings = @(
        @{ ParameterName = 'RetentionDays'; ConfigPath = @('RetentionDays'); ValueType = 'Int'; Minimum = 1; Maximum = 365 }
        @{ ParameterName = 'EventLogArchiveRoot'; ConfigPath = @('Paths','EventLogArchiveRoot'); ValueType = 'String' }
        @{ ParameterName = 'WWWOutputPath'; ConfigPath = @('Paths','WWWOutputPath'); ValueType = 'String' }
        @{ ParameterName = 'TranscriptDirectory'; ConfigPath = @('Paths','TranscriptDirectory'); ValueType = 'String' }
        @{ ParameterName = 'LogDirectory'; ConfigPath = @('Paths','LogDirectory'); ValueType = 'String' }
        @{ ParameterName = 'WWWOutputFilePatterns'; ConfigPath = @('Cleanup','WWWOutputFilePatterns'); ValueType = 'StringArray' }
        @{ ParameterName = 'IisLogFilePatterns'; ConfigPath = @('Cleanup','IisLogFilePatterns'); ValueType = 'StringArray' }
        @{ ParameterName = 'SkipSecurityLogCheck'; ConfigPath = @('Cleanup','SkipSecurityLogCheck'); ValueType = 'Bool'; AsSwitch = $true }
        @{ ParameterName = 'SecurityAlertTo'; ConfigPath = @('Mail','SecurityAlertTo'); ValueType = 'StringArray' }
        @{ ParameterName = 'SecurityMailFrom'; ConfigPath = @('Mail','SecurityMailFrom'); ValueType = 'String' }
        @{ ParameterName = 'SummaryMailTo'; ConfigPath = @('Mail','SummaryMailTo'); ValueType = 'StringArray' }
        @{ ParameterName = 'SummaryMailFrom'; ConfigPath = @('Mail','SummaryMailFrom'); ValueType = 'String' }
        @{ ParameterName = 'SmtpServer'; ConfigPath = @('Mail','SmtpServer'); ValueType = 'String' }
        @{ ParameterName = 'ComputerName'; ConfigPath = @('Remote','ComputerName'); ValueType = 'StringArray' }
        @{ ParameterName = 'ThrottleLimit'; ConfigPath = @('Remote','ThrottleLimit'); ValueType = 'Int'; Minimum = 1; Maximum = 100 }
        @{ ParameterName = 'TimeoutSeconds'; ConfigPath = @('Remote','TimeoutSeconds'); ValueType = 'Int'; Minimum = 60; Maximum = 86400 }
        @{ ParameterName = 'ExpectedScriptHash'; ConfigPath = @('Remote','ExpectedScriptHash'); ValueType = 'String' }
        @{ ParameterName = 'SkipRemoteIntegrityCheck'; ConfigPath = @('Remote','SkipRemoteIntegrityCheck'); ValueType = 'Bool'; AsSwitch = $true }
        @{ ParameterName = 'AdditionalExchangeServers'; ConfigPath = @('Remote','AdditionalArchiveTargets'); ValueType = 'StringArray' }
        @{ ParameterName = 'ScanDomainControllers'; ConfigPath = @('Discovery','ScanDomainControllers'); ValueType = 'Bool' }
        @{ ParameterName = 'DomainControllerDiscoveryServers'; ConfigPath = @('Discovery','DomainControllerDiscoveryServers'); ValueType = 'StringArray' }
    )

    Write-UnrecognizedConfigurationKeyWarning -Configuration $configuration -Mappings $mappings

    foreach ($mapping in $mappings) {
        $valueType = if ($mapping.ContainsKey('ValueType') -and ![string]::IsNullOrWhiteSpace($mapping.ValueType)) {
            $mapping.ValueType
        }
        else {
            'Object'
        }

        Resolve-ConfiguredParameter `
            -Configuration $configuration `
            -BoundParameters $BoundParameters `
            -ParameterName $mapping.ParameterName `
            -ConfigPath $mapping.ConfigPath `
            -ValueType $valueType `
            -Minimum $mapping.Minimum `
            -Maximum $mapping.Maximum `
            -AsSwitch:($mapping.AsSwitch -eq $true)
    }

    Write-Verbose "Loaded configuration from '$Path'."
    return $true
}

function New-DirectoryIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-PathSafely -Path $Path -PathType Container)) {
        try {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            Write-Warning "Failed to create directory '$Path'. Error: $($_.Exception.Message)"
            return $false
        }
    }

    return $true
}

function ConvertTo-ArchiveOperationMetric {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ItemType,

        [int]$Succeeded = 0,

        [int]$Failed = 0,

        [string[]]$FailureDetails = @()
    )

    [pscustomobject]@{
        ItemType = $ItemType
        Succeeded = $Succeeded
        Failed = $Failed
        FailureDetails = @($FailureDetails)
    }
}

function Add-ArchiveOperationMetric {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Metrics,

        [object[]]$Metric
    )

    foreach ($item in @($Metric)) {
        if ($null -ne $item) {
            if ($item.PSObject.Properties['ItemType'] -and
                $item.PSObject.Properties['Succeeded'] -and
                $item.PSObject.Properties['Failed']) {
                [void]$Metrics.Add($item)
            }
            else {
                Write-Output $item
            }
        }
    }
}

function Add-ArchiveFailureDetail {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$FailureDetails,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $FailureDetails.Add($Message)
    Write-Warning $Message
}

function Test-CleanupPathSafety {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ItemType
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Warning "Refusing $ItemType because the path is empty."
        return $false
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        Write-Warning "Refusing $ItemType for invalid path '$Path'. Error: $($_.Exception.Message)"
        return $false
    }

    $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
    if (![string]::IsNullOrWhiteSpace($rootPath)) {
        $normalizedFullPath = $fullPath.TrimEnd('\')
        $normalizedRootPath = $rootPath.TrimEnd('\')

        if ([string]::Equals($normalizedFullPath, $normalizedRootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Refusing $ItemType at drive root '$fullPath'."
            return $false
        }
    }

    if (![string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $systemRoot = [System.IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')
        $normalizedFullPath = $fullPath.TrimEnd('\')

        if ([string]::Equals($normalizedFullPath, $systemRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $normalizedFullPath.StartsWith("$systemRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Refusing $ItemType under system root '$systemRoot'."
            return $false
        }
    }

    return $true
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
        Write-Verbose "No existing event log archive root found. Using '$systemDriveArchiveRoot'."
        return $systemDriveArchiveRoot
    }

    $selected = $existingCandidates |
        Sort-Object `
            @{ Expression = 'InRetentionCount'; Descending = $true },
            @{ Expression = 'TotalCount'; Descending = $true },
            @{ Expression = 'IsDefault'; Descending = $true } |
        Select-Object -First 1

    Write-Verbose "Selected event log archive root '$($selected.Path)' (in-retention artifacts: $($selected.InRetentionCount), total artifacts: $($selected.TotalCount))."
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
    $expiredSucceeded = 0
    $expiredFailed = 0
    $moveSucceeded = 0
    $moveFailed = 0
    $expiredFailureDetails = [System.Collections.Generic.List[string]]::new()
    $moveFailureDetails = [System.Collections.Generic.List[string]]::new()

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -le $OlderThan } |
        ForEach-Object {
            try {
                Write-Output "Removing expired archived $LogName event log '$($_.FullName)'."
                Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
                $expiredSucceeded++
            }
            catch {
                $expiredFailed++
                Add-ArchiveFailureDetail -FailureDetails $expiredFailureDetails -Message "Unable to remove expired $LogName event log '$($_.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $OlderThan } |
        ForEach-Object {
            $destination = Join-Path $DestinationPath $_.Name
            try {
                Move-Item -LiteralPath $_.FullName -Destination $destination -Verbose -ErrorAction Stop
                $moveSucceeded++
            }
            catch {
                Write-Warning "Move failed for '$($_.FullName)', attempting copy. Error: $($_.Exception.Message)"
                try {
                    Copy-Item -LiteralPath $_.FullName -Destination $destination -Force -ErrorAction Stop
                    Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -ErrorAction Stop
                    Write-Output "Copied and removed '$($_.FullName)' to '$destination'."
                    $moveSucceeded++
                }
                catch {
                    $moveFailed++
                    Add-ArchiveFailureDetail -FailureDetails $moveFailureDetails -Message "Copy fallback also failed for $LogName event log '$($_.FullName)'. Error: $($_.Exception.Message)"
                }
            }
        }

    @(
        ConvertTo-ArchiveOperationMetric -ItemType "$LogName expired archive cleanup" -Succeeded $expiredSucceeded -Failed $expiredFailed -FailureDetails $expiredFailureDetails
        ConvertTo-ArchiveOperationMetric -ItemType "$LogName archive relocation" -Succeeded $moveSucceeded -Failed $moveFailed -FailureDetails $moveFailureDetails
    )
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

        [string]$ItemType = 'Old file cleanup',

        [string[]]$Patterns = @('*')
    )

    $succeeded = 0
    $failed = 0
    $failureDetails = [System.Collections.Generic.List[string]]::new()

    if (!(Test-CleanupPathSafety -Path $Path -ItemType $ItemType)) {
        $failed++
        $failureDetails.Add("Skipped unsafe cleanup path '$Path'.")
        return ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails
    }

    if (!(Test-PathSafely -Path $Path -PathType Container)) {
        Write-Output "Skipping missing cleanup path '$Path'."
        return ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails
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
                $succeeded++
            }
            catch {
                $failed++
                Add-ArchiveFailureDetail -FailureDetails $failureDetails -Message "Unable to remove old file '$($_.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails
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

        [string]$TranscriptDirectory,

        [switch]$EmitOperationSummary
    )

    $datechk = (Get-Date).AddDays(-$RetentionDays)
    $operationMetrics = [System.Collections.Generic.List[object]]::new()

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
            if ((Test-CleanupPathSafety -Path $TranscriptDirectory -ItemType 'transcript directory') -and
                (New-DirectoryIfMissing -Path $TranscriptDirectory)) {
                $transcriptPath = Join-Path $TranscriptDirectory "EvtLogArchTranscript_$(Get-Date -Format yyyyMMdd).txt"
                Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
                $transcriptStarted = $true
            }
        }

        Write-Output "Starting local event log archive and cleanup on $($env:COMPUTERNAME)."

        $directorySucceeded = 0
        $directoryFailed = 0
        $directoryFailureDetails = [System.Collections.Generic.List[string]]::new()
        foreach ($directoryPath in @($EventLogArchiveRoot, $securityArchivePath, $applicationArchivePath, $systemArchivePath)) {
            if (New-DirectoryIfMissing -Path $directoryPath) {
                $directorySucceeded++
            }
            else {
                $directoryFailed++
                $directoryFailureDetails.Add("Unable to create or access directory '$directoryPath'.")
            }
        }
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (ConvertTo-ArchiveOperationMetric -ItemType 'Directory setup' -Succeeded $directorySucceeded -Failed $directoryFailed -FailureDetails $directoryFailureDetails)

        Test-SecurityLogFreshness -SkipCheck:$SkipSecurityLogCheck -AlertTo $SecurityAlertTo -MailFrom $SecurityMailFrom -MailServer $SmtpServer

        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Move-ArchivedEventLogs -LogName 'Security' -DestinationPath $securityArchivePath -OlderThan $datechk)
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Move-ArchivedEventLogs -LogName 'Application' -DestinationPath $applicationArchivePath -OlderThan $datechk)
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Move-ArchivedEventLogs -LogName 'System' -DestinationPath $systemArchivePath -OlderThan $datechk)

        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'Archive zip retention cleanup' -Patterns @('*.zip'))
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'Archive evtx retention cleanup' -Patterns @('*.evtx'))

        $compressionSucceeded = 0
        $compressionFailed = 0
        $compressionFailureDetails = [System.Collections.Generic.List[string]]::new()
        if (Test-CleanupPathSafety -Path $EventLogArchiveRoot -ItemType 'Archive compression') {
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
                    $compressionSucceeded++
                }
                catch {
                    $compressionFailed++
                    Add-ArchiveFailureDetail -FailureDetails $compressionFailureDetails -Message "Unable to compress or clean up '$($file.FullName)'. Error: $($_.Exception.Message)"
                }
            }
        }
        else {
            $compressionFailed++
            $compressionFailureDetails.Add("Skipped unsafe archive compression path '$EventLogArchiveRoot'.")
        }
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (ConvertTo-ArchiveOperationMetric -ItemType 'Archive compression' -Succeeded $compressionSucceeded -Failed $compressionFailed -FailureDetails $compressionFailureDetails)

        foreach ($iisLogDirectory in (Get-IisLogDirectories)) {
            Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $iisLogDirectory -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'IIS log cleanup' -Patterns $IisLogFilePatterns)
        }

        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $WWWOutputPath -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'WWWOutput cleanup' -Patterns $WWWOutputFilePatterns)

        Write-Output "Completed local event log archive and cleanup on $($env:COMPUTERNAME)."

        if ($EmitOperationSummary) {
            [pscustomobject]@{
                RecordType = 'EventLogArchiveOperationSummary'
                ComputerName = $env:COMPUTERNAME
                Metrics = @($operationMetrics)
            }
        }
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript
        }
    }
}

function Get-ArchiveComputerName {
    param(
        [string[]]$StaticTargets,

        [bool]$ScanDomainControllers = $true,

        [string[]]$DomainControllerDiscoveryServers = @()
    )

    $targets = @()

    if (!$ScanDomainControllers) {
        return $StaticTargets | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique -Descending
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to import ActiveDirectory module. Continuing with configured static targets only. Error: $($_.Exception.Message)"
        return $StaticTargets | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique -Descending
    }

    try {
        $targets += Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Warning "Unable to discover AD domain controllers in the current domain. Error: $($_.Exception.Message)"
    }

    foreach ($discoveryServer in @($DomainControllerDiscoveryServers | Where-Object { ![string]::IsNullOrWhiteSpace($_) })) {
        try {
            $targets += Get-ADDomainController -Filter * -Server $discoveryServer -ErrorAction Stop | Select-Object -ExpandProperty HostName
        }
        catch {
            Write-Warning "Unable to discover domain controllers from $discoveryServer. Error: $($_.Exception.Message)"
        }
    }

    $targets += $StaticTargets

    $targets |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique -Descending
}

function Get-BytesSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()

    try {
        $hashBytes = $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }

    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
}

function Get-StringSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return Get-BytesSha256 -Bytes ([System.Text.Encoding]::Unicode.GetBytes($Value))
}

function Read-ScriptFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $scriptBytes = [System.IO.File]::ReadAllBytes($ScriptPath)
    $scriptHash = Get-BytesSha256 -Bytes $scriptBytes
    $memoryStream = New-Object -TypeName System.IO.MemoryStream -ArgumentList @(,$scriptBytes)
    $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $memoryStream, ([System.Text.Encoding]::UTF8), $true

    try {
        $scriptText = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
        $memoryStream.Dispose()
    }

    [pscustomobject]@{
        Text = $scriptText
        Hash = $scriptHash
    }
}

function Test-RemoteScriptIntegrity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$ActualScriptHash,

        [string]$ExpectedScriptHash,

        [switch]$SkipCheck
    )

    if (![string]::IsNullOrWhiteSpace($ExpectedScriptHash)) {
        if (![string]::Equals($ActualScriptHash, $ExpectedScriptHash, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Remote script integrity check failed for '$ScriptPath'. Expected SHA256 '$ExpectedScriptHash' but found '$ActualScriptHash'."
        }

        Write-Verbose "Remote script file hash verified: $ActualScriptHash"
        return $true
    }

    if ($SkipCheck) {
        Write-Warning "Skipping remote script integrity verification for '$ScriptPath'. Current SHA256: $ActualScriptHash"
        return $false
    }

    $signature = Get-AuthenticodeSignature -FilePath $ScriptPath
    if ($signature.Status -eq 'Valid') {
        Write-Verbose "Remote script Authenticode signature is valid. SHA256: $ActualScriptHash"
        return $true
    }

    Write-Warning "Remote script '$ScriptPath' is not signed and no -ExpectedScriptHash was provided. Continuing without enforced script integrity. Current SHA256: $ActualScriptHash"
    return $false
}

function ConvertTo-HtmlEncodedText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ArchiveMetricTotal {
    param(
        [object[]]$Metrics,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $sum = ($Metrics | Measure-Object -Property $PropertyName -Sum).Sum
    if ($null -eq $sum) {
        return 0
    }

    return [int]$sum
}

function Get-ArchiveFailureRow {
    param(
        [object[]]$OperationSummaries
    )

    foreach ($summary in @($OperationSummaries)) {
        foreach ($metric in @($summary.Metrics)) {
            if (($metric.Failed -as [int]) -le 0) {
                continue
            }

            $details = @($metric.FailureDetails | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
            if ($details.Count -eq 0) {
                $details = @("$($metric.Failed) item(s) failed.")
            }

            foreach ($detail in $details) {
                [pscustomobject]@{
                    ComputerName = $summary.ComputerName
                    ItemType = $metric.ItemType
                    Detail = $detail
                }
            }
        }
    }
}

function ConvertTo-RemoteArchiveReportHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunDate,

        [Parameter(Mandatory = $true)]
        [string]$Controller,

        [object[]]$OperationSummaries = @(),

        [string[]]$RemoteErrors = @(),

        [switch]$RemoteRunFailed
    )

    $operationSummaries = @($OperationSummaries | Where-Object { $_.PSObject.Properties['Metrics'] })
    $failureRows = @(Get-ArchiveFailureRow -OperationSummaries $operationSummaries)
    $statusText = if ($RemoteRunFailed) {
        'Failed'
    }
    elseif ($failureRows.Count -gt 0) {
        'Completed with cleanup warnings'
    }
    else {
        'Completed'
    }

    $itemTypes = @(
        $operationSummaries |
            ForEach-Object { @($_.Metrics) } |
            Where-Object { $_.PSObject.Properties['ItemType'] } |
            Select-Object -ExpandProperty ItemType -Unique
    )

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#1f2933;">')
    [void]$builder.AppendLine("<p><strong>Event log archive run:</strong> $(ConvertTo-HtmlEncodedText $RunDate)<br />")
    [void]$builder.AppendLine("<strong>Controller:</strong> $(ConvertTo-HtmlEncodedText $Controller)<br />")
    [void]$builder.AppendLine("<strong>Status:</strong> $(ConvertTo-HtmlEncodedText $statusText)</p>")

    if ($operationSummaries.Count -gt 0 -and $itemTypes.Count -gt 0) {
        [void]$builder.AppendLine('<table cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#cbd5e1;">')
        [void]$builder.Append('<tr style="background:#f1f5f9;"><th align="left">Machine</th>')
        foreach ($itemType in $itemTypes) {
            [void]$builder.Append("<th align=""left"">$(ConvertTo-HtmlEncodedText $itemType)</th>")
        }
        [void]$builder.AppendLine('</tr>')

        foreach ($summary in ($operationSummaries | Sort-Object ComputerName)) {
            [void]$builder.Append("<tr><td><strong>$(ConvertTo-HtmlEncodedText $summary.ComputerName)</strong></td>")
            foreach ($itemType in $itemTypes) {
                $matchingMetrics = @($summary.Metrics | Where-Object { $_.ItemType -eq $itemType })
                if ($matchingMetrics.Count -eq 0) {
                    [void]$builder.Append('<td style="color:#64748b;">-</td>')
                    continue
                }

                $succeeded = Get-ArchiveMetricTotal -Metrics $matchingMetrics -PropertyName 'Succeeded'
                $failed = Get-ArchiveMetricTotal -Metrics $matchingMetrics -PropertyName 'Failed'
                [void]$builder.Append("<td><span style=""color:#0f7a35;font-weight:600;"">$succeeded succeeded</span><br /><span style=""color:#b42318;font-weight:600;"">$failed failed</span></td>")
            }
            [void]$builder.AppendLine('</tr>')
        }
        [void]$builder.AppendLine('</table>')
    }
    else {
        [void]$builder.AppendLine('<p>No per-machine cleanup summary was returned. Check the attached transcript for raw output.</p>')
    }

    if ($failureRows.Count -gt 0) {
        [void]$builder.AppendLine('<h3 style="margin-top:18px;">Cleanup Failures</h3>')
        [void]$builder.AppendLine('<table cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#cbd5e1;">')
        [void]$builder.AppendLine('<tr style="background:#fef2f2;"><th align="left">Machine</th><th align="left">Item type</th><th align="left">Detail</th></tr>')
        foreach ($failureRow in ($failureRows | Sort-Object ComputerName, ItemType, Detail)) {
            [void]$builder.AppendLine("<tr><td>$(ConvertTo-HtmlEncodedText $failureRow.ComputerName)</td><td>$(ConvertTo-HtmlEncodedText $failureRow.ItemType)</td><td>$(ConvertTo-HtmlEncodedText $failureRow.Detail)</td></tr>")
        }
        [void]$builder.AppendLine('</table>')
    }

    if ($RemoteErrors -and $RemoteErrors.Count -gt 0) {
        [void]$builder.AppendLine('<h3 style="margin-top:18px;">Remote Run Errors</h3><ul>')
        foreach ($remoteError in $RemoteErrors) {
            [void]$builder.AppendLine("<li>$(ConvertTo-HtmlEncodedText $remoteError)</li>")
        }
        [void]$builder.AppendLine('</ul>')
    }

    [void]$builder.AppendLine('<p>See the attached archive output for transcript details.</p>')
    [void]$builder.AppendLine('</body></html>')
    return $builder.ToString()
}

function Convert-ArchiveOperationSummariesToText {
    param(
        [object[]]$OperationSummaries = @()
    )

    $operationSummaries = @($OperationSummaries | Where-Object { $_.PSObject.Properties['Metrics'] })
    if ($operationSummaries.Count -eq 0) {
        return @('No per-machine cleanup summary was returned.')
    }

    $lines = @('Cleanup summary:')
    foreach ($summary in ($operationSummaries | Sort-Object ComputerName)) {
        $lines += "  $($summary.ComputerName)"
        foreach ($metric in @($summary.Metrics | Sort-Object ItemType)) {
            $lines += "    $($metric.ItemType): $($metric.Succeeded) succeeded, $($metric.Failed) failed"
        }
    }

    $failureRows = @(Get-ArchiveFailureRow -OperationSummaries $operationSummaries)
    if ($failureRows.Count -gt 0) {
        $lines += ''
        $lines += 'Cleanup failure details:'
        foreach ($failureRow in ($failureRows | Sort-Object ComputerName, ItemType, Detail)) {
            $lines += "  $($failureRow.ComputerName) | $($failureRow.ItemType) | $($failureRow.Detail)"
        }
    }

    return $lines
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

        [bool]$ScanDomainControllers,

        [string[]]$DomainControllerDiscoveryServers,

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

    if (!(Test-CleanupPathSafety -Path $LogDirectory -ItemType 'remote log directory')) {
        throw "Remote log directory '$LogDirectory' is not safe to use."
    }

    New-DirectoryIfMissing -Path $LogDirectory | Out-Null

    $runDate = Get-Date -Format yyyyMMdd
    $localDateChk = (Get-Date).AddDays(-$RetentionDays)
    $transcriptPath = Join-Path $LogDirectory "EvtLogArchRemoteTranscript_$runDate.txt"
    $resultPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.txt"
    $attachmentPath = Join-Path $LogDirectory "EvtLogArchRemote_$runDate.zip"
    $transcriptStarted = $false
    $jobs = $null
    $remoteRunFailed = $false
    $remoteErrors = [System.Collections.Generic.List[string]]::new()
    $operationSummaries = @()

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
        $sha256 = [System.Security.Cryptography.SHA256]::Create()

        try {
            $actualTextHash = ([System.BitConverter]::ToString($sha256.ComputeHash($scriptBytes))).Replace('-', '')
        }
        finally {
            $sha256.Dispose()
        }

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
            EmitOperationSummary = $true
            SkipConfig = $true
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

        $scriptFile = Read-ScriptFile -ScriptPath $PSCommandPath
        $scriptFileHash = $scriptFile.Hash
        Test-RemoteScriptIntegrity -ScriptPath $PSCommandPath -ActualScriptHash $scriptFileHash -ExpectedScriptHash $ExpectedScriptHash -SkipCheck:$SkipRemoteIntegrityCheck | Out-Null
        $scriptText = $scriptFile.Text
        $scriptTextHash = Get-StringSha256 -Value $scriptText

        if (!$ComputerName -or $ComputerName.Count -eq 0) {
            $ComputerName = Get-ArchiveComputerName -StaticTargets $AdditionalExchangeServers -ScanDomainControllers $ScanDomainControllers -DomainControllerDiscoveryServers $DomainControllerDiscoveryServers
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

            foreach ($unfinishedJob in $unfinishedJobs) {
                $remoteErrors.Add("$($unfinishedJob.Location) [$($unfinishedJob.State)] Timed out after $TimeoutSeconds seconds.")
            }
        }

        $receiveErrors = @()
        $results = Receive-Job -Job $jobs -ErrorAction SilentlyContinue -ErrorVariable receiveErrors
        $operationSummaries = @($results | Where-Object { $_.PSObject.Properties['RecordType'] -and $_.RecordType -eq 'EventLogArchiveOperationSummary' })
        $visibleResults = @($results | Where-Object { !($_.PSObject.Properties['RecordType'] -and $_.RecordType -eq 'EventLogArchiveOperationSummary') })
        $failedJobs = $childJobs | Where-Object { $_.State -notin @('Completed','Running') }

        if ($receiveErrors -or $failedJobs) {
            $remoteRunFailed = $true

            foreach ($receiveError in $receiveErrors) {
                $remoteErrors.Add($receiveError.ToString())
            }

            foreach ($failedJob in $failedJobs) {
                $reason = if ($failedJob.JobStateInfo.Reason) { $failedJob.JobStateInfo.Reason.Message } else { 'No failure reason reported.' }
                $remoteErrors.Add("$($failedJob.Location) [$($failedJob.State)] $reason")
            }
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
        $resultLines += Convert-ArchiveOperationSummariesToText -OperationSummaries $operationSummaries

        $resultLines += ''
        $resultLines += 'Remote output:'
        $resultLines += ($visibleResults | Out-String)
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
            Body = ConvertTo-RemoteArchiveReportHtml -RunDate $runDate -Controller $env:COMPUTERNAME -OperationSummaries $operationSummaries -RemoteErrors $remoteErrors -RemoteRunFailed:$remoteRunFailed
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
        }

        $currentRunTextLogs = @($transcriptPath, $resultPath) | Where-Object { Test-PathSafely -Path $_ -PathType Leaf }
        if ($currentRunTextLogs) {
            Compress-Archive -LiteralPath $currentRunTextLogs -DestinationPath $attachmentPath -CompressionLevel Optimal -Force -ErrorAction Stop
            $mailParams.Attachments = $attachmentPath
        }

        if ($remoteRunFailed) {
            $mailParams.Subject = 'Event Log Archiving Remote Output - Failed'
        }
        elseif ((Get-ArchiveFailureRow -OperationSummaries $operationSummaries)) {
            $mailParams.Subject = 'Event Log Archiving Remote Output - Cleanup Warnings'
        }

        Send-MailMessage @mailParams
    }
    catch {
        Write-Warning "Unable to package or send remote archive summary email. Error: $($_.Exception.Message)"
    }

    if (!$remoteRunFailed) {
        @($transcriptPath, $resultPath) |
            Where-Object { Test-PathSafely -Path $_ -PathType Leaf } |
            ForEach-Object { Remove-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue }
    }

    Get-ChildItem -LiteralPath $LogDirectory -Filter *.zip -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -le $localDateChk } | Remove-Item -Force -Confirm:$false -Verbose

    if ($remoteRunFailed) {
        throw "Remote archive run failed. See '$resultPath' for details."
    }
}

$configurationLoaded = $false
if ($Remote -and $SkipConfig) {
    throw "Remote mode cannot be used with -SkipConfig. Copy 'EventLogArchiving.config.sample.psd1' to 'EventLogArchiving.config.psd1' and update it, or pass -ConfigPath with a configured psd1 file."
}

if (!$SkipConfig) {
    $configurationLoaded = Import-EventLogArchiveConfiguration -Path $ConfigPath -BoundParameters $PSBoundParameters
}

if ($Remote -and !$configurationLoaded) {
    $defaultConfigPath = Resolve-DefaultConfigPath
    throw "Remote mode requires a configuration file. Copy 'EventLogArchiving.config.sample.psd1' to '$defaultConfigPath' and update it, or pass -ConfigPath with a configured psd1 file."
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
        -ScanDomainControllers $ScanDomainControllers `
        -DomainControllerDiscoveryServers $DomainControllerDiscoveryServers `
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
        -TranscriptDirectory $TranscriptDirectory `
        -EmitOperationSummary:$EmitOperationSummary
}
