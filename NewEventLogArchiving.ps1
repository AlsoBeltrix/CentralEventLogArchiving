<#
.SYNOPSIS
Archives Windows event log files and removes expired archive, IIS, and WWWOutput files.

.DESCRIPTION
Runs local cleanup by default. In local mode, the script moves archived Security,
Application, System, and other Archive-* .evtx files into archive folders, compresses
retained .evtx files, removes expired archive files, removes expired IIS logs, and
removes expired WWWOutput files.

Remote mode sends the current script text to remote targets and runs the same local
archive workflow on each target. Remote mode requires a configuration file unless
-ConfigPath points to one explicitly. Copy EventLogArchiving.config.sample.psd1 to
EventLogArchiving.config.psd1 and customize it for each deployment. The local
EventLogArchiving.config.psd1 file is intentionally ignored by Git so endpoint
settings are not overwritten by future script updates.

Configuration values are loaded before execution. Explicit command-line parameters
override configuration values. Remote worker sessions do not load their own config;
the controller sends resolved values to the remote targets.

.PARAMETER Remote
Runs the archive workflow on remote targets. The local archive also runs by default.
Use -Local:$false with -Remote to skip the local archive.

.PARAMETER Local
Controls whether the local archive runs. Defaults to true. Use -Local:$false to skip
the local archive when running in remote mode.

.PARAMETER ComputerName
Explicit remote target names. When supplied in remote mode, this exact list is used
and domain-controller discovery is bypassed.

.PARAMETER RetentionDays
Number of days to retain archive, IIS, and WWWOutput files. Valid range is 1 through
365. Defaults to 30.

.PARAMETER EventLogArchiveRoot
Root folder for event log archives. When omitted, the script chooses an existing
archive root based on retained artifacts, falling back to the system drive.

.PARAMETER WWWOutputPath
Folder containing WWWOutput files to remove after the retention period. When omitted,
WWWOutput cleanup is skipped.

.PARAMETER WWWOutputFilePatterns
File name patterns used when cleaning WWWOutputPath. Uses a runtime default of *.

.PARAMETER IisLogFilePatterns
File name patterns used when cleaning IIS log directories. Uses a runtime default of
*.log.

.PARAMETER ConfigPath
Path to a PowerShell data file containing configuration. If omitted, the script looks
for EventLogArchiving.config.psd1 beside the script. Remote mode requires a config
file unless the path is supplied explicitly.

.PARAMETER SkipConfig
Skips configuration loading. This is intended for remote worker invocation and local
troubleshooting. Remote controller mode cannot be used with -SkipConfig.

.PARAMETER SkipSecurityLogCheck
Skips the latest Security event log freshness check and related alert email.

.PARAMETER SecurityAlertTo
Recipients for Security event log freshness alert emails. If mail settings are not
configured, the freshness check still runs but no alert email is sent.

.PARAMETER SecurityMailFrom
Sender address for Security event log freshness alert emails. The alias -MailFrom is
also supported for compatibility.

.PARAMETER SmtpServer
SMTP server used for alert and summary email.

.PARAMETER TranscriptDirectory
Local-mode transcript directory. If omitted, defaults to a logs folder beside the
script when PSScriptRoot is available. Unsafe paths such as drive roots and the
Windows system root are rejected.

.PARAMETER LogDirectory
Remote controller transcript, result, and attachment directory. If omitted, defaults
to a logs folder beside the script. Unsafe paths such as drive roots and the Windows
system root are rejected.

.PARAMETER ThrottleLimit
Maximum concurrent remote jobs. Valid range is 1 through 100. Defaults to 10.

.PARAMETER TimeoutSeconds
Maximum time to wait for remote jobs. Valid range is 60 through 86400 seconds.
Defaults to 39600.

.PARAMETER ExpectedScriptHash
Expected SHA256 hash for the local script file before dispatching remote work. When
provided, the script file hash must match.

.PARAMETER SkipRemoteIntegrityCheck
Allows remote mode to continue when the local script is unsigned and no
ExpectedScriptHash is provided. The script still verifies that the text received by
each remote worker matches the controller's dispatched script text.

.PARAMETER DomainControllersOnly
Remote-mode convenience switch that runs only discovered domain controllers. It
ignores configured static remote targets for that run. Do not combine with
-ComputerName, -AdditionalArchiveTargets, or -ConfiguredTargetsOnly.

.PARAMETER ConfiguredTargetsOnly
Remote-mode convenience switch that runs configured static remote targets only and
disables domain-controller discovery for that run. Do not combine with
-DomainControllersOnly.

.PARAMETER ScanDomainControllers
Controls whether remote target discovery scans domain controllers. This is usually
set in configuration. Uses a runtime default of true.

.PARAMETER DomainControllerDiscoveryServers
Additional AD servers to query for domain-controller discovery, such as another
domain or forest. This is usually set in configuration.

.PARAMETER AdditionalExchangeServers
Additional static remote targets used when ComputerName is not supplied. The alias
-AdditionalArchiveTargets is also supported and matches the configuration key.

.PARAMETER SummaryMailTo
Recipients for remote summary emails.

.PARAMETER SummaryMailFrom
Sender address for remote summary emails.

.PARAMETER EmitOperationSummary
Emits structured per-machine cleanup metrics. This is used by remote worker sessions
so the controller can build the HTML report.

.EXAMPLE
.\NewEventLogArchiving.ps1

Runs the local archive and cleanup workflow using runtime defaults and any local
configuration file.

.EXAMPLE
.\NewEventLogArchiving.ps1 -RetentionDays 21

Runs local cleanup with a one-off retention override.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote

Runs the local archive and then the remote archive using EventLogArchiving.config.psd1.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote -Local:$false

Runs only the remote archive, skipping the local machine.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote -DomainControllersOnly

Runs remote mode against discovered domain controllers only.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote -ConfiguredTargetsOnly

Runs remote mode against configured static targets only and skips domain-controller
discovery.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote -ComputerName server1.contoso.com,server2.contoso.com

Runs remote mode against an explicit one-off target list. Explicit ComputerName
values bypass domain-controller discovery.

.EXAMPLE
.\NewEventLogArchiving.ps1 -Remote -ConfigPath .\CustomerA.config.psd1

Runs remote mode using an explicit configuration file.

.NOTES
The real EventLogArchiving.config.psd1 file is endpoint-local and ignored by Git.
Keep deployment-specific sample values in EventLogArchiving.config.sample.psd1.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remote,

    [bool]$Local = $true,

    [string[]]$ComputerName,

    [ValidateRange(1,365)]
    [int]$RetentionDays = 30,

    [string]$EventLogArchiveRoot,

    [string]$WWWOutputPath,

    [string[]]$WWWOutputFilePatterns,

    [string[]]$IisLogFilePatterns,

    [string]$ConfigPath,

    [switch]$SkipConfig,

    [switch]$SkipSecurityLogCheck,

    [string[]]$SecurityAlertTo,

    [Alias('MailFrom')]
    [string]$SecurityMailFrom,

    [string]$SmtpServer,

    [string]$TranscriptDirectory,

    [string]$LogDirectory,

    [ValidateRange(1,100)]
    [int]$ThrottleLimit = 10,

    [ValidateRange(60,86400)]
    [int]$TimeoutSeconds = 39600,

    [string]$ExpectedScriptHash,

    [switch]$SkipRemoteIntegrityCheck,

    [switch]$DomainControllersOnly,

    [switch]$ConfiguredTargetsOnly,

    [bool]$ScanDomainControllers,

    [string[]]$DomainControllerDiscoveryServers,

    [Alias('AdditionalArchiveTargets')]
    [string[]]$AdditionalExchangeServers,

    [string[]]$SummaryMailTo,

    [string]$SummaryMailFrom,

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
        $configuredValue = [System.Management.Automation.SwitchParameter][bool]$configuredValue
    }

    Set-Variable -Name $ParameterName -Scope Script -Value $configuredValue
    $script:EventLogArchiveConfiguredParameters[$ParameterName] = $true
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

        Write-Verbose "Configuration file '$Path' was not found. Using runtime defaults and command-line parameters."
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

function Test-EventLogArchiveParameterResolved {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    if ($BoundParameters.ContainsKey($ParameterName)) {
        return $true
    }

    return ($script:EventLogArchiveConfiguredParameters -is [hashtable] -and
        $script:EventLogArchiveConfiguredParameters.ContainsKey($ParameterName))
}

function Set-EventLogArchiveRuntimeDefaults {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'WWWOutputFilePatterns')) {
        $script:WWWOutputFilePatterns = @('*')
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'IisLogFilePatterns')) {
        $script:IisLogFilePatterns = @('*.log')
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'ScanDomainControllers')) {
        $script:ScanDomainControllers = $true
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'ComputerName')) {
        $script:ComputerName = @()
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'SecurityAlertTo')) {
        $script:SecurityAlertTo = @()
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'SummaryMailTo')) {
        $script:SummaryMailTo = @()
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'DomainControllerDiscoveryServers')) {
        $script:DomainControllerDiscoveryServers = @()
    }

    if (!(Test-EventLogArchiveParameterResolved -BoundParameters $BoundParameters -ParameterName 'AdditionalExchangeServers')) {
        $script:AdditionalExchangeServers = @()
    }
}

function New-DirectoryIfMissing {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-PathSafely -Path $Path -PathType Container)) {
        if (!$PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            return $true
        }

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

        [string[]]$FailureDetails = @(),

        [long]$BytesReclaimed = 0
    )

    [pscustomobject]@{
        ItemType = $ItemType
        Succeeded = $Succeeded
        Failed = $Failed
        BytesReclaimed = $BytesReclaimed
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
        [string]$ItemType,

        [ref]$ResolvedPath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Warning "Refusing $ItemType because the path is empty."
        return $false
    }

    try {
        $provider = $null
        $drive = $null
        $pathToValidate = $Path

        if ($ExecutionContext.SessionState.Path.IsProviderQualified($Path)) {
            $providerSeparatorIndex = $Path.IndexOf('::', [System.StringComparison]::Ordinal)
            $pathToValidate = $Path.Substring($providerSeparatorIndex + 2)
        }

        if (![System.IO.Path]::IsPathRooted($pathToValidate) -or
            $pathToValidate -match '^[A-Za-z]:[^\\/]' -or
            $pathToValidate -match '^[\\/][^\\/]') {
            Write-Warning "Refusing $ItemType for relative path '$Path'. Use a fully qualified filesystem path."
            return $false
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path,
            [ref]$provider,
            [ref]$drive
        )

        if ($provider.Name -ne 'FileSystem') {
            Write-Warning "Refusing $ItemType for non-filesystem path '$Path'."
            return $false
        }

        $fullPath = [System.IO.Path]::GetFullPath($fullPath)
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

    if ($PSBoundParameters.ContainsKey('ResolvedPath')) {
        $ResolvedPath.Value = $fullPath
    }

    return $true
}

function Get-AvailableArchivePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DesiredPath
    )

    if (!(Test-Path -LiteralPath $DesiredPath)) {
        return $DesiredPath
    }

    $directoryPath = [System.IO.Path]::GetDirectoryName($DesiredPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($DesiredPath)
    $extension = [System.IO.Path]::GetExtension($DesiredPath)

    for ($suffix = 1; $suffix -lt [int]::MaxValue; $suffix++) {
        $candidatePath = Join-Path $directoryPath ("{0}.{1}{2}" -f $baseName, $suffix, $extension)
        if (!(Test-Path -LiteralPath $candidatePath)) {
            return $candidatePath
        }
    }

    throw "Unable to select an unused archive destination for '$DesiredPath'."
}

function Get-StreamSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()

    try {
        $hashBytes = $sha256.ComputeHash($Stream)
    }
    finally {
        $sha256.Dispose()
    }

    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
}

function Test-ArchiveZipEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,

        [Parameter(Mandatory = $true)]
        [string]$EntryName,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)

    try {
        $entry = $archive.Entries |
            Where-Object { [string]::Equals($_.FullName, $EntryName, [System.StringComparison]::Ordinal) } |
            Select-Object -First 1

        if ($null -eq $entry) {
            return $false
        }

        $entryStream = $entry.Open()
        try {
            $entryHash = Get-StreamSha256 -Stream $entryStream
        }
        finally {
            $entryStream.Dispose()
        }

        return [string]::Equals($entryHash, $ExpectedHash, [System.StringComparison]::OrdinalIgnoreCase)
    }
    finally {
        $archive.Dispose()
    }
}

function Compress-ArchivedEventLog {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    $succeeded = 0
    $failed = 0
    $bytesReclaimed = [long]0
    $failureDetails = @()
    $publishedPath = $null
    $temporaryPath = Join-Path $File.DirectoryName ('.{0}.{1}.tmp.zip' -f $File.BaseName, [guid]::NewGuid().ToString('N'))
    $desiredPath = Join-Path $File.DirectoryName "$($File.BaseName).zip"

    if (!$PSCmdlet.ShouldProcess($File.FullName, "Compress event log and remove the source")) {
        return [pscustomobject]@{
            Succeeded = $succeeded
            Failed = $failed
            BytesReclaimed = $bytesReclaimed
            FailureDetails = $failureDetails
            DestinationPath = $publishedPath
        }
    }

    try {
        $originalLength = $File.Length
        $sourceStream = [System.IO.File]::OpenRead($File.FullName)
        try {
            $sourceHash = Get-StreamSha256 -Stream $sourceStream
        }
        finally {
            $sourceStream.Dispose()
        }

        Compress-Archive -LiteralPath $File.FullName -DestinationPath $temporaryPath -ErrorAction Stop

        if (!(Test-ArchiveZipEntry -ZipPath $temporaryPath -EntryName $File.Name -ExpectedHash $sourceHash)) {
            throw "ZIP verification failed for '$temporaryPath'."
        }

        $publishedPath = Get-AvailableArchivePath -DesiredPath $desiredPath
        Move-Item -LiteralPath $temporaryPath -Destination $publishedPath -ErrorAction Stop
        $compressedLength = (Get-Item -LiteralPath $publishedPath -ErrorAction Stop).Length
        Remove-Item -LiteralPath $File.FullName -Force -Confirm:$false -ErrorAction Stop
        $succeeded = 1
        $bytesReclaimed = [math]::Max(($originalLength - $compressedLength), 0)
    }
    catch {
        $failed = 1
        $failureDetails = @("Unable to safely compress or clean up '$($File.FullName)'. Error: $($_.Exception.Message)")
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }

    [pscustomobject]@{
        Succeeded = $succeeded
        Failed = $failed
        BytesReclaimed = $bytesReclaimed
        FailureDetails = $failureDetails
        DestinationPath = $publishedPath
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
    [CmdletBinding(SupportsShouldProcess = $true)]
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
    $expiredBytesReclaimed = [long]0
    $expiredFailureDetails = [System.Collections.Generic.List[string]]::new()
    $moveFailureDetails = [System.Collections.Generic.List[string]]::new()

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -le $OlderThan } |
        ForEach-Object {
            $file = $_
            if (!$PSCmdlet.ShouldProcess($file.FullName, "Remove expired archived $LogName event log")) {
                return
            }

            try {
                $fileLength = $file.Length
                Write-Output "Removing expired archived $LogName event log '$($file.FullName)'."
                Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
                $expiredSucceeded++
                $expiredBytesReclaimed += $fileLength
            }
            catch {
                $expiredFailed++
                Add-ArchiveFailureDetail -FailureDetails $expiredFailureDetails -Message "Unable to remove expired $LogName event log '$($file.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    Get-ChildItem -LiteralPath $eventLogDirectory -Filter "Archive-$LogName*.evtx" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $OlderThan } |
        ForEach-Object {
            $file = $_
            $desiredDestination = Join-Path $DestinationPath $file.Name
            $destination = Get-AvailableArchivePath -DesiredPath $desiredDestination

            if (!$PSCmdlet.ShouldProcess($file.FullName, "Move archived $LogName event log to '$destination'")) {
                return
            }

            try {
                Move-Item -LiteralPath $file.FullName -Destination $destination -Verbose -ErrorAction Stop
                $moveSucceeded++
            }
            catch {
                $moveError = $_.Exception.Message
                Write-Warning "Move failed for '$($file.FullName)', attempting copy. Error: $moveError"
                try {
                    if (!$PSCmdlet.ShouldProcess($file.FullName, "Copy archived $LogName event log to '$destination' and remove the source")) {
                        return
                    }

                    Copy-Item -LiteralPath $file.FullName -Destination $destination -ErrorAction Stop
                    Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -ErrorAction Stop
                    Write-Output "Copied and removed '$($file.FullName)' to '$destination'."
                    $moveSucceeded++
                }
                catch {
                    $moveFailed++
                    Add-ArchiveFailureDetail -FailureDetails $moveFailureDetails -Message "Copy fallback also failed for $LogName event log '$($file.FullName)'. Error: $($_.Exception.Message)"
                }
            }
        }

    @(
        ConvertTo-ArchiveOperationMetric -ItemType "$LogName expired archive cleanup" -Succeeded $expiredSucceeded -Failed $expiredFailed -FailureDetails $expiredFailureDetails -BytesReclaimed $expiredBytesReclaimed
        ConvertTo-ArchiveOperationMetric -ItemType "$LogName archive relocation" -Succeeded $moveSucceeded -Failed $moveFailed -FailureDetails $moveFailureDetails
    )
}

function Move-OtherArchivedEventLogs {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [datetime]$OlderThan,

        [string[]]$ExcludedLogNames = @('Security', 'Application', 'System')
    )

    $eventLogDirectory = Resolve-EventLogDirectory -LogName 'Security'
    Write-Output "Checking other archived event logs in '$eventLogDirectory'."
    $expiredSucceeded = 0
    $expiredFailed = 0
    $moveSucceeded = 0
    $moveFailed = 0
    $expiredBytesReclaimed = [long]0
    $expiredFailureDetails = [System.Collections.Generic.List[string]]::new()
    $moveFailureDetails = [System.Collections.Generic.List[string]]::new()
    $excludedFilePatterns = @($ExcludedLogNames | ForEach-Object { "Archive-$_.evtx"; "Archive-$_-*.evtx" })

    $otherArchivedLogs = @(
        Get-ChildItem -LiteralPath $eventLogDirectory -Filter 'Archive-*.evtx' -File -ErrorAction SilentlyContinue |
            Where-Object {
                $fileName = $_.Name
                !($excludedFilePatterns | Where-Object { $fileName -like $_ })
            }
    )

    $otherArchivedLogs |
        Where-Object { $_.LastWriteTime -le $OlderThan } |
        ForEach-Object {
            $file = $_
            if (!$PSCmdlet.ShouldProcess($file.FullName, 'Remove expired archived event log')) {
                return
            }

            try {
                $fileLength = $file.Length
                Write-Output "Removing expired archived event log '$($file.FullName)'."
                Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
                $expiredSucceeded++
                $expiredBytesReclaimed += $fileLength
            }
            catch {
                $expiredFailed++
                Add-ArchiveFailureDetail -FailureDetails $expiredFailureDetails -Message "Unable to remove expired other event log '$($file.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    $otherArchivedLogs |
        Where-Object { $_.LastWriteTime -gt $OlderThan } |
        ForEach-Object {
            $file = $_
            $desiredDestination = Join-Path $DestinationPath $file.Name
            $destination = Get-AvailableArchivePath -DesiredPath $desiredDestination

            if (!$PSCmdlet.ShouldProcess($file.FullName, "Move archived event log to '$destination'")) {
                return
            }

            try {
                Move-Item -LiteralPath $file.FullName -Destination $destination -Verbose -ErrorAction Stop
                $moveSucceeded++
            }
            catch {
                $moveError = $_.Exception.Message
                Write-Warning "Move failed for '$($file.FullName)', attempting copy. Error: $moveError"
                try {
                    if (!$PSCmdlet.ShouldProcess($file.FullName, "Copy archived event log to '$destination' and remove the source")) {
                        return
                    }

                    Copy-Item -LiteralPath $file.FullName -Destination $destination -ErrorAction Stop
                    Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -ErrorAction Stop
                    Write-Output "Copied and removed '$($file.FullName)' to '$destination'."
                    $moveSucceeded++
                }
                catch {
                    $moveFailed++
                    Add-ArchiveFailureDetail -FailureDetails $moveFailureDetails -Message "Copy fallback also failed for other event log '$($file.FullName)'. Error: $($_.Exception.Message)"
                }
            }
        }

    @(
        ConvertTo-ArchiveOperationMetric -ItemType 'Other expired archive cleanup' -Succeeded $expiredSucceeded -Failed $expiredFailed -FailureDetails $expiredFailureDetails -BytesReclaimed $expiredBytesReclaimed
        ConvertTo-ArchiveOperationMetric -ItemType 'Other archive relocation' -Succeeded $moveSucceeded -Failed $moveFailed -FailureDetails $moveFailureDetails
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
    [CmdletBinding(SupportsShouldProcess = $true)]
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
    $bytesReclaimed = [long]0
    $failureDetails = [System.Collections.Generic.List[string]]::new()

    $resolvedCleanupPath = $null
    if (!(Test-CleanupPathSafety -Path $Path -ItemType $ItemType -ResolvedPath ([ref]$resolvedCleanupPath))) {
        $failed++
        $failureDetails.Add("Skipped unsafe cleanup path '$Path'.")
        return ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails
    }

    if (!(Test-PathSafely -Path $resolvedCleanupPath -PathType Container)) {
        Write-Output "Skipping missing cleanup path '$resolvedCleanupPath'."
        return ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails
    }

    Write-Output "Removing files older than $RetentionDays days from '$resolvedCleanupPath'."

    Get-ChildItem -LiteralPath $resolvedCleanupPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $file = $_
            ($file.LastWriteTime -le $OlderThan) -and
                ($Patterns | Where-Object { $file.Name -like $_ })
        } |
        ForEach-Object {
            if (!$PSCmdlet.ShouldProcess($_.FullName, "Remove $ItemType item")) {
                return
            }

            try {
                $fileLength = $_.Length
                Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -Verbose -ErrorAction Stop
                $succeeded++
                $bytesReclaimed += $fileLength
            }
            catch {
                $failed++
                Add-ArchiveFailureDetail -FailureDetails $failureDetails -Message "Unable to remove old file '$($_.FullName)'. Error: $($_.Exception.Message)"
            }
        }

    ConvertTo-ArchiveOperationMetric -ItemType $ItemType -Succeeded $succeeded -Failed $failed -FailureDetails $failureDetails -BytesReclaimed $bytesReclaimed
}

function Test-SecurityLogFreshness {
    [CmdletBinding(SupportsShouldProcess = $true)]
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
        $mailSettingsAvailable = (@($AlertTo | Where-Object { ![string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -and
            ![string]::IsNullOrWhiteSpace($MailFrom) -and
            ![string]::IsNullOrWhiteSpace($MailServer))
        $alerts = @()

        if ($lastSecLog.Id -eq 521) {
            $alerts += [pscustomobject]@{
                Subject = "Unable to log events to security log on $($env:COMPUTERNAME)"
                Body = "Unable to log events to security log on $($env:COMPUTERNAME)`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($PSCommandPath)"
            }
        }

        if ($lastSecLog.TimeCreated -lt ((Get-Date).AddMinutes(-15))) {
            $alerts += [pscustomobject]@{
                Subject = "Check Security Logs on $($env:COMPUTERNAME)"
                Body = "Latest Security Log written more than 15 minutes ago`n$($lastSecLog | Format-List | Out-String) `n`nServer: $($env:COMPUTERNAME)`nScript: $($PSCommandPath)"
            }
        }

        foreach ($alert in $alerts) {
            if ($mailSettingsAvailable) {
                if ($PSCmdlet.ShouldProcess(($AlertTo -join ', '), "Send security log alert '$($alert.Subject)'")) {
                    Send-MailMessage -To $AlertTo -Subject $alert.Subject -Body $alert.Body -From $MailFrom -SmtpServer $MailServer
                }
            }
            else {
                Write-Warning "Security log alert '$($alert.Subject)' was not sent because SecurityAlertTo, SecurityMailFrom, or SmtpServer is not configured."
            }
        }
    }
    catch {
        Write-Warning "Unable to check the latest Security event log entry. Error: $($_.Exception.Message)"
    }
}

function Invoke-LocalArchive {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

    $resolvedArchiveRoot = $null
    if (!(Test-CleanupPathSafety -Path $EventLogArchiveRoot -ItemType 'event log archive root' -ResolvedPath ([ref]$resolvedArchiveRoot))) {
        throw "Event log archive root '$EventLogArchiveRoot' is not safe to use."
    }
    $EventLogArchiveRoot = $resolvedArchiveRoot

    if ([string]::IsNullOrWhiteSpace($TranscriptDirectory) -and ![string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $TranscriptDirectory = Join-Path $PSScriptRoot 'logs'
    }

    $securityArchivePath = Join-Path $EventLogArchiveRoot 'Sec_Logs'
    $applicationArchivePath = Join-Path $EventLogArchiveRoot 'App_Logs'
    $systemArchivePath = Join-Path $EventLogArchiveRoot 'Sys_Logs'
    $otherArchivePath = Join-Path $EventLogArchiveRoot 'Other_Logs'
    $transcriptStarted = $false

    try {
        if (![string]::IsNullOrWhiteSpace($TranscriptDirectory)) {
            $resolvedTranscriptDirectory = $null
            if ((Test-CleanupPathSafety -Path $TranscriptDirectory -ItemType 'transcript directory' -ResolvedPath ([ref]$resolvedTranscriptDirectory)) -and
                (New-DirectoryIfMissing -Path $resolvedTranscriptDirectory)) {
                $TranscriptDirectory = $resolvedTranscriptDirectory
                if (!$WhatIfPreference) {
                    $transcriptPath = Join-Path $TranscriptDirectory "EvtLogArchTranscript_$(Get-Date -Format yyyyMMdd).txt"
                    Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
                    $transcriptStarted = $true
                }
            }
        }

        Write-Output "Starting local event log archive and cleanup on $($env:COMPUTERNAME)."

        $directorySucceeded = 0
        $directoryFailed = 0
        $directoryFailureDetails = [System.Collections.Generic.List[string]]::new()
        foreach ($directoryPath in @($EventLogArchiveRoot, $securityArchivePath, $applicationArchivePath, $systemArchivePath, $otherArchivePath)) {
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
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Move-OtherArchivedEventLogs -DestinationPath $otherArchivePath -OlderThan $datechk)

        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'Archive zip retention cleanup' -Patterns @('*.zip'))
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $EventLogArchiveRoot -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'Archive evtx retention cleanup' -Patterns @('*.evtx'))

        $compressionSucceeded = 0
        $compressionFailed = 0
        $compressionBytesReclaimed = [long]0
        $compressionFailureDetails = [System.Collections.Generic.List[string]]::new()
        $resolvedCompressionRoot = $null
        if (Test-CleanupPathSafety -Path $EventLogArchiveRoot -ItemType 'Archive compression' -ResolvedPath ([ref]$resolvedCompressionRoot)) {
            $evtxFiles = Get-ChildItem -LiteralPath $resolvedCompressionRoot -Filter *.evtx -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $evtxFiles) {
                if (!(Test-Path -LiteralPath $file.FullName -PathType Leaf)) {
                    continue
                }

                $compressionResult = Compress-ArchivedEventLog -File $file
                $compressionSucceeded += $compressionResult.Succeeded
                $compressionFailed += $compressionResult.Failed
                $compressionBytesReclaimed += $compressionResult.BytesReclaimed
                if ($compressionResult.Succeeded -gt 0) {
                    Write-Output "Compressed '$($file.FullName)' to '$($compressionResult.DestinationPath)'."
                }
                foreach ($failureDetail in @($compressionResult.FailureDetails)) {
                    Add-ArchiveFailureDetail -FailureDetails $compressionFailureDetails -Message $failureDetail
                }
            }
        }
        else {
            $compressionFailed++
            $compressionFailureDetails.Add("Skipped unsafe archive compression path '$EventLogArchiveRoot'.")
        }
        Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (ConvertTo-ArchiveOperationMetric -ItemType 'Archive compression' -Succeeded $compressionSucceeded -Failed $compressionFailed -FailureDetails $compressionFailureDetails -BytesReclaimed $compressionBytesReclaimed)

        foreach ($iisLogDirectory in (Get-IisLogDirectories)) {
            Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $iisLogDirectory -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'IIS log cleanup' -Patterns $IisLogFilePatterns)
        }

        if (![string]::IsNullOrWhiteSpace($WWWOutputPath)) {
            Add-ArchiveOperationMetric -Metrics $operationMetrics -Metric (Remove-OldFiles -Path $WWWOutputPath -OlderThan $datechk -RetentionDays $RetentionDays -ItemType 'WWWOutput cleanup' -Patterns $WWWOutputFilePatterns)
        }

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

function Get-ArchiveMetricByteTotal {
    param(
        [object[]]$Metrics
    )

    $sum = ($Metrics | Where-Object { $_.PSObject.Properties['BytesReclaimed'] } | Measure-Object -Property BytesReclaimed -Sum).Sum
    if ($null -eq $sum) {
        return [long]0
    }

    return [long]$sum
}

function Format-ArchiveByteSize {
    param(
        [long]$Bytes
    )

    if ($Bytes -le 0) {
        return '-'
    }

    $units = @('B', 'KB', 'MB', 'GB', 'TB')
    $value = [double]$Bytes
    $unitIndex = 0
    while ($value -ge 1024 -and $unitIndex -lt ($units.Count - 1)) {
        $value = $value / 1024
        $unitIndex++
    }

    if ($unitIndex -eq 0) {
        return "$Bytes B"
    }

    return ('{0:N1} {1}' -f $value, $units[$unitIndex])
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

function Get-ArchiveMetricGroupName {
    param(
        [string]$ItemType
    )

    if ($ItemType -eq 'Directory setup') {
        return 'Setup'
    }

    if ($ItemType -like '* archive relocation') {
        return 'Archive moves'
    }

    if ($ItemType -like '* expired archive cleanup' -or $ItemType -like 'Archive * retention cleanup') {
        return 'Archive cleanup'
    }

    if ($ItemType -eq 'Archive compression') {
        return 'Compression'
    }

    if ($ItemType -eq 'IIS log cleanup' -or $ItemType -eq 'WWWOutput cleanup') {
        return 'Web cleanup'
    }

    return 'Other'
}

function Get-ArchiveMetricGroupTotal {
    param(
        [object[]]$Metrics,

        [Parameter(Mandatory = $true)]
        [string[]]$GroupName,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $matchingMetrics = @(
        $Metrics |
            Where-Object {
                $metricGroupName = Get-ArchiveMetricGroupName -ItemType $_.ItemType
                $GroupName -contains $metricGroupName
            }
    )

    Get-ArchiveMetricTotal -Metrics $matchingMetrics -PropertyName $PropertyName
}

function ConvertTo-ArchiveReportCellHtml {
    param(
        [int]$Succeeded,

        [int]$Failed
    )

    if ($Succeeded -eq 0 -and $Failed -eq 0) {
        return '<span style="color:#64748b;">-</span>'
    }

    return "<span style=""color:#0f7a35;font-weight:600;"">$Succeeded ok</span> <span style=""color:#b42318;font-weight:600;"">$Failed failed</span>"
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

    $summaryColumns = @(
        @{ Header = 'Setup'; Groups = @('Setup') }
        @{ Header = 'Archive moves'; Groups = @('Archive moves') }
        @{ Header = 'Archive cleanup'; Groups = @('Archive cleanup') }
        @{ Header = 'Compression'; Groups = @('Compression') }
        @{ Header = 'Web cleanup'; Groups = @('Web cleanup') }
    )

    $hasOtherMetrics = @(
        $operationSummaries |
            ForEach-Object { @($_.Metrics) } |
            Where-Object { (Get-ArchiveMetricGroupName -ItemType $_.ItemType) -eq 'Other' }
    ).Count -gt 0
    if ($hasOtherMetrics) {
        $summaryColumns += @{ Header = 'Other'; Groups = @('Other') }
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#1f2933;">')
    [void]$builder.AppendLine("<p><strong>Event log archive run:</strong> $(ConvertTo-HtmlEncodedText $RunDate)<br />")
    [void]$builder.AppendLine("<strong>Controller:</strong> $(ConvertTo-HtmlEncodedText $Controller)<br />")
    [void]$builder.AppendLine("<strong>Status:</strong> $(ConvertTo-HtmlEncodedText $statusText)</p>")

    if ($operationSummaries.Count -gt 0) {
        [void]$builder.AppendLine('<table cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#cbd5e1;">')
        [void]$builder.Append('<tr style="background:#f1f5f9;"><th align="left">Machine</th>')
        foreach ($summaryColumn in $summaryColumns) {
            [void]$builder.Append("<th align=""left"">$(ConvertTo-HtmlEncodedText $summaryColumn['Header'])</th>")
        }
        [void]$builder.Append('<th align="left">Total</th>')
        [void]$builder.Append('<th align="left">Space freed</th>')
        [void]$builder.AppendLine('</tr>')

        foreach ($summary in ($operationSummaries | Sort-Object ComputerName)) {
            [void]$builder.Append("<tr><td><strong>$(ConvertTo-HtmlEncodedText $summary.ComputerName)</strong></td>")
            foreach ($summaryColumn in $summaryColumns) {
                $succeeded = Get-ArchiveMetricGroupTotal -Metrics $summary.Metrics -GroupName $summaryColumn['Groups'] -PropertyName 'Succeeded'
                $failed = Get-ArchiveMetricGroupTotal -Metrics $summary.Metrics -GroupName $summaryColumn['Groups'] -PropertyName 'Failed'
                [void]$builder.Append("<td>$(ConvertTo-ArchiveReportCellHtml -Succeeded $succeeded -Failed $failed)</td>")
            }

            $totalSucceeded = Get-ArchiveMetricTotal -Metrics $summary.Metrics -PropertyName 'Succeeded'
            $totalFailed = Get-ArchiveMetricTotal -Metrics $summary.Metrics -PropertyName 'Failed'
            $totalBytesReclaimed = Get-ArchiveMetricByteTotal -Metrics $summary.Metrics
            [void]$builder.Append("<td>$(ConvertTo-ArchiveReportCellHtml -Succeeded $totalSucceeded -Failed $totalFailed)</td>")
            [void]$builder.Append("<td>$(ConvertTo-HtmlEncodedText (Format-ArchiveByteSize -Bytes $totalBytesReclaimed))</td>")
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [bool]$Local = $true,

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

    $resolvedLogDirectory = $null
    if (!(Test-CleanupPathSafety -Path $LogDirectory -ItemType 'remote log directory' -ResolvedPath ([ref]$resolvedLogDirectory))) {
        throw "Remote log directory '$LogDirectory' is not safe to use."
    }
    $LogDirectory = $resolvedLogDirectory

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
            [string]$SmtpServer,
            [bool]$WhatIf
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

        if ($WhatIf) {
            $parameters.WhatIf = $true
        }

        & $worker @parameters
    }

    try {
        if (!$WhatIfPreference) {
            Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop
            $transcriptStarted = $true
        }

        if ($Local) {
            $localResults = @(Invoke-LocalArchive `
                -RetentionDays $RetentionDays `
                -EventLogArchiveRoot $EventLogArchiveRoot `
                -WWWOutputPath $WWWOutputPath `
                -WWWOutputFilePatterns $WWWOutputFilePatterns `
                -IisLogFilePatterns $IisLogFilePatterns `
                -SkipSecurityLogCheck:$SkipSecurityLogCheck `
                -SecurityAlertTo $SecurityAlertTo `
                -SecurityMailFrom $SecurityMailFrom `
                -SmtpServer $SmtpServer `
                -EmitOperationSummary)

            $operationSummaries = @($localResults | Where-Object { $_.PSObject.Properties['RecordType'] -and $_.RecordType -eq 'EventLogArchiveOperationSummary' })
            $localResults |
                Where-Object { !($_.PSObject.Properties['RecordType'] -and $_.RecordType -eq 'EventLogArchiveOperationSummary') } |
                ForEach-Object { Write-Output $_ }
        }

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
            ([bool]$WhatIfPreference)
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
        $operationSummaries = @($operationSummaries) + @($results | Where-Object { $_.PSObject.Properties['RecordType'] -and $_.RecordType -eq 'EventLogArchiveOperationSummary' })
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
        if (!$WhatIfPreference) {
            $resultLines | Set-Content -Path $resultPath
        }
    }
    catch {
        $remoteRunFailed = $true
        $remoteErrors.Add($_.Exception.Message)
        Write-Warning "Remote archive run failed before completion. Error: $($_.Exception.Message)"

        try {
            if (!$WhatIfPreference) {
                @(
                    "Remote event log archive run failed: $runDate"
                    "Controller: $($env:COMPUTERNAME)"
                    "Error: $($_.Exception.Message)"
                ) | Set-Content -Path $resultPath
            }
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

    if ($WhatIfPreference) {
        if ($remoteRunFailed) {
            throw 'Remote archive WhatIf run failed before completion.'
        }

        return
    }

    $summaryMailSettingsAvailable = (@($SummaryMailTo | Where-Object { ![string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -and
        ![string]::IsNullOrWhiteSpace($SummaryMailFrom) -and
        ![string]::IsNullOrWhiteSpace($SmtpServer))

    if ($summaryMailSettingsAvailable) {
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
    }
    else {
        Write-Warning "Remote archive summary email was not sent because SummaryMailTo, SummaryMailFrom, or SmtpServer is not configured."
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

$script:EventLogArchiveConfiguredParameters = @{}
$configurationLoaded = $false
if ($Remote -and $SkipConfig) {
    throw "Remote mode cannot be used with -SkipConfig. Copy 'EventLogArchiving.config.sample.psd1' to 'EventLogArchiving.config.psd1' and update it, or pass -ConfigPath with a configured psd1 file."
}

if (!$SkipConfig) {
    $configurationLoaded = Import-EventLogArchiveConfiguration -Path $ConfigPath -BoundParameters $PSBoundParameters
}

Set-EventLogArchiveRuntimeDefaults -BoundParameters $PSBoundParameters

if ($Remote -and !$configurationLoaded) {
    $defaultConfigPath = Resolve-DefaultConfigPath
    throw "Remote mode requires a configuration file. Copy 'EventLogArchiving.config.sample.psd1' to '$defaultConfigPath' and update it, or pass -ConfigPath with a configured psd1 file."
}

if ($Remote) {
    if ($DomainControllersOnly -and $ConfiguredTargetsOnly) {
        throw "Use either -DomainControllersOnly or -ConfiguredTargetsOnly, not both."
    }

    if ($DomainControllersOnly) {
        if ($PSBoundParameters.ContainsKey('ComputerName') -or $PSBoundParameters.ContainsKey('AdditionalExchangeServers')) {
            throw "-DomainControllersOnly cannot be combined with explicit -ComputerName or -AdditionalArchiveTargets values."
        }

        if ($AdditionalExchangeServers.Count -gt 0) {
            Write-Warning "-DomainControllersOnly is ignoring $($AdditionalExchangeServers.Count) configured static target(s) for this run."
        }

        $ComputerName = @()
        $AdditionalExchangeServers = @()
        $ScanDomainControllers = $true
    }
    elseif ($ConfiguredTargetsOnly) {
        $ScanDomainControllers = $false
    }
}

if ($Remote) {
    Invoke-RemoteArchive `
        -Local $Local `
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
elseif ($Local) {
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
