@{
    RetentionDays = 30

    Paths = @{
        EventLogArchiveRoot = $null
        WWWOutputPath = 'E:\WWWOutput'
        TranscriptDirectory = $null
        LogDirectory = $null
    }

    Cleanup = @{
        WWWOutputFilePatterns = @('*')
        IisLogFilePatterns = @('*.log')
        SkipSecurityLogCheck = $false
    }

    Mail = @{
        SmtpServer = 'mailhost.analog.com'
        SecurityAlertTo = @('michael.coelho@analog.com')
        SecurityMailFrom = 'svc_scriptadm@analog.com'
        SummaryMailTo = @('michael.coelho@analog.com')
        SummaryMailFrom = 'michael.coelho@analog.com'
    }

    Remote = @{
        ComputerName = @()
        ThrottleLimit = 10
        TimeoutSeconds = 39600
        ExpectedScriptHash = $null
        SkipRemoteIntegrityCheck = $false
        AdditionalArchiveTargets = @(
            'ashbmbx9.ad.analog.com'
            'ashbmbx8.ad.analog.com'
            'scsqmbx10.ad.analog.com'
            'scsqmbx11.ad.analog.com'
            'ashbmbxtest1.ad.analog.com'
            'ASHBCASHYB4.ad.analog.com'
            'ASHBCASHYB5.ad.analog.com'
            'scsqcashyb7.ad.analog.com'
            'scsqcashyb6.ad.analog.com'
        )
    }

    Discovery = @{
        ScanDomainControllers = $true
        DomainControllerDiscoveryServers = @(
            'ashbfdc1.winroot.analog.com'
        )
    }
}
