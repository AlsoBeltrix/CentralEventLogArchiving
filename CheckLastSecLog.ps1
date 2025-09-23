$scriptBlock =  {
    "Checking $($env:COMPUTERNAME)"
    $lastSecLog = Get-WinEvent -LogName Security -MaxEvents 1
    $lastSecLog2 = Get-EventLog -LogName security -Newest 1
    if (($lastSecLog.TimeCreated -lt ((Get-Date).AddMinutes(-30))) -and ($lastSecLog2.TimeWritten -lt ((Get-Date).AddMinutes(-30)))) {
        $mailParams = @{
            To = @('Michael.Coelho@analog.com','Jose.Hernandez@analog.com','Sudhir.Gulati@analog.com','Venkatesh.MurthyVS@analog.com')
            Subject = "Check Security Logs on $($env:COMPUTERNAME)"
            Body = "Latest Security Log written more than 30 minutes ago`n$($lastSecLog | fl | out-string) `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)"
            From = "svc_scriptadm@analog.com"
            SmtpServer = "mailhost.analog.com"
            }
        }
    if (($lastseclog.Id -eq "521") -or ($lastseclog2.InstanceID -eq "521")) {
        $mailParams = @{
            To = @('Michael.Coelho@analog.com','Jose.Hernandez@analog.com','Sudhir.Gulati@analog.com','Venkatesh.MurthyVS@analog.com','Infosys-Tech@analog.com')
            Subject = "Unable to log events to security log on $($env:COMPUTERNAME)"
            Body = "Unable to log events to security log on $($env:COMPUTERNAME)`n$($lastSecLog | fl | out-string) `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)"
            From = "svc_scriptadm@analog.com"
            SmtpServer = "mailhost.analog.com"
            }
        }

# For Testing Only
<# 
    $testMailParams = @{
        To = @('Michael.Coelho@analog.com')
        Subject = "Last Security log on $($env:COMPUTERNAME)"
        Body = "Last security log on $($env:COMPUTERNAME)`n$($lastSecLog | fl | out-string)"
        From = "svc_scriptadm@analog.com"
        SmtpServer = "mailhost.analog.com"
        }
    Send-MailMessage @testMailParams
#>

    if ($mailParams) {
        Send-MailMessage @mailParams
        } 
    }

Import-Module ActiveDirectory
# Get a list of ad.analog.com DCs 
$DCs = Get-ADDomainController -Filter * | select -ExpandProperty hostname
# Add winroot.analog.com DCs
$DCs += Get-ADDomainController -Filter * -Server ashbfdc1.winroot.analog.com | select -ExpandProperty hostname
# Sort the list
$DCs = $DCs | Sort-Object 

# Run the code on all DCs
$jobs = Invoke-Command -AsJob -ScriptBlock $ScriptBlock -ComputerName $DCs -ThrottleLimit 10 -Verbose

# Wait for all jobs to complete
Wait-Job $jobs -Timeout 900

# Get the results of all jobs
$Results = Receive-Job -Job $jobs 
$Results | select *