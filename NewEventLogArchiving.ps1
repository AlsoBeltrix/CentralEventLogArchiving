$scriptBlock =  {

# Setup archive directories
    if (!(Test-Path $env:SystemDrive\Evt_Logs)) { New-Item $env:SystemDrive\Evt_Logs -ItemType Directory }
    if (!(Test-Path $env:SystemDrive\Evt_Logs\Sec_Logs)) { New-Item $env:SystemDrive\Evt_Logs\Sec_Logs -ItemType Directory }
    if (!(Test-Path $env:SystemDrive\Evt_Logs\App_Logs)) { New-Item $env:SystemDrive\Evt_Logs\App_Logs -ItemType Directory }
    if (!(Test-Path $env:SystemDrive\Evt_Logs\Sys_Logs)) { New-Item $env:SystemDrive\Evt_Logs\Sys_Logs -ItemType Directory }

<# Check for logging issues / small log files
    $SmallLogs  = Get-ChildItem $env:SystemRoot\system32\Winevt\Logs\Archive-Security* | ?{$_.Length -lt "1000000"}
    $SmallLogs += Get-ChildItem $env:SystemDrive\Evt_Logs\Sec_Logs\*.zip | ?{$_.Length -lt "1000000"}
    if ($SmallLogs) { Send-MailMessage -To Michael.Coelho@analog.com,Jose.Hernandez@analog.com -Subject "Check Security Logs on $($env:COMPUTERNAME)" -Body "$($SmallLogs | Out-String)" -from svc_scriptadm@analog.com -SmtpServer mailhost.analog.com
#>

# Check last security log timestamp
    $lastSecLog = Get-EventLog -LogName security -Newest 1
    if ($lastSecLog.timewritten -lt ((Get-Date).AddMinutes(-15))) {
        Send-MailMessage -To Michael.Coelho@analog.com,Jose.Hernandez@analog.com -Subject "Check Security Logs on $($env:COMPUTERNAME)" -Body "Latest Security Log written more than 15 minutes ago`n$($lastSecLog | out-string)" -from svc_scriptadm@analog.com -SmtpServer mailhost.analog.com
        }

# Move old event log files to the correct archive directory
    Get-ChildItem $env:SystemRoot\system32\Winevt\Logs\Archive-Security* | Move-Item -Destination $env:SystemDrive\Evt_Logs\Sec_Logs -Verbose
    Get-ChildItem $env:SystemRoot\system32\Winevt\Logs\Archive-Application* | Move-Item -Destination $env:SystemDrive\Evt_Logs\App_Logs -Verbose
    Get-ChildItem $env:SystemRoot\system32\Winevt\Logs\Archive-System* | Move-Item -Destination $env:SystemDrive\Evt_Logs\Sys_Logs -Verbose

# Keep 21 days worth of archived logs
# Change 21 to the desired number in the line below
    $datechk = (Get-Date).AddDays(-21)
    Get-ChildItem -Path $env:SystemDrive\Evt_Logs -Recurse -Include *.zip | ? {$_.LastWriteTime -le $datechk} | Remove-Item -Force -Confirm:$false -Verbose

# NTFS Compression
#    compact /C /S /A /I $env:SystemDrive\Evt_Logs\*.evtx

# Zip Compression
    foreach ($file in (gci $env:SystemDrive\Evt_Logs\ -Include *.evtx -Recurse)) {
        Compress-Archive -Path $file -DestinationPath "$($file.Directory)\$($file.BaseName).zip"
        Remove-Item $file -Confirm:$false
        }
    }

# Setup the job
[string] $rundate = Get-Date -Format yyyyMMdd
Start-Transcript D:\Scripts\EventLogArchive\Logs\EvtLogArchTranscript_$rundate.txt
Import-Module ActiveDirectory

# Get a list of ad.analog.com DCs 
$DCs = Get-ADDomainController -Filter * | select -ExpandProperty hostname

# Add winroot.analog.com DCs
$DCs += Get-ADDomainController -Filter * -Server ashbfdc1.winroot.analog.com | select -ExpandProperty hostname

# Add Exchange servers
$DCs += @("ashbmbx9.ad.analog.com","ashbmbx8.ad.analog.com","scsqmbx10.ad.analog.com","scsqmbx11.ad.analog.com","ashbmbxtest1.ad.analog.com","ASHBCASHYB4.ad.analog.com","ASHBCASHYB5.ad.analog.com","scsqcashyb7.ad.analog.com","scsqcashyb6.ad.analog.com")

# Sort the list
$DCs  = $DCs | sort -Descending

# Start the archive process
$jobs = Invoke-Command -AsJob -ScriptBlock $ScriptBlock -ComputerName $DCs -ThrottleLimit 10 -Verbose

# Wait for all jobs to complete
Wait-Job $jobs -Timeout 39600

# Get the results of all jobs
$Results = Receive-Job -Job $jobs 

# Export the results
$Results | Set-Content D:\Scripts\EventLogArchive\Logs\EvtLogArch_$rundate.txt

# Clean up & Email
Stop-Transcript

Compress-Archive -Path D:\Scripts\EventLogArchive\Logs\*.txt -DestinationPath D:\Scripts\EventLogArchive\logs\EvtLogArch_$rundate.zip -CompressionLevel Optimal -Force

Send-MailMessage -To Michael.Coelho@analog.com, Jose.Hernandez@analog.com -From "michael.coelho@analog.com" -Subject "Event Log Archiving Script Output" -Attachments D:\Scripts\EventLogArchive\logs\EvtLogArch_$rundate.zip -Body "See attached `n`nServer: $($env:COMPUTERNAME)`nScript: $($MyInvocation.InvocationName)" -SmtpServer mailhost.analog.com

Stop-Job $jobs
Remove-Job $jobs

gci D:\Scripts\EventLogArchive\Logs\*.txt | remove-item 
Get-ChildItem D:\Scripts\EventLogArchive\Logs -Recurse -Include *.zip | ? {$_.LastWriteTime -le $datechk} | Remove-Item -Force -Confirm:$false -Verbose