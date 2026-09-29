<#
.SYNOPSIS
    Export the lab VM's Sysmon and Security logs as event XML for DwellWatch's replay engine.

.DESCRIPTION
    Writes one file per log into a new folder under -Destination, named for the export time.
    The default destination, C:\vagrant\exports, is the lab/ folder on the host (Vagrant shares
    it), so the files arrive where `python -m dwellwatch.correlate` can read them:

        python -m dwellwatch.correlate lab/exports/<time>/*.xml

    -Since limits the export to events after that time, for example the start of a run.
#>
param(
    [string]$Destination = "C:\vagrant\exports",
    [datetime]$Since = [datetime]::MinValue
)
$ErrorActionPreference = "Stop"

$folder = Join-Path $Destination (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Path $folder -Force | Out-Null

$logs = [ordered]@{
    "Microsoft-Windows-Sysmon/Operational" = "sysmon.xml"
    "Security"                             = "security.xml"
}
$query = "*"
if ($Since -gt [datetime]::MinValue) {
    $query = "*[System[TimeCreated[@SystemTime>='{0}']]]" -f $Since.ToUniversalTime().ToString("o")
}

foreach ($log in $logs.Keys) {
    $file = Join-Path $folder $logs[$log]
    # /e:Events wraps the records in one root element; replay reads them an <Event> at a time.
    $xml = & wevtutil.exe qe $log "/q:$query" /f:xml /e:Events
    if ($LASTEXITCODE -ne 0) { throw "wevtutil could not export $log" }
    [System.IO.File]::WriteAllLines($file, [string[]]$xml, (New-Object System.Text.UTF8Encoding $false))
    $count = ([regex]::Matches(($xml -join "`n"), "<Event[ >]")).Count
    Write-Output ("{0}: {1} events -> {2}" -f $log, $count, $file)
}
