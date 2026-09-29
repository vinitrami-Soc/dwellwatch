<#
.SYNOPSIS
    Install or reconfigure Sysmon on the lab VM with DwellWatch's configuration.

.DESCRIPTION
    Downloads Sysmon from Sysinternals, refuses to run it unless it carries a valid Microsoft
    signature, and installs it with lab/sysmon/dwellwatch-sysmon.xml (Vagrant copies it to
    C:\DwellWatch first). Sysinternals serves only the current release, so the version installed
    is printed for the run notes in atomics/ rather than pinned. Run as Administrator.
#>
param(
    [string]$Config = "C:\DwellWatch\dwellwatch-sysmon.xml"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $Config)) { throw "Sysmon configuration not found at $Config" }

$work = "C:\DwellWatch\sysmon"
New-Item -ItemType Directory -Path $work -Force | Out-Null
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip" -UseBasicParsing
Expand-Archive -Path "$work\Sysmon.zip" -DestinationPath $work -Force

$sysmon = Join-Path $work "Sysmon64.exe"
$signature = Get-AuthenticodeSignature -FilePath $sysmon
if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
    throw "Sysmon64.exe is not validly signed by Microsoft ($($signature.Status)); not installing it"
}

if (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue) {
    & $sysmon -c $Config | Out-Null
} else {
    & $sysmon -accepteula -i $Config | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon did not accept $Config (exit $LASTEXITCODE)" }

# 1 GB, like the Security log.
& wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824
if ($LASTEXITCODE -ne 0) { throw "wevtutil could not resize the Sysmon log" }

$version = (Get-Item $sysmon).VersionInfo.FileVersion
Write-Output "Sysmon $version installed with $Config"
