<#
.SYNOPSIS
    Turn on the Windows Security auditing DwellWatch's rules read, on the lab VM.

.DESCRIPTION
    Subcategories are set by GUID, so this works whatever the display language of Windows.
    Each is listed with the events DwellWatch reads from it. Run as Administrator; Vagrant does.
#>
$ErrorActionPreference = "Stop"

$subcategories = [ordered]@{
    "{0CCE922B-69AE-11D9-BED3-505054503030}" = "Process Creation: 4688"
    "{0CCE9235-69AE-11D9-BED3-505054503030}" = "User Account Management: 4720, 4724, 4738"
    "{0CCE9237-69AE-11D9-BED3-505054503030}" = "Security Group Management: 4728, 4732, 4756"
    "{0CCE9215-69AE-11D9-BED3-505054503030}" = "Logon: 4624, 4625"
    "{0CCE921B-69AE-11D9-BED3-505054503030}" = "Special Logon: 4672"
    "{0CCE923F-69AE-11D9-BED3-505054503030}" = "Credential Validation: 4776"
    # Only a domain controller writes these; harmless elsewhere, and ready if a DC joins the lab.
    "{0CCE923B-69AE-11D9-BED3-505054503030}" = "Directory Service Access: 4662"
}

foreach ($guid in $subcategories.Keys) {
    & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol could not enable $($subcategories[$guid])"
    }
    Write-Output "audit on: $($subcategories[$guid])"
}

# Let the subcategories above win over the older, coarser category settings.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

# Record the command line in 4688, which the process creation rules need when Sysmon is absent.
$audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $audit -Force | Out-Null
Set-ItemProperty -Path $audit -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# 1 GB of Security log, so a week of lab activity is still there when it is exported.
& wevtutil.exe sl Security /ms:1073741824
if ($LASTEXITCODE -ne 0) { throw "wevtutil could not resize the Security log" }
Write-Output "Security log: 1 GB"
