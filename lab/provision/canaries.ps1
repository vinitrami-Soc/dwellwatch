<#
.SYNOPSIS
    Create the lab's file share: ordinary dummy documents and the DwellWatch canary files.

.DESCRIPTION
    C:\Shares\Finance holds plain-text files with office-style names, the kind ransomware reaches
    first, and canary documents whose names carry the token "dwellwatch-canary". Nothing touches the
    canaries in normal use, so any write to one is an alert (sigma/stage6_encryption/
    canary_file_touched.yml; wazuh/dwellwatch_fim_rules.xml watches the same folder). Every file is
    dummy text: this folder is what the encryption stage of the emulation is allowed to damage.
#>
$ErrorActionPreference = "Stop"

$share = "C:\Shares\Finance"
New-Item -ItemType Directory -Path $share -Force | Out-Null

$documents = @(
    "budget-2026-q1.xlsx", "budget-2026-q2.xlsx", "supplier-list.docx", "payroll-summary.xlsx",
    "board-minutes-march.docx", "invoices-april.xlsx", "contracts-index.docx", "expenses-policy.docx"
)
foreach ($name in $documents) {
    Set-Content -Path (Join-Path $share $name) -Value "DwellWatch lab dummy file: $name. Not a real document." -Encoding UTF8
}

$canaries = @("dwellwatch-canary-q3-budget.xlsx", "dwellwatch-canary-passwords.docx")
foreach ($name in $canaries) {
    foreach ($folder in @($share, "C:\Users\Public\Documents")) {
        Set-Content -Path (Join-Path $folder $name) -Value "DwellWatch canary file. Any change to it is an alert." -Encoding UTF8
    }
}

if (-not (Get-SmbShare -Name "Finance" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Finance" -Path $share -ChangeAccess "Everyone" | Out-Null
}
Write-Output "share \\$env:COMPUTERNAME\Finance: $($documents.Count) dummy files and $($canaries.Count) canaries"
