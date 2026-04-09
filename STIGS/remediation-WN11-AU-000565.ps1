<#
.SYNOPSIS
    Changes Audit Policy to audit failed logons (4625) on Windows 11 per DISA STIG WN11-AU-000565.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-09
    Last Modified   : 2026-04-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000565

.TESTED ON
    Date(s) Tested  : 2026-4-09
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-AU-000565.ps1
#>
auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable

$verify = auditpol /get /subcategory:"Other Logon/Logoff Events"
if ($verify -match "Failure") {
    Write-Host "SUCCESS: WN11-AU-000565 remediated. Other Logon/Logoff Events failure auditing is enabled." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-AU-000565 remediation unsuccessful. Manual review required." -ForegroundColor Red
}