<#
.SYNOPSIS

Enables success auditing for Credential Validation under Account Logon so authentication events are captured in 
the Security event log on Windows 11 per DISA STIG WN11-AU-000010.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-10
    Last Modified   : 2026-04-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000010

.TESTED ON
    Date(s) Tested  : 2026-4-10
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-AU-000010.ps1
#>
auditpol /set /subcategory:"Credential Validation" /success:enable

$verify = auditpol /get /subcategory:"Credential Validation"
if ($verify -match "Success") {
    Write-Host "SUCCESS: WN11-AU-000010 remediated. Credential Validation success auditing is enabled." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-AU-000010 remediation unsuccessful. Manual review required." -ForegroundColor Red
}