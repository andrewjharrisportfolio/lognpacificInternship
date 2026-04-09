<#
.SYNOPSIS
    Renames built-in guest account on Windows 11 per DISA STIG WN11-CC-000025.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-09
    Last Modified   : 2026-04-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000025

.TESTED ON
    Date(s) Tested  : 2026-4-09
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-CC-000025.ps1
#>
Rename-LocalUser -Name "Guest" -NewName "EnterpriseAux"
$verify = Get-LocalUser -Name "EnterpriseAux"
if ($verify.Name -eq "EnterpriseAux") {
    Write-Host "SUCCESS: WN11-SO-000025 remediated. Guest account renamed to EnterpriseAux." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-SO-000025 remediation unsuccessful. Manual review required." -ForegroundColor Red
}