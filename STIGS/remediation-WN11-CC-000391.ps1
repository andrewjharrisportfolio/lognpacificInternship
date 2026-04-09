<#
.SYNOPSIS
    Disables Internet Explorer 11 on Windows 11 per DISA STIG WN11-CC-000391.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-09
    Last Modified   : 2026-04-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000391

.TESTED ON
    Date(s) Tested  : 2026-4-09
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-CC-000391.ps1
#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
$registryName = "NotifyDisableIEOptions"
$registryValue = 0
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -Type DWord
$verify = Get-ItemProperty -Path $registryPath -Name $registryName
if ($verify.NotifyDisableIEOptions -eq 0) {
    Write-Host "SUCCESS: WN11-CC-000391 remediated. NotifyDisableIEOptions is set to 0." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-CC-000391 remediation unsuccessful. Manual review required." -ForegroundColor Red
}
