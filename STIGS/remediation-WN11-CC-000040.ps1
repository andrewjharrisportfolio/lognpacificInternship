<#
.SYNOPSIS

Disables insecure guest logons to SMB servers, ensuring shared resources require proper authentication instead of allowing unauthenticated access 
on Windows 11 per DISA STIG WN11-CC-000040.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-10
    Last Modified   : 2026-04-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000040

.TESTED ON
    Date(s) Tested  : 2026-4-10
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-CC-000040.ps1
#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$registryName = "AllowInsecureGuestAuth"
$registryValue = 0
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -Type DWord
$verify = Get-ItemProperty -Path $registryPath -Name $registryName
if ($verify.AllowInsecureGuestAuth -eq 0) {
    Write-Host "SUCCESS: WN11-CC-000040 remediated. AllowInsecureGuestAuth is set to 0." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-CC-000040 remediation unsuccessful. Manual review required." -ForegroundColor Red
}