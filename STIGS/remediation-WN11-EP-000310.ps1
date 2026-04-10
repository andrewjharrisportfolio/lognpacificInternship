<#
.SYNOPSIS

Enables Kernel DMA Protection to block drive-by Direct Memory Access attacks from unauthorized devices connected via Thunderbolt 3 ports 
on Windows 11 per DISA STIG WN11-EP-000310.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-10
    Last Modified   : 2026-04-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.TESTED ON
    Date(s) Tested  : 2026-4-10
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-EP-000310.ps1
#>
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
$registryName = "DeviceEnumerationPolicy"
$registryValue = 0
if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -Type DWord
$verify = Get-ItemProperty -Path $registryPath -Name $registryName
if ($verify.DeviceEnumerationPolicy -eq 0) {
    Write-Host "SUCCESS: WN11-EP-000310 remediated. DeviceEnumerationPolicy is set to 0." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-EP-000310 remediation unsuccessful. Manual review required." -ForegroundColor Red
}
