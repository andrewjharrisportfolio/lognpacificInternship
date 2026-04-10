<#
.SYNOPSIS
    Enables certificate padding check for WinVerifyTrust on Windows Server 2022 to 
    remediate CVE-2013-3900, preventing PE file signature bypass attacks per DISA 
    STIG WN22-00-000110.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-10
    Last Modified   : 2026-04-10
    Version         : 1.0
    CVEs            : CVE-2013-3900
    Plugin IDs      : N/A
    STIG-ID         : WN22-00-000110

.TESTED ON
    Date(s) Tested  : 2026-04-10
    Tested By       : Andrew Harris
    Systems Tested  : Windows Server 2022 VM
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN22-00-000110.ps1
#>
$paths = @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)

foreach ($path in $paths) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name "EnableCertPaddingCheck" -Value "1" -Type String
}

foreach ($path in $paths) {
    $verify = Get-ItemProperty -Path $path -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
    if ($verify.EnableCertPaddingCheck -eq "1") {
        Write-Host "SUCCESS: WN22-00-000110 remediated. EnableCertPaddingCheck is set at $path" -ForegroundColor Green
    } else {
        Write-Host "FAILED: WN22-00-000110 remediation unsuccessful at $path. Manual review required." -ForegroundColor Red
    }
}