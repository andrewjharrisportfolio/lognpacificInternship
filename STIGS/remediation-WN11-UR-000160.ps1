<#
.SYNOPSIS

Restricts the 'Restore files and directories' user right to only the Administrators group, preventing unauthorized users from bypassing file permissions 
and accessing or overwriting sensitive data on Windows 11 per DISA STIG WN11-UR-000160.

.NOTES
    Author          : Andrew Harris
    LinkedIn        : https://www.linkedin.com/in/andrewjharris8/
    GitHub          : https://github.com/andrewjharrisportfolio/lognpacificInternship/tree/main/STIGS
    Date Created    : 2026-04-10
    Last Modified   : 2026-04-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000160

.TESTED ON
    Date(s) Tested  : 2026-4-10
    Tested By       : Andrew Harris
    Systems Tested  : Windows 11 
    PowerShell Ver. : 5.1

.USAGE
    .\remediation-WN11-UR-000160.ps1
#>
$tempFile = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tempFile /quiet
$content = Get-Content $tempFile
$content = $content -replace "SeRestorePrivilege.*", "SeRestorePrivilege = *S-1-5-32-544"
Set-Content $tempFile $content
secedit /configure /db secedit.sdb /cfg $tempFile /quiet
Remove-Item $tempFile
secedit /export /areas USER_RIGHTS /cfg "$env:TEMP\verify.inf" /quiet
$verifyContent = Get-Content "$env:TEMP\verify.inf"
if ($verifyContent -match "SeRestorePrivilege = \*S-1-5-32-544") {
    Write-Host "SUCCESS: WN11-UR-000160 remediated. Restore files and directories right restricted to Administrators only." -ForegroundColor Green
} else {
    Write-Host "FAILED: WN11-UR-000160 remediation unsuccessful. Manual review required." -ForegroundColor Red
}

