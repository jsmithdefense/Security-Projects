<#
.SYNOPSIS
    This PowerShell script sets account lockout duration to 15 minutes or greater
.NOTES
    Author          : Julian Smith
    LinkedIn        : linkedin.com/in/jsmithsec/
    GitHub          : github.com/jsmithdefense
    Date Created    : 2026-02-23
    Last Modified   : 2026-02-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : 21156
    STIG-ID         : WN11-AC-000005

.TESTED ON
    Date(s) Tested  : 2026-02-23;
    Tested By       : Julian Smith
    Systems Tested  : vuln-machine
    PowerShell Ver. : 7

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN11-AC-000005.ps1
#>

secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "LockoutDuration = .*", "LockoutDuration = 15" | Set-Content C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
Remove-Item -Force C:\secpol.cfg
gpupdate /force
