# Vulnerability Remediation Lab

<img width="1000" alt="image" src="https://github.com/user-attachments/assets/cfc5dbcf-3fcb-4a71-9c13-2a49f8bab3e6">

## Overview
This lab simulates a vulnerability management workflow using Tenable scans against Windows systems hosted in Azure. The goal is to identify failed DISA STIG findings, remediate them with PowerShell or Bash, and validate the fixes through follow-up checks and rescanning.

The project is focused on practical baseline enforcement. Translating vulnerability findings into targeted configuration changes, validating those changes locally, confirming remediation status through scanner feedback, then automating the whole process.

## Objectives
- Perform vulnerability scanning with Tenable against Azure-hosted systems
- Identify and analyze failed DISA STIG findings
- Develop script-based remediations for recurring configuration issues
- Validate fixes through local checks and follow-up scans
- Document remediation logic in a repeatable way

## Technology Utilized
- **Tenable / Nessus** — vulnerability discovery and compliance validation
- **Azure Virtual Machines** — scan engine and remediation targets
- **PowerShell & Bash** — script-based remediation and validation
- **Windows security policy, registry, and audit settings** — hardening controls mapped to STIG findings

## Workflow
1. Run a vulnerability or compliance scan against the target system
2. Review failed STIG findings and determine the required control setting
3. Implement manual remediation and validation with an additional scan
4. Automate the remediation solution through PowerShell or Bash
5. Validate the change locally with native system commands or policy checks
6. Rescan to confirm the finding is remediated or downgraded


### PowerShell Scripts
- [WN11-AU-000050 STIG Remediation - **Enable Process Creation Auditing**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-AU-000050_Proccess_Create_Auditing)
- [WN11-AU-000560 STIG Remediation - **Enable Logon Auditing**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-AU-000560_Enable_Logon_Auditing)
- [WN11-CC-000110 STIG Remediation - **Disable HTTP Printing**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-CC-000110_Disable_HTTP_Printitng)
- [WN11-CC-000185 STIG Remediation - **Disable Autorun Commands**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-CC-000185_Disable_Autorun_Commands)
- [WN11-CC-000005 STIG Remediation - **Disable Camera From Lock Screen**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-CC-000005_Disable_Lock_Screen_Camera)
- [WN11-CC-000315 STIG Remediation - **Disable Automatic Privilege Elevation**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-CC-000315_Disable_Automatic_Privelage_Elevation)
- [WN11-AC-000005 STIG Remediation - **Configure Account Lockout Duration**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-AC-000005_Lockout_Duration)
- [WN11-AC-000010 STIG Remediation - **Limit Logon Attempts**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-AC-000010_Limit_Logon_Attempts)
- [WN11-00-000090 STIG Remediation - **Enable Password Expiration**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-00-000090_Password_Expiration)
- [WN11-00-000395 STIG Remediation - **Disable PortProxy**](https://github.com/jsmithdefense/Security-Projects/blob/main/Vulnerability-Management/STIG-Implementations/WN11-00-000395_Disable_PortProxy)

## Note
Some remediations may require validation through both local command-line checks and rescanning, depending on how the control is assessed by Tenable.
