<img src="https://capsule-render.vercel.app/api?type=venom&height=220&color=0:000000,100:1da1f2&text=Projects&fontSize=60&fontColor=B9D9EB&animation=fadeIn&fontAlignY=40" width="100%"/>

### _Detection & Alerting_



- [**Credential Exposure Risk** — Azure](Detection-and-Alerting/Azure-Credential-Exposure.md)

  > _Adapted Microsoft CTI report to model how implicit trust of storage keys enables identity-less persistence, developed KQL detection for anomalous credential enumeration as a potential post-compromise indicator_
  
- [**Brute Force Detection** — Sentinel](Detection-and-Alerting/Sentinel-Brute-Force-Detection.md)

  > _Created scheduled KQL analytics rule to detect repeated failed authentication attempts from single IPs, tuned threshold to 20 failures over 5 hours to balance noise reduction with detection coverage_

- [**Endpoint monitoring & Alert Refinement** — Wazuh](Detection-and-Alerting/Wazuh-Endpoint-Monitoring-Alert-Tuning.md)

  > _Deployed multi-OS Wazuh EDR with secure VPN configuration, baselined behavior to tune detections and reduce compliance noise_

---

### _Threat Investigations_


- [**Internet Exposure & Initial Access** — Defender XDR](Threat-Investigation/MDXDR-Internet-Exposure-Initial-Access.md)

  > _Investigated Azure resource misconfiguration resulting in unintended internet exposure, assessed authentication outcomes, and recommended NSG hardening_

- [**Data Exfiltration** — Defender XDR](Threat-Investigation/MDXDR-Insider-Threat-Investigation.md)

  > _Investigated suspected insider data exfiltration following employee PIP placement, observed PowerShell data staging on endpoint, found no evidence of network exfiltration beyond local staging activity_

- [**Tor Browser Final Project** — Defender XDR](Threat-Investigation/Tor-Browser-Final-Project/MDXDR-Tor-Browser.md)

  > _Investigated unauthorized Tor browser usage on corporate endpoint, observed installation and active network connections to Tor nodes, isolated device and notified management_

- [**Spear-Phishing** — Splunk](Threat-Investigation/Splunk-Phishing-Lateral-Movement.md)

  > _Investigated spear-phishing campaign from initial access through exfiltration, observed 4 compromised hosts with PowerShell C2 beaconing. Estimated ~120MB data exfiltrated_

- [**Intel-Driven Threat Hunt** — Splunk](Threat-Investigation/Splunk-Intel-Driven-Threat-Hunt.md)

  > _Conducted CTI-informed threat hunt for APT web targeting, observed 26,000+ unsuccessful credential stuffing attempts against phpMyAdmin endpoint, recommended exposure reduction controls_
---

### _Vulnerability Management_
Repeatable, consistent PowerShell scripts to automate Windows 11 STIG remediation and reduce human error

- [WN11-AU-000050 STIG Remediation - **Enable Process Creation Auditing**](Vulnerability-Management/STIG-Implementations/WN11-AU-000050_Proccess_Create_Auditing)
- [WN11-AU-000560 STIG Remediation - **Enable Logon Auditing**](Vulnerability-Management/STIG-Implementations/WN11-AU-000560_Enable_Logon_Auditing)
- [WN11-CC-000110 STIG Remediation - **Disable HTTP Printing**](Vulnerability-Management/STIG-Implementations/WN11-CC-000110_Disable_HTTP_Printitng)
- [WN11-CC-000185 STIG Remediation - **Disable Autorun Commands**](Vulnerability-Management/STIG-Implementations/WN11-CC-000185_Disable_Autorun_Commands)
- [WN11-CC-000005 STIG Remediation - **Disable Camera From Lock Screen**](Vulnerability-Management/STIG-Implementations/WN11-CC-000005_Disable_Lock_Screen_Camera)
- [WN11-CC-000315 STIG Remediation - **Disable Automatic Elevation**](Vulnerability-Management/STIG-Implementations/WN11-CC-000315_Disable_Automatic_Privelage_Elevation)
- [WN11-AC-000005 STIG Remediation - **Configure Account Lockout Duration**](Vulnerability-Management/STIG-Implementations/WN11-AC-000005_Lockout_Duration)
- [WN11-AC-000010 STIG Remdeiation - **Limit Logon Attempts**](Vulnerability-Management/STIG-Implementations/WN11-AC-000010_Limit_Logon_Attempts)
- [WN11-00-000090 STIG Remediation - **Enable Password Expiration**](Vulnerability-Management/STIG-Implementations/WN11-00-000090_Password_Expiration)
- [WN11-00-000395 SITG Remediation - **Disable PortProxy**](Vulnerability-Management/STIG-Implementations/WN11-00-000395_Disable_PortProxy)

