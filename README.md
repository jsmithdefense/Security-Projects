<img src="https://capsule-render.vercel.app/api?type=venom&height=220&color=0:000000,100:1da1f2&text=Projects&fontSize=60&fontColor=B9D9EB&animation=fadeIn&fontAlignY=40" width="100%"/>

### Azure:

- [**RBAC Risk Intelligence**](https://github.com/jsmithdefense/Azure-RBAC-Risk-Analyzer)

  > _Built a tool that enumerated all role assignments across a tenant, ranks subscriptions and principals by cumulative risk score, and generates AI remediation playbooks which can be executed either manually or automatically via Azure SDK_

- [**Threat Modeling Cloud Storage and Credential Exposure Risk**](Azure/azure-credential-exposure.md)

  > _Used a Microsoft CTI report to model how implicit trust of keys or SAS tokens enables a path to silent persistence in Azure. I built a KQL detection that flags identities enumarating their credentials outside of their normal pattern_
  
- [**Azure VM Exposure & Access Hardening**](Azure/azure-vm-exposure-and-access-hardening.md)

  > _Created scheduled KQL analytics rule to detect repeated failed authentication attempts from single IPs, tuned threshold to 20 failures over 5 hours to balance noise reduction with detection coverage_


---

### Defender XDR:

- [**Investigating Unintended Azure VM Exposure**](Defender-XDR/mdxdr-internet-exposure-initial-access.md)

  > _Investigated Azure resource misconfiguration resulting in unintended internet exposure, assessed authentication outcomes, and recommended NSG hardening_

- [**Investigating a Potential Insider Threat**](Defender-XDR/mdxdr-insider-threat-investigation.md)

  > _Investigated suspected insider data exfiltration following employee PIP placement, observed PowerShell data staging on endpoint, found no evidence of network exfiltration beyond local staging activity_


- [**Investigating Unauthorized Tor Browser Usage**](Defender-XDR/tor-browser-final-project)

  > _Investigated unauthorized Tor browser usage on corporate endpoint, observed installation and active network connections to Tor nodes, isolated device and notified management_

---

### Tenable:

[READ ME](Tenable/README.md)

- [WN11-AU-000050 STIG Remediation - **Enable Process Creation Auditing**](Tenable/STIG-Implementations/WN11-AU-000050_Proccess_Create_Auditing)
- [WN11-AU-000560 STIG Remediation - **Enable Logon Auditing**](Tenable/STIG-Implementations/WN11-AU-000560_Enable_Logon_Auditing)
- [WN11-CC-000110 STIG Remediation - **Disable HTTP Printing**](Tenable/STIG-Implementations/WN11-CC-000110_Disable_HTTP_Printitng)
- [WN11-CC-000185 STIG Remediation - **Disable Autorun Commands**](Tenable/STIG-Implementations/WN11-CC-000185_Disable_Autorun_Commands)
- [WN11-CC-000005 STIG Remediation - **Disable Camera From Lock Screen**](Tenable/STIG-Implementations/WN11-CC-000005_Disable_Lock_Screen_Camera)
- [WN11-CC-000315 STIG Remediation - **Disable Automatic Elevation**](Tenable/STIG-Implementations/WN11-CC-000315_Disable_Automatic_Privelage_Elevation)
- [WN11-AC-000005 STIG Remediation - **Configure Account Lockout Duration**](Tenable/STIG-Implementations/WN11-AC-000005_Lockout_Duration)
- [WN11-AC-000010 STIG Remdeiation - **Limit Logon Attempts**](Tenable/STIG-Implementations/WN11-AC-000010_Limit_Logon_Attempts)
- [WN11-00-000090 STIG Remediation - **Enable Password Expiration**](Tenable/STIG-Implementations/WN11-00-000090_Password_Expiration)
- [WN11-00-000395 SITG Remediation - **Disable PortProxy**](Tenable/STIG-Implementations/WN11-00-000395_Disable_PortProxy)

---

### Splunk:

- [**Investigating a Spear-Phishing Campaign**](Splunk/splunk-phishing-lateral-movement.md)

  > _Investigated spear-phishing campaign from initial access through exfiltration, observed 4 compromised hosts with PowerShell C2 beaconing. Estimated ~120MB data exfiltrated_

- [**Intel-Driven Threat Hunting**](Splunk/splunk-intel-driven-threat-hunt.md)

  > _Conducted CTI-informed threat hunt for APT web targeting, observed 26,000+ unsuccessful credential stuffing attempts against phpMyAdmin endpoint, recommended exposure reduction controls_

---

### Other:

- [**Multi-Host Hands-On-Keybaord Intrusion CTF**](OTHER/sentinel-the-broker-threat-hunt-ctf.md)

  > _Traced credential dumping, lateral movement, persistence techniques, and payroll data staging across enterprise endpoints_

- [**Wazuh EDR Homelab**](OTHER/sentinel-the-broker-threat-hunt-ctf.md)

  > _Deployed Wazuh as a multi-OS EDR solution in my homelab. All traffic is routed and encrypted via a Tailscale mesh network to prevent public internet exposure._
