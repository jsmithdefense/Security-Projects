<img src="https://capsule-render.vercel.app/api?type=venom&height=220&color=0:000000,100:1da1f2&text=Projects&fontSize=60&fontColor=B9D9EB&animation=fadeIn&fontAlignY=40" width="100%"/>

### _Detection & Alerting_



- [**Credential Exposure Risk** — Azure](Detection-and-Alerting/Azure-Credential-Exposure.md)

  > _Adapted Microsoft CTI report to model how implicit trust of storage keys enables identity-less persistence, developed KQL detection for anomalous credential enumeration as a potential post-compromise indicator_
  
- [**Azure VM Exposure & Access Hardening** — Azure / Sentinel](Detection-and-Alerting/Azure-VM-Exposure-and-Access-Hardening.md)

  > _Created scheduled KQL analytics rule to detect repeated failed authentication attempts from single IPs, tuned threshold to 20 failures over 5 hours to balance noise reduction with detection coverage_

- [**Endpoint monitoring & Alert Refinement** — Wazuh](Detection-and-Alerting/Wazuh-Endpoint-Monitoring-Alert-Tuning.md)

  > _Deployed multi-OS Wazuh EDR with secure VPN configuration, baselined behavior to tune detections and reduce compliance noise_

---

### _Threat Investigations_


- [**Internet Exposure & Initial Access** — Defender XDR](Threat-Investigation/MDXDR-Internet-Exposure-Initial-Access.md)

  > _Investigated Azure resource misconfiguration resulting in unintended internet exposure, assessed authentication outcomes, and recommended NSG hardening_

- [**Data Exfiltration** — Defender XDR](Threat-Investigation/MDXDR-Insider-Threat-Investigation.md)

  > _Investigated suspected insider data exfiltration following employee PIP placement, observed PowerShell data staging on endpoint, found no evidence of network exfiltration beyond local staging activity_

- [**"The Broker" Threat Hunt CTF Writeup** — Sentinel / Defender XDR ](Threat-Investigation/Sentinel-The-Broker-Threat-Hunt-CTF.md)
  > _Investigated multi-host hands-on-keyboard intrusion, traced credential dumping, lateral movement, persistence mechanisms, and payroll data staging across enterprise endpoints_
  
- [**Tor Browser Final Project** — Defender XDR](Threat-Investigation/Tor-Browser-Final-Project/MDXDR-Tor-Browser.md)

  > _Investigated unauthorized Tor browser usage on corporate endpoint, observed installation and active network connections to Tor nodes, isolated device and notified management_

- [**Spear-Phishing** — Splunk](Threat-Investigation/Splunk-Phishing-Lateral-Movement.md)

  > _Investigated spear-phishing campaign from initial access through exfiltration, observed 4 compromised hosts with PowerShell C2 beaconing. Estimated ~120MB data exfiltrated_

- [**Intel-Driven Threat Hunt** — Splunk](Threat-Investigation/Splunk-Intel-Driven-Threat-Hunt.md)

  > _Conducted CTI-informed threat hunt for APT web targeting, observed 26,000+ unsuccessful credential stuffing attempts against phpMyAdmin endpoint, recommended exposure reduction controls_
---

### _Vulnerability Management_

  - [READ ME](Vulnerability-Management/README.md)
