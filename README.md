### _Threat Investigation_
> Alert validation and investiation accross endpoint, identity, network, and cloud telemetry.

- [**Internet Exposure & Initial Access** — Defender XDR](Threat-Investigation/MDXDR-Internet-Exposure-Initial-Access.md)

  _Investigated Azure resource misconfiguration resulting in unintended internet exposure, assessed authentication outcomes, and recommended NSG hardening_

- [**Data Exfiltration** — Defender XDR](Threat-Investigation/MDXDR-Insider-Threat-Investigation.md)

  _Analyzed anomalous outbound data transfer following potential compromise, assessed file access and network telemetry to confirm exfiltration path and scope_

- [**Tor Browser Final Project** — Defender XDR](Threat-Investigation/Tor-Browser-Final-Project/MDXDR-Tor-Browser.md)

  _Detected suspicious Tor browser usage on endpoints, analyzed network telemetry to assess security risk_

- [**Spear-Phishing** — Splunk](Threat-Investigation/Splunk-Phishing-Lateral-Movement.md)

  _Traced phishing campaign from initial access through exfiltration, correlated web/email/auth/endpoint logs to asses scope and impact_

- [**Intel-Driven Threat Hunt** — Splunk](Threat-Investigation/Splunk-Intel-Driven-Threat-Hunt.md)

  _Proactively hunted for IOCs accross endpoint and network telemetry, assesed organizational risk and reported findings_ 

---

### _Detection & Alerting_

> Creating, tuning, and validating detections to improve signal quality and reduce noise.

- [**Credential Exposure Risk** — Azure](Detection-and-Alerting/Azure-Credential-Exposure.md)

  _CTI-informed threat model and KQL detection for anomalous storage credential enumeration_
  
- [**Brute Force Detection** — Sentinel](Detection-and-Alerting/Sentinel-Brute-Force-Detection.md)

  _Created scheduled KQL analytics rule to detect repeated failed authentication attempts from single IPs, tuned threshold to 20 failures over 5 hours to balance noise reduction with detection coverage_

- [**Endpoint monitoring & Alert Refinement** — Wazuh](Detection-and-Alerting/Wazuh-Endpoint-Monitoring-Alert-Tuning.md)

  _Deployed multi-OS Wazuh EDR with secure VPN configuration, baselined behavior to tune detections and reduce compliance noise_
  
---

### _Vulnerability Management_

> Identifying misconfigurations and reducing attack surface.

- [**WN11-AU-000050 STIG Remediation**](Vulnerability-Management/STIG-Implementations/WN11-AU-000050)
---

### _Skills Referenced_
- Microsoft Defender XDR  
- Microsoft Sentinel (KQL)  
- Splunk Enterprise Security (SPL)    
- Tenable  
- OSINT and CTI
