### _Threat Investigation_
> Alert validation and investiation accross endpoint, identity, network, and cloud telemetry.

- [**Internet Exposure & Initial Access** — Defender XDR](Threat-Investigation/MDXDR-Internet-Exposure-Initial-Access.md)

  _Investigated Azure resource misconfiguration leading to public exposure, validated authentication attempts, recommended NSG hardening_

- [**Data Exfiltration** — Defender XDR](Threat-Investigation/MDXDR-Insider-Threat-Investigation.md)

  _Analyzed anomalous outbound data transfer following potential compromise, validated file access and network telemetry to confirm exfiltration path and scope_

- [**Spear-Phishing** — Splunk](Threat-Investigation/Splunk-Phishing-Lateral-Movement.md)

  _Traced phishing campaign from initial access through exfiltration, correlated web/email/auth/endpoint logs to asses scope and impact_

- [**Intel-Driven Threat Hunt** — Splunk](Threat-Investigation/Splunk-Intel-Driven-Threat-Hunt.md)

  _Proactively hunted for IOCs accross endpoint and network telemetry, assesed organizational risk and validated findings_ 

---

### _Detection & Alerting_

> Creating, tuning, and validating detections to improve signal quality and reduce noise.

- [**Brute Force Detection** — Sentinel](Detection-and-Alerting/Sentinel-Brute-Force-Detection.md)

  _Created scheduled KQL analytics rule to detect repeated failed authentication attempts from single IPs, tuned threshold to 20 failures over 5 hours to balance noise reduction with detection coverage_

- [**Endpoint monitoring & Alert Refinement** — Wazuh](Detection-and-Alerting/Wazuh-Endpoint-Monitoring-Alert-Tuning.md)

---

### _Vulnerability Management_

> Identifying misconfigurations and reducing attack surface.

- ( Projects will be added as work is migrated. )

---

### _Skills Referenced_
- Microsoft Defender XDR  
- Microsoft Sentinel (KQL)  
- Splunk Enterprise Security (SPL)    
- Tenable  
- OSINT and CTI
