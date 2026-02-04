# Security Projects Index

This repository contains hands-on security investigations and defensive projects across SOC operations, detection and alerting, and vulnerability management.  
Each project documents analysis performed, evidence reviewed, and conclusions reached.

---

### Threat Investigations

Focused on validating alerts, assessing risk, and determining appropriate response actions across endpoint, identity, network, and cloud telemetry.

[**Internet Exposure & Initial Access** — Defender XDR](Threat-Investigation/MDXDR-Internet-Exposure-Initial-Access.md)

[**Data Exfiltration Investigation** — Defender XDR](Threat-Investigation/MDXDR-Insider-Threat-Investigation.md)

**Spear Phishing Investigation** — Splunk Enterprise Security  
  End-to-end analysis of a phishing event to assess scope, affected users, and escalation requirements.

**Lateral Movement Assessment** — Splunk Enterprise Security  
  Investigation of post-compromise activity to validate lateral movement and determine spread.

#### Skills Demonstrated
- Alert validation and incident investigation  
- Correlation of endpoint, identity, network, and cloud data  
- Impact assessment and scope determination  
- Escalation, remediation, or closure decisions  

---

### Detection & Alerting

Projects focused on creating, tuning, and validating detections to improve signal quality and reduce noise.


- **Brute Force Detection & Incident Creation** — Microsoft Sentinel  
  Creation of scheduled query rules to detect repeated authentication failures and generate incidents.

- **Alert Tuning & Noise Reduction** — Defender XDR  
  Review and adjustment of alert logic to reduce benign positives.

- **Detection Validation via Threat Emulation** — Wazuh / Sentinel  
  Validation of detections against controlled activity to confirm expected alert behavior.

### Skills Demonstrated
- Detection logic development (KQL, SPL)  
- Alert thresholding and suppression  
- Incident creation and entity mapping  

---

### Vulnerability Management & Exposure Reduction

Projects focused on identifying misconfigurations and reducing attack surface.

- **Azure Resource Exposure Assessment** — Azure / Defender XDR  
  Identification and assessment of unintentionally internet-exposed cloud resources.

- **Network Security Group Hardening** — Azure  
  Review and restriction of inbound access to reduce unnecessary exposure.

- **Endpoint Exposure Review** — Tenable / Defender  
  Assessment of endpoint configuration and exposure risks.

### Skills Demonstrated
- Misconfiguration identification  
- Exposure and risk assessment  
- Compensating control recommendations  

---

## Endpoint Monitoring & Lab Environments

Hands-on environments used to understand telemetry generation and alert behavior.

### Projects
- **Wazuh EDR Deployment & Tuning** — Wazuh  
  Deployment and tuning of endpoint monitoring across multiple operating systems.

- **Multi-OS Endpoint Telemetry Analysis** — Windows / Linux / macOS  
  Analysis of endpoint behavior to distinguish expected activity from suspicious signals.

### Skills Demonstrated
- Endpoint agent deployment and configuration  
- Log ingestion and normalization  
- Alert noise analysis  

---

## Tools & Technologies Referenced
- Microsoft Defender XDR  
- Microsoft Sentinel (KQL)  
- Splunk Enterprise Security (SPL)  
- Wazuh EDR  
- Tenable  
- OSINT and threat intelligence sources  
