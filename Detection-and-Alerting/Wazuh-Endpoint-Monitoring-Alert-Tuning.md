## Endpoint Monitoring & Alert Tuning — Wazuh EDR Home Lab

![Alt text](https://media.licdn.com/dms/image/v2/D5622AQEQcZfWnN0DIw/feedshare-shrink_2048_1536/B56Zt2IQcaHAAw-/0/1767213436365?e=1772064000&v=beta&t=4VP5lnhgMZkcgGvQkUxBNrX7K3oXSd8XXkVuZbqBCkg)

### Environment Overview

This project involved deploying and operating a Wazuh endpoint monitoring environment to gain hands-on experience with endpoint telemetry collection, normalization, and detection tuning across operating systems.

The environment consists of multiple endpoints (Windows, macOS, and Linux) reporting to a centralized Wazuh manager hosted on isolated infrastructure. All agent/manager communication is routed through a Tailscale VPN mesh network, providing encrypted transport and reachability without exposing services to the public internet.

This architecture enables secure, continuous host-level visibility across endpoints.

---

### Telemetry Collection & Architecture

Each endpoint runs a Wazuh agent responsible for collecting high-fidelity telemetry from the host, including:

* Process creation and execution activity
* File integrity changes
* Authentication and user activity
* System configuration and security events

The centralized manager aggregates, normalizes, and enriches this telemetry, providing a single point for detection logic, alerting, and investigation workflows.

Operating the environment clarified the separation of responsibilities between **agents** (data collection) and the **manager** (analysis, correlation, and alert generation).

---

### Detection Tuning & Baseline Development

A key focus of this project was tuning default detections to reduce noise and improve alert fidelity. This required establishing behavioral baselines for each operating system and workload, including:

* Normal process execution patterns
* Expected authentication behavior
* Legitimate administrative and maintenance activity

The initial Wazuh deployment included several out-of-the-box rule sets focused on compliance and configuration assessment (CIS benchmark checks, NIST 800-53). While valuable for posture management, these controls generated high alert volume with limited relevance to threat detection.

For this environment, I de-prioritized compliance focused alerts in favor of behavioral and activity based detections aligned with investigation and triage workflows. This reduced noise and improved the signal quality of alerts.

Through iterative tuning, I observed that endpoint and network telemetry alone may often present as ambigous without environmental context. Alerts only become actionable when technical signals are interpreted relative to what is normal for the host, user, and enviorment.

---

### Analytical Outcomes & Lessons Learned

Operating the Wazuh environment strengthened my understanding of:

* How raw endpoint telemetry is transformed into analyst-consumable alerts
* The role of behavioral indicators when static indicators are weak or ambiguous
* Why alerts require contextual validation 
* How detection logic quality directly impacts analyst workload and decision making

---

### Summary

This deployment provided practical experience operating in an EDR environment. This piece of my homelab serves as a platform for continued experimentation with detection logic and reinforces a context driven approach to investigations and triage.
