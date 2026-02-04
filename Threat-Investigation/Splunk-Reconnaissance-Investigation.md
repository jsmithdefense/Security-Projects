## Web Reconnaissance Investigation — User-Agent Anomaly Analysis (Splunk ES)

**Environment:** Splunk Enterprise Security
**Organization (Simulated):** Frothly (craft beverage manufacturer)

---

## 1. Scenario Overview

This investigation assessed suspected reconnaissance activity targeting Frothly’s public-facing web infrastructure. The objective was to identify low-noise indicators of automated probing, validate whether activity escalated beyond reconnaissance, and determine whether further host-level investigation or response actions were required.

The analysis focused on identifying adversary tooling and behavior through repeatable HTTP patterns rather than relying on signature-based alerts.

---

## 2. Scope and Constraints

* **Time range:** August 2017
* **Initial detection context:** No technique or alert provided
* **Analytical hint:** User-agent strings may reveal unintended attacker fingerprints

Given the absence of a triggering alert, the investigation followed a **hypothesis-driven approach**, beginning with traffic baselining.

---

## 3. Detection Strategy

**Objective:**
Identify reconnaissance activity using low-variance HTTP artifacts aligned with early-stage adversary behavior.

**Initial indicators of interest:**

* High-frequency requests consistent with automated crawling
* Concentrated request volume from limited source IPs
* Abnormal or tool-specific user-agent strings
* Repeated access to administrative or sensitive paths

This approach aligns with **MITRE ATT&CK Reconnaissance and Resource Development tactics**, particularly automated web scanning and enumeration.

---

## 4. Data Sources

The following data sources were evaluated to establish baseline behavior and identify anomalies:

* `stream:http` — primary source for HTTP request analysis
* `pan:traffic` — supplemental network context where available

Sourcetypes were enumerated to confirm sufficient coverage prior to deeper analysis.

---

## 5. Baseline Analysis — HTTP User-Agents

HTTP traffic was baseline-reviewed by user-agent to identify outliers within the selected time range.

**Key findings:**

* Majority of user-agents aligned with common browser profiles
* Two outliers exhibited characteristics consistent with automation:

  * `Mozilla/5.0 Jorgee`
  * `Python-urllib/2.7`

These user-agents became the focus of subsequent analysis.

---

## 6. User-Agent Attribution and OSINT Validation

### User-Agent: `Mozilla/5.0 Jorgee`

OSINT enrichment identified this user-agent as a known web vulnerability scanner:

* **WHOIS:** Source IP associated with Brazilian telecommunications infrastructure
* **AbuseIPDB:** Flagged as suspicious infrastructure
* **GreyNoise:** Indicated likely targeting behavior
* **FortiGuard:** Identified *Jorgee* as a scanner commonly used against PHP-based services

The geographic and tooling profile was anomalous relative to Frothly’s expected traffic patterns.

### User-Agent: `Python-urllib/2.7`

* **WHOIS:** Source IP resolved to private address space
* **GreyNoise:** Confirmed internal origin

This activity was assessed as benign and excluded from further analysis.

---

## 7. Hypothesis Formation

Based on observed behavior and OSINT validation, the working hypothesis was:

> Frothly is experiencing automated reconnaissance and probing activity using a known vulnerability scanning tool, with no confirmed exploitation.

The investigation then pivoted to validate whether reconnaissance escalated into authentication abuse or successful access.

---

## 8. Validation — Request Patterns and Targeting

Analysis of requests associated with `Mozilla/5.0 Jorgee` revealed:

* Repeated requests targeting exposed administrative paths
* Heavy focus on `/phpmyadmin/index.php`
* Use of `HEAD` and `GET` methods consistent with enumeration
* Over 26,000 requests against a single endpoint, indicating successful discovery of a viable target

The activity pattern was consistent with **automated probing rather than interactive exploitation**.

---

## 9. Escalation Check — Authentication Outcomes

HTTP response analysis showed:

* Only `302` and `400` status codes observed
* No `200 OK` responses
* No evidence of authenticated sessions
* No navigation beyond the targeted administrative endpoint

Given the absence of successful authentication or lateral interaction, escalation into host telemetry was not warranted.

---

## 10. Conclusion

The investigation confirmed **automated reconnaissance and probing activity** originating from infrastructure associated with a known web vulnerability scanner (`Mozilla/5.0 Jorgee`). While the attacker successfully identified an exposed administrative endpoint, no evidence of credential compromise, authenticated access, or post-reconnaissance activity was observed.

The incident was assessed as **reconnaissance without impact**, requiring exposure reduction rather than incident response escalation.

---

## 11. Lessons Learned

* User-agent baselining is an effective low-noise method for detecting reconnaissance
* Automated scanners exhibit predictable request methods and path targeting
* HTTP status code correlation is critical for validating unsuccessful brute-force attempts
* OSINT enrichment materially improves confidence in infrastructure attribution
* Geographic anomalies should be treated as suspicious until disproven

---

## 12. Recommended Improvements

* Restrict administrative interfaces behind VPN or IP allowlists
* Implement WAF rules to block known scanner signatures
* Enhance application-layer logging for authentication outcomes
* Develop detections for repeated `HEAD`/`GET` requests targeting sensitive paths
* Continuously monitor internet-exposed assets to prevent unintended exposure
