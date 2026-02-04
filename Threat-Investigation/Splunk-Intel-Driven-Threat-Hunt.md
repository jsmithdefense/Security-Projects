## Intel-Driven Threat Hunt — Web Reconnaissance & Credential Abuse Detection with Splunk 

### Environment & Scenario Context

Following reporting from external threat intelligence sources indicating that the Taedonggang APT was targeting public-facing web infrastructure, Frothly conducted a proactive threat hunt to assess potential exposure. 

Using Splunk Enterprise Security, the objective was to identify activity consistent with the reported threat actor’s tradecraft and determine whether escalation or mitigation is warranted.

---

### Detection Approach

Given the absence of a triggering alert, a hypothesis driven approach was applied, focusing on HTTP artifacts commonly associated with automated reconnaissance.

Notes guiding the hunt:

* Automated scanners generate high frequency, repeatable request patterns
* Reconnaissance activity often reveals tool fingerprints via user-agent strings
* Enumeration targets administrative or sensitive application paths

**Timeframe:** August 2017

**ATT&CK Techniques Observed:**

* T1595 – Active Scanning
* T1592 – Gather Victim Host Information
* T1110.004 - Credential Stuffing (attempted)

---

### Data Sources Reviewed

* `stream:http` — primary source for HTTP request and user-agent analysis
* `pan:traffic` — supplemental network context where available


---

### Baseline Analysis — HTTP User-Agent Distribution

```kql
index=botsv2 sourcetype="stream:http" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00" 
| top http_user_agent, src_ip, dest_ip limit=20
```

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*eLeCCpDfncclrEDmfmP6qQ.png)

Baseline analysis of HTTP traffic by user-agent to identify deviations from expected browser behavior.

**Findings:**

* Majority of traffic aligned with common browser user-agents
* Two anomalous user-agents were identified:

  * `Mozilla/5.0 Jorgee`
  * `Python-urllib/2.7`

These outliers became the focus of attribution and behavioral analysis.

---

### User-Agent Attribution & OSINT Validation

#### `Mozilla/5.0 Jorgee`

* **WHOIS:** Source IP associated with Brazilian telecommunications infrastructure
* **AbuseIPDB:** Infrastructure flagged as suspicious
* **GreyNoise:** Activity assessed as likely targeting behavior
* **FortiGuard:** Identified *Jorgee* as a known web vulnerability scanner targeting PHP-based services

The geographic profile and tooling fingerprint were anomalous relative to Frothly’s expected traffic baseline.

#### `Python-urllib/2.7`

This activity was assessed as benign and excluded from further investigation.

---

### Targeting & Request Pattern Analysis

```kql
index=botsv2 sourcetype="stream:http" http_user_agent="Mozilla/5.0 Jorgee" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00"
| top http_user_agent src_ip dest_ip http_method site url showperc=f limit=5
```

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ZbdoXaSJZcOoeV9Tv55nZw.png)

Web request analysis associated with `Mozilla/5.0 Jorgee` revealed:

* High-volume requests targeting exposed administrative paths
* Concentrated enumeration of `/phpmyadmin/index.php`
* Use of `HEAD` and `GET` methods consistent with automated enumeration
* Over 26,000 requests against a single endpoint, indicating successful target identification

The request structure and repetition consistent with automated activity rather than human exploitation.

---

### Initial Access Investigation

HTTP request analysis showed:

* Repeated `GET` requests to the phpMyAdmin login endpoint

* Explicit username and password pairs embedded in the query string (e.g., pma_username, pma_password)

* Iteration through common administrative and default credentials (root, admin, administrator, etc.)

* Consistent user-agent string (Mozilla/5.0 Jorgee) across attempts

* Activity aligns with MITRE technique T1110.004 – Credential Stuffing

### Authentication Outcome Validation

![Alt text ](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*caIMU_7KQeWC4KazX35ANA.png)

HTTP response analysis showed:

* Only `302` and `400` status codes observed
* No `200 OK` responses
* No evidence of authenticated sessions

**Given the absence of successful authentication or lateral interaction, escalation into host telemetry was not required.**

---

### Conclusion

The investigation confirmed automated reconnaissance activity originating from infrastructure associated with a known web vulnerability scanner (`Mozilla/5.0 Jorgee`). While an exposed administrative endpoint was successfully identified, no evidence of credential compromise, authenticated access, or post-reconnaissance exploitation was observed.

The activity was assessed as **reconnaissance without impact**, requiring exposure reduction rather than incident response escalation.

---

### Recommended Mitigations & Improvements

* Restrict administrative interfaces behind VPN or IP allowlists
* Implement WAF rules to block known scanner signatures
* Improve application-layer authentication logging
* Develop detections for repeated `HEAD`/`GET` requests targeting sensitive paths
* Continuously monitor internet-exposed assets for unintended exposure
