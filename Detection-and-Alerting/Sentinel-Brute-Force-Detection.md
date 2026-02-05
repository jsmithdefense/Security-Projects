## Creating a Brute Force Detection Rule in Microsoft Sentinel  

I created a scheduled analytics rule in Microsoft Sentinel to detect potential brute force activity by alerting when the same remote IP generates repeated failed logon attempts against the same host within a defined time window.

This rule was built within a shared Azure honeynet environment where virtual machines are intentionally exposed to the internet and routinely receive authentication attempts.

**MITRE ATT&CK Mapping**:

- `T1110` – Brute Force

- `T1110.001` – Password Guessing

- `T1110.004` – Credential Stuffing

---

### Data Source

The rule queries `DeviceLogonEvents`, which contains host-centric log on telemetry forwarded from Defender for Endpoint.

**Fields used:**

* `TimeGenerated`
* `ActionType`
* `RemoteIP`
* `DeviceName`

---

### Detection Logic

1. Filter logon events to the last **5 hours**
2. Keep only failed logon attempts
3. Count failures by `RemoteIP` and `DeviceName`
4. Trigger when the failure count reaches or exceeds 20

---

### KQL Query

```kql
let lookback = 5h;
DeviceLogonEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| where FailedAttempts >= 20
| order by FailedAttempts
```
 **20 failed attempts** was chosen to reduce noise from occasional mistyped credentials while still capturing activity consistent with automated brute force behavior in this environment.

---

### Sentinel Rule Configuration

* **Rule type:** Scheduled query rule
* **Query frequency:** Periodic (scheduled)
* **Lookback period:** 5 hours (defined in query)
* **Alert trigger:** Generate alert when query returns results
* **Severity:** Medium
* **Entity mapping:**

  * Host → `DeviceName`
  * IP address → `RemoteIP`


<img width="1497" height="433" alt="image" src="https://github.com/user-attachments/assets/cf176895-2060-4025-a996-f6dea06a2505" />

---

### Alert Interpretation

A triggered alert indicates:

* Repeated failed authentication attempts
* A single external IP targeting the same host
* Activity consistent with automated password guessing or brute force attempts

This alert does **not** confirm successful authentication or compromise.

---

### Risk Reduction

To reduce exposure, inbound access to affected virtual machines can be restricted at the network layer (e.g., tightening NSG inbound rules or using Azure Bastion instead of exposing RDP/SSH publicly.

