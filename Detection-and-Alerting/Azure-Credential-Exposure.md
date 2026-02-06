## Detecting Credential Exposure Risk Across Azure Storage Trust Boundaries

### Threat Context (CTI Reference)

This work was informed by a Microsoft CTI report describing threat activity targeting **Azure Blob Storage** through abuse of **implicit trust relationships**.

[Full Report](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)

The attack model centers on:

* Publicly accessible Blob Storage containers
* Authorization via **SAS tokens or account keys**, where identity is **not re-evaluated** on access
* Downstream services (Azure Functions, Logic Apps, scheduled processes) implicitly trusting data written to storage
* Poisoning or abuse of automation triggered by storage events

In this model, the primary risk is **data-plane abuse**: once a valid token is presented, access is granted without identity validation, enabling stealthy persistence or downstream compromise.

> This threat model assumes visibility into **resource-level storage access telemetry**.

#### _CTI Report Threat Model_


<img width="1296" height="744" alt="image" src="https://github.com/user-attachments/assets/d2f12498-6870-4ef7-b197-f323a2ee85be" />


> *Public Blob Storage → SAS/Key Authorization → Implicitly Trusted Downstream Services*

---

### Environment Constraints

In my Azure honeynet environment:

* Public Blob Storage containers are **not used**
* Storage accounts **don't expose public data-plane access**
* Resource-level storage access logging (read/write/delete) is **not available**
* Available telemetry is primarily **management-plane logging** via `AzureActivity`

As a result, the CTI attack cannot be directly detected as described because the relevant logs do not exist in this environment. Therefore, I reframed the problem:

> *What risk-adjacent behaviors can be observed given only management-level telemetry?*

#### _Enviorment Threat Model_

<img width="1624" height="776" alt="image" src="https://github.com/user-attachments/assets/2008e388-9df2-4e37-a094-40cc4c46217a" />


---

### Detection Reassessment

While reviewing available logs, I identified visibility into **credential-related management operations**, including:

* `LISTKEYS`
* `LISTSERVICESAS`
* Key regeneration
* Storage account configuration changes

These operations occur at the **management plane** and require prior identity evaluation.

Although they don't directly detect data-plane abuse, they can indicate **credential exposure risk** and potential **post-compromise activity**.

---

### MITRE ATT&CK Mapping

> MITRE ATT&CK T1098.001 (Account Manipulation: Additional Cloud Credentials) 

Enumerating storage account keys or SAS tokens enables the reuse of long-lived cloud credentials that provide persistent access independent of identity re-evaluation.

Although enumeration does not create new credentials, it exposes existing long-lived secrets that can be reused without further identity validation.

---

### Detection Hypothesis

If an identity that has not recently interacted with storage credentials suddenly enumerates keys or SAS tokens, this may indicate elevated risk following identity compromise or preparation for persistence.

This is **not** a detection of public blob abuse itself. It's a **supporting detection** focused on **credential exposure behavior** in environments with limited data-plane visibility.

#### Logic & KQL:

1. Establish a **baseline** of identities that have enumerated storage credentials over a defined window
2. Observe **recent activity** within a short detection window
3. Alert when:

   * An identity enumerates storage keys or SAS tokens
   * That identity has **not performed similar actions during the baseline period**

This approach reduces noise while highlighting **new or unexpected credential interaction**.

```kql
let baseline = 14d;
let window = 1h;
let KnownSources = 
    AzureActivity
    | where TimeGenerated between (ago(baseline) .. ago(window))
    | where ActivityStatusValue == "Success"
    | where OperationNameValue has_any ("LISTKEYS", "LISTSERVICESAS")
    | summarize by Caller;
AzureActivity
| where TimeGenerated >= ago(window)
| where ActivityStatusValue == "Success"
| where OperationNameValue has_any ("LISTKEYS", "LISTSERVICESAS")
| join kind=leftanti KnownSources on Caller
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId, ResourceGroup, CorrelationId
| order by TimeGenerated desc
```

---

### What This Detection Answers

This detection can help answer:

* **Who** is enumerating storage credentials?
* **When** did this occur?
* **Is this behavior new or expected?**

It does **not** inherintly confirm credential misuse, copying, or downstream abuse.

---

### Limitations and Tradeoffs

* This detection operates at the **management plane**, not the data plane
* It assumes identity compromise **may have already occurred**
* It does not observe public blob access, poisoning, or downstream execution
* It is best classified as **risk signal**, not a standalone incident

If correlated with evidence of identity compromise, this activity may indicate an attempt to establish persistence through key or SAS reuse.

---

### TL;DR

Due to limited data-plane visibility in my environment, I pivoted from direct detection of public blob abuse to identifying management-plane behaviors that expose long-lived cloud credentials.

This detection highlights previously unseen identities enumerating storage keys or SAS tokens—an action that can enable persistence independent of identity re-evaluation—and serves as a supporting risk signal when correlated with identity compromise.
