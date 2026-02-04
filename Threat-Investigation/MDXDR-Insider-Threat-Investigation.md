# Investigating a Data Exfiltration with Microsoft Defender for Endpoint 

### Goal & Scenario

An employee working in a sensitive department was recently placed on a performance improvement plan (PIP). Following this action, management raised concerns that the employee may attempt to remove proprietary information prior to departure.

The objective of this investigation was to assess the employee’s activity on their corporate endpoint `vuln-machine` , using Microsoft Defender for Endpoint to determine whether any indicators of data exfiltration were present.
 

### Analyze Recent Device File Events

```kql
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where DeviceName == "vuln-machine"
| where RequestAccountName == "Vuln-Admin"
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, RequestAccountName, RequestAccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FileName, FileSize, SHA256
| order by Timestamp asc
```

- This query isolates recent file creation and modification activity initiated by PowerShell under the suspected users device.

Recent File Activity:


![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*nHaHvK-r_LaIy4xdNb8CXA.png)



Process Tree:

![Alt tect](https://miro.medium.com/v2/resize:fit:640/format:webp/1*IrETlO7ixQ9eVlyPLhnvsw.png)

Results showed execution of a PowerShell script exfiltratedata.ps1, followed by the introduction of compression tooling and staged employee data.

### Asses Outbound Network Activity Following Data Staging

```kql
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where DeviceName == "vuln-machine"
| where ActionType == "ConnectionSuccess"
| where RemotePort in ("443", "80")
| where InitiatingProcessFileName == "powershell.exe"
| sort by Timestamp asc
```
- This query identifies successful outbound HTTP/S connections initiated by PowerShell on the target endpoint.

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*beEu4OAXoFK9B6FQK9FCOg.png)

Two outbound connections were observered. Neither exhibited cahracteristics consistent with data exfiltration.

### TL;DR
A PowerShell script executed under a privileged user staged employee data, indicating exfiltration preparation. 

Endpoint network telemetry showed no evidence of outbound data transfer to attacker controlled infrastructure, suggesting the activity did not progress beyond local staging.


  
