 
# Environment & Objective:
Identify endpoints exhibiting indicators of initial access attempts within the last 24 hours and validate whether initial access attempts progresed into successful compromise within a large-scale Azure honeynet environment.


## Initial Scoping

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*6uG4iw65orC40gA-IMkAJQ.png)

> Two endpoints were identified `windows-1` & `windows-2`

Incidents from the last 24 hours categorized as initial access related were reviewed in Defender XDR. `windows-2` was prioritized due to a higher number of associated alerts, indicating an elevated interest and a higher risk for compromise.

## Alert and Evidence Review


_Associated Alerts:_


![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*607eEj9CjJoVwz7JG9xkPg.png)


_Associated IPs:_

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*E_C4EoHlEEDhRJYqfdZqWw.png)

Analysis of associated alerts and entities confirmed:
- Repeated RDP authentication attempts
- Multiple external source IPs
- No indicators of post-authentication activity

_VirusTotal:_


![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*OTR8XANzIL35o-PO-1qyow.png)

External reputation lookups flagged the source IPs as malicious by multiple vendors

## Validation of Authentication Outcomes
To confirm whether any initial access attempts were successful, DeviceLogonEvents were queried over a 180-day window for the identified IPs:
```kql
let lookback = 180d;
DeviceLogonEvents
| where Timestamp >= ago(lookback)
| where RemoteIP in ("119.148.8.66", "121.182.226.243", "42.204.187.63", "20.75.54.7", "80.94.95.43")
| where ActionType in ("LogonFailed", "LogonSuccess")
| summarize FailedAttempts = count() by RemoteIP, ActionType, FailureReason
This query counts failed and successful login attempts from specified IPs over the last 180 days.
```

_Query Results:_


![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Dk31J3ElNzgsy8MhWw3Bqg.png)

No LogonSuccess events were observed for these IPs within the queried timeframe

The activity was assessed as unsuccessful brute-force behavior with no evidence of compromise.

## Remediation & Risk Reduction Steps:
In a production environment, response actions would depend on the system’s intended exposure and organizational policy.

If the resource were not intended to be internet-facing, access could be restricted at the network security group (NSG) level to eliminate unnecessary RDP exposure. If public access were required, compensating controls such as tighter NSG rules, IP allowlisting, or additional access controls could be implemented to reduce repeated brute-force attempts.

> No remediation actions were applied in this honeynet environment.
