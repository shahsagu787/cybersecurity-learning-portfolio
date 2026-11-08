# Cybersecurity Portfolio - Week 3, Day 15
## Topic: Windows Process Genealogy, Registry Persistence & Sysinternals (`Process Explorer` & `Autoruns`)

**Objective:** 
Transition from Linux process and persistence auditing (`ps aux`, `cron`, `.bashrc`) to Windows endpoint forensics using the **Microsoft Sysinternals Suite** (`Process Explorer` and `Autoruns`). Analyze live Windows parent-child process trees (`services.exe` $\rightarrow$ `svchost.exe` and `explorer.exe` $\rightarrow$ user applications), distinguish betweennormal system daemons and malicious process masquerading, and audit Windows Registry `Run` keys (`HKLM` and `HKCU`) for startup persistence.

### :hammer_and_wrench: Tools & Environment
* **Host OS:** Windows (`SAGARSHAH\shahs`)
* **Forensic Utilities:** Microsoft Sysinternals **Process Explorer** (`procexp64.exe`) & **Autoruns** (`Autoruns64.exe`)
* **Reference Frameworks:** 13Cubed / SANS Windows Process Genealogy, MITRE ATT&CK (`T1547.001`, `T1036`, `T1059.001`)

---

### :mag: Part 1: Windows Process Genealogy — Normal vs. Suspicious Parent-Child Trees

In Windows incident response, threat actors frequently name malicious binaries after legitimate system executables (such as `svchost.exe` or `lsass.exe` — **MITRE ATT&CK `T1036` Masquerading**) or use weaponized Office documents to spawn command interpreters. SOC analysts validate process legitimacy by inspecting the **Parent Process**, **Execution Path**, and **Session Context**:

| Process Name | Role in Windows OS | Expected Parent Process | Expected Image Path | :rotating_light: SOC Anomaly / Malware Indicator |
| :--- | :--- | :--- | :--- | :--- |
| **`services.exe`** | Service Control Manager (initializes and manages background Windows services). | `wininit.exe` | `C:\Windows\System32\services.exe` | Executing outside `System32` or spawned by a user-level process (`explorer.exe`, `cmd.exe`). |
| **`svchost.exe`** | Generic Host Process for Windows `.dll` services (Pink service rows in Process Explorer). | **`services.exe` ONLY** | `C:\Windows\System32\svchost.exe` | **High-Priority Alert:** Any `svchost.exe` whose parent is **not** `services.exe`, or running from `C:\Users\Public\` or `AppData`. |
| **`lsass.exe`** | Local Security Authority Subsystem Service (validates logins and manages credentials in memory). | `wininit.exe` | `C:\Windows\System32\lsass.exe` | Multiple running instances (only **one** `lsass.exe` should exist, observed at `PID 1556`), or suspicious processes opening read handles to `lsass.exe` (`T1003.001` Mimikatz credential dumping). |
| **`explorer.exe`** | Windows GUI Desktop Shell (Start Menu, Taskbar, File Explorer). | `userinit.exe` (exits after initialization) | `C:\Windows\explorer.exe` | Spawning unexpected background scripts or initiating raw external C2 network connections. |
| **`winword.exe` / `excel.exe`** | Microsoft Office productivity applications (`EXCEL.EXE` observed at `PID 21820`). | `explorer.exe` | `C:\Program Files\Microsoft Office\...` | **Critical Phishing / Macro Alert (`T1204.002`):** `winword.exe` or `EXCEL.EXE` spawning child shells such as **`powershell.exe`**, **`cmd.exe`**, **`wscript.exe`**, or **`rundll32.exe`**. |

---

### :computer: Part 2: Live Process Tree Analysis (`ProcessExplorer.jpg`)

Using **Sysinternals Process Explorer** (`procexp64.exe`), I inspected the active process hierarchy and memory footprint across system services (highlighted in **pink**) and user-context applications (highlighted in **purple**):

1. **Background Service Hierarchy (Pink Rows):**
   * Verified multiple legitimate `svchost.exe` instances (`PIDs 12072, 12948, 13584, 14400`, etc.) running under `Microsoft Corporation` alongside third-party endpoint security services (`sapissvc.exe` — `PID 10040` and `scanwscsex.exe` — `PID 21396`, *Quick Heal Technologies Antimalware Scan Service*) and virtualization services (`vmcompute.exe` — `PID 20104`, *Hyper-V Host Compute Service* powering WSL).
2. **Core Credential & Security Processes:**
   * Confirmed a single legitimate instance of **`lsass.exe`** (`PID 1556`, *Local Security Authority Process*) alongside **`LsaIso.exe`** (`PID 1536`, *Credential Guard / LSA Isolated*).
3. **User Desktop Genealogy (`explorer.exe` — `PID 6596`):**
   * Traced interactive user applications directly indented as child processes underneath **`explorer.exe` (`PID 6596`)**:
     * `SecurityHealthSystray.exe` (`PID 17912`) — Windows Security notification icon
     * `RtkAudUService64.exe` (`PID 18096`) — Realtek HD Audio Universal Service
     * `chrome.exe` (`PID 4544`) — Google Chrome browser
     * `EXCEL.EXE` (`PID 21820`) — Microsoft Excel
     * `procexp64.exe` (`PID 26232`) — Sysinternals Process Explorer

*(Screenshot: Inspecting Windows background services, `lsass.exe`, and the `explorer.exe` parent-child process tree in Sysinternals Process Explorer)*
![Sysinternals Process Explorer Hierarchy](ProcessExplorer.jpg)

---

### :lock: Part 3: Registry Startup Persistence Auditing (`Autoruns.jpg`)

Just as Linux adversaries abuse `/etc/crontab` and `~/.bashrc` for persistence, Windows malware frequently registers startup entries inside the Windows Registry `Run` and `RunOnce` keys (**MITRE ATT&CK `T1547.001` - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**).

Using **Sysinternals Autoruns** (`Autoruns64.exe`) filtered to the **Logon** tab, I audited both user-specific (`HKCU`) and machine-wide (`HKLM`) startup locations and verified publisher digital signatures:

1. **`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (Current User Logon):**
   * `Adobe Acrobat Synchronizer` — `(Verified) Adobe Inc.` (`C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe`)
   * `MicrosoftEdgeAutoLaunch` — `(Verified) Microsoft Corporation` (`msedge.exe`)
   * `OneDrive` — `(Verified) Microsoft Corporation` (`C:\Users\shahs\AppData\Local\Microsoft\OneDrive\OneDrive.exe`)
2. **`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (Machine-Wide Logon):**
   * `Quick Heal Core UI` — `(Verified) QUICK HEAL TECHNOLOGIES` (`D:\QuickHeal\Quick Heal Internet Security\strtupap.exe`)
   * `RtkAudUService` — `(Verified) Realtek Semiconductor Corp.` (`C:\WINDOWS\System32\RtkAudUService64.exe`)
3. **Start Menu Startup Folder (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`):**
   * `FxSound.lnk` — `(Verified) FxSound, LLC` (`C:\Program Files\FxSound LLC\FxSound\FxSound.exe`)

*(Screenshot: Auditing `HKCU` and `HKLM` Registry `Run` persistence keys and digital signature verification in Sysinternals Autoruns)*
![Sysinternals Autoruns Registry Persistence](Autoruns.jpg)

---

### :bulb: Conclusion
Successfully analyzed live Windows process trees and Registry autostart mechanisms using Microsoft Sysinternals **Process Explorer** and **Autoruns**. Established a baseline understanding of legitimate parent-child relationships (`services.exe` $\rightarrow$ `svchost.exe` and `explorer.exe` $\rightarrow$ user apps) versus high-severity SOC indicators (such as `EXCEL.EXE` or `winword.exe` spawning `powershell.exe` or unverified binaries hiding inside `CurrentVersion\Run`).