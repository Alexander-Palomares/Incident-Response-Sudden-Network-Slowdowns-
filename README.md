# 🛡️ Internal Port Scanning Incident Response — Cybersecurity Threat Hunt

## 📄 Scenario Summary

During routine monitoring, the server team reported significant performance degradation affecting legacy systems in the `10.0.0.0/16` subnet. While external DDoS attacks were ruled out, internal traffic remained unrestricted. The security team suspected unauthorized scanning or data movement inside the network.

---

## 1. 🧰 Preparation

**🎯 Goal:** Define the hypothesis and hunting objective.

**Observation:**  
The `windows-target-1` device exhibited abnormal network behavior. Network traffic originating from internal hosts is unrestricted. There is also unrestricted use of PowerShell in the environment.

**Hypothesis:**  
An internal host may be scanning the network or transferring large files, leading to performance issues.

---

## 2. 📥 Data Collection

**🎯 Goal:** Gather logs from key data sources.

**Relevant Tables:**  
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceProcessEvents`

**Initial Query (Connection Failures):**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount
```

---

### 3. 🔍 Data Analysis
**🎯 Goal:** Confirm suspicious behavior by testing the hypothesis.

🧪 Port Scan Detection
```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize PortCount = count() by DeviceName, LocalIP, RemotePort
```

**Result:**

The port numbers scanned were sequential — a strong indicator of a port scanning attempt.

🧪 Identify Triggering Process

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-05-07T12:37:46.317813Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Result:**

A suspicious PowerShell script named portscan.ps1 was launched around the time the scanning started.

---

### 4. 🕵️‍♂️ Investigation
**🎯 Goal:** Validate findings and map behavior to attacker TTPs.

**Manual Review:**

- The script was executed by the SYSTEM account — this is unauthorized and highly suspicious.

**Device Actions:**

- Manually inspected the script on the host.
- Confirmed behavior aligned with internal reconnaissance.

**🧬 Mapped TTPs (MITRE ATT&CK):**

| **Tactic**    | **Technique**                        | **ID**   |
|---------------|--------------------------------------|----------|
| Discovery     | Network Service Scanning             | T1046    |
| Execution     | PowerShell                           | T1086    |
| Persistence   | Scheduled Task/Job *(suspected)*     | T1053    |
| Impact        | Data Destruction *(potential)*       | T1485    |

---

## 5. 🚨 Response

🎯 **Goal:** Contain and eliminate the threat.

### ✅ Actions Taken:
- **Isolation:** Immediately isolated `windows-target-1` from the network.
- **Scan:** Conducted a malware scan — results came back clean.
- **Containment:** Left device isolated to prevent further activity.
- **Remediation:** A ticket was filed to re-image or rebuild the machine.

---

## 6. 📝 Documentation

🎯 **Goal:** Record findings for future use.

- Port scan detected from internal VM (`windows-target-1`) using `portscan.ps1`.
- Triggered by `SYSTEM` account, not authorized by any admin.
- Confirmed via `DeviceNetworkEvents` and `DeviceProcessEvents`.
- Correlated event time to identify suspicious PowerShell execution.
- Took actions to isolate and rebuild the device to eliminate potential backdoors.

---

## 7. 🛠️ Improvement

🎯 **Goal:** Strengthen defenses and refine hunting strategies.

### 🔐 Prevention Suggestions:
- **PowerShell Restrictions:** Enforce PowerShell Constrained Language Mode, and enable detailed logging (Script Block, Module).
- **Least Privilege Enforcement:** Prevent `SYSTEM` or high-privilege accounts from launching custom scripts without approval.
- **Internal Network Monitoring:** Add alerts for internal scanning behavior, including port sweeps and rapid connection failures.

### 🔁 Hunt Process Enhancements:
- **Alert Tuning:** Automate alerts for excessive failed internal connections.
- **Behavioral Baselines:** Track normal PowerShell usage across hosts to flag anomalies.
- **Pivot Automation:** Automate linkages between process events and network activity for faster triage.
- **SYSTEM Account Rules:** Trigger detections when `SYSTEM` or other privileged users run scripts unexpectedly.

---


