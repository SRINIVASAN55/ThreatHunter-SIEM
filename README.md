# ThreatHunter-SIEM

**Detection Engine for Security Analysts**

[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://python.org)
[![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)](https://attack.mitre.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

---

### What it detects

```
ALERT  [HIGH]    Brute-force SSH — 847 attempts in 60s from 185.220.101.45
ALERT  [CRIT]    Lateral movement — SMB relay detected on 10.0.0.x/24
ALERT  [MED]     Suspicious process tree — cmd.exe spawned by winword.exe
ALERT  [HIGH]    C2 beacon — 4h interval, JA3: a0e9f5d64349fb13191bc781f81f42e1
ALERT  [LOW]     Unusual outbound DNS — 247 unique subdomains queried today
```

ThreatHunter correlates events across logs, network flows, and process telemetry to surface the signals that matter — not noise.

---

### Architecture

```
Log Sources          Correlation Engine        Output
──────────           ──────────────────        ──────
auth.log      ──┐
syslog        ──┤──▶  Rule Engine        ──▶  Terminal alerts
network.pcap  ──┤      (MITRE-mapped)          JSON timeline
process evts  ──┤                              HTML report
custom feeds  ──┘──▶  Threat Intel      ──▶  Webhook / SIEM
                       (IOC matching)
```

---

### Rules Engine

Each rule maps to a MITRE technique. Ships with detections for:

- **T1110** — Brute force (SSH, RDP, web login)
- **T1021** — Remote service abuse (SMB, WinRM, RDP)
- **T1059** — Scripting interpreter abuse
- **T1071** — Application-layer C2 (HTTP/DNS/ICMP)
- **T1003** — Credential dumping indicators
- **T1053** — Scheduled task creation anomalies
- **T1078** — Valid account misuse (impossible travel, off-hours)
- **T1190** — Exploit public-facing application

---

### Install & Run

```bash
git clone https://github.com/SRINIVASAN55/ThreatHunter-SIEM
cd ThreatHunter-SIEM
pip install -r requirements.txt

# Watch live logs
python threat_hunter.py --watch /var/log

# Hunt through historical logs
python threat_hunter.py --hunt --logdir /var/log --days 30

# Generate incident report
python threat_hunter.py --report --output report.html
```

---

### Sample Incident Report

After a hunt session ThreatHunter generates a timeline like this:

```
[2024-01-15 02:13:44]  INITIAL ACCESS    — Spearphishing link clicked (T1566.002)
[2024-01-15 02:14:02]  EXECUTION         — PowerShell download cradle (T1059.001)
[2024-01-15 02:14:19]  PERSISTENCE       — Registry run key added (T1547.001)
[2024-01-15 02:31:07]  CREDENTIAL ACCESS — LSASS memory read (T1003.001)
[2024-01-15 03:02:55]  LATERAL MOVEMENT  — Pass-the-hash to DC (T1550.002)
[2024-01-15 03:44:12]  EXFILTRATION      — 2.3GB to 185.220.101.45:443 (T1041)
```

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
