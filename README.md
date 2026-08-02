# ThreatHunter-SIEM

![CI](https://github.com/SRINIVASAN55/ThreatHunter-SIEM/actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg)



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

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.8 or higher |
| OS | Linux, macOS, Windows |
| Log files | auth.log, syslog, or any line-based log |

Check your Python version:
```bash
python3 --version
```

---

## Installation

```bash
git clone https://github.com/SRINIVASAN55/ThreatHunter-SIEM.git
cd ThreatHunter-SIEM
pip install -r requirements.txt
```

---

## Running It

### Demo mode — see it in action immediately
```bash
python3 threathunter.py --demo
```
Runs a built-in simulated attack scenario (brute force → lateral movement → exfiltration) and shows exactly how ThreatHunter detects and reports it. No log files needed.

### Analyze a log file
```bash
python3 threathunter.py --file /var/log/auth.log
python3 threathunter.py --file /var/log/syslog
python3 threathunter.py --file /path/to/any.log
```
Scans the file against all detection rules and prints findings with severity, MITRE technique ID, and recommended response.

### Analyze multiple log files at once
```bash
python3 threathunter.py --file /var/log/auth.log --file /var/log/syslog --file /var/log/apache2/access.log
```

### Live tail — monitor logs in real time
```bash
python3 threathunter.py --file /var/log/auth.log --tail
```
Watches the log file for new lines and alerts instantly. Like `tail -f` but with threat detection on top.

### Save report to a directory
```bash
python3 threathunter.py --file /var/log/auth.log --output ./reports/
```
Writes an HTML report and JSON findings file to `./reports/`.

### Use a custom rules file
```bash
python3 threathunter.py --file /var/log/auth.log --rules my_rules.json
```
Override the built-in rules with your own detection logic in JSON format.

---

## All CLI Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--file` | `-f` | Log file to analyze (repeatable) | `-f /var/log/auth.log` |
| `--tail` | | Live tail mode on the last `--file` | `--tail` |
| `--demo` | | Run built-in attack scenario | `--demo` |
| `--output` | `-o` | Directory for HTML/JSON reports | `-o ./reports` |
| `--rules` | | Custom rules JSON file | `--rules my_rules.json` |

---

## Architecture

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

## Detection Rules (MITRE Mapped)

- **T1110** — Brute force (SSH, RDP, web login)
- **T1021** — Remote service abuse (SMB, WinRM, RDP)
- **T1059** — Scripting interpreter abuse
- **T1071** — Application-layer C2 (HTTP/DNS/ICMP)
- **T1003** — Credential dumping indicators
- **T1053** — Scheduled task creation anomalies
- **T1078** — Valid account misuse (off-hours, impossible travel)
- **T1190** — Exploit public-facing application

---

## Troubleshooting

**`No findings` on a log file you know has issues**
→ Try `--demo` first to confirm the tool works, then check log format — ThreatHunter expects line-based text logs.

**`Permission denied` reading log files**
→ Run with `sudo` or copy logs to a readable location: `sudo cp /var/log/auth.log ~/auth.log`

**Report not generated**
→ Make sure the output directory exists: `mkdir -p ./reports` then re-run with `-o ./reports`

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
