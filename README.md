<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=2&height=80&text=🎯%20ThreatHunter-SIEM&fontSize=30&fontColor=ffffff" width="100%"/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![SIEM](https://img.shields.io/badge/SIEM-BlueTeam-blue?style=for-the-badge)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)](https://attack.mitre.org/)
[![No Dependencies](https://img.shields.io/badge/stdlib-only-green?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Lightweight SIEM & threat detection engine — runs entirely on Python stdlib.**  
Ingests syslog, Apache/Nginx, and JSON logs. Applies 19 built-in MITRE ATT&CK-mapped detection rules. Generates HTML dashboards and JSON reports.

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| 📥 **Multi-format Log Ingestion** | Syslog, Apache/Nginx access logs, JSON/structured logs |
| 🔍 **19 Detection Rules** | Covering brute force, SQLi, XSS, webshells, reverse shells, and more |
| 🗺️ **MITRE ATT&CK Mapped** | Every rule tagged with MITRE technique IDs |
| 📊 **HTML Dashboard** | Color-coded alert dashboard with category breakdown |
| 📄 **JSON Reports** | Machine-readable reports for integration with other tools |
| 🔴 **Live Tail Mode** | Real-time monitoring of live log files |
| 🎭 **Demo Mode** | Built-in attack scenario replay — no logs needed |

---

## 🛡️ Detection Rules (19 Built-in)

| Rule ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | Brute Force Login | HIGH | T1110 |
| AUTH-002 | Sudo/Root Execution | HIGH | T1548 |
| AUTH-004 | New User Created | HIGH | T1136 |
| NET-001 | Reverse Shell | CRITICAL | T1059 |
| NET-002 | Port Scan | HIGH | T1046 |
| NET-003 | DNS Tunneling | HIGH | T1071.004 |
| MAL-001 | Webshell Access | CRITICAL | T1505.003 |
| MAL-002 | Base64 Payload | HIGH | T1027 |
| MAL-003 | Cron Persistence | HIGH | T1053 |
| WEB-001 | SQL Injection | CRITICAL | T1190 |
| WEB-002 | XSS Attempt | HIGH | T1059.007 |
| WEB-003 | Path Traversal | HIGH | T1083 |
| SYS-002 | Firewall Disabled | CRITICAL | T1562.004 |
| SYS-003 | Log Clearing | CRITICAL | T1070 |
| ...+5 more | | | |

---

## 🚀 Quick Start

```bash
git clone https://github.com/SRINIVASAN55/ThreatHunter-SIEM.git
cd ThreatHunter-SIEM

# Run demo mode (built-in attack scenario — no logs needed)
python threathunter.py --demo

# Analyze log files
python threathunter.py -f sample_logs/auth.log
python threathunter.py -f sample_logs/web_access.log

# Analyze multiple logs
python threathunter.py -f /var/log/auth.log -f /var/log/nginx/access.log

# Live tail mode
python threathunter.py -f /var/log/syslog --tail
```

---

## 📊 Sample Alert Output

```
███ [CRITICAL] [10:28:00] Webshell Access [MAL-001]
      Category : Webshell
      MITRE    : T1505.003
      Source   : 10.0.0.5
      Log      : "GET /uploads/c99.php?cmd=id HTTP/1.1" 200 128
      Fix      : Remove webshell, scan server, rotate credentials.

███ [CRITICAL] [10:33:00] Log Clearing [SYS-003]
      Category : Defense Evasion
      MITRE    : T1070
      Log      : bash: rm /var/log/auth.log
```

---

## 📄 License

MIT License © 2024 [Srinivasan S](https://github.com/SRINIVASAN55)
