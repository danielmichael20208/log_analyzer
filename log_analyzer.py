"""
log_analyzer.py — Suspicious Log Activity Detector
Daniel Michael | github.com/danielmichael20208

Reads Linux auth.log / Apache access.log style files,
detects suspicious patterns, and exports SIEM-ready JSON events.

Usage:
  python log_analyzer.py --file auth.log
  python log_analyzer.py --file access.log --type apache
  python log_analyzer.py --demo
"""

import re
import json
import argparse
from datetime import datetime, timezone
from collections import defaultdict

# ─────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5   # failed logins from same IP before alert
SCAN_PORT_THRESHOLD   = 10  # requests to different paths = scan alert
SIEM_OUTPUT_FILE      = "siem_events.json"

# ─────────────────────────────────────────────────────────
#  DEMO LOG DATA (used when --demo flag is passed)
# ─────────────────────────────────────────────────────────
DEMO_AUTH_LOG = """
Jan 15 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:05 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:07 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:09 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:25:00 server sshd[1235]: Accepted password for daniel from 10.0.0.5 port 22 ssh2
Jan 15 10:26:00 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 15 10:26:01 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 15 10:26:02 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 15 10:26:03 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 15 10:26:04 server sshd[1236]: Failed password for admin from 203.0.113.42 port 22 ssh2
Jan 15 10:30:00 server sudo[1300]: daniel : TTY=pts/0 ; PWD=/home/daniel ; USER=root ; COMMAND=/bin/bash
Jan 15 10:31:00 server sshd[1237]: Invalid user hacker from 198.51.100.7 port 22 ssh2
""".strip()

DEMO_ACCESS_LOG = """
192.168.1.50 - - [15/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 512
192.168.1.50 - - [15/Jan/2026:10:00:02 +0000] "GET /about.html HTTP/1.1" 200 300
10.0.0.20 - - [15/Jan/2026:10:01:00 +0000] "GET /admin HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:01 +0000] "GET /wp-admin HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:02 +0000] "GET /phpmyadmin HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:03 +0000] "GET /.env HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:04 +0000] "GET /config.php HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:05 +0000] "GET /backup.zip HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:06 +0000] "GET /login HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:07 +0000] "GET /shell.php HTTP/1.1" 404 128
10.0.0.20 - - [15/Jan/2026:10:01:08 +0000] "GET /etc/passwd HTTP/1.1" 400 128
10.0.0.20 - - [15/Jan/2026:10:01:09 +0000] "GET /uploads/shell.php HTTP/1.1" 404 128
203.0.113.5 - - [15/Jan/2026:10:02:00 +0000] "GET /page.php?id=1' OR '1'='1 HTTP/1.1" 500 256
""".strip()

# ─────────────────────────────────────────────────────────
#  PATTERNS
# ─────────────────────────────────────────────────────────
SUSPICIOUS_PATHS = [
    r'\.env', r'wp-admin', r'phpmyadmin', r'\.git', r'backup',
    r'shell\.php', r'config\.php', r'/etc/passwd', r'\.htaccess',
]

SQLI_PATTERNS = [
    r"'.*OR.*'.*'", r"UNION.*SELECT", r"DROP.*TABLE",
    r"1=1", r"--\s*$", r"xp_cmdshell",
]

# ─────────────────────────────────────────────────────────
#  EVENT BUILDER
# ─────────────────────────────────────────────────────────
def make_event(event_type, severity, source_ip, description, raw_line=""):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,       # LOW / MEDIUM / HIGH / CRITICAL
        "source_ip": source_ip,
        "description": description,
        "raw": raw_line.strip(),
    }

# ─────────────────────────────────────────────────────────
#  AUTH LOG PARSER
# ─────────────────────────────────────────────────────────
def analyze_auth_log(content):
    events = []
    failed_attempts = defaultdict(int)   # ip → count
    failed_users    = defaultdict(set)   # ip → set of usernames tried

    failed_re  = re.compile(r'Failed password for (\S+) from ([\d.]+)')
    accept_re  = re.compile(r'Accepted password for (\S+) from ([\d.]+)')
    invalid_re = re.compile(r'Invalid user (\S+) from ([\d.]+)')
    sudo_re    = re.compile(r'sudo.*USER=root.*COMMAND=(.*)')

    lines = content.strip().split('\n')
    print(f"\n[*] Analyzing auth log — {len(lines)} lines")

    for line in lines:
        # Failed password
        m = failed_re.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            failed_attempts[ip] += 1
            failed_users[ip].add(user)
            if failed_attempts[ip] == BRUTE_FORCE_THRESHOLD:
                events.append(make_event(
                    "BRUTE_FORCE_DETECTED", "HIGH", ip,
                    f"Brute-force threshold reached: {failed_attempts[ip]} failed logins "
                    f"targeting user(s): {', '.join(failed_users[ip])}", line
                ))
                print(f"  [!] BRUTE FORCE — {ip} ({failed_attempts[ip]} attempts, users: {', '.join(failed_users[ip])})")
            elif failed_attempts[ip] > BRUTE_FORCE_THRESHOLD:
                # Continue incrementing but don't spam events
                pass
            else:
                events.append(make_event(
                    "FAILED_LOGIN", "LOW", ip,
                    f"Failed login for '{user}'", line
                ))
            continue

        # Accepted login
        m = accept_re.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            severity = "MEDIUM" if failed_attempts.get(ip, 0) > 0 else "INFO"
            events.append(make_event(
                "SUCCESSFUL_LOGIN", severity, ip,
                f"Successful login for '{user}'" +
                (f" (after {failed_attempts[ip]} failed attempts)" if failed_attempts.get(ip) else ""),
                line
            ))
            if severity == "MEDIUM":
                print(f"  [!] SUSPICIOUS LOGIN — {ip} succeeded after {failed_attempts[ip]} failures")
            else:
                print(f"  [+] Login OK — {user} from {ip}")
            continue

        # Invalid user
        m = invalid_re.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            events.append(make_event(
                "INVALID_USER_ATTEMPT", "MEDIUM", ip,
                f"Login attempt for non-existent user '{user}'", line
            ))
            print(f"  [!] INVALID USER — '{user}' from {ip}")
            continue

        # Sudo to root
        m = sudo_re.search(line)
        if m:
            cmd = m.group(1).strip()
            events.append(make_event(
                "SUDO_ROOT_ESCALATION", "HIGH", "localhost",
                f"Privilege escalation to root — command: {cmd}", line
            ))
            print(f"  [!] SUDO ROOT — command: {cmd}")

    # Summary: IPs that exceeded threshold
    for ip, count in failed_attempts.items():
        if count > BRUTE_FORCE_THRESHOLD:
            events.append(make_event(
                "BRUTE_FORCE_SUMMARY", "CRITICAL", ip,
                f"Total of {count} failed login attempts from {ip}, "
                f"targeting: {', '.join(failed_users[ip])}"
            ))

    return events

# ─────────────────────────────────────────────────────────
#  APACHE ACCESS LOG PARSER
# ─────────────────────────────────────────────────────────
def analyze_access_log(content):
    events = []
    ip_paths = defaultdict(set)   # ip → set of paths (scan detection)

    access_re = re.compile(
        r'([\d.]+) .+? "(\w+) (.+?) HTTP.+?" (\d{3})'
    )

    lines = content.strip().split('\n')
    print(f"\n[*] Analyzing access log — {len(lines)} lines")

    for line in lines:
        m = access_re.search(line)
        if not m:
            continue
        ip, method, path, status = m.group(1), m.group(2), m.group(3), m.group(4)
        ip_paths[ip].add(path)

        # Suspicious path check
        for pattern in SUSPICIOUS_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                events.append(make_event(
                    "SUSPICIOUS_PATH_ACCESS", "HIGH", ip,
                    f"Request to sensitive path: {path} (status {status})", line
                ))
                print(f"  [!] SUSPICIOUS PATH — {ip} → {path} [{status}]")
                break

        # SQLi check
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                events.append(make_event(
                    "SQL_INJECTION_ATTEMPT", "CRITICAL", ip,
                    f"Possible SQL injection in request: {path}", line
                ))
                print(f"  [!!!] SQLI ATTEMPT — {ip} → {path}")
                break

    # Port/path scan detection
    for ip, paths in ip_paths.items():
        if len(paths) >= SCAN_PORT_THRESHOLD:
            events.append(make_event(
                "PATH_SCAN_DETECTED", "HIGH", ip,
                f"Possible web scan — {len(paths)} unique paths requested: "
                f"{', '.join(list(paths)[:5])}...", ""
            ))
            print(f"  [!] SCAN DETECTED — {ip} hit {len(paths)} unique paths")

    return events

# ─────────────────────────────────────────────────────────
#  SIEM EXPORT
# ─────────────────────────────────────────────────────────
def export_siem(events, output_file):
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "total_events": len(events),
        "by_severity": {
            "CRITICAL": sum(1 for e in events if e["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for e in events if e["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for e in events if e["severity"] == "MEDIUM"),
            "LOW":      sum(1 for e in events if e["severity"] == "LOW"),
        },
        "events": events,
    }
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)
    return summary

# ─────────────────────────────────────────────────────────
#  PRINT REPORT
# ─────────────────────────────────────────────────────────
def print_report(summary):
    print("\n" + "="*52)
    print("  SCAN COMPLETE — SIEM REPORT")
    print("="*52)
    print(f"  Total events : {summary['total_events']}")
    print(f"  CRITICAL     : {summary['by_severity']['CRITICAL']}")
    print(f"  HIGH         : {summary['by_severity']['HIGH']}")
    print(f"  MEDIUM       : {summary['by_severity']['MEDIUM']}")
    print(f"  LOW          : {summary['by_severity']['LOW']}")
    print(f"\n  Output saved : {SIEM_OUTPUT_FILE}")
    print("="*52)

    if summary["by_severity"]["CRITICAL"] > 0:
        print("\n  [!!!] CRITICAL events detected — immediate review recommended")
    elif summary["by_severity"]["HIGH"] > 0:
        print("\n  [!] HIGH severity events found — review recommended")
    else:
        print("\n  [OK] No critical threats detected")

# ─────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Log Analyzer — Suspicious Activity Detector")
    parser.add_argument("--file",  help="Path to log file")
    parser.add_argument("--type",  choices=["auth", "apache"], default="auth", help="Log type (default: auth)")
    parser.add_argument("--demo",  action="store_true", help="Run with built-in demo data")
    args = parser.parse_args()

    print("\n  Log Analyzer — Suspicious Activity Detector")
    print("  Daniel Michael | github.com/danielmichael20208\n")

    if args.demo:
        print("[*] Running in DEMO mode\n")
        print("[*] --- AUTH LOG ---")
        auth_events = analyze_auth_log(DEMO_AUTH_LOG)
        print("\n[*] --- ACCESS LOG ---")
        access_events = analyze_access_log(DEMO_ACCESS_LOG)
        all_events = auth_events + access_events
    elif args.file:
        with open(args.file, "r") as f:
            content = f.read()
        if args.type == "auth":
            all_events = analyze_auth_log(content)
        else:
            all_events = analyze_access_log(content)
    else:
        print("[!] Provide --file <path> or use --demo")
        print("    Example: python log_analyzer.py --demo")
        return

    summary = export_siem(all_events, SIEM_OUTPUT_FILE)
    print_report(summary)

if __name__ == "__main__":
    main()
