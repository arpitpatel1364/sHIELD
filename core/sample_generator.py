"""Generate realistic sample logs containing various attack patterns for demo."""

import random
from datetime import datetime, timedelta

IPS = ["192.168.1.45", "10.0.0.7", "203.0.113.88", "198.51.100.42", "172.16.0.9",
       "91.108.4.1", "185.220.101.5", "45.33.32.156", "198.199.80.1"]

PATHS = ["/", "/login", "/api/users", "/dashboard", "/admin", "/static/app.js",
         "/api/products", "/checkout", "/profile", "/api/v2/data"]

ATTACK_PATHS = [
    "/admin/config.php",
    "/?id=1' UNION SELECT username,password FROM users--",
    "/../../etc/passwd",
    "/search?q=<script>alert(document.cookie)</script>",
    "/wp-config.php",
    "/.env",
    "/phpmyadmin/",
    "/api/users?filter=1 OR 1=1",
    "/.git/config",
    "/backup.sql",
]

USERS = ["admin", "root", "www-data", "alice", "bob", "charlie", "anonymous"]


def random_ts(base: datetime, offset_secs: int = 0, jitter: int = 3600) -> str:
    dt = base + timedelta(seconds=offset_secs + random.randint(0, jitter))
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def apache_line(ip, ts, method, path, status, size=512):
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size}'


def syslog_auth(ts_str, ip, user, success=False):
    dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S +0000")
    syslog_ts = dt.strftime("%b %d %H:%M:%S")
    if success:
        return f"{syslog_ts} server sshd: Accepted password for {user} from {ip} port 22 ssh2"
    else:
        return f"{syslog_ts} server sshd: Failed password for invalid user {user} from {ip} port 22 ssh2"


def generate_sample_logs() -> str:
    base = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    lines = []

    # 1. Normal traffic
    for i in range(80):
        ip = random.choice(IPS[:5])
        ts = random_ts(base, i * 40)
        path = random.choice(PATHS)
        status = random.choices([200, 200, 200, 301, 304, 404], weights=[60, 20, 10, 5, 3, 2])[0]
        lines.append(apache_line(ip, ts, "GET", path, status))

    # 2. Brute force from one IP (> 5 fails in short window)
    bforce_ip = "91.108.4.1"
    bforce_base = base + timedelta(hours=1)
    for i in range(12):
        ts = random_ts(bforce_base, i * 15, jitter=10)
        lines.append(syslog_auth(ts, bforce_ip, "admin", success=False))
    lines.append(syslog_auth(random_ts(bforce_base, 200), bforce_ip, "admin", success=True))

    # 3. SQL Injection attempts
    sqli_ip = "185.220.101.5"
    for path in ATTACK_PATHS[1:2] + ATTACK_PATHS[7:8]:
        ts = random_ts(base, 1800)
        lines.append(apache_line(sqli_ip, ts, "GET", path, 200))
        lines.append(apache_line(sqli_ip, ts, "POST", path, 500))

    # 4. Directory traversal
    for p in ATTACK_PATHS[2:3]:
        ts = random_ts(base, 2100)
        lines.append(apache_line("45.33.32.156", ts, "GET", p, 403))

    # 5. XSS attempt
    ts = random_ts(base, 2400)
    lines.append(apache_line("198.199.80.1", ts, "GET", ATTACK_PATHS[3], 200))

    # 6. Sensitive file access
    for p in [ATTACK_PATHS[0], ATTACK_PATHS[4], ATTACK_PATHS[5], ATTACK_PATHS[8], ATTACK_PATHS[9]]:
        ts = random_ts(base, 2700 + random.randint(0, 300))
        lines.append(apache_line(random.choice([sqli_ip, "45.33.32.156"]), ts, "GET", p, random.choice([200, 403, 404])))

    # 7. Directory scanning (many 404s from same IP)
    scan_ip = "198.199.80.1"
    for i in range(25):
        ts = random_ts(base, 3600 + i * 8, jitter=5)
        fake_path = f"/probe-{random.randint(1000,9999)}"
        lines.append(apache_line(scan_ip, ts, "GET", fake_path, 404))

    # 8. High volume (DoS-like)
    dos_ip = "172.16.0.9"
    for i in range(220):
        ts = random_ts(base, 5000 + i * 1, jitter=0)
        lines.append(apache_line(dos_ip, ts, "GET", "/api/heavy", 200))

    # 9. Scanner UA
    ts = random_ts(base, 4000)
    scanner_raw = f'{sqli_ip} - - [{ts}] "GET /vulnerabilities HTTP/1.1" 200 1234 "-" "sqlmap/1.7 (https://sqlmap.org)"'
    lines.append(scanner_raw)

    random.shuffle(lines)
    return "\n".join(lines)


if __name__ == "__main__":
    print(generate_sample_logs())
