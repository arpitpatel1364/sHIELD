"""
SHIELD - Log Analyzer & Intrusion Detection System
Core analysis engine
"""

import re
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class ThreatLevel(Enum):
    INFO    = "INFO"
    LOW     = "LOW"
    MEDIUM  = "MEDIUM"
    HIGH    = "HIGH"
    CRITICAL = "CRITICAL"

    def score(self):
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


@dataclass
class LogEntry:
    raw: str
    timestamp: Optional[datetime] = None
    ip: Optional[str] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    message: Optional[str] = None
    source: str = "unknown"

    def to_dict(self):
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class ThreatEvent:
    rule_id: str
    rule_name: str
    level: ThreatLevel
    description: str
    ip: Optional[str]
    user: Optional[str]
    timestamp: datetime
    evidence: list[str] = field(default_factory=list)
    count: int = 1

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "level": self.level.value,
            "description": self.description,
            "ip": self.ip,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "evidence": self.evidence,
            "count": self.count,
        }


@dataclass
class AnalysisReport:
    generated_at: datetime
    total_entries: int
    parsed_entries: int
    threats: list[ThreatEvent]
    summary: dict
    top_ips: list[tuple]
    top_paths: list[tuple]
    timeline: dict
    risk_score: int

    def to_dict(self):
        return {
            "generated_at": self.generated_at.isoformat(),
            "total_entries": self.total_entries,
            "parsed_entries": self.parsed_entries,
            "threats": [t.to_dict() for t in self.threats],
            "summary": self.summary,
            "top_ips": self.top_ips,
            "top_paths": self.top_paths,
            "timeline": self.timeline,
            "risk_score": self.risk_score,
        }


# ─── Log Parsers ─────────────────────────────────────────────────────────────

PARSERS = [
    # Apache / Nginx combined log
    {
        "name": "apache_combined",
        "pattern": re.compile(
            r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3})'
        ),
        "ts_fmt": "%d/%b/%Y:%H:%M:%S %z",
    },
    # SSH failed/accepted
    {
        "name": "ssh",
        "pattern": re.compile(
            r'(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*?(?P<status>Failed|Accepted|Invalid)\s+'
            r'(?:password|publickey)?\s*for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
        ),
        "ts_fmt": "%b %d %H:%M:%S",
    },
    # Auth / syslog style
    {
        "name": "syslog",
        "pattern": re.compile(
            r'(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+\S+:\s+(?P<message>.*)'
        ),
        "ts_fmt": "%b %d %H:%M:%S",
    },
    # Generic timestamp + message
    {
        "name": "generic",
        "pattern": re.compile(
            r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+(?P<message>.*)'
        ),
        "ts_fmt": "%Y-%m-%dT%H:%M:%S",
    },
]

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

ACTIVE_SCHEMA = None

class LogSchemaAutodetector:
    """Analyzes sample log lines to automatically detect schema patterns (delimiters, columns, values)."""
    @staticmethod
    def detect_schema(samples: list[str]) -> Optional[dict]:
        if not samples:
            return None
        lines = [line.strip() for line in samples if line.strip() and not line.strip().startswith("#")]
        if not lines:
            return None
        
        # JSON check
        json_count = sum(1 for line in lines if line.startswith("{") and line.endswith("}"))
        if json_count > len(lines) * 0.7:
            return {"type": "json"}
            
        # Detect delimiters
        delimiters = ['|', ',', '\t', ';']
        delim_counts = {d: [] for d in delimiters}
        for line in lines:
            for d in delimiters:
                delim_counts[d].append(line.count(d))
                
        best_delim = None
        for d, counts in delim_counts.items():
            if all(c > 0 for c in counts) and len(set(counts)) == 1:
                best_delim = d
                break
            elif all(c > 0 for c in counts):
                best_delim = d
        if not best_delim:
            best_delim = ' '
            
        split_lines = []
        for line in lines:
            if best_delim == ' ':
                split_lines.append(line.split())
            else:
                split_lines.append([t.strip() for t in line.split(best_delim)])
                
        num_cols = min(len(parts) for parts in split_lines)
        if num_cols == 0:
            return None
            
        ip_col = None
        ts_col = None
        method_col = None
        path_col = None
        status_col = None
        msg_col = None
        
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        status_pattern = re.compile(r'^\b[1-5]\d{2}\b$')
        method_pattern = re.compile(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$', re.IGNORECASE)
        path_pattern = re.compile(r'^/[a-zA-Z0-9_\-\.\/]*$')
        
        for col_idx in range(num_cols):
            tokens = [line_parts[col_idx] for line_parts in split_lines if col_idx < len(line_parts)]
            if ip_col is None and any(ip_pattern.search(tok) for tok in tokens):
                ip_col = col_idx
                continue
            if method_col is None and any(method_pattern.search(tok) for tok in tokens):
                method_col = col_idx
                continue
            if status_col is None and all(status_pattern.match(tok) for tok in tokens if tok.isdigit()):
                status_col = col_idx
                continue
            if path_col is None and any(path_pattern.match(tok) for tok in tokens):
                path_col = col_idx
                continue
            if ts_col is None:
                is_ts = False
                for tok in tokens:
                    if ('-' in tok or '/' in tok or ':' in tok) and any(c.isdigit() for c in tok):
                        is_ts = True
                        break
                if is_ts:
                    ts_col = col_idx
                    continue
                    
        mapped_cols = {ip_col, ts_col, method_col, path_col, status_col}
        for col_idx in range(num_cols - 1, -1, -1):
            if col_idx not in mapped_cols:
                msg_col = col_idx
                break
                
        return {
            "type": "delimited",
            "delimiter": best_delim,
            "ip_col": ip_col,
            "ts_col": ts_col,
            "method_col": method_col,
            "path_col": path_col,
            "status_col": status_col,
            "msg_col": msg_col
        }


def parse_line(line: str, source: str = "unknown") -> Optional[LogEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    global ACTIVE_SCHEMA
    if ACTIVE_SCHEMA and ACTIVE_SCHEMA.get("type") == "delimited":
        try:
            delim = ACTIVE_SCHEMA["delimiter"]
            parts = line.split() if delim == ' ' else [p.strip() for p in line.split(delim)]
            
            ip = None
            if ACTIVE_SCHEMA["ip_col"] is not None and ACTIVE_SCHEMA["ip_col"] < len(parts):
                raw_ip = parts[ACTIVE_SCHEMA["ip_col"]]
                ip_match = IP_RE.search(raw_ip)
                ip = ip_match.group() if ip_match else raw_ip
                
            method = parts[ACTIVE_SCHEMA["method_col"]] if ACTIVE_SCHEMA["method_col"] is not None and ACTIVE_SCHEMA["method_col"] < len(parts) else None
            path = parts[ACTIVE_SCHEMA["path_col"]] if ACTIVE_SCHEMA["path_col"] is not None and ACTIVE_SCHEMA["path_col"] < len(parts) else None
            
            status = None
            if ACTIVE_SCHEMA["status_col"] is not None and ACTIVE_SCHEMA["status_col"] < len(parts):
                st_val = parts[ACTIVE_SCHEMA["status_col"]]
                if st_val.isdigit():
                    status = int(st_val)
                    
            message = parts[ACTIVE_SCHEMA["msg_col"]] if ACTIVE_SCHEMA["msg_col"] is not None and ACTIVE_SCHEMA["msg_col"] < len(parts) else line[:200]
            
            ts = None
            if ACTIVE_SCHEMA["ts_col"] is not None and ACTIVE_SCHEMA["ts_col"] < len(parts):
                ts_str = parts[ACTIVE_SCHEMA["ts_col"]].strip("[]() ")
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%b %d %H:%M:%S"]:
                    try:
                        ts = datetime.strptime(ts_str.split(" ")[0].split(":")[0] + ":" + ":".join(ts_str.split(" ")[0].split(":")[1:]) if ":" in ts_str else ts_str, fmt)
                        break
                    except Exception:
                        pass
                        
            return LogEntry(
                raw=line,
                timestamp=ts or datetime.now(),
                ip=ip,
                user=None,
                method=method,
                path=path,
                status=status,
                message=message,
                source=source
            )
        except Exception:
            pass

    # Handle structured JSON logs
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            ip = data.get("ip") or data.get("client_ip") or data.get("host") or (IP_RE.search(line) and IP_RE.search(line).group())
            user = data.get("user") or data.get("username")
            path = data.get("path") or data.get("uri") or data.get("url") or data.get("request")
            method = data.get("method") or data.get("request_method")
            
            status_val = data.get("status") or data.get("response_code")
            status = None
            if status_val is not None:
                try:
                    status = int(status_val)
                except (ValueError, TypeError):
                    # Fallback in case status is a string like "200 OK"
                    status_str = str(status_val).split()[0]
                    if status_str.isdigit():
                        status = int(status_str)
            
            msg = data.get("message") or data.get("msg") or line[:200]
            
            ts = None
            ts_str = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            if ts_str is not None:
                if isinstance(ts_str, (int, float)):
                    try:
                        # Handle milliseconds vs seconds epoch
                        if ts_str > 1e11:
                            ts = datetime.fromtimestamp(ts_str / 1000.0)
                        else:
                            ts = datetime.fromtimestamp(ts_str)
                    except Exception:
                        pass
                else:
                    ts_str_str = str(ts_str)
                    for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"]:
                        try:
                            ts = datetime.strptime(ts_str_str, fmt)
                            break
                        except Exception:
                            pass
            
            return LogEntry(
                raw=line,
                timestamp=ts or datetime.now(),
                ip=ip,
                user=user,
                method=method,
                path=path,
                status=status,
                message=msg,
                source=source,
            )
        except Exception:
            pass

    for p in PARSERS:
        m = p["pattern"].search(line)
        if not m:
            continue
        gd = m.groupdict()

        ts = None
        for key in ("ts", "timestamp"):
            if gd.get(key):
                raw_ts = gd[key].strip()
                for fmt in [p["ts_fmt"], "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        ts = datetime.strptime(raw_ts.split(" ")[0] + " " + raw_ts.split(" ")[1] if len(raw_ts.split()) > 1 else raw_ts, fmt)
                        break
                    except Exception:
                        pass
                break

        if ts and ts.year == 1900:
            ts = ts.replace(year=datetime.now().year)

        status = None
        if gd.get("status") and gd["status"].isdigit():
            status = int(gd["status"])

        ip = gd.get("ip") or (IP_RE.search(line) and IP_RE.search(line).group())

        return LogEntry(
            raw=line,
            timestamp=ts or datetime.now(),
            ip=ip,
            user=gd.get("user"),
            method=gd.get("method"),
            path=gd.get("path"),
            status=status,
            message=gd.get("message", line[:200]),
            source=source,
        )

    # Fallback: at least extract IP if present
    ip_match = IP_RE.search(line)
    return LogEntry(raw=line, timestamp=datetime.now(), ip=ip_match.group() if ip_match else None,
                    message=line[:200], source=source)


# ─── Detection Rules ──────────────────────────────────────────────────────────

class DetectionEngine:
    """Stateful rule engine. Call feed() per entry, then finalize() for aggregate rules."""

    SQLI_PATTERNS = re.compile(
        r"(?:union[\s+]+select|select\s+.*from|insert\s+into|drop\s+table"
        r"|--\s*$|;\s*--|'\s*or\s+'1'='1|1=1|exec\s*\(|xp_cmdshell)",
        re.IGNORECASE,
    )
    XSS_PATTERNS = re.compile(
        r"(?:<script[^>]*>|javascript:|onerror=|onload=|eval\(|alert\(|document\.cookie)",
        re.IGNORECASE,
    )
    PATH_TRAVERSAL = re.compile(r"\.\.[\\/]|%2e%2e[\\/]|%252e", re.IGNORECASE)
    SCANNER_UA     = re.compile(r"(?:nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster)", re.IGNORECASE)
    SENSITIVE_PATHS = re.compile(
        r"(?:/admin|/phpmyadmin|/actuator|/api/v\d+/admin)",
        re.IGNORECASE,
    )
    LFI_RFI = re.compile(
        r"(?:=https?://|=ftp://|/etc/passwd|/etc/hosts|/win\.ini|boot\.ini)",
        re.IGNORECASE,
    )
    CMD_INJECTION = re.compile(
        r"(?:[;&|`]\s*(?:cat|wget|curl|ping|id|whoami|uname|sh|bash|powershell|cmd\.exe)\b|\$\(.*\))",
        re.IGNORECASE,
    )
    WEB_SHELL = re.compile(
        r"(?:shell\.php|cmd\.php|c99\.php|r57\.php|eval-stdin\.php|backdoor\.php|shell\.jsp|cmd\.jsp|cmd\.aspx)",
        re.IGNORECASE,
    )
    CREDENTIAL_LEAK = re.compile(
        r"(?:\.env|\.git/config|wp-config\.php|database\.yml|config\.json|settings\.py|backup\.sql|dump\.sql|\.bak|\.sql)",
        re.IGNORECASE,
    )

    BRUTE_THRESHOLD  = 5    # failed logins from one IP in window
    SCAN_THRESHOLD   = 20   # 404s from one IP in window
    DOS_THRESHOLD    = 200  # total requests from one IP in window
    WINDOW_MINUTES   = 5

    def __init__(self):
        self._ip_fail: defaultdict[str, list[datetime]]  = defaultdict(list)
        self._ip_404:  defaultdict[str, list[datetime]]  = defaultdict(list)
        self._ip_req:  defaultdict[str, list[datetime]]  = defaultdict(list)
        self.threats: list[ThreatEvent] = []
        self._emitted_agg_keys = set()

    def feed_realtime(self, entry: LogEntry) -> list[ThreatEvent]:
        """Feeds a single entry, runs per-entry rules, runs IP-specific agg rules, and returns new threats found."""
        start_len = len(self.threats)
        self.feed(entry)
        
        # Check aggregates for the IP immediately
        if entry.ip:
            self._check_realtime_agg(entry.ip, entry.timestamp or datetime.now())
            
        return self.threats[start_len:]

    def _check_realtime_agg(self, ip: str, ts: datetime):
        # 1. Brute Force
        if ip in self._ip_fail:
            max_cnt, peak_window = self._get_max_window_count(self._ip_fail[ip])
            if max_cnt >= self.BRUTE_THRESHOLD:
                # Key on ip and a block multiplier to avoid double alerting too frequently
                key = ("R008", ip, max_cnt // 5)
                if key not in self._emitted_agg_keys:
                    self._emitted_agg_keys.add(key)
                    self.threats.append(ThreatEvent(
                        rule_id="R008",
                        rule_name="Brute Force Attack",
                        level=ThreatLevel.CRITICAL,
                        description=f"Brute force: {max_cnt} failed logins from {ip} in {self.WINDOW_MINUTES}min",
                        ip=ip,
                        user=None,
                        timestamp=peak_window[-1],
                        count=max_cnt,
                        evidence=[f"{max_cnt} failures in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                    ))

        # 2. Directory Scanning
        if ip in self._ip_404:
            max_cnt, peak_window = self._get_max_window_count(self._ip_404[ip])
            if max_cnt >= self.SCAN_THRESHOLD:
                key = ("R009", ip, max_cnt // 10)
                if key not in self._emitted_agg_keys:
                    self._emitted_agg_keys.add(key)
                    self.threats.append(ThreatEvent(
                        rule_id="R009",
                        rule_name="Directory Scanning",
                        level=ThreatLevel.HIGH,
                        description=f"Directory scan: {max_cnt} 404s from {ip} in {self.WINDOW_MINUTES}min",
                        ip=ip,
                        user=None,
                        timestamp=peak_window[-1],
                        count=max_cnt,
                        evidence=[f"{max_cnt} 404 responses in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                    ))

        # 3. DoS Attack
        if ip in self._ip_req:
            max_cnt, peak_window = self._get_max_window_count(self._ip_req[ip])
            if max_cnt >= self.DOS_THRESHOLD:
                key = ("R010", ip, max_cnt // 50)
                if key not in self._emitted_agg_keys:
                    self._emitted_agg_keys.add(key)
                    self.threats.append(ThreatEvent(
                        rule_id="R010",
                        rule_name="Possible DoS Attack",
                        level=ThreatLevel.CRITICAL,
                        description=f"High request rate: {max_cnt} reqs from {ip} in {self.WINDOW_MINUTES}min",
                        ip=ip,
                        user=None,
                        timestamp=peak_window[-1],
                        count=max_cnt,
                        evidence=[f"{max_cnt} requests in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                    ))


    # ── per-entry rules ───────────────────────────────────────────────────────

    def feed(self, entry: LogEntry):
        self._track_counts(entry)
        self._check_injection(entry)
        self._check_traversal(entry)
        self._check_sensitive(entry)
        self._check_scanner(entry)
        self._check_auth_failure(entry)
        self._check_server_error(entry)
        self._check_lfi_rfi(entry)
        self._check_cmd_injection(entry)
        self._check_web_shell(entry)
        self._check_cred_leak(entry)

    def _track_counts(self, e: LogEntry):
        now = e.timestamp or datetime.now()
        if e.ip:
            self._ip_req[e.ip].append(now)
            if e.status == 404:
                self._ip_404[e.ip].append(now)

        # SSH/auth fail tracking
        msg = (e.message or "").lower()
        if (("failed" in msg or "invalid" in msg or "failure" in msg) or (e.status in (401, 403))) and e.ip:
            self._ip_fail[e.ip].append(now)

    def _get_max_window_count(self, ts_list: list[datetime]) -> tuple[int, list[datetime]]:
        if not ts_list:
            return 0, []
        
        def naive(dt: datetime) -> datetime:
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
            
        sorted_ts = sorted(ts_list, key=naive)
        max_count = 0
        best_window = []
        
        left = 0
        n = len(sorted_ts)
        window_delta = timedelta(minutes=self.WINDOW_MINUTES)
        
        for right in range(n):
            right_time = naive(sorted_ts[right])
            while right_time - naive(sorted_ts[left]) > window_delta:
                left += 1
            
            count = right - left + 1
            if count > max_count:
                max_count = count
                best_window = sorted_ts[left:right+1]
                
        return max_count, best_window

    def _emit(self, rule_id, name, level, desc, entry, evidence=None):
        self.threats.append(ThreatEvent(
            rule_id=rule_id,
            rule_name=name,
            level=level,
            description=desc,
            ip=entry.ip,
            user=entry.user,
            timestamp=entry.timestamp or datetime.now(),
            evidence=evidence or [entry.raw[:200]],
        ))

    def _check_injection(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.message, e.raw]))
        if self.SQLI_PATTERNS.search(target):
            self._emit("R001", "SQL Injection Attempt", ThreatLevel.HIGH,
                       f"Possible SQLi in request from {e.ip}", e,
                       [f"Matched SQLi: {target[:200]}"])
        if self.XSS_PATTERNS.search(target):
            self._emit("R002", "XSS Attempt", ThreatLevel.MEDIUM,
                       f"Possible XSS payload from {e.ip}", e,
                       [f"Matched XSS: {target[:200]}"])

    def _check_traversal(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.PATH_TRAVERSAL.search(target):
            self._emit("R003", "Path Traversal Attempt", ThreatLevel.HIGH,
                       f"Directory traversal detected from {e.ip}", e,
                       [f"Matched traversal: {target[:200]}"])

    def _check_sensitive(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.SENSITIVE_PATHS.search(target):
            self._emit("R004", "Sensitive Path Access", ThreatLevel.MEDIUM,
                       f"Access to sensitive admin/management resource by {e.ip}", e,
                       [f"Path: {e.path or e.raw[:100]}"])

    def _check_scanner(self, e: LogEntry):
        if self.SCANNER_UA.search(e.raw):
            self._emit("R005", "Security Scanner Detected", ThreatLevel.HIGH,
                       f"Known vulnerability scanner UA from {e.ip}", e,
                       [f"Scanner UA: {e.raw[:200]}"])

    def _check_auth_failure(self, e: LogEntry):
        msg = (e.message or e.raw).lower()
        is_auth_msg = any(x in msg for x in ("failed password", "authentication failure", "invalid user", "failed login", "unauthorized"))
        is_auth_status = e.status in (401, 403)
        if is_auth_msg or is_auth_status:
            self._emit("R006", "Authentication Failure", ThreatLevel.LOW,
                       f"Login failure for user '{e.user or 'unknown'}' from {e.ip}", e,
                       [f"Failure log: {e.raw[:200]}"])

    def _check_server_error(self, e: LogEntry):
        if e.status and e.status >= 500:
            self._emit("R007", "Server Error", ThreatLevel.LOW,
                       f"HTTP {e.status} response logged", e,
                       [f"Status {e.status} message: {e.raw[:100]}"])

    def _check_lfi_rfi(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.message, e.raw]))
        if self.LFI_RFI.search(target):
            self._emit("R011", "LFI/RFI Attempt", ThreatLevel.HIGH,
                       f"Possible Local/Remote File Inclusion from {e.ip}", e,
                       [f"Matched LFI/RFI: {target[:200]}"])

    def _check_cmd_injection(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.message, e.raw]))
        if self.CMD_INJECTION.search(target):
            self._emit("R012", "Command Injection Attempt", ThreatLevel.HIGH,
                       f"Possible command injection from {e.ip}", e,
                       [f"Matched command injection: {target[:200]}"])

    def _check_web_shell(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.WEB_SHELL.search(target):
            self._emit("R013", "Web Shell Access Attempt", ThreatLevel.HIGH,
                       f"Web shell file access detected from {e.ip}", e,
                       [f"File: {e.path or e.raw[:100]}"])

    def _check_cred_leak(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.CREDENTIAL_LEAK.search(target):
            self._emit("R014", "Sensitive Config Access", ThreatLevel.HIGH,
                       f"Access to configuration/backup file from {e.ip}", e,
                       [f"File: {e.path or e.raw[:100]}"])

    # ── aggregate rules (call after all entries fed) ──────────────────────────

    def finalize(self, all_entries: list[LogEntry]):
        self._agg_brute_force(all_entries)
        self._agg_port_scan(all_entries)
        self._agg_dos(all_entries)

    def _agg_brute_force(self, entries: list[LogEntry]):
        for ip, fail_ts in self._ip_fail.items():
            if not ip:
                continue
            max_cnt, peak_window = self._get_max_window_count(fail_ts)
            if max_cnt >= self.BRUTE_THRESHOLD:
                self.threats.append(ThreatEvent(
                    rule_id="R008",
                    rule_name="Brute Force Attack",
                    level=ThreatLevel.CRITICAL,
                    description=f"Brute force: {max_cnt} failed logins from {ip} in {self.WINDOW_MINUTES}min",
                    ip=ip,
                    user=None,
                    timestamp=peak_window[-1],
                    count=max_cnt,
                    evidence=[f"{max_cnt} failures in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                ))

    def _agg_port_scan(self, entries: list[LogEntry]):
        for ip, ts_404 in self._ip_404.items():
            if not ip:
                continue
            max_cnt, peak_window = self._get_max_window_count(ts_404)
            if max_cnt >= self.SCAN_THRESHOLD:
                self.threats.append(ThreatEvent(
                    rule_id="R009",
                    rule_name="Directory Scanning",
                    level=ThreatLevel.HIGH,
                    description=f"Directory scan: {max_cnt} 404s from {ip} in {self.WINDOW_MINUTES}min",
                    ip=ip,
                    user=None,
                    timestamp=peak_window[-1],
                    count=max_cnt,
                    evidence=[f"{max_cnt} 404 responses in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                ))

    def _agg_dos(self, entries: list[LogEntry]):
        for ip, req_ts in self._ip_req.items():
            if not ip:
                continue
            max_cnt, peak_window = self._get_max_window_count(req_ts)
            if max_cnt >= self.DOS_THRESHOLD:
                self.threats.append(ThreatEvent(
                    rule_id="R010",
                    rule_name="Possible DoS Attack",
                    level=ThreatLevel.CRITICAL,
                    description=f"High request rate: {max_cnt} reqs from {ip} in {self.WINDOW_MINUTES}min",
                    ip=ip,
                    user=None,
                    timestamp=peak_window[-1],
                    count=max_cnt,
                    evidence=[f"{max_cnt} requests in {self.WINDOW_MINUTES} minutes starting at {peak_window[0].strftime('%H:%M:%S')}"],
                ))


# ─── Main Analyzer ────────────────────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self):
        self.engine = DetectionEngine()

    def analyze(self, log_text: str, source: str = "upload") -> AnalysisReport:
        lines = log_text.splitlines()
        total = len(lines)
        entries: list[LogEntry] = []

        for line in lines:
            e = parse_line(line, source)
            if e:
                entries.append(e)
                self.engine.feed(e)

        self.engine.finalize(entries)

        # Deduplicate threats
        threats = self._dedup(self.engine.threats)

        # Stats
        ip_counter    = Counter(e.ip   for e in entries if e.ip)
        path_counter  = Counter(e.path for e in entries if e.path)
        status_counts = Counter(e.status for e in entries if e.status)

        timeline: dict[str, int] = defaultdict(int)
        for e in entries:
            if e.timestamp:
                key = e.timestamp.strftime("%H:%M")
                timeline[key] += 1

        level_counts = Counter(t.level.value for t in threats)
        risk_score = sum(t.level.score() * t.count for t in threats)
        risk_score = min(100, risk_score)

        return AnalysisReport(
            generated_at=datetime.now(),
            total_entries=total,
            parsed_entries=len(entries),
            threats=sorted(threats, key=lambda t: t.level.score(), reverse=True),
            summary={
                "by_level": dict(level_counts),
                "status_codes": {str(k): v for k, v in status_counts.items()},
                "unique_ips": len(ip_counter),
                "unique_paths": len(path_counter),
            },
            top_ips=ip_counter.most_common(10),
            top_paths=path_counter.most_common(10),
            timeline=dict(sorted(timeline.items())),
            risk_score=risk_score,
        )

    def _dedup(self, threats: list[ThreatEvent]) -> list[ThreatEvent]:
        seen: dict[str, ThreatEvent] = {}
        for t in threats:
            key = f"{t.rule_id}:{t.ip}:{t.user}"
            if key in seen:
                seen[key].count += t.count
                for ev in t.evidence:
                    if ev not in seen[key].evidence and len(seen[key].evidence) < 5:
                        seen[key].evidence.append(ev)
            else:
                seen[key] = t
        return list(seen.values())
