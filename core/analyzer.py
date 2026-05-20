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


def parse_line(line: str, source: str = "unknown") -> Optional[LogEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

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
        r"(?:/etc/passwd|/etc/shadow|\.env|\.git/config|wp-config\.php"
        r"|/admin|/phpmyadmin|/actuator|/api/v\d+/admin|\.bak|\.sql)",
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

    # ── per-entry rules ───────────────────────────────────────────────────────

    def feed(self, entry: LogEntry):
        self._track_counts(entry)
        self._check_injection(entry)
        self._check_traversal(entry)
        self._check_sensitive(entry)
        self._check_scanner(entry)
        self._check_auth_failure(entry)
        self._check_server_error(entry)

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

    def _window(self, timestamps: list[datetime], anchor: datetime) -> list[datetime]:
        # Normalise both to naive UTC for comparison
        def naive(dt: datetime) -> datetime:
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        anchor_n = naive(anchor)
        cutoff = anchor_n - timedelta(minutes=self.WINDOW_MINUTES)
        return [t for t in timestamps if naive(t) >= cutoff]

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
                       [f"Matched in: {target[:200]}"])
        if self.XSS_PATTERNS.search(target):
            self._emit("R002", "XSS Attempt", ThreatLevel.MEDIUM,
                       f"Possible XSS payload from {e.ip}", e)

    def _check_traversal(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.PATH_TRAVERSAL.search(target):
            self._emit("R003", "Path Traversal Attempt", ThreatLevel.HIGH,
                       f"Directory traversal detected from {e.ip}", e)

    def _check_sensitive(self, e: LogEntry):
        target = " ".join(filter(None, [e.path, e.raw]))
        if self.SENSITIVE_PATHS.search(target):
            self._emit("R004", "Sensitive Path Access", ThreatLevel.MEDIUM,
                       f"Access to sensitive resource by {e.ip}", e,
                       [f"Path: {e.path or e.raw[:100]}"])

    def _check_scanner(self, e: LogEntry):
        if self.SCANNER_UA.search(e.raw):
            self._emit("R005", "Security Scanner Detected", ThreatLevel.HIGH,
                       f"Known vulnerability scanner UA from {e.ip}", e)

    def _check_auth_failure(self, e: LogEntry):
        msg = (e.message or e.raw).lower()
        if any(x in msg for x in ("failed password", "authentication failure", "invalid user", "failed login")):
            if e.status in (401, 403) or True:
                self._emit("R006", "Authentication Failure", ThreatLevel.LOW,
                           f"Login failure for user '{e.user}' from {e.ip}", e)

    def _check_server_error(self, e: LogEntry):
        if e.status and e.status >= 500:
            self._emit("R007", "Server Error", ThreatLevel.LOW,
                       f"HTTP {e.status} response logged", e)

    # ── aggregate rules (call after all entries fed) ──────────────────────────

    def finalize(self, all_entries: list[LogEntry]):
        self._agg_brute_force(all_entries)
        self._agg_port_scan(all_entries)
        self._agg_dos(all_entries)

    def _agg_brute_force(self, entries: list[LogEntry]):
        seen: dict[str, bool] = {}
        for e in entries:
            if not e.ip:
                continue
            anchor = e.timestamp or datetime.now()
            recent = self._window(self._ip_fail[e.ip], anchor)
            if len(recent) >= self.BRUTE_THRESHOLD and e.ip not in seen:
                seen[e.ip] = True
                self.threats.append(ThreatEvent(
                    rule_id="R008",
                    rule_name="Brute Force Attack",
                    level=ThreatLevel.CRITICAL,
                    description=f"Brute force: {len(recent)} failed logins from {e.ip} in {self.WINDOW_MINUTES}min",
                    ip=e.ip,
                    user=e.user,
                    timestamp=anchor,
                    count=len(recent),
                    evidence=[f"{len(recent)} failures in {self.WINDOW_MINUTES} minutes"],
                ))

    def _agg_port_scan(self, entries: list[LogEntry]):
        seen: dict[str, bool] = {}
        for e in entries:
            if not e.ip:
                continue
            anchor = e.timestamp or datetime.now()
            recent = self._window(self._ip_404[e.ip], anchor)
            if len(recent) >= self.SCAN_THRESHOLD and e.ip not in seen:
                seen[e.ip] = True
                self.threats.append(ThreatEvent(
                    rule_id="R009",
                    rule_name="Directory Scanning",
                    level=ThreatLevel.HIGH,
                    description=f"Directory scan: {len(recent)} 404s from {e.ip} in {self.WINDOW_MINUTES}min",
                    ip=e.ip,
                    user=None,
                    timestamp=anchor,
                    count=len(recent),
                    evidence=[f"{len(recent)} 404 responses in {self.WINDOW_MINUTES} minutes"],
                ))

    def _agg_dos(self, entries: list[LogEntry]):
        seen: dict[str, bool] = {}
        for e in entries:
            if not e.ip:
                continue
            anchor = e.timestamp or datetime.now()
            recent = self._window(self._ip_req[e.ip], anchor)
            if len(recent) >= self.DOS_THRESHOLD and e.ip not in seen:
                seen[e.ip] = True
                self.threats.append(ThreatEvent(
                    rule_id="R010",
                    rule_name="Possible DoS Attack",
                    level=ThreatLevel.CRITICAL,
                    description=f"High request rate: {len(recent)} reqs from {e.ip} in {self.WINDOW_MINUTES}min",
                    ip=e.ip,
                    user=None,
                    timestamp=anchor,
                    count=len(recent),
                    evidence=[f"{len(recent)} requests in {self.WINDOW_MINUTES} minutes"],
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

        # Deduplicate threats (same rule+IP within 10 events)
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
                seen[key].count += 1
            else:
                seen[key] = t
        return list(seen.values())
