#!/usr/bin/env python3
"""
SHIELD — Log Analyzer & Intrusion Detection System
CLI runner
"""

import sys
import os
import json
import argparse
import tty
import termios
import select
import glob
import webbrowser
import http.server
import urllib.parse
import threading
from pathlib import Path
from typing import Optional


# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent))

from core.analyzer import LogAnalyzer
from core.sample_generator import generate_sample_logs


LEVEL_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[31m",  # red
    "MEDIUM":   "\033[33m",  # yellow
    "LOW":      "\033[34m",  # blue
    "INFO":     "\033[37m",  # grey
}
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def print_banner():
    banner = f"""
{GREEN}{BOLD}
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████╗███████║██║█████╗  ██║     ██║  ██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
{RESET}
  {BOLD}Log Analyzer & Intrusion Detection System{RESET}
  ─────────────────────────────────────────
"""
    print(banner)


def print_report(report, verbose=False):
    print(f"\n{BOLD}[ ANALYSIS REPORT ]{RESET}")
    print(f"  Generated : {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Entries   : {report.parsed_entries}/{report.total_entries} parsed")
    print(f"  Unique IPs: {report.summary['unique_ips']}")

    score = report.risk_score
    if score >= 75:
        sc = color(f"{score}/100 ⚠ CRITICAL", LEVEL_COLORS["CRITICAL"])
    elif score >= 50:
        sc = color(f"{score}/100 ⚠ HIGH", LEVEL_COLORS["HIGH"])
    elif score >= 25:
        sc = color(f"{score}/100 ⚠ MEDIUM", LEVEL_COLORS["MEDIUM"])
    else:
        sc = color(f"{score}/100 ✓ LOW", GREEN)
    print(f"  Risk Score: {BOLD}{sc}{RESET}\n")

    # Threats
    print(f"{BOLD}[ THREATS DETECTED — {len(report.threats)} ]{RESET}")
    for t in report.threats:
        lvl_color = LEVEL_COLORS.get(t.level.value, "")
        tag = color(f"[{t.level.value:8s}]", lvl_color)
        ip  = f" from {t.ip}" if t.ip else ""
        user = f" user={t.user}" if t.user else ""
        print(f"  {tag} {BOLD}{t.rule_name}{RESET}{ip}{user}")
        print(f"            {t.description}")
        if verbose and t.evidence:
            for ev in t.evidence[:2]:
                print(f"            {color('↳', CYAN)} {ev[:120]}")
        print()

    # Top IPs
    if report.top_ips:
        print(f"{BOLD}[ TOP OFFENDING IPs ]{RESET}")
        for ip, count in report.top_ips[:5]:
            bar = "█" * min(30, count // 5)
            print(f"  {ip:<20} {count:>5}  {CYAN}{bar}{RESET}")
        print()

    # Status code summary
    if report.summary.get("status_codes"):
        print(f"{BOLD}[ HTTP STATUS CODES ]{RESET}")
        for code, cnt in sorted(report.summary["status_codes"].items()):
            c = int(code)
            clr = LEVEL_COLORS["HIGH"] if c >= 500 else LEVEL_COLORS["MEDIUM"] if c >= 400 else GREEN
            print(f"  HTTP {color(code, clr)}: {cnt}")
        print()

    # Threat summary by level
    by_level = report.summary.get("by_level", {})
    if by_level:
        print(f"{BOLD}[ THREAT SUMMARY ]{RESET}")
        for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = by_level.get(lvl, 0)
            if cnt:
                clr = LEVEL_COLORS.get(lvl, "")
                print(f"  {color(lvl, clr):<30} {cnt}")
        print()


def get_key() -> Optional[str]:
    if not sys.stdin.isatty():
        try:
            return sys.stdin.read(1)
        except Exception:
            return None
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except Exception:
        try:
            return sys.stdin.read(1)
        except Exception:
            return None
        
    try:
        tty.setraw(fd)
        rlist, _, _ = select.select([sys.stdin], [], [])
        if rlist:
            b = os.read(fd, 1)
            if b == b'\x1b':
                rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
                if rlist:
                    b2 = os.read(fd, 1)
                    if b2 == b'[':
                        rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
                        if rlist:
                            b3 = os.read(fd, 1)
                            return f"\x1b[{b3.decode('utf-8', errors='ignore')}"
                        return "\x1b["
                    return f"\x1b{b2.decode('utf-8', errors='ignore')}"
                return "\x1b"
            return b.decode('utf-8', errors='ignore')
    except Exception:
        try:
            return sys.stdin.read(1)
        except Exception:
            return None
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            pass
    return None


def choose_option(title: str, options: list[str], default_index: int = 0) -> int:
    """
    Displays a list of options. Use Up/Down arrow keys to navigate,
    Enter to select, and Escape to return -1 (cancel).
    """
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    print(f"\n{BOLD}{title}{RESET}")
    print(f"  {CYAN}[Controls: ↑/↓ Navigate | Enter Select | ESC Cancel/Back]{RESET}")
    for i, opt in enumerate(options):
        if i == default_index:
            sys.stdout.write(f" {GREEN}{BOLD}➔  {opt}{RESET}\n")
        else:
            sys.stdout.write(f"    {opt}\n")
    sys.stdout.flush()

    selected_index = default_index

    try:
        while True:
            key = get_key()
            if key == "\x1b":
                sys.stdout.write(f"\033[{len(options) + 3}A")
                for _ in range(len(options) + 3):
                    sys.stdout.write("\033[K\n")
                sys.stdout.write(f"\033[{len(options) + 3}A")
                sys.stdout.flush()
                return -1
            elif key in ("\r", "\n"):
                sys.stdout.write(f"\033[{len(options) + 3}A")
                for _ in range(len(options) + 3):
                    sys.stdout.write("\033[K\n")
                sys.stdout.write(f"\033[{len(options) + 3}A")
                sys.stdout.flush()
                return selected_index
            elif key == "\x1b[A":
                selected_index = (selected_index - 1) % len(options)
            elif key == "\x1b[B":
                selected_index = (selected_index + 1) % len(options)

            sys.stdout.write(f"\033[{len(options)}A")
            for i, opt in enumerate(options):
                if i == selected_index:
                    sys.stdout.write(f"\033[K {GREEN}{BOLD}➔  {opt}{RESET}\n")
                else:
                    sys.stdout.write(f"\033[K    {opt}\n")
            sys.stdout.flush()
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def prompt_input(prompt_text: str, default: str = "") -> Optional[str]:
    sys.stdout.write("\033[?25h")
    sys.stdout.write(f"{BOLD}{prompt_text}{RESET}")
    if default:
        sys.stdout.write(f"[{default}] ")
    sys.stdout.flush()
    
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except Exception:
        try:
            return input().strip() or default
        except (KeyboardInterrupt, EOFError):
            return None

    user_input = ""
    try:
        tty.setraw(fd)
        while True:
            rlist, _, _ = select.select([sys.stdin], [], [])
            if rlist:
                b = os.read(fd, 1)
                ch = b.decode('utf-8', errors='ignore')
                if ch == '\x1b':
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if rlist:
                        os.read(fd, 2)
                        continue
                    return None
                elif ch in ('\r', '\n'):
                    break
                elif ch in ('\x7f', '\x08'):
                    if len(user_input) > 0:
                        user_input = user_input[:-1]
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif ord(ch) >= 32:
                    user_input += ch
                    sys.stdout.write(ch)
                    sys.stdout.flush()
    except Exception:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            pass
    
    print()
    val = user_input.strip()
    if not val:
        return default
    return val


def choose_file() -> Optional[str]:
    log_files = sorted(glob.glob("*.log") + glob.glob("*.txt"))
    options = ["[ Enter file path manually... ]"]
    if log_files:
        options.extend(log_files)
    options.append("[ Back to Main Menu ]")
    
    idx = choose_option("Select a log file to analyze:", options)
    if idx == -1 or idx == len(options) - 1:
        return None
    
    if idx == 0:
        while True:
            path_str = prompt_input("Enter log file path: ")
            if path_str is None:
                return None
            path = Path(path_str)
            if path.is_file():
                return str(path)
            else:
                print(f"{LEVEL_COLORS['CRITICAL']}Error: File '{path_str}' does not exist or is not a file.{RESET}")
                print("Press any key to try again, or ESC to go back...")
                key = get_key()
                sys.stdout.write("\033[3A\033[K\n\033[K\n\033[K\033[3A")
                sys.stdout.flush()
                if key == "\x1b":
                    return None
    else:
        return options[idx]


def pause_and_continue():
    print(f"\n{CYAN}Press any key (or ESC) to return to the main menu...{RESET}")
    get_key()
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path in ('/', '/dashboard.html', '/index.html'):
            try:
                content = Path('core/templates/dashboard.html').read_text(encoding='utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            except Exception as e:
                self.send_error(404, f"dashboard.html not found: {e}")
        elif parsed_path.path.startswith('/static/'):
            try:
                safe_path = Path('core/static').resolve()
                file_path = (Path('core') / parsed_path.path.lstrip('/')).resolve()
                if file_path.is_file() and file_path.relative_to(safe_path):
                    ext = file_path.suffix.lower()
                    content_type = 'application/octet-stream'
                    if ext == '.css':
                        content_type = 'text/css; charset=utf-8'
                    elif ext == '.js':
                        content_type = 'application/javascript; charset=utf-8'
                    elif ext == '.svg':
                        content_type = 'image/svg+xml'
                    
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.end_headers()
                    self.wfile.write(file_path.read_bytes())
                else:
                    self.send_error(404, "File not found")
            except Exception as e:
                self.send_error(404, f"File not found: {e}")
        elif parsed_path.path in ('/ui.css', '/style.css'):
            try:
                content = Path('core/static/css/style.css').read_text(encoding='utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/css; charset=utf-8')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            except Exception as e:
                self.send_error(404, f"CSS not found: {e}")
        elif parsed_path.path == '/app.js':
            try:
                content = Path('core/static/js/app.js').read_text(encoding='utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript; charset=utf-8')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            except Exception as e:
                self.send_error(404, f"app.js not found: {e}")
        elif parsed_path.path == '/api/sample_logs':
            try:
                from core.sample_generator import generate_sample_logs
                logs = generate_sample_logs()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(logs.encode('utf-8'))
            except Exception as e:
                self.send_error(500, str(e))
        elif parsed_path.path == '/api/live':
            try:
                query_params = urllib.parse.parse_qs(parsed_path.query)
                file_param = query_params.get('file', [''])[0]
                cursor_param = query_params.get('cursor', [''])[0]
                
                if not file_param:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing 'file' parameter"}).encode('utf-8'))
                    return
                
                file_path = Path(file_param).expanduser().resolve()
                if not file_path.is_file():
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"File '{file_param}' not found"}).encode('utf-8'))
                    return
                
                file_size = file_path.stat().st_size
                cursor = 0
                if cursor_param:
                    try:
                        cursor = int(cursor_param)
                    except ValueError:
                        cursor = 0
                
                if cursor < 0:
                    cursor = file_size
                
                new_content = ""
                new_cursor = cursor
                
                if file_size > cursor:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(cursor)
                        new_content = f.read()
                        new_cursor = f.tell()
                elif file_size < cursor:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        new_content = f.read()
                        new_cursor = f.tell()
                
                response_data = {
                    "new_content": new_content,
                    "cursor": new_cursor,
                    "file_size": file_size
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == '/api/analyze':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                
                try:
                    payload = json.loads(post_data.decode('utf-8'))
                    log_text = payload.get('log_text', '')
                    source = payload.get('source', 'web_upload')
                except json.JSONDecodeError:
                    log_text = post_data.decode('utf-8')
                    source = 'web_upload'
                
                from core.analyzer import LogAnalyzer
                analyzer = LogAnalyzer()
                report = analyzer.analyze(log_text, source=source)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(report.to_dict()).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_error(404, "Not Found")
            
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def start_server_on_free_port(start_port=8000):
    port = start_port
    while True:
        try:
            server_address = ('', port)
            http.server.HTTPServer.allow_reuse_address = True
            httpd = http.server.HTTPServer(server_address, DashboardHandler)
            break
        except OSError:
            port += 1
            if port > 8050:
                print(f"  {LEVEL_COLORS['CRITICAL']}Error: No free port found in range 8000-8050.{RESET}")
                return
    
    print(f"\n{GREEN}❯ Professional Web Dashboard server running at:{RESET}")
    print(f"   {BOLD}http://localhost:{port}/{RESET}")
    print(f"\n{CYAN}Press Ctrl+C to stop the server and return to the main menu.{RESET}")
    
    def open_browser():
        import time
        time.sleep(0.5)
        try:
            import webbrowser
            webbrowser.open(f"http://localhost:{port}/")
        except Exception:
            pass
            
    threading.Thread(target=open_browser, daemon=True).start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{LEVEL_COLORS['CRITICAL']}Server stopped.{RESET}")
    finally:
        httpd.server_close()


def run_interactive_menu():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()
    while True:
        print_banner()
        main_options = [
            " >> Run Demo Analysis (Attack Simulations)",
            " >> Analyze a Log File",
            " >> Generate and Save Sample Log File",
            " >> Analyze from Standard Input (stdin)",
            " >> Open Visual Dashboard (recommended)",
            " >> Exit"
        ]
        
        choice = choose_option("What would you like to do?", main_options)
        
        if choice in (-1, len(main_options) - 1):
            print(f"\n{GREEN}Goodbye!{RESET}")
            break
            
        elif choice == 0:
            verbose_choice = choose_option(
                "Show verbose evidence details?",
                ["No (compact report)", "Yes (show evidence details)"]
            )
            if verbose_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            verbose = (verbose_choice == 1)
            
            output_path = None
            save_choice = choose_option(
                "Save JSON report to a file?",
                ["No", "Yes"]
            )
            if save_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            if save_choice == 1:
                output_path = prompt_input("Enter output path: ", "reports/sample_report.json")
                if output_path is None:
                    sys.stdout.write("\033[H\033[J")
                    sys.stdout.flush()
                    continue
            
            print(f"\n{GREEN}❯ Running Demo Analysis...{RESET}\n")
            log_text = generate_sample_logs()
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source="sample_logs")
            print_report(report, verbose=verbose)
            
            if output_path:
                out = Path(output_path)
                try:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(json.dumps(report.to_dict(), indent=2))
                    print(f"  {GREEN}✓{RESET} Report saved to {output_path}")
                except Exception as e:
                    print(f"  {LEVEL_COLORS['CRITICAL']}Error saving report: {e}{RESET}")
            
            pause_and_continue()
            
        elif choice == 1:
            file_path = choose_file()
            if not file_path:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
                
            verbose_choice = choose_option(
                "Show verbose evidence details?",
                ["No (compact report)", "Yes (show evidence details)"]
            )
            if verbose_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            verbose = (verbose_choice == 1)
            
            output_path = None
            save_choice = choose_option(
                "Save JSON report to a file?",
                ["No", "Yes"]
            )
            if save_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            if save_choice == 1:
                output_path = prompt_input("Enter output path: ", "reports/file_report.json")
                if output_path is None:
                    sys.stdout.write("\033[H\033[J")
                    sys.stdout.flush()
                    continue
            
            path = Path(file_path)
            try:
                log_text = path.read_text(errors="replace")
            except Exception as e:
                print(f"\n{LEVEL_COLORS['CRITICAL']}Error reading file: {e}{RESET}")
                pause_and_continue()
                continue
                
            print(f"\n{GREEN}❯ Analyzing {file_path}...{RESET}\n")
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source=file_path)
            print_report(report, verbose=verbose)
            
            if output_path:
                out = Path(output_path)
                try:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(json.dumps(report.to_dict(), indent=2))
                    print(f"  {GREEN}✓{RESET} Report saved to {output_path}")
                except Exception as e:
                    print(f"  {LEVEL_COLORS['CRITICAL']}Error saving report: {e}{RESET}")
                
            pause_and_continue()
            
        elif choice == 2:
            output_path = prompt_input("Enter path to save sample logs: ", "sample_security_logs.log")
            if output_path is None:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
                
            print(f"\n{GREEN}❯ Generating sample security logs...{RESET}")
            log_text = generate_sample_logs()
            out = Path(output_path)
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(log_text)
                print(f"  {GREEN}✓{RESET} Successfully generated {len(log_text.splitlines())} sample log entries.")
                print(f"  {GREEN}✓{RESET} Saved to: {BOLD}{out.resolve()}{RESET}")
            except Exception as e:
                print(f"  {LEVEL_COLORS['CRITICAL']}Error saving logs file: {e}{RESET}")
            
            pause_and_continue()
            
def setup_email_config_interactive(notifier) -> bool:
    print(f"\n{BOLD}[ EMAIL CONFIGURATION SETUP ]{RESET}")
    print("To receive real-time email alerts, configure your SMTP server details.")
    current = notifier.config
    enabled = choose_option("Enable Email Notifications?", ["No", "Yes"], 1 if current.get("enabled") else 0)
    if enabled in (-1, 0):
        current["enabled"] = False
        notifier.save_config(current)
        print(f"  {CYAN}Email notifications disabled.{RESET}")
        return False
    smtp_server = prompt_input("SMTP Server (e.g. smtp.gmail.com): ", current.get("smtp_server"))
    if not smtp_server:
        print(f"  {LEVEL_COLORS['CRITICAL']}Error: SMTP Server is required.{RESET}")
        return False
    smtp_port_str = prompt_input("SMTP Port (usually 587 or 465): ", str(current.get("smtp_port") or "587"))
    try:
        smtp_port = int(smtp_port_str)
    except ValueError:
        smtp_port = 587
    smtp_user = prompt_input("SMTP Username/Email: ", current.get("smtp_user"))
    smtp_password = prompt_input("SMTP Password/App Password: ", current.get("smtp_password"))
    from_email = prompt_input("Sender Address (From): ", current.get("from_email") or smtp_user)
    to_email = prompt_input("Receiver Address (To): ", current.get("to_email"))
    if not to_email:
         print(f"  {LEVEL_COLORS['CRITICAL']}Error: Receiver email is required.{RESET}")
         return False
    new_config = {
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "from_email": from_email,
        "to_email": to_email,
        "enabled": True
    }
    notifier.save_config(new_config)
    print(f"  {GREEN}✓ Email configuration saved to reports/email_config.json{RESET}")
    print("  Testing SMTP configuration...")
    test_subject = " SHIELD - Test Alert Connection"
    test_body = "<p>SMTP validation successful. Your live threat email alert system is ready to receive logs!</p>"
    if notifier.send_smtp_email(test_subject, test_body):
        print(f"  {GREEN}✓ Test email sent successfully to {to_email}!{RESET}")
        return True
    else:
        print(f"  {LEVEL_COLORS['CRITICAL']}✗ Failed to send test email. Please check credentials/port settings.{RESET}")
        return False


def run_live_analysis(enable_email=False, output_path=None):
    from core.notifier import Notifier
    from core.analyzer import LogEntry, LogAnalyzer, AnalysisReport, parse_line
    notifier = Notifier()
    if enable_email:
        if sys.stdin.isatty():
            if not notifier.is_configured():
                setup_email_config_interactive(notifier)
        else:
            if not notifier.is_configured():
                print(f"  {LEVEL_COLORS['HIGH']}Warning: Email alerts requested but SMTP config not found.{RESET}")
                print(f"  Please configure reports/email_config.json or set SHIELD_SMTP_* env vars. Running without email.{RESET}")
                notifier.config["enabled"] = False
    
    Path("reports").mkdir(parents=True, exist_ok=True)
    alerts_log = Path("reports/shield_live_alerts.log")
    entries_log = Path("reports/shield_live_entries.log")
    
    print(f"\n{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"  {BOLD} SHIELD LIVE STREAMING INTRUSION DETECTION ENGINE{RESET}")
    print(f"  Watching: {BOLD}Standard Input (stdin){RESET}")
    print(f"  Alerts Log File: {BOLD}{alerts_log.resolve()}{RESET}")
    print(f"  Status: {GREEN}ACTIVE & LISTENING{RESET}")
    if notifier.config.get("enabled"):
        print(f"  Email Alerts: {GREEN}ENABLED{RESET} -> {notifier.config.get('to_email')}")
    else:
        print(f"  Email Alerts: {LEVEL_COLORS['INFO']}DISABLED{RESET}")
    print(f"{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")
    print(f"{CYAN}Press Ctrl+C at any time to stop the stream, save the report, and exit.{RESET}\n")

    analyzer = LogAnalyzer()
    all_entries = []
    total_count = 0
    parsed_count = 0
    
    from collections import deque
    log_buffer = deque(maxlen=15)
    last_written_idx = -1
    
    # ── Autodetect Profiling Phase ──
    print(f"  {CYAN}Inference Phase: Analyzing first log lines to autodetect format...{RESET}")
    samples = []
    for _ in range(15):
        line = sys.stdin.readline()
        if not line:
            break
        samples.append(line)
        
    from core.analyzer import LogSchemaAutodetector
    import core.analyzer
    schema = LogSchemaAutodetector.detect_schema(samples)
    if schema:
        core.analyzer.ACTIVE_SCHEMA = schema
        print(f"  {GREEN}✓ Format Autodetected:{RESET}")
        if schema["type"] == "json":
            print(f"    Type: {BOLD}JSON Log Structure{RESET}")
        else:
            delim_name = "Space" if schema["delimiter"] == " " else f"'{schema['delimiter']}'"
            print(f"    Type: {BOLD}Delimited text{RESET} (Delimiter: {delim_name})")
            print(f"    Mapped Columns: IP={schema['ip_col']}, Timestamp={schema['ts_col']}, Method={schema['method_col']}, Status={schema['status_col']}, Message={schema['msg_col']}")
    else:
        print(f"  {LEVEL_COLORS['HIGH']}Could not confidently infer log format. Falling back to default pattern matching.{RESET}")
    print()

    try:
        # Process the sampled lines first so we don't lose any data
        for line in samples:
            total_count += 1
            log_buffer.append((total_count, line))
            e = parse_line(line, source="live_stdin")
            if not e:
                continue
            parsed_count += 1
            all_entries.append(e)
            sys.stdout.write(f"\033[90m[Parsed] {e.ip or 'No-IP'} -> {e.method or 'GET'} {e.path or '/'}\033[0m\n")
            sys.stdout.flush()
            new_threats = analyzer.engine.feed_realtime(e)
            if new_threats:
                with open(entries_log, "a", encoding="utf-8") as f:
                    for idx, l in log_buffer:
                        if idx > last_written_idx:
                            f.write(l)
                last_written_idx = total_count
                for t in new_threats:
                    lvl_color = LEVEL_COLORS.get(t.level.value, "")
                    alert_line = f"\n  {LEVEL_COLORS['CRITICAL']} ALERT:{RESET} {lvl_color}{BOLD}[{t.level.value}]{RESET} {BOLD}{t.rule_name}{RESET} from {t.ip or 'Unknown'}"
                    desc_line = f"     Description: {t.description}"
                    ev_line = f"     Evidence: {t.evidence[0] if t.evidence else 'N/A'}"
                    print(alert_line)
                    print(desc_line)
                    print(ev_line)
                    print(f"  \a")
                    with open(alerts_log, "a", encoding="utf-8") as af:
                        af.write(f"[{t.timestamp.isoformat()}] [{t.level.value}] {t.rule_name} - IP: {t.ip or 'N/A'} - {t.description}\n")
                    if notifier.config.get("enabled") and t.level.score() >= 3:
                        email_subject = f" SHIELD ALERT: {t.level.value} - {t.rule_name} ({t.ip or 'N/A'})"
                        email_html = notifier.build_threat_html(t)
                        print(f"     {CYAN}Sending real-time alert email...{RESET}", end="", flush=True)
                        if notifier.send_smtp_email(email_subject, email_html):
                            print(f" {GREEN}Sent.{RESET}")
                        else:
                            print(f" {LEVEL_COLORS['CRITICAL']}Failed.{RESET}")

        # Now read remaining lines from stdin
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            total_count += 1
            log_buffer.append((total_count, line))
            e = parse_line(line, source="live_stdin")
            if not e:
                continue
            parsed_count += 1
            all_entries.append(e)
            sys.stdout.write(f"\033[90m[Parsed] {e.ip or 'No-IP'} -> {e.method or 'GET'} {e.path or '/'}\033[0m\n")
            sys.stdout.flush()
            new_threats = analyzer.engine.feed_realtime(e)
            if new_threats:
                with open(entries_log, "a", encoding="utf-8") as f:
                    for idx, l in log_buffer:
                        if idx > last_written_idx:
                            f.write(l)
                last_written_idx = total_count
                for t in new_threats:
                    lvl_color = LEVEL_COLORS.get(t.level.value, "")
                    alert_line = f"\n  {LEVEL_COLORS['CRITICAL']} ALERT:{RESET} {lvl_color}{BOLD}[{t.level.value}]{RESET} {BOLD}{t.rule_name}{RESET} from {t.ip or 'Unknown'}"
                    desc_line = f"     Description: {t.description}"
                    ev_line = f"     Evidence: {t.evidence[0] if t.evidence else 'N/A'}"
                    
                    # Print immediately to terminal
                    print(alert_line)
                    print(desc_line)
                    print(ev_line)
                    print(f"  \a") # Terminal bell sound
                    
                    # Append alert log file
                    with open(alerts_log, "a", encoding="utf-8") as af:
                        af.write(f"[{t.timestamp.isoformat()}] [{t.level.value}] {t.rule_name} - IP: {t.ip or 'N/A'} - {t.description}\n")
                        
                    # Email alert
                    if notifier.config.get("enabled") and t.level.score() >= 3: # Send email for High/Critical
                        email_subject = f" SHIELD ALERT: {t.level.value} - {t.rule_name} ({t.ip or 'N/A'})"
                        email_html = notifier.build_threat_html(t)
                        print(f"     {CYAN}Sending real-time alert email...{RESET}", end="", flush=True)
                        if notifier.send_smtp_email(email_subject, email_html):
                            print(f" {GREEN}Sent.{RESET}")
                        else:
                            print(f" {LEVEL_COLORS['CRITICAL']}Failed.{RESET}")
                            
    except KeyboardInterrupt:
        print(f"\n\n{LEVEL_COLORS['CRITICAL']}Stream parsing stopped by operator.{RESET}")
        
    # Compile Report
    print(f"\n{GREEN}❯ Summarizing stream analysis...{RESET}")
    report = analyzer.analyze("", source="live_stdin") # Build final analytics
    # Feed aggregated threats and counters
    report.total_entries = total_count
    report.parsed_entries = parsed_count
    report.threats = sorted(analyzer.engine.threats, key=lambda t: t.level.score(), reverse=True)
    
    # Recalculate stats
    from collections import Counter
    ip_counter = Counter(ent.ip for ent in all_entries if ent.ip)
    path_counter = Counter(ent.path for ent in all_entries if ent.path)
    status_counts = Counter(ent.status for ent in all_entries if ent.status)
    level_counts = Counter(thr.level.value for thr in report.threats)
    
    report.top_ips = ip_counter.most_common(10)
    report.top_paths = path_counter.most_common(10)
    report.summary = {
        "by_level": dict(level_counts),
        "status_codes": {str(k): v for k, v in status_counts.items()},
        "unique_ips": len(ip_counter),
        "unique_paths": len(path_counter)
    }
    report.risk_score = min(100, sum(thr.level.score() * thr.count for thr in report.threats))
    
    # Save Report
    out_path = Path(output_path or "reports/shield_live_report.json")
    out_path.write_text(json.dumps(report.to_dict(), indent=2))
    print(f"  {GREEN}✓{RESET} Full report saved to: {BOLD}{out_path.resolve()}{RESET}")
    print(f"  Processed Logs: {total_count} lines ({parsed_count} parsed)")
    print(f"  Threats Found : {len(report.threats)}")
    
    # Final Email Report
    if notifier.config.get("enabled"):
        print(f"  {CYAN}Sending final summary report email...{RESET}", end="", flush=True)
        summary_subject = f"SHIELD Report: {report.risk_score}/100 Risk Score ({len(report.threats)} Threats)"
        summary_html = notifier.build_summary_html(report)
        if notifier.send_smtp_email(summary_subject, summary_html, attachment_path=out_path):
            print(f" {GREEN}Sent.{RESET}")
        else:
            print(f" {LEVEL_COLORS['CRITICAL']}Failed.{RESET}")
            
    pause_and_continue()


def run_interactive_menu():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()
    while True:
        print_banner()
        main_options = [
            " >> Run Demo Analysis (Attack Simulations)",
            " >> Analyze a Log File",
            " >> Generate and Save Sample Log File",
            " >> Analyze from Standard Input (stdin) - Batch",
            " >> Continuous Live Stream Analysis (stdin)",
            " >> Open Visual Dashboard (recommended)",
            " >> Exit"
        ]
        
        choice = choose_option("What would you like to do?", main_options)
        
        if choice in (-1, len(main_options) - 1):
            print(f"\n{GREEN}Goodbye!{RESET}")
            break
            
        elif choice == 0:
            verbose_choice = choose_option(
                "Show verbose evidence details?",
                ["No (compact report)", "Yes (show evidence details)"]
            )
            if verbose_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            verbose = (verbose_choice == 1)
            
            output_path = None
            save_choice = choose_option(
                "Save JSON report to a file?",
                ["No", "Yes"]
            )
            if save_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            if save_choice == 1:
                output_path = prompt_input("Enter output path: ", "reports/sample_report.json")
                if output_path is None:
                    sys.stdout.write("\033[H\033[J")
                    sys.stdout.flush()
                    continue
            
            print(f"\n{GREEN}❯ Running Demo Analysis...{RESET}\n")
            log_text = generate_sample_logs()
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source="sample_logs")
            print_report(report, verbose=verbose)
            
            if output_path:
                out = Path(output_path)
                try:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(json.dumps(report.to_dict(), indent=2))
                    print(f"  {GREEN}✓{RESET} Report saved to {output_path}")
                except Exception as e:
                    print(f"  {LEVEL_COLORS['CRITICAL']}Error saving report: {e}{RESET}")
            
            pause_and_continue()
            
        elif choice == 1:
            file_path = choose_file()
            if not file_path:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
                
            verbose_choice = choose_option(
                "Show verbose evidence details?",
                ["No (compact report)", "Yes (show evidence details)"]
            )
            if verbose_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            verbose = (verbose_choice == 1)
            
            output_path = None
            save_choice = choose_option(
                "Save JSON report to a file?",
                ["No", "Yes"]
            )
            if save_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            if save_choice == 1:
                output_path = prompt_input("Enter output path: ", "reports/file_report.json")
                if output_path is None:
                    sys.stdout.write("\033[H\033[J")
                    sys.stdout.flush()
                    continue
            
            path = Path(file_path)
            try:
                log_text = path.read_text(errors="replace")
            except Exception as e:
                print(f"\n{LEVEL_COLORS['CRITICAL']}Error reading file: {e}{RESET}")
                pause_and_continue()
                continue
                
            print(f"\n{GREEN}❯ Analyzing {file_path}...{RESET}\n")
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source=file_path)
            print_report(report, verbose=verbose)
            
            if output_path:
                out = Path(output_path)
                try:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(json.dumps(report.to_dict(), indent=2))
                    print(f"  {GREEN}✓{RESET} Report saved to {output_path}")
                except Exception as e:
                    print(f"  {LEVEL_COLORS['CRITICAL']}Error saving report: {e}{RESET}")
                
            pause_and_continue()
            
        elif choice == 2:
            output_path = prompt_input("Enter path to save sample logs: ", "sample_security_logs.log")
            if output_path is None:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
                
            print(f"\n{GREEN}❯ Generating sample security logs...{RESET}")
            log_text = generate_sample_logs()
            out = Path(output_path)
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(log_text)
                print(f"  {GREEN}✓{RESET} Successfully generated {len(log_text.splitlines())} sample log entries.")
                print(f"  {GREEN}✓{RESET} Saved to: {BOLD}{out.resolve()}{RESET}")
            except Exception as e:
                print(f"  {LEVEL_COLORS['CRITICAL']}Error saving logs file: {e}{RESET}")
            
            pause_and_continue()
            
        elif choice == 3:
            print(f"\n{BOLD}Reading logs from stdin.{RESET}")
            print("Paste your logs below, then press Ctrl+D (on a new line) to finish.\n")
            try:
                log_text = sys.stdin.read()
            except KeyboardInterrupt:
                print(f"\n{LEVEL_COLORS['CRITICAL']}Cancelled.{RESET}")
                pause_and_continue()
                continue
            if not log_text.strip():
                print(f"\n{LEVEL_COLORS['MEDIUM']}No logs provided.{RESET}")
                pause_and_continue()
                continue
            print(f"\n{GREEN}❯ Analyzing stdin logs...{RESET}\n")
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source="stdin")
            print_report(report, verbose=False)
            pause_and_continue()
            
        elif choice == 4:
            email_choice = choose_option(
                "Enable real-time Email alerts for this stream?",
                ["No, stream only", "Yes, configure/enable email notifications"]
            )
            if email_choice == -1:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
            enable_email = (email_choice == 1)
            run_live_analysis(enable_email=enable_email)
            sys.stdout.write("\033[H\033[J")
            sys.stdout.flush()

        elif choice == 5:
            start_server_on_free_port()
            sys.stdout.write("\033[H\033[J")
            sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(
        description="SHIELD — Log Analyzer & Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shield.py                               # Start the interactive TUI menu (Up/Down, Enter, ESC)
  python shield.py --demo                        # Run on generated sample logs
  python shield.py -f /var/log/nginx/access.log  # Analyze a log file
  python shield.py --stdin                       # Read standard input batch
  python shield.py --stdin --live                # Continuous live stream TUI
  python shield.py --stdin --live --email        # Live stream + real-time email alerts
        """,
    )
    parser.add_argument("-f", "--file",    help="Log file to analyze")
    parser.add_argument("--stdin",  action="store_true", help="Read from stdin")
    parser.add_argument("--live",   action="store_true", help="Continuous live stream mode")
    parser.add_argument("--email",  action="store_true", help="Enable email alerts for live streaming")
    parser.add_argument("--demo",   action="store_true", help="Run on generated sample logs")
    parser.add_argument("--server", action="store_true", help="Start local web dashboard server")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show evidence snippets")
    parser.add_argument("--json-only", action="store_true", help="Output raw JSON only")
    args = parser.parse_args()

    if args.server:
        start_server_on_free_port()
        sys.exit(0)

    if not (args.file or args.stdin or args.demo):
        if sys.stdin.isatty():
            run_interactive_menu()
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    if not args.json_only:
        print_banner()

    if args.stdin and args.live:
        run_live_analysis(enable_email=args.email, output_path=args.output)
        sys.exit(0)

    # Load log text
    if args.demo:
        log_text = generate_sample_logs()
        source = "sample_logs"
        if not args.json_only:
            print(f"  {GREEN}✓{RESET} Generated {len(log_text.splitlines())} sample log entries\n")
    elif args.stdin:
        log_text = sys.stdin.read()
        source = "stdin"
    else:
        path = Path(args.file)
        if not path.exists():
            print(f"  Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        log_text = path.read_text(errors="replace")
        source = str(path)
        if not args.json_only:
            print(f"  {GREEN}✓{RESET} Loaded {len(log_text.splitlines())} lines from {source}\n")

    # Analyze
    analyzer = LogAnalyzer()
    report = analyzer.analyze(log_text, source=source)

    if args.json_only:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report, verbose=args.verbose)

    # Save JSON
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"  {GREEN}✓{RESET} Report saved to {args.output}")

    max_level = max((t.level.score() for t in report.threats), default=0)
    sys.exit(1 if max_level >= 3 else 0)



if __name__ == "__main__":
    main()
