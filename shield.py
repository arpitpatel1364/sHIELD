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
{CYAN}{BOLD}
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


def run_interactive_menu():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()
    while True:
        print_banner()
        main_options = [
            "📊  Run Demo Analysis (Attack Simulations)",
            "🔍  Analyze a Log File",
            "💾  Generate and Save Demo Log File",
            "📥  Analyze from Standard Input (stdin)",
            "🌐  Open Visual Dashboard (dashboard.html)",
            "❌  Exit"
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
                output_path = prompt_input("Enter output path: ", "reports/demo_report.json")
                if output_path is None:
                    sys.stdout.write("\033[H\033[J")
                    sys.stdout.flush()
                    continue
            
            print(f"\n{GREEN}⚡ Running Demo Analysis...{RESET}\n")
            log_text = generate_sample_logs()
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source="demo")
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
                
            print(f"\n{GREEN}⚡ Analyzing {file_path}...{RESET}\n")
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
            output_path = prompt_input("Enter path to save demo logs: ", "demo_logs.log")
            if output_path is None:
                sys.stdout.write("\033[H\033[J")
                sys.stdout.flush()
                continue
                
            print(f"\n{GREEN}⚡ Generating demo logs...{RESET}")
            log_text = generate_sample_logs()
            out = Path(output_path)
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(log_text)
                print(f"  {GREEN}✓{RESET} Successfully generated {len(log_text.splitlines())} demo log entries.")
                print(f"  {GREEN}✓{RESET} Saved to: {BOLD}{out.resolve()}{RESET}")
            except Exception as e:
                print(f"  {LEVEL_COLORS['CRITICAL']}Error saving logs file: {e}{RESET}")
            
            pause_and_continue()
            
        elif choice == 3:
            print(f"\n{BOLD}📥 Reading logs from stdin.{RESET}")
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
                
            print(f"\n{GREEN}⚡ Analyzing stdin logs...{RESET}\n")
            analyzer = LogAnalyzer()
            report = analyzer.analyze(log_text, source="stdin")
            print_report(report, verbose=False)
            pause_and_continue()
            
        elif choice == 4:
            print(f"\n{GREEN}🌐 Opening dashboard.html in your default web browser...{RESET}")
            try:
                webbrowser.open(f"file://{os.path.abspath('dashboard.html')}")
                print(f"  {GREEN}✓{RESET} Opened successfully!")
            except Exception as e:
                print(f"  {LEVEL_COLORS['CRITICAL']}Failed to open automatically: {e}{RESET}")
                print(f"  Please open {BOLD}dashboard.html{RESET} manually in your browser.")
            pause_and_continue()


def main():
    parser = argparse.ArgumentParser(
        description="SHIELD — Log Analyzer & Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shield.py                               # Start the interactive TUI menu (Up/Down, Enter, ESC)
  python shield.py --demo                        # Run on generated sample logs
  python shield.py -f /var/log/nginx/access.log  # Analyze a log file
  python shield.py -f auth.log -o report.json    # Save JSON report
  cat access.log | python shield.py --stdin      # Read from stdin
  python shield.py --demo --verbose              # Show evidence snippets
        """,
    )
    parser.add_argument("-f", "--file",    help="Log file to analyze")
    parser.add_argument("--stdin",  action="store_true", help="Read from stdin")
    parser.add_argument("--demo",   action="store_true", help="Run on generated sample logs")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show evidence snippets")
    parser.add_argument("--json-only", action="store_true", help="Output raw JSON only")
    args = parser.parse_args()

    if not (args.file or args.stdin or args.demo):
        if sys.stdin.isatty():
            run_interactive_menu()
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    if not args.json_only:
        print_banner()

    # Load log text
    if args.demo:
        log_text = generate_sample_logs()
        source = "demo"
        if not args.json_only:
            print(f"  {GREEN}✓{RESET} Generated {len(log_text.splitlines())} demo log entries\n")
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

    # Exit with non-zero if CRITICAL/HIGH threats found
    max_level = max((t.level.score() for t in report.threats), default=0)
    sys.exit(1 if max_level >= 3 else 0)


if __name__ == "__main__":
    main()
