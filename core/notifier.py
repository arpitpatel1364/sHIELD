import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path
from datetime import datetime

CONFIG_PATH = Path("reports/email_config.json")

class Notifier:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self) -> dict:
        # Load from file if exists
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        
        # Fallback to environment variables
        return {
            "smtp_server": os.getenv("SHIELD_SMTP_SERVER", ""),
            "smtp_port": int(os.getenv("SHIELD_SMTP_PORT", "587")),
            "smtp_user": os.getenv("SHIELD_SMTP_USER", ""),
            "smtp_password": os.getenv("SHIELD_SMTP_PASSWORD", ""),
            "from_email": os.getenv("SHIELD_FROM_EMAIL", ""),
            "to_email": os.getenv("SHIELD_TO_EMAIL", ""),
            "enabled": os.getenv("SHIELD_EMAIL_ENABLED", "false").lower() == "true"
        }

    def save_config(self, config: dict):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
        self.config = config

    def is_configured(self) -> bool:
        c = self.config
        return bool(c.get("smtp_server") and c.get("to_email"))

    def send_smtp_email(self, subject: str, html_body: str, attachment_path: Path = None) -> bool:
        if not self.config.get("enabled") or not self.is_configured():
            return False

        c = self.config
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = c.get("from_email") or c.get("smtp_user")
        msg["To"] = c.get("to_email")

        # Attach HTML content
        msg.attach(MIMEText(html_body, "html"))

        # Attach file if specified
        if attachment_path and attachment_path.exists():
            try:
                with open(attachment_path, "rb") as f:
                    part = MIMEApplication(f.read(), Name=attachment_path.name)
                part['Content-Disposition'] = f'attachment; filename="{attachment_path.name}"'
                msg.attach(part)
            except Exception as e:
                print(f"\033[91mFailed to attach file: {e}\033[0m")

        try:
            # Use SSL or STARTTLS based on port
            port = int(c.get("smtp_port", 587))
            if port == 465:
                server = smtplib.SMTP_SSL(c["smtp_server"], port, timeout=10)
            else:
                server = smtplib.SMTP(c["smtp_server"], port, timeout=10)
                server.starttls()

            if c.get("smtp_user") and c.get("smtp_password"):
                server.login(c["smtp_user"], c["smtp_password"])

            server.sendmail(msg["From"], msg["To"].split(","), msg.as_string())
            server.quit()
            return True
        except Exception as e:
            print(f"\n\033[91m[Email Error] Failed to send email to {c['to_email']}: {e}\033[0m")
            return False

    def build_threat_html(self, threat) -> str:
        """Builds a beautiful premium HTML alert for a single threat event."""
        level = threat.level.value
        level_colors = {
            "CRITICAL": "#f43f5e",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#6b7280"
        }
        color = level_colors.get(level, "#10b981")
        evidence_html = "".join(f"<li style='font-family: monospace; font-size: 12px; background: #1e1e2e; color: #cdd6f4; padding: 6px; margin: 4px 0; border-radius: 4px; border-left: 3px solid {color}; list-style: none;'>{ev}</li>" for ev in threat.evidence)

        template_path = Path("core/templates/email_template.html")
        if template_path.exists():
            full_html = template_path.read_text(encoding="utf-8")
            try:
                html = full_html.split("<!-- THREAT_ALERT_START -->")[1].split("<!-- THREAT_ALERT_END -->")[0].strip()
            except Exception:
                html = full_html
        else:
            return f"Threat Detected: {threat.rule_name} from {threat.ip}"

        return html.replace("{{color}}", color)\
                   .replace("{{level}}", level)\
                   .replace("{{rule_name}}", threat.rule_name)\
                   .replace("{{description}}", threat.description)\
                   .replace("{{ip}}", threat.ip or "Unknown")\
                   .replace("{{user}}", threat.user or "N/A")\
                   .replace("{{timestamp}}", threat.timestamp.strftime('%Y-%m-%d %H:%M:%S'))\
                   .replace("{{count}}", str(threat.count))\
                   .replace("{{evidence_html}}", evidence_html)

    def build_summary_html(self, report) -> str:
        """Builds a beautiful premium summary HTML email for an entire analysis run."""
        level_counts = report.summary.get("by_level", {})
        unique_ips = report.summary.get("unique_ips", 0)
        
        score = report.risk_score
        if score >= 75:
            risk_color = "#f43f5e"
            risk_text = "CRITICAL"
        elif score >= 50:
            risk_color = "#f97316"
            risk_text = "HIGH"
        elif score >= 25:
            risk_color = "#eab308"
            risk_text = "MEDIUM"
        else:
            risk_color = "#10b981"
            risk_text = "LOW"

        threats_html = ""
        level_colors = {"CRITICAL": "#f43f5e", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#6b7280"}
        for t in report.threats[:10]:
            clr = level_colors.get(t.level.value, "#10b981")
            threats_html += f"""
            <tr style="border-bottom: 1px solid #313244;">
                <td style="padding: 12px; color: {clr}; font-weight: bold;">[{t.level.value}]</td>
                <td style="padding: 12px; color: #cdd6f4;">{t.rule_name}</td>
                <td style="padding: 12px; font-family: monospace; color: #bac2de;">{t.ip or 'N/A'}</td>
                <td style="padding: 12px; text-align: right; color: #a6adc8;">{t.count}</td>
            </tr>
            """
        
        if not report.threats:
            threats_html = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #a6adc8;">No threats detected during this run. Clean report! 🎉</td></tr>'

        template_path = Path("core/templates/email_template.html")
        if template_path.exists():
            full_html = template_path.read_text(encoding="utf-8")
            try:
                html = full_html.split("<!-- SUMMARY_REPORT_START -->")[1].split("<!-- SUMMARY_REPORT_END -->")[0].strip()
            except Exception:
                html = full_html
        else:
            return f"Summary Report: {score}/100 Risk Score, {len(report.threats)} threats."

        return html.replace("{{risk_color}}", risk_color)\
                   .replace("{{risk_score}}", str(score))\
                   .replace("{{risk_text}}", risk_text)\
                   .replace("{{total_entries}}", str(report.total_entries))\
                   .replace("{{unique_ips}}", str(unique_ips))\
                   .replace("{{threat_count}}", str(len(report.threats)))\
                   .replace("{{critical_count}}", str(level_counts.get("CRITICAL", 0)))\
                   .replace("{{high_count}}", str(level_counts.get("HIGH", 0)))\
                   .replace("{{medium_count}}", str(level_counts.get("MEDIUM", 0)))\
                   .replace("{{low_count}}", str(level_counts.get("LOW", 0)))\
                   .replace("{{threats_html}}", threats_html)
