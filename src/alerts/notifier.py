"""
Cybwatch Email Notifier

sends alert notifications via email
"""

import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any

from ..config import settings


class EmailNotifier:
    """Sends alerts via email"""
    
    def __init__(self):
        self.enabled = settings.email_enabled
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_user = settings.smtp_user
        self.smtp_password = settings.smtp_password
        self.email_from = settings.email_from
        self.email_to = settings.email_to
    
    def send(self, alert: Dict[str, Any]) -> bool:
        """
        Send an alert via email
        
        Returns True/False for status of sent
        """
        if not self.enabled:
            return False
        
        if not all([self.smtp_host, self.smtp_user, self.smtp_password, 
                    self.email_from, self.email_to]):
            return False
        
        try:
            subject = f"[Cybwatch] {alert.get('severity', 'ALERT').upper()}: {alert.get('rule_name', 'Unknown')}"
            body = self._format_body(alert)
            
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            return True
        except Exception:
            return False
    
    def _format_body(self, alert: Dict[str, Any]) -> str:
        """Format alert to email"""
        lines = [
            f"Severity: {alert.get('severity', 'unknown')}",
            f"Rule: {alert.get('rule_name', 'unknown')}",
            f"Description: {alert.get('description', 'No description')}",
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        
        if alert.get("source_ip"):
            lines.append(f"Source IP: {alert['source_ip']}")
        if alert.get("destination_ip"):
            lines.append(f"Destination IP: {alert['destination_ip']}")
        
        return "\n".join(lines)
