"""
Alert notifications: a loud console banner for every High/Critical
alert (always on), plus an optional email hook (off by default —
needs real SMTP credentials in config.py to work).

This is intentionally decoupled from the DB layer — insert_alert()
calls notify() as its last step, but a failure here should never
prevent the alert from having been recorded.
"""

import smtplib
from email.mime.text import MIMEText

from app.config import (
    NOTIFY_MIN_SEVERITY, EMAIL_NOTIFICATIONS_ENABLED,
    SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
    ALERT_EMAIL_FROM, ALERT_EMAIL_TO,
)

_SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _meets_threshold(severity):
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(NOTIFY_MIN_SEVERITY, 2)


def _console_banner(alert_type, source_ip, description, severity):
    bar = "!" * 60
    print(f"\n{bar}\n  [{severity.upper()} ALERT] {alert_type}\n"
          f"  Source: {source_ip}\n  {description}\n{bar}\n")


def _send_email(alert_type, source_ip, description, severity):
    if not (SMTP_USERNAME and SMTP_PASSWORD and ALERT_EMAIL_FROM and ALERT_EMAIL_TO):
        print("[notifier] Email notifications enabled but SMTP settings incomplete — skipping.")
        return
    try:
        msg = MIMEText(f"Source IP: {source_ip}\nSeverity: {severity}\n\n{description}")
        msg["Subject"] = f"[NIDS] {severity} alert: {alert_type}"
        msg["From"] = ALERT_EMAIL_FROM
        msg["To"] = ALERT_EMAIL_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())
    except Exception as e:
        # A notification failure should never take down alert processing.
        print(f"[notifier] Email send failed: {e}")


def notify(alert_type, source_ip, description, severity):
    if not _meets_threshold(severity):
        return

    _console_banner(alert_type, source_ip, description, severity)

    if EMAIL_NOTIFICATIONS_ENABLED:
        _send_email(alert_type, source_ip, description, severity)
