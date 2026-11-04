"""Sends mail to the sandbox's mail catcher (Mailpit). Nothing leaves the lab."""
import logging
import smtplib
from email.message import EmailMessage

from .settings import settings

log = logging.getLogger("lab.mail")


def send(to: str, subject: str, body: str) -> bool:
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5) as smtp:
            smtp.send_message(msg)
        return True
    except OSError as exc:
        log.warning("Mail to %s not delivered: %s", to, exc)
        return False
