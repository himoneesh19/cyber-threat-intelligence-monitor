from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class EmailDispatcher:
    """
    Dispatches security alerts and digests via SMTP (Gmail App Password / STARTTLS).
    Handles multiple recipients and validates credentials gracefully.
    """

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        recipients: str | list[str] | None = None,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 587
    ) -> None:
        self.username = (username or os.getenv("SMTP_USERNAME", "")).strip()
        self.password = (password or os.getenv("SMTP_APP_PASSWORD", "")).replace(" ", "").strip()

        recips = recipients or os.getenv("ALERT_EMAIL", "")
        if isinstance(recips, str):
            self.recipients = [r.strip() for r in recips.split(",") if r.strip()]
        else:
            self.recipients = recips

        self.smtp_host = os.getenv("SMTP_HOST", smtp_host)
        self.smtp_port = int(os.getenv("SMTP_PORT", str(smtp_port)))

    def is_configured(self) -> bool:
        """Returns True if sender credentials and at least one recipient exist."""
        return bool(self.username and self.password and self.recipients)

    def send_email(
        self,
        subject: str,
        text_body: str,
        html_body: str | None = None,
        dry_run: bool = False
    ) -> bool:
        """
        Sends an email message via SMTP.
        If dry_run is True, logs the message without connecting to the SMTP server.
        """
        if dry_run:
            logger.info("[DRY RUN] Would send email '%s' to %s", subject, self.recipients)
            return True

        if not self.is_configured():
            logger.warning(
                "SMTP is not configured. Missing SMTP_USERNAME, SMTP_APP_PASSWORD, or ALERT_EMAIL. Email not sent."
            )
            return False

        message = EmailMessage()
        message["From"] = f"Cyber Threat Monitor <{self.username}>"
        message["To"] = ", ".join(self.recipients)
        message["Subject"] = subject
        message.set_content(text_body)

        if html_body:
            message.add_alternative(html_body, subtype="html")

        try:
            logger.info("Connecting to SMTP server %s:%d...", self.smtp_host, self.smtp_port)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.username, self.password)
                server.send_message(message)

            logger.info("Email successfully sent to %s with subject: %s", self.recipients, subject)
            return True
        except smtplib.SMTPAuthenticationError as auth_err:
            logger.error("SMTP Authentication Failed. Ensure you are using a 16-character Google App Password: %s", auth_err)
            return False
        except Exception as exc:
            logger.error("Failed to send email via SMTP: %s", exc)
            return False


_DEFAULT_DISPATCHER = EmailDispatcher()


def send_email(
    subject: str,
    text_body: str,
    html_body: str | None = None,
    dry_run: bool = False
) -> bool:
    return _DEFAULT_DISPATCHER.send_email(subject, text_body, html_body, dry_run=dry_run)
