#!/usr/bin/env python3
"""
Interactive local email delivery test for Cyber Threat Monitor.
Prompts for Gmail credentials securely (without saving to shell history)
and verifies STARTTLS delivery to your inbox.
"""
import getpass
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.config import ROOT_DIR  # Triggers .env loading automatically
from src.notifiers.email_smtp import EmailDispatcher


def main():
    print("=" * 70)
    print("📧 GMAIL SMTP LOCAL CONNECTIVITY & DELIVERY TEST")
    print("=" * 70)

    # Check if credentials exist from .env or environment
    env_user = os.getenv("SMTP_USERNAME", "").strip()
    env_pass = os.getenv("SMTP_APP_PASSWORD", "").strip()
    env_alert = os.getenv("ALERT_EMAIL", "").strip()

    if env_user and env_pass and env_alert:
        print(f"✅ Found credentials loaded from .env:")
        print(f"   • Sender     : {env_user}")
        print(f"   • Recipient  : {env_alert}")
        print(f"   • Password   : {'*' * 12} (16-char App Password)")
        proceed = input("\nSend test email using these credentials? [Y/n]: ").strip().lower()
        if proceed != "n":
            username = env_user
            password = env_pass
            recipient = env_alert
        else:
            username = input("\nEnter sender Gmail address: ").strip()
            password = getpass.getpass("Enter 16-character Google App Password: ").strip()
            recipient = input("Enter destination inbox: ").strip() or username
    else:
        print("Credentials are used in-memory only and never saved to Git.\n")
        username = input("Enter your sender Gmail address: ").strip()
        password = getpass.getpass("Enter your 16-character Google App Password: ").strip()
        recipient = input(f"Destination inbox [{username}]: ").strip() or username

    if not password:
        print("❌ Error: Google App Password cannot be empty.")
        return 1

    print(f"\nSending to: {recipient}")
    print("Connecting to smtp.gmail.com:587 with STARTTLS...")

    dispatcher = EmailDispatcher(
        username=username,
        password=password,
        recipients=recipient
    )

    subject = "🔔 [VERIFICATION] Cyber Threat Monitor Email Delivery Test"
    text_body = (
        "This test email confirms that your Gmail SMTP configuration works.\n\n"
        "Your automated security pipeline will be able to dispatch urgent zero-day alerts "
        "and morning daily digests to this address.\n"
    )
    html_body = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
    <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">
        <div style="background:#0f172a;padding:22px 26px;color:#ffffff;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:700;color:#38bdf8;">Setup Verification</div>
            <h1 style="margin:6px 0 0;font-size:20px;color:#ffffff;">✅ SMTP Delivery Verified</h1>
        </div>
        <div style="padding:24px 26px;color:#334155;line-height:1.6;">
            <p style="margin-top:0;">Hello,</p>
            <p>This test email confirms that your <b>Gmail SMTP credentials are configured correctly</b> and ready for deployment.</p>
            <div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:12px 16px;border-radius:0 6px 6px 0;margin:18px 0;font-size:13px;color:#166534;">
                <b>Pipeline Ready:</b> Your automated GitHub Actions workflow will be able to send urgent flash alerts and 9:00 AM daily security digests to <b>{recipient}</b>.
            </div>
            <p style="font-size:13px;color:#64748b;">You can now safely add these secrets to your GitHub repository.</p>
        </div>
        <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:14px 26px;font-size:11px;color:#94a3b8;text-align:center;">
            Global Cyber Threat Monitor &bull; Automated Telemetry
        </div>
    </div>
</body>
</html>"""

    success = dispatcher.send_email(subject, text_body, html_body)

    if success:
        print("\n" + "=" * 70)
        print(f"🎉 SUCCESS! A test email was delivered to {recipient}.")
        print("Please check your inbox (and spam/promotions folder just in case).")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print("❌ FAILED: Could not send email.")
        print("Please verify:")
        print("1. You used a 16-character Google App Password (not your normal Gmail password).")
        print("2. 2-Step Verification is turned ON on your Google account.")
        print("3. Generate a new password at: https://myaccount.google.com/apppasswords")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
