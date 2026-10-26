from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.notifiers import build_urgent_alert_email, build_daily_digest_email, EmailDispatcher


class TestEmailTemplates(unittest.TestCase):
    def setUp(self):
        self.sample_threats = [
            {
                "cve_id": "CVE-2026-1111",
                "title": "Remote Code Execution in Next.js Server Actions <script>alert(1)</script>",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "is_cisa_kev": True,
                "is_urgent": True,
                "cisa_required_action": "Upgrade to next@15.0.4 immediately.",
                "cisa_due_date": "2026-11-15",
                "epss_score": 0.88,
                "category": "Web & Application Frameworks",
                "technologies": ["Next.js", "Node.js"],
                "summary": "An input validation flaw allows arbitrary code execution.",
                "sources": [{"name": "CISA KEV", "url": "https://cisa.gov/example"}]
            },
            {
                "cve_id": "CVE-2026-2222",
                "title": "SQL Injection in PostgreSQL pg_dump",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "is_cisa_kev": False,
                "is_urgent": False,
                "cisa_required_action": "Apply minor release updates.",
                "cisa_due_date": "",
                "epss_score": 0.05,
                "category": "Databases & Storage",
                "technologies": ["PostgreSQL"],
                "summary": "Improper escaping of identifiers in dump utility.",
                "sources": [{"name": "NVD", "url": "https://nvd.nist.gov/example"}]
            }
        ]

    def test_build_urgent_alert(self):
        urgent_items = [t for t in self.sample_threats if t["is_urgent"]]
        subject, text_body, html_body = build_urgent_alert_email(urgent_items)

        self.assertIn("URGENT SECURITY ALERT", subject)
        self.assertIn("1 Active Exploit", subject)
        self.assertIn("CVE-2026-1111", text_body)
        self.assertIn("CVE-2026-1111", html_body)
        self.assertIn("CISA KEV (ACTIVE EXPLOIT)", html_body)
        self.assertIn("CVSS 9.8", html_body)
        self.assertIn("Upgrade to next@15.0.4 immediately.", html_body)

        # XSS test: script tags in title must be escaped
        self.assertNotIn("<script>alert(1)</script>", html_body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_body)

    def test_build_daily_digest(self):
        subject, text_body, html_body = build_daily_digest_email(self.sample_threats)

        self.assertIn("Daily Security Digest", subject)
        self.assertIn("2 Threats Analyzed", subject)
        self.assertIn("Immediate Attention Required (1)", html_body)
        self.assertIn("Databases &amp; Storage", html_body)
        self.assertIn("Next.js", html_body)
        self.assertIn("PostgreSQL", html_body)

    def test_dispatcher_dry_run(self):
        dispatcher = EmailDispatcher(
            username="test@gmail.com",
            password="testpassword",
            recipients="admin@example.com"
        )
        self.assertTrue(dispatcher.is_configured())
        sent = dispatcher.send_email(
            subject="Test Subject",
            text_body="Test Body",
            html_body="<p>Test Body</p>",
            dry_run=True
        )
        self.assertTrue(sent)


if __name__ == "__main__":
    unittest.main()
