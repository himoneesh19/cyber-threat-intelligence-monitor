from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.portal import generate_portal


class TestPortalGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name) / "test_portal"
        self.sample_threats = [
            {
                "cve_id": "CVE-2026-1111",
                "title": "Sample Next.js RCE",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "is_cisa_kev": True,
                "category": "Web & Application Frameworks",
                "technologies": ["Next.js"]
            }
        ]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_portal(self):
        out = generate_portal(self.sample_threats, output_dir=self.output_dir)
        self.assertTrue((out / "data" / "threats.json").exists())
        self.assertTrue((out / "index.html").exists())
        self.assertTrue((out / "style.css").exists())
        self.assertTrue((out / "app.js").exists())

        # Verify JSON content
        data = json.loads((out / "data" / "threats.json").read_text(encoding="utf-8"))
        self.assertEqual(data["total_threats"], 1)
        self.assertEqual(data["threats"][0]["cve_id"], "CVE-2026-1111")


if __name__ == "__main__":
    unittest.main()
