from __future__ import annotations

import unittest
from src.engine.assimilator import assimilate_threats


class TestAssimilator(unittest.TestCase):
    def test_canonical_deduplication_and_merging(self):
        # Two records for the same CVE from different sources:
        # One from NVD, one from CISA KEV
        raw_records = [
            {
                "source": "NVD",
                "cve_id": "CVE-2026-9999",
                "title": "CVE-2026-9999: Flaw in OpenSSL TLS handshake",
                "summary": "Buffer overflow in OpenSSL parsing TLS packets.",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "is_cisa_kev": False,
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
                "references": ["https://openssl.org/news/secadv.txt"]
            },
            {
                "source": "CISA KEV",
                "cve_id": "CVE-2026-9999",
                "title": "OpenSSL TLS Buffer Overflow Active Exploit",
                "summary": "Confirmed active exploitation of OpenSSL buffer overflow.",
                "severity": "CRITICAL",
                "cvss_score": None,
                "is_cisa_kev": True,
                "cisa_required_action": "Apply patch immediately before 2026-11-01.",
                "cisa_due_date": "2026-11-01",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "references": []
            }
        ]

        assimilated = assimilate_threats(raw_records)

        # Must merge into exactly 1 record, not 2
        self.assertEqual(len(assimilated), 1)
        merged = assimilated[0]

        self.assertEqual(merged["cve_id"], "CVE-2026-9999")
        self.assertTrue(merged["is_cisa_kev"])
        self.assertEqual(merged["severity"], "CRITICAL")
        self.assertEqual(merged["cvss_score"], 8.1)
        self.assertEqual(merged["cisa_due_date"], "2026-11-01")
        self.assertTrue(merged["is_urgent"])
        self.assertEqual(len(merged["sources"]), 2)
        source_names = [s["name"] for s in merged["sources"]]
        self.assertIn("NVD", source_names)
        self.assertIn("CISA KEV", source_names)


if __name__ == "__main__":
    unittest.main()
