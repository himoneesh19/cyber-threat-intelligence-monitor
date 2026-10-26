import unittest
from unittest.mock import MagicMock
from src.collectors.thn_news import collect_thn_news


class TestTHNNewsCollector(unittest.TestCase):
    def test_atom_feed_with_cve(self):
        atom_xml = """<?xml version="1.0" encoding="utf-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
            <entry>
                <title>Critical PHP Vulnerability CVE-2026-109618 Leaked Online</title>
                <link href="https://thehackernews.com/2026/10/critical-php-vulnerability.html"/>
                <summary>A severe remote code execution flaw in PHP core was disclosed prior to patch.</summary>
                <published>2026-10-21T10:00:00Z</published>
            </entry>
        </feed>
        """
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = atom_xml
        mock_session.get.return_value = mock_response

        records = collect_thn_news(url="https://mock-feed", session=mock_session)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cve_id"], "CVE-2026-109618")
        self.assertEqual(records[0]["source"], "The Hacker News")
        self.assertEqual(records[0]["severity"], "CRITICAL")
        self.assertIn("Critical PHP Vulnerability", records[0]["title"])

    def test_rss_feed_with_zero_day_unpatched(self):
        rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <item>
                    <title>New Zero-Day Flaw in Linux Kernel Actively Exploited</title>
                    <link>https://thehackernews.com/2026/10/linux-kernel-zero-day.html</link>
                    <description>Attackers are actively exploiting an unpatched vulnerability in Linux servers.</description>
                    <pubDate>2026-10-22T08:00:00Z</pubDate>
                </item>
            </channel>
        </rss>
        """
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = rss_xml
        mock_session.get.return_value = mock_response

        records = collect_thn_news(url="https://mock-feed", session=mock_session)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["cve_id"].startswith("THN:"))
        self.assertEqual(records[0]["severity"], "CRITICAL")
        self.assertIn("vendor emergency release", records[0]["cisa_required_action"])

    def test_invalid_feed_returns_empty_list(self):
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection timed out")

        records = collect_thn_news(url="https://failing-feed", session=mock_session)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
