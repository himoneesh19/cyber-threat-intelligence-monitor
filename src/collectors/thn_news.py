from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
import requests

from src.config import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
ZERO_DAY_KEYWORDS = re.compile(
    r"\b(zero-day|0-day|unpatched|actively exploited|emergency patch|rce|remote code execution)\b",
    re.IGNORECASE
)


def _first_elem(entry: ET.Element, *tags: str) -> ET.Element | None:
    for tag in tags:
        elem = entry.find(tag)
        if elem is not None:
            return elem
    return None


def collect_thn_news(
    url: str = "https://thehackernews.com/feeds/posts/default",
    max_items: int = 25,
    session: requests.Session | None = None
) -> list[dict[str, Any]]:
    """
    Ingests breaking cyber threat advisories and 0-day news from The Hacker News Atom/RSS feed.
    Identifies CVEs and urgent unpatched vulnerabilities before they reach NVD/CISA catalogs.
    """
    sess = session or requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml"
    }

    logger.info("Fetching breaking cyber news from The Hacker News (%s)", url)
    try:
        response = sess.get(url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
        xml_text = response.text
    except Exception as exc:
        logger.error("Failed fetching The Hacker News feed: %s", exc)
        return []

    try:
        root = ET.fromstring(xml_text)
    except Exception as exc:
        logger.error("Failed parsing The Hacker News XML: %s", exc)
        return []

    results: list[dict[str, Any]] = []

    # Handle Atom vs RSS XML
    # Atom namespaces: {http://www.w3.org/2005/Atom}
    entries = root.findall("{http://www.w3.org/2005/Atom}entry")
    if not entries:
        # Fallback to RSS items: channel/item
        entries = root.findall(".//item")

    for entry in entries[:max_items]:
        # Extract title
        title_elem = _first_elem(entry, "{http://www.w3.org/2005/Atom}title", "title")
        title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""

        # Extract content or summary
        content_elem = _first_elem(
            entry,
            "{http://www.w3.org/2005/Atom}content",
            "{http://www.w3.org/2005/Atom}summary",
            "description"
        )
        content_text = content_elem.text if content_elem is not None and content_elem.text else ""
        # Strip HTML tags simply
        clean_summary = re.sub(r"<[^>]+>", " ", content_text).strip()
        clean_summary = re.sub(r"\s+", " ", clean_summary)[:600]

        # Extract URL
        link_elem = _first_elem(entry, "{http://www.w3.org/2005/Atom}link", "link")
        if link_elem is not None:
            article_url = link_elem.attrib.get("href") or link_elem.text or "#"
        else:
            article_url = "#"

        # Published date
        pub_elem = _first_elem(
            entry,
            "{http://www.w3.org/2005/Atom}published",
            "{http://www.w3.org/2005/Atom}updated",
            "pubDate"
        )
        published_at = pub_elem.text if pub_elem is not None else None

        combined_text = f"{title} {clean_summary}"

        # Look for CVE references
        cve_matches = list(set(CVE_REGEX.findall(combined_text)))
        has_urgent_keywords = bool(ZERO_DAY_KEYWORDS.search(combined_text))

        if cve_matches:
            for cve in cve_matches:
                cve_id = cve.upper()
                results.append({
                    "source": "The Hacker News",
                    "cve_id": cve_id,
                    "title": f"[Breaking News] {title}",
                    "vendor": "",
                    "product": "",
                    "published_at": published_at,
                    "updated_at": published_at,
                    "severity": "CRITICAL" if has_urgent_keywords else "HIGH",
                    "cvss_score": None,
                    "is_cisa_kev": False,
                    "cisa_required_action": "Review breaking news advisory and apply emergency vendor mitigations.",
                    "summary": clean_summary,
                    "url": article_url,
                    "references": [article_url]
                })
        elif has_urgent_keywords and ("vulnerability" in combined_text.lower() or "flaw" in combined_text.lower() or "rce" in combined_text.lower()):
            # Important advisory that might not have a formal CVE assigned yet (0-day)
            slug = re.sub(r"[^A-Za-z0-9]+", "-", title[:40]).strip("-").upper()
            pseudo_id = f"THN:{slug}" if slug else "THN:BREAKING-ADVISORY"
            results.append({
                "source": "The Hacker News",
                "cve_id": pseudo_id,
                "title": f"[Breaking News] {title}",
                "vendor": "",
                "product": "",
                "published_at": published_at,
                "updated_at": published_at,
                "severity": "CRITICAL",
                "cvss_score": None,
                "is_cisa_kev": False,
                "cisa_required_action": "Review vendor emergency release notes for zero-day mitigations.",
                "summary": clean_summary,
                "url": article_url,
                "references": [article_url]
            })

    logger.info("Extracted %d actionable threat records from The Hacker News", len(results))
    return results
