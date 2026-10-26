from __future__ import annotations

import logging
from typing import Any
import requests

from src.config import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger(__name__)


def collect_cisa_kev(url: str, session: requests.Session | None = None) -> list[dict[str, Any]]:
    """
    Ingests the official CISA Known Exploited Vulnerabilities (KEV) Catalog.
    Every item in this feed is confirmed to be actively exploited in the wild.
    """
    sess = session or requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    logger.info("Fetching CISA KEV from %s", url)
    response = sess.get(url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
    response.raise_for_status()

    data = response.json()
    vulns = data.get("vulnerabilities", [])
    logger.info("Retrieved %d entries from CISA KEV catalog", len(vulns))

    results: list[dict[str, Any]] = []
    for item in vulns:
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        results.append({
            "source": "CISA KEV",
            "cve_id": cve_id,
            "title": item.get("vulnerabilityName") or f"{cve_id} (Active Exploitation)",
            "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "published_at": item.get("dateAdded"),
            "updated_at": item.get("dateAdded"),
            "severity": "CRITICAL",  # All active exploits are treated with top priority
            "cvss_score": None,      # Will be enriched by NVD/GHSA
            "is_cisa_kev": True,
            "cisa_required_action": item.get("requiredAction", "Apply updates per vendor instructions."),
            "cisa_due_date": item.get("dueDate", ""),
            "known_ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
            "summary": item.get("shortDescription", ""),
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
            "references": [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            ]
        })

    return results
