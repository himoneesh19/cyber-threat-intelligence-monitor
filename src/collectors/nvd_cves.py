from __future__ import annotations

import logging
import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any
import requests

from src.config import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger(__name__)


def collect_nvd_cves(
    url: str,
    hours_back: int = 48,
    session: requests.Session | None = None
) -> list[dict[str, Any]]:
    """
    Ingests recent vulnerability updates from the official NIST NVD 2.0 API.
    Uses rolling modification timestamp windows to ensure only recent changes are retrieved.
    Includes exponential backoff with jitter to handle NVD's strict rate limits.
    """
    sess = session or requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    nvd_api_key = os.getenv("NVD_API_KEY", "").strip()
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
        logger.info("Using authenticated NVD API Key (elevated rate limits)")
    else:
        logger.info("No NVD API Key provided; using standard rate-limited endpoint")

    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=hours_back)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    params: dict[str, Any] = {
        "lastModStartDate": start_dt.strftime(fmt) + "Z",
        "lastModEndDate": end_dt.strftime(fmt) + "Z",
        "resultsPerPage": 500,
        "startIndex": 0
    }

    results: list[dict[str, Any]] = []
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        try:
            logger.info("Fetching NVD CVEs from %s (attempt %d/%d)", url, attempt, max_retries)
            response = sess.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT_SECONDS)

            if response.status_code in (403, 429, 503):
                # Rate limit or temporary NVD downtime
                sleep_time = (2 ** attempt) + random.uniform(1.0, 3.0)
                logger.warning("NVD returned HTTP %d. Backing off for %.1fs...", response.status_code, sleep_time)
                time.sleep(sleep_time)
                continue

            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            logger.info("Received %d records from NVD API", len(vulns))

            for entry in vulns:
                cve = entry.get("cve", {})
                cve_id = (cve.get("id") or "").strip().upper()
                if not cve_id:
                    continue

                descriptions = cve.get("descriptions") or []
                desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

                # Extract CVSS v3.1 / v4.0 / v2
                metrics = cve.get("metrics") or {}
                cvss_score = None
                severity = "UNKNOWN"

                for m_key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
                    m_list = metrics.get(m_key) or []
                    if m_list:
                        cvss_data = m_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = (cvss_data.get("baseSeverity") or m_list[0].get("baseSeverity") or "UNKNOWN").upper()
                        break

                if cvss_score is not None and severity == "UNKNOWN":
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                results.append({
                    "source": "NVD",
                    "cve_id": cve_id,
                    "title": f"{cve_id}: {desc[:140]}..." if len(desc) > 140 else f"{cve_id}: {desc}",
                    "vendor": "",
                    "product": "",
                    "published_at": cve.get("published"),
                    "updated_at": cve.get("lastModified") or cve.get("published"),
                    "severity": severity,
                    "cvss_score": float(cvss_score) if cvss_score is not None else None,
                    "is_cisa_kev": False,
                    "cisa_required_action": "Consult vendor advisories and apply available patches.",
                    "summary": desc,
                    "url": cve_url,
                    "references": refs[:10]
                })

            return results

        except requests.exceptions.RequestException as exc:
            logger.warning("NVD request error on attempt %d: %s", attempt, exc)
            if attempt < max_retries:
                time.sleep(2 ** attempt)
            else:
                logger.error("All NVD retry attempts exhausted: %s", exc)

    return results
