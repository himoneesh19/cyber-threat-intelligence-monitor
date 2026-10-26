from __future__ import annotations

import logging
from typing import Any
import requests

from src.config import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger(__name__)


def fetch_epss_scores(
    cve_ids: list[str],
    url: str = "https://api.first.org/data/v1/epss",
    session: requests.Session | None = None
) -> dict[str, dict[str, float]]:
    """
    Fetches FIRST.org EPSS (Exploit Prediction Scoring System) probability scores.
    EPSS represents the empirical probability (0.00 to 1.00) that a vulnerability
    will be exploited in the wild within 30 days.
    """
    if not cve_ids:
        return {}

    sess = session or requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    # Deduplicate and filter valid CVE IDs
    valid_cves = sorted({c.upper().strip() for c in cve_ids if c.upper().strip().startswith("CVE-")})
    scores: dict[str, dict[str, float]] = {}

    # Query in batches of 40 to avoid URL length limits
    batch_size = 40
    for i in range(0, len(valid_cves), batch_size):
        batch = valid_cves[i:i + batch_size]
        try:
            resp = sess.get(url, headers=headers, params={"cve": ",".join(batch)}, timeout=HTTP_TIMEOUT_SECONDS)
            if resp.status_code != 200:
                logger.warning("EPSS endpoint returned status %d for batch %d", resp.status_code, i)
                continue

            data = resp.json().get("data", [])
            for item in data:
                cve = item.get("cve")
                if cve:
                    try:
                        scores[cve] = {
                            "epss": float(item.get("epss", 0.0)),
                            "percentile": float(item.get("percentile", 0.0))
                        }
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            logger.warning("Failed querying EPSS batch: %s", exc)

    logger.info("Retrieved EPSS scores for %d/%d requested CVEs", len(scores), len(valid_cves))
    return scores
