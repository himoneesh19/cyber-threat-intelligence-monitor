from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
import requests

from src.config import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger(__name__)


def collect_github_advisories(
    url: str,
    days_back: int = 7,
    max_pages: int = 2,
    session: requests.Session | None = None
) -> list[dict[str, Any]]:
    """
    Ingests open-source and ecosystem security advisories from GitHub Advisory Database.
    Covers npm, PyPI, Go, Composer/Packagist, Maven, Cargo, NuGet, RubyGems.
    """
    sess = session or requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    results: list[dict[str, Any]] = []

    for page in range(1, max_pages + 1):
        params = {
            "per_page": 100,
            "page": page,
            "sort": "updated",
            "direction": "desc"
        }

        logger.info("Fetching GitHub Advisories page %d from %s", page, url)
        try:
            resp = sess.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT_SECONDS)
            if resp.status_code == 403:
                logger.warning("GitHub API rate limit hit or access denied: %s", resp.text[:200])
                break
            resp.raise_for_status()
            items = resp.json()
        except Exception as exc:
            logger.error("Failed fetching GitHub Advisories page %d: %s", page, exc)
            break

        if not isinstance(items, list) or not items:
            break

        reached_cutoff = False
        for item in items:
            updated_str = item.get("updated_at") or item.get("published_at")
            if updated_str:
                try:
                    dt = datetime.fromisoformat(updated_str.replace("Z", "+00:00")).astimezone(timezone.utc)
                    if dt < cutoff:
                        reached_cutoff = True
                        continue
                except Exception:
                    pass

            ghsa_id = item.get("ghsa_id") or ""
            cve_id = (item.get("cve_id") or "").strip().upper()
            if not cve_id and not ghsa_id:
                continue

            cvss_obj = item.get("cvss") or {}
            cvss_score = cvss_obj.get("score")
            severity = (item.get("severity") or "UNKNOWN").upper()

            # Packages affected
            packages: list[dict[str, Any]] = []
            for vuln in item.get("vulnerabilities") or []:
                pkg = vuln.get("package") or {}
                pkg_name = pkg.get("name")
                if pkg_name:
                    packages.append({
                        "name": pkg_name,
                        "ecosystem": pkg.get("ecosystem", "unknown"),
                        "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                        "first_patched_version": vuln.get("first_patched_version")
                    })

            references = []
            for r in (item.get("references") or []):
                if isinstance(r, str) and r:
                    references.append(r)
                elif isinstance(r, dict) and r.get("url"):
                    references.append(r["url"])

            advisory_url = item.get("html_url") or f"https://github.com/advisories/{ghsa_id}"

            results.append({
                "source": "GitHub Security Advisories",
                "cve_id": cve_id or ghsa_id,
                "ghsa_id": ghsa_id,
                "title": item.get("summary") or ghsa_id,
                "vendor": packages[0]["ecosystem"] if packages else "Open Source",
                "product": ", ".join(p["name"] for p in packages[:3]),
                "published_at": item.get("published_at"),
                "updated_at": item.get("updated_at") or item.get("published_at"),
                "severity": severity,
                "cvss_score": float(cvss_score) if cvss_score is not None else None,
                "is_cisa_kev": False,
                "cisa_required_action": "Review patched versions and update dependencies in repository.",
                "summary": item.get("description") or item.get("summary") or "",
                "url": advisory_url,
                "packages": packages,
                "references": references[:10]
            })

        if reached_cutoff:
            logger.info("Reached cutoff date (%d days back) on page %d", days_back, page)
            break

    logger.info("Collected %d advisories from GitHub Advisories", len(results))
    return results
