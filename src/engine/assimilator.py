from __future__ import annotations

import logging
from typing import Any
from src.engine.classifier import classify_threat

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4
}


def assimilate_threats(
    raw_records: list[dict[str, Any]],
    epss_scores: dict[str, dict[str, float]] | None = None,
    urgent_cvss_threshold: float = 9.0
) -> list[dict[str, Any]]:
    """
    Performs Canonical Entity Resolution:
    Aggregates multi-source telemetry, deduplicates records referencing the same CVE,
    merges enrichment data (CISA KEV, NVD CVSS, GHSA packages, EPSS scores),
    and classifies each unique threat into categories and technology stacks.
    """
    epss_map = epss_scores or {}
    grouped_by_cve: dict[str, list[dict[str, Any]]] = {}

    # 1. Group records by canonical CVE (or GHSA if no CVE exists)
    for rec in raw_records:
        canonical_key = (rec.get("cve_id") or rec.get("ghsa_id") or "").strip().upper()
        if not canonical_key:
            continue
        grouped_by_cve.setdefault(canonical_key, []).append(rec)

    assimilated: list[dict[str, Any]] = []

    # 2. Merge each group into a single consolidated threat record
    for cve_id, group in grouped_by_cve.items():
        is_cisa_kev = any(r.get("is_cisa_kev", False) for r in group)
        cisa_item = next((r for r in group if r.get("source") == "CISA KEV"), None)

        # Merge severity: pick highest priority
        severities = [r.get("severity", "UNKNOWN").upper() for r in group]
        if is_cisa_kev:
            best_severity = "CRITICAL"
        else:
            best_severity = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 4)) if severities else "UNKNOWN"

        # Merge CVSS score: take max available
        cvss_scores = [r.get("cvss_score") for r in group if r.get("cvss_score") is not None]
        best_cvss = max(cvss_scores) if cvss_scores else None

        # Pick best title and summary (prefer detailed descriptions over generic ones)
        titles = [r.get("title", "") for r in group if r.get("title")]
        best_title = titles[0] if titles else f"{cve_id}: Security Advisory"

        summaries = [r.get("summary", "") for r in group if r.get("summary")]
        best_summary = max(summaries, key=len) if summaries else "No description provided."

        # Merge distinct source links
        sources: list[dict[str, str]] = []
        seen_source_names = set()
        for r in group:
            src_name = r.get("source", "Advisory")
            if src_name not in seen_source_names:
                sources.append({"name": src_name, "url": r.get("url", "#")})
                seen_source_names.add(src_name)

        # Merge affected packages
        packages: list[dict[str, Any]] = []
        seen_pkgs = set()
        for r in group:
            for pkg in r.get("packages") or []:
                pkg_key = f"{pkg.get('ecosystem')}:{pkg.get('name')}"
                if pkg_key not in seen_pkgs:
                    packages.append(pkg)
                    seen_pkgs.add(pkg_key)

        # Merge reference links
        all_refs = set()
        for r in group:
            for ref in r.get("references") or []:
                if ref:
                    all_refs.add(ref)

        # EPSS Score
        epss_info = epss_map.get(cve_id, {})
        epss_score = epss_info.get("epss")
        epss_percentile = epss_info.get("percentile")

        # CISA metadata
        cisa_action = cisa_item.get("cisa_required_action") if cisa_item else "Review vendor guidance and apply recommended mitigations."
        cisa_due_date = cisa_item.get("cisa_due_date") if cisa_item else ""
        known_ransomware = cisa_item.get("known_ransomware") if cisa_item else "Unknown"

        # Construct merged record
        merged_record = {
            "cve_id": cve_id,
            "title": best_title,
            "severity": best_severity,
            "cvss_score": best_cvss,
            "is_cisa_kev": is_cisa_kev,
            "cisa_required_action": cisa_action,
            "cisa_due_date": cisa_due_date,
            "known_ransomware": known_ransomware,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "summary": best_summary,
            "packages": packages,
            "sources": sources,
            "references": sorted(all_refs)[:15],
            "published_at": next((r.get("published_at") for r in group if r.get("published_at")), None),
            "updated_at": next((r.get("updated_at") for r in group if r.get("updated_at")), None),
        }

        # 3. Classify into Category and Technology Tags
        category, technologies = classify_threat(merged_record)
        merged_record["category"] = category
        merged_record["technologies"] = technologies

        # 4. Determine Urgency
        is_urgent = False
        urgent_reasons = []

        if is_cisa_kev:
            is_urgent = True
            urgent_reasons.append("Active Exploitation (CISA KEV)")
        if best_severity == "CRITICAL" or (best_cvss is not None and best_cvss >= urgent_cvss_threshold):
            is_urgent = True
            urgent_reasons.append(f"Critical Severity (CVSS {best_cvss or '9+'})")
        if epss_score is not None and epss_score >= 0.60:
            is_urgent = True
            urgent_reasons.append(f"High Exploit Probability (EPSS {epss_score:.1%})")

        merged_record["is_urgent"] = is_urgent
        merged_record["urgent_reasons"] = urgent_reasons

        assimilated.append(merged_record)

    # Sort assimilated threats: KEV first, then Severity (CRITICAL -> LOW), then CVSS score
    assimilated.sort(key=lambda x: (
        0 if x.get("is_cisa_kev") else 1,
        SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4),
        -(x.get("cvss_score") or 0.0),
        -(x.get("epss_score") or 0.0)
    ))

    logger.info("Assimilated %d raw source records into %d canonical threat entities", len(raw_records), len(assimilated))
    return assimilated
