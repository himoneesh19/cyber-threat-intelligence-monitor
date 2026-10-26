#!/usr/bin/env python3
"""
Enterprise Cyber Threat Intelligence Monitor & Assimilation Pipeline
Entrypoint for scheduled workflows and local diagnostic runs.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

# Ensure project root is in sys.path when invoked directly
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.collectors import (
    collect_cisa_kev,
    collect_github_advisories,
    collect_nvd_cves,
    fetch_epss_scores,
    collect_thn_news,
)
from src.config import load_sources, DEFAULT_URGENT_CVSS_THRESHOLD
from src.engine import assimilate_threats, StateManager
from src.notifiers import (
    build_urgent_alert_email,
    build_daily_digest_email,
    send_email,
    EmailDispatcher
)
from src.portal import generate_portal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ThreatMonitor")
IST = ZoneInfo("Asia/Kolkata")


def run_pipeline(
    sources_to_run: list[str] | None = None,
    dry_run: bool = False,
    skip_epss: bool = False,
    force_digest: bool = False,
    test_email: bool = False,
    urgent_threshold: float = DEFAULT_URGENT_CVSS_THRESHOLD
) -> dict[str, Any]:
    sources = load_sources()
    state_mgr = StateManager()
    state = state_mgr.load_state()

    raw_records: list[dict[str, Any]] = []
    source_stats: dict[str, int] = {}
    errors: list[str] = []

    target_sources = sources_to_run or ["cisa", "github", "nvd", "news"]

    # 1. Ingest CISA KEV
    if "cisa" in target_sources and "cisa_kev" in sources:
        try:
            kev_items = collect_cisa_kev(sources["cisa_kev"])
            raw_records.extend(kev_items)
            source_stats["CISA KEV"] = len(kev_items)
        except Exception as exc:
            err = f"CISA KEV collection failed: {exc}"
            logger.error(err)
            errors.append(err)

    # 2. Ingest GitHub Advisories
    if "github" in target_sources and "github_advisories" in sources:
        try:
            ghsa_items = collect_github_advisories(sources["github_advisories"], days_back=7)
            raw_records.extend(ghsa_items)
            source_stats["GitHub Advisories"] = len(ghsa_items)
        except Exception as exc:
            err = f"GitHub Advisories collection failed: {exc}"
            logger.error(err)
            errors.append(err)

    # 3. Ingest NVD CVEs
    if "nvd" in target_sources and "nvd_cves" in sources:
        try:
            nvd_items = collect_nvd_cves(sources["nvd_cves"], hours_back=48)
            raw_records.extend(nvd_items)
            source_stats["NVD 2.0"] = len(nvd_items)
        except Exception as exc:
            err = f"NVD CVE collection failed: {exc}"
            logger.error(err)
            errors.append(err)

    # 4. Ingest Breaking News & Zero-Days (The Hacker News)
    if "news" in target_sources and "thn_news" in sources:
        try:
            thn_items = collect_thn_news(sources["thn_news"], max_items=25)
            raw_records.extend(thn_items)
            source_stats["The Hacker News"] = len(thn_items)
        except Exception as exc:
            err = f"The Hacker News collection failed: {exc}"
            logger.error(err)
            errors.append(err)

    if not raw_records and errors:
        raise RuntimeError(f"All data sources failed: {'; '.join(errors)}")

    logger.info("Total raw telemetry records ingested: %d", len(raw_records))

    # 4. Fetch EPSS Exploit Prediction Scores
    epss_scores: dict[str, dict[str, float]] = {}
    if not skip_epss and "epss" in sources:
        all_cves = [r["cve_id"] for r in raw_records if r.get("cve_id")]
        try:
            epss_scores = fetch_epss_scores(all_cves, sources["epss"])
        except Exception as exc:
            logger.warning("EPSS lookup error: %s", exc)

    # 5. Assimilate, Deduplicate, Classify & Prioritize
    assimilated = assimilate_threats(
        raw_records=raw_records,
        epss_scores=epss_scores,
        urgent_cvss_threshold=urgent_threshold
    )

    # 6. Deduplicate against seen state
    new_threats, existing_threats = state_mgr.filter_new_threats(assimilated, state)

    # 7. Print Executive Summary
    urgent_new = [t for t in new_threats if t.get("is_urgent")]
    urgent_count = len(urgent_new)
    kev_count = sum(1 for t in new_threats if t.get("is_cisa_kev"))

    category_distribution: dict[str, int] = {}
    for t in new_threats:
        cat = t.get("category", "General")
        category_distribution[cat] = category_distribution.get(cat, 0) + 1

    print("\n" + "=" * 80)
    print("🛡️  CYBER THREAT INTELLIGENCE INGESTION & ASSIMILATION SUMMARY")
    print("=" * 80)
    print(f"Sources Queried        : {', '.join(source_stats.keys())}")
    for src, count in source_stats.items():
        print(f"  - {src:<20}: {count} records")
    print("-" * 80)
    print(f"Total Raw Records Ingested   : {len(raw_records)}")
    print(f"Assimilated Canonical CVEs   : {len(assimilated)}")
    print(f"Newly Observed Threats       : {len(new_threats)}")
    print(f"Urgent / Actionable Threats  : {urgent_count} (CISA KEV Active Exploits: {kev_count})")
    print("-" * 80)
    print("Category Breakdown (New Threats):")
    for cat, cnt in sorted(category_distribution.items(), key=lambda x: -x[1]):
        print(f"  • {cat:<32}: {cnt}")
    print("=" * 80)

    # 8. Notifications Dispatch
    dispatcher = EmailDispatcher()
    is_email_configured = dispatcher.is_configured()

    if not is_email_configured and not dry_run:
        logger.info("Email secrets not provided. Skipping SMTP dispatch.")

    # A. Send Urgent Flash Alert for qualifying new threats
    if urgent_new:
        subj, text_body, html_body = build_urgent_alert_email(urgent_new)
        if dry_run:
            logger.info("[DRY RUN] Generated urgent alert email for %d threats: %s", len(urgent_new), subj)
        else:
            send_email(subj, text_body, html_body)

    # B. Send Daily Digest during daily window (09:00 - 09:30 IST) or if forced
    now_ist = datetime.now(IST)
    is_daily_window = (now_ist.hour == 9 and now_ist.minute < 30) or force_digest
    send_empty = os.getenv("SEND_EMPTY_DAILY_DIGEST", "false").lower() == "true"

    if is_daily_window:
        if new_threats or send_empty:
            d_subj, d_text, d_html = build_daily_digest_email(new_threats if new_threats else assimilated[:10])
            if dry_run:
                logger.info("[DRY RUN] Generated daily digest email: %s", d_subj)
            else:
                send_email(d_subj, d_text, d_html)
        else:
            logger.info("Daily window active, but no new threats observed. Skipped empty digest.")

    # C. Handle Test Email if requested
    if test_email or os.getenv("SEND_TEST_EMAIL", "false").lower() == "true":
        t_subj = "🔔 [TEST] Cyber Threat Monitor SMTP Verification"
        t_body = "This test email confirms that your Gmail SMTP credentials are configured correctly."
        t_html = "<div style='font-family:sans-serif;padding:20px;background:#f8fafc;border-radius:8px;'><h2>✅ SMTP Connectivity Verified</h2><p>Your automated cyber threat pipeline is connected and able to send security alerts.</p></div>"
        send_email(t_subj, t_body, t_html, dry_run=dry_run)

    # 9. Update & Compile Web Portal for GitHub Pages
    try:
        portal_path = generate_portal(assimilated)
        logger.info("Updated Web Portal at %s (%d threats)", portal_path, len(assimilated))
    except Exception as exc:
        logger.error("Failed generating Web Portal: %s", exc)

    # 10. Save state unless dry run
    if not dry_run:
        state_mgr.save_state(state)
    else:
        logger.info("Dry-run mode enabled; state not written to disk.")

    return {
        "raw_count": len(raw_records),
        "assimilated_count": len(assimilated),
        "new_count": len(new_threats),
        "urgent_count": urgent_count,
        "new_threats": new_threats,
        "errors": errors
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence Pipeline CLI")
    parser.add_argument("--dry-run", action="store_true", help="Run without persisting state or sending live emails")
    parser.add_argument("--sources", nargs="+", choices=["cisa", "github", "nvd", "news"], help="Select specific sources")
    parser.add_argument("--skip-epss", action="store_true", help="Skip EPSS scoring lookups")
    parser.add_argument("--force-digest", action="store_true", help="Force building and sending the daily digest regardless of hour")
    parser.add_argument("--test-email", action="store_true", help="Send a test verification email")
    parser.add_argument("--urgent-threshold", type=float, default=DEFAULT_URGENT_CVSS_THRESHOLD, help="CVSS threshold for urgent alert")

    args = parser.parse_args()

    try:
        run_pipeline(
            sources_to_run=args.sources,
            dry_run=args.dry_run,
            skip_epss=args.skip_epss,
            force_digest=args.force_digest,
            test_email=args.test_email,
            urgent_threshold=args.urgent_threshold
        )
        return 0
    except Exception as exc:
        logger.exception("Pipeline execution failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
