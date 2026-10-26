from __future__ import annotations

import html
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

# Colors for severities and badges
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#fee2e2", "text": "#991b1b", "border": "#f87171"},
    "HIGH": {"bg": "#ffedd5", "text": "#9a3412", "border": "#fb923c"},
    "MEDIUM": {"bg": "#fef9c3", "text": "#854d0e", "border": "#facc15"},
    "LOW": {"bg": "#f0fdf4", "text": "#166534", "border": "#86efac"},
    "UNKNOWN": {"bg": "#f1f5f9", "text": "#475569", "border": "#cbd5e1"},
}


def _render_threat_card(item: dict[str, Any]) -> str:
    cve_id = html.escape(item.get("cve_id", "Vulnerability"))
    title = html.escape(item.get("title", ""))
    summary = html.escape((item.get("summary") or "").strip()[:800])
    action = html.escape(item.get("cisa_required_action") or "Review vendor advisory and apply available patches.")
    severity = item.get("severity", "UNKNOWN").upper()
    sev_style = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])

    cvss = item.get("cvss_score")
    cvss_badge = f'<span style="display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;border-radius:4px;background:#e0e7ff;color:#3730a3;margin-right:6px;">CVSS {cvss}</span>' if cvss is not None else ""

    kev_badge = ""
    if item.get("is_cisa_kev"):
        kev_badge = '<span style="display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;border-radius:4px;background:#dc2626;color:#ffffff;margin-right:6px;">🔥 CISA KEV (ACTIVE EXPLOIT)</span>'

    epss = item.get("epss_score")
    epss_badge = ""
    if epss is not None and epss >= 0.10:
        epss_badge = f'<span style="display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;border-radius:4px;background:#fae8ff;color:#86198f;margin-right:6px;">EPSS {epss:.1%}</span>'

    tech_pills = ""
    for tech in item.get("technologies") or []:
        tech_pills += f'<span style="display:inline-block;padding:2px 6px;font-size:10px;font-weight:600;border-radius:3px;background:#f1f5f9;color:#334155;margin-right:4px;">{html.escape(tech)}</span>'

    sources_html = ""
    for s in item.get("sources") or []:
        s_name = html.escape(s.get("name", "Advisory"))
        s_url = html.escape(s.get("url", "#"), quote=True)
        sources_html += f'<a href="{s_url}" style="color:#2563eb;text-decoration:none;font-weight:600;font-size:12px;margin-right:12px;">↗ {s_name}</a> '

    cisa_due_row = ""
    if item.get("cisa_due_date"):
        cisa_due_row = f'<div style="font-size:12px;color:#b91c1c;font-weight:700;margin-top:4px;">⏱️ CISA Federal Due Date: {html.escape(item["cisa_due_date"])}</div>'

    return f"""
    <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:14px;box-shadow:0 1px 2px rgba(0,0,0,0.04);">
        <div style="margin-bottom:8px;">
            <span style="display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;border-radius:4px;background:{sev_style['bg']};color:{sev_style['text']};border:1px solid {sev_style['border']};margin-right:6px;">{severity}</span>
            {cvss_badge}
            {kev_badge}
            {epss_badge}
        </div>
        <div style="font-size:15px;font-weight:700;color:#0f172a;margin-bottom:6px;line-height:1.3;">
            {cve_id}: {title}
        </div>
        {f'<div style="margin-bottom:8px;">{tech_pills}</div>' if tech_pills else ''}
        <div style="font-size:13px;color:#475569;line-height:1.5;margin-bottom:10px;">
            {summary}
        </div>
        <div style="background:#f8fafc;border-left:3px solid #2563eb;padding:8px 12px;border-radius:0 4px 4px 0;margin-bottom:10px;font-size:12px;color:#1e293b;">
            <b>Suggested Action:</b> {action}
            {cisa_due_row}
        </div>
        <div style="padding-top:4px;border-top:1px dashed #f1f5f9;">
            {sources_html}
        </div>
    </div>
    """


def build_urgent_alert_email(urgent_items: list[dict[str, Any]]) -> tuple[str, str, str]:
    """
    Builds a high-impact, immediate flash alert email for critical/exploited threats.
    Returns: (subject, text_body, html_body)
    """
    count = len(urgent_items)
    now_ist = datetime.now(IST).strftime("%d %b %Y, %I:%M %p IST")
    subject = f"🚨 [URGENT SECURITY ALERT] {count} Active Exploit / Critical Threat(s) Detected"

    # Plain Text
    plain_lines = [
        f"URGENT CYBER THREAT ALERT — {now_ist}",
        "=" * 70,
        f"Automated intelligence detected {count} high-risk or actively exploited vulnerability record(s).",
        "Verify your exposed assets and apply immediate mitigations.",
        "",
    ]
    for item in urgent_items:
        plain_lines.extend([
            f"[{item.get('severity','UNKNOWN')}] {item.get('cve_id')}: {item.get('title')}",
            f"Category: {item.get('category')} | Technologies: {', '.join(item.get('technologies', [])) or 'General'}",
            f"CISA KEV Active Exploit: {'YES' if item.get('is_cisa_kev') else 'NO'} | CVSS: {item.get('cvss_score') or 'N/A'}",
            f"Action: {item.get('cisa_required_action') or 'Consult vendor advisory.'}",
            f"Primary Link: {item.get('sources', [{'url': '#'}])[0]['url']}",
            "-" * 70,
        ])
    plain_body = "\n".join(plain_lines)

    # HTML Cards
    cards_html = "".join(_render_threat_card(item) for item in urgent_items)

    html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(subject)}</title>
</head>
<body style="margin:0;padding:20px;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
    <div style="max-width:680px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">
        <!-- Urgent Red Header -->
        <div style="background:#dc2626;padding:24px 28px;color:#ffffff;">
            <div style="font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:700;opacity:0.9;">High-Priority Intervention</div>
            <h1 style="margin:6px 0 0;font-size:22px;font-weight:800;color:#ffffff;line-height:1.2;">🚨 Urgent Security Flash Alert</h1>
            <div style="font-size:13px;margin-top:6px;opacity:0.95;">{now_ist} &bull; {count} Critical Vulnerability / Active Exploit(s)</div>
        </div>

        <!-- Alert Context Banner -->
        <div style="background:#fef2f2;border-bottom:1px solid #fee2e2;padding:14px 28px;font-size:13px;color:#991b1b;line-height:1.5;">
            <b>Attention Required:</b> Telemetry identified threats with verified in-the-wild exploitation or critical severity. Check whether your production environments, containers, or web applications are running vulnerable versions.
        </div>

        <!-- Threat Cards -->
        <div style="padding:24px 28px;background:#f8fafc;">
            {cards_html}
        </div>

        <!-- Footer -->
        <div style="padding:20px 28px;background:#0f172a;color:#94a3b8;font-size:11px;text-align:center;line-height:1.6;">
            Aggregated from CISA KEV &bull; NIST NVD &bull; GitHub Security Advisories &bull; FIRST EPSS<br>
            Automated intelligence &bull; Always test patches before deploying to critical production infrastructure.
        </div>
    </div>
</body>
</html>"""
    return subject, plain_body, html_body


def build_daily_digest_email(
    threats: list[dict[str, Any]],
    scan_date: datetime | None = None
) -> tuple[str, str, str]:
    """
    Builds the executive daily cybersecurity briefing categorized by technology stacks.
    Returns: (subject, text_body, html_body)
    """
    now = scan_date or datetime.now(IST)
    date_str = now.strftime("%d %b %Y")
    total_count = len(threats)
    urgent_count = sum(1 for t in threats if t.get("is_urgent"))
    kev_count = sum(1 for t in threats if t.get("is_cisa_kev"))
    critical_count = sum(1 for t in threats if t.get("severity") == "CRITICAL")
    high_count = sum(1 for t in threats if t.get("severity") == "HIGH")

    subject = f"🛡️ Daily Security Digest — {date_str} | {total_count} Threats Analyzed"

    # Plain text summary
    plain_lines = [
        f"DAILY CYBERSECURITY INTELLIGENCE DIGEST — {date_str}",
        "=" * 70,
        f"Total Threats Ingested: {total_count}",
        f"Active KEV Exploits: {kev_count} | Critical (CVSS 9+): {critical_count} | High: {high_count}",
        "-" * 70,
    ]

    # Group threats by category
    categorized: dict[str, list[dict[str, Any]]] = {}
    for t in threats:
        cat = t.get("category", "General Security & Vulnerabilities")
        categorized.setdefault(cat, []).append(t)

    for cat, items in categorized.items():
        plain_lines.append(f"\n### {cat.upper()} ({len(items)})")
        for item in items[:10]:
            plain_lines.append(f"  * [{item.get('severity')}] {item.get('cve_id')}: {item.get('title')}")
            plain_lines.append(f"    Action: {item.get('cisa_required_action')}")

    plain_body = "\n".join(plain_lines)

    # HTML Sections
    sections_html = ""
    # Put Urgent/KEV section first if any exist
    urgent_items = [t for t in threats if t.get("is_urgent")]
    if urgent_items:
        sections_html += f"""
        <div style="margin-bottom:28px;">
            <div style="font-size:16px;font-weight:800;color:#dc2626;margin-bottom:12px;padding-bottom:6px;border-bottom:2px solid #fecaca;display:flex;align-items:center;">
                ⚡ Immediate Attention Required ({len(urgent_items)})
            </div>
            {''.join(_render_threat_card(t) for t in urgent_items[:15])}
        </div>
        """

    for cat_name, items in categorized.items():
        # Exclude items already rendered in urgent to avoid duplication
        non_urgent_items = [t for t in items if not t.get("is_urgent")]
        if not non_urgent_items:
            continue

        sections_html += f"""
        <div style="margin-bottom:28px;">
            <div style="font-size:16px;font-weight:800;color:#0f172a;margin-bottom:12px;padding-bottom:6px;border-bottom:2px solid #e2e8f0;">
                📁 {html.escape(cat_name)} ({len(non_urgent_items)})
            </div>
            {''.join(_render_threat_card(t) for t in non_urgent_items[:10])}
        </div>
        """

    html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(subject)}</title>
</head>
<body style="margin:0;padding:20px;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
    <div style="max-width:700px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">
        <!-- Slate Executive Header -->
        <div style="background:#0f172a;padding:26px 30px;color:#ffffff;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:700;color:#38bdf8;">Global Security Monitor</span>
                <span style="font-size:12px;color:#94a3b8;">{date_str}</span>
            </div>
            <h1 style="margin:8px 0 0;font-size:22px;font-weight:800;color:#ffffff;">🛡️ Daily Cyber Threat Briefing</h1>
            <div style="font-size:13px;color:#cbd5e1;margin-top:6px;">Multi-source telemetry across Cloud, Web, Databases, OS, and AI</div>
        </div>

        <!-- Executive Metrics KPI Ribbon -->
        <div style="background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:16px 24px;text-align:center;">
            <table width="100%" cellpadding="0" cellspacing="0" style="table-layout:fixed;">
                <tr>
                    <td align="center" style="padding:4px;">
                        <div style="font-size:20px;font-weight:800;color:{'#dc2626' if kev_count > 0 else '#475569'};">{kev_count}</div>
                        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">Active KEV</div>
                    </td>
                    <td align="center" style="padding:4px;border-left:1px solid #e2e8f0;">
                        <div style="font-size:20px;font-weight:800;color:#b91c1c;">{critical_count}</div>
                        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">Critical</div>
                    </td>
                    <td align="center" style="padding:4px;border-left:1px solid #e2e8f0;">
                        <div style="font-size:20px;font-weight:800;color:#d97706;">{high_count}</div>
                        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">High</div>
                    </td>
                    <td align="center" style="padding:4px;border-left:1px solid #e2e8f0;">
                        <div style="font-size:20px;font-weight:800;color:#0284c7;">{total_count}</div>
                        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">Total New</div>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Main Body -->
        <div style="padding:26px 30px;background:#f8fafc;">
            {sections_html}
        </div>

        <!-- Footer -->
        <div style="padding:20px 30px;background:#0f172a;color:#94a3b8;font-size:11px;text-align:center;line-height:1.6;">
            Sources: CISA Known Exploited Vulnerabilities &bull; NIST NVD &bull; GitHub Advisory Database &bull; FIRST EPSS<br>
            Delivered automatically via GitHub Actions &bull; Configure alert filters in repository settings.
        </div>
    </div>
</body>
</html>"""
    return subject, plain_body, html_body
