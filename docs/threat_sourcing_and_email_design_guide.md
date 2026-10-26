# Industry Standards Guide: Threat Intelligence Sourcing & Security Advisory Email Design

**Document Version:** 1.0.0  
**Target Scope:** Building an Enterprise-Grade Cyber Threat Intelligence (CTI) Aggregation & Notification Platform from Scratch  
**Target Audience:** Security Engineers, DevSecOps Architects, and Full-Stack Engineers  

---

## 1. Executive Overview & Architecture Blueprint

When architecting an automated cyber threat intelligence (CTI) monitoring and notification platform from scratch, engineering teams routinely encounter two catastrophic failure modes:

1. **The Sourcing Failure (Alert Fatigue / Stale Data):** Ingesting raw, unfiltered vulnerability feeds that flood security engineers with noise, or conversely, relying on lagging secondary aggregators that report critical zero-days hours or days after active exploitation has begun in the wild.
2. **The Formatting Failure (Unusable Alerts):** Dispatching generic, unformatted email dumps that fail spam filters (SPF/DKIM/DMARC), break in Outlook or mobile dark mode, or lack the critical operational context (affected assets, CVSS vectors, EPSS probability, and immediate remediation steps) needed for swift triage.

A production-grade CTI notification platform must treat **intelligence ingestion** as a rigorous data-pipeline discipline and **email delivery** as mission-critical, human-factors engineering.

```
+---------------------------------------------------------------------------------------------------+
|                                 1. TIERED THREAT SOURCING PIPELINE                                |
|                                                                                                   |
|  [Tier 1: Authoritative Govt]       [Tier 2: Vendor CSAF / VEX]       [Tier 3: Exploit Telemetry] |
|   CISA KEV / RVWP, US-CERT           MSRC, Red Hat, AWS, Cisco         EPSS, GreyNoise, Exploit-DB|
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             2. DATA NORMALIZATION & ASSIMILATION                                  |
|                                                                                                   |
|  * Canonical CVE Entity Resolution (De-duplicating multi-source mentions)                         |
|  * Admiralty Code Credibility Scoring (NATO A1-F6 reliability matrix)                             |
|  * Context Enrichment: MITRE ATT&CK Tactics + CVSS v3.1/v4.0 + EPSS Probability                   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             3. INTELLIGENT DISPATCH & FORMATTING                                  |
|                                                                                                   |
|   CRITICAL / ACTIVE EXPLOIT (KEV / EPSS > 0.15)                  ROUTINE / SCHEDULED UPDATE       |
|   ---------------------------------------------                  --------------------------       |
|   ==> P0/P1 Immediate Flash Alert                                ==> Daily/Weekly CTI Digest      |
|   * TLP:CLEAR / TLP:AMBER Header                                 * Executive Metric Summary       |
|   * BLUF (Bottom Line Up Front)                                  * Prioritized Triage Matrix      |
|   * Concrete Remediation & Due Dates                             * Categorized by Tech Stacks     |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        4. ENTERPRISE DELIVERABILITY & COMPLIANCE                                  |
|                                                                                                   |
|  * Multi-part MIME (Resilient HTML + Pristine Plain-Text ASCII fallback)                          |
|  * Outlook/Apple Mail/Gmail Dark-Mode Inversion Hardening                                         |
|  * SPF + DKIM + DMARC (p=reject) + BIMI Authentication (Bypassing Proofpoint/Defender Spam Gates) |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Intelligence Sourcing: Standards & Architecture

### 2.1 The 4-Tier Threat Source Hierarchy

Relying on a single source (e.g., NIST NVD) is hazardous. Between 2024 and 2026, NIST NVD experienced well-documented backlogs where thousands of newly published CVEs went unenriched for weeks. A resilient architecture ingests across four distinct tiers:

| Tier | Category | Authoritative Sources | Ingestion Frequency | Latency / Value Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Authoritative Government & CERT Feeds** | • CISA KEV (Known Exploited Vulnerabilities)<br>• CISA RVWP (Ransomware Warning Pilot)<br>• JPCERT/CC, CERT-EU, BSI Advisories | 30–60 mins | **Zero false-positives for active exploitation.** CISA KEV is mandatory for US Federal civilian agencies (BOD 22-01) and represents the gold standard for verified in-the-wild attacks. |
| **Tier 2** | **Direct Machine-Readable Vendor Feeds (CSAF / VEX)** | • Microsoft MSRC (CSAF API)<br>• Red Hat Security Data API<br>• Cisco PSIRT, AWS Security Bulletins, Google Cloud Advisories | 15–30 mins | **First to publish.** Vendors publish patches and workarounds hours or days before NVD indexes them. Ingesting machine-readable CSAF 2.0 (Common Security Advisory Framework) eliminates parsing ambiguity. |
| **Tier 3** | **Exploit Probability & Weaponization Telemetry** | • FIRST EPSS (Exploit Prediction Scoring System)<br>• GreyNoise Intelligence (Mass scanning alerts)<br>• Exploit-DB, Metasploit, Packet Storm | 1–4 hours | **Predictive & real-time telemetry.** EPSS predicts the likelihood of weaponization within 30 days. GreyNoise separates benign Internet background noise from targeted opportunistic scanning. |
| **Tier 4** | **Curated OSINT & Technical Journalism** | • BleepingComputer RSS<br>• The Hacker News (THN)<br>• KrebsOnSecurity<br>• SANS Internet Storm Center (ISC) Diary | 1–2 hours | **Contextual intelligence.** Uncovers active campaigns, zero-day threat actors, targeted industries, and real-world blast radiuses before formal CVE assignments finalize. |

---

### 2.2 Source Reliability & Credibility Assessment (The Admiralty / NATO System)

Industry-standard CTI teams evaluate intelligence using the **NATO / Admiralty System** (FM 2-22.3), scoring both source reliability (letters A–F) and information credibility (numbers 1–6):

```
       SOURCE RELIABILITY                     INFORMATION CREDIBILITY
  A = Completely Reliable                1 = Confirmed by other independent sources
  B = Usually Reliable                   2 = Probably True
  C = Fairly Reliable                    3 = Possibly True
  D = Not Usually Reliable               4 = Doubtfully True
  E = Unreliable                         5 = Improbable
  F = Reliability Cannot Be Judged       6 = Truth Cannot Be Judged
```

* **Tier 1 (CISA KEV, Vendor CSAF):** Graded **A1** (Authoritative, verified). Immediate alerts can trigger autonomously.
* **Tier 3 (EPSS / GreyNoise telemetry):** Graded **B2** (Highly reliable statistical signal, probable weaponization).
* **Tier 4 (Social media, unverified leak channels, forums):** Graded **E3 to F6**. Must **never** trigger unmoderated P0 alerts; require multi-source corroboration before dispatch.

---

### 2.3 Essential Taxonomies and Standards for Sourcing

When building data models from scratch, adhere to established international standards rather than inventing proprietary schemas:

1. **CSAF 2.0 (OASIS Common Security Advisory Framework):** The standard machine-readable JSON format for vendor security bulletins, supporting VEX (Vulnerability Exploitability eXchange) profiles to convey whether a product is affected, fixed, or not affected.
2. **MITRE ATT&CK Framework:** Maps threats to adversary Tactics, Techniques, and Procedures (TTPs). Example: A vulnerability in an external web interface must be linked to technique `T1190` (*Exploit Public-Facing Application*).
3. **CVSS v3.1 and CVSS v4.0:** CVSS v4.0 introduces distinct metrics for Base, Threat (exploit maturity), and Environmental metrics, avoiding the common mistake of treating a raw CVSS 9.8 score as an urgent fire drill if the exploit maturity is unproven.
4. **FIRST EPSS (Exploit Prediction Scoring System):** Ingest EPSS percentiles. A CVE with CVSS 9.8 but an EPSS score of 0.001 (0.1% probability of exploit) has far lower real-world urgency than a CVSS 7.5 vulnerability with an EPSS of 0.85 (85% probability) and an active CISA KEV entry.

---

### 2.4 Ingestion Pipeline Engineering Principles

When collecting data across distributed feeds:

* **HTTP Conditional Requests (ETags & `If-Modified-Since`):** Do not pull multi-megabyte feeds (like NIST NVD or CISA KEV JSON) on raw timers without cache validation headers. Store HTTP `ETag` and `Last-Modified` timestamps to save bandwidth and prevent API rate-limiting blocks.
* **Circuit Breakers & Exponential Backoff:** APIs (particularly NVD 2.0) apply aggressive rate limits (e.g., 5 requests per 30 seconds without an API key). Implement jittered exponential backoff and isolate collectors so a timeout on one feed never halts the entire ingestion cycle.
* **Schema Validation at the Boundary:** Enforce strict typing (e.g., JSON Schema or Pydantic models). If a feed vendor modifies their payload format, fail gracefully with an alert rather than corrupting state storage.

---

### 2.5 Canonical Entity Resolution & Multi-Feed Deduplication

One of the most frequent beginner mistakes is alerting on each feed independently. If a VMware zero-day drops, CISA publishes a KEV record, Red Hat posts a security advisory, and BleepingComputer writes an article. 

**Anti-Pattern:** The user receives 3 separate, fragmented emails over 4 hours.  
**Industry Standard (Canonical Entity Resolution):**
1. Extract all identifier keys (`CVE-YYYY-XXXXX`, `GHSA-xxxx-xxxx`, vendor bulletin ID `MS24-xxx`).
2. Map to a single canonical record keyed by the canonical CVE ID.
3. Merge telemetry:
   * **NVD** provides the canonical description and base CVSS score.
   * **CISA KEV** provides the active exploitation flag and remediation deadline.
   * **FIRST EPSS** provides the mathematical exploitation probability.
   * **OSINT / News** provides the narrative attack vector and proof-of-concept links.

---

## 3. Security Advisory Email Formatting & Design Standards

### 3.1 Overcoming SecOps Alert Fatigue

Security analysts and engineering leads receive hundreds of automated emails daily. If an email requires scrolling through paragraphs of dense text to identify which internal systems are affected and what command to execute, **the notification has failed**.

Advisory emails must satisfy two distinct operational needs:
1. **The 10-Second Executive Scan:** High-level metrics, blast radius, business risk, and compliance deadlines.
2. **The 60-Second Engineer Triage:** Affected package/CPE, exact patched versions, temporary mitigations/firewall rules, and links to source advisories.

---

### 3.2 FIRST TLP 2.0 (Traffic Light Protocol) Header

Every security notification must state its distribution classification according to the **FIRST TLP 2.0** standard:

```
+--------------------------------------------------------------------------------------------------+
|  TLP:CLEAR        May be distributed freely across the Internet without restriction.             |
|  TLP:GREEN        Limited disclosure; share within community or organization.                    |
|  TLP:AMBER        Strictly need-to-know within the recipient organization.                       |
|  TLP:AMBER+STRICT Restricted exclusively to the recipient organization's internal team only.     |
|  TLP:RED          Restricted exclusively to named recipients present in the direct discussion.   |
+--------------------------------------------------------------------------------------------------+
```

Display a high-visibility badge at the very top of the email header (e.g., `TLP:CLEAR | PUBLIC SECURITY ADVISORY`).

---

### 3.3 The BLUF (Bottom Line Up Front) Information Architecture

Never bury the lead. Every flash alert and digest must lead with a structured BLUF container placed prominently above the fold:

* **What:** Summary of the vulnerability and attack vector in plain English.
* **Impacted Assets:** Exact technology stacks, container base images, operating systems, or cloud services.
* **Exploitation State:** Explicit indicator (e.g., `🔴 ACTIVE IN THE WILD (CISA KEV)`, `🟡 WEAPONIZED POC PUBLIC`, or `🟢 THEORETICAL / NO EXPLOIT`).
* **Required Action:** The exact command, patch version, or mitigating network rule.
* **Deadline:** Federal CISA BOD 22-01 date or enterprise SLA (e.g., "Critical SLAs require mitigation within 24 hours").

---

### 3.4 Email Types: Flash Alert vs. Daily Intelligence Digest

A dual-tier notification model must be enforced:

#### Archetype A: The Immediate Flash Alert (P0 / P1 Emergency)
* **Trigger Criteria:** Any item added to CISA KEV, any zero-day with verified in-the-wild exploitation, or any critical vulnerability (CVSS ≥ 9.0 with EPSS ≥ 0.20) matching your tech stack.
* **Volume:** Infrequent (1 to 3 times per week maximum).
* **Subject Line Standard:**
  `🚨 [URGENT P1] Active Exploit: <Product/Vendor> (<CVE-ID>) - Immediate Patch Required`
* **Layout:** Focused exclusively on the single threat (or small cluster). High-contrast urgent alert banner, affected asset list, and copy-paste remediation commands.

#### Archetype B: The Daily/Weekly Executive Digest
* **Trigger Criteria:** Scheduled run (e.g., daily at 08:00 AM recipient local time).
* **Volume:** Once per scheduled cycle.
* **Subject Line Standard:**
  `🛡️ Daily Threat Digest — 24 Oct 2026 | 3 Critical, 7 High Vulnerabilities Analyzed`
* **Layout:**
  1. **Executive Metric Bar:** Total threats analyzed, KEV counts, critical vs. high counts.
  2. **Priority Triage Matrix (Table):** A scannable 5-column table listing the top urgent threats.
  3. **Categorized Threat Sections:** Grouped logically by technology domains (Cloud Infrastructure, Web & Application Frameworks, Operating Systems, Networking & Hardware, AI & Machine Learning).
  4. **Direct Reference Links:** Footnotes linking back to NVD, vendor advisories, and the live threat portal.

---

### 3.5 The "Priority Triage Matrix" Table Specification

For daily digests, include a compact HTML table at the top of the body for instant triage:

| CVE ID | Impacted Component | Severity / Score | Exploit Status | Remediation Action |
| :--- | :--- | :---: | :---: | :--- |
| **CVE-2026-1849** | Palo Alto PAN-OS | **CRITICAL** (CVSS 9.8) | 🔥 **Active (KEV)** | Upgrade to Hotfix `11.1.2-h3` by Oct 26 |
| **CVE-2026-3091** | Next.js Server Actions | **HIGH** (CVSS 8.6) | ⚠️ **PoC Public** | Bump package to `15.0.4+` |
| **CVE-2026-2204** | OpenSSL 3.x | **MEDIUM** (CVSS 6.5) | 🟢 **No Exploit** | Rebuild base Docker images |

---

### 3.6 Delivery Architecture: In-Body Reporting vs. PDF Attachments (The "Best of Both Worlds" Solution)

A frequent architectural question arises when designing threat notifications:  
*“Should the email body contain only a high-level summary, with the full report attached as a PDF?”*

The industry answer depends strictly on the **target audience and operational context**:

```
+--------------------------------------------------------------------------------------------------+
|                                OPERATIONAL VS. EXECUTIVE PARADIGM                                |
|                                                                                                  |
|   OPERATIONAL / TACTICAL ALERTS                      STRATEGIC / EXECUTIVE REPORTING             |
|   (SOC, DevSecOps, SysAdmins, On-Call)               (CISO, Board of Directors, Audit Teams)     |
|   ------------------------------------               ---------------------------------------     |
|   * Needs: Speed, triage efficiency, copy-paste      * Needs: Formal synthesis, branding, print  |
|   * Format: Full In-Body HTML + Plain-Text           * Format: Summary Email + Formal PDF Report |
|   * Latency: Sub-minute critical delivery            * Cadence: Weekly / Monthly Rollup          |
|   * Delivery: NO ATTACHMENTS (Zero Sandboxing)       * Delivery: Portal Link / PDF on Demand     |
+--------------------------------------------------------------------------------------------------+
```

#### Why Raw PDF Attachments are an Anti-Pattern for Real-Time Threat Alerts

Attaching raw `.pdf` files to automated, real-time security alerts introduces four serious enterprise risks:

1. **Secure Email Gateway (SEG) Sandboxing Delays:**  
   Enterprise mail protection gateways (Proofpoint Enterprise Protection, Microsoft Defender for Office 365, Mimecast) subject all email attachments to automated virtual-machine sandboxing. This analysis cycle introduces a **3 to 15+ minute delivery delay**—unacceptable for P0 zero-day flash alerts where seconds count.
2. **The "Phishing Training" Conflict:**  
   Security awareness programs relentlessly train corporate employees: *"Never open automated or unsolicited PDF attachments claiming to be urgent security warnings."* Sending automated internal alert emails with attached PDFs encourages dangerous user habits and elevates IT helpdesk phishing reports.
3. **Friction in On-Call Incident Response:**  
   On-call engineers triaging alerts on smartphones or terminal environments need to instantly copy CVE identifiers, package names, and mitigation commands. Interacting with a multi-page PDF on mobile or attempting to copy formatted code blocks introduces unnecessary operational latency.
4. **SOAR & Ticketing Ingestion Breakage:**  
   Enterprise SecOps environments route alert emails directly into ticketing systems (ServiceNow, Jira) or SOAR engines (Splunk SOAR, Cortex XSOAR). Parsing text-based email bodies or structured JSON is native and resilient; extracting tabular data from binary PDF streams is error-prone.

#### When PDF Reporting IS the Industry Standard

A formal PDF report is the gold standard for **Strategic, Executive, and Compliance Intelligence**:
* **Board of Directors & CISO Briefings:** High-level threat summaries accompanied by a polished, multi-page PDF formatted for tablets, printing, and board presentation.
* **Audit & Compliance Artifacts:** Static, non-modifiable PDF documentation required for SOC 2, ISO 27001, or FedRAMP vulnerability tracking and SLA compliance audits.
* **Weekly/Monthly Retrospectives:** Rolling summaries of vulnerability trends, mean time to remediate (MTTR), and infrastructure exposure.

#### The Recommended "Best of Both Worlds" Architecture

Leading enterprise platforms (Mandiant, CrowdStrike Falcon, Recorded Future, CISA) combine the speed of in-body triage with the formality of PDF reports using a **decoupled portal architecture**:

```
[ Automated Ingestion Engine ]
              |
              +---> 1. DISPATCH EMAIL: High-level BLUF + Priority Triage Table (In-Body HTML)
              |     - Zero attachments (Bypasses SEG sandbox delays and spam filters)
              |     - 10-second instant triage for on-call engineers
              |
              +---> 2. DEEP LINK: "[ ↗ View Full Interactive Threat Portal & Export PDF ]"
                    - Links directly to the web portal (portal/index.html)
                    - Engineers filter, search, and copy CLI commands interactively
                    - Executives & auditors click "Export as PDF" to generate printable reports on demand
```

This decoupled model achieves:
* **Zero email delivery latency:** No heavy attachments to trigger spam quarantine or sandboxing bottlenecks.
* **Instant mobile triage:** All vital metadata (CVE, CVSS, EPSS, command, due date) remains visible in the email body.
* **On-demand executive artifacts:** High-fidelity, print-ready PDF export is available whenever required via the web portal.

---

## 4. HTML Email Engineering & Deliverability Standards

Developing HTML for email is notoriously distinct from modern web development. Security teams often read emails on legacy enterprise desktop clients (Microsoft Outlook using the Word 2016 rendering engine), modern mobile apps (iOS Mail, Android Gmail), and browser clients.

### 4.1 Cross-Client Rendering Hardening

To ensure visual consistency and prevent layout breakage:

* **Table-Based Hybrid Layouts:** Rely on nested HTML tables with inline styles for critical structural scaffolding. Avoid modern CSS Grid or complex Flexbox in emails, as Outlook desktop ignores them completely.
* **Explicit Pixel Widths:** Constrain the email container to a maximum width of `600px` to `680px`. This prevents horizontal scrolling on mobile viewports and avoids awkwardly stretched single-column text on 4K desktop displays.
* **Outlook MSO Conditional Comments:** Wrap main layout wrappers in conditional comments for Outlook:
  ```html
  <!--[if mso]>
  <table role="presentation" width="640" align="center" style="width:640px;">
  <tr><td>
  <![endif]-->
  ```

---

### 4.2 Dark Mode Resilience

Modern email clients (Apple Mail, Outlook for Mac/Windows, Gmail Android) apply automatic color inversion algorithms to HTML emails. Unprepared email designs suffer unreadable black-on-black text, washed-out badge colors, or invisible borders.

* **Include Modern Dark Mode Meta Tags:**
  ```html
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  ```
* **Use Media Queries with Explicit Fallbacks:**
  ```css
  @media (prefers-color-scheme: dark) {
      .email-bg { background-color: #0b0f19 !important; }
      .card-bg  { background-color: #1e293b !important; border-color: #334155 !important; }
      .text-primary { color: #f8fafc !important; }
      .text-muted   { color: #94a3b8 !important; }
  }
  ```
* **High Contrast Ratios (WCAG 2.1 AA):** Ensure text-to-background contrast exceeds `4.5:1` for regular text and `3:1` for bold badge labels across both light and dark backgrounds.

---

### 4.3 Inbox Preview Text (Preheader Optimization)

Email clients display a 40–100 character preview snippet in the recipient's inbox alongside the subject line. If omitted, clients pull the first available text (e.g., *"View in browser"* or legal disclaimers).

Inject a hidden preheader block directly after the opening `<body>` tag:

```html
<div style="display:none;font-size:1px;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;mso-hide:all;font-family:sans-serif;">
    CRITICAL: 2 zero-day vulnerabilities added to CISA KEV affecting PAN-OS and VMware. Patch before Oct 26.
    &#847; &zwnj; &nbsp; &#8199; &shy; <!-- Padding to prevent body text leaking into preview -->
</div>
```

---

### 4.4 Multi-Part MIME & ASCII Terminal Fallback (RFC 2046)

Never send an HTML-only email. Sending single-part HTML significantly elevates spam scores in enterprise mail gateways. Furthermore, many incident response engineers read security alerts through CLI email clients (Mutt, Alpine, NeoMutt) or automated webhook parsers.

Always dispatch `multipart/alternative` containing:
1. `text/plain`: A meticulously structured ASCII plain-text version with clear visual delimiters (`=====`, `-----`), bulleted markdown-style items, and fully expanded raw URLs.
2. `text/html`: The responsive, styled HTML document.

---

### 4.5 Deliverability & Enterprise Mail Gatekeeper Compliance

Enterprise security teams utilize stringent mail inspection gateways (Proofpoint Enterprise Protection, Microsoft Defender for Office 365, Mimecast). Threat alert emails that mention exploit tools, malware names, and CVE numbers are naturally scrutinized.

To guarantee inbox delivery without quarantine:

1. **SPF (Sender Policy Framework - RFC 7208):** Explicitly authorize the sending mail server or SMTP relay IP addresses in DNS.
2. **DKIM (DomainKeys Identified Mail - RFC 6376):** Cryptographically sign all outgoing alert emails with a 2048-bit key.
3. **DMARC (RFC 7489):** Publish a strict DMARC policy (`v=DMARC1; p=reject; pct=100; sp=reject; adkim=s; aspf=s`). Enterprise spam filters heavily penalize or reject domains configured with `p=none` or missing DMARC.
4. **BIMI with VMC (Brand Indicators for Message Identification):** Publish a verified BIMI DNS record with an official SVG logo authenticated by a Verified Mark Certificate (VMC). In Gmail and Apple Mail, this displays a verified security badge alongside the sender identity, mitigating internal phishing suspicion.
5. **Clean HTML-to-Text Ratio:** Avoid image-heavy newsletters. Keep image usage minimal (e.g., company logo or status icons only) and rely on clean typography and CSS styling.

---

## 5. End-to-End Implementation Checklist (Building from Scratch)

Use this step-by-step checklist to guide system construction:

```
[ ] STEP 1: SOURCING FOUNDATION
    [ ] 1.1 Ingest CISA KEV JSON (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
    [ ] 1.2 Ingest FIRST EPSS CSV/API (https://api.first.org/data/v1/epss)
    [ ] 1.3 Ingest GitHub Security Advisories API (GHSA / OSV) for package dependencies
    [ ] 1.4 Ingest NIST NVD 2.0 API with registered API key and rate-limiter
    [ ] 1.5 Implement HTTP Conditional GET (ETag / Last-Modified caching)

[ ] STEP 2: ASSIMILATION & DATA ENRICHMENT
    [ ] 2.1 Build canonical entity resolution engine (Key by CVE ID)
    [ ] 2.2 Classify vulnerabilities by technology stack (AWS, Linux, Node.js, Python, Docker, etc.)
    [ ] 2.3 Map CVEs to MITRE ATT&CK enterprise tactics and techniques
    [ ] 2.4 Compute Urgency Score: (is_cisa_kev OR (cvss >= 9.0 AND epss >= 0.15))
    [ ] 2.5 Persist seen state with deduplication to prevent repetitive alerting

[ ] STEP 3: EMAIL TEMPLATING & UX
    [ ] 3.1 Construct FIRST TLP 2.0 classification header banner
    [ ] 3.2 Implement BLUF executive summary container at top of layout
    [ ] 3.3 Create 5-column triage matrix table for scheduled digest
    [ ] 3.4 Build responsive, dark-mode-resilient threat cards (WCAG 2.1 AA compliant)
    [ ] 3.5 Inject invisible preheader preview text snippet

[ ] STEP 4: EMAIL ENGINEERING & DELIVERABILITY
    [ ] 4.1 Compile dual-engine templates: HTML (inline CSS) + Plain Text (ASCII)
    [ ] 4.2 Test rendering across Outlook Word Engine, Apple Mail, and Gmail
    [ ] 4.3 Configure sending domain with SPF, DKIM (2048-bit), and DMARC (p=reject)
    [ ] 4.4 Validate spam score with tools like Mail-Tester / MXToolbox
    [ ] 4.5 Set up automated bounce and delivery failure telemetry
```

---

## 6. Authoritative Industry Standards & References

### Threat Intelligence & Vulnerability Taxonomies
* **CISA Known Exploited Vulnerabilities (KEV) Catalog & BOD 22-01:**  
  [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)  
  *Binding Operational Directive 22-01 driving federal remediation deadlines.*
* **FIRST TLP 2.0 (Traffic Light Protocol Standard):**  
  [https://www.first.org/tlp/](https://www.first.org/tlp/)  
  *The international standard for information sharing classification (CLEAR, GREEN, AMBER, AMBER+STRICT, RED).*
* **FIRST EPSS (Exploit Prediction Scoring System):**  
  [https://www.first.org/epss/](https://www.first.org/epss/)  
  *Data-driven statistical framework predicting real-world exploitation probability.*
* **OASIS CSAF 2.0 (Common Security Advisory Framework):**  
  [https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)  
  *Global JSON standard for machine-readable security advisories and VEX documents.*
* **NIST National Vulnerability Database (NVD 2.0 API):**  
  [https://nvd.nist.gov/developers/vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities)  
  *Official specification for querying CVE and CPE vulnerability records.*
* **MITRE ATT&CK Framework:**  
  [https://attack.mitre.org/](https://attack.mitre.org/)  
  *Curated knowledge base of adversary tactics and techniques.*
* **US Army FM 2-22.3 / NATO Intelligence Admiralty System:**  
  [https://irp.fas.org/doddir/army/fm2-22-3.pdf](https://irp.fas.org/doddir/army/fm2-22-3.pdf)  
  *Standards for source reliability and information credibility grading.*

### Email Engineering & Deliverability Standards
* **RFC 5322 (Internet Message Format) & RFC 2046 (MIME Multipart):**  
  [https://datatracker.ietf.org/doc/html/rfc5322](https://datatracker.ietf.org/doc/html/rfc5322) | [https://datatracker.ietf.org/doc/html/rfc2046](https://datatracker.ietf.org/doc/html/rfc2046)  
  *Foundational IETF standards for email structure and multi-part MIME encoding.*
* **DMARC RFC 7489 (Domain-based Message Authentication, Reporting, and Conformance):**  
  [https://datatracker.ietf.org/doc/html/rfc7489](https://datatracker.ietf.org/doc/html/rfc7489)  
  *Policy specification preventing domain spoofing and ensuring enterprise inbox placement.*
* **BIMI Group (Brand Indicators for Message Identification):**  
  [https://bimigroup.org/](https://bimigroup.org/)  
  *Standards for authenticated sender visual indicators in Apple Mail and Gmail.*
* **Can I Email (Cross-Client CSS & HTML Support Table):**  
  [https://www.caniemail.com/](https://www.caniemail.com/)  
  *Definitive compatibility index for HTML/CSS features across major email clients.*
* **Web Content Accessibility Guidelines (WCAG 2.1 AA):**  
  [https://www.w3.org/WAI/WCAG21/quickref/](https://www.w3.org/WAI/WCAG21/quickref/)  
  *Standard guidelines for color contrast, readability, and accessible typography.*
