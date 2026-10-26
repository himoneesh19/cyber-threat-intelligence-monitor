# Global Cyber Threat Intelligence Monitor & Portal

An automated, proactive cybersecurity threat intelligence pipeline running on **GitHub Actions (100% Free Tier)**. It monitors authoritative official security feeds, assimilates multi-source telemetry, classifies vulnerabilities by technology and category, pushes prioritized email alerts, and hosts a live, searchable web portal on **GitHub Pages**.

---

## 🛡️ Key Features

- **Multi-Source Official Feeds**:
  - **CISA KEV Catalog**: Confirmed in-the-wild active exploits with federal remediation deadlines.
  - **GitHub Security Advisories (GHSA)**: Real-time supply-chain zero-days and package ecosystem advisories (npm, PyPI, Go, Packagist, Maven, NuGet, etc.).
  - **NIST NVD 2.0 API**: Universal CVE registry with CVSS v3.1/v4.0 scoring and exponential backoff retry.
  - **FIRST.org EPSS**: Exploit Prediction Scoring System probability scores (0.0% to 100.0%).
- **Canonical Entity Resolution**: Merges duplicate records across CISA, NVD, and GHSA into unified canonical CVE entities.
- **Technology & Category Taxonomy Engine**: Automatically tags threats into standard categories (*Cloud & Infrastructure, Web Frameworks, Databases, OS, Networking, AI & LLMs, Enterprise*) and specific technologies (*AWS, Next.js, React, Node.js, PHP, PostgreSQL, Docker, Linux, Python*).
- **Two-Tier Push Alerting (Gmail SMTP)**:
  - **Immediate Flash Alerts**: Sent within 30 minutes for new CISA KEV additions or CVSS ≥ 9.0 vulnerabilities.
  - **Daily Threat Digest**: Consolidated executive briefing delivered at 09:00 AM IST.
- **Zero-Cost Web Portal (GitHub Pages)**:
  - Searchable by CVE ID, product, vendor, or keywords.
  - Filter by category and technology chips.
  - Interactive **Audit Status Checklist** (persisted in browser `localStorage`).
  - Direct JSON feed export (`threats.json`).
- **Production-Grade Resiliency**:
  - Conditional commits: Only commits when real threats appear to avoid Git history bloat.
  - `[skip ci]` tags to prevent recursive CI loops.
  - Dead-man switch: Sends an emergency email notification if the workflow encounters an unhandled failure.

---

## 🚀 Quickstart & Setup (Under 5 Minutes)

### Step 1: Create a GitHub Repository
1. Create a new repository on [GitHub](https://github.com/) (e.g. `global-security-monitor`).
   - *Public*: Unlimited free GitHub Actions minutes.
   - *Private*: 2,000 free minutes/month (this workflow uses ~1,080 minutes/month).
2. Push this codebase to your repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Cyber Threat Monitor"
   git branch -M main
   git remote add origin https://github.com/<YOUR-USERNAME>/<YOUR-REPO-NAME>.git
   git push -u origin main
   ```

### Step 2: Configure GitHub Secrets
Open your GitHub repository and go to **Settings → Secrets and variables → Actions → New repository secret**.

Add the following three secrets:

| Secret Name | Value | Description |
| :--- | :--- | :--- |
| `SMTP_USERNAME` | `your-email@gmail.com` | Your Gmail address (sender) |
| `SMTP_APP_PASSWORD` | `xxxx xxxx xxxx xxxx` | 16-character [Google App Password](https://myaccount.google.com/apppasswords) |
| `ALERT_EMAIL` | `your-inbox@gmail.com` | Destination inbox (can be same or multiple comma-separated) |
| `NVD_API_KEY` | *(Optional)* | [NIST NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) for 10x higher rate limits |

> [!IMPORTANT]
> Use a **Google App Password**, not your regular Gmail account password. You must have 2-Step Verification enabled on your Google account to generate one.

### Step 3: Enable GitHub Pages (Web Portal)
1. In your GitHub repository, open **Settings → Pages**.
2. Under **Build and deployment → Branch**:
   - Select branch: `main`
   - Select folder: `/docs`
3. Click **Save**.
4. Your live dashboard will be accessible at:
   `https://<YOUR-USERNAME>.github.io/<YOUR-REPO-NAME>/`

### Step 4: Enable Workflow Permissions
1. In **Settings → Actions → General → Workflow permissions**.
2. Select **Read and write permissions** (required to update `data/seen.json` and `docs/portal/data/threats.json`).
3. Click **Save**.

---

## ⏸️ Pausing / Unpausing the Automated Schedule

If you want to store code on GitHub without running background scans or sending emails:

- **To Pause Automated Monitoring**: In [.github/workflows/security-monitor.yml](.github/workflows/security-monitor.yml), comment out the `schedule` trigger:
  ```yaml
  on:
    # schedule:
    #   - cron: "0,30 * * * *"
    workflow_dispatch:
  ```
  *(Alternatively, in GitHub: open **Actions** tab → click **Global Security Monitor** → click `...` → **Disable workflow**).*

- **To Unpause / Activate**: Uncomment the `schedule` lines and push to `main` (or click **Enable workflow** in the GitHub Actions tab).

---

## 💻 Local Testing & Diagnostic Commands

Test the ingestion and classification engine locally on your machine anytime:

```bash
# Run full ingestion in dry-run mode (does not send emails or modify state)
python3 src/main.py --dry-run

# Run only CISA KEV and GitHub Advisories (fastest test)
python3 src/main.py --dry-run --sources cisa github --skip-epss

# Test email templates and daily digest generation
python3 src/main.py --dry-run --force-digest

# Run all unit tests
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 📁 Repository Structure

```text
.
├── .github/
│   └── workflows/
│       └── security-monitor.yml   # 30-min scheduled runner & failure notifier
├── config/
│   ├── sources.json               # Feed endpoints (CISA, NVD, GHSA, EPSS)
│   └── taxonomy.json              # Keyword detection & category mappings
├── data/
│   └── seen.json                  # Deduplication state history
├── docs/
│   ├── implementation_plan.md     # Architectural plan & gap analysis
│   ├── index.html                 # GitHub Pages entry redirect
│   ├── portal/                    # [Distribution] Generated build served live on GitHub Pages
│   │   ├── index.html
│   │   ├── style.css
│   │   ├── app.js
│   │   └── data/threats.json      # Dynamic threat database generated by pipeline
│   ├── sample_daily_digest.html   # Email digest preview
│   └── sample_urgent_alert.html   # Flash alert email preview
├── portal/                        # [Source] Frontend source code (edit your UI/CSS/JS here)
├── src/
│   ├── collectors/                # Ingestion modules (CISA, NVD, GHSA, EPSS)
│   ├── engine/                    # Classifier, Assimilator, StateManager
│   ├── notifiers/                 # HTML templates & SMTP transport
│   ├── portal/                    # Portal compiler
│   ├── config.py                  # Shared constants
│   └── main.py                    # Orchestrator entrypoint
├── tests/                         # Unit tests
└── requirements.txt
```

---

## 📄 License
MIT License. Free for personal and commercial cybersecurity operations.
