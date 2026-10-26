from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "config"
DATA_DIR = ROOT_DIR / "data"

# Automatically load .env file if present locally (without requiring python-dotenv)
ENV_FILE = ROOT_DIR / ".env"
if ENV_FILE.exists():
    try:
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass

SOURCES_FILE = CONFIG_DIR / "sources.json"
TAXONOMY_FILE = CONFIG_DIR / "taxonomy.json"
STATE_FILE = DATA_DIR / "seen.json"

DEFAULT_SOURCES = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "github_advisories": "https://api.github.com/advisories",
    "nvd_cves": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "epss": "https://api.first.org/data/v1/epss",
    "aws_security_bulletins": "https://aws.amazon.com/security/security-bulletins/rss/"
}


def load_sources() -> dict[str, str]:
    if SOURCES_FILE.exists():
        try:
            return json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return DEFAULT_SOURCES


def load_taxonomy() -> dict[str, Any]:
    if TAXONOMY_FILE.exists():
        try:
            return json.loads(TAXONOMY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"categories": {}, "technology_aliases": {}}


USER_AGENT = "CyberThreatMonitor/1.0 (Enterprise Proactive Threat Intelligence Pipeline)"
HTTP_TIMEOUT_SECONDS = int(os.getenv("HTTP_TIMEOUT_SECONDS", "25"))
DEFAULT_URGENT_CVSS_THRESHOLD = float(os.getenv("URGENT_CVSS_THRESHOLD", "9.0"))
DEFAULT_RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "45"))
