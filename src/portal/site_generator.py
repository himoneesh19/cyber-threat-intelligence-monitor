from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR

logger = logging.getLogger(__name__)

PORTAL_SRC_DIR = ROOT_DIR / "portal"
PORTAL_OUTPUT_DIR = ROOT_DIR / "docs" / "portal"
DATA_OUTPUT_DIR = PORTAL_OUTPUT_DIR / "data"


def generate_portal(
    threats: list[dict[str, Any]],
    output_dir: Path = PORTAL_OUTPUT_DIR
) -> Path:
    """
    Compiles and exports the static Web Portal for GitHub Pages.
    Generates data/threats.json and copies HTML/CSS/JS assets.
    """
    out_dir = Path(output_dir)
    data_dir = out_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Export threats.json
    threats_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_threats": len(threats),
        "threats": threats
    }
    threats_json_path = data_dir / "threats.json"
    threats_json_path.write_text(json.dumps(threats_payload, indent=2) + "\n", encoding="utf-8")
    logger.info("Exported %d threats to %s", len(threats), threats_json_path)

    # 2. Copy portal assets if source exists
    if PORTAL_SRC_DIR.exists():
        for asset in ("index.html", "style.css", "app.js"):
            src_file = PORTAL_SRC_DIR / asset
            if src_file.exists():
                shutil.copy2(src_file, out_dir / asset)

        logger.info("Copied web portal assets to %s", out_dir)

    # 3. Create a root docs/index.html redirect if needed
    docs_root = ROOT_DIR / "docs"
    docs_index = docs_root / "index.html"
    if not docs_index.exists():
        # Redirect docs/index.html -> portal/
        docs_index.write_text("""<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; url=portal/">
    <title>Global Threat Monitor</title>
</head>
<body>
    <p>Redirecting to <a href="portal/">Cyber Threat Intelligence Portal</a>...</p>
</body>
</html>
""", encoding="utf-8")

    return out_dir
