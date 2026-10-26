from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from src.config import DATA_DIR, DEFAULT_RETENTION_DAYS, STATE_FILE

logger = logging.getLogger(__name__)


class StateManager:
    """
    Manages deduplication state in data/seen.json.
    Ensures safe loading, atomic saves with backups, and rolling retention purging.
    """

    def __init__(self, state_file: Path = STATE_FILE, retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        self.state_file = state_file
        self.retention_days = retention_days
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    def load_state(self) -> dict[str, Any]:
        """Loads state dictionary with fallback to backup on error."""
        if not self.state_file.exists():
            return {"seen": {}, "last_run_utc": None}

        try:
            content = self.state_file.read_text(encoding="utf-8")
            data = json.loads(content)
            if isinstance(data, dict) and "seen" in data:
                return data
        except Exception as exc:
            logger.warning("Failed parsing state file (%s), attempting backup...", exc)
            bak_file = self.state_file.with_suffix(".json.bak")
            if bak_file.exists():
                try:
                    return json.loads(bak_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

        return {"seen": {}, "last_run_utc": None}

    def save_state(self, state: dict[str, Any]) -> None:
        """Atomically saves state and prunes entries older than retention window."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.retention_days)

        seen = state.get("seen", {})
        pruned_seen: dict[str, Any] = {}

        for k, v in seen.items():
            first_seen_str = v.get("first_seen_utc")
            if first_seen_str:
                try:
                    dt = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00")).astimezone(timezone.utc)
                    if dt < cutoff:
                        continue
                except Exception:
                    pass
            pruned_seen[k] = v

        state["seen"] = pruned_seen
        state["last_run_utc"] = now.isoformat()

        # Atomic write
        tmp_file = self.state_file.with_suffix(".json.tmp")
        bak_file = self.state_file.with_suffix(".json.bak")

        try:
            tmp_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if self.state_file.exists():
                self.state_file.replace(bak_file)
            tmp_file.replace(self.state_file)
            logger.info("Saved deduplication state (%d tracked threats)", len(pruned_seen))
        except Exception as exc:
            logger.error("Failed saving state: %s", exc)

    def filter_new_threats(
        self,
        assimilated_threats: list[dict[str, Any]],
        state: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Deduplicates against seen history.
        Returns (new_threats, already_seen_threats).
        """
        seen = state.setdefault("seen", {})
        now_iso = datetime.now(timezone.utc).isoformat()

        new_threats: list[dict[str, Any]] = []
        existing_threats: list[dict[str, Any]] = []

        for threat in assimilated_threats:
            key = threat["cve_id"]
            if key not in seen:
                # Newly discovered threat
                threat["first_seen_utc"] = now_iso
                seen[key] = {
                    "first_seen_utc": now_iso,
                    "title": threat.get("title", "")[:200],
                    "severity": threat.get("severity"),
                    "category": threat.get("category"),
                    "technologies": threat.get("technologies", [])
                }
                new_threats.append(threat)
            else:
                existing_threats.append(threat)

        return new_threats, existing_threats
