from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from src.engine.state_manager import StateManager


class TestStateManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.temp_dir.name) / "test_seen.json"
        self.mgr = StateManager(state_file=self.state_file, retention_days=30)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_filter_and_save_state(self):
        state = self.mgr.load_state()
        self.assertEqual(len(state.get("seen", {})), 0)

        threats = [
            {"cve_id": "CVE-2026-1111", "title": "Threat 1", "severity": "HIGH"},
            {"cve_id": "CVE-2026-2222", "title": "Threat 2", "severity": "CRITICAL"}
        ]

        new_items, existing = self.mgr.filter_new_threats(threats, state)
        self.assertEqual(len(new_items), 2)
        self.assertEqual(len(existing), 0)

        self.mgr.save_state(state)
        self.assertTrue(self.state_file.exists())

        # Second run with same items -> should be recognized as existing
        state_2 = self.mgr.load_state()
        new_items_2, existing_2 = self.mgr.filter_new_threats(threats, state_2)
        self.assertEqual(len(new_items_2), 0)
        self.assertEqual(len(existing_2), 2)


if __name__ == "__main__":
    unittest.main()
