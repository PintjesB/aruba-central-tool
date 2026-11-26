import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from compliance_trends import historical_approvals, compliance_trends
from local_standards import create_standard
from test_configuration_history import snapshot


class TrendTests(unittest.TestCase):
    def test_approvals_only_at_capture_time(self):
        approval = {"id": "a", "standard": "s", "candidate": "c",
                    "created_at": "2026-01-02T00:00:00+00:00", "expiry": "2026-01-10"}
        revoke = {"exception": "a", "standard": "s", "created_at": "2026-01-05T00:00:00+00:00"}
        def at(day, revocations):
            return historical_approvals([approval], revocations, "s", {"c": {}},
                                        datetime(2026, 1, day, tzinfo=timezone.utc))
        self.assertFalse(at(1, [revoke]))
        self.assertEqual(at(3, [revoke]), {"c": [approval]})
        self.assertFalse(at(6, [revoke]))
        self.assertFalse(at(11, []))

    def test_frozen_standard_across_captures_and_timestamp_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            base, current = snapshot(), snapshot("Changed")
            base["captured_at"] = "2026-01-01T12:00:00+00:00"
            current["captured_at"] = "2026-01-02T12:00:00+00:00"
            names = ["config-audit-base.json", "config-audit-current.json", "config-audit-unknown.json"]
            for name, data in zip(names, (base, current, snapshot())):
                (directory / name).write_text(json.dumps(data))
            standard = create_standard(directory, name="Test", snapshot=names[1],
                                       baseline_name=names[0], persona="ACCESS_SWITCH",
                                       reference="3", module="all", target="2", confirmed=True)
            result = compliance_trends(directory, standard, list(reversed(names)), confirmed=True)
            self.assertEqual([v["snapshot"] for v in result["entries"]], names[:2])
            self.assertEqual(result["entries"][0]["counts"]["matches_reference"], 2)
            self.assertEqual(result["entries"][1]["counts"]["differences_observed"], 1)
            self.assertEqual(result["skipped"][0]["snapshot"], names[2])
            self.assertFalse(result["safe_to_apply"])
            from config_app import Workspace
            html = Workspace(directory).trends({"snapshot": names[1], "standard": standard["id"], "confirmed": "yes"})
            self.assertIn("Historical compliance observations", html)
            self.assertIn("Skipped snapshots", html)
