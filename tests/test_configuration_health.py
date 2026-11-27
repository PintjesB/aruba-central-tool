import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.configuration_health import configuration_health
from aruba_central.config_app import Workspace
from test_consolidation import fixture


class ConfigurationHealthTests(unittest.TestCase):
    def test_unknown_membership_stays_separate_and_rollup_preserves_counts(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        entry["scopes"][2]["metadata"] = {"siteId": 2}
        sites = configuration_health(bundle, group_by="site")
        devices = configuration_health(bundle, group_by="device")
        self.assertEqual(sum(r["devices"] for r in sites), len(devices))
        self.assertEqual(sum(r["devices"] for r in sites if r["membership_unknown"]), 2)
        for key in ("expected_views", "parsed_views", "local_definitions", "global_matches"):
            self.assertEqual(sum(r["counts"].get(key, 0) for r in sites), sum(r["counts"].get(key, 0) for r in devices))
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).assessment({"snapshot": name, "mode": "health", "group_by": "site"})
            self.assertIn("Membership not established", html)
            self.assertIn("Unparsed views", html)
            self.assertIn("not a health score", html)

    def test_drilldown_only_shows_selected_members(self):
        bundle = fixture()
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["metadata"] = {"siteId": 2}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            query = {"snapshot": name, "mode": "health", "persona": "ACCESS_SWITCH", "group_by": "device", "parent_kind": "site"}
            html = workspace.assessment({**query, "drill": "scope:2"})
            self.assertIn("Devices in Site", html)
            self.assertIn("device=3", html)
            self.assertNotIn("device=4", html)
            html = workspace.assessment({**query, "drill": "unknown"})
            self.assertNotIn("device=3", html)
            self.assertIn("device=4", html)
            with self.assertRaises(ValueError):
                workspace.assessment({**query, "drill": "scope:999"})
