import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from aruba_central.optimization_worklist import optimization_worklist, engineering_group_id
from test_consolidation import fixture


class OptimizationWorklistTests(unittest.TestCase):
    def test_worklist_preserves_exact_finding_identity_and_explicit_units(self):
        bundle = fixture()
        findings = profile_recommendations(bundle)
        port_group = {"persona": "ACCESS_SWITCH", "ports": [{"scope": "3", "port": "1/1/1"}, {"scope": "4", "port": "1/1/2"}]}
        duplicate_group = {"module": "dns", "identities": ["A", "B"], "usage": {
            "A": {"shared_devices": [{"persona": "ACCESS_SWITCH", "scope": "3"}], "unknown_devices": []},
            "B": {"shared_devices": [{"persona": "ACCESS_SWITCH", "scope": "3"}], "unknown_devices": []}}}
        rows = optimization_worklist(bundle, findings, {"port_groups": [port_group], "library_duplicates": [duplicate_group]})
        by_category = {row["category"]: row for row in rows}
        self.assertEqual(by_category["remove_override"]["next_step"], "Evidence blocks preview")
        self.assertEqual(by_category["promote_local"]["instances"], 2)
        self.assertEqual(by_category["ports"]["known"], 2)
        self.assertIsNone(by_category["ports"]["unknown"])
        self.assertEqual(by_category["duplicates"]["known"], 1)
        self.assertEqual(by_category["duplicates"]["unit"], "Library names")
        self.assertEqual(by_category["ports"]["params"]["group"], engineering_group_id("ports", port_group))
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.assessment({"snapshot": name})
            self.assertIn("Prioritized optimization worklist", html)
            self.assertIn("Review finding", html)
            reviewed = workspace.reviewed_snapshot(name)
            finding = next(f for f in profile_recommendations(reviewed) if f["action"] == "promote_local")
            advisor = workspace.advisor({"snapshot": name, "group": finding["id"], "finding": "promote_local"})
            self.assertEqual(advisor.count('data-action="promote_local"'), 1)
            self.assertNotIn('data-action="remove_override"', advisor)


    def test_reduction_scenarios_are_conditional_and_exclude_ports(self):
        from aruba_central.optimization_worklist import reduction_scenario
        def estimate(category, instances=4, next_step="Inspect change preview"):
            return reduction_scenario({"category": category, "instances": instances, "next_step": next_step})
        self.assertEqual(estimate("remove_override")["count"], 4)
        self.assertIsNone(estimate("remove_override", next_step="Evidence blocks preview")["count"])
        self.assertEqual(estimate("promote_local")["count"], 3)
        self.assertEqual(estimate("reuse_library")["count"], 4)
        self.assertEqual(estimate("duplicates")["count"], 3)
        self.assertEqual(estimate("duplicates")["unit"], "Library names")
        self.assertIsNone(estimate("ports")["count"])
