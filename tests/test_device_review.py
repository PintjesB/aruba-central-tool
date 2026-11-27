import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.device_review import device_review
from test_consolidation import fixture


class DeviceReviewTests(unittest.TestCase):
    def test_device_hub_preserves_membership_and_module_evidence(self):
        bundle = fixture()
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["metadata"] = {"siteId": 2}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            report = device_review(reviewed, "ACCESS_SWITCH", "3")
            self.assertEqual(report["membership"]["site"]["id"], "2")
            self.assertFalse(report["safe_to_apply"])
            self.assertTrue(report["modules"])
            html = workspace.scopes({"snapshot": name, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"})
            self.assertIn("Device review actions", html)
            self.assertIn("Configuration by module", html)
            self.assertIn("device=3", html)
            self.assertIn("scope=2", html)
            self.assertIn("Review device", workspace.scopes({"snapshot": name}))
            with self.assertRaises(ValueError):
                device_review(reviewed, "ACCESS_SWITCH", "2")
