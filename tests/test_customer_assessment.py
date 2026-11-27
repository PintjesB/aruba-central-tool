import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from test_consolidation import fixture


class CustomerAssessmentTests(unittest.TestCase):
    def test_report_contains_aggregate_counts_not_raw_device_names(self):
        bundle = fixture()
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["name"] = "private-device-marker"
        bundle["collection_checkpoint"] = {"mixed_capture_times": True}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.assessment({"snapshot": name, "mode": "customer-report"})
            self.assertIn("Network configuration assessment", html)
            self.assertIn("Evidence gaps and validation", html)
            self.assertIn("Print / save PDF", html)
            self.assertIn("Evidence limitation", html)
            self.assertIn("@media print", html)
            self.assertNotIn("private-device-marker", html)
            self.assertIn("Open customer assessment report", workspace.assessment({"snapshot": name}))
