import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from test_consolidation import fixture


class NACPayloadTests(unittest.TestCase):
    def test_private_details_and_report_are_not_embedded_in_overview(self):
        bundle = fixture()
        bundle["nac_registrations"] = {"status": "response_received", "rows": [
            {"id": "a", "macAddress": "00:00:00:00:00:01", "customEvidence": "private-a" * 100},
            {"id": "b", "macAddress": "00:00:00:00:00:02", "customEvidence": "private-b" * 100}]}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            binding = snapshot_binding(workspace, name, workspace.reviewed_snapshot(name))
            overview = workspace.nac({"snapshot": name})
            self.assertIn("Review registration", overview)
            self.assertNotIn("private-a", overview)
            self.assertNotIn("private-b", overview)
            self.assertNotIn("data-private-report=", overview)
            q = {"snapshot": name, "binding": binding}
            detail = workspace.nac({**q, "registration": "0"})
            self.assertIn("private-a", detail)
            self.assertNotIn("private-b", detail)
            exported = workspace.nac({**q, "export": "1"})
            self.assertIn("data-private-report=", exported)
            self.assertIn("private-a", exported)
            self.assertIn("private-b", exported)
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                workspace.nac({**q, "registration": "0"})
