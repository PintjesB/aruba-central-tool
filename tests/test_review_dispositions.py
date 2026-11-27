import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from aruba_central.optimization_worklist import optimization_worklist
from aruba_central.review_dispositions import snapshot_binding, finding_key, read_disposition, update_disposition
from test_consolidation import fixture


class ReviewDispositionTests(unittest.TestCase):
    def test_disposition_survives_restart_but_not_snapshot_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            rows = optimization_worklist(bundle, profile_recommendations(bundle), workspace.advanced_snapshot(bundle))
            key = finding_key(snapshot_binding(workspace, name, bundle), rows[0])
            self.assertEqual(read_disposition(directory, key)["state"], "open")
            update_disposition(workspace, name, key, "intentional", "Retain this exception")
            reopened = Workspace(directory)
            self.assertEqual(read_disposition(directory, key)["state"], "intentional")
            html = reopened.assessment({"snapshot": name, "state": "intentional"})
            self.assertIn("Retain this exception", html)
            self.assertIn("Set status", html)
            self.assertFalse(read_disposition(directory, key)["safe_to_apply"])
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                update_disposition(reopened, name, key, "reviewed", "")
            new_bundle = reopened.reviewed_snapshot(name)
            new_key = finding_key(snapshot_binding(reopened, name, new_bundle), rows[0])
            self.assertNotEqual(new_key, key)
            self.assertEqual(read_disposition(directory, new_key)["state"], "open")
            with self.assertRaises(ValueError):
                read_disposition(directory, "../invalid")
