import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.optimization_worklist import optimization_worklist
from aruba_central.review_dispositions import finding_key, snapshot_binding, update_disposition
from test_consolidation import fixture


class WorklistCacheTests(unittest.TestCase):
    def test_cached_rows_preserve_current_dispositions_and_snapshot_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            with patch("aruba_central.optimization_worklist.optimization_worklist", wraps=optimization_worklist) as compute:
                rows = workspace.optimization_worklist(bundle)
                self.assertTrue(rows)
                before = json.dumps(rows, sort_keys=True)
                key = finding_key(snapshot_binding(workspace, name, bundle), rows[0])
                update_disposition(workspace, name, key, "deferred", "Local review note")
                html = workspace.assessment({"snapshot": name, "state": "deferred"})
                self.assertIn("Local review note", html)
                self.assertEqual(compute.call_count, 1)
                self.assertEqual(json.dumps(rows, sort_keys=True), before)
                path.write_text(path.read_text() + " ")
                new_bundle = workspace.reviewed_snapshot(name)
                fresh = workspace.optimization_worklist(new_bundle)
                self.assertIsNot(fresh, rows)
                self.assertNotEqual(finding_key(snapshot_binding(workspace, name, new_bundle), fresh[0]), key)
                workspace.optimization_worklist(bundle)
                self.assertIs(workspace.optimization_worklist(new_bundle), fresh)
                self.assertEqual(compute.call_count, 3)
