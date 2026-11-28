import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.override_view import device_override_rows
from aruba_central.review_dispositions import snapshot_binding
from test_consolidation import fixture


class LazyOverrideTests(unittest.TestCase):
    def test_exact_override_evidence_not_embedded_in_worklist(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            findings, _ = device_override_rows(bundle, "ACCESS_SWITCH")
            row = findings[0]
            overview = workspace.overrides({"snapshot": name, "result": "all"})
            self.assertIn("data-inspect-url=", overview)
            self.assertNotIn("Expected fallback after removing device-local copy", overview)
            q = {"snapshot": name, "persona": "ACCESS_SWITCH", "device": row["device"],
                 "module": row["module"], "identity": row["identity"], "detail": "1",
                 "binding": snapshot_binding(workspace, name, bundle)}
            html = workspace.overrides(q)
            self.assertIn("template data-advisor-evidence", html)
            self.assertIn("Expected fallback after removing device-local copy", html)
            self.assertIn("Trace configuration source", html)
            with self.assertRaises(ValueError):
                workspace.overrides({**q, "identity": "not-observed"})
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                workspace.overrides(q)
