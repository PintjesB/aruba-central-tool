import unittest
import tempfile
import json
from pathlib import Path
from assessment_review import assessment
from test_consolidation import fixture


class AssessmentTests(unittest.TestCase):
    def test_worklists_and_coverage(self):
        data = fixture()
        report = assessment(data)
        self.assertGreater(report["device_function_pairs"], 0)
        self.assertGreater(report["coverage"]["expected"], 0)
        self.assertGreaterEqual(report["coverage"]["expected"], report["coverage"]["parsed"])
        self.assertEqual(report["consolidation"]["groups"], sum(report["actions"].get(k, 0) for k in ("remove_override", "promote_local", "reuse_library")))
        self.assertFalse(report["safe_to_apply"])
        self.assertFalse(report["complete"])

    def test_workspace_links_and_report(self):
        from config_app import Workspace
        with tempfile.TemporaryDirectory() as tmp:
            name = "config-audit-test.json"
            (Path(tmp) / name).write_text(json.dumps(fixture()))
            html = Workspace(tmp).assessment({"snapshot": name})
            for label in ("Evidence to resolve", "Optimization opportunities", "Export private report JSON", "Open worklist"):
                self.assertIn(label, html)
