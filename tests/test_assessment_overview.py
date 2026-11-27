import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding, finding_key, update_disposition
from aruba_central.assessment_overview import review_overview
from test_consolidation import fixture


class AssessmentOverviewTests(unittest.TestCase):
    def test_status_counts_and_category_links_follow_actual_dispositions(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            rows = workspace.optimization_worklist(bundle)
            key = finding_key(snapshot_binding(workspace, name, bundle), rows[0])
            update_disposition(workspace, name, key, "investigate", "Check source")
            html = workspace.assessment({"snapshot": name})
            self.assertIn("Review workload", html)
            self.assertIn("state=investigate#optimization-worklist", html)
            self.assertIn("category=remove_override#optimization-worklist", html)
            self.assertIn("Check source", html)
            self.assertIn("preview blocked", html)
            filtered = workspace.assessment({"snapshot": name, "state": "investigate"})
            self.assertEqual(filtered.count('data-bulk-key="'), 1)
            self.assertIn('aria-current="true"', filtered)

    def test_status_summary_does_not_confuse_blocked_with_review_state(self):
        row = {"category": "remove_override", "next_step": "Evidence blocks preview"}
        result = review_overview([(row, "unused", {"state": "reviewed"})])
        self.assertEqual(result["states"], {"reviewed": 1})
        self.assertEqual(result["categories"]["remove_override"], {"total": 1, "reviewed": 1, "blocked": 1})
