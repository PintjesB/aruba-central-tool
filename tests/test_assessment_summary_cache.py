import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.assessment_review import assessment
from test_consolidation import fixture


class AssessmentSummaryCacheTests(unittest.TestCase):
    def test_same_capture_reuses_aggregate_but_not_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            with patch("aruba_central.assessment_review.assessment", wraps=assessment) as compute:
                report = workspace.assessment_snapshot(bundle)
                expected = json.dumps(report, sort_keys=True)
                workspace.assessment({"snapshot": name})
                workspace.assessment({"snapshot": name, "mode": "customer-report"})
                self.assertEqual(compute.call_count, 1)
                self.assertEqual(json.dumps(report, sort_keys=True), expected)
                path.write_text(path.read_text() + " ")
                new_bundle = workspace.reviewed_snapshot(name)
                new_report = workspace.assessment_snapshot(new_bundle)
                self.assertIsNot(new_report, report)
                self.assertEqual(compute.call_count, 2)
                workspace.assessment_snapshot(bundle)
                self.assertIs(workspace.assessment_snapshot(new_bundle), new_report)
                self.assertEqual(compute.call_count, 3)
