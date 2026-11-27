import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from test_consolidation import fixture


class ConsolidationCacheTests(unittest.TestCase):
    def test_reuses_recommendations_across_views_without_mutating_base_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            with patch("aruba_central.consolidation.profile_recommendations", wraps=profile_recommendations) as compute:
                findings = workspace.consolidation_snapshot(bundle)
                expected = json.dumps(findings, sort_keys=True)
                workspace.advisor({"snapshot": name})
                workspace.assessment({"snapshot": name})
                workspace.assessment({"snapshot": name, "mode": "customer-report"})
                self.assertEqual(compute.call_count, 1)
                self.assertEqual(json.dumps(findings, sort_keys=True), expected)
                path.write_text(path.read_text() + " ")
                new_bundle = workspace.reviewed_snapshot(name)
                new_findings = workspace.consolidation_snapshot(new_bundle)
                self.assertIsNot(new_findings, findings)
                self.assertEqual(compute.call_count, 2)
                workspace.consolidation_snapshot(bundle)
                self.assertIs(workspace.consolidation_snapshot(new_bundle), new_findings)
                self.assertEqual(compute.call_count, 3)
