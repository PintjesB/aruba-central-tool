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

    def test_policy_evidence_shared_across_views_and_replaced_with_capture(self):
        from aruba_central.policy_variants import policy_variants
        from aruba_central.policy_rule_review import policy_rule_groups
        from aruba_central.policy_sequence_review import policy_sequence_reviews
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            w = Workspace(directory)
            bundle = w.reviewed_snapshot(name)
            with patch("aruba_central.policy_variants.policy_variants", wraps=policy_variants) as v, \
                 patch("aruba_central.policy_rule_review.policy_rule_groups", wraps=policy_rule_groups) as r, \
                 patch("aruba_central.policy_sequence_review.policy_sequence_reviews", wraps=policy_sequence_reviews) as s:
                w.assessment_snapshot(bundle)
                first = w.policy_snapshot(bundle, "rules")
                w.advanced({"snapshot": name, "workflow": "variants"})
                w.advanced({"snapshot": name, "workflow": "rules"})
                self.assertEqual((v.call_count, r.call_count, s.call_count), (1, 1, 1))
                path.write_text(path.read_text() + " ")
                new_bundle = w.reviewed_snapshot(name)
                new_rules = w.policy_snapshot(new_bundle, "rules")
                self.assertIsNot(first, new_rules)
                w.policy_snapshot(bundle, "rules")
                self.assertIs(w.policy_snapshot(new_bundle, "rules"), new_rules)
                self.assertEqual(r.call_count, 3)
