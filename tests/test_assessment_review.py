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


    def test_assessment_exposes_policy_and_checkpoint_evidence(self):
        from test_policy_rule_review import policy, rule
        from test_policy_sequence_review import capture
        data = fixture()
        data["library"]["modules"]["policies"] = {"status": "list_parsed", "profiles": {
            "broad": policy([rule(1, source=None), rule(2)]), "specific": policy([rule(1)])}}
        data["unadapted_profiles"] = {"policy-groups": {"library": capture([
            {"name": "broad", "position": 1}, {"name": "specific", "position": 2}])}}
        data["collection_checkpoint"] = {"enabled": True, "mixed_capture_times": True,
                                         "reused_pairs": 2, "additional_observations_reused": {"library": 1}}
        report = assessment(data)
        self.assertEqual(report["policy_rules"]["groups_with_findings"], 1)
        self.assertEqual(report["policy_sequences"]["cross_policy_candidates"], 2)
        self.assertTrue(report["checkpoint"]["mixed_capture_times"])
