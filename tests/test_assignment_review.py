import unittest
from aruba_central.assignment_review import assignment_review
from test_inheritance_review import fixture


class AssignmentReviewTests(unittest.TestCase):
    def test_recipient_visibility_and_overlapping_assignments(self):
        entry = fixture(group="Office", global_="Office")
        body = {"vlan": 20, "name": "Office"}
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {**body, "@": {"aruba-annotation:object_type": "SHARED"}}}}})
        assignment = {"profile-type": "layer2-vlan", "profile-instance": "20", "device-function": "ACCESS_SWITCH"}
        bundle = {"results": {"ACCESS_SWITCH": entry}, "library": {
            "modules": {"layer2-vlan": {"status": "list_parsed", "profiles": {"20": body}}},
            "assignments": {"status": "response_received", "rows": [
                {**assignment, "scope-id": "1"}, {**assignment, "scope-id": "4"},
                {**assignment, "scope-id": "4"}, {**assignment, "scope-id": "999"}, {}]}}}
        report = assignment_review(bundle)
        self.assertEqual(len(report["rows"]), 3)
        self.assertEqual(len(report["overlaps"]), 1)
        self.assertEqual(len(report["invalid_rows"]), 1)
        self.assertEqual(report["rows"][0]["recipients"][0]["status"], "matching_shared")
        self.assertFalse(report["rows"][-1]["scope_resolved"])
        self.assertFalse(report["complete"])
        self.assertFalse(report["safe_to_apply"])

    def test_unknown_membership_is_not_nonmembership(self):
        entry = fixture(group_known=False)
        bundle = {"results": {"ACCESS_SWITCH": entry}, "library": {"assignments": {"rows": [
            {"profile-type": "layer2-vlan", "profile-instance": "20", "device-function": "ACCESS_SWITCH", "scope-id": "4"}]}}}
        row = assignment_review(bundle)["rows"][0]
        self.assertEqual(row["known_count"], 0)
        self.assertEqual(row["unknown_count"], 1)
        self.assertEqual(row["recipients"][0]["status"], "membership_unverified")

    def test_workspace_renders_assignment_review(self):
        import json
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from test_configuration_history import snapshot
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-test.json"
            (Path(directory) / name).write_text(json.dumps(snapshot()))
            html = Workspace(directory).assignments({"snapshot": name})
            self.assertIn("Assignment worklist", html)
            self.assertIn("Overlapping assignment observations", html)
            self.assertIn("Export private report JSON", html)


    def test_lazy_assignment_evidence_and_shared_analysis_cache(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.config_app import Workspace
        from aruba_central.review_dispositions import snapshot_binding
        from test_configuration_history import snapshot
        bundle = snapshot()
        bundle["library"]["assignments"] = {"status": "response_received", "rows": [
            {"profile-type": "layer2-vlan", "profile-instance": "20", "device-function": "ACCESS_SWITCH", "scope-id": "1"}]}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-test.json"
            path = Path(directory) / name
            path.write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            binding = snapshot_binding(workspace, name, reviewed)
            with patch("aruba_central.assignment_review.assignment_review", wraps=assignment_review) as analyze:
                workspace.assessment_snapshot(reviewed)
                html = workspace.assignments({"snapshot": name})
                self.assertIn("data-inspect-url=", html)
                self.assertNotIn("Library definition captured:", html)
                self.assertEqual(analyze.call_count, 1)
                query = {"snapshot": name, "detail": "assignment", "index": "0", "binding": binding}
                self.assertIn("Library definition captured:", workspace.assignments(query))
                self.assertEqual(analyze.call_count, 1)
                self.assertIn("Export private report JSON", workspace.assignments({"snapshot": name, "export": "1", "binding": binding}))
                with self.assertRaises(ValueError):
                    workspace.assignments({**query, "binding": "stale"})
                with self.assertRaises(ValueError):
                    workspace.assignments({**query, "index": "999"})
                path.write_text(json.dumps({**bundle, "tenant_name": "Changed"}))
                with self.assertRaises(ValueError):
                    workspace.assignments(query)
                self.assertEqual(analyze.call_count, 2)
