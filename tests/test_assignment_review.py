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


    def test_filters_retain_complete_atomic_overlap_and_do_not_mutate_report(self):
        from aruba_central.assignment_review import filter_assignment_review
        from copy import deepcopy
        def row(identity, scope, **kw):
            return {"persona": "ACCESS_SWITCH", "module": "dns", "identity": identity, "scope": scope,
                    "scope_resolved": True, "library_present": True,
                    "recipients": [{"status": "matching_shared"}], **kw}
        first, second = row("first", "1"), row("second", "2")
        missing = {**row("missing", "999"), "scope_resolved": False, "recipients": []}
        collision = {"persona": "ACCESS_SWITCH", "module": "dns", "device": "3", "identity": "*",
                     "assignments": [{"identity": "first", "scope": "1"}, {"identity": "second", "scope": "2"}]}
        report = {"rows": [first, second, missing], "overlaps": [collision], "invalid_rows": [{}]}
        original = deepcopy(report)
        filtered = filter_assignment_review(report, identity="first")
        self.assertEqual(filtered["rows"], [first])
        self.assertEqual(filtered["overlaps"], [collision])
        self.assertEqual(filter_assignment_review(report, state="overlap")["rows"], [first, second])
        self.assertEqual(filter_assignment_review(report, state="scope_unresolved")["rows"], [missing])
        self.assertEqual(filter_assignment_review(report, state="attention")["rows"], [first, second, missing])
        self.assertEqual(filter_assignment_review(report, state="no_recipients")["rows"], [])
        self.assertEqual(filter_assignment_review(report, state="scope_unresolved")["rows"], [missing])
        self.assertEqual(report, original)
        with self.assertRaises(ValueError):
            filter_assignment_review(report, state="unknown")


    def test_filtered_workspace_uses_exact_review_context(self):
        import json
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from aruba_central.review_dispositions import snapshot_binding
        from test_configuration_history import snapshot
        bundle = snapshot()
        assignment = {"profile-type": "layer2-vlan", "profile-instance": "20", "device-function": "ACCESS_SWITCH"}
        bundle["library"]["assignments"] = {"status": "response_received", "rows": [
            {**assignment, "scope-id": "1"}, {**assignment, "scope-id": "999"}]}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-test.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            binding = snapshot_binding(workspace, name, reviewed)
            query = {"snapshot": name, "state": "scope_unresolved"}
            html = workspace.assignments(query)
            self.assertIn("Scope unresolved", html)
            self.assertIn("state=scope_unresolved", html)
            self.assertNotIn("Scope resolved</", html)
            detail = workspace.assignments({**query, "detail": "assignment", "index": "0", "binding": binding})
            self.assertIn("999", detail)
            with self.assertRaises(ValueError):
                workspace.assignments({**query, "detail": "assignment", "index": "1", "binding": binding})


    def test_direct_conflicts_do_not_qualify_matching_shared_or_confirmed_absence(self):
        from aruba_central.assignment_review import filter_assignment_review
        from test_configuration_history import snapshot
        data = snapshot()
        data["library"]["assignments"] = {"status":"response_received","rows":[
            {"profile-type":"layer2-vlan","profile-instance":"20","device-function":"ACCESS_SWITCH","scope-id":"4"}]}
        view = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]
        view["profiles"]["20"]["@"] = {"aruba-annotation:object_type":"SHARED"}
        direct={"status":"identity_observed","profile":{"vlan":20,"name":"Different"}}
        data["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{"20":{"effective":direct}}}}}}
        report=assignment_review(data)
        recipient=report["rows"][0]["recipients"][0]
        self.assertEqual(recipient["status"],"individual_evidence_conflict")
        self.assertEqual(len(filter_assignment_review(report,state="individual_evidence_conflict")["rows"]),1)
        self.assertEqual(len(filter_assignment_review(report,state="matching_shared")["rows"]),0)
        view["profiles"].clear()
        self.assertEqual(assignment_review(data)["rows"][0]["recipients"][0]["individual_conflict"]["collection_state"],"count_confirmed_absent")
        direct["status"]="collection_only_sampled"
        self.assertEqual(assignment_review(data)["rows"][0]["recipients"][0]["status"],"not_visible")
        data["keyed_profile_details"]["profiles"]["Library"]={"":{"layer2-vlan":{"20":{"library":{"status":"identity_observed","profile":{"vlan":20,"name":"Different"}}}}}}
        report=assignment_review(data)
        self.assertIn("library_individual_conflict",report["rows"][0])
        self.assertEqual(report["rows"][0]["recipients"][0]["status"],"individual_evidence_conflict")

    def test_keyed_assignment_identity_evidence_never_resolves_scope_or_membership(self):
        from aruba_central.assignment_review import filter_assignment_review
        assignment={"profile-type":"layer2-vlan","profile-instance":"20","device-function":"ACCESS_SWITCH","scope-id":"999"}
        rows=[assignment,{**assignment,"scope-id":"998"},{**assignment,"scope-id":"997"},{**assignment,"scope-id":"996"},{**assignment,"scope-id":"995"}]
        records=[{"selector":rows[0],"status":"identity_observed","identity_format":"scope_map_resource"},
                 {"selector":rows[1],"status":"identity_observed","body_matches_inventory":False},
                 {"selector":rows[2],"status":"scope_only_observed"},
                 {"selector":rows[3],"status":"identity_unresolved"},
                 {"selector":rows[3],"status":"identity_observed"}]
        data={"results":{"ACCESS_SWITCH":fixture()},"library":{"assignments":{"rows":rows}},
              "keyed_assignment_details":{"records":records}}
        report=assignment_review(data)
        self.assertEqual([r["assignment_evidence_state"] for r in report["rows"]],
                         ["identity_observed","body_difference_observed","scope_only_observed","multiple_observations","not_collected"])
        self.assertTrue(all(not r["scope_resolved"] and not r["recipients"] for r in report["rows"]))
        self.assertEqual(len(filter_assignment_review(report,state="assignment_identity_observed")["rows"]),1)
        self.assertEqual(len(filter_assignment_review(report,state="assignment_body_difference")["rows"]),1)
        self.assertEqual(len(filter_assignment_review(report,state="assignment_identity_unverified")["rows"]),3)
        self.assertEqual(report["rows"][0]["individual_assignment_observations"],records[:1])
        self.assertFalse(report["safe_to_apply"])
