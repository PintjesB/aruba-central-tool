import unittest
from aruba_central.identity_review import identity_collisions


class IdentityReviewTests(unittest.TestCase):
    def test_exact_names_and_contexts_are_preserved(self):
        def view(*names):
            return {"status":"list_parsed","profiles":{n:{"name":n} for n in names}}
        data={"results":{"ACCESS_SWITCH":{"scopes":[{"id":"1","kind":"device"}],"modules":{"roles":{"scope_results":[
            {"scope":"1","local_view":view("Employee"),"effective_view":view("Employee","employee")}]}}}},
            "library":{"modules":{"roles":view(" EMPLOYEE ","Guest")}}}
        rows=identity_collisions(data)
        self.assertEqual(len(rows),1)
        r=rows[0]
        self.assertEqual(r["identities"],[" EMPLOYEE ","Employee","employee"])
        self.assertEqual(r["same_context_collisions"],1)
        self.assertEqual(r["context_count"],3)
        self.assertEqual(len(r["observations"]),4)
        self.assertFalse(r["safe_to_apply"])
        data["results"]["ACCESS_SWITCH"]["modules"]["roles"]["scope_results"][0]["effective_view"]=view("employee")
        self.assertEqual(identity_collisions(data)[0]["same_context_collisions"],0)


    def test_unresolved_reads_link_to_exact_collision_context_without_adding_names(self):
        def view(*names):
            return {"status":"list_parsed","profiles":{n:{"name":n} for n in names}}
        data={"results":{"ACCESS_SWITCH":{"scopes":[{"id":"1","kind":"device"}],"modules":{"roles":{"scope_results":[
            {"scope":"1","local_view":view("Employee"),"effective_view":view("Employee","employee")}]}}}},
            "keyed_profile_details":{"profiles":{"ACCESS_SWITCH":{"1":{"roles":{"Employee":{
                "effective":{"status":"schema_unresolved","raw":{"name":"employee"}},
                "local":{"status":"schema_unresolved","raw":{"name":"EMPLOYEE"}}}}}}}}}
        row=identity_collisions(data)[0]
        self.assertEqual(row["identities"],["Employee","employee"])
        reads={r["view"]:r for r in row["unresolved_individual_responses"]}
        self.assertTrue(reads["effective"]["both_names_observed_in_context"])
        self.assertFalse(reads["local"]["both_names_observed_in_context"])
        self.assertEqual(reads["local"]["returned_identity"],"EMPLOYEE")


    def test_active_capture_identity_cache_shared_by_assessment_and_inspector(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.config_app import Workspace
        from aruba_central.identity_review import identity_collisions
        from test_consolidation import fixture
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-test.json"
            path=Path(directory)/name
            path.write_text(json.dumps(fixture()))
            w=Workspace(directory)
            bundle=w.reviewed_snapshot(name)
            with patch("aruba_central.identity_review.identity_collisions",wraps=identity_collisions) as calc:
                w.assessment_snapshot(bundle)
                first=w.identity_snapshot(bundle)
                w.assessment({"snapshot":name,"mode":"identities"})
                self.assertIs(first,w.identity_snapshot(bundle))
                self.assertEqual(calc.call_count,1)
                path.write_text(path.read_text()+" ")
                changed=w.reviewed_snapshot(name)
                self.assertIsNot(bundle,changed)
                self.assertEqual(w.identity_snapshot(changed),first)
                self.assertEqual(calc.call_count,2)
