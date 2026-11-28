import unittest
from aruba_central.source_review import source_trace
from test_inheritance_review import fixture


class SourceTests(unittest.TestCase):
    def test_nearest_direct_source_and_different_global(self):
        entry = fixture(group="Office", global_="Different")
        ann = {"aruba-annotation:inherited": True, "aruba-annotation:object_type": "LOCAL"}
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20, "name": "Office", "@": ann}}}})
        bundle = {"results": {"ACCESS_SWITCH": entry}}
        result = source_trace(bundle, "ACCESS_SWITCH", "5", "layer2-vlan", "20")
        self.assertEqual(result["observed_source_scope"], "4")
        self.assertEqual(result["chain"][-1]["status"], "direct_difference")
        self.assertFalse(result["safe_to_apply"])

    def test_unknown_group_does_not_prove_site_source(self):
        entry = fixture(site="Office", group_known=False)
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20, "name": "Office", "@": {"aruba-annotation:inherited": True}}}}})
        result = source_trace({"results": {"ACCESS_SWITCH": entry}}, "ACCESS_SWITCH", "5", "layer2-vlan", "20")
        self.assertIsNone(result["observed_source_scope"])
        self.assertIn("3", result["matching_direct_scopes"])
        self.assertTrue(result["blockers"])


    def test_source_path_marks_only_qualified_winner_and_links_exact_scope(self):
        from aruba_central.source_view import inheritance_path
        entry = fixture(group="Office", global_="Different")
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20, "name": "Office", "@": {"aruba-annotation:inherited": True}}}}})
        result = source_trace({"results": {"ACCESS_SWITCH": entry}}, "ACCESS_SWITCH", "5", "layer2-vlan", "20")
        html = inheritance_path(result, "/test/", "capture.json", "ACCESS_SWITCH")
        self.assertEqual(html.count('class="source-winner"'), 1)
        self.assertIn("Direct definition differs", html)
        self.assertIn("scope=4", html)
        self.assertIn("Observed configuration precedence", html)
        result["observed_source_scope"] = None
        html = inheritance_path(result, "/test/", "capture.json", "ACCESS_SWITCH")
        self.assertNotIn('class="source-winner"', html)
        self.assertIn("No unique source is established", html)

    def test_individual_conflicts_block_unqualified_source_claims(self):
        from aruba_central.source_view import inheritance_path
        entry = fixture(group="Office", global_="Different")
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope":"5","effective_view":{
            "status":"list_parsed","count_confirmed":True,"profiles":{"20":{"vlan":20,"name":"Office",
                "@":{"aruba-annotation:inherited":True}}}}})
        bundle={"results":{"ACCESS_SWITCH":entry},"library":None}
        self.assertEqual(source_trace(bundle,"ACCESS_SWITCH","5","layer2-vlan","20")["observed_source_scope"],"4")
        def read(name):
            return {"status":"identity_observed","profile":{"vlan":20,"name":name}}
        bundle["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{
            "4":{"layer2-vlan":{"20":{"effective":read("Different")}}}}}}
        result=source_trace(bundle,"ACCESS_SWITCH","5","layer2-vlan","20")
        self.assertIsNone(result["observed_source_scope"])
        row=next(r for r in result["chain"] if r["scope"]=="4")
        self.assertEqual(row["status"],"individual_evidence_conflict")
        self.assertIn("individual_conflict",row["effective"])
        self.assertNotIn("4",result["matching_direct_scopes"])
        self.assertIn("Contradictory individual evidence",inheritance_path(result,"/test/","capture.json","ACCESS_SWITCH"))
        bundle["keyed_profile_details"]["profiles"]["ACCESS_SWITCH"]={"5":{"layer2-vlan":{"20":{"effective":read("Other")}}}}
        result=source_trace(bundle,"ACCESS_SWITCH","5","layer2-vlan","20")
        self.assertEqual(result["effective"]["state"],"individual_evidence_conflict")
        self.assertIsNone(result["observed_source_scope"])
        self.assertFalse(result["safe_to_apply"])
