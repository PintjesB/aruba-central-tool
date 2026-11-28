import unittest
from aruba_central.policy_sequence_review import sequence_entries, compare_sequence, policy_sequence_reviews
from test_policy_rule_review import policy, rule


def capture(rows):
    return {"status": "response_received", "raw": {"policy-group": {"policy-group-list": rows}}}


class PolicySequenceTests(unittest.TestCase):
    def test_order_and_cross_policy_overlap(self):
        parsed = sequence_entries(capture([{"name": "specific", "position": 20}, {"name": "broad", "position": 10}]))
        view = {"status": "list_parsed", "count_confirmed": True,
                "profiles": {"broad": policy([rule(1, source=None)]),
                             "specific": policy([rule(1, action="OTHER_ACTION")])}}
        result = compare_sequence(parsed, view)
        self.assertEqual([r["name"] for r in result["references"]], ["broad", "specific"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertFalse(result["findings"][0]["same_action"])
        self.assertFalse(result["safe_to_apply"])
        self.assertFalse(result["complete"])

    def test_duplicate_order_and_missing_targets(self):
        parsed = sequence_entries(capture([{"name": "a", "position": 1}, {"name": "b", "position": 1}]))
        self.assertEqual(parsed["status"], "duplicate_name_or_position")
        self.assertFalse(compare_sequence(parsed, {})["findings"])
        parsed = sequence_entries(capture([{"name": "a", "position": 1}]))
        self.assertEqual(compare_sequence(parsed, {"status": "list_parsed", "profiles": {}})["references"][0]["status"], "target_unverified")
        self.assertEqual(compare_sequence(parsed, {"status": "list_parsed", "profiles": {}, "count_confirmed": True})["references"][0]["status"], "not_observed")

    def test_unfiltered_scope_does_not_resolve_other_function(self):
        raw = capture([{"name": "broad", "position": 1}])
        bundle = {"unadapted_profiles": {"policy-groups": {"source_views": [
            {"persona": "ALL_DEVICE_FUNCTIONS", "scope": "1", "effective": raw},
            {"persona": "CAMPUS_AP", "scope": "1", "effective": raw}]}},
            "results": {"CAMPUS_AP": {"scopes": [{"id": "1", "kind": "global"}],
              "modules": {"policies": {"scope_results": [{"scope": "1", "effective_view": {
                 "status": "list_parsed", "profiles": {"broad": policy([rule(1)])}}}]}}}}}
        results = policy_sequence_reviews(bundle)
        self.assertEqual(results[0]["references"][0]["status"], "target_unverified")
        self.assertEqual(results[1]["references"][0]["status"], "rules_observed")


    def test_conflicting_policy_target_never_participates_in_sequence_comparison(self):
        raw=capture([{"name":"broad","position":1},{"name":"specific","position":2}])
        view={"status":"list_parsed","count_confirmed":True,"profiles":{
            "broad":policy([rule(1,source=None)]),"specific":policy([rule(1)])}}
        data={"results":{},"unadapted_profiles":{"policy-groups":{"library":raw}},
              "library":{"modules":{"policies":view}},
              "keyed_profile_details":{"profiles":{"Library":{"":{"policies":{"broad":{"library":{
                  "status":"identity_observed","profile":policy([])}}}}}}}}
        result=policy_sequence_reviews(data)[0]
        self.assertEqual([r["status"] for r in result["references"]],["individual_evidence_conflict","rules_observed"])
        self.assertFalse(result["findings"])


    def test_cross_policy_partial_overlap_distinguished_from_full_containment(self):
        parsed=sequence_entries(capture([{"name":"a","position":1},{"name":"b","position":2}]))
        view={"status":"list_parsed","profiles":{"a":policy([rule(1,source="guest")]),
              "b":policy([rule(1,source=None,destination="staff",action="OTHER_ACTION")])}}
        result=compare_sequence(parsed,view)
        self.assertEqual(result["findings"][0]["condition_relationship"],"partial_overlap")
        self.assertFalse(result["findings"][0]["same_action"])

    def test_cross_policy_rule_qualification_matches_individual_review(self):
        parsed=sequence_entries(capture([{"name":"a","position":1},{"name":"b","position":2}]))
        invalid=rule(1,source=None)
        invalid["action"]={"type":42}
        view={"status":"list_parsed","profiles":{"a":policy([invalid,rule(2,source=None)]),
              "b":policy([rule(1),rule(2,extra=True)])}}
        result=compare_sequence(parsed,view)
        self.assertEqual(len(result["findings"]),1)
        self.assertEqual(result["findings"][0]["earlier_rule"]["position"],2)
        for ref in result["references"]:
            self.assertEqual(ref["rule_count"],2)
            self.assertEqual(ref["qualified_rule_count"],1)
            self.assertEqual(ref["unsupported_rule_count"],1)
        limited=compare_sequence(parsed,view,limit=0)
        self.assertTrue(limited["truncated"])
        self.assertEqual(limited["references"][1]["qualified_rule_count"],1)
        self.assertFalse(limited["findings"])

    def test_sequence_target_contexts_explain_unverified_targets_without_inference(self):
        raw=capture([{"name":"private-name","position":1}])
        contexts=[("ALL_DEVICE_FUNCTIONS","1"),("OTHER","1"),("CAMPUS_AP","9"),
                  ("CAMPUS_AP","2"),("CAMPUS_AP","3"),("CAMPUS_AP","1")]
        data={"unadapted_profiles":{"policy-groups":{"source_views":[
            {"persona":p,"scope":s,"effective":raw} for p,s in contexts],"library":raw}},
            "results":{"CAMPUS_AP":{"scopes":[{"id":s,"kind":"site"} for s in ("1","2","3")],
            "modules":{"policies":{"scope_results":[
                {"scope":"1","effective_view":{"status":"list_parsed","count_confirmed":True,"profiles":{}}},
                {"scope":"3","effective_view":{"status":"read_failed"}}]}}}}}
        reports=policy_sequence_reviews(data)
        self.assertEqual([r["target_context"] for r in reports],[
            "unfiltered_function","function_not_collected","scope_not_observed",
            "policy_view_not_collected","policy_view_unqualified","policy_view_parsed","policy_view_not_collected"])
        self.assertEqual(reports[5]["references"][0]["status"],"not_observed")
        self.assertTrue(all(not r["findings"] and not r["safe_to_apply"] for r in reports))
        self.assertTrue(all(r["references"][0]["status"]=="target_unverified" for r in reports[:5]))

    def test_alternative_policy_identity_observations_never_qualify_sequence_targets(self):
        raw=capture([{"name":"broad","position":1},{"name":"specific","position":2}])
        bodies={"broad":policy([rule(1)]),"specific":policy([rule(1)])}
        mixed=[{"name":name,**body} for name,body in bodies.items()]
        data={"results":{"CAMPUS_AP":{"scopes":[{"id":"1","kind":"global"}],"modules":{
            "policies":{"scope_results":[{"scope":"1","effective_view":{"status":"list_parsed","profiles":bodies}}]}}}},
            "library":{"modules":{"policies":{"status":"list_parsed","profiles":{"broad":bodies["broad"]}}}},
            "unadapted_profiles":{"policy-groups":{"source_views":[{"persona":"ALL_DEVICE_FUNCTIONS","scope":"1","effective":raw},
                {"persona":"ALL_DEVICE_FUNCTIONS","scope":"2","effective":raw}]},
                "policies":{"source_views":[{"persona":"UNFILTERED_SCOPE","scope":"1","effective":{
                    "status":"response_received","raw":{"policy":mixed}}}]}}}
        reports=policy_sequence_reviews(data)
        first=reports[0]["references"][0]
        self.assertEqual(first["status"],"target_unverified")
        self.assertEqual({r["context"] for r in first["alternative_observations"]},
                         {"other_function_same_scope","unfiltered_same_scope","library_definition"})
        self.assertEqual({r["context"] for r in reports[1]["references"][0]["alternative_observations"]},{"library_definition"})
        self.assertTrue(all(not r["findings"] and not r["safe_to_apply"] for r in reports))
        self.assertNotIn("alternative_observations",reports[1]["references"][1])
