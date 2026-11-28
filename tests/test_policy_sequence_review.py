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
