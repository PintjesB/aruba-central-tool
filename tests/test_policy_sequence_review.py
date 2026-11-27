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
