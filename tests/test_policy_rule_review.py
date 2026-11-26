import unittest
from policy_rule_review import rule_review, policy_rule_groups


def rule(position, source="guest", destination=None, action="ACTION_ALLOW", **extra):
    def address(value):
        return {"type": "ADDRESS_ANY"} if value is None else {"type": "ADDRESS_ROLE", "role": value}
    return {"position": position, "condition": {"type": "CONDITION_DEFAULT", "rule-type": "RULE_ANY",
            "source": address(source), "destination": address(destination)}, "action": {"type": action}, **extra}


def policy(rules):
    return {"name": "test", "type": "POLICY_TYPE_SECURITY",
            "security-policy": {"type": "SECURITY_POLICY_TYPE_DEFAULT", "policy-rule": rules}}


class PolicyRuleTests(unittest.TestCase):
    def test_rule_order_and_full_cover(self):
        result = rule_review("policies", policy([rule(30, destination="staff", action="OTHER_ACTION"),
                                                rule(20), rule(10, source=None)]))
        self.assertTrue(result["order_verified"])
        self.assertEqual(result["qualified_match_rules"], 3)
        self.assertEqual([(v["earlier_position"], v["later_position"]) for v in result["findings"]], [(10, 20), (10, 30), (20, 30)])
        self.assertEqual(result["findings"][0]["status"], "broader_earlier_same_action")
        self.assertEqual(result["findings"][1]["status"], "broader_earlier_different_action")
        self.assertFalse(result["safe_to_apply"])

    def test_same_match_and_other_role_do_not_infer_overlap(self):
        result = rule_review("policies", policy([rule(1), rule(2), rule(3, action="OTHER_ACTION"), rule(4, source="staff")]))
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(result["findings"][0]["status"], "duplicate_condition_same_action")
        self.assertEqual(result["findings"][1]["status"], "same_condition_different_action")

    def test_unknown_fields_and_order_are_not_semantically_qualified(self):
        result = rule_review("policies", policy([rule(1, source=None, **{"time-profile": "office-hours"}), rule(2)]))
        self.assertEqual(result["unsupported_rules"], 1)
        self.assertFalse(result["findings"])
        duplicate = rule_review("policies", policy([rule(1), rule(1)]))
        self.assertFalse(duplicate["order_verified"])
        self.assertFalse(duplicate["findings"])

    def test_acl_structural_duplicates_only(self):
        row = {"action": "permit", "match": {"unknown": 1}}
        result = rule_review("role-acls", {"rules": [row, row, {"action": "deny", "match": {"unknown": 1}}]})
        self.assertEqual(result["findings"][0]["status"], "identical_acl_record")
        self.assertEqual(result["unsupported_rules"], 3)
        self.assertFalse(result["order_verified"])

    def test_groups_identical_observations_across_devices(self):
        body = policy([rule(1), rule(2)])
        bundle = {"results": {"CAMPUS_AP": {"scopes": [{"id": "1", "kind": "device"}, {"id": "2", "kind": "device"}],
                   "modules": {"policies": {"scope_results": [{"scope": sid, "effective_view": {
                       "status": "list_parsed", "profiles": {"test": body}}} for sid in ("1", "2")]}}}}}
        groups = policy_rule_groups(bundle)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["locations"]), 2)
        self.assertEqual(len(groups[0]["findings"]), 1)
