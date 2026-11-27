import unittest
from aruba_central.role_acl_review import literal_destination, acl_prefix_review
from aruba_central.policy_rule_review import rule_review
from aruba_central.advanced_review import explicit_references


def rule(position, destination, action="PERMIT", role="Guest", vrf="default", **fields):
    return {"position": position, "src-role": role, "vrf": vrf, "action": action,
            "destination": destination, **fields}


class RoleACLTests(unittest.TestCase):
    def test_ipv4_literal_host_network_and_role_context(self):
        net = {"address-type": "ADDRESS_NETWORK", "ipv4-subnet-address": "10.0.0.0", "ipv4-prefix": "24"}
        host = {"address-type": "ADDRESS_HOST", "ipv4-address": "10.0.0.5"}
        body = {"acl-type": "ACL_IPV4", "rules": [
            rule(30, host, action="DENY", count=True),
            rule(10, net, count=False),
            rule(40, host, role="Staff"),
            rule(50, host, vrf="other")]}
        result = rule_review("role-acls", body)
        self.assertTrue(result["order_verified"])
        self.assertEqual(result["unsupported_rules"], 0)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["status"], "acl_prefix_overlap_different_action")
        self.assertEqual(finding["coverage"], "earlier_contains_later")
        self.assertEqual(finding["counter_setting"], "different")
        self.assertFalse(result["safe_to_apply"])

    def test_ipv6_reverse_containment(self):
        host = {"address-type": "ADDRESS_HOST", "ipv6-address": "2001:db8::1"}
        net = {"address-type": "ADDRESS_NETWORK", "ipv6-subnet-address": "2001:db8::", "ipv6-prefix": "64"}
        result = acl_prefix_review({"acl-type": "ACL_IPV6", "rules": [rule(1, host), rule(2, net)]})
        self.assertEqual(result["findings"][0]["coverage"], "later_contains_earlier")
        self.assertEqual(result["findings"][0]["counter_setting"], "unverified")

    def test_unknown_or_inconsistent_predicates_not_interpreted(self):
        host = {"address-type": "ADDRESS_HOST", "ipv4-address": "10.0.0.1"}
        self.assertIsNone(literal_destination({**host, "ipv6-address": "::1"}, 4))
        self.assertIsNone(literal_destination({"address-type": "ADDRESS_NETWORK", "ipv4-subnet-address": "10.0.0.1", "ipv4-prefix": "24"}, 4))
        self.assertIsNone(literal_destination(host, 6))
        result = acl_prefix_review({"acl-type": "ACL_IPV4", "rules": [rule(1, host, vrf=""), rule(2, host, service="tcp")]})
        self.assertEqual(result["unsupported_rules"], 2)
        self.assertFalse(result["findings"])
        result = acl_prefix_review({"acl-type": "ACL_IPV4", "rules": [rule(1, host), rule(1, host)]})
        self.assertFalse(result["order_verified"])
        self.assertFalse(result["findings"])

    def test_role_dependency_paths(self):
        refs = list(explicit_references({"rules": [{"src-role": "Guest"}]}, module="role-acls"))
        self.assertIn(("roles", "Guest", ("rules", 0, "src-role")), refs)
        self.assertEqual(list(explicit_references({"source": {"type": "ADDRESS_ROLE", "role": "Guest"}}, module="policies")),
                         [("roles", "Guest", ("source", "role"))])
