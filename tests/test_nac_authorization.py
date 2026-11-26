import unittest
from unittest.mock import patch
from nac_authorization import capture_nac_configuration, enforcement_attributes, policy_review


def captured(profiles, confirmed=True):
    return {"status": "list_parsed", "profiles": profiles, "count_confirmed": confirmed}


def radius(*pairs):
    return [{"radius-profile": {"defined-attr": [{"attr-name": name, "value": value} for name, value in pairs]}}]


class NACAuthorizationTests(unittest.TestCase):
    def test_default_queries_for_tenant_resources(self):
        with patch("central_tool.read_module_view", return_value=captured({})) as reader:
            result = capture_nac_configuration(object())
        self.assertEqual(set(result), {"static-tag", "authz-policies", "identity-stores"})
        self.assertTrue(all(call.args[-1] == {} for call in reader.call_args_list))

    def test_conditional_union_and_store_evidence(self):
        bundle = {"nac_configuration": {
            "identity-stores": captured({"store-a": {"id": "store-a"}}),
            "authz-policies": captured({"p": {"policy-id": "p", "name": "Devices",
                "policy-type": "DEVICE", "position": 5, "enable": True, "identity-stores": ["store-a", "missing"],
                "default-enf-profile": radius(("ATTR_VLAN_ID", "20"), ("ATTR_SSID", "Office")),
                "rule": [{"position": 3, "enable": True, "conditions": {"condition": []},
                          "enf-profile": radius(("ATTR_VLAN_ID", "30"))},
                         {"position": 1, "enable": False, "enf-profile": []}]}})},
            "library": {"modules": {"auth-profiles": captured({"auth": {
                "auth-profile-id": "auth", "name": "MAB", "auth-type": "MAB",
                "identity-stores": ["store-a"], "networks": ["Office"]}})}}}
        result = policy_review(bundle)
        p = result["policies"][0]
        self.assertTrue(result["policy_order_verified"])
        self.assertTrue(p["rule_order_verified"])
        self.assertEqual([r["position"] for r in p["rules"]], [1, 3])
        values = {v["name"]: (v["value"], v["source"]) for v in p["rules"][1]["combined_candidate_attributes"]}
        self.assertEqual(values, {"ATTR_VLAN_ID": ("30", "rule"), "ATTR_SSID": ("Office", "default")})
        self.assertEqual([r["status"] for r in p["identity_stores"]["references"]], ["observed", "not_observed"])
        self.assertEqual(result["authentication"][0]["identity_stores"]["references"][0]["status"], "observed")
        self.assertFalse(result["safe_to_apply"])

    def test_unknown_and_repeated_attributes_do_not_qualify_union(self):
        attrs, gaps = enforcement_attributes(radius(("ATTR_VLAN_ID", "20"), ("ATTR_VLAN_ID", "30")))
        self.assertTrue(gaps)
        bundle = {"nac_configuration": {"authz-policies": captured({"p": {
            "position": 1, "default-enf-profile": radius(("ATTR_VLAN_ID", "20")),
            "rule": [{"position": 1, "enf-profile": [{"unknown-profile": {}}]}]}})}}
        row = policy_review(bundle)["policies"][0]["rules"][0]
        self.assertEqual(row["status"], "enforcement_unqualified")
        self.assertFalse(row["combined_candidate_attributes"])
