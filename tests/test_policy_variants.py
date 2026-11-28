import unittest
from aruba_central.policy_variants import policy_variants


class PolicyVariantTests(unittest.TestCase):
    def test_groups_bodies_with_device_function_and_evidence_coverage(self):
        def view(profiles, confirmed=True):
            return {"status": "list_parsed", "count_confirmed": confirmed, "profiles": profiles}
        scopes = [{"id": str(n), "kind": "device", "name": "Device " + str(n)} for n in range(1, 6)]
        def row(n, profile):
            return {"scope": str(n), "effective_view": profile}
        profiles = {"scope_results": [
            row(1, view({"20": {"vlan": 20, "name": "Office"}})),
            row(2, view({"20": {"vlan": 20, "name": "Office", "@": {"source": "different annotation"}}})),
            row(3, view({"20": {"vlan": 20, "name": "Guest"}})),
            row(4, view({})), row(5, view({}, False))]}
        bundle = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {"layer2-vlan": profiles}}}}
        result = policy_variants(bundle)
        self.assertEqual(len(result), 1)
        finding = result[0]
        self.assertEqual(finding["status"], "explicit_differences")
        self.assertEqual([len(v["devices"]) for v in finding["variants"]], [2, 1])
        self.assertEqual(finding["present_count"], 3)
        self.assertEqual(finding["absent"][0]["scope"], "4")
        self.assertEqual(finding["unknown"][0]["scope"], "5")
        self.assertFalse(finding["safe_to_apply"])

    def test_missing_fields_are_not_confirmed_setting_differences(self):
        scopes = [{"id": str(n), "kind": "device"} for n in (1, 2)]
        views = [{"scope": "1", "effective_view": {"status": "list_parsed", "profiles": {"p": {"name": "p", "enable": True}}}},
                 {"scope": "2", "effective_view": {"status": "list_parsed", "profiles": {"p": {"name": "p"}}}}]
        bundle = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {"roles": {"scope_results": views}}}}}
        self.assertEqual(policy_variants(bundle)[0]["status"], "field_evidence_differs")


    def test_variant_membership_and_conflicting_bodies_remain_separate(self):
        from test_configuration_history import snapshot
        data=snapshot("Other")
        data["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{"20":{
            "effective":{"status":"identity_observed","profile":{"vlan":20,"name":"Contradiction"}}}}}}}}
        row=policy_variants(data)[0]
        self.assertEqual(row["status"],"individual_evidence_conflict")
        self.assertEqual(row["present_count"],1)
        self.assertEqual([r["scope"] for r in row["individual_conflicts"]],["4"])
        self.assertEqual(row["membership_distribution"]["site"],[{"scope":"2","name":"Site","variant_numbers":[1]}])
        self.assertEqual([r["scope"] for r in row["unknown"]],["5"])
        data["keyed_profile_details"]={}
        row=policy_variants(data)[0]
        self.assertEqual(row["status"],"explicit_differences")
        self.assertEqual(row["membership_distribution"]["site"][0]["variant_numbers"],[1,2])
