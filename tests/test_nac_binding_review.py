import unittest
from nac_binding_review import tag_condition_observations, vlan_identity, nac_bindings


class NACBindingTests(unittest.TestCase):
    def test_condition_values_are_candidates_not_authorization(self):
        tags = {"t1": {"name": "Office"}, "t2": {"name": "Office"}}
        conditions = {"condition": [{"position": 1, "condition-group": [
            {"position": 2, "attr": "unknown.attribute", "operator": "OP_EQUALS", "value": "Office"},
            {"position": 3, "attr": "other", "values": ["t1", "missing"]}]}]}
        matches = tag_condition_observations(conditions, tags)
        self.assertEqual(matches[0]["tag_candidates"], ["t1", "t2"])
        self.assertEqual(matches[1]["tag_candidates"], ["t1"])
        self.assertEqual(matches[0]["status"], "exact_value_observation_not_tag_semantics")

    def test_vlan_visibility_distinguishes_absence_and_unknown(self):
        def view(profiles, confirmed):
            return {"status": "list_parsed", "profiles": profiles, "count_confirmed": confirmed}
        bundle = {"results": {"ACCESS_SWITCH": {"scopes": [
            {"id": sid, "kind": "device", "name": sid} for sid in ("1", "2", "3")],
            "modules": {"layer2-vlan": {"scope_results": [
                {"scope": "1", "effective_view": view({"20": {"vlan": 20, "name": "Office"}}, True)},
                {"scope": "2", "effective_view": view({}, True)},
                {"scope": "3", "effective_view": view({}, False)}]}}}}}
        regs = {"tag_definitions": {}, "rows": []}
        auth = {"policies": [{"id": "p", "name": "Policy", "conditions": None, "enabled": True,
            "default_attributes": [{"kind": "defined-attr", "name": "ATTR_VLAN_ID", "value": "20", "source": "default"}],
            "default_gaps": [], "rules": []}]}
        result = nac_bindings(bundle, regs, auth)
        self.assertEqual([v["status"] for v in result["vlan_visibility"]["20"]],
                         ["observed", "count_confirmed_absence", "unverified"])
        self.assertEqual(result["vlan_targets"][0]["status"], "conditional_vlan_candidate")
        self.assertFalse(result["safe_to_apply"])
        self.assertIsNone(vlan_identity("20-30"))
        self.assertIsNone(vlan_identity("4095"))
