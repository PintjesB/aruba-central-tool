import unittest
from aruba_central.nac_binding_review import tag_condition_observations, vlan_identity, nac_bindings


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


    def test_role_attribute_value_candidates_do_not_imply_authorization(self):
        from aruba_central.nac_role_review import role_enforcement_review
        role={"name":"Employee","enable":True}
        bundle={"results":{"ACCESS_SWITCH":{"scopes":[{"id":"1","kind":"device"},{"id":"2","kind":"device"}],"modules":{"roles":{"scope_results":[
            {"scope":"1","effective_view":{"status":"list_parsed","count_confirmed":True,"profiles":{"Employee":role}}},
            {"scope":"2","effective_view":{"status":"list_parsed","count_confirmed":True,"profiles":{"employee":{"name":"employee"}}}}]}}}},
            "library":{"modules":{"roles":{"status":"list_parsed","profiles":{"Employee":role}}}}}
        attrs=[{"kind":"custom-attr","name":"Aruba-User-Role","value":"Employee"},
               {"kind":"defined-attr","name":"UNKNOWN_ENUM","value":"Employee"},
               {"kind":"custom-attr","name":"Aruba-User-Role","value":"Missing"},
               {"kind":"defined-attr","name":"ATTR_VLAN_ID","value":"Employee"}]
        r=role_enforcement_review(bundle,attrs)
        self.assertEqual([t["status"] for t in r["targets"]],["explicit_role_attribute","exact_role_name_candidate_not_attribute_semantics","explicit_role_attribute"])
        self.assertEqual(r["visibility"]["Employee"]["similar_exact_names"],["employee"])
        self.assertEqual([d["status"] for d in r["visibility"]["Employee"]["devices"]],["observed","count_confirmed_absence"])
        self.assertEqual(r["visibility"]["Employee"]["devices"][0]["library_comparison"],"exact_library_body")
        self.assertFalse(r["safe_to_apply"])
        bundle["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"1":{"roles":{"Employee":{"effective":{"status":"identity_observed","profile":{"name":"Employee","enable":False}}}}}}}}
        r=role_enforcement_review(bundle,attrs)
        self.assertEqual(r["visibility"]["Employee"]["devices"][0]["status"],"individual_evidence_conflict")


    def test_nac_vlan_conflicting_individual_evidence_and_original_occurrence(self):
        from aruba_central.nac_binding_review import vlan_coverage,context_label
        from test_configuration_history import snapshot
        data=snapshot()
        data["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{"20":{
            "effective":{"status":"identity_observed","profile":{"vlan":20,"name":"Different"}}}}}}}}
        rows=vlan_coverage(data,{"20"})["20"]
        self.assertEqual(next(r for r in rows if r["scope"]=="4")["status"],"individual_evidence_conflict")
        self.assertEqual(next(r for r in rows if r["scope"]=="3")["status"],"observed")
        self.assertEqual(context_label({"rule":1,"rule_index":0,"captured_rule_index":2}),"Rule 1 (captured #3)")
