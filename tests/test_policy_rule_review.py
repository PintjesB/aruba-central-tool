import unittest
from aruba_central.policy_rule_review import rule_review, policy_rule_groups


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


    def test_individual_conflicts_cannot_qualify_rule_groups(self):
        body=policy([rule(1),rule(2)])
        view={"status":"list_parsed","count_confirmed":True,"profiles":{"test":body}}
        data={"results":{"CAMPUS_AP":{"scopes":[{"id":"1","kind":"device"},{"id":"2","kind":"device"}],
            "modules":{"policies":{"scope_results":[{"scope":sid,"effective_view":view} for sid in ("1","2")]}}}},
            "library":{"modules":{"policies":view}},
            "keyed_profile_details":{"profiles":{"CAMPUS_AP":{"1":{"policies":{"test":{
                "effective":{"status":"identity_observed","profile":policy([rule(1)])}}}}},
                "Library":{"":{"policies":{"test":{"library":{"status":"identity_observed","profile":policy([])}}}}}}}}
        groups=policy_rule_groups(data)
        qualified=[r for r in groups if r["status"]!="individual_evidence_conflict"]
        self.assertEqual(len(qualified),1)
        self.assertEqual(qualified[0]["locations"][0]["scope"],"2")
        conflicts=[r for r in groups if r["status"]=="individual_evidence_conflict"]
        self.assertEqual(len(conflicts),2)
        self.assertTrue(all(not r["findings"] and not r["order_verified"] for r in conflicts))


    def test_partial_and_reverse_containment_are_not_full_shadowing(self):
        result=rule_review("policies",policy([rule(1,source="guest",destination=None),
            rule(2,source=None,destination="staff",action="OTHER_ACTION"),
            rule(3,source=None,destination=None)]))
        pairs={(r["earlier_position"],r["later_position"]):r for r in result["findings"]}
        self.assertEqual(pairs[1,2]["condition_relationship"],"partial_overlap")
        self.assertEqual(pairs[1,2]["status"],"partial_overlap_different_action")
        self.assertEqual(pairs[1,3]["condition_relationship"],"later_contains_earlier")
        self.assertFalse(result["safe_to_apply"])


    def test_unsupported_rule_reasons_reconcile_and_action_must_be_qualified(self):
        malformed=rule(2)
        malformed["action"]={"type":42}
        extra=rule(3,**{"time-profile":"office"})
        result=rule_review("policies",policy([rule(1),malformed,extra]))
        self.assertEqual(result["qualified_match_rules"],1)
        self.assertEqual(result["unsupported_reasons"],{"action_unqualified":1,"additional_rule_fields":1})
        self.assertEqual(sum(result["unsupported_reasons"].values()),result["unsupported_rules"])
        self.assertEqual(result["findings"],[])

    def test_exact_unsupported_rule_repetition_is_structural_only(self):
        result=rule_review("policies",policy([rule(30,**{"time-profile":"office"}),
            rule(10,**{"time-profile":"office"}),rule(20,**{"time-profile":"other"}),rule(40)]))
        self.assertTrue(result["order_verified"])
        self.assertEqual(result["qualified_match_rules"],1)
        self.assertEqual(result["unsupported_rules"],3)
        self.assertEqual(len(result["findings"]),1)
        finding=result["findings"][0]
        self.assertEqual(finding["status"],"identical_unsupported_security_rule_body")
        self.assertEqual((finding["earlier_position"],finding["later_position"]),(10,30))
        self.assertNotIn("condition_relationship",finding)
        self.assertFalse(result["safe_to_apply"])
        limited=rule_review("policies",policy([rule(1,extra=True),rule(2,extra=True)]),limit=0)
        self.assertTrue(limited["truncated"])
        self.assertFalse(limited["findings"])

    def test_policy_schema_families_distinguish_documented_nonsecurity_and_invalid_shapes(self):
        from aruba_central.policy_rule_review import rule_review, policy_schema_state
        for kind,state in (("POLICY_NETWORK_ACL","network_acl"),("POLICY_QOS","qos"),
                           ("POLICY_PBR","pbr"),("POLICY_MIRROR","mirror")):
            result=rule_review("policies",{"type":kind})
            self.assertEqual(result["schema_state"],state)
            self.assertEqual(result["status"],"rule_schema_unqualified")
            self.assertFalse(result["findings"])
        for body,state in (({},"policy_type_missing"),({"type":[]},"policy_type_unrecognized"),
                           ({"type":"POLICY_TYPE_SECURITY"},"security_body_missing"),
                           ({"type":"POLICY_TYPE_SECURITY","security-policy":{}},"security_type_unqualified"),
                           ({"type":"POLICY_TYPE_SECURITY","security-policy":{"type":"SECURITY_POLICY_TYPE_DEFAULT"}},"security_rule_list_unqualified")):
            self.assertEqual(policy_schema_state("policies",body),state)
        self.assertEqual(policy_schema_state("role-acls",{}),"acl_rule_list_unqualified")
        self.assertEqual(policy_schema_state("role-acls",{"rules":[]}),"qualified")

    def test_policy_body_shape_distinguishes_empty_and_missing_rule_list(self):
        from aruba_central.policy_rule_review import policy_body_shape
        self.assertEqual(policy_body_shape({"name":"a"}),"identity_only")
        self.assertEqual(policy_body_shape({"name":"a","description":"x"}),"metadata_only")
        self.assertEqual(policy_body_shape({"name":"a","unknown":True}),"security_wrapper_missing")
        self.assertEqual(policy_body_shape({"security-policy":None}),"security_wrapper_invalid")
        self.assertEqual(policy_body_shape({"security-policy":{}}),"security_subtype_missing")
        self.assertEqual(policy_body_shape({"security-policy":{"type":"other"}}),"security_subtype_other")
        for state,rules in (("rule_list_null",None),("rule_list_invalid",{}),("rule_list_empty",[]),("rule_list_present",[rule(1)])):
            self.assertEqual(policy_body_shape({"security-policy":{"type":"SECURITY_POLICY_TYPE_DEFAULT","policy-rule":rules}}),state)
        self.assertEqual(policy_body_shape({"security-policy":{"type":"SECURITY_POLICY_TYPE_DEFAULT"}}),"rule_list_missing")
        body=policy([rule(1)])
        del body["type"]
        result=rule_review("policies",body)
        self.assertEqual(result["body_shape"],"rule_list_present")
        self.assertEqual(result["status"],"rule_schema_unqualified")
        self.assertFalse(result["order_verified"])

    def test_policy_library_body_relation_never_completes_missing_type(self):
        body=policy([rule(1)])
        partial={k:v for k,v in body.items() if k!="type"}
        view={"status":"list_parsed","profiles":{"test":partial}}
        bundle={"results":{"CAMPUS_AP":{"scopes":[{"id":"1","kind":"device"}],"modules":{
                    "policies":{"scope_results":[{"scope":"1","effective_view":view}]}}}},
                "library":{"modules":{"policies":{"status":"list_parsed","profiles":{"test":body}}}}}
        report=next(r for r in policy_rule_groups(bundle) if r["persona"]=="CAMPUS_AP")
        self.assertEqual(report["library_body_relation"],"only_missing_policy_type")
        self.assertEqual(report["status"],"rule_schema_unqualified")
        self.assertFalse(report["safe_to_apply"])
        view["profiles"]["test"]={"name":"test"}
        report=next(r for r in policy_rule_groups(bundle) if r["persona"]=="CAMPUS_AP")
        self.assertEqual(report["library_body_relation"],"different_body")
        self.assertEqual(report["body_shape"],"identity_only")

    def test_missing_outer_type_has_separate_conditional_preview(self):
        body=policy([rule(1,source=None),rule(2,action="OTHER_ACTION")])
        del body["type"]
        report=rule_review("policies",body)
        self.assertEqual(report["status"],"rule_schema_unqualified")
        self.assertFalse(report["findings"])
        self.assertFalse(report["order_verified"])
        preview=report["conditional_security_preview"]
        self.assertEqual(preview["context"],"outer_policy_type_missing")
        self.assertEqual(len(preview["findings"]),1)
        self.assertFalse(preview["safe_to_apply"])
        for other in ({**body,"type":None},{**body,"type":"POLICY_NETWORK_ACL"},{**body,"unknown":{}}):
            self.assertNotIn("conditional_security_preview",rule_review("policies",other))
        body["security-policy"]["policy-rule"]=[rule(1),rule(1)]
        self.assertFalse(rule_review("policies",body)["conditional_security_preview"]["order_verified"])
