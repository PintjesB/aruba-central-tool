import json
import unittest
from unittest.mock import patch
from aruba_central.engineering_qualification import engineering_qualification,FIELDS


class EngineeringQualificationTests(unittest.TestCase):
    def test_only_fixed_numeric_fields_exported(self):
        report={category:{key:1 for key in fields} for category,fields in FIELDS.items()}
        report["captured_at"]="private-marker"
        report["engineering"]["private-name"]="private-marker"
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            result=engineering_qualification({})
            self.assertNotIn("private",json.dumps(result))
            self.assertEqual(result["counts"]["identity_collisions"]["linked_same_context_responses"],1)
            report["engineering"]["conditional_nac_observations"]="private-marker"
            with self.assertRaises(ValueError):
                engineering_qualification({})


    def test_gap_reasons_reconcile_without_exporting_exact_scope_or_identity(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        from unittest.mock import patch
        data=fixture()
        data["library"]["assignments"]["rows"]=[
            {"profile-type":"layer2-vlan","profile-instance":"30","device-function":"UNOBSERVED_FUNCTION","scope-id":"private-scope"}]
        engineering={"library_duplicates":[],"port_groups":[],"shadowed":[],"references":[
            {"status":"conflicting_observation","target":"private-target","source_body_conflict":True,"target_body_conflict":False},
            {"status":"conflicting_observation","target":"private-target","source_body_conflict":True,"target_body_conflict":True},
            {"status":"unresolved","target":None},
            {"status":"not_observed","target":"private-target"},
            {"status":"conditional_enforcement_candidate","source_evidence":"nac_enforcement","target":"private-target"}]}
        report=assessment(data,engineering=engineering)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value=data),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification(data)["counts"]
        e=counts["engineering"]
        self.assertEqual(e["source_only"],1)
        self.assertEqual(e["both_ends"],1)
        self.assertEqual(e["unknown_identity"],1)
        self.assertEqual(e["named_target_not_observed"],1)
        self.assertEqual(e["unresolved_references"],4)
        self.assertEqual(e["conditional_nac_observations"],1)
        self.assertEqual(counts["assignments"]["function_not_collected"],1)
        self.assertEqual(counts["assignments"]["unknown_scopes"],1)
        self.assertNotIn("private-",json.dumps(counts))

    def test_policy_gap_breakdown_uses_only_fixed_category_names(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        base={"findings":[],"unsupported_rules":2,"status":"captured_order_review","order_verified":True,"truncated":False}
        rules=[{**base,"module":"policies","unsupported_reasons":{"unsupported_address_shape":1,"private-rule":1}},
               {**base,"module":"role-acls","acl_unsupported_reasons":{"vrf_unqualified":2,"private-acl":1}}]
        sequences=[{"status":"order_observed","target_context":"unfiltered_function","references":[
            {"status":"target_unverified"},{"status":"target_unverified"}],"findings":[],"truncated":False},
            {"status":"order_observed","target_context":"private-context","references":[
            {"status":"not_observed"}],"findings":[],"truncated":False}]
        report=assessment(fixture(),rules=rules,sequences=sequences)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification({})["counts"]
        self.assertEqual(counts["policy_rules"]["security_unsupported_address_shape"],1)
        self.assertEqual(counts["policy_rules"]["acl_vrf_unqualified"],2)
        self.assertEqual(counts["policy_sequences"]["gap_context_unfiltered_function"],2)
        self.assertEqual(counts["policy_sequences"]["gap_context_unknown"],1)
        self.assertEqual(counts["policy_sequences"]["unqualified_targets"],3)
        self.assertEqual(counts["policy_sequences"]["target_not_observed"],1)
        self.assertNotIn("private-",json.dumps(counts))

    def test_engineering_contradiction_counts_remain_anonymous(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        engineering={"library_duplicates":[],"shadowed":[],"precedence_conflicts":[{"private":"scope"}],
            "port_groups":[{"ports":[{},{}],"conversion_review":[{"status":"individual_evidence_conflict"}],
                "conflicting_library_matches":[{"identity":"private-profile"}],
                "matching_library_profiles":[{"visibility":[{"status":"individual_evidence_conflict"}]}]}],
            "references":[{"status":"unresolved","target":"private-target","target_evidence":"target_collection_incomplete"}]}
        report=assessment(fixture(),engineering=engineering)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification({})["counts"]["engineering"]
        for key in ("precedence_conflicts","port_conversion_conflicts","port_library_conflicts","port_visibility_conflicts","reference_target_collection_incomplete"):
            self.assertEqual(counts[key],1)
        self.assertNotIn("private-",json.dumps(counts))

    def test_unresolved_scope_keyed_evidence_is_counted_without_claiming_recipients(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        data=fixture()
        row={"profile-type":"layer2-vlan","profile-instance":"30","device-function":"ACCESS_SWITCH","scope-id":"private-scope"}
        data["library"]["assignments"]["rows"]=[row]
        data["keyed_assignment_details"]={"records":[{"selector":row,"status":"identity_observed"}]}
        engineering={"library_duplicates":[],"port_groups":[],"shadowed":[],"references":[
            {"status":"unresolved","target":"private-target","target_individual_status":"identity_observed"}]}
        report=assessment(data,engineering=engineering)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value=data),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification(data)["counts"]
        self.assertEqual(counts["assignments"]["unresolved_scope_keyed_identity_observed"],1)
        self.assertEqual(counts["assignments"]["unknown_scopes"],1)
        self.assertEqual(counts["engineering"]["unresolved_reference_target_individual_identity"],1)
        self.assertNotIn("private-",json.dumps(counts))

    def test_policy_family_and_alternate_context_counts_are_fixed_and_not_double_counted(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        base={"findings":[],"unsupported_rules":0,"status":"rule_schema_unqualified","order_verified":False,"truncated":False}
        rules=[{**base,"module":"policies","schema_state":"network_acl"},{**base,"module":"policies","schema_state":"private-marker"}]
        sequences=[{"status":"order_observed","target_context":"unfiltered_function","references":[
            {"status":"rule_schema_unqualified","schema_state":"network_acl","alternative_observations":[
                {"context":"library_definition","status":"identity_observed"},
                {"context":"library_definition","status":"identity_observed"},
                {"context":"other_function_same_scope","status":"individual_evidence_conflict"}]},
            {"status":"target_unverified","alternative_observations":[{"context":"private-marker","status":"identity_observed"}]}],
            "findings":[],"truncated":False}]
        report=assessment(fixture(),rules=rules,sequences=sequences)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification({})["counts"]
        self.assertEqual(counts["policy_rules"]["schema_network_acl"],1)
        self.assertEqual(counts["policy_rules"]["schema_unknown"],1)
        self.assertEqual(counts["policy_sequences"]["alternative_any"],1)
        self.assertEqual(counts["policy_sequences"]["schema_network_acl"],1)
        self.assertEqual(counts["policy_sequences"]["alternative_library_definition"],1)
        self.assertEqual(counts["policy_sequences"]["alternative_other_function_same_scope"],0)
        self.assertNotIn("private-marker",json.dumps(counts))

    def test_library_preview_counts_remain_separate_from_effective_candidates(self):
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        rules=[{"findings":[],"unsupported_rules":0,"status":"rule_schema_unqualified","order_verified":False,
                "truncated":False,"module":"policies","body_shape":"identity_only","library_body_relation":"different_body"}]
        sequences=[{"status":"order_observed","target_context":"unfiltered_function","references":[{"status":"target_unverified"}],
                    "findings":[],"truncated":False,"library_preview":{"findings":[{"private":"marker"}],"truncated":False,
                    "references":[{"status":"rules_observed"},{"status":"rule_schema_unqualified"}]}}]
        report=assessment(fixture(),rules=rules,sequences=sequences)
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            counts=engineering_qualification({})["counts"]
        self.assertEqual(counts["policy_rules"]["body_shape_identity_only"],1)
        self.assertEqual(counts["policy_rules"]["library_relation_different_body"],1)
        self.assertEqual(counts["policy_sequences"]["cross_policy_candidates"],0)
        self.assertEqual(counts["policy_sequences"]["library_preview_candidates"],1)
        self.assertEqual(counts["policy_sequences"]["library_preview_qualified_targets"],1)
        self.assertEqual(counts["policy_sequences"]["library_preview_unqualified_targets"],1)
        self.assertNotIn("private",json.dumps(counts))

    def test_named_reference_gap_qualification_uses_only_fixed_contexts(self):
        from aruba_central.engineering_qualification import named_reference_gaps
        from aruba_central.assessment_review import assessment
        from test_consolidation import fixture
        ref={"status":"unresolved","target":"private-vlan","source_module":"wlan-ssids","target_module":"layer2-vlan",
             "target_evidence":"target_view_unqualified","target_alternative_observations":[
                {"context":"same_site_observation","status":"identity_observed","scope":"private-site"},
                {"context":"same_site_observation","status":"identity_observed"},
                {"context":"library_definition","status":"individual_evidence_conflict"},
                {"context":"private-context","status":"identity_observed"}]}
        records=[ref,{**ref,"target_alternative_observations":[]}]
        report=named_reference_gaps(records)
        self.assertEqual(sum(r["observations"] for r in report),2)
        self.assertEqual({tuple(r["positive_contexts"]) for r in report},{(),("same_site_observation",)})
        self.assertNotIn("private",json.dumps(report))
        engineering={"references":records,"port_groups":[],"library_duplicates":[],"shadowed":[]}
        counts=assessment(fixture(),engineering=engineering)["engineering"]
        self.assertEqual(counts["reference_alternative_any"],1)
        self.assertEqual(counts["reference_alternative_none"],1)
        self.assertEqual(counts["reference_alternative_same_site_observation"],1)
        self.assertEqual(counts["reference_alternative_library_definition"],0)

    def test_absent_vlan_set_members_are_not_conflated_with_direct_references(self):
        from aruba_central.assessment_review import assessment
        from aruba_central.engineering_qualification import reference_absence_patterns
        from test_consolidation import fixture
        base={"status":"not_observed","target_evidence":"count_confirmed_absence","target_module":"layer2-vlan",
              "persona":"ACCESS_SWITCH","scope":"private-scope","source":"private-source","source_view":"effective"}
        refs=[{**base,"source_module":"stp","path":["mstp",0,"mstp-vlans"],"target":str(i)} for i in range(10,100)]
        refs += [{**base,"source_module":"ethernet-interfaces","path":["switchport","native-vlan"],"target":"20"},
                 {**base,"source_module":"named-vlan","path":["vlan","vlan-id-ranges"],"target":"30"},
                 {**base,"source_module":"other","path":["mstp",0,"mstp-vlans"],"target":"40"},
                 {**base,"source_module":"stp","path":["mstp",0,"mstp-vlans"],"target":"20","status":"conflicting_observation"}]
        counts=assessment(fixture(),engineering={"references":refs,"port_groups":[],"library_duplicates":[],"shadowed":[]})["engineering"]
        self.assertEqual(counts["reference_absence_vlan_stp_member"],90)
        self.assertEqual(counts["reference_absence_vlan_selection_member"],1)
        self.assertEqual(counts["reference_absence_direct_or_unclassified"],2)
        self.assertEqual(counts["reference_absent_set_source_fields"],2)
        self.assertEqual(counts["unresolved_references"],94)
        report=reference_absence_patterns(refs)
        self.assertEqual(sum(r["observations"] for r in report),93)
        self.assertNotIn("private",json.dumps(report))
