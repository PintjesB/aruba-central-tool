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
