import json
import unittest

from aruba_central.engineering_qualification import reference_identity_patterns


class FocusedEngineeringTests(unittest.TestCase):
    def test_reference_patterns_preserve_documented_fields_and_hide_values(self):
        base={"status":"unresolved","target":None,"source_module":"roles","target_module":"layer2-vlan",
              "source":"private-profile","scope":"private-scope","source_view":"effective"}
        records=[{**base,"path":["private-wrapper",0,"access-vlan-name"]},
                 {**base,"path":["private-wrapper",5,"access-vlan-name"]},
                 {**base,"path":["private-key"]},
                 {**base,"path":["private-key"],"source_module":"private-module","source_view":"private-view"},
                 {**base,"path":["private-key"],"status":"conflicting_observation"},
                 {**base,"path":["private-key"],"source_evidence":"nac_enforcement"},
                 {**base,"path":["private-key"],"target":"private-target"}]
        report=reference_identity_patterns(records)
        self.assertEqual(sum(r["observations"] for r in report),4)
        self.assertEqual(report[0],{"source_module":"roles","target_module":"layer2-vlan",
                                    "field":"access-vlan-name","path_shape":"list_member",
                                    "source_view":"effective","source_value_shape":"unknown","observations":2})
        self.assertNotIn("private",json.dumps(report))
        self.assertTrue(any(r["source_module"]=="other" and r["source_view"]=="other" for r in report))

    def test_unknown_value_shape_is_allowlisted(self):
        base={"status":"unresolved","target":None,"source_module":"roles","target_module":"layer2-vlan",
              "path":["access-vlan-name"],"source_view":"effective"}
        report=reference_identity_patterns([{**base,"source_value_shape":"empty_string"},
                                           {**base,"source_value_shape":"private-value"}])
        self.assertEqual({r["source_value_shape"] for r in report},{"empty_string","unknown"})
        self.assertNotIn("private",json.dumps(report))

    def test_role_vlan_name_evidence_hides_names_ids_and_unknown_values(self):
        from aruba_central.engineering_qualification import role_vlan_name_evidence
        ref={"status":"unresolved","role_vlan_name_review":{"field_context":"gateway_access_vlan_name",
             "status":"single_candidate_id","configured_name":"private-name","observations":[
                 {"context":"library_vlan_name","status":"identity_observed","vlan_id":"private-id"},
                 {"context":"library_vlan_name","status":"identity_observed","vlan_id":"private-id2"},
                 {"context":"private-context","status":"identity_observed"}]}}
        result=role_vlan_name_evidence([ref,ref,{**ref,"status":"conflicting_observation"}])
        self.assertEqual(result,[{"field_context":"gateway_access_vlan_name","status":"single_candidate_id",
                                  "positive_contexts":["library_vlan_name"],"observations":2}])
        self.assertNotIn("private",json.dumps(result))

    def test_named_gap_field_patterns_count_distinct_targets_without_leaking_values(self):
        from aruba_central.engineering_qualification import named_reference_field_gaps
        base={"status":"unresolved","target":"private-id","persona":"CAMPUS_AP","scope":"private-scope",
              "source":"private-source","source_view":"effective","source_module":"ap-port-profiles",
              "target_module":"layer2-vlan","path":["switchport","trunk-vlan-ranges"],
              "target_evidence":"target_view_unqualified"}
        result=named_reference_field_gaps([base,{**base,"scope":"private-other"},
                 {**base,"target_alternative_observations":[{"status":"identity_observed","context":"library_definition"}]}])
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["observations"],2)
        self.assertEqual(result[0]["distinct_source_fields"],2)
        self.assertEqual(result[0]["distinct_target_identities"],1)
        self.assertEqual(result[0]["field"],"trunk-vlan-ranges")
        self.assertNotIn("private",json.dumps(result))

    def test_target_groups_deduplicate_across_reason_buckets(self):
        from aruba_central.engineering_qualification import named_reference_target_groups
        base={"status":"unresolved","target":"private-id","target_module":"layer2-vlan",
              "target_evidence":"target_view_unqualified"}
        result=named_reference_target_groups([base]*57+[
            {**base,"target_evidence":"target_collection_incomplete"},
            {**base,"target":"private-other"},
            {**base,"target_alternative_observations":[{"status":"identity_observed","context":"library_definition"}]},
            {**base,"source_evidence":"nac_enforcement"}])
        self.assertEqual(result,[{"target_module":"layer2-vlan","distinct_target_identities":2,
            "observations":59,"reason_groups":{"multiple_reasons":1,"target_view_unqualified":1}}])
        self.assertNotIn("private",json.dumps(result))
