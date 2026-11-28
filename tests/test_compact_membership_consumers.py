import unittest
from aruba_central.optimization_dependencies import attach_dependency_review
from aruba_central.dependency_impact import dependency_impact
from aruba_central.vlan_membership import target_label


class CompactMembershipConsumersTests(unittest.TestCase):
    def test_matching_sets_are_consumers_not_unknown_identities(self):
        ref={"persona":"CAMPUS_AP","scope":"1","source_view":"effective","source_scope_kind":"device",
             "source_module":"ap-port-profiles","source":"port","target_module":"layer2-vlan",
             "target":None,"target_member_ranges":[[10,19],[21,30]],"target_member_count":20,
             "status":"unresolved","path":["switchport","trunk-vlan-ranges"]}
        unknown={**ref,"source":"unknown"}
        del unknown["target_member_ranges"],unknown["target_member_count"]
        refs=[ref,unknown]
        findings=[{"persona":persona,"module":"layer2-vlan","identity":identity}
                  for persona,identity in (("CAMPUS_AP","10"),("CAMPUS_AP","20"),("ACCESS_SWITCH","10"))]
        a,b,c=[f["dependency_review"] for f in attach_dependency_review(findings,refs)]
        self.assertEqual(a["consumers"],[ref])
        self.assertEqual(a["unqualified_edges"],[ref])
        self.assertEqual(a["unresolved_target_observations"],[unknown])
        self.assertEqual(a["observed_consumer_devices"],0)
        self.assertFalse(b["consumers"])
        self.assertEqual(b["unresolved_target_observations"],[unknown])
        self.assertEqual(c["other_function_consumers"],[ref])
        self.assertEqual(c["other_function_unresolved_targets"],[unknown])
        impact=dependency_impact(refs,"layer2-vlan","10")
        self.assertEqual(impact["direct"],[ref])
        self.assertEqual(impact["unresolved_target_observations"],[unknown])
        self.assertFalse(impact["paths"])
        self.assertEqual(target_label(ref),"20 VLAN set members")
        self.assertEqual(target_label(unknown),"Unknown")
