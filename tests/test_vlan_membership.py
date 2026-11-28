import unittest
from aruba_central.advanced_review import profile_reference_observations, target_reference_evidence
from aruba_central.vlan_membership import intervals,target_fields,target_matches,target_token
from aruba_central.dependency_impact import dependency_impact


class MembershipTests(unittest.TestCase):
    def test_large_range_preserves_exact_members_and_known_edges(self):
        body={"switchport":{"trunk-vlan-ranges":["1-4094"]}}
        refs=list(profile_reference_observations("ap-port-profiles","port",body,{},known_ids={"20","30"}))
        self.assertEqual(len(refs),3)
        compact=next(target for _,target,_ in refs if isinstance(target,tuple))
        self.assertEqual(compact,((1,19),(21,29),(31,4094)))
        fields=target_fields({},compact)
        self.assertEqual(fields["target_member_count"],4092)
        self.assertEqual(target_token(fields),compact)
        ref={"persona":"CAMPUS_AP","scope":"1","source_module":"ap-port-profiles","source":"port",
             "source_view":"effective","target_module":"layer2-vlan",**fields,
             "status":"unresolved","target_evidence":"set_target_view_unqualified","path":["switchport","trunk-vlan-ranges"]}
        self.assertTrue(target_matches(ref,"layer2-vlan","4094"))
        self.assertFalse(target_matches(ref,"layer2-vlan","20"))
        self.assertFalse(target_matches(ref,"layer2-vlan","4095"))
        self.assertFalse(target_matches(ref,"roles","4094"))
        self.assertEqual(len(dependency_impact([ref],"layer2-vlan","4094")["direct"]),1)
        self.assertEqual(len(dependency_impact([ref],"layer2-vlan","20")["direct"]),0)
        self.assertEqual(len(dependency_impact([ref],"layer2-vlan","20")["unresolved_target_observations"]),0)
        self.assertFalse(dependency_impact([ref],"layer2-vlan","4094")["paths"])
        self.assertEqual(target_reference_evidence({},compact),("unresolved","set_target_view_unqualified"))
        self.assertEqual(target_reference_evidence({"status":"list_parsed","count_confirmed":True},compact),
                         ("not_observed","set_count_confirmed_absence"))
        self.assertEqual(intervals({"1","3","4"}),((1,1),(3,4)))
