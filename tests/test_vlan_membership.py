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

    def test_large_capture_is_bounded_and_preserves_every_observed_identity(self):
        from aruba_central.advanced_review import advanced_analysis
        from aruba_central.vlan_membership import member_count
        from aruba_central.engineering_qualification import reference_absence_patterns
        def scope(sid):
            return {"id":sid,"kind":"device","name":sid}
        def view(profiles):
            return {"status":"list_parsed","profiles":profiles,"count_confirmed":True}
        def module(ids,profiles):
            return {"scope_results":[{"scope":sid,"effective_view":view(profiles)} for sid in ids]}
        aps=[str(i) for i in range(1,58)]
        switches=["100","101","102","103"]
        vlans={str(i):{"vlan":i} for i in range(1,30)}
        trunk={"port":{"profile-name":"port","switchport":{"trunk-vlan-ranges":["1-4094"]}}}
        stp={"stp":{"mstp":[{"mstp-vlans":["1-4094"]}]}}
        bundle={"results":{
            "CAMPUS_AP":{"scopes":[scope(sid) for sid in aps],"modules":{"ap-port-profiles":module(aps,trunk)}},
            "ACCESS_SWITCH":{"scopes":[scope(sid) for sid in switches],"modules":{
                 "layer2-vlan":module(switches,vlans),"stp":module(switches,stp)}}},
            "library":{"modules":{"ap-port-profiles":view(trunk),"layer2-vlan":view(vlans)}}}
        refs=advanced_analysis(bundle)["references"]
        ap_refs=[r for r in refs if r["source_module"]=="ap-port-profiles"]
        stp_refs=[r for r in refs if r["source_module"]=="stp"]
        self.assertEqual(len(ap_refs),58*30)
        self.assertEqual(len(stp_refs),4*30)
        self.assertEqual(sum(member_count(r) for r in ap_refs),58*4094)
        self.assertEqual(sum(member_count(r) for r in stp_refs),4*4094)
        self.assertEqual(sum(r.get("target_member_count",0) for r in stp_refs),4*(4094-29))
        self.assertEqual({r["target"] for r in stp_refs if r["status"]=="observed"},set(vlans))
        self.assertEqual(sum(r["observations"] for r in reference_absence_patterns(stp_refs)),4*(4094-29))
        for identity in ("1","29","30","4094"):
            impact=dependency_impact(stp_refs,"layer2-vlan",identity)
            self.assertEqual(len(impact["direct"]),4)
        self.assertFalse(dependency_impact(stp_refs,"layer2-vlan","4095")["direct"])

    def test_direct_scalar_reference_is_never_compacted(self):
        from aruba_central.vlan_membership import member_targets
        ids={str(i) for i in range(1,100)}
        self.assertEqual(len(list(member_targets(ids,"stp",["unknown","vlan"],set()))),99)
        self.assertEqual(list(member_targets(ids,"stp",["mstp",0,"mstp-vlans"],set())),[((1,99),)])
