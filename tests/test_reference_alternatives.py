import unittest

from aruba_central.dependency_evidence import qualify_reference_edges


class ReferenceAlternativeTests(unittest.TestCase):
    def test_same_site_and_library_observations_do_not_resolve_cross_device_edges(self):
        def scope(id,kind,**metadata):
            return {"id":id,"kind":kind,"metadata":metadata}
        bundle={"results":{
            "CAMPUS_AP":{"scopes":[scope("10","site"),scope("ap","device",siteId=10)],"modules":{}},
            "ACCESS_SWITCH":{"scopes":[scope("10","site"),scope("20","site"),
                scope("sw","device",siteId=10),scope("remote","device",siteId=20),
                scope("unknown","device"),scope("conflict","device",siteId=10)],"modules":{}}},
            "library":{"modules":{"layer2-vlan":{"status":"list_parsed","profiles":{"20":{"vlan":20}}}}},
            "keyed_profile_details":{"profiles":{"ACCESS_SWITCH":{"conflict":{"layer2-vlan":{"20":{"effective":{
                "status":"identity_observed","profile":{"vlan":20,"name":"different"}}}}}}}}}
        view={"status":"list_parsed","profiles":{"20":{"vlan":20}}}
        effective={"ACCESS_SWITCH":{"layer2-vlan":{sid:view for sid in ("10","sw","remote","unknown","conflict")}}}
        ref={"persona":"CAMPUS_AP","scope":"ap","source_module":"wlan-ssids","source":"ssid",
             "source_view":"effective","target_module":"layer2-vlan","target":"20",
             "status":"unresolved","target_evidence":"target_view_unqualified"}
        records=qualify_reference_edges(bundle,[ref],effective)
        self.assertEqual(records[0]["status"],"unresolved")
        self.assertEqual(records[0]["target_evidence"],"target_view_unqualified")
        observations=records[0]["target_alternative_observations"]
        self.assertEqual({(r["context"],r["scope"]) for r in observations},
                         {("library_definition",""),("same_site_observation","10"),("same_site_observation","sw"),
                          ("same_site_observation","conflict")})
        self.assertEqual(next(r["status"] for r in observations if r["scope"]=="conflict"),"individual_evidence_conflict")
        site_ref={**ref,"scope":"10"}
        site_ref.pop("target_alternative_observations")
        records=qualify_reference_edges(bundle,[site_ref],effective)
        observations=records[0]["target_alternative_observations"]
        self.assertEqual(next(r["context"] for r in observations if r["scope"]=="10"),"other_function_same_scope")
        self.assertEqual(len([r for r in observations if r["scope"]=="10"]),1)
        self.assertEqual(records[0]["status"],"unresolved")
