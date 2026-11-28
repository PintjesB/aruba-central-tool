import unittest

from aruba_central.dependency_evidence import qualify_reference_edges


class RoleVlanNameTests(unittest.TestCase):
    def test_exact_role_vlan_name_candidates_do_not_resolve_or_cross_site(self):
        def scope(id,kind,**metadata):
            return {"id":id,"kind":kind,"metadata":metadata}
        bundle={"results":{
            "CAMPUS_AP":{"scopes":[scope("10","site"),scope("ap","device",siteId=10)],"modules":{}},
            "ACCESS_SWITCH":{"scopes":[scope("10","site"),scope("20","site"),
                scope("sw","device",siteId=10),scope("remote","device",siteId=20)],"modules":{}}},
            "library":{"modules":{"layer2-vlan":{"status":"list_parsed","profiles":{"20":{"name":"exact"}}}}}}
        def view(profiles):
            return {"status":"list_parsed","profiles":profiles}
        effective={"CAMPUS_AP":{"roles":{"ap":view({"role":{"access-vlan-name":"exact"}})}},
                   "ACCESS_SWITCH":{"layer2-vlan":{"sw":view({"20":{"name":"exact"},"21":{"name":"EXACT"}}),
                                                    "remote":view({"30":{"name":"exact"}})}}}
        base={"persona":"CAMPUS_AP","scope":"ap","source_module":"roles","source":"role","source_view":"effective",
              "target_module":"layer2-vlan","target":None,"path":["access-vlan-name"],
              "status":"unresolved","target_evidence":"identity_unqualified"}
        record=qualify_reference_edges(bundle,[dict(base)],effective)[0]
        self.assertEqual(record["status"],"unresolved")
        self.assertIsNone(record["target"])
        review=record["role_vlan_name_review"]
        self.assertEqual(review["status"],"single_candidate_id")
        self.assertEqual(review["field_context"],"gateway_access_vlan_name")
        self.assertEqual({(obs["context"],obs["vlan_id"]) for obs in review["observations"]},
                         {("library_vlan_name","20"),("same_site_vlan_name","20")})
        effective["ACCESS_SWITCH"]["layer2-vlan"]["sw"]["profiles"]["22"]={"name":"exact"}
        review=qualify_reference_edges(bundle,[dict(base)],effective)[0]["role_vlan_name_review"]
        self.assertEqual(review["status"],"multiple_candidate_ids")
        self.assertFalse(review["safe_to_apply"])
        effective["CAMPUS_AP"]["roles"]["ap"]["profiles"]["role"]={"access-vlan-name":"missing"}
        review=qualify_reference_edges(bundle,[dict(base)],effective)[0]["role_vlan_name_review"]
        self.assertEqual(review["status"],"no_observed_candidate")
        self.assertFalse(review["observations"])
