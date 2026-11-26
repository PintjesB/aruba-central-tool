import unittest
from advanced_review import advanced_analysis


def view(profiles):
    return {"status": "list_parsed", "profiles": profiles}


class AdvancedTests(unittest.TestCase):
    def test_grouping_references_and_shadowing(self):
        scopes = [{"id": "1", "kind": "global", "name": "Global"},
                  {"id": "2", "kind": "device", "name": "A"},
                  {"id": "3", "kind": "device", "name": "B"}]
        port = {"switchport": {"access-vlan": 10}, "routing": False}
        vlan = {"vlan": 10, "name": "local", "@": {
            "aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}}
        def module(mapping):
            return {"scope_results": [{"scope": sid, "effective_view": v} for sid, v in mapping.items()]}
        bundle = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
            "ethernet-interfaces": module({"2": view({"1": {"name": "1", **port},
                                                       "2": {"name": "2", "description": "desk", **port},
                                                       "3": {"name": "3", "sw-profile": "existing"},
                                                       "4": {"name": "4", "lag": {"id": 1}, **port}}),
                                           "3": view({"1": {"name": "1", **port}})}),
            "layer2-vlan": module({"1": view({"10": {"vlan": 10, "name": "global"}}),
                                   "2": view({"10": vlan}),
                                   "3": {"status": "empty_object", "profiles": {}}}),
            "sw-port-profiles": module({"2": view({"existing": {"profile-name": "existing"}})})}}},
            "library": {"modules": {"sw-port-profiles": view({
                "a": {"profile-name": "a", **port}, "b": {"profile-name": "b", **port}})}}}
        data = advanced_analysis(bundle)
        self.assertEqual(len(data["port_groups"]), 1)
        self.assertEqual(len(data["port_groups"][0]["ports"]), 3)
        self.assertEqual([m["identity"] for m in data["port_groups"][0]["matching_library_profiles"]], ["a", "b"])
        self.assertEqual(len(data["port_groups"][0]["proposed_mapping"]), 3)
        self.assertTrue(data["port_groups"][0]["dependencies"])
        self.assertEqual(data["library_duplicates"][0]["identities"], ["a", "b"])
        self.assertEqual(data["shadowed"][0]["relationship"], "different_body")
        self.assertTrue(any(r["target"] == "existing" and r["status"] == "observed" for r in data["references"]))
        self.assertTrue(any(r["scope"] == "3" and r["status"] == "unresolved" for r in data["references"]))
        self.assertFalse(data["reference_graph_complete"])
        self.assertFalse(data["safe_to_apply"])

    def test_group_shadows_site_and_global_when_membership_and_source_are_observed(self):
        scopes = [{"id": "1", "kind": "global", "name": "Global"},
                  {"id": "2", "kind": "site", "name": "Site", "metadata": {"id": 20}},
                  {"id": "3", "kind": "group", "name": "Group", "metadata": {"id": 30}},
                  {"id": "4", "kind": "device", "name": "Switch",
                   "metadata": {"siteId": 20, "deviceGroupId": 30}}]
        direct = {"aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}
        inherited = {**direct, "aruba-annotation:inherited": True}
        def vlan(name, ann):
            return view({"10": {"vlan": 10, "name": name, "@": ann}})
        data = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
            "layer2-vlan": {"scope_results": [
                {"scope": "1", "effective_view": vlan("Global", direct)},
                {"scope": "2", "effective_view": vlan("Site", direct)},
                {"scope": "3", "effective_view": vlan("Group", direct)},
                {"scope": "4", "effective_view": vlan("Group", inherited)}]}}}}}
        findings = advanced_analysis(data)["shadowed"]
        self.assertEqual({f["winning_scope"] for f in findings}, {"Group"})
        self.assertEqual({f["higher_scope"] for f in findings}, {"Site", "Global"})
        scopes[-1]["metadata"].pop("deviceGroupId")
        self.assertEqual(advanced_analysis(data)["shadowed"], [])
