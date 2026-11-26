import unittest
from inheritance_review import nearest_fallback


def fixture(group=None, site=None, collection=None, global_=None, group_known=True):
    scopes = [{"id": "1", "kind": "global", "name": "Global"},
              {"id": "2", "kind": "collection", "name": "Collection"},
              {"id": "3", "kind": "site", "name": "Site", "metadata": {"collectionId": "2"}},
              {"id": "4", "kind": "group", "name": "Group"},
              {"id": "5", "kind": "device", "name": "Device",
               "metadata": {"siteId": "3", **({"deviceGroupId": "4"} if group_known else {})}}]
    views = []
    for sid, value in (("1", global_), ("2", collection), ("3", site), ("4", group)):
        profiles = {} if value is None else {"20": {"vlan": 20, "name": value, "@": {
            "aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}}}
        views.append({"scope": sid, "effective_view": {"status": "list_parsed",
                       "count_confirmed": True, "profiles": profiles}})
    return {"scopes": scopes, "modules": {"layer2-vlan": {"scope_results": views}}}


class InheritanceTests(unittest.TestCase):
    def resolve(self, entry):
        body = {"vlan": 20, "name": "Office"}
        return nearest_fallback(entry, "layer2-vlan", "5", "20", body, body,
                                {"aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"})

    def test_group_match_wins_despite_global_difference(self):
        result = self.resolve(fixture(group="Office", site="Different", global_="Different"))
        self.assertEqual(result["status"], "matching_fallback")
        self.assertEqual(result["source"]["scope"], "4")
        self.assertEqual(result["differences"], [])
        self.assertFalse(result["safe_to_apply"])

    def test_global_match_does_not_make_device_override_redundant(self):
        result = self.resolve(fixture(group="Different", global_="Office"))
        self.assertEqual(result["status"], "different_fallback")
        self.assertEqual(result["source"]["scope"], "4")

    def test_count_confirmed_absence_allows_next_scope(self):
        result = self.resolve(fixture(site="Office"))
        self.assertEqual(result["status"], "matching_fallback")
        self.assertEqual(result["source"]["scope"], "3")

    def test_unknown_membership_prevents_resolution(self):
        result = self.resolve(fixture(site="Office", group_known=False))
        self.assertEqual(result["status"], "candidate_unverified")
        self.assertTrue(result["blockers"])

    def test_uncounted_absence_prevents_resolution(self):
        entry = fixture(site="Office")
        entry["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["count_confirmed"] = False
        self.assertEqual(self.resolve(entry)["status"], "candidate_unverified")


    def atomic_fixture(self, module="dns", ancestor_name="GroupDNS", ancestor_value="192.0.2.1"):
        entry = fixture()
        ann = {"aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}
        local = {"name": "DeviceDNS", "servers": ["192.0.2.1"]}
        views = entry["modules"].pop("layer2-vlan")["scope_results"]
        views[-1]["effective_view"]["profiles"] = {ancestor_name: {"name": ancestor_name, "servers": [ancestor_value], "@": ann}}
        device_view = {"status": "list_parsed", "count_confirmed": True, "profiles": {"DeviceDNS": {**local, "@": ann}}}
        views.append({"scope": "5", "local_view": device_view, "effective_view": device_view})
        entry["modules"][module] = {"scope_results": views}
        return entry, local, ann

    def test_atomic_different_name_same_settings_is_review_only(self):
        for module in ("dns", "ntp"):
            entry, local, ann = self.atomic_fixture(module)
            result = nearest_fallback(entry, module, "5", "DeviceDNS", local, local, ann)
            self.assertEqual(result["status"], "matching_settings_identity_changed")
            self.assertEqual(result["source"]["identity"], "GroupDNS")
            self.assertEqual(result["setting_differences"], [])
            self.assertTrue(result["blockers"])
            self.assertFalse(result["safe_to_apply"])

    def test_atomic_same_name_same_settings_matches(self):
        entry, local, ann = self.atomic_fixture(ancestor_name="DeviceDNS")
        result = nearest_fallback(entry, "dns", "5", "DeviceDNS", local, local, ann)
        self.assertEqual(result["status"], "matching_fallback")

    def test_atomic_different_settings_are_not_redundant(self):
        entry, local, ann = self.atomic_fixture(ancestor_value="192.0.2.2")
        result = nearest_fallback(entry, "dns", "5", "DeviceDNS", local, local, ann)
        self.assertEqual(result["status"], "different_fallback")

    def test_atomic_multiple_ancestor_profiles_are_ambiguous(self):
        entry, local, ann = self.atomic_fixture()
        profiles = entry["modules"]["dns"]["scope_results"][-2]["effective_view"]["profiles"]
        profiles["OtherDNS"] = {"name": "OtherDNS", "servers": ["192.0.2.3"], "@": ann}
        result = nearest_fallback(entry, "dns", "5", "DeviceDNS", local, local, ann)
        self.assertEqual(result["status"], "unresolved")
        self.assertIn("group atomic profile cardinality not confirmed", result["blockers"])

    def test_atomic_unconfirmed_device_cardinality_blocks_resolution(self):
        entry, local, ann = self.atomic_fixture()
        entry["modules"]["dns"]["scope_results"][-1]["effective_view"]["count_confirmed"] = False
        result = nearest_fallback(entry, "dns", "5", "DeviceDNS", local, local, ann)
        self.assertEqual(result["status"], "unresolved")
        self.assertIn("Atomic device profile cardinality not confirmed", result["blockers"])
