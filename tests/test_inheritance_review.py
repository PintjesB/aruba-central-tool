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
