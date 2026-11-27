import unittest
from aruba_central.source_review import source_trace
from test_inheritance_review import fixture


class SourceTests(unittest.TestCase):
    def test_nearest_direct_source_and_different_global(self):
        entry = fixture(group="Office", global_="Different")
        ann = {"aruba-annotation:inherited": True, "aruba-annotation:object_type": "LOCAL"}
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20, "name": "Office", "@": ann}}}})
        bundle = {"results": {"ACCESS_SWITCH": entry}}
        result = source_trace(bundle, "ACCESS_SWITCH", "5", "layer2-vlan", "20")
        self.assertEqual(result["observed_source_scope"], "4")
        self.assertEqual(result["chain"][-1]["status"], "direct_difference")
        self.assertFalse(result["safe_to_apply"])

    def test_unknown_group_does_not_prove_site_source(self):
        entry = fixture(site="Office", group_known=False)
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20, "name": "Office", "@": {"aruba-annotation:inherited": True}}}}})
        result = source_trace({"results": {"ACCESS_SWITCH": entry}}, "ACCESS_SWITCH", "5", "layer2-vlan", "20")
        self.assertIsNone(result["observed_source_scope"])
        self.assertIn("3", result["matching_direct_scopes"])
        self.assertTrue(result["blockers"])
