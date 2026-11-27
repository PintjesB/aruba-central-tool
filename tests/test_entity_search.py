import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.entity_search import find_entities
from test_consolidation import fixture


class EntitySearchTests(unittest.TestCase):
    def test_entity_search_deduplicates_saved_and_effective_and_links_exact_identity(self):
        bundle = fixture()
        result = find_entities(bundle, '"Switch A" "Local repeat"', category="profile")
        self.assertTrue(result["rows"])
        vlan = [r for r in result["rows"] if r["module"] == "layer2-vlan"]
        self.assertEqual(len(vlan), 1)
        self.assertEqual(vlan[0]["identity"], "20")
        self.assertEqual(vlan[0]["scope"], "3")
        self.assertIn("Saved and effective", vlan[0]["state"])
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.report({"snapshot": name, "mode": "entities", "q": '"Switch A" "Local repeat"', "entity_category": "profile"})
            self.assertIn("Find devices and profiles", html)
            self.assertIn("identity=20", html)
            self.assertIn("scope=3", html)
            detail = workspace.report({"snapshot": name, "persona": "ACCESS_SWITCH", "scope": "3",
                                        "module": "layer2-vlan", "identity": "20", "view": "all"})
            self.assertIn("1 records", detail)
            self.assertIn("Exact profile:", detail)
            self.assertIn("20 · Local repeat", detail)
            self.assertNotIn("40 · Exception", detail)
            self.assertIn("mode=entities", workspace.home({"snapshot": name}))

    def test_search_counts_all_types_but_paginates_selected_category(self):
        bundle = fixture()
        result = find_entities(bundle, "Switch", category="device", limit=1)
        self.assertEqual(result["total"], 2)
        self.assertEqual(len(result["rows"]), 1)
        self.assertGreater(result["counts"]["profile"], 0)
        second = find_entities(bundle, "Switch", category="device", limit=1, offset=1)
        self.assertNotEqual(result["rows"][0]["identity"], second["rows"][0]["identity"])


    def test_saved_and_effective_names_are_both_searchable(self):
        bundle = fixture()
        row = bundle["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][2]
        row["effective_view"]["profiles"]["20"]["name"] = "Effective-only-label"
        result = find_entities(bundle, "Effective-only-label", category="profile")
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["identity"], "20")
        self.assertIn("Effective-only-label", result["rows"][0]["alternate_label"])
