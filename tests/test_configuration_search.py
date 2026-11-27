import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.configuration_search import search_configuration
from aruba_central.config_app import Workspace
from test_consolidation import fixture


class ConfigurationSearchTests(unittest.TestCase):
    def test_search_distinguishes_sources_and_caps_results(self):
        bundle = fixture()
        bundle["unadapted_profiles"] = {"example-module": {"source_views": [{
            "persona": "ACCESS_SWITCH", "scope": "3", "committed": {"status": "response_received", "raw": {"nested": {"value": "needle-private"}}},
            "effective": {}}], "library": {}}}
        bundle["keyed_profile_details"] = {"profiles": {"ACCESS_SWITCH": {"3": {"layer2-vlan": {"10": {
            "local": {"status": "identity_observed", "profile": {"name": "needle-private"}},
            "effective": {"status": "collection_only_sampled", "profile": {"name": "needle-private"}}}}}}}}
        result = search_configuration(bundle, "needle-private", limit=1)
        self.assertEqual(result["total"], 2)
        self.assertTrue(result["truncated"])
        rows = search_configuration(bundle, "needle-private")["matches"]
        self.assertEqual({r["source"] for r in rows}, {"supplemental", "individual"})
        raw = search_configuration(bundle, "nested needle-private", module="example-module")["matches"]
        self.assertEqual(raw[0]["path"], ["nested", "value"])
        self.assertEqual(raw[0]["scope"], "3")
        self.assertEqual(search_configuration(bundle, "needle-private", persona="Library")["total"], 0)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "needle-private"})
            self.assertIn("2 matching fields", html)
            self.assertIn("Inspect source", html)
            self.assertIn("nested.value", html)
