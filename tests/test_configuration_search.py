import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.configuration_search import search_configuration, grouped_search
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

    def test_exact_evidence_link_does_not_substitute_another_profile(self):
        bundle = fixture()
        rows = search_configuration(bundle, "10", module="layer2-vlan")["matches"]
        row = next(r for r in rows if r["identity"] == "10")
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            row = next(r for r in search_configuration(reviewed, "10", module="layer2-vlan")["matches"] if r["identity"] == "10")
            query = {"snapshot": name, "mode": "evidence", "persona": row["persona"],
                     "module": row["module"], "scope": row["scope"], "evidence": row["evidence_id"]}
            html = workspace.report(query)
            self.assertIn("Captured configuration evidence", html)
            self.assertIn("Complete captured value", html)
            with self.assertRaises(ValueError):
                workspace.report({**query, "evidence": "0" * 64})
            with self.assertRaises(ValueError):
                workspace.report({**query, "scope": "nonexistent"})

    def test_search_batches_are_complete_and_disjoint(self):
        bundle = fixture()
        all_rows = search_configuration(bundle, "10", module="layer2-vlan", limit=1000)
        total = all_rows["total"]
        self.assertGreater(total, 2)
        expected = all_rows["matches"]
        observed = []
        for offset in range(0, total, 2):
            batch = search_configuration(bundle, "10", module="layer2-vlan", limit=2, offset=offset)
            self.assertEqual(batch["total"], total)
            self.assertEqual(batch["truncated"], offset + len(batch["matches"]) < total)
            observed.extend(batch["matches"])
        self.assertEqual(observed, expected)
        with self.assertRaises(ValueError):
            search_configuration(bundle, "10", offset=-1)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "10", "offset": "300"})
            self.assertIn("Previous result batch", html)
            self.assertIn("loaded batch only", html)

    def test_grouped_search_preserves_types_and_evidence_sources(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        for scope in entry["modules"]["layer2-vlan"]["scope_results"]:
            if scope["scope"] in ("3", "4"):
                scope["effective_view"] = {"status": "list_parsed", "profiles": {"10": {"test-needle": False}}}
        entry["modules"]["layer2-vlan"]["scope_results"][0]["effective_view"]["profiles"]["10"]["test-needle"] = 0
        groups = grouped_search(bundle, "test-needle", module="layer2-vlan")
        false_group = next(g for g in groups["groups"] if g["selector"][-1] is False)
        self.assertEqual(false_group["devices"], 2)
        self.assertEqual(false_group["observations"], 2)
        self.assertTrue(any(type(g["selector"][-1]) is int for g in groups["groups"]))
        rows = search_configuration(bundle, "test-needle", module="layer2-vlan", group=false_group["id"])
        self.assertEqual(rows["total"], 2)
        self.assertTrue(all(r["value"] is False for r in rows["matches"]))
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "test-needle", "presentation": "grouped"})
            self.assertIn("distinct field/value groups", html)
            self.assertIn("Inspect matching observations", html)
