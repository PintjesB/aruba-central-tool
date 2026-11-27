import unittest
from aruba_central.dependency_impact import dependency_impact


def edge(source, target, scope="1", view="effective", state="observed", persona="ACCESS_SWITCH"):
    return {"source_module": source[0], "source": source[1],
            "target_module": target[0], "target": target[1],
            "scope": scope, "persona": persona, "device": scope, "path": ["reference"],
            "source_view": view, "status": state}


class ImpactTests(unittest.TestCase):
    def test_transitive_paths_keep_scopes_separate_and_stop_cycles(self):
        vlan = ("layer2-vlan", "20")
        profile = ("sw-port-profiles", "Office")
        port = ("ethernet-interfaces", "1/1/1")
        refs = [edge(profile, vlan), edge(port, profile), edge(vlan, port),
                edge(("ethernet-interfaces", "2/1/1"), profile, scope="2"),
                edge(("roles", "guest"), vlan, view="saved"),
                edge(("roles", "unknown"), ("layer2-vlan", None), state="unresolved")]
        result = dependency_impact(refs, *vlan)
        self.assertEqual({(p["module"], p["identity"], p["depth"]) for p in result["paths"] if p["direction"] == "consumers"},
                         {("sw-port-profiles", "Office", 1), ("ethernet-interfaces", "1/1/1", 2)})
        self.assertTrue(all(p["scope"] == "1" for p in result["paths"]))
        self.assertEqual(len(result["direct"]), 3)
        self.assertEqual(len(result["unresolved_target_observations"]), 1)
        self.assertFalse(result["complete"])

    def test_unresolved_edges_not_traversed_and_library_separate(self):
        root = ("roles", "employee")
        refs = [edge(root, ("object-groups", "missing"), state="not_observed"),
                edge(("wlan-ssids", "Office"), root, persona="Library", scope="Library", view="library", state="definition_observed")]
        result = dependency_impact(refs, *root)
        self.assertEqual(len(result["direct"]), 2)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["persona"], "Library")
        self.assertFalse(dependency_impact(refs, *root, persona="ACCESS_SWITCH")["paths"])
        self.assertTrue(dependency_impact(refs, *root, limit=0)["truncated"])

    def test_workspace_page(self):
        import json
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from test_consolidation import fixture
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-test.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            page = Workspace(directory).impact({"snapshot": name, "module": "layer2-vlan", "identity": "10"})
            self.assertIn("Resolved reference chains", page)
            self.assertIn("Direct references", page)
            self.assertIn('data-nav="Dependency impact" aria-current="page"', page)
