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


    def test_indirect_unqualified_boundary_is_not_a_resolved_path(self):
        root=("roles","root")
        intermediate=("policies","p")
        blocked=("object-groups","target")
        refs=[edge(root,intermediate),edge(intermediate,blocked,state="conflicting_observation"),
              edge(blocked,("roles","other")),edge(intermediate,("object-groups",None),state="unresolved"),
              edge(intermediate,blocked,scope="2",state="not_observed")]
        result=dependency_impact(refs,*root)
        self.assertEqual([(p["module"],p["identity"]) for p in result["paths"]],[intermediate])
        boundaries=result["unqualified_boundaries"]
        self.assertEqual(len(boundaries),2)
        self.assertTrue(all(r["depth"]==1 and r["scope"]=="1" for r in boundaries))
        self.assertEqual({r["unqualified_edge"]["status"] for r in boundaries},{"conflicting_observation","unresolved"})
        self.assertTrue(all(len(r["resolved_prefix"])==1 for r in boundaries))
        self.assertTrue(dependency_impact(refs,*root,limit=1)["boundary_truncated"])


    def test_conditional_tenant_candidates_remain_visible_for_scoped_selection(self):
        root=("roles","employee")
        refs=[edge(("wlan-ssids","Office"),root),edge(("authz-policies","policy"),root,scope="NAC",persona="NAC",view="tenant",state="conditional_enforcement_candidate"),
              edge(("authz-policies","other"),("roles","Other"),scope="NAC",persona="NAC",view="tenant",state="conditional_enforcement_candidate")]
        for r in refs[1:]:
            r["source_evidence"]="nac_enforcement"
        report=dependency_impact(refs,*root,persona="ACCESS_SWITCH",scope="1")
        self.assertEqual(report["direct"],refs[:1])
        self.assertEqual(report["conditional_tenant_observations"],refs[1:2])
        self.assertEqual(len(report["paths"]),1)
        self.assertEqual(report["paths"][0]["persona"],"ACCESS_SWITCH")
        self.assertFalse(report["complete"])


    def test_lazy_impact_evidence_preserves_exact_selection(self):
        import tempfile,json
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.config_app import Workspace
        from aruba_central.review_dispositions import snapshot_binding,digest
        from test_consolidation import fixture
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-test.json"
            (Path(directory)/name).write_text(json.dumps(fixture()))
            w=Workspace(directory)
            root=("layer2-vlan","10")
            refs=[edge(("roles","role-"+str(i)),root) for i in range(120)]
            refs[-1]["private-evidence"]="last-private-marker"
            query={"snapshot":name,"module":root[0],"identity":root[1]}
            with patch.object(w,"advanced_snapshot",return_value={"references":refs}):
                page=w.impact(query)
                self.assertNotIn("last-private-marker",page)
                self.assertIn("of 120 observations",page)
                self.assertIn("data-inspect-url",page)
                bundle=w.reviewed_snapshot(name)
                key=digest([snapshot_binding(w,name,bundle),*root,"",""])
                detail=w.impact({**query,"detail":"direct","index":"119","binding":key})
                self.assertIn("last-private-marker",detail)
                with self.assertRaises(ValueError):
                    w.impact({**query,"identity":"20","detail":"direct","index":"119","binding":key})
