import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import digest, snapshot_binding
from test_consolidation import fixture


class ReferenceWorklistTests(unittest.TestCase):
    def test_filtered_rows_lazy_details_and_complete_export(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-test.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            w = Workspace(directory)
            refs = [{"persona": "ACCESS_SWITCH", "device": "Switch", "scope": "1",
                     "source_module": "roles", "source": f"role-{i:03d}", "source_view": "effective",
                     "target_module": "policies", "target": "policy", "path": ["rule"],
                     "status": "unresolved", "target_evidence": "target_collection_incomplete"}
                    for i in range(120)]
            refs[-1]["private-evidence"] = "last-private-marker"
            refs.append({**refs[0], "source": "resolved-only", "status": "observed"})
            query = {"snapshot": name, "workflow": "references"}
            bundle = w.reviewed_snapshot(name)
            binding = digest([snapshot_binding(w,name,bundle), "references"])
            with patch.object(w, "advanced_snapshot", return_value={"references":refs,"shadowed":[],
                         "port_groups":[],"library_duplicates":[]}):
                html = w.advanced(query)
                self.assertIn("of 120 matching observations", html)
                self.assertIn("role-049", html)
                self.assertNotIn("role-050", html)
                self.assertNotIn("last-private-marker", html)
                self.assertNotIn("resolved-only", html)
                self.assertIn("target collection incomplete", html.lower())
                last = w.advanced({**query,"ref_offset":"100"})
                self.assertIn("role-119", last)
                self.assertNotIn("last-private-marker", last)
                filtered = w.advanced({**query,"ref_q":"role-119","ref_module":"policies"})
                self.assertIn("of 1 matching observations", filtered)
                self.assertIn("of 120 matching observations", w.advanced({**query,"ref_evidence":"target_collection_incomplete"}))
                self.assertIn("of 0 matching observations", w.advanced({**query,"ref_evidence":"count_confirmed_absence"}))
                with self.assertRaises(ValueError):
                    w.advanced({**query,"ref_evidence":"invalid"})
                detail = w.advanced({**query,"reference_detail":"119","binding":binding})
                self.assertIn("last-private-marker", detail)
                with self.assertRaises(ValueError):
                    w.advanced({**query,"workflow":"resolved","reference_detail":"0","binding":binding})
                with self.assertRaises(ValueError):
                    w.advanced({**query,"reference_detail":"120","binding":binding})
                with self.assertRaises(ValueError):
                    w.advanced({**query,"ref_offset":"150"})
                exported = w.advanced({**query,"reference_export":"1","binding":binding})
                self.assertIn("last-private-marker", exported)
                self.assertIn("role-000", exported)
                self.assertNotIn("resolved-only", exported)
                path.write_text(path.read_text() + " ")
                with self.assertRaises(ValueError):
                    w.advanced({**query,"reference_detail":"119","binding":binding})

    def test_unknown_field_patterns_preserve_exact_source_module_and_list_path(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.config_app import Workspace
        from aruba_central.central_tool import canonical
        from test_consolidation import fixture
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-test.json"
            (Path(directory)/name).write_text(json.dumps(fixture()))
            w=Workspace(directory)
            base={"persona":"ACCESS_SWITCH","scope":"1","device":"Switch","source_module":"roles",
                  "source":"r","target_module":"layer2-vlan","target":None,"status":"unresolved"}
            refs=[{**base,"path":["fields",0,"vlan"]},{**base,"path":["fields",3,"vlan"]},
                  {**base,"path":["fields","0","vlan"]},{**base,"source_module":"wlan-ssids","path":["fields",0,"vlan"]},
                  {**base,"path":["fields","[]","vlan"]}]
            with patch.object(w,"advanced_snapshot",return_value={"references":refs,"shadowed":[],"port_groups":[],"library_duplicates":[]}):
                query={"snapshot":name,"workflow":"references"}
                html=w.advanced(query)
                self.assertIn("Unknown reference identity patterns (4)",html)
                self.assertIn("Inspect field",html)
                detail=w.advanced({**query,"ref_source":"roles","ref_field":canonical(["fields",{"index":"*"},"vlan"])})
                self.assertIn("of 2 matching observations",detail)
                self.assertIn("Clear field filter",detail)
                exact=w.advanced({**query,"ref_source":"roles","ref_field":canonical(["fields","0","vlan"])})
                self.assertIn("of 1 matching observations",exact)

    def test_alternative_context_filters_exclude_conflicts_and_unknown_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-test.json"
            (Path(directory)/name).write_text(json.dumps(fixture()))
            w=Workspace(directory)
            base={"persona":"CAMPUS_AP","scope":"1","device":"AP","source_module":"wlan-ssids",
                  "source":"test","target_module":"layer2-vlan","target":"20","status":"unresolved",
                  "path":["vlan-id-range"],"target_evidence":"target_view_unqualified"}
            refs=[{**base,"source":"positive-site","target_alternative_observations":[
                      {"context":"same_site_observation","status":"identity_observed"}]},
                  {**base,"source":"conflicting-site","target_alternative_observations":[
                      {"context":"same_site_observation","status":"individual_evidence_conflict"}]},
                  {**base,"source":"unknown-identity","target":None},
                  {**base,"source":"positive-library","target_alternative_observations":[
                      {"context":"library_definition","status":"identity_observed"}]}]
            with patch.object(w,"advanced_snapshot",return_value={"references":refs,"shadowed":[],"port_groups":[],"library_duplicates":[]}):
                query={"snapshot":name,"workflow":"references"}
                html=w.advanced({**query,"ref_context":"same_site_observation"})
                self.assertIn("of 1 matching observations",html)
                self.assertIn("positive-site",html)
                self.assertNotIn("conflicting-site",html)
                self.assertIn("Observed elsewhere",html)
                html=w.advanced({**query,"ref_context":"no_positive_context"})
                self.assertIn("of 1 matching observations",html)
                self.assertIn("conflicting-site",html)
                self.assertNotIn("unknown-identity",html)
                with self.assertRaises(ValueError):
                    w.advanced({**query,"ref_context":"invalid"})

    def test_set_membership_absence_worklist_remains_searchable(self):
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-test.json"
            (Path(directory)/name).write_text(json.dumps(fixture()))
            w=Workspace(directory)
            base={"persona":"ACCESS_SWITCH","scope":"1","device":"Switch","source":"profile",
                  "source_view":"effective","target_module":"layer2-vlan","status":"not_observed",
                  "target_evidence":"count_confirmed_absence"}
            refs=[{**base,"source_module":"stp","path":["mstp",0,"mstp-vlans"],"target":str(i)} for i in range(1,101)]
            refs.append({**base,"source_module":"ethernet-interfaces","path":["switchport","native-vlan"],"target":"200"})
            with patch.object(w,"advanced_snapshot",return_value={"references":refs,"shadowed":[],"port_groups":[],"library_duplicates":[]}):
                query={"snapshot":name,"workflow":"references"}
                html=w.advanced(query)
                self.assertIn("1 distinct captured set fields",html)
                self.assertIn("not a missing definition by itself",html)
                self.assertIn("of 101 matching observations",html)
                html=w.advanced({**query,"ref_semantics":"direct_or_unclassified"})
                self.assertIn("of 1 matching observations",html)
                self.assertIn("200",html)
                html=w.advanced({**query,"ref_semantics":"vlan_stp_member","ref_q":"99"})
                self.assertIn("of 1 matching observations",html)
                with self.assertRaises(ValueError):
                    w.advanced({**query,"ref_semantics":"invalid"})
