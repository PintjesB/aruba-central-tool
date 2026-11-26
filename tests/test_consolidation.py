import unittest
from consolidation import profile_recommendations
from central_tool import review_module_scope


def fixture():
    def view(bodies):
        return {"status": "list_parsed", "profiles": {str(v["vlan"]): v for v in bodies}}
    def vlan(number, name):
        return {"vlan": number, "name": name}
    global_profiles = [vlan(10, "Shared"), vlan(40, "Global")]
    scope_specs = [
        ("1", "global", "Global", [], global_profiles),
        ("2", "site", "Site", [], [vlan(10, "Different"), vlan(40, "Global")]),
        ("3", "device", "Switch A", [vlan(10, "Shared"), vlan(20, "Local repeat"), vlan(30, "Reuse"),
                                  vlan(40, "Exception"), vlan(50, "Unique")],
         [vlan(10, "Shared"), vlan(20, "Local repeat"), vlan(30, "Reuse"), vlan(40, "Exception"), vlan(50, "Unique")]),
        ("4", "device", "Switch B", [vlan(20, "Local repeat"), vlan(30, "Reuse")],
         [vlan(10, "Different"), vlan(20, "Local repeat"), vlan(30, "Reuse"), vlan(40, "Global")]),
        ("5", "device", "Unknown", [], []),
    ]
    scopes = []
    results = []
    for sid, kind, name, local, effective in scope_specs:
        scopes.append({"id": sid, "kind": kind, "name": name})
        local_view, effective_view = view(local), view(effective)
        if sid == "5":
            effective_view = {"status": "empty_object", "profiles": {}}
        review = review_module_scope(local_view, effective_view, view(global_profiles)["profiles"],
                                     is_global=kind == "global")
        results.append({"scope": sid, "scope_kind": kind, "local_view": local_view,
                        "effective_view": effective_view, "review": review})
    return {"schema": 1, "kind": "configuration_audit", "captured_at": "test",
            "results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
                "layer2-vlan": {"scope_results": results, "device_scope_only": False},
                "system-info": {"scope_results": results, "device_scope_only": False},
                "ethernet-interfaces": {"scope_results": results, "device_scope_only": True}}}},
            "library": {"modules": {"layer2-vlan": view([vlan(30, "Reuse"), vlan(60, "Unassigned")])},
                        "assignments": {"status": "response_received", "rows": [
                            {"profile-type": "layer2-vlan", "profile-instance": "30"}]}}}


class ConsolidationTests(unittest.TestCase):
    def test_advisor_groups_and_keeps_uncertainty(self):
        findings = profile_recommendations(fixture())
        by_id = {f["identity"]: f for f in findings}
        self.assertEqual(by_id["10"]["action"], "remove_override")
        self.assertTrue(any("intermediate scope" in b for b in by_id["10"]["blockers"]))
        self.assertEqual(by_id["20"]["action"], "promote_local")
        self.assertEqual(len(by_id["20"]["sources"]), 2)
        self.assertEqual(len(by_id["20"]["observed_devices"]["unknown"]), 1)
        self.assertEqual(by_id["30"]["action"], "reuse_library")
        self.assertEqual(by_id["40"]["action"], "conflict")
        self.assertEqual(by_id["50"]["action"], "create_library")
        self.assertEqual(by_id["60"]["action"], "unassigned_library")
        self.assertTrue(all(f["module"] == "layer2-vlan" for f in findings))
        self.assertTrue(all(not f["safe_to_apply"] for f in findings))
        self.assertEqual(len({f["id"] for f in findings}), len(findings))

    def test_missing_assignment_evidence_does_not_report_unused(self):
        bundle = fixture()
        bundle["library"]["assignments"] = {"status": "request_rejected", "rows": []}
        self.assertFalse(any(f["action"] == "unassigned_library" for f in profile_recommendations(bundle)))

    def test_advisor_page_is_read_only_and_selectable(self):
        import tempfile
        import json
        from pathlib import Path
        from config_app import Workspace
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).advisor({"snapshot": name})
            self.assertIn("Review redundant override", html)
            self.assertIn("Consolidate repeated local profiles", html)
            self.assertIn("Reuse existing Library profile", html)
            self.assertIn("Export private preview JSON", html)
            self.assertIn("not executable API operations", html)
            self.assertNotIn("Apply changes</button>", html)
